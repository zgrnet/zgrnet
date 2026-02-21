//! UDP socket optimizations.
//!
//! Provides `SocketConfig` and `applySocketOptions()` to configure
//! SO_RCVBUF/SNDBUF, and on Linux: recvmmsg/sendmmsg, GRO/GSO, SO_BUSY_POLL.

const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");

pub const default_recv_buf_size: u32 = 4 * 1024 * 1024; // 4MB
pub const default_send_buf_size: u32 = 4 * 1024 * 1024; // 4MB
pub const default_busy_poll_us: u32 = 50;
pub const default_gso_segment: u32 = 1400;
pub const default_batch_size: u32 = 64;

/// Configuration for UDP socket optimizations.
pub const SocketConfig = struct {
    recv_buf_size: u32 = default_recv_buf_size,
    send_buf_size: u32 = default_send_buf_size,
    reuse_port: bool = false,
    busy_poll_us: u32 = 0,
    gro: bool = false,
    gso_segment: u32 = 0,

    /// Returns a config with all optimizations enabled.
    pub fn full() SocketConfig {
        return .{
            .recv_buf_size = default_recv_buf_size,
            .send_buf_size = default_send_buf_size,
            .busy_poll_us = default_busy_poll_us,
            .gro = true,
            .gso_segment = default_gso_segment,
        };
    }
};

/// Result of a single optimization attempt.
pub const OptimizationEntry = struct {
    name: []const u8,
    applied: bool,
    actual_value: u32 = 0,
};

/// Collects results of all optimization attempts on a socket.
pub const OptimizationReport = struct {
    entries: [max_entries]OptimizationEntry = undefined,
    count: usize = 0,

    const max_entries = 8;

    pub fn add(self: *OptimizationReport, entry: OptimizationEntry) void {
        if (self.count < max_entries) {
            self.entries[self.count] = entry;
            self.count += 1;
        }
    }

    pub fn allApplied(self: *const OptimizationReport) bool {
        for (self.entries[0..self.count]) |e| {
            if (!e.applied) return false;
        }
        return true;
    }
};

/// Apply all configured optimizations to a socket file descriptor.
/// Each optimization is tried independently; failures don't block others.
pub fn applySocketOptions(fd: posix.socket_t, cfg: SocketConfig) OptimizationReport {
    var report = OptimizationReport{};

    const sol_socket: i32 = posix.SOL.SOCKET;

    // SO_RCVBUF
    const recv_buf: i32 = @intCast(if (cfg.recv_buf_size > 0) cfg.recv_buf_size else default_recv_buf_size);
    if (trySetsockoptInt(fd, sol_socket, posix.SO.RCVBUF, recv_buf)) {
        report.add(.{ .name = "SO_RCVBUF", .applied = true, .actual_value = tryGetsockoptInt(fd, sol_socket, posix.SO.RCVBUF) });
    } else {
        report.add(.{ .name = "SO_RCVBUF", .applied = false });
    }

    // SO_SNDBUF
    const send_buf: i32 = @intCast(if (cfg.send_buf_size > 0) cfg.send_buf_size else default_send_buf_size);
    if (trySetsockoptInt(fd, sol_socket, posix.SO.SNDBUF, send_buf)) {
        report.add(.{ .name = "SO_SNDBUF", .applied = true, .actual_value = tryGetsockoptInt(fd, sol_socket, posix.SO.SNDBUF) });
    } else {
        report.add(.{ .name = "SO_SNDBUF", .applied = false });
    }

    // Linux-specific options (later phases)
    if (comptime builtin.os.tag == .linux) {
        applyLinuxOptions(fd, cfg, &report);
    }

    return report;
}

fn trySetsockoptInt(fd: posix.socket_t, level: i32, optname: u32, value: i32) bool {
    posix.setsockopt(fd, level, optname, std.mem.asBytes(&value)) catch return false;
    return true;
}

/// Read an integer socket option. Returns 0 on error.
pub fn tryGetsockoptInt(fd: posix.socket_t, level: i32, optname: u32) u32 {
    var value: i32 = 0;
    var len: posix.socklen_t = @sizeOf(i32);
    const rc = std.c.getsockopt(
        fd,
        level,
        @intCast(optname),
        @ptrCast(&value),
        &len,
    );
    if (rc < 0) return 0;
    return @intCast(value);
}

const SO_BUSY_POLL: u32 = 46;
const UDP_GRO: u32 = 104;
const UDP_SEGMENT: u32 = 103;

/// Check if UDP_SEGMENT (GSO) is available on a socket.
/// Probes by setting and immediately clearing the option to avoid side effects.
pub fn gsoSupported(fd: posix.socket_t) bool {
    const proto: i32 = @intCast(std.posix.IPPROTO.UDP);
    if (trySetsockoptInt(fd, proto, UDP_SEGMENT, 1400)) {
        _ = trySetsockoptInt(fd, proto, UDP_SEGMENT, 0);
        return true;
    }
    return false;
}

fn applyLinuxOptions(fd: posix.socket_t, cfg: SocketConfig, report: *OptimizationReport) void {
    if (cfg.busy_poll_us > 0) {
        const val: i32 = @intCast(cfg.busy_poll_us);
        if (trySetsockoptInt(fd, posix.SOL.SOCKET, SO_BUSY_POLL, val)) {
            report.add(.{ .name = "SO_BUSY_POLL", .applied = true, .actual_value = cfg.busy_poll_us });
        } else {
            report.add(.{ .name = "SO_BUSY_POLL", .applied = false });
        }
    }

    if (cfg.gro) {
        if (trySetsockoptInt(fd, std.posix.IPPROTO.UDP, UDP_GRO, 1)) {
            report.add(.{ .name = "UDP_GRO", .applied = true, .actual_value = 1 });
        } else {
            report.add(.{ .name = "UDP_GRO", .applied = false });
        }
    }
}

// ============================================================================
// SO_REUSEPORT
// ============================================================================

/// Set SO_REUSEPORT on a socket before bind.
/// Allows multiple sockets to bind to the same address for kernel load balancing.
pub fn setReusePort(fd: posix.socket_t) bool {
    const val: i32 = 1;
    posix.setsockopt(fd, @intCast(posix.SOL.SOCKET), posix.SO.REUSEPORT, std.mem.asBytes(&val)) catch return false;
    return true;
}

// ============================================================================
// Batch I/O (Linux recvmmsg / sendmmsg)
// ============================================================================

pub const default_batch_count: u32 = 64;

/// Result of a single received message in a batch.
pub const BatchRecvResult = struct {
    n: usize,
    src_addr: [4]u8,
    src_port: u16,
};

/// Batch reader using recvmmsg (Linux only, no-op on other platforms).
pub const BatchReader = struct {
    fd: posix.socket_t,
    batch_size: usize,

    pub fn init(fd: posix.socket_t, batch_size: usize) BatchReader {
        return .{ .fd = fd, .batch_size = batch_size };
    }

    /// Read up to batch_size packets using recvmmsg.
    /// Returns the number of packets received. Each buffer[i] is filled
    /// with data and results[i] contains the metadata.
    pub fn readBatch(
        self: *const BatchReader,
        buffers: [][]u8,
        results: []BatchRecvResult,
    ) !usize {
        if (comptime builtin.os.tag != .linux) {
            // Non-Linux fallback: single recvfrom
            var from_addr: posix.sockaddr.in = undefined;
            var from_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
            const n = posix.recvfrom(self.fd, buffers[0], 0, @ptrCast(&from_addr), &from_len) catch return error.RecvFailed;
            if (n == 0) return 0;
            results[0] = .{
                .n = n,
                .src_addr = @bitCast(from_addr.addr),
                .src_port = std.mem.bigToNative(u16, from_addr.port),
            };
            return 1;
        }

        const max_batch = 64;
        const count = @min(buffers.len, @min(results.len, @min(self.batch_size, max_batch)));
        if (count == 0) return 0;

        var msgs: [max_batch]std.os.linux.mmsghdr_const = undefined;
        var iovecs: [max_batch]posix.iovec = undefined;
        var addrs: [max_batch]posix.sockaddr.in = undefined;

        for (0..count) |i| {
            iovecs[i] = .{
                .base = buffers[i].ptr,
                .len = buffers[i].len,
            };
            addrs[i] = std.mem.zeroes(posix.sockaddr.in);
            msgs[i] = .{
                .msg_hdr = .{
                    .name = @ptrCast(&addrs[i]),
                    .namelen = @sizeOf(posix.sockaddr.in),
                    .iov = @ptrCast(&iovecs[i]),
                    .iovlen = 1,
                    .control = .{ .len = 0, .ptr = null },
                    .flags = 0,
                },
                .msg_len = 0,
            };
        }

        const rc = std.os.linux.recvmmsg(
            self.fd,
            &msgs,
            count,
            0,
            null,
        );
        const err = posix.errno(rc);
        if (err != .SUCCESS) {
            return posix.unexpectedErrno(err);
        }

        const received: usize = @intCast(rc);
        for (0..received) |i| {
            results[i] = .{
                .n = msgs[i].msg_len,
                .src_addr = @bitCast(addrs[i].addr),
                .src_port = std.mem.bigToNative(u16, addrs[i].port),
            };
        }
        return received;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "applySocketOptions: SO_RCVBUF and SO_SNDBUF" {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch |err| {
        std.debug.print("socket() failed: {}\n", .{err});
        return;
    };
    defer posix.close(fd);

    const report = applySocketOptions(fd, .{});
    try std.testing.expect(report.count >= 2);
    try std.testing.expect(report.entries[0].applied); // SO_RCVBUF
    try std.testing.expect(report.entries[1].applied); // SO_SNDBUF
}

test "applySocketOptions: verify actual buffer size" {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
    defer posix.close(fd);

    _ = applySocketOptions(fd, .{
        .recv_buf_size = 2 * 1024 * 1024,
        .send_buf_size = 1 * 1024 * 1024,
    });

    // Verify getsockopt returns a non-zero value. The actual value may be
    // less than requested due to kernel limits (net.core.rmem_max on Linux).
    const sol_socket: i32 = posix.SOL.SOCKET;
    const actual_rcv = tryGetsockoptInt(fd, sol_socket, posix.SO.RCVBUF);
    try std.testing.expect(actual_rcv > 0);

    const actual_snd = tryGetsockoptInt(fd, sol_socket, posix.SO.SNDBUF);
    try std.testing.expect(actual_snd > 0);
}

test "setReusePort: multiple bind" {
    const fd1 = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
    defer posix.close(fd1);

    try std.testing.expect(setReusePort(fd1));

    const sa = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = 0,
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
    };
    posix.bind(fd1, @ptrCast(&sa), @sizeOf(posix.sockaddr.in)) catch return;

    // Get the bound port
    var bound: posix.sockaddr.in = undefined;
    var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    posix.getsockname(fd1, @ptrCast(&bound), &bound_len) catch return;

    // Bind second socket to same address
    const fd2 = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
    defer posix.close(fd2);

    try std.testing.expect(setReusePort(fd2));
    posix.bind(fd2, @ptrCast(&bound), @sizeOf(posix.sockaddr.in)) catch |err| {
        std.debug.print("second bind failed: {}\n", .{err});
        return error.TestUnexpectedResult;
    };
}

test "applySocketOptions: full config graceful degradation" {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
    defer posix.close(fd);

    const report = applySocketOptions(fd, SocketConfig.full());

    // SO_RCVBUF and SO_SNDBUF must always succeed
    try std.testing.expect(report.count >= 2);
    try std.testing.expect(report.entries[0].applied); // SO_RCVBUF
    try std.testing.expect(report.entries[1].applied); // SO_SNDBUF

    // Linux-only options may fail on macOS, that's fine
    // The point is: no crash, and basic RCVBUF/SNDBUF always work
}

test "OptimizationReport: allApplied" {
    var report = OptimizationReport{};
    report.add(.{ .name = "SO_RCVBUF", .applied = true, .actual_value = 4194304 });
    report.add(.{ .name = "SO_SNDBUF", .applied = true, .actual_value = 4194304 });
    try std.testing.expect(report.allApplied());

    report.add(.{ .name = "SO_BUSY_POLL", .applied = false });
    try std.testing.expect(!report.allApplied());
}
