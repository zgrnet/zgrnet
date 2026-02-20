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
    batch_size: u32 = 0,
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

fn applyLinuxOptions(fd: posix.socket_t, cfg: SocketConfig, report: *OptimizationReport) void {
    _ = fd;
    _ = cfg;
    _ = report;
}

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

    const actual_rcv = tryGetsockoptInt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF);
    try std.testing.expect(actual_rcv >= 2 * 1024 * 1024);

    const actual_snd = tryGetsockoptInt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF);
    try std.testing.expect(actual_snd >= 1 * 1024 * 1024);
}

test "OptimizationReport: allApplied" {
    var report = OptimizationReport{};
    report.add(.{ .name = "SO_RCVBUF", .applied = true, .actual_value = 4194304 });
    report.add(.{ .name = "SO_SNDBUF", .applied = true, .actual_value = 4194304 });
    try std.testing.expect(report.allApplied());

    report.add(.{ .name = "SO_BUSY_POLL", .applied = false });
    try std.testing.expect(!report.allApplied());
}
