//! IO Service benchmarks
//!
//! Benchmarks for KqueueIO event dispatch throughput.
//! Uses pipes to generate real I/O events.

const std = @import("std");
const posix = std.posix;
const async_mod = @import("async");
const KqueueIO = async_mod.KqueueIO;
const ReadyCallback = async_mod.ReadyCallback;

/// Benchmark: poll + callback throughput via pipe
///
/// Writer thread writes in chunks, KqueueIO polls and fires read callback.
/// Measures how many IO events per second the kqueue backend can dispatch.
pub fn benchPollCallback(allocator: std.mem.Allocator) void {
    const iterations: usize = 64 * 1024 * 1024; // 64 MB

    var io = KqueueIO.init(allocator) catch {
        std.debug.print("KqueueIO poll+callback:    SKIPPED (init failed)\n", .{});
        return;
    };
    defer io.deinit();

    const pipe_fds = posix.pipe() catch {
        std.debug.print("KqueueIO poll+callback:    SKIPPED (pipe failed)\n", .{});
        return;
    };
    defer posix.close(pipe_fds[0]);
    defer posix.close(pipe_fds[1]);

    // Set read end non-blocking
    const flags = posix.fcntl(pipe_fds[0], posix.F.GETFL, 0) catch 0;
    var o_flags: posix.O = @bitCast(@as(u32, @intCast(flags)));
    o_flags.NONBLOCK = true;
    _ = posix.fcntl(pipe_fds[0], posix.F.SETFL, @as(usize, @as(u32, @bitCast(o_flags)))) catch {};

    var bytes_read: u64 = 0;
    var read_buf: [4096]u8 = undefined;

    const Ctx = struct {
        bytes: *u64,
        buf: *[4096]u8,

        fn onReady(ptr: ?*anyopaque, fd: posix.fd_t) void {
            const self: *@This() = @ptrCast(@alignCast(ptr.?));
            // Drain all available bytes
            while (true) {
                const n = posix.read(fd, self.buf) catch break;
                if (n == 0) break;
                self.bytes.* += n;
            }
        }
    };

    var ctx = Ctx{
        .bytes = &bytes_read,
        .buf = &read_buf,
    };

    io.registerRead(pipe_fds[0], .{
        .ptr = @ptrCast(&ctx),
        .callback = Ctx.onReady,
    });

    // Writer thread: writes in chunks for throughput
    const writer = std.Thread.spawn(.{}, struct {
        fn run(fd: posix.fd_t, total: usize) void {
            var buf: [4096]u8 = undefined;
            @memset(&buf, 0x42);
            var remaining = total;
            while (remaining > 0) {
                const chunk = @min(remaining, buf.len);
                const n = posix.write(fd, buf[0..chunk]) catch return;
                remaining -= n;
            }
        }
    }.run, .{ pipe_fds[1], iterations }) catch {
        std.debug.print("KqueueIO poll+callback:    SKIPPED (thread failed)\n", .{});
        return;
    };

    const start = std.time.nanoTimestamp();

    // Poll until all bytes received
    const total_bytes: u64 = iterations;
    while (bytes_read < total_bytes) {
        _ = io.poll(100);
    }

    const end = std.time.nanoTimestamp();
    writer.join();

    const elapsed_ns: u64 = @intCast(end - start);
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const bytes_per_sec = @as(f64, @floatFromInt(bytes_read)) / (@as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0);

    std.debug.print("KqueueIO poll+callback:    {d:.1} MB/sec ({d:.0}ms, {d} bytes via pipe)\n", .{
        bytes_per_sec / (1024.0 * 1024.0),
        elapsed_ms,
        bytes_read,
    });
}

/// Benchmark: register/unregister churn
///
/// Measures how fast we can register and unregister file descriptors.
pub fn benchRegisterChurn(allocator: std.mem.Allocator) void {
    const iterations: usize = 200_000;

    var io = KqueueIO.init(allocator) catch {
        std.debug.print("KqueueIO register churn:   SKIPPED (init failed)\n", .{});
        return;
    };
    defer io.deinit();

    // Create a pipe just for a valid fd
    const pipe_fds = posix.pipe() catch {
        std.debug.print("KqueueIO register churn:   SKIPPED (pipe failed)\n", .{});
        return;
    };
    defer posix.close(pipe_fds[0]);
    defer posix.close(pipe_fds[1]);

    // Warmup
    for (0..1000) |_| {
        io.registerRead(pipe_fds[0], ReadyCallback.noop);
        io.unregister(pipe_fds[0]);
    }

    const start = std.time.nanoTimestamp();

    for (0..iterations) |_| {
        io.registerRead(pipe_fds[0], ReadyCallback.noop);
        io.unregister(pipe_fds[0]);
    }

    const end = std.time.nanoTimestamp();
    const elapsed_ns: u64 = @intCast(end - start);
    const ns_per_op = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iterations));
    const ops_per_sec = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0);

    std.debug.print("KqueueIO register churn:   {d:.0} ns/op ({d:.2} M ops/sec)\n", .{
        ns_per_op,
        ops_per_sec / 1_000_000.0,
    });
}

/// Benchmark: wake() latency
///
/// Measures round-trip time for wake() to interrupt a blocking poll().
pub fn benchWakeLatency(allocator: std.mem.Allocator) void {
    const iterations: usize = 100_000;

    var io = KqueueIO.init(allocator) catch {
        std.debug.print("KqueueIO wake latency:     SKIPPED (init failed)\n", .{});
        return;
    };
    defer io.deinit();

    // Warmup: non-blocking polls
    for (0..1000) |_| {
        io.wake();
        _ = io.poll(0);
    }

    const start = std.time.nanoTimestamp();

    for (0..iterations) |_| {
        io.wake();
        _ = io.poll(0); // Should return immediately due to wake
    }

    const end = std.time.nanoTimestamp();
    const elapsed_ns: u64 = @intCast(end - start);
    const ns_per_op = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iterations));

    std.debug.print("KqueueIO wake latency:     {d:.0} ns/op\n", .{ns_per_op});
}

/// Run all IO benchmarks
pub fn runAll(allocator: std.mem.Allocator) void {
    std.debug.print("\n[IO Backend - KqueueIO]\n", .{});
    benchPollCallback(allocator);
    benchRegisterChurn(allocator);
    benchWakeLatency(allocator);
}
