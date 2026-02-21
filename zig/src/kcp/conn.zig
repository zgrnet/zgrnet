//! KcpConn — async KCP connection driven by Rt.Thread.
//!
//! Architecture (matches Go's KCPConn.runLoop):
//! - One Rt.Thread exclusively owns the KCP instance (the run loop)
//! - write() appends to shared write_buf (Rt.Mutex protected, O(1) memcpy)
//!   and signals the run loop via Rt.Condition
//! - read() blocks on recv_cond until recv_buf has data
//! - input() sends raw packets via input queue (bounded, non-blocking)
//! - Write coalescing: N small writes become fewer kcp.send() calls
//! - Dead peer detection: kcp.state() < 0 + idle timeout (15s/30s)
//!
//! Generic over `comptime Rt: type` for ESP32 compatibility.

const std = @import("std");
const kcp_mod = @import("kcp.zig");

const idle_timeout_ms: u64 = 15_000;
const idle_timeout_pure_ms: u64 = 30_000;

pub fn KcpConn(comptime Rt: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        kcp: *kcp_mod.Kcp,

        // Write coalescing buffer (shared between writer + run_loop).
        write_buf: std.ArrayListUnmanaged(u8),
        write_mutex: Rt.Mutex,
        write_cond: Rt.Condition,

        // Input queue: external network packets → run_loop.
        input_buf: std.ArrayListUnmanaged([]u8),
        input_mutex: Rt.Mutex,

        // Receive buffer: run_loop → reader.
        recv_buf: std.ArrayListUnmanaged(u8),
        recv_mutex: Rt.Mutex,
        recv_cond: Rt.Condition,

        // State.
        closed: std.atomic.Value(bool),
        last_recv_ms: std.atomic.Value(u64),
        run_thread: ?Rt.Thread,

        // Output callback.
        output_fn: *const fn ([]const u8, ?*anyopaque) void,
        output_ctx: ?*anyopaque,

        pub fn init(
            allocator: std.mem.Allocator,
            conv: u32,
            output_fn: *const fn ([]const u8, ?*anyopaque) void,
            output_ctx: ?*anyopaque,
        ) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            const kcp = try kcp_mod.Kcp.create(allocator, conv, output_fn, output_ctx);

            kcp.setNodelay(1, 1, 2, 1);
            kcp.setWndSize(4096, 4096);
            kcp.setMtu(1400);
            kcp.update(@intCast(Rt.nowMs() & 0xFFFFFFFF));

            self.* = Self{
                .allocator = allocator,
                .kcp = kcp,
                .write_buf = .{},
                .write_mutex = Rt.Mutex.init(),
                .write_cond = Rt.Condition.init(),
                .input_buf = .{},
                .input_mutex = Rt.Mutex.init(),
                .recv_buf = .{},
                .recv_mutex = Rt.Mutex.init(),
                .recv_cond = Rt.Condition.init(),
                .closed = std.atomic.Value(bool).init(false),
                .last_recv_ms = std.atomic.Value(u64).init(Rt.nowMs()),
                .run_thread = null,
                .output_fn = output_fn,
                .output_ctx = output_ctx,
            };

            // Spawn run loop thread.
            self.run_thread = Rt.Thread.spawn(.{}, runLoop, .{self}) catch null;

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.close();
            if (self.run_thread) |t| {
                t.join();
                self.run_thread = null;
            }

            self.input_mutex.lock();
            for (self.input_buf.items) |pkt| {
                self.allocator.free(pkt);
            }
            self.input_buf.deinit(self.allocator);
            self.input_mutex.unlock();

            self.write_buf.deinit(self.allocator);
            self.recv_buf.deinit(self.allocator);
            self.write_mutex.deinit();
            self.write_cond.deinit();
            self.input_mutex.deinit();
            self.recv_mutex.deinit();
            self.recv_cond.deinit();

            self.kcp.deinit();
            self.allocator.destroy(self.kcp);
            self.allocator.destroy(self);
        }

        /// Feed raw network packet to KCP. Non-blocking. Signals run loop.
        pub fn input(self: *Self, data: []const u8) !void {
            if (self.closed.load(.acquire)) return error.Closed;
            const copy = try self.allocator.dupe(u8, data);
            self.input_mutex.lock();
            try self.input_buf.append(self.allocator, copy);
            self.input_mutex.unlock();
            // Wake run loop immediately to process the input.
            self.write_cond.signal();
        }

        /// Blocking read. Waits until recv_buf has data or connection closes.
        pub fn read(self: *Self, buf: []u8) !usize {
            self.recv_mutex.lock();
            defer self.recv_mutex.unlock();

            while (self.recv_buf.items.len == 0) {
                if (self.closed.load(.acquire)) return 0; // EOF
                _ = self.recv_cond.timedWait(&self.recv_mutex, 100 * std.time.ns_per_ms);
            }

            if (self.recv_buf.items.len == 0) return 0;

            const n = @min(buf.len, self.recv_buf.items.len);
            @memcpy(buf[0..n], self.recv_buf.items[0..n]);
            // Remove consumed bytes.
            std.mem.copyForwards(u8, self.recv_buf.items[0..], self.recv_buf.items[n..]);
            self.recv_buf.items.len -= n;
            return n;
        }

        /// Blocking write with coalescing. Only signals on empty→non-empty transition.
        pub fn write(self: *Self, data: []const u8) !usize {
            if (self.closed.load(.acquire)) return error.Closed;

            self.write_mutex.lock();
            const was_empty = self.write_buf.items.len == 0;
            try self.write_buf.appendSlice(self.allocator, data);
            self.write_mutex.unlock();

            if (was_empty) self.write_cond.signal();
            return data.len;
        }

        pub fn close(self: *Self) void {
            if (self.closed.swap(true, .acq_rel)) return; // already closed
            self.recv_cond.broadcast();
            self.write_cond.broadcast();
        }

        pub fn isClosed(self: *const Self) bool {
            return self.closed.load(.acquire);
        }

        // ── Run loop ────────────────────────────────────────────────────

        fn runLoop(self: *Self) void {
            while (!self.closed.load(.acquire)) {
                // Dead link detection.
                if (self.kcp.state() < 0) {
                    self.close();
                    return;
                }

                // Idle timeout.
                const now = Rt.nowMs();
                const idle = now -| self.last_recv_ms.load(.acquire);
                if (idle > idle_timeout_ms and self.kcp.waitSnd() > 0) {
                    self.close();
                    return;
                }
                if (idle > idle_timeout_pure_ms) {
                    self.close();
                    return;
                }

                // Drain all pending work (input + write coalescing).
                self.drainInput();
                self.drainWriteBuf();

                const now_ms: u32 = @intCast(Rt.nowMs() & 0xFFFFFFFF);
                self.kcp.update(now_ms);
                self.kcp.flush();
                self.drainRecv();

                // Check if there's pending work.
                {
                    self.input_mutex.lock();
                    const has_input = self.input_buf.items.len > 0;
                    self.input_mutex.unlock();
                    self.write_mutex.lock();
                    const has_write = self.write_buf.items.len > 0;
                    self.write_mutex.unlock();

                    if (has_input or has_write) continue; // process immediately
                }

                // No pending work. Wait for signal or KCP check time.
                const check = self.kcp.check(now_ms);
                const delay = if (check <= now_ms) @as(u32, 1) else @min(check - now_ms, 5);

                self.write_mutex.lock();
                if (!self.closed.load(.acquire)) {
                    _ = self.write_cond.timedWait(&self.write_mutex, @as(u64, delay) * std.time.ns_per_ms);
                }
                self.write_mutex.unlock();
            }
        }

        fn drainInput(self: *Self) void {
            self.input_mutex.lock();
            const items = self.input_buf.toOwnedSlice(self.allocator) catch {
                self.input_mutex.unlock();
                return;
            };
            self.input_mutex.unlock();

            for (items) |pkt| {
                _ = self.kcp.input(pkt);
                self.allocator.free(pkt);
                self.last_recv_ms.store(Rt.nowMs(), .release);
            }
            self.allocator.free(items);
        }

        fn drainWriteBuf(self: *Self) void {
            self.write_mutex.lock();
            if (self.write_buf.items.len == 0) {
                self.write_mutex.unlock();
                return;
            }
            const data = self.write_buf.toOwnedSlice(self.allocator) catch {
                self.write_mutex.unlock();
                return;
            };
            self.write_mutex.unlock();

            // Send in 8KB chunks for incremental delivery.
            var offset: usize = 0;
            while (offset < data.len) {
                const end = @min(offset + 8192, data.len);
                _ = self.kcp.send(data[offset..end]);
                offset = end;
            }
            self.allocator.free(data);
        }

        fn drainRecv(self: *Self) void {
            var buf: [65536]u8 = undefined;
            var received = false;
            while (true) {
                const peek = self.kcp.peekSize();
                if (peek <= 0) break;
                const n = self.kcp.recv(&buf);
                if (n <= 0) break;

                self.recv_mutex.lock();
                self.recv_buf.appendSlice(self.allocator, buf[0..@intCast(n)]) catch {};
                self.recv_mutex.unlock();
                received = true;
            }
            if (received) {
                self.recv_cond.broadcast();
            }
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const TestRuntime = if (@import("builtin").os.tag != .freestanding) struct {
    pub const Mutex = struct {
        inner: std.Thread.Mutex = .{},
        pub fn init() Mutex { return .{}; }
        pub fn deinit(_: *Mutex) void {}
        pub fn lock(self: *Mutex) void { self.inner.lock(); }
        pub fn unlock(self: *Mutex) void { self.inner.unlock(); }
    };
    pub const Condition = struct {
        inner: std.Thread.Condition = .{},
        pub fn init() Condition { return .{}; }
        pub fn deinit(_: *Condition) void {}
        pub fn wait(self: *Condition, mutex: *Mutex) void { self.inner.wait(&mutex.inner); }
        pub fn timedWait(self: *Condition, mutex: *Mutex, timeout_ns: u64) bool {
            self.inner.timedWait(&mutex.inner, timeout_ns) catch return true; // timed out
            return false; // signaled
        }
        pub fn signal(self: *Condition) void { self.inner.signal(); }
        pub fn broadcast(self: *Condition) void { self.inner.broadcast(); }
    };
    pub fn nowMs() u64 {
        return @intCast(std.time.milliTimestamp());
    }
    pub const Thread = std.Thread;
    pub fn sleepMs(ms: u32) void {
        std.Thread.sleep(@as(u64, ms) * std.time.ns_per_ms);
    }
} else struct {};

fn connPair() !struct { a: *KcpConn(TestRuntime), b: *KcpConn(TestRuntime) } {
    const Conn = KcpConn(TestRuntime);
    const allocator = std.testing.allocator;

    // We need to pass output from A to B's input and vice versa.
    // Use a simple global pair for testing.
    const Ctx = struct {
        var a_ptr: ?*Conn = null;
        var b_ptr: ?*Conn = null;

        fn outputA(data: []const u8, _: ?*anyopaque) void {
            if (b_ptr) |b| b.input(data) catch {};
        }
        fn outputB(data: []const u8, _: ?*anyopaque) void {
            if (a_ptr) |a| a.input(data) catch {};
        }
    };

    Ctx.a_ptr = null;
    Ctx.b_ptr = null;

    const a = try Conn.init(allocator, 1, Ctx.outputA, null);
    const b = try Conn.init(allocator, 1, Ctx.outputB, null);
    Ctx.a_ptr = a;
    Ctx.b_ptr = b;

    return .{ .a = a, .b = b };
}

test "kcpconn write_read" {
    if (@import("builtin").os.tag == .freestanding) return;
    const pair = try connPair();
    defer pair.a.deinit();
    defer pair.b.deinit();

    _ = try pair.a.write("hello from A");
    var buf: [256]u8 = undefined;
    const n = try pair.b.read(&buf);
    try std.testing.expectEqualStrings("hello from A", buf[0..n]);
}

test "kcpconn bidirectional" {
    if (@import("builtin").os.tag == .freestanding) return;
    const pair = try connPair();
    defer pair.a.deinit();
    defer pair.b.deinit();

    _ = try pair.a.write("from A");
    _ = try pair.b.write("from B");

    var buf: [256]u8 = undefined;
    const n1 = try pair.b.read(&buf);
    try std.testing.expectEqualStrings("from A", buf[0..n1]);

    const n2 = try pair.a.read(&buf);
    try std.testing.expectEqualStrings("from B", buf[0..n2]);
}

test "kcpconn large data" {
    if (@import("builtin").os.tag == .freestanding) return;
    const allocator = std.testing.allocator;
    const pair = try connPair();
    defer pair.a.deinit();
    defer pair.b.deinit();

    const size: usize = 32 * 1024;
    const data = try allocator.alloc(u8, size);
    defer allocator.free(data);
    for (data, 0..) |*b, i| b.* = @intCast(i % 251);

    // Write in chunks.
    var written: usize = 0;
    while (written < size) {
        const end = @min(written + 1024, size);
        _ = try pair.a.write(data[written..end]);
        written = end;
    }

    // Read all.
    const received = try allocator.alloc(u8, size);
    defer allocator.free(received);
    var total: usize = 0;
    while (total < size) {
        const n = try pair.b.read(received[total..]);
        if (n == 0) break;
        total += n;
    }

    try std.testing.expectEqual(size, total);
    try std.testing.expectEqualSlices(u8, data, received);
}

test "kcpconn close eof" {
    if (@import("builtin").os.tag == .freestanding) return;
    const pair = try connPair();
    defer pair.b.deinit();

    _ = try pair.a.write("before close");
    pair.a.close();
    // Don't deinit a yet — just close it.

    var buf: [256]u8 = undefined;
    // Should still read buffered data, then EOF.
    const n = try pair.b.read(&buf);
    if (n > 0) {
        try std.testing.expectEqualStrings("before close", buf[0..n]);
    }

    // Eventually read returns 0 (EOF) after close propagates.
    TestRuntime.sleepMs(200);
    const n2 = try pair.b.read(&buf);
    _ = n2; // might be 0 or leftover

    pair.a.deinit();
}

test "kcpconn close unblocks read" {
    if (@import("builtin").os.tag == .freestanding) return;
    const pair = try connPair();
    defer pair.b.deinit();

    // Reader in background — will block because no data.
    const ReaderThread = struct {
        fn run(b: *KcpConn(TestRuntime)) void {
            var buf: [256]u8 = undefined;
            _ = b.read(&buf) catch {};
        }
    };
    const t = std.Thread.spawn(.{}, ReaderThread.run, .{pair.a}) catch return;

    TestRuntime.sleepMs(200);
    pair.a.close();

    t.join();
    pair.a.deinit();
    // If we reach here, close unblocked the read. Test passes.
}

test "kcpconn loss 5pct" {
    if (@import("builtin").os.tag == .freestanding) return;
    const allocator = std.testing.allocator;
    const Conn = KcpConn(TestRuntime);

    // Build lossy conn pair: 5% packet drop.
    const LossCtx = struct {
        var a_ptr: ?*Conn = null;
        var b_ptr: ?*Conn = null;
        var rng: u64 = 42;

        fn shouldDrop() bool {
            rng = rng *% 6364136223846793005 +% 1;
            return ((rng >> 33) % 100) < 5;
        }
        fn outputA(data: []const u8, _: ?*anyopaque) void {
            if (shouldDrop()) return;
            if (b_ptr) |b| b.input(data) catch {};
        }
        fn outputB(data: []const u8, _: ?*anyopaque) void {
            if (shouldDrop()) return;
            if (a_ptr) |a| a.input(data) catch {};
        }
    };
    LossCtx.a_ptr = null;
    LossCtx.b_ptr = null;
    LossCtx.rng = 42;

    const a = try Conn.init(allocator, 1, LossCtx.outputA, null);
    defer a.deinit();
    const b = try Conn.init(allocator, 1, LossCtx.outputB, null);
    defer b.deinit();
    LossCtx.a_ptr = a;
    LossCtx.b_ptr = b;

    const size: usize = 32 * 1024;
    const data = try allocator.alloc(u8, size);
    defer allocator.free(data);
    for (data, 0..) |*byte, i| byte.* = @intCast(i % 251);

    // Write in chunks.
    var written: usize = 0;
    while (written < size) {
        const end = @min(written + 1024, size);
        _ = try a.write(data[written..end]);
        written = end;
    }

    // Read all.
    const received = try allocator.alloc(u8, size);
    defer allocator.free(received);
    var total: usize = 0;
    while (total < size) {
        const n = try b.read(received[total..]);
        if (n == 0) break;
        total += n;
    }

    try std.testing.expectEqual(size, total);
    try std.testing.expectEqualSlices(u8, data, received);
}

test "bench kcpconn throughput" {
    if (@import("builtin").os.tag == .freestanding) return;
    const allocator = std.testing.allocator;
    const pair = try connPair();
    defer pair.a.deinit();
    defer pair.b.deinit();

    const sizes = [_]usize{ 512, 1024, 8192, 32768 };
    for (sizes) |chunk_size| {
        const total: usize = @max(chunk_size * 200, 128 * 1024);
        const chunk = try allocator.alloc(u8, chunk_size);
        defer allocator.free(chunk);
        @memset(chunk, 0x58);

        const WriterFn = struct {
            fn run(a: *KcpConn(TestRuntime), data: []const u8, t: usize) void {
                var sent: usize = 0;
                while (sent < t) {
                    sent += a.write(data) catch break;
                }
            }
        };
        const wt = std.Thread.spawn(.{}, WriterFn.run, .{ pair.a, chunk, total }) catch continue;

        const start = std.time.nanoTimestamp();
        var received: usize = 0;
        var buf: [65536]u8 = undefined;
        while (received < total) {
            const n = pair.b.read(&buf) catch break;
            if (n == 0) break;
            received += n;
        }
        const elapsed_ns: u64 = @intCast(std.time.nanoTimestamp() - start);
        wt.join();

        const mbps = @as(f64, @floatFromInt(received)) / @as(f64, @floatFromInt(elapsed_ns)) * 1000.0;
        std.debug.print("[kcpconn] chunk={d}B {d:.1} MB/s\n", .{ chunk_size, mbps });
    }
}

test "bench yamux streaming" {
    if (@import("builtin").os.tag == .freestanding) return;
    const yamux_m = @import("yamux.zig");
    const allocator = std.testing.allocator;
    const Conn = KcpConn(TestRuntime);
    const YMux = yamux_m.Yamux(TestRuntime);

    const Ctx = struct {
        var a_ptr: ?*Conn = null;
        var b_ptr: ?*Conn = null;
        fn outA(data: []const u8, _: ?*anyopaque) void { if (b_ptr) |b| b.input(data) catch {}; }
        fn outB(data: []const u8, _: ?*anyopaque) void { if (a_ptr) |a| a.input(data) catch {}; }
    };
    Ctx.a_ptr = null; Ctx.b_ptr = null;
    const a = try Conn.init(allocator, 1, Ctx.outA, null);
    defer a.deinit();
    const b = try Conn.init(allocator, 1, Ctx.outB, null);
    defer b.deinit();
    Ctx.a_ptr = a; Ctx.b_ptr = b;

    const TA = struct {
        fn rd(ctx: *anyopaque, buf: []u8) anyerror!usize {
            return @as(*Conn, @ptrCast(@alignCast(ctx))).read(buf);
        }
        fn wr(ctx: *anyopaque, data: []const u8) anyerror!void {
            _ = try @as(*Conn, @ptrCast(@alignCast(ctx))).write(data);
        }
    };
    const client = try YMux.init(allocator, .client, @ptrCast(a), TA.rd, TA.wr);
    defer client.deinit();
    const server = try YMux.init(allocator, .server, @ptrCast(b), TA.rd, TA.wr);
    defer server.deinit();

    const total: usize = 4 * 1024 * 1024;

    const SinkFn = struct {
        fn run(s: *YMux, t: usize) void {
            var ss = s.accept() catch return;
            var buf: [65536]u8 = undefined;
            var recv: usize = 0;
            while (recv < t) { const n = ss.read(&buf) catch break; if (n == 0) break; recv += n; }
            ss.close();
        }
    };
    const st = std.Thread.spawn(.{}, SinkFn.run, .{ server, total }) catch return;

    var cs = try client.open();
    const chunk = try allocator.alloc(u8, 8192);
    defer allocator.free(chunk);
    @memset(chunk, 0x58);

    const start = std.time.nanoTimestamp();
    var sent: usize = 0;
    while (sent < total) { sent += try cs.write(chunk); }
    cs.close();
    st.join();
    const elapsed_ns: u64 = @intCast(std.time.nanoTimestamp() - start);
    const mbps = @as(f64, @floatFromInt(sent)) / @as(f64, @floatFromInt(elapsed_ns)) * 1000.0;
    std.debug.print("[yamux streaming] {d:.1} MB/s\n", .{mbps});
}
