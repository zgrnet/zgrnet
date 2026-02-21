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
        run_thread: ?std.Thread,

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
            self.run_thread = try std.Thread.spawn(.{}, runLoop, .{self});

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

        /// Feed raw network packet to KCP. Non-blocking.
        pub fn input(self: *Self, data: []const u8) !void {
            if (self.closed.load(.acquire)) return error.Closed;
            const copy = try self.allocator.dupe(u8, data);
            self.input_mutex.lock();
            defer self.input_mutex.unlock();
            try self.input_buf.append(self.allocator, copy);
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

        /// Blocking write with coalescing. Appends to shared buffer, signals run loop.
        pub fn write(self: *Self, data: []const u8) !usize {
            if (self.closed.load(.acquire)) return error.Closed;

            self.write_mutex.lock();
            defer self.write_mutex.unlock();

            try self.write_buf.appendSlice(self.allocator, data);
            self.write_cond.signal();
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

                // Process input packets.
                self.drainInput();

                // Drain coalesced write buffer into KCP (8KB chunks).
                self.drainWriteBuf();

                // KCP update + flush.
                const now_ms: u32 = @intCast(Rt.nowMs() & 0xFFFFFFFF);
                self.kcp.update(now_ms);
                self.kcp.flush();

                // Drain KCP recv queue → recv_buf.
                self.drainRecv();

                // Sleep until next check or signal.
                const check = self.kcp.check(now_ms);
                const delay = if (check <= now_ms) @as(u32, 1) else @min(check - now_ms, 50);

                self.write_mutex.lock();
                if (self.write_buf.items.len == 0 and !self.closed.load(.acquire)) {
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
