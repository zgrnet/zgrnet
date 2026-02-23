//! KcpConn — KCP connection driven by a dedicated Rt.Thread.
//!
//! Architecture:
//! - One Rt.Thread exclusively owns the KCP instance (the run loop)
//! - write() pushes to write_buf with backpressure (single-copy from user data)
//! - read() blocks on recv_cond until recv_buf has data
//! - input() sends raw packets via Channel (bounded ring buffer)
//! - Write coalescing: multiple writes accumulate in write_buf, flushed together
//! - Dead peer detection: kcp.state() < 0 + idle timeout (15s/30s)
//!
//! Run loop idle strategy (3 tiers):
//!   1. Data flowing → tight loop
//!   2. Pending retransmits (waitSnd > 0) → 1ms timedWait
//!   3. Truly idle → 1s timedWait (idle timeout check)
//!
//! Generic over `comptime Rt: type` for ESP32 compatibility.

const std = @import("std");
const kcp_mod = @import("kcp.zig");
const channel_pkg = @import("channel");

const idle_timeout_ms: u64 = 15_000;
const idle_timeout_pure_ms: u64 = 30_000;
const write_buf_capacity: usize = 16 * 1024 * 1024; // 16MB write buffer - large enough for all test data
const max_send_chunk: usize = 32 * 1024; // 32KB chunks

// ============================================================================
// KcpConn
// ============================================================================

pub fn KcpConn(comptime Rt: type) type {
    return struct {
        const Self = @This();
        const InputChan = channel_pkg.Channel([]u8, 256, Rt);

        allocator: std.mem.Allocator,
        kcp: *kcp_mod.Kcp,

        // Write buffer: single-copy from user data, drained by run loop
        write_buf: std.ArrayListUnmanaged(u8),
        write_mutex: Rt.Mutex,
        write_cond: Rt.Condition, // for backpressure when full

        input_ch: InputChan,

        // Wake mechanism for tier 2/3 idle blocking.
        wake_mutex: Rt.Mutex,
        wake_cond: Rt.Condition,
        wake_signaled: bool,

        recv_buf: std.ArrayListUnmanaged(u8),
        recv_mutex: Rt.Mutex,
        recv_cond: Rt.Condition,

        closed: std.atomic.Value(bool),
        last_recv_ms: std.atomic.Value(u64),
        run_thread: ?Rt.Thread,

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
                .input_ch = InputChan.init(),
                .wake_mutex = Rt.Mutex.init(),
                .wake_cond = Rt.Condition.init(),
                .wake_signaled = false,
                .recv_buf = .{},
                .recv_mutex = Rt.Mutex.init(),
                .recv_cond = Rt.Condition.init(),
                .closed = std.atomic.Value(bool).init(false),
                .last_recv_ms = std.atomic.Value(u64).init(Rt.nowMs()),
                .run_thread = null,
                .output_fn = output_fn,
                .output_ctx = output_ctx,
            };

            self.run_thread = Rt.Thread.spawn(.{}, runLoop, .{self}) catch null;

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.close();
            if (self.run_thread) |t| {
                t.join();
                self.run_thread = null;
            }

            while (self.input_ch.tryRecv()) |pkt| {
                self.allocator.free(pkt);
            }
            self.input_ch.deinit();

            self.recv_buf.deinit(self.allocator);
            self.write_buf.deinit(self.allocator);
            self.wake_mutex.deinit();
            self.wake_cond.deinit();
            self.write_mutex.deinit();
            self.write_cond.deinit();
            self.recv_mutex.deinit();
            self.recv_cond.deinit();

            self.kcp.deinit();
            self.allocator.destroy(self.kcp);
            self.allocator.destroy(self);
        }

        /// Feed raw network packet to KCP. Thread-safe.
        pub fn input(self: *Self, data: []const u8) !void {
            if (self.closed.load(.acquire)) return error.Closed;
            const copy = try self.allocator.dupe(u8, data);
            self.input_ch.send(copy) catch {
                self.allocator.free(copy);
                return error.Closed;
            };
            self.notifyWake();
        }

        /// Blocking read. Waits until recv_buf has data or connection closes.
        pub fn read(self: *Self, buf: []u8) !usize {
            self.recv_mutex.lock();
            defer self.recv_mutex.unlock();

            while (self.recv_buf.items.len == 0) {
                if (self.closed.load(.acquire)) return 0;
                _ = self.recv_cond.timedWait(&self.recv_mutex, 100 * std.time.ns_per_ms);
            }

            if (self.recv_buf.items.len == 0) return 0;

            const n = @min(buf.len, self.recv_buf.items.len);
            @memcpy(buf[0..n], self.recv_buf.items[0..n]);
            std.mem.copyForwards(u8, self.recv_buf.items[0..], self.recv_buf.items[n..]);
            self.recv_buf.items.len -= n;
            return n;
        }

        /// Write with coalescing. Single-copy from user data to write_buf.
        /// If write_buf is full, waits for drainWriteBuf to swap it out.
        pub fn write(self: *Self, data: []const u8) !usize {
            if (self.closed.load(.acquire)) return error.Closed;

            self.write_mutex.lock();

            var offset: usize = 0;
            while (offset < data.len) {
                if (self.closed.load(.acquire)) {
                    self.write_mutex.unlock();
                    return error.Closed;
                }

                const remaining = data.len - offset;
                const available = write_buf_capacity - self.write_buf.items.len;

                if (available > 0) {
                    // Space available: append data (single copy)
                    const to_write = @min(remaining, available);
                    try self.write_buf.appendSlice(self.allocator, data[offset..][0..to_write]);
                    offset += to_write;
                } else {
                    // Buffer full: wait for drainWriteBuf to make space
                    // drainWriteBuf will broadcast after swapping
                    if (comptime @hasDecl(Rt.Condition, "timedWait")) {
                        _ = self.write_cond.timedWait(&self.write_mutex, 5 * std.time.ns_per_ms);
                    } else {
                        self.write_mutex.unlock();
                        Rt.sleepMs(5);
                        self.write_mutex.lock();
                    }
                }
            }
            self.write_mutex.unlock();
            // Notify run loop to process the new data
            self.notifyWake();
            return data.len;
        }

        pub fn close(self: *Self) void {
            if (self.closed.swap(true, .acq_rel)) return;
            self.recv_cond.broadcast();
            self.input_ch.close();
            self.notifyWake();
        }

        pub fn isClosed(self: *const Self) bool {
            return self.closed.load(.acquire);
        }

        // ── Wake mechanism (only for tier 2/3) ──────────────────────────

        fn notifyWake(self: *Self) void {
            self.wake_mutex.lock();
            if (!self.wake_signaled) {
                self.wake_signaled = true;
                self.wake_cond.signal();
            }
            self.wake_mutex.unlock();
        }

        fn timedWaitWake(self: *Self, timeout_ms: u64) void {
            self.wake_mutex.lock();
            if (!self.wake_signaled and !self.closed.load(.acquire)) {
                if (comptime @hasDecl(Rt.Condition, "timedWait")) {
                    _ = self.wake_cond.timedWait(&self.wake_mutex, timeout_ms * std.time.ns_per_ms);
                } else {
                    self.wake_mutex.unlock();
                    std.Thread.sleep(timeout_ms * std.time.ns_per_ms);
                    self.wake_mutex.lock();
                }
            }
            self.wake_signaled = false;
            self.wake_mutex.unlock();
        }

        /// Drain write_buf and send to KCP. Called under run loop's exclusive access.
        /// **Critical optimization**: swap buffer out and unlock BEFORE kcp.send()
        /// to allow writer thread to continue appending data in parallel.
        fn drainWriteBuf(self: *Self, swap_buf: *std.ArrayListUnmanaged(u8)) bool {
            self.write_mutex.lock();

            if (self.write_buf.items.len == 0) {
                self.write_mutex.unlock();
                return false;
            }

            // Swap write_buf with the reusable swap_buf
            // This moves all data to swap_buf and leaves write_buf empty with capacity
            std.mem.swap(std.ArrayListUnmanaged(u8), &self.write_buf, swap_buf);

            // CRITICAL: Unlock BEFORE kcp.send() to allow writer to continue!
            // Signal any waiting writers that space is available
            self.write_cond.broadcast();
            self.write_mutex.unlock();

            // Send all data (now without holding any lock)
            // Send in 32KB chunks - balance between syscall overhead and KCP efficiency
            var offset: usize = 0;
            while (offset < swap_buf.items.len) {
                const end = @min(offset + max_send_chunk, swap_buf.items.len);
                _ = self.kcp.send(swap_buf.items[offset..end]);
                offset = end;
            }

            // Clear but retain capacity for reuse (no deinit!)
            swap_buf.clearRetainingCapacity();
            return true;
        }

        // ── Run loop ────────────────────────────────────────────────────

        fn runLoop(self: *Self) void {
            // Reusable buffer for swapping with write_buf
            // This avoids repeated allocation/deallocation
            var swap_buf: std.ArrayListUnmanaged(u8) = .{};
            defer swap_buf.deinit(self.allocator);

            while (!self.closed.load(.acquire)) {
                if (self.kcp.state() < 0) {
                    self.close();
                    return;
                }

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

                var did_work = false;

                // Drain input channel
                while (self.input_ch.tryRecv()) |pkt| {
                    _ = self.kcp.input(pkt);
                    self.allocator.free(pkt);
                    self.last_recv_ms.store(Rt.nowMs(), .release);
                    did_work = true;
                }

                // Drain write buffer — single batch send (no scratch buffer!)
                if (self.drainWriteBuf(&swap_buf)) {
                    did_work = true;
                }

                const now_ms: u32 = @intCast(Rt.nowMs() & 0xFFFFFFFF);
                self.kcp.update(now_ms);
                self.kcp.flush();
                self.drainRecv();

                // Tier 1: data flowing → loop immediately.
                if (did_work or !self.input_ch.isEmpty()) {
                    // Check if write_buf has data (requires lock, but only when already did_work)
                    self.write_mutex.lock();
                    const has_write = self.write_buf.items.len > 0;
                    self.write_mutex.unlock();
                    if (has_write) continue;
                }

                // Tier 2: pending retransmits → 1ms bounded wait.
                if (self.kcp.waitSnd() > 0) {
                    self.timedWaitWake(1);
                    continue;
                }

                // Tier 3: truly idle → 1s bounded wait.
                self.timedWaitWake(1000);
            }
        }

        fn drainRecv(self: *Self) void {
            var received = false;
            while (true) {
                const peek = self.kcp.peekSize();
                if (peek <= 0) break;

                self.recv_mutex.lock();
                self.recv_buf.ensureTotalCapacity(self.allocator, self.recv_buf.items.len + @as(usize, @intCast(peek))) catch {
                    self.recv_mutex.unlock();
                    break;
                };
                const spare = self.recv_buf.items.ptr[self.recv_buf.items.len..self.recv_buf.capacity];
                const n = self.kcp.recv(spare);
                if (n <= 0) {
                    self.recv_mutex.unlock();
                    break;
                }
                self.recv_buf.items.len += @intCast(n);
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
            self.inner.timedWait(&mutex.inner, timeout_ns) catch return true;
            return false;
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

    var written: usize = 0;
    while (written < size) {
        const end = @min(written + 1024, size);
        _ = try pair.a.write(data[written..end]);
        written = end;
    }

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

    var buf: [256]u8 = undefined;
    const n = try pair.b.read(&buf);
    try std.testing.expectEqualStrings("before close", buf[0..n]);

    pair.a.close();
    pair.a.deinit();

    pair.b.close();
    const n2 = try pair.b.read(&buf);
    try std.testing.expectEqual(@as(usize, 0), n2);
}

test "kcpconn close unblocks read" {
    if (@import("builtin").os.tag == .freestanding) return;
    const pair = try connPair();
    defer pair.b.deinit();

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
}

test "kcpconn loss 5pct" {
    if (@import("builtin").os.tag == .freestanding) return;
    const allocator = std.testing.allocator;
    const Conn = KcpConn(TestRuntime);

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

    var written: usize = 0;
    while (written < size) {
        const end = @min(written + 1024, size);
        _ = try a.write(data[written..end]);
        written = end;
    }

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
    Ctx.a_ptr = null;
    Ctx.b_ptr = null;
    const a = try Conn.init(allocator, 1, Ctx.outA, null);
    defer a.deinit();
    const b = try Conn.init(allocator, 1, Ctx.outB, null);
    defer b.deinit();
    Ctx.a_ptr = a;
    Ctx.b_ptr = b;

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

test "kcpconn read peer dead" {
    if (@import("builtin").os.tag == .freestanding) return;
    const pair = try connPair();
    defer pair.b.deinit();

    _ = try pair.a.write("setup");
    var buf: [256]u8 = undefined;
    _ = try pair.b.read(&buf);

    pair.a.close();
    pair.a.deinit();

    const start = std.time.nanoTimestamp();
    const n = try pair.b.read(&buf);
    const elapsed_ms = @divFloor(@as(u64, @intCast(std.time.nanoTimestamp() - start)), std.time.ns_per_ms);

    try std.testing.expectEqual(@as(usize, 0), n);
    try std.testing.expect(elapsed_ms < 35_000);
    std.debug.print("[read_peer_dead] returned in {d}ms\n", .{elapsed_ms});
}
