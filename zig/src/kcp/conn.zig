//! KcpConn — KCP connection with single-threaded selector-based polling.
//!
//! Architecture:
//! - Single-threaded: No internal thread, user calls poll() to drive KCP
//! - Channel-based: Uses embed-zig Channel with select support
//! - Selector: External KcpSelector manages multiple connections via kqueue/epoll
//!
//! API Compatibility:
//! - init(), deinit(), write(), read(), input(), close(), isClosed() - unchanged
//! - NEW: poll() - must be called to process pending I/O
//!
//! Generic over `comptime Rt: type` for ESP32 compatibility.

const std = @import("std");
const kcp_mod = @import("kcp.zig");

const idle_timeout_ms: u64 = 15_000;
const idle_timeout_pure_ms: u64 = 30_000;

// Use embed-zig's Channel from platform/std
const platform = @import("std_impl");
const Channel = platform.channel.Channel;

// ============================================================================
// KcpConn
// ============================================================================

pub fn KcpConn(comptime Rt: type) type {
    return struct {
        const Self = @This();
        const InputChan = Channel([]u8, 256);
        const WriteChan = Channel([]const u8, 64);

        allocator: std.mem.Allocator,
        kcp: *kcp_mod.Kcp,

        // Channels for async I/O (single-threaded, no contention)
        input_ch: InputChan,
        write_ch: WriteChan,

        // Receive buffer and synchronization
        recv_buf: std.ArrayListUnmanaged(u8),
        recv_mutex: Rt.Mutex,
        recv_cond: Rt.Condition,

        // State
        closed: bool,
        last_recv_ms: u64,

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

            kcp.setNodelay(2, 1, 2, 1);
            kcp.setWndSize(4096, 4096);
            kcp.setMtu(1400);
            kcp.update(@intCast(Rt.nowMs() & 0xFFFFFFFF));

            self.* = Self{
                .allocator = allocator,
                .kcp = kcp,
                .input_ch = try InputChan.init(),
                .write_ch = try WriteChan.init(),
                .recv_buf = .{},
                .recv_mutex = Rt.Mutex.init(),
                .recv_cond = Rt.Condition.init(),
                .closed = false,
                .last_recv_ms = Rt.nowMs(),
                .output_fn = output_fn,
                .output_ctx = output_ctx,
            };

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.close();

            // Drain and free pending input packets
            while (self.input_ch.tryRecv()) |pkt| {
                self.allocator.free(pkt);
            }
            self.input_ch.deinit();

            // Drain and free pending write data
            while (self.write_ch.tryRecv()) |data| {
                self.allocator.free(data);
            }
            self.write_ch.deinit();

            self.recv_buf.deinit(self.allocator);
            self.recv_mutex.deinit();
            self.recv_cond.deinit();

            self.kcp.deinit();
            self.allocator.destroy(self.kcp);
            self.allocator.destroy(self);
        }

        /// Feed raw network packet to KCP. Thread-safe (single-threaded use only).
        pub fn input(self: *Self, data: []const u8) !void {
            if (self.closed) return error.Closed;
            const copy = try self.allocator.dupe(u8, data);
            self.input_ch.send(copy) catch {
                self.allocator.free(copy);
                return error.Closed;
            };
        }

        /// Blocking read. Waits until recv_buf has data or connection closes.
        pub fn read(self: *Self, buf: []u8) !usize {
            self.recv_mutex.lock();
            defer self.recv_mutex.unlock();

            while (self.recv_buf.items.len == 0) {
                if (self.closed) return 0;
                _ = self.recv_cond.timedWait(&self.recv_mutex, 100 * std.time.ns_per_ms);
            }

            if (self.recv_buf.items.len == 0) return 0;

            const n = @min(buf.len, self.recv_buf.items.len);
            @memcpy(buf[0..n], self.recv_buf.items[0..n]);
            std.mem.copyForwards(u8, self.recv_buf.items[0..], self.recv_buf.items[n..]);
            self.recv_buf.items.len -= n;
            return n;
        }

        /// Non-blocking read. Returns immediately with available data (may be 0).
        pub fn readNonBlock(self: *Self, buf: []u8) !usize {
            self.recv_mutex.lock();
            defer self.recv_mutex.unlock();

            if (self.recv_buf.items.len == 0) return 0;

            const n = @min(buf.len, self.recv_buf.items.len);
            @memcpy(buf[0..n], self.recv_buf.items[0..n]);
            std.mem.copyForwards(u8, self.recv_buf.items[0..], self.recv_buf.items[n..]);
            self.recv_buf.items.len -= n;
            return n;
        }

        /// Write data. Sends through channel for processing in poll().
        /// Note: data is copied to ensure lifetime safety.
        pub fn write(self: *Self, data: []const u8) !usize {
            if (self.closed) return error.Closed;

            // Copy data to ensure lifetime safety (Channel stores slice, not data)
            const copy = try self.allocator.dupe(u8, data);
            self.write_ch.send(copy) catch {
                self.allocator.free(copy);
                return error.Closed;
            };
            return data.len;
        }

        pub fn close(self: *Self) void {
            if (self.closed) return;
            self.closed = true;
            self.recv_cond.broadcast();
            self.input_ch.close();
        }

        pub fn isClosed(self: *const Self) bool {
            return self.closed;
        }

        /// Get the file descriptor for select/poll operations.
        /// Returns the input channel's notifier fd.
        pub fn selectFd(self: *const Self) std.posix.fd_t {
            return self.input_ch.selectFd();
        }

        /// Poll this connection - process pending I/O.
        /// Must be called regularly to drive KCP processing.
        /// Returns true if any work was done.
        pub fn poll(self: *Self) bool {
            if (self.closed) return false;

            if (self.kcp.state() < 0) {
                self.close();
                return false;
            }

            const now = Rt.nowMs();
            const idle = now -| self.last_recv_ms;
            if (idle > idle_timeout_ms and self.kcp.waitSnd() > 0) {
                self.close();
                return false;
            }
            if (idle > idle_timeout_pure_ms) {
                self.close();
                return false;
            }

            var did_work = false;
            var wrote_data = false;

            // Drain input channel
            while (self.input_ch.tryRecv()) |pkt| {
                _ = self.kcp.input(pkt);
                self.allocator.free(pkt);
                self.last_recv_ms = Rt.nowMs();
                did_work = true;
            }

            // Drain write channel and send to KCP in chunks
            while (self.write_ch.tryRecv()) |data| {
                // Send in 8KB chunks
                var offset: usize = 0;
                while (offset < data.len) {
                    const chunk = data[offset..@min(offset + 8192, data.len)];
                    _ = self.kcp.send(chunk);
                    offset += chunk.len;
                }
                self.allocator.free(data);
                did_work = true;
                wrote_data = true;
            }

            // Update KCP timer
            const now_ms: u32 = @intCast(Rt.nowMs() & 0xFFFFFFFF);
            self.kcp.update(now_ms);
            if (wrote_data) {
                // Explicitly flush after local writes; ACK-only traffic is flushed
                // by KCP update scheduling to avoid excessive tiny packets.
                self.kcp.flush();
            }
            self.drainRecv();

            return did_work or !self.input_ch.isEmpty() or !self.write_ch.isEmpty();
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
// KcpSelector — Manages multiple KcpConn connections with select
// ============================================================================

const Selector = platform.selector.Selector;

pub fn KcpSelector(comptime Rt: type, comptime max_conns: usize) type {
    return struct {
        const Self = @This();
        const ConnType = KcpConn(Rt);

        selector: Selector(max_conns),
        conns: [max_conns]?*ConnType,
        num_conns: usize,

        pub fn init() !Self {
            return .{
                .selector = try Selector(max_conns).init(),
                .conns = [_]?*ConnType{null} ** max_conns,
                .num_conns = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            self.selector.deinit();
        }

        /// Register a connection with the selector.
        /// Returns error.TooMany if max_conns is reached.
        pub fn register(self: *Self, conn: *ConnType) error{TooMany}!void {
            if (self.num_conns >= max_conns) return error.TooMany;
            _ = try self.selector.addRecv(&conn.input_ch);
            self.conns[self.num_conns] = conn;
            self.num_conns += 1;
        }

        /// Wait for any connection to have pending input, or timeout.
        /// Returns the index of the ready connection, or max_conns on timeout.
        /// Returns error.Empty if no connections registered.
        pub fn wait(self: *Self, timeout_ms: ?u32) error{Empty}!usize {
            return self.selector.wait(timeout_ms);
        }

        /// Poll all registered connections.
        /// Returns true if any work was done.
        pub fn pollAll(self: *Self) bool {
            var did_work = false;
            for (0..self.num_conns) |i| {
                if (self.conns[i]) |conn| {
                    if (conn.poll()) {
                        did_work = true;
                    }
                }
            }
            return did_work;
        }

        /// Poll a specific connection by index.
        pub fn pollAt(self: *Self, idx: usize) bool {
            if (idx >= self.num_conns) return false;
            if (self.conns[idx]) |conn| {
                return conn.poll();
            }
            return false;
        }

        /// Get connection at index.
        pub fn getConn(self: *Self, idx: usize) ?*ConnType {
            if (idx >= self.num_conns) return null;
            return self.conns[idx];
        }

        /// Reset the selector (clear all registrations).
        pub fn reset(self: *Self) void {
            self.selector.reset();
            self.num_conns = 0;
        }

        /// Number of registered connections.
        pub fn count(self: *const Self) usize {
            return self.num_conns;
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const TestRuntime = if (@import("builtin").os.tag != .freestanding) struct {
    pub const Mutex = struct {
        inner: std.Thread.Mutex = .{},
        pub fn init() Mutex {
            return .{};
        }
        pub fn deinit(_: *Mutex) void {}
        pub fn lock(self: *Mutex) void {
            self.inner.lock();
        }
        pub fn unlock(self: *Mutex) void {
            self.inner.unlock();
        }
    };
    pub const Condition = struct {
        inner: std.Thread.Condition = .{},
        pub fn init() Condition {
            return .{};
        }
        pub fn deinit(_: *Condition) void {}
        pub fn wait(self: *Condition, mutex: *Mutex) void {
            self.inner.wait(&mutex.inner);
        }
        pub fn timedWait(self: *Condition, mutex: *Mutex, timeout_ns: u64) bool {
            self.inner.timedWait(&mutex.inner, timeout_ns) catch return true;
            return false;
        }
        pub fn signal(self: *Condition) void {
            self.inner.signal();
        }
        pub fn broadcast(self: *Condition) void {
            self.inner.broadcast();
        }
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

    const Ctx = struct {
        var a_ptr: ?*Conn = null;
        var b_ptr: ?*Conn = null;
        fn outA(data: []const u8, _: ?*anyopaque) void {
            if (b_ptr) |b| b.input(data) catch {};
        }
        fn outB(data: []const u8, _: ?*anyopaque) void {
            if (a_ptr) |a| a.input(data) catch {};
        }
    };
    Ctx.a_ptr = null;
    Ctx.b_ptr = null;

    const allocator = std.testing.allocator;
    const a = try Conn.init(allocator, 1, Ctx.outA, null);
    const b = try Conn.init(allocator, 1, Ctx.outB, null);
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

    // Poll multiple times to allow data to flow through KCP
    for (0..100) |_| {
        _ = pair.a.poll();
        _ = pair.b.poll();
    }

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

    // Poll both connections multiple times
    for (0..100) |_| {
        _ = pair.a.poll();
        _ = pair.b.poll();
    }

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
        // Poll after each write to prevent buffer overflow
        _ = pair.a.poll();
    }

    // Poll until all data is sent
    for (0..100) |_| {
        _ = pair.a.poll();
        _ = pair.b.poll();
    }

    const received = try allocator.alloc(u8, size);
    defer allocator.free(received);
    var total: usize = 0;
    while (total < size) {
        const n = try pair.b.read(received[total..]);
        if (n == 0) {
            _ = pair.a.poll();
            _ = pair.b.poll();
            continue;
        }
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
    _ = pair.a.poll();
    _ = pair.b.poll();

    var buf: [256]u8 = undefined;
    const n = try pair.b.read(&buf);
    try std.testing.expectEqualStrings("before close", buf[0..n]);

    pair.a.close();
    pair.a.deinit();

    pair.b.close();
    const n2 = try pair.b.read(&buf);
    try std.testing.expectEqual(@as(usize, 0), n2);
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

    // Poll until all data is transferred
    for (0..1000) |_| {
        _ = a.poll();
        _ = b.poll();
    }

    const received = try allocator.alloc(u8, size);
    defer allocator.free(received);
    var total: usize = 0;
    while (total < size) {
        const n = try b.read(received[total..]);
        if (n == 0) {
            _ = a.poll();
            _ = b.poll();
            continue;
        }
        total += n;
    }

    try std.testing.expectEqual(size, total);
    try std.testing.expectEqualSlices(u8, data, received);
}

test "kcpselector basic" {
    if (@import("builtin").os.tag == .freestanding) return;
    const allocator = std.testing.allocator;
    const Conn = KcpConn(TestRuntime);
    const Sel = KcpSelector(TestRuntime, 4);

    var sel = try Sel.init();
    defer sel.deinit();

    const Ctx = struct {
        var a_ptr: ?*Conn = null;
        var b_ptr: ?*Conn = null;
        fn outA(data: []const u8, _: ?*anyopaque) void {
            if (b_ptr) |b| b.input(data) catch {};
        }
        fn outB(data: []const u8, _: ?*anyopaque) void {
            if (a_ptr) |a| a.input(data) catch {};
        }
    };
    Ctx.a_ptr = null;
    Ctx.b_ptr = null;

    const a = try Conn.init(allocator, 1, Ctx.outA, null);
    defer a.deinit();
    const b = try Conn.init(allocator, 1, Ctx.outB, null);
    defer b.deinit();
    Ctx.a_ptr = a;
    Ctx.b_ptr = b;

    try sel.register(a);
    try sel.register(b);
    try std.testing.expectEqual(@as(usize, 2), sel.count());

    // Send data from a to b
    _ = try a.write("hello");

    // Wait for data to arrive at b
    const ready = sel.wait(100) catch |err| switch (err) {
        error.Empty => @panic("should not be empty"),
    };

    // Poll the ready connection
    _ = sel.pollAt(ready);
    _ = b.poll();

    var buf: [256]u8 = undefined;
    const n = try b.read(&buf);
    try std.testing.expectEqualStrings("hello", buf[0..n]);
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

        // Single-threaded: write and poll in main thread
        const start = std.time.nanoTimestamp();
        var sent: usize = 0;
        var received: usize = 0;
        var buf: [65536]u8 = undefined;
        var poll_count: usize = 0;

        while (received < total) {
            // Write
            if (sent < total) {
                _ = pair.a.write(chunk) catch 0;
                sent += chunk_size;
            }

            // Poll both connections
            _ = pair.a.poll();
            _ = pair.b.poll();
            poll_count += 1;

            // Read
            const n = pair.b.read(&buf) catch 0;
            received += n;

            // Safety check
            if (poll_count > total / chunk_size + 1000) break;
        }

        const elapsed_ns: u64 = @intCast(std.time.nanoTimestamp() - start);
        const mbps = @as(f64, @floatFromInt(received)) / @as(f64, @floatFromInt(elapsed_ns)) * 1000.0;
        std.debug.print("[kcpconn select] chunk={d}B {d:.1} MB/s\n", .{ chunk_size, mbps });
    }
}

// ============================================================================
// Concurrent/Multi-stream Tests (align with Go/Rust)
// ============================================================================

test "kcpconn concurrent writers" {
    // Equivalent to Go's TestKCPConn_BUG1_ConcurrentWriteRace
    if (@import("builtin").os.tag == .freestanding) return;
    const allocator = std.testing.allocator;
    const pair = try connPair();
    defer pair.a.deinit();
    defer pair.b.deinit();

    const num_writers = 10;
    const writes_per_writer = 100;
    const msg_size = 128;
    const total_expected = num_writers * writes_per_writer * msg_size;

    const msg = try allocator.alloc(u8, msg_size);
    defer allocator.free(msg);
    @memset(msg, 'R');

    // Spawn writer threads
    const Writer = struct {
        fn run(conn: *KcpConn(TestRuntime), data: []const u8, count: usize) void {
            for (0..count) |_| {
                _ = conn.write(data) catch {};
            }
        }
    };

    var threads: [num_writers]std.Thread = undefined;
    for (0..num_writers) |i| {
        threads[i] = std.Thread.spawn(.{}, Writer.run, .{ pair.a, msg, writes_per_writer }) catch continue;
    }

    // Reader in main thread
    var received: usize = 0;
    var buf: [64 * 1024]u8 = undefined;
    while (received < total_expected) {
        _ = pair.a.poll();
        _ = pair.b.poll();
        const n = pair.b.read(&buf) catch 0;
        received += n;
    }

    for (0..num_writers) |i| {
        threads[i].join();
    }

    try std.testing.expectEqual(total_expected, received);
}

test "kcpconn packet loss 5pct" {
    // Equivalent to Go's TestKCPConn_PacketLoss_5pct
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

    // Poll until all data is transferred
    for (0..1000) |_| {
        _ = a.poll();
        _ = b.poll();
    }

    const received = try allocator.alloc(u8, size);
    defer allocator.free(received);
    var total: usize = 0;
    while (total < size) {
        const n = try b.read(received[total..]);
        if (n == 0) {
            _ = a.poll();
            _ = b.poll();
            continue;
        }
        total += n;
    }

    try std.testing.expectEqual(size, total);
    try std.testing.expectEqualSlices(u8, data, received);
}
