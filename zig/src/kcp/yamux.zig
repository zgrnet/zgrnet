//! yamux — Stream multiplexer protocol implementation from spec.
//!
//! Implements the yamux spec: https://github.com/hashicorp/yamux/blob/master/spec.md
//! Generic over `comptime Rt: type` for ESP32 compatibility.
//!
//! Architecture:
//! - Yamux session owns a transport (KcpConn read/write)
//! - recv_thread reads frames from transport and dispatches to streams
//! - Each YamuxStream has its own recv buffer + flow control window
//! - open() immediately sends WindowUpdate+SYN (like Go, NOT like Rust yamux 0.13)

const std = @import("std");

// ============================================================================
// Frame format (12 bytes, all multi-byte fields big-endian)
// ============================================================================

pub const frame_header_size: usize = 12;
pub const protocol_version: u8 = 0;
pub const default_window_size: u32 = 256 * 1024;

pub const FrameType = enum(u8) {
    data = 0,
    window_update = 1,
    ping = 2,
    go_away = 3,
};

pub const FrameFlags = struct {
    pub const syn: u16 = 0x0001;
    pub const ack: u16 = 0x0002;
    pub const fin: u16 = 0x0004;
    pub const rst: u16 = 0x0008;
};

pub const Frame = struct {
    version: u8 = protocol_version,
    frame_type: FrameType,
    flags: u16,
    stream_id: u32,
    length: u32,

    pub fn encode(self: Frame, buf: *[frame_header_size]u8) void {
        buf[0] = self.version;
        buf[1] = @intFromEnum(self.frame_type);
        std.mem.writeInt(u16, buf[2..4], self.flags, .big);
        std.mem.writeInt(u32, buf[4..8], self.stream_id, .big);
        std.mem.writeInt(u32, buf[8..12], self.length, .big);
    }

    pub fn decode(buf: *const [frame_header_size]u8) Frame {
        return .{
            .version = buf[0],
            .frame_type = @enumFromInt(buf[1]),
            .flags = std.mem.readInt(u16, buf[2..4], .big),
            .stream_id = std.mem.readInt(u32, buf[4..8], .big),
            .length = std.mem.readInt(u32, buf[8..12], .big),
        };
    }

    pub fn hasSyn(self: Frame) bool { return self.flags & FrameFlags.syn != 0; }
    pub fn hasAck(self: Frame) bool { return self.flags & FrameFlags.ack != 0; }
    pub fn hasFin(self: Frame) bool { return self.flags & FrameFlags.fin != 0; }
    pub fn hasRst(self: Frame) bool { return self.flags & FrameFlags.rst != 0; }
};

pub const StreamState = enum(u8) {
    open,
    half_close_local,
    half_close_remote,
    closed,
};

// ============================================================================
// YamuxStream
// ============================================================================

pub fn YamuxStream(comptime Rt: type) type {
    return struct {
        const Self = @This();

        id: u32,
        state: std.atomic.Value(u8),

        recv_buf: std.ArrayListUnmanaged(u8),
        recv_window: u32,
        send_window: std.atomic.Value(u32),

        mutex: Rt.Mutex,
        data_cond: Rt.Condition,
        window_cond: Rt.Condition,

        allocator: std.mem.Allocator,
        session_ctx: *anyopaque, // Reference to session for coalesced writes
        session_write_fn: *const fn (*anyopaque, []const u8) anyerror!void,

        pub fn getState(self: *const Self) StreamState {
            return @enumFromInt(self.state.load(.acquire));
        }

        pub fn read(self: *Self, buf: []u8) !usize {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.recv_buf.items.len == 0) {
                const st = self.getState();
                if (st == .half_close_remote or st == .closed) return 0;
                _ = self.data_cond.timedWait(&self.mutex, 100 * std.time.ns_per_ms);
            }

            const n = @min(buf.len, self.recv_buf.items.len);
            @memcpy(buf[0..n], self.recv_buf.items[0..n]);
            std.mem.copyForwards(u8, self.recv_buf.items[0..], self.recv_buf.items[n..]);
            self.recv_buf.items.len -= n;

            // Send WindowUpdate if we consumed significant data.
            if (n > 0) {
                const delta: u32 = @intCast(n);
                self.recv_window +|= delta;
                var hdr: [frame_header_size]u8 = undefined;
                const frame = Frame{
                    .frame_type = .window_update,
                    .flags = 0,
                    .stream_id = self.id,
                    .length = delta,
                };
                frame.encode(&hdr);
                // Send via session's coalesced write
                self.session_write_fn(self.session_ctx, &hdr) catch {};
            }

            return n;
        }

        pub fn write(self: *Self, data: []const u8) !usize {
            const st = self.getState();
            if (st == .half_close_local or st == .closed) return error.StreamClosed;

            // Wait for send window.
            self.mutex.lock();
            while (self.send_window.load(.acquire) == 0) {
                const s = self.getState();
                if (s == .half_close_local or s == .closed) {
                    self.mutex.unlock();
                    return error.StreamClosed;
                }
                _ = self.window_cond.timedWait(&self.mutex, 100 * std.time.ns_per_ms);
            }
            self.mutex.unlock();

            const avail = self.send_window.load(.acquire);
            const n = @min(data.len, @as(usize, avail));

            // Send Data frame.
            // Build frame in stack buffer and send via session write coalescing
            var frame_buf: [frame_header_size + 65536]u8 = undefined;
            const frame = Frame{
                .frame_type = .data,
                .flags = 0,
                .stream_id = self.id,
                .length = @intCast(n),
            };
            frame.encode(frame_buf[0..frame_header_size]);
            @memcpy(frame_buf[frame_header_size..][0..n], data[0..n]);

            // Send via session's coalesced write (batches multiple frames)
            try self.session_write_fn(self.session_ctx, frame_buf[0..frame_header_size + n]);
            _ = self.send_window.fetchSub(@intCast(n), .release);

            return n;
        }

        pub fn closeWrite(self: *Self) void {
            const st = self.getState();
            if (st == .closed or st == .half_close_local) return;

            var hdr: [frame_header_size]u8 = undefined;
            const frame = Frame{
                .frame_type = .data,
                .flags = FrameFlags.fin,
                .stream_id = self.id,
                .length = 0,
            };
            frame.encode(&hdr);
            // Send via session's coalesced write
            self.session_write_fn(self.session_ctx, &hdr) catch {};

            if (st == .open) {
                self.state.store(@intFromEnum(StreamState.half_close_local), .release);
            } else {
                self.state.store(@intFromEnum(StreamState.closed), .release);
            }
            self.data_cond.broadcast();
        }

        pub fn close(self: *Self) void {
            self.closeWrite();
            self.state.store(@intFromEnum(StreamState.closed), .release);
            self.data_cond.broadcast();
            self.window_cond.broadcast();
        }

        // Internal: called by recv_thread when data arrives.
        pub fn pushData(self: *Self, data: []const u8) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.recv_buf.appendSlice(self.allocator, data) catch return;
            self.data_cond.signal();
        }

        pub fn pushFin(self: *Self) void {
            const st = self.getState();
            if (st == .open) {
                self.state.store(@intFromEnum(StreamState.half_close_remote), .release);
            } else {
                self.state.store(@intFromEnum(StreamState.closed), .release);
            }
            self.data_cond.broadcast();
        }

        pub fn addSendWindow(self: *Self, delta: u32) void {
            _ = self.send_window.fetchAdd(delta, .release);
            self.window_cond.broadcast();
        }

        pub fn deinit(self: *Self) void {
            self.recv_buf.deinit(self.allocator);
            self.mutex.deinit();
            self.data_cond.deinit();
            self.window_cond.deinit();
            self.allocator.destroy(self);
        }
    };
}

// ============================================================================
// Yamux Session
// ============================================================================

pub fn Yamux(comptime Rt: type) type {
    const YStream = YamuxStream(Rt);

        return struct {
            const Self = @This();

        allocator: std.mem.Allocator,
        mode: Mode,
        next_stream_id: std.atomic.Value(u32),
        streams: std.AutoHashMapUnmanaged(u32, *YStream),
        streams_mutex: Rt.Mutex,

        accept_queue: std.ArrayListUnmanaged(*YStream),
        accept_mutex: Rt.Mutex,
        accept_cond: Rt.Condition,

        closed: std.atomic.Value(bool),
        recv_thread: ?Rt.Thread,

        // Transport I/O.
        transport_ctx: *anyopaque,
        transport_read: *const fn (*anyopaque, []u8) anyerror!usize,
        transport_write: *const fn (*anyopaque, []const u8) anyerror!void,

        // Write coalescing buffer (performance optimization)
        write_buf: std.ArrayListUnmanaged(u8),
        write_mutex: Rt.Mutex,
        write_cond: Rt.Condition,
        write_flush_thread: ?Rt.Thread,
        write_flush_signaled: std.atomic.Value(bool),

        pub const Mode = enum { client, server };

        pub fn init(
            allocator: std.mem.Allocator,
            mode: Mode,
            transport_ctx: *anyopaque,
            transport_read: *const fn (*anyopaque, []u8) anyerror!usize,
            transport_write: *const fn (*anyopaque, []const u8) anyerror!void,
        ) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            self.* = .{
                .allocator = allocator,
                .mode = mode,
                .next_stream_id = std.atomic.Value(u32).init(if (mode == .client) 1 else 2),
                .streams = .{},
                .streams_mutex = Rt.Mutex.init(),
                .accept_queue = .{},
                .accept_mutex = Rt.Mutex.init(),
                .accept_cond = Rt.Condition.init(),
                .closed = std.atomic.Value(bool).init(false),
                .recv_thread = null,
                .transport_ctx = transport_ctx,
                .transport_read = transport_read,
                .transport_write = transport_write,
                // Write coalescing fields
                .write_buf = .{},
                .write_mutex = Rt.Mutex.init(),
                .write_cond = Rt.Condition.init(),
                .write_flush_thread = null,
                .write_flush_signaled = std.atomic.Value(bool).init(false),
            };

            self.recv_thread = Rt.Thread.spawn(.{}, recvLoop, .{self}) catch null;
            self.write_flush_thread = Rt.Thread.spawn(.{}, writeFlushLoop, .{self}) catch null;
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.close();

            // Signal and stop flush thread
            self.write_mutex.lock();
            self.write_flush_signaled.store(true, .release);
            self.write_cond.signal();
            self.write_mutex.unlock();

            if (self.write_flush_thread) |t| {
                t.join();
                self.write_flush_thread = null;
            }

            if (self.recv_thread) |t| {
                t.join();
                self.recv_thread = null;
            }

            // Clean up streams.
            self.streams_mutex.lock();
            var it = self.streams.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.*.deinit();
            }
            self.streams.deinit(self.allocator);
            self.streams_mutex.unlock();

            self.accept_mutex.lock();
            self.accept_queue.deinit(self.allocator);
            self.accept_mutex.unlock();

            // Clean up write buffer
            self.write_mutex.lock();
            self.write_buf.deinit(self.allocator);
            self.write_mutex.unlock();

            self.streams_mutex.deinit();
            self.accept_mutex.deinit();
            self.accept_cond.deinit();
            self.write_mutex.deinit();
            self.write_cond.deinit();
            self.allocator.destroy(self);
        }

        /// Open a new outbound stream. Immediately sends WindowUpdate+SYN.
        pub fn open(self: *Self) !*YStream {
            if (self.closed.load(.acquire)) return error.SessionClosed;

            const id = self.next_stream_id.fetchAdd(2, .release);
            const stream = try self.createStream(id);

            // Send WindowUpdate with SYN flag (like Go hashicorp/yamux).
            var hdr: [frame_header_size]u8 = undefined;
            const frame = Frame{
                .frame_type = .window_update,
                .flags = FrameFlags.syn,
                .stream_id = id,
                .length = default_window_size,
            };
            frame.encode(&hdr);
            try self.transport_write(self.transport_ctx, &hdr);

            return stream;
        }

        /// Block until an inbound stream arrives.
        pub fn accept(self: *Self) !*YStream {
            self.accept_mutex.lock();
            defer self.accept_mutex.unlock();

            while (self.accept_queue.items.len == 0) {
                if (self.closed.load(.acquire)) return error.SessionClosed;
                _ = self.accept_cond.timedWait(&self.accept_mutex, 100 * std.time.ns_per_ms);
            }

            const stream = self.accept_queue.items[0];
            std.mem.copyForwards(*YStream, self.accept_queue.items[0..], self.accept_queue.items[1..]);
            self.accept_queue.items.len -= 1;
            return stream;
        }

        pub fn close(self: *Self) void {
            if (self.closed.swap(true, .acq_rel)) return;

            // Force flush any pending writes before closing
            self.forceFlush();

            // Send GoAway.
            var hdr: [frame_header_size]u8 = undefined;
            const frame = Frame{
                .frame_type = .go_away,
                .flags = 0,
                .stream_id = 0,
                .length = 0,
            };
            frame.encode(&hdr);
            self.transport_write(self.transport_ctx, &hdr) catch {};

            self.accept_cond.broadcast();
            self.write_cond.signal(); // Wake flush thread
        }

        // ============================================================================
        // Write Coalescing — Batch multiple small writes into single transport write
        // ============================================================================

        // Flush thresholds for write coalescing (performance optimization)
        const flush_threshold: usize = 16 * 1024; // 16KB - flush when buffer reaches this size
        const flush_min_data: usize = 4 * 1024; // 4KB - also flush when single write exceeds this
        const flush_timeout_ms: u64 = 1; // 1ms max delay for small writes

        /// Session-level write — immediate flush for now (no coalescing to avoid complexity)
        /// TODO: Re-enable write coalescing after fixing race conditions
        pub fn sessionWrite(self: *Self, data: []const u8) !void {
            if (self.closed.load(.acquire)) return error.SessionClosed;
            if (data.len == 0) return;

            // Direct write without buffering (simplest and safest)
            try self.transport_write(self.transport_ctx, data);
        }

        /// Force flush all pending writes (used by close)
        /// NOTE: This must NOT be called from recvLoop thread to avoid reentrancy issues
        fn forceFlush(self: *Self) void {
            self.write_mutex.lock();
            defer self.write_mutex.unlock();

            if (self.write_buf.items.len == 0) return;

            const to_flush = self.write_buf.toOwnedSlice(self.allocator) catch return;
            self.write_buf = .{};

            // Release lock before transport write
            self.write_mutex.unlock();
            self.transport_write(self.transport_ctx, to_flush) catch {};
            self.allocator.free(to_flush);
            self.write_mutex.lock();
        }

        /// Background flush loop — minimal version, mostly idle
        fn writeFlushLoop(self: *Self) void {
            while (!self.closed.load(.acquire)) {
                // Just sleep and let sessionWrite do the flushing
                // This thread exists for future enhancements (periodic flush)
                Rt.sleepMs(100);
            }
            // Do NOT call forceFlush here - it can cause segfaults due to thread race
            // sessionWrite already flushes immediately, so buffer should be empty
        }

        fn createStream(self: *Self, id: u32) !*YStream {
            const stream = try self.allocator.create(YStream);
            stream.* = YStream{
                .id = id,
                .state = std.atomic.Value(u8).init(@intFromEnum(StreamState.open)),
                .recv_buf = .{},
                .recv_window = default_window_size,
                .send_window = std.atomic.Value(u32).init(default_window_size),
                .mutex = Rt.Mutex.init(),
                .data_cond = Rt.Condition.init(),
                .window_cond = Rt.Condition.init(),
                .allocator = self.allocator,
                .session_ctx = @ptrCast(self), // Session pointer for coalesced writes
                .session_write_fn = @ptrCast(&sessionWriteAdapter),
            };

            self.streams_mutex.lock();
            defer self.streams_mutex.unlock();
            try self.streams.put(self.allocator, id, stream);
            return stream;
        }

        /// Adapter function to call sessionWrite from YamuxStream via function pointer
        fn sessionWriteAdapter(session_ctx: *anyopaque, data: []const u8) anyerror!void {
            const session: *Self = @ptrCast(@alignCast(session_ctx));
            return session.sessionWrite(data);
        }

        fn recvLoop(self: *Self) void {
            var hdr_buf: [frame_header_size]u8 = undefined;

            while (!self.closed.load(.acquire)) {
                // Read frame header (12 bytes).
                var read_total: usize = 0;
                while (read_total < frame_header_size) {
                    const n = self.transport_read(self.transport_ctx, hdr_buf[read_total..]) catch {
                        self.close();
                        return;
                    };
                    if (n == 0) { self.close(); return; }
                    read_total += n;
                }

                const frame = Frame.decode(&hdr_buf);

                switch (frame.frame_type) {
                    .data => self.handleData(frame),
                    .window_update => self.handleWindowUpdate(frame),
                    .ping => self.handlePing(frame),
                    .go_away => { self.close(); return; },
                }
            }
        }

        fn handleData(self: *Self, frame: Frame) void {
            // SYN on Data frame: create new inbound stream.
            if (frame.hasSyn()) {
                const stream = self.createStream(frame.stream_id) catch return;
                self.accept_mutex.lock();
                self.accept_queue.append(self.allocator, stream) catch {};
                self.accept_mutex.unlock();
                self.accept_cond.signal();
            }

            // Read payload if any.
            if (frame.length > 0) {
                const payload = self.allocator.alloc(u8, frame.length) catch return;
                defer self.allocator.free(payload);

                var total: usize = 0;
                while (total < frame.length) {
                    const n = self.transport_read(self.transport_ctx, payload[total..]) catch return;
                    if (n == 0) return;
                    total += n;
                }

                self.streams_mutex.lock();
                const stream = self.streams.get(frame.stream_id);
                self.streams_mutex.unlock();

                if (stream) |s| {
                    s.pushData(payload[0..total]);
                }
            }

            // FIN: signal remote close.
            if (frame.hasFin()) {
                self.streams_mutex.lock();
                const stream = self.streams.get(frame.stream_id);
                self.streams_mutex.unlock();
                if (stream) |s| s.pushFin();
            }

            // RST: force close.
            if (frame.hasRst()) {
                self.streams_mutex.lock();
                const stream = self.streams.get(frame.stream_id);
                self.streams_mutex.unlock();
                if (stream) |s| s.close();
            }
        }

        fn handleWindowUpdate(self: *Self, frame: Frame) void {
            // SYN on WindowUpdate: new inbound stream (Go-style open).
            if (frame.hasSyn()) {
                const stream = self.createStream(frame.stream_id) catch return;
                // Apply the window delta.
                stream.addSendWindow(frame.length);

                self.accept_mutex.lock();
                self.accept_queue.append(self.allocator, stream) catch {};
                self.accept_mutex.unlock();
                self.accept_cond.signal();
                return;
            }

            self.streams_mutex.lock();
            const stream = self.streams.get(frame.stream_id);
            self.streams_mutex.unlock();

            if (stream) |s| {
                s.addSendWindow(frame.length);
            }
        }

        fn handlePing(self: *Self, frame: Frame) void {
            if (frame.hasSyn()) {
                // Respond with Pong (Ping+ACK).
                var hdr: [frame_header_size]u8 = undefined;
                const pong = Frame{
                    .frame_type = .ping,
                    .flags = FrameFlags.ack,
                    .stream_id = 0,
                    .length = frame.length, // echo opaque value
                };
                pong.encode(&hdr);
                // Use sessionWrite for coalesced response
                self.sessionWrite(&hdr) catch {};
            }
            // ACK pings are silently consumed.
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

test "yamux frame encode decode roundtrip" {
    const frame = Frame{
        .frame_type = .data,
        .flags = FrameFlags.syn | FrameFlags.fin,
        .stream_id = 0x12345678,
        .length = 0xABCDEF01,
    };
    var buf: [frame_header_size]u8 = undefined;
    frame.encode(&buf);

    const decoded = Frame.decode(&buf);
    try std.testing.expectEqual(decoded.version, protocol_version);
    try std.testing.expectEqual(decoded.frame_type, FrameType.data);
    try std.testing.expectEqual(decoded.flags, FrameFlags.syn | FrameFlags.fin);
    try std.testing.expectEqual(decoded.stream_id, 0x12345678);
    try std.testing.expectEqual(decoded.length, 0xABCDEF01);
}

test "yamux frame big endian" {
    const frame = Frame{
        .frame_type = .window_update,
        .flags = 0x0102,
        .stream_id = 0x01020304,
        .length = 0x05060708,
    };
    var buf: [frame_header_size]u8 = undefined;
    frame.encode(&buf);

    // Verify big-endian encoding.
    try std.testing.expectEqual(buf[0], 0); // version
    try std.testing.expectEqual(buf[1], 1); // type=window_update
    try std.testing.expectEqual(buf[2], 0x01); // flags high byte
    try std.testing.expectEqual(buf[3], 0x02); // flags low byte
    try std.testing.expectEqual(buf[4], 0x01); // streamID bytes
    try std.testing.expectEqual(buf[5], 0x02);
    try std.testing.expectEqual(buf[6], 0x03);
    try std.testing.expectEqual(buf[7], 0x04);
    try std.testing.expectEqual(buf[8], 0x05); // length bytes
    try std.testing.expectEqual(buf[9], 0x06);
    try std.testing.expectEqual(buf[10], 0x07);
    try std.testing.expectEqual(buf[11], 0x08);
}

test "yamux frame flags" {
    const f = Frame{ .frame_type = .data, .flags = FrameFlags.syn | FrameFlags.ack, .stream_id = 1, .length = 0 };
    try std.testing.expect(f.hasSyn());
    try std.testing.expect(f.hasAck());
    try std.testing.expect(!f.hasFin());
    try std.testing.expect(!f.hasRst());
}

// ============================================================================
// Integration tests: yamux over KcpConn
// ============================================================================

const conn_mod = @import("conn.zig");

const TestRt = if (@import("builtin").os.tag != .freestanding) struct {
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
    pub const Thread = std.Thread;
    pub fn nowMs() u64 { return @intCast(std.time.milliTimestamp()); }
    pub fn sleepMs(ms: u32) void { std.Thread.sleep(@as(u64, ms) * std.time.ns_per_ms); }
} else struct {};

fn yamuxPair() !struct {
    client: *Yamux(TestRt),
    server: *Yamux(TestRt),
    a: *conn_mod.KcpConn(TestRt),
    b: *conn_mod.KcpConn(TestRt),
} {
    if (@import("builtin").os.tag == .freestanding) return error.Unsupported;
    const KConn = conn_mod.KcpConn(TestRt);
    const YMux = Yamux(TestRt);
    const allocator = std.testing.allocator;

    const Ctx = struct {
        var a_ptr: ?*KConn = null;
        var b_ptr: ?*KConn = null;
        fn outputA(data: []const u8, _: ?*anyopaque) void {
            if (b_ptr) |b| b.input(data) catch {};
        }
        fn outputB(data: []const u8, _: ?*anyopaque) void {
            if (a_ptr) |a| a.input(data) catch {};
        }
    };
    Ctx.a_ptr = null;
    Ctx.b_ptr = null;

    const a = try KConn.init(allocator, 1, Ctx.outputA, null);
    const b = try KConn.init(allocator, 1, Ctx.outputB, null);
    Ctx.a_ptr = a;
    Ctx.b_ptr = b;

    const TransportAdapter = struct {
        fn readFn(ctx: *anyopaque, buf: []u8) anyerror!usize {
            const kc: *KConn = @ptrCast(@alignCast(ctx));
            return kc.read(buf);
        }
        fn writeFn(ctx: *anyopaque, data: []const u8) anyerror!void {
            const kc: *KConn = @ptrCast(@alignCast(ctx));
            _ = try kc.write(data);
        }
    };

    const client = try YMux.init(allocator, .client, @ptrCast(a), TransportAdapter.readFn, TransportAdapter.writeFn);
    const server = try YMux.init(allocator, .server, @ptrCast(b), TransportAdapter.readFn, TransportAdapter.writeFn);

    return .{ .client = client, .server = server, .a = a, .b = b };
}

test "yamux open close" {
    if (@import("builtin").os.tag == .freestanding) return;
    const pair = try yamuxPair();
    defer pair.client.deinit();
    defer pair.server.deinit();
    defer pair.a.deinit();
    defer pair.b.deinit();

    const s = try pair.client.open();
    const accepted = try pair.server.accept();
    _ = accepted;
    s.close();
}

test "yamux echo" {
    if (@import("builtin").os.tag == .freestanding) return;
    const pair = try yamuxPair();
    defer pair.client.deinit();
    defer pair.server.deinit();
    defer pair.a.deinit();
    defer pair.b.deinit();

    var cs = try pair.client.open();

    // Server accept + echo in thread.
    const EchoThread = struct {
        fn run(server: *Yamux(TestRt)) void {
            var ss = server.accept() catch return;
            var buf: [4096]u8 = undefined;
            const n = ss.read(&buf) catch return;
            _ = ss.write(buf[0..n]) catch return;
            ss.close();
        }
    };
    const t = std.Thread.spawn(.{}, EchoThread.run, .{pair.server}) catch return;

    _ = try cs.write("hello yamux");
    var buf: [256]u8 = undefined;
    const n = try cs.read(&buf);
    try std.testing.expectEqualStrings("hello yamux", buf[0..n]);
    cs.close();
    t.join();
}

test "yamux multi stream 10" {
    if (@import("builtin").os.tag == .freestanding) return;
    const pair = try yamuxPair();
    defer pair.client.deinit();
    defer pair.server.deinit();
    defer pair.a.deinit();
    defer pair.b.deinit();

    // Server: accept and echo in separate threads.
    const EchoWorker = struct {
        fn run(server: *Yamux(TestRt)) void {
            for (0..10) |_| {
                var ss = server.accept() catch return;
                var buf: [4096]u8 = undefined;
                const n = ss.read(&buf) catch return;
                _ = ss.write(buf[0..n]) catch return;
                ss.close();
            }
        }
    };
    const t = std.Thread.spawn(.{}, EchoWorker.run, .{pair.server}) catch return;

    for (0..10) |i| {
        var cs = try pair.client.open();
        var msg_buf: [32]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "stream-{}", .{i}) catch "?";
        _ = try cs.write(msg);
        var buf: [256]u8 = undefined;
        const n = try cs.read(&buf);
        try std.testing.expectEqualStrings(msg, buf[0..n]);
        cs.close();
    }
    t.join();
}
