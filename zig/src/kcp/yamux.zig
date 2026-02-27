//! yamux — Single-threaded stream multiplexer protocol implementation.
//!
//! Implements the yamux spec: https://github.com/hashicorp/yamux/blob/master/spec.md
//! Generic over `comptime Rt: type` for ESP32 compatibility.
//!
//! Architecture (Single-threaded):
//! - Yamux session owns a transport (KcpConn read/write)
//! - User calls poll() to drive frame processing
//! - Each YamuxStream has its own recv buffer + flow control window
//! - open() immediately sends WindowUpdate+SYN (like Go, NOT like Rust yamux 0.13)

const std = @import("std");
const platform = @import("std_impl");

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

    pub fn hasSyn(self: Frame) bool {
        return self.flags & FrameFlags.syn != 0;
    }
    pub fn hasAck(self: Frame) bool {
        return self.flags & FrameFlags.ack != 0;
    }
    pub fn hasFin(self: Frame) bool {
        return self.flags & FrameFlags.fin != 0;
    }
    pub fn hasRst(self: Frame) bool {
        return self.flags & FrameFlags.rst != 0;
    }
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
        state: u8, // No longer atomic - single threaded

        recv_buf: std.ArrayListUnmanaged(u8),
        recv_window: u32,
        send_window: u32, // No longer atomic

        mutex: Rt.Mutex,
        data_cond: Rt.Condition,
        window_cond: Rt.Condition,

        allocator: std.mem.Allocator,
        session_ctx: *anyopaque,
        session_write_fn: *const fn (*anyopaque, []const u8) anyerror!void,

        pub fn getState(self: *const Self) StreamState {
            return @enumFromInt(self.state);
        }

        pub fn read(self: *Self, buf: []u8) !usize {
            self.mutex.lock();

            while (self.recv_buf.items.len == 0) {
                const st = self.getState();
                if (st == .half_close_remote or st == .closed) {
                    self.mutex.unlock();
                    return 0;
                }
                _ = self.data_cond.timedWait(&self.mutex, 100 * std.time.ns_per_ms);
            }

            const n = @min(buf.len, self.recv_buf.items.len);
            @memcpy(buf[0..n], self.recv_buf.items[0..n]);
            std.mem.copyForwards(u8, self.recv_buf.items[0..], self.recv_buf.items[n..]);
            self.recv_buf.items.len -= n;
            const remaining = self.recv_buf.items.len;
            self.mutex.unlock();

            // Go yamux-compatible window update strategy:
            // delta = (max_window - buffered) - advertised_recv_window
            // send only when delta >= max_window/2.
            if (n > 0) {
                const max_window: u32 = default_window_size;
                const remaining_u32: u32 = @intCast(@min(remaining, @as(usize, max_window)));
                const available: u32 = max_window - remaining_u32;

                if (available > self.recv_window) {
                    const delta = available - self.recv_window;
                    if (delta >= (max_window / 2)) {
                        self.recv_window +|= delta;

                        var hdr: [frame_header_size]u8 = undefined;
                        const frame = Frame{
                            .frame_type = .window_update,
                            .flags = 0,
                            .stream_id = self.id,
                            .length = delta,
                        };
                        frame.encode(&hdr);
                        self.session_write_fn(self.session_ctx, &hdr) catch |err| {
                            std.log.warn("[yamux] stream={d} window_update send failed: {s}", .{ self.id, @errorName(err) });
                        };
                    }
                }
            }

            return n;
        }

        pub fn write(self: *Self, data: []const u8) !usize {
            const st = self.getState();
            if (st == .half_close_local or st == .closed) return error.StreamClosed;

            // Wait for send window.
            self.mutex.lock();
            while (self.send_window == 0) {
                const s = self.getState();
                if (s == .half_close_local or s == .closed) {
                    self.mutex.unlock();
                    return error.StreamClosed;
                }
                _ = self.window_cond.timedWait(&self.mutex, 100 * std.time.ns_per_ms);
            }
            self.mutex.unlock();

            const avail = self.send_window;
            const n = @min(@min(data.len, @as(usize, avail)), @as(usize, 65536));

            // Send Data frame.
            var frame_buf: [frame_header_size + 65536]u8 = undefined;
            const frame = Frame{
                .frame_type = .data,
                .flags = 0,
                .stream_id = self.id,
                .length = @intCast(n),
            };
            frame.encode(frame_buf[0..frame_header_size]);
            @memcpy(frame_buf[frame_header_size..][0..n], data[0..n]);

            try self.session_write_fn(self.session_ctx, frame_buf[0 .. frame_header_size + n]);
            self.send_window -= @intCast(n);

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
            self.session_write_fn(self.session_ctx, &hdr) catch {};

            if (st == .open) {
                self.state = @intFromEnum(StreamState.half_close_local);
            } else {
                self.state = @intFromEnum(StreamState.closed);
            }
            self.data_cond.broadcast();
        }

        pub fn close(self: *Self) void {
            self.closeWrite();
            self.state = @intFromEnum(StreamState.closed);
            self.data_cond.broadcast();
            self.window_cond.broadcast();
        }

        // Internal: called by poll when data arrives.
        pub fn pushData(self: *Self, data: []const u8) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.recv_buf.appendSlice(self.allocator, data) catch return;

            const delta: u32 = @intCast(@min(data.len, @as(usize, std.math.maxInt(u32))));
            if (delta >= self.recv_window) {
                self.recv_window = 0;
            } else {
                self.recv_window -= delta;
            }

            self.data_cond.signal();
        }

        pub fn pushFin(self: *Self) void {
            const st = self.getState();
            if (st == .open) {
                self.state = @intFromEnum(StreamState.half_close_remote);
            } else {
                self.state = @intFromEnum(StreamState.closed);
            }
            self.data_cond.broadcast();
        }

        pub fn addSendWindow(self: *Self, delta: u32) void {
            self.send_window += delta;
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
// Yamux Session (Single-threaded)
// ============================================================================

pub fn Yamux(comptime Rt: type) type {
    const YStream = YamuxStream(Rt);

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        mode: Mode,
        next_stream_id: u32, // No longer atomic
        streams: std.AutoHashMapUnmanaged(u32, *YStream),
        streams_mutex: Rt.Mutex,

        accept_queue: std.ArrayListUnmanaged(*YStream),
        accept_mutex: Rt.Mutex,
        accept_cond: Rt.Condition,

        // Transport RX staging buffer to handle partial frame reads.
        rx_buf: std.ArrayListUnmanaged(u8),

        closed: bool, // No longer atomic

        // Transport I/O.
        transport_ctx: *anyopaque,
        transport_read: *const fn (*anyopaque, []u8) anyerror!usize,
        transport_write: *const fn (*anyopaque, []const u8) anyerror!void,
        transport_poll: *const fn (*anyopaque) void,
        transport_select_fd: ?*const fn (*anyopaque) std.posix.fd_t, // NEW: get fd for select

        pub const Mode = enum { client, server };

        pub fn init(
            allocator: std.mem.Allocator,
            mode: Mode,
            transport_ctx: *anyopaque,
            transport_read: *const fn (*anyopaque, []u8) anyerror!usize,
            transport_write: *const fn (*anyopaque, []const u8) anyerror!void,
            transport_poll: *const fn (*anyopaque) void,
            transport_select_fd: ?*const fn (*anyopaque) std.posix.fd_t, // NEW
        ) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            self.* = .{
                .allocator = allocator,
                .mode = mode,
                .next_stream_id = if (mode == .client) 1 else 2,
                .streams = .{},
                .streams_mutex = Rt.Mutex.init(),
                .accept_queue = .{},
                .accept_mutex = Rt.Mutex.init(),
                .accept_cond = Rt.Condition.init(),
                .rx_buf = .{},
                .closed = false,
                .transport_ctx = transport_ctx,
                .transport_read = transport_read,
                .transport_write = transport_write,
                .transport_poll = transport_poll,
                .transport_select_fd = transport_select_fd,
            };

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.close();

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

            self.rx_buf.deinit(self.allocator);

            self.streams_mutex.deinit();
            self.accept_mutex.deinit();
            self.accept_cond.deinit();
            self.allocator.destroy(self);
        }

        /// Open a new outbound stream. Immediately sends WindowUpdate+SYN.
        pub fn open(self: *Self) !*YStream {
            if (self.closed) return error.SessionClosed;

            const id = self.next_stream_id;
            self.next_stream_id += 2;
            const stream = try self.createStream(id);

            // Send WindowUpdate with SYN flag.
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
                if (self.closed) return error.SessionClosed;
                _ = self.accept_cond.timedWait(&self.accept_mutex, 100 * std.time.ns_per_ms);
            }

            const stream = self.accept_queue.items[0];
            std.mem.copyForwards(*YStream, self.accept_queue.items[0..], self.accept_queue.items[1..]);
            self.accept_queue.items.len -= 1;
            return stream;
        }

        pub fn close(self: *Self) void {
            if (self.closed) return;
            self.closed = true;

            // Send GoAway frame
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
        }

        /// Poll the session - drive frame processing.
        /// Must be called regularly to process incoming frames.
        /// Returns true if any work was done.
        pub fn poll(self: *Self) bool {
            if (self.closed) return false;

            var did_work = false;

            // Poll the transport first (drive KCP)
            self.transport_poll(self.transport_ctx);
            did_work = self.pullTransportData() or did_work;

            // Process all complete buffered frames.
            while (self.processOneBufferedFrame()) {
                did_work = true;
            }

            return did_work;
        }

        /// Process multiple frames in one poll call.
        /// Returns number of frames processed.
        pub fn pollMultiple(self: *Self, max_frames: usize) usize {
            var count: usize = 0;
            for (0..max_frames) |_| {
                if (!self.poll()) break;
                count += 1;
            }
            return count;
        }

        /// Get the file descriptor for select/poll operations.
        /// Returns -1 if transport doesn't support select.
        pub fn getSelectFd(self: *const Self) std.posix.fd_t {
            if (self.transport_select_fd) |get_fd| {
                return get_fd(self.transport_ctx);
            }
            return -1;
        }

        /// Optimized poll that processes more data per call.
        /// This version drives KCP and then processes frames in a tight loop.
        pub fn pollOptimized(self: *Self, max_frames: usize) usize {
            if (self.closed) return 0;

            // Poll transport (drive KCP)
            self.transport_poll(self.transport_ctx);
            _ = self.pullTransportData();

            // Process complete buffered frames in batch.
            var count: usize = 0;
            while (count < max_frames and self.processOneBufferedFrame()) {
                count += 1;
            }

            return count;
        }

        fn pullTransportData(self: *Self) bool {
            var did_read = false;
            var tmp: [4096]u8 = undefined;

            while (true) {
                const n = self.transport_read(self.transport_ctx, &tmp) catch break;
                if (n == 0) break;

                self.rx_buf.appendSlice(self.allocator, tmp[0..n]) catch break;
                did_read = true;

                // Non-full read usually means no more immediate data.
                if (n < tmp.len) break;
            }

            return did_read;
        }

        fn processOneBufferedFrame(self: *Self) bool {
            if (self.rx_buf.items.len < frame_header_size) return false;

            var hdr_buf: [frame_header_size]u8 = undefined;
            @memcpy(&hdr_buf, self.rx_buf.items[0..frame_header_size]);

            // Validate frame type byte before enum cast to avoid panic on
            // malformed/corrupted data from interop peers.
            if (hdr_buf[1] > @intFromEnum(FrameType.go_away)) {
                // Drop one byte and try to re-sync.
                std.mem.copyForwards(u8, self.rx_buf.items[0..], self.rx_buf.items[1..]);
                self.rx_buf.items.len -= 1;
                return true;
            }

            const frame = Frame.decode(&hdr_buf);
            const payload_len: usize = if (frame.frame_type == .data) @as(usize, frame.length) else 0;
            const total_len = frame_header_size + payload_len;
            if (self.rx_buf.items.len < total_len) return false;

            const payload = self.rx_buf.items[frame_header_size..total_len];
            self.handleFrame(frame, payload);

            std.mem.copyForwards(u8, self.rx_buf.items[0..], self.rx_buf.items[total_len..]);
            self.rx_buf.items.len -= total_len;
            return true;
        }

        fn handleFrame(self: *Self, frame: Frame, payload: []const u8) void {
            switch (frame.frame_type) {
                .data => self.handleData(frame, payload),
                .window_update => self.handleWindowUpdate(frame),
                .ping => self.handlePing(frame),
                .go_away => self.close(),
            }
        }

        fn sessionWrite(self: *Self, data: []const u8) !void {
            if (self.closed) return error.SessionClosed;
            if (data.len == 0) return;
            try self.transport_write(self.transport_ctx, data);
        }

        fn createStream(self: *Self, id: u32) !*YStream {
            const stream = try self.allocator.create(YStream);
            stream.* = YStream{
                .id = id,
                .state = @intFromEnum(StreamState.open),
                .recv_buf = .{},
                .recv_window = default_window_size,
                .send_window = default_window_size,
                .mutex = Rt.Mutex.init(),
                .data_cond = Rt.Condition.init(),
                .window_cond = Rt.Condition.init(),
                .allocator = self.allocator,
                .session_ctx = @ptrCast(self),
                .session_write_fn = @ptrCast(&sessionWriteAdapter),
            };

            self.streams_mutex.lock();
            defer self.streams_mutex.unlock();
            try self.streams.put(self.allocator, id, stream);
            return stream;
        }

        fn sessionWriteAdapter(session_ctx: *anyopaque, data: []const u8) anyerror!void {
            const session: *Self = @ptrCast(@alignCast(session_ctx));
            return session.sessionWrite(data);
        }

        fn handleData(self: *Self, frame: Frame, payload: []const u8) void {
            // SYN on Data frame: create new inbound stream.
            if (frame.hasSyn()) {
                const stream = self.createStream(frame.stream_id) catch return;
                self.accept_mutex.lock();
                self.accept_queue.append(self.allocator, stream) catch {};
                self.accept_mutex.unlock();
                self.accept_cond.signal();

                // Acknowledge inbound stream creation.
                self.sendWindowUpdateAck(frame.stream_id);
            }

            // Read payload if any.
            if (frame.length > 0 and payload.len >= frame.length) {
                self.streams_mutex.lock();
                const stream = self.streams.get(frame.stream_id);
                self.streams_mutex.unlock();

                if (stream) |s| {
                    s.pushData(payload[0..frame.length]);
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
                stream.addSendWindow(frame.length);

                self.accept_mutex.lock();
                self.accept_queue.append(self.allocator, stream) catch {};
                self.accept_mutex.unlock();
                self.accept_cond.signal();

                // Acknowledge inbound stream creation and advertise our window.
                self.sendWindowUpdateAck(frame.stream_id);
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
                    .length = frame.length,
                };
                pong.encode(&hdr);
                self.sessionWrite(&hdr) catch {};
            }
            // ACK pings are silently consumed.
        }

        fn sendWindowUpdateAck(self: *Self, stream_id: u32) void {
            var hdr: [frame_header_size]u8 = undefined;
            const ack = Frame{
                .frame_type = .window_update,
                .flags = FrameFlags.ack,
                .stream_id = stream_id,
                .length = 0,
            };
            ack.encode(&hdr);
            self.sessionWrite(&hdr) catch |err| {
                std.log.warn("[yamux] stream={d} open ack send failed: {s}", .{ stream_id, @errorName(err) });
            };
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

    try std.testing.expectEqual(buf[0], 0);
    try std.testing.expectEqual(buf[1], 1);
    try std.testing.expectEqual(buf[2], 0x01);
    try std.testing.expectEqual(buf[3], 0x02);
    try std.testing.expectEqual(buf[4], 0x01);
    try std.testing.expectEqual(buf[5], 0x02);
    try std.testing.expectEqual(buf[6], 0x03);
    try std.testing.expectEqual(buf[7], 0x04);
    try std.testing.expectEqual(buf[8], 0x05);
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
// Integration tests: yamux over KcpConn (single-threaded)
// ============================================================================

const conn_mod = @import("conn.zig");

const TestRt = if (@import("builtin").os.tag != .freestanding) struct {
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
            return kc.readNonBlock(buf); // Use non-blocking read
        }
        fn writeFn(ctx: *anyopaque, data: []const u8) anyerror!void {
            const kc: *KConn = @ptrCast(@alignCast(ctx));
            _ = try kc.write(data);
        }
        fn pollFn(ctx: *anyopaque) void {
            const kc: *KConn = @ptrCast(@alignCast(ctx));
            _ = kc.poll();
        }
        fn selectFdFn(ctx: *anyopaque) std.posix.fd_t {
            const kc: *KConn = @ptrCast(@alignCast(ctx));
            return kc.selectFd();
        }
    };

    const client = try YMux.init(allocator, .client, @ptrCast(a), TransportAdapter.readFn, TransportAdapter.writeFn, TransportAdapter.pollFn, TransportAdapter.selectFdFn);
    const server = try YMux.init(allocator, .server, @ptrCast(b), TransportAdapter.readFn, TransportAdapter.writeFn, TransportAdapter.pollFn, TransportAdapter.selectFdFn);

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

    // Poll both sides
    for (0..100) |_| {
        _ = pair.client.poll();
        _ = pair.server.poll();
    }

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

    // Poll to process open
    for (0..10) |_| {
        _ = pair.client.poll();
        _ = pair.server.poll();
    }

    var ss = try pair.server.accept();

    _ = try cs.write("hello yamux");

    // Poll to send data
    for (0..10) |_| {
        _ = pair.client.poll();
        _ = pair.server.poll();
    }

    // Server echo
    var buf: [4096]u8 = undefined;
    const n = try ss.read(&buf);
    _ = try ss.write(buf[0..n]);
    ss.close();

    // Poll to send response
    for (0..10) |_| {
        _ = pair.client.poll();
        _ = pair.server.poll();
    }

    var client_buf: [256]u8 = undefined;
    const rn = try cs.read(&client_buf);
    try std.testing.expectEqualStrings("hello yamux", client_buf[0..rn]);
    cs.close();
}

test "yamux streaming throughput" {
    if (@import("builtin").os.tag == .freestanding) return;
    const allocator = std.testing.allocator;
    const pair = try yamuxPair();
    defer pair.client.deinit();
    defer pair.server.deinit();
    defer pair.a.deinit();
    defer pair.b.deinit();

    const chunk_size: usize = 8192;
    const total: usize = 4 * 1024 * 1024;

    var cs = try pair.client.open();

    // Poll to process open
    for (0..10) |_| {
        _ = pair.client.poll();
        _ = pair.server.poll();
    }

    var ss = try pair.server.accept();

    const chunk = try allocator.alloc(u8, chunk_size);
    defer allocator.free(chunk);
    @memset(chunk, 0x58);

    // Sink in main thread
    const start = std.time.nanoTimestamp();
    var sent: usize = 0;
    var received: usize = 0;
    var sink_buf: [65536]u8 = undefined;

    while (received < total) {
        // Send
        if (sent < total) {
            const n = cs.write(chunk) catch 0;
            sent += n;
        }

        // Poll both
        _ = pair.client.poll();
        _ = pair.server.poll();

        // Receive
        const n = ss.read(&sink_buf) catch 0;
        received += n;
    }

    const elapsed_ns: u64 = @intCast(std.time.nanoTimestamp() - start);
    const mbps = @as(f64, @floatFromInt(received)) / @as(f64, @floatFromInt(elapsed_ns)) * 1000.0;
    std.debug.print("[yamux streaming] {d:.1} MB/s\n", .{mbps});

    cs.close();
    ss.close();
}

// ============================================================================
// Multi-stream Tests (align with Go/Rust)
// ============================================================================

test "yamux multi stream 10" {
    // Equivalent to Go's TestYamux_MultiStream_10
    if (@import("builtin").os.tag == .freestanding) return;
    const allocator = std.testing.allocator;
    const pair = try yamuxPair();
    defer pair.client.deinit();
    defer pair.server.deinit();
    defer pair.a.deinit();
    defer pair.b.deinit();

    const YStream = YamuxStream(TestRt);
    const num_streams = 10;

    // Client: open streams
    var client_streams: [num_streams]*YStream = undefined;
    for (0..num_streams) |i| {
        client_streams[i] = try pair.client.open();
        // Poll to send SYN
        for (0..5) |_| {
            _ = pair.client.poll();
            _ = pair.server.poll();
        }
    }

    // Server: accept streams
    var server_streams: [num_streams]*YStream = undefined;
    for (0..num_streams) |i| {
        server_streams[i] = try pair.server.accept();
    }

    // Exchange data on all streams
    for (0..num_streams) |i| {
        const msg = try std.fmt.allocPrint(allocator, "stream-{d:04}", .{i});
        defer allocator.free(msg);

        _ = try client_streams[i].write(msg);

        // Poll to send
        for (0..5) |_| {
            _ = pair.client.poll();
            _ = pair.server.poll();
        }

        var buf: [256]u8 = undefined;
        const n = try server_streams[i].read(&buf);

        // Echo back with prefix
        const response = try std.fmt.allocPrint(allocator, "echo{s}", .{buf[0..n]});
        defer allocator.free(response);
        _ = try server_streams[i].write(response);
        server_streams[i].close();

        // Poll to send response
        for (0..5) |_| {
            _ = pair.client.poll();
            _ = pair.server.poll();
        }

        var client_buf: [256]u8 = undefined;
        const rn = try client_streams[i].read(&client_buf);
        try std.testing.expectEqualStrings(response, client_buf[0..rn]);
        client_streams[i].close();
    }
}

test "yamux multi stream throughput" {
    // Equivalent to Go's BenchmarkYamux_Throughput_10
    if (@import("builtin").os.tag == .freestanding) return;
    const allocator = std.testing.allocator;
    const pair = try yamuxPair();
    defer pair.client.deinit();
    defer pair.server.deinit();
    defer pair.a.deinit();
    defer pair.b.deinit();

    const YStream = YamuxStream(TestRt);
    const num_streams = 10;
    const chunk_size: usize = 8192;
    const total_per_stream: usize = 1 * 1024 * 1024; // 1MB per stream

    // Open streams
    var client_streams: [num_streams]*YStream = undefined;
    var server_streams: [num_streams]*YStream = undefined;

    for (0..num_streams) |i| {
        client_streams[i] = try pair.client.open();
        for (0..5) |_| {
            _ = pair.client.poll();
            _ = pair.server.poll();
        }
        server_streams[i] = try pair.server.accept();
    }

    const chunk = try allocator.alloc(u8, chunk_size);
    defer allocator.free(chunk);
    @memset(chunk, 0x58);

    // Send on all streams concurrently (in main thread)
    const start = std.time.nanoTimestamp();
    var sent: [num_streams]usize = .{0} ** num_streams;
    var received: [num_streams]usize = .{0} ** num_streams;
    var buf: [65536]u8 = undefined;

    var all_done = false;
    while (!all_done) {
        all_done = true;

        for (0..num_streams) |i| {
            // Send
            if (sent[i] < total_per_stream) {
                const n = client_streams[i].write(chunk) catch 0;
                sent[i] += n;
                all_done = false;
            }

            // Poll
            _ = pair.client.poll();
            _ = pair.server.poll();

            // Receive
            const n = server_streams[i].read(&buf) catch 0;
            received[i] += n;
            if (received[i] < total_per_stream) {
                all_done = false;
            }
        }
    }

    const elapsed_ns: u64 = @intCast(std.time.nanoTimestamp() - start);
    var total_received: usize = 0;
    for (received) |r| total_received += r;
    const mbps = @as(f64, @floatFromInt(total_received)) / @as(f64, @floatFromInt(elapsed_ns)) * 1000.0;
    std.debug.print("[yamux multi {d} streams] {d:.1} MB/s\n", .{ num_streams, mbps });

    for (0..num_streams) |i| {
        client_streams[i].close();
        server_streams[i].close();
    }
}

// ============================================================================
// YamuxSelector - Select-based multi-session management
// ============================================================================

const Selector = platform.selector.Selector;

pub fn YamuxSelector(comptime Rt: type, comptime max_sessions: usize) type {
    return struct {
        const Self = @This();
        const SessionType = Yamux(Rt);
        const FdSource = struct {
            fd: i32,
            pub fn selectFd(self: *const @This()) i32 {
                return self.fd;
            }
        };

        selector: Selector(max_sessions, max_sessions),
        sessions: [max_sessions]?*SessionType,
        sources: [max_sessions]FdSource,
        num_sessions: usize,

        pub fn init() !Self {
            return .{
                .selector = try Selector(max_sessions, max_sessions).init(),
                .sessions = [_]?*SessionType{null} ** max_sessions,
                .sources = [_]FdSource{.{ .fd = -1 }} ** max_sessions,
                .num_sessions = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            self.selector.deinit();
        }

        /// Register a Yamux session with the selector.
        /// The session must support getSelectFd().
        pub fn register(self: *Self, session: *SessionType) error{ TooMany, NoSelectFd, PollCtlFailed }!void {
            if (self.num_sessions >= max_sessions) return error.TooMany;

            const fd = session.getSelectFd();
            if (fd < 0) return error.NoSelectFd;

            self.sources[self.num_sessions].fd = fd;
            _ = try self.selector.addRecv(&self.sources[self.num_sessions]);
            self.sessions[self.num_sessions] = session;
            self.num_sessions += 1;
        }

        /// Wait for any session to have pending data, or timeout.
        /// Returns the index of the ready session, or max_sessions on timeout.
        pub fn wait(self: *Self, timeout_ms: ?u32) error{ Empty, PollWaitFailed }!usize {
            while (true) {
                return self.selector.wait(timeout_ms) catch |err| switch (err) {
                    error.Interrupted => continue,
                    error.Empty => error.Empty,
                    error.PollWaitFailed => error.PollWaitFailed,
                };
            }
        }

        /// Poll the session at the given index.
        /// Returns number of frames processed.
        pub fn pollAt(self: *Self, idx: usize, max_frames: usize) usize {
            if (idx >= self.num_sessions) return 0;
            if (self.sessions[idx]) |session| {
                return session.pollOptimized(max_frames);
            }
            return 0;
        }

        /// Poll all sessions.
        /// Returns total frames processed.
        pub fn pollAll(self: *Self, max_frames: usize) usize {
            var total: usize = 0;
            for (0..self.num_sessions) |i| {
                total += self.pollAt(i, max_frames);
            }
            return total;
        }

        /// Get session at index.
        pub fn getSession(self: *Self, idx: usize) ?*SessionType {
            if (idx >= self.num_sessions) return null;
            return self.sessions[idx];
        }

        /// Number of registered sessions.
        pub fn count(self: *const Self) usize {
            return self.num_sessions;
        }
    };
}
