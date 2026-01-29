//! Stream - A multiplexed reliable stream over KCP.

const std = @import("std");
const kcp = @import("kcp.zig");

/// Stream state
pub const StreamState = enum {
    init,
    open,
    local_close, // We sent FIN
    remote_close, // We received FIN
    closed,
};

/// Stream errors
pub const StreamError = error{
    StreamClosed,
    KcpSendFailed,
    Timeout,
};

/// Stream represents a multiplexed stream over KCP.
pub const Stream = struct {
    id: u32,
    mux: *Mux,
    kcp_instance: ?kcp.Kcp,
    state: StreamState,
    recv_buf: std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,

    /// Initialize a new stream.
    pub fn init(allocator: std.mem.Allocator, id: u32, mux: *Mux) !*Stream {
        const self = try allocator.create(Stream);
        errdefer allocator.destroy(self);

        self.* = Stream{
            .id = id,
            .mux = mux,
            .kcp_instance = null,
            .state = .open,
            .recv_buf = .{},
            .allocator = allocator,
        };

        // Create KCP after self is stable
        // Note: We pass null for output callback initially
        self.kcp_instance = try kcp.Kcp.init(id, null, null);
        if (self.kcp_instance) |*k| {
            k.setDefaultConfig();
        }

        return self;
    }

    /// Deinitialize the stream.
    pub fn deinit(self: *Stream) void {
        if (self.kcp_instance) |*k| {
            k.deinit();
        }
        self.recv_buf.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    /// Get stream ID.
    pub fn getId(self: *const Stream) u32 {
        return self.id;
    }

    /// Get stream state.
    pub fn getState(self: *const Stream) StreamState {
        return self.state;
    }

    /// Write data to the stream.
    pub fn write(self: *Stream, data: []const u8) StreamError!usize {
        if (self.state == .closed or self.state == .local_close) {
            return StreamError.StreamClosed;
        }

        if (self.kcp_instance) |*k| {
            const n = k.send(data);
            if (n < 0) {
                return StreamError.KcpSendFailed;
            }
            return @intCast(n);
        }

        return StreamError.KcpSendFailed;
    }

    /// Read data from the stream.
    pub fn read(self: *Stream, buffer: []u8) StreamError!usize {
        if (self.recv_buf.items.len == 0) {
            if (self.state == .closed or self.state == .remote_close) {
                return 0; // EOF
            }
            return 0; // No data available
        }

        const n = @min(buffer.len, self.recv_buf.items.len);
        @memcpy(buffer[0..n], self.recv_buf.items[0..n]);

        // Remove read data from buffer
        const remaining = self.recv_buf.items.len - n;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.recv_buf.items[0..remaining], self.recv_buf.items[n..]);
        }
        self.recv_buf.shrinkRetainingCapacity(remaining);

        return n;
    }

    /// Close the stream.
    pub fn close(self: *Stream) void {
        if (self.state == .closed) return;

        if (self.state == .open) {
            self.state = .local_close;
        } else {
            self.state = .closed;
        }

        // Send FIN
        self.mux.sendFin(self.id) catch {};
    }

    /// Input data from KCP.
    pub fn kcpInput(self: *Stream, data: []const u8) void {
        if (self.state == .closed) return;
        if (self.kcp_instance) |*k| {
            _ = k.input(data);
        }
    }

    /// Receive data from KCP and buffer it.
    pub fn kcpRecv(self: *Stream) void {
        if (self.kcp_instance) |*k| {
            var buf: [64 * 1024]u8 = undefined;
            while (true) {
                const size = k.peekSize();
                if (size <= 0) break;

                const n = k.recv(&buf);
                if (n <= 0) break;

                self.recv_buf.appendSlice(self.allocator, buf[0..@intCast(n)]) catch break;
            }
        }
    }

    /// Update KCP state.
    pub fn kcpUpdate(self: *Stream, current: u32) void {
        if (self.state == .closed) return;
        if (self.kcp_instance) |*k| {
            k.update(current);
        }
    }

    /// Handle FIN from remote.
    pub fn handleFin(self: *Stream) void {
        if (self.state == .local_close) {
            self.state = .closed;
        } else if (self.state == .open) {
            self.state = .remote_close;
        }
    }

    /// KCP output callback
    fn kcpOutput(data: []const u8, user: ?*anyopaque) void {
        if (user) |u| {
            const stream: *Stream = @ptrCast(@alignCast(u));
            stream.mux.sendPsh(stream.id, data) catch {};
        }
    }
};

/// Mux configuration
pub const MuxConfig = struct {
    max_frame_size: usize = 32 * 1024,
    max_receive_buffer: usize = 256 * 1024,
    accept_backlog: usize = 256,
};

/// Mux multiplexes multiple streams over a single connection.
pub const Mux = struct {
    config: MuxConfig,
    output_fn: *const fn ([]const u8) anyerror!void,
    is_client: bool,
    streams: std.AutoHashMap(u32, *Stream),
    next_id: u32,
    accept_queue: std.ArrayListUnmanaged(*Stream),
    closed: bool,
    allocator: std.mem.Allocator,

    /// Initialize a new Mux.
    pub fn init(
        allocator: std.mem.Allocator,
        config: MuxConfig,
        is_client: bool,
        output_fn: *const fn ([]const u8) anyerror!void,
    ) !*Mux {
        const self = try allocator.create(Mux);
        errdefer allocator.destroy(self);

        self.* = Mux{
            .config = config,
            .output_fn = output_fn,
            .is_client = is_client,
            .streams = .init(allocator),
            .next_id = if (is_client) 1 else 2, // Client: odd, Server: even
            .accept_queue = .{},
            .closed = false,
            .allocator = allocator,
        };

        return self;
    }

    /// Deinitialize the Mux.
    pub fn deinit(self: *Mux) void {
        // Close all streams
        var iter = self.streams.valueIterator();
        while (iter.next()) |stream| {
            stream.*.deinit();
        }
        self.streams.deinit();
        self.accept_queue.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    /// Open a new stream.
    pub fn openStream(self: *Mux) !*Stream {
        if (self.closed) return error.MuxClosed;

        const id = self.next_id;
        self.next_id += 2;

        const stream = try Stream.init(self.allocator, id, self);
        errdefer stream.deinit();

        try self.streams.put(id, stream);

        // Send SYN
        try self.sendSyn(id);

        return stream;
    }

    /// Accept an incoming stream.
    pub fn acceptStream(self: *Mux) !*Stream {
        if (self.closed) return error.MuxClosed;
        if (self.accept_queue.items.len == 0) return error.NoStreamAvailable;

        return self.accept_queue.orderedRemove(0);
    }

    /// Get number of active streams.
    pub fn numStreams(self: *const Mux) usize {
        return self.streams.count();
    }

    /// Check if closed.
    pub fn isClosed(self: *const Mux) bool {
        return self.closed;
    }

    /// Close the Mux.
    pub fn closeMux(self: *Mux) void {
        self.closed = true;
    }

    /// Input a frame.
    pub fn input(self: *Mux, data: []const u8) !void {
        if (self.closed) return error.MuxClosed;

        const frame = try kcp.Frame.decode(data);

        switch (frame.cmd) {
            .syn => try self.handleSyn(frame.stream_id),
            .fin => self.handleFin(frame.stream_id),
            .psh => self.handlePsh(frame.stream_id, frame.payload),
            .nop => {}, // Keepalive, nothing to do
            .upd => {}, // TODO: Flow control
        }
    }

    /// Handle SYN (stream open request).
    fn handleSyn(self: *Mux, id: u32) !void {
        if (self.streams.contains(id)) return; // Duplicate SYN

        const stream = try Stream.init(self.allocator, id, self);
        errdefer stream.deinit();

        try self.streams.put(id, stream);
        try self.accept_queue.append(self.allocator, stream);
    }

    /// Handle FIN (stream close).
    fn handleFin(self: *Mux, id: u32) void {
        if (self.streams.get(id)) |stream| {
            stream.handleFin();
        }
    }

    /// Handle PSH (data).
    fn handlePsh(self: *Mux, id: u32, payload: []const u8) void {
        if (self.streams.get(id)) |stream| {
            stream.kcpInput(payload);
            stream.kcpRecv();
        }
    }

    /// Send a SYN frame.
    fn sendSyn(self: *Mux, id: u32) !void {
        try self.sendFrame(.{
            .cmd = .syn,
            .stream_id = id,
            .payload = &[_]u8{},
        });
    }

    /// Send a FIN frame.
    pub fn sendFin(self: *Mux, id: u32) !void {
        try self.sendFrame(.{
            .cmd = .fin,
            .stream_id = id,
            .payload = &[_]u8{},
        });
    }

    /// Send a PSH frame.
    pub fn sendPsh(self: *Mux, id: u32, payload: []const u8) !void {
        try self.sendFrame(.{
            .cmd = .psh,
            .stream_id = id,
            .payload = payload,
        });
    }

    /// Send a frame.
    fn sendFrame(self: *Mux, frame: kcp.Frame) !void {
        if (self.closed) return error.MuxClosed;

        var buf: [kcp.FrameHeaderSize + kcp.MaxPayloadSize]u8 = undefined;
        const encoded = try frame.encode(&buf);
        try self.output_fn(encoded);
    }

    /// Remove a stream from the Mux.
    pub fn removeStream(self: *Mux, id: u32) void {
        _ = self.streams.remove(id);
    }

    /// Update all streams.
    pub fn update(self: *Mux, current: u32) void {
        var iter = self.streams.valueIterator();
        while (iter.next()) |stream| {
            stream.*.kcpUpdate(current);
            stream.*.kcpRecv();
        }
    }
};

// Tests
test "Frame encode decode" {
    const frame = kcp.Frame{
        .cmd = .syn,
        .stream_id = 1,
        .payload = &[_]u8{},
    };
    var buf: [kcp.FrameHeaderSize]u8 = undefined;
    const encoded = try frame.encode(&buf);
    const decoded = try kcp.Frame.decode(encoded);
    try std.testing.expectEqual(kcp.Cmd.syn, decoded.cmd);
    try std.testing.expectEqual(@as(u32, 1), decoded.stream_id);
}

test "Mux init deinit" {
    const allocator = std.testing.allocator;

    const outputFn = struct {
        fn output(_: []const u8) anyerror!void {}
    }.output;

    const mux = try Mux.init(allocator, .{}, true, outputFn);
    mux.deinit();
}

test "Mux open stream" {
    const allocator = std.testing.allocator;

    const outputFn = struct {
        fn output(_: []const u8) anyerror!void {}
    }.output;

    const mux = try Mux.init(allocator, .{}, true, outputFn);
    defer mux.deinit();

    const stream = try mux.openStream();
    try std.testing.expectEqual(@as(u32, 1), stream.getId());
    try std.testing.expectEqual(@as(usize, 1), mux.numStreams());
}

test "Stream state" {
    const allocator = std.testing.allocator;

    const outputFn = struct {
        fn output(_: []const u8) anyerror!void {}
    }.output;

    const mux = try Mux.init(allocator, .{}, true, outputFn);
    defer mux.deinit();

    const stream = try mux.openStream();
    try std.testing.expectEqual(StreamState.open, stream.getState());
}
