//! Stream - A multiplexed reliable stream over KCP.

const std = @import("std");
const kcp = @import("kcp.zig");
const ring_buffer = @import("ring_buffer.zig");

/// Re-export RingBuffer for convenience
pub const RingBuffer = ring_buffer.RingBuffer;

/// Stream state
pub const StreamState = enum {
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
    recv_buf: RingBuffer(u8), // O(1) head removal
    allocator: std.mem.Allocator,
    output_error: bool, // Set on transport output error

    /// Initialize a new stream.
    pub fn init(allocator: std.mem.Allocator, id: u32, mux: *Mux) !*Stream {
        const self = try allocator.create(Stream);
        errdefer allocator.destroy(self);

        self.* = Stream{
            .id = id,
            .mux = mux,
            .kcp_instance = null,
            .state = .open,
            .recv_buf = RingBuffer(u8).init(allocator),
            .allocator = allocator,
            .output_error = false,
        };

        // Create KCP with output callback that routes data through the Mux
        self.kcp_instance = try kcp.Kcp.init(id, &Stream.kcpOutput, self);
        if (self.kcp_instance) |*k| {
            k.setUserPtr(); // Set user pointer for callback to access this Stream
            k.setDefaultConfig();
        }

        return self;
    }

    /// Deinitialize the stream.
    pub fn deinit(self: *Stream) void {
        if (self.kcp_instance) |*k| {
            k.deinit();
        }
        self.recv_buf.deinit();
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
        if (self.recv_buf.readableLength() == 0) {
            if (self.state == .closed or self.state == .remote_close) {
                return 0; // EOF
            }
            return 0; // No data available
        }

        // LinearFifo.read() automatically removes data from head - O(1)
        return self.recv_buf.read(buffer);
    }

    /// Receive data directly from KCP into user-provided buffer (zero-copy fast path).
    /// Returns the number of bytes received, or 0 if no data available.
    /// This bypasses the internal recv_buf for lower latency when caller can process immediately.
    pub fn recvIntoBuffer(self: *Stream, buffer: []u8) StreamError!usize {
        // First drain any buffered data
        if (self.recv_buf.readableLength() > 0) {
            return self.recv_buf.read(buffer);
        }

        // No buffered data, try direct receive from KCP
        if (self.kcp_instance) |*k| {
            const size = k.peekSize();
            if (size <= 0) {
                if (self.state == .closed or self.state == .remote_close) {
                    return 0; // EOF
                }
                return 0; // No data available
            }

            // Direct receive into user buffer if it fits
            if (buffer.len >= @as(usize, @intCast(size))) {
                const n = k.recv(buffer);
                if (n > 0) {
                    return @intCast(n);
                }
            } else {
                // Buffer too small, need intermediate allocation
                const tmp = try self.allocator.alloc(u8, @intCast(size));
                defer self.allocator.free(tmp);

                const n = k.recv(tmp);
                if (n > 0) {
                    const copy_len = @min(buffer.len, @as(usize, @intCast(n)));
                    @memcpy(buffer[0..copy_len], tmp[0..copy_len]);
                    // Buffer remaining data
                    if (@as(usize, @intCast(n)) > copy_len) {
                        try self.recv_buf.write(tmp[copy_len..@intCast(n)]);
                    }
                    return copy_len;
                }
            }
        }

        return 0;
    }

    /// Close the stream.
    /// Shutdown the write-half of the stream.
    /// Sends a FIN frame to the remote peer and transitions to `local_close` state.
    /// The stream can still receive data until a FIN is received from the peer.
    pub fn shutdown(self: *Stream) void {
        if (self.state == .closed or self.state == .local_close) return;

        // Only send FIN when transitioning from open to local_close
        const should_send_fin = self.state == .open;

        if (self.state == .open) {
            self.state = .local_close;
        } else {
            self.state = .closed;
        }

        // Send FIN (only once)
        if (should_send_fin) {
            self.mux.sendFin(self.id) catch {};
        }
    }

    /// Check if a transport output error has occurred.
    pub fn hasOutputError(self: *const Stream) bool {
        return self.output_error;
    }

    /// Input data from KCP.
    pub fn kcpInput(self: *Stream, data: []const u8) void {
        if (self.state == .closed) return;
        if (self.kcp_instance) |*k| {
            _ = k.input(data);
        }
    }

    /// Receive data from KCP and buffer it.
    /// Uses stack buffer for common MTU-sized messages, heap fallback for oversized.
    /// Heap buffer is reused across loop iterations to avoid repeated allocations.
    /// Returns true if any data was received.
    pub fn kcpRecv(self: *Stream) bool {
        var received = false;
        if (self.kcp_instance) |*k| {
            // Reusable MTU-sized stack buffer for common case
            var stack_buf: [1500]u8 = undefined;
            // Reusable heap buffer for oversized messages
            var heap_buf: ?[]u8 = null;
            defer if (heap_buf) |buf| self.allocator.free(buf);

            while (true) {
                const size = k.peekSize();
                if (size <= 0) break;

                const usize_size: usize = @intCast(size);

                if (usize_size <= stack_buf.len) {
                    // Common path: use stack buffer (no allocation)
                    const n = k.recv(stack_buf[0..usize_size]);
                    if (n <= 0) break;
                    self.recv_buf.write(stack_buf[0..@intCast(n)]) catch break;
                    received = true;
                } else {
                    // Rare path: reuse or grow heap buffer for oversized messages
                    if (heap_buf == null or heap_buf.?.len < usize_size) {
                        if (heap_buf) |old| self.allocator.free(old);
                        heap_buf = self.allocator.alloc(u8, usize_size) catch break;
                    }
                    const n = k.recv(heap_buf.?[0..usize_size]);
                    if (n <= 0) break;
                    self.recv_buf.write(heap_buf.?[0..@intCast(n)]) catch break;
                    received = true;
                }
            }
        }
        return received;
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
            stream.mux.sendPsh(stream.id, data) catch |err| {
                stream.output_error = true;
                std.log.err("Mux output error in stream {d}: {s}", .{ stream.id, @errorName(err) });
            };
        }
    }
};

/// Mux configuration
pub const MuxConfig = struct {
    max_frame_size: usize = 32 * 1024,
    max_receive_buffer: usize = 256 * 1024,
};

/// Callback when stream has data available to read.
pub const OnStreamDataFn = *const fn (stream_id: u32) void;

/// Callback when a new stream is accepted.
pub const OnNewStreamFn = *const fn (stream: *Stream) void;

/// Mux multiplexes multiple streams over a single connection.
pub const Mux = struct {
    config: MuxConfig,
    output_fn: *const fn ([]const u8) anyerror!void,
    on_stream_data: OnStreamDataFn,
    on_new_stream: OnNewStreamFn,
    is_client: bool,
    streams: std.AutoHashMap(u32, *Stream),
    next_id: u32,
    closed: bool,
    allocator: std.mem.Allocator,

    /// Initialize a new Mux.
    pub fn init(
        allocator: std.mem.Allocator,
        config: MuxConfig,
        is_client: bool,
        output_fn: *const fn ([]const u8) anyerror!void,
        on_stream_data: OnStreamDataFn,
        on_new_stream: OnNewStreamFn,
    ) !*Mux {
        const self = try allocator.create(Mux);
        errdefer allocator.destroy(self);

        self.* = Mux{
            .config = config,
            .output_fn = output_fn,
            .on_stream_data = on_stream_data,
            .on_new_stream = on_new_stream,
            .is_client = is_client,
            .streams = .init(allocator),
            .next_id = if (is_client) 1 else 2, // Client: odd, Server: even
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
        errdefer _ = self.streams.remove(id); // Remove from map before deinit to avoid dangling pointer

        // Send SYN
        try self.sendSyn(id);

        return stream;
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
        }
    }

    /// Handle SYN (stream open request).
    fn handleSyn(self: *Mux, id: u32) !void {
        if (self.streams.contains(id)) return; // Duplicate SYN

        const stream = try Stream.init(self.allocator, id, self);
        errdefer stream.deinit();

        try self.streams.put(id, stream);

        // Notify via callback
        self.on_new_stream(stream);
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
            if (stream.kcpRecv()) {
                self.on_stream_data(id);
            }
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

        const required_size = kcp.FrameHeaderSize + frame.payload.len;
        var stack_buf: [1500]u8 = undefined; // MTU-sized stack buffer

        if (required_size <= stack_buf.len) {
            // Use stack buffer for typical small frames
            const encoded = try frame.encode(&stack_buf);
            try self.output_fn(encoded);
        } else {
            // Heap allocate for oversized frames
            const buf = try self.allocator.alloc(u8, required_size);
            defer self.allocator.free(buf);
            const encoded = try frame.encode(buf);
            try self.output_fn(encoded);
        }
    }

    /// Remove a stream from the Mux.
    pub fn removeStream(self: *Mux, id: u32) void {
        _ = self.streams.remove(id);
    }

    /// Update all streams.
    pub fn update(self: *Mux, current: u32) void {
        var iter = self.streams.iterator();
        while (iter.next()) |entry| {
            const id = entry.key_ptr.*;
            const stream = entry.value_ptr.*;
            stream.kcpUpdate(current);
            if (stream.kcpRecv()) {
                self.on_stream_data(id);
            }
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
    const onStreamData = struct {
        fn cb(_: u32) void {}
    }.cb;
    const onNewStream = struct {
        fn cb(_: *Stream) void {}
    }.cb;

    const mux = try Mux.init(allocator, .{}, true, outputFn, onStreamData, onNewStream);
    mux.deinit();
}

test "Mux open stream" {
    const allocator = std.testing.allocator;

    const outputFn = struct {
        fn output(_: []const u8) anyerror!void {}
    }.output;
    const onStreamData = struct {
        fn cb(_: u32) void {}
    }.cb;
    const onNewStream = struct {
        fn cb(_: *Stream) void {}
    }.cb;

    const mux = try Mux.init(allocator, .{}, true, outputFn, onStreamData, onNewStream);
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
    const onStreamData = struct {
        fn cb(_: u32) void {}
    }.cb;
    const onNewStream = struct {
        fn cb(_: *Stream) void {}
    }.cb;

    const mux = try Mux.init(allocator, .{}, true, outputFn, onStreamData, onNewStream);
    defer mux.deinit();

    const stream = try mux.openStream();
    try std.testing.expectEqual(StreamState.open, stream.getState());
}
