//! Stream - A multiplexed reliable stream over KCP.

const std = @import("std");
const kcp = @import("kcp.zig");

/// RingBuffer - O(1) read/write from head/tail
pub fn RingBuffer(comptime T: type) type {
    return struct {
        const Self = @This();

        buf: []T,
        head: usize = 0,
        tail: usize = 0,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .buf = &[_]T{},
                .head = 0,
                .tail = 0,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.buf.len > 0) {
                self.allocator.free(self.buf);
            }
        }

        pub fn readableLength(self: *const Self) usize {
            if (self.tail >= self.head) {
                return self.tail - self.head;
            } else {
                return self.buf.len - self.head + self.tail;
            }
        }

        pub fn read(self: *Self, dest: []T) usize {
            const to_read = @min(dest.len, self.readableLength());
            if (to_read == 0) return 0;

            const head = self.head;
            const cap = self.buf.len;

            // Use @memcpy for efficient bulk copy (handles wrap-around with at most 2 copies)
            const part1_len = @min(to_read, cap - head);
            @memcpy(dest[0..part1_len], self.buf[head..][0..part1_len]);

            const part2_len = to_read - part1_len;
            if (part2_len > 0) {
                @memcpy(dest[part1_len..][0..part2_len], self.buf[0..part2_len]);
            }

            self.head = (head + to_read) % cap;
            return to_read;
        }

        pub fn write(self: *Self, src: []const T) !void {
            // Ensure capacity
            const needed = self.readableLength() + src.len + 1;
            if (needed > self.buf.len) {
                try self.grow(needed);
            }

            // Use @memcpy for efficient bulk copy (handles wrap-around)
            const tail = self.tail;
            const cap = self.buf.len;
            const part1_len = @min(src.len, cap - tail);
            @memcpy(self.buf[tail..][0..part1_len], src[0..part1_len]);

            const part2_len = src.len - part1_len;
            if (part2_len > 0) {
                @memcpy(self.buf[0..part2_len], src[part1_len..][0..part2_len]);
            }

            self.tail = (tail + src.len) % cap;
        }

        fn grow(self: *Self, min_cap: usize) !void {
            var new_cap = if (self.buf.len == 0) 64 else self.buf.len;
            while (new_cap < min_cap) {
                new_cap *= 2;
            }

            const new_buf = try self.allocator.alloc(T, new_cap);
            const len = self.readableLength();

            // Use @memcpy for efficient bulk copy (handles wrap-around)
            if (len > 0) {
                const head = self.head;
                const cap = self.buf.len;
                const part1_len = @min(len, cap - head);
                @memcpy(new_buf[0..part1_len], self.buf[head..][0..part1_len]);

                const part2_len = len - part1_len;
                if (part2_len > 0) {
                    @memcpy(new_buf[part1_len..][0..part2_len], self.buf[0..part2_len]);
                }
            }

            if (self.buf.len > 0) {
                self.allocator.free(self.buf);
            }

            self.buf = new_buf;
            self.head = 0;
            self.tail = len;
        }
    };
}

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
    /// Uses stack buffer for common MTU-sized messages, heap fallback for oversized.
    pub fn kcpRecv(self: *Stream) void {
        if (self.kcp_instance) |*k| {
            // Reusable MTU-sized stack buffer for common case
            var stack_buf: [1500]u8 = undefined;

            while (true) {
                const size = k.peekSize();
                if (size <= 0) break;

                const usize_size: usize = @intCast(size);

                if (usize_size <= stack_buf.len) {
                    // Common path: use stack buffer (no allocation)
                    const n = k.recv(stack_buf[0..usize_size]);
                    if (n <= 0) break;
                    self.recv_buf.write(stack_buf[0..@intCast(n)]) catch break;
                } else {
                    // Rare path: heap allocate for oversized messages
                    const buf = self.allocator.alloc(u8, usize_size) catch break;
                    defer self.allocator.free(buf);
                    const n = k.recv(buf);
                    if (n <= 0) break;
                    self.recv_buf.write(buf[0..@intCast(n)]) catch break;
                }
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
            stream.mux.sendPsh(stream.id, data) catch |err| {
                std.log.err("Mux output error in stream {d}: {s}", .{ stream.id, @errorName(err) });
            };
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
