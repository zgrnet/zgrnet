//! Stream - A multiplexed reliable stream over KCP.

const std = @import("std");
const kcp_mod = @import("kcp.zig");
const ring_buffer = @import("ring_buffer.zig");

const kcp = kcp_mod;

/// Re-export RingBuffer for convenience
pub const RingBuffer = ring_buffer.RingBuffer;

/// Stream state (u32 for atomic compatibility)
pub const StreamState = enum(u32) {
    open = 0,
    local_close = 1, // We sent FIN
    remote_close = 2, // We received FIN
    closed = 3,
};

/// Stream errors
pub const StreamError = error{
    StreamClosed,
    KcpSendFailed,
    Timeout,
};

/// Stream represents a multiplexed stream over KCP.
/// Uses fine-grained locking for better concurrency:
/// - kcp_mutex: protects KCP operations (send/recv/update)
/// - recv_mutex: protects recv_buf only
/// - state/output_error: atomic for lock-free reads
pub const Stream = struct {
    id: u32,
    mux: *Mux,
    kcp_instance: ?kcp.Kcp,
    recv_buf: RingBuffer(u8), // O(1) head removal
    allocator: std.mem.Allocator,

    // Fine-grained locks (lock order: kcp_mutex -> recv_mutex)
    kcp_mutex: std.Thread.Mutex, // Protects kcp_instance operations
    recv_mutex: std.Thread.Mutex, // Protects recv_buf only

    // Atomic state for lock-free reads
    state: std.atomic.Value(StreamState),
    output_error: std.atomic.Value(bool),

    /// Initialize a new stream.
    pub fn init(allocator: std.mem.Allocator, id: u32, mux: *Mux) !*Stream {
        const self = try allocator.create(Stream);
        errdefer allocator.destroy(self);

        self.* = Stream{
            .id = id,
            .mux = mux,
            .kcp_instance = null,
            .recv_buf = RingBuffer(u8).init(allocator),
            .allocator = allocator,
            .kcp_mutex = .{},
            .recv_mutex = .{},
            .state = std.atomic.Value(StreamState).init(.open),
            .output_error = std.atomic.Value(bool).init(false),
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

    /// Get stream state (lock-free atomic read).
    pub fn getState(self: *const Stream) StreamState {
        return self.state.load(.seq_cst);
    }

    /// Write data to the stream.
    /// Note: KCP send() returns 0 on success, < 0 on error.
    /// We return data.len on success to indicate bytes accepted.
    /// Uses kcp_mutex only (not recv_mutex).
    pub fn write(self: *Stream, data: []const u8) StreamError!usize {
        // Lock-free state check
        const current_state = self.state.load(.seq_cst);
        if (current_state == .closed or current_state == .local_close) {
            return StreamError.StreamClosed;
        }

        self.kcp_mutex.lock();
        defer self.kcp_mutex.unlock();

        if (self.kcp_instance) |*k| {
            const ret = k.send(data);
            if (ret < 0) {
                return StreamError.KcpSendFailed;
            }
            // Flush immediately for better throughput (same as Go/Rust)
            k.flush();
            // KCP returns 0 on success, we return bytes accepted
            return data.len;
        }

        return StreamError.KcpSendFailed;
    }

    /// Read data from the stream.
    /// Uses recv_mutex only (not kcp_mutex) for better concurrency.
    pub fn read(self: *Stream, buffer: []u8) StreamError!usize {
        self.recv_mutex.lock();
        defer self.recv_mutex.unlock();

        if (self.recv_buf.readableLength() == 0) {
            // Lock-free state check
            const current_state = self.state.load(.seq_cst);
            if (current_state == .closed or current_state == .remote_close) {
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
    /// Lock order: kcp_mutex -> recv_mutex (if both needed).
    pub fn recvIntoBuffer(self: *Stream, buffer: []u8) StreamError!usize {
        // First drain any buffered data (recv_mutex only)
        self.recv_mutex.lock();
        if (self.recv_buf.readableLength() > 0) {
            const n = self.recv_buf.read(buffer);
            self.recv_mutex.unlock();
            return n;
        }
        self.recv_mutex.unlock();

        // No buffered data, try direct receive from KCP (kcp_mutex)
        self.kcp_mutex.lock();
        defer self.kcp_mutex.unlock();

        if (self.kcp_instance) |*k| {
            const size = k.peekSize();
            if (size <= 0) {
                const current_state = self.state.load(.seq_cst);
                if (current_state == .closed or current_state == .remote_close) {
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
                const tmp = self.allocator.alloc(u8, @intCast(size)) catch return 0;
                defer self.allocator.free(tmp);

                const n = k.recv(tmp);
                if (n > 0) {
                    const copy_len = @min(buffer.len, @as(usize, @intCast(n)));
                    @memcpy(buffer[0..copy_len], tmp[0..copy_len]);
                    // Buffer remaining data (need recv_mutex)
                    if (@as(usize, @intCast(n)) > copy_len) {
                        self.recv_mutex.lock();
                        self.recv_buf.write(tmp[copy_len..@intCast(n)]) catch {};
                        self.recv_mutex.unlock();
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
    /// Uses atomic CAS for thread-safe state transition.
    pub fn shutdown(self: *Stream) void {
        const current_state = self.state.load(.seq_cst);
        if (current_state == .closed or current_state == .local_close) return;

        // Only send FIN when transitioning from open to local_close
        const should_send_fin = current_state == .open;

        if (current_state == .open) {
            self.state.store(.local_close, .seq_cst);
        } else {
            self.state.store(.closed, .seq_cst);
        }

        // Send FIN (only once)
        if (should_send_fin) {
            self.mux.sendFin(self.id) catch {};
        }
    }

    /// Check if a transport output error has occurred (lock-free).
    pub fn hasOutputError(self: *const Stream) bool {
        return self.output_error.load(.seq_cst);
    }

    /// Input data from KCP.
    /// Uses kcp_mutex only.
    pub fn kcpInput(self: *Stream, data: []const u8) void {
        // Lock-free state check
        if (self.state.load(.seq_cst) == .closed) return;

        self.kcp_mutex.lock();
        defer self.kcp_mutex.unlock();

        if (self.kcp_instance) |*k| {
            _ = k.input(data);
        }
    }

    /// Receive data from KCP and buffer it.
    /// Uses stack buffer for common MTU-sized messages, heap fallback for oversized.
    /// Returns true if any data was received.
    /// Fine-grained locking: kcp_mutex for KCP ops, recv_mutex for buffer ops.
    pub fn kcpRecv(self: *Stream) bool {
        var received = false;
        // Stack buffer for common case (MTU-sized messages)
        var stack_buf: [1500]u8 = undefined;
        // Heap buffer for oversized messages (allocated on demand)
        var heap_buf: ?[]u8 = null;
        defer if (heap_buf) |buf| self.allocator.free(buf);

        while (true) {
            // Phase 1: Peek and recv from KCP (kcp_mutex)
            self.kcp_mutex.lock();
            const size = if (self.kcp_instance) |*k| k.peekSize() else -1;
            if (size <= 0) {
                self.kcp_mutex.unlock();
                break;
            }

            const usize_size: usize = @intCast(size);
            var data_slice: []u8 = undefined;

            if (usize_size <= stack_buf.len) {
                // Common path: use stack buffer
                const n = if (self.kcp_instance) |*k| k.recv(stack_buf[0..usize_size]) else -1;
                self.kcp_mutex.unlock();
                if (n <= 0) break;
                data_slice = stack_buf[0..@intCast(n)];
            } else {
                // Rare path: allocate/grow heap buffer for oversized
                if (heap_buf == null or heap_buf.?.len < usize_size) {
                    if (heap_buf) |old| self.allocator.free(old);
                    heap_buf = self.allocator.alloc(u8, usize_size) catch {
                        self.kcp_mutex.unlock();
                        break;
                    };
                }
                const n = if (self.kcp_instance) |*k| k.recv(heap_buf.?[0..usize_size]) else -1;
                self.kcp_mutex.unlock();
                if (n <= 0) break;
                data_slice = heap_buf.?[0..@intCast(n)];
            }

            // Phase 2: Write to recv_buf (recv_mutex)
            self.recv_mutex.lock();
            self.recv_buf.write(data_slice) catch {
                self.recv_mutex.unlock();
                break;
            };
            self.recv_mutex.unlock();
            received = true;
        }

        return received;
    }

    /// Update KCP state.
    /// Uses kcp_mutex only.
    pub fn kcpUpdate(self: *Stream, current: u32) void {
        // Lock-free state check
        if (self.state.load(.seq_cst) == .closed) return;

        self.kcp_mutex.lock();
        defer self.kcp_mutex.unlock();

        if (self.kcp_instance) |*k| {
            k.update(current);
        }
    }

    /// Handle FIN from remote.
    /// Uses atomic state transitions.
    pub fn handleFin(self: *Stream) void {
        const current_state = self.state.load(.seq_cst);
        if (current_state == .local_close) {
            self.state.store(.closed, .seq_cst);
        } else if (current_state == .open) {
            self.state.store(.remote_close, .seq_cst);
        }
    }

    /// KCP output callback
    fn kcpOutput(data: []const u8, user: ?*anyopaque) void {
        if (user) |u| {
            const stream: *Stream = @ptrCast(@alignCast(u));
            stream.mux.sendPsh(stream.id, data) catch |err| {
                stream.output_error.store(true, .seq_cst);
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

/// Callback when stream has data available to read (with user data).
pub const OnStreamDataFn = *const fn (stream_id: u32, user_data: ?*anyopaque) void;

/// Callback when a new stream is accepted (with user data).
pub const OnNewStreamFn = *const fn (stream: *Stream, user_data: ?*anyopaque) void;

/// Output callback type (with user data for context).
pub const OutputFn = *const fn (data: []const u8, user_data: ?*anyopaque) anyerror!void;

/// Mux multiplexes multiple streams over a single connection.
/// Thread-safe: all public methods are protected by mutex.
pub const Mux = struct {
    config: MuxConfig,
    output_fn: OutputFn,
    on_stream_data: OnStreamDataFn,
    on_new_stream: OnNewStreamFn,
    user_data: ?*anyopaque,
    is_client: bool,
    streams: std.AutoHashMap(u32, *Stream),
    next_id: u32,
    closed: bool,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,

    /// Initialize a new Mux.
    pub fn init(
        allocator: std.mem.Allocator,
        config: MuxConfig,
        is_client: bool,
        output_fn: OutputFn,
        on_stream_data: OnStreamDataFn,
        on_new_stream: OnNewStreamFn,
        user_data: ?*anyopaque,
    ) !*Mux {
        const self = try allocator.create(Mux);
        errdefer allocator.destroy(self);

        self.* = Mux{
            .config = config,
            .output_fn = output_fn,
            .on_stream_data = on_stream_data,
            .on_new_stream = on_new_stream,
            .user_data = user_data,
            .is_client = is_client,
            .streams = .init(allocator),
            .next_id = if (is_client) 1 else 2, // Client: odd, Server: even
            .closed = false,
            .allocator = allocator,
            .mutex = .{},
        };

        return self;
    }

    /// Deinitialize the Mux.
    pub fn deinit(self: *Mux) void {
        self.mutex.lock();
        defer self.mutex.unlock();

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
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.closed) return error.MuxClosed;

        const id = self.next_id;
        self.next_id += 2;

        const stream = try Stream.init(self.allocator, id, self);
        errdefer stream.deinit();

        try self.streams.put(id, stream);
        errdefer _ = self.streams.remove(id); // Remove from map before deinit to avoid dangling pointer

        // Send SYN (unlocked - output_fn may need to acquire other locks)
        self.mutex.unlock();
        defer self.mutex.lock();
        try self.sendSynUnlocked(id);

        return stream;
    }

    /// Get number of active streams.
    pub fn numStreams(self: *Mux) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.streams.count();
    }

    /// Check if closed.
    pub fn isClosed(self: *Mux) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.closed;
    }

    /// Close the Mux.
    pub fn closeMux(self: *Mux) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closed = true;
    }

    /// Input a frame.
    pub fn input(self: *Mux, data: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.closed) return error.MuxClosed;

        const frame = try kcp.Frame.decode(data);

        switch (frame.cmd) {
            .syn => try self.handleSynLocked(frame.stream_id),
            .fin => self.handleFinLocked(frame.stream_id),
            .psh => self.handlePshLocked(frame.stream_id, frame.payload),
            .nop => {}, // Keepalive, nothing to do
        }
    }

    /// Handle SYN (stream open request). Must be called with mutex held.
    fn handleSynLocked(self: *Mux, id: u32) !void {
        if (self.streams.contains(id)) return; // Duplicate SYN

        const stream = try Stream.init(self.allocator, id, self);
        errdefer stream.deinit();

        try self.streams.put(id, stream);

        // Notify via callback (unlock to avoid deadlock)
        self.mutex.unlock();
        defer self.mutex.lock();
        self.on_new_stream(stream, self.user_data);
    }

    /// Handle FIN (stream close). Must be called with mutex held.
    fn handleFinLocked(self: *Mux, id: u32) void {
        if (self.streams.get(id)) |stream| {
            stream.handleFin();
        }
    }

    /// Handle PSH (data). Must be called with mutex held.
    fn handlePshLocked(self: *Mux, id: u32, payload: []const u8) void {
        if (self.streams.get(id)) |stream| {
            stream.kcpInput(payload);
            if (stream.kcpRecv()) {
                // Unlock before callback to avoid deadlock
                self.mutex.unlock();
                defer self.mutex.lock();
                self.on_stream_data(id, self.user_data);
            }
        }
    }

    /// Send a SYN frame (unlocked version for use when mutex is temporarily released).
    fn sendSynUnlocked(self: *Mux, id: u32) !void {
        try self.sendFrameUnlocked(.{
            .cmd = .syn,
            .stream_id = id,
            .payload = &[_]u8{},
        });
    }

    /// Send a FIN frame.
    pub fn sendFin(self: *Mux, id: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.sendFrameUnlocked(.{
            .cmd = .fin,
            .stream_id = id,
            .payload = &[_]u8{},
        });
    }

    /// Send a PSH frame.
    pub fn sendPsh(self: *Mux, id: u32, payload: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.sendFrameUnlocked(.{
            .cmd = .psh,
            .stream_id = id,
            .payload = payload,
        });
    }

    /// Send a frame (must NOT hold mutex - output_fn may acquire other locks).
    fn sendFrameUnlocked(self: *Mux, frame: kcp.Frame) !void {
        if (self.closed) return error.MuxClosed;

        const required_size = kcp.FrameHeaderSize + frame.payload.len;
        var stack_buf: [1500]u8 = undefined; // MTU-sized stack buffer

        if (required_size <= stack_buf.len) {
            // Use stack buffer for typical small frames
            const encoded = try frame.encode(&stack_buf);
            try self.output_fn(encoded, self.user_data);
        } else {
            // Heap allocate for oversized frames
            const buf = try self.allocator.alloc(u8, required_size);
            defer self.allocator.free(buf);
            const encoded = try frame.encode(buf);
            try self.output_fn(encoded, self.user_data);
        }
    }

    /// Remove a stream from the Mux.
    pub fn removeStream(self: *Mux, id: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.streams.remove(id);
    }

    /// Update all streams.
    /// Lock order: We release mux.mutex before calling stream methods to avoid
    /// deadlock with Stream.write() which holds kcp_mutex and calls sendPsh().
    pub fn update(self: *Mux, current: u32) void {
        // Use arena allocator for temporary dynamic lists to handle any number of streams
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        var stream_list = std.array_list.AlignedManaged(*Stream, null).init(alloc);
        var id_list = std.array_list.AlignedManaged(u32, null).init(alloc);

        // Collect stream pointers under lock
        self.mutex.lock();
        var iter = self.streams.iterator();
        while (iter.next()) |entry| {
            stream_list.append(entry.value_ptr.*) catch break;
            id_list.append(entry.key_ptr.*) catch break;
        }
        self.mutex.unlock();

        // Update streams without holding mux.mutex (avoids deadlock with write->sendPsh)
        for (stream_list.items, id_list.items) |stream, id| {
            stream.kcpUpdate(current);
            if (stream.kcpRecv()) {
                self.on_stream_data(id, self.user_data);
            }
        }
    }

    /// Get a stream by ID.
    pub fn getStream(self: *Mux, id: u32) ?*Stream {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.streams.get(id);
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
        fn output(_: []const u8, _: ?*anyopaque) anyerror!void {}
    }.output;
    const onStreamData = struct {
        fn cb(_: u32, _: ?*anyopaque) void {}
    }.cb;
    const onNewStream = struct {
        fn cb(_: *Stream, _: ?*anyopaque) void {}
    }.cb;

    const mux = try Mux.init(allocator, .{}, true, outputFn, onStreamData, onNewStream, null);
    mux.deinit();
}

test "Mux open stream" {
    const allocator = std.testing.allocator;

    const outputFn = struct {
        fn output(_: []const u8, _: ?*anyopaque) anyerror!void {}
    }.output;
    const onStreamData = struct {
        fn cb(_: u32, _: ?*anyopaque) void {}
    }.cb;
    const onNewStream = struct {
        fn cb(_: *Stream, _: ?*anyopaque) void {}
    }.cb;

    const mux = try Mux.init(allocator, .{}, true, outputFn, onStreamData, onNewStream, null);
    defer mux.deinit();

    const stream = try mux.openStream();
    try std.testing.expectEqual(@as(u32, 1), stream.getId());
    try std.testing.expectEqual(@as(usize, 1), mux.numStreams());
}

test "Stream state" {
    const allocator = std.testing.allocator;

    const outputFn = struct {
        fn output(_: []const u8, _: ?*anyopaque) anyerror!void {}
    }.output;
    const onStreamData = struct {
        fn cb(_: u32, _: ?*anyopaque) void {}
    }.cb;
    const onNewStream = struct {
        fn cb(_: *Stream, _: ?*anyopaque) void {}
    }.cb;

    const mux = try Mux.init(allocator, .{}, true, outputFn, onStreamData, onNewStream, null);
    defer mux.deinit();

    const stream = try mux.openStream();
    try std.testing.expectEqual(StreamState.open, stream.getState());
}
