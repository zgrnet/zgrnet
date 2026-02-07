//! Stream - A multiplexed reliable stream over KCP.
//!
//! Uses comptime generics for zero-cost async primitives:
//! - TimerServiceT: For KCP update scheduling (1ms interval)
//! - Output is synchronous (caller provides callback)
//!
//! ## Architecture
//!
//! ```
//! Mux<TimerServiceT>
//!   ├── timer_service: *TimerServiceT (injected)
//!   ├── streams: HashMap<u32, *Stream>
//!   ├── update_handle: TimerHandle (KCP timer)
//!   └── output_fn: callback to send data
//! ```

const std = @import("std");
const kcp_mod = @import("kcp.zig");
const ring_buffer = @import("ring_buffer.zig");
const async_mod = @import("../async/mod.zig");
const concepts = async_mod.concepts;

const kcp = kcp_mod;
const Task = async_mod.Task;
const TimerHandle = async_mod.TimerHandle;
const Channel = async_mod.Channel;
const Signal = async_mod.Signal;

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
    MuxClosed,
};

/// Mux errors
pub const MuxError = error{
    MuxClosed,
    OutOfMemory,
    InvalidFrame,
};

/// Mux configuration
pub const MuxConfig = struct {
    max_frame_size: usize = 32 * 1024,
    max_receive_buffer: usize = 16 * 1024 * 1024, // 16MB to allow larger transfers
    update_interval_ms: u32 = 1, // KCP update interval
};

/// Output callback type.
pub const OutputFn = *const fn (data: []const u8, user_data: ?*anyopaque) anyerror!void;

/// Callback when a new stream is accepted.
pub const OnNewStreamFn = *const fn (stream: *Stream, user_data: ?*anyopaque) void;

/// Stream represents a multiplexed stream over KCP.
/// Uses fine-grained locking for better concurrency.
pub const Stream = struct {
    id: u32,
    proto: u8, // Stream protocol type (from SYN payload)
    metadata: []const u8, // Stream metadata (from SYN payload), owned
    mux_ptr: *anyopaque, // Type-erased Mux pointer (to avoid circular comptime dependency)
    send_frame_fn: *const fn (mux: *anyopaque, cmd: kcp.Cmd, stream_id: u32, payload: []const u8) anyerror!void,
    kcp_instance: ?kcp.Kcp,
    recv_buf: RingBuffer(u8),
    allocator: std.mem.Allocator,

    // Fine-grained locks
    kcp_mutex: std.Thread.Mutex,
    recv_mutex: std.Thread.Mutex,

    // Atomic state
    state: std.atomic.Value(StreamState),
    output_error: std.atomic.Value(bool),

    // Reference counting
    ref_count: std.atomic.Value(u32),

    // Max receive buffer (from config)
    max_receive_buffer: usize,

    // Condition variable for blocking read
    data_available: std.Thread.Condition,

    /// Initialize a new stream with protocol type and metadata.
    pub fn init(
        allocator: std.mem.Allocator,
        id: u32,
        proto: u8,
        metadata: []const u8,
        mux_ptr: *anyopaque,
        send_frame_fn: *const fn (*anyopaque, kcp.Cmd, u32, []const u8) anyerror!void,
        max_recv_buf: usize,
    ) !*Stream {
        const self = try allocator.create(Stream);
        errdefer allocator.destroy(self);

        // Copy metadata to owned memory
        const meta_copy = if (metadata.len > 0)
            try allocator.dupe(u8, metadata)
        else
            &[_]u8{};

        self.* = Stream{
            .id = id,
            .proto = proto,
            .metadata = meta_copy,
            .mux_ptr = mux_ptr,
            .send_frame_fn = send_frame_fn,
            .kcp_instance = null,
            .recv_buf = RingBuffer(u8).init(allocator),
            .allocator = allocator,
            .kcp_mutex = .{},
            .recv_mutex = .{},
            .state = std.atomic.Value(StreamState).init(.open),
            .output_error = std.atomic.Value(bool).init(false),
            .ref_count = std.atomic.Value(u32).init(1),
            .max_receive_buffer = max_recv_buf,
            .data_available = .{},
        };

        // Create KCP with output callback
        self.kcp_instance = try kcp.Kcp.init(id, &Stream.kcpOutput, self);
        if (self.kcp_instance) |*k| {
            k.setUserPtr();
            k.setDefaultConfig();
        }

        return self;
    }

    /// Increment reference count.
    pub fn retain(self: *Stream) void {
        _ = self.ref_count.fetchAdd(1, .seq_cst);
    }

    /// Decrement reference count and free if zero.
    pub fn release(self: *Stream) bool {
        const old = self.ref_count.fetchSub(1, .seq_cst);
        if (old == 1) {
            self.deinitInternal();
            return true;
        }
        return false;
    }

    /// Close the stream (user API).
    pub fn close(self: *Stream) void {
        self.shutdown();
        _ = self.release();
    }

    fn deinitInternal(self: *Stream) void {
        if (self.kcp_instance) |*k| {
            k.deinit();
        }
        if (self.metadata.len > 0) {
            self.allocator.free(@constCast(self.metadata));
        }
        self.recv_buf.deinit();
        self.allocator.destroy(self);
    }

    /// Get stream ID.
    pub fn getId(self: *const Stream) u32 {
        return self.id;
    }

    /// Get stream protocol type (from SYN payload).
    /// Returns 0 (RAW) if no protocol was specified.
    pub fn getProto(self: *const Stream) u8 {
        return self.proto;
    }

    /// Get stream metadata (from SYN payload).
    /// Returns empty slice if no metadata was specified.
    pub fn getMetadata(self: *const Stream) []const u8 {
        return self.metadata;
    }

    /// Get stream state.
    pub fn getState(self: *const Stream) StreamState {
        return self.state.load(.seq_cst);
    }

    /// Write data to the stream.
    pub fn write(self: *Stream, data: []const u8) StreamError!usize {
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
            k.flush();
            return data.len;
        }

        return StreamError.KcpSendFailed;
    }

    /// Flush pending data.
    pub fn flush(self: *Stream) StreamError!void {
        self.kcp_mutex.lock();
        defer self.kcp_mutex.unlock();

        if (self.kcp_instance) |*k| {
            k.flush();
        }
    }

    /// Read data from the stream (non-blocking).
    /// Returns 0 if no data available or EOF.
    pub fn read(self: *Stream, buffer: []u8) StreamError!usize {
        self.recv_mutex.lock();
        defer self.recv_mutex.unlock();

        if (self.recv_buf.readableLength() == 0) {
            const current_state = self.state.load(.seq_cst);
            if (current_state == .closed or current_state == .remote_close) {
                return 0; // EOF
            }
            return 0; // No data available
        }

        return self.recv_buf.read(buffer);
    }

    /// Read data from the stream (blocking).
    /// Blocks until data is available, EOF, or timeout.
    pub fn readBlocking(self: *Stream, buffer: []u8, timeout_ns: ?u64) StreamError!usize {
        self.recv_mutex.lock();
        defer self.recv_mutex.unlock();

        // Wait for data if buffer is empty
        while (self.recv_buf.readableLength() == 0) {
            const current_state = self.state.load(.seq_cst);
            if (current_state == .closed or current_state == .remote_close) {
                return 0; // EOF
            }

            if (timeout_ns) |ns| {
                self.data_available.timedWait(&self.recv_mutex, ns) catch {
                    // Timeout
                    return 0;
                };
            } else {
                self.data_available.wait(&self.recv_mutex);
            }
        }

        return self.recv_buf.read(buffer);
    }

    /// Shutdown write side.
    pub fn shutdown(self: *Stream) void {
        const current_state = self.state.load(.seq_cst);
        if (current_state == .closed or current_state == .local_close) return;

        const should_send_fin = current_state == .open;

        if (current_state == .open) {
            self.state.store(.local_close, .seq_cst);
        } else {
            self.state.store(.closed, .seq_cst);
        }

        if (should_send_fin) {
            self.send_frame_fn(self.mux_ptr, .fin, self.id, &[_]u8{}) catch {};
        }
    }

    /// Input data from KCP.
    pub fn kcpInput(self: *Stream, data: []const u8) void {
        if (self.state.load(.seq_cst) == .closed) return;

        self.kcp_mutex.lock();
        defer self.kcp_mutex.unlock();

        if (self.kcp_instance) |*k| {
            _ = k.input(data);
        }
    }

    /// Receive from KCP and buffer.
    pub fn kcpRecv(self: *Stream) bool {
        var received = false;
        var stack_buf: [1500]u8 = undefined;
        var heap_buf: ?[]u8 = null;
        defer if (heap_buf) |buf| self.allocator.free(buf);

        while (true) {
            self.kcp_mutex.lock();
            const size = if (self.kcp_instance) |*k| k.peekSize() else -1;
            if (size <= 0) {
                self.kcp_mutex.unlock();
                break;
            }

            const usize_size: usize = @intCast(size);
            var data_slice: []u8 = undefined;

            if (usize_size <= stack_buf.len) {
                const n = if (self.kcp_instance) |*k| k.recv(stack_buf[0..usize_size]) else -1;
                self.kcp_mutex.unlock();
                if (n <= 0) break;
                data_slice = stack_buf[0..@intCast(n)];
            } else {
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

            self.recv_mutex.lock();
            const current_size = self.recv_buf.readableLength();
            if (current_size + data_slice.len > self.max_receive_buffer) {
                self.recv_mutex.unlock();
                break;
            }
            self.recv_buf.write(data_slice) catch {
                self.recv_mutex.unlock();
                break;
            };
            // Signal waiting readers that data is available
            self.data_available.signal();
            self.recv_mutex.unlock();
            received = true;
        }

        return received;
    }

    /// Update KCP state.
    pub fn kcpUpdate(self: *Stream, current: u32) void {
        if (self.state.load(.seq_cst) == .closed) return;

        self.kcp_mutex.lock();
        defer self.kcp_mutex.unlock();

        if (self.kcp_instance) |*k| {
            k.update(current);
        }
    }

    /// Handle FIN from remote.
    pub fn handleFin(self: *Stream) void {
        const current_state = self.state.load(.seq_cst);
        if (current_state == .local_close) {
            self.state.store(.closed, .seq_cst);
        } else if (current_state == .open) {
            self.state.store(.remote_close, .seq_cst);
        }
        // Wake up any blocked readers
        self.data_available.broadcast();
    }

    /// KCP output callback.
    fn kcpOutput(data: []const u8, user: ?*anyopaque) void {
        if (user) |u| {
            const stream: *Stream = @ptrCast(@alignCast(u));
            stream.send_frame_fn(stream.mux_ptr, .psh, stream.id, data) catch |err| {
                stream.output_error.store(true, .seq_cst);
                std.log.err("Stream {d} output error: {s}", .{ stream.id, @errorName(err) });
            };
        }
    }
};

/// Mux multiplexes streams over a single connection.
/// Uses comptime generics for zero-cost timer scheduling.
pub fn Mux(comptime TimerServiceT: type) type {
    // Compile-time check for TimerService interface
    comptime {
        concepts.assertTimerService(TimerServiceT);
    }

    return struct {
        const Self = @This();

        config: MuxConfig,
        timer_service: *TimerServiceT,
        output_fn: OutputFn,
        on_new_stream: OnNewStreamFn,
        user_data: ?*anyopaque,
        is_client: bool,
        streams: std.AutoHashMap(u32, *Stream),
        next_id: u32,
        closed: std.atomic.Value(bool),
        allocator: std.mem.Allocator,
        mutex: std.Thread.Mutex,
        update_handle: TimerHandle,
        ref_count: std.atomic.Value(u32),

        // Accept channel for incoming streams
        accept_chan: ?*Channel(*Stream),

        /// Initialize a new Mux.
        pub fn init(
            allocator: std.mem.Allocator,
            timer_service: *TimerServiceT,
            config: MuxConfig,
            is_client: bool,
            output_fn: OutputFn,
            on_new_stream: OnNewStreamFn,
            user_data: ?*anyopaque,
        ) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            // Create accept channel on heap
            const accept_chan = try allocator.create(Channel(*Stream));
            errdefer allocator.destroy(accept_chan);
            accept_chan.* = try Channel(*Stream).init(allocator, 16);

            self.* = Self{
                .config = config,
                .timer_service = timer_service,
                .output_fn = output_fn,
                .on_new_stream = on_new_stream,
                .user_data = user_data,
                .is_client = is_client,
                .streams = std.AutoHashMap(u32, *Stream).init(allocator),
                .next_id = if (is_client) 1 else 2,
                .closed = std.atomic.Value(bool).init(false),
                .allocator = allocator,
                .mutex = .{},
                .update_handle = TimerHandle.null_handle,
                .ref_count = std.atomic.Value(u32).init(1),
                .accept_chan = accept_chan,
            };

            // Schedule first KCP update
            self.scheduleUpdate();

            return self;
        }

        /// Schedule the next KCP update.
        fn scheduleUpdate(self: *Self) void {
            if (self.closed.load(.acquire)) return;

            self.update_handle = self.timer_service.schedule(
                self.config.update_interval_ms,
                Task.init(Self, self, doUpdate),
            );
        }

        /// KCP update task (called by timer).
        fn doUpdate(self: *Self) void {
            if (self.closed.load(.acquire)) return;

            const current: u32 = @intCast(@mod(std.time.milliTimestamp(), std.math.maxInt(u32)));

            // Collect all streams with dynamic array to avoid missing any
            var stream_list: std.ArrayListUnmanaged(*Stream) = .{};
            defer stream_list.deinit(self.allocator);

            self.mutex.lock();
            var iter = self.streams.valueIterator();
            while (iter.next()) |stream_ptr| {
                stream_list.append(self.allocator, stream_ptr.*) catch {
                    // On OOM, update what we have so far
                    break;
                };
            }
            self.mutex.unlock();

            // Update outside lock
            for (stream_list.items) |stream| {
                stream.kcpUpdate(current);
                _ = stream.kcpRecv();
            }

            // Schedule next update
            self.scheduleUpdate();
        }

        /// Retain reference.
        pub fn retain(self: *Self) void {
            _ = self.ref_count.fetchAdd(1, .seq_cst);
        }

        /// Release reference.
        pub fn release(self: *Self) bool {
            const old = self.ref_count.fetchSub(1, .seq_cst);
            if (old == 1) {
                self.deinitInternal();
                return true;
            }
            return false;
        }

        /// Close the Mux.
        pub fn deinit(self: *Self) void {
            self.closed.store(true, .release);

            // Cancel timer
            self.timer_service.cancel(self.update_handle);

            // Close accept channel
            if (self.accept_chan) |ch| {
                ch.close();
                ch.deinit();
                self.allocator.destroy(ch);
            }

            // Release all streams
            self.mutex.lock();
            var iter = self.streams.valueIterator();
            while (iter.next()) |stream_ptr| {
                stream_ptr.*.state.store(.closed, .seq_cst);
                _ = stream_ptr.*.release();
            }
            self.streams.deinit();
            self.mutex.unlock();

            _ = self.release();
        }

        fn deinitInternal(self: *Self) void {
            self.allocator.destroy(self);
        }

        /// Check if closed.
        pub fn isClosed(self: *Self) bool {
            return self.closed.load(.acquire);
        }

        /// Open a new stream with protocol type and metadata.
        /// The proto and metadata are sent in the SYN frame payload so the remote
        /// side can identify the stream type upon acceptance.
        /// Use proto=0 (RAW) and metadata=&.{} for untyped streams.
        pub fn openStream(self: *Self, proto: u8, metadata: []const u8) MuxError!*Stream {
            if (self.closed.load(.acquire)) return MuxError.MuxClosed;

            self.mutex.lock();
            defer self.mutex.unlock();

            const id = self.next_id;
            self.next_id += 2;

            const stream = Stream.init(
                self.allocator,
                id,
                proto,
                metadata,
                self,
                sendFrameWrapper,
                self.config.max_receive_buffer,
            ) catch return MuxError.OutOfMemory;

            self.streams.put(id, stream) catch {
                _ = stream.release();
                return MuxError.OutOfMemory;
            };

            // Send SYN with proto + metadata as payload
            const syn_payload = if (proto != 0 or metadata.len > 0) blk: {
                const total = std.math.add(usize, 1, metadata.len) catch return MuxError.OutOfMemory;
                const buf = self.allocator.alloc(u8, total) catch return MuxError.OutOfMemory;
                buf[0] = proto;
                if (metadata.len > 0) {
                    @memcpy(buf[1..], metadata);
                }
                break :blk buf;
            } else &[_]u8{};
            defer if (proto != 0 or metadata.len > 0) self.allocator.free(syn_payload);

            self.sendFrameInternal(.syn, id, syn_payload) catch {
                _ = self.streams.remove(id);
                _ = stream.release();
                return MuxError.OutOfMemory;
            };

            stream.retain(); // User's reference
            return stream;
        }

        /// Accept an incoming stream (blocks until available or closed).
        pub fn acceptStream(self: *Self) ?*Stream {
            if (self.accept_chan) |ch| {
                return ch.recv();
            }
            return null;
        }

        /// Try to accept a stream without blocking.
        pub fn tryAcceptStream(self: *Self) ?*Stream {
            if (self.accept_chan) |ch| {
                return ch.tryRecv();
            }
            return null;
        }

        /// Input a frame from the network.
        pub fn input(self: *Self, data: []const u8) MuxError!void {
            if (self.closed.load(.acquire)) return MuxError.MuxClosed;

            const frame = kcp.Frame.decode(data) catch return MuxError.InvalidFrame;

            self.mutex.lock();
            defer self.mutex.unlock();

            switch (frame.cmd) {
                .syn => self.handleSynWithPayload(frame.stream_id, frame.payload),
                .fin => self.handleFin(frame.stream_id),
                .psh => self.handlePsh(frame.stream_id, frame.payload),
                .nop => {},
            }
        }

        fn handleSynWithPayload(self: *Self, id: u32, payload: []const u8) void {
            if (self.streams.contains(id)) return;

            // Parse proto + metadata from SYN payload
            const proto: u8 = if (payload.len >= 1) payload[0] else 0;
            const metadata: []const u8 = if (payload.len > 1) payload[1..] else &[_]u8{};

            const stream = Stream.init(
                self.allocator,
                id,
                proto,
                metadata,
                self,
                sendFrameWrapper,
                self.config.max_receive_buffer,
            ) catch return;

            self.streams.put(id, stream) catch {
                _ = stream.release();
                return;
            };

            // Push to accept channel
            if (self.accept_chan) |ch| {
                stream.retain(); // Reference for accept channel
                if (!ch.trySend(stream)) {
                    _ = stream.release(); // Channel full
                }
            }

            // Also call callback
            self.mutex.unlock();
            self.on_new_stream(stream, self.user_data);
            self.mutex.lock();
        }

        fn handleFin(self: *Self, id: u32) void {
            if (self.streams.get(id)) |stream| {
                stream.handleFin();
            }
        }

        fn handlePsh(self: *Self, id: u32, payload: []const u8) void {
            const stream = self.streams.get(id) orelse return;
            stream.retain();

            self.mutex.unlock();
            stream.kcpInput(payload);
            _ = stream.kcpRecv();
            _ = stream.release();
            self.mutex.lock();
        }

        /// Send a frame (called from Stream).
        fn sendFrameWrapper(mux_ptr: *anyopaque, cmd: kcp.Cmd, stream_id: u32, payload: []const u8) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(mux_ptr));
            try self.sendFrameInternal(cmd, stream_id, payload);
        }

        fn sendFrameInternal(self: *Self, cmd: kcp.Cmd, stream_id: u32, payload: []const u8) !void {
            if (self.closed.load(.acquire)) return MuxError.MuxClosed;

            const frame = kcp.Frame{
                .cmd = cmd,
                .stream_id = stream_id,
                .payload = payload,
            };

            const required_size = kcp.FrameHeaderSize + payload.len;
            var stack_buf: [1500]u8 = undefined;

            if (required_size <= stack_buf.len) {
                const encoded = try frame.encode(&stack_buf);
                try self.output_fn(encoded, self.user_data);
            } else {
                const buf = try self.allocator.alloc(u8, required_size);
                defer self.allocator.free(buf);
                const encoded = try frame.encode(buf);
                try self.output_fn(encoded, self.user_data);
            }
        }

        /// Remove a stream.
        pub fn removeStream(self: *Self, id: u32) void {
            self.mutex.lock();
            const maybe_stream = self.streams.fetchRemove(id);
            self.mutex.unlock();

            if (maybe_stream) |kv| {
                _ = kv.value.release();
            }
        }

        /// Get stream count.
        pub fn numStreams(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.streams.count();
        }
    };
}

// Convenience type alias for common timer service
pub const SimpleMux = Mux(async_mod.SimpleTimerService);

// ============================================================================
// Tests
// ============================================================================

test "Mux comptime check" {
    // Just verify the type compiles
    const MuxType = Mux(async_mod.SimpleTimerService);
    _ = MuxType;
}

test "Stream init deinit" {
    const allocator = std.testing.allocator;

    const DummyMux = struct {
        fn sendFrame(_: *anyopaque, _: kcp.Cmd, _: u32, _: []const u8) anyerror!void {}
    };

    var dummy: u8 = 0;
    const stream = try Stream.init(allocator, 1, 0, &[_]u8{}, &dummy, DummyMux.sendFrame, 256 * 1024);
    defer _ = stream.release();

    try std.testing.expectEqual(@as(u32, 1), stream.getId());
    try std.testing.expectEqual(@as(u8, 0), stream.getProto());
    try std.testing.expectEqual(@as(usize, 0), stream.getMetadata().len);
    try std.testing.expectEqual(StreamState.open, stream.getState());
}
