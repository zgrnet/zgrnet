//! KCP - A Fast and Reliable ARQ Protocol
//! Zig bindings for the KCP C library.

const std = @import("std");
const c = @cImport({
    @cInclude("ikcp.h");
});

/// KCP control block wrapper
pub const Kcp = struct {
    kcp: *c.ikcpcb,
    output_fn: ?*const fn ([]const u8, ?*anyopaque) void,
    user_data: ?*anyopaque,

    /// Create a new KCP control block (stack-allocated, requires manual setUserPtr call).
    /// conv: Connection ID (must be the same on both sides)
    /// NOTE: Prefer using `create()` for heap allocation with automatic user pointer setup.
    pub fn init(conv: u32, output_fn: ?*const fn ([]const u8, ?*anyopaque) void, user_data: ?*anyopaque) !Kcp {
        var self = Kcp{
            .kcp = undefined,
            .output_fn = output_fn,
            .user_data = user_data,
        };

        const kcp = c.ikcp_create(conv, null) orelse return error.KcpCreateFailed;
        self.kcp = kcp;

        // Set output callback
        _ = c.ikcp_setoutput(kcp, kcpOutputCallback);

        return self;
    }

    /// Create a heap-allocated KCP instance with user pointer automatically set.
    /// This is the preferred factory function as it ensures correct initialization in one step.
    pub fn create(allocator: std.mem.Allocator, conv: u32, output_fn: ?*const fn ([]const u8, ?*anyopaque) void, user_data: ?*anyopaque) !*Kcp {
        const self = try allocator.create(Kcp);
        errdefer allocator.destroy(self);

        self.* = Kcp{
            .kcp = undefined,
            .output_fn = output_fn,
            .user_data = user_data,
        };

        const kcp = c.ikcp_create(conv, null) orelse return error.KcpCreateFailed;
        self.kcp = kcp;

        // Set output callback and user pointer in one atomic step
        _ = c.ikcp_setoutput(kcp, kcpOutputCallback);
        self.kcp.*.user = @ptrCast(self);

        return self;
    }

    /// Set the user pointer for callbacks. Must be called after init if you need
    /// the callback to access this Kcp instance.
    /// NOTE: Not needed if using create() factory function.
    pub fn setUserPtr(self: *Kcp) void {
        self.kcp.*.user = @ptrCast(self);
    }

    /// Release the KCP control block.
    pub fn deinit(self: *Kcp) void {
        c.ikcp_release(self.kcp);
        self.* = undefined;
    }

    /// Set nodelay mode for fast transmission.
    /// nodelay: 0 = disable, 1 = enable
    /// interval: Internal update interval in ms (10-100ms recommended)
    /// resend: Fast resend trigger (0 = disable, 2 = recommended)
    /// nc: Disable congestion control (0 = enable, 1 = disable)
    pub fn setNodelay(self: *Kcp, nodelay: i32, interval: i32, resend: i32, nc: i32) void {
        _ = c.ikcp_nodelay(self.kcp, nodelay, interval, resend, nc);
    }

    /// Set window size.
    /// sndwnd: Send window size
    /// rcvwnd: Receive window size
    pub fn setWndSize(self: *Kcp, sndwnd: i32, rcvwnd: i32) void {
        _ = c.ikcp_wndsize(self.kcp, sndwnd, rcvwnd);
    }

    /// Set MTU (Maximum Transmission Unit).
    pub fn setMtu(self: *Kcp, mtu: i32) void {
        _ = c.ikcp_setmtu(self.kcp, mtu);
    }

    /// Apply default fast mode configuration.
    /// Matches Go/Rust settings for optimal throughput.
    pub fn setDefaultConfig(self: *Kcp) void {
        self.setNodelay(1, 1, 2, 1); // Fast mode with 1ms interval (same as Go/Rust)
        self.setWndSize(4096, 4096); // Large window for high throughput (same as Go/Rust)
        self.setMtu(1400);
    }

    /// Send data through KCP.
    /// Returns number of bytes queued, or negative on error.
    pub fn send(self: *Kcp, data: []const u8) i32 {
        return c.ikcp_send(self.kcp, data.ptr, @intCast(data.len));
    }

    /// Receive data from KCP.
    /// Returns number of bytes received, or negative if no data available.
    pub fn recv(self: *Kcp, buffer: []u8) i32 {
        return c.ikcp_recv(self.kcp, buffer.ptr, @intCast(buffer.len));
    }

    /// Input data from lower layer (e.g., UDP).
    /// Returns 0 on success, negative on error.
    pub fn input(self: *Kcp, data: []const u8) i32 {
        return c.ikcp_input(self.kcp, data.ptr, @intCast(data.len));
    }

    /// Update KCP state. Should be called periodically.
    /// current: Current time in milliseconds.
    pub fn update(self: *Kcp, current: u32) void {
        c.ikcp_update(self.kcp, current);
    }

    /// Check when to call update next.
    /// Returns next update time in milliseconds.
    pub fn check(self: *Kcp, current: u32) u32 {
        return c.ikcp_check(self.kcp, current);
    }

    /// Flush pending data immediately.
    pub fn flush(self: *Kcp) void {
        c.ikcp_flush(self.kcp);
    }

    /// Get number of bytes waiting to be sent.
    pub fn waitSnd(self: *Kcp) i32 {
        return c.ikcp_waitsnd(self.kcp);
    }

    /// Peek at the size of the next available message.
    /// Returns size in bytes, or negative if no message available.
    pub fn peekSize(self: *Kcp) i32 {
        return c.ikcp_peeksize(self.kcp);
    }

    /// Get the connection ID.
    pub fn getConv(self: *const Kcp) u32 {
        return self.kcp.*.conv;
    }

    /// KCP output callback (called by C library)
    fn kcpOutputCallback(buf: [*c]const u8, len: c_int, kcp_ptr: [*c]c.ikcpcb, user: ?*anyopaque) callconv(.c) c_int {
        _ = kcp_ptr;
        if (user) |u| {
            const self: *Kcp = @ptrCast(@alignCast(u));
            if (self.output_fn) |output| {
                const data = buf[0..@intCast(len)];
                output(data, self.user_data);
            }
        }
        return 0;
    }
};

/// Frame command types for multiplexing
pub const Cmd = enum(u8) {
    syn = 0x01, // Stream open
    fin = 0x02, // Stream close
    psh = 0x03, // Data
    nop = 0x04, // Keepalive

    pub fn fromByte(byte: u8) ?Cmd {
        return switch (byte) {
            0x01 => .syn,
            0x02 => .fin,
            0x03 => .psh,
            0x04 => .nop,
            else => null,
        };
    }
};

/// Frame header size: cmd(1) + stream_id(4) + length(2) = 7 bytes
pub const FrameHeaderSize: usize = 7;

/// Maximum payload size
pub const MaxPayloadSize: usize = 65535;

/// Frame represents a multiplexed stream frame.
pub const Frame = struct {
    cmd: Cmd,
    stream_id: u32,
    payload: []const u8,

    /// Encode frame to bytes.
    pub fn encode(self: *const Frame, buffer: []u8) ![]u8 {
        const total_len = FrameHeaderSize + self.payload.len;
        if (buffer.len < total_len) return error.BufferTooSmall;
        if (self.payload.len > MaxPayloadSize) return error.PayloadTooLarge;

        buffer[0] = @intFromEnum(self.cmd);
        std.mem.writeInt(u32, buffer[1..5], self.stream_id, .little);
        std.mem.writeInt(u16, buffer[5..7], @intCast(self.payload.len), .little);

        if (self.payload.len > 0) {
            @memcpy(buffer[FrameHeaderSize..][0..self.payload.len], self.payload);
        }

        return buffer[0..total_len];
    }

    /// Encode frame and return allocated slice.
    pub fn encodeAlloc(self: *const Frame, allocator: std.mem.Allocator) ![]u8 {
        const total_len = FrameHeaderSize + self.payload.len;
        const buffer = try allocator.alloc(u8, total_len);
        errdefer allocator.free(buffer);

        _ = try self.encode(buffer);
        return buffer;
    }

    /// Decode frame from bytes.
    pub fn decode(data: []const u8) !Frame {
        if (data.len < FrameHeaderSize) return error.FrameTooShort;

        const cmd = Cmd.fromByte(data[0]) orelse return error.InvalidCmd;
        const stream_id = std.mem.readInt(u32, data[1..5], .little);
        const payload_len = std.mem.readInt(u16, data[5..7], .little);

        if (data.len < FrameHeaderSize + payload_len) return error.FrameTooShort;

        return Frame{
            .cmd = cmd,
            .stream_id = stream_id,
            .payload = data[FrameHeaderSize..][0..payload_len],
        };
    }

    /// Decode only the header, returning cmd, stream_id, and payload length.
    pub fn decodeHeader(data: []const u8) !struct { cmd: Cmd, stream_id: u32, payload_len: u16 } {
        if (data.len < FrameHeaderSize) return error.FrameTooShort;

        const cmd = Cmd.fromByte(data[0]) orelse return error.InvalidCmd;
        const stream_id = std.mem.readInt(u32, data[1..5], .little);
        const payload_len = std.mem.readInt(u16, data[5..7], .little);

        return .{
            .cmd = cmd,
            .stream_id = stream_id,
            .payload_len = payload_len,
        };
    }
};

// Tests
test "Kcp basic" {
    var kcp_inst = try Kcp.init(123, null, null);
    defer kcp_inst.deinit();

    kcp_inst.setUserPtr();
    kcp_inst.setDefaultConfig();

    try std.testing.expectEqual(@as(u32, 123), kcp_inst.getConv());
    try std.testing.expectEqual(@as(i32, 0), kcp_inst.waitSnd());
}

test "Kcp two instances" {
    // Create two KCP instances
    var kcp_a = try Kcp.init(1, null, null);
    defer kcp_a.deinit();
    
    var kcp_b = try Kcp.init(1, null, null);
    defer kcp_b.deinit();

    kcp_a.setDefaultConfig();
    kcp_b.setDefaultConfig();

    // Test init/deinit
    try std.testing.expectEqual(@as(i32, 0), kcp_a.waitSnd());
    try std.testing.expectEqual(@as(i32, 0), kcp_b.waitSnd());
}

test "Kcp raw create release" {
    // Test raw C API
    const kcp_ptr = c.ikcp_create(1, null);
    try std.testing.expect(kcp_ptr != null);
    
    // Just release without any operation
    c.ikcp_release(kcp_ptr);
}

test "Kcp raw with config" {
    // Test raw C API with config
    const kcp_ptr = c.ikcp_create(1, null);
    try std.testing.expect(kcp_ptr != null);
    
    _ = c.ikcp_nodelay(kcp_ptr, 1, 10, 2, 1);
    _ = c.ikcp_wndsize(kcp_ptr, 128, 128);
    _ = c.ikcp_setmtu(kcp_ptr, 1400);
    
    c.ikcp_release(kcp_ptr);
}

// Dummy output callback for tests
fn dummyOutput(_: [*c]const u8, _: c_int, _: [*c]c.ikcpcb, _: ?*anyopaque) callconv(.c) c_int {
    return 0;
}

test "Kcp send recv loopback" {
    // Simple test: send data, verify it queues
    const kcp_a = c.ikcp_create(1, null);
    defer c.ikcp_release(kcp_a);
    const kcp_b = c.ikcp_create(1, null);
    defer c.ikcp_release(kcp_b);

    // Configure both
    _ = c.ikcp_nodelay(kcp_a, 1, 10, 2, 1);
    _ = c.ikcp_wndsize(kcp_a, 128, 128);
    _ = c.ikcp_nodelay(kcp_b, 1, 10, 2, 1);
    _ = c.ikcp_wndsize(kcp_b, 128, 128);

    // Set dummy output to avoid null pointer
    _ = c.ikcp_setoutput(kcp_a, dummyOutput);
    _ = c.ikcp_setoutput(kcp_b, dummyOutput);

    // Send data from A
    const data = "hello world from kcp";
    const send_ret = c.ikcp_send(kcp_a, data.ptr, @intCast(data.len));
    try std.testing.expect(send_ret >= 0);

    // Update and flush A (now safe with dummy output)
    c.ikcp_update(kcp_a, 0);
    c.ikcp_flush(kcp_a);

    // Verify data is queued
    try std.testing.expect(c.ikcp_waitsnd(kcp_a) > 0);
}

// Static buffer for full roundtrip test
var roundtrip_buf: [8192]u8 = undefined;
var roundtrip_len: usize = 0;

fn roundtripOutput(buf: [*c]const u8, len: c_int, _: [*c]c.ikcpcb, _: ?*anyopaque) callconv(.c) c_int {
    const size: usize = @intCast(len);
    if (roundtrip_len + size <= roundtrip_buf.len) {
        @memcpy(roundtrip_buf[roundtrip_len..][0..size], buf[0..size]);
        roundtrip_len += size;
    }
    return 0;
}

test "Kcp full roundtrip" {
    // Reset buffer
    roundtrip_len = 0;

    // Create KCP instances
    const kcp_a = c.ikcp_create(1, null);
    defer c.ikcp_release(kcp_a);
    const kcp_b = c.ikcp_create(1, null);
    defer c.ikcp_release(kcp_b);

    // Configure
    _ = c.ikcp_nodelay(kcp_a, 1, 10, 2, 1);
    _ = c.ikcp_wndsize(kcp_a, 256, 256);
    _ = c.ikcp_nodelay(kcp_b, 1, 10, 2, 1);
    _ = c.ikcp_wndsize(kcp_b, 256, 256);

    // Set output callback for both (B needs one too for ACKs)
    _ = c.ikcp_setoutput(kcp_a, roundtripOutput);
    _ = c.ikcp_setoutput(kcp_b, dummyOutput);

    // Send data from A
    const data = "hello from A to B!";
    const send_ret = c.ikcp_send(kcp_a, data.ptr, @intCast(data.len));
    try std.testing.expect(send_ret >= 0);

    // Update A - this triggers output callback
    c.ikcp_update(kcp_a, 0);
    c.ikcp_flush(kcp_a);

    // Check that packets were captured
    try std.testing.expect(roundtrip_len > 0);

    // Feed packets to B
    const input_ret = c.ikcp_input(kcp_b, &roundtrip_buf, @intCast(roundtrip_len));
    try std.testing.expect(input_ret >= 0);

    // Update B
    c.ikcp_update(kcp_b, 0);

    // Receive on B
    var recv_buf: [1024]u8 = undefined;
    const recv_ret = c.ikcp_recv(kcp_b, &recv_buf, recv_buf.len);

    // Should receive the data
    try std.testing.expect(recv_ret > 0);
    const received = recv_buf[0..@intCast(recv_ret)];
    try std.testing.expectEqualStrings(data, received);
}

// Global buffers for KCP benchmark (static to avoid callback complexity)
var bench_net_a_to_b: [65536]u8 = undefined;
var bench_len_a_to_b: usize = 0;
var bench_net_b_to_a: [65536]u8 = undefined;
var bench_len_b_to_a: usize = 0;

fn benchOutputA(buf: [*c]const u8, len: c_int, _: [*c]c.ikcpcb, _: ?*anyopaque) callconv(.c) c_int {
    const size: usize = @intCast(len);
    if (bench_len_a_to_b + size <= bench_net_a_to_b.len) {
        @memcpy(bench_net_a_to_b[bench_len_a_to_b..][0..size], buf[0..size]);
        bench_len_a_to_b += size;
    }
    return 0;
}

fn benchOutputB(buf: [*c]const u8, len: c_int, _: [*c]c.ikcpcb, _: ?*anyopaque) callconv(.c) c_int {
    const size: usize = @intCast(len);
    if (bench_len_b_to_a + size <= bench_net_b_to_a.len) {
        @memcpy(bench_net_b_to_a[bench_len_b_to_a..][0..size], buf[0..size]);
        bench_len_b_to_a += size;
    }
    return 0;
}

test "benchmark Kcp send recv" {
    const iters: u64 = 10_000;
    const data = "benchmark data payload 1234567890";
    const data_size = data.len;

    const kcp_a = c.ikcp_create(1, null);
    defer c.ikcp_release(kcp_a);
    const kcp_b = c.ikcp_create(1, null);
    defer c.ikcp_release(kcp_b);

    _ = c.ikcp_nodelay(kcp_a, 1, 10, 2, 1);
    _ = c.ikcp_wndsize(kcp_a, 256, 256);
    _ = c.ikcp_nodelay(kcp_b, 1, 10, 2, 1);
    _ = c.ikcp_wndsize(kcp_b, 256, 256);

    _ = c.ikcp_setoutput(kcp_a, benchOutputA);
    _ = c.ikcp_setoutput(kcp_b, benchOutputB);

    var recv_buf: [1024]u8 = undefined;
    var current: u32 = 0;

    const start = std.time.Instant.now() catch unreachable;

    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        bench_len_a_to_b = 0;
        bench_len_b_to_a = 0;

        _ = c.ikcp_send(kcp_a, data.ptr, @intCast(data.len));
        c.ikcp_update(kcp_a, current);
        c.ikcp_flush(kcp_a);

        if (bench_len_a_to_b > 0) {
            _ = c.ikcp_input(kcp_b, &bench_net_a_to_b, @intCast(bench_len_a_to_b));
        }
        c.ikcp_update(kcp_b, current);

        if (bench_len_b_to_a > 0) {
            _ = c.ikcp_input(kcp_a, &bench_net_b_to_a, @intCast(bench_len_b_to_a));
        }

        _ = c.ikcp_recv(kcp_b, &recv_buf, recv_buf.len);
        current += 10;
    }

    const end = std.time.Instant.now() catch unreachable;
    const elapsed_ns = end.since(start);
    const us_per_op = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iters)) / 1000.0;
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1e9;
    const throughput_mbps = @as(f64, @floatFromInt(data_size * 8 * iters)) / elapsed_s / 1e6;
    std.debug.print("\nZig KCP send/recv: {d:.2} us/op, {d:.1} Mbps ({} bytes/msg)\n", .{ us_per_op, throughput_mbps, data_size });
}

test "Frame encode decode" {
    const allocator = std.testing.allocator;

    const frame = Frame{
        .cmd = .psh,
        .stream_id = 42,
        .payload = "hello",
    };

    const encoded = try frame.encodeAlloc(allocator);
    defer allocator.free(encoded);

    const decoded = try Frame.decode(encoded);

    try std.testing.expectEqual(Cmd.psh, decoded.cmd);
    try std.testing.expectEqual(@as(u32, 42), decoded.stream_id);
    try std.testing.expectEqualStrings("hello", decoded.payload);
}

test "Frame header decode" {
    var buffer: [7]u8 = undefined;
    const frame = Frame{
        .cmd = .syn,
        .stream_id = 100,
        .payload = "",
    };

    _ = try frame.encode(&buffer);
    const header = try Frame.decodeHeader(&buffer);

    try std.testing.expectEqual(Cmd.syn, header.cmd);
    try std.testing.expectEqual(@as(u32, 100), header.stream_id);
    try std.testing.expectEqual(@as(u16, 0), header.payload_len);
}

test "Cmd fromByte" {
    try std.testing.expectEqual(Cmd.syn, Cmd.fromByte(0x01).?);
    try std.testing.expectEqual(Cmd.fin, Cmd.fromByte(0x02).?);
    try std.testing.expectEqual(Cmd.psh, Cmd.fromByte(0x03).?);
    try std.testing.expectEqual(Cmd.nop, Cmd.fromByte(0x04).?);
    try std.testing.expect(Cmd.fromByte(0x05) == null);
    try std.testing.expect(Cmd.fromByte(0x00) == null);
    try std.testing.expect(Cmd.fromByte(0xFF) == null);
}

// Benchmarks
const bench_iterations: u64 = 10_000_000;

var sink: u64 = 0;

pub fn benchmarkFrameEncode() u64 {
    const payload = "hello world benchmark payload data";

    const start = std.time.nanoTimestamp();
    var checksum: u64 = 0;
    var i: u64 = 0;
    while (i < bench_iterations) : (i += 1) {
        const frame = Frame{
            .cmd = .psh,
            .stream_id = @truncate(i),
            .payload = payload,
        };
        var buf: [FrameHeaderSize + 64]u8 = undefined;
        const encoded = frame.encode(&buf) catch continue;
        // Use varying bytes (stream_id at offset 1-4) to prevent optimization
        checksum +%= encoded[1];
        checksum +%= encoded[2];
    }
    const end = std.time.nanoTimestamp();
    sink = checksum; // Prevent optimization
    return @intCast(@as(i128, end - start));
}

pub fn benchmarkFrameDecode() u64 {
    const payload = "hello world benchmark payload data";
    const frame = Frame{
        .cmd = .psh,
        .stream_id = 12345,
        .payload = payload,
    };
    var encoded_buf: [FrameHeaderSize + 64]u8 = undefined;
    const encoded = frame.encode(&encoded_buf) catch return 0;

    const start = std.time.nanoTimestamp();
    var checksum: u64 = 0;
    var i: u64 = 0;
    while (i < bench_iterations) : (i += 1) {
        const decoded = Frame.decode(encoded) catch continue;
        // Combine with loop counter to prevent constant folding
        checksum +%= decoded.stream_id +% i;
        checksum +%= decoded.payload.len;
    }
    const end = std.time.nanoTimestamp();
    sink = checksum; // Prevent optimization
    return @intCast(@as(i128, end - start));
}

var volatile_sink: u64 = 0;
var volatile_input: u32 = 12345;

test "benchmark Frame encode" {
    const payload = "hello world benchmark payload data";
    const frame_size = FrameHeaderSize + payload.len;
    const iters: usize = 10_000_000;

    var buf: [FrameHeaderSize + 64]u8 = undefined;

    // Pre-generate random stream_ids
    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
        break :blk seed;
    });
    const random = prng.random();

    var stream_ids: [1024]u32 = undefined;
    for (&stream_ids) |*sid| {
        sid.* = random.int(u32);
    }

    const start = std.time.Instant.now() catch unreachable;
    var checksum: u64 = 0;
    for (0..iters) |i| {
        const frame = Frame{
            .cmd = .psh,
            .stream_id = stream_ids[i % 1024],
            .payload = payload,
        };
        const encoded = frame.encode(&buf) catch unreachable;
        checksum +%= encoded[1];
    }
    const end = std.time.Instant.now() catch unreachable;

    volatile_sink = checksum;

    const elapsed_ns = end.since(start);
    const elapsed_ms = elapsed_ns / 1_000_000;
    const ns_per_op = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iters));
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1e9;
    const throughput_gbps = @as(f64, @floatFromInt(frame_size * 8 * iters)) / elapsed_s / 1e9;
    std.debug.print("\nZig Frame encode: {d:.1} ns/op, {d:.2} Gbps ({}ms, sum={})\n", .{ ns_per_op, throughput_gbps, elapsed_ms, checksum });
}

test "benchmark Frame decode header" {
    const payload = "hello world benchmark payload data";
    const frame = Frame{
        .cmd = .psh,
        .stream_id = 12345,
        .payload = payload,
    };
    var encoded_buf: [FrameHeaderSize + 64]u8 = undefined;
    const encoded = frame.encode(&encoded_buf) catch unreachable;
    const frame_size = encoded.len;
    const iters: u64 = 10_000_000;

    var sum: u64 = 0;
    const start = std.time.Instant.now() catch unreachable;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const header = Frame.decodeHeader(encoded) catch unreachable;
        sum +%= header.stream_id;
        // Force the read to happen
        @as(*volatile u64, @ptrCast(&sum)).* = sum;
    }
    const end = std.time.Instant.now() catch unreachable;

    volatile_sink = sum;

    const elapsed_ns = end.since(start);
    const ns_per_op = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iters));
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1e9;
    const throughput_gbps = @as(f64, @floatFromInt(frame_size * 8 * iters)) / elapsed_s / 1e9;
    std.debug.print("\nZig Frame decode_header: {d:.1} ns/op, {d:.2} Gbps ({} bytes/frame)\n", .{ ns_per_op, throughput_gbps, frame_size });
}
