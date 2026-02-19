//! Listener API — Handler Registry, Stream Header, and Listener SDK.
//!
//! The registry maps proto bytes to handler information. When zgrnetd
//! receives a KCP stream, it looks up the proto and routes accordingly.
//!
//! Stream Header wire format:
//!   [pubkey: 32B][proto: 1B][metadata_len: 2B big-endian][metadata: NB]

const std = @import("std");
const mem = std.mem;

/// Handler mode — stream (KCP) or dgram (raw UDP).
pub const Mode = enum {
    stream,
    dgram,
};

/// Maximum number of registered handlers.
pub const max_handlers = 256;

/// Registered protocol handler.
pub const Handler = struct {
    proto: u8,
    name: [64]u8,
    name_len: usize,
    mode: Mode,
    sock: [256]u8,
    sock_len: usize,
    active: std.atomic.Value(i64),

    pub fn getName(self: *const Handler) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn getSock(self: *const Handler) []const u8 {
        return self.sock[0..self.sock_len];
    }

    pub fn addActive(self: *Handler, delta: i64) void {
        _ = self.active.fetchAdd(delta, .monotonic);
    }

    pub fn getActive(self: *const Handler) i64 {
        return self.active.load(.monotonic);
    }
};

/// Handler Registry — maps proto bytes to handlers.
/// Fixed-size, no allocator needed. Direct [256] array lookup by proto.
pub const Registry = struct {
    handlers: [256]?Handler,
    count: usize,

    pub fn init() Registry {
        return .{
            .handlers = .{null} ** 256,
            .count = 0,
        };
    }

    pub fn register(
        self: *Registry,
        proto: u8,
        name: []const u8,
        mode: Mode,
        sock_dir: []const u8,
    ) !*Handler {
        if (self.handlers[proto] != null) return error.ProtoRegistered;

        var h = Handler{
            .proto = proto,
            .name = undefined,
            .name_len = @min(name.len, 64),
            .mode = mode,
            .sock = undefined,
            .sock_len = 0,
            .active = std.atomic.Value(i64).init(0),
        };
        @memcpy(h.name[0..h.name_len], name[0..h.name_len]);

        // Build socket path: sock_dir/name.sock
        var buf: [256]u8 = undefined;
        const sock_path = std.fmt.bufPrint(&buf, "{s}/{s}.sock", .{ sock_dir, name }) catch {
            return error.NameTooLong;
        };
        h.sock_len = sock_path.len;
        @memcpy(h.sock[0..h.sock_len], sock_path);

        self.handlers[proto] = h;
        self.count += 1;
        return &(self.handlers[proto].?);
    }

    pub fn unregister(self: *Registry, proto: u8) void {
        if (self.handlers[proto] != null) {
            self.handlers[proto] = null;
            self.count -= 1;
        }
    }

    pub fn lookup(self: *const Registry, proto: u8) ?*const Handler {
        if (self.handlers[proto]) |*h| {
            return h;
        }
        return null;
    }
};

// ════════════════════════════════════════════════════════════════════════
// Stream Header
// ════════════════════════════════════════════════════════════════════════

/// Minimum header size: 32 (pubkey) + 1 (proto) + 2 (metadata_len).
pub const stream_header_size: usize = 35;

/// Parsed stream header.
pub const StreamMeta = struct {
    remote_pubkey: [32]u8,
    proto: u8,
    metadata: []const u8,
};

/// Writes a stream header to the buffer. Returns total bytes written.
pub fn writeStreamHeader(
    buf: []u8,
    pubkey: *const [32]u8,
    proto: u8,
    metadata: []const u8,
) !usize {
    const total = stream_header_size + metadata.len;
    if (buf.len < total) return error.BufferTooSmall;

    @memcpy(buf[0..32], pubkey);
    buf[32] = proto;
    buf[33] = @intCast(metadata.len >> 8);
    buf[34] = @intCast(metadata.len & 0xff);
    if (metadata.len > 0) {
        @memcpy(buf[35..total], metadata);
    }
    return total;
}

/// Reads a stream header from the buffer. Returns StreamMeta.
pub fn readStreamHeader(buf: []const u8) !StreamMeta {
    if (buf.len < stream_header_size) return error.BufferTooSmall;

    var pubkey: [32]u8 = undefined;
    @memcpy(&pubkey, buf[0..32]);

    const proto = buf[32];
    const meta_len: usize = (@as(usize, buf[33]) << 8) | @as(usize, buf[34]);
    const total = stream_header_size + meta_len;

    if (buf.len < total) return error.BufferTooSmall;

    return StreamMeta{
        .remote_pubkey = pubkey,
        .proto = proto,
        .metadata = buf[35..total],
    };
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

test "registry register and lookup" {
    var r = Registry.init();
    _ = try r.register(69, "proxy", .stream, "/tmp/handlers");
    const h = r.lookup(69);
    try std.testing.expect(h != null);
    try std.testing.expectEqual(@as(u8, 69), h.?.proto);
    try std.testing.expect(r.lookup(70) == null);
}

test "registry duplicate proto" {
    var r = Registry.init();
    _ = try r.register(69, "proxy", .stream, "/tmp");
    try std.testing.expectError(error.ProtoRegistered, r.register(69, "proxy2", .stream, "/tmp"));
}

test "registry unregister" {
    var r = Registry.init();
    _ = try r.register(69, "proxy", .stream, "/tmp");
    r.unregister(69);
    try std.testing.expect(r.lookup(69) == null);
}

test "stream header roundtrip" {
    const pubkey = [_]u8{0x42} ** 32;
    const metadata = "hello world";
    var buf: [256]u8 = undefined;

    const n = try writeStreamHeader(&buf, &pubkey, 69, metadata);
    try std.testing.expectEqual(stream_header_size + metadata.len, n);

    const meta = try readStreamHeader(buf[0..n]);
    try std.testing.expectEqual(@as(u8, 69), meta.proto);
    try std.testing.expectEqualSlices(u8, &pubkey, &meta.remote_pubkey);
    try std.testing.expectEqualSlices(u8, metadata, meta.metadata);
}

test "stream header empty metadata" {
    const pubkey = [_]u8{0x01} ** 32;
    var buf: [64]u8 = undefined;

    const n = try writeStreamHeader(&buf, &pubkey, 128, &.{});
    try std.testing.expectEqual(stream_header_size, n);

    const meta = try readStreamHeader(buf[0..n]);
    try std.testing.expectEqual(@as(u8, 128), meta.proto);
    try std.testing.expectEqual(@as(usize, 0), meta.metadata.len);
}
