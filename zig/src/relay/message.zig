//! Relay and PING/PONG message encoding/decoding.
//!
//! All encode/decode functions handle the message body AFTER the protocol
//! byte has been stripped by noise.decodePayload().

const std = @import("std");
const mem = std.mem;

/// Relay message header sizes (excluding protocol byte).
pub const relay0_header_size: usize = 1 + 1 + 32; // ttl + strategy + dst_key = 34
pub const relay1_header_size: usize = 1 + 1 + 32 + 32; // ttl + strategy + src_key + dst_key = 66
pub const relay2_header_size: usize = 32; // src_key = 32

/// Ping message size: ping_id(4) + timestamp(8) = 12
pub const ping_size: usize = 4 + 8;

/// Pong message size: ping_id(4) + timestamp(8) + load(1) + relay_count(2) + bw_avail(2) + price(4) = 21
pub const pong_size: usize = 4 + 8 + 1 + 2 + 2 + 4;

/// Default TTL for relay messages.
pub const default_ttl: u8 = 8;

/// Routing strategy preference.
pub const Strategy = enum(u8) {
    /// Relay node decides (default).
    auto = 0,
    /// Prefer lowest latency.
    fastest = 1,
    /// Prefer lowest cost.
    cheapest = 2,
    _,
};

/// Relay error type.
pub const RelayError = error{
    TooShort,
    TtlExpired,
    NoRoute,
};

/// RELAY_0 - first-hop relay message (protocol 66).
pub const Relay0 = struct {
    ttl: u8,
    strategy: Strategy,
    dst_key: [32]u8,
    payload: []const u8,
};

/// RELAY_1 - middle-hop relay message (protocol 67).
pub const Relay1 = struct {
    ttl: u8,
    strategy: Strategy,
    src_key: [32]u8,
    dst_key: [32]u8,
    payload: []const u8,
};

/// RELAY_2 - last-hop relay message (protocol 68).
pub const Relay2 = struct {
    src_key: [32]u8,
    payload: []const u8,
};

/// PING probe request (protocol 70).
pub const Ping = struct {
    ping_id: u32,
    timestamp: u64,
};

/// PONG probe response (protocol 71).
pub const Pong = struct {
    ping_id: u32,
    timestamp: u64,
    load: u8,
    relay_count: u16,
    bw_avail: u16,
    price: u32,
};

// ============================================================================
// Relay0
// ============================================================================

/// Encode a Relay0 message into buf. Returns the number of bytes written.
pub fn encodeRelay0(r: *const Relay0, buf: []u8) error{TooShort}!usize {
    const total = relay0_header_size + r.payload.len;
    if (buf.len < total) return error.TooShort;
    buf[0] = r.ttl;
    buf[1] = @intFromEnum(r.strategy);
    @memcpy(buf[2..34], &r.dst_key);
    if (r.payload.len > 0) {
        @memcpy(buf[34 .. 34 + r.payload.len], r.payload);
    }
    return total;
}

/// Decode a Relay0 message. Payload slice references the input data.
pub fn decodeRelay0(data: []const u8) error{TooShort}!Relay0 {
    if (data.len < relay0_header_size) return error.TooShort;
    return Relay0{
        .ttl = data[0],
        .strategy = @enumFromInt(data[1]),
        .dst_key = data[2..34].*,
        .payload = data[34..],
    };
}

// ============================================================================
// Relay1
// ============================================================================

/// Encode a Relay1 message into buf.
pub fn encodeRelay1(r: *const Relay1, buf: []u8) error{TooShort}!usize {
    const total = relay1_header_size + r.payload.len;
    if (buf.len < total) return error.TooShort;
    buf[0] = r.ttl;
    buf[1] = @intFromEnum(r.strategy);
    @memcpy(buf[2..34], &r.src_key);
    @memcpy(buf[34..66], &r.dst_key);
    if (r.payload.len > 0) {
        @memcpy(buf[66 .. 66 + r.payload.len], r.payload);
    }
    return total;
}

/// Decode a Relay1 message.
pub fn decodeRelay1(data: []const u8) error{TooShort}!Relay1 {
    if (data.len < relay1_header_size) return error.TooShort;
    return Relay1{
        .ttl = data[0],
        .strategy = @enumFromInt(data[1]),
        .src_key = data[2..34].*,
        .dst_key = data[34..66].*,
        .payload = data[66..],
    };
}

// ============================================================================
// Relay2
// ============================================================================

/// Encode a Relay2 message into buf.
pub fn encodeRelay2(r: *const Relay2, buf: []u8) error{TooShort}!usize {
    const total = relay2_header_size + r.payload.len;
    if (buf.len < total) return error.TooShort;
    @memcpy(buf[0..32], &r.src_key);
    if (r.payload.len > 0) {
        @memcpy(buf[32 .. 32 + r.payload.len], r.payload);
    }
    return total;
}

/// Decode a Relay2 message.
pub fn decodeRelay2(data: []const u8) error{TooShort}!Relay2 {
    if (data.len < relay2_header_size) return error.TooShort;
    return Relay2{
        .src_key = data[0..32].*,
        .payload = data[32..],
    };
}

// ============================================================================
// Ping
// ============================================================================

/// Encode a Ping message into buf.
pub fn encodePing(p: *const Ping, buf: []u8) error{TooShort}!usize {
    if (buf.len < ping_size) return error.TooShort;
    mem.writeInt(u32, buf[0..4], p.ping_id, .little);
    mem.writeInt(u64, buf[4..12], p.timestamp, .little);
    return ping_size;
}

/// Decode a Ping message.
pub fn decodePing(data: []const u8) error{TooShort}!Ping {
    if (data.len < ping_size) return error.TooShort;
    return Ping{
        .ping_id = mem.readInt(u32, data[0..4], .little),
        .timestamp = mem.readInt(u64, data[4..12], .little),
    };
}

// ============================================================================
// Pong
// ============================================================================

/// Encode a Pong message into buf.
pub fn encodePong(p: *const Pong, buf: []u8) error{TooShort}!usize {
    if (buf.len < pong_size) return error.TooShort;
    mem.writeInt(u32, buf[0..4], p.ping_id, .little);
    mem.writeInt(u64, buf[4..12], p.timestamp, .little);
    buf[12] = p.load;
    mem.writeInt(u16, buf[13..15], p.relay_count, .little);
    mem.writeInt(u16, buf[15..17], p.bw_avail, .little);
    mem.writeInt(u32, buf[17..21], p.price, .little);
    return pong_size;
}

/// Decode a Pong message.
pub fn decodePong(data: []const u8) error{TooShort}!Pong {
    if (data.len < pong_size) return error.TooShort;
    return Pong{
        .ping_id = mem.readInt(u32, data[0..4], .little),
        .timestamp = mem.readInt(u64, data[4..12], .little),
        .load = data[12],
        .relay_count = mem.readInt(u16, data[13..15], .little),
        .bw_avail = mem.readInt(u16, data[15..17], .little),
        .price = mem.readInt(u32, data[17..21], .little),
    };
}

// ============================================================================
// Tests
// ============================================================================

test "relay0 roundtrip" {
    var dst_key: [32]u8 = undefined;
    for (0..32) |i| {
        dst_key[i] = @intCast(i);
    }
    const payload = "hello relay world";

    const orig = Relay0{ .ttl = 8, .strategy = .fastest, .dst_key = dst_key, .payload = payload };
    var buf: [256]u8 = undefined;
    const n = try encodeRelay0(&orig, &buf);
    try std.testing.expectEqual(relay0_header_size + payload.len, n);

    const decoded = try decodeRelay0(buf[0..n]);
    try std.testing.expectEqual(@as(u8, 8), decoded.ttl);
    try std.testing.expectEqual(Strategy.fastest, decoded.strategy);
    try std.testing.expectEqualSlices(u8, &dst_key, &decoded.dst_key);
    try std.testing.expectEqualStrings(payload, decoded.payload);
}

test "relay0 too short" {
    var short: [relay0_header_size - 1]u8 = undefined;
    try std.testing.expectError(error.TooShort, decodeRelay0(&short));
}

test "relay1 roundtrip" {
    var src_key: [32]u8 = undefined;
    var dst_key: [32]u8 = undefined;
    for (0..32) |i| {
        src_key[i] = @intCast(i);
        dst_key[i] = @intCast(i + 100);
    }
    const payload = "relay1 payload";

    const orig = Relay1{ .ttl = 7, .strategy = .cheapest, .src_key = src_key, .dst_key = dst_key, .payload = payload };
    var buf: [256]u8 = undefined;
    const n = try encodeRelay1(&orig, &buf);
    try std.testing.expectEqual(relay1_header_size + payload.len, n);

    const decoded = try decodeRelay1(buf[0..n]);
    try std.testing.expectEqual(@as(u8, 7), decoded.ttl);
    try std.testing.expectEqual(Strategy.cheapest, decoded.strategy);
    try std.testing.expectEqualSlices(u8, &src_key, &decoded.src_key);
    try std.testing.expectEqualSlices(u8, &dst_key, &decoded.dst_key);
    try std.testing.expectEqualStrings(payload, decoded.payload);
}

test "relay1 too short" {
    var short: [relay1_header_size - 1]u8 = undefined;
    try std.testing.expectError(error.TooShort, decodeRelay1(&short));
}

test "relay2 roundtrip" {
    var src_key: [32]u8 = undefined;
    for (0..32) |i| {
        src_key[i] = @intCast(i + 50);
    }
    const payload = "final hop payload";

    const orig = Relay2{ .src_key = src_key, .payload = payload };
    var buf: [256]u8 = undefined;
    const n = try encodeRelay2(&orig, &buf);
    try std.testing.expectEqual(relay2_header_size + payload.len, n);

    const decoded = try decodeRelay2(buf[0..n]);
    try std.testing.expectEqualSlices(u8, &src_key, &decoded.src_key);
    try std.testing.expectEqualStrings(payload, decoded.payload);
}

test "relay2 too short" {
    var short: [relay2_header_size - 1]u8 = undefined;
    try std.testing.expectError(error.TooShort, decodeRelay2(&short));
}

test "ping roundtrip" {
    const orig = Ping{ .ping_id = 12345, .timestamp = 9876543210 };
    var buf: [ping_size]u8 = undefined;
    const n = try encodePing(&orig, &buf);
    try std.testing.expectEqual(ping_size, n);

    const decoded = try decodePing(&buf);
    try std.testing.expectEqual(@as(u32, 12345), decoded.ping_id);
    try std.testing.expectEqual(@as(u64, 9876543210), decoded.timestamp);
}

test "ping too short" {
    var short: [ping_size - 1]u8 = undefined;
    try std.testing.expectError(error.TooShort, decodePing(&short));
}

test "pong roundtrip" {
    const orig = Pong{
        .ping_id = 12345,
        .timestamp = 9876543210,
        .load = 128,
        .relay_count = 42,
        .bw_avail = 1024,
        .price = 500,
    };
    var buf: [pong_size]u8 = undefined;
    const n = try encodePong(&orig, &buf);
    try std.testing.expectEqual(pong_size, n);

    const decoded = try decodePong(&buf);
    try std.testing.expectEqual(@as(u32, 12345), decoded.ping_id);
    try std.testing.expectEqual(@as(u64, 9876543210), decoded.timestamp);
    try std.testing.expectEqual(@as(u8, 128), decoded.load);
    try std.testing.expectEqual(@as(u16, 42), decoded.relay_count);
    try std.testing.expectEqual(@as(u16, 1024), decoded.bw_avail);
    try std.testing.expectEqual(@as(u32, 500), decoded.price);
}

test "pong too short" {
    var short: [pong_size - 1]u8 = undefined;
    try std.testing.expectError(error.TooShort, decodePong(&short));
}

test "strategy enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(Strategy.auto));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(Strategy.fastest));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(Strategy.cheapest));
}
