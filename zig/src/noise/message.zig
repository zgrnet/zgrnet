//! Wire protocol message types and parsing.
//!
//! This module defines the message formats for the Noise-based protocol,
//! including handshake messages and transport messages.

const std = @import("std");
const crypto = @import("crypto.zig");
const keypair = @import("keypair.zig");

const Key = keypair.Key;
const key_length = keypair.key_length;

/// Message type constants for the wire protocol.
pub const MessageType = enum(u8) {
    /// Handshake initiation message (Type 1).
    handshake_init = 1,
    /// Handshake response message (Type 2).
    handshake_resp = 2,
    /// Cookie reply for DoS protection (Type 3).
    cookie_reply = 3,
    /// Encrypted transport message (Type 4).
    transport = 4,
    _,
};

/// Protocol field values (inside encrypted payload).
pub const Protocol = enum(u8) {
    // Transport layer protocols (0-63, matching IP protocol numbers)
    /// Raw data (default)
    raw = 0,
    /// ICMP in ZigNet (no IP header)
    icmp = 1,
    /// IP in ZigNet (complete IP packet)
    ip = 4,
    /// TCP in ZigNet (no IP header)
    tcp = 6,
    /// UDP in ZigNet (no IP header)
    udp = 17,

    // ZigNet extension protocols (64-127)
    /// KCP reliable UDP
    kcp = 64,
    /// UDP proxy
    udp_proxy = 65,
    /// Relay first hop
    relay_0 = 66,
    /// Relay middle hop
    relay_1 = 67,
    /// Relay last hop
    relay_2 = 68,
    /// TCP proxy via KCP stream
    tcp_proxy = 69,
    /// Ping probe request
    ping = 70,
    /// Pong probe response
    pong = 71,
    /// Relay first hop BIND (relay_id + dst_pubkey)
    relay_0_bind = 72,
    /// Relay first hop ALIAS (relay_id + payload)
    relay_0_alias = 73,
    /// Relay middle hop BIND (relay_id + src + dst pubkey)
    relay_1_bind = 74,
    /// Relay middle hop ALIAS (relay_id + payload)
    relay_1_alias = 75,
    /// Relay last hop BIND (relay_id + src_pubkey)
    relay_2_bind = 76,
    /// Relay last hop ALIAS (relay_id + payload)
    relay_2_alias = 77,

    // Application layer protocols (128-255)
    /// Chat messages
    chat = 128,
    /// File transfer
    file = 129,
    /// Audio/video streams
    media = 130,
    /// Signaling (WebRTC, etc.)
    signal = 131,
    /// Remote procedure calls
    rpc = 132,
    _,
};

/// Tag size for AEAD.
pub const tag_size = crypto.tag_size;

/// Handshake initiation message size.
/// type(1) + sender_idx(4) + ephemeral(32) + static_enc(48) = 85
pub const handshake_init_size = 1 + 4 + 32 + 48;

/// Handshake response message size.
/// type(1) + sender_idx(4) + receiver_idx(4) + ephemeral(32) + encrypted_empty(16) = 57
pub const handshake_resp_size = 1 + 4 + 4 + 32 + 16;

/// Transport message header size.
/// type(1) + receiver_idx(4) + counter(8) = 13
pub const transport_header_size = 1 + 4 + 8;

/// Maximum payload size (64KB - headers - tag - protocol byte).
pub const max_payload_size = 65535 - transport_header_size - tag_size - 1;

/// Maximum packet size we accept.
pub const max_packet_size = 65535;

/// Message parsing errors.
pub const MessageError = error{
    /// Message is too short.
    TooShort,
    /// Invalid message type.
    InvalidType,
};

/// A parsed handshake initiation message (Type 1).
pub const HandshakeInit = struct {
    /// Sender's session index.
    sender_index: u32,
    /// Ephemeral public key.
    ephemeral: Key,
    /// Encrypted static key (48 bytes = 32B key + 16B tag).
    static_encrypted: [48]u8,
};

/// A parsed handshake response message (Type 2).
pub const HandshakeResp = struct {
    /// Sender's session index.
    sender_index: u32,
    /// Receiver's session index (from initiation).
    receiver_index: u32,
    /// Ephemeral public key.
    ephemeral: Key,
    /// Encrypted empty payload (16 bytes, just tag).
    empty_encrypted: [16]u8,
};

/// A parsed transport message (Type 4).
pub const TransportMessage = struct {
    /// Receiver's session index.
    receiver_index: u32,
    /// Counter/nonce.
    counter: u64,
    /// Ciphertext (includes 16-byte auth tag).
    ciphertext: []const u8,
};

/// Parse a handshake initiation message.
pub fn parseHandshakeInit(data: []const u8) MessageError!HandshakeInit {
    if (data.len < handshake_init_size) {
        return MessageError.TooShort;
    }
    if (data[0] != @intFromEnum(MessageType.handshake_init)) {
        return MessageError.InvalidType;
    }

    const sender_index = std.mem.readInt(u32, data[1..5], .little);

    var ephemeral: Key = undefined;
    @memcpy(&ephemeral.data, data[5..37]);

    var static_encrypted: [48]u8 = undefined;
    @memcpy(&static_encrypted, data[37..85]);

    return HandshakeInit{
        .sender_index = sender_index,
        .ephemeral = ephemeral,
        .static_encrypted = static_encrypted,
    };
}

/// Build a handshake initiation message.
pub fn buildHandshakeInit(
    sender_index: u32,
    ephemeral: *const Key,
    static_encrypted: []const u8,
) [handshake_init_size]u8 {
    var msg: [handshake_init_size]u8 = undefined;
    msg[0] = @intFromEnum(MessageType.handshake_init);
    std.mem.writeInt(u32, msg[1..5], sender_index, .little);
    @memcpy(msg[5..37], ephemeral.asBytes());
    @memcpy(msg[37..85], static_encrypted[0..48]);
    return msg;
}

/// Parse a handshake response message.
pub fn parseHandshakeResp(data: []const u8) MessageError!HandshakeResp {
    if (data.len < handshake_resp_size) {
        return MessageError.TooShort;
    }
    if (data[0] != @intFromEnum(MessageType.handshake_resp)) {
        return MessageError.InvalidType;
    }

    const sender_index = std.mem.readInt(u32, data[1..5], .little);
    const receiver_index = std.mem.readInt(u32, data[5..9], .little);

    var ephemeral: Key = undefined;
    @memcpy(&ephemeral.data, data[9..41]);

    var empty_encrypted: [16]u8 = undefined;
    @memcpy(&empty_encrypted, data[41..57]);

    return HandshakeResp{
        .sender_index = sender_index,
        .receiver_index = receiver_index,
        .ephemeral = ephemeral,
        .empty_encrypted = empty_encrypted,
    };
}

/// Build a handshake response message.
pub fn buildHandshakeResp(
    sender_index: u32,
    receiver_index: u32,
    ephemeral: *const Key,
    empty_encrypted: []const u8,
) [handshake_resp_size]u8 {
    var msg: [handshake_resp_size]u8 = undefined;
    msg[0] = @intFromEnum(MessageType.handshake_resp);
    std.mem.writeInt(u32, msg[1..5], sender_index, .little);
    std.mem.writeInt(u32, msg[5..9], receiver_index, .little);
    @memcpy(msg[9..41], ephemeral.asBytes());
    @memcpy(msg[41..57], empty_encrypted[0..16]);
    return msg;
}

/// Parse a transport message.
pub fn parseTransportMessage(data: []const u8) MessageError!TransportMessage {
    if (data.len < transport_header_size + tag_size) {
        return MessageError.TooShort;
    }
    if (data[0] != @intFromEnum(MessageType.transport)) {
        return MessageError.InvalidType;
    }

    const receiver_index = std.mem.readInt(u32, data[1..5], .little);
    const counter = std.mem.readInt(u64, data[5..13], .little);

    return TransportMessage{
        .receiver_index = receiver_index,
        .counter = counter,
        .ciphertext = data[13..],
    };
}

/// Build a transport message header.
pub fn buildTransportHeader(
    receiver_index: u32,
    counter: u64,
) [transport_header_size]u8 {
    var header: [transport_header_size]u8 = undefined;
    header[0] = @intFromEnum(MessageType.transport);
    std.mem.writeInt(u32, header[1..5], receiver_index, .little);
    std.mem.writeInt(u64, header[5..13], counter, .little);
    return header;
}

/// Build a full transport message with ciphertext.
pub fn buildTransportMessage(
    allocator: std.mem.Allocator,
    receiver_index: u32,
    counter: u64,
    ciphertext: []const u8,
) ![]u8 {
    const msg = try allocator.alloc(u8, transport_header_size + ciphertext.len);
    const header = buildTransportHeader(receiver_index, counter);
    @memcpy(msg[0..transport_header_size], &header);
    @memcpy(msg[transport_header_size..], ciphertext);
    return msg;
}

/// Well-known service IDs (matches Go/Rust constants).
pub const Service = struct {
    pub const relay: u64 = 0;
    pub const proxy: u64 = 1;
    pub const tun: u64 = 2;
    pub const dns: u64 = 3;
    pub const admin: u64 = 4;
};

/// Encode a protobuf-style varint (unsigned LEB128).
pub fn encodeVarint(buf: []u8, value: u64) usize {
    var v = value;
    var i: usize = 0;
    while (v >= 0x80) : (i += 1) {
        buf[i] = @intCast((v & 0x7F) | 0x80);
        v >>= 7;
    }
    buf[i] = @intCast(v & 0x7F);
    return i + 1;
}

/// Decode a protobuf-style varint. Returns value and bytes consumed.
pub const VarintResult = struct { value: u64, consumed: usize };

pub fn decodeVarint(data: []const u8) MessageError!VarintResult {
    var value: u64 = 0;
    var shift: u6 = 0;
    for (data, 0..) |byte, i| {
        if (i >= 10) return MessageError.TooShort; // overflow protection
        value |= @as(u64, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) {
            return VarintResult{ .value = value, .consumed = i + 1 };
        }
        shift +|= 7;
    }
    return MessageError.TooShort;
}

/// Returns the encoded length of a varint value.
pub fn varintLen(value: u64) usize {
    if (value == 0) return 1;
    var v = value;
    var len: usize = 0;
    while (v > 0) : (len += 1) {
        v >>= 7;
    }
    return len;
}

/// Encode a payload: protocol(1B) | service(varint) | data.
pub fn encodePayload(
    allocator: std.mem.Allocator,
    protocol: Protocol,
    service: u64,
    payload: []const u8,
) ![]u8 {
    const svc_len = varintLen(service);
    const result = try allocator.alloc(u8, 1 + svc_len + payload.len);
    result[0] = @intFromEnum(protocol);
    _ = encodeVarint(result[1..], service);
    @memcpy(result[1 + svc_len ..], payload);
    return result;
}

/// Decode a payload: protocol(1B) | service(varint) | data.
pub const DecodeResult = struct {
    protocol: Protocol,
    service: u64,
    payload: []const u8,
};

pub fn decodePayload(data: []const u8) MessageError!DecodeResult {
    if (data.len < 2) {
        return MessageError.TooShort;
    }
    const protocol: Protocol = @enumFromInt(data[0]);
    const vr = try decodeVarint(data[1..]);
    return DecodeResult{
        .protocol = protocol,
        .service = vr.value,
        .payload = data[1 + vr.consumed ..],
    };
}

/// Get the message type from raw data.
pub fn getMessageType(data: []const u8) MessageError!MessageType {
    if (data.len == 0) {
        return MessageError.TooShort;
    }
    return @enumFromInt(data[0]);
}

// =============================================================================
// Tests
// =============================================================================

test "handshake init roundtrip" {
    const sender_index: u32 = 12345;
    const ephemeral = Key{ .data = [_]u8{0xAA} ** 32 };
    const static_encrypted = [_]u8{0xBB} ** 48;

    const msg = buildHandshakeInit(sender_index, &ephemeral, &static_encrypted);
    try std.testing.expectEqual(msg.len, handshake_init_size);

    const parsed = try parseHandshakeInit(&msg);
    try std.testing.expectEqual(parsed.sender_index, sender_index);
    try std.testing.expectEqualSlices(u8, &parsed.ephemeral.data, &ephemeral.data);
    try std.testing.expectEqualSlices(u8, &parsed.static_encrypted, &static_encrypted);
}

test "handshake resp roundtrip" {
    const sender_index: u32 = 11111;
    const receiver_index: u32 = 22222;
    const ephemeral = Key{ .data = [_]u8{0xCC} ** 32 };
    const empty_encrypted = [_]u8{0xDD} ** 16;

    const msg = buildHandshakeResp(sender_index, receiver_index, &ephemeral, &empty_encrypted);
    try std.testing.expectEqual(msg.len, handshake_resp_size);

    const parsed = try parseHandshakeResp(&msg);
    try std.testing.expectEqual(parsed.sender_index, sender_index);
    try std.testing.expectEqual(parsed.receiver_index, receiver_index);
    try std.testing.expectEqualSlices(u8, &parsed.ephemeral.data, &ephemeral.data);
    try std.testing.expectEqualSlices(u8, &parsed.empty_encrypted, &empty_encrypted);
}

test "transport message roundtrip" {
    const allocator = std.testing.allocator;
    const receiver_index: u32 = 33333;
    const counter: u64 = 44444;
    const ciphertext = [_]u8{0xEE} ** 100;

    const msg = try buildTransportMessage(allocator, receiver_index, counter, &ciphertext);
    defer allocator.free(msg);
    try std.testing.expectEqual(msg.len, transport_header_size + ciphertext.len);

    const parsed = try parseTransportMessage(msg);
    try std.testing.expectEqual(parsed.receiver_index, receiver_index);
    try std.testing.expectEqual(parsed.counter, counter);
    try std.testing.expectEqualSlices(u8, parsed.ciphertext, &ciphertext);
}

test "varint zero" {
    var buf: [10]u8 = undefined;
    const n = encodeVarint(&buf, 0);
    try std.testing.expectEqual(n, 1);
    try std.testing.expectEqual(buf[0], 0);

    const vr = try decodeVarint(buf[0..n]);
    try std.testing.expectEqual(vr.value, 0);
    try std.testing.expectEqual(vr.consumed, 1);
}

test "varint one byte max (127)" {
    var buf: [10]u8 = undefined;
    const n = encodeVarint(&buf, 127);
    try std.testing.expectEqual(n, 1);
    try std.testing.expectEqual(buf[0], 127);

    const vr = try decodeVarint(buf[0..n]);
    try std.testing.expectEqual(vr.value, 127);
}

test "varint two byte (128)" {
    var buf: [10]u8 = undefined;
    const n = encodeVarint(&buf, 128);
    try std.testing.expectEqual(n, 2);
    try std.testing.expectEqual(buf[0], 0x80);
    try std.testing.expectEqual(buf[1], 0x01);

    const vr = try decodeVarint(buf[0..n]);
    try std.testing.expectEqual(vr.value, 128);
}

test "varint roundtrip 1000 values" {
    var buf: [10]u8 = undefined;
    const test_values = [_]u64{ 0, 1, 127, 128, 255, 256, 16383, 16384, 65535, 1 << 21, 1 << 28, 1 << 35, 1 << 63 - 1 };
    for (test_values) |v| {
        const n = encodeVarint(&buf, v);
        try std.testing.expectEqual(n, varintLen(v));
        const vr = try decodeVarint(buf[0..n]);
        try std.testing.expectEqual(vr.value, v);
        try std.testing.expectEqual(vr.consumed, n);
    }
}

test "varintLen" {
    try std.testing.expectEqual(varintLen(0), 1);
    try std.testing.expectEqual(varintLen(1), 1);
    try std.testing.expectEqual(varintLen(127), 1);
    try std.testing.expectEqual(varintLen(128), 2);
    try std.testing.expectEqual(varintLen(16383), 2);
    try std.testing.expectEqual(varintLen(16384), 3);
}

test "payload roundtrip with service" {
    const allocator = std.testing.allocator;
    const protocol = Protocol.kcp;
    const service: u64 = Service.proxy;
    const payload = "hello world";

    const encoded = try encodePayload(allocator, protocol, service, payload);
    defer allocator.free(encoded);

    const decoded = try decodePayload(encoded);
    try std.testing.expectEqual(decoded.protocol, protocol);
    try std.testing.expectEqual(decoded.service, service);
    try std.testing.expectEqualSlices(u8, decoded.payload, payload);
}

test "payload service zero" {
    const allocator = std.testing.allocator;
    const encoded = try encodePayload(allocator, Protocol.kcp, 0, "data");
    defer allocator.free(encoded);

    const decoded = try decodePayload(encoded);
    try std.testing.expectEqual(decoded.service, 0);
    try std.testing.expectEqualSlices(u8, decoded.payload, "data");
}

test "payload empty data" {
    const allocator = std.testing.allocator;
    const encoded = try encodePayload(allocator, Protocol.kcp, 42, "");
    defer allocator.free(encoded);

    const decoded = try decodePayload(encoded);
    try std.testing.expectEqual(decoded.service, 42);
    try std.testing.expectEqual(decoded.payload.len, 0);
}

test "payload large service" {
    const allocator = std.testing.allocator;
    const big_svc: u64 = 1 << 35;
    const encoded = try encodePayload(allocator, Protocol.raw, big_svc, "x");
    defer allocator.free(encoded);

    const decoded = try decodePayload(encoded);
    try std.testing.expectEqual(decoded.service, big_svc);
    try std.testing.expectEqualSlices(u8, decoded.payload, "x");
}

test "service constants" {
    try std.testing.expectEqual(Service.relay, 0);
    try std.testing.expectEqual(Service.proxy, 1);
    try std.testing.expectEqual(Service.tun, 2);
    try std.testing.expectEqual(Service.dns, 3);
    try std.testing.expectEqual(Service.admin, 4);
}

test "message too short" {
    try std.testing.expectError(MessageError.TooShort, parseHandshakeInit(&[_]u8{ 1, 2, 3 }));
    try std.testing.expectError(MessageError.TooShort, parseHandshakeResp(&[_]u8{ 1, 2, 3 }));
    try std.testing.expectError(MessageError.TooShort, parseTransportMessage(&[_]u8{ 1, 2, 3 }));
    try std.testing.expectError(MessageError.TooShort, decodePayload(&[_]u8{}));
    try std.testing.expectError(MessageError.TooShort, getMessageType(&[_]u8{}));
}

test "invalid message type" {
    var msg = [_]u8{0} ** handshake_init_size;
    msg[0] = @intFromEnum(MessageType.transport); // Wrong type
    try std.testing.expectError(MessageError.InvalidType, parseHandshakeInit(&msg));

    var msg2 = [_]u8{0} ** handshake_resp_size;
    msg2[0] = @intFromEnum(MessageType.handshake_init); // Wrong type
    try std.testing.expectError(MessageError.InvalidType, parseHandshakeResp(&msg2));

    var msg3 = [_]u8{0} ** (transport_header_size + tag_size);
    msg3[0] = @intFromEnum(MessageType.handshake_init); // Wrong type
    try std.testing.expectError(MessageError.InvalidType, parseTransportMessage(&msg3));
}

test "protocol constants" {
    try std.testing.expectEqual(@intFromEnum(Protocol.icmp), 1);
    try std.testing.expectEqual(@intFromEnum(Protocol.ip), 4);
    try std.testing.expectEqual(@intFromEnum(Protocol.tcp), 6);
    try std.testing.expectEqual(@intFromEnum(Protocol.udp), 17);
    try std.testing.expectEqual(@intFromEnum(Protocol.kcp), 64);
    try std.testing.expectEqual(@intFromEnum(Protocol.chat), 128);
}
