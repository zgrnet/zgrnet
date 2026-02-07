//! Wire protocol message types and parsing.
//!
//! This module defines the message formats for the Noise-based protocol,
//! including handshake messages and transport messages.

const std = @import("std");
const crypto = @import("cipher.zig");
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

/// Encode a payload with protocol byte.
pub fn encodePayload(
    allocator: std.mem.Allocator,
    protocol: Protocol,
    payload: []const u8,
) ![]u8 {
    const result = try allocator.alloc(u8, 1 + payload.len);
    result[0] = @intFromEnum(protocol);
    @memcpy(result[1..], payload);
    return result;
}

/// Decode a payload to extract protocol and data.
pub const DecodeResult = struct {
    protocol: Protocol,
    payload: []const u8,
};

pub fn decodePayload(data: []const u8) MessageError!DecodeResult {
    if (data.len == 0) {
        return MessageError.TooShort;
    }
    return DecodeResult{
        .protocol = @enumFromInt(data[0]),
        .payload = data[1..],
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

test "payload roundtrip" {
    const allocator = std.testing.allocator;
    const protocol = Protocol.chat;
    const payload = "hello world";

    const encoded = try encodePayload(allocator, protocol, payload);
    defer allocator.free(encoded);
    try std.testing.expectEqual(encoded.len, 1 + payload.len);

    const decoded = try decodePayload(encoded);
    try std.testing.expectEqual(decoded.protocol, protocol);
    try std.testing.expectEqualSlices(u8, decoded.payload, payload);
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
