//! SOCKS5 and HTTP CONNECT proxy protocol implementation.
//!
//! Provides SOCKS5 address parsing, reply building, and UDP datagram helpers.
//! The server accept loop is left to the caller; this module focuses on
//! protocol parsing and formatting that is independent of the I/O backend.

const std = @import("std");
const noise_address = @import("../noise/address.zig");
const Address = noise_address.Address;
const AddressError = noise_address.AddressError;
const ATYP_IPV4 = noise_address.ATYP_IPV4;
const ATYP_DOMAIN = noise_address.ATYP_DOMAIN;
const ATYP_IPV6 = noise_address.ATYP_IPV6;

// SOCKS5 protocol constants
pub const VERSION5: u8 = 0x05;
pub const AUTH_NONE: u8 = 0x00;
pub const AUTH_NO_ACCEPT: u8 = 0xFF;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACH: u8 = 0x03;
pub const REP_HOST_UNREACH: u8 = 0x04;
pub const REP_CONN_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

pub const Error = error{
    InvalidProtocol,
    InvalidAuth,
    UnsupportedCommand,
    InvalidAddress,
    FragmentNotSupported,
    DatagramTooShort,
    InvalidRSV,
    ConnectionRefused,
    EndOfStream,
    BufferTooSmall,
};

/// SOCKS5 request parsed from the wire.
pub const Request = struct {
    cmd: u8,
    addr: Address,
};

/// Read SOCKS5 auth negotiation and accept NO AUTH.
/// Returns error if no acceptable method is found.
pub fn negotiateAuth(reader: anytype, writer: anytype) !void {
    // Read NMETHODS
    var n_methods_buf: [1]u8 = undefined;
    _ = try reader.readAll(&n_methods_buf);
    const n_methods = n_methods_buf[0];

    // Read methods
    var methods_buf: [256]u8 = undefined;
    const methods = methods_buf[0..n_methods];
    _ = try reader.readAll(methods);

    // Check for NO AUTH
    var has_no_auth = false;
    for (methods) |m| {
        if (m == AUTH_NONE) {
            has_no_auth = true;
            break;
        }
    }

    if (!has_no_auth) {
        _ = try writer.write(&[_]u8{ VERSION5, AUTH_NO_ACCEPT });
        return Error.InvalidAuth;
    }

    _ = try writer.write(&[_]u8{ VERSION5, AUTH_NONE });
}

/// Read a SOCKS5 request (after auth negotiation).
/// Returns the command and target address.
pub fn readRequest(reader: anytype, host_buf: []u8) !Request {
    var header: [4]u8 = undefined;
    _ = try reader.readAll(&header);

    if (header[0] != VERSION5) {
        return Error.InvalidProtocol;
    }

    const cmd = header[1];
    const atyp = header[3];

    const addr = try readAddress(reader, atyp, host_buf);
    return .{ .cmd = cmd, .addr = addr };
}

/// Read a SOCKS5 address from a stream.
pub fn readAddress(reader: anytype, atyp: u8, host_buf: []u8) !Address {
    switch (atyp) {
        ATYP_IPV4 => {
            var buf: [6]u8 = undefined;
            _ = try reader.readAll(&buf);
            const ip_str = std.fmt.bufPrint(host_buf, "{}.{}.{}.{}", .{
                buf[0], buf[1], buf[2], buf[3],
            }) catch return Error.BufferTooSmall;
            const port = std.mem.readInt(u16, buf[4..6], .big);
            return .{ .atyp = ATYP_IPV4, .host = ip_str, .port = port };
        },
        ATYP_DOMAIN => {
            var len_buf: [1]u8 = undefined;
            _ = try reader.readAll(&len_buf);
            const domain_len: usize = len_buf[0];
            if (domain_len == 0) return Error.InvalidAddress;

            var buf: [257]u8 = undefined; // max domain 255 + 2 port
            _ = try reader.readAll(buf[0 .. domain_len + 2]);
            const port = std.mem.readInt(u16, buf[domain_len..][0..2], .big);
            // Copy domain to host_buf
            if (host_buf.len < domain_len) return Error.BufferTooSmall;
            @memcpy(host_buf[0..domain_len], buf[0..domain_len]);
            return .{ .atyp = ATYP_DOMAIN, .host = host_buf[0..domain_len], .port = port };
        },
        ATYP_IPV6 => {
            var buf: [18]u8 = undefined;
            _ = try reader.readAll(&buf);
            const octets: [16]u8 = buf[0..16].*;
            const ip6 = std.net.Ip6Address.init(octets, 0, 0, 0);
            // Format IPv6 address
            var tmp: [64]u8 = undefined;
            const full = std.fmt.bufPrint(&tmp, "{f}", .{ip6}) catch return Error.BufferTooSmall;
            // Strip brackets: "[addr]:0" → "addr"
            if (full.len < 4 or full[0] != '[') return Error.InvalidAddress;
            const close = std.mem.indexOfScalar(u8, full, ']') orelse return Error.InvalidAddress;
            const bare = full[1..close];
            if (host_buf.len < bare.len) return Error.BufferTooSmall;
            @memcpy(host_buf[0..bare.len], bare);
            const port = std.mem.readInt(u16, buf[16..18], .big);
            return .{ .atyp = ATYP_IPV6, .host = host_buf[0..bare.len], .port = port };
        },
        else => return Error.InvalidAddress,
    }
}

/// Build a SOCKS5 reply into a buffer.
/// Returns the slice written.
pub fn buildReply(buf: []u8, rep: u8, addr: ?*const Address) ![]u8 {
    if (addr) |a| {
        const encoded_size = a.encodedSize() catch 7;
        if (buf.len < 3 + encoded_size) return Error.BufferTooSmall;
        buf[0] = VERSION5;
        buf[1] = rep;
        buf[2] = 0x00;
        _ = a.encode(buf[3..]) catch {
            // Fallback to 0.0.0.0:0
            buf[3] = ATYP_IPV4;
            @memset(buf[4..10], 0);
            return buf[0..10];
        };
        return buf[0 .. 3 + encoded_size];
    } else {
        // Default: 0.0.0.0:0
        if (buf.len < 10) return Error.BufferTooSmall;
        buf[0] = VERSION5;
        buf[1] = rep;
        buf[2] = 0x00;
        buf[3] = ATYP_IPV4;
        @memset(buf[4..10], 0);
        return buf[0..10];
    }
}

/// Parse a SOCKS5 UDP datagram.
/// Format: RSV(2) + FRAG(1) + ATYP(1) + ADDR(var) + PORT(2) + DATA(var)
/// Returns the target address and payload slice.
pub fn parseSOCKS5UDP(data: []const u8, host_buf: []u8) !struct { addr: Address, payload: []const u8 } {
    if (data.len < 4) return Error.DatagramTooShort;
    if (data[0] != 0 or data[1] != 0) return Error.InvalidRSV;
    if (data[2] != 0) return Error.FragmentNotSupported;

    const result = try Address.decode(data[3..], host_buf);
    const payload = data[3 + result.consumed ..];
    return .{ .addr = result.addr, .payload = payload };
}

/// Build a SOCKS5 UDP datagram.
/// Format: RSV(2) + FRAG(1) + encoded_addr + DATA
/// Returns the slice written into buf.
pub fn buildSOCKS5UDP(buf: []u8, addr: *const Address, data: []const u8) ![]u8 {
    const addr_size = try addr.encodedSize();
    const total = 3 + addr_size + data.len;
    if (buf.len < total) return Error.BufferTooSmall;

    buf[0] = 0x00; // RSV
    buf[1] = 0x00; // RSV
    buf[2] = 0x00; // FRAG
    _ = try addr.encode(buf[3..]);
    @memcpy(buf[3 + addr_size .. 3 + addr_size + data.len], data);
    return buf[0..total];
}

// =============================================================================
// Tests
// =============================================================================

test "negotiateAuth NO AUTH accepted" {
    // Simulate client sending: NMETHODS=1, METHODS=[0x00]
    const input = [_]u8{ 0x01, 0x00 };
    var reader = std.io.fixedBufferStream(&input);
    var output_buf: [64]u8 = undefined;
    var writer = std.io.fixedBufferStream(&output_buf);

    try negotiateAuth(reader.reader(), writer.writer());

    const written = writer.getWritten();
    try std.testing.expectEqual(@as(usize, 2), written.len);
    try std.testing.expectEqual(VERSION5, written[0]);
    try std.testing.expectEqual(AUTH_NONE, written[1]);
}

test "negotiateAuth reject" {
    // Only offer USER/PASS (0x02)
    const input = [_]u8{ 0x01, 0x02 };
    var reader = std.io.fixedBufferStream(&input);
    var output_buf: [64]u8 = undefined;
    var writer = std.io.fixedBufferStream(&output_buf);

    const result = negotiateAuth(reader.reader(), writer.writer());
    try std.testing.expectError(Error.InvalidAuth, result);

    const written = writer.getWritten();
    try std.testing.expectEqual(VERSION5, written[0]);
    try std.testing.expectEqual(AUTH_NO_ACCEPT, written[1]);
}

test "readRequest CONNECT IPv4" {
    // VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4, 10.0.0.1:8080
    const input = [_]u8{
        0x05, CMD_CONNECT, 0x00, ATYP_IPV4,
        10,   0,           0,    1,
        0x1F, 0x90, // port 8080
    };
    var reader = std.io.fixedBufferStream(&input);
    var host_buf: [64]u8 = undefined;

    const req = try readRequest(reader.reader(), &host_buf);
    try std.testing.expectEqual(CMD_CONNECT, req.cmd);
    try std.testing.expectEqualStrings("10.0.0.1", req.addr.host);
    try std.testing.expectEqual(@as(u16, 8080), req.addr.port);
}

test "readRequest CONNECT domain" {
    const domain = "example.com";
    const input = [_]u8{
        0x05,             CMD_CONNECT, 0x00, ATYP_DOMAIN,
        @intCast(domain.len),
    } ++ domain.* ++ [_]u8{ 0x01, 0xBB }; // port 443

    var reader = std.io.fixedBufferStream(&input);
    var host_buf: [64]u8 = undefined;

    const req = try readRequest(reader.reader(), &host_buf);
    try std.testing.expectEqual(CMD_CONNECT, req.cmd);
    try std.testing.expectEqualStrings("example.com", req.addr.host);
    try std.testing.expectEqual(@as(u16, 443), req.addr.port);
}

test "buildReply success with address" {
    const addr = Address.ipv4("10.0.0.1", 80);
    var buf: [64]u8 = undefined;
    const reply = try buildReply(&buf, REP_SUCCESS, &addr);
    try std.testing.expectEqual(VERSION5, reply[0]);
    try std.testing.expectEqual(REP_SUCCESS, reply[1]);
    try std.testing.expectEqual(@as(u8, 0x00), reply[2]);
    try std.testing.expectEqual(ATYP_IPV4, reply[3]);
}

test "buildReply failure without address" {
    var buf: [64]u8 = undefined;
    const reply = try buildReply(&buf, REP_GENERAL_FAILURE, null);
    try std.testing.expectEqual(@as(usize, 10), reply.len);
    try std.testing.expectEqual(VERSION5, reply[0]);
    try std.testing.expectEqual(REP_GENERAL_FAILURE, reply[1]);
    try std.testing.expectEqual(ATYP_IPV4, reply[3]);
}

test "parseSOCKS5UDP roundtrip" {
    const addr = Address.ipv4("10.0.0.1", 53);
    const data = "dns query";
    var buf: [128]u8 = undefined;
    const pkt = try buildSOCKS5UDP(&buf, &addr, data);

    var host_buf: [64]u8 = undefined;
    const result = try parseSOCKS5UDP(pkt, &host_buf);
    try std.testing.expectEqualStrings("10.0.0.1", result.addr.host);
    try std.testing.expectEqual(@as(u16, 53), result.addr.port);
    try std.testing.expectEqualStrings("dns query", result.payload);
}

test "parseSOCKS5UDP domain roundtrip" {
    const addr = Address.domain("example.com", 443);
    const data = "test payload";
    var buf: [128]u8 = undefined;
    const pkt = try buildSOCKS5UDP(&buf, &addr, data);

    var host_buf: [64]u8 = undefined;
    const result = try parseSOCKS5UDP(pkt, &host_buf);
    try std.testing.expectEqualStrings("example.com", result.addr.host);
    try std.testing.expectEqual(@as(u16, 443), result.addr.port);
    try std.testing.expectEqualStrings("test payload", result.payload);
}

test "parseSOCKS5UDP too short" {
    var host_buf: [64]u8 = undefined;
    try std.testing.expectError(Error.DatagramTooShort, parseSOCKS5UDP(&[_]u8{ 0, 0 }, &host_buf));
}

test "parseSOCKS5UDP invalid RSV" {
    var host_buf: [64]u8 = undefined;
    try std.testing.expectError(Error.InvalidRSV, parseSOCKS5UDP(&[_]u8{ 0xFF, 0, 0, 0x01, 0, 0, 0, 0, 0, 0 }, &host_buf));
}

test "parseSOCKS5UDP fragment" {
    var host_buf: [64]u8 = undefined;
    try std.testing.expectError(Error.FragmentNotSupported, parseSOCKS5UDP(&[_]u8{ 0, 0, 0x01, 0x01, 0, 0, 0, 0, 0, 0 }, &host_buf));
}
