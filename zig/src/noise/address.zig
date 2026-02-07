//! Network address encoding/decoding (SOCKS5 compatible).
//!
//! Wire format: atyp(1B) | addr(var) | port(2B BE)
//!   atyp=0x01: IPv4, addr=4 bytes
//!   atyp=0x03: Domain, addr=1 byte len + string
//!   atyp=0x04: IPv6, addr=16 bytes

const std = @import("std");

/// Address type constants (SOCKS5 compatible).
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// Address errors.
pub const AddressError = error{
    TooShort,
    InvalidType,
    InvalidDomain,
    BufferTooSmall,
};

/// A network address with type, host, and port.
pub const Address = struct {
    atyp: u8,
    host: []const u8,
    port: u16,

    /// Create an IPv4 address.
    pub fn ipv4(host: []const u8, port: u16) Address {
        return .{ .atyp = ATYP_IPV4, .host = host, .port = port };
    }

    /// Create an IPv6 address.
    pub fn ipv6(host: []const u8, port: u16) Address {
        return .{ .atyp = ATYP_IPV6, .host = host, .port = port };
    }

    /// Create a domain address.
    pub fn domain(host: []const u8, port: u16) Address {
        return .{ .atyp = ATYP_DOMAIN, .host = host, .port = port };
    }

    /// Returns the encoded size of this address.
    pub fn encodedSize(self: *const Address) AddressError!usize {
        return switch (self.atyp) {
            ATYP_IPV4 => 1 + 4 + 2,
            ATYP_DOMAIN => blk: {
                if (self.host.len == 0 or self.host.len > 255) return AddressError.InvalidDomain;
                break :blk 1 + 1 + self.host.len + 2;
            },
            ATYP_IPV6 => 1 + 16 + 2,
            else => AddressError.InvalidType,
        };
    }

    /// Encode the address into the given buffer.
    /// Returns the slice of bytes written.
    pub fn encode(self: *const Address, buf: []u8) AddressError![]u8 {
        const size = try self.encodedSize();
        if (buf.len < size) return AddressError.BufferTooSmall;

        switch (self.atyp) {
            ATYP_IPV4 => {
                buf[0] = ATYP_IPV4;
                const a = std.net.Ip4Address.parse(self.host, 0) catch return AddressError.InvalidType;
                const bytes: [4]u8 = @bitCast(a.sa.addr);
                @memcpy(buf[1..5], &bytes);
                std.mem.writeInt(u16, buf[5..7], self.port, .big);
                return buf[0..7];
            },
            ATYP_DOMAIN => {
                if (self.host.len == 0 or self.host.len > 255) return AddressError.InvalidDomain;
                buf[0] = ATYP_DOMAIN;
                buf[1] = @intCast(self.host.len);
                @memcpy(buf[2 .. 2 + self.host.len], self.host);
                std.mem.writeInt(u16, buf[2 + self.host.len ..][0..2], self.port, .big);
                return buf[0..size];
            },
            ATYP_IPV6 => {
                buf[0] = ATYP_IPV6;
                const a = std.net.Ip6Address.parse(self.host, 0) catch return AddressError.InvalidType;
                @memcpy(buf[1..17], &a.sa.addr);
                std.mem.writeInt(u16, buf[17..19], self.port, .big);
                return buf[0..19];
            },
            else => return AddressError.InvalidType,
        }
    }

    /// Encode with allocator (convenience).
    pub fn encodeAlloc(self: *const Address, allocator: std.mem.Allocator) ![]u8 {
        const size = try self.encodedSize();
        const buf = try allocator.alloc(u8, size);
        _ = try self.encode(buf);
        return buf;
    }

    /// Decode result type.
    pub const DecodeResult = struct {
        addr: Address,
        consumed: usize,
    };

    /// Decode an address from bytes.
    /// For IPv4/IPv6, the host string is written into `host_buf`.
    /// For domains, host points directly into `data`.
    /// Returns the address and number of bytes consumed.
    pub fn decode(data: []const u8, host_buf: []u8) AddressError!DecodeResult {
        if (data.len == 0) return AddressError.TooShort;

        switch (data[0]) {
            ATYP_IPV4 => {
                if (data.len < 7) return AddressError.TooShort;
                const ip_str = std.fmt.bufPrint(host_buf, "{}.{}.{}.{}", .{
                    data[1], data[2], data[3], data[4],
                }) catch return AddressError.BufferTooSmall;
                const port = std.mem.readInt(u16, data[5..7], .big);
                return .{
                    .addr = .{ .atyp = ATYP_IPV4, .host = ip_str, .port = port },
                    .consumed = 7,
                };
            },
            ATYP_DOMAIN => {
                if (data.len < 2) return AddressError.TooShort;
                const domain_len: usize = data[1];
                if (domain_len == 0) return AddressError.InvalidDomain;
                if (data.len < 2 + domain_len + 2) return AddressError.TooShort;
                const host = data[2 .. 2 + domain_len];
                const port = std.mem.readInt(u16, data[2 + domain_len ..][0..2], .big);
                const consumed = 2 + domain_len + 2;
                return .{
                    .addr = .{ .atyp = ATYP_DOMAIN, .host = host, .port = port },
                    .consumed = consumed,
                };
            },
            ATYP_IPV6 => {
                if (data.len < 19) return AddressError.TooShort;
                const octets: [16]u8 = data[1..17].*;
                // Use std.net.Ip6Address for proper formatting with :: compression
                const ip6 = std.net.Ip6Address.init(octets, 0, 0, 0);
                // Ip6Address.format() outputs "[addr]:port", we need just "addr"
                const ip_str = formatIp6(host_buf, ip6) orelse return AddressError.BufferTooSmall;
                const port = std.mem.readInt(u16, data[17..19], .big);
                return .{
                    .addr = .{ .atyp = ATYP_IPV6, .host = ip_str, .port = port },
                    .consumed = 19,
                };
            },
            else => return AddressError.InvalidType,
        }
    }

    /// Decode with allocator: copies host string to owned memory.
    pub fn decodeAlloc(allocator: std.mem.Allocator, data: []const u8) !DecodeResult {
        var host_buf: [64]u8 = undefined;
        const result = try decode(data, &host_buf);
        const host_copy = try allocator.dupe(u8, result.addr.host);
        return .{
            .addr = .{ .atyp = result.addr.atyp, .host = host_copy, .port = result.addr.port },
            .consumed = result.consumed,
        };
    }
};

/// Format a std.net.Ip6Address into a bare address string (no brackets, no port).
/// std.net.Ip6Address formats as "[addr]:port", so we format to a temp buffer
/// and strip the surrounding brackets and port suffix.
fn formatIp6(host_buf: []u8, ip6: std.net.Ip6Address) ?[]u8 {
    var tmp: [64]u8 = undefined;
    const full = std.fmt.bufPrint(&tmp, "{f}", .{ip6}) catch return null;
    // Output is e.g. "[2001:db8::1]:0"

    // Strip leading '[' and trailing ']:port'
    if (full.len < 4 or full[0] != '[') return null;
    const close_bracket = std.mem.indexOfScalar(u8, full, ']') orelse return null;
    const bare = full[1..close_bracket]; // "2001:db8::1"

    if (host_buf.len < bare.len) return null;
    @memcpy(host_buf[0..bare.len], bare);
    return host_buf[0..bare.len];
}

// =============================================================================
// Tests
// =============================================================================

test "address IPv4 roundtrip" {
    const addr = Address.ipv4("192.168.1.1", 8080);
    var buf: [64]u8 = undefined;
    const encoded = try addr.encode(&buf);
    try std.testing.expectEqual(@as(usize, 7), encoded.len);
    try std.testing.expectEqual(@as(u8, ATYP_IPV4), encoded[0]);

    var host_buf: [64]u8 = undefined;
    const result = try Address.decode(encoded, &host_buf);
    try std.testing.expectEqual(@as(u8, ATYP_IPV4), result.addr.atyp);
    try std.testing.expectEqual(@as(u16, 8080), result.addr.port);
    try std.testing.expectEqual(@as(usize, 7), result.consumed);
    try std.testing.expectEqualStrings("192.168.1.1", result.addr.host);
}

test "address IPv6 roundtrip" {
    const addr = Address.ipv6("2001:db8::1", 443);
    var buf: [64]u8 = undefined;
    const encoded = try addr.encode(&buf);
    try std.testing.expectEqual(@as(usize, 19), encoded.len);
    try std.testing.expectEqual(@as(u8, ATYP_IPV6), encoded[0]);

    var host_buf: [64]u8 = undefined;
    const result = try Address.decode(encoded, &host_buf);
    try std.testing.expectEqual(@as(u8, ATYP_IPV6), result.addr.atyp);
    try std.testing.expectEqual(@as(u16, 443), result.addr.port);
    try std.testing.expectEqual(@as(usize, 19), result.consumed);
    try std.testing.expectEqualStrings("2001:db8::1", result.addr.host);
}

test "address IPv6 all zeros" {
    const addr = Address.ipv6("::", 0);
    var buf: [64]u8 = undefined;
    const encoded = try addr.encode(&buf);
    try std.testing.expectEqual(@as(usize, 19), encoded.len);

    var host_buf: [64]u8 = undefined;
    const result = try Address.decode(encoded, &host_buf);
    try std.testing.expectEqualStrings("::", result.addr.host);
}

test "address IPv6 full" {
    const addr = Address.ipv6("2001:db8:0:0:0:0:0:1", 1234);
    var buf: [64]u8 = undefined;
    const encoded = try addr.encode(&buf);

    var host_buf: [64]u8 = undefined;
    const result = try Address.decode(encoded, &host_buf);
    // std.net formats with :: compression
    try std.testing.expectEqualStrings("2001:db8::1", result.addr.host);
    try std.testing.expectEqual(@as(u16, 1234), result.addr.port);
}

test "address domain roundtrip" {
    const addr = Address.domain("example.com", 80);
    var buf: [64]u8 = undefined;
    const encoded = try addr.encode(&buf);
    try std.testing.expectEqual(@as(usize, 15), encoded.len); // 1+1+11+2
    try std.testing.expectEqual(@as(u8, ATYP_DOMAIN), encoded[0]);

    var host_buf: [64]u8 = undefined;
    const result = try Address.decode(encoded, &host_buf);
    try std.testing.expectEqual(@as(u8, ATYP_DOMAIN), result.addr.atyp);
    try std.testing.expectEqualStrings("example.com", result.addr.host);
    try std.testing.expectEqual(@as(u16, 80), result.addr.port);
    try std.testing.expectEqual(@as(usize, 15), result.consumed);
}

test "address decode errors" {
    var host_buf: [64]u8 = undefined;

    // Empty data
    try std.testing.expectError(AddressError.TooShort, Address.decode(&[_]u8{}, &host_buf));

    // Too short for IPv4
    try std.testing.expectError(AddressError.TooShort, Address.decode(&[_]u8{ 0x01, 1, 2 }, &host_buf));

    // Too short for IPv6
    try std.testing.expectError(AddressError.TooShort, Address.decode(&[_]u8{ 0x04, 1, 2, 3 }, &host_buf));

    // Domain with zero length
    try std.testing.expectError(AddressError.InvalidDomain, Address.decode(&[_]u8{ 0x03, 0 }, &host_buf));

    // Unknown type
    try std.testing.expectError(AddressError.InvalidType, Address.decode(&[_]u8{ 0xFF, 1, 2, 3 }, &host_buf));
}

test "address encode errors" {
    var buf: [64]u8 = undefined;

    // Invalid IPv4
    const bad_v4 = Address.ipv4("not-an-ip", 80);
    try std.testing.expectError(AddressError.InvalidType, bad_v4.encode(&buf));

    // Invalid IPv6
    const bad_v6 = Address.ipv6("not-ipv6", 80);
    try std.testing.expectError(AddressError.InvalidType, bad_v6.encode(&buf));

    // Empty domain
    const bad_domain = Address.domain("", 80);
    try std.testing.expectError(AddressError.InvalidDomain, bad_domain.encode(&buf));

    // Unknown type
    const bad_type = Address{ .atyp = 0xFF, .host = "test", .port = 80 };
    try std.testing.expectError(AddressError.InvalidType, bad_type.encode(&buf));
}
