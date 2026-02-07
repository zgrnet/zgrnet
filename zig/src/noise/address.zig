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
                // Parse "a.b.c.d" into 4 bytes
                const parsed = parseIPv4(self.host) orelse return AddressError.InvalidType;
                @memcpy(buf[1..5], &parsed);
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
                const parsed = parseIPv6(self.host) orelse return AddressError.InvalidType;
                @memcpy(buf[1..17], &parsed);
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
                // Format IPv6 from 16 bytes — use compact notation
                const octets: [16]u8 = data[1..17].*;
                const groups: [8]u16 = .{
                    std.mem.readInt(u16, octets[0..2], .big),
                    std.mem.readInt(u16, octets[2..4], .big),
                    std.mem.readInt(u16, octets[4..6], .big),
                    std.mem.readInt(u16, octets[6..8], .big),
                    std.mem.readInt(u16, octets[8..10], .big),
                    std.mem.readInt(u16, octets[10..12], .big),
                    std.mem.readInt(u16, octets[12..14], .big),
                    std.mem.readInt(u16, octets[14..16], .big),
                };
                if (host_buf.len < 39) return AddressError.BufferTooSmall;
                const ip_str = formatIPv6(host_buf[0..39], groups);
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

/// Parse IPv4 string "a.b.c.d" to 4 bytes.
fn parseIPv4(s: []const u8) ?[4]u8 {
    if (s.len == 0) return null;
    var result: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var num: u16 = 0;
    var has_digit = false;

    for (s) |ch| {
        if (ch == '.') {
            if (!has_digit or octet_idx >= 3) return null;
            if (num > 255) return null;
            result[octet_idx] = @intCast(num);
            octet_idx += 1;
            num = 0;
            has_digit = false;
        } else if (ch >= '0' and ch <= '9') {
            num = num * 10 + (ch - '0');
            has_digit = true;
        } else {
            return null;
        }
    }

    if (!has_digit or octet_idx != 3 or num > 255) return null;
    result[3] = @intCast(num);
    return result;
}

/// Parse IPv6 string to 16 bytes. Supports :: notation.
fn parseIPv6(s: []const u8) ?[16]u8 {
    if (s.len == 0) return null;
    var result: [16]u8 = .{0} ** 16;
    var groups: [8]u16 = .{0} ** 8;
    var group_idx: usize = 0;
    var double_colon_pos: ?usize = null;
    var num: u16 = 0;
    var has_digit = false;
    var i: usize = 0;

    // Handle leading ::
    if (s.len >= 2 and s[0] == ':' and s[1] == ':') {
        double_colon_pos = 0;
        i = 2;
        if (i == s.len) {
            // Just "::" — all zeros
            return result;
        }
    }

    while (i < s.len) {
        const ch = s[i];
        if (ch == ':') {
            if (!has_digit) {
                // This shouldn't happen if we handled leading :: above
                return null;
            }
            if (group_idx >= 8) return null;
            groups[group_idx] = num;
            group_idx += 1;
            num = 0;
            has_digit = false;

            // Check for ::
            if (i + 1 < s.len and s[i + 1] == ':') {
                if (double_colon_pos != null) return null; // Only one :: allowed
                double_colon_pos = group_idx;
                i += 2;
                continue;
            }
        } else {
            const digit = hexDigit(ch) orelse return null;
            num = num * 16 + digit;
            has_digit = true;
        }
        i += 1;
    }

    // Store last group
    if (has_digit) {
        if (group_idx >= 8) return null;
        groups[group_idx] = num;
        group_idx += 1;
    }

    // Expand :: if present
    if (double_colon_pos) |pos| {
        const groups_after = group_idx - pos;
        const zeros_needed = 8 - group_idx;
        // Shift groups after :: to the end
        var j: usize = 7;
        var src: usize = group_idx;
        while (src > pos) {
            src -= 1;
            groups[j] = groups[src];
            if (j == 0) break;
            j -= 1;
        }
        // Zero out the gap
        var k: usize = pos;
        while (k < pos + zeros_needed) : (k += 1) {
            groups[k] = 0;
        }
        _ = groups_after;
    } else {
        if (group_idx != 8) return null;
    }

    // Convert groups to bytes
    for (0..8) |g| {
        result[g * 2] = @intCast(groups[g] >> 8);
        result[g * 2 + 1] = @intCast(groups[g] & 0xFF);
    }

    return result;
}

fn hexDigit(ch: u8) ?u16 {
    if (ch >= '0' and ch <= '9') return ch - '0';
    if (ch >= 'a' and ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' and ch <= 'F') return ch - 'A' + 10;
    return null;
}

/// Format 8 IPv6 groups into compact string with :: compression.
fn formatIPv6(buf: []u8, groups: [8]u16) []u8 {
    // Find the longest run of consecutive zeros for :: compression
    var best_start: usize = 8;
    var best_len: usize = 0;
    var run_start: usize = 0;
    var run_len: usize = 0;

    for (0..8) |gi| {
        if (groups[gi] == 0) {
            if (run_len == 0) run_start = gi;
            run_len += 1;
        } else {
            if (run_len > best_len and run_len >= 2) {
                best_start = run_start;
                best_len = run_len;
            }
            run_len = 0;
        }
    }
    if (run_len > best_len and run_len >= 2) {
        best_start = run_start;
        best_len = run_len;
    }

    var pos: usize = 0;
    var need_sep = false;

    if (best_len >= 2) {
        // Format with :: compression
        var gi: usize = 0;
        while (gi < 8) : (gi += 1) {
            if (gi == best_start) {
                // Write "::" for the compressed zero run
                buf[pos] = ':';
                pos += 1;
                buf[pos] = ':';
                pos += 1;
                gi += best_len - 1; // skip zero groups (loop will +1)
                need_sep = false;
                // If :: is at the end, no trailing separator needed
                continue;
            }
            if (need_sep) {
                buf[pos] = ':';
                pos += 1;
            }
            pos += formatHexGroup(buf[pos..], groups[gi]);
            need_sep = true;
        }
    } else {
        // No compression
        for (0..8) |gi| {
            if (gi > 0) {
                buf[pos] = ':';
                pos += 1;
            }
            pos += formatHexGroup(buf[pos..], groups[gi]);
        }
    }

    return buf[0..pos];
}

fn formatHexGroup(buf: []u8, val: u16) usize {
    const hex = "0123456789abcdef";
    if (val == 0) {
        buf[0] = '0';
        return 1;
    }
    var v = val;
    var digits: [4]u8 = undefined;
    var count: usize = 0;
    while (v > 0) {
        digits[count] = hex[@intCast(v & 0xF)];
        v >>= 4;
        count += 1;
    }
    // Reverse
    for (0..count) |d| {
        buf[d] = digits[count - 1 - d];
    }
    return count;
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

test "parseIPv4" {
    const result = parseIPv4("10.0.0.1").?;
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 1 }, result);

    try std.testing.expectEqual(@as(?[4]u8, null), parseIPv4(""));
    try std.testing.expectEqual(@as(?[4]u8, null), parseIPv4("not-an-ip"));
    try std.testing.expectEqual(@as(?[4]u8, null), parseIPv4("256.0.0.1"));
}

test "parseIPv6" {
    // Full address
    const full = parseIPv6("2001:0db8:0000:0000:0000:0000:0000:0001").?;
    try std.testing.expectEqual(@as(u8, 0x20), full[0]);
    try std.testing.expectEqual(@as(u8, 0x01), full[1]);
    try std.testing.expectEqual(@as(u8, 0x01), full[15]);

    // Compressed
    const compressed = parseIPv6("2001:db8::1").?;
    try std.testing.expectEqualSlices(u8, &full, &compressed);

    // All zeros
    const zeros = parseIPv6("::").?;
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 16), &zeros);

    // Invalid
    try std.testing.expectEqual(@as(?[16]u8, null), parseIPv6(""));
    try std.testing.expectEqual(@as(?[16]u8, null), parseIPv6("not-ipv6"));
}
