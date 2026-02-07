//! IP Packet parsing and building utilities.
//!
//! Handles IPv4/IPv6 header parsing, construction, and checksum recalculation.
//! Used by Host to strip/rebuild IP headers when forwarding packets between
//! the TUN device and encrypted UDP transport.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Parsed information from an IP packet.
pub const PacketInfo = struct {
    version: u8, // 4 or 6
    protocol: u8, // IP protocol number (1=ICMP, 6=TCP, 17=UDP)
    src_ip: []const u8, // source IP address (4 bytes for v4, 16 bytes for v6)
    dst_ip: []const u8, // destination IP address
    payload: []const u8, // transport layer payload (after IP header)
    header_len: usize, // IP header length in bytes
};

pub const PacketError = error{
    TooShort,
    TooLarge,
    InvalidVersion,
};

/// Parse an IP packet and extract header info.
/// Handles both IPv4 and IPv6 based on the version nibble.
/// The returned slices point into the original packet buffer.
pub fn parseIpPacket(pkt: []const u8) PacketError!PacketInfo {
    if (pkt.len < 1) return PacketError.TooShort;

    const version = pkt[0] >> 4;
    return switch (version) {
        4 => parseIpv4(pkt),
        6 => parseIpv6(pkt),
        else => PacketError.InvalidVersion,
    };
}

fn parseIpv4(pkt: []const u8) PacketError!PacketInfo {
    if (pkt.len < 20) return PacketError.TooShort;

    const ihl: usize = @as(usize, pkt[0] & 0x0F) * 4;
    if (ihl < 20 or pkt.len < ihl) return PacketError.TooShort;

    return PacketInfo{
        .version = 4,
        .protocol = pkt[9],
        .src_ip = pkt[12..16],
        .dst_ip = pkt[16..20],
        .payload = pkt[ihl..],
        .header_len = ihl,
    };
}

fn parseIpv6(pkt: []const u8) PacketError!PacketInfo {
    if (pkt.len < 40) return PacketError.TooShort;

    return PacketInfo{
        .version = 6,
        .protocol = pkt[6], // Next Header
        .src_ip = pkt[8..24],
        .dst_ip = pkt[24..40],
        .payload = pkt[40..],
        .header_len = 40,
    };
}

/// Build an IPv4 packet from components into the provided buffer.
/// Constructs a minimal 20-byte IPv4 header and appends the transport payload.
/// Recalculates both IP header checksum and transport checksums (TCP/UDP).
/// Allocates exactly the needed size. Caller must free the returned slice.
pub fn buildIpv4Packet(
    allocator: Allocator,
    src_ip: [4]u8,
    dst_ip: [4]u8,
    protocol: u8,
    payload: []const u8,
) (PacketError || Allocator.Error)![]u8 {
    const header_len: usize = 20;
    const total_len = header_len + payload.len;
    if (total_len > 65535) return PacketError.TooLarge;

    const buf = try allocator.alloc(u8, total_len);
    errdefer allocator.free(buf);

    // IPv4 header
    buf[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    buf[1] = 0x00; // DSCP / ECN
    std.mem.writeInt(u16, buf[2..4], @intCast(total_len), .big);
    buf[4] = 0; // Identification
    buf[5] = 0;
    buf[6] = 0x40; // Don't Fragment flag
    buf[7] = 0x00; // Fragment offset
    buf[8] = 64; // TTL
    buf[9] = protocol;
    buf[10] = 0; // Header checksum (computed below)
    buf[11] = 0;
    @memcpy(buf[12..16], &src_ip);
    @memcpy(buf[16..20], &dst_ip);

    // Compute IP header checksum
    const cs = ipChecksum(buf[0..header_len]);
    std.mem.writeInt(u16, buf[10..12], cs, .big);

    // Copy transport payload
    @memcpy(buf[header_len .. header_len + payload.len], payload);

    // Fix transport layer checksum (TCP/UDP use pseudo-header with IPs)
    fixTransportChecksum(buf[header_len .. header_len + payload.len], &src_ip, &dst_ip, protocol);

    return buf;
}

/// Build an IPv6 packet from components.
/// Allocates exactly the needed size. Caller must free the returned slice.
pub fn buildIpv6Packet(
    allocator: Allocator,
    src_ip: [16]u8,
    dst_ip: [16]u8,
    protocol: u8,
    payload: []const u8,
) (PacketError || Allocator.Error)![]u8 {
    const header_len: usize = 40;
    const total_len = header_len + payload.len;
    if (payload.len > 65535) return PacketError.TooLarge;

    const buf = try allocator.alloc(u8, total_len);
    errdefer allocator.free(buf);

    // IPv6 header
    buf[0] = 0x60; // Version 6
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0; // Traffic class and flow label
    std.mem.writeInt(u16, buf[4..6], @intCast(payload.len), .big);
    buf[6] = protocol; // Next Header
    buf[7] = 64; // Hop Limit
    @memcpy(buf[8..24], &src_ip);
    @memcpy(buf[24..40], &dst_ip);

    // Copy transport payload
    @memcpy(buf[header_len .. header_len + payload.len], payload);

    // Fix transport layer checksum
    fixTransportChecksumV6(buf[header_len .. header_len + payload.len], &src_ip, &dst_ip, protocol);

    return buf;
}

/// Recalculates TCP/UDP checksums for IPv4.
fn fixTransportChecksum(transport: []u8, src_ip: *const [4]u8, dst_ip: *const [4]u8, protocol: u8) void {
    switch (protocol) {
        6 => { // TCP
            if (transport.len < 20) return;
            // Zero out existing checksum
            transport[16] = 0;
            transport[17] = 0;
            const cs = pseudoHeaderChecksum(src_ip, dst_ip, protocol, transport);
            std.mem.writeInt(u16, transport[16..18], cs, .big);
        },
        17 => { // UDP
            if (transport.len < 8) return;
            // In IPv4, UDP checksum 0 means "not computed" — leave as is
            if (transport[6] == 0 and transport[7] == 0) return;
            transport[6] = 0;
            transport[7] = 0;
            var cs = pseudoHeaderChecksum(src_ip, dst_ip, protocol, transport);
            if (cs == 0) cs = 0xFFFF; // RFC 768: transmitted as all ones
            std.mem.writeInt(u16, transport[6..8], cs, .big);
        },
        // ICMP (protocol 1): checksum doesn't use pseudo-header, no fix needed
        else => {},
    }
}

/// Recalculates TCP/UDP/ICMPv6 checksums for IPv6.
fn fixTransportChecksumV6(transport: []u8, src_ip: *const [16]u8, dst_ip: *const [16]u8, protocol: u8) void {
    switch (protocol) {
        6 => { // TCP
            if (transport.len < 20) return;
            transport[16] = 0;
            transport[17] = 0;
            const cs = pseudoHeaderChecksumV6(src_ip, dst_ip, protocol, transport);
            std.mem.writeInt(u16, transport[16..18], cs, .big);
        },
        17 => { // UDP
            if (transport.len < 8) return;
            transport[6] = 0;
            transport[7] = 0;
            var cs = pseudoHeaderChecksumV6(src_ip, dst_ip, protocol, transport);
            if (cs == 0) cs = 0xFFFF;
            std.mem.writeInt(u16, transport[6..8], cs, .big);
        },
        58 => { // ICMPv6 (uses pseudo-header, unlike ICMPv4)
            if (transport.len < 8) return;
            transport[2] = 0;
            transport[3] = 0;
            const cs = pseudoHeaderChecksumV6(src_ip, dst_ip, protocol, transport);
            std.mem.writeInt(u16, transport[2..4], cs, .big);
        },
        else => {},
    }
}

/// Computes the TCP/UDP checksum including IPv4 pseudo-header.
fn pseudoHeaderChecksum(src_ip: *const [4]u8, dst_ip: *const [4]u8, protocol: u8, data: []const u8) u16 {
    var sum: u32 = 0;

    // Pseudo-header: src IP (4 bytes)
    sum += @as(u32, src_ip[0]) << 8 | @as(u32, src_ip[1]);
    sum += @as(u32, src_ip[2]) << 8 | @as(u32, src_ip[3]);
    // Pseudo-header: dst IP (4 bytes)
    sum += @as(u32, dst_ip[0]) << 8 | @as(u32, dst_ip[1]);
    sum += @as(u32, dst_ip[2]) << 8 | @as(u32, dst_ip[3]);
    // Pseudo-header: zero + protocol (2 bytes)
    sum += @as(u32, protocol);
    // Pseudo-header: TCP/UDP length (2 bytes)
    sum += @as(u32, @intCast(data.len));

    // Data
    sum = checksumData(sum, data);

    return checksumFold(sum);
}

/// Computes the checksum including IPv6 pseudo-header.
fn pseudoHeaderChecksumV6(src_ip: *const [16]u8, dst_ip: *const [16]u8, protocol: u8, data: []const u8) u16 {
    var sum: u32 = 0;

    // Pseudo-header: src IP (16 bytes)
    var i: usize = 0;
    while (i < 16) : (i += 2) {
        sum += @as(u32, src_ip[i]) << 8 | @as(u32, src_ip[i + 1]);
    }
    // Pseudo-header: dst IP (16 bytes)
    i = 0;
    while (i < 16) : (i += 2) {
        sum += @as(u32, dst_ip[i]) << 8 | @as(u32, dst_ip[i + 1]);
    }
    // Pseudo-header: upper-layer length (4 bytes, big-endian)
    sum += @as(u32, @intCast(data.len));
    // Pseudo-header: zero + next header (4 bytes)
    sum += @as(u32, protocol);

    // Data
    sum = checksumData(sum, data);

    return checksumFold(sum);
}

/// Computes the IPv4 header checksum.
pub fn ipChecksum(header: []const u8) u16 {
    var sum: u32 = 0;
    sum = checksumData(sum, header);
    return checksumFold(sum);
}

/// Adds data bytes to a running checksum sum.
fn checksumData(initial: u32, data: []const u8) u32 {
    var sum = initial;
    var idx: usize = 0;
    while (idx + 1 < data.len) : (idx += 2) {
        sum += @as(u32, data[idx]) << 8 | @as(u32, data[idx + 1]);
    }
    if (data.len % 2 == 1) {
        sum += @as(u32, data[data.len - 1]) << 8;
    }
    return sum;
}

/// Folds a 32-bit sum into a 16-bit one's complement checksum.
fn checksumFold(initial: u32) u16 {
    var sum = initial;
    while (sum > 0xFFFF) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    return @intCast(~sum & 0xFFFF);
}

// ============================================================================
// Tests
// ============================================================================

test "parseIpPacket: IPv4 ICMP" {
    // Minimal IPv4 header (20 bytes) + 8 bytes ICMP payload
    var pkt = [_]u8{
        0x45, 0x00, 0x00, 0x1C, // version/IHL, DSCP, total length=28
        0x00, 0x00, 0x40, 0x00, // identification, flags, fragment offset
        0x40, 0x01, 0x00, 0x00, // TTL=64, protocol=ICMP(1), checksum=0
        100,  64,   0,    1, // src IP: 100.64.0.1
        100,  64,   0,    2, // dst IP: 100.64.0.2
        // ICMP payload (8 bytes)
        0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
    };

    const info = try parseIpPacket(&pkt);
    try std.testing.expectEqual(@as(u8, 4), info.version);
    try std.testing.expectEqual(@as(u8, 1), info.protocol);
    try std.testing.expectEqualSlices(u8, &.{ 100, 64, 0, 1 }, info.src_ip);
    try std.testing.expectEqualSlices(u8, &.{ 100, 64, 0, 2 }, info.dst_ip);
    try std.testing.expectEqual(@as(usize, 8), info.payload.len);
    try std.testing.expectEqual(@as(usize, 20), info.header_len);
}

test "parseIpPacket: IPv6" {
    // Minimal IPv6 header (40 bytes) + 4 bytes payload
    var pkt: [44]u8 = undefined;
    pkt[0] = 0x60; // version 6
    pkt[1] = 0;
    pkt[2] = 0;
    pkt[3] = 0;
    std.mem.writeInt(u16, pkt[4..6], 4, .big); // payload length = 4
    pkt[6] = 58; // Next Header = ICMPv6
    pkt[7] = 64; // Hop Limit
    @memset(pkt[8..24], 0x11); // src IP
    @memset(pkt[24..40], 0x22); // dst IP
    @memset(pkt[40..44], 0xAA); // payload

    const info = try parseIpPacket(&pkt);
    try std.testing.expectEqual(@as(u8, 6), info.version);
    try std.testing.expectEqual(@as(u8, 58), info.protocol);
    try std.testing.expectEqual(@as(usize, 40), info.header_len);
    try std.testing.expectEqual(@as(usize, 4), info.payload.len);
}

test "parseIpPacket: too short" {
    const empty = [_]u8{};
    try std.testing.expectError(PacketError.TooShort, parseIpPacket(&empty));

    const short = [_]u8{0x45}; // IPv4 but too short
    try std.testing.expectError(PacketError.TooShort, parseIpPacket(&short));
}

test "parseIpPacket: invalid version" {
    var pkt = [_]u8{ 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectError(PacketError.InvalidVersion, parseIpPacket(&pkt));
}

test "buildIpv4Packet: ICMP" {
    const allocator = std.testing.allocator;
    const payload = [_]u8{ 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01 };
    const pkt = try buildIpv4Packet(allocator, .{ 100, 64, 0, 1 }, .{ 100, 64, 0, 2 }, 1, &payload);
    defer allocator.free(pkt);

    try std.testing.expectEqual(@as(usize, 28), pkt.len);
    try std.testing.expectEqual(@as(u8, 0x45), pkt[0]);
    try std.testing.expectEqual(@as(u8, 64), pkt[8]); // TTL
    try std.testing.expectEqual(@as(u8, 1), pkt[9]); // Protocol = ICMP

    // Parse back
    const info = try parseIpPacket(pkt);
    try std.testing.expectEqualSlices(u8, &.{ 100, 64, 0, 1 }, info.src_ip);
    try std.testing.expectEqualSlices(u8, &.{ 100, 64, 0, 2 }, info.dst_ip);

    // Verify IP header checksum
    try std.testing.expectEqual(@as(u16, 0), ipChecksum(pkt[0..20]));
}

test "buildIpv4Packet: round-trip" {
    const allocator = std.testing.allocator;
    const src = [4]u8{ 10, 0, 0, 1 };
    const dst = [4]u8{ 10, 0, 0, 2 };
    const payload = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

    const pkt = try buildIpv4Packet(allocator, src, dst, 1, &payload);
    defer allocator.free(pkt);
    const info = try parseIpPacket(pkt);

    try std.testing.expectEqual(@as(u8, 4), info.version);
    try std.testing.expectEqual(@as(u8, 1), info.protocol);
    try std.testing.expectEqualSlices(u8, &src, info.src_ip);
    try std.testing.expectEqualSlices(u8, &dst, info.dst_ip);
    try std.testing.expectEqualSlices(u8, &payload, info.payload);
}

test "checksumFold: basic" {
    // Known: a simple sum that needs folding
    const result = checksumFold(0);
    try std.testing.expectEqual(@as(u16, 0xFFFF), result);
}
