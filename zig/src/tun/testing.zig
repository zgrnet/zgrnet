//! Test utilities for TUN device testing.
//!
//! Provides functions to build and verify IP packets for testing.

const std = @import("std");

/// ICMP message types
pub const IcmpType = enum(u8) {
    echo_reply = 0,
    echo_request = 8,
};

/// IP protocol numbers
pub const IpProtocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
};

/// Calculate IPv4 header checksum
pub fn calculateIpv4Checksum(header: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    // Sum all 16-bit words, skipping checksum field (bytes 10-11)
    while (i < header.len) : (i += 2) {
        if (i == 10) {
            // Skip checksum field
            continue;
        }
        const word: u16 = (@as(u16, header[i]) << 8) | header[i + 1];
        sum += word;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~@as(u16, @truncate(sum));
}

/// Calculate ICMP checksum
pub fn calculateIcmpChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    // Sum all 16-bit words
    while (i + 1 < data.len) : (i += 2) {
        const word: u16 = (@as(u16, data[i]) << 8) | data[i + 1];
        sum += word;
    }

    // If odd length, add last byte
    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~@as(u16, @truncate(sum));
}

/// Build an IPv4 header
pub fn buildIpv4Header(
    buf: *[20]u8,
    src: [4]u8,
    dst: [4]u8,
    protocol: IpProtocol,
    payload_len: u16,
) void {
    const total_len = 20 + payload_len;

    // Version (4) and IHL (5 = 20 bytes)
    buf[0] = 0x45;
    // DSCP and ECN
    buf[1] = 0x00;
    // Total length
    buf[2] = @truncate(total_len >> 8);
    buf[3] = @truncate(total_len);
    // Identification
    buf[4] = 0x00;
    buf[5] = 0x01;
    // Flags and fragment offset
    buf[6] = 0x40; // Don't fragment
    buf[7] = 0x00;
    // TTL
    buf[8] = 64;
    // Protocol
    buf[9] = @intFromEnum(protocol);
    // Checksum (placeholder)
    buf[10] = 0x00;
    buf[11] = 0x00;
    // Source address
    buf[12] = src[0];
    buf[13] = src[1];
    buf[14] = src[2];
    buf[15] = src[3];
    // Destination address
    buf[16] = dst[0];
    buf[17] = dst[1];
    buf[18] = dst[2];
    buf[19] = dst[3];

    // Calculate and set checksum
    const checksum = calculateIpv4Checksum(buf);
    buf[10] = @truncate(checksum >> 8);
    buf[11] = @truncate(checksum);
}

/// Build an ICMP echo request/reply packet
///
/// Returns the total packet length (IP header + ICMP).
pub fn buildIcmpPacket(
    buf: []u8,
    src: [4]u8,
    dst: [4]u8,
    icmp_type: IcmpType,
) usize {
    const icmp_len: u16 = 8; // ICMP header only, no data
    const total_len = 20 + icmp_len;

    if (buf.len < total_len) {
        return 0;
    }

    // Build IP header
    buildIpv4Header(buf[0..20], src, dst, .icmp, icmp_len);

    // Build ICMP header
    const icmp = buf[20..];
    icmp[0] = @intFromEnum(icmp_type); // Type
    icmp[1] = 0; // Code
    icmp[2] = 0; // Checksum (placeholder)
    icmp[3] = 0;
    icmp[4] = 0x00; // Identifier
    icmp[5] = 0x01;
    icmp[6] = 0x00; // Sequence number
    icmp[7] = 0x01;

    // Calculate ICMP checksum
    const checksum = calculateIcmpChecksum(icmp[0..icmp_len]);
    icmp[2] = @truncate(checksum >> 8);
    icmp[3] = @truncate(checksum);

    return total_len;
}

/// Verify if a packet is an ICMP echo reply
pub fn isIcmpReply(packet: []const u8) bool {
    if (packet.len < 28) return false;

    // Check IP version
    if ((packet[0] >> 4) != 4) return false;

    // Check protocol is ICMP
    if (packet[9] != @intFromEnum(IpProtocol.icmp)) return false;

    // Check ICMP type is echo reply
    const icmp_offset = (packet[0] & 0x0F) * 4;
    if (packet.len < icmp_offset + 1) return false;

    return packet[icmp_offset] == @intFromEnum(IcmpType.echo_reply);
}

/// Verify IPv4 header checksum
pub fn verifyIpv4Checksum(header: []const u8) bool {
    if (header.len < 20) return false;

    var sum: u32 = 0;
    var i: usize = 0;

    while (i + 1 < 20) : (i += 2) {
        const word: u16 = (@as(u16, header[i]) << 8) | header[i + 1];
        sum += word;
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @as(u16, @truncate(sum)) == 0xFFFF;
}

/// Extract source IP from IPv4 packet
pub fn getSrcIp(packet: []const u8) ?[4]u8 {
    if (packet.len < 20) return null;
    return packet[12..16].*;
}

/// Extract destination IP from IPv4 packet
pub fn getDstIp(packet: []const u8) ?[4]u8 {
    if (packet.len < 20) return null;
    return packet[16..20].*;
}

test "buildIpv4Header" {
    var buf: [20]u8 = undefined;
    buildIpv4Header(&buf, .{ 192, 168, 1, 1 }, .{ 192, 168, 1, 2 }, .icmp, 8);

    // Verify version and IHL
    try std.testing.expectEqual(@as(u8, 0x45), buf[0]);

    // Verify addresses
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1 }, buf[12..16]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 2 }, buf[16..20]);

    // Verify checksum is valid
    try std.testing.expect(verifyIpv4Checksum(&buf));
}

test "buildIcmpPacket" {
    var buf: [64]u8 = undefined;
    const len = buildIcmpPacket(&buf, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, .echo_request);

    try std.testing.expectEqual(@as(usize, 28), len);

    // Verify IP header
    try std.testing.expectEqual(@as(u8, 0x45), buf[0]);
    try std.testing.expectEqual(@as(u8, @intFromEnum(IpProtocol.icmp)), buf[9]);

    // Verify ICMP type
    try std.testing.expectEqual(@as(u8, @intFromEnum(IcmpType.echo_request)), buf[20]);
}

test "isIcmpReply" {
    var buf: [64]u8 = undefined;
    _ = buildIcmpPacket(&buf, .{ 10, 0, 0, 2 }, .{ 10, 0, 0, 1 }, .echo_reply);
    try std.testing.expect(isIcmpReply(&buf));

    _ = buildIcmpPacket(&buf, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, .echo_request);
    try std.testing.expect(!isIcmpReply(&buf));
}

test "calculateIcmpChecksum" {
    // Test with known ICMP packet
    const icmp_data = [_]u8{
        8, 0, // Type: Echo Request, Code: 0
        0, 0, // Checksum placeholder
        0, 1, // Identifier
        0, 1, // Sequence
    };
    const checksum = calculateIcmpChecksum(&icmp_data);

    // Verify checksum is non-zero
    try std.testing.expect(checksum != 0);

    // Create packet with correct checksum and verify it sums to 0xFFFF
    var packet: [8]u8 = icmp_data;
    packet[2] = @truncate(checksum >> 8);
    packet[3] = @truncate(checksum);

    // Sum should be 0xFFFF (ones' complement check)
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < packet.len) : (i += 2) {
        sum += (@as(u32, packet[i]) << 8) | packet[i + 1];
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    try std.testing.expectEqual(@as(u32, 0xFFFF), sum);
}

test "calculateIcmpChecksum odd length" {
    // Test with odd-length data
    const data = [_]u8{ 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 }; // 7 bytes
    const checksum = calculateIcmpChecksum(&data);
    try std.testing.expect(checksum != 0);
}

test "verifyIpv4Checksum" {
    var header: [20]u8 = undefined;
    buildIpv4Header(&header, .{ 192, 168, 1, 1 }, .{ 192, 168, 1, 2 }, .icmp, 8);

    // Valid checksum
    try std.testing.expect(verifyIpv4Checksum(&header));

    // Corrupt checksum
    header[10] ^= 0xFF;
    try std.testing.expect(!verifyIpv4Checksum(&header));

    // Too short
    try std.testing.expect(!verifyIpv4Checksum(header[0..10]));
}

test "getSrcIp and getDstIp" {
    var buf: [64]u8 = undefined;
    _ = buildIcmpPacket(&buf, .{ 192, 168, 1, 100 }, .{ 10, 0, 0, 1 }, .echo_request);

    // Get source IP
    const src = getSrcIp(&buf);
    try std.testing.expect(src != null);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 100 }, &src.?);

    // Get destination IP
    const dst = getDstIp(&buf);
    try std.testing.expect(dst != null);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 1 }, &dst.?);

    // Too short packet
    try std.testing.expect(getSrcIp(buf[0..10]) == null);
    try std.testing.expect(getDstIp(buf[0..15]) == null);
}

test "buildIpv4Header various protocols" {
    var buf: [20]u8 = undefined;

    // TCP
    buildIpv4Header(&buf, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, .tcp, 20);
    try std.testing.expectEqual(@as(u8, @intFromEnum(IpProtocol.tcp)), buf[9]);
    try std.testing.expect(verifyIpv4Checksum(&buf));

    // UDP
    buildIpv4Header(&buf, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, .udp, 8);
    try std.testing.expectEqual(@as(u8, @intFromEnum(IpProtocol.udp)), buf[9]);
    try std.testing.expect(verifyIpv4Checksum(&buf));

    // ICMP
    buildIpv4Header(&buf, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, .icmp, 8);
    try std.testing.expectEqual(@as(u8, @intFromEnum(IpProtocol.icmp)), buf[9]);
    try std.testing.expect(verifyIpv4Checksum(&buf));
}

test "buildIcmpPacket buffer too small" {
    var small_buf: [20]u8 = undefined;
    const len = buildIcmpPacket(&small_buf, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, .echo_request);
    try std.testing.expectEqual(@as(usize, 0), len);
}

// ============================================================================
// TUN Device Tests (require root/admin privileges)
// ============================================================================

const Tun = @import("mod.zig").Tun;
const TunError = @import("mod.zig").TunError;

test "tun create and close" {
    // This test requires root/admin privileges
    var tun = Tun.create(null) catch |err| {
        // Skip test if permission denied (not running as root)
        if (err == TunError.PermissionDenied) {
            std.debug.print("Skipping test: requires root/admin privileges\n", .{});
            return;
        }
        return err;
    };
    defer tun.close();

    // Verify we got a valid name
    const name = tun.getName();
    try std.testing.expect(name.len > 0);
    std.debug.print("Created TUN device: {s}\n", .{name});
}

test "tun mtu" {
    var tun = Tun.create(null) catch |err| {
        if (err == TunError.PermissionDenied) {
            std.debug.print("Skipping test: requires root/admin privileges\n", .{});
            return;
        }
        return err;
    };
    defer tun.close();

    // Get default MTU
    const mtu = try tun.getMtu();
    std.debug.print("Default MTU: {d}\n", .{mtu});

    // Set new MTU
    try tun.setMtu(1400);
    const new_mtu = try tun.getMtu();
    try std.testing.expectEqual(@as(u32, 1400), new_mtu);
}

test "tun nonblocking" {
    var tun = Tun.create(null) catch |err| {
        if (err == TunError.PermissionDenied) {
            std.debug.print("Skipping test: requires root/admin privileges\n", .{});
            return;
        }
        return err;
    };
    defer tun.close();

    // Enable non-blocking mode
    try tun.setNonBlocking(true);

    // Read should return WouldBlock immediately (no data available)
    var buf: [1500]u8 = undefined;
    const result = tun.read(&buf);
    try std.testing.expectError(TunError.WouldBlock, result);
}

test "tun ip config" {
    var tun = Tun.create(null) catch |err| {
        if (err == TunError.PermissionDenied) {
            std.debug.print("Skipping test: requires root/admin privileges\n", .{});
            return;
        }
        return err;
    };
    defer tun.close();

    // Set IPv4 address
    try tun.setIPv4(.{ 10, 0, 100, 1 }, .{ 255, 255, 255, 0 });

    // Bring interface up
    try tun.setUp();

    std.debug.print("TUN {s} configured with IP 10.0.100.1/24\n", .{tun.getName()});

    // Bring interface down
    try tun.setDown();
}

test "tun ipv6 config" {
    var tun = Tun.create(null) catch |err| {
        if (err == TunError.PermissionDenied) {
            std.debug.print("Skipping test: requires root/admin privileges\n", .{});
            return;
        }
        return err;
    };
    defer tun.close();

    // Set IPv6 address fd00::1/64
    // fd00::1 = 0xfd, 0x00, 0x00, ..., 0x01
    const ipv6_addr = [16]u8{ 0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    try tun.setIPv6(ipv6_addr, 64);

    // Bring interface up
    try tun.setUp();

    std.debug.print("TUN {s} configured with IPv6 fd00::1/64\n", .{tun.getName()});

    // Bring interface down
    try tun.setDown();
}

test "tun read write" {
    // Test TUN read/write by sending UDP from host through TUN:
    // 1. TUN IP = 10.0.0.1/24, non-blocking mode
    // 2. Host sends UDP packet to 10.0.0.2 (in TUN subnet)
    // 3. Kernel routes packet through TUN
    // 4. Read packet from TUN and verify

    var tun = Tun.create(null) catch |err| {
        if (err == TunError.PermissionDenied) {
            std.debug.print("Skipping test: requires root/admin privileges\n", .{});
            return;
        }
        return err;
    };
    defer tun.close();

    // Configure TUN with IP 10.0.0.1/24
    try tun.setIPv4(.{ 10, 0, 0, 1 }, .{ 255, 255, 255, 0 });
    try tun.setUp();
    try tun.setNonBlocking(true);

    std.debug.print("TUN {s} configured with 10.0.0.1/24 (non-blocking)\n", .{tun.getName()});

    // Create UDP socket and send to 10.0.0.2 (in TUN subnet)
    // This packet will be routed through TUN by the kernel
    const udp_sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch |err| {
        std.debug.print("Failed to create UDP socket: {}\n", .{err});
        return err;
    };
    defer std.posix.close(udp_sock);

    const dest_addr = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 12345),
        .addr = @bitCast([4]u8{ 10, 0, 0, 2 }),
    };

    const msg = "hello from TUN test";
    _ = std.posix.sendto(udp_sock, msg, 0, @ptrCast(&dest_addr), @sizeOf(@TypeOf(dest_addr))) catch |err| {
        std.debug.print("sendto() failed: {}\n", .{err});
        return err;
    };
    std.debug.print("Sent UDP packet to 10.0.0.2:12345\n", .{});

    // Use poll() to wait for packet with 100ms timeout
    var fds = [_]std.posix.pollfd{.{
        .fd = @intCast(tun.getHandle()),
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};

    const ready = std.posix.poll(&fds, 100) catch |err| {
        std.debug.print("poll() failed: {}\n", .{err});
        return err;
    };

    // Read packets until we find the IPv4 UDP packet we sent
    // (Skip any IPv6 packets like router solicitations)
    var attempts: usize = 0;
    const max_attempts = 10;

    while (attempts < max_attempts) : (attempts += 1) {
        if (ready > 0 and (fds[0].revents & std.posix.POLL.IN) != 0) {
            // Data available, read it
            var read_buf: [1500]u8 = undefined;
            const n = tun.read(&read_buf) catch |err| {
                std.debug.print("read() failed: {}\n", .{err});
                return err;
            };

            std.debug.print("Read {d} bytes from TUN\n", .{n});

            // Verify it's a valid IP packet
            try std.testing.expect(n >= 20); // At least IP header

            // Check IP version
            const version = read_buf[0] >> 4;
            if (version != 4) {
                std.debug.print("Skipping non-IPv4 packet (version {d})\n", .{version});
                continue;
            }

            // Verify destination IP is 10.0.0.2
            const dst_ip = getDstIp(read_buf[0..n]) orelse unreachable;
            try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 2 }, &dst_ip);

            // Check protocol is UDP (17)
            try std.testing.expectEqual(@as(u8, 17), read_buf[9]);

            std.debug.print("Verified: UDP packet to {d}.{d}.{d}.{d}\n", .{
                dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
            });
            return; // Success!
        } else {
            // No packet within timeout - this is a test failure
            std.debug.print("ERROR: No packet received within 100ms\n", .{});
            return error.TestUnexpectedResult;
        }
    }

    std.debug.print("ERROR: No IPv4 packet found after {d} attempts\n", .{max_attempts});
    return error.TestUnexpectedResult;
}

test "tun handle" {
    var tun = Tun.create(null) catch |err| {
        if (err == TunError.PermissionDenied) {
            std.debug.print("Skipping test: requires root/admin privileges\n", .{});
            return;
        }
        return err;
    };
    defer tun.close();

    const handle = tun.getHandle();
    // On Unix, handle should be a valid file descriptor (>= 0)
    // On Windows, it should be a valid HANDLE
    try std.testing.expect(@as(i64, @intCast(handle)) >= 0);
    std.debug.print("TUN handle: {d}\n", .{handle});
}
