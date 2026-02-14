//! Portable network endpoint — replaces posix.sockaddr for cross-platform use.
//!
//! This type is used throughout the net/ layer instead of posix.sockaddr,
//! enabling compilation on platforms without POSIX (e.g., ESP32 with lwIP).

const std = @import("std");
const mem = std.mem;

/// A portable IPv4 endpoint (address + port).
/// Replaces posix.sockaddr.in / posix.sockaddr + posix.socklen_t.
pub const Endpoint = struct {
    /// IPv4 address in network byte order (big-endian), e.g., {127, 0, 0, 1}.
    addr: [4]u8 = .{ 0, 0, 0, 0 },
    /// Port in host byte order.
    port: u16 = 0,

    pub const zero = Endpoint{};

    /// Create from IP octets and port.
    pub fn init(addr: [4]u8, port: u16) Endpoint {
        return .{ .addr = addr, .port = port };
    }

    /// Parse from "host:port" string (e.g., "127.0.0.1:8080", "0.0.0.0:0").
    pub fn parse(s: []const u8) ?Endpoint {
        const colon = mem.lastIndexOfScalar(u8, s, ':') orelse return null;
        const host = s[0..colon];
        const port_str = s[colon + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return null;

        var addr: [4]u8 = .{ 0, 0, 0, 0 };
        if (mem.eql(u8, host, "0.0.0.0")) {
            // addr stays all zeros
        } else {
            var octets_it = mem.splitScalar(u8, host, '.');
            var idx: usize = 0;
            while (octets_it.next()) |octet_str| : (idx += 1) {
                if (idx >= 4) return null;
                addr[idx] = std.fmt.parseInt(u8, octet_str, 10) catch return null;
            }
            if (idx != 4) return null;
        }

        return Endpoint{ .addr = addr, .port = port };
    }

    /// Format as "a.b.c.d:port".
    pub fn format(self: Endpoint, buf: []u8) []const u8 {
        var stream = std.io.fixedBufferStream(buf);
        const writer = stream.writer();
        writer.print("{d}.{d}.{d}.{d}:{d}", .{
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.port,
        }) catch {};
        return stream.getWritten();
    }

    /// Check if the endpoint is the zero/unset value.
    pub fn isZero(self: Endpoint) bool {
        return self.port == 0 and self.addr[0] == 0 and self.addr[1] == 0 and
            self.addr[2] == 0 and self.addr[3] == 0;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Endpoint.parse" {
    const ep1 = Endpoint.parse("127.0.0.1:8080").?;
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, ep1.addr);
    try std.testing.expectEqual(@as(u16, 8080), ep1.port);

    const ep2 = Endpoint.parse("0.0.0.0:0").?;
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, ep2.addr);
    try std.testing.expectEqual(@as(u16, 0), ep2.port);

    try std.testing.expect(Endpoint.parse("invalid") == null);
    try std.testing.expect(Endpoint.parse("256.0.0.1:80") == null);
}

test "Endpoint.format" {
    const ep = Endpoint.init(.{ 192, 168, 1, 1 }, 443);
    var buf: [32]u8 = undefined;
    const s = ep.format(&buf);
    try std.testing.expectEqualStrings("192.168.1.1:443", s);
}

test "Endpoint.isZero" {
    try std.testing.expect(Endpoint.zero.isZero());
    try std.testing.expect(!Endpoint.init(.{ 127, 0, 0, 1 }, 80).isZero());
}
