//! UDP Transport implementation.
//!
//! Provides a simple UDP transport that connects to a fixed remote address.
//! Does not support roaming - suitable for direct P2P connections.

const std = @import("std");
const posix = std.posix;
const net = std.net;

/// UDP address wrapper.
pub const UdpAddr = struct {
    inner: net.Address,

    const Self = @This();

    /// Create from net.Address.
    pub fn init(addr: net.Address) Self {
        return .{ .inner = addr };
    }

    /// Parse from string like "127.0.0.1:8080".
    pub fn parse(addr_str: []const u8) !Self {
        // Find last colon (for host:port split)
        const colon_pos = std.mem.lastIndexOfScalar(u8, addr_str, ':') orelse return error.InvalidAddress;
        const host = addr_str[0..colon_pos];
        const port_str = addr_str[colon_pos + 1 ..];

        const port_num = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidAddress;

        // Use std.net.Ip4Address.parse for robust IPv4 address parsing
        const ip4 = std.net.Ip4Address.parse(host, port_num) catch return error.InvalidAddress;

        return .{
            .inner = net.Address{ .in = ip4 },
        };
    }

    /// Get port.
    pub fn port(self: Self) u16 {
        return self.inner.getPort();
    }

    /// Format as string.
    pub fn format(self: Self, buf: []u8) ![]const u8 {
        var stream = std.io.fixedBufferStream(buf);
        try self.inner.format(&[_]u8{}, stream.writer());
        return stream.getWritten();
    }
};

/// Unconnected UDP Transport.
///
/// This transport can send/receive to/from any address, suitable for
/// servers or listeners that need to communicate with multiple peers.
pub const UdpTransport = struct {
    fd: posix.fd_t,
    local_addr: UdpAddr,

    const Self = @This();

    /// Bind to a local address.
    ///
    /// # Arguments
    /// * `addr_str` - Local address to bind to (e.g., "127.0.0.1:0" for any available port)
    pub fn init(addr_str: []const u8) !Self {
        const local = try UdpAddr.parse(addr_str);

        // Create socket
        const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        errdefer posix.close(fd);

        // Bind
        try posix.bind(fd, &local.inner.any, local.inner.getOsSockLen());

        // Get actual bound address
        var bound_addr: net.Address = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        try posix.getsockname(fd, &bound_addr.any, &bound_len);

        return .{
            .fd = fd,
            .local_addr = UdpAddr.init(bound_addr),
        };
    }

    /// Send data to a specific address.
    pub fn sendTo(self: Self, data: []const u8, to_addr: UdpAddr) !usize {
        return posix.sendto(self.fd, data, 0, &to_addr.inner.any, to_addr.inner.getOsSockLen());
    }

    /// Receive data from any address.
    pub fn recvFrom(self: Self, buf: []u8) !struct { bytes_read: usize, from: UdpAddr } {
        var from_addr: net.Address = undefined;
        var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        const n = try posix.recvfrom(self.fd, buf, 0, &from_addr.any, &from_len);
        return .{
            .bytes_read = n,
            .from = UdpAddr.init(from_addr),
        };
    }

    /// Get the local address.
    pub fn getLocalAddr(self: Self) UdpAddr {
        return self.local_addr;
    }

    /// Close the transport.
    pub fn close(self: Self) void {
        posix.close(self.fd);
    }

    /// Set receive timeout in milliseconds.
    pub fn setRecvTimeout(self: Self, timeout_ms: u32) !void {
        const tv = posix.timeval{
            .sec = @intCast(timeout_ms / 1000),
            .usec = @intCast((timeout_ms % 1000) * 1000),
        };
        try posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
    }

    /// Set send timeout in milliseconds.
    pub fn setSendTimeout(self: Self, timeout_ms: u32) !void {
        const tv = posix.timeval{
            .sec = @intCast(timeout_ms / 1000),
            .usec = @intCast((timeout_ms % 1000) * 1000),
        };
        try posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv));
    }
};

// =============================================================================
// Tests
// =============================================================================

test "UdpTransport send/recv" {
    // Create two transports
    var server = try UdpTransport.init("127.0.0.1:0");
    defer server.close();

    var client = try UdpTransport.init("127.0.0.1:0");
    defer client.close();

    // Send from client to server
    const data = "hello world";
    _ = try client.sendTo(data, server.getLocalAddr());

    // Receive on server
    var recv_buf: [1024]u8 = undefined;
    const result = try server.recvFrom(&recv_buf);

    try std.testing.expectEqualStrings(data, recv_buf[0..result.bytes_read]);
}

test "UdpAddr.parse" {
    const addr = try UdpAddr.parse("127.0.0.1:8080");
    try std.testing.expectEqual(@as(u16, 8080), addr.port());
}
