//! UDP Transport implementation.
//!
//! Provides a simple UDP transport that connects to a fixed remote address.
//! Does not support roaming - suitable for direct P2P connections.

const std = @import("std");
const posix = std.posix;
const net = std.net;
const transport = @import("transport.zig");

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

        // Parse IPv4
        var octets: [4]u8 = undefined;
        var octet_it = std.mem.splitScalar(u8, host, '.');
        var i: usize = 0;
        while (octet_it.next()) |octet_str| : (i += 1) {
            if (i >= 4) return error.InvalidAddress;
            octets[i] = std.fmt.parseInt(u8, octet_str, 10) catch return error.InvalidAddress;
        }
        if (i != 4) return error.InvalidAddress;

        return .{
            .inner = net.Address.initIp4(octets, port_num),
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

    /// Convert to transport.Addr.
    pub fn toAddr(self: Self) transport.Addr {
        return .{ .udp = self };
    }
};

/// UDP Transport over a connected UDP socket.
///
/// This transport connects to a fixed remote address and does not support
/// roaming. Suitable for simple P2P connections where the remote endpoint
/// has a stable address.
pub const Udp = struct {
    fd: posix.fd_t,
    local_addr: UdpAddr,
    remote_addr: UdpAddr,

    const Self = @This();

    /// Create a new UDP transport.
    ///
    /// # Arguments
    /// * `local_addr` - Local address to bind to (e.g., "0.0.0.0:0" for any)
    /// * `remote_addr` - Remote address to connect to
    pub fn init(local_addr_str: []const u8, remote_addr_str: []const u8) !Self {
        const local = try UdpAddr.parse(local_addr_str);
        const remote = try UdpAddr.parse(remote_addr_str);

        // Create socket
        const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        errdefer posix.close(fd);

        // Bind
        try posix.bind(fd, &local.inner.any, local.inner.getOsSockLen());

        // Connect to remote
        try posix.connect(fd, &remote.inner.any, remote.inner.getOsSockLen());

        // Get actual bound address
        var bound_addr: net.Address = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        try posix.getsockname(fd, &bound_addr.any, &bound_len);

        return .{
            .fd = fd,
            .local_addr = UdpAddr.init(bound_addr),
            .remote_addr = remote,
        };
    }

    /// Create from existing file descriptor.
    pub fn fromFd(fd: posix.fd_t, remote_addr: UdpAddr) !Self {
        // Connect to remote
        try posix.connect(fd, &remote_addr.inner.any, remote_addr.inner.getOsSockLen());

        // Get local address
        var local_addr: net.Address = undefined;
        var local_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        try posix.getsockname(fd, &local_addr.any, &local_len);

        return .{
            .fd = fd,
            .local_addr = UdpAddr.init(local_addr),
            .remote_addr = remote_addr,
        };
    }

    /// Send data to the connected remote.
    pub fn send(self: Self, data: []const u8) !usize {
        return posix.send(self.fd, data, 0);
    }

    /// Receive data.
    pub fn recv(self: Self, buf: []u8) !usize {
        return posix.recv(self.fd, buf, 0);
    }

    /// Close the transport.
    pub fn close(self: *Self) void {
        posix.close(self.fd);
        self.fd = -1;
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

    /// Set receive buffer size.
    pub fn setRecvBufferSize(self: Self, size: u32) !void {
        try posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.RCVBUF, std.mem.asBytes(&size));
    }

    /// Set send buffer size.
    pub fn setSendBufferSize(self: Self, size: u32) !void {
        try posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&size));
    }

    // =========================================================================
    // Transport interface implementation
    // =========================================================================

    /// Send via Transport interface.
    pub fn transportSend(self: *Self, data: []const u8, _: transport.Addr) transport.TransportError!void {
        _ = self.send(data) catch return error.IoError;
    }

    /// Receive via Transport interface.
    pub fn transportRecv(self: *Self, buf: []u8) transport.TransportError!transport.RecvResult {
        const n = self.recv(buf) catch return error.IoError;
        return .{
            .bytes_read = n,
            .from_addr = self.remote_addr.toAddr(),
        };
    }

    /// Get local address via Transport interface.
    pub fn transportLocalAddr(self: *Self) transport.Addr {
        return self.local_addr.toAddr();
    }

    /// Close via Transport interface.
    pub fn transportClose(self: *Self) transport.TransportError!void {
        self.close();
    }

    /// Get Transport vtable.
    pub fn asTransport(self: *Self) transport.Transport {
        return .{
            .ptr = self,
            .vtable = &.{
                .send = @ptrCast(&transportSend),
                .recv = @ptrCast(&transportRecv),
                .local_addr = @ptrCast(&transportLocalAddr),
                .close = @ptrCast(&transportClose),
            },
        };
    }
};

// =============================================================================
// Tests
// =============================================================================

test "UdpAddr.parse" {
    const addr = try UdpAddr.parse("127.0.0.1:8080");
    try std.testing.expectEqual(@as(u16, 8080), addr.port());
}

test "Udp send/recv" {
    // Create server socket
    const server_addr = net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    const server_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(server_fd);

    try posix.bind(server_fd, &server_addr.any, server_addr.getOsSockLen());

    // Get bound address
    var bound_addr: net.Address = undefined;
    var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(server_fd, &bound_addr.any, &bound_len);

    const server_port = bound_addr.getPort();

    // Create client transport
    var buf: [32]u8 = undefined;
    const addr_str = try std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{server_port});

    var client = try Udp.init("127.0.0.1:0", addr_str);
    defer client.close();

    // Send from client
    const data = "hello world";
    const sent = try client.send(data);
    try std.testing.expectEqual(data.len, sent);

    // Receive on server
    var recv_buf: [1024]u8 = undefined;
    var from_addr: posix.sockaddr = undefined;
    var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    const received = try posix.recvfrom(server_fd, &recv_buf, 0, &from_addr, &from_len);

    try std.testing.expectEqualStrings(data, recv_buf[0..received]);
}

test "Udp round-trip" {
    // Create server socket
    const server_addr = net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    const server_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(server_fd);

    try posix.bind(server_fd, &server_addr.any, server_addr.getOsSockLen());

    var bound_addr: net.Address = undefined;
    var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(server_fd, &bound_addr.any, &bound_len);

    // Create client
    var buf: [32]u8 = undefined;
    const addr_str = try std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{bound_addr.getPort()});

    var client = try Udp.init("127.0.0.1:0", addr_str);
    defer client.close();

    // Send request
    _ = try client.send("ping");

    // Server receives and sends response
    var recv_buf: [1024]u8 = undefined;
    var from_addr: posix.sockaddr = undefined;
    var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    _ = try posix.recvfrom(server_fd, &recv_buf, 0, &from_addr, &from_len);

    _ = try posix.sendto(server_fd, "pong", 0, &from_addr, from_len);

    // Client receives response
    const n = try client.recv(&recv_buf);
    try std.testing.expectEqualStrings("pong", recv_buf[0..n]);
}
