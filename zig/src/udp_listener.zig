//! UDP Listener Transport implementation.
//!
//! Provides an unconnected UDP transport that can send to and receive from
//! multiple remote addresses. Suitable for Host which manages multiple peers.

const std = @import("std");
const posix = std.posix;
const net = std.net;
const transport = @import("transport.zig");
const udp = @import("udp.zig");

/// UDP Listener over an unconnected UDP socket.
///
/// Can send to and receive from multiple remote addresses.
/// Suitable for Host which manages multiple peers on a single port.
pub const UdpListener = struct {
    fd: posix.fd_t,
    local_addr: udp.UdpAddr,
    closed: std.atomic.Value(bool),

    const Self = @This();

    /// Create a new UDP listener bound to the specified address.
    ///
    /// Use "0.0.0.0:0" to let the OS assign an available port.
    /// Use "0.0.0.0:51820" to bind to a specific port.
    pub fn bind(bind_addr_str: []const u8) !Self {
        const bind_addr = try udp.UdpAddr.parse(bind_addr_str);

        // Create socket
        const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        errdefer posix.close(fd);

        // Bind
        try posix.bind(fd, &bind_addr.inner.any, bind_addr.inner.getOsSockLen());

        // Get actual bound address
        var bound_addr: net.Address = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        try posix.getsockname(fd, &bound_addr.any, &bound_len);

        return .{
            .fd = fd,
            .local_addr = udp.UdpAddr.init(bound_addr),
            .closed = std.atomic.Value(bool).init(false),
        };
    }

    /// Get the local port.
    pub fn port(self: Self) u16 {
        return self.local_addr.port();
    }

    /// Get the local address.
    pub fn localAddrUdp(self: Self) udp.UdpAddr {
        return self.local_addr;
    }

    /// Check if closed.
    pub fn isClosed(self: *Self) bool {
        return self.closed.load(.seq_cst);
    }

    /// Send data to the specified address.
    pub fn sendTo(self: *Self, data: []const u8, to_addr: transport.Addr) transport.TransportError!void {
        if (self.closed.load(.seq_cst)) {
            return error.Closed;
        }

        const dest = switch (to_addr) {
            .udp => |a| a.inner,
            .mock => return error.InvalidAddress,
        };

        _ = posix.sendto(self.fd, data, 0, &dest.any, dest.getOsSockLen()) catch {
            return error.IoError;
        };
    }

    /// Receive data and return the sender's address.
    pub fn recvFrom(self: *Self, buf: []u8) transport.TransportError!transport.RecvResult {
        if (self.closed.load(.seq_cst)) {
            return error.Closed;
        }

        var from_addr: posix.sockaddr = undefined;
        var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);

        const n = posix.recvfrom(self.fd, buf, 0, &from_addr, &from_len) catch |err| {
            if (err == error.WouldBlock) {
                return error.IoError; // Timeout
            }
            return error.IoError;
        };

        // Convert sockaddr to net.Address
        const addr = net.Address{ .any = from_addr };

        return .{
            .bytes_read = n,
            .from_addr = (udp.UdpAddr.init(addr)).toAddr(),
        };
    }

    /// Get local address via Transport interface.
    pub fn localAddr(self: *Self) transport.Addr {
        return self.local_addr.toAddr();
    }

    /// Close the transport.
    pub fn close(self: *Self) void {
        if (!self.closed.swap(true, .seq_cst)) {
            posix.close(self.fd);
        }
    }

    /// Set receive timeout in milliseconds.
    pub fn setRecvTimeout(self: Self, timeout_ms: u32) !void {
        const tv = posix.timeval{
            .sec = @intCast(timeout_ms / 1000),
            .usec = @intCast((timeout_ms % 1000) * 1000),
        };
        try posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
    }

    /// Get Transport vtable.
    pub fn asTransport(self: *Self) transport.Transport {
        return .{
            .ptr = self,
            .vtable = &.{
                .send = @ptrCast(&sendToTransport),
                .recv = @ptrCast(&recvFromTransport),
                .local_addr = @ptrCast(&localAddrTransport),
                .close = @ptrCast(&closeTransport),
            },
        };
    }

    // Transport vtable implementations
    fn sendToTransport(self: *Self, data: []const u8, addr: transport.Addr) transport.TransportError!void {
        return self.sendTo(data, addr);
    }

    fn recvFromTransport(self: *Self, buf: []u8) transport.TransportError!transport.RecvResult {
        return self.recvFrom(buf);
    }

    fn localAddrTransport(self: *Self) transport.Addr {
        return self.localAddr();
    }

    fn closeTransport(self: *Self) transport.TransportError!void {
        self.close();
    }
};

// =============================================================================
// Tests
// =============================================================================

test "UdpListener.bind" {
    var listener = try UdpListener.bind("127.0.0.1:0");
    defer listener.close();

    try std.testing.expect(listener.port() > 0);
    try std.testing.expect(!listener.isClosed());
}

test "UdpListener send/recv" {
    var listener1 = try UdpListener.bind("127.0.0.1:0");
    defer listener1.close();

    var listener2 = try UdpListener.bind("127.0.0.1:0");
    defer listener2.close();

    const addr2 = listener2.localAddr();

    // Send from listener1 to listener2
    const data = "hello world";
    try listener1.sendTo(data, addr2);

    // Receive on listener2
    var buf: [1024]u8 = undefined;
    const result = try listener2.recvFrom(&buf);

    try std.testing.expectEqualStrings(data, buf[0..result.bytes_read]);
}

test "UdpListener multiple peers" {
    var server = try UdpListener.bind("127.0.0.1:0");
    defer server.close();

    var client1 = try UdpListener.bind("127.0.0.1:0");
    defer client1.close();

    var client2 = try UdpListener.bind("127.0.0.1:0");
    defer client2.close();

    const server_addr = server.localAddr();

    // Both clients send to server
    try client1.sendTo("from client1", server_addr);
    try client2.sendTo("from client2", server_addr);

    // Server receives both
    var buf: [1024]u8 = undefined;
    var msg1_buf: [32]u8 = undefined;
    var msg2_buf: [32]u8 = undefined;
    var msg1: []u8 = &.{};
    var msg2: []u8 = &.{};

    const result1 = try server.recvFrom(&buf);
    @memcpy(msg1_buf[0..result1.bytes_read], buf[0..result1.bytes_read]);
    msg1 = msg1_buf[0..result1.bytes_read];

    const result2 = try server.recvFrom(&buf);
    @memcpy(msg2_buf[0..result2.bytes_read], buf[0..result2.bytes_read]);
    msg2 = msg2_buf[0..result2.bytes_read];

    // Check both messages received (order may vary)
    const found1 = std.mem.eql(u8, msg1, "from client1") or std.mem.eql(u8, msg2, "from client1");
    const found2 = std.mem.eql(u8, msg1, "from client2") or std.mem.eql(u8, msg2, "from client2");

    try std.testing.expect(found1);
    try std.testing.expect(found2);
}
