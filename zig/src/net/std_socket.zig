//! StdUdpSocket — posix-based UDP socket implementing the UdpSocket trait.
//!
//! This is the desktop/POSIX implementation. On ESP32, a lwIP-based
//! implementation would provide the same interface.

const std = @import("std");
const posix = std.posix;
const mem = std.mem;

const socket_trait = @import("socket.zig");
const SocketError = socket_trait.SocketError;
const RecvFromResult = socket_trait.RecvFromResult;
const sockopt_mod = @import("sockopt.zig");

pub const StdUdpSocket = struct {
    fd: posix.socket_t,

    const Self = @This();

    /// Create a UDP socket.
    pub fn udp() SocketError!Self {
        const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch {
            return error.CreateFailed;
        };
        return .{ .fd = fd };
    }

    /// Close the socket.
    pub fn close(self: *Self) void {
        posix.close(self.fd);
    }

    /// Bind to a local address and port.
    pub fn bind(self: *Self, addr: [4]u8, port: u16) SocketError!void {
        const sa = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = mem.nativeToBig(u16, port),
            .addr = @bitCast(addr),
        };
        posix.bind(self.fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in)) catch {
            return error.BindFailed;
        };
        _ = sockopt_mod.applySocketOptions(self.fd, .{});
    }

    /// Send data to a specific address.
    pub fn sendTo(self: *Self, addr: [4]u8, port: u16, data: []const u8) SocketError!usize {
        const sa = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = mem.nativeToBig(u16, port),
            .addr = @bitCast(addr),
        };
        return posix.sendto(self.fd, data, 0, @ptrCast(&sa), @sizeOf(posix.sockaddr.in)) catch {
            return error.SendFailed;
        };
    }

    /// Receive data with source address.
    pub fn recvFromWithAddr(self: *Self, buf: []u8) SocketError!RecvFromResult {
        var from_addr: posix.sockaddr.in = undefined;
        var from_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

        const n = posix.recvfrom(self.fd, buf, 0, @ptrCast(&from_addr), &from_len) catch |err| {
            if (err == error.WouldBlock) return error.WouldBlock;
            return error.RecvFailed;
        };

        if (n == 0) return error.Closed;

        return RecvFromResult{
            .len = n,
            .src = .{
                .addr = @bitCast(from_addr.addr),
                .port = mem.bigToNative(u16, from_addr.port),
            },
        };
    }

    /// Set non-blocking mode.
    pub fn setNonBlocking(self: *Self, non_blocking: bool) void {
        const current_flags = posix.fcntl(self.fd, posix.F.GETFL, 0) catch 0;
        var o_flags: posix.O = @bitCast(@as(u32, @intCast(current_flags)));
        o_flags.NONBLOCK = non_blocking;
        _ = posix.fcntl(self.fd, posix.F.SETFL, @as(usize, @as(u32, @bitCast(o_flags)))) catch {};
    }

    /// Get the bound port (after bind with port 0).
    pub fn getBoundPort(self: *Self) SocketError!u16 {
        var addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        posix.getsockname(self.fd, @ptrCast(&addr), &addr_len) catch {
            return error.BindFailed;
        };
        return mem.bigToNative(u16, addr.port);
    }

    /// Get the underlying file descriptor (for IOBackend registration).
    pub fn getFd(self: *Self) i32 {
        return @intCast(self.fd);
    }
};

// Compile-time trait validation
comptime {
    _ = socket_trait.from(StdUdpSocket);
}

// ============================================================================
// Tests
// ============================================================================

test "StdUdpSocket create and close" {
    var sock = try StdUdpSocket.udp();
    defer sock.close();
    try std.testing.expect(sock.getFd() >= 0);
}

test "StdUdpSocket bind and getBoundPort" {
    var sock = try StdUdpSocket.udp();
    defer sock.close();

    try sock.bind(.{ 127, 0, 0, 1 }, 0);
    const port = try sock.getBoundPort();
    try std.testing.expect(port > 0);
}

test "StdUdpSocket sendTo/recvFromWithAddr" {
    var server = try StdUdpSocket.udp();
    defer server.close();
    try server.bind(.{ 127, 0, 0, 1 }, 0);
    const server_port = try server.getBoundPort();

    var client = try StdUdpSocket.udp();
    defer client.close();
    try client.bind(.{ 127, 0, 0, 1 }, 0);

    const data = "hello";
    _ = try client.sendTo(.{ 127, 0, 0, 1 }, server_port, data);

    var buf: [256]u8 = undefined;
    const result = try server.recvFromWithAddr(&buf);
    try std.testing.expectEqual(data.len, result.len);
    try std.testing.expectEqualSlices(u8, data, buf[0..result.len]);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, result.src.addr);
}
