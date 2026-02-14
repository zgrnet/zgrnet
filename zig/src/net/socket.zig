//! UDP Socket trait — platform-agnostic socket interface for the net/ layer.
//!
//! On desktop (std), this is implemented by StdUdpSocket using posix.
//! On ESP32, this would be implemented using lwIP sockets.
//!
//! The trait requires:
//! - Static: `udp() !Self` — create a UDP socket
//! - Instance: `bind(addr, port) !void`
//! - Instance: `sendTo(addr, port, data) !usize`
//! - Instance: `recvFromWithAddr(buf) !RecvFromResult`
//! - Instance: `close() void`
//! - Instance: `setNonBlocking(bool) void`
//! - Instance: `getBoundPort() !u16`
//! - Instance: `getFd() i32` — for IOBackend (kqueue/epoll) registration

const std = @import("std");
const endpoint_mod = @import("endpoint.zig");
pub const Endpoint = endpoint_mod.Endpoint;

/// Result from recvFromWithAddr — includes source address.
pub const RecvFromResult = struct {
    len: usize,
    src: Endpoint,
};

/// Socket error types (compatible with trait.socket.Error).
pub const SocketError = error{
    CreateFailed,
    BindFailed,
    SendFailed,
    RecvFailed,
    WouldBlock,
    Closed,
};

/// Validate that a type implements the UdpSocket interface.
pub fn from(comptime Impl: type) type {
    comptime {
        _ = @as(*const fn () SocketError!Impl, &Impl.udp);
        _ = @as(*const fn (*Impl) void, &Impl.close);
        _ = @as(*const fn (*Impl, [4]u8, u16) SocketError!void, &Impl.bind);
        _ = @as(*const fn (*Impl, [4]u8, u16, []const u8) SocketError!usize, &Impl.sendTo);
        _ = @as(*const fn (*Impl, []u8) SocketError!RecvFromResult, &Impl.recvFromWithAddr);
        _ = @as(*const fn (*Impl, bool) void, &Impl.setNonBlocking);
        _ = @as(*const fn (*Impl) SocketError!u16, &Impl.getBoundPort);
        _ = @as(*const fn (*Impl) i32, &Impl.getFd);
    }
    return Impl;
}
