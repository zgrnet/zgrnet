//! Transport abstraction for datagram-based communication.
//!
//! This module provides a unified interface for sending and receiving packets,
//! regardless of the underlying protocol (UDP, QUIC, etc.).

const std = @import("std");
const posix = std.posix;

/// Transport errors.
pub const TransportError = error{
    /// I/O error.
    IoError,
    /// Invalid address type.
    InvalidAddress,
    /// Transport is closed.
    Closed,
    /// No peer connected (for mock transport).
    NoPeer,
    /// Inbox full (for mock transport).
    InboxFull,
    /// Connection reset.
    ConnectionResetByPeer,
    /// Would block.
    WouldBlock,
    /// Address in use.
    AddressInUse,
    /// Address not available.
    AddressNotAvailable,
    /// Network unreachable.
    NetworkUnreachable,
    /// Out of memory.
    OutOfMemory,
};

/// Result of a receive operation.
pub const RecvResult = struct {
    /// Number of bytes received.
    bytes_read: usize,
    /// Sender's address.
    from_addr: Addr,
};

// =============================================================================
// Address Interface
// =============================================================================

/// Abstract address interface.
pub const Addr = union(enum) {
    /// UDP socket address.
    udp: UdpAddr,
    /// Mock address for testing.
    mock: MockAddr,

    pub fn network(self: Addr) []const u8 {
        return switch (self) {
            .udp => "udp",
            .mock => |m| m.network(),
        };
    }

    pub fn format(
        self: Addr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .udp => |a| try writer.print("{any}", .{a.addr}),
            .mock => |m| try writer.print("{s}", .{m.name}),
        }
    }
};

/// UDP address wrapper.
pub const UdpAddr = struct {
    addr: std.net.Address,

    pub fn init(addr: std.net.Address) UdpAddr {
        return UdpAddr{ .addr = addr };
    }

    pub fn fromString(host: []const u8, port: u16) !UdpAddr {
        const addr = try std.net.Address.parseIp(host, port);
        return UdpAddr{ .addr = addr };
    }
};

/// Mock address for testing.
pub const MockAddr = struct {
    name: []const u8,

    pub fn init(name: []const u8) MockAddr {
        return MockAddr{ .name = name };
    }

    pub fn network(self: MockAddr) []const u8 {
        _ = self;
        return "mock";
    }
};

// =============================================================================
// Transport Interface
// =============================================================================

/// Abstract transport interface.
pub const Transport = union(enum) {
    /// UDP transport.
    udp: *UdpTransport,
    /// Mock transport for testing.
    mock: *MockTransport,

    pub fn sendTo(self: Transport, data: []const u8, addr: Addr) TransportError!void {
        switch (self) {
            .udp => |t| try t.sendTo(data, addr),
            .mock => |t| try t.sendTo(data, addr),
        }
    }

    pub fn recvFrom(self: Transport, buf: []u8) TransportError!RecvResult {
        return switch (self) {
            .udp => |t| try t.recvFrom(buf),
            .mock => |t| try t.recvFrom(buf),
        };
    }

    pub fn close(self: Transport) void {
        switch (self) {
            .udp => |t| t.close(),
            .mock => |t| t.close(),
        }
    }

    pub fn localAddr(self: Transport) Addr {
        return switch (self) {
            .udp => |t| t.localAddr(),
            .mock => |t| t.localAddr(),
        };
    }
};

// =============================================================================
// UDP Transport
// =============================================================================

/// UDP transport implementation.
pub const UdpTransport = struct {
    socket: posix.socket_t,
    local_address: std.net.Address,
    closed: bool = false,

    /// Creates a new UDP transport bound to the specified address.
    pub fn bind(address: std.net.Address) !*UdpTransport {
        const sock = try posix.socket(
            @intFromEnum(address.any.family),
            posix.SOCK.DGRAM,
            0,
        );
        errdefer posix.close(sock);

        try posix.bind(sock, &address.any, address.getOsSockLen());

        const self = try std.heap.page_allocator.create(UdpTransport);
        self.* = UdpTransport{
            .socket = sock,
            .local_address = address,
        };
        return self;
    }

    /// Sends data to the specified address.
    pub fn sendTo(self: *UdpTransport, data: []const u8, addr: Addr) TransportError!void {
        if (self.closed) {
            return TransportError.Closed;
        }

        const udp_addr = switch (addr) {
            .udp => |a| a,
            else => return TransportError.InvalidAddress,
        };

        _ = posix.sendto(
            self.socket,
            data,
            0,
            &udp_addr.addr.any,
            udp_addr.addr.getOsSockLen(),
        ) catch |err| {
            return switch (err) {
                error.ConnectionResetByPeer => TransportError.ConnectionResetByPeer,
                error.NetworkUnreachable => TransportError.NetworkUnreachable,
                error.WouldBlock => TransportError.WouldBlock,
                else => TransportError.IoError,
            };
        };
    }

    /// Receives data from the transport.
    pub fn recvFrom(self: *UdpTransport, buf: []u8) TransportError!RecvResult {
        if (self.closed) {
            return TransportError.Closed;
        }

        var from_addr: std.net.Address = undefined;
        var from_len: posix.socklen_t = @sizeOf(std.net.Address);

        const n = posix.recvfrom(
            self.socket,
            buf,
            0,
            @ptrCast(&from_addr.any),
            &from_len,
        ) catch |err| {
            return switch (err) {
                error.ConnectionResetByPeer => TransportError.ConnectionResetByPeer,
                error.WouldBlock => TransportError.WouldBlock,
                else => TransportError.IoError,
            };
        };

        return RecvResult{
            .bytes_read = n,
            .from_addr = Addr{ .udp = UdpAddr.init(from_addr) },
        };
    }

    /// Closes the transport.
    pub fn close(self: *UdpTransport) void {
        if (!self.closed) {
            posix.close(self.socket);
            self.closed = true;
        }
    }

    /// Returns the local address.
    pub fn localAddr(self: *UdpTransport) Addr {
        return Addr{ .udp = UdpAddr.init(self.local_address) };
    }

    /// Frees the transport.
    pub fn deinit(self: *UdpTransport) void {
        self.close();
        std.heap.page_allocator.destroy(self);
    }
};

// =============================================================================
// Mock Transport (for testing)
// =============================================================================

/// A packet in the mock transport.
const MockPacket = struct {
    data: []u8,
    from: MockAddr,
};

/// Mock transport for testing.
/// Two mock transports can be connected to simulate a network.
pub const MockTransport = struct {
    allocator: std.mem.Allocator,
    local_addr_name: []const u8,
    peer: ?*MockTransport = null,
    inbox: std.ArrayListUnmanaged(MockPacket) = .{},
    closed: bool = false,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},

    /// Creates a new mock transport.
    pub fn init(allocator: std.mem.Allocator, name: []const u8) !*MockTransport {
        const self = try allocator.create(MockTransport);
        self.* = MockTransport{
            .allocator = allocator,
            .local_addr_name = name,
        };
        return self;
    }

    /// Connects two mock transports together.
    pub fn connect(a: *MockTransport, b: *MockTransport) void {
        a.peer = b;
        b.peer = a;
    }

    /// Sends data to the peer transport.
    pub fn sendTo(self: *MockTransport, data: []const u8, addr: Addr) TransportError!void {
        _ = addr;

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.closed) {
            return TransportError.Closed;
        }

        const peer = self.peer orelse return TransportError.NoPeer;

        peer.mutex.lock();
        defer peer.mutex.unlock();

        if (peer.closed) {
            return TransportError.Closed;
        }

        // Copy data for the peer's inbox
        const data_copy = peer.allocator.dupe(u8, data) catch return TransportError.OutOfMemory;
        peer.inbox.append(peer.allocator, MockPacket{
            .data = data_copy,
            .from = MockAddr.init(self.local_addr_name),
        }) catch {
            peer.allocator.free(data_copy);
            return TransportError.InboxFull;
        };

        peer.cond.signal();
    }

    /// Receives data from the inbox.
    pub fn recvFrom(self: *MockTransport, buf: []u8) TransportError!RecvResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.closed) {
            return TransportError.Closed;
        }

        // Wait for a packet
        while (self.inbox.items.len == 0 and !self.closed) {
            self.cond.wait(&self.mutex);
        }

        if (self.closed) {
            return TransportError.Closed;
        }

        const packet = self.inbox.orderedRemove(0);
        defer self.allocator.free(packet.data);

        const n = @min(buf.len, packet.data.len);
        @memcpy(buf[0..n], packet.data[0..n]);

        return RecvResult{
            .bytes_read = n,
            .from_addr = Addr{ .mock = packet.from },
        };
    }

    /// Closes the transport.
    pub fn close(self: *MockTransport) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.closed = true;
        self.cond.broadcast();
    }

    /// Returns the local address.
    pub fn localAddr(self: *MockTransport) Addr {
        return Addr{ .mock = MockAddr.init(self.local_addr_name) };
    }

    /// Injects a packet directly into the inbox.
    pub fn injectPacket(self: *MockTransport, data: []const u8, from: []const u8) TransportError!void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.closed) {
            return TransportError.Closed;
        }

        const data_copy = self.allocator.dupe(u8, data) catch return TransportError.OutOfMemory;
        self.inbox.append(self.allocator, MockPacket{
            .data = data_copy,
            .from = MockAddr.init(from),
        }) catch {
            self.allocator.free(data_copy);
            return TransportError.InboxFull;
        };

        self.cond.signal();
    }

    /// Frees the transport and all pending packets.
    pub fn deinit(self: *MockTransport) void {
        self.close();

        // Free remaining packets
        for (self.inbox.items) |packet| {
            self.allocator.free(packet.data);
        }
        self.inbox.deinit(self.allocator);

        self.allocator.destroy(self);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "mock addr" {
    const addr = MockAddr.init("test-addr");
    try std.testing.expectEqualStrings(addr.network(), "mock");
    try std.testing.expectEqualStrings(addr.name, "test-addr");
}

test "mock transport send recv" {
    const allocator = std.testing.allocator;

    const t1 = try MockTransport.init(allocator, "peer1");
    defer t1.deinit();
    const t2 = try MockTransport.init(allocator, "peer2");
    defer t2.deinit();

    MockTransport.connect(t1, t2);

    // Send from t1 to t2
    const data = "hello world";
    try t1.sendTo(data, Addr{ .mock = MockAddr.init("peer2") });

    // Receive on t2
    var buf: [1024]u8 = undefined;
    const result = try t2.recvFrom(&buf);
    try std.testing.expectEqualStrings(buf[0..result.bytes_read], data);
    try std.testing.expectEqualStrings(result.from_addr.mock.name, "peer1");

    // Send back from t2 to t1
    try t2.sendTo("reply", Addr{ .mock = MockAddr.init("peer1") });
    const result2 = try t1.recvFrom(&buf);
    try std.testing.expectEqualStrings(buf[0..result2.bytes_read], "reply");
    try std.testing.expectEqualStrings(result2.from_addr.mock.name, "peer2");
}

test "mock transport no peer" {
    const allocator = std.testing.allocator;
    const t = try MockTransport.init(allocator, "alone");
    defer t.deinit();

    try std.testing.expectError(
        TransportError.NoPeer,
        t.sendTo("test", Addr{ .mock = MockAddr.init("nobody") }),
    );
}

test "mock transport inject" {
    const allocator = std.testing.allocator;
    const t = try MockTransport.init(allocator, "test");
    defer t.deinit();

    try t.injectPacket("injected", "sender");

    var buf: [1024]u8 = undefined;
    const result = try t.recvFrom(&buf);
    try std.testing.expectEqualStrings(buf[0..result.bytes_read], "injected");
    try std.testing.expectEqualStrings(result.from_addr.mock.name, "sender");
}

test "udp addr" {
    const addr = try UdpAddr.fromString("127.0.0.1", 8080);
    const wrapped = Addr{ .udp = addr };
    try std.testing.expectEqualStrings(wrapped.network(), "udp");
}
