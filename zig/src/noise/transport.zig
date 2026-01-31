//! Transport abstraction for datagram-based communication.
//!
//! This module provides a unified interface for sending and receiving packets,
//! regardless of the underlying protocol (UDP, QUIC, etc.).

const std = @import("std");

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

// Import UDP types from net module
const transport_udp = @import("../net/transport_udp.zig");
pub const UdpAddr = transport_udp.UdpAddr;
pub const UdpTransport = transport_udp.UdpTransport;

/// Abstract address interface.
/// Note: UDP address is defined in udp.zig to avoid circular dependencies.
pub const Addr = union(enum) {
    /// Mock address for testing.
    mock: MockAddr,
    /// UDP address.
    udp: UdpAddr,

    pub fn network(self: Addr) []const u8 {
        return switch (self) {
            .mock => |m| m.network(),
            .udp => "udp",
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
            .mock => |m| try writer.print("{s}", .{m.name}),
            .udp => |a| {
                var buf: [64]u8 = undefined;
                const str = a.format(&buf) catch "?";
                try writer.print("{s}", .{str});
            },
        }
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
    /// Mock transport for testing.
    mock: *MockTransport,
    /// UDP transport.
    udp: *UdpTransport,

    pub fn sendTo(self: Transport, data: []const u8, addr: Addr) TransportError!void {
        switch (self) {
            .mock => |t| try t.sendTo(data, addr),
            .udp => |t| {
                const udp_addr = switch (addr) {
                    .udp => |a| a,
                    else => return TransportError.InvalidAddress,
                };
                _ = t.sendTo(data, udp_addr) catch return TransportError.IoError;
            },
        }
    }

    pub fn recvFrom(self: Transport, buf: []u8) TransportError!RecvResult {
        return switch (self) {
            .mock => |t| try t.recvFrom(buf),
            .udp => |t| {
                const result = t.recvFrom(buf) catch |err| {
                    // Preserve WouldBlock for timeout handling in dial()
                    if (err == error.WouldBlock) {
                        return TransportError.WouldBlock;
                    }
                    return TransportError.IoError;
                };
                return RecvResult{
                    .bytes_read = result.bytes_read,
                    .from_addr = Addr{ .udp = result.from },
                };
            },
        };
    }

    pub fn close(self: Transport) void {
        switch (self) {
            .mock => |t| t.close(),
            .udp => |t| t.close(),
        }
    }

    pub fn localAddr(self: Transport) Addr {
        return switch (self) {
            .mock => |t| t.localAddr(),
            .udp => |t| Addr{ .udp = t.getLocalAddr() },
        };
    }

    /// Sets the deadline for future recvFrom calls.
    /// null means recvFrom will not time out.
    pub fn setReadDeadline(self: Transport, deadline_ns: ?i128) TransportError!void {
        switch (self) {
            .mock => |t| try t.setReadDeadline(deadline_ns),
            .udp => |t| {
                if (deadline_ns) |ns| {
                    const now = std.time.nanoTimestamp();
                    const timeout_ns = ns - now;
                    if (timeout_ns > 0) {
                        const timeout_ms: u32 = @intCast(@divFloor(timeout_ns, 1_000_000));
                        t.setRecvTimeout(timeout_ms) catch return TransportError.IoError;
                    }
                } else {
                    t.setRecvTimeout(0) catch return TransportError.IoError;
                }
            },
        }
    }

    /// Sets the deadline for future sendTo calls.
    /// null means sendTo will not time out.
    pub fn setWriteDeadline(self: Transport, deadline_ns: ?i128) TransportError!void {
        switch (self) {
            .mock => |t| try t.setWriteDeadline(deadline_ns),
            .udp => |t| {
                if (deadline_ns) |ns| {
                    const now = std.time.nanoTimestamp();
                    const timeout_ns = ns - now;
                    if (timeout_ns > 0) {
                        const timeout_ms: u32 = @intCast(@divFloor(timeout_ns, 1_000_000));
                        t.setSendTimeout(timeout_ms) catch return TransportError.IoError;
                    }
                } else {
                    t.setSendTimeout(0) catch return TransportError.IoError;
                }
            },
        }
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

    /// Sets the read deadline (no-op for mock transport).
    pub fn setReadDeadline(self: *MockTransport, deadline_ns: ?i128) TransportError!void {
        _ = self;
        _ = deadline_ns;
        // No-op for mock transport
    }

    /// Sets the write deadline (no-op for mock transport).
    pub fn setWriteDeadline(self: *MockTransport, deadline_ns: ?i128) TransportError!void {
        _ = self;
        _ = deadline_ns;
        // No-op for mock transport
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
