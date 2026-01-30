//! Peer management for remote nodes.

const std = @import("std");
const Mutex = std.Thread.Mutex;
const Allocator = std.mem.Allocator;

const keypair = @import("keypair.zig");
const session_mod = @import("session.zig");
const transport_mod = @import("transport.zig");

pub const Key = keypair.Key;
pub const Session = session_mod.Session;
pub const Addr = transport_mod.Addr;

/// Peer connection state.
pub const PeerState = enum {
    /// Not connected.
    idle,
    /// Handshake in progress.
    connecting,
    /// Connection established.
    established,
    /// Connection attempt failed.
    failed,

    pub fn format(
        self: PeerState,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.writeAll(switch (self) {
            .idle => "idle",
            .connecting => "connecting",
            .established => "established",
            .failed => "failed",
        });
    }
};

/// Configuration for creating a peer.
pub const PeerConfig = struct {
    public_key: Key,
    endpoint: ?Addr = null,
    mtu: ?u16 = null,
};

/// Represents a remote node in the network.
pub const Peer = struct {
    allocator: Allocator,
    mutex: Mutex = .{},

    // Identity
    public_key: Key,

    // Connection state
    state: PeerState = .idle,
    endpoint: ?Addr = null,
    session: ?*Session = null,

    // Timestamps (nanoseconds since boot)
    created_at: i128,
    last_handshake: ?i128 = null,
    last_activity: ?i128 = null,

    // MTU
    mtu: u16,

    // Statistics (atomic)
    tx_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    rx_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    tx_pkts: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    rx_pkts: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Creates a new peer with the given configuration.
    pub fn init(allocator: Allocator, cfg: PeerConfig) Peer {
        return .{
            .allocator = allocator,
            .public_key = cfg.public_key,
            .endpoint = cfg.endpoint,
            .mtu = cfg.mtu orelse 1280, // IPv6 minimum
            .created_at = std.time.nanoTimestamp(),
        };
    }

    /// Returns the peer's public key.
    pub fn getPublicKey(self: *Peer) Key {
        return self.public_key;
    }

    /// Returns the current connection state.
    pub fn getState(self: *Peer) PeerState {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.state;
    }

    /// Sets the connection state.
    pub fn setState(self: *Peer, state: PeerState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.state = state;
    }

    /// Returns the current endpoint.
    pub fn getEndpoint(self: *Peer) ?Addr {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.endpoint;
    }

    /// Sets the endpoint (for roaming support).
    pub fn setEndpoint(self: *Peer, addr: Addr) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.endpoint = addr;
    }

    /// Returns whether the peer has an active session.
    pub fn hasSession(self: *Peer) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.session != null;
    }

    /// Returns the session pointer (for direct access).
    pub fn getSession(self: *Peer) ?*Session {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.session;
    }

    /// Sets the session and updates state to established.
    pub fn setSession(self: *Peer, session: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.session = session;
        self.state = .established;
        self.last_handshake = std.time.nanoTimestamp();
    }

    /// Clears the session and sets state to idle.
    pub fn clearSession(self: *Peer) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.session) |session| {
            session.expire();
            self.allocator.destroy(session);
        }
        self.session = null;
        self.state = .idle;
    }

    /// Returns the path MTU.
    pub fn getMtu(self: *Peer) u16 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.mtu;
    }

    /// Sets the path MTU.
    pub fn setMtu(self: *Peer, mtu: u16) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.mtu = mtu;
    }

    /// Returns when the last handshake occurred.
    pub fn getLastHandshake(self: *Peer) ?i128 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.last_handshake;
    }

    /// Returns when the last activity occurred.
    pub fn getLastActivity(self: *Peer) ?i128 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.last_activity;
    }

    /// Updates the last activity timestamp.
    pub fn updateActivity(self: *Peer) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.last_activity = std.time.nanoTimestamp();
    }

    /// Adds to the transmitted bytes counter.
    pub fn addTxBytes(self: *Peer, n: u64) void {
        _ = self.tx_bytes.fetchAdd(n, .monotonic);
        _ = self.tx_pkts.fetchAdd(1, .monotonic);
    }

    /// Adds to the received bytes counter.
    pub fn addRxBytes(self: *Peer, n: u64) void {
        _ = self.rx_bytes.fetchAdd(n, .monotonic);
        _ = self.rx_pkts.fetchAdd(1, .monotonic);
    }

    /// Returns the total transmitted bytes.
    pub fn getTxBytes(self: *Peer) u64 {
        return self.tx_bytes.load(.monotonic);
    }

    /// Returns the total received bytes.
    pub fn getRxBytes(self: *Peer) u64 {
        return self.rx_bytes.load(.monotonic);
    }

    /// Returns the total transmitted packets.
    pub fn getTxPackets(self: *Peer) u64 {
        return self.tx_pkts.load(.monotonic);
    }

    /// Returns the total received packets.
    pub fn getRxPackets(self: *Peer) u64 {
        return self.rx_pkts.load(.monotonic);
    }

    /// Returns true if the peer has an established connection.
    pub fn isEstablished(self: *Peer) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.state == .established and self.session != null;
    }

    /// Returns true if the peer's session has expired.
    pub fn isExpired(self: *Peer) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.session) |session| {
            return session.isExpired();
        }
        return false;
    }

    /// Returns information about the peer.
    pub fn getInfo(self: *Peer) PeerInfo {
        self.mutex.lock();
        defer self.mutex.unlock();

        return .{
            .public_key = self.public_key,
            .endpoint = self.endpoint,
            .state = self.state,
            .last_handshake = self.last_handshake,
            .last_activity = self.last_activity,
            .mtu = self.mtu,
            .tx_bytes = self.tx_bytes.load(.monotonic),
            .rx_bytes = self.rx_bytes.load(.monotonic),
            .tx_packets = self.tx_pkts.load(.monotonic),
            .rx_packets = self.rx_pkts.load(.monotonic),
        };
    }
};

/// Read-only information about a peer.
pub const PeerInfo = struct {
    public_key: Key,
    endpoint: ?Addr,
    state: PeerState,
    last_handshake: ?i128,
    last_activity: ?i128,
    mtu: u16,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_packets: u64,
    rx_packets: u64,
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;
const KeyPair = keypair.KeyPair;

test "peer state format" {
    var buf: [32]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try std.fmt.format(stream.writer(), "{any}", .{PeerState.idle});
    try testing.expectEqualStrings(stream.getWritten(), ".idle");
}

test "new peer" {
    const kp = KeyPair.generate();
    var peer = Peer.init(testing.allocator, .{
        .public_key = kp.public,
    });

    try testing.expectEqual(peer.getPublicKey(), kp.public);
    try testing.expectEqual(peer.getState(), PeerState.idle);
    try testing.expectEqual(peer.getMtu(), 1280);
    try testing.expect(!peer.isEstablished());
}

test "peer with custom mtu" {
    const kp = KeyPair.generate();
    var peer = Peer.init(testing.allocator, .{
        .public_key = kp.public,
        .mtu = 1400,
    });

    try testing.expectEqual(peer.getMtu(), 1400);
}

test "peer state transitions" {
    const kp = KeyPair.generate();
    var peer = Peer.init(testing.allocator, .{
        .public_key = kp.public,
    });

    peer.setState(.connecting);
    try testing.expectEqual(peer.getState(), PeerState.connecting);

    peer.setState(.established);
    try testing.expectEqual(peer.getState(), PeerState.established);

    peer.setState(.failed);
    try testing.expectEqual(peer.getState(), PeerState.failed);
}

test "peer statistics" {
    const kp = KeyPair.generate();
    var peer = Peer.init(testing.allocator, .{
        .public_key = kp.public,
    });

    try testing.expectEqual(peer.getTxBytes(), 0);
    try testing.expectEqual(peer.getRxBytes(), 0);

    peer.addTxBytes(100);
    peer.addTxBytes(50);
    peer.addRxBytes(200);

    try testing.expectEqual(peer.getTxBytes(), 150);
    try testing.expectEqual(peer.getRxBytes(), 200);
    try testing.expectEqual(peer.getTxPackets(), 2);
    try testing.expectEqual(peer.getRxPackets(), 1);
}

test "peer activity" {
    const kp = KeyPair.generate();
    var peer = Peer.init(testing.allocator, .{
        .public_key = kp.public,
    });

    try testing.expect(peer.getLastActivity() == null);

    peer.updateActivity();
    try testing.expect(peer.getLastActivity() != null);
}

test "peer info" {
    const kp = KeyPair.generate();
    var peer = Peer.init(testing.allocator, .{
        .public_key = kp.public,
        .mtu = 1400,
    });

    peer.addTxBytes(100);
    peer.addRxBytes(200);
    peer.setState(.established);

    const info = peer.getInfo();
    try testing.expectEqual(info.public_key, kp.public);
    try testing.expectEqual(info.state, PeerState.established);
    try testing.expectEqual(info.mtu, 1400);
    try testing.expectEqual(info.tx_bytes, 100);
    try testing.expectEqual(info.rx_bytes, 200);
}
