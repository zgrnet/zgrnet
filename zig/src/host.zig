//! Host is the main entry point for ZigNet networking.
//!
//! Provides a complete implementation with synchronous APIs.
//! The user should call `processIncoming()` or `recvMessage()` regularly
//! to handle incoming packets.

const std = @import("std");
const Mutex = std.Thread.Mutex;
const Allocator = std.mem.Allocator;

const keypair = @import("keypair.zig");
const transport_mod = @import("transport.zig");
const message_mod = @import("message.zig");
const peer_mod = @import("peer.zig");
const peer_manager_mod = @import("peer_manager.zig");
const handshake_mod = @import("handshake.zig");
const session_mod = @import("session.zig");

pub const Key = keypair.Key;
pub const KeyPair = keypair.KeyPair;
pub const Transport = transport_mod.Transport;
pub const Addr = transport_mod.Addr;
pub const Peer = peer_mod.Peer;
pub const PeerState = peer_mod.PeerState;
pub const PeerInfo = peer_mod.PeerInfo;
pub const PeerManager = peer_manager_mod.PeerManager;
pub const Protocol = message_mod.Protocol;

/// Message received from a peer.
pub const Message = struct {
    from: Key,
    protocol: Protocol,
    data: []u8,
    allocator: Allocator,

    pub fn deinit(self: *Message) void {
        self.allocator.free(self.data);
    }
};

/// Configuration for creating a Host.
pub const HostConfig = struct {
    /// The host's identity key pair. If null, a new one is generated.
    private_key: ?KeyPair = null,
    /// The transport to use.
    transport: Transport,
    /// Default MTU for new peers.
    mtu: ?u16 = null,
    /// Whether to allow unknown peers.
    allow_unknown_peers: bool = false,
};

/// Host errors.
pub const HostError = error{
    NoTransport,
    Closed,
    Timeout,
    PeerError,
    PeerNotFound,
    NotEstablished,
    NoEndpoint,
    HandshakeFailed,
    HandshakeTimeout,
    TransportError,
    OutOfMemory,
};

/// Host is the main entry point for ZigNet networking.
pub const Host = struct {
    allocator: Allocator,
    key_pair: KeyPair,
    peer_manager: PeerManager,
    config: ConfigInner,
    closed: std.atomic.Value(bool),
    recv_buf: []u8,

    const ConfigInner = struct {
        mtu: u16,
        allow_unknown_peers: bool,
    };

    /// Creates a new Host.
    pub fn init(allocator: Allocator, cfg: HostConfig) !Host {
        const key_pair = cfg.private_key orelse KeyPair.generate();
        const recv_buf = try allocator.alloc(u8, message_mod.max_packet_size);

        return .{
            .allocator = allocator,
            .key_pair = key_pair,
            .peer_manager = PeerManager.init(allocator, key_pair, cfg.transport),
            .config = .{
                .mtu = cfg.mtu orelse 1280,
                .allow_unknown_peers = cfg.allow_unknown_peers,
            },
            .closed = std.atomic.Value(bool).init(false),
            .recv_buf = recv_buf,
        };
    }

    /// Deinitializes the host.
    pub fn deinit(self: *Host) void {
        self.allocator.free(self.recv_buf);
        self.peer_manager.deinit();
    }

    /// Returns the host's public key.
    pub fn getPublicKey(self: *Host) Key {
        return self.key_pair.public;
    }

    /// Adds a new peer.
    pub fn addPeer(self: *Host, pk: Key, endpoint: ?Addr) HostError!void {
        const peer = self.allocator.create(Peer) catch return HostError.OutOfMemory;
        peer.* = Peer.init(self.allocator, .{
            .public_key = pk,
            .endpoint = endpoint,
            .mtu = self.config.mtu,
        });

        self.peer_manager.addPeer(peer) catch |err| {
            self.allocator.destroy(peer);
            return switch (err) {
                peer_manager_mod.PeerManagerError.PeerExists => HostError.PeerError,
                peer_manager_mod.PeerManagerError.OutOfMemory => HostError.OutOfMemory,
                else => HostError.PeerError,
            };
        };
    }

    /// Removes a peer.
    pub fn removePeer(self: *Host, pk: Key) void {
        self.peer_manager.removePeer(pk);
    }

    /// Gets information about a peer.
    pub fn getPeer(self: *Host, pk: Key) ?PeerInfo {
        if (self.peer_manager.getPeer(pk)) |peer| {
            return peer.getInfo();
        }
        return null;
    }

    /// Returns the number of peers.
    pub fn peerCount(self: *Host) usize {
        return self.peer_manager.count();
    }

    /// Connects to a peer (performs handshake).
    /// This is a blocking operation that waits for the handshake to complete.
    pub fn connect(self: *Host, pk: Key) HostError!void {
        return self.connectWithTimeout(pk, 10_000_000_000); // 10 seconds in ns
    }

    /// Connects to a peer with custom timeout (in nanoseconds).
    pub fn connectWithTimeout(self: *Host, pk: Key, timeout_ns: i128) HostError!void {
        if (self.closed.load(.seq_cst)) {
            return HostError.Closed;
        }

        const peer = self.peer_manager.getPeer(pk) orelse return HostError.PeerNotFound;

        if (peer.isEstablished()) {
            return; // Already connected
        }

        const endpoint = peer.getEndpoint() orelse return HostError.NoEndpoint;
        peer.setState(.connecting);

        // Start handshake
        const local_idx = session_mod.generateIndex();

        var hs = handshake_mod.HandshakeState.init(.{
            .pattern = .ik,
            .initiator = true,
            .local_static = self.key_pair,
            .remote_static = pk,
        }) catch return HostError.HandshakeFailed;

        // Generate handshake initiation
        var msg1_buf: [256]u8 = undefined;
        const msg1 = hs.writeMessage(&.{}, &msg1_buf) catch return HostError.HandshakeFailed;

        // Get ephemeral key
        const ephemeral = hs.localEphemeral() orelse return HostError.HandshakeFailed;

        // Build wire message
        var wire_buf: [256]u8 = undefined;
        const wire_msg = message_mod.buildHandshakeInit(&wire_buf, local_idx, ephemeral, msg1[keypair.key_size..]) catch return HostError.HandshakeFailed;

        // Send handshake init
        self.peer_manager.transport.send(wire_msg, endpoint) catch return HostError.TransportError;

        // Wait for response (blocking)
        const deadline = std.time.nanoTimestamp() + timeout_ns;
        while (std.time.nanoTimestamp() < deadline) {
            // Try to receive
            const result = self.peer_manager.transport.recv(self.recv_buf) catch {
                continue;
            };

            if (result.bytes_read == 0) continue;

            const msg_type = self.recv_buf[0];
            if (msg_type == message_mod.MessageType.handshake_resp) {
                // Parse response
                const resp = message_mod.parseHandshakeResp(self.recv_buf[0..result.bytes_read]) catch continue;

                if (resp.receiver_index != local_idx) continue;

                // Process response
                var noise_msg: [keypair.key_size + 16]u8 = undefined;
                @memcpy(noise_msg[0..keypair.key_size], &resp.ephemeral);
                @memcpy(noise_msg[keypair.key_size..], resp.empty_encrypted);

                var payload_buf: [64]u8 = undefined;
                _ = hs.readMessage(&noise_msg, &payload_buf) catch {
                    peer.setState(.failed);
                    return HostError.HandshakeFailed;
                };

                // Get transport keys
                const keys = hs.split() catch {
                    peer.setState(.failed);
                    return HostError.HandshakeFailed;
                };

                // Create session
                const session = self.allocator.create(session_mod.Session) catch {
                    peer.setState(.failed);
                    return HostError.OutOfMemory;
                };
                session.* = session_mod.Session.init(.{
                    .local_index = local_idx,
                    .remote_index = resp.sender_index,
                    .send_key = keys.send_cipher.key,
                    .recv_key = keys.recv_cipher.key,
                    .remote_pk = pk,
                });

                // Register session
                peer.setSession(session);
                self.peer_manager.registerIndex(local_idx, peer);

                // Update endpoint
                peer.setEndpoint(result.from_addr);

                return; // Success!
            } else if (msg_type == message_mod.MessageType.handshake_init) {
                // Handle incoming handshake from this or other peer
                self.handleHandshakeInit(self.recv_buf[0..result.bytes_read], result.from_addr) catch {};
            } else if (msg_type == message_mod.MessageType.transport) {
                // Queue for later processing
                // For simplicity, we ignore transport messages during connect
            }
        }

        peer.setState(.failed);
        return HostError.HandshakeTimeout;
    }

    /// Handles an incoming handshake init.
    fn handleHandshakeInit(self: *Host, data: []const u8, from: Addr) HostError!void {
        self.peer_manager.handleHandshakeInit(data, from, self.config.allow_unknown_peers) catch |err| {
            return switch (err) {
                peer_manager_mod.PeerManagerError.UnknownPeer => HostError.PeerError,
                peer_manager_mod.PeerManagerError.OutOfMemory => HostError.OutOfMemory,
                else => HostError.HandshakeFailed,
            };
        };
    }

    /// Disconnects from a peer.
    pub fn disconnect(self: *Host, pk: Key) void {
        if (self.peer_manager.getPeer(pk)) |peer| {
            peer.clearSession();
            peer.setState(.idle);
        }
    }

    /// Sends a message to a peer.
    pub fn send(self: *Host, pk: Key, protocol: Protocol, data: []const u8) HostError!void {
        if (self.closed.load(.seq_cst)) {
            return HostError.Closed;
        }

        self.peer_manager.send(pk, protocol, data) catch |err| {
            return switch (err) {
                peer_manager_mod.PeerManagerError.PeerNotFound => HostError.PeerNotFound,
                peer_manager_mod.PeerManagerError.NotEstablished => HostError.NotEstablished,
                peer_manager_mod.PeerManagerError.NoEndpoint => HostError.NoEndpoint,
                peer_manager_mod.PeerManagerError.TransportError => HostError.TransportError,
                peer_manager_mod.PeerManagerError.OutOfMemory => HostError.OutOfMemory,
                else => HostError.PeerError,
            };
        };
    }

    /// Receives a message (blocking).
    /// Returns null if no message is available or an error occurs.
    /// Caller is responsible for calling msg.deinit() when done.
    pub fn recvMessage(self: *Host) HostError!?Message {
        if (self.closed.load(.seq_cst)) {
            return HostError.Closed;
        }

        const result = self.peer_manager.transport.recv(self.recv_buf) catch {
            return null;
        };

        if (result.bytes_read == 0) return null;

        return self.processPacket(self.recv_buf[0..result.bytes_read], result.from_addr);
    }

    /// Process a single incoming packet.
    /// Returns a Message if it was a transport message, null otherwise.
    fn processPacket(self: *Host, data: []const u8, from: Addr) HostError!?Message {
        if (data.len == 0) return null;

        const msg_type = data[0];
        switch (msg_type) {
            message_mod.MessageType.handshake_init => {
                self.handleHandshakeInit(data, from) catch {};
                return null;
            },
            message_mod.MessageType.handshake_resp => {
                // Response handled in connect()
                return null;
            },
            message_mod.MessageType.transport => {
                const msg_result = self.peer_manager.handleTransport(data, from) catch {
                    return null;
                };

                // Copy data to owned buffer
                const owned_data = self.allocator.dupe(u8, msg_result.payload) catch {
                    return HostError.OutOfMemory;
                };

                return Message{
                    .from = msg_result.peer.getPublicKey(),
                    .protocol = msg_result.protocol,
                    .data = owned_data,
                    .allocator = self.allocator,
                };
            },
            else => return null,
        }
    }

    /// Closes the host.
    pub fn close(self: *Host) void {
        self.closed.store(true, .seq_cst);
        self.peer_manager.clear();
    }

    /// Returns true if the host is closed.
    pub fn isClosed(self: *Host) bool {
        return self.closed.load(.seq_cst);
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "new host" {
    const kp = KeyPair.generate();
    var transport = try transport_mod.MockTransport.init(testing.allocator, "test");
    defer transport.deinit();

    var host = try Host.init(testing.allocator, .{
        .private_key = kp,
        .transport = Transport{ .mock = transport },
    });
    defer host.deinit();

    try testing.expectEqual(host.getPublicKey(), kp.public);
}

test "host generates key" {
    var transport = try transport_mod.MockTransport.init(testing.allocator, "test");
    defer transport.deinit();

    var host = try Host.init(testing.allocator, .{
        .transport = Transport{ .mock = transport },
    });
    defer host.deinit();

    try testing.expect(!host.getPublicKey().isZero());
}

test "host add remove peer" {
    var transport = try transport_mod.MockTransport.init(testing.allocator, "test");
    defer transport.deinit();

    var host = try Host.init(testing.allocator, .{
        .transport = Transport{ .mock = transport },
    });
    defer host.deinit();

    const peer_kp = KeyPair.generate();

    try host.addPeer(peer_kp.public, null);
    try testing.expect(host.getPeer(peer_kp.public) != null);
    try testing.expectEqual(@as(usize, 1), host.peerCount());

    host.removePeer(peer_kp.public);
    try testing.expect(host.getPeer(peer_kp.public) == null);
    try testing.expectEqual(@as(usize, 0), host.peerCount());
}

test "host close" {
    var transport = try transport_mod.MockTransport.init(testing.allocator, "test");
    defer transport.deinit();

    var host = try Host.init(testing.allocator, .{
        .transport = Transport{ .mock = transport },
    });
    defer host.deinit();

    try testing.expect(!host.isClosed());
    host.close();
    try testing.expect(host.isClosed());
}

test "host send not established" {
    var transport = try transport_mod.MockTransport.init(testing.allocator, "test");
    defer transport.deinit();

    var host = try Host.init(testing.allocator, .{
        .transport = Transport{ .mock = transport },
    });
    defer host.deinit();

    const peer_kp = KeyPair.generate();
    try host.addPeer(peer_kp.public, null);

    try testing.expectError(HostError.NotEstablished, host.send(peer_kp.public, .chat, "test"));
}

test "host default mtu" {
    var transport = try transport_mod.MockTransport.init(testing.allocator, "test");
    defer transport.deinit();

    var host = try Host.init(testing.allocator, .{
        .transport = Transport{ .mock = transport },
    });
    defer host.deinit();

    const peer_kp = KeyPair.generate();
    try host.addPeer(peer_kp.public, null);

    const info = host.getPeer(peer_kp.public).?;
    try testing.expectEqual(@as(u16, 1280), info.mtu);
}

test "host custom mtu" {
    var transport = try transport_mod.MockTransport.init(testing.allocator, "test");
    defer transport.deinit();

    var host = try Host.init(testing.allocator, .{
        .transport = Transport{ .mock = transport },
        .mtu = 1400,
    });
    defer host.deinit();

    const peer_kp = KeyPair.generate();
    try host.addPeer(peer_kp.public, null);

    const info = host.getPeer(peer_kp.public).?;
    try testing.expectEqual(@as(u16, 1400), info.mtu);
}
