//! Peer manager for managing connections to multiple peers.

const std = @import("std");
const Mutex = std.Thread.Mutex;
const Allocator = std.mem.Allocator;

const keypair = @import("keypair.zig");
const session_mod = @import("session.zig");
const transport_mod = @import("transport.zig");
const message_mod = @import("message.zig");
const peer_mod = @import("peer.zig");
const handshake_mod = @import("handshake.zig");

pub const Key = keypair.Key;
pub const KeyPair = keypair.KeyPair;
pub const Session = session_mod.Session;
pub const Transport = transport_mod.Transport;
pub const Addr = transport_mod.Addr;
pub const Peer = peer_mod.Peer;
pub const PeerConfig = peer_mod.PeerConfig;
pub const PeerState = peer_mod.PeerState;

/// Peer manager errors.
pub const PeerManagerError = error{
    PeerExists,
    PeerNotFound,
    NoEndpoint,
    HandshakeFailed,
    HandshakeTimeout,
    NoPendingHandshake,
    UnknownPeer,
    SessionNotFound,
    NotEstablished,
    HostClosed,
    TransportError,
    SessionError,
    MessageError,
    OutOfMemory,
};

/// Pending handshake state.
const PendingHandshake = struct {
    peer: *Peer,
    hs_state: handshake_mod.HandshakeState,
    local_idx: u32,
    created_at: i128,
};

/// Manages all peers and their connections.
pub const PeerManager = struct {
    allocator: Allocator,
    mutex: Mutex = .{},
    by_pubkey: std.AutoHashMap(Key, *Peer),
    by_index: std.AutoHashMap(u32, *Peer),
    pending: std.AutoHashMap(u32, PendingHandshake),
    local_key: KeyPair,
    transport: Transport,

    /// Creates a new peer manager.
    pub fn init(allocator: Allocator, local_key: KeyPair, transport: Transport) PeerManager {
        return .{
            .allocator = allocator,
            .by_pubkey = std.AutoHashMap(Key, *Peer).init(allocator),
            .by_index = std.AutoHashMap(u32, *Peer).init(allocator),
            .pending = std.AutoHashMap(u32, PendingHandshake).init(allocator),
            .local_key = local_key,
            .transport = transport,
        };
    }

    /// Deinitializes the peer manager and frees all peers.
    pub fn deinit(self: *PeerManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Clear pending handshakes
        self.pending.clearAndFree();

        var it = self.by_pubkey.valueIterator();
        while (it.next()) |peer_ptr| {
            peer_ptr.*.clearSession();
            self.allocator.destroy(peer_ptr.*);
        }

        self.by_pubkey.deinit();
        self.by_index.deinit();
    }

    /// Adds a new peer.
    pub fn addPeer(self: *PeerManager, peer: *Peer) PeerManagerError!void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const pk = peer.public_key;
        if (self.by_pubkey.contains(pk)) {
            return PeerManagerError.PeerExists;
        }

        self.by_pubkey.put(pk, peer) catch return PeerManagerError.OutOfMemory;
    }

    /// Removes a peer by public key.
    pub fn removePeer(self: *PeerManager, pk: Key) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.by_pubkey.fetchRemove(pk)) |removed| {
            const peer = removed.value;
            // Remove from index mapping
            if (peer.getSession()) |session| {
                _ = self.by_index.remove(session.local_index);
            }
            peer.clearSession();
            self.allocator.destroy(peer);
        }
    }

    /// Gets a peer by public key.
    pub fn getPeer(self: *PeerManager, pk: Key) ?*Peer {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.by_pubkey.get(pk);
    }

    /// Gets a peer by session index.
    pub fn getPeerByIndex(self: *PeerManager, index: u32) ?*Peer {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.by_index.get(index);
    }

    /// Returns the number of peers.
    pub fn count(self: *PeerManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.by_pubkey.count();
    }

    /// Sends a message to a peer.
    pub fn send(self: *PeerManager, pk: Key, protocol: message_mod.Protocol, payload: []const u8) PeerManagerError!void {
        const peer = self.getPeer(pk) orelse return PeerManagerError.PeerNotFound;

        if (!peer.isEstablished()) {
            return PeerManagerError.NotEstablished;
        }

        const endpoint = peer.getEndpoint() orelse return PeerManagerError.NoEndpoint;

        // Get session and encrypt
        const session = peer.getSession() orelse return PeerManagerError.NotEstablished;

        // Encode payload with protocol
        const plaintext = self.allocator.alloc(u8, 1 + payload.len) catch return PeerManagerError.OutOfMemory;
        defer self.allocator.free(plaintext);
        plaintext[0] = @intFromEnum(protocol);
        @memcpy(plaintext[1..], payload);

        // Encrypt
        const ciphertext = self.allocator.alloc(u8, plaintext.len + session_mod.tag_size) catch return PeerManagerError.OutOfMemory;
        defer self.allocator.free(ciphertext);

        const counter = session.encrypt(plaintext, ciphertext) catch return PeerManagerError.SessionError;

        // Build and send message
        const msg = message_mod.buildTransportMessage(self.allocator, session.remoteIndex(), counter, ciphertext) catch return PeerManagerError.OutOfMemory;
        defer self.allocator.free(msg);

        peer.addTxBytes(msg.len);
        peer.updateActivity();

        self.transport.sendTo(msg, endpoint) catch return PeerManagerError.TransportError;
    }

    /// Handles an incoming transport message.
    pub fn handleTransport(self: *PeerManager, data: []const u8, from: Addr) PeerManagerError!struct { peer: *Peer, protocol: message_mod.Protocol, payload: []const u8 } {
        const msg = message_mod.parseTransportMessage(data) catch return PeerManagerError.MessageError;

        const peer = self.getPeerByIndex(msg.receiver_index) orelse return PeerManagerError.SessionNotFound;

        const session = peer.getSession() orelse return PeerManagerError.SessionNotFound;

        // Decrypt
        const plaintext_len = msg.ciphertext.len - session_mod.tag_size;
        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return PeerManagerError.OutOfMemory;
        errdefer self.allocator.free(plaintext);

        _ = session.decrypt(msg.ciphertext, msg.counter, plaintext) catch return PeerManagerError.SessionError;

        // Decode protocol and payload
        const decoded = message_mod.decodePayload(plaintext) catch return PeerManagerError.MessageError;

        // Update stats and roaming
        peer.addRxBytes(data.len);
        peer.updateActivity();

        // Roaming: update endpoint if changed
        const current = peer.getEndpoint();
        if (current == null) {
            peer.setEndpoint(from);
        }

        return .{
            .peer = peer,
            .protocol = decoded.protocol,
            .payload = decoded.payload,
        };
    }

    /// Expires stale peers.
    pub fn expireStale(self: *PeerManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var expired = std.ArrayListUnmanaged(Key){};
        defer expired.deinit(self.allocator);

        var it = self.by_pubkey.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.isExpired()) {
                expired.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (expired.items) |pk| {
            if (self.by_pubkey.get(pk)) |peer| {
                if (peer.getSession()) |session| {
                    _ = self.by_index.remove(session.local_index);
                }
                peer.clearSession();
            }
        }

        return expired.items.len;
    }

    /// Expires pending handshakes that are too old.
    pub fn expirePendingHandshakes(self: *PeerManager, max_age_ns: i128) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.nanoTimestamp();
        var expired = std.ArrayListUnmanaged(u32){};
        defer expired.deinit(self.allocator);

        var it = self.pending.iterator();
        while (it.next()) |entry| {
            if (now - entry.value_ptr.created_at > max_age_ns) {
                expired.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (expired.items) |idx| {
            if (self.pending.fetchRemove(idx)) |removed| {
                removed.value.peer.setState(.failed);
            }
        }

        return expired.items.len;
    }

    /// Clears all peers and pending handshakes.
    pub fn clear(self: *PeerManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Clear pending handshakes
        var pending_it = self.pending.valueIterator();
        while (pending_it.next()) |p| {
            p.peer.setState(.failed);
        }
        self.pending.clearAndFree();

        var it = self.by_pubkey.valueIterator();
        while (it.next()) |peer_ptr| {
            peer_ptr.*.clearSession();
            self.allocator.destroy(peer_ptr.*);
        }

        self.by_pubkey.clearAndFree();
        self.by_index.clearAndFree();
    }

    /// Registers a session for a peer.
    pub fn registerSession(self: *PeerManager, pk: Key, session: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.by_pubkey.get(pk)) |peer| {
            // Remove old index mapping
            if (peer.getSession()) |old_session| {
                _ = self.by_index.remove(old_session.local_index);
            }

            peer.setSession(session);
            self.by_index.put(session.local_index, peer) catch {};
        }
    }

    /// Registers a peer by its local index.
    pub fn registerIndex(self: *PeerManager, local_index: u32, peer: *Peer) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.by_index.put(local_index, peer) catch {};
    }

    /// Handles an incoming handshake initiation (responder side).
    pub fn handleHandshakeInit(self: *PeerManager, data: []const u8, from: Addr, allow_unknown: bool) PeerManagerError!void {
        const hs_init = message_mod.parseHandshakeInit(data) catch return PeerManagerError.MessageError;

        // Create responder handshake state
        var hs = handshake_mod.HandshakeState.init(.{
            .pattern = .ik,
            .initiator = false,
            .local_static = self.local_key,
            .remote_static = null, // Will be learned from message
        }) catch return PeerManagerError.HandshakeFailed;

        // Reconstruct noise message
        var noise_msg: [keypair.key_size + keypair.key_size + 16 + 16]u8 = undefined;
        @memcpy(noise_msg[0..keypair.key_size], &hs_init.ephemeral);
        @memcpy(noise_msg[keypair.key_size..], hs_init.static_encrypted);

        // Process handshake
        var payload_buf: [64]u8 = undefined;
        _ = hs.readMessage(&noise_msg, &payload_buf) catch return PeerManagerError.HandshakeFailed;

        // Get initiator's static key
        const initiator_pk = hs.remoteStatic() orelse return PeerManagerError.HandshakeFailed;
        if (initiator_pk.isZero()) {
            return PeerManagerError.HandshakeFailed;
        }

        // Find or create peer
        var peer: *Peer = undefined;
        {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.by_pubkey.get(initiator_pk)) |p| {
                peer = p;
            } else if (allow_unknown) {
                peer = self.allocator.create(Peer) catch return PeerManagerError.OutOfMemory;
                peer.* = Peer.init(self.allocator, .{
                    .public_key = initiator_pk,
                    .endpoint = from,
                });
                self.by_pubkey.put(initiator_pk, peer) catch {
                    self.allocator.destroy(peer);
                    return PeerManagerError.OutOfMemory;
                };
            } else {
                return PeerManagerError.UnknownPeer;
            }
        }

        // Generate our index
        const local_idx = session_mod.generateIndex();

        // Generate response
        var msg2_buf: [256]u8 = undefined;
        const msg2 = hs.writeMessage(&.{}, &msg2_buf) catch return PeerManagerError.HandshakeFailed;

        // Get ephemeral
        const ephemeral = hs.localEphemeral() orelse return PeerManagerError.HandshakeFailed;

        // Build wire message
        var wire_buf: [128]u8 = undefined;
        const wire_msg = message_mod.buildHandshakeResp(&wire_buf, local_idx, hs_init.sender_index, ephemeral, msg2[keypair.key_size..]) catch return PeerManagerError.MessageError;

        // Get transport keys (swapped for responder)
        const keys = hs.split() catch return PeerManagerError.HandshakeFailed;

        // Create session
        const session = self.allocator.create(Session) catch return PeerManagerError.OutOfMemory;
        session.* = session_mod.Session.init(.{
            .local_index = local_idx,
            .remote_index = hs_init.sender_index,
            .send_key = keys.recv_cipher.key, // Swapped for responder
            .recv_key = keys.send_cipher.key,
            .remote_pk = initiator_pk,
        });

        // Register session
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            peer.setSession(session);
            peer.setEndpoint(from);
            self.by_index.put(local_idx, peer) catch {};
        }

        // Send response
        self.transport.send(wire_msg, from) catch return PeerManagerError.TransportError;
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "new peer manager" {
    const kp = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(testing.allocator, "test");
    defer transport.deinit();

    var pm = PeerManager.init(testing.allocator, kp, Transport{ .mock = transport });
    defer pm.deinit();

    try testing.expectEqual(@as(usize, 0), pm.count());
}

test "add remove peer" {
    const kp = KeyPair.generate();
    const peer_kp = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(testing.allocator, "test");
    defer transport.deinit();

    var pm = PeerManager.init(testing.allocator, kp, Transport{ .mock = transport });
    defer pm.deinit();

    const peer = try testing.allocator.create(Peer);
    peer.* = Peer.init(testing.allocator, .{ .public_key = peer_kp.public });

    // Add peer
    try pm.addPeer(peer);
    try testing.expectEqual(@as(usize, 1), pm.count());

    // Try duplicate
    try testing.expectError(PeerManagerError.PeerExists, pm.addPeer(peer));

    // Get peer
    try testing.expect(pm.getPeer(peer_kp.public) != null);

    // Remove peer
    pm.removePeer(peer_kp.public);
    try testing.expectEqual(@as(usize, 0), pm.count());
    try testing.expect(pm.getPeer(peer_kp.public) == null);
}

test "send not established" {
    const kp = KeyPair.generate();
    const peer_kp = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(testing.allocator, "test");
    defer transport.deinit();

    var pm = PeerManager.init(testing.allocator, kp, Transport{ .mock = transport });
    defer pm.deinit();

    const peer = try testing.allocator.create(Peer);
    peer.* = Peer.init(testing.allocator, .{ .public_key = peer_kp.public });
    try pm.addPeer(peer);

    try testing.expectError(PeerManagerError.NotEstablished, pm.send(peer_kp.public, .chat, "test"));
}

test "send unknown peer" {
    const kp = KeyPair.generate();
    const unknown_kp = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(testing.allocator, "test");
    defer transport.deinit();

    var pm = PeerManager.init(testing.allocator, kp, Transport{ .mock = transport });
    defer pm.deinit();

    try testing.expectError(PeerManagerError.PeerNotFound, pm.send(unknown_kp.public, .chat, "test"));
}

test "clear" {
    const kp = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(testing.allocator, "test");
    defer transport.deinit();

    var pm = PeerManager.init(testing.allocator, kp, Transport{ .mock = transport });
    defer pm.deinit();

    for (0..5) |_| {
        const peer_kp = KeyPair.generate();
        const peer = try testing.allocator.create(Peer);
        peer.* = Peer.init(testing.allocator, .{ .public_key = peer_kp.public });
        try pm.addPeer(peer);
    }

    pm.clear();
    try testing.expectEqual(@as(usize, 0), pm.count());
}
