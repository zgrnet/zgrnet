//! Connection management for Noise-based communication.
//!
//! This module provides the `Conn` type which manages the handshake process
//! and provides a simple API for sending and receiving encrypted messages.

const std = @import("std");
const mem = std.mem;
const Mutex = std.Thread.Mutex;

const keypair = @import("keypair.zig");
const handshake_mod = @import("handshake.zig");
const session_mod = @import("session.zig");
const transport_mod = @import("transport.zig");
const message = @import("message.zig");

const Key = keypair.Key;
const KeyPair = keypair.KeyPair;
const key_size = keypair.key_size;
const HandshakeState = handshake_mod.HandshakeState;
const Pattern = handshake_mod.Pattern;
const Session = session_mod.Session;
const SessionConfig = session_mod.SessionConfig;
const Transport = transport_mod.Transport;
const Addr = transport_mod.Addr;
const HandshakeInit = message.HandshakeInit;
const Protocol = message.Protocol;

/// Connection state.
pub const ConnState = enum {
    /// Newly created connection.
    new,
    /// Handshake in progress.
    handshaking,
    /// Connection established, ready for data transfer.
    established,
    /// Connection closed.
    closed,

    pub fn format(
        self: ConnState,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.writeAll(switch (self) {
            .new => "new",
            .handshaking => "handshaking",
            .established => "established",
            .closed => "closed",
        });
    }
};

/// Connection errors.
pub const ConnError = error{
    /// Missing local key pair.
    MissingLocalKey,
    /// Missing transport.
    MissingTransport,
    /// Missing remote public key.
    MissingRemotePK,
    /// Missing remote address.
    MissingRemoteAddr,
    /// Invalid connection state.
    InvalidState,
    /// Connection not established.
    NotEstablished,
    /// Invalid receiver index.
    InvalidReceiverIndex,
    /// Handshake not complete.
    HandshakeIncomplete,
    /// Handshake error.
    HandshakeError,
    /// Session error.
    SessionError,
    /// Message error.
    MessageError,
    /// Transport error.
    TransportError,
    /// Out of memory.
    OutOfMemory,
};

/// Configuration for creating a connection.
pub const ConnConfig = struct {
    /// Local static key pair.
    local_key: KeyPair,
    /// Remote peer's public key (required for initiator).
    remote_pk: ?Key = null,
    /// Underlying datagram transport.
    transport: Transport,
    /// Remote peer's address.
    remote_addr: ?Addr = null,
};

/// Result of a receive operation.
pub const RecvResult = struct {
    protocol: Protocol,
    bytes_read: usize,
};

/// A connection to a remote peer.
///
/// Manages the handshake process and provides a simple API
/// for sending and receiving encrypted messages.
pub const Conn = struct {
    allocator: mem.Allocator,
    mutex: Mutex = .{},

    // Configuration
    local_key: KeyPair,
    remote_pk: Key,
    transport: Transport,
    remote_addr: ?Addr,

    // State
    state: ConnState = .new,
    session: ?Session = null,
    local_idx: u32,

    /// Creates a new connection with the given configuration.
    pub fn init(allocator: mem.Allocator, cfg: ConnConfig) Conn {
        return Conn{
            .allocator = allocator,
            .local_key = cfg.local_key,
            .remote_pk = cfg.remote_pk orelse Key.zero,
            .transport = cfg.transport,
            .remote_addr = cfg.remote_addr,
            .local_idx = session_mod.generateIndex(),
        };
    }

    /// Initiates a handshake with the remote peer.
    /// This is a blocking call that completes the full handshake.
    pub fn open(self: *Conn) ConnError!void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check state
        if (self.state != .new) {
            return ConnError.InvalidState;
        }
        if (self.remote_pk.isZero()) {
            return ConnError.MissingRemotePK;
        }
        if (self.remote_addr == null) {
            return ConnError.MissingRemoteAddr;
        }
        self.state = .handshaking;

        // Create handshake state (IK pattern)
        var hs = HandshakeState.init(.{
            .pattern = .IK,
            .initiator = true,
            .local_static = self.local_key,
            .remote_static = self.remote_pk,
        }) catch {
            self.state = .new;
            return ConnError.HandshakeError;
        };

        // Generate and send handshake initiation
        var msg1_buf: [key_size + key_size + 16]u8 = undefined; // ephemeral + encrypted_static
        const msg1_len = hs.writeMessage(&[_]u8{}, &msg1_buf) catch {
            self.state = .new;
            return ConnError.HandshakeError;
        };

        // Extract ephemeral public key from local_ephemeral
        const ephemeral = if (hs.local_ephemeral) |le| le.public else {
            self.state = .new;
            return ConnError.HandshakeError;
        };

        // Build wire message: msg1_buf contains ephemeral(32) + encrypted_static(48) = 80 bytes
        // We need to send: type(1) + sender_idx(4) + ephemeral(32) + encrypted_static(48) = 85
        const wire_msg = message.buildHandshakeInit(
            self.local_idx,
            &ephemeral,
            msg1_buf[key_size..msg1_len],
        );

        // Send handshake init
        self.transport.sendTo(&wire_msg, self.remote_addr.?) catch {
            self.state = .new;
            return ConnError.TransportError;
        };

        // Wait for handshake response
        var buf: [message.max_packet_size]u8 = undefined;
        const result = self.transport.recvFrom(&buf) catch {
            self.state = .new;
            return ConnError.TransportError;
        };

        // Parse response
        const resp = message.parseHandshakeResp(buf[0..result.bytes_read]) catch {
            self.state = .new;
            return ConnError.MessageError;
        };

        // Verify receiver index matches our sender index
        if (resp.receiver_index != self.local_idx) {
            self.state = .new;
            return ConnError.InvalidReceiverIndex;
        }

        // Reconstruct the noise message and process
        // Response format: ephemeral(32) + empty_encrypted(16) = 48 bytes
        var noise_msg: [key_size + 16]u8 = undefined;
        @memcpy(noise_msg[0..key_size], resp.ephemeral.asBytes());
        @memcpy(noise_msg[key_size..][0..16], &resp.empty_encrypted);

        var payload_buf: [1]u8 = undefined;
        _ = hs.readMessage(&noise_msg, &payload_buf) catch {
            self.state = .new;
            return ConnError.HandshakeError;
        };

        // Complete handshake
        try self.completeHandshake(&hs, resp.sender_index);
    }

    /// Processes an incoming handshake initiation and completes the handshake.
    /// Returns the handshake response to send back.
    pub fn accept(self: *Conn, msg: *const HandshakeInit) ConnError![message.handshake_resp_size]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check state
        if (self.state != .new) {
            return ConnError.InvalidState;
        }
        self.state = .handshaking;

        // Create handshake state (IK pattern - responder)
        var hs = HandshakeState.init(.{
            .pattern = .IK,
            .initiator = false,
            .local_static = self.local_key,
        }) catch {
            self.state = .new;
            return ConnError.HandshakeError;
        };

        // Reconstruct the noise message: ephemeral(32) + static_enc(48) = 80 bytes
        var noise_msg: [key_size + 48]u8 = undefined;
        @memcpy(noise_msg[0..key_size], msg.ephemeral.asBytes());
        @memcpy(noise_msg[key_size..][0..48], &msg.static_encrypted);

        var payload_buf: [1]u8 = undefined;
        _ = hs.readMessage(&noise_msg, &payload_buf) catch {
            self.state = .new;
            return ConnError.HandshakeError;
        };

        // Get remote public key from handshake
        self.remote_pk = hs.getRemoteStatic();

        // Generate response
        var msg2_buf: [key_size + 16]u8 = undefined;
        const msg2_len = hs.writeMessage(&[_]u8{}, &msg2_buf) catch {
            self.state = .new;
            return ConnError.HandshakeError;
        };

        // Store initiator's index as remote index
        const remote_idx = msg.sender_index;

        // Complete handshake
        try self.completeHandshake(&hs, remote_idx);

        // Extract ephemeral for response
        const ephemeral = if (hs.local_ephemeral) |le| le.public else {
            self.state = .new;
            return ConnError.HandshakeError;
        };

        // Build wire response message
        return message.buildHandshakeResp(
            self.local_idx,
            remote_idx,
            &ephemeral,
            msg2_buf[key_size..msg2_len],
        );
    }

    /// Completes the handshake and creates the session.
    fn completeHandshake(self: *Conn, hs: *const HandshakeState, remote_idx: u32) ConnError!void {
        if (!hs.isFinished()) {
            return ConnError.HandshakeIncomplete;
        }

        // Get transport keys
        const send_cipher, const recv_cipher = hs.split() catch {
            self.state = .new;
            return ConnError.HandshakeError;
        };

        // Create session
        self.session = Session.init(.{
            .local_index = self.local_idx,
            .remote_index = remote_idx,
            .send_key = send_cipher.getKey(),
            .recv_key = recv_cipher.getKey(),
            .remote_pk = self.remote_pk,
        });

        self.state = .established;
    }

    /// Sends an encrypted message to the remote peer.
    pub fn send(self: *Conn, protocol: Protocol, payload: []const u8) ConnError!void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state != .established) {
            return ConnError.NotEstablished;
        }
        const remote_addr = self.remote_addr orelse return ConnError.MissingRemoteAddr;

        var session = &(self.session orelse return ConnError.NotEstablished);

        // Encode payload with protocol byte
        const plaintext = self.allocator.alloc(u8, 1 + payload.len) catch return ConnError.OutOfMemory;
        defer self.allocator.free(plaintext);
        plaintext[0] = @intFromEnum(protocol);
        @memcpy(plaintext[1..], payload);

        // Encrypt
        const ciphertext = self.allocator.alloc(u8, plaintext.len + session_mod.tag_size) catch return ConnError.OutOfMemory;
        defer self.allocator.free(ciphertext);

        const counter = session.encrypt(plaintext, ciphertext) catch return ConnError.SessionError;

        // Build wire message
        const msg = message.buildTransportMessage(self.allocator, session.remoteIndex(), counter, ciphertext) catch return ConnError.OutOfMemory;
        defer self.allocator.free(msg);

        // Send
        self.transport.sendTo(msg, remote_addr) catch return ConnError.TransportError;
    }

    /// Receives and decrypts a message from the remote peer.
    /// Returns the protocol and number of bytes written to the output buffer.
    pub fn recv(self: *Conn, out_buf: []u8) ConnError!RecvResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state != .established) {
            return ConnError.NotEstablished;
        }

        var session = &(self.session orelse return ConnError.NotEstablished);

        // Receive packet
        var buf: [message.max_packet_size]u8 = undefined;
        const result = self.transport.recvFrom(&buf) catch return ConnError.TransportError;

        // Parse transport message
        const msg = message.parseTransportMessage(buf[0..result.bytes_read]) catch return ConnError.MessageError;

        // Verify receiver index
        if (msg.receiver_index != self.local_idx) {
            return ConnError.InvalidReceiverIndex;
        }

        // Decrypt
        const plaintext_len = msg.ciphertext.len - session_mod.tag_size;
        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return ConnError.OutOfMemory;
        defer self.allocator.free(plaintext);

        _ = session.decrypt(msg.ciphertext, msg.counter, plaintext) catch return ConnError.SessionError;

        // Decode protocol and payload
        const decoded = message.decodePayload(plaintext) catch return ConnError.MessageError;

        const bytes_to_copy = @min(out_buf.len, decoded.payload.len);
        @memcpy(out_buf[0..bytes_to_copy], decoded.payload[0..bytes_to_copy]);

        return RecvResult{
            .protocol = decoded.protocol,
            .bytes_read = bytes_to_copy,
        };
    }

    /// Closes the connection.
    pub fn close(self: *Conn) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state == .closed) {
            return;
        }

        self.state = .closed;
        if (self.session) |*session| {
            session.expire();
        }
    }

    /// Returns the current connection state.
    pub fn getState(self: *Conn) ConnState {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.state;
    }

    /// Returns the remote peer's public key.
    pub fn getRemotePublicKey(self: *Conn) Key {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.remote_pk;
    }

    /// Returns the local session index.
    pub fn getLocalIndex(self: *Conn) u32 {
        return self.local_idx;
    }

    /// Updates the remote address (for NAT traversal).
    pub fn setRemoteAddr(self: *Conn, addr: Addr) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.remote_addr = addr;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "conn state display" {
    var buf: [32]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try std.fmt.format(stream.writer(), "{any}", .{ConnState.new});
    try std.testing.expectEqualStrings(stream.getWritten(), ".new");
}

test "conn new" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .transport = Transport{ .mock = transport },
    });

    try std.testing.expectEqual(conn.getState(), ConnState.new);
    try std.testing.expect(conn.local_idx != 0);
}

test "conn open missing remote pk" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .transport = Transport{ .mock = transport },
        .remote_addr = Addr{ .mock = transport_mod.MockAddr.init("peer") },
    });

    try std.testing.expectError(ConnError.MissingRemotePK, conn.open());
}

test "conn open missing remote addr" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const peer_key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .remote_pk = peer_key.public,
        .transport = Transport{ .mock = transport },
    });

    try std.testing.expectError(ConnError.MissingRemoteAddr, conn.open());
}

test "conn send not established" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .transport = Transport{ .mock = transport },
    });

    try std.testing.expectError(ConnError.NotEstablished, conn.send(.chat, "test"));
}

test "conn recv not established" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .transport = Transport{ .mock = transport },
    });

    var buf: [1024]u8 = undefined;
    try std.testing.expectError(ConnError.NotEstablished, conn.recv(&buf));
}

test "conn close" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .transport = Transport{ .mock = transport },
    });

    conn.close();
    try std.testing.expectEqual(conn.getState(), ConnState.closed);

    // Double close should be ok
    conn.close();
}

test "conn handshake and communication" {
    const allocator = std.testing.allocator;

    const initiator_key = KeyPair.generate();
    const responder_key = KeyPair.generate();

    const initiator_transport = try transport_mod.MockTransport.init(allocator, "initiator");
    defer initiator_transport.deinit();
    const responder_transport = try transport_mod.MockTransport.init(allocator, "responder");
    defer responder_transport.deinit();

    transport_mod.MockTransport.connect(initiator_transport, responder_transport);

    var initiator = Conn.init(allocator, .{
        .local_key = initiator_key,
        .remote_pk = responder_key.public,
        .transport = Transport{ .mock = initiator_transport },
        .remote_addr = Addr{ .mock = transport_mod.MockAddr.init("responder") },
    });

    var responder = Conn.init(allocator, .{
        .local_key = responder_key,
        .transport = Transport{ .mock = responder_transport },
        .remote_addr = Addr{ .mock = transport_mod.MockAddr.init("initiator") },
    });

    // Spawn responder thread
    const Thread = std.Thread;
    const responder_thread = try Thread.spawn(.{}, struct {
        fn run(r: *Conn, rt: *transport_mod.MockTransport) void {
            // Receive handshake init
            var buf: [message.max_packet_size]u8 = undefined;
            const result = rt.recvFrom(&buf) catch return;
            const init_msg = message.parseHandshakeInit(buf[0..result.bytes_read]) catch return;

            // Process and respond
            const resp = r.accept(&init_msg) catch return;
            rt.sendTo(&resp, Addr{ .mock = transport_mod.MockAddr.init("initiator") }) catch return;
        }
    }.run, .{ &responder, responder_transport });

    // Give responder time to start
    std.Thread.sleep(10 * std.time.ns_per_ms);

    // Initiator opens connection
    try initiator.open();

    responder_thread.join();

    // Verify both sides are established
    try std.testing.expectEqual(initiator.getState(), ConnState.established);
    try std.testing.expectEqual(responder.getState(), ConnState.established);

    // Test communication: initiator -> responder
    try initiator.send(.chat, "Hello from initiator!");
    var recv_buf: [1024]u8 = undefined;
    const recv_result = try responder.recv(&recv_buf);
    try std.testing.expectEqual(recv_result.protocol, .chat);
    try std.testing.expectEqualStrings(recv_buf[0..recv_result.bytes_read], "Hello from initiator!");

    // Test communication: responder -> initiator
    try responder.send(.rpc, "Hello from responder!");
    const recv_result2 = try initiator.recv(&recv_buf);
    try std.testing.expectEqual(recv_result2.protocol, .rpc);
    try std.testing.expectEqualStrings(recv_buf[0..recv_result2.bytes_read], "Hello from responder!");
}
