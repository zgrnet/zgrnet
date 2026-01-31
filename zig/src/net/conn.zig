//! Connection management for Noise-based communication.
//!
//! This module provides the `Conn` type which manages the handshake process
//! and provides a simple API for sending and receiving encrypted messages.

const std = @import("std");
const mem = std.mem;
const Mutex = std.Thread.Mutex;

const noise = @import("../noise/mod.zig");

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const key_size = noise.key_size;
const HandshakeState = noise.HandshakeState;
const Pattern = noise.Pattern;
const Session = noise.Session;
const SessionConfig = noise.SessionConfig;
const Transport = noise.Transport;
const Addr = noise.Addr;
const HandshakeInit = noise.HandshakeInit;
const Protocol = noise.Protocol;

// Internal module access for constants
const session_mod = noise.session;
const message = noise.message;
const transport_mod = noise.transport;

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
    /// Handshake failed.
    HandshakeFailed,
    /// Connection timed out (no data received for too long).
    ConnTimeout,
    /// Handshake attempt exceeded maximum duration.
    HandshakeTimeout,
    /// Session expired (too old or too many messages).
    SessionExpired,
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

/// An inbound packet from the listener.
/// Contains an owned copy of the transport message data.
pub const InboundPacket = struct {
    receiver_index: u32,
    counter: u64,
    ciphertext: []u8, // Allocated copy
    addr: Addr,
    allocator: mem.Allocator,

    pub fn deinit(self: *InboundPacket) void {
        self.allocator.free(self.ciphertext);
    }
};

/// Maximum number of inbound packets to queue.
const max_inbound_queue = 64;

// Import constants
const consts = @import("consts.zig");

/// A connection to a remote peer.
///
/// Manages the handshake process and provides a simple API
/// for sending and receiving encrypted messages.
///
/// The connection follows WireGuard's timer model:
/// - tick() is called periodically to handle time-based actions
/// - send() queues data if no session and triggers handshake
/// - recv() processes incoming messages and updates state
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
    local_idx: u32,

    // Session management (WireGuard-style rotation)
    // current: active session for sending
    // previous: previous session (for receiving delayed packets)
    current: ?Session = null,
    previous: ?Session = null,

    // Handshake state (for pending rekey)
    hs_state: ?HandshakeState = null,
    handshake_started: ?i128 = null,

    // Timestamps (in nanoseconds from std.time.nanoTimestamp)
    session_created: ?i128 = null,
    last_sent: ?i128 = null,
    last_received: ?i128 = null,
    handshake_attempt_start: ?i128 = null,
    last_handshake_sent: ?i128 = null,

    // Role
    is_initiator: bool = false,

    // Rekey state
    rekey_triggered: bool = false,

    // Inbound queue for listener-managed connections
    // When set, recv() reads from this queue instead of the transport
    inbound_queue: ?std.ArrayListUnmanaged(InboundPacket) = null,
    inbound_signal: std.Thread.Condition = .{},

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

    /// Processes an incoming handshake initiation and completes the handshake.
    /// Returns the handshake response to send back.
    /// Note: This doesn't perform blocking I/O, so holding the lock is acceptable.
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

        // Get remote public key from handshake and update atomically
        const remote_pk = hs.getRemoteStatic();

        // Generate response
        var msg2_buf: [key_size + 16]u8 = undefined;
        const msg2_len = hs.writeMessage(&[_]u8{}, &msg2_buf) catch {
            self.state = .new;
            return ConnError.HandshakeError;
        };

        // Store initiator's index as remote index
        const remote_idx = msg.sender_index;

        // Complete handshake (updates remote_pk atomically with state)
        try self.completeHandshakeLocked(&hs, remote_idx, remote_pk);

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
    /// Must be called with mutex held.
    /// If remote_pk is provided, it will be set atomically with the state transition.
    fn completeHandshakeLocked(self: *Conn, hs: *const HandshakeState, remote_idx: u32, remote_pk: ?Key) ConnError!void {
        if (!hs.isFinished()) {
            return ConnError.HandshakeIncomplete;
        }

        // Get transport keys
        const send_cipher, const recv_cipher = hs.split() catch {
            self.state = .new;
            return ConnError.HandshakeError;
        };

        // Update remote_pk if provided (for responder case)
        if (remote_pk) |pk| {
            self.remote_pk = pk;
        }

        // Create session
        self.current = Session.init(.{
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
        // Phase 1: Check state and encrypt (with lock)
        var remote_addr: Addr = undefined;
        const msg = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.state != .established) {
                return ConnError.NotEstablished;
            }
            remote_addr = self.remote_addr orelse return ConnError.MissingRemoteAddr;

            var session = &(self.current orelse return ConnError.NotEstablished);

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
            break :blk message.buildTransportMessage(self.allocator, session.remoteIndex(), counter, ciphertext) catch return ConnError.OutOfMemory;
        };
        defer self.allocator.free(msg);

        // Phase 2: Send (without lock)
        self.transport.sendTo(msg, remote_addr) catch return ConnError.TransportError;

        // Update last sent time
        self.mutex.lock();
        self.last_sent = std.time.nanoTimestamp();
        self.mutex.unlock();
    }

    /// Sends an empty keepalive message to the remote peer.
    /// This is used to keep NAT mappings alive and to signal liveness.
    pub fn sendKeepalive(self: *Conn) ConnError!void {
        // Protocol 0 is used for keepalive (empty message)
        return self.send(@enumFromInt(0), &.{});
    }

    /// Receives and decrypts a message from the remote peer.
    /// Returns the protocol and number of bytes written to the output buffer.
    pub fn recv(self: *Conn, out_buf: []u8) ConnError!RecvResult {
        // Phase 1: Check state and inbound queue (with lock)
        self.mutex.lock();
        if (self.state != .established) {
            self.mutex.unlock();
            return ConnError.NotEstablished;
        }

        // Check if we have an inbound queue (listener-managed connection)
        if (self.inbound_queue) |*queue| {
            // Wait for packet in queue
            while (queue.items.len == 0 and self.state == .established) {
                self.inbound_signal.wait(&self.mutex);
            }

            if (self.state != .established) {
                self.mutex.unlock();
                return ConnError.NotEstablished;
            }

            if (queue.items.len == 0) {
                self.mutex.unlock();
                return ConnError.NotEstablished;
            }

            // Pop packet from queue
            var pkt = queue.orderedRemove(0);
            defer pkt.deinit();
            
            // Update remote address for NAT traversal
            self.remote_addr = pkt.addr;

            // Verify receiver index
            if (pkt.receiver_index != self.local_idx) {
                self.mutex.unlock();
                return ConnError.InvalidReceiverIndex;
            }

            var session = &(self.current orelse {
                self.mutex.unlock();
                return ConnError.NotEstablished;
            });

            // Decrypt
            const plaintext_len = pkt.ciphertext.len - session_mod.tag_size;
            const plaintext = self.allocator.alloc(u8, plaintext_len) catch {
                self.mutex.unlock();
                return ConnError.OutOfMemory;
            };
            defer self.allocator.free(plaintext);

            _ = session.decrypt(pkt.ciphertext, pkt.counter, plaintext) catch {
                self.mutex.unlock();
                return ConnError.SessionError;
            };

            // Decode protocol and payload
            const decoded = message.decodePayload(plaintext) catch {
                self.mutex.unlock();
                return ConnError.MessageError;
            };

            const bytes_to_copy = @min(out_buf.len, decoded.payload.len);
            @memcpy(out_buf[0..bytes_to_copy], decoded.payload[0..bytes_to_copy]);

            self.mutex.unlock();
            return RecvResult{
                .protocol = decoded.protocol,
                .bytes_read = bytes_to_copy,
            };
        }
        self.mutex.unlock();

        // Direct connection: receive packet from transport
        var buf: [message.max_packet_size]u8 = undefined;
        const result = self.transport.recvFrom(&buf) catch return ConnError.TransportError;

        // Phase 3: Decrypt and process (with lock)
        self.mutex.lock();
        defer self.mutex.unlock();

        // Re-check state in case it changed
        if (self.state != .established) {
            return ConnError.NotEstablished;
        }

        var session = &(self.current orelse return ConnError.NotEstablished);

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

    /// Initiates a rekey by starting a new handshake.
    /// This is called when the current session is too old or has too many messages.
    /// Note: Must be called WITHOUT holding the mutex.
    fn initiateRekey(self: *Conn) ConnError!void {
        // Get necessary data with lock
        var remote_addr: Addr = undefined;
        var new_idx: u32 = undefined;
        {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Check if already have pending handshake
            if (self.hs_state != null) {
                return;
            }

            remote_addr = self.remote_addr orelse return ConnError.MissingRemoteAddr;
            new_idx = session_mod.generateIndex();
        }

        // Create new handshake state (outside lock)
        var hs = HandshakeState.init(.{
            .pattern = .IK,
            .initiator = true,
            .local_static = self.local_key,
            .remote_static = self.remote_pk,
        }) catch return ConnError.HandshakeFailed;

        // Generate handshake init message
        var msg_buf: [message.max_packet_size]u8 = undefined;
        const msg_len = hs.writeMessage(&.{}, &msg_buf) catch return ConnError.HandshakeFailed;
        _ = msg_len;

        const ephemeral = hs.local_ephemeral orelse return ConnError.HandshakeFailed;
        // static_encrypted is 48 bytes: 32 bytes encrypted static public key + 16 bytes tag
        const wire_msg = message.buildHandshakeInit(new_idx, &ephemeral.public, msg_buf[key_size .. key_size + 48]);

        // Send message
        self.transport.sendTo(&wire_msg, remote_addr) catch return ConnError.TransportError;

        // Update state with lock
        const now = std.time.nanoTimestamp();
        self.mutex.lock();
        defer self.mutex.unlock();

        // Double-check no one else started a handshake
        if (self.hs_state != null) {
            return;
        }

        self.hs_state = hs;
        self.local_idx = new_idx;
        self.handshake_started = now;
        self.handshake_attempt_start = now;
        self.last_handshake_sent = now;
        self.is_initiator = true;
        self.rekey_triggered = true;
    }

    /// Retransmits the handshake initiation with a new ephemeral key.
    /// According to WireGuard, each retransmit generates new ephemeral keys.
    /// Note: Must be called WITHOUT holding the mutex.
    fn retransmitHandshake(self: *Conn) ConnError!void {
        // Get necessary data with lock
        var remote_addr: Addr = undefined;
        var local_idx: u32 = undefined;
        {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Check if we have a pending handshake
            if (self.hs_state == null) {
                return;
            }

            remote_addr = self.remote_addr orelse return ConnError.MissingRemoteAddr;
            local_idx = self.local_idx;
        }

        // Create new handshake state with new ephemeral key (outside lock)
        var hs = HandshakeState.init(.{
            .pattern = .IK,
            .initiator = true,
            .local_static = self.local_key,
            .remote_static = self.remote_pk,
        }) catch return ConnError.HandshakeFailed;

        // Generate handshake init message
        var msg_buf: [message.max_packet_size]u8 = undefined;
        const msg_len = hs.writeMessage(&.{}, &msg_buf) catch return ConnError.HandshakeFailed;
        _ = msg_len;

        const ephemeral = hs.local_ephemeral orelse return ConnError.HandshakeFailed;
        // static_encrypted is 48 bytes: 32 bytes encrypted static public key + 16 bytes tag
        const wire_msg = message.buildHandshakeInit(local_idx, &ephemeral.public, msg_buf[key_size .. key_size + 48]);

        // Send message
        self.transport.sendTo(&wire_msg, remote_addr) catch return ConnError.TransportError;

        // Update state with lock
        const now = std.time.nanoTimestamp();
        self.mutex.lock();
        defer self.mutex.unlock();

        self.hs_state = hs;
        self.last_handshake_sent = now;
    }

    /// Performs periodic maintenance on the connection.
    /// This method should be called periodically by the connection manager.
    ///
    /// Tick directly executes time-based actions:
    /// - Sends keepalive if we haven't sent anything recently but have received data
    /// - Triggers rekey if session is too old (initiator only)
    ///
    /// Returns error if:
    /// - ConnTimeout: connection timed out (no data received for RejectAfterTime)
    /// - HandshakeTimeout: handshake attempt exceeded RekeyAttemptTime (90s)
    /// - SessionExpired: session expired (too many messages)
    pub fn tick(self: *Conn) ConnError!void {
        const now: i128 = std.time.nanoTimestamp();

        // Read state under lock
        var state: ConnState = undefined;
        var last_sent_time: ?i128 = null;
        var last_recv_time: ?i128 = null;
        var session_created_time: ?i128 = null;
        var handshake_attempt_start_time: ?i128 = null;
        var last_handshake_sent_time: ?i128 = null;
        var is_initiator: bool = false;
        var rekey_triggered: bool = false;
        var has_hs_state: bool = false;
        var send_nonce: u64 = 0;
        var recv_nonce: u64 = 0;

        {
            self.mutex.lock();
            defer self.mutex.unlock();

            state = self.state;
            last_sent_time = self.last_sent;
            last_recv_time = self.last_received;
            session_created_time = self.session_created;
            handshake_attempt_start_time = self.handshake_attempt_start;
            last_handshake_sent_time = self.last_handshake_sent;
            is_initiator = self.is_initiator;
            rekey_triggered = self.rekey_triggered;
            has_hs_state = self.hs_state != null;

            if (self.current) |*session| {
                send_nonce = session.send_nonce.load(.acquire);
                recv_nonce = session.recvMaxNonce();
            }
        }

        switch (state) {
            .new => {
                // Nothing to do for new connections
                return;
            },
            .handshaking => {
                // Check if handshake attempt has exceeded RekeyAttemptTime (90s)
                if (handshake_attempt_start_time) |start| {
                    const elapsed: u64 = @intCast(now - start);
                    if (elapsed > consts.rekey_attempt_time_ns) {
                        return ConnError.HandshakeTimeout;
                    }
                }

                // Check if we need to retransmit handshake (every RekeyTimeout = 5s)
                if (has_hs_state) {
                    if (last_handshake_sent_time) |last_sent| {
                        const elapsed: u64 = @intCast(now - last_sent);
                        if (elapsed > consts.rekey_timeout_ns) {
                            try self.retransmitHandshake();
                        }
                    }
                }
                return;
            },
            .established => {
                // Check if connection has timed out (no messages received)
                if (last_recv_time) |last_recv| {
                    const elapsed: u64 = @intCast(now - last_recv);
                    if (elapsed > consts.reject_after_time_ns) {
                        return ConnError.ConnTimeout;
                    }
                }

                // Check message-based rejection (nonce exhaustion)
                if (send_nonce > consts.reject_after_messages or recv_nonce > consts.reject_after_messages) {
                    return ConnError.SessionExpired;
                }

                // Check if we're waiting for rekey response (have pending handshake)
                if (has_hs_state) {
                    // Check if handshake attempt has exceeded RekeyAttemptTime (90s)
                    if (handshake_attempt_start_time) |start| {
                        const elapsed: u64 = @intCast(now - start);
                        if (elapsed > consts.rekey_attempt_time_ns) {
                            return ConnError.HandshakeTimeout;
                        }
                    }

                    // Check if we need to retransmit handshake (every RekeyTimeout = 5s)
                    if (last_handshake_sent_time) |last_sent| {
                        const elapsed: u64 = @intCast(now - last_sent);
                        if (elapsed > consts.rekey_timeout_ns) {
                            try self.retransmitHandshake();
                        }
                    }
                    return;
                }

                // Disconnection detection (WireGuard Section 5):
                // If no packets received for KeepaliveTimeout + RekeyTimeout (15s),
                // initiate a new handshake to re-establish connection
                const disconnection_threshold_ns = consts.keepalive_timeout_ns + consts.rekey_timeout_ns;
                if (is_initiator) {
                    if (last_recv_time) |last_recv| {
                        const elapsed: u64 = @intCast(now - last_recv);
                        if (elapsed > disconnection_threshold_ns) {
                            try self.initiateRekey();
                            return;
                        }
                    }
                }

                // Check if rekey is needed (session too old or too many messages, initiator only)
                if (is_initiator and !rekey_triggered) {
                    var needs_rekey = false;

                    // Time-based rekey trigger
                    if (session_created_time) |session_time| {
                        const elapsed: u64 = @intCast(now - session_time);
                        if (elapsed > consts.rekey_after_time_ns) {
                            needs_rekey = true;
                        }
                    }

                    // Message-based rekey trigger
                    if (send_nonce > consts.rekey_after_messages) {
                        needs_rekey = true;
                    }

                    if (needs_rekey) {
                        try self.initiateRekey();
                        return;
                    }
                }

                // Passive keepalive: send empty message if we haven't sent recently
                // but have received data recently (peer is active)
                if (last_sent_time) |last_sent| {
                    if (last_recv_time) |last_recv| {
                        const sent_delta: u64 = @intCast(now - last_sent);
                        const recv_delta: u64 = @intCast(now - last_recv);
                        if (sent_delta > consts.keepalive_timeout_ns and recv_delta < consts.keepalive_timeout_ns) {
                            _ = self.sendKeepalive() catch {};
                        }
                    }
                }

                return;
            },
            .closed => {
                return ConnError.InvalidState;
            },
        }
    }

    /// Closes the connection.
    pub fn close(self: *Conn) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state == .closed) {
            return;
        }

        self.state = .closed;
        if (self.current) |*session| {
            session.expire();
        }
    }

    /// Returns the current connection state.
    pub fn getState(self: *Conn) ConnState {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.state;
    }

    /// Sets the connection state (for use by dial).
    pub fn setState(self: *Conn, new_state: ConnState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.state = new_state;
    }

    /// Sets the current session (for use by dial).
    pub fn setSession(self: *Conn, session: Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.current = session;
        self.session_created = std.time.nanoTimestamp();
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

    /// Sets up the inbound queue for listener-managed connections.
    /// This should only be called by Listener before the connection is returned.
    pub fn setupInbound(self: *Conn) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.inbound_queue = .{};
    }

    /// Delivers a parsed transport message to the connection's inbound queue.
    /// Returns false if the queue is full or the connection is closed.
    pub fn deliverPacket(self: *Conn, pkt: InboundPacket) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state == .closed) {
            return false;
        }

        if (self.inbound_queue) |*queue| {
            if (queue.items.len >= max_inbound_queue) {
                return false; // Queue full
            }
            queue.append(self.allocator, pkt) catch return false;
            self.inbound_signal.signal();
            return true;
        }
        return false;
    }

    /// Returns whether this connection has an inbound queue (listener-managed).
    pub fn hasInbound(self: *Conn) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.inbound_queue != null;
    }

    /// Deinitializes the connection and frees resources.
    pub fn deinit(self: *Conn) void {
        self.close();
        if (self.inbound_queue) |*queue| {
            for (queue.items) |*pkt| {
                pkt.deinit();
            }
            queue.deinit(self.allocator);
        }
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
    const dial_mod = @import("dial.zig");

    const allocator = std.testing.allocator;

    const initiator_key = KeyPair.generate();
    const responder_key = KeyPair.generate();

    const initiator_transport = try transport_mod.MockTransport.init(allocator, "initiator");
    defer initiator_transport.deinit();
    const responder_transport = try transport_mod.MockTransport.init(allocator, "responder");
    defer responder_transport.deinit();

    transport_mod.MockTransport.connect(initiator_transport, responder_transport);

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

    // Initiator dials connection
    const initiator = dial_mod.dial(.{
        .allocator = allocator,
        .local_key = initiator_key,
        .remote_pk = responder_key.public,
        .transport = Transport{ .mock = initiator_transport },
        .remote_addr = Addr{ .mock = transport_mod.MockAddr.init("responder") },
    }) catch |err| {
        responder_thread.join();
        return err;
    };
    defer allocator.destroy(initiator);

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

// ============================================
// Tick tests
// ============================================

test "tick new conn" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .transport = Transport{ .mock = transport },
    });

    // Tick on new connection should succeed
    try conn.tick();
}

test "tick closed conn" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .transport = Transport{ .mock = transport },
    });

    conn.close();

    // Tick on closed connection should fail
    const result = conn.tick();
    try std.testing.expectError(ConnError.InvalidState, result);
}

test "tick conn timeout" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const server_key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    const session = Session.init(.{
        .local_index = 1,
        .remote_index = 2,
        .send_key = Key{ .data = [_]u8{1} ** 32 },
        .recv_key = Key{ .data = [_]u8{2} ** 32 },
        .remote_pk = server_key.public,
    });

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .remote_pk = server_key.public,
        .transport = Transport{ .mock = transport },
    });

    // Manually set established state with old lastReceived
    const now = std.time.nanoTimestamp();
    conn.state = .established;
    conn.current = session;
    conn.last_sent = now;
    conn.last_received = now - @as(i128, consts.reject_after_time_ns) - std.time.ns_per_s;
    conn.session_created = now;

    const result = conn.tick();
    try std.testing.expectError(ConnError.ConnTimeout, result);
}

test "tick handshake timeout" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .transport = Transport{ .mock = transport },
    });

    // Manually set handshaking state with expired attempt
    const now = std.time.nanoTimestamp();
    conn.state = .handshaking;
    conn.handshake_attempt_start = now - @as(i128, consts.rekey_attempt_time_ns) - std.time.ns_per_s;

    const result = conn.tick();
    try std.testing.expectError(ConnError.HandshakeTimeout, result);
}

test "tick no action when recent" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const server_key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    const session = Session.init(.{
        .local_index = 1,
        .remote_index = 2,
        .send_key = Key{ .data = [_]u8{1} ** 32 },
        .recv_key = Key{ .data = [_]u8{2} ** 32 },
        .remote_pk = server_key.public,
    });

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .remote_pk = server_key.public,
        .transport = Transport{ .mock = transport },
    });

    const now = std.time.nanoTimestamp();
    conn.state = .established;
    conn.current = session;
    conn.last_sent = now;
    conn.last_received = now;
    conn.session_created = now;

    // Tick should succeed without any action
    try conn.tick();
}

test "tick responder no rekey" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const server_key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    const session = Session.init(.{
        .local_index = 1,
        .remote_index = 2,
        .send_key = Key{ .data = [_]u8{1} ** 32 },
        .recv_key = Key{ .data = [_]u8{2} ** 32 },
        .remote_pk = server_key.public,
    });

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .remote_pk = server_key.public,
        .transport = Transport{ .mock = transport },
    });

    const now = std.time.nanoTimestamp();
    conn.state = .established;
    conn.current = session;
    conn.is_initiator = false; // Responder
    conn.last_sent = now;
    conn.last_received = now;
    // Old session (past RekeyAfterTime)
    conn.session_created = now - @as(i128, consts.rekey_after_time_ns) - std.time.ns_per_s;

    try conn.tick();

    // Responder should NOT trigger rekey
    try std.testing.expect(conn.hs_state == null);
}

test "tick rekey not duplicate" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const server_key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    const session = Session.init(.{
        .local_index = 1,
        .remote_index = 2,
        .send_key = Key{ .data = [_]u8{1} ** 32 },
        .recv_key = Key{ .data = [_]u8{2} ** 32 },
        .remote_pk = server_key.public,
    });

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .remote_pk = server_key.public,
        .transport = Transport{ .mock = transport },
    });

    const now = std.time.nanoTimestamp();
    conn.state = .established;
    conn.current = session;
    conn.is_initiator = true;
    conn.rekey_triggered = true; // Already triggered
    conn.last_sent = now;
    conn.last_received = now;
    conn.session_created = now - @as(i128, consts.rekey_after_time_ns) - std.time.ns_per_s;

    try conn.tick();

    // Should NOT trigger rekey again when already triggered
    try std.testing.expect(conn.hs_state == null);
}

test "send keepalive not established" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .transport = Transport{ .mock = transport },
    });

    // Send keepalive on non-established connection should fail
    const result = conn.sendKeepalive();
    try std.testing.expectError(ConnError.NotEstablished, result);
}

// ============================================
// Disconnection detection tests
// ============================================

test "tick disconnection detection initiator" {
    // Test that initiator detects disconnection when no packets received
    // for KeepaliveTimeout + RekeyTimeout (15s) and initiates new handshake
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const server_key = KeyPair.generate();

    const client_transport = try transport_mod.MockTransport.init(allocator, "client");
    defer client_transport.deinit();
    const server_transport = try transport_mod.MockTransport.init(allocator, "server");
    defer server_transport.deinit();
    transport_mod.MockTransport.connect(client_transport, server_transport);

    const session = Session.init(.{
        .local_index = 1,
        .remote_index = 2,
        .send_key = Key{ .data = [_]u8{1} ** 32 },
        .recv_key = Key{ .data = [_]u8{2} ** 32 },
        .remote_pk = server_key.public,
    });

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .remote_pk = server_key.public,
        .transport = Transport{ .mock = client_transport },
        .remote_addr = Addr{ .mock = transport_mod.MockAddr.init("server") },
    });

    // Set as initiator with no recent received data (past disconnection threshold)
    const disconnection_threshold_ns = consts.keepalive_timeout_ns + consts.rekey_timeout_ns;
    const now = std.time.nanoTimestamp();
    conn.state = .established;
    conn.current = session;
    conn.is_initiator = true;
    conn.last_sent = now;
    conn.last_received = now - @as(i128, disconnection_threshold_ns) - std.time.ns_per_s;
    conn.session_created = now;

    // Tick should detect disconnection and initiate rekey
    try conn.tick();

    // Verify that a new handshake was initiated
    try std.testing.expect(conn.hs_state != null);
    try std.testing.expect(conn.rekey_triggered == true);
}

test "tick disconnection detection responder no action" {
    // Test that responder does NOT initiate handshake on disconnection
    // (only initiator is responsible for re-establishing connection)
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const server_key = KeyPair.generate();
    const transport = try transport_mod.MockTransport.init(allocator, "test");
    defer transport.deinit();

    const session = Session.init(.{
        .local_index = 1,
        .remote_index = 2,
        .send_key = Key{ .data = [_]u8{1} ** 32 },
        .recv_key = Key{ .data = [_]u8{2} ** 32 },
        .remote_pk = server_key.public,
    });

    var conn = Conn.init(allocator, .{
        .local_key = key,
        .remote_pk = server_key.public,
        .transport = Transport{ .mock = transport },
    });

    // Set as responder with no recent received data
    const disconnection_threshold_ns = consts.keepalive_timeout_ns + consts.rekey_timeout_ns;
    const now = std.time.nanoTimestamp();
    conn.state = .established;
    conn.current = session;
    conn.is_initiator = false; // Responder
    conn.last_sent = now;
    conn.last_received = now - @as(i128, disconnection_threshold_ns) - std.time.ns_per_s;
    conn.session_created = now;

    try conn.tick();

    // Responder should NOT initiate handshake
    try std.testing.expect(conn.hs_state == null);
}
