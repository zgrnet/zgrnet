//! Dial function for initiating connections.
//!
//! This module provides a `dial` function that creates a connection
//! and performs the handshake with the remote peer using WireGuard-style
//! retry mechanism.

const std = @import("std");
const noise = @import("../noise/mod.zig");
const conn_mod = @import("conn.zig");
const consts = @import("consts.zig");

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const key_size = noise.key_size;
const Transport = noise.Transport;
const TransportError = noise.transport.TransportError;
const Addr = noise.Addr;
const HandshakeState = noise.HandshakeState;
const Pattern = noise.Pattern;
const Session = noise.Session;
const SessionConfig = noise.SessionConfig;
const message = noise.message;

const Conn = conn_mod.Conn;
const ConnConfig = conn_mod.ConnConfig;
const ConnState = conn_mod.ConnState;
const ConnError = conn_mod.ConnError;

/// Dial errors.
pub const DialError = error{
    /// Timeout waiting for handshake.
    HandshakeTimeout,
    /// Missing remote public key.
    MissingRemotePK,
    /// Handshake error.
    HandshakeError,
    /// Transport error.
    TransportError,
    /// Message error.
    MessageError,
    /// Invalid receiver index.
    InvalidReceiverIndex,
    /// Out of memory.
    OutOfMemory,
};

/// Options for dialing a remote peer.
pub const DialOptions = struct {
    /// Memory allocator.
    allocator: std.mem.Allocator,
    /// Local static key pair.
    local_key: KeyPair,
    /// Remote peer's public key.
    remote_pk: Key,
    /// Underlying datagram transport.
    transport: Transport,
    /// Remote peer's address.
    remote_addr: Addr,
    /// Deadline in nanoseconds (absolute timestamp).
    /// If null, defaults to now + REKEY_ATTEMPT_TIME (90s).
    deadline_ns: ?i128 = null,
};

/// Dials a remote peer and returns an established connection.
///
/// This implements WireGuard's retry mechanism:
/// - Sends handshake initiation
/// - Waits up to REKEY_TIMEOUT (5s) for response
/// - Retransmits with new ephemeral keys on timeout
/// - Gives up after deadline is reached
pub fn dial(opts: DialOptions) DialError!*Conn {
    // Validate inputs
    if (opts.remote_pk.isZero()) {
        return DialError.MissingRemotePK;
    }

    const now = std.time.nanoTimestamp();
    const deadline = opts.deadline_ns orelse (now + @as(i128, consts.rekey_attempt_time_ns));

    // Create the connection
    const conn = opts.allocator.create(Conn) catch return DialError.OutOfMemory;
    conn.* = Conn.init(opts.allocator, .{
        .local_key = opts.local_key,
        .remote_pk = opts.remote_pk,
        .transport = opts.transport,
        .remote_addr = opts.remote_addr,
    });

    // Get local index for handshake
    const local_idx = conn.getLocalIndex();

    // Set state to handshaking
    conn.setState(.handshaking);

    // Retry loop with fresh ephemeral keys each attempt
    while (true) {
        // Check deadline
        const current_time = std.time.nanoTimestamp();
        if (current_time >= deadline) {
            conn.setState(.new);
            opts.allocator.destroy(conn);
            return DialError.HandshakeTimeout;
        }

        // Create fresh handshake state with new ephemeral keys
        var hs = HandshakeState.init(.{
            .pattern = .IK,
            .initiator = true,
            .local_static = opts.local_key,
            .remote_static = opts.remote_pk,
        }) catch {
            conn.setState(.new);
            opts.allocator.destroy(conn);
            return DialError.HandshakeError;
        };

        // Generate handshake initiation message
        var msg1_buf: [key_size + key_size + 16]u8 = undefined;
        const msg1_len = hs.writeMessage(&[_]u8{}, &msg1_buf) catch {
            conn.setState(.new);
            opts.allocator.destroy(conn);
            return DialError.HandshakeError;
        };

        // Extract ephemeral public key
        const ephemeral = if (hs.local_ephemeral) |le| le.public else {
            conn.setState(.new);
            opts.allocator.destroy(conn);
            return DialError.HandshakeError;
        };

        // Build wire message
        const wire_msg = message.buildHandshakeInit(
            local_idx,
            &ephemeral,
            msg1_buf[key_size..msg1_len],
        );

        // Send handshake initiation
        opts.transport.sendTo(&wire_msg, opts.remote_addr) catch {
            conn.setState(.new);
            opts.allocator.destroy(conn);
            return DialError.TransportError;
        };

        // Calculate read deadline: min(now + REKEY_TIMEOUT, total deadline)
        const recv_time = std.time.nanoTimestamp();
        const rekey_deadline = recv_time + @as(i128, consts.rekey_timeout_ns);
        const read_deadline = @min(rekey_deadline, deadline);

        // Set read deadline on transport
        opts.transport.setReadDeadline(read_deadline) catch {
            conn.setState(.new);
            opts.allocator.destroy(conn);
            return DialError.TransportError;
        };

        // Wait for handshake response
        var buf: [message.max_packet_size]u8 = undefined;
        const recv_result = opts.transport.recvFrom(&buf);

        // Clear deadline (ignore errors - best effort)
        opts.transport.setReadDeadline(null) catch {};

        // Handle receive result
        const result = recv_result catch |err| {
            // Check if it's a timeout - retry with new ephemeral keys
            if (err == TransportError.WouldBlock) {
                continue;
            }
            conn.setState(.new);
            opts.allocator.destroy(conn);
            return DialError.TransportError;
        };
        
        // Update remote address for NAT traversal
        conn.setRemoteAddr(result.from_addr);

        // Parse response
        const resp = message.parseHandshakeResp(buf[0..result.bytes_read]) catch {
            conn.setState(.new);
            opts.allocator.destroy(conn);
            return DialError.MessageError;
        };

        // Verify receiver index matches our sender index
        if (resp.receiver_index != local_idx) {
            conn.setState(.new);
            opts.allocator.destroy(conn);
            return DialError.InvalidReceiverIndex;
        }

        // Reconstruct the noise message and process
        var noise_msg: [key_size + 16]u8 = undefined;
        @memcpy(noise_msg[0..key_size], resp.ephemeral.asBytes());
        @memcpy(noise_msg[key_size..][0..16], &resp.empty_encrypted);

        var payload_buf: [1]u8 = undefined;
        _ = hs.readMessage(&noise_msg, &payload_buf) catch {
            conn.setState(.new);
            opts.allocator.destroy(conn);
            return DialError.HandshakeError;
        };

        // Complete handshake - create session
        if (!hs.isFinished()) {
            conn.setState(.new);
            opts.allocator.destroy(conn);
            return DialError.HandshakeError;
        }

        // Get transport keys
        const ciphers = hs.split() catch {
            conn.setState(.new);
            opts.allocator.destroy(conn);
            return DialError.HandshakeError;
        };

        // Create session
        const session = Session.init(.{
            .local_index = local_idx,
            .remote_index = resp.sender_index,
            .send_key = ciphers[0].key,
            .recv_key = ciphers[1].key,
            .remote_pk = opts.remote_pk,
        });

        // Set session and state on connection
        conn.setSession(session);
        conn.setState(.established);

        return conn;
    }
}

test "dial options default deadline" {
    const opts = DialOptions{
        .allocator = std.testing.allocator,
        .local_key = KeyPair.generate(),
        .remote_pk = Key.zero,
        .transport = .{ .mock = undefined },
        .remote_addr = .{ .mock = .{ .name = "test" } },
    };
    try std.testing.expectEqual(@as(?i128, null), opts.deadline_ns);
}

test "dial missing remote pk" {
    const allocator = std.testing.allocator;
    const transport = try noise.transport.MockTransport.init(allocator, "test");
    defer transport.deinit();

    const result = dial(.{
        .allocator = allocator,
        .local_key = KeyPair.generate(),
        .remote_pk = Key.zero,
        .transport = .{ .mock = transport },
        .remote_addr = .{ .mock = .{ .name = "peer" } },
    });

    try std.testing.expectError(DialError.MissingRemotePK, result);
}
