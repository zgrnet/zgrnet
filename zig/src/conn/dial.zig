//! Dial function for initiating connections.
//!
//! This module provides a `dial` function that creates a connection
//! and performs the handshake with the remote peer.

const std = @import("std");
const noise = @import("../noise/root.zig");
const conn_mod = @import("conn.zig");
const consts = @import("consts.zig");

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const Transport = noise.Transport;
const Addr = noise.Addr;

const Conn = conn_mod.Conn;
const ConnConfig = conn_mod.ConnConfig;
const ConnState = conn_mod.ConnState;
const ConnError = conn_mod.ConnError;

/// Dial errors.
pub const DialError = error{
    /// Timeout waiting for handshake.
    Timeout,
    /// Connection error.
    ConnError,
    /// Transport error.
    TransportError,
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
    /// Timeout in nanoseconds (default: REKEY_ATTEMPT_TIME).
    timeout_ns: ?u64 = null,
};

/// Dials a remote peer and returns an established connection.
///
/// This is a blocking call that:
/// 1. Creates a new connection
/// 2. Initiates the handshake
/// 3. Waits for the handshake to complete
pub fn dial(opts: DialOptions) (DialError || ConnError)!*Conn {
    const timeout_ns = opts.timeout_ns orelse consts.rekey_attempt_time_ns;
    const start = std.time.nanoTimestamp();

    // Create the connection
    const conn = opts.allocator.create(Conn) catch return DialError.ConnError;
    conn.* = Conn.init(opts.allocator, .{
        .local_key = opts.local_key,
        .remote_pk = opts.remote_pk,
        .transport = opts.transport,
        .remote_addr = opts.remote_addr,
    });

    // Initiate the handshake
    conn.open() catch |err| {
        opts.allocator.destroy(conn);
        return err;
    };

    // Wait for the handshake to complete
    // Note: In a real implementation, we'd poll or have a callback
    // For now, this is synchronous (open() completes the handshake)
    while (conn.getState() != .established) {
        const now = std.time.nanoTimestamp();
        const elapsed: u64 = @intCast(now - start);
        if (elapsed > timeout_ns) {
            opts.allocator.destroy(conn);
            return DialError.Timeout;
        }

        // In a real implementation, we'd wait for the response here
        // For now, open() is synchronous and completes the handshake
        break;
    }

    return conn;
}

test "dial options default timeout" {
    const opts = DialOptions{
        .allocator = std.testing.allocator,
        .local_key = KeyPair.generate(),
        .remote_pk = Key.zero,
        .transport = .{ .mock = undefined },
        .remote_addr = .{ .mock = .{ .name = "test" } },
    };
    try std.testing.expectEqual(@as(?u64, null), opts.timeout_ns);
}
