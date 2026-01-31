//! Time constants for connection management.
//!
//! These values are based on WireGuard's timing parameters (Section 6 of whitepaper).

const std = @import("std");

/// Duration after which a rekey should be initiated.
/// After this time, the initiator should start a new handshake.
/// WireGuard: 120 seconds
pub const rekey_after_time_ns: u64 = 120 * std.time.ns_per_s;

/// Duration after which a session should be rejected.
/// Messages using sessions older than this should not be accepted.
/// WireGuard: 180 seconds
pub const reject_after_time_ns: u64 = 180 * std.time.ns_per_s;

/// Maximum duration to keep retrying handshake.
/// After this time without successful handshake, give up.
/// WireGuard: 90 seconds
pub const rekey_attempt_time_ns: u64 = 90 * std.time.ns_per_s;

/// Interval between handshake retransmissions.
/// Also used as the timeout for waiting handshake response.
/// WireGuard: 5 seconds
pub const rekey_timeout_ns: u64 = 5 * std.time.ns_per_s;

/// Duration of inactivity after which a keepalive should be sent
/// to maintain the connection and NAT mappings.
/// WireGuard: 10 seconds
pub const keepalive_timeout_ns: u64 = 10 * std.time.ns_per_s;

/// Session age at which receiving data triggers rekey.
/// Calculated as: reject_after_time - keepalive_timeout - rekey_timeout = 165s
/// This gives enough time to complete rekey before session rejection.
pub const rekey_on_recv_threshold_ns: u64 = 165 * std.time.ns_per_s;

/// When all sessions should be cleared if no new session.
/// WireGuard: reject_after_time * 3 = 540 seconds
pub const session_cleanup_time_ns: u64 = 540 * std.time.ns_per_s;

/// Number of messages after which a rekey should be triggered,
/// regardless of time elapsed.
/// WireGuard: 2^60
pub const rekey_after_messages: u64 = 1 << 60;

/// Maximum number of messages that can be sent or received on a single
/// session before it must be rekeyed.
/// WireGuard: 2^64 - 2^13 - 1. This equals (2^64 - 1) - 2^13.
pub const reject_after_messages: u64 = std.math.maxInt(u64) - (1 << 13);

// =============================================================================
// Tests
// =============================================================================

test "time constants values" {
    try std.testing.expectEqual(@as(u64, 120 * std.time.ns_per_s), rekey_after_time_ns);
    try std.testing.expectEqual(@as(u64, 180 * std.time.ns_per_s), reject_after_time_ns);
    try std.testing.expectEqual(@as(u64, 90 * std.time.ns_per_s), rekey_attempt_time_ns);
    try std.testing.expectEqual(@as(u64, 5 * std.time.ns_per_s), rekey_timeout_ns);
    try std.testing.expectEqual(@as(u64, 10 * std.time.ns_per_s), keepalive_timeout_ns);
    try std.testing.expectEqual(@as(u64, 165 * std.time.ns_per_s), rekey_on_recv_threshold_ns);
    try std.testing.expectEqual(@as(u64, 540 * std.time.ns_per_s), session_cleanup_time_ns);
}

test "message constants values" {
    try std.testing.expectEqual(@as(u64, 1 << 60), rekey_after_messages);
    // Verify reject_after_messages calculation
    try std.testing.expectEqual(std.math.maxInt(u64) - (1 << 13), reject_after_messages);
}

test "rekey_on_recv_threshold calculation" {
    // reject_after_time - keepalive_timeout - rekey_timeout = 165s
    const expected = reject_after_time_ns - keepalive_timeout_ns - rekey_timeout_ns;
    try std.testing.expectEqual(expected, rekey_on_recv_threshold_ns);
}
