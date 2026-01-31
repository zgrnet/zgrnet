//! Time constants for connection management.
//!
//! These values are based on WireGuard's timing parameters (Section 6 of whitepaper).

use std::time::Duration;

/// Duration after which a rekey should be initiated.
/// After this time, the initiator should start a new handshake.
/// WireGuard: 120 seconds
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);

/// Duration after which a session should be rejected.
/// Messages using sessions older than this should not be accepted.
/// WireGuard: 180 seconds
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// Maximum duration to keep retrying handshake.
/// After this time without successful handshake, give up.
/// WireGuard: 90 seconds
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);

/// Interval between handshake retransmissions.
/// Also used as the timeout for waiting handshake response.
/// WireGuard: 5 seconds
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);

/// Duration of inactivity after which a keepalive should be sent
/// to maintain the connection and NAT mappings.
/// WireGuard: 10 seconds
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Session age at which receiving data triggers rekey.
/// Calculated as: REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT = 165s
/// This gives enough time to complete rekey before session rejection.
pub const REKEY_ON_RECV_THRESHOLD: Duration = Duration::from_secs(165);

/// When all sessions should be cleared if no new session.
/// WireGuard: REJECT_AFTER_TIME * 3 = 540 seconds
pub const SESSION_CLEANUP_TIME: Duration = Duration::from_secs(540);

/// Number of messages after which a rekey should be triggered,
/// regardless of time elapsed.
/// WireGuard: 2^60
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

/// Maximum number of messages that can be sent or received on a single
/// session before it must be rekeyed.
/// WireGuard: 2^64 - 2^13 - 1. This equals (2^64 - 1) - 2^13.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_constants_values() {
        assert_eq!(REKEY_AFTER_TIME.as_secs(), 120);
        assert_eq!(REJECT_AFTER_TIME.as_secs(), 180);
        assert_eq!(REKEY_ATTEMPT_TIME.as_secs(), 90);
        assert_eq!(REKEY_TIMEOUT.as_secs(), 5);
        assert_eq!(KEEPALIVE_TIMEOUT.as_secs(), 10);
        assert_eq!(REKEY_ON_RECV_THRESHOLD.as_secs(), 165);
        assert_eq!(SESSION_CLEANUP_TIME.as_secs(), 540);
    }

    #[test]
    fn test_message_constants_values() {
        assert_eq!(REKEY_AFTER_MESSAGES, 1 << 60);
        // Verify REJECT_AFTER_MESSAGES calculation
        assert_eq!(REJECT_AFTER_MESSAGES, u64::MAX - (1 << 13));
    }

    #[test]
    fn test_rekey_on_recv_threshold_calculation() {
        // REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT = 165s
        let expected = REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT;
        assert_eq!(REKEY_ON_RECV_THRESHOLD, expected);
    }
}
