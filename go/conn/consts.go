package conn

import "time"

// Time constants for connection management.
// These values are based on WireGuard's timing parameters (Section 6 of whitepaper).
const (
	// RekeyAfterTime is the duration after which a rekey should be initiated.
	// After this time, the initiator should start a new handshake.
	// WireGuard: 120 seconds
	RekeyAfterTime = 120 * time.Second

	// RejectAfterTime is the duration after which a session should be rejected.
	// Messages using sessions older than this should not be accepted.
	// WireGuard: 180 seconds
	RejectAfterTime = 180 * time.Second

	// RekeyAttemptTime is the maximum duration to keep retrying handshake.
	// After this time without successful handshake, give up.
	// WireGuard: 90 seconds
	RekeyAttemptTime = 90 * time.Second

	// RekeyTimeout is the interval between handshake retransmissions.
	// Also used as the timeout for waiting handshake response.
	// WireGuard: 5 seconds
	RekeyTimeout = 5 * time.Second

	// KeepaliveTimeout is the duration of inactivity after which a keepalive
	// should be sent to maintain the connection and NAT mappings.
	// WireGuard: 10 seconds
	KeepaliveTimeout = 10 * time.Second

	// RekeyOnRecvThreshold is the session age at which receiving data triggers rekey.
	// Calculated as: RejectAfterTime - KeepaliveTimeout - RekeyTimeout = 165s
	// This gives enough time to complete rekey before session rejection.
	RekeyOnRecvThreshold = RejectAfterTime - KeepaliveTimeout - RekeyTimeout

	// SessionCleanupTime is when all sessions should be cleared if no new session.
	// WireGuard: RejectAfterTime * 3 = 540 seconds
	SessionCleanupTime = RejectAfterTime * 3

	// RekeyAfterMessages is the number of messages after which a rekey should
	// be triggered, regardless of time elapsed.
	// WireGuard: 2^60
	RekeyAfterMessages = 1 << 60

	// RejectAfterMessages is the maximum number of messages that can be sent
	// or received on a single session before it must be rekeyed.
	// WireGuard: 2^64 - 2^13 - 1 (but we use a simpler approximation)
	RejectAfterMessages = ^uint64(0) - (1 << 13)
)
