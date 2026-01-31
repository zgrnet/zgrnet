package conn

import "time"

// Time constants for connection management.
// These values are based on WireGuard's timing parameters.
const (
	// RekeyAfterTime is the duration after which a rekey should be initiated.
	// After this time, the initiator should start a new handshake.
	RekeyAfterTime = 120 * time.Second

	// RejectAfterTime is the duration after which a session should be rejected.
	// Messages using sessions older than this should not be accepted.
	RejectAfterTime = 180 * time.Second

	// KeepaliveTimeout is the duration of inactivity after which a keepalive
	// should be sent to maintain the connection and NAT mappings.
	KeepaliveTimeout = 25 * time.Second

	// HandshakeTimeout is the maximum duration to wait for a handshake response.
	HandshakeTimeout = 5 * time.Second

	// RekeyAfterMessages is the number of messages after which a rekey should
	// be triggered, regardless of time elapsed.
	RekeyAfterMessages = 1 << 60

	// RejectAfterMessages is the maximum number of messages that can be sent
	// or received on a single session before it must be rekeyed.
	RejectAfterMessages = ^uint64(0) - (1 << 4)
)
