package net

import "errors"

// Connection errors.
var (
	// ErrMissingLocalKey indicates that the local key pair was not provided.
	ErrMissingLocalKey = errors.New("net: missing local key pair")

	// ErrMissingTransport indicates that the transport was not provided.
	ErrMissingTransport = errors.New("net: missing transport")

	// ErrMissingRemotePK indicates that the remote public key was not provided.
	ErrMissingRemotePK = errors.New("net: missing remote public key")

	// ErrMissingRemoteAddr indicates that the remote address was not provided.
	ErrMissingRemoteAddr = errors.New("net: missing remote address")

	// ErrInvalidConnState indicates an invalid connection state for the operation.
	ErrInvalidConnState = errors.New("net: invalid connection state")

	// ErrNotEstablished indicates the connection is not yet established.
	ErrNotEstablished = errors.New("net: connection not established")

	// ErrInvalidReceiverIndex indicates a mismatched receiver index.
	ErrInvalidReceiverIndex = errors.New("net: invalid receiver index")

	// ErrInvalidRemotePK indicates the remote public key doesn't match.
	ErrInvalidRemotePK = errors.New("net: invalid remote public key")

	// ErrHandshakeIncomplete indicates the handshake has not completed.
	ErrHandshakeIncomplete = errors.New("net: handshake not complete")

	// ErrHandshakeTimeout indicates the handshake timed out.
	// This is returned when handshake attempts exceed RekeyAttemptTime (90s).
	ErrHandshakeTimeout = errors.New("net: handshake timeout")

	// ErrConnClosed indicates the connection has been closed.
	ErrConnClosed = errors.New("net: connection closed")

	// ErrConnTimeout indicates the connection has timed out due to inactivity.
	// This is returned when no data is received for RejectAfterTime (180s).
	ErrConnTimeout = errors.New("net: connection timeout")

	// ErrListenerClosed indicates the listener has been closed.
	ErrListenerClosed = errors.New("net: listener closed")

	// ErrSessionExpired indicates the session has expired and cannot be used.
	ErrSessionExpired = errors.New("net: session expired")
)
