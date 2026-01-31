package conn

import "errors"

// Connection errors.
var (
	// ErrMissingLocalKey indicates that the local key pair was not provided.
	ErrMissingLocalKey = errors.New("conn: missing local key pair")

	// ErrMissingTransport indicates that the transport was not provided.
	ErrMissingTransport = errors.New("conn: missing transport")

	// ErrMissingRemotePK indicates that the remote public key was not provided.
	ErrMissingRemotePK = errors.New("conn: missing remote public key")

	// ErrMissingRemoteAddr indicates that the remote address was not provided.
	ErrMissingRemoteAddr = errors.New("conn: missing remote address")

	// ErrInvalidConnState indicates an invalid connection state for the operation.
	ErrInvalidConnState = errors.New("conn: invalid connection state")

	// ErrNotEstablished indicates the connection is not yet established.
	ErrNotEstablished = errors.New("conn: connection not established")

	// ErrInvalidReceiverIndex indicates a mismatched receiver index.
	ErrInvalidReceiverIndex = errors.New("conn: invalid receiver index")

	// ErrInvalidRemotePK indicates the remote public key doesn't match.
	ErrInvalidRemotePK = errors.New("conn: invalid remote public key")

	// ErrHandshakeIncomplete indicates the handshake has not completed.
	ErrHandshakeIncomplete = errors.New("conn: handshake not complete")

	// ErrHandshakeTimeout indicates the handshake timed out.
	// This is returned when handshake attempts exceed RekeyAttemptTime (90s).
	ErrHandshakeTimeout = errors.New("conn: handshake timeout")

	// ErrConnClosed indicates the connection has been closed.
	ErrConnClosed = errors.New("conn: connection closed")

	// ErrConnTimeout indicates the connection has timed out due to inactivity.
	// This is returned when no data is received for RejectAfterTime (180s).
	ErrConnTimeout = errors.New("conn: connection timeout")

	// ErrListenerClosed indicates the listener has been closed.
	ErrListenerClosed = errors.New("conn: listener closed")

	// ErrSessionExpired indicates the session has expired and cannot be used.
	ErrSessionExpired = errors.New("conn: session expired")
)
