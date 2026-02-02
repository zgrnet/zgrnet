package net

import (
	"context"
	"fmt"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// Dial establishes a connection to a remote peer with context support.
// The context can be used to cancel the dial or set a custom timeout.
//
// Parameters:
//   - ctx: context for cancellation and timeout control
//   - transport: the underlying datagram transport (e.g., UDP)
//   - addr: the remote peer's address
//   - remotePK: the remote peer's public key (required for IK pattern)
//   - localKey: the local key pair for authentication
//
// The dial implements WireGuard's retry mechanism:
//   - Sends handshake initiation
//   - Waits up to RekeyTimeout (5s) for response
//   - Retransmits with new ephemeral keys on timeout
//   - Gives up after context deadline or cancellation
//
// Returns an established connection ready for Send/Recv, or an error.
func Dial(ctx context.Context, transport noise.Transport, addr noise.Addr, remotePK noise.PublicKey, localKey *noise.KeyPair) (*Conn, error) {
	if localKey == nil {
		return nil, ErrMissingLocalKey
	}
	if transport == nil {
		return nil, ErrMissingTransport
	}
	if remotePK.IsZero() {
		return nil, ErrMissingRemotePK
	}
	if addr == nil {
		return nil, ErrMissingRemoteAddr
	}

	// Create a new connection
	c, err := newConn(localKey, transport, addr, remotePK)
	if err != nil {
		return nil, err
	}

	// Perform the handshake with retry
	if err := c.dialWithRetry(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

// dialWithRetry performs the initiator side of the Noise IK handshake with
// automatic retry on timeout. Follows WireGuard's handshake retry mechanism.
func (c *Conn) dialWithRetry(ctx context.Context) error {
	c.mu.Lock()
	if c.state != ConnStateNew {
		c.mu.Unlock()
		return ErrInvalidConnState
	}
	c.state = ConnStateHandshaking
	c.handshakeStarted = time.Now()
	c.handshakeAttemptStart = time.Now()
	localKey := c.localKey
	remotePK := c.remotePK
	localIdx := c.localIdx
	transport := c.transport
	remoteAddr := c.remoteAddr
	c.mu.Unlock()

	// Retry loop with exponential backoff would be more sophisticated,
	// but WireGuard uses fixed RekeyTimeout intervals
	for {
		select {
		case <-ctx.Done():
			return c.failHandshake(ctx.Err())
		default:
		}

		// Create fresh handshake state with new ephemeral keys
		hs, err := noise.NewHandshakeState(noise.Config{
			Pattern:      noise.PatternIK,
			Initiator:    true,
			LocalStatic:  localKey,
			RemoteStatic: &remotePK,
		})
		if err != nil {
			return c.failHandshake(err)
		}

		// Generate handshake initiation message
		msg1, err := hs.WriteMessage(nil)
		if err != nil {
			return c.failHandshake(err)
		}

		// Build and send wire message
		wireMsg := noise.BuildHandshakeInit(localIdx, hs.LocalEphemeral(), msg1[noise.KeySize:])
		if err := transport.SendTo(wireMsg, remoteAddr); err != nil {
			return c.failHandshake(err)
		}

		c.mu.Lock()
		c.hsState = hs
		c.lastHandshakeSent = time.Now()
		c.isInitiator = true
		c.mu.Unlock()

		// Wait for response with timeout
		resp, err := c.waitForHandshakeResponse(ctx, hs)
		if err == context.DeadlineExceeded || err == ErrHandshakeTimeout {
			// Timeout waiting for response, retry with new ephemeral keys
			continue
		}
		if err != nil {
			return c.failHandshake(err)
		}

		// Complete handshake
		return c.completeHandshake(resp.SenderIndex, nil)
	}
}

// waitForHandshakeResponse waits for a handshake response with RekeyTimeout.
// Uses transport's SetReadDeadline to implement timeout instead of goroutines
// to avoid race conditions and goroutine leaks.
func (c *Conn) waitForHandshakeResponse(ctx context.Context, hs *noise.HandshakeState) (*noise.HandshakeRespMessage, error) {
	deadline := time.Now().Add(RekeyTimeout)

	// Check if parent context has earlier deadline
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	// Set read deadline on transport
	if err := c.transport.SetReadDeadline(deadline); err != nil {
		// Transport doesn't support deadlines - required for DialContext timeouts
		return nil, fmt.Errorf("transport does not support SetReadDeadline: %w", err)
	}

	// Read response (will timeout based on deadline)
	buf := make([]byte, noise.MaxPacketSize)
	n, fromAddr, err := c.transport.RecvFrom(buf)

	// Clear deadline
	_ = c.transport.SetReadDeadline(time.Time{})

	if err != nil {
		// Check if it's a timeout error
		if isTimeoutError(err) {
			return nil, ErrHandshakeTimeout
		}
		return nil, err
	}

	// Parse response
	resp, err := noise.ParseHandshakeResp(buf[:n])
	if err != nil {
		return nil, err
	}

	// Verify receiver index
	c.mu.RLock()
	localIdx := c.localIdx
	c.mu.RUnlock()

	if resp.ReceiverIndex != localIdx {
		return nil, ErrInvalidReceiverIndex
	}

	// Process the response
	noiseMsg := make([]byte, noise.KeySize+16)
	copy(noiseMsg[:noise.KeySize], resp.Ephemeral[:])
	copy(noiseMsg[noise.KeySize:], resp.Empty)

	if _, err := hs.ReadMessage(noiseMsg); err != nil {
		return nil, err
	}

	// Update remote address for NAT traversal (peer's address might have changed)
	if fromAddr != nil {
		c.mu.Lock()
		c.remoteAddr = fromAddr
		c.mu.Unlock()
	}

	return resp, nil
}

// isTimeoutError checks if an error is a timeout error.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	// Check for net.Error timeout
	type timeoutError interface {
		Timeout() bool
	}
	if te, ok := err.(timeoutError); ok {
		return te.Timeout()
	}
	return false
}
