package conn

import (
	"context"
	"time"

	"github.com/vibing/zgrnet/noise"
)

// Dial establishes a connection to a remote peer with default timeout.
// It performs the Noise IK handshake and returns an established connection.
//
// Parameters:
//   - transport: the underlying datagram transport (e.g., UDP)
//   - addr: the remote peer's address
//   - remotePK: the remote peer's public key (required for IK pattern)
//   - localKey: the local key pair for authentication
//
// Returns an established connection ready for Send/Recv, or an error.
func Dial(transport noise.Transport, addr noise.Addr, remotePK noise.PublicKey, localKey *noise.KeyPair) (*Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), RekeyAttemptTime)
	defer cancel()
	return DialContext(ctx, transport, addr, remotePK, localKey)
}

// DialContext establishes a connection to a remote peer with context support.
// The context can be used to cancel the dial or set a custom timeout.
//
// The dial implements WireGuard's retry mechanism:
//   - Sends handshake initiation
//   - Waits up to RekeyTimeout (5s) for response
//   - Retransmits with new ephemeral keys on timeout
//   - Gives up after RekeyAttemptTime (90s) or context cancellation
func DialContext(ctx context.Context, transport noise.Transport, addr noise.Addr, remotePK noise.PublicKey, localKey *noise.KeyPair) (*Conn, error) {
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
func (c *Conn) waitForHandshakeResponse(ctx context.Context, hs *noise.HandshakeState) (*noise.HandshakeRespMessage, error) {
	// Create a timeout context for this receive attempt
	recvCtx, cancel := context.WithTimeout(ctx, RekeyTimeout)
	defer cancel()

	// Channel for receive result
	type recvResult struct {
		data []byte
		err  error
	}
	resultCh := make(chan recvResult, 1)

	go func() {
		buf := make([]byte, noise.MaxPacketSize)
		n, _, err := c.transport.RecvFrom(buf)
		if err != nil {
			resultCh <- recvResult{nil, err}
			return
		}
		resultCh <- recvResult{buf[:n], nil}
	}()

	select {
	case <-recvCtx.Done():
		return nil, ErrHandshakeTimeout
	case result := <-resultCh:
		if result.err != nil {
			return nil, result.err
		}

		// Parse response
		resp, err := noise.ParseHandshakeResp(result.data)
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

		return resp, nil
	}
}
