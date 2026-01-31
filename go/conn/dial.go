package conn

import (
	"time"

	"github.com/vibing/zgrnet/noise"
)

// Dial establishes a connection to a remote peer.
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

	// Perform the handshake
	if err := c.dial(); err != nil {
		return nil, err
	}

	return c, nil
}

// dial performs the initiator side of the Noise IK handshake.
func (c *Conn) dial() error {
	c.mu.Lock()
	if c.state != ConnStateNew {
		c.mu.Unlock()
		return ErrInvalidConnState
	}

	c.state = ConnStateHandshaking
	c.handshakeStarted = time.Now()

	// Create handshake state (IK pattern - we know remote's public key)
	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:      noise.PatternIK,
		Initiator:    true,
		LocalStatic:  c.localKey,
		RemoteStatic: &c.remotePK,
	})
	if err != nil {
		c.state = ConnStateNew
		c.mu.Unlock()
		return err
	}
	c.hsState = hs
	c.mu.Unlock()

	// Generate and send handshake initiation
	msg1, err := hs.WriteMessage(nil)
	if err != nil {
		return c.failHandshake(err)
	}

	// msg1 format: ephemeral(32) + encrypted_static(48) = 80 bytes
	// Build wire message
	wireMsg := noise.BuildHandshakeInit(c.localIdx, hs.LocalEphemeral(), msg1[noise.KeySize:])
	if err := c.transport.SendTo(wireMsg, c.remoteAddr); err != nil {
		return c.failHandshake(err)
	}

	// Wait for handshake response
	buf := make([]byte, noise.MaxPacketSize)
	n, _, err := c.transport.RecvFrom(buf)
	if err != nil {
		return c.failHandshake(err)
	}

	// Parse response
	resp, err := noise.ParseHandshakeResp(buf[:n])
	if err != nil {
		return c.failHandshake(err)
	}

	// Verify receiver index matches our sender index
	if resp.ReceiverIndex != c.localIdx {
		return c.failHandshake(ErrInvalidReceiverIndex)
	}

	// Reconstruct the noise message and process
	noiseMsg := make([]byte, noise.KeySize+16)
	copy(noiseMsg[:noise.KeySize], resp.Ephemeral[:])
	copy(noiseMsg[noise.KeySize:], resp.Empty)

	if _, err := hs.ReadMessage(noiseMsg); err != nil {
		return c.failHandshake(err)
	}

	// Complete handshake
	return c.completeHandshake(resp.SenderIndex, nil)
}
