package conn

import (
	"sync"
	"time"

	"github.com/vibing/zgrnet/noise"
)

// recvBufferPool is a pool for receive buffers to reduce allocations.
var recvBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, noise.MaxPacketSize)
		return &buf
	},
}

// ConnState represents the state of a connection.
type ConnState int

const (
	// ConnStateNew indicates a newly created connection.
	ConnStateNew ConnState = iota
	// ConnStateHandshaking indicates the connection is performing handshake.
	ConnStateHandshaking
	// ConnStateEstablished indicates the connection is ready for data transfer.
	ConnStateEstablished
	// ConnStateClosed indicates the connection has been closed.
	ConnStateClosed
)

func (s ConnState) String() string {
	switch s {
	case ConnStateNew:
		return "new"
	case ConnStateHandshaking:
		return "handshaking"
	case ConnStateEstablished:
		return "established"
	case ConnStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// Conn represents a connection to a remote peer.
// It manages the session and provides a simple API
// for sending and receiving encrypted messages.
type Conn struct {
	mu sync.RWMutex

	// Configuration
	localKey   *noise.KeyPair
	remotePK   noise.PublicKey
	transport  noise.Transport
	remoteAddr noise.Addr

	// State
	state    ConnState
	session  *noise.Session
	hsState  *noise.HandshakeState
	localIdx uint32

	// Timestamps
	createdAt        time.Time
	handshakeStarted time.Time
	lastSent         time.Time
	lastReceived     time.Time

	// Inbound channel for listener-managed connections
	// When set, Recv() reads from this channel instead of the transport
	inbound chan inboundPacket
}

// inboundPacket represents a parsed transport message from the listener
type inboundPacket struct {
	msg  *noise.TransportMessage
	addr noise.Addr
}

// newConn creates a new connection (internal use only).
// Use Dial() or Listener.Accept() to create connections.
func newConn(localKey *noise.KeyPair, transport noise.Transport, remoteAddr noise.Addr, remotePK noise.PublicKey) (*Conn, error) {
	if localKey == nil {
		return nil, ErrMissingLocalKey
	}
	if transport == nil {
		return nil, ErrMissingTransport
	}

	localIdx, err := noise.GenerateIndex()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	return &Conn{
		localKey:     localKey,
		remotePK:     remotePK,
		transport:    transport,
		remoteAddr:   remoteAddr,
		state:        ConnStateNew,
		localIdx:     localIdx,
		createdAt:    now,
		lastSent:     now,
		lastReceived: now,
	}, nil
}

// accept processes an incoming handshake initiation and completes the handshake.
// This is used by the Listener to accept incoming connections.
// Returns the handshake response to send back.
func (c *Conn) accept(msg *noise.HandshakeInitMessage) ([]byte, error) {
	c.mu.Lock()
	if c.state != ConnStateNew {
		c.mu.Unlock()
		return nil, ErrInvalidConnState
	}

	c.state = ConnStateHandshaking
	c.handshakeStarted = time.Now()

	// Create handshake state (IK pattern - responder)
	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:     noise.PatternIK,
		Initiator:   false,
		LocalStatic: c.localKey,
	})
	if err != nil {
		c.state = ConnStateNew
		c.mu.Unlock()
		return nil, err
	}
	c.hsState = hs
	c.mu.Unlock()

	// Reconstruct the noise message: ephemeral(32) + static_enc(48) = 80 bytes
	noiseMsg := make([]byte, noise.KeySize+48)
	copy(noiseMsg[:noise.KeySize], msg.Ephemeral[:])
	copy(noiseMsg[noise.KeySize:], msg.Static)

	if _, err := hs.ReadMessage(noiseMsg); err != nil {
		return nil, c.failHandshake(err)
	}

	// Get remote public key from handshake
	remotePK := hs.RemoteStatic()

	// Generate response
	msg2, err := hs.WriteMessage(nil)
	if err != nil {
		return nil, c.failHandshake(err)
	}

	// Store initiator's index as remote index
	remoteIdx := msg.SenderIndex

	// Complete handshake (updates remotePK atomically with state)
	if err := c.completeHandshake(remoteIdx, &remotePK); err != nil {
		return nil, err
	}

	// Build wire response message
	return noise.BuildHandshakeResp(c.localIdx, remoteIdx, hs.LocalEphemeral(), msg2[noise.KeySize:]), nil
}

// completeHandshake finalizes the handshake and creates the session.
// If remotePK is not nil, it will be set atomically with the state transition.
func (c *Conn) completeHandshake(remoteIdx uint32, remotePK *noise.PublicKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.hsState == nil || !c.hsState.IsFinished() {
		return ErrHandshakeIncomplete
	}

	// Get transport keys
	sendCS, recvCS, err := c.hsState.Split()
	if err != nil {
		c.resetHandshakeStateLocked()
		return err
	}

	// Update remotePK if provided (for responder case)
	if remotePK != nil {
		c.remotePK = *remotePK
	}

	// Create session
	session, err := noise.NewSession(noise.SessionConfig{
		LocalIndex:  c.localIdx,
		RemoteIndex: remoteIdx,
		SendKey:     sendCS.Key(),
		RecvKey:     recvCS.Key(),
		RemotePK:    c.remotePK,
	})
	if err != nil {
		c.resetHandshakeStateLocked()
		return err
	}

	now := time.Now()
	c.session = session
	c.hsState = nil // Clear handshake state
	c.state = ConnStateEstablished
	c.lastSent = now
	c.lastReceived = now

	return nil
}

// resetHandshakeStateLocked resets the connection to new state.
// Must be called with c.mu held.
func (c *Conn) resetHandshakeStateLocked() {
	c.state = ConnStateNew
	c.hsState = nil
}

// failHandshake handles handshake failure.
func (c *Conn) failHandshake(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetHandshakeStateLocked()
	return err
}

// Send sends an encrypted message to the remote peer.
// The protocol byte indicates the type of payload.
func (c *Conn) Send(protocol byte, payload []byte) error {
	c.mu.RLock()
	if c.state != ConnStateEstablished {
		c.mu.RUnlock()
		return ErrNotEstablished
	}
	session := c.session
	remoteAddr := c.remoteAddr
	c.mu.RUnlock()

	// Encode payload with protocol byte
	plaintext := noise.EncodePayload(protocol, payload)

	// Encrypt
	ciphertext, counter, err := session.Encrypt(plaintext)
	if err != nil {
		return err
	}

	// Build wire message
	msg := noise.BuildTransportMessage(session.RemoteIndex(), counter, ciphertext)

	// Send
	if err := c.transport.SendTo(msg, remoteAddr); err != nil {
		return err
	}

	// Update last sent time
	c.mu.Lock()
	c.lastSent = time.Now()
	c.mu.Unlock()

	return nil
}

// SendKeepalive sends an empty keepalive message to maintain the connection.
func (c *Conn) SendKeepalive() error {
	c.mu.RLock()
	if c.state != ConnStateEstablished {
		c.mu.RUnlock()
		return ErrNotEstablished
	}
	session := c.session
	remoteAddr := c.remoteAddr
	c.mu.RUnlock()

	// Encrypt empty payload
	ciphertext, counter, err := session.Encrypt(nil)
	if err != nil {
		return err
	}

	// Build wire message
	msg := noise.BuildTransportMessage(session.RemoteIndex(), counter, ciphertext)

	// Send
	if err := c.transport.SendTo(msg, remoteAddr); err != nil {
		return err
	}

	// Update last sent time
	c.mu.Lock()
	c.lastSent = time.Now()
	c.mu.Unlock()

	return nil
}

// Recv receives and decrypts a message from the remote peer.
// Returns the protocol byte and decrypted payload.
// This is a blocking call.
func (c *Conn) Recv() (protocol byte, payload []byte, err error) {
	c.mu.RLock()
	if c.state != ConnStateEstablished {
		c.mu.RUnlock()
		return 0, nil, ErrNotEstablished
	}
	session := c.session
	inbound := c.inbound
	c.mu.RUnlock()

	var msg *noise.TransportMessage

	if inbound != nil {
		// Listener-managed connection: read pre-parsed message from inbound channel
		pkt, ok := <-inbound
		if !ok {
			return 0, nil, ErrConnClosed
		}
		msg = pkt.msg
	} else {
		// Direct connection: read from transport using pooled buffer
		bufPtr := recvBufferPool.Get().(*[]byte)
		defer recvBufferPool.Put(bufPtr)
		buf := *bufPtr

		n, _, err := c.transport.RecvFrom(buf)
		if err != nil {
			return 0, nil, err
		}

		// Parse transport message
		parsed, err := noise.ParseTransportMessage(buf[:n])
		if err != nil {
			return 0, nil, err
		}

		// Copy ciphertext before buffer is reused (buffer returned to pool on function exit)
		// Modify parsed in-place to avoid allocating a new TransportMessage struct
		cipherCopy := make([]byte, len(parsed.Ciphertext))
		copy(cipherCopy, parsed.Ciphertext)
		parsed.Ciphertext = cipherCopy
		msg = parsed
	}

	// Verify receiver index
	if msg.ReceiverIndex != session.LocalIndex() {
		return 0, nil, ErrInvalidReceiverIndex
	}

	// Decrypt
	plaintext, err := session.Decrypt(msg.Ciphertext, msg.Counter)
	if err != nil {
		return 0, nil, err
	}

	// Update last received time
	c.mu.Lock()
	c.lastReceived = time.Now()
	c.mu.Unlock()

	// Handle keepalive (empty payload)
	if len(plaintext) == 0 {
		return 0, nil, nil
	}

	// Decode protocol and payload
	return noise.DecodePayload(plaintext)
}

// Tick checks the connection state and returns an action that should be taken.
// This method should be called periodically by the connection manager.
// The returned TickAction indicates what the caller should do:
//   - TickActionNone: no action needed
//   - TickActionSendKeepalive: call SendKeepalive()
//   - TickActionRekey: initiate a new handshake
//
// If the connection has timed out, Tick returns ErrConnTimeout.
func (c *Conn) Tick(now time.Time) (TickAction, error) {
	c.mu.RLock()
	state := c.state
	lastSent := c.lastSent
	lastReceived := c.lastReceived
	createdAt := c.createdAt
	handshakeStarted := c.handshakeStarted
	c.mu.RUnlock()

	switch state {
	case ConnStateNew:
		// Nothing to do for new connections
		return TickActionNone, nil

	case ConnStateHandshaking:
		// Check handshake timeout
		if now.Sub(handshakeStarted) > HandshakeTimeout {
			return TickActionNone, ErrHandshakeTimeout
		}
		return TickActionNone, nil

	case ConnStateEstablished:
		// Check if connection has timed out (no messages received)
		if now.Sub(lastReceived) > RejectAfterTime {
			return TickActionNone, ErrConnTimeout
		}

		// Check if rekey is needed (session too old)
		if now.Sub(createdAt) > RekeyAfterTime {
			return TickActionRekey, nil
		}

		// Check if keepalive is needed (haven't sent anything recently)
		if now.Sub(lastSent) > KeepaliveTimeout {
			return TickActionSendKeepalive, nil
		}

		return TickActionNone, nil

	case ConnStateClosed:
		return TickActionNone, ErrConnClosed

	default:
		return TickActionNone, ErrInvalidConnState
	}
}

// Close closes the connection.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == ConnStateClosed {
		return nil
	}

	c.state = ConnStateClosed
	if c.session != nil {
		c.session.Expire()
	}

	return nil
}

// State returns the current connection state.
func (c *Conn) State() ConnState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// RemotePublicKey returns the remote peer's public key.
func (c *Conn) RemotePublicKey() noise.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.remotePK
}

// RemoteAddr returns the remote peer's address.
func (c *Conn) RemoteAddr() noise.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.remoteAddr
}

// LocalIndex returns the local session index.
func (c *Conn) LocalIndex() uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.localIdx
}

// Session returns the underlying session (nil if not established).
func (c *Conn) Session() *noise.Session {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.session
}

// SetSession sets the session (for roaming/migration).
// This also updates the state to Established.
func (c *Conn) SetSession(s *Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.session = s
	if s != nil {
		c.state = ConnStateEstablished
		c.localIdx = s.LocalIndex()
	}
}

// SetRemoteAddr updates the remote address (for NAT traversal).
func (c *Conn) SetRemoteAddr(addr noise.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remoteAddr = addr
}

// LastSent returns when the last message was sent.
func (c *Conn) LastSent() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastSent
}

// LastReceived returns when the last message was received.
func (c *Conn) LastReceived() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastReceived
}

// setInbound sets up the inbound channel for listener-managed connections.
// This should only be called by Listener before the connection is returned.
func (c *Conn) setInbound(ch chan inboundPacket) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inbound = ch
}

// deliverPacket delivers a parsed transport message to the connection's inbound channel.
// Returns false if the channel is full or the connection is closed.
func (c *Conn) deliverPacket(msg *noise.TransportMessage, addr noise.Addr) bool {
	c.mu.RLock()
	inbound := c.inbound
	state := c.state
	c.mu.RUnlock()

	if inbound == nil || state == ConnStateClosed {
		return false
	}

	select {
	case inbound <- inboundPacket{msg: msg, addr: addr}:
		return true
	default:
		return false
	}
}
