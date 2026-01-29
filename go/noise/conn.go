package noise

import (
	"errors"
	"sync"
	"time"
)

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
// It manages the handshake process and provides a simple API
// for sending and receiving encrypted messages.
type Conn struct {
	mu sync.RWMutex

	// Configuration
	localKey   *KeyPair
	remotePK   PublicKey
	transport  Transport
	remoteAddr Addr

	// State
	state    ConnState
	session  *Session
	hsState  *HandshakeState
	localIdx uint32

	// Timestamps
	createdAt time.Time

	// Inbound channel for listener-managed connections
	// When set, Recv() reads from this channel instead of the transport
	inbound chan inboundPacket
}

// inboundPacket represents a packet received from the listener
type inboundPacket struct {
	data []byte
	addr Addr
}

// ConnConfig contains the configuration for creating a connection.
type ConnConfig struct {
	// LocalKey is the local static key pair.
	LocalKey *KeyPair
	// RemotePK is the remote peer's public key (required for initiator).
	RemotePK PublicKey
	// Transport is the underlying datagram transport.
	Transport Transport
	// RemoteAddr is the remote peer's address.
	RemoteAddr Addr
}

// NewConn creates a new connection with the given configuration.
// The connection is not yet established; call Dial() or process incoming
// handshake messages to complete the handshake.
func NewConn(cfg ConnConfig) (*Conn, error) {
	if cfg.LocalKey == nil {
		return nil, ErrMissingLocalKey
	}
	if cfg.Transport == nil {
		return nil, ErrMissingTransport
	}

	localIdx, err := GenerateIndex()
	if err != nil {
		return nil, err
	}

	return &Conn{
		localKey:   cfg.LocalKey,
		remotePK:   cfg.RemotePK,
		transport:  cfg.Transport,
		remoteAddr: cfg.RemoteAddr,
		state:      ConnStateNew,
		localIdx:   localIdx,
		createdAt:  time.Now(),
	}, nil
}

// Open initiates a handshake with the remote peer.
// This is a blocking call that completes the full handshake.
// The connection must have RemotePK and RemoteAddr configured.
func (c *Conn) Open() error {
	c.mu.Lock()
	if c.state != ConnStateNew {
		c.mu.Unlock()
		return ErrInvalidConnState
	}
	if c.remotePK.IsZero() {
		c.mu.Unlock()
		return ErrMissingRemotePK
	}
	if c.remoteAddr == nil {
		c.mu.Unlock()
		return ErrMissingRemoteAddr
	}

	c.state = ConnStateHandshaking

	// Create handshake state (IK pattern - we know remote's public key)
	hs, err := NewHandshakeState(Config{
		Pattern:      PatternIK,
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
	wireMsg := BuildHandshakeInit(c.localIdx, hs.LocalEphemeral(), msg1[KeySize:])
	if err := c.transport.SendTo(wireMsg, c.remoteAddr); err != nil {
		return c.failHandshake(err)
	}

	// Wait for handshake response
	buf := make([]byte, MaxPacketSize)
	n, _, err := c.transport.RecvFrom(buf)
	if err != nil {
		return c.failHandshake(err)
	}

	// Parse response
	resp, err := ParseHandshakeResp(buf[:n])
	if err != nil {
		return c.failHandshake(err)
	}

	// Verify receiver index matches our sender index
	if resp.ReceiverIndex != c.localIdx {
		return c.failHandshake(ErrInvalidReceiverIndex)
	}

	// Reconstruct the noise message and process
	noiseMsg := make([]byte, KeySize+16)
	copy(noiseMsg[:KeySize], resp.Ephemeral[:])
	copy(noiseMsg[KeySize:], resp.Empty)

	if _, err := hs.ReadMessage(noiseMsg); err != nil {
		return c.failHandshake(err)
	}

	// Complete handshake
	return c.completeHandshake(resp.SenderIndex, nil)
}

// Accept processes an incoming handshake initiation and completes the handshake.
// This is used by the responder to accept incoming connections.
// Returns the handshake response to send back.
func (c *Conn) Accept(msg *HandshakeInitMessage) ([]byte, error) {
	c.mu.Lock()
	if c.state != ConnStateNew {
		c.mu.Unlock()
		return nil, ErrInvalidConnState
	}

	c.state = ConnStateHandshaking

	// Create handshake state (IK pattern - responder)
	hs, err := NewHandshakeState(Config{
		Pattern:     PatternIK,
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
	noiseMsg := make([]byte, KeySize+48)
	copy(noiseMsg[:KeySize], msg.Ephemeral[:])
	copy(noiseMsg[KeySize:], msg.Static)

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
	return BuildHandshakeResp(c.localIdx, remoteIdx, hs.LocalEphemeral(), msg2[KeySize:]), nil
}

// completeHandshake finalizes the handshake and creates the session.
// If remotePK is not nil, it will be set atomically with the state transition.
func (c *Conn) completeHandshake(remoteIdx uint32, remotePK *PublicKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.hsState == nil || !c.hsState.IsFinished() {
		return ErrHandshakeIncomplete
	}

	// Get transport keys
	sendCS, recvCS, err := c.hsState.Split()
	if err != nil {
		c.state = ConnStateNew
		return err
	}

	// Update remotePK if provided (for responder case)
	if remotePK != nil {
		c.remotePK = *remotePK
	}

	// Create session
	session, err := NewSession(SessionConfig{
		LocalIndex:  c.localIdx,
		RemoteIndex: remoteIdx,
		SendKey:     sendCS.Key(),
		RecvKey:     recvCS.Key(),
		RemotePK:    c.remotePK,
	})
	if err != nil {
		c.state = ConnStateNew
		return err
	}

	c.session = session
	c.hsState = nil // Clear handshake state
	c.state = ConnStateEstablished

	return nil
}

// failHandshake handles handshake failure.
func (c *Conn) failHandshake(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = ConnStateNew
	c.hsState = nil
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
	plaintext := EncodePayload(protocol, payload)

	// Encrypt
	ciphertext, counter, err := session.Encrypt(plaintext)
	if err != nil {
		return err
	}

	// Build wire message
	msg := BuildTransportMessage(session.RemoteIndex(), counter, ciphertext)

	// Send
	return c.transport.SendTo(msg, remoteAddr)
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

	var data []byte

	if inbound != nil {
		// Listener-managed connection: read from inbound channel
		pkt, ok := <-inbound
		if !ok {
			return 0, nil, ErrConnClosed
		}
		data = pkt.data
	} else {
		// Direct connection: read from transport
		buf := make([]byte, MaxPacketSize)
		n, _, err := c.transport.RecvFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		data = buf[:n]
	}

	// Parse transport message
	msg, err := ParseTransportMessage(data)
	if err != nil {
		return 0, nil, err
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

	// Decode protocol and payload
	return DecodePayload(plaintext)
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
func (c *Conn) RemotePublicKey() PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.remotePK
}

// RemoteAddr returns the remote peer's address.
func (c *Conn) RemoteAddr() Addr {
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
func (c *Conn) Session() *Session {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.session
}

// SetRemoteAddr updates the remote address (for NAT traversal).
func (c *Conn) SetRemoteAddr(addr Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remoteAddr = addr
}

// setInbound sets up the inbound channel for listener-managed connections.
// This should only be called by Listener before the connection is returned.
func (c *Conn) setInbound(ch chan inboundPacket) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inbound = ch
}

// deliverPacket delivers a packet to the connection's inbound channel.
// Returns false if the channel is full or the connection is closed.
func (c *Conn) deliverPacket(data []byte, addr Addr) bool {
	c.mu.RLock()
	inbound := c.inbound
	state := c.state
	c.mu.RUnlock()

	if inbound == nil || state == ConnStateClosed {
		return false
	}

	select {
	case inbound <- inboundPacket{data: data, addr: addr}:
		return true
	default:
		return false
	}
}

// Connection errors.
var (
	ErrMissingLocalKey      = errors.New("noise: missing local key pair")
	ErrMissingTransport     = errors.New("noise: missing transport")
	ErrMissingRemotePK      = errors.New("noise: missing remote public key")
	ErrMissingRemoteAddr    = errors.New("noise: missing remote address")
	ErrInvalidConnState     = errors.New("noise: invalid connection state")
	ErrNotEstablished       = errors.New("noise: connection not established")
	ErrInvalidReceiverIndex = errors.New("noise: invalid receiver index")
	ErrHandshakeIncomplete  = errors.New("noise: handshake not complete")
	ErrConnClosed           = errors.New("noise: connection closed")
)
