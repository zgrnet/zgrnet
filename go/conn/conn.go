package conn

import (
	"log"
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
//
// The connection follows WireGuard's timer model:
// - Tick() is called periodically to handle time-based actions
// - Send() queues data if no session and triggers handshake
// - Recv() processes incoming messages and updates state
type Conn struct {
	mu sync.RWMutex

	// Configuration
	localKey   *noise.KeyPair
	remotePK   noise.PublicKey
	transport  noise.Transport
	remoteAddr noise.Addr

	// Connection state
	state    ConnState
	localIdx uint32

	// Session management (WireGuard-style rotation)
	// current: active session for sending
	// previous: previous session (for receiving delayed packets)
	current  *noise.Session
	previous *noise.Session

	// Handshake state
	hsState               *noise.HandshakeState
	handshakeStarted      time.Time // When current handshake attempt started
	handshakeAttemptStart time.Time // When we first started trying to handshake (for 90s timeout)
	lastHandshakeSent     time.Time // When we last sent a handshake message
	isInitiator           bool      // Whether we initiated the current/pending session

	// Timestamps
	createdAt      time.Time
	sessionCreated time.Time // When current session was established
	lastSent       time.Time
	lastReceived   time.Time

	// Pending packets waiting for session establishment
	pendingPackets [][]byte

	// Rekey state
	rekeyTriggered bool // Whether we've already triggered rekey for current session age

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
		localKey:       localKey,
		remotePK:       remotePK,
		transport:      transport,
		remoteAddr:     remoteAddr,
		state:          ConnStateNew,
		localIdx:       localIdx,
		createdAt:      now,
		lastSent:       now,
		lastReceived:   now,
		pendingPackets: make([][]byte, 0),
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

	if c.hsState == nil || !c.hsState.IsFinished() {
		c.mu.Unlock()
		return ErrHandshakeIncomplete
	}

	// Get transport keys
	sendCS, recvCS, err := c.hsState.Split()
	if err != nil {
		c.resetHandshakeStateLocked()
		c.mu.Unlock()
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
		c.mu.Unlock()
		return err
	}

	now := time.Now()

	// Rotate sessions: current -> previous
	if c.current != nil {
		c.previous = c.current
	}

	c.current = session
	c.sessionCreated = now
	c.hsState = nil // Clear handshake state
	c.handshakeStarted = time.Time{}
	c.handshakeAttemptStart = time.Time{}
	c.lastHandshakeSent = time.Time{}
	c.state = ConnStateEstablished
	c.lastSent = now
	c.lastReceived = now
	c.rekeyTriggered = false // Reset rekey trigger for new session

	// Get pending packets count before unlocking
	hasPending := len(c.pendingPackets) > 0
	c.mu.Unlock()

	// Flush pending packets (outside the lock)
	if hasPending {
		c.flushPendingPackets()
	}

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
//
// If the connection is not established, the packet is queued and
// a handshake will be triggered (if not already in progress).
//
// If the session is too old, the packet is sent but a rekey is
// also triggered in the background.
func (c *Conn) Send(protocol byte, payload []byte) error {
	plaintext := noise.EncodePayload(protocol, payload)
	return c.sendPayload(plaintext, false)
}

// SendKeepalive sends an empty keepalive message to maintain the connection.
// Keepalive messages are only sent if the connection is established;
// they are not queued.
func (c *Conn) SendKeepalive() error {
	return c.sendPayload(nil, true)
}

// sendPayload encrypts and sends a payload to the remote peer.
// This is the common implementation for Send and SendKeepalive.
// If isKeepalive is true, the message is not queued if no session is available.
func (c *Conn) sendPayload(plaintext []byte, isKeepalive bool) error {
	c.mu.Lock()

	// Check connection state
	if c.state == ConnStateClosed {
		c.mu.Unlock()
		return ErrConnClosed
	}

	// If no valid session, queue the packet (unless it's a keepalive)
	if c.current == nil || c.state != ConnStateEstablished {
		if isKeepalive {
			c.mu.Unlock()
			return ErrNotEstablished
		}

		// Queue the packet
		if plaintext != nil {
			pktCopy := make([]byte, len(plaintext))
			copy(pktCopy, plaintext)
			c.pendingPackets = append(c.pendingPackets, pktCopy)
		}

		// Trigger handshake if not already in progress
		needHandshake := c.hsState == nil && c.state == ConnStateNew
		c.mu.Unlock()

		if needHandshake {
			// This will be handled by the external dialer or listener
			// For now, return an error indicating the packet is queued
			return ErrNotEstablished
		}
		return nil
	}

	session := c.current
	sessionCreated := c.sessionCreated
	remoteAddr := c.remoteAddr
	isInitiator := c.isInitiator
	rekeyTriggered := c.rekeyTriggered
	c.mu.Unlock()

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
	now := time.Now()
	c.mu.Lock()
	c.lastSent = now
	c.mu.Unlock()

	// Check if rekey is needed (initiator only, session too old or message count)
	// Only trigger once per session
	if isInitiator && !rekeyTriggered {
		needRekey := false

		// Check time-based rekey
		if !sessionCreated.IsZero() && now.Sub(sessionCreated) > RekeyAfterTime {
			needRekey = true
		}

		// Check message-count-based rekey
		if counter >= RekeyAfterMessages {
			needRekey = true
		}

		if needRekey {
			// Trigger rekey in background (non-blocking)
			go func() {
				if err := c.initiateRekey(); err != nil {
					log.Printf("conn: background rekey on send failed: %v", err)
				}
			}()
		}
	}

	return nil
}

// flushPendingPackets sends all queued packets after session establishment.
// This should be called after a successful handshake completion.
func (c *Conn) flushPendingPackets() {
	c.mu.Lock()
	packets := c.pendingPackets
	c.pendingPackets = nil
	c.mu.Unlock()

	for _, pkt := range packets {
		_ = c.sendPayload(pkt, false)
	}
}

// Recv receives and decrypts a message from the remote peer.
// Returns the protocol byte and decrypted payload.
// This is a blocking call.
//
// Recv handles multiple message types:
//   - Transport messages: decrypted and returned
//   - Handshake responses: processed to complete rekey (returns empty payload)
//
// When receiving data on an old session (initiator only), Recv may
// trigger a rekey in the background.
func (c *Conn) Recv() (protocol byte, payload []byte, err error) {
	c.mu.RLock()
	state := c.state
	inbound := c.inbound
	current := c.current
	hsState := c.hsState
	c.mu.RUnlock()

	// Check basic state
	if state == ConnStateClosed {
		return 0, nil, ErrConnClosed
	}

	// For new connections with no session and no pending handshake, return early
	// This prevents blocking on RecvFrom when there's nothing to receive
	if state == ConnStateNew && current == nil && hsState == nil {
		return 0, nil, ErrNotEstablished
	}

	var data []byte
	var fromAddr noise.Addr

	if inbound != nil {
		// Listener-managed connection: read pre-parsed message from inbound channel
		pkt, ok := <-inbound
		if !ok {
			return 0, nil, ErrConnClosed
		}
		// For listener-managed connections, we receive pre-parsed transport messages
		return c.handleTransportMessage(pkt.msg)
	}

	// Direct connection: read from transport using pooled buffer
	bufPtr := recvBufferPool.Get().(*[]byte)
	defer recvBufferPool.Put(bufPtr)
	buf := *bufPtr

	n, addr, err := c.transport.RecvFrom(buf)
	if err != nil {
		return 0, nil, err
	}

	data = buf[:n]
	fromAddr = addr

	// Get message type
	msgType, err := noise.GetMessageType(data)
	if err != nil {
		return 0, nil, err
	}

	switch msgType {
	case noise.MessageTypeTransport:
		msg, err := noise.ParseTransportMessage(data)
		if err != nil {
			return 0, nil, err
		}
		// Copy ciphertext before buffer is reused
		cipherCopy := make([]byte, len(msg.Ciphertext))
		copy(cipherCopy, msg.Ciphertext)
		msg.Ciphertext = cipherCopy
		return c.handleTransportMessage(msg)

	case noise.MessageTypeHandshakeResp:
		resp, err := noise.ParseHandshakeResp(data)
		if err != nil {
			return 0, nil, err
		}
		return c.handleHandshakeResponse(resp, fromAddr)

	case noise.MessageTypeHandshakeInit:
		// For direct connections acting as responder during rekey
		// This is unusual for Dial'd connections but possible
		init, err := noise.ParseHandshakeInit(data)
		if err != nil {
			return 0, nil, err
		}
		return c.handleHandshakeInit(init, fromAddr)

	default:
		return 0, nil, noise.ErrInvalidMessageType
	}
}

// handleTransportMessage processes an incoming transport message.
func (c *Conn) handleTransportMessage(msg *noise.TransportMessage) (byte, []byte, error) {
	c.mu.RLock()
	current := c.current
	previous := c.previous
	sessionCreated := c.sessionCreated
	isInitiator := c.isInitiator
	rekeyTriggered := c.rekeyTriggered
	c.mu.RUnlock()

	if current == nil {
		return 0, nil, ErrNotEstablished
	}

	// Try to find the right session based on receiver index
	var session *noise.Session
	if msg.ReceiverIndex == current.LocalIndex() {
		session = current
	} else if previous != nil && msg.ReceiverIndex == previous.LocalIndex() {
		session = previous
	} else {
		return 0, nil, ErrInvalidReceiverIndex
	}

	// Decrypt
	plaintext, err := session.Decrypt(msg.Ciphertext, msg.Counter)
	if err != nil {
		return 0, nil, err
	}

	// Update last received time
	now := time.Now()
	c.mu.Lock()
	c.lastReceived = now
	c.mu.Unlock()

	// Check if we should trigger rekey on receive (initiator only)
	// WireGuard: trigger at RekeyOnRecvThreshold (165s) if not already triggered
	if isInitiator && !rekeyTriggered && !sessionCreated.IsZero() {
		if now.Sub(sessionCreated) > RekeyOnRecvThreshold {
			go func() {
				if err := c.initiateRekey(); err != nil {
					log.Printf("conn: background rekey on receive failed: %v", err)
				}
			}()
		}
	}

	// Handle keepalive (empty payload)
	if len(plaintext) == 0 {
		return 0, nil, nil
	}

	// Decode protocol and payload
	return noise.DecodePayload(plaintext)
}

// handleHandshakeResponse processes an incoming handshake response.
// This is called when we're the initiator and receive a response during rekey.
func (c *Conn) handleHandshakeResponse(resp *noise.HandshakeRespMessage, fromAddr noise.Addr) (byte, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify we have a pending handshake and this is for us
	if c.hsState == nil {
		return 0, nil, ErrInvalidConnState
	}

	if resp.ReceiverIndex != c.localIdx {
		return 0, nil, ErrInvalidReceiverIndex
	}

	// Reconstruct noise message: ephemeral(32) + encrypted_nothing(16) = 48 bytes
	noiseMsg := make([]byte, noise.KeySize+16)
	copy(noiseMsg[:noise.KeySize], resp.Ephemeral[:])
	copy(noiseMsg[noise.KeySize:], resp.Empty)

	// Read handshake response
	if _, err := c.hsState.ReadMessage(noiseMsg); err != nil {
		c.resetHandshakeStateLocked()
		return 0, nil, err
	}

	// Get transport keys
	sendCS, recvCS, err := c.hsState.Split()
	if err != nil {
		c.resetHandshakeStateLocked()
		return 0, nil, err
	}

	// Create new session
	session, err := noise.NewSession(noise.SessionConfig{
		LocalIndex:  c.localIdx,
		RemoteIndex: resp.SenderIndex,
		SendKey:     sendCS.Key(),
		RecvKey:     recvCS.Key(),
		RemotePK:    c.remotePK,
	})
	if err != nil {
		c.resetHandshakeStateLocked()
		return 0, nil, err
	}

	now := time.Now()

	// Rotate sessions
	if c.current != nil {
		c.previous = c.current
	}

	c.current = session
	c.sessionCreated = now
	c.hsState = nil
	c.handshakeStarted = time.Time{}
	c.handshakeAttemptStart = time.Time{}
	c.lastHandshakeSent = time.Time{}
	c.state = ConnStateEstablished
	c.lastReceived = now
	c.rekeyTriggered = false
	c.isInitiator = true

	// Update remote address if it changed (NAT traversal)
	if fromAddr != nil {
		c.remoteAddr = fromAddr
	}

	// Return empty payload to indicate handshake completion
	// Caller should continue receiving to get actual data
	return 0, nil, nil
}

// handleHandshakeInit processes an incoming handshake initiation.
// This is called when the peer initiates a rekey.
func (c *Conn) handleHandshakeInit(init *noise.HandshakeInitMessage, fromAddr noise.Addr) (byte, []byte, error) {
	// Copy necessary data under lock, then release for crypto operations
	c.mu.RLock()
	localKey := c.localKey
	expectedRemotePK := c.remotePK
	transport := c.transport
	remoteAddr := c.remoteAddr
	if fromAddr != nil {
		remoteAddr = fromAddr
	}
	c.mu.RUnlock()

	// Perform crypto operations outside lock
	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:     noise.PatternIK,
		Initiator:   false,
		LocalStatic: localKey,
	})
	if err != nil {
		return 0, nil, err
	}

	// Reconstruct noise message: ephemeral(32) + static_enc(48) = 80 bytes
	noiseMsg := make([]byte, noise.KeySize+48)
	copy(noiseMsg[:noise.KeySize], init.Ephemeral[:])
	copy(noiseMsg[noise.KeySize:], init.Static)

	if _, err := hs.ReadMessage(noiseMsg); err != nil {
		return 0, nil, err
	}

	// Verify remote public key matches
	remotePK := hs.RemoteStatic()
	if expectedRemotePK != remotePK {
		return 0, nil, ErrInvalidRemotePK
	}

	// Generate response
	msg2, err := hs.WriteMessage(nil)
	if err != nil {
		return 0, nil, err
	}

	// Generate new local index for the new session
	newIdx, err := noise.GenerateIndex()
	if err != nil {
		return 0, nil, err
	}

	// Build wire response
	wireResp := noise.BuildHandshakeResp(newIdx, init.SenderIndex, hs.LocalEphemeral(), msg2[noise.KeySize:])

	// Get transport keys
	sendCS, recvCS, err := hs.Split()
	if err != nil {
		return 0, nil, err
	}

	// Create new session
	session, err := noise.NewSession(noise.SessionConfig{
		LocalIndex:  newIdx,
		RemoteIndex: init.SenderIndex,
		SendKey:     sendCS.Key(),
		RecvKey:     recvCS.Key(),
		RemotePK:    expectedRemotePK,
	})
	if err != nil {
		return 0, nil, err
	}

	// Send response (outside lock)
	if err := transport.SendTo(wireResp, remoteAddr); err != nil {
		return 0, nil, err
	}

	// Now acquire lock to update state
	now := time.Now()
	c.mu.Lock()
	// Rotate sessions
	if c.current != nil {
		c.previous = c.current
	}
	c.current = session
	c.localIdx = newIdx
	c.sessionCreated = now
	c.state = ConnStateEstablished
	c.lastReceived = now
	c.lastSent = now
	c.rekeyTriggered = false
	c.isInitiator = false
	if fromAddr != nil {
		c.remoteAddr = fromAddr
	}
	c.mu.Unlock()

	// Return empty payload to indicate handshake completion
	return 0, nil, nil
}

// Tick performs periodic maintenance on the connection.
// This method should be called periodically by the connection manager.
//
// Tick directly executes time-based actions:
//   - Sends keepalive if we haven't sent anything recently but have received data
//   - Retransmits handshake initiation if waiting for response
//   - Triggers rekey if session is too old (initiator only)
//
// Returns nil on success. Returns an error if:
//   - ErrConnTimeout: connection timed out (no data received for RejectAfterTime)
//   - ErrHandshakeTimeout: handshake attempt exceeded RekeyAttemptTime (90s)
//   - ErrConnClosed: connection was closed
func (c *Conn) Tick() error {
	now := time.Now()

	c.mu.RLock()
	state := c.state
	lastSent := c.lastSent
	lastReceived := c.lastReceived
	sessionCreated := c.sessionCreated
	isInitiator := c.isInitiator
	handshakeAttemptStart := c.handshakeAttemptStart
	lastHandshakeSent := c.lastHandshakeSent
	hsState := c.hsState
	session := c.current
	c.mu.RUnlock()

	switch state {
	case ConnStateNew:
		// Nothing to do for new connections
		return nil

	case ConnStateHandshaking:
		// Check if handshake attempt has exceeded RekeyAttemptTime (90s)
		if !handshakeAttemptStart.IsZero() && now.Sub(handshakeAttemptStart) > RekeyAttemptTime {
			return ErrHandshakeTimeout
		}

		// Check if we need to retransmit handshake (every RekeyTimeout = 5s)
		if hsState != nil && !lastHandshakeSent.IsZero() && now.Sub(lastHandshakeSent) > RekeyTimeout {
			// Retransmit handshake initiation
			if err := c.retransmitHandshake(); err != nil {
				return err
			}
		}
		return nil

	case ConnStateEstablished:
		// Check if connection has timed out (no messages received)
		if now.Sub(lastReceived) > RejectAfterTime {
			return ErrConnTimeout
		}

		// Check message-based rejection (nonce exhaustion)
		if session != nil {
			sendNonce := session.SendNonce()
			recvNonce := session.RecvMaxNonce()
			if sendNonce > RejectAfterMessages || recvNonce > RejectAfterMessages {
				return ErrSessionExpired
			}
		}

		// Check if we're waiting for rekey response
		if hsState != nil {
			// Check if handshake attempt has exceeded RekeyAttemptTime (90s)
			if !handshakeAttemptStart.IsZero() && now.Sub(handshakeAttemptStart) > RekeyAttemptTime {
				return ErrHandshakeTimeout
			}

			// Check if we need to retransmit handshake (every RekeyTimeout = 5s)
			if !lastHandshakeSent.IsZero() && now.Sub(lastHandshakeSent) > RekeyTimeout {
				if err := c.retransmitHandshake(); err != nil {
					return err
				}
			}
			return nil
		}

		// Disconnection detection (WireGuard Section 5):
		// If no packets received for KeepaliveTimeout + RekeyTimeout (15s),
		// initiate a new handshake to re-establish connection (handles roaming)
		disconnectionThreshold := KeepaliveTimeout + RekeyTimeout
		if isInitiator && now.Sub(lastReceived) > disconnectionThreshold {
			// No packets received for 15s, try to re-establish
			if err := c.initiateRekey(); err != nil {
				return err
			}
			return nil
		}

		// Check if rekey is needed (session too old or too many messages, initiator only)
		// Only trigger once per session (rekeyTriggered is reset when new session is established)
		c.mu.RLock()
		rekeyTriggered := c.rekeyTriggered
		c.mu.RUnlock()

		if isInitiator && !rekeyTriggered {
			needsRekey := false

			// Time-based rekey trigger
			if !sessionCreated.IsZero() && now.Sub(sessionCreated) > RekeyAfterTime {
				needsRekey = true
			}

			// Message-based rekey trigger
			if session != nil {
				sendNonce := session.SendNonce()
				recvNonce := session.RecvMaxNonce()
				if sendNonce > RekeyAfterMessages || recvNonce > RekeyAfterMessages {
					needsRekey = true
				}
			}

			if needsRekey {
				if err := c.initiateRekey(); err != nil {
					return err
				}
				return nil
			}
		}

		// Passive keepalive: send empty message if we haven't sent recently
		// but have received data recently (peer is active)
		sentDelta := now.Sub(lastSent)
		recvDelta := now.Sub(lastReceived)
		if sentDelta > KeepaliveTimeout && recvDelta < KeepaliveTimeout {
			if err := c.SendKeepalive(); err != nil {
				return err
			}
		}

		return nil

	case ConnStateClosed:
		return ErrConnClosed

	default:
		return ErrInvalidConnState
	}
}

// initiateRekey starts a new handshake to rekey the connection.
// This is called when the current session is too old.
func (c *Conn) initiateRekey() error {
	// Check if already have pending handshake and copy necessary data
	c.mu.Lock()
	if c.hsState != nil {
		c.mu.Unlock()
		return nil
	}
	localKey := c.localKey
	remotePK := c.remotePK
	transport := c.transport
	remoteAddr := c.remoteAddr
	c.mu.Unlock()

	// Perform crypto operations outside lock
	newIdx, err := noise.GenerateIndex()
	if err != nil {
		return err
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:      noise.PatternIK,
		Initiator:    true,
		LocalStatic:  localKey,
		RemoteStatic: &remotePK,
	})
	if err != nil {
		return err
	}

	msg1, err := hs.WriteMessage(nil)
	if err != nil {
		return err
	}

	wireMsg := noise.BuildHandshakeInit(newIdx, hs.LocalEphemeral(), msg1[noise.KeySize:])

	// Send outside lock
	if err := transport.SendTo(wireMsg, remoteAddr); err != nil {
		return err
	}

	// Update state under lock
	now := time.Now()
	c.mu.Lock()
	// Double-check no one else started a handshake while we were working
	if c.hsState != nil {
		c.mu.Unlock()
		return nil
	}
	c.hsState = hs
	c.localIdx = newIdx
	c.handshakeStarted = now
	c.handshakeAttemptStart = now
	c.lastHandshakeSent = now
	c.isInitiator = true
	c.rekeyTriggered = true
	c.mu.Unlock()

	return nil
}

// retransmitHandshake resends the handshake initiation with a new ephemeral key.
// According to WireGuard, each retransmit generates new ephemeral keys.
func (c *Conn) retransmitHandshake() error {
	// Copy necessary data under lock
	c.mu.RLock()
	if c.hsState == nil {
		c.mu.RUnlock()
		return nil
	}
	localKey := c.localKey
	remotePK := c.remotePK
	localIdx := c.localIdx
	transport := c.transport
	remoteAddr := c.remoteAddr
	c.mu.RUnlock()

	// Perform crypto operations outside lock
	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:      noise.PatternIK,
		Initiator:    true,
		LocalStatic:  localKey,
		RemoteStatic: &remotePK,
	})
	if err != nil {
		return err
	}

	msg1, err := hs.WriteMessage(nil)
	if err != nil {
		return err
	}

	wireMsg := noise.BuildHandshakeInit(localIdx, hs.LocalEphemeral(), msg1[noise.KeySize:])

	// Send outside lock
	if err := transport.SendTo(wireMsg, remoteAddr); err != nil {
		return err
	}

	// Update state under lock
	c.mu.Lock()
	c.hsState = hs
	c.lastHandshakeSent = time.Now()
	c.mu.Unlock()

	return nil
}

// Close closes the connection.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == ConnStateClosed {
		return nil
	}

	c.state = ConnStateClosed

	// Expire all sessions
	if c.current != nil {
		c.current.Expire()
	}
	if c.previous != nil {
		c.previous.Expire()
	}

	// Clear pending packets
	c.pendingPackets = nil

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

// Session returns the underlying current session (nil if not established).
func (c *Conn) Session() *noise.Session {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current
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
