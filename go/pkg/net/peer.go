package net

import (
	"bytes"
	"time"

	"github.com/vibing/zgrnet/pkg/kcp"
	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/relay"
)

// stream wraps kcp.Stream for peer-specific operations.
type stream = kcp.Stream

// mux wraps kcp.Mux for peer-specific operations.
type mux = kcp.Mux

// Stream is a multiplexed reliable stream over KCP.
type Stream = kcp.Stream

// isKCPClient determines if we are the KCP client for a peer.
// Uses deterministic rule: smaller public key is client (uses odd stream IDs).
// This ensures consistent stream ID allocation regardless of who initiated the connection.
func (u *UDP) isKCPClient(remotePK noise.PublicKey) bool {
	return bytes.Compare(u.localKey.Public[:], remotePK[:]) < 0
}

// muxResources holds the resources created by createMux.
type muxResources struct {
	mux         *mux
	acceptChan  chan *stream
	inboundChan chan protoPacket
}

// createMux creates a new Mux and associated channels for a peer.
// The caller is responsible for assigning the returned resources to peer
// and starting the mux update loop.
func (u *UDP) createMux(peer *peerState) *muxResources {
	// Determine client/server role based on public key comparison
	isClient := u.isKCPClient(peer.pk)

	acceptChan := make(chan *stream, 16)
	inboundChan := make(chan protoPacket, InboundChanSize)

	m := kcp.NewMux(
		kcp.DefaultConfig(),
		isClient,
		// Output function: send KCP frames through the encrypted session
		func(data []byte) error {
			return u.sendToPeer(peer, noise.ProtocolKCP, data)
		},
		// OnStreamData: called when a stream has data available
		func(streamID uint32) {
			// This is handled internally by Stream.Read
		},
		// OnNewStream: called when remote opens a new stream
		func(s *stream) {
			select {
			case acceptChan <- s:
			default:
				// Accept queue full, close the stream
				s.Close()
			}
		},
	)

	return &muxResources{
		mux:         m,
		acceptChan:  acceptChan,
		inboundChan: inboundChan,
	}
}

// startMuxUpdateLoop starts the mux update goroutine.
// Should be called after mux is assigned to peer.
func (u *UDP) startMuxUpdateLoop(m *mux) {
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		u.muxUpdateLoop(m)
	}()
}

// muxUpdateLoop periodically updates the Mux for KCP retransmissions.
// It takes a reference to the specific mux it's responsible for, so it exits
// correctly when that mux is closed (even if peer.mux is replaced with a new one).
func (u *UDP) muxUpdateLoop(m *mux) {
	ticker := time.NewTicker(1 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if m.IsClosed() {
				return
			}
			m.Update(uint32(time.Now().UnixMilli()))
		case <-u.closeChan:
			return
		}
	}
}

// sendToPeer sends data to a peer with the given protocol byte.
// If the peer has a relay route in the RouteTable, the data is first encrypted
// with the peer's session (inner layer), wrapped in RELAY_0, then sent through
// the relay peer's session (outer layer). Otherwise, sends directly.
func (u *UDP) sendToPeer(peer *peerState, protocol byte, data []byte) error {
	if u.routeTable == nil {
		return u.sendDirect(peer, protocol, data)
	}

	relayPK := u.routeTable.RelayFor(peer.pk)
	if relayPK == nil {
		return u.sendDirect(peer, protocol, data)
	}

	// Relay path: encrypt with peer's session (inner), wrap in RELAY_0, send via relay.
	peer.mu.RLock()
	session := peer.session
	peer.mu.RUnlock()

	if session == nil {
		return ErrNoSession
	}

	// Inner encryption: peer's session
	plaintext := noise.EncodePayload(protocol, data)
	ciphertext, counter, err := session.Encrypt(plaintext)
	if err != nil {
		return err
	}
	type4msg := noise.BuildTransportMessage(session.RemoteIndex(), counter, ciphertext)

	// Wrap in RELAY_0
	relay0Data := relay.EncodeRelay0(&relay.Relay0{
		TTL:      relay.DefaultTTL,
		Strategy: relay.StrategyAuto,
		DstKey:   [32]byte(peer.pk),
		Payload:  type4msg,
	})

	// Send through relay peer (direct, no further wrapping)
	u.mu.RLock()
	relayPeer, exists := u.peers[*relayPK]
	u.mu.RUnlock()
	if !exists {
		return ErrPeerNotFound
	}

	return u.sendDirect(relayPeer, noise.ProtocolRelay0, relay0Data)
}

// sendDirect sends data directly to a peer (no relay wrapping).
// This is used by executeRelayAction (relay engine already computed the next hop)
// and as the base case for sendToPeer when no relay route exists.
func (u *UDP) sendDirect(peer *peerState, protocol byte, data []byte) error {
	peer.mu.RLock()
	session := peer.session
	endpoint := peer.endpoint
	peer.mu.RUnlock()

	if endpoint == nil {
		return ErrNoEndpoint
	}
	if session == nil {
		return ErrNoSession
	}

	// Encode payload with protocol byte
	plaintext := noise.EncodePayload(protocol, data)

	// Encrypt
	ciphertext, counter, err := session.Encrypt(plaintext)
	if err != nil {
		return err
	}

	// Build and send transport message
	msg := noise.BuildTransportMessage(session.RemoteIndex(), counter, ciphertext)
	n, err := u.socket.WriteToUDP(msg, endpoint)
	if err != nil {
		return err
	}

	// Update stats
	u.totalTx.Add(uint64(n))
	peer.mu.Lock()
	peer.txBytes += uint64(n)
	peer.mu.Unlock()

	return nil
}

// OpenStream opens a new KCP stream to the specified peer.
// The peer must be in established state with mux initialized.
// proto specifies the stream protocol type (e.g., noise.ProtocolTCPProxy).
// metadata contains additional data sent with the SYN frame (e.g., encoded Address).
// Use proto=0 and metadata=nil for untyped streams.
func (u *UDP) OpenStream(pk noise.PublicKey, proto byte, metadata []byte) (*Stream, error) {
	if u.closed.Load() {
		return nil, ErrClosed
	}

	u.mu.RLock()
	peer, exists := u.peers[pk]
	u.mu.RUnlock()

	if !exists {
		return nil, ErrPeerNotFound
	}

	peer.mu.RLock()
	state := peer.state
	m := peer.mux
	peer.mu.RUnlock()

	if state != PeerStateEstablished {
		return nil, ErrNoSession
	}

	if m == nil {
		return nil, ErrNoSession
	}

	return m.OpenStream(proto, metadata)
}

// AcceptStream accepts an incoming KCP stream from the specified peer.
// This blocks until a stream is available or the UDP is closed.
// The peer must be in established state with mux initialized.
func (u *UDP) AcceptStream(pk noise.PublicKey) (*Stream, error) {
	if u.closed.Load() {
		return nil, ErrClosed
	}

	u.mu.RLock()
	peer, exists := u.peers[pk]
	u.mu.RUnlock()

	if !exists {
		return nil, ErrPeerNotFound
	}

	peer.mu.RLock()
	acceptChan := peer.acceptChan
	peer.mu.RUnlock()

	if acceptChan == nil {
		return nil, ErrNoSession
	}

	select {
	case s := <-acceptChan:
		return s, nil
	case <-u.closeChan:
		return nil, ErrClosed
	}
}

// Read reads raw data from the specified peer (non-KCP protocols).
// Returns the protocol byte, number of bytes read, and any error.
// This is a blocking call.
func (u *UDP) Read(pk noise.PublicKey, buf []byte) (proto byte, n int, err error) {
	if u.closed.Load() {
		return 0, 0, ErrClosed
	}

	u.mu.RLock()
	peer, exists := u.peers[pk]
	u.mu.RUnlock()

	if !exists {
		return 0, 0, ErrPeerNotFound
	}

	// Get inbound channel (fast path: already initialized)
	peer.mu.RLock()
	inboundChan := peer.inboundChan
	peer.mu.RUnlock()

	// Slow path: initialize if needed
	if inboundChan == nil {
		peer.mu.Lock()
		if peer.inboundChan == nil {
			peer.inboundChan = make(chan protoPacket, InboundChanSize)
		}
		inboundChan = peer.inboundChan
		peer.mu.Unlock()
	}

	select {
	case pkt := <-inboundChan:
		n = copy(buf, pkt.payload)
		return pkt.protocol, n, nil
	case <-u.closeChan:
		return 0, 0, ErrClosed
	}
}

// Write writes raw data to the specified peer with the given protocol byte.
// Returns the number of bytes written and any error.
func (u *UDP) Write(pk noise.PublicKey, proto byte, data []byte) (n int, err error) {
	if u.closed.Load() {
		return 0, ErrClosed
	}

	u.mu.RLock()
	peer, exists := u.peers[pk]
	u.mu.RUnlock()

	if !exists {
		return 0, ErrPeerNotFound
	}

	if err := u.sendToPeer(peer, proto, data); err != nil {
		return 0, err
	}

	return len(data), nil
}

// GetMux returns the Mux for a peer.
// Returns nil if mux is not initialized (session not established).
func (u *UDP) GetMux(pk noise.PublicKey) (*mux, error) {
	if u.closed.Load() {
		return nil, ErrClosed
	}

	u.mu.RLock()
	peer, exists := u.peers[pk]
	u.mu.RUnlock()

	if !exists {
		return nil, ErrPeerNotFound
	}

	peer.mu.RLock()
	m := peer.mux
	peer.mu.RUnlock()

	if m == nil {
		return nil, ErrNoSession
	}

	return m, nil
}
