package net

import (
	"time"

	"github.com/vibing/zgrnet/pkg/kcp"
	"github.com/vibing/zgrnet/pkg/noise"
)

// stream wraps kcp.Stream for peer-specific operations.
type stream = kcp.Stream

// mux wraps kcp.Mux for peer-specific operations.
type mux = kcp.Mux

// Stream is a multiplexed reliable stream over KCP.
type Stream = kcp.Stream

// initMux initializes the Mux for a peer (called lazily).
func (u *UDP) initMux(peer *peerState, isClient bool) {
	peer.muxOnce.Do(func() {
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

		// Assign under lock to avoid race with decryptTransport
		peer.mu.Lock()
		peer.acceptChan = acceptChan
		peer.inboundChan = inboundChan
		peer.mux = m
		peer.mu.Unlock()

		// Start the Mux update goroutine
		u.wg.Add(1)
		go func() {
			defer u.wg.Done()
			u.muxUpdateLoop(peer)
		}()
	})
}

// muxUpdateLoop periodically updates the Mux for KCP retransmissions.
func (u *UDP) muxUpdateLoop(peer *peerState) {
	ticker := time.NewTicker(1 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			peer.mu.RLock()
			m := peer.mux
			peer.mu.RUnlock()

			if m != nil && !m.IsClosed() {
				m.Update(uint32(time.Now().UnixMilli()))
			} else {
				return
			}
		}

		// Check if UDP is closed
		if u.closed.Load() {
			return
		}
	}
}

// sendToPeer sends data to a peer with the given protocol byte.
func (u *UDP) sendToPeer(peer *peerState, protocol byte, data []byte) error {
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
// The peer must be in established state.
func (u *UDP) OpenStream(pk noise.PublicKey) (*Stream, error) {
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
	peer.mu.RUnlock()

	if state != PeerStateEstablished {
		return nil, ErrNoSession
	}

	// Initialize Mux if not already done (as client - we initiate streams)
	u.initMux(peer, true)

	return peer.mux.OpenStream()
}

// AcceptStream accepts an incoming KCP stream from the specified peer.
// This blocks until a stream is available or the UDP is closed.
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

	// Initialize Mux if not already done (as server - we accept streams)
	u.initMux(peer, false)

	select {
	case s := <-peer.acceptChan:
		return s, nil
	case <-u.closedChan():
		return nil, ErrClosed
	}
}

// closedChan returns a channel that's closed when UDP is closed.
func (u *UDP) closedChan() <-chan struct{} {
	// This is a simple implementation; a more efficient one would use
	// a dedicated close channel
	ch := make(chan struct{})
	go func() {
		for !u.closed.Load() {
			time.Sleep(100 * time.Millisecond)
		}
		close(ch)
	}()
	return ch
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
	case <-u.closedChan():
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

// GetMux returns the Mux for a peer, initializing it if necessary.
// isClient determines stream ID allocation.
func (u *UDP) GetMux(pk noise.PublicKey, isClient bool) (*mux, error) {
	if u.closed.Load() {
		return nil, ErrClosed
	}

	u.mu.RLock()
	peer, exists := u.peers[pk]
	u.mu.RUnlock()

	if !exists {
		return nil, ErrPeerNotFound
	}

	u.initMux(peer, isClient)
	return peer.mux, nil
}
