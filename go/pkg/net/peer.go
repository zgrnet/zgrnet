package net

import (
	"bytes"
	"net"
	"time"

	"github.com/vibing/zgrnet/pkg/kcp"
	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/relay"
)

// isKCPClient determines if we are the KCP client for a peer.
// Uses deterministic rule: smaller public key is client (uses odd stream IDs).
// This ensures consistent stream ID allocation regardless of who initiated the connection.
func (u *UDP) isKCPClient(remotePK noise.PublicKey) bool {
	return bytes.Compare(u.localKey.Public[:], remotePK[:]) < 0
}

// createServiceMux creates a new ServiceMux for a peer.
func (u *UDP) createServiceMux(peer *peerState) *kcp.ServiceMux {
	isClient := u.isKCPClient(peer.pk)

	return kcp.NewServiceMux(kcp.ServiceMuxConfig{
		IsClient: isClient,
		Output: func(service uint64, data []byte) error {
			return u.sendToPeerWithService(peer, noise.ProtocolKCP, service, data)
		},
	})
}

// sendToPeerWithService sends data to a peer with protocol + service.
func (u *UDP) sendToPeerWithService(peer *peerState, protocol byte, service uint64, data []byte) error {
	if u.routeTable == nil {
		return u.sendDirectWithService(peer, protocol, service, data)
	}

	relayPK := u.routeTable.RelayFor(peer.pk)
	if relayPK == nil {
		return u.sendDirectWithService(peer, protocol, service, data)
	}

	peer.mu.RLock()
	session := peer.session
	peer.mu.RUnlock()

	if session == nil {
		return ErrNoSession
	}

	plaintext := noise.EncodePayload(protocol, service, data)
	ciphertext, counter, err := session.Encrypt(plaintext)
	if err != nil {
		return err
	}
	type4msg := noise.BuildTransportMessage(session.RemoteIndex(), counter, ciphertext)

	relay0Data := relay.EncodeRelay0(&relay.Relay0{
		TTL:      relay.DefaultTTL,
		Strategy: relay.StrategyAuto,
		DstKey:   [32]byte(peer.pk),
		Payload:  type4msg,
	})

	u.mu.RLock()
	relayPeer, exists := u.peers[*relayPK]
	u.mu.RUnlock()
	if !exists {
		return ErrPeerNotFound
	}

	return u.sendDirect(relayPeer, noise.ProtocolRelay0, relay0Data)
}

// sendDirectWithService sends data directly to a peer with protocol + service.
func (u *UDP) sendDirectWithService(peer *peerState, protocol byte, service uint64, data []byte) error {
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

	plaintext := noise.EncodePayload(protocol, service, data)
	ciphertext, counter, err := session.Encrypt(plaintext)
	if err != nil {
		return err
	}

	msg := noise.BuildTransportMessage(session.RemoteIndex(), counter, ciphertext)

	n, err := u.socket.WriteToUDP(msg, endpoint)
	if err != nil {
		return err
	}

	u.totalTx.Add(uint64(n))
	peer.mu.Lock()
	peer.txBytes += uint64(n)
	peer.mu.Unlock()

	return nil
}

// sendToPeer sends data to a peer with the given protocol byte (service=0 default).
func (u *UDP) sendToPeer(peer *peerState, protocol byte, data []byte) error {
	return u.sendToPeerWithService(peer, protocol, 0, data)
}

// sendDirect sends data directly to a peer (service=0 default).
func (u *UDP) sendDirect(peer *peerState, protocol byte, data []byte) error {
	return u.sendDirectWithService(peer, protocol, 0, data)
}

// OpenStream opens a new yamux stream to the specified peer on the given service.
func (u *UDP) OpenStream(pk noise.PublicKey, service uint64) (net.Conn, error) {
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
	m := peer.serviceMux
	peer.mu.RUnlock()

	if state != PeerStateEstablished {
		return nil, ErrNoSession
	}
	if m == nil {
		return nil, ErrNoSession
	}

	return m.OpenStream(service)
}

// AcceptStream accepts an incoming yamux stream from the specified peer.
// Returns the stream, service ID, and any error.
func (u *UDP) AcceptStream(pk noise.PublicKey) (net.Conn, uint64, error) {
	if u.closed.Load() {
		return nil, 0, ErrClosed
	}

	u.mu.RLock()
	peer, exists := u.peers[pk]
	u.mu.RUnlock()

	if !exists {
		return nil, 0, ErrPeerNotFound
	}

	peer.mu.RLock()
	m := peer.serviceMux
	peer.mu.RUnlock()

	if m == nil {
		return nil, 0, ErrNoSession
	}

	return m.AcceptStream()
}

// closedChan returns a channel that's closed when UDP is closed.
func (u *UDP) closedChan() <-chan struct{} {
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

	peer.mu.RLock()
	inboundChan := peer.inboundChan
	peer.mu.RUnlock()

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

// GetServiceMux returns the ServiceMux for a peer.
func (u *UDP) GetServiceMux(pk noise.PublicKey) (*kcp.ServiceMux, error) {
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
	m := peer.serviceMux
	peer.mu.RUnlock()

	if m == nil {
		return nil, ErrNoSession
	}

	return m, nil
}
