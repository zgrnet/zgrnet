// Package net provides network abstractions built on the Noise Protocol.
package net

import (
	"errors"
	"iter"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vibing/zgrnet/conn"
	"github.com/vibing/zgrnet/noise"
)

// PeerState represents the connection state of a peer.
type PeerState int

const (
	// PeerStateNew indicates a newly registered peer.
	PeerStateNew PeerState = iota
	// PeerStateConnecting indicates the peer is performing handshake.
	PeerStateConnecting
	// PeerStateEstablished indicates the peer has an active session.
	PeerStateEstablished
	// PeerStateFailed indicates the connection attempt failed.
	PeerStateFailed
)

func (s PeerState) String() string {
	switch s {
	case PeerStateNew:
		return "new"
	case PeerStateConnecting:
		return "connecting"
	case PeerStateEstablished:
		return "established"
	case PeerStateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// HostInfo contains information about the local host.
type HostInfo struct {
	PublicKey noise.PublicKey
	Addr      net.Addr
	PeerCount int
	RxBytes   uint64
	TxBytes   uint64
	LastSeen  time.Time
}

// PeerInfo contains information about a peer.
type PeerInfo struct {
	PublicKey noise.PublicKey
	Endpoint  net.Addr
	State     PeerState
	RxBytes   uint64
	TxBytes   uint64
	LastSeen  time.Time
}

// Peer represents a complete peer with info and connection.
type Peer struct {
	Info *PeerInfo
	Conn *conn.Conn
}

// Errors
var (
	ErrClosed          = errors.New("net: udp closed")
	ErrPeerNotFound    = errors.New("net: peer not found")
	ErrNoEndpoint      = errors.New("net: peer has no endpoint")
	ErrNoSession       = errors.New("net: peer has no established session")
	ErrHandshakeFailed = errors.New("net: handshake failed")
)

// UDP represents a UDP-based network using the Noise Protocol.
// It manages multiple peers, handles handshakes, and supports roaming.
type UDP struct {
	socket   *net.UDPConn
	localKey *noise.KeyPair

	// Options
	allowUnknown bool

	// Peer management
	mu      sync.RWMutex
	peers   map[noise.PublicKey]*peerState
	byIndex map[uint32]*peerState // lookup by session index

	// Pending handshakes (as initiator)
	pending map[uint32]*pendingHandshake

	// Statistics
	totalRx  atomic.Uint64
	totalTx  atomic.Uint64
	lastSeen atomic.Value // time.Time

	// State
	closed atomic.Bool
}

// peerState holds the internal state for a peer.
type peerState struct {
	mu       sync.RWMutex
	pk       noise.PublicKey
	endpoint *net.UDPAddr
	session  *noise.Session
	hsState  *noise.HandshakeState // during handshake
	state    PeerState
	rxBytes  uint64
	txBytes  uint64
	lastSeen time.Time
}

// pendingHandshake tracks an outgoing handshake.
type pendingHandshake struct {
	peer      *peerState
	hsState   *noise.HandshakeState
	localIdx  uint32
	done      chan error
	createdAt time.Time
}

// Option configures UDP options.
type Option func(*options)

type options struct {
	bindAddr     string
	allowUnknown bool
}

// WithBindAddr sets the local address to bind to.
// Default is ":0" (random port).
func WithBindAddr(addr string) Option {
	return func(o *options) {
		o.bindAddr = addr
	}
}

// WithAllowUnknown allows accepting connections from unknown peers.
func WithAllowUnknown(allow bool) Option {
	return func(o *options) {
		o.allowUnknown = allow
	}
}

// NewUDP creates a new UDP network.
func NewUDP(key *noise.KeyPair, opts ...Option) (*UDP, error) {
	if key == nil {
		return nil, errors.New("net: key is required")
	}

	// Apply options
	o := &options{
		bindAddr: ":0",
	}
	for _, opt := range opts {
		opt(o)
	}

	// Resolve and bind address
	addr, err := net.ResolveUDPAddr("udp", o.bindAddr)
	if err != nil {
		return nil, err
	}

	socket, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	u := &UDP{
		socket:       socket,
		localKey:     key,
		allowUnknown: o.allowUnknown,
		peers:        make(map[noise.PublicKey]*peerState),
		byIndex:      make(map[uint32]*peerState),
		pending:      make(map[uint32]*pendingHandshake),
	}
	u.lastSeen.Store(time.Time{})

	return u, nil
}

// SetPeerEndpoint sets or updates a peer's endpoint address.
// If the peer doesn't exist, it creates a new peer entry.
func (u *UDP) SetPeerEndpoint(pk noise.PublicKey, endpoint net.Addr) {
	if u.closed.Load() {
		return
	}

	udpAddr, ok := endpoint.(*net.UDPAddr)
	if !ok {
		// Try to resolve string
		if addr, err := net.ResolveUDPAddr("udp", endpoint.String()); err == nil {
			udpAddr = addr
		} else {
			return
		}
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	peer, exists := u.peers[pk]
	if !exists {
		peer = &peerState{
			pk:    pk,
			state: PeerStateNew,
		}
		u.peers[pk] = peer
	}

	peer.mu.Lock()
	peer.endpoint = udpAddr
	peer.mu.Unlock()
}

// RemovePeer removes a peer and its associated state.
func (u *UDP) RemovePeer(pk noise.PublicKey) {
	u.mu.Lock()
	defer u.mu.Unlock()

	peer, exists := u.peers[pk]
	if !exists {
		return
	}

	// Remove from index map if has session
	peer.mu.RLock()
	if peer.session != nil {
		delete(u.byIndex, peer.session.LocalIndex())
	}
	peer.mu.RUnlock()

	delete(u.peers, pk)
}

// HostInfo returns information about the local host.
func (u *UDP) HostInfo() *HostInfo {
	u.mu.RLock()
	peerCount := len(u.peers)
	u.mu.RUnlock()

	lastSeen, _ := u.lastSeen.Load().(time.Time)

	return &HostInfo{
		PublicKey: u.localKey.Public,
		Addr:      u.socket.LocalAddr(),
		PeerCount: peerCount,
		RxBytes:   u.totalRx.Load(),
		TxBytes:   u.totalTx.Load(),
		LastSeen:  lastSeen,
	}
}

// PeerInfo returns information about a specific peer.
func (u *UDP) PeerInfo(pk noise.PublicKey) *PeerInfo {
	u.mu.RLock()
	peer, exists := u.peers[pk]
	u.mu.RUnlock()

	if !exists {
		return nil
	}

	peer.mu.RLock()
	defer peer.mu.RUnlock()

	var endpoint net.Addr
	if peer.endpoint != nil {
		endpoint = peer.endpoint
	}

	return &PeerInfo{
		PublicKey: peer.pk,
		Endpoint:  endpoint,
		State:     peer.state,
		RxBytes:   peer.rxBytes,
		TxBytes:   peer.txBytes,
		LastSeen:  peer.lastSeen,
	}
}

// Peers returns an iterator over all peers.
func (u *UDP) Peers() iter.Seq[*Peer] {
	return func(yield func(*Peer) bool) {
		u.mu.RLock()
		// Copy keys to avoid holding lock during iteration
		keys := make([]noise.PublicKey, 0, len(u.peers))
		for pk := range u.peers {
			keys = append(keys, pk)
		}
		u.mu.RUnlock()

		for _, pk := range keys {
			u.mu.RLock()
			ps, exists := u.peers[pk]
			u.mu.RUnlock()

			if !exists {
				continue
			}

			ps.mu.RLock()
			var endpoint net.Addr
			if ps.endpoint != nil {
				endpoint = ps.endpoint
			}
			info := &PeerInfo{
				PublicKey: ps.pk,
				Endpoint:  endpoint,
				State:     ps.state,
				RxBytes:   ps.rxBytes,
				TxBytes:   ps.txBytes,
				LastSeen:  ps.lastSeen,
			}
			ps.mu.RUnlock()

			peer := &Peer{
				Info: info,
				Conn: nil, // TODO: implement if needed
			}

			if !yield(peer) {
				return
			}
		}
	}
}

// Conn returns the conn.Conn for a peer.
// Currently returns nil as Conn is not used without rekey logic.
func (u *UDP) Conn(pk noise.PublicKey) *conn.Conn {
	// In this simplified implementation, we don't use conn.Conn
	// The session management is done directly in UDP
	return nil
}

// WriteTo sends encrypted data to a peer.
func (u *UDP) WriteTo(pk noise.PublicKey, data []byte) error {
	if u.closed.Load() {
		return ErrClosed
	}

	u.mu.RLock()
	peer, exists := u.peers[pk]
	u.mu.RUnlock()

	if !exists {
		return ErrPeerNotFound
	}

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

	// Encrypt the data
	encrypted, nonce, err := session.Encrypt(data)
	if err != nil {
		return err
	}

	// Build transport message
	msg := noise.BuildTransportMessage(session.RemoteIndex(), nonce, encrypted)

	// Send
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

// ReadFrom reads the next decrypted message from any peer.
// It handles handshakes internally and only returns transport data.
// Returns the sender's public key, number of bytes, and any error.
func (u *UDP) ReadFrom(buf []byte) (pk noise.PublicKey, n int, err error) {
	if u.closed.Load() {
		return pk, 0, ErrClosed
	}

	recvBuf := make([]byte, noise.MaxPacketSize)

	for {
		if u.closed.Load() {
			return pk, 0, ErrClosed
		}

		// Read from socket
		nr, fromAddr, err := u.socket.ReadFromUDP(recvBuf)
		if err != nil {
			if u.closed.Load() {
				return pk, 0, ErrClosed
			}
			return pk, 0, err
		}

		if nr < 1 {
			continue
		}

		// Update stats
		u.totalRx.Add(uint64(nr))
		u.lastSeen.Store(time.Now())

		// Parse message type
		msgType := recvBuf[0]

		switch msgType {
		case noise.MessageTypeHandshakeInit:
			u.handleHandshakeInit(recvBuf[:nr], fromAddr)
			continue // Don't return handshake to caller

		case noise.MessageTypeHandshakeResp:
			u.handleHandshakeResp(recvBuf[:nr], fromAddr)
			continue // Don't return handshake to caller

		case noise.MessageTypeTransport:
			pk, n, err = u.handleTransport(recvBuf[:nr], fromAddr, buf)
			if err != nil {
				continue // Try again on error
			}
			return pk, n, nil

		default:
			// Unknown message type, ignore
			continue
		}
	}
}

// handleHandshakeInit processes an incoming handshake initiation.
func (u *UDP) handleHandshakeInit(data []byte, from *net.UDPAddr) {
	msg, err := noise.ParseHandshakeInit(data)
	if err != nil {
		return
	}

	// Create handshake state to process the init
	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:     noise.PatternIK,
		Initiator:   false,
		LocalStatic: u.localKey,
	})
	if err != nil {
		return
	}

	// Build Noise message from wire format
	// Noise IK message 1: e(32) + encrypted_s(48) = 80 bytes
	noiseMsg := make([]byte, noise.KeySize+48)
	copy(noiseMsg[:noise.KeySize], msg.Ephemeral[:])
	copy(noiseMsg[noise.KeySize:], msg.Static)

	// Read the handshake message
	_, err = hs.ReadMessage(noiseMsg)
	if err != nil {
		return
	}

	// Get the remote's public key
	remotePK := hs.RemoteStatic()

	// Check if peer is known or if we allow unknown peers
	u.mu.Lock()
	peer, exists := u.peers[remotePK]
	if !exists {
		if !u.allowUnknown {
			u.mu.Unlock()
			return
		}
		// Create new peer
		peer = &peerState{
			pk:    remotePK,
			state: PeerStateNew,
		}
		u.peers[remotePK] = peer
	}
	u.mu.Unlock()

	// Generate local index for response
	localIdx, err := noise.GenerateIndex()
	if err != nil {
		return
	}

	// Write response message
	respPayload, err := hs.WriteMessage(nil)
	if err != nil {
		return
	}

	// Build wire message
	// Noise IK message 2: e(32) + encrypted_empty(16) = 48 bytes
	ephemeral := hs.LocalEphemeral()
	wireMsg := noise.BuildHandshakeResp(localIdx, msg.SenderIndex, ephemeral, respPayload[noise.KeySize:])

	// Send response
	_, err = u.socket.WriteToUDP(wireMsg, from)
	if err != nil {
		return
	}

	// Complete handshake and create session
	sendCS, recvCS, err := hs.Split()
	if err != nil {
		return
	}

	session, err := noise.NewSession(noise.SessionConfig{
		LocalIndex:  localIdx,
		RemoteIndex: msg.SenderIndex,
		SendKey:     sendCS.Key(),
		RecvKey:     recvCS.Key(),
		RemotePK:    remotePK,
	})
	if err != nil {
		return
	}

	// Update peer state
	peer.mu.Lock()
	peer.endpoint = from
	peer.session = session
	peer.state = PeerStateEstablished
	peer.lastSeen = time.Now()
	peer.mu.Unlock()

	// Register in index map
	u.mu.Lock()
	u.byIndex[localIdx] = peer
	u.mu.Unlock()
}

// handleHandshakeResp processes an incoming handshake response.
func (u *UDP) handleHandshakeResp(data []byte, from *net.UDPAddr) {
	msg, err := noise.ParseHandshakeResp(data)
	if err != nil {
		return
	}

	// Find the pending handshake by receiver index (our local index)
	u.mu.Lock()
	pending, exists := u.pending[msg.ReceiverIndex]
	if !exists {
		u.mu.Unlock()
		return
	}
	delete(u.pending, msg.ReceiverIndex)
	u.mu.Unlock()

	// Build Noise message from wire format
	// Noise IK message 2: e(32) + encrypted_empty(16) = 48 bytes
	noiseMsg := make([]byte, noise.KeySize+16)
	copy(noiseMsg[:noise.KeySize], msg.Ephemeral[:])
	copy(noiseMsg[noise.KeySize:], msg.Empty)

	// Read the handshake response
	_, err = pending.hsState.ReadMessage(noiseMsg)
	if err != nil {
		pending.peer.mu.Lock()
		pending.peer.state = PeerStateFailed
		pending.peer.mu.Unlock()
		if pending.done != nil {
			pending.done <- ErrHandshakeFailed
		}
		return
	}

	// Complete handshake and create session
	sendCS, recvCS, err := pending.hsState.Split()
	if err != nil {
		pending.peer.mu.Lock()
		pending.peer.state = PeerStateFailed
		pending.peer.mu.Unlock()
		if pending.done != nil {
			pending.done <- err
		}
		return
	}

	session, err := noise.NewSession(noise.SessionConfig{
		LocalIndex:  pending.localIdx,
		RemoteIndex: msg.SenderIndex,
		SendKey:     sendCS.Key(),
		RecvKey:     recvCS.Key(),
		RemotePK:    pending.peer.pk,
	})
	if err != nil {
		pending.peer.mu.Lock()
		pending.peer.state = PeerStateFailed
		pending.peer.mu.Unlock()
		if pending.done != nil {
			pending.done <- err
		}
		return
	}

	// Update peer state
	peer := pending.peer
	peer.mu.Lock()
	peer.endpoint = from // Roaming: update endpoint
	peer.session = session
	peer.state = PeerStateEstablished
	peer.lastSeen = time.Now()
	peer.mu.Unlock()

	// Register in index map
	u.mu.Lock()
	u.byIndex[pending.localIdx] = peer
	u.mu.Unlock()

	// Signal completion
	if pending.done != nil {
		pending.done <- nil
	}
}

// handleTransport processes an incoming transport message.
func (u *UDP) handleTransport(data []byte, from *net.UDPAddr, outBuf []byte) (pk noise.PublicKey, n int, err error) {
	msg, err := noise.ParseTransportMessage(data)
	if err != nil {
		return pk, 0, err
	}

	// Find peer by receiver index
	u.mu.RLock()
	peer, exists := u.byIndex[msg.ReceiverIndex]
	u.mu.RUnlock()

	if !exists {
		return pk, 0, ErrPeerNotFound
	}

	peer.mu.Lock()
	session := peer.session
	peer.mu.Unlock()

	if session == nil {
		return pk, 0, ErrNoSession
	}

	// Decrypt
	plaintext, err := session.Decrypt(msg.Ciphertext, msg.Counter)
	if err != nil {
		return pk, 0, err
	}

	// Copy to output buffer
	n = copy(outBuf, plaintext)

	// Update peer state (roaming + stats)
	peer.mu.Lock()
	if peer.endpoint == nil || peer.endpoint.String() != from.String() {
		peer.endpoint = from // Roaming
	}
	peer.rxBytes += uint64(len(data))
	peer.lastSeen = time.Now()
	peer.mu.Unlock()

	return peer.pk, n, nil
}

// Connect initiates a handshake with a peer.
// The peer must have an endpoint set via SetPeerEndpoint.
// A receive loop (ReadFrom) must be running to process the handshake response.
func (u *UDP) Connect(pk noise.PublicKey) error {
	if u.closed.Load() {
		return ErrClosed
	}

	u.mu.RLock()
	peer, exists := u.peers[pk]
	u.mu.RUnlock()

	if !exists {
		return ErrPeerNotFound
	}

	return u.initiateHandshake(peer)
}

// initiateHandshake starts a handshake with a peer.
// This is called internally when needed.
func (u *UDP) initiateHandshake(peer *peerState) error {
	peer.mu.Lock()
	endpoint := peer.endpoint
	pk := peer.pk
	peer.state = PeerStateConnecting
	peer.mu.Unlock()

	if endpoint == nil {
		return ErrNoEndpoint
	}

	// Generate local index
	localIdx, err := noise.GenerateIndex()
	if err != nil {
		return err
	}

	// Create handshake state
	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:      noise.PatternIK,
		Initiator:    true,
		LocalStatic:  u.localKey,
		RemoteStatic: &pk,
	})
	if err != nil {
		return err
	}

	// Write handshake initiation
	msg1, err := hs.WriteMessage(nil)
	if err != nil {
		return err
	}

	// Build wire message
	ephemeral := hs.LocalEphemeral()
	wireMsg := noise.BuildHandshakeInit(localIdx, ephemeral, msg1[noise.KeySize:])

	// Register pending handshake
	done := make(chan error, 1)
	u.mu.Lock()
	u.pending[localIdx] = &pendingHandshake{
		peer:      peer,
		hsState:   hs,
		localIdx:  localIdx,
		done:      done,
		createdAt: time.Now(),
	}
	u.mu.Unlock()

	// Send handshake initiation
	_, err = u.socket.WriteToUDP(wireMsg, endpoint)
	if err != nil {
		u.mu.Lock()
		delete(u.pending, localIdx)
		u.mu.Unlock()
		return err
	}

	// Wait for response with timeout
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		u.mu.Lock()
		delete(u.pending, localIdx)
		u.mu.Unlock()
		peer.mu.Lock()
		peer.state = PeerStateFailed
		peer.mu.Unlock()
		return errors.New("net: handshake timeout")
	}
}

// Close closes the UDP network.
func (u *UDP) Close() error {
	if u.closed.Swap(true) {
		return nil // Already closed
	}
	return u.socket.Close()
}
