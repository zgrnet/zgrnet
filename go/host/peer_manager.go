package host

import (
	"errors"
	"sync"
	"time"

	"github.com/vibing/zgrnet/noise"
)

// pendingHandshake tracks an in-progress handshake.
type pendingHandshake struct {
	peer      *Peer
	hsState   *noise.HandshakeState
	localIdx  uint32
	done      chan error
	createdAt time.Time
}

// PeerManager manages all peers and their connections.
// It provides routing based on session index and public key lookup.
type PeerManager struct {
	mu sync.RWMutex

	// Peer lookup
	byPubkey map[noise.PublicKey]*Peer
	byIndex  map[uint32]*Peer // session index -> peer

	// Pending handshakes (by local index)
	pending map[uint32]*pendingHandshake

	// Local identity
	localKey *noise.KeyPair

	// Transport (shared for all peers)
	transport noise.Transport
}

// NewPeerManager creates a new peer manager.
func NewPeerManager(localKey *noise.KeyPair, transport noise.Transport) *PeerManager {
	return &PeerManager{
		byPubkey:  make(map[noise.PublicKey]*Peer),
		byIndex:   make(map[uint32]*Peer),
		pending:   make(map[uint32]*pendingHandshake),
		localKey:  localKey,
		transport: transport,
	}
}

// AddPeer registers a new peer.
// If a peer with the same public key already exists, it returns an error.
func (pm *PeerManager) AddPeer(peer *Peer) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pk := peer.PublicKey()
	if _, exists := pm.byPubkey[pk]; exists {
		return ErrPeerExists
	}

	pm.byPubkey[pk] = peer
	return nil
}

// RemovePeer removes a peer by public key.
func (pm *PeerManager) RemovePeer(pk noise.PublicKey) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	peer, exists := pm.byPubkey[pk]
	if !exists {
		return
	}

	// Remove from index mapping
	if session := peer.Session(); session != nil {
		delete(pm.byIndex, session.LocalIndex())
	}

	// Clear the session
	peer.ClearSession()

	delete(pm.byPubkey, pk)
}

// GetPeer returns a peer by public key.
func (pm *PeerManager) GetPeer(pk noise.PublicKey) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.byPubkey[pk]
}

// GetPeerByIndex returns a peer by session index.
func (pm *PeerManager) GetPeerByIndex(index uint32) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.byIndex[index]
}

// ListPeers returns all peers.
func (pm *PeerManager) ListPeers() []*Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	peers := make([]*Peer, 0, len(pm.byPubkey))
	for _, peer := range pm.byPubkey {
		peers = append(peers, peer)
	}
	return peers
}

// Count returns the number of peers.
func (pm *PeerManager) Count() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.byPubkey)
}

// Dial initiates a connection to a peer.
// The peer must already be registered with AddPeer.
// This method blocks until the handshake completes or times out.
func (pm *PeerManager) Dial(pk noise.PublicKey) error {
	return pm.DialWithTimeout(pk, 10*time.Second)
}

// DialWithTimeout initiates a connection with a custom timeout.
func (pm *PeerManager) DialWithTimeout(pk noise.PublicKey, timeout time.Duration) error {
	peer := pm.GetPeer(pk)
	if peer == nil {
		return ErrPeerNotFound
	}

	if peer.IsEstablished() {
		return nil // Already connected
	}

	endpoint := peer.Endpoint()
	if endpoint == nil {
		return ErrNoEndpoint
	}

	// Start async handshake
	done, err := pm.dialAsync(peer, endpoint)
	if err != nil {
		return err
	}

	// Wait for completion or timeout
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		// Clean up pending handshake
		pm.mu.Lock()
		for idx, p := range pm.pending {
			if p.peer == peer {
				delete(pm.pending, idx)
				break
			}
		}
		pm.mu.Unlock()
		peer.SetState(PeerStateFailed)
		return ErrHandshakeTimeout
	}
}

// dialAsync starts a handshake without blocking.
// Returns a channel that receives nil on success or an error on failure.
func (pm *PeerManager) dialAsync(peer *Peer, endpoint noise.Addr) (chan error, error) {
	peer.SetState(PeerStateConnecting)

	// Generate local index
	localIdx, err := noise.GenerateIndex()
	if err != nil {
		peer.SetState(PeerStateFailed)
		return nil, err
	}

	// Create handshake state (IK pattern - we know remote's public key)
	remotePK := peer.publicKey
	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:      noise.PatternIK,
		Initiator:    true,
		LocalStatic:  pm.localKey,
		RemoteStatic: &remotePK,
	})
	if err != nil {
		peer.SetState(PeerStateFailed)
		return nil, err
	}

	// Generate handshake initiation message
	msg1, err := hs.WriteMessage(nil)
	if err != nil {
		peer.SetState(PeerStateFailed)
		return nil, err
	}

	// Build wire message
	wireMsg := noise.BuildHandshakeInit(localIdx, hs.LocalEphemeral(), msg1[noise.KeySize:])

	// Register pending handshake before sending (to handle fast responses)
	done := make(chan error, 1)
	pm.mu.Lock()
	pm.pending[localIdx] = &pendingHandshake{
		peer:      peer,
		hsState:   hs,
		localIdx:  localIdx,
		done:      done,
		createdAt: time.Now(),
	}
	pm.mu.Unlock()

	// Send handshake initiation
	if err := pm.transport.SendTo(wireMsg, endpoint); err != nil {
		pm.mu.Lock()
		delete(pm.pending, localIdx)
		pm.mu.Unlock()
		peer.SetState(PeerStateFailed)
		return nil, err
	}

	return done, nil
}

// HandleHandshakeResp processes an incoming handshake response.
// This is called by the receive loop when a response is received.
func (pm *PeerManager) HandleHandshakeResp(data []byte, from noise.Addr) error {
	resp, err := noise.ParseHandshakeResp(data)
	if err != nil {
		return err
	}

	pm.mu.Lock()
	pending, exists := pm.pending[resp.ReceiverIndex]
	if !exists {
		pm.mu.Unlock()
		return ErrNoPendingHandshake
	}
	delete(pm.pending, resp.ReceiverIndex)
	pm.mu.Unlock()

	peer := pending.peer
	hs := pending.hsState

	// Reconstruct the noise message and process
	noiseMsg := make([]byte, noise.KeySize+16)
	copy(noiseMsg[:noise.KeySize], resp.Ephemeral[:])
	copy(noiseMsg[noise.KeySize:], resp.Empty)

	if _, err := hs.ReadMessage(noiseMsg); err != nil {
		peer.SetState(PeerStateFailed)
		pending.done <- err
		return err
	}

	// Get transport keys
	sendCS, recvCS, err := hs.Split()
	if err != nil {
		peer.SetState(PeerStateFailed)
		pending.done <- err
		return err
	}

	// Create session
	session, err := noise.NewSession(noise.SessionConfig{
		LocalIndex:  pending.localIdx,
		RemoteIndex: resp.SenderIndex,
		SendKey:     sendCS.Key(),
		RecvKey:     recvCS.Key(),
		RemotePK:    peer.publicKey,
	})
	if err != nil {
		peer.SetState(PeerStateFailed)
		pending.done <- err
		return err
	}

	// Register session
	pm.mu.Lock()
	peer.SetSession(session)
	pm.byIndex[session.LocalIndex()] = peer
	pm.mu.Unlock()

	// Update endpoint (roaming support)
	peer.SetEndpoint(from)

	// Signal success
	pending.done <- nil
	return nil
}

// HandleHandshakeInit processes an incoming handshake initiation.
// If the peer is known, it accepts the handshake and establishes a session.
// If the peer is unknown, it creates a new peer (if allowUnknown is true).
func (pm *PeerManager) HandleHandshakeInit(data []byte, from noise.Addr, allowUnknown bool) error {
	msg, err := noise.ParseHandshakeInit(data)
	if err != nil {
		return err
	}

	// Create a connection to process the handshake
	conn, err := noise.NewConn(noise.ConnConfig{
		LocalKey:   pm.localKey,
		Transport:  pm.transport,
		RemoteAddr: from,
	})
	if err != nil {
		return err
	}

	// Process the handshake (this extracts the remote public key)
	resp, err := conn.Accept(msg)
	if err != nil {
		return err
	}

	remotePK := conn.RemotePublicKey()
	session := conn.Session()
	if session == nil {
		return ErrHandshakeFailed
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if we know this peer
	peer, exists := pm.byPubkey[remotePK]
	if !exists {
		if !allowUnknown {
			return ErrUnknownPeer
		}
		// Create a new peer for this connection
		peer = NewPeer(PeerConfig{
			PublicKey: remotePK,
			Endpoint:  from,
		})
		pm.byPubkey[remotePK] = peer
	}

	// Remove old session index mapping if exists
	if oldSession := peer.Session(); oldSession != nil {
		delete(pm.byIndex, oldSession.LocalIndex())
	}

	// Update peer with new session
	peer.SetSession(session)
	peer.SetEndpoint(from) // Update endpoint (roaming)
	pm.byIndex[session.LocalIndex()] = peer

	// Send the response
	return pm.transport.SendTo(resp, from)
}

// HandleTransport processes an incoming transport message.
// Returns the peer, protocol, and payload if successful.
func (pm *PeerManager) HandleTransport(data []byte, from noise.Addr) (*Peer, byte, []byte, error) {
	msg, err := noise.ParseTransportMessage(data)
	if err != nil {
		return nil, 0, nil, err
	}

	pm.mu.RLock()
	peer := pm.byIndex[msg.ReceiverIndex]
	pm.mu.RUnlock()

	if peer == nil {
		return nil, 0, nil, ErrSessionNotFound
	}

	session := peer.Session()
	if session == nil {
		return nil, 0, nil, ErrSessionNotFound
	}

	// Decrypt
	plaintext, err := session.Decrypt(msg.Ciphertext, msg.Counter)
	if err != nil {
		return nil, 0, nil, err
	}

	// Decode protocol and payload
	protocol, payload, err := noise.DecodePayload(plaintext)
	if err != nil {
		return nil, 0, nil, err
	}

	// Update stats and roaming
	peer.AddRxBytes(uint64(len(data)))
	peer.UpdateActivity()

	// Roaming: update endpoint if it changed (only after successful decrypt)
	currentEndpoint := peer.Endpoint()
	if currentEndpoint == nil || currentEndpoint.String() != from.String() {
		peer.SetEndpoint(from)
	}

	return peer, protocol, payload, nil
}

// Send sends an encrypted message to a peer.
func (pm *PeerManager) Send(pk noise.PublicKey, protocol byte, payload []byte) error {
	peer := pm.GetPeer(pk)
	if peer == nil {
		return ErrPeerNotFound
	}

	if !peer.IsEstablished() {
		return ErrNotEstablished
	}

	session := peer.Session()
	if session == nil {
		return ErrNotEstablished
	}

	endpoint := peer.Endpoint()
	if endpoint == nil {
		return ErrNoEndpoint
	}

	// Encode payload with protocol
	plaintext := noise.EncodePayload(protocol, payload)

	// Encrypt
	ciphertext, counter, err := session.Encrypt(plaintext)
	if err != nil {
		return err
	}

	// Build and send message
	msg := noise.BuildTransportMessage(session.RemoteIndex(), counter, ciphertext)

	peer.AddTxBytes(uint64(len(msg)))
	peer.UpdateActivity()

	return pm.transport.SendTo(msg, endpoint)
}

// ExpireStale removes peers with expired sessions.
// Returns the number of peers removed.
func (pm *PeerManager) ExpireStale() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var expired []*Peer
	for _, peer := range pm.byPubkey {
		if peer.IsExpired() {
			expired = append(expired, peer)
		}
	}

	for _, peer := range expired {
		if session := peer.Session(); session != nil {
			delete(pm.byIndex, session.LocalIndex())
		}
		peer.ClearSession()
	}

	return len(expired)
}

// StartMaintenance starts a background goroutine for periodic maintenance.
// Returns a stop function.
func (pm *PeerManager) StartMaintenance(interval time.Duration) func() {
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				pm.ExpireStale()
			case <-stop:
				return
			}
		}
	}()

	return func() {
		close(stop)
		<-done
	}
}

// ExpirePendingHandshakes removes handshakes that have been pending too long.
// Returns the number of handshakes expired.
func (pm *PeerManager) ExpirePendingHandshakes(maxAge time.Duration) int {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var expired []uint32
	now := time.Now()
	for idx, p := range pm.pending {
		if now.Sub(p.createdAt) > maxAge {
			expired = append(expired, idx)
		}
	}

	for _, idx := range expired {
		if p, ok := pm.pending[idx]; ok {
			p.peer.SetState(PeerStateFailed)
			select {
			case p.done <- ErrHandshakeTimeout:
			default:
			}
			delete(pm.pending, idx)
		}
	}

	return len(expired)
}

// Clear removes all peers and pending handshakes.
func (pm *PeerManager) Clear() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Cancel all pending handshakes
	for _, p := range pm.pending {
		select {
		case p.done <- ErrHostClosed:
		default:
		}
	}
	pm.pending = make(map[uint32]*pendingHandshake)

	for _, peer := range pm.byPubkey {
		peer.ClearSession()
	}

	pm.byPubkey = make(map[noise.PublicKey]*Peer)
	pm.byIndex = make(map[uint32]*Peer)
}

// PeerManager errors.
var (
	ErrPeerExists         = errors.New("host: peer already exists")
	ErrPeerNotFound       = errors.New("host: peer not found")
	ErrNoEndpoint         = errors.New("host: peer has no endpoint")
	ErrHandshakeFailed    = errors.New("host: handshake failed")
	ErrHandshakeTimeout   = errors.New("host: handshake timed out")
	ErrNoPendingHandshake = errors.New("host: no pending handshake for index")
	ErrUnknownPeer        = errors.New("host: unknown peer")
	ErrSessionNotFound    = errors.New("host: session not found")
	ErrNotEstablished     = errors.New("host: connection not established")
)
