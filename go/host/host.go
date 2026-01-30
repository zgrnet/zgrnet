package host

import (
	"errors"
	"log"
	"sync"
	"time"

	"github.com/vibing/zgrnet/noise"
)

// Message represents a received message from a peer.
type Message struct {
	From     noise.PublicKey
	Protocol byte
	Data     []byte
}

// HostConfig contains configuration for creating a Host.
type HostConfig struct {
	// PrivateKey is the host's identity key pair.
	// If nil, a new key pair will be generated.
	PrivateKey *noise.KeyPair

	// ListenAddr is the address to listen on (e.g., ":51820").
	// Required for accepting incoming connections.
	ListenAddr string

	// Transport allows injecting a custom transport (for testing).
	// If nil and ListenAddr is provided, a UDP transport will be created.
	Transport noise.Transport

	// MTU is the default MTU for new peers (default: 1280).
	MTU uint16

	// AllowUnknownPeers determines whether to accept connections from unknown peers.
	AllowUnknownPeers bool
}

// Host is the main entry point for ZigNet networking.
// It manages the local identity, peer connections, and message routing.
type Host struct {
	mu sync.RWMutex

	// Identity
	keyPair *noise.KeyPair

	// Networking
	transport   noise.Transport
	peerManager *PeerManager

	// Configuration
	config HostConfig

	// Message queue for Recv()
	inbox chan *Message

	// Lifecycle
	closed bool
	done   chan struct{}
	wg     sync.WaitGroup
}

// NewHost creates a new Host with the given configuration.
func NewHost(cfg HostConfig) (*Host, error) {
	// Generate key pair if not provided
	keyPair := cfg.PrivateKey
	if keyPair == nil {
		var err error
		keyPair, err = noise.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
	}

	// Use provided transport or create one
	transport := cfg.Transport
	if transport == nil && cfg.ListenAddr != "" {
		// For now, we don't have a real UDP listener transport
		// This would be: transport, err = NewUDPListenerTransport(cfg.ListenAddr)
		return nil, ErrNoTransport
	}
	if transport == nil {
		return nil, ErrNoTransport
	}

	h := &Host{
		keyPair:   keyPair,
		transport: transport,
		config:    cfg,
		inbox:     make(chan *Message, 256),
		done:      make(chan struct{}),
	}

	h.peerManager = NewPeerManager(keyPair, transport)

	// Start receive loop
	h.wg.Add(1)
	go h.receiveLoop()

	// Start maintenance
	h.wg.Add(1)
	go h.maintenanceLoop()

	return h, nil
}

// PublicKey returns the host's public key.
func (h *Host) PublicKey() noise.PublicKey {
	return h.keyPair.Public
}

// AddPeer adds a new peer to the host.
func (h *Host) AddPeer(pk noise.PublicKey, endpoint noise.Addr) error {
	mtu := h.config.MTU
	if mtu == 0 {
		mtu = 1280
	}

	peer := NewPeer(PeerConfig{
		PublicKey: pk,
		Endpoint:  endpoint,
		MTU:       mtu,
	})

	return h.peerManager.AddPeer(peer)
}

// RemovePeer removes a peer from the host.
func (h *Host) RemovePeer(pk noise.PublicKey) {
	h.peerManager.RemovePeer(pk)
}

// GetPeer returns information about a peer.
func (h *Host) GetPeer(pk noise.PublicKey) *PeerInfo {
	peer := h.peerManager.GetPeer(pk)
	if peer == nil {
		return nil
	}
	info := peer.Info()
	return &info
}

// ListPeers returns information about all peers.
func (h *Host) ListPeers() []PeerInfo {
	peers := h.peerManager.ListPeers()
	infos := make([]PeerInfo, len(peers))
	for i, peer := range peers {
		infos[i] = peer.Info()
	}
	return infos
}

// Connect initiates a connection to a peer.
// The peer must be added first with AddPeer.
func (h *Host) Connect(pk noise.PublicKey) error {
	return h.peerManager.Dial(pk)
}

// Disconnect closes the connection to a peer.
// The peer remains registered and can be reconnected.
func (h *Host) Disconnect(pk noise.PublicKey) error {
	peer := h.peerManager.GetPeer(pk)
	if peer == nil {
		return ErrPeerNotFound
	}

	peer.ClearSession()
	return nil
}

// Send sends a message to a peer.
func (h *Host) Send(pk noise.PublicKey, protocol byte, data []byte) error {
	return h.peerManager.Send(pk, protocol, data)
}

// Recv waits for and returns the next incoming message.
// This is a blocking call.
func (h *Host) Recv() (*Message, error) {
	select {
	case msg := <-h.inbox:
		return msg, nil
	case <-h.done:
		return nil, ErrHostClosed
	}
}

// RecvTimeout waits for the next message with a timeout.
func (h *Host) RecvTimeout(timeout time.Duration) (*Message, error) {
	select {
	case msg := <-h.inbox:
		return msg, nil
	case <-time.After(timeout):
		return nil, ErrTimeout
	case <-h.done:
		return nil, ErrHostClosed
	}
}

// Close shuts down the host.
func (h *Host) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	close(h.done)
	h.mu.Unlock()

	// Close transport first to unblock receiveLoop
	var transportErr error
	if h.transport != nil {
		transportErr = h.transport.Close()
	}

	// Wait for goroutines to stop
	h.wg.Wait()

	// Clear all peers
	h.peerManager.Clear()

	return transportErr
}

// receiveLoop handles incoming packets.
func (h *Host) receiveLoop() {
	defer h.wg.Done()

	buf := make([]byte, noise.MaxPacketSize)

	for {
		select {
		case <-h.done:
			return
		default:
		}

		n, from, err := h.transport.RecvFrom(buf)
		if err != nil {
			// Check if we're closing
			h.mu.RLock()
			closed := h.closed
			h.mu.RUnlock()
			if closed {
				return
			}
			continue
		}

		if n < 1 {
			continue
		}

		msgType := buf[0]

		switch msgType {
		case noise.MessageTypeHandshakeInit:
			h.handleHandshakeInit(buf[:n], from)

		case noise.MessageTypeHandshakeResp:
			h.handleHandshakeResp(buf[:n], from)

		case noise.MessageTypeTransport:
			h.handleTransport(buf[:n], from)
		}
	}
}

// handleHandshakeInit processes incoming handshake initiations.
func (h *Host) handleHandshakeInit(data []byte, from noise.Addr) {
	if err := h.peerManager.HandleHandshakeInit(data, from, h.config.AllowUnknownPeers); err != nil {
		// TODO: Use a more structured logger.
		log.Printf("host: failed to handle handshake init from %s: %v", from.String(), err)
	}
}

// handleHandshakeResp processes incoming handshake responses.
func (h *Host) handleHandshakeResp(data []byte, from noise.Addr) {
	if err := h.peerManager.HandleHandshakeResp(data, from); err != nil {
		// TODO: Use a more structured logger.
		log.Printf("host: failed to handle handshake response from %s: %v", from.String(), err)
	}
}

// handleTransport processes incoming transport messages.
func (h *Host) handleTransport(data []byte, from noise.Addr) {
	peer, protocol, payload, err := h.peerManager.HandleTransport(data, from)
	if err != nil {
		return
	}

	// Queue message for Recv()
	msg := &Message{
		From:     peer.PublicKey(),
		Protocol: protocol,
		Data:     payload,
	}

	select {
	case h.inbox <- msg:
	default:
		// Inbox full, drop message.
		// TODO: Use a more structured logger and consider adding a metric for this.
		log.Printf("host: inbox full, dropping message from %x", msg.From[:8])
	}
}

// maintenanceLoop performs periodic maintenance tasks.
func (h *Host) maintenanceLoop() {
	defer h.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.peerManager.ExpireStale()
			h.peerManager.ExpirePendingHandshakes(30 * time.Second)
		case <-h.done:
			return
		}
	}
}

// Host errors.
var (
	ErrNoTransport = errors.New("host: no transport provided")
	ErrHostClosed  = errors.New("host: host is closed")
	ErrTimeout     = errors.New("host: operation timed out")
)
