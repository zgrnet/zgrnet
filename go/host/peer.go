package host

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/vibing/zgrnet/noise"
)

// PeerState represents the connection state of a peer.
type PeerState int

const (
	// PeerStateIdle indicates the peer is not connected.
	PeerStateIdle PeerState = iota
	// PeerStateConnecting indicates a handshake is in progress.
	PeerStateConnecting
	// PeerStateEstablished indicates the connection is established.
	PeerStateEstablished
	// PeerStateFailed indicates the connection attempt failed.
	PeerStateFailed
)

func (s PeerState) String() string {
	switch s {
	case PeerStateIdle:
		return "idle"
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

// Peer represents a remote node in the network.
type Peer struct {
	mu sync.RWMutex

	// Identity
	publicKey noise.PublicKey

	// Connection state
	state    PeerState
	endpoint noise.Addr    // Current active endpoint
	session  *noise.Session // Active session (nil if not established)

	// Timestamps
	lastHandshake time.Time
	lastActivity  time.Time
	createdAt     time.Time

	// MTU (Path MTU Discovery)
	mtu uint16

	// Statistics
	txBytes atomic.Uint64
	rxBytes atomic.Uint64
	txPkts  atomic.Uint64
	rxPkts  atomic.Uint64
}

// PeerConfig contains the configuration for creating a peer.
type PeerConfig struct {
	PublicKey noise.PublicKey
	Endpoint  noise.Addr
	MTU       uint16 // Default: 1280 (IPv6 minimum)
}

// NewPeer creates a new peer with the given configuration.
func NewPeer(cfg PeerConfig) *Peer {
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1280 // IPv6 minimum MTU
	}

	return &Peer{
		publicKey: cfg.PublicKey,
		endpoint:  cfg.Endpoint,
		state:     PeerStateIdle,
		mtu:       mtu,
		createdAt: time.Now(),
	}
}

// PublicKey returns the peer's public key.
func (p *Peer) PublicKey() noise.PublicKey {
	return p.publicKey
}

// State returns the current connection state.
func (p *Peer) State() PeerState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// SetState updates the connection state.
func (p *Peer) SetState(state PeerState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = state
}

// Endpoint returns the current active endpoint.
func (p *Peer) Endpoint() noise.Addr {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.endpoint
}

// SetEndpoint updates the endpoint (for roaming support).
func (p *Peer) SetEndpoint(addr noise.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.endpoint = addr
}

// Session returns the active session.
func (p *Peer) Session() *noise.Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.session
}

// SetSession sets the active session and updates state to established.
func (p *Peer) SetSession(session *noise.Session) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.session = session
	if session != nil {
		p.state = PeerStateEstablished
		p.lastHandshake = time.Now()
	}
}

// ClearSession clears the session and sets state to idle.
func (p *Peer) ClearSession() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.session != nil {
		p.session.Expire()
	}
	p.session = nil
	p.state = PeerStateIdle
}

// MTU returns the path MTU for this peer.
func (p *Peer) MTU() uint16 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.mtu
}

// SetMTU updates the path MTU.
func (p *Peer) SetMTU(mtu uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mtu = mtu
}

// LastHandshake returns when the last successful handshake occurred.
func (p *Peer) LastHandshake() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastHandshake
}

// LastActivity returns when the last activity (send/recv) occurred.
func (p *Peer) LastActivity() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastActivity
}

// UpdateActivity updates the last activity timestamp.
func (p *Peer) UpdateActivity() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastActivity = time.Now()
}

// CreatedAt returns when the peer was created.
func (p *Peer) CreatedAt() time.Time {
	return p.createdAt
}

// AddTxBytes adds to the transmitted bytes counter.
func (p *Peer) AddTxBytes(n uint64) {
	p.txBytes.Add(n)
	p.txPkts.Add(1)
}

// AddRxBytes adds to the received bytes counter.
func (p *Peer) AddRxBytes(n uint64) {
	p.rxBytes.Add(n)
	p.rxPkts.Add(1)
}

// TxBytes returns the total transmitted bytes.
func (p *Peer) TxBytes() uint64 {
	return p.txBytes.Load()
}

// RxBytes returns the total received bytes.
func (p *Peer) RxBytes() uint64 {
	return p.rxBytes.Load()
}

// TxPackets returns the total transmitted packets.
func (p *Peer) TxPackets() uint64 {
	return p.txPkts.Load()
}

// RxPackets returns the total received packets.
func (p *Peer) RxPackets() uint64 {
	return p.rxPkts.Load()
}

// IsEstablished returns true if the peer has an established connection.
func (p *Peer) IsEstablished() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state == PeerStateEstablished && p.session != nil
}

// IsExpired returns true if the peer's session has expired.
func (p *Peer) IsExpired() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.session == nil {
		return false
	}
	return p.session.IsExpired()
}

// PeerInfo contains read-only information about a peer.
type PeerInfo struct {
	PublicKey     noise.PublicKey
	Endpoint      string
	State         PeerState
	LastHandshake time.Time
	LastActivity  time.Time
	MTU           uint16
	TxBytes       uint64
	RxBytes       uint64
	TxPackets     uint64
	RxPackets     uint64
}

// Info returns a snapshot of the peer's information.
func (p *Peer) Info() PeerInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	endpoint := ""
	if p.endpoint != nil {
		endpoint = p.endpoint.String()
	}

	return PeerInfo{
		PublicKey:     p.publicKey,
		Endpoint:      endpoint,
		State:         p.state,
		LastHandshake: p.lastHandshake,
		LastActivity:  p.lastActivity,
		MTU:           p.mtu,
		TxBytes:       p.txBytes.Load(),
		RxBytes:       p.rxBytes.Load(),
		TxPackets:     p.txPkts.Load(),
		RxPackets:     p.rxPkts.Load(),
	}
}
