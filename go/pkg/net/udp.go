// Package net provides network abstractions built on the Noise Protocol.
package net

import (
	"errors"
	"iter"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/relay"
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
	Conn *Conn
}

// Errors
var (
	ErrClosed          = errors.New("net: udp closed")
	ErrPeerNotFound    = errors.New("net: peer not found")
	ErrNoEndpoint      = errors.New("net: peer has no endpoint")
	ErrNoSession       = errors.New("net: peer has no established session")
	ErrHandshakeFailed = errors.New("net: handshake failed")
	ErrNoData          = errors.New("net: no data available")
)

// protoPacket represents a received packet with its protocol byte.
type protoPacket struct {
	protocol byte
	payload  []byte
}

// packet represents a packet in the processing pipeline.
// It carries raw data and gets decrypted in parallel by workers.
// Consumers wait on the ready channel before accessing decrypted data.
type packet struct {
	// Input (set by ioLoop)
	data []byte       // buffer from pool (owns the memory)
	n    int          // actual data length
	from *net.UDPAddr // sender address

	// Output (set by decryptWorker)
	pk       noise.PublicKey // sender's public key (after decrypt)
	protocol byte            // protocol byte
	payload  []byte          // decrypted payload (slice into data or copy)
	payloadN int             // payload length
	err      error           // decrypt error (if any)

	// Ownership: true if this packet is in outputChan (ReadFrom will release it).
	// false means decryptWorker must release it after processing.
	// Atomic because ioLoop writes it while decryptWorker reads it concurrently.
	inOutput atomic.Bool

	// Release guard: prevents double-release when multiple goroutines
	// race to release the same packet (e.g., during shutdown).
	released atomic.Bool

	// Synchronization
	ready chan struct{} // closed when decryption is complete
}

// outstandingPackets tracks the number of packets currently acquired from the pool
// but not yet released. Used for leak detection in tests.
var outstandingPackets atomic.Int64

// bufferPool provides reusable buffers for receiving UDP packets.
var bufferPool = sync.Pool{
	New: func() any {
		return make([]byte, noise.MaxPacketSize)
	},
}

// packetPool provides reusable packet structs.
var packetPool = sync.Pool{
	New: func() any {
		return &packet{
			ready: make(chan struct{}),
		}
	},
}

// acquirePacket gets a packet from the pool and resets it.
func acquirePacket() *packet {
	outstandingPackets.Add(1)
	p := packetPool.Get().(*packet)
	p.data = bufferPool.Get().([]byte)
	p.n = 0
	p.pk = noise.PublicKey{}
	p.protocol = 0
	p.payload = nil
	p.payloadN = 0
	p.err = nil
	p.inOutput.Store(false)
	p.released.Store(false)
	p.ready = make(chan struct{})
	return p
}

// releasePacket returns a packet to the pool.
// Safe to call from multiple goroutines — only the first call takes effect.
func releasePacket(p *packet) {
	if !p.released.CompareAndSwap(false, true) {
		return
	}
	outstandingPackets.Add(-1)
	if p.data != nil {
		bufferPool.Put(p.data)
		p.data = nil
	}
	packetPool.Put(p)
}

// UDP represents a UDP-based network using the Noise Protocol.
// It manages multiple peers, handles handshakes, and supports roaming.
type UDP struct {
	socket   *net.UDPConn
	localKey *noise.KeyPair

	// Socket configuration (for GSO/GRO, busy-poll, buffer sizes)
	socketConfig SocketConfig

	// Options
	allowUnknown bool

	// Relay routing and forwarding
	routeTable   *relay.RouteTable // nil = no relay; used for both forwarding and outbound wrapping
	localMetrics relay.NodeMetrics // local metrics for PONG responses

	// Peer management
	mu      sync.RWMutex
	peers   map[noise.PublicKey]*peerState
	byIndex map[uint32]*peerState // lookup by session index

	// Pending handshakes (as initiator)
	pending map[uint32]*pendingHandshake

	// Pipeline channels for async I/O processing
	decryptChan chan *packet   // ioLoop -> decryptWorkers
	outputChan  chan *packet   // ioLoop -> ReadFrom (same packet, wait for ready)
	closeChan   chan struct{}  // signal to stop goroutines
	wg          sync.WaitGroup // tracks running goroutines

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

	// Stream multiplexing (initialized when session is established)
	mux        *mux
	acceptChan chan *stream // incoming streams from remote

	// Protocol routing for non-KCP packets
	inboundChan chan protoPacket // incoming non-KCP packets
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
	bindAddr          string
	allowUnknown      bool
	decryptWorkers    int // 0 = runtime.NumCPU()
	rawChanSize       int // 0 = use RawChanSize constant
	decryptedChanSize int // 0 = use DecryptedChanSize constant
	routeTable        *relay.RouteTable
	localMetrics      relay.NodeMetrics
	socketConfig      SocketConfig
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

// WithDecryptWorkers sets the number of parallel decrypt workers.
// Default is runtime.NumCPU().
func WithDecryptWorkers(n int) Option {
	return func(o *options) {
		o.decryptWorkers = n
	}
}

// WithRouter sets the relay router for forwarding relay packets.
// If nil (default), relay packets are dropped.
// Deprecated: Use WithRouteTable instead.
func WithRouter(r relay.Router) Option {
	return func(o *options) {
		if rt, ok := r.(*relay.RouteTable); ok {
			o.routeTable = rt
		}
	}
}

// WithRouteTable sets the route table for relay forwarding and outbound wrapping.
func WithRouteTable(rt *relay.RouteTable) Option {
	return func(o *options) {
		o.routeTable = rt
	}
}

// WithLocalMetrics sets the local node metrics for PONG responses.
func WithLocalMetrics(m relay.NodeMetrics) Option {
	return func(o *options) {
		o.localMetrics = m
	}
}

// WithRawChanSize sets the raw packet channel size.
// Default is RawChanSize (4096).
func WithRawChanSize(n int) Option {
	return func(o *options) {
		o.rawChanSize = n
	}
}

// WithDecryptedChanSize sets the decrypted packet channel size.
// Default is DecryptedChanSize (256).
func WithDecryptedChanSize(n int) Option {
	return func(o *options) {
		o.decryptedChanSize = n
	}
}

// WithSocketConfig sets the socket configuration (GSO, GRO, busy-poll, buffer sizes).
// Default is DefaultSocketConfig().
func WithSocketConfig(cfg SocketConfig) Option {
	return func(o *options) {
		o.socketConfig = cfg
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

	// Apply socket configuration (ApplySocketOptions handles zero values individually)
	socketConfig := o.socketConfig
	ApplySocketOptions(socket, socketConfig)

	rawSize := o.rawChanSize
	if rawSize <= 0 {
		rawSize = RawChanSize
	}
	decryptedSize := o.decryptedChanSize
	if decryptedSize <= 0 {
		decryptedSize = DecryptedChanSize
	}

	u := &UDP{
		socket:       socket,
		localKey:     key,
		socketConfig: socketConfig,
		allowUnknown: o.allowUnknown,
		routeTable:   o.routeTable,
		localMetrics: o.localMetrics,
		peers:        make(map[noise.PublicKey]*peerState),
		byIndex:      make(map[uint32]*peerState),
		pending:      make(map[uint32]*pendingHandshake),
		decryptChan:  make(chan *packet, rawSize),
		outputChan:   make(chan *packet, decryptedSize),
		closeChan:    make(chan struct{}),
	}
	u.lastSeen.Store(time.Time{})

	// Determine number of decrypt workers
	workers := o.decryptWorkers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	// Start pipeline goroutines
	u.wg.Add(1 + workers)
	go func() {
		defer u.wg.Done()
		u.ioLoop()
	}()
	for i := 0; i < workers; i++ {
		go func() {
			defer u.wg.Done()
			u.decryptWorker()
		}()
	}

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
	session := peer.session
	peer.mu.RUnlock()
	if session != nil {
		delete(u.byIndex, session.LocalIndex())
	}

	delete(u.peers, pk)
}

// SetRouter sets the relay router for forwarding relay packets at runtime.
// Deprecated: Use SetRouteTable instead.
func (u *UDP) SetRouter(r relay.Router) {
	if rt, ok := r.(*relay.RouteTable); ok {
		u.routeTable = rt
	}
}

// SetRouteTable sets the route table at runtime.
func (u *UDP) SetRouteTable(rt *relay.RouteTable) {
	u.routeTable = rt
}

// RouteTable returns the current route table, or nil if none is set.
func (u *UDP) RouteTable() *relay.RouteTable {
	return u.routeTable
}

// SetLocalMetrics updates the local node metrics for PONG responses.
func (u *UDP) SetLocalMetrics(m relay.NodeMetrics) {
	u.localMetrics = m
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

// GetConn returns the Conn for a peer.
// Currently returns nil as Conn is not used without rekey logic.
func (u *UDP) GetConn(pk noise.PublicKey) *Conn {
	// In this simplified implementation, we don't use Conn
	// The session management is done directly in UDP
	return nil
}

// WriteTo sends encrypted data to a peer.
// Uses a default protocol byte (ProtocolRaw) for transport.
// If the peer has a relay route, data is automatically sent through the relay.
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

	return u.sendToPeer(peer, noise.ProtocolRaw, data)
}

// ReadFrom reads the next decrypted message from any peer.
// It handles handshakes internally and only returns transport data.
// Returns the sender's public key, number of bytes, and any error.
func (u *UDP) ReadFrom(buf []byte) (pk noise.PublicKey, n int, err error) {
	pk, _, n, err = u.ReadPacket(buf)
	return
}

// ReadPacket reads the next decrypted message from any peer, including the protocol byte.
// Unlike ReadFrom, this also returns the protocol byte from the encrypted payload.
// Returns the sender's public key, protocol byte, number of bytes, and any error.
func (u *UDP) ReadPacket(buf []byte) (pk noise.PublicKey, proto byte, n int, err error) {
	for {
		if u.closed.Load() {
			return pk, 0, 0, ErrClosed
		}

		// Get next packet from output queue
		var pkt *packet
		select {
		case p, ok := <-u.outputChan:
			if !ok {
				return pk, 0, 0, ErrClosed
			}
			pkt = p
		case <-u.closeChan:
			return pk, 0, 0, ErrClosed
		}

		// Wait for decryption to complete
		select {
		case <-pkt.ready:
			// Decryption done
		case <-u.closeChan:
			// Shutting down. The decrypt worker may have already exited
			// without processing this packet, so pkt.ready may never close.
			// Try non-blocking check; if not ready, abandon the packet
			// (acceptable leak during shutdown — process is exiting).
			select {
			case <-pkt.ready:
				releasePacket(pkt)
			default:
				// Packet still held by decrypt worker or abandoned; don't
				// release to avoid racing with a worker that's mid-write.
			}
			return pk, 0, 0, ErrClosed
		}

		// Check for errors (handshake, KCP routed internally, etc.)
		if pkt.err != nil {
			releasePacket(pkt)
			continue // Try next packet
		}

		// Copy decrypted data to caller's buffer
		n = copy(buf, pkt.payload[:pkt.payloadN])
		pk = pkt.pk
		proto = pkt.protocol
		releasePacket(pkt)
		return pk, proto, n, nil
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

	// Create mux resources before acquiring the lock
	muxRes := u.createMux(peer)

	// Update peer state and mux in the same lock
	// This ensures mux is ready when packets start routing to this peer
	peer.mu.Lock()
	peer.endpoint = from
	peer.session = session
	peer.mux = muxRes.mux
	peer.acceptChan = muxRes.acceptChan
	peer.inboundChan = muxRes.inboundChan
	peer.state = PeerStateEstablished
	peer.lastSeen = time.Now()
	peer.mu.Unlock()

	// Register in index map
	u.mu.Lock()
	u.byIndex[localIdx] = peer
	u.mu.Unlock()

	// Start the mux update loop
	u.startMuxUpdateLoop(muxRes.mux)
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

	// Create mux resources before acquiring the lock
	peer := pending.peer
	muxRes := u.createMux(peer)

	// Update peer state and mux in the same lock
	// This ensures mux is ready when packets start routing to this peer
	peer.mu.Lock()
	peer.endpoint = from // Roaming: update endpoint
	peer.session = session
	peer.mux = muxRes.mux
	peer.acceptChan = muxRes.acceptChan
	peer.inboundChan = muxRes.inboundChan
	peer.state = PeerStateEstablished
	peer.lastSeen = time.Now()
	peer.mu.Unlock()

	// Register in index map
	u.mu.Lock()
	u.byIndex[pending.localIdx] = peer
	u.mu.Unlock()

	// Start the mux update loop
	u.startMuxUpdateLoop(muxRes.mux)

	// Signal completion
	if pending.done != nil {
		pending.done <- nil
	}
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
// If the peer has a relay route, the handshake is sent through the relay.
// Otherwise, it is sent directly to the peer's endpoint.
func (u *UDP) initiateHandshake(peer *peerState) error {
	peer.mu.Lock()
	endpoint := peer.endpoint
	pk := peer.pk
	peer.state = PeerStateConnecting
	peer.mu.Unlock()

	// Check for relay route
	var relayPK *noise.PublicKey
	if u.routeTable != nil {
		relayPK = u.routeTable.RelayFor(pk)
	}

	// Need either a direct endpoint or a relay route
	if endpoint == nil && relayPK == nil {
		return ErrNoEndpoint
	}

	localIdx, err := noise.GenerateIndex()
	if err != nil {
		return err
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:      noise.PatternIK,
		Initiator:    true,
		LocalStatic:  u.localKey,
		RemoteStatic: &pk,
	})
	if err != nil {
		return err
	}

	msg1, err := hs.WriteMessage(nil)
	if err != nil {
		return err
	}

	ephemeral := hs.LocalEphemeral()
	wireMsg := noise.BuildHandshakeInit(localIdx, ephemeral, msg1[noise.KeySize:])

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

	if relayPK != nil {
		// Send handshake through relay: wrap in RELAY_0(dst=pk)
		relay0Data := relay.EncodeRelay0(&relay.Relay0{
			TTL:      relay.DefaultTTL,
			Strategy: relay.StrategyAuto,
			DstKey:   [32]byte(pk),
			Payload:  wireMsg,
		})

		u.mu.RLock()
		relayPeer, relayExists := u.peers[*relayPK]
		u.mu.RUnlock()

		if !relayExists {
			u.mu.Lock()
			delete(u.pending, localIdx)
			u.mu.Unlock()
			return ErrPeerNotFound
		}

		err = u.sendDirect(relayPeer, noise.ProtocolRelay0, relay0Data)
	} else {
		// Direct handshake to endpoint
		_, err = u.socket.WriteToUDP(wireMsg, endpoint)
	}

	if err != nil {
		u.mu.Lock()
		delete(u.pending, localIdx)
		u.mu.Unlock()
		return err
	}

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

	// Signal goroutines to stop
	close(u.closeChan)

	// Close socket (will unblock ioLoop's ReadFromUDP)
	err := u.socket.Close()

	// Wait for all goroutines to finish BEFORE closing channels
	// This prevents race condition where ioLoop is writing to channels
	// while we're closing them
	u.wg.Wait()

	// Now safe to close channels (all writers have exited)
	close(u.decryptChan)
	close(u.outputChan)

	return err
}

// ioLoop reads packets from the socket and dispatches them.
// Each packet goes to both decryptChan (for workers) and outputChan (for ReadFrom).
// On Linux, uses recvmmsg batch reading for reduced syscall overhead.
// This goroutine only does I/O, no decryption, to maximize throughput.
func (u *UDP) ioLoop() {
	bc := newBatchConn(u.socket, DefaultBatchSize)
	if bc != nil {
		u.ioLoopBatch(bc)
	} else {
		u.ioLoopSingle()
	}
}

// ioLoopBatch reads packets using recvmmsg (Linux).
func (u *UDP) ioLoopBatch(bc *batchConn) {
	pkts := make([]*packet, DefaultBatchSize)
	bufs := make([][]byte, DefaultBatchSize)

	for {
		if u.closed.Load() {
			return
		}

		// Acquire batch of packets from pool
		count := 0
		for count < DefaultBatchSize {
			pkts[count] = acquirePacket()
			bufs[count] = pkts[count].data
			count++
		}

		// Batch read (blocks until ≥1 packet available)
		n, err := bc.ReadBatch(bufs[:count])
		if err != nil {
			for i := 0; i < count; i++ {
				releasePacket(pkts[i])
			}
			if u.closed.Load() {
				return
			}
			continue
		}

		// Release unused packets
		for i := n; i < count; i++ {
			releasePacket(pkts[i])
		}

		// Dispatch received packets
		for i := 0; i < n; i++ {
			pkt := pkts[i]
			pkt.n = bc.ReceivedN(i)
			pkt.from = bc.ReceivedFrom(i)

			if pkt.n < 1 || pkt.from == nil {
				releasePacket(pkt)
				continue
			}

			u.totalRx.Add(uint64(pkt.n))
			u.lastSeen.Store(time.Now())

			u.dispatchToChannels(pkt)
		}
	}
}

// ioLoopSingle reads packets one at a time (non-Linux fallback).
func (u *UDP) ioLoopSingle() {
	for {
		if u.closed.Load() {
			return
		}

		pkt := acquirePacket()

		n, from, err := u.socket.ReadFromUDP(pkt.data)
		if err != nil {
			releasePacket(pkt)
			if u.closed.Load() {
				return
			}
			continue
		}

		if u.closed.Load() {
			releasePacket(pkt)
			return
		}

		if n < 1 {
			releasePacket(pkt)
			continue
		}

		pkt.n = n
		pkt.from = from

		u.totalRx.Add(uint64(n))
		u.lastSeen.Store(time.Now())

		u.dispatchToChannels(pkt)
	}
}

// dispatchToChannels sends a packet to both outputChan and decryptChan.
func (u *UDP) dispatchToChannels(pkt *packet) {
	select {
	case <-u.closeChan:
		releasePacket(pkt)
		return
	default:
	}

	select {
	case u.outputChan <- pkt:
		pkt.inOutput.Store(true)
	case <-u.closeChan:
		releasePacket(pkt)
		return
	default:
	}

	select {
	case u.decryptChan <- pkt:
	case <-u.closeChan:
		if !pkt.inOutput.Load() {
			releasePacket(pkt)
		}
		return
	default:
		if pkt.inOutput.Load() {
			pkt.err = ErrNoData
			close(pkt.ready)
		} else {
			releasePacket(pkt)
		}
	}
}

// decryptWorker processes packets from decryptChan.
// Multiple workers run in parallel for higher throughput.
// After processing, it signals ready so ReadFrom can consume.
// If the packet is not in outputChan (inOutput == false), the worker
// releases it directly to prevent pool leaks.
func (u *UDP) decryptWorker() {
	for {
		select {
		case pkt, ok := <-u.decryptChan:
			if !ok {
				return // channel closed
			}
			u.processPacket(pkt)
			close(pkt.ready)
			if !pkt.inOutput.Load() {
				releasePacket(pkt)
			}
		case <-u.closeChan:
			return
		}
	}
}

// processPacket handles a single packet - parses, decrypts, and fills result fields.
// Called by decryptWorker. Sets pkt.err if processing fails.
func (u *UDP) processPacket(pkt *packet) {
	data := pkt.data[:pkt.n]
	from := pkt.from

	if len(data) < 1 {
		pkt.err = ErrNoData
		return
	}

	// Parse message type
	msgType := data[0]

	switch msgType {
	case noise.MessageTypeHandshakeInit:
		u.handleHandshakeInit(data, from)
		pkt.err = ErrNoData // Not a data packet

	case noise.MessageTypeHandshakeResp:
		u.handleHandshakeResp(data, from)
		pkt.err = ErrNoData // Not a data packet

	case noise.MessageTypeTransport:
		u.decryptTransport(pkt, data, from)

	default:
		pkt.err = ErrNoData
	}
}

// decryptTransport decrypts a transport message and fills pkt fields.
// Also routes KCP packets to mux and non-KCP to inboundChan.
func (u *UDP) decryptTransport(pkt *packet, data []byte, from *net.UDPAddr) {
	msg, err := noise.ParseTransportMessage(data)
	if err != nil {
		pkt.err = err
		return
	}

	// Find peer by receiver index
	u.mu.RLock()
	peer, exists := u.byIndex[msg.ReceiverIndex]
	u.mu.RUnlock()

	if !exists {
		pkt.err = ErrPeerNotFound
		return
	}

	peer.mu.RLock()
	session := peer.session
	peer.mu.RUnlock()

	if session == nil {
		pkt.err = ErrNoSession
		return
	}

	// Decrypt
	plaintext, err := session.Decrypt(msg.Ciphertext, msg.Counter)
	if err != nil {
		pkt.err = err
		return
	}

	// Update peer state (roaming + stats) and get mux/inboundChan
	peer.mu.Lock()
	if peer.endpoint == nil || peer.endpoint.String() != from.String() {
		peer.endpoint = from // Roaming
	}
	peer.rxBytes += uint64(len(data))
	peer.lastSeen = time.Now()
	// Initialize inboundChan if needed (for Peer.Read callers)
	if peer.inboundChan == nil {
		peer.inboundChan = make(chan protoPacket, InboundChanSize)
	}
	inboundChan := peer.inboundChan
	muxInstance := peer.mux
	peer.mu.Unlock()

	// Fill packet fields
	pkt.pk = peer.pk

	// Parse protocol byte
	if len(plaintext) == 0 {
		// Empty keepalive packet
		pkt.err = ErrNoData
		return
	}

	protocol, _, payload, err := noise.DecodePayload(plaintext)
	if err != nil {
		pkt.err = err
		return
	}

	pkt.protocol = protocol
	// Make a copy of payload since plaintext references the pool buffer
	pkt.payload = make([]byte, len(payload))
	copy(pkt.payload, payload)
	pkt.payloadN = len(payload)

	// Route based on protocol
	switch protocol {
	case noise.ProtocolKCP:
		// mux is initialized when session is established (handshake complete)
		if muxInstance != nil {
			muxInstance.Input(payload)
		}
		// Don't deliver KCP to ReadFrom
		pkt.err = ErrNoData

	case noise.ProtocolRelay0:
		if u.routeTable != nil {
			action, err := relay.HandleRelay0(u.routeTable, pkt.pk, payload)
			if err == nil {
				u.executeRelayAction(action)
			}
		}
		pkt.err = ErrNoData // Relay packets are not delivered to ReadFrom

	case noise.ProtocolRelay1:
		if u.routeTable != nil {
			action, err := relay.HandleRelay1(u.routeTable, payload)
			if err == nil {
				u.executeRelayAction(action)
			}
		}
		pkt.err = ErrNoData

	case noise.ProtocolRelay2:
		// Last hop: extract src and inner payload.
		// The inner payload is a complete Type 4 transport message.
		// We re-process it through the normal decrypt pipeline.
		src, innerPayload, err := relay.HandleRelay2(payload)
		if err == nil && len(innerPayload) > 0 {
			u.processRelayedPacket(pkt, src, innerPayload, from)
			return // pkt fields already set by processRelayedPacket
		}
		pkt.err = ErrNoData

	case noise.ProtocolPing:
		if u.routeTable != nil {
			action, err := relay.HandlePing(pkt.pk, payload, u.localMetrics)
			if err == nil {
				u.executeRelayAction(action)
			}
		}
		pkt.err = ErrNoData

	case noise.ProtocolPong:
		// PONG responses are delivered to ReadFrom for upper layer processing.
		// The caller can decode them with relay.DecodePong().
		if inboundChan != nil {
			select {
			case inboundChan <- protoPacket{protocol: protocol, payload: pkt.payload}:
			default:
			}
		}

	default:
		// Route to inboundChan for Peer.Read() callers (non-blocking)
		if inboundChan != nil {
			select {
			case inboundChan <- protoPacket{protocol: protocol, payload: pkt.payload}:
				// Delivered to Peer.Read
			default:
				// Channel full, drop for Peer.Read path
			}
		}
		// Always leave pkt valid for ReadFrom callers
		// pkt.err remains nil so ReadFrom can deliver it
	}
}

// executeRelayAction sends a relay forwarding action to the target peer.
// Uses sendDirect because the relay engine already computed the next hop.
func (u *UDP) executeRelayAction(action *relay.Action) {
	pk := noise.PublicKey(action.Dst)

	u.mu.RLock()
	peer, exists := u.peers[pk]
	u.mu.RUnlock()

	if !exists {
		return
	}

	_ = u.sendDirect(peer, action.Protocol, action.Data)
}

// processRelayedPacket handles a RELAY_2 inner payload.
// The inner payload can be:
//   - Type 4 (Transport): decrypt with the end-to-end session, route to mux/inbound
//   - Type 1 (HandshakeInit): relayed handshake initiation from src through relay
//   - Type 2 (HandshakeResp): relayed handshake response from src through relay
//
// pkt.pk is the relay peer's public key (who delivered the RELAY_2 to us).
func (u *UDP) processRelayedPacket(pkt *packet, src [32]byte, innerPayload []byte, from *net.UDPAddr) {
	if len(innerPayload) == 0 {
		pkt.err = ErrNoData
		return
	}

	msgType := innerPayload[0]

	switch msgType {
	case noise.MessageTypeHandshakeInit:
		relayPK := pkt.pk // the relay peer who forwarded this to us
		u.handleRelayedHandshakeInit(innerPayload, src, relayPK)
		pkt.err = ErrNoData

	case noise.MessageTypeHandshakeResp:
		u.handleRelayedHandshakeResp(innerPayload, src)
		pkt.err = ErrNoData

	case noise.MessageTypeTransport:
		u.processRelayedTransport(pkt, src, innerPayload)

	default:
		pkt.err = ErrNoData
	}
}

// processRelayedTransport handles a Type 4 transport message inside RELAY_2.
func (u *UDP) processRelayedTransport(pkt *packet, src [32]byte, innerPayload []byte) {
	msg, err := noise.ParseTransportMessage(innerPayload)
	if err != nil {
		pkt.err = ErrNoData
		return
	}

	u.mu.RLock()
	innerPeer, exists := u.byIndex[msg.ReceiverIndex]
	u.mu.RUnlock()

	if !exists {
		pkt.err = ErrPeerNotFound
		return
	}

	innerPeer.mu.RLock()
	session := innerPeer.session
	innerPeer.mu.RUnlock()

	if session == nil {
		pkt.err = ErrNoSession
		return
	}

	innerPlaintext, err := session.Decrypt(msg.Ciphertext, msg.Counter)
	if err != nil {
		pkt.err = ErrNoData
		return
	}

	if len(innerPlaintext) == 0 {
		pkt.err = ErrNoData
		return
	}

	innerProto, _, innerData, err := noise.DecodePayload(innerPlaintext)
	if err != nil {
		pkt.err = ErrNoData
		return
	}

	pkt.pk = noise.PublicKey(src)
	pkt.protocol = innerProto
	pkt.payload = make([]byte, len(innerData))
	copy(pkt.payload, innerData)
	pkt.payloadN = len(innerData)
	pkt.err = nil

	if innerProto == noise.ProtocolKCP {
		innerPeer.mu.RLock()
		mux := innerPeer.mux
		innerPeer.mu.RUnlock()
		if mux != nil {
			mux.Input(innerData)
		}
		pkt.err = ErrNoData
		return
	}

	innerPeer.mu.RLock()
	inChan := innerPeer.inboundChan
	innerPeer.mu.RUnlock()
	if inChan != nil {
		select {
		case inChan <- protoPacket{protocol: innerProto, payload: pkt.payload}:
		default:
		}
	}
}

// handleRelayedHandshakeInit processes a Handshake Initiation that arrived
// through a relay (inside RELAY_2). Like handleHandshakeInit but:
//   - Learns relay route: src → relayPK (so response goes back through relay)
//   - Sends response via RELAY_0 through relay (not direct WriteToUDP)
//   - Does NOT set peer.endpoint (relayed peer has no direct endpoint)
func (u *UDP) handleRelayedHandshakeInit(data []byte, src [32]byte, relayPK noise.PublicKey) {
	msg, err := noise.ParseHandshakeInit(data)
	if err != nil {
		return
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:     noise.PatternIK,
		Initiator:   false,
		LocalStatic: u.localKey,
	})
	if err != nil {
		return
	}

	noiseMsg := make([]byte, noise.KeySize+48)
	copy(noiseMsg[:noise.KeySize], msg.Ephemeral[:])
	copy(noiseMsg[noise.KeySize:], msg.Static)

	_, err = hs.ReadMessage(noiseMsg)
	if err != nil {
		return
	}

	remotePK := hs.RemoteStatic()

	u.mu.Lock()
	peer, exists := u.peers[remotePK]
	if !exists {
		if !u.allowUnknown {
			u.mu.Unlock()
			return
		}
		peer = &peerState{
			pk:    remotePK,
			state: PeerStateNew,
		}
		u.peers[remotePK] = peer
	}
	u.mu.Unlock()

	// Learn relay route: to reach the remote peer, go through relay
	if u.routeTable != nil {
		u.routeTable.AddRoute(remotePK, relayPK)
	}

	localIdx, err := noise.GenerateIndex()
	if err != nil {
		return
	}

	respPayload, err := hs.WriteMessage(nil)
	if err != nil {
		return
	}

	ephemeral := hs.LocalEphemeral()
	wireMsg := noise.BuildHandshakeResp(localIdx, msg.SenderIndex, ephemeral, respPayload[noise.KeySize:])

	// Send response through relay (wrapped in RELAY_0)
	u.mu.RLock()
	relayPeer, relayExists := u.peers[relayPK]
	u.mu.RUnlock()

	if !relayExists {
		return
	}

	relay0Data := relay.EncodeRelay0(&relay.Relay0{
		TTL:      relay.DefaultTTL,
		Strategy: relay.StrategyAuto,
		DstKey:   [32]byte(remotePK),
		Payload:  wireMsg,
	})

	if err := u.sendDirect(relayPeer, noise.ProtocolRelay0, relay0Data); err != nil {
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

	muxRes := u.createMux(peer)

	peer.mu.Lock()
	// No endpoint for relayed peers — all traffic goes through relay
	peer.session = session
	peer.mux = muxRes.mux
	peer.acceptChan = muxRes.acceptChan
	peer.inboundChan = muxRes.inboundChan
	peer.state = PeerStateEstablished
	peer.lastSeen = time.Now()
	peer.mu.Unlock()

	u.mu.Lock()
	u.byIndex[localIdx] = peer
	u.mu.Unlock()

	u.startMuxUpdateLoop(muxRes.mux)
}

// handleRelayedHandshakeResp processes a Handshake Response that arrived
// through a relay (inside RELAY_2). Like handleHandshakeResp but does NOT
// set peer.endpoint (relayed peer, the relay route was set by the initiator).
func (u *UDP) handleRelayedHandshakeResp(data []byte, src [32]byte) {
	msg, err := noise.ParseHandshakeResp(data)
	if err != nil {
		return
	}

	u.mu.Lock()
	pending, exists := u.pending[msg.ReceiverIndex]
	if !exists {
		u.mu.Unlock()
		return
	}
	delete(u.pending, msg.ReceiverIndex)
	u.mu.Unlock()

	noiseMsg := make([]byte, noise.KeySize+16)
	copy(noiseMsg[:noise.KeySize], msg.Ephemeral[:])
	copy(noiseMsg[noise.KeySize:], msg.Empty)

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

	peer := pending.peer
	muxRes := u.createMux(peer)

	peer.mu.Lock()
	// No endpoint update for relayed peers — relay route handles routing
	peer.session = session
	peer.mux = muxRes.mux
	peer.acceptChan = muxRes.acceptChan
	peer.inboundChan = muxRes.inboundChan
	peer.state = PeerStateEstablished
	peer.lastSeen = time.Now()
	peer.mu.Unlock()

	u.mu.Lock()
	u.byIndex[pending.localIdx] = peer
	u.mu.Unlock()

	u.startMuxUpdateLoop(muxRes.mux)

	if pending.done != nil {
		pending.done <- nil
	}
}
