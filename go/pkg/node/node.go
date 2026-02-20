// Package node provides a high-level embeddable network node for zgrnet.
//
// Node wraps the low-level UDP transport, Noise Protocol encryption, and KCP
// stream multiplexing into a simple API suitable for apps, embedded devices,
// and Go services. Unlike Host, Node does not require TUN or root privileges.
//
// Basic usage:
//
//	n, err := node.New(node.Config{PrivateKey: keyPair, ListenPort: 0})
//	if err != nil { ... }
//	defer n.Stop()
//
//	n.AddPeer(node.PeerConfig{PublicKey: remotePK, Endpoint: "1.2.3.4:51820"})
//
//	stream, err := n.Dial(remotePK, 8080)
//	// or
//	stream, err := n.AcceptStream()
package node

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vibing/zgrnet/pkg/kcp"
	znet "github.com/vibing/zgrnet/pkg/net"
	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/relay"
)

// State represents the lifecycle state of a Node.
type State int32

const (
	StateStopped State = iota
	StateRunning
	StateSuspended
)

func (s State) String() string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateRunning:
		return "running"
	case StateSuspended:
		return "suspended"
	default:
		return "unknown"
	}
}

// Errors returned by Node operations.
var (
	ErrNotRunning     = errors.New("node: not running")
	ErrAlreadyRunning = errors.New("node: already running")
	ErrPeerNotFound   = errors.New("node: peer not found")
	ErrNotConnected   = errors.New("node: peer not connected")
	ErrStopped        = errors.New("node: stopped")
)

// Config holds the configuration for creating a Node.
type Config struct {
	// PrivateKey is the Noise Protocol keypair. Required.
	PrivateKey *noise.KeyPair

	// ListenPort is the UDP port to listen on. 0 for OS-assigned.
	ListenPort int

	// AllowUnknown allows accepting connections from peers not added via AddPeer.
	AllowUnknown bool
}

// PeerConfig holds the configuration for adding a peer.
type PeerConfig struct {
	// PublicKey is the peer's Curve25519 public key. Required.
	PublicKey noise.PublicKey

	// Endpoint is the peer's UDP address in "host:port" format.
	// Empty means responder-only (wait for the peer to connect to us).
	Endpoint string
}

// Node is an embeddable zgrnet network node.
//
// It provides Dial (active connect), AcceptStream (passive accept),
// and raw UDP send/recv — all over Noise-encrypted KCP transport.
// No TUN device, no root privileges required.
type Node struct {
	config Config
	udp    *znet.UDP

	// Global accept channel aggregates streams from all peers.
	acceptCh chan *Stream

	// Tracks per-peer accept goroutines.
	peerMu   sync.Mutex
	peerDone map[noise.PublicKey]chan struct{} // signal to stop per-peer accept loop

	// Lifecycle
	state atomic.Int32
	done  chan struct{}
	wg    sync.WaitGroup
}

// New creates a new Node but does not start it.
// Call Start() to begin listening and accepting connections.
func New(cfg Config) (*Node, error) {
	if cfg.PrivateKey == nil {
		return nil, errors.New("node: PrivateKey is required")
	}

	rt := relay.NewRouteTable()

	bindAddr := fmt.Sprintf("127.0.0.1:%d", cfg.ListenPort)
	udp, err := znet.NewUDP(
		cfg.PrivateKey,
		znet.WithBindAddr(bindAddr),
		znet.WithAllowUnknown(cfg.AllowUnknown),
		znet.WithRouteTable(rt),
	)
	if err != nil {
		return nil, fmt.Errorf("node: create UDP: %w", err)
	}

	n := &Node{
		config:   cfg,
		udp:      udp,
		acceptCh: make(chan *Stream, 64),
		peerDone: make(map[noise.PublicKey]chan struct{}),
		done:     make(chan struct{}),
	}
	n.state.Store(int32(StateRunning))

	// Start the background receive loop.
	// This is required for handshakes and transport messages to be processed.
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.recvLoop()
	}()

	return n, nil
}

// Stop shuts down the Node and releases all resources.
func (n *Node) Stop() {
	if !n.state.CompareAndSwap(int32(StateRunning), int32(StateStopped)) &&
		!n.state.CompareAndSwap(int32(StateSuspended), int32(StateStopped)) {
		return // already stopped
	}

	close(n.done)

	// Stop all per-peer accept loops.
	n.peerMu.Lock()
	for _, ch := range n.peerDone {
		close(ch)
	}
	n.peerMu.Unlock()

	n.udp.Close()
	n.wg.Wait()
}

// State returns the current lifecycle state.
func (n *Node) State() State {
	return State(n.state.Load())
}

// PublicKey returns this node's public key.
func (n *Node) PublicKey() noise.PublicKey {
	return n.config.PrivateKey.Public
}

// LocalAddr returns the local UDP address the node is listening on.
func (n *Node) LocalAddr() net.Addr {
	return n.udp.HostInfo().Addr
}

// AddPeer registers a peer. If endpoint is provided, initiates a handshake.
func (n *Node) AddPeer(cfg PeerConfig) error {
	if n.State() != StateRunning {
		return ErrNotRunning
	}

	if cfg.Endpoint != "" {
		ep, err := net.ResolveUDPAddr("udp", cfg.Endpoint)
		if err != nil {
			return fmt.Errorf("node: resolve endpoint %q: %w", cfg.Endpoint, err)
		}
		n.udp.SetPeerEndpoint(cfg.PublicKey, ep)
	} else {
		// Register peer without endpoint (responder-only).
		n.udp.SetPeerEndpoint(cfg.PublicKey, &net.UDPAddr{})
	}

	// Start accept forwarder goroutine for this peer.
	n.startAcceptLoop(cfg.PublicKey)

	return nil
}

// RemovePeer removes a peer and closes all associated streams.
func (n *Node) RemovePeer(pk noise.PublicKey) {
	// Stop the accept loop for this peer.
	n.peerMu.Lock()
	if ch, ok := n.peerDone[pk]; ok {
		close(ch)
		delete(n.peerDone, pk)
	}
	n.peerMu.Unlock()

	n.udp.RemovePeer(pk)
}

// Peers returns information about all registered peers.
func (n *Node) Peers() []znet.PeerInfo {
	var result []znet.PeerInfo
	for p := range n.udp.Peers() {
		result = append(result, *p.Info)
	}
	return result
}

// Connect initiates a handshake with a peer. The peer must have been added
// via AddPeer with an endpoint. Blocks until the handshake completes or fails.
func (n *Node) Connect(pk noise.PublicKey) error {
	if n.State() != StateRunning {
		return ErrNotRunning
	}
	return n.udp.Connect(pk)
}

// Dial connects to a peer and opens a KCP stream.
//
// pk identifies the remote peer. port is the target port carried as metadata
// in the stream's SYN frame (proto=TCP_PROXY, address=127.0.0.1:port).
//
// If the peer is not yet connected, Dial automatically initiates a handshake
// and waits for it to complete before opening the stream.
func (n *Node) Dial(pk noise.PublicKey, port uint16) (*Stream, error) {
	if n.State() != StateRunning {
		return nil, ErrNotRunning
	}

	// Ensure peer is connected.
	info := n.udp.PeerInfo(pk)
	if info == nil {
		return nil, ErrPeerNotFound
	}
	if info.State != znet.PeerStateEstablished {
		if err := n.udp.Connect(pk); err != nil {
			return nil, fmt.Errorf("node: connect to %s: %w", pk.ShortString(), err)
		}
	}

	// Build target address metadata.
	addr := &noise.Address{
		Type: noise.AddressTypeIPv4,
		Host: "127.0.0.1",
		Port: port,
	}
	metadata := addr.Encode()

	raw, err := n.udp.OpenStream(pk, noise.ProtocolKCP, metadata)
	if err != nil {
		return nil, fmt.Errorf("node: open stream to %s:%d: %w", pk.ShortString(), port, err)
	}

	return &Stream{Stream: raw, remotePK: pk}, nil
}

// OpenStream opens a raw KCP stream to a peer with custom proto and metadata.
// Use Dial for the common case of TCP_PROXY streams.
func (n *Node) OpenStream(pk noise.PublicKey, proto byte, metadata []byte) (*Stream, error) {
	if n.State() != StateRunning {
		return nil, ErrNotRunning
	}

	info := n.udp.PeerInfo(pk)
	if info == nil {
		return nil, ErrPeerNotFound
	}
	if info.State != znet.PeerStateEstablished {
		if err := n.udp.Connect(pk); err != nil {
			return nil, fmt.Errorf("node: connect: %w", err)
		}
	}

	raw, err := n.udp.OpenStream(pk, proto, metadata)
	if err != nil {
		return nil, err
	}
	return &Stream{Stream: raw, remotePK: pk}, nil
}

// DialRelay connects to a remote peer through a relay and opens a KCP stream.
//
// relayPK is the public key of the relay node that both this node and the
// remote peer are connected to. The relay node forwards handshake and data
// packets between the two peers (via RELAY_0/RELAY_2).
//
// The relay route is registered in the RouteTable, so all subsequent traffic
// to dst automatically goes through the relay (including KCP stream data).
//
// Both this node and the relay must have established sessions (call AddPeer +
// Connect for the relay first).
func (n *Node) DialRelay(dst noise.PublicKey, relayPK noise.PublicKey, port uint16) (*Stream, error) {
	if n.State() != StateRunning {
		return nil, ErrNotRunning
	}

	// Register relay route: dst → relay
	n.udp.RouteTable().AddRoute(dst, relayPK)

	// Register the peer without an endpoint (relay-only).
	// AddPeer is idempotent if the peer is already registered.
	n.AddPeer(PeerConfig{PublicKey: dst})

	// Dial goes through initiateHandshake (relay-aware) then OpenStream.
	return n.Dial(dst, port)
}

// RouteTable returns the node's relay route table.
func (n *Node) RouteTable() *relay.RouteTable {
	return n.udp.RouteTable()
}

// AcceptStream waits for an incoming KCP stream from any peer.
// Returns the stream with RemotePubkey() identifying the sender.
func (n *Node) AcceptStream() (*Stream, error) {
	select {
	case s := <-n.acceptCh:
		return s, nil
	case <-n.done:
		return nil, ErrStopped
	}
}

// WriteTo sends raw data to a peer with the given protocol byte.
// This is a connectionless send (no stream, no reliability).
func (n *Node) WriteTo(data []byte, protocol byte, pk noise.PublicKey) error {
	if n.State() != StateRunning {
		return ErrNotRunning
	}
	_, err := n.udp.Write(pk, protocol, data)
	return err
}

// ReadFrom reads the next raw packet from any peer.
// Returns the number of bytes read, the protocol byte, and the sender's public key.
func (n *Node) ReadFrom(buf []byte) (int, byte, noise.PublicKey, error) {
	pk, proto, n2, err := n.udp.ReadPacket(buf)
	return n2, proto, pk, err
}

// UDP returns the underlying UDP transport. Advanced use only.
func (n *Node) UDP() *znet.UDP {
	return n.udp
}

// recvLoop runs in the background to drive the UDP receive pipeline.
// Without this, handshakes and transport messages won't be processed.
func (n *Node) recvLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-n.done:
			return
		default:
		}
		_, _, err := n.udp.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, znet.ErrClosed) {
				return
			}
			continue
		}
	}
}

// startAcceptLoop starts a goroutine that forwards accepted streams
// from one peer into the global acceptCh.
func (n *Node) startAcceptLoop(pk noise.PublicKey) {
	n.peerMu.Lock()
	if _, exists := n.peerDone[pk]; exists {
		n.peerMu.Unlock()
		return // already running
	}
	stopCh := make(chan struct{})
	n.peerDone[pk] = stopCh
	n.peerMu.Unlock()

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.acceptLoopForPeer(pk, stopCh)
	}()
}

// acceptLoopForPeer reads accepted streams from a specific peer and
// pushes them to the global accept channel.
//
// It first waits for the peer to reach PeerStateEstablished (polling at 50ms),
// then enters the blocking AcceptStream loop.
func (n *Node) acceptLoopForPeer(pk noise.PublicKey, stop <-chan struct{}) {
	// Phase 1: Wait for the peer to establish a session.
	// AcceptStream returns ErrNoSession immediately if the peer isn't
	// connected yet, so we poll PeerInfo to avoid a busy loop.
	for {
		info := n.udp.PeerInfo(pk)
		if info != nil && info.State == znet.PeerStateEstablished {
			break
		}
		select {
		case <-stop:
			return
		case <-n.done:
			return
		case <-time.After(50 * time.Millisecond):
			// Retry.
		}
	}

	// Phase 2: Accept streams. AcceptStream blocks until a stream arrives
	// or the UDP instance is closed, so this is not a busy loop.
	for {
		raw, err := n.udp.AcceptStream(pk)
		if err != nil {
			if errors.Is(err, znet.ErrClosed) || errors.Is(err, znet.ErrPeerNotFound) {
				return
			}
			// Session may have been reset (rekey, reconnect). Go back to
			// waiting for re-establishment.
			select {
			case <-stop:
				return
			case <-n.done:
				return
			case <-time.After(50 * time.Millisecond):
				continue
			}
		}

		s := &Stream{Stream: raw, remotePK: pk}
		select {
		case n.acceptCh <- s:
		case <-stop:
			raw.Close()
			return
		case <-n.done:
			raw.Close()
			return
		}
	}
}

// Stream wraps a KCP stream with the remote peer's public key.
type Stream struct {
	*kcp.Stream
	remotePK noise.PublicKey
}

// RemotePubkey returns the public key of the peer on the other end.
func (s *Stream) RemotePubkey() noise.PublicKey {
	return s.remotePK
}
