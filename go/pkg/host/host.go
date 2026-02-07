package host

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"

	znet "github.com/vibing/zgrnet/pkg/net"
	"github.com/vibing/zgrnet/pkg/noise"
)

// TunDevice is the interface for reading/writing IP packets from/to a TUN device.
// The real tun.Device satisfies this interface.
// For testing, a mock implementation can be provided.
type TunDevice interface {
	Read(buf []byte) (int, error)
	Write(buf []byte) (int, error)
	Close() error
}

// Config holds the configuration for creating a Host.
type Config struct {
	// PrivateKey is the local keypair for Noise Protocol handshakes.
	PrivateKey *noise.KeyPair

	// TunIPv4 is the local IPv4 address assigned to the TUN device.
	// Typically in the CGNAT range (100.64.0.0/10).
	TunIPv4 net.IP

	// MTU is the Maximum Transmission Unit for the TUN device.
	// Recommended: 1400. Default: 1400 if zero.
	MTU int

	// ListenPort is the UDP port to listen on. 0 for random.
	ListenPort int

	// Peers is the list of initial peers.
	Peers []PeerConfig
}

// PeerConfig holds the configuration for a peer.
type PeerConfig struct {
	// PublicKey is the peer's Curve25519 public key.
	PublicKey noise.PublicKey

	// Endpoint is the peer's UDP address in "host:port" format.
	// Empty string means no known endpoint (responder-only).
	Endpoint string

	// IPv4 is an optional static IPv4 assignment.
	// If nil, an address is automatically allocated from the CGNAT pool.
	IPv4 net.IP
}

// Host bridges a TUN virtual network device with encrypted UDP transport.
// It routes IP packets between the TUN device and remote peers using the
// Noise Protocol for encryption.
//
// Outbound: TUN.Read -> parse dst IP -> lookup peer -> strip IP header -> encrypt -> UDP send
// Inbound:  UDP recv -> decrypt -> lookup src IP -> rebuild IP header -> TUN.Write
type Host struct {
	tun     TunDevice
	udp     *znet.UDP
	ipAlloc *IPAllocator
	tunIPv4 net.IP
	mtu     int

	closeChan chan struct{}
	closed    atomic.Bool
	wg        sync.WaitGroup

	mu    sync.RWMutex
	peers map[noise.PublicKey]*PeerConfig
}

// New creates a new Host with the given configuration and TUN device.
// The caller is responsible for creating and configuring the TUN device
// (IP address, MTU, bringing it up) before passing it to New.
//
// The Host takes ownership of the TUN device and will close it on Host.Close().
func New(cfg Config, tunDev TunDevice) (*Host, error) {
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("host: private key is required")
	}
	if cfg.TunIPv4 == nil {
		return nil, fmt.Errorf("host: TUN IPv4 address is required")
	}

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1400
	}

	// Create UDP transport
	bindAddr := fmt.Sprintf(":%d", cfg.ListenPort)
	udp, err := znet.NewUDP(cfg.PrivateKey,
		znet.WithBindAddr(bindAddr),
		znet.WithAllowUnknown(true),
	)
	if err != nil {
		return nil, fmt.Errorf("host: create UDP failed: %w", err)
	}

	h := &Host{
		tun:       tunDev,
		udp:       udp,
		ipAlloc:   NewIPAllocator(),
		tunIPv4:   cfg.TunIPv4.To4(),
		mtu:       mtu,
		closeChan: make(chan struct{}),
		peers:     make(map[noise.PublicKey]*PeerConfig),
	}

	// Register initial peers
	for i := range cfg.Peers {
		if err := h.addPeerLocked(&cfg.Peers[i]); err != nil {
			udp.Close()
			return nil, fmt.Errorf("host: add peer failed: %w", err)
		}
	}

	return h, nil
}

// addPeerLocked adds a peer without holding h.mu (called during construction).
func (h *Host) addPeerLocked(p *PeerConfig) error {
	// Assign IP
	if p.IPv4 != nil {
		if err := h.ipAlloc.AssignStatic(p.PublicKey, p.IPv4); err != nil {
			return err
		}
	} else {
		if _, err := h.ipAlloc.Assign(p.PublicKey); err != nil {
			return err
		}
	}

	// Set endpoint in UDP layer
	if p.Endpoint != "" {
		addr, err := net.ResolveUDPAddr("udp", p.Endpoint)
		if err != nil {
			return fmt.Errorf("host: resolve endpoint %q: %w", p.Endpoint, err)
		}
		h.udp.SetPeerEndpoint(p.PublicKey, addr)
	}

	h.peers[p.PublicKey] = p
	return nil
}

// AddPeer dynamically adds a peer to the host.
// An IPv4 address is automatically allocated from the CGNAT pool.
func (h *Host) AddPeer(pk noise.PublicKey, endpoint string) error {
	p := &PeerConfig{
		PublicKey: pk,
		Endpoint:  endpoint,
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	return h.addPeerLocked(p)
}

// AddPeerWithIP dynamically adds a peer with a specific static IPv4 address.
func (h *Host) AddPeerWithIP(pk noise.PublicKey, endpoint string, ipv4 net.IP) error {
	p := &PeerConfig{
		PublicKey: pk,
		Endpoint:  endpoint,
		IPv4:      ipv4,
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	return h.addPeerLocked(p)
}

// Connect initiates a Noise handshake with the specified peer.
// The peer must have an endpoint set. This call blocks until the
// handshake completes or times out (5 seconds).
func (h *Host) Connect(pk noise.PublicKey) error {
	return h.udp.Connect(pk)
}

// Run starts the outbound and inbound forwarding loops.
// This call blocks until Close() is called.
func (h *Host) Run() error {
	h.wg.Add(2)
	go h.outboundLoop()
	go h.inboundLoop()

	<-h.closeChan
	h.wg.Wait()
	return nil
}

// Close gracefully shuts down the host.
// Closes the TUN device, UDP transport, and waits for all goroutines to exit.
func (h *Host) Close() error {
	if h.closed.Swap(true) {
		return nil
	}
	close(h.closeChan)

	// Close TUN and UDP to unblock the loops
	h.tun.Close()
	h.udp.Close()

	h.wg.Wait()
	return nil
}

// LocalAddr returns the local UDP address the host is listening on.
func (h *Host) LocalAddr() net.Addr {
	return h.udp.HostInfo().Addr
}

// PublicKey returns the host's public key.
func (h *Host) PublicKey() noise.PublicKey {
	return h.udp.HostInfo().PublicKey
}

// outboundLoop reads IP packets from the TUN device and forwards them to peers.
//
// Flow: TUN.Read -> parse dst IP -> lookup peer pubkey -> strip IP header -> UDP.Write
func (h *Host) outboundLoop() {
	defer h.wg.Done()

	buf := make([]byte, h.mtu+40) // extra room for oversized packets

	for {
		if h.closed.Load() {
			return
		}

		n, err := h.tun.Read(buf)
		if err != nil {
			if h.closed.Load() {
				return
			}
			log.Printf("host: tun read error: %v", err)
			continue
		}

		if n == 0 {
			continue
		}

		h.handleOutbound(buf[:n])
	}
}

// handleOutbound processes a single outbound IP packet from TUN.
func (h *Host) handleOutbound(ipPkt []byte) {
	info, err := ParseIPPacket(ipPkt)
	if err != nil {
		return
	}

	// Look up peer by destination IP
	pk, ok := h.ipAlloc.LookupByIP(info.DstIP)
	if !ok {
		return // no peer for this destination
	}

	// Map IP protocol number to noise protocol byte
	switch info.Protocol {
	case 1: // ICMP
		h.udp.Write(pk, noise.ProtocolICMP, info.Payload)
	case 6: // TCP
		h.udp.Write(pk, noise.ProtocolTCP, info.Payload)
	case 17: // UDP
		h.udp.Write(pk, noise.ProtocolUDP, info.Payload)
	default:
		// For unrecognized protocols, send as ProtocolIP (complete IP packet)
		h.udp.Write(pk, noise.ProtocolIP, ipPkt)
	}
}

// inboundLoop reads decrypted packets from UDP and writes them to the TUN device.
//
// Flow: UDP.ReadPacket -> lookup src pubkey -> rebuild IP header -> TUN.Write
func (h *Host) inboundLoop() {
	defer h.wg.Done()

	buf := make([]byte, noise.MaxPacketSize)

	for {
		if h.closed.Load() {
			return
		}

		pk, proto, n, err := h.udp.ReadPacket(buf)
		if err != nil {
			if h.closed.Load() {
				return
			}
			log.Printf("host: udp read error: %v", err)
			continue
		}

		if n == 0 {
			continue
		}

		h.handleInbound(pk, proto, buf[:n])
	}
}

// handleInbound processes a single inbound packet from a peer.
func (h *Host) handleInbound(pk noise.PublicKey, proto byte, payload []byte) {
	switch proto {
	case noise.ProtocolIP:
		// Complete IP packet - write directly to TUN
		h.tun.Write(payload)

	case noise.ProtocolICMP, noise.ProtocolTCP, noise.ProtocolUDP:
		// Transport payload without IP header - rebuild and write to TUN
		srcIP, ok := h.ipAlloc.LookupByPubkey(pk)
		if !ok {
			return
		}

		ipPkt, err := BuildIPv4Packet(srcIP, h.tunIPv4, proto, payload)
		if err != nil {
			return
		}

		h.tun.Write(ipPkt)

	default:
		// Unknown protocol, ignore
	}
}
