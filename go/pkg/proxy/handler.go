package proxy

import (
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// HandleTCPProxy handles an incoming TCP_PROXY (proto=69) KCP stream.
//
// It decodes the target address from the stream's metadata (SYN frame),
// checks the policy, dials the real TCP target, and relays data
// bidirectionally between the stream and the target connection.
//
// The stream must have blocking Read semantics (kcp.Stream does).
//
// If dial is nil, DefaultDial is used. If policy is nil, all addresses allowed.
func HandleTCPProxy(stream io.ReadWriteCloser, metadata []byte, dial DialFunc, policy Policy) error {
	defer stream.Close()

	addr, _, err := noise.DecodeAddress(metadata)
	if err != nil {
		return err
	}

	if !checkPolicy(policy, addr) {
		return ErrPolicyDenied
	}

	if dial == nil {
		dial = DefaultDial
	}

	remote, err := dial(addr)
	if err != nil {
		return err
	}
	defer remote.Close()

	Relay(stream, remote)
	return nil
}

// DefaultDial connects to the target address via TCP.
// Used as the default DialFunc for HandleTCPProxy when running as an
// exit node that connects to real internet targets.
func DefaultDial(addr *noise.Address) (io.ReadWriteCloser, error) {
	target := net.JoinHostPort(addr.Host, strconv.Itoa(int(addr.Port)))
	return net.DialTimeout("tcp", target, 10*time.Second)
}

// UDPProxyHandler forwards UDP_PROXY (protocol=65) packets between the
// tunnel and real UDP targets. It maintains a single UDP socket for
// forwarding and listens for responses to route them back.
//
// Wire format (both directions): addr.Encode() + data
type UDPProxyHandler struct {
	conn   *net.UDPConn                // local socket for forwarding to targets
	send   func(response []byte) error // send response back through tunnel
	policy Policy                      // nil = allow all
	closed atomic.Bool
	wg     sync.WaitGroup
}

// NewUDPProxyHandler creates a handler and starts a response receive loop.
// send is called with the encoded response (addr + data) for each reply
// received from a real UDP target.
// If policy is nil, all target addresses are allowed.
func NewUDPProxyHandler(send func(response []byte) error, policy Policy) (*UDPProxyHandler, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}

	h := &UDPProxyHandler{
		conn:   conn,
		send:   send,
		policy: policy,
	}

	// Start response receive loop
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.receiveLoop()
	}()

	return h, nil
}

// HandlePacket processes a single UDP_PROXY payload.
// payload format: addr.Encode() + data
// It decodes the target address and forwards the data via UDP.
func (h *UDPProxyHandler) HandlePacket(payload []byte) error {
	addr, consumed, err := noise.DecodeAddress(payload)
	if err != nil {
		return err
	}

	if !checkPolicy(h.policy, addr) {
		return ErrPolicyDenied
	}

	data := payload[consumed:]

	target, err := net.ResolveUDPAddr("udp",
		net.JoinHostPort(addr.Host, strconv.Itoa(int(addr.Port))))
	if err != nil {
		return err
	}

	_, err = h.conn.WriteToUDP(data, target)
	return err
}

// receiveLoop reads responses from real UDP targets and sends them back
// through the tunnel with the source address prepended.
func (h *UDPProxyHandler) receiveLoop() {
	buf := make([]byte, 65535)
	for {
		n, from, err := h.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		// Build source address
		var addr noise.Address
		if ip4 := from.IP.To4(); ip4 != nil {
			addr = noise.Address{
				Type: noise.AddressTypeIPv4,
				Host: from.IP.String(),
				Port: uint16(from.Port),
			}
		} else {
			addr = noise.Address{
				Type: noise.AddressTypeIPv6,
				Host: from.IP.String(),
				Port: uint16(from.Port),
			}
		}

		encoded := addr.Encode()
		if encoded == nil {
			continue
		}

		// Build response: addr.Encode() + data
		response := make([]byte, len(encoded)+n)
		copy(response, encoded)
		copy(response[len(encoded):], buf[:n])

		h.send(response)
	}
}

// Close stops the handler and waits for the receive loop to exit.
func (h *UDPProxyHandler) Close() error {
	if h.closed.Swap(true) {
		return nil
	}
	err := h.conn.Close()
	h.wg.Wait()
	return err
}
