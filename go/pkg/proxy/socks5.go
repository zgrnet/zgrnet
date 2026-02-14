// Package proxy implements SOCKS5 and HTTP CONNECT proxy servers.
//
// The proxy server accepts client connections (SOCKS5 or HTTP CONNECT),
// parses target addresses, and dials remote targets through a pluggable
// DialFunc. For zgrnet integration, the DialFunc opens KCP streams via
// the UDP high-level API with proto=TCP_PROXY(69).
package proxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// SOCKS5 protocol constants.
const (
	Version5 = 0x05

	// Authentication methods.
	AuthNone     = 0x00
	AuthNoAccept = 0xFF

	// Commands.
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	// Reply codes.
	RepSuccess          = 0x00
	RepGeneralFailure   = 0x01
	RepNotAllowed       = 0x02
	RepNetworkUnreach   = 0x03
	RepHostUnreach      = 0x04
	RepConnRefused      = 0x05
	RepTTLExpired       = 0x06
	RepCmdNotSupported  = 0x07
	RepAddrNotSupported = 0x08
)

// Errors.
var (
	ErrUnsupportedVersion = errors.New("proxy: unsupported SOCKS version")
	ErrNoAcceptableAuth   = errors.New("proxy: no acceptable auth method")
	ErrUnsupportedCommand = errors.New("proxy: unsupported command")
	ErrInvalidAddress     = errors.New("proxy: invalid address")
)

// DialFunc opens a connection to the target address.
// The returned io.ReadWriteCloser must have blocking Read semantics.
type DialFunc func(addr *noise.Address) (io.ReadWriteCloser, error)

// UDPRelay handles UDP data exchange through the tunnel.
type UDPRelay interface {
	// WriteTo sends UDP data to the target address through the tunnel.
	WriteTo(addr *noise.Address, data []byte) error
	// ReadFrom reads a UDP response from the tunnel.
	// Returns source address, number of data bytes copied to buf, and error.
	ReadFrom(buf []byte) (addr *noise.Address, n int, err error)
	// Close closes the relay.
	Close() error
}

// NewUDPRelayFunc creates a new UDPRelay for a UDP association.
// Each UDP ASSOCIATE connection gets its own relay instance.
type NewUDPRelayFunc func() (UDPRelay, error)

// ProxyStats holds proxy connection statistics.
type ProxyStats struct {
	TotalConnections uint64 `json:"total_connections"`
	ActiveConnections int64 `json:"active_connections"`
	BytesSent        uint64 `json:"bytes_sent"`
	BytesReceived    uint64 `json:"bytes_received"`
	Errors           uint64 `json:"errors"`
}

// Server is a SOCKS5 proxy server.
type Server struct {
	listenAddr string
	dial       DialFunc        // For TCP CONNECT
	newRelay   NewUDPRelayFunc // For UDP ASSOCIATE (nil = not supported)
	policy     Policy          // nil = allow all

	mu       sync.Mutex
	listener net.Listener

	closed atomic.Bool
	wg     sync.WaitGroup

	// Atomic stats counters
	totalConns  atomic.Uint64
	activeConns atomic.Int64
	bytesSent   atomic.Uint64
	bytesRecv   atomic.Uint64
	errors      atomic.Uint64
}

// GetStats returns a snapshot of proxy connection statistics.
func (s *Server) GetStats() ProxyStats {
	return ProxyStats{
		TotalConnections:  s.totalConns.Load(),
		ActiveConnections: s.activeConns.Load(),
		BytesSent:         s.bytesSent.Load(),
		BytesReceived:     s.bytesRecv.Load(),
		Errors:            s.errors.Load(),
	}
}

// SetPolicy sets the policy for target address validation.
// If nil (default), all addresses are allowed.
func (s *Server) SetPolicy(p Policy) {
	s.policy = p
}

// NewServer creates a new proxy server.
// listenAddr is the TCP address to listen on (e.g. "127.0.0.1:1080").
// dial is the function used to connect to target addresses.
func NewServer(listenAddr string, dial DialFunc) *Server {
	return &Server{
		listenAddr: listenAddr,
		dial:       dial,
	}
}

// ListenAndServe binds to the configured address and starts serving.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve accepts connections on the given listener.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return nil
			}
			continue
		}

		s.wg.Add(1)
		s.totalConns.Add(1)
		s.activeConns.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.activeConns.Add(-1)
			s.handleConn(conn)
		}()
	}
}

// Addr returns the listener address. Returns nil if not listening.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()
	if ln == nil {
		return nil
	}
	return ln.Addr()
}

// Close stops the server and waits for active connections to finish.
func (s *Server) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()
	var err error
	if ln != nil {
		err = ln.Close()
	}
	s.wg.Wait()
	return err
}

// handleConn processes a single client connection.
// Detects SOCKS5 (0x05) vs HTTP CONNECT ('C') by first byte.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	// Set a deadline for the handshake phase
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Read first byte to detect protocol
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		return
	}

	switch first[0] {
	case Version5:
		s.handleSOCKS5(conn)
	case 'C':
		s.handleHTTPConnect(conn)
	default:
		// Unknown protocol
		return
	}
}

// handleSOCKS5 processes a SOCKS5 connection (version byte already consumed).
func (s *Server) handleSOCKS5(conn net.Conn) {
	// === Auth negotiation ===
	// Read NMETHODS
	var nMethods [1]byte
	if _, err := io.ReadFull(conn, nMethods[:]); err != nil {
		return
	}

	// Read method list
	methods := make([]byte, nMethods[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Check for NO AUTH (0x00)
	hasNoAuth := false
	for _, m := range methods {
		if m == AuthNone {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		conn.Write([]byte{Version5, AuthNoAccept})
		return
	}

	// Accept NO AUTH
	if _, err := conn.Write([]byte{Version5, AuthNone}); err != nil {
		return
	}

	// === Request ===
	// VER(1) + CMD(1) + RSV(1) + ATYP(1) = 4 bytes
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return
	}

	if header[0] != Version5 {
		return
	}

	cmd := header[1]
	atyp := header[3]

	// Parse address
	addr, err := ReadAddress(conn, atyp)
	if err != nil {
		sendReply(conn, RepAddrNotSupported, nil)
		return
	}

	// Clear deadline for the relay phase
	conn.SetDeadline(time.Time{})

	switch cmd {
	case CmdConnect:
		s.handleConnect(conn, addr)
	case CmdUDPAssociate:
		s.handleUDPAssociate(conn, addr)
	default:
		sendReply(conn, RepCmdNotSupported, nil)
	}
}

// handleConnect handles the SOCKS5 CONNECT command.
func (s *Server) handleConnect(conn net.Conn, addr *noise.Address) {
	if !checkPolicy(s.policy, addr) {
		sendReply(conn, RepNotAllowed, nil)
		return
	}

	// Dial the target through the tunnel
	remote, err := s.dial(addr)
	if err != nil {
		sendReply(conn, RepGeneralFailure, nil)
		return
	}
	defer remote.Close()

	// Send success reply with the target address as bound address
	sendReply(conn, RepSuccess, addr)

	// Relay data bidirectionally
	Relay(conn, remote)
}

// handleUDPAssociate handles the SOCKS5 UDP ASSOCIATE command.
//
// The server binds a local UDP port, returns it to the client, then relays
// UDP datagrams between the client (SOCKS5 UDP format) and the tunnel
// (UDPRelay). The TCP connection serves as a control channel — when it
// closes, the association ends.
func (s *Server) handleUDPAssociate(conn net.Conn, addr *noise.Address) {
	if s.newRelay == nil {
		sendReply(conn, RepCmdNotSupported, nil)
		return
	}

	// Create a relay for this association
	relay, err := s.newRelay()
	if err != nil {
		sendReply(conn, RepGeneralFailure, nil)
		return
	}

	// Determine bind IP from TCP listener (matches the SOCKS5 listen address)
	var bindIP net.IP
	s.mu.Lock()
	if s.listener != nil {
		if tcpAddr, ok := s.listener.Addr().(*net.TCPAddr); ok {
			bindIP = tcpAddr.IP
		}
	}
	s.mu.Unlock()
	if bindIP == nil {
		bindIP = net.IPv4(127, 0, 0, 1)
	}

	// Bind a local UDP socket for the client
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP})
	if err != nil {
		relay.Close()
		sendReply(conn, RepGeneralFailure, nil)
		return
	}

	// Send bound address to client
	boundAddr := udpConn.LocalAddr().(*net.UDPAddr)
	replyAddr := &noise.Address{
		Type: noise.AddressTypeIPv4,
		Host: boundAddr.IP.String(),
		Port: uint16(boundAddr.Port),
	}
	sendReply(conn, RepSuccess, replyAddr)

	// Track the client's UDP address (set on first packet received)
	var clientAddr atomic.Pointer[net.UDPAddr]

	var wg sync.WaitGroup

	// Outbound: client UDP → tunnel
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, from, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			clientAddr.Store(from)

			targetAddr, data, err := ParseSOCKS5UDP(buf[:n])
			if err != nil {
				continue
			}
			relay.WriteTo(targetAddr, data)
		}
	}()

	// Inbound: tunnel → client UDP
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			srcAddr, n, err := relay.ReadFrom(buf)
			if err != nil {
				return
			}

			ca := clientAddr.Load()
			if ca == nil {
				continue // No client connected yet
			}

			pkt := BuildSOCKS5UDP(srcAddr, buf[:n])
			if pkt != nil {
				udpConn.WriteToUDP(pkt, ca)
			}
		}
	}()

	// Wait for TCP control connection to close (signals end of association)
	io.Copy(io.Discard, conn)

	// Cleanup: close sockets to unblock goroutines, then wait
	udpConn.Close()
	relay.Close()
	wg.Wait()
}

// handleHTTPConnect handles an HTTP CONNECT request.
//
// Format: "CONNECT host:port HTTP/1.x\r\n" + headers + "\r\n"
// The first byte 'C' has already been consumed by handleConn.
func (s *Server) handleHTTPConnect(conn net.Conn) {
	// Use a small bufio.Reader for header parsing.
	// The 4KB default buffer limits how much data can accumulate
	// before a newline, preventing unbounded memory growth from
	// malicious clients sending very long header lines.
	reader := bufio.NewReaderSize(conn, 4096)

	// Read the rest of the first line (we already consumed 'C')
	restOfLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	firstLine := "C" + restOfLine

	// Parse: "CONNECT host:port HTTP/1.x\r\n"
	parts := strings.SplitN(strings.TrimSpace(firstLine), " ", 3)
	if len(parts) < 2 || parts[0] != "CONNECT" {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	target := parts[1] // "host:port"

	// Read remaining headers until empty line
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Parse target address
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		// Try as host-only (default port 443 for CONNECT)
		host = target
		portStr = "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// Determine address type
	addr := &noise.Address{Port: uint16(port)}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			addr.Type = noise.AddressTypeIPv4
		} else {
			addr.Type = noise.AddressTypeIPv6
		}
		addr.Host = ip.String()
	} else {
		addr.Type = noise.AddressTypeDomain
		addr.Host = host
	}

	// Clear deadline for relay phase
	conn.SetDeadline(time.Time{})

	// Policy check
	if !checkPolicy(s.policy, addr) {
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return
	}

	// Dial the target
	remote, err := s.dial(addr)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	// Send success response
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Relay using buffered reader (may have data buffered beyond headers)
	bc := &bufferedConn{reader: reader, conn: conn}
	Relay(bc, remote)
}

// bufferedConn wraps a net.Conn with a bufio.Reader for reads.
// This ensures any data buffered during HTTP header parsing is not lost.
type bufferedConn struct {
	reader *bufio.Reader
	conn   net.Conn
}

func (c *bufferedConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *bufferedConn) Write(p []byte) (int, error) { return c.conn.Write(p) }
func (c *bufferedConn) Close() error                { return c.conn.Close() }

// CloseWrite supports half-close for the relay.
func (c *bufferedConn) CloseWrite() error {
	if tc, ok := c.conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}

// sendReply sends a SOCKS5 reply to the client.
// Format: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(var) + BND.PORT(2)
func sendReply(conn net.Conn, rep byte, addr *noise.Address) {
	if addr != nil {
		if encoded := addr.Encode(); encoded != nil {
			reply := make([]byte, 3+len(encoded))
			reply[0] = Version5
			reply[1] = rep
			reply[2] = 0x00 // RSV
			copy(reply[3:], encoded)
			conn.Write(reply)
			return
		}
	}

	// Default bound address: 0.0.0.0:0
	conn.Write([]byte{Version5, rep, 0x00, noise.AddressTypeIPv4, 0, 0, 0, 0, 0, 0})
}

// ReadAddress reads a SOCKS5 address from a reader.
// atyp is the address type byte already read from the stream.
func ReadAddress(r io.Reader, atyp byte) (*noise.Address, error) {
	switch atyp {
	case noise.AddressTypeIPv4:
		var buf [6]byte // 4 bytes IP + 2 bytes port
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, err
		}
		return &noise.Address{
			Type: noise.AddressTypeIPv4,
			Host: net.IP(buf[:4]).String(),
			Port: binary.BigEndian.Uint16(buf[4:6]),
		}, nil

	case noise.AddressTypeDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, err
		}
		domainLen := int(lenBuf[0])
		if domainLen == 0 {
			return nil, ErrInvalidAddress
		}
		buf := make([]byte, domainLen+2) // domain + 2 bytes port
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return &noise.Address{
			Type: noise.AddressTypeDomain,
			Host: string(buf[:domainLen]),
			Port: binary.BigEndian.Uint16(buf[domainLen:]),
		}, nil

	case noise.AddressTypeIPv6:
		var buf [18]byte // 16 bytes IP + 2 bytes port
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, err
		}
		return &noise.Address{
			Type: noise.AddressTypeIPv6,
			Host: net.IP(buf[:16]).String(),
			Port: binary.BigEndian.Uint16(buf[16:18]),
		}, nil

	default:
		return nil, fmt.Errorf("proxy: unsupported address type 0x%02x", atyp)
	}
}

// Relay copies data bidirectionally between two ReadWriteClosers.
// Returns when either direction encounters an error or EOF.
// Supports half-close via CloseWrite if the underlying type supports it.
func Relay(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	// a → b
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if tc, ok := b.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
	}()

	// b → a
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		if tc, ok := a.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

// ParseSOCKS5UDP parses a SOCKS5 UDP datagram.
// Format: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(var) + DST.PORT(2) + DATA(var)
// Returns the target address and the data payload.
func ParseSOCKS5UDP(data []byte) (addr *noise.Address, payload []byte, err error) {
	if len(data) < 4 {
		return nil, nil, errors.New("proxy: UDP datagram too short")
	}
	if data[0] != 0 || data[1] != 0 {
		return nil, nil, errors.New("proxy: invalid RSV in UDP datagram")
	}
	if data[2] != 0 {
		return nil, nil, errors.New("proxy: fragmented UDP not supported")
	}
	// Decode address starting at byte 3 (atyp + addr + port)
	addr, consumed, err := noise.DecodeAddress(data[3:])
	if err != nil {
		return nil, nil, err
	}
	payload = data[3+consumed:]
	return addr, payload, nil
}

// BuildSOCKS5UDP builds a SOCKS5 UDP datagram.
// Format: RSV(2) + FRAG(1) + ATYP(1) + SRC.ADDR(var) + SRC.PORT(2) + DATA(var)
func BuildSOCKS5UDP(addr *noise.Address, data []byte) []byte {
	encoded := addr.Encode()
	if encoded == nil {
		return nil
	}
	pkt := make([]byte, 3+len(encoded)+len(data))
	// RSV(2) + FRAG(1) = 0x00 0x00 0x00
	copy(pkt[3:], encoded)
	copy(pkt[3+len(encoded):], data)
	return pkt
}
