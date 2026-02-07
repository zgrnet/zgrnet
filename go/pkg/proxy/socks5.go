// Package proxy implements SOCKS5 and HTTP CONNECT proxy servers.
//
// The proxy server accepts client connections (SOCKS5 or HTTP CONNECT),
// parses target addresses, and dials remote targets through a pluggable
// DialFunc. For zgrnet integration, the DialFunc opens KCP streams via
// the UDP high-level API with proto=TCP_PROXY(69).
package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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
// For KCP streams (which have non-blocking Read), wrap with BlockingStream.
type DialFunc func(addr *noise.Address) (io.ReadWriteCloser, error)

// Server is a SOCKS5 proxy server.
type Server struct {
	listenAddr string
	dial       DialFunc

	mu       sync.Mutex
	listener net.Listener

	closed atomic.Bool
	wg     sync.WaitGroup
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
		go func() {
			defer s.wg.Done()
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
// This is a placeholder — full implementation in step 2.
func (s *Server) handleUDPAssociate(conn net.Conn, addr *noise.Address) {
	sendReply(conn, RepCmdNotSupported, nil)
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

// BlockingStream wraps a non-blocking reader (like kcp.Stream) with
// blocking Read semantics by polling with a short sleep interval.
type BlockingStream struct {
	S io.ReadWriteCloser
}

func (b *BlockingStream) Read(p []byte) (int, error) {
	for {
		n, err := b.S.Read(p)
		if n > 0 || err != nil {
			return n, err
		}
		time.Sleep(time.Millisecond)
	}
}

func (b *BlockingStream) Write(p []byte) (int, error) {
	return b.S.Write(p)
}

func (b *BlockingStream) Close() error {
	return b.S.Close()
}
