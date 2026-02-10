package dns

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Default constants.
const (
	DefaultTTL      = 60 // 60 seconds, short TTL for quick peer updates
	DefaultUpstream = "8.8.8.8:53"
	ZigorNetSuffix  = ".zigor.net"
	LocalhostLabel  = "localhost"
)

// IPAllocator maps public keys to allocated IPs.
// This interface is mocked for now; will be replaced by the real
// IPAllocator from the Host module when integrated.
type IPAllocator interface {
	// LookupByPubkey returns the IPv4 address assigned to the given public key.
	LookupByPubkey(pubkey [32]byte) (net.IP, bool)
	// LookupByIP returns the public key for the given IPv4 address.
	LookupByIP(ip net.IP) ([32]byte, bool)
}

// ServerConfig holds configuration for the DNS server.
type ServerConfig struct {
	// ListenAddr is the address to listen on (e.g., "100.64.0.1:53" or ":5353").
	ListenAddr string
	// TunIPv4 is the local TUN device IPv4 address.
	TunIPv4 net.IP
	// TunIPv6 is the local TUN device IPv6 address (optional).
	TunIPv6 net.IP
	// Upstream is the upstream DNS server address (e.g., "8.8.8.8:53").
	Upstream string
	// IPAlloc is the IP allocator for pubkey -> IP mapping (optional).
	IPAlloc IPAllocator
	// FakePool is the Fake IP pool for route-matched domains (optional).
	FakePool *FakeIPPool
	// MatchDomains are domain suffixes that should get Fake IPs.
	// If a query matches one of these suffixes, a Fake IP is assigned.
	MatchDomains []string
}

// Server is a Magic DNS server.
type Server struct {
	config ServerConfig
	conn   *net.UDPConn
	mu     sync.RWMutex
	closed bool
	wg     sync.WaitGroup
}

// NewServer creates a new DNS server with the given configuration.
func NewServer(config ServerConfig) *Server {
	if config.Upstream == "" {
		config.Upstream = DefaultUpstream
	}
	return &Server{config: config}
}

// upstreamTimeout is the maximum time to wait for an upstream DNS response.
const upstreamTimeout = 5 * time.Second

// ListenAndServe starts the DNS server. Blocks until closed.
func (s *Server) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("dns: resolve listen addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("dns: listen: %w", err)
	}

	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			s.mu.RLock()
			closed := s.closed
			s.mu.RUnlock()
			if closed {
				return nil
			}
			return fmt.Errorf("dns: read: %w", err)
		}

		// Copy the query data for the goroutine
		query := make([]byte, n)
		copy(query, buf[:n])

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			resp, err := s.HandleQuery(query)
			if err != nil {
				return // silently drop malformed queries
			}
			conn.WriteToUDP(resp, remoteAddr)
		}()
	}
}

// Addr returns the server's listener address, or nil if not listening.
func (s *Server) Addr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

// Close shuts down the DNS server.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	conn := s.conn
	s.mu.Unlock()

	if conn != nil {
		conn.Close()
	}
	s.wg.Wait()
	return nil
}

// HandleQuery processes a DNS query and returns the response bytes.
// This is the core resolution logic, exported for testing.
func (s *Server) HandleQuery(queryData []byte) ([]byte, error) {
	msg, err := DecodeMessage(queryData)
	if err != nil {
		return nil, err
	}

	if len(msg.Questions) == 0 {
		resp := NewResponse(msg, RCodeFormErr)
		return EncodeMessage(resp)
	}

	q := msg.Questions[0]
	name := strings.ToLower(q.Name)

	// Try zigor.net resolution first
	if strings.HasSuffix(name, ZigorNetSuffix) || name == "zigor.net" {
		return s.resolveZigorNet(msg, name, q.Type)
	}

	// Try Fake IP matching
	if s.config.FakePool != nil && s.matchesDomain(name) {
		return s.resolveFakeIP(msg, name, q.Type)
	}

	// Forward to upstream
	return s.forwardUpstream(queryData)
}

// resolveZigorNet handles *.zigor.net queries.
func (s *Server) resolveZigorNet(query *Message, name string, qtype uint16) ([]byte, error) {
	// Extract the subdomain part (everything before .zigor.net)
	var subdomain string
	if name == "zigor.net" {
		subdomain = ""
	} else {
		subdomain = strings.TrimSuffix(name, ZigorNetSuffix)
	}

	// "localhost.zigor.net" -> TUN IP
	if subdomain == LocalhostLabel {
		return s.respondWithTunIP(query, name, qtype)
	}

	// "{first32hex}.{last32hex}.zigor.net" -> peer IP via IPAllocator
	// Pubkey is split into two 32-char labels to comply with RFC 1035 (max 63 chars/label).
	if parts := strings.SplitN(subdomain, ".", 2); len(parts) == 2 {
		combined := parts[0] + parts[1]
		if len(combined) == 64 && isHexString(combined) {
			return s.respondWithPeerIP(query, name, combined, qtype)
		}
	}

	// Unknown *.zigor.net subdomain -> NXDOMAIN
	resp := NewResponse(query, RCodeNXDomain)
	return EncodeMessage(resp)
}

// respondWithTunIP creates a response with the local TUN IP.
func (s *Server) respondWithTunIP(query *Message, name string, qtype uint16) ([]byte, error) {
	resp := NewResponse(query, RCodeNoError)

	switch qtype {
	case TypeA:
		if ip4 := s.config.TunIPv4.To4(); ip4 != nil {
			var addr [4]byte
			copy(addr[:], ip4)
			resp.Answers = append(resp.Answers, NewARecord(name, DefaultTTL, addr))
		}
	case TypeAAAA:
		if s.config.TunIPv6 != nil {
			if ip6 := s.config.TunIPv6.To16(); ip6 != nil {
				var addr [16]byte
				copy(addr[:], ip6)
				resp.Answers = append(resp.Answers, NewAAAARecord(name, DefaultTTL, addr))
			}
		}
	}

	return EncodeMessage(resp)
}

// respondWithPeerIP resolves a hex pubkey to a peer IP.
func (s *Server) respondWithPeerIP(query *Message, name, hexPubkey string, qtype uint16) ([]byte, error) {
	if s.config.IPAlloc == nil {
		resp := NewResponse(query, RCodeServFail)
		return EncodeMessage(resp)
	}

	pubkeyBytes, err := hex.DecodeString(hexPubkey)
	if err != nil || len(pubkeyBytes) != 32 {
		resp := NewResponse(query, RCodeNXDomain)
		return EncodeMessage(resp)
	}

	var pubkey [32]byte
	copy(pubkey[:], pubkeyBytes)

	ip, ok := s.config.IPAlloc.LookupByPubkey(pubkey)
	if !ok {
		resp := NewResponse(query, RCodeNXDomain)
		return EncodeMessage(resp)
	}

	resp := NewResponse(query, RCodeNoError)

	switch qtype {
	case TypeA:
		if ip4 := ip.To4(); ip4 != nil {
			var addr [4]byte
			copy(addr[:], ip4)
			resp.Answers = append(resp.Answers, NewARecord(name, DefaultTTL, addr))
		}
	}

	return EncodeMessage(resp)
}

// resolveFakeIP assigns a Fake IP for a route-matched domain.
func (s *Server) resolveFakeIP(query *Message, name string, qtype uint16) ([]byte, error) {
	if qtype != TypeA {
		// Only A records for Fake IPs
		resp := NewResponse(query, RCodeNoError)
		return EncodeMessage(resp)
	}

	ip := s.config.FakePool.Assign(name)
	resp := NewResponse(query, RCodeNoError)
	var addr [4]byte
	copy(addr[:], ip.To4())
	resp.Answers = append(resp.Answers, NewARecord(name, DefaultTTL, addr))
	return EncodeMessage(resp)
}

// forwardUpstream forwards a DNS query to the upstream resolver.
// Each query gets its own UDP socket to avoid response mismatch under
// concurrency (goroutine A reading goroutine B's response on a shared socket).
func (s *Server) forwardUpstream(queryData []byte) ([]byte, error) {
	upstreamAddr, err := net.ResolveUDPAddr("udp", s.config.Upstream)
	if err != nil {
		return nil, fmt.Errorf("dns: resolve upstream: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("dns: dial upstream: %w", err)
	}
	defer conn.Close()

	// Set read deadline to avoid hanging forever (especially on Windows
	// where UDP to unreachable ports doesn't fail fast).
	conn.SetReadDeadline(time.Now().Add(upstreamTimeout))

	_, err = conn.Write(queryData)
	if err != nil {
		return nil, fmt.Errorf("dns: write upstream: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("dns: read upstream: %w", err)
	}

	return buf[:n], nil
}

// matchesDomain checks if the query name matches any of the configured match domains.
func (s *Server) matchesDomain(name string) bool {
	for _, suffix := range s.config.MatchDomains {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// isHexString returns true if s contains only hex characters.
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
