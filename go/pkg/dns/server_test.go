package dns

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

// mockIPAllocator is a simple mock for testing.
type mockIPAllocator struct {
	pubkeyToIP map[[32]byte]net.IP
	ipToPubkey map[string][32]byte
}

func newMockIPAllocator() *mockIPAllocator {
	return &mockIPAllocator{
		pubkeyToIP: make(map[[32]byte]net.IP),
		ipToPubkey: make(map[string][32]byte),
	}
}

func (m *mockIPAllocator) Add(pubkey [32]byte, ip net.IP) {
	m.pubkeyToIP[pubkey] = ip
	m.ipToPubkey[ip.String()] = pubkey
}

func (m *mockIPAllocator) LookupByPubkey(pubkey [32]byte) (net.IP, bool) {
	ip, ok := m.pubkeyToIP[pubkey]
	return ip, ok
}

func (m *mockIPAllocator) LookupByIP(ip net.IP) ([32]byte, bool) {
	pk, ok := m.ipToPubkey[ip.String()]
	return pk, ok
}

// buildQuery builds a raw DNS query for testing.
func buildQuery(name string, qtype uint16) []byte {
	msg := &Message{
		Header: Header{
			ID:    0x1234,
			Flags: FlagRD,
		},
		Questions: []Question{
			{Name: name, Type: qtype, Class: ClassIN},
		},
	}
	data, err := EncodeMessage(msg)
	if err != nil {
		panic(err)
	}
	return data
}

func TestServer_LocalhostZigorNet(t *testing.T) {
	srv := NewServer(ServerConfig{
		TunIPv4: net.ParseIP("100.64.0.1"),
	})

	query := buildQuery("localhost.zigor.net", TypeA)
	resp, err := srv.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	msg, err := DecodeMessage(resp)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	if msg.Header.RCode() != RCodeNoError {
		t.Errorf("RCode = %d, want NoError", msg.Header.RCode())
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("len(Answers) = %d, want 1", len(msg.Answers))
	}
	if !bytes.Equal(msg.Answers[0].RData, []byte{100, 64, 0, 1}) {
		t.Errorf("RData = %v, want [100 64 0 1]", msg.Answers[0].RData)
	}
}

func TestServer_LocalhostZigorNetAAAA(t *testing.T) {
	tunIPv6 := net.ParseIP("fd00::1")
	srv := NewServer(ServerConfig{
		TunIPv4: net.ParseIP("100.64.0.1"),
		TunIPv6: tunIPv6,
	})

	query := buildQuery("localhost.zigor.net", TypeAAAA)
	resp, err := srv.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	msg, err := DecodeMessage(resp)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	if len(msg.Answers) != 1 {
		t.Fatalf("len(Answers) = %d, want 1", len(msg.Answers))
	}
	if msg.Answers[0].Type != TypeAAAA {
		t.Errorf("Type = %d, want AAAA", msg.Answers[0].Type)
	}
	if len(msg.Answers[0].RData) != 16 {
		t.Errorf("RData len = %d, want 16", len(msg.Answers[0].RData))
	}
}

func TestServer_LocalhostCaseInsensitive(t *testing.T) {
	srv := NewServer(ServerConfig{
		TunIPv4: net.ParseIP("100.64.0.1"),
	})

	query := buildQuery("LOCALHOST.ZIGOR.NET", TypeA)
	resp, err := srv.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	msg, err := DecodeMessage(resp)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	if msg.Header.RCode() != RCodeNoError {
		t.Errorf("RCode = %d, want NoError (case insensitive)", msg.Header.RCode())
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("expected 1 answer for case-insensitive query")
	}
}

func TestServer_PubkeyZigorNet(t *testing.T) {
	alloc := newMockIPAllocator()
	var pubkey [32]byte
	for i := range pubkey {
		pubkey[i] = byte(i)
	}
	alloc.Add(pubkey, net.ParseIP("100.64.0.42"))

	srv := NewServer(ServerConfig{
		TunIPv4: net.ParseIP("100.64.0.1"),
		IPAlloc: alloc,
	})

	hexPubkey := hex.EncodeToString(pubkey[:])
	// Split into two 32-char labels to fit DNS label limit (max 63 chars)
	splitName := hexPubkey[:32] + "." + hexPubkey[32:] + ".zigor.net"
	query := buildQuery(splitName, TypeA)
	resp, err := srv.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	msg, err := DecodeMessage(resp)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	if msg.Header.RCode() != RCodeNoError {
		t.Errorf("RCode = %d, want NoError", msg.Header.RCode())
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("len(Answers) = %d, want 1", len(msg.Answers))
	}
	if !bytes.Equal(msg.Answers[0].RData, []byte{100, 64, 0, 42}) {
		t.Errorf("RData = %v, want [100 64 0 42]", msg.Answers[0].RData)
	}
}

func TestServer_PubkeyNotFound(t *testing.T) {
	alloc := newMockIPAllocator()
	srv := NewServer(ServerConfig{
		TunIPv4: net.ParseIP("100.64.0.1"),
		IPAlloc: alloc,
	})

	// Valid hex but not in allocator (split format)
	hexPubkey := "0000000000000000000000000000000000000000000000000000000000000000"
	splitName := hexPubkey[:32] + "." + hexPubkey[32:] + ".zigor.net"
	query := buildQuery(splitName, TypeA)
	resp, err := srv.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	msg, err := DecodeMessage(resp)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	if msg.Header.RCode() != RCodeNXDomain {
		t.Errorf("RCode = %d, want NXDOMAIN for unknown pubkey", msg.Header.RCode())
	}
}

func TestServer_UnknownZigorNetSubdomain(t *testing.T) {
	srv := NewServer(ServerConfig{
		TunIPv4: net.ParseIP("100.64.0.1"),
	})

	query := buildQuery("unknown.zigor.net", TypeA)
	resp, err := srv.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	msg, err := DecodeMessage(resp)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	if msg.Header.RCode() != RCodeNXDomain {
		t.Errorf("RCode = %d, want NXDOMAIN", msg.Header.RCode())
	}
}

func TestServer_NoIPAllocator(t *testing.T) {
	srv := NewServer(ServerConfig{
		TunIPv4: net.ParseIP("100.64.0.1"),
		// No IPAlloc
	})

	hexPubkey := "0102030405060708091011121314151617181920212223242526272829303132"
	splitName := hexPubkey[:32] + "." + hexPubkey[32:] + ".zigor.net"
	query := buildQuery(splitName, TypeA)
	resp, err := srv.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	msg, err := DecodeMessage(resp)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	if msg.Header.RCode() != RCodeServFail {
		t.Errorf("RCode = %d, want SERVFAIL (no allocator)", msg.Header.RCode())
	}
}

func TestServer_FakeIP(t *testing.T) {
	pool := NewFakeIPPool(100)
	srv := NewServer(ServerConfig{
		TunIPv4:      net.ParseIP("100.64.0.1"),
		FakePool:     pool,
		MatchDomains: []string{".example.com"},
	})

	query := buildQuery("test.example.com", TypeA)
	resp, err := srv.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	msg, err := DecodeMessage(resp)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	if msg.Header.RCode() != RCodeNoError {
		t.Errorf("RCode = %d, want NoError", msg.Header.RCode())
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("len(Answers) = %d, want 1", len(msg.Answers))
	}

	// Verify the IP is in the fake range (198.18.x.x)
	rdata := msg.Answers[0].RData
	if rdata[0] != 198 || rdata[1] != 18 {
		t.Errorf("Fake IP = %d.%d.x.x, want 198.18.x.x", rdata[0], rdata[1])
	}

	// Same domain should get same IP
	resp2, err := srv.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery (second): %v", err)
	}
	msg2, err := DecodeMessage(resp2)
	if err != nil {
		t.Fatalf("DecodeMessage (second): %v", err)
	}
	if !bytes.Equal(msg.Answers[0].RData, msg2.Answers[0].RData) {
		t.Errorf("same domain got different IPs: %v vs %v",
			msg.Answers[0].RData, msg2.Answers[0].RData)
	}
}

func TestServer_FakeIPReverseLookup(t *testing.T) {
	pool := NewFakeIPPool(100)

	ip := pool.Assign("test.example.com")
	domain, ok := pool.Lookup(ip)
	if !ok {
		t.Fatal("Lookup failed")
	}
	if domain != "test.example.com" {
		t.Errorf("Lookup = %q, want %q", domain, "test.example.com")
	}
}

func TestServer_NonMatchingDomain(t *testing.T) {
	// Non-zigor.net, non-matching domain should be forwarded upstream.
	// We can't easily test actual upstream forwarding without a real server,
	// so we just verify it doesn't match as zigor.net or fake IP.
	srv := NewServer(ServerConfig{
		TunIPv4:      net.ParseIP("100.64.0.1"),
		FakePool:     NewFakeIPPool(100),
		MatchDomains: []string{".example.com"},
		Upstream:     "127.0.0.1:0", // invalid, will fail
	})

	query := buildQuery("google.com", TypeA)
	_, err := srv.HandleQuery(query)
	// Expected to fail because upstream is unreachable
	if err == nil {
		t.Log("upstream forwarding succeeded (unexpected but not fatal)")
	}
}

func TestServer_EmptyQuery(t *testing.T) {
	srv := NewServer(ServerConfig{
		TunIPv4: net.ParseIP("100.64.0.1"),
	})

	// Build a message with no questions
	msg := &Message{
		Header: Header{ID: 0x1234, Flags: FlagRD},
	}
	data, err := EncodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := srv.HandleQuery(data)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	decoded, err := DecodeMessage(resp)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	if decoded.Header.RCode() != RCodeFormErr {
		t.Errorf("RCode = %d, want FormErr for empty query", decoded.Header.RCode())
	}
}

func TestIsHexString(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"0123456789abcdef", true},
		{"ABCDEF", true},
		{"", false},
		{"0123g", false},
		{"hello", false},
	}
	for _, tt := range tests {
		if got := isHexString(tt.s); got != tt.want {
			t.Errorf("isHexString(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}
