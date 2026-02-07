package dns

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// TestServerListenAndServe tests the full UDP server lifecycle:
// start, query via real UDP, and graceful shutdown.
func TestServerListenAndServe(t *testing.T) {
	srv := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0", // OS picks free port
		TunIPv4:    net.ParseIP("100.64.0.1"),
	})

	// Start server in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	// Wait for server to start by polling
	var serverAddr *net.UDPAddr
	for i := 0; i < 50; i++ {
		srv.mu.RLock()
		conn := srv.conn
		srv.mu.RUnlock()
		if conn != nil {
			serverAddr = conn.LocalAddr().(*net.UDPAddr)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if serverAddr == nil {
		t.Fatal("server did not start in time")
	}

	// Send a real DNS query via UDP
	client, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	query := buildQuery("localhost.zigor.net", TypeA)
	_, err = client.Write(query)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read response
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	resp, err := DecodeMessage(buf[:n])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Header.RCode() != RCodeNoError {
		t.Errorf("RCode = %d, want NoError", resp.Header.RCode())
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("len(Answers) = %d, want 1", len(resp.Answers))
	}
	if !bytes.Equal(resp.Answers[0].RData, []byte{100, 64, 0, 1}) {
		t.Errorf("RData = %v, want [100 64 0 1]", resp.Answers[0].RData)
	}

	// Graceful shutdown
	if err := srv.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// ListenAndServe should return nil on graceful close
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("ListenAndServe returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not exit after Close")
	}
}

// TestServerUpstreamForwarding tests forwarding to a real (fake) upstream.
func TestServerUpstreamForwarding(t *testing.T) {
	// Start a fake upstream DNS server
	upstreamAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := net.ListenUDP("udp", upstreamAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	// Fake upstream: read query, respond with a canned answer
	go func() {
		buf := make([]byte, 4096)
		n, remote, err := upstream.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Parse query, build response
		msg, err := DecodeMessage(buf[:n])
		if err != nil {
			return
		}
		resp := NewResponse(msg, RCodeNoError)
		resp.Answers = []ResourceRecord{
			NewARecord(msg.Questions[0].Name, 300, [4]byte{93, 184, 216, 34}),
		}
		data, _ := EncodeMessage(resp)
		upstream.WriteToUDP(data, remote)
	}()

	actualAddr := upstream.LocalAddr().(*net.UDPAddr)
	srv := NewServer(ServerConfig{
		TunIPv4:  net.ParseIP("100.64.0.1"),
		Upstream: actualAddr.String(),
	})

	// Query a non-zigor.net domain -> should forward to upstream
	query := buildQuery("example.com", TypeA)
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
	if !bytes.Equal(msg.Answers[0].RData, []byte{93, 184, 216, 34}) {
		t.Errorf("RData = %v, want [93 184 216 34]", msg.Answers[0].RData)
	}
}

// TestServerMalformedQuery tests that malformed queries are handled.
func TestServerMalformedQuery(t *testing.T) {
	srv := NewServer(ServerConfig{
		TunIPv4: net.ParseIP("100.64.0.1"),
	})

	// Totally invalid data
	_, err := srv.HandleQuery([]byte{0x00, 0x01})
	if err == nil {
		t.Error("expected error for malformed query")
	}
}

// TestServerListenAndServe_MalformedDrop tests that the server drops
// malformed queries without crashing (integration test).
func TestServerListenAndServe_MalformedDrop(t *testing.T) {
	srv := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TunIPv4:    net.ParseIP("100.64.0.1"),
	})

	go srv.ListenAndServe()
	defer srv.Close()

	// Wait for server
	for i := 0; i < 50; i++ {
		srv.mu.RLock()
		conn := srv.conn
		srv.mu.RUnlock()
		if conn != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.mu.RLock()
	conn := srv.conn
	srv.mu.RUnlock()
	if conn == nil {
		t.Fatal("server did not start")
	}

	addr := conn.LocalAddr().(*net.UDPAddr)
	client, _ := net.DialUDP("udp", nil, addr)
	defer client.Close()

	// Send garbage
	client.Write([]byte{0xFF, 0xFF})

	// Send a valid query after garbage -- should still work
	time.Sleep(50 * time.Millisecond)
	query := buildQuery("localhost.zigor.net", TypeA)
	client.Write(query)

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read after malformed: %v", err)
	}
	resp, err := DecodeMessage(buf[:n])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Header.RCode() != RCodeNoError {
		t.Errorf("RCode = %d after malformed, want NoError", resp.Header.RCode())
	}
}

// TestServerCloseBeforeListen tests that Close is safe without ListenAndServe.
func TestServerCloseBeforeListen(t *testing.T) {
	srv := NewServer(ServerConfig{
		TunIPv4: net.ParseIP("100.64.0.1"),
	})
	// Should not panic
	if err := srv.Close(); err != nil {
		t.Errorf("Close before Listen: %v", err)
	}
}

// TestEncodeMessageWithAuthoritiesAndAdditionals tests encoding all RR sections.
func TestEncodeMessageWithAuthoritiesAndAdditionals(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 0x5555, Flags: FlagQR | FlagAA},
		Questions: []Question{
			{Name: "example.com", Type: TypeA, Class: ClassIN},
		},
		Answers: []ResourceRecord{
			NewARecord("example.com", 60, [4]byte{1, 2, 3, 4}),
		},
		Authorities: []ResourceRecord{
			{Name: "example.com", Type: 2 /* NS */, Class: ClassIN, TTL: 3600,
				RData: func() []byte {
					b, _ := encodeName("ns1.example.com")
					return b
				}()},
		},
		Additionals: []ResourceRecord{
			NewARecord("ns1.example.com", 3600, [4]byte{5, 6, 7, 8}),
		},
	}

	encoded, err := EncodeMessage(msg)
	if err != nil {
		t.Fatalf("EncodeMessage: %v", err)
	}

	decoded, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	if len(decoded.Answers) != 1 {
		t.Errorf("Answers = %d, want 1", len(decoded.Answers))
	}
	if len(decoded.Authorities) != 1 {
		t.Errorf("Authorities = %d, want 1", len(decoded.Authorities))
	}
	if len(decoded.Additionals) != 1 {
		t.Errorf("Additionals = %d, want 1", len(decoded.Additionals))
	}
	if decoded.Additionals[0].Name != "ns1.example.com" {
		t.Errorf("Additional name = %q, want %q", decoded.Additionals[0].Name, "ns1.example.com")
	}
}

// TestHeaderOpcode tests the Opcode accessor.
func TestHeaderOpcode(t *testing.T) {
	h := Header{Flags: 0}
	if h.Opcode() != 0 {
		t.Errorf("Opcode = %d, want 0", h.Opcode())
	}

	// Opcode = 1 (IQUERY, bits 14:11 = 0001)
	h.Flags = 1 << 11
	if h.Opcode() != 1 {
		t.Errorf("Opcode = %d, want 1", h.Opcode())
	}

	// Opcode = 2 (STATUS)
	h.Flags = 2 << 11
	if h.Opcode() != 2 {
		t.Errorf("Opcode = %d, want 2", h.Opcode())
	}
}

// TestFakeIPPoolWrapAround tests IP allocation wrapping.
func TestFakeIPPoolWrapAround(t *testing.T) {
	pool := NewFakeIPPool(200000) // large enough to not evict

	// Force the offset near the end
	pool.nextOff = pool.maxOff

	ip1 := pool.Assign("last.com")
	if ip1 == nil {
		t.Fatal("Assign at maxOff returned nil")
	}

	// Next allocation should wrap to offset 1
	ip2 := pool.Assign("wrap.com")
	if ip2 == nil {
		t.Fatal("Assign after wrap returned nil")
	}

	// ip2 should be 198.18.0.1 (base + 1)
	if !ip2.Equal(net.IPv4(198, 18, 0, 1)) {
		t.Errorf("wrapped IP = %v, want 198.18.0.1", ip2)
	}
}

// TestFakeIPPoolEvictEmpty tests eviction on empty pool (edge case).
func TestFakeIPPoolEvictEmpty(t *testing.T) {
	pool := NewFakeIPPool(1)
	// Force evict on empty — should not panic
	pool.evictLRU()
	if pool.Size() != 0 {
		t.Errorf("Size = %d after empty evict", pool.Size())
	}
}

// TestFakeIPPoolLookupNilIP tests Lookup with nil IP.
func TestFakeIPPoolLookupNilIP(t *testing.T) {
	pool := NewFakeIPPool(10)
	_, ok := pool.Lookup(nil)
	if ok {
		t.Error("Lookup(nil) should return false")
	}
}

// TestServerFakeIPAAAA tests that AAAA queries to fake-IP domains return empty.
func TestServerFakeIPAAAA(t *testing.T) {
	pool := NewFakeIPPool(100)
	srv := NewServer(ServerConfig{
		TunIPv4:      net.ParseIP("100.64.0.1"),
		FakePool:     pool,
		MatchDomains: []string{".example.com"},
	})

	query := buildQuery("test.example.com", TypeAAAA)
	resp, err := srv.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	msg, err := DecodeMessage(resp)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	// AAAA for fake IP domain: should be NoError but no answers
	if msg.Header.RCode() != RCodeNoError {
		t.Errorf("RCode = %d, want NoError", msg.Header.RCode())
	}
	if len(msg.Answers) != 0 {
		t.Errorf("len(Answers) = %d, want 0 (no AAAA for fake IP)", len(msg.Answers))
	}
}

// TestServerLocalhostNoIPv6 tests AAAA query when no IPv6 is configured.
func TestServerLocalhostNoIPv6(t *testing.T) {
	srv := NewServer(ServerConfig{
		TunIPv4: net.ParseIP("100.64.0.1"),
		// No TunIPv6
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

	if msg.Header.RCode() != RCodeNoError {
		t.Errorf("RCode = %d, want NoError", msg.Header.RCode())
	}
	// No IPv6 configured -> no answers, but still NoError
	if len(msg.Answers) != 0 {
		t.Errorf("len(Answers) = %d, want 0 (no IPv6)", len(msg.Answers))
	}
}

// TestServerPubkeyAAAA tests AAAA query for pubkey (only A supported).
func TestServerPubkeyAAAA(t *testing.T) {
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

	hexPk := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	splitName := hexPk[:32] + "." + hexPk[32:] + ".zigor.net"
	query := buildQuery(splitName, TypeAAAA)
	resp, err := srv.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	msg, err := DecodeMessage(resp)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	// AAAA for pubkey: NoError but no answers (only IPv4 allocated)
	if msg.Header.RCode() != RCodeNoError {
		t.Errorf("RCode = %d, want NoError", msg.Header.RCode())
	}
	if len(msg.Answers) != 0 {
		t.Errorf("len(Answers) = %d, want 0", len(msg.Answers))
	}
}

// TestServerBareZigorNet tests query for "zigor.net" itself (no subdomain).
func TestServerBareZigorNet(t *testing.T) {
	srv := NewServer(ServerConfig{
		TunIPv4: net.ParseIP("100.64.0.1"),
	})

	query := buildQuery("zigor.net", TypeA)
	resp, err := srv.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	msg, err := DecodeMessage(resp)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	// bare "zigor.net" has empty subdomain -> NXDOMAIN
	if msg.Header.RCode() != RCodeNXDomain {
		t.Errorf("RCode = %d, want NXDOMAIN for bare zigor.net", msg.Header.RCode())
	}
}

// TestDecodeNameTruncatedLabel tests a name where the label extends past data.
func TestDecodeNameTruncatedLabel(t *testing.T) {
	// Label says 10 bytes but only 3 available
	data := []byte{10, 'a', 'b', 'c'}
	_, _, err := decodeName(data, 0)
	if err != ErrTruncated {
		t.Errorf("expected ErrTruncated, got %v", err)
	}
}

// TestDecodeNameTruncatedPointer tests a pointer that extends past data.
func TestDecodeNameTruncatedPointer(t *testing.T) {
	// Compression pointer but only 1 byte
	data := []byte{0xC0}
	_, _, err := decodeName(data, 0)
	if err != ErrTruncated {
		t.Errorf("expected ErrTruncated for short pointer, got %v", err)
	}
}

// TestDecodeRRsTruncated tests truncated resource record section.
func TestDecodeRRsTruncated(t *testing.T) {
	// Valid name followed by incomplete RR fields
	data := []byte{3, 'f', 'o', 'o', 0, 0x00} // name "foo" + 1 byte of RR (need 10)
	_, _, err := decodeRRs(data, 0, 1)
	if err != ErrTruncated {
		t.Errorf("expected ErrTruncated for short RR, got %v", err)
	}
}

// TestDecodeRRsTruncatedRData tests RR with rdlength exceeding data.
func TestDecodeRRsTruncatedRData(t *testing.T) {
	// name "foo" + type(2) + class(2) + ttl(4) + rdlen(2)=100 but no rdata
	data := []byte{
		3, 'f', 'o', 'o', 0, // name
		0, 1, // type = A
		0, 1, // class = IN
		0, 0, 0, 60, // ttl = 60
		0, 100, // rdlen = 100 (but no data follows)
	}
	_, _, err := decodeRRs(data, 0, 1)
	if err != ErrTruncated {
		t.Errorf("expected ErrTruncated for short rdata, got %v", err)
	}
}
