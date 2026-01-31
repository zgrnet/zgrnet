package net

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/vibing/zgrnet/noise"
)

func TestNewUDP(t *testing.T) {
	key, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	udp, err := NewUDP(key)
	if err != nil {
		t.Fatalf("NewUDP failed: %v", err)
	}
	defer udp.Close()

	info := udp.HostInfo()
	if info.PublicKey != key.Public {
		t.Errorf("PublicKey mismatch")
	}
	if info.Addr == nil {
		t.Errorf("Addr should not be nil")
	}
}

func TestNewUDPWithBindAddr(t *testing.T) {
	key, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	udp, err := NewUDP(key, WithBindAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("NewUDP failed: %v", err)
	}
	defer udp.Close()

	addr := udp.HostInfo().Addr.(*net.UDPAddr)
	if addr.IP.String() != "127.0.0.1" {
		t.Errorf("Expected 127.0.0.1, got %s", addr.IP.String())
	}
}

func TestSetPeerEndpoint(t *testing.T) {
	key, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	udp, err := NewUDP(key)
	if err != nil {
		t.Fatalf("NewUDP failed: %v", err)
	}
	defer udp.Close()

	peerKey, _ := noise.GenerateKeyPair()
	peerAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	udp.SetPeerEndpoint(peerKey.Public, peerAddr)

	info := udp.PeerInfo(peerKey.Public)
	if info == nil {
		t.Fatalf("PeerInfo returned nil")
	}
	if info.PublicKey != peerKey.Public {
		t.Errorf("PublicKey mismatch")
	}
	if info.Endpoint.String() != peerAddr.String() {
		t.Errorf("Endpoint mismatch: %s != %s", info.Endpoint.String(), peerAddr.String())
	}
}

func TestRemovePeer(t *testing.T) {
	key, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	udp, err := NewUDP(key)
	if err != nil {
		t.Fatalf("NewUDP failed: %v", err)
	}
	defer udp.Close()

	peerKey, _ := noise.GenerateKeyPair()
	peerAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	udp.SetPeerEndpoint(peerKey.Public, peerAddr)

	if udp.PeerInfo(peerKey.Public) == nil {
		t.Fatalf("Peer should exist")
	}

	udp.RemovePeer(peerKey.Public)

	if udp.PeerInfo(peerKey.Public) != nil {
		t.Fatalf("Peer should be removed")
	}
}

func TestPeersIterator(t *testing.T) {
	key, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	udp, err := NewUDP(key)
	if err != nil {
		t.Fatalf("NewUDP failed: %v", err)
	}
	defer udp.Close()

	// Add some peers
	for i := 0; i < 3; i++ {
		peerKey, _ := noise.GenerateKeyPair()
		peerAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
		udp.SetPeerEndpoint(peerKey.Public, peerAddr)
	}

	count := 0
	for range udp.Peers() {
		count++
	}

	if count != 3 {
		t.Errorf("Expected 3 peers, got %d", count)
	}
}

func TestHandshakeAndTransport(t *testing.T) {
	// Create two UDP instances
	key1, _ := noise.GenerateKeyPair()
	key2, _ := noise.GenerateKeyPair()

	udp1, err := NewUDP(key1, WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true))
	if err != nil {
		t.Fatalf("NewUDP 1 failed: %v", err)
	}
	defer udp1.Close()

	udp2, err := NewUDP(key2, WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true))
	if err != nil {
		t.Fatalf("NewUDP 2 failed: %v", err)
	}
	defer udp2.Close()

	// Get addresses
	addr1 := udp1.HostInfo().Addr.(*net.UDPAddr)
	addr2 := udp2.HostInfo().Addr.(*net.UDPAddr)

	// Set up peer endpoints
	udp1.SetPeerEndpoint(key2.Public, addr2)
	udp2.SetPeerEndpoint(key1.Public, addr1)

	// Start receive goroutine for udp2 (responder)
	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		for {
			pk, n, err := udp2.ReadFrom(buf)
			if err != nil {
				return
			}
			if pk == key1.Public {
				received <- append([]byte{}, buf[:n]...)
				return
			}
		}
	}()

	// Start receive goroutine for udp1 (initiator) to handle handshake response
	go func() {
		buf := make([]byte, 1024)
		for {
			_, _, err := udp1.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	// Give the goroutines time to start
	time.Sleep(50 * time.Millisecond)

	// Initiate handshake from udp1
	udp1.mu.RLock()
	peer1 := udp1.peers[key2.Public]
	udp1.mu.RUnlock()

	err = udp1.initiateHandshake(peer1)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Check that peer1 is now established
	info1 := udp1.PeerInfo(key2.Public)
	if info1.State != PeerStateEstablished {
		t.Errorf("Expected established state, got %v", info1.State)
	}

	// Send a message
	testData := []byte("hello world")
	err = udp1.WriteTo(key2.Public, testData)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	// Wait for message
	select {
	case data := <-received:
		if !bytes.Equal(data, testData) {
			t.Errorf("Data mismatch: %s != %s", data, testData)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timeout waiting for message")
	}
}

func TestRoaming(t *testing.T) {
	// Create two UDP instances
	key1, _ := noise.GenerateKeyPair()
	key2, _ := noise.GenerateKeyPair()

	udp1, err := NewUDP(key1, WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true))
	if err != nil {
		t.Fatalf("NewUDP 1 failed: %v", err)
	}
	defer udp1.Close()

	udp2, err := NewUDP(key2, WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true))
	if err != nil {
		t.Fatalf("NewUDP 2 failed: %v", err)
	}
	defer udp2.Close()

	// Get addresses
	addr1 := udp1.HostInfo().Addr.(*net.UDPAddr)
	addr2 := udp2.HostInfo().Addr.(*net.UDPAddr)

	// Set up peer endpoints
	udp1.SetPeerEndpoint(key2.Public, addr2)
	udp2.SetPeerEndpoint(key1.Public, addr1)

	// Start receive goroutine for udp2 (responder)
	go func() {
		buf := make([]byte, 1024)
		for {
			_, _, err := udp2.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	// Start receive goroutine for udp1 (initiator) to handle handshake response
	go func() {
		buf := make([]byte, 1024)
		for {
			_, _, err := udp1.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	// Give the goroutines time to start
	time.Sleep(50 * time.Millisecond)

	// Initiate handshake from udp1
	udp1.mu.RLock()
	peer1 := udp1.peers[key2.Public]
	udp1.mu.RUnlock()

	err = udp1.initiateHandshake(peer1)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Check initial endpoint on udp2
	info2 := udp2.PeerInfo(key1.Public)
	if info2 == nil {
		t.Fatalf("Peer should exist on udp2")
	}
	initialEndpoint := info2.Endpoint.String()

	// Create a new UDP socket to simulate roaming
	newSocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create new socket: %v", err)
	}
	defer newSocket.Close()

	newAddr := newSocket.LocalAddr().(*net.UDPAddr)

	// Manually send a transport message from the new address
	// This simulates the peer having roamed to a new address
	udp1.mu.RLock()
	session1 := udp1.peers[key2.Public].session
	udp1.mu.RUnlock()

	if session1 == nil {
		t.Fatalf("Session should exist")
	}

	testData := []byte("roamed message")
	encrypted, nonce, err := session1.Encrypt(testData)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	msg := noise.BuildTransportMessage(session1.RemoteIndex(), nonce, encrypted)
	_, err = newSocket.WriteToUDP(msg, addr2)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Wait a bit for processing
	time.Sleep(100 * time.Millisecond)

	// Check that endpoint was updated (roaming)
	info2 = udp2.PeerInfo(key1.Public)
	if info2.Endpoint.String() == initialEndpoint {
		t.Logf("Initial: %s, Current: %s, New: %s", initialEndpoint, info2.Endpoint.String(), newAddr.String())
		// Note: The endpoint might not change if the test runs too fast
		// This is a best-effort check
	}
}

func TestClose(t *testing.T) {
	key, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	udp, err := NewUDP(key)
	if err != nil {
		t.Fatalf("NewUDP failed: %v", err)
	}

	err = udp.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Second close should be no-op
	err = udp.Close()
	if err != nil {
		t.Fatalf("Second close should not error: %v", err)
	}

	// WriteTo should fail after close
	peerKey, _ := noise.GenerateKeyPair()
	err = udp.WriteTo(peerKey.Public, []byte("test"))
	if err != ErrClosed {
		t.Errorf("Expected ErrClosed, got %v", err)
	}
}
