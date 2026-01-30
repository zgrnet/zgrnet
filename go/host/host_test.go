package host

import (
	"testing"
	"time"

	"github.com/vibing/zgrnet/noise"
)

func TestNewHost(t *testing.T) {
	kp, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	transport := noise.NewMockTransport("test")
	defer transport.Close()

	h, err := NewHost(HostConfig{
		PrivateKey: kp,
		Transport:  transport,
	})
	if err != nil {
		t.Fatalf("Failed to create host: %v", err)
	}
	defer h.Close()

	if h.PublicKey() != kp.Public {
		t.Errorf("Expected public key %x, got %x", kp.Public, h.PublicKey())
	}
}

func TestHostGeneratesKeyPair(t *testing.T) {
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	h, err := NewHost(HostConfig{
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("Failed to create host: %v", err)
	}
	defer h.Close()

	pk := h.PublicKey()
	var zero noise.PublicKey
	if pk == zero {
		t.Error("Expected non-zero public key")
	}
}

func TestHostAddRemovePeer(t *testing.T) {
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	h, err := NewHost(HostConfig{
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("Failed to create host: %v", err)
	}
	defer h.Close()

	peerKP, _ := noise.GenerateKeyPair()

	// Add peer
	if err := h.AddPeer(peerKP.Public, nil); err != nil {
		t.Fatalf("Failed to add peer: %v", err)
	}

	// Check peer exists
	info := h.GetPeer(peerKP.Public)
	if info == nil {
		t.Fatal("Expected peer to exist")
	}

	// Check list
	peers := h.ListPeers()
	if len(peers) != 1 {
		t.Errorf("Expected 1 peer, got %d", len(peers))
	}

	// Remove peer
	h.RemovePeer(peerKP.Public)

	info = h.GetPeer(peerKP.Public)
	if info != nil {
		t.Error("Expected peer to be removed")
	}

	peers = h.ListPeers()
	if len(peers) != 0 {
		t.Errorf("Expected 0 peers, got %d", len(peers))
	}
}

func TestHostClose(t *testing.T) {
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	h, err := NewHost(HostConfig{
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("Failed to create host: %v", err)
	}

	if err := h.Close(); err != nil {
		t.Errorf("Failed to close host: %v", err)
	}

	// Recv should return ErrHostClosed
	_, err = h.Recv()
	if err != ErrHostClosed {
		t.Errorf("Expected ErrHostClosed, got %v", err)
	}
}

func TestHostRecvTimeout(t *testing.T) {
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	h, err := NewHost(HostConfig{
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("Failed to create host: %v", err)
	}
	defer h.Close()

	start := time.Now()
	_, err = h.RecvTimeout(50 * time.Millisecond)
	elapsed := time.Since(start)

	if err != ErrTimeout {
		t.Errorf("Expected ErrTimeout, got %v", err)
	}

	if elapsed < 45*time.Millisecond || elapsed > 100*time.Millisecond {
		t.Errorf("Expected ~50ms timeout, got %v", elapsed)
	}
}
