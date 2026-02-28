package net

import (
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// createConnectedPair creates two connected UDP instances for testing.
// Returns (server, client, serverKey, clientKey).
// Caller must Close() both.
func createConnectedPair(t *testing.T, serverOpts ...Option) (*UDP, *UDP, *noise.KeyPair, *noise.KeyPair) {
	t.Helper()

	serverKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	clientKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	baseOpts := []Option{WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true)}
	server, err := NewUDP(serverKey, append(baseOpts, serverOpts...)...)
	if err != nil {
		t.Fatalf("NewUDP server: %v", err)
	}

	client, err := NewUDP(clientKey, WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true))
	if err != nil {
		server.Close()
		t.Fatalf("NewUDP client: %v", err)
	}

	serverAddr := server.HostInfo().Addr
	clientAddr := client.HostInfo().Addr
	server.SetPeerEndpoint(clientKey.Public, clientAddr)
	client.SetPeerEndpoint(serverKey.Public, serverAddr)

	// Start receive loops (needed for handshake + packet routing)
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, _, err := client.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	// Server receive loop — don't consume ReadFrom so outputChan fills up.
	// Let the ioLoop + decrypt workers run but nobody drains outputChan.
	// We start this ONLY for handshake processing; individual tests may
	// choose not to drain further.

	// Actually, we DO need a reader during handshake. We'll start it and
	// let the caller decide whether to stop it.
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, _, err := server.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	// Handshake
	if err := client.Connect(serverKey.Public); err != nil {
		client.Close()
		server.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	return server, client, serverKey, clientKey
}

// TestPacketLeakWhenOutputChanFull verifies that packets sent to decryptChan
// but dropped from outputChan (because it's full) are still properly released.
//
// Bug: When outputChan is full, ioLoop's second select hits default. The packet
// is already in decryptChan and will be processed by a worker, but nobody calls
// releasePacket — ReadFrom only releases packets it receives from outputChan.
func TestPacketLeakWhenOutputChanFull(t *testing.T) {
	serverKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	clientKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Server with tiny outputChan (1 slot) — fills up immediately.
	server, err := NewUDP(serverKey,
		WithBindAddr("127.0.0.1:0"),
		WithAllowUnknown(true),
		WithDecryptedChanSize(1),
		WithDecryptWorkers(1),
	)
	if err != nil {
		t.Fatalf("NewUDP server: %v", err)
	}
	defer server.Close()

	client, err := NewUDP(clientKey,
		WithBindAddr("127.0.0.1:0"),
		WithAllowUnknown(true),
	)
	if err != nil {
		t.Fatalf("NewUDP client: %v", err)
	}
	defer client.Close()

	serverAddr := server.HostInfo().Addr
	clientAddr := client.HostInfo().Addr
	server.SetPeerEndpoint(clientKey.Public, clientAddr)
	client.SetPeerEndpoint(serverKey.Public, serverAddr)

	// Client needs a reader for handshake response
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, _, err := client.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	// Temporarily read from server to allow handshake to complete.
	// We use a channel to stop the reader after handshake.
	hsComplete := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-hsComplete:
				return
			default:
			}
			if _, _, err := server.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	if err := client.Connect(serverKey.Public); err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Stop the server reader — outputChan will now fill up and stay full.
	close(hsComplete)
	time.Sleep(50 * time.Millisecond)

	// Record baseline outstanding packets
	before := outstandingPackets.Load()

	// Send 50 packets. With outputChan=1, most will hit the default branch
	// in ioLoop's second select (outputChan full). These packets go to
	// decryptChan, get processed, but nobody releases them.
	const numPackets = 50
	for i := 0; i < numPackets; i++ {
		if err := client.WriteTo(serverKey.Public, []byte("leak-test")); err != nil {
			t.Logf("WriteTo %d: %v", i, err)
		}
	}

	// Wait for all packets to be processed by decrypt workers
	time.Sleep(1 * time.Second)

	after := outstandingPackets.Load()
	leaked := after - before

	// Allow up to outputChanSize (1) packets to be legitimately queued
	// in the outputChan waiting for ReadFrom to drain them.
	const outputChanSize = 1
	if leaked > outputChanSize {
		t.Errorf("PACKET POOL LEAK: %d packets acquired but never released "+
			"(before=%d, after=%d, allowed=%d in outputChan). "+
			"Packets processed by decryptWorker but not in outputChan should be released.",
			leaked, before, after, outputChanSize)
	}
}

// TestClosedChanGoroutineLeak verifies that AcceptStream does not leak
// goroutines via closedChan().
//
// Bug: closedChan() creates a new goroutine each time it's called. When
// AcceptStream returns (e.g., a stream arrives), the closedChan goroutine
// keeps running until UDP is closed. N calls = N leaked goroutines.
func TestClosedChanGoroutineLeak(t *testing.T) {
	server, client, serverKey, clientKey := createConnectedPair(t)
	defer server.Close()
	defer client.Close()

	// Let goroutines settle
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	// Call AcceptStream 10 times, each time opening a stream so it returns.
	// After AcceptStream returns, its closedChan goroutine should be gone
	// (but with the current bug, it keeps running).
	const iterations = 10
	for i := 0; i < iterations; i++ {
		// Accept in background
		accepted := make(chan io.ReadWriteCloser, 1)
		go func() {
			s, _, err := server.AcceptStream(clientKey.Public)
			if err != nil {
				return
			}
			accepted <- s
		}()

		time.Sleep(20 * time.Millisecond)
		cs, err := client.OpenStream(serverKey.Public, 0)
		if err != nil {
			t.Fatalf("OpenStream %d: %v", i, err)
		}

		select {
		case ss := <-accepted:
			ss.Close()
		case <-time.After(3 * time.Second):
			t.Fatalf("Timeout waiting for AcceptStream %d", i)
		}
		cs.Close()
	}

	// All AcceptStream calls have returned. Let goroutines settle.
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	after := runtime.NumGoroutine()
	leaked := after - baseline

	// With the bug: each AcceptStream call leaks 1 closedChan goroutine.
	// 10 iterations = ~10 leaked goroutines.
	// Without the bug: all goroutines exit when AcceptStream returns.
	// Allow some slack for GC / runtime noise.
	if leaked > 3 {
		t.Errorf("GOROUTINE LEAK: %d goroutines leaked after %d AcceptStream calls "+
			"(baseline=%d, after=%d). closedChan() likely leaking goroutines.",
			leaked, iterations, baseline, after)
	}
}
