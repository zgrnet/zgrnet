package net

import (
	"testing"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

func TestPeerOpenStreamAcceptStream(t *testing.T) {
	// Generate key pairs
	clientKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}
	serverKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key: %v", err)
	}

	// Create UDP instances
	client, err := NewUDP(clientKey, WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true))
	if err != nil {
		t.Fatalf("Failed to create client UDP: %v", err)
	}
	defer client.Close()

	server, err := NewUDP(serverKey, WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true))
	if err != nil {
		t.Fatalf("Failed to create server UDP: %v", err)
	}
	defer server.Close()

	// Set up peer endpoints
	clientAddr := client.HostInfo().Addr
	serverAddr := server.HostInfo().Addr
	client.SetPeerEndpoint(serverKey.Public, serverAddr)
	server.SetPeerEndpoint(clientKey.Public, clientAddr)

	// Start receive loops
	clientRecvDone := make(chan struct{})
	serverRecvDone := make(chan struct{})

	go func() {
		defer close(clientRecvDone)
		buf := make([]byte, 65535)
		for {
			_, _, err := client.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer close(serverRecvDone)
		buf := make([]byte, 65535)
		for {
			_, _, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	// Connect client to server
	if err := client.Connect(serverKey.Public); err != nil {
		t.Fatalf("Client handshake failed: %v", err)
	}

	// Wait for handshake to complete on server side
	time.Sleep(100 * time.Millisecond)

	// Open stream from client
	clientStream, err := client.OpenStream(serverKey.Public, 0, nil)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}
	defer clientStream.Close()

	// Accept stream on server
	serverStreamChan := make(chan *Stream, 1)
	serverErrChan := make(chan error, 1)
	go func() {
		stream, err := server.AcceptStream(clientKey.Public)
		if err != nil {
			serverErrChan <- err
			return
		}
		serverStreamChan <- stream
	}()

	// Write data from client
	testData := []byte("Hello from client stream!")
	n, err := clientStream.Write(testData)
	if err != nil {
		t.Fatalf("Failed to write to stream: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write returned %d, expected %d", n, len(testData))
	}

	// Wait for server to accept the stream
	var serverStream *Stream
	select {
	case serverStream = <-serverStreamChan:
	case err := <-serverErrChan:
		t.Fatalf("Server AcceptStream failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for server to accept stream")
	}
	defer serverStream.Close()

	// Give time for KCP to process
	time.Sleep(200 * time.Millisecond)

	// Read data on server
	readBuf := make([]byte, 1024)
	n, err = serverStream.Read(readBuf)
	if err != nil {
		t.Fatalf("Failed to read from stream: %v", err)
	}
	if string(readBuf[:n]) != string(testData) {
		t.Errorf("Read data mismatch: got %q, expected %q", string(readBuf[:n]), string(testData))
	}
}

func TestPeerReadWrite(t *testing.T) {
	// Generate key pairs
	clientKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}
	serverKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key: %v", err)
	}

	// Create UDP instances
	client, err := NewUDP(clientKey, WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true))
	if err != nil {
		t.Fatalf("Failed to create client UDP: %v", err)
	}
	defer client.Close()

	server, err := NewUDP(serverKey, WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true))
	if err != nil {
		t.Fatalf("Failed to create server UDP: %v", err)
	}
	defer server.Close()

	// Set up peer endpoints
	clientAddr := client.HostInfo().Addr
	serverAddr := server.HostInfo().Addr
	client.SetPeerEndpoint(serverKey.Public, serverAddr)
	server.SetPeerEndpoint(clientKey.Public, clientAddr)

	// Start receive loops
	go func() {
		buf := make([]byte, 65535)
		for {
			_, _, err := client.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			_, _, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	// Connect client to server
	if err := client.Connect(serverKey.Public); err != nil {
		t.Fatalf("Client handshake failed: %v", err)
	}

	// Wait for handshake
	time.Sleep(100 * time.Millisecond)

	// Test Write with custom protocol
	testData := []byte("Hello with custom protocol!")
	testProto := byte(noise.ProtocolChat) // Use chat protocol

	// Start Read goroutine on server
	readResultChan := make(chan struct {
		proto   byte
		n       int
		err     error
		payload []byte
	}, 1)
	go func() {
		buf := make([]byte, 1024)
		proto, n, err := server.Read(clientKey.Public, buf)
		readResultChan <- struct {
			proto   byte
			n       int
			err     error
			payload []byte
		}{proto, n, err, buf[:n]}
	}()

	// Write from client
	n, err := client.Write(serverKey.Public, testProto, testData)
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write returned %d, expected %d", n, len(testData))
	}

	// Wait for Read result
	select {
	case result := <-readResultChan:
		if result.err != nil {
			t.Fatalf("Read failed: %v", result.err)
		}
		if result.proto != testProto {
			t.Errorf("Protocol mismatch: got %d, expected %d", result.proto, testProto)
		}
		if string(result.payload) != string(testData) {
			t.Errorf("Payload mismatch: got %q, expected %q", string(result.payload), string(testData))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for Read")
	}
}
