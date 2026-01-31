package net

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/vibing/zgrnet/noise"
)

func TestNewListenerMissingLocalKey(t *testing.T) {
	_, err := NewListener(ListenerConfig{
		Transport: NewMockTransport("test"),
	})
	if err != ErrMissingLocalKey {
		t.Errorf("NewListener() error = %v, want ErrMissingLocalKey", err)
	}
}

func TestNewListenerMissingTransport(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	_, err := NewListener(ListenerConfig{
		LocalKey: key,
	})
	if err != ErrMissingTransport {
		t.Errorf("NewListener() error = %v, want ErrMissingTransport", err)
	}
}

func TestNewListenerSuccess(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")

	listener, err := NewListener(ListenerConfig{
		LocalKey:  key,
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("NewListener() error = %v", err)
	}
	defer listener.Close()

	if listener.LocalPublicKey() != key.Public {
		t.Error("LocalPublicKey() mismatch")
	}

	if listener.LocalAddr().String() != "test" {
		t.Errorf("LocalAddr() = %s, want test", listener.LocalAddr().String())
	}
}

func TestListenerClose(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")

	listener, _ := NewListener(ListenerConfig{
		LocalKey:  key,
		Transport: transport,
	})

	// Close should work
	if err := listener.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Double close should be ok
	if err := listener.Close(); err != nil {
		t.Errorf("Double Close() error = %v", err)
	}
}

func TestListenerAcceptAfterClose(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")

	listener, _ := NewListener(ListenerConfig{
		LocalKey:  key,
		Transport: transport,
	})

	listener.Close()

	_, err := listener.Accept()
	if err != ErrListenerClosed {
		t.Errorf("Accept() error = %v, want ErrListenerClosed", err)
	}
}

func TestListenerAcceptConnection(t *testing.T) {
	// Create listener with real UDP
	serverKey, _ := noise.GenerateKeyPair()
	serverTransport, err := NewUDPTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewUDPTransport() error = %v", err)
	}
	defer serverTransport.Close()

	listener, err := NewListener(ListenerConfig{
		LocalKey:  serverKey,
		Transport: serverTransport,
	})
	if err != nil {
		t.Fatalf("NewListener() error = %v", err)
	}
	defer listener.Close()

	// Create client with real UDP
	clientKey, _ := noise.GenerateKeyPair()
	clientTransport, err := NewUDPTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewUDPTransport() error = %v", err)
	}
	defer clientTransport.Close()

	// Start client dial in goroutine
	done := make(chan error)
	var clientConn *Conn
	go func() {
		var err error
		clientConn, err = Dial(context.Background(), clientTransport, serverTransport.LocalAddr(), serverKey.Public, clientKey)
		done <- err
	}()

	// Accept connection on server
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}

	// Wait for client dial to complete
	if err := <-done; err != nil {
		t.Fatalf("Client Dial() error = %v", err)
	}

	// Verify both sides are established
	if clientConn.State() != ConnStateEstablished {
		t.Errorf("Client state = %v, want ConnStateEstablished", clientConn.State())
	}
	if serverConn.State() != ConnStateEstablished {
		t.Errorf("Server state = %v, want ConnStateEstablished", serverConn.State())
	}

	// Verify remote public keys
	if clientConn.RemotePublicKey() != serverKey.Public {
		t.Error("Client remote public key mismatch")
	}
	if serverConn.RemotePublicKey() != clientKey.Public {
		t.Error("Server remote public key mismatch")
	}
}

func TestListenerMultipleConnections(t *testing.T) {
	// Create listener with real UDP
	serverKey, _ := noise.GenerateKeyPair()
	serverTransport, err := NewUDPTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewUDPTransport() error = %v", err)
	}
	defer serverTransport.Close()

	listener, err := NewListener(ListenerConfig{
		LocalKey:  serverKey,
		Transport: serverTransport,
	})
	if err != nil {
		t.Fatalf("NewListener() error = %v", err)
	}
	defer listener.Close()

	// Connect multiple clients
	numClients := 3
	clients := make([]*Conn, numClients)
	clientTransports := make([]*UDPTransport, numClients)

	for i := 0; i < numClients; i++ {
		clientKey, _ := noise.GenerateKeyPair()
		clientTransport, err := NewUDPTransport("127.0.0.1:0")
		if err != nil {
			t.Fatalf("NewUDPTransport() error = %v", err)
		}
		clientTransports[i] = clientTransport

		// Dial and accept
		idx := i // Capture loop variable
		done := make(chan error)
		go func() {
			var err error
			clients[idx], err = Dial(context.Background(), clientTransport, serverTransport.LocalAddr(), serverKey.Public, clientKey)
			done <- err
		}()

		serverConn, err := listener.Accept()
		if err != nil {
			t.Fatalf("Accept() error = %v", err)
		}

		if err := <-done; err != nil {
			t.Fatalf("Client %d Dial() error = %v", i, err)
		}

		// Verify connection
		if serverConn.State() != ConnStateEstablished {
			t.Errorf("Client %d: server conn not established", i)
		}
	}

	// Clean up
	for i := range clientTransports {
		clientTransports[i].Close()
		clients[i].Close()
	}
}

func TestListenerSessionManager(t *testing.T) {
	serverKey, _ := noise.GenerateKeyPair()
	serverTransport, err := NewUDPTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewUDPTransport() error = %v", err)
	}
	defer serverTransport.Close()

	listener, err := NewListener(ListenerConfig{
		LocalKey:  serverKey,
		Transport: serverTransport,
	})
	if err != nil {
		t.Fatalf("NewListener() error = %v", err)
	}
	defer listener.Close()

	manager := listener.SessionManager()
	if manager == nil {
		t.Fatal("SessionManager() returned nil")
	}

	// Initially no sessions
	if manager.Count() != 0 {
		t.Errorf("Initial session count = %d, want 0", manager.Count())
	}

	// Connect a client
	clientKey, _ := noise.GenerateKeyPair()
	clientTransport, err := NewUDPTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewUDPTransport() error = %v", err)
	}
	defer clientTransport.Close()

	done := make(chan error)
	go func() {
		_, err := Dial(context.Background(), clientTransport, serverTransport.LocalAddr(), serverKey.Public, clientKey)
		done <- err
	}()

	listener.Accept()
	<-done

	// Should now have one session
	if manager.Count() != 1 {
		t.Errorf("Session count = %d, want 1", manager.Count())
	}

	// Should be able to look up by public key
	session := manager.GetByPubkey(clientKey.Public)
	if session == nil {
		t.Error("GetByPubkey() returned nil")
	}
}

func TestListenerSendTo(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("server")

	listener, _ := NewListener(ListenerConfig{
		LocalKey:  key,
		Transport: transport,
	})
	defer listener.Close()

	// Create a peer transport to receive
	peerTransport := NewMockTransport("peer")
	transport.Connect(peerTransport)
	defer peerTransport.Close()

	// Send data through listener
	testData := []byte("test data")
	if err := listener.SendTo(testData, peerTransport.LocalAddr()); err != nil {
		t.Fatalf("SendTo() error = %v", err)
	}

	// Receive on peer
	buf := make([]byte, 1024)
	n, _, err := peerTransport.RecvFrom(buf)
	if err != nil {
		t.Fatalf("RecvFrom() error = %v", err)
	}

	if !bytes.Equal(buf[:n], testData) {
		t.Errorf("Received data mismatch")
	}
}

func TestListenerIgnoresInvalidMessages(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("server")

	listener, _ := NewListener(ListenerConfig{
		LocalKey:  key,
		Transport: transport,
	})
	defer listener.Close()

	// Inject invalid messages
	from := NewMockAddr("attacker")

	// Too short
	transport.InjectPacket([]byte{}, from)

	// Unknown type
	transport.InjectPacket([]byte{99, 1, 2, 3}, from)

	// Truncated handshake init
	transport.InjectPacket([]byte{noise.MessageTypeHandshakeInit, 1, 2, 3}, from)

	// Give listener time to process
	time.Sleep(50 * time.Millisecond)

	// Listener should still be working - try a valid connection
	clientKey, _ := noise.GenerateKeyPair()
	clientTransport := NewMockTransport("client")
	clientTransport.Connect(transport)
	defer clientTransport.Close()

	done := make(chan error)
	var clientConn *Conn
	go func() {
		var err error
		clientConn, err = Dial(context.Background(), clientTransport, transport.LocalAddr(), key.Public, clientKey)
		done <- err
	}()

	// Should still be able to accept valid connections
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("Dial() error = %v", err)
	}

	if serverConn.State() != ConnStateEstablished {
		t.Error("Connection should be established")
	}

	// Close both to clean up
	clientConn.Close()
	serverConn.Close()
}
