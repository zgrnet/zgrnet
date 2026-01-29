package transport

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/vibing/zgrnet/noise"
)

func TestUDPAddr(t *testing.T) {
	addr := &UDPAddr{&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51820}}

	if addr.Network() != "udp" {
		t.Errorf("Network() = %q, want %q", addr.Network(), "udp")
	}

	if addr.String() != "127.0.0.1:51820" {
		t.Errorf("String() = %q, want %q", addr.String(), "127.0.0.1:51820")
	}

	// Test nil UDPAddr
	nilAddr := &UDPAddr{nil}
	if nilAddr.String() != "" {
		t.Errorf("nil UDPAddr.String() = %q, want empty", nilAddr.String())
	}
}

func TestNewUDP(t *testing.T) {
	// Create a simple UDP server to accept connections
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer server.Close()

	// Create UDP transport connecting to server
	udp, err := NewUDP(":0", server.LocalAddr().String())
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}
	defer udp.Close()

	// Verify addresses
	if udp.LocalAddr() == nil {
		t.Error("LocalAddr() returned nil")
	}
	if udp.LocalAddr().Network() != "udp" {
		t.Errorf("LocalAddr().Network() = %q, want %q", udp.LocalAddr().Network(), "udp")
	}

	if udp.RemoteAddr() == nil {
		t.Error("RemoteAddr() returned nil")
	}
	if udp.RemoteAddr().String() != server.LocalAddr().String() {
		t.Errorf("RemoteAddr() = %q, want %q", udp.RemoteAddr().String(), server.LocalAddr().String())
	}
}

func TestNewUDP_InvalidAddresses(t *testing.T) {
	tests := []struct {
		name       string
		localAddr  string
		remoteAddr string
	}{
		{"invalid local", "invalid:addr:format", "127.0.0.1:51820"},
		{"invalid remote", ":0", "invalid:addr:format"},
		{"invalid remote host", ":0", "nonexistent.invalid.host.example:51820"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewUDP(tt.localAddr, tt.remoteAddr)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestUDP_SendRecv(t *testing.T) {
	// Create server
	serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer server.Close()

	// Create client transport
	client, err := NewUDP(":0", server.LocalAddr().String())
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}
	defer client.Close()

	// Test send
	testData := []byte("hello, world!")
	if err := client.SendTo(testData, nil); err != nil {
		t.Fatalf("SendTo: %v", err)
	}

	// Receive on server
	buf := make([]byte, 1024)
	server.SetReadDeadline(time.Now().Add(time.Second))
	n, clientAddr, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP: %v", err)
	}

	if !bytes.Equal(buf[:n], testData) {
		t.Errorf("received %q, want %q", buf[:n], testData)
	}

	// Test receive - server sends back
	responseData := []byte("hello back!")
	_, err = server.WriteToUDP(responseData, clientAddr)
	if err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}

	// Client receives
	n, addr, err := client.RecvFrom(buf)
	if err != nil {
		t.Fatalf("RecvFrom: %v", err)
	}

	if !bytes.Equal(buf[:n], responseData) {
		t.Errorf("received %q, want %q", buf[:n], responseData)
	}

	// Verify returned address is the remote address
	if addr.String() != server.LocalAddr().String() {
		t.Errorf("RecvFrom addr = %q, want %q", addr.String(), server.LocalAddr().String())
	}
}

func TestUDP_Close(t *testing.T) {
	serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	server, _ := net.ListenUDP("udp", serverAddr)
	defer server.Close()

	udp, err := NewUDP(":0", server.LocalAddr().String())
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}

	// Close should succeed
	if err := udp.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	// Operations after close should fail
	if err := udp.SendTo([]byte("test"), nil); err == nil {
		t.Error("SendTo after Close should fail")
	}
}

func TestUDP_SetBuffers(t *testing.T) {
	serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	server, _ := net.ListenUDP("udp", serverAddr)
	defer server.Close()

	udp, err := NewUDP(":0", server.LocalAddr().String())
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}
	defer udp.Close()

	// These may fail on some systems due to permissions, but shouldn't panic
	_ = udp.SetReadBuffer(65536)
	_ = udp.SetWriteBuffer(65536)
}

// TestUDP_ImplementsTransport verifies UDP implements noise.Transport interface
func TestUDP_ImplementsTransport(t *testing.T) {
	serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	server, _ := net.ListenUDP("udp", serverAddr)
	defer server.Close()

	udp, err := NewUDP(":0", server.LocalAddr().String())
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}
	defer udp.Close()

	// Compile-time check that UDP implements noise.Transport
	var _ noise.Transport = udp
}

// TestUDP_WithConn tests UDP transport with noise.Conn for handshake
func TestUDP_WithConn(t *testing.T) {
	// Generate key pairs
	serverKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	clientKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Create server listener using raw UDP (simulating a simple server)
	serverUDPAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	serverUDP, err := net.ListenUDP("udp", serverUDPAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer serverUDP.Close()

	// Create server-side transport wrapper
	serverTransport := &udpServerTransport{conn: serverUDP}

	// Create client transport
	clientTransport, err := NewUDP(":0", serverUDP.LocalAddr().String())
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}
	defer clientTransport.Close()

	// Channel to collect errors from goroutines
	errCh := make(chan error, 2)

	// Server goroutine - accept handshake
	go func() {
		// Create server conn
		serverConn, err := noise.NewConn(noise.ConnConfig{
			LocalKey:  serverKey,
			Transport: serverTransport,
		})
		if err != nil {
			errCh <- err
			return
		}

		// Read handshake init
		buf := make([]byte, noise.MaxPacketSize)
		n, addr, err := serverTransport.RecvFrom(buf)
		if err != nil {
			errCh <- err
			return
		}

		// Parse and process handshake
		msg, err := noise.ParseHandshakeInit(buf[:n])
		if err != nil {
			errCh <- err
			return
		}

		// Set remote address
		serverConn.SetRemoteAddr(addr)

		// Accept the handshake
		resp, err := serverConn.Accept(msg)
		if err != nil {
			errCh <- err
			return
		}

		// Send response
		if err := serverTransport.SendTo(resp, addr); err != nil {
			errCh <- err
			return
		}

		// Verify connection established
		if serverConn.State() != noise.ConnStateEstablished {
			errCh <- err
			return
		}

		// Wait for message
		proto, data, err := serverConn.Recv()
		if err != nil {
			errCh <- err
			return
		}

		if proto != noise.ProtocolChat {
			t.Errorf("protocol = %d, want %d", proto, noise.ProtocolChat)
		}
		if string(data) != "hello from client" {
			t.Errorf("data = %q, want %q", data, "hello from client")
		}

		// Send response
		if err := serverConn.Send(noise.ProtocolChat, []byte("hello from server")); err != nil {
			errCh <- err
			return
		}

		errCh <- nil
	}()

	// Client - initiate handshake
	go func() {
		clientConn, err := noise.NewConn(noise.ConnConfig{
			LocalKey:   clientKey,
			RemotePK:   serverKey.Public,
			Transport:  clientTransport,
			RemoteAddr: clientTransport.RemoteAddr(),
		})
		if err != nil {
			errCh <- err
			return
		}

		// Perform handshake
		if err := clientConn.Open(); err != nil {
			errCh <- err
			return
		}

		// Verify connection established
		if clientConn.State() != noise.ConnStateEstablished {
			t.Error("client connection not established")
		}

		// Send message
		if err := clientConn.Send(noise.ProtocolChat, []byte("hello from client")); err != nil {
			errCh <- err
			return
		}

		// Receive response
		proto, data, err := clientConn.Recv()
		if err != nil {
			errCh <- err
			return
		}

		if proto != noise.ProtocolChat {
			t.Errorf("protocol = %d, want %d", proto, noise.ProtocolChat)
		}
		if string(data) != "hello from server" {
			t.Errorf("data = %q, want %q", data, "hello from server")
		}

		errCh <- nil
	}()

	// Wait for both goroutines with timeout
	timeout := time.After(5 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("goroutine error: %v", err)
			}
		case <-timeout:
			t.Fatal("test timeout")
		}
	}
}

// udpServerTransport wraps a listening UDP socket to implement noise.Transport
// This is a simple helper for testing the server side
type udpServerTransport struct {
	conn       *net.UDPConn
	clientAddr *net.UDPAddr
}

func (t *udpServerTransport) SendTo(data []byte, addr noise.Addr) error {
	var udpAddr *net.UDPAddr
	if addr != nil {
		if ua, ok := addr.(*udpServerAddr); ok {
			udpAddr = ua.UDPAddr
		}
	}
	if udpAddr == nil {
		udpAddr = t.clientAddr
	}
	_, err := t.conn.WriteToUDP(data, udpAddr)
	return err
}

func (t *udpServerTransport) RecvFrom(buf []byte) (int, noise.Addr, error) {
	t.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, addr, err := t.conn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}
	t.clientAddr = addr
	return n, &udpServerAddr{addr}, nil
}

func (t *udpServerTransport) Close() error {
	return t.conn.Close()
}

func (t *udpServerTransport) LocalAddr() noise.Addr {
	return &udpServerAddr{t.conn.LocalAddr().(*net.UDPAddr)}
}

type udpServerAddr struct {
	*net.UDPAddr
}

func (a *udpServerAddr) Network() string { return "udp" }
func (a *udpServerAddr) String() string  { return a.UDPAddr.String() }
