package noise

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestConnStates(t *testing.T) {
	tests := []struct {
		state ConnState
		str   string
	}{
		{ConnStateNew, "new"},
		{ConnStateHandshaking, "handshaking"},
		{ConnStateEstablished, "established"},
		{ConnStateClosed, "closed"},
		{ConnState(99), "unknown"},
	}

	for _, tt := range tests {
		if tt.state.String() != tt.str {
			t.Errorf("ConnState(%d).String() = %s, want %s", tt.state, tt.state.String(), tt.str)
		}
	}
}

func TestNewConnMissingLocalKey(t *testing.T) {
	_, err := NewConn(ConnConfig{
		Transport: NewMockTransport("test"),
	})
	if err != ErrMissingLocalKey {
		t.Errorf("NewConn() error = %v, want ErrMissingLocalKey", err)
	}
}

func TestNewConnMissingTransport(t *testing.T) {
	key, _ := GenerateKeyPair()
	_, err := NewConn(ConnConfig{
		LocalKey: key,
	})
	if err != ErrMissingTransport {
		t.Errorf("NewConn() error = %v, want ErrMissingTransport", err)
	}
}

func TestNewConnSuccess(t *testing.T) {
	key, _ := GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, err := NewConn(ConnConfig{
		LocalKey:  key,
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("NewConn() error = %v", err)
	}

	if conn.State() != ConnStateNew {
		t.Errorf("State() = %v, want ConnStateNew", conn.State())
	}

	if conn.LocalIndex() == 0 {
		t.Error("LocalIndex() should not be 0")
	}
}

func TestConnOpenMissingRemotePK(t *testing.T) {
	key, _ := GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, _ := NewConn(ConnConfig{
		LocalKey:   key,
		Transport:  transport,
		RemoteAddr: NewMockAddr("peer"),
	})

	err := conn.Open()
	if err != ErrMissingRemotePK {
		t.Errorf("Open() error = %v, want ErrMissingRemotePK", err)
	}
}

func TestConnOpenMissingRemoteAddr(t *testing.T) {
	key, _ := GenerateKeyPair()
	peerKey, _ := GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, _ := NewConn(ConnConfig{
		LocalKey: key,
		Transport: transport,
		RemotePK: peerKey.Public,
	})

	err := conn.Open()
	if err != ErrMissingRemoteAddr {
		t.Errorf("Open() error = %v, want ErrMissingRemoteAddr", err)
	}
}

func TestConnClose(t *testing.T) {
	key, _ := GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, _ := NewConn(ConnConfig{
		LocalKey:  key,
		Transport: transport,
	})

	// Close should work
	if err := conn.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if conn.State() != ConnStateClosed {
		t.Errorf("State() = %v, want ConnStateClosed", conn.State())
	}

	// Double close should be ok
	if err := conn.Close(); err != nil {
		t.Errorf("Double Close() error = %v", err)
	}
}

func TestConnSendNotEstablished(t *testing.T) {
	key, _ := GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, _ := NewConn(ConnConfig{
		LocalKey:  key,
		Transport: transport,
	})

	err := conn.Send(ProtocolChat, []byte("hello"))
	if err != ErrNotEstablished {
		t.Errorf("Send() error = %v, want ErrNotEstablished", err)
	}
}

func TestConnRecvNotEstablished(t *testing.T) {
	key, _ := GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, _ := NewConn(ConnConfig{
		LocalKey:  key,
		Transport: transport,
	})

	_, _, err := conn.Recv()
	if err != ErrNotEstablished {
		t.Errorf("Recv() error = %v, want ErrNotEstablished", err)
	}
}

// TestConnHandshakeAndCommunication tests the full handshake and communication flow
func TestConnHandshakeAndCommunication(t *testing.T) {
	// Create key pairs
	initiatorKey, _ := GenerateKeyPair()
	responderKey, _ := GenerateKeyPair()

	// Create transports
	initiatorTransport := NewMockTransport("initiator")
	responderTransport := NewMockTransport("responder")
	initiatorTransport.Connect(responderTransport)
	defer initiatorTransport.Close()
	defer responderTransport.Close()

	// Create connections
	initiatorConn, _ := NewConn(ConnConfig{
		LocalKey:   initiatorKey,
		RemotePK:   responderKey.Public,
		Transport:  initiatorTransport,
		RemoteAddr: responderTransport.LocalAddr(),
	})

	responderConn, _ := NewConn(ConnConfig{
		LocalKey:   responderKey,
		Transport:  responderTransport,
		RemoteAddr: initiatorTransport.LocalAddr(),
	})

	var wg sync.WaitGroup
	var initiatorErr, responderErr error

	// Start responder listening
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Receive handshake init
		buf := make([]byte, MaxPacketSize)
		n, _, err := responderTransport.RecvFrom(buf)
		if err != nil {
			responderErr = err
			return
		}

		// Parse and process
		initMsg, err := ParseHandshakeInit(buf[:n])
		if err != nil {
			responderErr = err
			return
		}

		resp, err := responderConn.Accept(initMsg)
		if err != nil {
			responderErr = err
			return
		}

		// Send response
		if err := responderTransport.SendTo(resp, initiatorTransport.LocalAddr()); err != nil {
			responderErr = err
			return
		}
	}()

	// Give responder time to start
	time.Sleep(10 * time.Millisecond)

	// Start initiator dial
	wg.Add(1)
	go func() {
		defer wg.Done()
		initiatorErr = initiatorConn.Open()
	}()

	wg.Wait()

	if initiatorErr != nil {
		t.Fatalf("Initiator Dial() error = %v", initiatorErr)
	}
	if responderErr != nil {
		t.Fatalf("Responder error = %v", responderErr)
	}

	// Verify connections are established
	if initiatorConn.State() != ConnStateEstablished {
		t.Errorf("Initiator state = %v, want ConnStateEstablished", initiatorConn.State())
	}
	if responderConn.State() != ConnStateEstablished {
		t.Errorf("Responder state = %v, want ConnStateEstablished", responderConn.State())
	}

	// Verify sessions
	if initiatorConn.Session() == nil {
		t.Error("Initiator session is nil")
	}
	if responderConn.Session() == nil {
		t.Error("Responder session is nil")
	}

	// Verify remote public keys
	if initiatorConn.RemotePublicKey() != responderKey.Public {
		t.Error("Initiator remote public key mismatch")
	}
	if responderConn.RemotePublicKey() != initiatorKey.Public {
		t.Error("Responder remote public key mismatch")
	}

	// Test bidirectional communication
	t.Run("Initiator to Responder", func(t *testing.T) {
		testData := []byte("Hello from initiator!")

		// Send from initiator
		if err := initiatorConn.Send(ProtocolChat, testData); err != nil {
			t.Fatalf("Send() error = %v", err)
		}

		// Receive on responder
		proto, payload, err := responderConn.Recv()
		if err != nil {
			t.Fatalf("Recv() error = %v", err)
		}

		if proto != ProtocolChat {
			t.Errorf("protocol = %d, want %d", proto, ProtocolChat)
		}
		if !bytes.Equal(payload, testData) {
			t.Errorf("payload = %s, want %s", string(payload), string(testData))
		}
	})

	t.Run("Responder to Initiator", func(t *testing.T) {
		testData := []byte("Hello from responder!")

		// Send from responder
		if err := responderConn.Send(ProtocolRPC, testData); err != nil {
			t.Fatalf("Send() error = %v", err)
		}

		// Receive on initiator
		proto, payload, err := initiatorConn.Recv()
		if err != nil {
			t.Fatalf("Recv() error = %v", err)
		}

		if proto != ProtocolRPC {
			t.Errorf("protocol = %d, want %d", proto, ProtocolRPC)
		}
		if !bytes.Equal(payload, testData) {
			t.Errorf("payload = %s, want %s", string(payload), string(testData))
		}
	})
}

func TestConnSetRemoteAddr(t *testing.T) {
	key, _ := GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, _ := NewConn(ConnConfig{
		LocalKey:  key,
		Transport: transport,
	})

	// Initially nil
	if conn.RemoteAddr() != nil {
		t.Error("RemoteAddr() should be nil initially")
	}

	// Set address
	addr := NewMockAddr("new-addr")
	conn.SetRemoteAddr(addr)

	if conn.RemoteAddr().String() != "new-addr" {
		t.Errorf("RemoteAddr() = %s, want new-addr", conn.RemoteAddr().String())
	}
}

func TestConnMultipleMessages(t *testing.T) {
	// Setup two connected peers
	initiatorKey, _ := GenerateKeyPair()
	responderKey, _ := GenerateKeyPair()

	initiatorTransport := NewMockTransport("initiator")
	responderTransport := NewMockTransport("responder")
	initiatorTransport.Connect(responderTransport)
	defer initiatorTransport.Close()
	defer responderTransport.Close()

	initiatorConn, _ := NewConn(ConnConfig{
		LocalKey:   initiatorKey,
		RemotePK:   responderKey.Public,
		Transport:  initiatorTransport,
		RemoteAddr: responderTransport.LocalAddr(),
	})

	responderConn, _ := NewConn(ConnConfig{
		LocalKey:   responderKey,
		Transport:  responderTransport,
		RemoteAddr: initiatorTransport.LocalAddr(),
	})

	// Perform handshake
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, MaxPacketSize)
		n, _, _ := responderTransport.RecvFrom(buf)
		initMsg, _ := ParseHandshakeInit(buf[:n])
		resp, _ := responderConn.Accept(initMsg)
		responderTransport.SendTo(resp, initiatorTransport.LocalAddr())
	}()

	time.Sleep(10 * time.Millisecond)
	initiatorConn.Open()
	wg.Wait()

	// Send multiple messages
	for i := 0; i < 100; i++ {
		// Initiator -> Responder
		msg := []byte("message")
		initiatorConn.Send(ProtocolUDP, msg)

		proto, payload, err := responderConn.Recv()
		if err != nil {
			t.Fatalf("Message %d: Recv() error = %v", i, err)
		}
		if proto != ProtocolUDP || !bytes.Equal(payload, msg) {
			t.Fatalf("Message %d: mismatch", i)
		}

		// Responder -> Initiator
		responderConn.Send(ProtocolTCP, msg)

		proto, payload, err = initiatorConn.Recv()
		if err != nil {
			t.Fatalf("Message %d: Recv() error = %v", i, err)
		}
		if proto != ProtocolTCP || !bytes.Equal(payload, msg) {
			t.Fatalf("Message %d: mismatch", i)
		}
	}
}

func TestConnDifferentProtocols(t *testing.T) {
	// Setup two connected peers
	initiatorKey, _ := GenerateKeyPair()
	responderKey, _ := GenerateKeyPair()

	initiatorTransport := NewMockTransport("initiator")
	responderTransport := NewMockTransport("responder")
	initiatorTransport.Connect(responderTransport)
	defer initiatorTransport.Close()
	defer responderTransport.Close()

	initiatorConn, _ := NewConn(ConnConfig{
		LocalKey:   initiatorKey,
		RemotePK:   responderKey.Public,
		Transport:  initiatorTransport,
		RemoteAddr: responderTransport.LocalAddr(),
	})

	responderConn, _ := NewConn(ConnConfig{
		LocalKey:   responderKey,
		Transport:  responderTransport,
		RemoteAddr: initiatorTransport.LocalAddr(),
	})

	// Perform handshake
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, MaxPacketSize)
		n, _, _ := responderTransport.RecvFrom(buf)
		initMsg, _ := ParseHandshakeInit(buf[:n])
		resp, _ := responderConn.Accept(initMsg)
		responderTransport.SendTo(resp, initiatorTransport.LocalAddr())
	}()

	time.Sleep(10 * time.Millisecond)
	initiatorConn.Open()
	wg.Wait()

	// Test different protocol types
	protocols := []byte{
		ProtocolICMP,
		ProtocolIP,
		ProtocolTCP,
		ProtocolUDP,
		ProtocolKCP,
		ProtocolChat,
		ProtocolFile,
		ProtocolRPC,
	}

	for _, proto := range protocols {
		msg := []byte("test payload")
		initiatorConn.Send(proto, msg)

		recvProto, payload, err := responderConn.Recv()
		if err != nil {
			t.Fatalf("Protocol %d: Recv() error = %v", proto, err)
		}
		if recvProto != proto {
			t.Errorf("Protocol %d: got %d", proto, recvProto)
		}
		if !bytes.Equal(payload, msg) {
			t.Errorf("Protocol %d: payload mismatch", proto)
		}
	}
}
