package conn

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/vibing/zgrnet/noise"
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

func TestConnClose(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

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
	key, _ := noise.GenerateKeyPair()
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	err := conn.Send(noise.ProtocolChat, []byte("hello"))
	if err != ErrNotEstablished {
		t.Errorf("Send() error = %v, want ErrNotEstablished", err)
	}
}

func TestConnRecvNotEstablished(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	_, _, err := conn.Recv()
	if err != ErrNotEstablished {
		t.Errorf("Recv() error = %v, want ErrNotEstablished", err)
	}
}

func TestConnSetRemoteAddr(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	// Initially nil
	if conn.RemoteAddr() != nil {
		t.Error("RemoteAddr() should be nil initially")
	}

	// Set address
	addr := noise.NewMockAddr("new-addr")
	conn.SetRemoteAddr(addr)

	if conn.RemoteAddr().String() != "new-addr" {
		t.Errorf("RemoteAddr() = %s, want new-addr", conn.RemoteAddr().String())
	}
}

// TestDialAndCommunication tests the full handshake and communication flow using Dial
func TestDialAndCommunication(t *testing.T) {
	// Create key pairs
	initiatorKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() initiator error = %v", err)
	}
	responderKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() responder error = %v", err)
	}

	// Create transports
	initiatorTransport := noise.NewMockTransport("initiator")
	responderTransport := noise.NewMockTransport("responder")
	initiatorTransport.Connect(responderTransport)
	defer initiatorTransport.Close()
	defer responderTransport.Close()

	var wg sync.WaitGroup
	var initiatorConn, responderConn *Conn
	var initiatorErr, responderErr error

	// Start responder listening
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Create responder connection
		responderConn, responderErr = newConn(responderKey, responderTransport, initiatorTransport.LocalAddr(), noise.PublicKey{})
		if responderErr != nil {
			return
		}

		// Receive handshake init
		buf := make([]byte, noise.MaxPacketSize)
		n, _, err := responderTransport.RecvFrom(buf)
		if err != nil {
			responderErr = err
			return
		}

		// Parse and process
		initMsg, err := noise.ParseHandshakeInit(buf[:n])
		if err != nil {
			responderErr = err
			return
		}

		resp, err := responderConn.accept(initMsg)
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
		initiatorConn, initiatorErr = Dial(initiatorTransport, responderTransport.LocalAddr(), responderKey.Public, initiatorKey)
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
		if err := initiatorConn.Send(noise.ProtocolChat, testData); err != nil {
			t.Fatalf("Send() error = %v", err)
		}

		// Receive on responder
		proto, payload, err := responderConn.Recv()
		if err != nil {
			t.Fatalf("Recv() error = %v", err)
		}

		if proto != noise.ProtocolChat {
			t.Errorf("protocol = %d, want %d", proto, noise.ProtocolChat)
		}
		if !bytes.Equal(payload, testData) {
			t.Errorf("payload = %s, want %s", string(payload), string(testData))
		}
	})

	t.Run("Responder to Initiator", func(t *testing.T) {
		testData := []byte("Hello from responder!")

		// Send from responder
		if err := responderConn.Send(noise.ProtocolRPC, testData); err != nil {
			t.Fatalf("Send() error = %v", err)
		}

		// Receive on initiator
		proto, payload, err := initiatorConn.Recv()
		if err != nil {
			t.Fatalf("Recv() error = %v", err)
		}

		if proto != noise.ProtocolRPC {
			t.Errorf("protocol = %d, want %d", proto, noise.ProtocolRPC)
		}
		if !bytes.Equal(payload, testData) {
			t.Errorf("payload = %s, want %s", string(payload), string(testData))
		}
	})
}

func TestConnMultipleMessages(t *testing.T) {
	// Setup two connected peers
	initiatorKey, _ := noise.GenerateKeyPair()
	responderKey, _ := noise.GenerateKeyPair()

	initiatorTransport := noise.NewMockTransport("initiator")
	responderTransport := noise.NewMockTransport("responder")
	initiatorTransport.Connect(responderTransport)
	defer initiatorTransport.Close()
	defer responderTransport.Close()

	var wg sync.WaitGroup
	var initiatorConn, responderConn *Conn
	var responderErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		responderConn, _ = newConn(responderKey, responderTransport, initiatorTransport.LocalAddr(), noise.PublicKey{})
		buf := make([]byte, noise.MaxPacketSize)
		n, _, err := responderTransport.RecvFrom(buf)
		if err != nil {
			responderErr = err
			return
		}
		initMsg, err := noise.ParseHandshakeInit(buf[:n])
		if err != nil {
			responderErr = err
			return
		}
		resp, err := responderConn.accept(initMsg)
		if err != nil {
			responderErr = err
			return
		}
		if err := responderTransport.SendTo(resp, initiatorTransport.LocalAddr()); err != nil {
			responderErr = err
			return
		}
	}()

	time.Sleep(10 * time.Millisecond)

	var err error
	initiatorConn, err = Dial(initiatorTransport, responderTransport.LocalAddr(), responderKey.Public, initiatorKey)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	wg.Wait()

	if responderErr != nil {
		t.Fatalf("Responder error = %v", responderErr)
	}

	// Send multiple messages
	for i := 0; i < 100; i++ {
		// Initiator -> Responder
		msg := []byte("message")
		initiatorConn.Send(noise.ProtocolUDP, msg)

		proto, payload, err := responderConn.Recv()
		if err != nil {
			t.Fatalf("Message %d: Recv() error = %v", i, err)
		}
		if proto != noise.ProtocolUDP || !bytes.Equal(payload, msg) {
			t.Fatalf("Message %d: mismatch", i)
		}

		// Responder -> Initiator
		responderConn.Send(noise.ProtocolTCP, msg)

		proto, payload, err = initiatorConn.Recv()
		if err != nil {
			t.Fatalf("Message %d: Recv() error = %v", i, err)
		}
		if proto != noise.ProtocolTCP || !bytes.Equal(payload, msg) {
			t.Fatalf("Message %d: mismatch", i)
		}
	}
}
