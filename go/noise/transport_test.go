package noise

import (
	"net"
	"testing"
)

func TestUDPAddr(t *testing.T) {
	addr := &UDPAddr{&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}}

	if addr.Network() != "udp" {
		t.Errorf("Network() = %s, want udp", addr.Network())
	}

	if addr.String() != "127.0.0.1:1234" {
		t.Errorf("String() = %s, want 127.0.0.1:1234", addr.String())
	}

	// Test nil address
	nilAddr := &UDPAddr{}
	if nilAddr.String() != "<nil>" {
		t.Errorf("nil String() = %s, want <nil>", nilAddr.String())
	}
}

func TestUDPTransport(t *testing.T) {
	// Create two transports
	t1, err := NewUDPTransport(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("NewUDPTransport() error = %v", err)
	}
	defer t1.Close()

	t2, err := NewUDPTransport(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("NewUDPTransport() error = %v", err)
	}
	defer t2.Close()

	// Get addresses
	addr1 := t1.LocalAddr()
	addr2 := t2.LocalAddr()

	// Send from t1 to t2
	testData := []byte("hello")
	if err := t1.SendTo(testData, addr2); err != nil {
		t.Fatalf("SendTo() error = %v", err)
	}

	// Receive on t2
	buf := make([]byte, 1024)
	n, from, err := t2.RecvFrom(buf)
	if err != nil {
		t.Fatalf("RecvFrom() error = %v", err)
	}

	if string(buf[:n]) != "hello" {
		t.Errorf("RecvFrom() data = %s, want hello", string(buf[:n]))
	}

	if from.String() != addr1.String() {
		t.Errorf("RecvFrom() from = %s, want %s", from.String(), addr1.String())
	}
}

func TestUDPTransportInvalidAddr(t *testing.T) {
	transport, err := NewUDPTransport(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("NewUDPTransport() error = %v", err)
	}
	defer transport.Close()

	// Try to send to a mock address (wrong type)
	mockAddr := NewMockAddr("test")
	err = transport.SendTo([]byte("test"), mockAddr)
	if err != ErrInvalidAddress {
		t.Errorf("SendTo() error = %v, want ErrInvalidAddress", err)
	}
}

func TestMockAddr(t *testing.T) {
	addr := NewMockAddr("test-addr")

	if addr.Network() != "mock" {
		t.Errorf("Network() = %s, want mock", addr.Network())
	}

	if addr.String() != "test-addr" {
		t.Errorf("String() = %s, want test-addr", addr.String())
	}
}

func TestMockTransport(t *testing.T) {
	t1 := NewMockTransport("peer1")
	t2 := NewMockTransport("peer2")

	// Connect the transports
	t1.Connect(t2)

	// Send from t1 to t2
	testData := []byte("hello world")
	if err := t1.SendTo(testData, t2.LocalAddr()); err != nil {
		t.Fatalf("SendTo() error = %v", err)
	}

	// Receive on t2
	buf := make([]byte, 1024)
	n, from, err := t2.RecvFrom(buf)
	if err != nil {
		t.Fatalf("RecvFrom() error = %v", err)
	}

	if string(buf[:n]) != "hello world" {
		t.Errorf("RecvFrom() data = %s, want hello world", string(buf[:n]))
	}

	if from.String() != "peer1" {
		t.Errorf("RecvFrom() from = %s, want peer1", from.String())
	}

	// Test bidirectional
	if err := t2.SendTo([]byte("reply"), t1.LocalAddr()); err != nil {
		t.Fatalf("SendTo() error = %v", err)
	}

	n, from, err = t1.RecvFrom(buf)
	if err != nil {
		t.Fatalf("RecvFrom() error = %v", err)
	}

	if string(buf[:n]) != "reply" {
		t.Errorf("RecvFrom() data = %s, want reply", string(buf[:n]))
	}
}

func TestMockTransportClose(t *testing.T) {
	transport := NewMockTransport("test")

	// Close the transport
	if err := transport.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Try to send after close
	err := transport.SendTo([]byte("test"), NewMockAddr("peer"))
	if err != ErrTransportClosed {
		t.Errorf("SendTo() after close error = %v, want ErrTransportClosed", err)
	}

	// Try to receive after close
	buf := make([]byte, 1024)
	_, _, err = transport.RecvFrom(buf)
	if err != ErrTransportClosed {
		t.Errorf("RecvFrom() after close error = %v, want ErrTransportClosed", err)
	}

	// Double close should be ok
	if err := transport.Close(); err != nil {
		t.Errorf("Double Close() error = %v", err)
	}
}

func TestMockTransportNoPeer(t *testing.T) {
	transport := NewMockTransport("test")
	defer transport.Close()

	// Try to send without a peer
	err := transport.SendTo([]byte("test"), NewMockAddr("peer"))
	if err != ErrNoPeer {
		t.Errorf("SendTo() without peer error = %v, want ErrNoPeer", err)
	}
}

func TestMockTransportInjectPacket(t *testing.T) {
	transport := NewMockTransport("test")
	defer transport.Close()

	// Inject a packet
	from := NewMockAddr("sender")
	if err := transport.InjectPacket([]byte("injected"), from); err != nil {
		t.Fatalf("InjectPacket() error = %v", err)
	}

	// Receive the packet
	buf := make([]byte, 1024)
	n, addr, err := transport.RecvFrom(buf)
	if err != nil {
		t.Fatalf("RecvFrom() error = %v", err)
	}

	if string(buf[:n]) != "injected" {
		t.Errorf("RecvFrom() data = %s, want injected", string(buf[:n]))
	}

	if addr.String() != "sender" {
		t.Errorf("RecvFrom() from = %s, want sender", addr.String())
	}
}
