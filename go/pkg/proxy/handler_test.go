package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/vibing/zgrnet/pkg/noise"
)

func TestHandleTCPProxy_Echo(t *testing.T) {
	// Start a TCP echo server as the "real" target
	echoAddr, cleanup := echoServer(t)
	defer cleanup()

	// Encode the echo server address as metadata
	host, portStr, _ := net.SplitHostPort(echoAddr)
	addr := &noise.Address{
		Type: noise.AddressTypeIPv4,
		Host: host,
		Port: parsePort(t, portStr),
	}
	metadata := addr.Encode()

	// Create a pipe to simulate the KCP stream
	clientEnd, streamEnd := net.Pipe()
	defer clientEnd.Close()

	// Handle the stream in a goroutine (uses default dial)
	errCh := make(chan error, 1)
	go func() {
		errCh <- HandleTCPProxy(streamEnd, metadata, nil)
	}()

	// Send data through the "stream" side
	testData := []byte("tcp proxy test data")
	if _, err := clientEnd.Write(testData); err != nil {
		t.Fatal(err)
	}

	// Read echoed data
	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientEnd, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, testData) {
		t.Fatalf("expected %q, got %q", testData, buf)
	}

	// Close client end → relay ends → handler returns
	clientEnd.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestHandleTCPProxy_CustomDial(t *testing.T) {
	echoAddr, cleanup := echoServer(t)
	defer cleanup()

	// Use custom dial that connects to the echo server regardless of address
	customDial := dialFixed(echoAddr)

	// Metadata encodes a fake address (custom dial ignores it)
	addr := &noise.Address{
		Type: noise.AddressTypeDomain,
		Host: "target.example.com",
		Port: 9999,
	}
	metadata := addr.Encode()

	clientEnd, streamEnd := net.Pipe()
	defer clientEnd.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- HandleTCPProxy(streamEnd, metadata, customDial)
	}()

	testData := []byte("custom dial proxy test")
	clientEnd.Write(testData)

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientEnd, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, testData) {
		t.Fatalf("expected %q, got %q", testData, buf)
	}

	clientEnd.Close()
	<-errCh
}

func TestHandleTCPProxy_InvalidMetadata(t *testing.T) {
	_, streamEnd := net.Pipe()
	err := HandleTCPProxy(streamEnd, []byte{0xFF}, nil) // invalid address type
	if err == nil {
		t.Fatal("expected error for invalid metadata")
	}
}

func TestHandleTCPProxy_DialError(t *testing.T) {
	addr := &noise.Address{
		Type: noise.AddressTypeIPv4,
		Host: "10.0.0.1",
		Port: 80,
	}
	metadata := addr.Encode()

	failDial := func(a *noise.Address) (io.ReadWriteCloser, error) {
		return nil, errors.New("connection refused")
	}

	_, streamEnd := net.Pipe()
	err := HandleTCPProxy(streamEnd, metadata, failDial)
	if err == nil {
		t.Fatal("expected error for dial failure")
	}
}

func TestHandleTCPProxy_LargePayload(t *testing.T) {
	echoAddr, cleanup := echoServer(t)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(echoAddr)
	addr := &noise.Address{
		Type: noise.AddressTypeIPv4,
		Host: host,
		Port: parsePort(t, portStr),
	}

	clientEnd, streamEnd := net.Pipe()
	defer clientEnd.Close()

	go HandleTCPProxy(streamEnd, addr.Encode(), nil)

	// Send a large payload (64KB)
	testData := make([]byte, 64*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	go func() {
		clientEnd.Write(testData)
	}()

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientEnd, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, testData) {
		t.Fatal("large payload mismatch")
	}

	clientEnd.Close()
}

func TestDefaultDial(t *testing.T) {
	echoAddr, cleanup := echoServer(t)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(echoAddr)
	addr := &noise.Address{
		Type: noise.AddressTypeIPv4,
		Host: host,
		Port: parsePort(t, portStr),
	}

	conn, err := DefaultDial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Verify connection works
	testData := []byte("default dial test")
	conn.Write(testData)

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, testData) {
		t.Fatalf("expected %q, got %q", testData, buf)
	}
}

// parsePort converts a port string to uint16.
func parsePort(t *testing.T, s string) uint16 {
	t.Helper()
	p, err := net.LookupPort("tcp", s)
	if err != nil {
		t.Fatal(err)
	}
	return uint16(p)
}
