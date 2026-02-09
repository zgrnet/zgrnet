package net

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/proxy"
)

// TestProxyThroughput measures throughput through the full proxy stack:
// SOCKS5 client → proxy.Server → KCP stream → exit peer → TCP target
func TestProxyThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping throughput test in short mode")
	}
	const totalSize = 32 * 1024 * 1024 // 32 MB

	clientKey, _ := noise.GenerateKeyPair()
	serverKey, _ := noise.GenerateKeyPair()

	client, err := NewUDP(clientKey, WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server, err := NewUDP(serverKey, WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client.SetPeerEndpoint(serverKey.Public, server.HostInfo().Addr)
	server.SetPeerEndpoint(clientKey.Public, client.HostInfo().Addr)

	// Drain non-KCP packets
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, _, err := client.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, _, err := server.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	if err := client.Connect(serverKey.Public); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	// Start HTTP server (the "target" that the exit peer dials)
	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer httpLn.Close()
	httpPort := httpLn.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", totalSize))
		chunk := make([]byte, 64*1024)
		remaining := totalSize
		for remaining > 0 {
			n := len(chunk)
			if n > remaining {
				n = remaining
			}
			written, err := w.Write(chunk[:n])
			if err != nil {
				return
			}
			remaining -= written
		}
	})
	httpSrv := &http.Server{Handler: mux}
	go httpSrv.Serve(httpLn)
	defer httpSrv.Close()

	// Start proxy server on client side (dials through tunnel)
	proxySrv := proxy.NewServer("127.0.0.1:0", func(addr *noise.Address) (io.ReadWriteCloser, error) {
		metadata := addr.Encode()
		stream, err := client.OpenStream(serverKey.Public, noise.ProtocolTCPProxy, metadata)
		if err != nil {
			return nil, err
		}
		return stream, nil
	})
	go proxySrv.ListenAndServe()
	defer proxySrv.Close()

	// Exit peer: accept streams, dial real target
	go func() {
		for {
			stream, err := server.AcceptStream(clientKey.Public)
			if err != nil {
				return
			}
			go func() {
				proxy.HandleTCPProxy(stream, stream.Metadata(), nil, nil)
			}()
		}
	}()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)
	proxyAddr := proxySrv.Addr()
	if proxyAddr == nil {
		t.Fatal("proxy didn't start")
	}

	// SOCKS5 connect through proxy
	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	target := fmt.Sprintf("127.0.0.1:%d", httpPort)
	if err := socks5Connect(conn, target); err != nil {
		t.Fatal(err)
	}

	// Send HTTP GET
	httpReq := fmt.Sprintf("GET /data HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	conn.Write([]byte(httpReq))

	// Read all data — stop when we've received the expected amount
	start := time.Now()
	buf := make([]byte, 256*1024)
	totalRead := 0
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		totalRead += n
		if err != nil {
			break
		}
		if totalRead >= totalSize {
			break
		}
	}
	elapsed := time.Since(start)

	dataBytes := totalRead - 200 // subtract HTTP headers
	mbps := float64(dataBytes) / elapsed.Seconds() / (1024 * 1024)
	t.Logf("Layer 3 (SOCKS5 + KCP + Noise): %d bytes in %s = %.1f MB/s",
		totalRead, elapsed.Round(time.Millisecond), mbps)
	fmt.Printf("THROUGHPUT_PROXY=%.1f\n", mbps)
}

// TestRelayThroughput isolates the io.Copy relay pattern over KCP.
// No SOCKS5, no HandleTCPProxy — just io.Copy unidirectional relay
// between a TCP pipe and a KCP stream, like proxy.Relay does.
func TestRelayThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping throughput test in short mode")
	}
	const totalSize = 32 * 1024 * 1024

	clientKey, _ := noise.GenerateKeyPair()
	serverKey, _ := noise.GenerateKeyPair()

	client, err := NewUDP(clientKey, WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server, err := NewUDP(serverKey, WithBindAddr("127.0.0.1:0"), WithAllowUnknown(true))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client.SetPeerEndpoint(serverKey.Public, server.HostInfo().Addr)
	server.SetPeerEndpoint(clientKey.Public, client.HostInfo().Addr)

	go func() {
		buf := make([]byte, 65535)
		for {
			if _, _, err := client.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, _, err := server.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	if err := client.Connect(serverKey.Public); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	clientStream, err := client.OpenStream(serverKey.Public, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.AcceptStream(clientKey.Public)
	if err != nil {
		t.Fatal(err)
	}

	// Create a TCP pipe (simulates what the proxy does: TCP ↔ Relay ↔ KCP)
	tcpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer tcpLn.Close()

	// Writer side: connect to TCP listener, write data through TCP → KCP
	tcpWriter, _ := net.Dial("tcp", tcpLn.Addr().String())
	defer tcpWriter.Close()
	tcpWriterServer, _ := tcpLn.Accept()
	defer tcpWriterServer.Close()

	// Reader side: another TCP pipe for KCP → TCP
	tcpLn2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer tcpLn2.Close()
	tcpReader, _ := net.Dial("tcp", tcpLn2.Addr().String())
	defer tcpReader.Close()
	tcpReaderServer, _ := tcpLn2.Accept()
	defer tcpReaderServer.Close()

	// Exit side relay: TCP → KCP
	go func() {
		io.Copy(serverStream, tcpWriterServer)
	}()

	// Client side relay: KCP → TCP
	go func() {
		io.Copy(tcpReaderServer, clientStream)
	}()

	// Write data to the TCP writer
	start := time.Now()
	go func() {
		chunk := make([]byte, 64*1024)
		written := 0
		for written < totalSize {
			n, err := tcpWriter.Write(chunk)
			if err != nil {
				return
			}
			written += n
		}
		tcpWriter.Close()
	}()

	// Read data from the TCP reader
	buf := make([]byte, 256*1024)
	totalRead := 0
	for totalRead < totalSize {
		tcpReader.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := tcpReader.Read(buf)
		totalRead += n
		if err != nil {
			break
		}
	}
	elapsed := time.Since(start)

	mbps := float64(totalRead) / elapsed.Seconds() / (1024 * 1024)
	t.Logf("Layer 2.75 (TCP → io.Copy → KCP → io.Copy → TCP): %d bytes in %s = %.1f MB/s",
		totalRead, elapsed.Round(time.Millisecond), mbps)
	fmt.Printf("THROUGHPUT_RELAY=%.1f\n", mbps)
}

// socks5Connect does a SOCKS5 CONNECT handshake.
func socks5Connect(conn net.Conn, target string) error {
	host, portStr, _ := net.SplitHostPort(target)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	conn.Write([]byte{0x05, 0x01, 0x00})
	var resp [2]byte
	io.ReadFull(conn, resp[:])
	if resp[1] != 0x00 {
		return fmt.Errorf("auth rejected")
	}

	ip := net.ParseIP(host).To4()
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port))
	conn.Write(req)

	var reply [10]byte
	io.ReadFull(conn, reply[:])
	if reply[1] != 0x00 {
		return fmt.Errorf("connect failed: 0x%02x", reply[1])
	}
	return nil
}
