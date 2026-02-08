package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// echoServer starts a TCP echo server and returns its address and cleanup func.
func echoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	return ln.Addr().String(), func() {
		ln.Close()
		wg.Wait()
	}
}

// dialFixed returns a DialFunc that always connects to a fixed TCP address,
// ignoring the SOCKS5 target address. Useful for testing the protocol layer.
func dialFixed(target string) DialFunc {
	return func(addr *noise.Address) (io.ReadWriteCloser, error) {
		return net.Dial("tcp", target)
	}
}

// startServer creates and starts a proxy server for testing.
// Returns the server and its listen address string.
func startServer(t *testing.T, dial DialFunc) (*Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	srv := NewServer("", dial)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return srv, addr
}

// socks5Handshake performs the SOCKS5 auth negotiation on conn.
func socks5Handshake(t *testing.T, conn net.Conn) {
	t.Helper()
	// VER=5, NMETHODS=1, METHODS=[NO AUTH]
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("handshake failed: got %v", reply)
	}
}

// readSOCKS5Reply reads a SOCKS5 reply header and bound address.
// Returns the reply code.
func readSOCKS5Reply(t *testing.T, conn net.Conn) byte {
	t.Helper()
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatal(err)
	}
	// Consume bound address based on ATYP
	switch header[3] {
	case noise.AddressTypeIPv4:
		io.ReadFull(conn, make([]byte, 6)) // 4 IP + 2 port
	case noise.AddressTypeDomain:
		var l [1]byte
		io.ReadFull(conn, l[:])
		io.ReadFull(conn, make([]byte, int(l[0])+2))
	case noise.AddressTypeIPv6:
		io.ReadFull(conn, make([]byte, 18)) // 16 IP + 2 port
	}
	return header[1]
}

// --- Auth negotiation tests ---

func TestSOCKS5_Handshake_NoAuth(t *testing.T) {
	echoAddr, cleanup := echoServer(t)
	defer cleanup()

	_, addr := startServer(t, dialFixed(echoAddr))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send handshake
	conn.Write([]byte{0x05, 0x01, 0x00})

	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("expected [05 00], got [%02x %02x]", reply[0], reply[1])
	}
}

func TestSOCKS5_Handshake_Reject(t *testing.T) {
	_, addr := startServer(t, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Only offer USER/PASS auth (not supported)
	conn.Write([]byte{0x05, 0x01, 0x02})

	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != AuthNoAccept {
		t.Fatalf("expected [05 FF], got [%02x %02x]", reply[0], reply[1])
	}
}

func TestSOCKS5_Handshake_MultipleMethodsIncludingNone(t *testing.T) {
	echoAddr, cleanup := echoServer(t)
	defer cleanup()

	_, addr := startServer(t, dialFixed(echoAddr))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Offer USER/PASS + NO AUTH
	conn.Write([]byte{0x05, 0x02, 0x02, 0x00})

	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[1] != AuthNone {
		t.Fatalf("expected method 00, got %02x", reply[1])
	}
}

// --- CONNECT tests ---

func TestSOCKS5_Connect_IPv4(t *testing.T) {
	echoAddr, cleanup := echoServer(t)
	defer cleanup()

	_, addr := startServer(t, dialFixed(echoAddr))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	// CONNECT to 127.0.0.1:80
	conn.Write([]byte{
		0x05, CmdConnect, 0x00, noise.AddressTypeIPv4,
		127, 0, 0, 1,
		0x00, 0x50, // port 80
	})

	rep := readSOCKS5Reply(t, conn)
	if rep != RepSuccess {
		t.Fatalf("expected RepSuccess, got 0x%02x", rep)
	}

	// Test bidirectional relay through echo server
	testData := []byte("hello socks5 ipv4")
	if _, err := conn.Write(testData); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, testData) {
		t.Fatalf("expected %q, got %q", testData, buf)
	}
}

func TestSOCKS5_Connect_Domain(t *testing.T) {
	echoAddr, cleanup := echoServer(t)
	defer cleanup()

	_, addr := startServer(t, dialFixed(echoAddr))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	// CONNECT to example.com:443
	domain := "example.com"
	req := []byte{0x05, CmdConnect, 0x00, noise.AddressTypeDomain, byte(len(domain))}
	req = append(req, []byte(domain)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, 443)
	req = append(req, portBuf...)
	conn.Write(req)

	rep := readSOCKS5Reply(t, conn)
	if rep != RepSuccess {
		t.Fatalf("expected RepSuccess, got 0x%02x", rep)
	}

	// Test relay
	testData := []byte("hello socks5 domain")
	conn.Write(testData)

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, testData) {
		t.Fatalf("expected %q, got %q", testData, buf)
	}
}

func TestSOCKS5_Connect_IPv6(t *testing.T) {
	echoAddr, cleanup := echoServer(t)
	defer cleanup()

	_, addr := startServer(t, dialFixed(echoAddr))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	// CONNECT to [::1]:8080
	ip := net.ParseIP("::1").To16()
	req := []byte{0x05, CmdConnect, 0x00, noise.AddressTypeIPv6}
	req = append(req, ip...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, 8080)
	req = append(req, portBuf...)
	conn.Write(req)

	rep := readSOCKS5Reply(t, conn)
	if rep != RepSuccess {
		t.Fatalf("expected RepSuccess, got 0x%02x", rep)
	}

	// Test relay
	testData := []byte("hello socks5 ipv6")
	conn.Write(testData)

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, testData) {
		t.Fatalf("expected %q, got %q", testData, buf)
	}
}

func TestSOCKS5_Connect_DialError(t *testing.T) {
	_, addr := startServer(t, func(a *noise.Address) (io.ReadWriteCloser, error) {
		return nil, errors.New("dial failed")
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	// CONNECT to 10.0.0.1:80
	conn.Write([]byte{
		0x05, CmdConnect, 0x00, noise.AddressTypeIPv4,
		10, 0, 0, 1,
		0x00, 0x50,
	})

	rep := readSOCKS5Reply(t, conn)
	if rep != RepGeneralFailure {
		t.Fatalf("expected RepGeneralFailure, got 0x%02x", rep)
	}
}

func TestSOCKS5_Connect_AddressParsing(t *testing.T) {
	// Verify the dial function receives the correct parsed address.
	tests := []struct {
		name     string
		request  []byte
		wantHost string
		wantPort uint16
	}{
		{
			name:     "IPv4",
			request:  []byte{0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x1F, 0x90},
			wantHost: "10.0.0.1",
			wantPort: 8080,
		},
		{
			name: "Domain",
			request: func() []byte {
				d := "proxy.example.org"
				r := []byte{0x05, 0x01, 0x00, 0x03, byte(len(d))}
				r = append(r, []byte(d)...)
				p := make([]byte, 2)
				binary.BigEndian.PutUint16(p, 9090)
				return append(r, p...)
			}(),
			wantHost: "proxy.example.org",
			wantPort: 9090,
		},
		{
			name: "IPv6",
			request: func() []byte {
				ip := net.ParseIP("2001:db8::1").To16()
				r := []byte{0x05, 0x01, 0x00, 0x04}
				r = append(r, ip...)
				p := make([]byte, 2)
				binary.BigEndian.PutUint16(p, 443)
				return append(r, p...)
			}(),
			wantHost: "2001:db8::1",
			wantPort: 443,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var got *noise.Address

			dial := func(addr *noise.Address) (io.ReadWriteCloser, error) {
				mu.Lock()
				got = addr
				mu.Unlock()
				return nil, errors.New("intentional")
			}

			_, srvAddr := startServer(t, dial)

			conn, err := net.Dial("tcp", srvAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			socks5Handshake(t, conn)
			conn.Write(tt.request)

			// Read reply (GeneralFailure expected since dial returns error)
			readSOCKS5Reply(t, conn)

			mu.Lock()
			defer mu.Unlock()
			if got == nil {
				t.Fatal("dial was not called")
			}
			if got.Host != tt.wantHost {
				t.Errorf("host: got %q, want %q", got.Host, tt.wantHost)
			}
			if got.Port != tt.wantPort {
				t.Errorf("port: got %d, want %d", got.Port, tt.wantPort)
			}
		})
	}
}

// --- Command tests ---

func TestSOCKS5_UnsupportedCommand(t *testing.T) {
	_, addr := startServer(t, func(a *noise.Address) (io.ReadWriteCloser, error) {
		return nil, errors.New("should not be called")
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	// BIND command (0x02, not supported)
	conn.Write([]byte{
		0x05, CmdBind, 0x00, noise.AddressTypeIPv4,
		127, 0, 0, 1,
		0x00, 0x50,
	})

	rep := readSOCKS5Reply(t, conn)
	if rep != RepCmdNotSupported {
		t.Fatalf("expected RepCmdNotSupported, got 0x%02x", rep)
	}
}

func TestSOCKS5_UDPAssociate_NotYetSupported(t *testing.T) {
	_, addr := startServer(t, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	// UDP ASSOCIATE
	conn.Write([]byte{
		0x05, CmdUDPAssociate, 0x00, noise.AddressTypeIPv4,
		0, 0, 0, 0,
		0x00, 0x00,
	})

	rep := readSOCKS5Reply(t, conn)
	if rep != RepCmdNotSupported {
		t.Fatalf("expected RepCmdNotSupported, got 0x%02x", rep)
	}
}

// --- ReadAddress unit tests ---

func TestReadAddress_IPv4(t *testing.T) {
	// 192.168.1.1:8080
	data := []byte{192, 168, 1, 1, 0x1F, 0x90}
	addr, err := ReadAddress(bytes.NewReader(data), noise.AddressTypeIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if addr.Type != noise.AddressTypeIPv4 {
		t.Errorf("type: got 0x%02x, want 0x%02x", addr.Type, noise.AddressTypeIPv4)
	}
	if addr.Host != "192.168.1.1" {
		t.Errorf("host: got %q, want %q", addr.Host, "192.168.1.1")
	}
	if addr.Port != 8080 {
		t.Errorf("port: got %d, want %d", addr.Port, 8080)
	}
}

func TestReadAddress_Domain(t *testing.T) {
	domain := "example.com"
	var data []byte
	data = append(data, byte(len(domain)))
	data = append(data, []byte(domain)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, 443)
	data = append(data, portBuf...)

	addr, err := ReadAddress(bytes.NewReader(data), noise.AddressTypeDomain)
	if err != nil {
		t.Fatal(err)
	}
	if addr.Host != "example.com" {
		t.Errorf("host: got %q, want %q", addr.Host, "example.com")
	}
	if addr.Port != 443 {
		t.Errorf("port: got %d, want %d", addr.Port, 443)
	}
}

func TestReadAddress_IPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1").To16()
	var data []byte
	data = append(data, ip...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, 8080)
	data = append(data, portBuf...)

	addr, err := ReadAddress(bytes.NewReader(data), noise.AddressTypeIPv6)
	if err != nil {
		t.Fatal(err)
	}
	if addr.Host != "2001:db8::1" {
		t.Errorf("host: got %q, want %q", addr.Host, "2001:db8::1")
	}
	if addr.Port != 8080 {
		t.Errorf("port: got %d, want %d", addr.Port, 8080)
	}
}

func TestReadAddress_DomainEmpty(t *testing.T) {
	// Domain with length 0
	data := []byte{0x00}
	_, err := ReadAddress(bytes.NewReader(data), noise.AddressTypeDomain)
	if err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestReadAddress_UnsupportedType(t *testing.T) {
	_, err := ReadAddress(bytes.NewReader([]byte{0}), 0x02)
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestReadAddress_ShortRead(t *testing.T) {
	// IPv4 needs 6 bytes, provide only 3
	_, err := ReadAddress(bytes.NewReader([]byte{1, 2, 3}), noise.AddressTypeIPv4)
	if err == nil {
		t.Fatal("expected error for short read")
	}
}

// --- Relay test ---

func TestRelay_Bidirectional(t *testing.T) {
	// Create two pipes to simulate client and server
	clientConn, proxyA := net.Pipe()
	proxyB, serverConn := net.Pipe()

	// Start relay between proxyA and proxyB
	done := make(chan struct{})
	go func() {
		Relay(proxyA, proxyB)
		close(done)
	}()

	// Client → Server
	testData := []byte("client to server")
	go func() {
		clientConn.Write(testData)
	}()

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(serverConn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, testData) {
		t.Fatalf("client→server: expected %q, got %q", testData, buf)
	}

	// Server → Client
	respData := []byte("server to client")
	go func() {
		serverConn.Write(respData)
	}()

	buf2 := make([]byte, len(respData))
	if _, err := io.ReadFull(clientConn, buf2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf2, respData) {
		t.Fatalf("server→client: expected %q, got %q", respData, buf2)
	}

	// Close both sides to end relay
	clientConn.Close()
	serverConn.Close()
	<-done
}

// --- Server lifecycle tests ---

func TestServer_Close(t *testing.T) {
	srv, _ := startServer(t, nil)

	// Close should succeed
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}

	// Double close should be no-op
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
}

// === UDP ASSOCIATE tests ===

// directUDPRelay forwards UDP packets directly (no tunnel).
// Used for testing the SOCKS5 UDP protocol without zgrnet.
type directUDPRelay struct {
	conn *net.UDPConn
}

func newDirectUDPRelay() (UDPRelay, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	return &directUDPRelay{conn: conn}, nil
}

func (r *directUDPRelay) WriteTo(addr *noise.Address, data []byte) error {
	target, err := net.ResolveUDPAddr("udp", net.JoinHostPort(addr.Host, strconv.Itoa(int(addr.Port))))
	if err != nil {
		return err
	}
	_, err = r.conn.WriteToUDP(data, target)
	return err
}

func (r *directUDPRelay) ReadFrom(buf []byte) (*noise.Address, int, error) {
	n, from, err := r.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, 0, err
	}
	addr := &noise.Address{
		Type: noise.AddressTypeIPv4,
		Host: from.IP.String(),
		Port: uint16(from.Port),
	}
	return addr, n, nil
}

func (r *directUDPRelay) Close() error {
	return r.conn.Close()
}

// udpEchoServer starts a UDP echo server.
func udpEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], from)
		}
	}()
	return conn.LocalAddr().String(), func() { conn.Close() }
}

// startServerWithUDP creates a proxy server with UDP relay support.
func startServerWithUDP(t *testing.T, dial DialFunc, newRelay NewUDPRelayFunc) (*Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	srv := NewServer("", dial)
	srv.newRelay = newRelay
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return srv, addr
}

// readSOCKS5ReplyWithAddr reads a SOCKS5 reply and returns the reply code
// and the bound address.
func readSOCKS5ReplyWithAddr(t *testing.T, conn net.Conn) (byte, *noise.Address) {
	t.Helper()
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatal(err)
	}
	addr, err := ReadAddress(conn, header[3])
	if err != nil {
		t.Fatal(err)
	}
	return header[1], addr
}

func TestSOCKS5_UDPAssociate(t *testing.T) {
	echoAddr, cleanup := udpEchoServer(t)
	defer cleanup()

	_, srvAddr := startServerWithUDP(t, nil, newDirectUDPRelay)

	// Connect TCP control channel
	conn, err := net.Dial("tcp", srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	// Send UDP ASSOCIATE request (client addr 0.0.0.0:0)
	conn.Write([]byte{
		0x05, CmdUDPAssociate, 0x00, noise.AddressTypeIPv4,
		0, 0, 0, 0,
		0, 0,
	})

	// Read reply: should contain the bound UDP address
	rep, boundAddr := readSOCKS5ReplyWithAddr(t, conn)
	if rep != RepSuccess {
		t.Fatalf("expected RepSuccess, got 0x%02x", rep)
	}
	if boundAddr.Port == 0 {
		t.Fatal("expected non-zero bound port")
	}

	// Parse echo server address
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)

	// Create client UDP socket
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()

	// Build SOCKS5 UDP packet targeting the echo server
	targetAddr := &noise.Address{
		Type: noise.AddressTypeIPv4,
		Host: echoHost,
		Port: uint16(echoPort),
	}
	testData := []byte("hello udp associate")
	pkt := BuildSOCKS5UDP(targetAddr, testData)
	if pkt == nil {
		t.Fatal("failed to build SOCKS5 UDP packet")
	}

	// Send to proxy's bound UDP port
	proxyUDPAddr, err := net.ResolveUDPAddr("udp",
		net.JoinHostPort(boundAddr.Host, strconv.Itoa(int(boundAddr.Port))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientUDP.WriteToUDP(pkt, proxyUDPAddr); err != nil {
		t.Fatal(err)
	}

	// Read response with timeout
	clientUDP.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := clientUDP.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}

	// Parse SOCKS5 UDP response
	respAddr, respData, err := ParseSOCKS5UDP(buf[:n])
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(respData, testData) {
		t.Fatalf("expected %q, got %q", testData, respData)
	}
	if respAddr.Host != echoHost {
		t.Errorf("response addr host: got %q, want %q", respAddr.Host, echoHost)
	}
	if respAddr.Port != uint16(echoPort) {
		t.Errorf("response addr port: got %d, want %d", respAddr.Port, echoPort)
	}
}

func TestSOCKS5_UDPAssociate_NoRelay(t *testing.T) {
	// Server without UDP relay should return CmdNotSupported
	_, addr := startServer(t, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	conn.Write([]byte{
		0x05, CmdUDPAssociate, 0x00, noise.AddressTypeIPv4,
		0, 0, 0, 0,
		0, 0,
	})

	rep := readSOCKS5Reply(t, conn)
	if rep != RepCmdNotSupported {
		t.Fatalf("expected RepCmdNotSupported, got 0x%02x", rep)
	}
}

func TestSOCKS5_UDPAssociate_MultiplePackets(t *testing.T) {
	echoAddr, cleanup := udpEchoServer(t)
	defer cleanup()

	_, srvAddr := startServerWithUDP(t, nil, newDirectUDPRelay)

	conn, err := net.Dial("tcp", srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	conn.Write([]byte{
		0x05, CmdUDPAssociate, 0x00, noise.AddressTypeIPv4,
		0, 0, 0, 0, 0, 0,
	})

	rep, boundAddr := readSOCKS5ReplyWithAddr(t, conn)
	if rep != RepSuccess {
		t.Fatalf("expected RepSuccess, got 0x%02x", rep)
	}

	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()

	proxyUDPAddr, _ := net.ResolveUDPAddr("udp",
		net.JoinHostPort(boundAddr.Host, strconv.Itoa(int(boundAddr.Port))))

	targetAddr := &noise.Address{
		Type: noise.AddressTypeIPv4,
		Host: echoHost,
		Port: uint16(echoPort),
	}

	// Send multiple packets and verify each echo
	for i := 0; i < 5; i++ {
		testData := []byte("packet-" + strconv.Itoa(i))
		pkt := BuildSOCKS5UDP(targetAddr, testData)
		clientUDP.WriteToUDP(pkt, proxyUDPAddr)

		clientUDP.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 65535)
		n, _, err := clientUDP.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		_, respData, err := ParseSOCKS5UDP(buf[:n])
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if !bytes.Equal(respData, testData) {
			t.Fatalf("packet %d: expected %q, got %q", i, testData, respData)
		}
	}
}

// --- ParseSOCKS5UDP / BuildSOCKS5UDP unit tests ---

func TestParseSOCKS5UDP(t *testing.T) {
	// Build a valid packet: RSV(00 00) + FRAG(00) + address(IPv4 127.0.0.1:80) + data
	addr := &noise.Address{Type: noise.AddressTypeIPv4, Host: "127.0.0.1", Port: 80}
	encoded := addr.Encode()
	pkt := make([]byte, 3+len(encoded)+5)
	copy(pkt[3:], encoded)
	copy(pkt[3+len(encoded):], []byte("hello"))

	gotAddr, gotData, err := ParseSOCKS5UDP(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if gotAddr.Host != "127.0.0.1" || gotAddr.Port != 80 {
		t.Errorf("addr: got %s:%d, want 127.0.0.1:80", gotAddr.Host, gotAddr.Port)
	}
	if !bytes.Equal(gotData, []byte("hello")) {
		t.Errorf("data: got %q, want %q", gotData, "hello")
	}
}

func TestParseSOCKS5UDP_TooShort(t *testing.T) {
	_, _, err := ParseSOCKS5UDP([]byte{0, 0})
	if err == nil {
		t.Fatal("expected error for short packet")
	}
}

func TestParseSOCKS5UDP_InvalidRSV(t *testing.T) {
	_, _, err := ParseSOCKS5UDP([]byte{0xFF, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err == nil {
		t.Fatal("expected error for invalid RSV")
	}
}

func TestParseSOCKS5UDP_Fragment(t *testing.T) {
	_, _, err := ParseSOCKS5UDP([]byte{0x00, 0x00, 0x01, 0x01, 0, 0, 0, 0, 0, 0})
	if err == nil {
		t.Fatal("expected error for fragmented packet")
	}
}

func TestBuildSOCKS5UDP(t *testing.T) {
	addr := &noise.Address{Type: noise.AddressTypeIPv4, Host: "10.0.0.1", Port: 53}
	data := []byte("dns query")
	pkt := BuildSOCKS5UDP(addr, data)
	if pkt == nil {
		t.Fatal("expected non-nil packet")
	}

	// Verify header
	if pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
		t.Errorf("expected RSV+FRAG=0, got %v", pkt[:3])
	}

	// Roundtrip
	gotAddr, gotData, err := ParseSOCKS5UDP(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if gotAddr.Host != "10.0.0.1" || gotAddr.Port != 53 {
		t.Errorf("addr roundtrip: got %s:%d", gotAddr.Host, gotAddr.Port)
	}
	if !bytes.Equal(gotData, data) {
		t.Errorf("data roundtrip: got %q", gotData)
	}
}

// === HTTP CONNECT tests ===

func TestHTTPConnect_Basic(t *testing.T) {
	echoAddr, cleanup := echoServer(t)
	defer cleanup()

	_, addr := startServer(t, dialFixed(echoAddr))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send HTTP CONNECT request
	req := "CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1:443\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	// Read response line
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	respStr := string(resp[:n])
	if !bytes.Contains(resp[:n], []byte("200")) {
		t.Fatalf("expected 200 response, got: %s", respStr)
	}

	// Test relay through echo server
	testData := []byte("hello http connect")
	if _, err := conn.Write(testData); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, testData) {
		t.Fatalf("expected %q, got %q", testData, buf)
	}
}

func TestHTTPConnect_Domain(t *testing.T) {
	echoAddr, cleanup := echoServer(t)
	defer cleanup()

	// Verify the dial function receives the correct parsed address
	var mu sync.Mutex
	var got *noise.Address

	dial := func(a *noise.Address) (io.ReadWriteCloser, error) {
		mu.Lock()
		got = a
		mu.Unlock()
		return net.Dial("tcp", echoAddr)
	}

	_, addr := startServer(t, dial)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := "CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\n\r\n"
	conn.Write([]byte(req))

	// Read response
	resp := make([]byte, 256)
	conn.Read(resp)

	mu.Lock()
	defer mu.Unlock()
	if got == nil {
		t.Fatal("dial was not called")
	}
	if got.Type != noise.AddressTypeDomain {
		t.Errorf("type: got 0x%02x, want 0x%02x (domain)", got.Type, noise.AddressTypeDomain)
	}
	if got.Host != "example.com" {
		t.Errorf("host: got %q, want %q", got.Host, "example.com")
	}
	if got.Port != 8443 {
		t.Errorf("port: got %d, want %d", got.Port, 8443)
	}
}

func TestHTTPConnect_IPv6(t *testing.T) {
	echoAddr, cleanup := echoServer(t)
	defer cleanup()

	var mu sync.Mutex
	var got *noise.Address

	dial := func(a *noise.Address) (io.ReadWriteCloser, error) {
		mu.Lock()
		got = a
		mu.Unlock()
		return net.Dial("tcp", echoAddr)
	}

	_, addr := startServer(t, dial)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := "CONNECT [::1]:443 HTTP/1.1\r\n\r\n"
	conn.Write([]byte(req))

	resp := make([]byte, 256)
	conn.Read(resp)

	mu.Lock()
	defer mu.Unlock()
	if got == nil {
		t.Fatal("dial was not called")
	}
	if got.Type != noise.AddressTypeIPv6 {
		t.Errorf("type: got 0x%02x, want 0x%02x (IPv6)", got.Type, noise.AddressTypeIPv6)
	}
	if got.Host != "::1" {
		t.Errorf("host: got %q, want %q", got.Host, "::1")
	}
}

func TestHTTPConnect_DialError(t *testing.T) {
	_, addr := startServer(t, func(a *noise.Address) (io.ReadWriteCloser, error) {
		return nil, errors.New("connection refused")
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := "CONNECT example.com:443 HTTP/1.1\r\n\r\n"
	conn.Write([]byte(req))

	resp := make([]byte, 256)
	n, _ := conn.Read(resp)
	if !bytes.Contains(resp[:n], []byte("502")) {
		t.Fatalf("expected 502 response, got: %s", string(resp[:n]))
	}
}

func TestHTTPConnect_BadRequest(t *testing.T) {
	_, addr := startServer(t, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Not a CONNECT method
	req := "CGET / HTTP/1.1\r\n\r\n"
	conn.Write([]byte(req))

	resp := make([]byte, 256)
	n, _ := conn.Read(resp)
	if !bytes.Contains(resp[:n], []byte("400")) {
		t.Fatalf("expected 400 response, got: %s", string(resp[:n]))
	}
}

func TestBuildSOCKS5UDP_Domain(t *testing.T) {
	addr := &noise.Address{Type: noise.AddressTypeDomain, Host: "example.com", Port: 53}
	data := []byte("query")
	pkt := BuildSOCKS5UDP(addr, data)
	if pkt == nil {
		t.Fatal("expected non-nil packet")
	}

	gotAddr, gotData, err := ParseSOCKS5UDP(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if gotAddr.Host != "example.com" || gotAddr.Port != 53 {
		t.Errorf("addr: got %s:%d", gotAddr.Host, gotAddr.Port)
	}
	if !bytes.Equal(gotData, data) {
		t.Errorf("data: got %q", gotData)
	}
}
