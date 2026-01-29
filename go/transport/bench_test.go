package transport

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"

	"github.com/vibing/zgrnet/noise"
)

// BenchmarkUDP_SendRecv benchmarks raw UDP send/recv throughput
func BenchmarkUDP_SendRecv(b *testing.B) {
	// Create server
	serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		b.Fatalf("ListenUDP: %v", err)
	}
	defer server.Close()

	// Create client transport
	client, err := NewUDP(":0", server.LocalAddr().String())
	if err != nil {
		b.Fatalf("NewUDP: %v", err)
	}
	defer client.Close()

	// Server goroutine - echo back
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		for i := 0; i < b.N; i++ {
			n, addr, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			server.WriteToUDP(buf[:n], addr)
		}
	}()

	// Benchmark data
	data := make([]byte, 1400) // Typical MTU payload
	buf := make([]byte, 1500)

	b.ResetTimer()
	b.SetBytes(int64(len(data) * 2)) // Send + Recv

	for i := 0; i < b.N; i++ {
		if err := client.SendTo(data, nil); err != nil {
			b.Fatalf("SendTo: %v", err)
		}
		if _, _, err := client.RecvFrom(buf); err != nil {
			b.Fatalf("RecvFrom: %v", err)
		}
	}

	b.StopTimer()
	client.Close()
	server.Close()
	wg.Wait()
}

// BenchmarkUDP_Throughput benchmarks one-way UDP throughput
func BenchmarkUDP_Throughput(b *testing.B) {
	serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		b.Fatalf("ListenUDP: %v", err)
	}
	defer server.Close()

	client, err := NewUDP(":0", server.LocalAddr().String())
	if err != nil {
		b.Fatalf("NewUDP: %v", err)
	}
	defer client.Close()

	// Server goroutine - just drain
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)
		for {
			_, _, err := server.ReadFromUDP(buf)
			if err != nil {
				close(done)
				return
			}
		}
	}()

	data := make([]byte, 1400)
	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		if err := client.SendTo(data, nil); err != nil {
			b.Fatalf("SendTo: %v", err)
		}
	}

	b.StopTimer()
	client.Close()
	server.Close()
	<-done
}

// BenchmarkUDP_WithNoise benchmarks UDP with Noise encryption
func BenchmarkUDP_WithNoise(b *testing.B) {
	// Generate key pairs
	serverKey, _ := noise.GenerateKeyPair()
	clientKey, _ := noise.GenerateKeyPair()

	// Create server
	serverUDPAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	serverUDP, err := net.ListenUDP("udp", serverUDPAddr)
	if err != nil {
		b.Fatalf("ListenUDP: %v", err)
	}
	defer serverUDP.Close()

	// Create client transport
	clientTransport, err := NewUDP(":0", serverUDP.LocalAddr().String())
	if err != nil {
		b.Fatalf("NewUDP: %v", err)
	}
	defer clientTransport.Close()

	// Server transport wrapper
	serverTransport := &benchServerTransport{conn: serverUDP}

	// Setup channels
	serverReady := make(chan *noise.Conn, 1)
	clientReady := make(chan *noise.Conn, 1)
	errCh := make(chan error, 2)

	// Server goroutine - accept handshake
	go func() {
		serverConn, err := noise.NewConn(noise.ConnConfig{
			LocalKey:  serverKey,
			Transport: serverTransport,
		})
		if err != nil {
			errCh <- err
			return
		}

		buf := make([]byte, noise.MaxPacketSize)
		n, addr, err := serverTransport.RecvFrom(buf)
		if err != nil {
			errCh <- err
			return
		}

		msg, err := noise.ParseHandshakeInit(buf[:n])
		if err != nil {
			errCh <- err
			return
		}

		serverConn.SetRemoteAddr(addr)
		resp, err := serverConn.Accept(msg)
		if err != nil {
			errCh <- err
			return
		}

		if err := serverTransport.SendTo(resp, addr); err != nil {
			errCh <- err
			return
		}

		serverReady <- serverConn
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

		if err := clientConn.Open(); err != nil {
			errCh <- err
			return
		}

		clientReady <- clientConn
		errCh <- nil
	}()

	// Wait for both connections
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			b.Fatalf("setup error: %v", err)
		}
	}

	serverConn := <-serverReady
	clientConn := <-clientReady

	// Server echo goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			proto, data, err := serverConn.Recv()
			if err != nil {
				return
			}
			if err := serverConn.Send(proto, data); err != nil {
				return
			}
		}
	}()

	// Benchmark data
	data := make([]byte, 1024)
	b.ResetTimer()
	b.SetBytes(int64(len(data) * 2)) // Send + Recv

	for i := 0; i < b.N; i++ {
		if err := clientConn.Send(noise.ProtocolChat, data); err != nil {
			b.Fatalf("Send: %v", err)
		}
		if _, _, err := clientConn.Recv(); err != nil {
			b.Fatalf("Recv: %v", err)
		}
	}

	b.StopTimer()
	clientConn.Close()
	serverConn.Close()
	wg.Wait()
}

// BenchmarkUDP_ParallelSend benchmarks parallel UDP sends
func BenchmarkUDP_ParallelSend(b *testing.B) {
	serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		b.Fatalf("ListenUDP: %v", err)
	}
	defer server.Close()

	client, err := NewUDP(":0", server.LocalAddr().String())
	if err != nil {
		b.Fatalf("NewUDP: %v", err)
	}
	defer client.Close()

	// Drain server
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)
		for {
			_, _, err := server.ReadFromUDP(buf)
			if err != nil {
				close(done)
				return
			}
		}
	}()

	data := make([]byte, 512)
	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			client.SendTo(data, nil)
		}
	})

	b.StopTimer()
	client.Close()
	server.Close()
	<-done
}

// BenchmarkUDP_NoiseParallel benchmarks parallel encrypted sends
func BenchmarkUDP_NoiseParallel(b *testing.B) {
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("ResolveUDPAddr: %v", err)
	}
	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		b.Fatalf("ListenUDP: %v", err)
	}
	defer server.Close()

	clientUDP, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatalf("DialUDP: %v", err)
	}
	defer clientUDP.Close()

	sendKey := noise.Hash([]byte("send"))
	recvKey := noise.Hash([]byte("recv"))

	session, err := noise.NewSession(noise.SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
	})
	if err != nil {
		b.Fatalf("NewSession: %v", err)
	}

	plaintext := make([]byte, 1400)

	done := make(chan struct{})
	go func() {
		buf := make([]byte, noise.MaxPacketSize)
		for {
			_, err := server.Read(buf)
			if err != nil {
				close(done)
				return
			}
		}
	}()

	b.ResetTimer()
	b.SetBytes(int64(len(plaintext)))

	b.RunParallel(func(pb *testing.PB) {
		sendBuf := make([]byte, noise.MaxPacketSize)
		for pb.Next() {
			ct, cnt, _ := session.Encrypt(plaintext)
			sendBuf[0] = noise.MessageTypeTransport
			binary.LittleEndian.PutUint32(sendBuf[1:5], 2)
			binary.LittleEndian.PutUint64(sendBuf[5:13], cnt)
			copy(sendBuf[13:], ct)
			clientUDP.Write(sendBuf[:13+len(ct)])
		}
	})

	b.StopTimer()
	clientUDP.Close()
	server.Close()
	<-done
}

// BenchmarkUDP_NoiseThroughput benchmarks one-way encrypted throughput
func BenchmarkUDP_NoiseThroughput(b *testing.B) {
	// Create UDP pair
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("ResolveUDPAddr: %v", err)
	}
	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		b.Fatalf("ListenUDP: %v", err)
	}
	defer server.Close()

	clientUDP, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatalf("DialUDP: %v", err)
	}
	defer clientUDP.Close()

	// Create session
	sendKey := noise.Hash([]byte("send"))
	recvKey := noise.Hash([]byte("recv"))

	clientSession, err := noise.NewSession(noise.SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
	})
	if err != nil {
		b.Fatalf("NewSession: %v", err)
	}

	// Pre-allocate
	plaintext := make([]byte, 1400) // MTU-sized
	sendBuf := make([]byte, noise.MaxPacketSize)

	// Server drain goroutine
	done := make(chan struct{})
	go func() {
		buf := make([]byte, noise.MaxPacketSize)
		for {
			_, err := server.Read(buf)
			if err != nil {
				close(done)
				return
			}
		}
	}()

	b.ResetTimer()
	b.SetBytes(int64(len(plaintext)))

	for i := 0; i < b.N; i++ {
		// Encrypt
		ct, cnt, _ := clientSession.Encrypt(plaintext)

		// Build message
		sendBuf[0] = noise.MessageTypeTransport
		binary.LittleEndian.PutUint32(sendBuf[1:5], 2)
		binary.LittleEndian.PutUint64(sendBuf[5:13], cnt)
		copy(sendBuf[13:], ct)

		// Send
		clientUDP.Write(sendBuf[:13+len(ct)])
	}

	b.StopTimer()
	clientUDP.Close()
	server.Close()
	<-done
}

// BenchmarkUDP_RawNoise benchmarks UDP with raw Session API (no Conn overhead)
func BenchmarkUDP_RawNoise(b *testing.B) {
	// Create UDP pair
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("ResolveUDPAddr: %v", err)
	}
	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		b.Fatalf("ListenUDP: %v", err)
	}
	defer server.Close()

	clientUDP, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatalf("DialUDP: %v", err)
	}
	defer clientUDP.Close()

	// Create sessions directly (skip handshake for benchmark)
	sendKey := noise.Hash([]byte("send"))
	recvKey := noise.Hash([]byte("recv"))

	clientSession, err := noise.NewSession(noise.SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
	})
	if err != nil {
		b.Fatalf("NewSession (client): %v", err)
	}

	serverSession, err := noise.NewSession(noise.SessionConfig{
		LocalIndex:  2,
		RemoteIndex: 1,
		SendKey:     recvKey,
		RecvKey:     sendKey,
	})
	if err != nil {
		b.Fatalf("NewSession (server): %v", err)
	}

	// Pre-allocate buffers
	plaintext := make([]byte, 1024)
	sendBuf := make([]byte, noise.MaxPacketSize)
	recvBuf := make([]byte, noise.MaxPacketSize)

	// Server echo goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			n, addr, err := server.ReadFromUDP(recvBuf)
			if err != nil {
				return
			}

			// Parse header
			if n < 13 {
				continue
			}
			// receiverIdx := binary.LittleEndian.Uint32(recvBuf[1:5])
			counter := binary.LittleEndian.Uint64(recvBuf[5:13])
			ciphertext := recvBuf[13:n]

			// Decrypt
			pt, err := serverSession.Decrypt(ciphertext, counter)
			if err != nil {
				continue
			}

			// Re-encrypt and send back
			ct, cnt, _ := serverSession.Encrypt(pt)

			// Build response in-place
			sendBuf[0] = noise.MessageTypeTransport
			binary.LittleEndian.PutUint32(sendBuf[1:5], 1) // client's index
			binary.LittleEndian.PutUint64(sendBuf[5:13], cnt)
			copy(sendBuf[13:], ct)

			server.WriteToUDP(sendBuf[:13+len(ct)], addr)
		}
	}()

	b.ResetTimer()
	b.SetBytes(int64(len(plaintext) * 2))

	for i := 0; i < b.N; i++ {
		// Encrypt
		ct, cnt, _ := clientSession.Encrypt(plaintext)

		// Build message in sendBuf
		sendBuf[0] = noise.MessageTypeTransport
		binary.LittleEndian.PutUint32(sendBuf[1:5], 2) // server's index
		binary.LittleEndian.PutUint64(sendBuf[5:13], cnt)
		copy(sendBuf[13:], ct)

		// Send
		clientUDP.Write(sendBuf[:13+len(ct)])

		// Recv
		n, _ := clientUDP.Read(recvBuf)

		// Parse and decrypt
		counter := binary.LittleEndian.Uint64(recvBuf[5:13])
		ciphertext := recvBuf[13:n]
		clientSession.Decrypt(ciphertext, counter)
	}

	b.StopTimer()
	clientUDP.Close()
	server.Close()
	wg.Wait()
}

// benchServerTransport is a helper for server-side benchmarks
type benchServerTransport struct {
	conn       *net.UDPConn
	clientAddr *net.UDPAddr
}

func (t *benchServerTransport) SendTo(data []byte, addr noise.Addr) error {
	var udpAddr *net.UDPAddr
	if addr != nil {
		if ua, ok := addr.(*benchServerAddr); ok {
			udpAddr = ua.UDPAddr
		}
	}
	if udpAddr == nil {
		udpAddr = t.clientAddr
	}
	_, err := t.conn.WriteToUDP(data, udpAddr)
	return err
}

func (t *benchServerTransport) RecvFrom(buf []byte) (int, noise.Addr, error) {
	n, addr, err := t.conn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}
	t.clientAddr = addr
	return n, &benchServerAddr{addr}, nil
}

func (t *benchServerTransport) Close() error {
	return t.conn.Close()
}

func (t *benchServerTransport) LocalAddr() noise.Addr {
	return &benchServerAddr{t.conn.LocalAddr().(*net.UDPAddr)}
}

type benchServerAddr struct {
	*net.UDPAddr
}

func (a *benchServerAddr) Network() string { return "udp" }
func (a *benchServerAddr) String() string  { return a.UDPAddr.String() }
