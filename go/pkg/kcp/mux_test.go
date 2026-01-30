package kcp

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestMuxPipe creates a pair of connected Muxes for testing.
func newMuxPair(t *testing.T) (*Mux, *Mux) {
	// Channels for packet exchange
	clientToServer := make(chan []byte, 1000)
	serverToClient := make(chan []byte, 1000)

	clientMux := NewMux(DefaultConfig(), true, func(data []byte) error {
		select {
		case clientToServer <- append([]byte(nil), data...):
		default:
			t.Log("clientToServer channel full")
		}
		return nil
	})

	serverMux := NewMux(DefaultConfig(), false, func(data []byte) error {
		select {
		case serverToClient <- append([]byte(nil), data...):
		default:
			t.Log("serverToClient channel full")
		}
		return nil
	})

	// Packet forwarding goroutine
	go func() {
		for {
			select {
			case data := <-clientToServer:
				serverMux.Input(data)
			case data := <-serverToClient:
				clientMux.Input(data)
			case <-clientMux.die:
				return
			case <-serverMux.die:
				return
			}
		}
	}()

	return clientMux, serverMux
}

func TestMuxOpenAccept(t *testing.T) {
	clientMux, serverMux := newMuxPair(t)
	defer clientMux.Close()
	defer serverMux.Close()

	// Client opens a stream
	clientStream, err := clientMux.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}

	// Server accepts the stream
	done := make(chan struct{})
	var serverStream *Stream
	go func() {
		defer close(done)
		var err error
		serverStream, err = serverMux.AcceptStream()
		if err != nil {
			t.Errorf("AcceptStream() error = %v", err)
		}
	}()

	// Wait for accept
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("AcceptStream() timeout")
	}

	// Verify stream IDs
	if clientStream.ID()%2 != 1 {
		t.Errorf("Client stream ID = %d, want odd", clientStream.ID())
	}
	if serverStream != nil && serverStream.ID() != clientStream.ID() {
		t.Errorf("Server stream ID = %d, want %d", serverStream.ID(), clientStream.ID())
	}
}

func TestMuxStreamReadWrite(t *testing.T) {
	clientMux, serverMux := newMuxPair(t)
	defer clientMux.Close()
	defer serverMux.Close()

	// Client opens stream
	clientStream, err := clientMux.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}

	// Server accepts
	serverStream, err := serverMux.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream() error = %v", err)
	}

	// Client writes
	testData := []byte("hello from client")
	n, err := clientStream.Write(testData)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write() = %d, want %d", n, len(testData))
	}

	// Server reads
	buf := make([]byte, 1024)
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, err := serverStream.Read(buf)
		if err != nil {
			t.Errorf("Read() error = %v", err)
			return
		}
		if !bytes.Equal(buf[:n], testData) {
			t.Errorf("Read() = %q, want %q", buf[:n], testData)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Read() timeout")
	}
}

func TestMuxBidirectional(t *testing.T) {
	clientMux, serverMux := newMuxPair(t)
	defer clientMux.Close()
	defer serverMux.Close()

	clientStream, _ := clientMux.OpenStream()
	serverStream, _ := serverMux.AcceptStream()

	// Exchange messages
	clientMsg := []byte("client says hello")
	serverMsg := []byte("server says hello back")

	var wg sync.WaitGroup
	wg.Add(2)

	// Client sends, then reads
	go func() {
		defer wg.Done()
		clientStream.Write(clientMsg)

		buf := make([]byte, 1024)
		n, _ := clientStream.Read(buf)
		if !bytes.Equal(buf[:n], serverMsg) {
			t.Errorf("Client received %q, want %q", buf[:n], serverMsg)
		}
	}()

	// Server reads, then sends
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		n, _ := serverStream.Read(buf)
		if !bytes.Equal(buf[:n], clientMsg) {
			t.Errorf("Server received %q, want %q", buf[:n], clientMsg)
		}

		serverStream.Write(serverMsg)
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Bidirectional test timeout")
	}
}

func TestMuxMultipleStreams(t *testing.T) {
	clientMux, serverMux := newMuxPair(t)
	defer clientMux.Close()
	defer serverMux.Close()

	numStreams := 5
	var wg sync.WaitGroup
	wg.Add(numStreams * 2)

	// Open multiple streams
	for i := 0; i < numStreams; i++ {
		go func(idx int) {
			defer wg.Done()

			clientStream, err := clientMux.OpenStream()
			if err != nil {
				t.Errorf("Stream %d: OpenStream() error = %v", idx, err)
				return
			}

			// Write stream index
			msg := []byte{byte(idx)}
			clientStream.Write(msg)

			// Read echo
			buf := make([]byte, 10)
			n, err := clientStream.Read(buf)
			if err != nil {
				t.Errorf("Stream %d: Read() error = %v", idx, err)
				return
			}
			if n != 1 || buf[0] != byte(idx)+100 {
				t.Errorf("Stream %d: got %v, want [%d]", idx, buf[:n], idx+100)
			}
		}(i)
	}

	// Accept and echo
	for i := 0; i < numStreams; i++ {
		go func() {
			defer wg.Done()

			serverStream, err := serverMux.AcceptStream()
			if err != nil {
				t.Errorf("AcceptStream() error = %v", err)
				return
			}

			// Read
			buf := make([]byte, 10)
			n, err := serverStream.Read(buf)
			if err != nil {
				t.Errorf("Server Read() error = %v", err)
				return
			}

			// Echo with modification
			buf[0] += 100
			serverStream.Write(buf[:n])
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Multiple streams test timeout")
	}
}

func TestMuxStreamClose(t *testing.T) {
	clientMux, serverMux := newMuxPair(t)
	defer clientMux.Close()
	defer serverMux.Close()

	clientStream, _ := clientMux.OpenStream()
	serverStream, _ := serverMux.AcceptStream()

	// Client closes
	clientStream.Close()

	// Wait for FIN to propagate
	time.Sleep(100 * time.Millisecond)

	// Server should get EOF
	buf := make([]byte, 10)
	_, err := serverStream.Read(buf)
	if err != io.EOF {
		t.Errorf("Read() after close error = %v, want io.EOF", err)
	}
}

func TestMuxLargeData(t *testing.T) {
	clientMux, serverMux := newMuxPair(t)
	defer clientMux.Close()
	defer serverMux.Close()

	clientStream, _ := clientMux.OpenStream()
	serverStream, _ := serverMux.AcceptStream()

	// Send 100KB
	testData := bytes.Repeat([]byte("X"), 100*1024)

	var wg sync.WaitGroup
	wg.Add(2)

	// Writer
	go func() {
		defer wg.Done()
		// Write in chunks to avoid overwhelming KCP
		chunkSize := 8192
		written := 0
		for written < len(testData) {
			end := written + chunkSize
			if end > len(testData) {
				end = len(testData)
			}
			n, err := clientStream.Write(testData[written:end])
			if err != nil {
				t.Errorf("Write() error = %v", err)
				return
			}
			written += n
		}
	}()

	// Reader
	go func() {
		defer wg.Done()
		received := make([]byte, 0, len(testData))
		buf := make([]byte, 4096)

		for len(received) < len(testData) {
			n, err := serverStream.Read(buf)
			if err != nil {
				t.Errorf("Read() error = %v", err)
				break
			}
			received = append(received, buf[:n]...)
		}

		if !bytes.Equal(received, testData) {
			t.Errorf("Received %d bytes, want %d", len(received), len(testData))
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Large data test timeout")
	}
}

func TestMuxNumStreams(t *testing.T) {
	clientMux, serverMux := newMuxPair(t)
	defer clientMux.Close()
	defer serverMux.Close()

	if n := clientMux.NumStreams(); n != 0 {
		t.Errorf("Initial NumStreams() = %d, want 0", n)
	}

	// Open streams
	stream1, _ := clientMux.OpenStream()
	serverMux.AcceptStream()

	stream2, _ := clientMux.OpenStream()
	serverMux.AcceptStream()

	if n := clientMux.NumStreams(); n != 2 {
		t.Errorf("After open NumStreams() = %d, want 2", n)
	}

	// Close one
	stream1.Close()
	time.Sleep(100 * time.Millisecond)

	if n := clientMux.NumStreams(); n != 1 {
		t.Errorf("After close NumStreams() = %d, want 1", n)
	}

	// Close another
	stream2.Close()
	time.Sleep(100 * time.Millisecond)

	if n := clientMux.NumStreams(); n != 0 {
		t.Errorf("After all close NumStreams() = %d, want 0", n)
	}
}

func TestMuxPacketLoss(t *testing.T) {
	// Simulate 10% packet loss
	var dropCount int64
	var totalCount int64

	clientToServer := make(chan []byte, 1000)
	serverToClient := make(chan []byte, 1000)

	clientMux := NewMux(DefaultConfig(), true, func(data []byte) error {
		count := atomic.AddInt64(&totalCount, 1)
		// Drop 10% of packets (every 10th packet)
		if count%10 == 0 {
			atomic.AddInt64(&dropCount, 1)
			return nil // Don't forward
		}
		select {
		case clientToServer <- append([]byte(nil), data...):
		default:
		}
		return nil
	})
	defer clientMux.Close()

	serverMux := NewMux(DefaultConfig(), false, func(data []byte) error {
		select {
		case serverToClient <- append([]byte(nil), data...):
		default:
		}
		return nil
	})
	defer serverMux.Close()

	// Forwarding
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case data := <-clientToServer:
				serverMux.Input(data)
			case data := <-serverToClient:
				clientMux.Input(data)
			}
		}
	}()

	clientStream, _ := clientMux.OpenStream()
	serverStream, _ := serverMux.AcceptStream()

	// Send larger data - KCP should handle retransmission
	testData := bytes.Repeat([]byte("X"), 50*1024)
	n, err := clientStream.Write(testData)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write() = %d, want %d", n, len(testData))
	}

	// Read with timeout - need to read all data
	buf := make([]byte, 64*1024)
	recvDone := make(chan struct{})
	var recvErr error
	received := make([]byte, 0, len(testData))

	go func() {
		defer close(recvDone)
		for len(received) < len(testData) {
			n, err := serverStream.Read(buf)
			if err != nil {
				recvErr = err
				return
			}
			received = append(received, buf[:n]...)
		}
	}()

	select {
	case <-recvDone:
		if recvErr != nil {
			t.Fatalf("Read() error = %v", recvErr)
		}
		if !bytes.Equal(received, testData) {
			t.Errorf("Received %d bytes, want %d", len(received), len(testData))
		} else {
			t.Logf("Successfully received all %d bytes with %d/%d packets dropped",
				len(received), atomic.LoadInt64(&dropCount), atomic.LoadInt64(&totalCount))
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("Read() timeout with packet loss. Received %d/%d bytes, dropped %d/%d packets",
			len(received), len(testData), atomic.LoadInt64(&dropCount), atomic.LoadInt64(&totalCount))
	}

	close(done)
}

func BenchmarkMuxOpenClose(b *testing.B) {
	clientToServer := make(chan []byte, 10000)
	serverToClient := make(chan []byte, 10000)

	clientMux := NewMux(DefaultConfig(), true, func(data []byte) error {
		select {
		case clientToServer <- append([]byte(nil), data...):
		default:
		}
		return nil
	})
	defer clientMux.Close()

	serverMux := NewMux(DefaultConfig(), false, func(data []byte) error {
		select {
		case serverToClient <- append([]byte(nil), data...):
		default:
		}
		return nil
	})
	defer serverMux.Close()

	// Forwarding
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case data := <-clientToServer:
				serverMux.Input(data)
			case data := <-serverToClient:
				clientMux.Input(data)
			}
		}
	}()

	// Accept in parallel
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			_, err := serverMux.AcceptStream()
			if err != nil {
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream, err := clientMux.OpenStream()
		if err != nil {
			b.Fatal(err)
		}
		stream.Close()
	}
	b.StopTimer()

	close(done)
	clientMux.Close()
	serverMux.Close()
	<-acceptDone
}

func BenchmarkMuxThroughput(b *testing.B) {
	clientToServer := make(chan []byte, 10000)
	serverToClient := make(chan []byte, 10000)

	clientMux := NewMux(DefaultConfig(), true, func(data []byte) error {
		select {
		case clientToServer <- append([]byte(nil), data...):
		default:
		}
		return nil
	})
	defer clientMux.Close()

	serverMux := NewMux(DefaultConfig(), false, func(data []byte) error {
		select {
		case serverToClient <- append([]byte(nil), data...):
		default:
		}
		return nil
	})
	defer serverMux.Close()

	// Forwarding
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case data := <-clientToServer:
				serverMux.Input(data)
			case data := <-serverToClient:
				clientMux.Input(data)
			}
		}
	}()

	clientStream, _ := clientMux.OpenStream()
	serverStream, _ := serverMux.AcceptStream()

	data := bytes.Repeat([]byte("X"), 1024)
	buf := make([]byte, 2048)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		clientStream.Write(data)
		n, _ := serverStream.Read(buf)
		if n == 0 {
			// Wait for data if not immediately available
			time.Sleep(time.Millisecond)
			serverStream.Read(buf)
		}
	}
	b.StopTimer()

	close(done)
}
