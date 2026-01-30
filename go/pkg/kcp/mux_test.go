package kcp

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// readWithPoll reads from a stream with polling since Read() is non-blocking.
// It polls every 1ms until data is available or timeout.
func readWithPoll(s *Stream, buf []byte, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, err := s.Read(buf)
		if err != nil {
			return n, err
		}
		if n > 0 {
			return n, nil
		}
		time.Sleep(time.Millisecond)
	}
	return 0, nil
}

// readAllWithPoll reads all expected data from a stream with polling.
func readAllWithPoll(s *Stream, expected int, timeout time.Duration) ([]byte, error) {
	buf := make([]byte, expected*2)
	received := make([]byte, 0, expected)
	deadline := time.Now().Add(timeout)
	for len(received) < expected && time.Now().Before(deadline) {
		n, err := s.Read(buf)
		if err != nil && err != io.EOF {
			return received, err
		}
		if n > 0 {
			received = append(received, buf[:n]...)
		} else {
			time.Sleep(time.Millisecond)
		}
	}
	return received, nil
}

// muxPair holds a connected pair of Muxes with stream channels.
type muxPair struct {
	client        *Mux
	server        *Mux
	clientStreams chan *Stream // New streams from server's perspective (client opened)
	serverStreams chan *Stream // New streams from client's perspective (server opened)
}

// newMuxPair creates a pair of connected Muxes for testing.
func newMuxPair(t *testing.T) *muxPair {
	// Channels for packet exchange
	clientToServer := make(chan []byte, 1000)
	serverToClient := make(chan []byte, 1000)

	// Channels for new stream notification
	clientStreams := make(chan *Stream, 100)
	serverStreams := make(chan *Stream, 100)

	var clientMux, serverMux *Mux

	clientMux = NewMux(DefaultConfig(), true, func(data []byte) error {
		select {
		case clientToServer <- append([]byte(nil), data...):
		default:
			t.Log("clientToServer channel full")
		}
		return nil
	}, func(streamID uint32) {
		// onStreamData - nothing to do in tests
	}, func(stream *Stream) {
		// onNewStream - server opened a stream to us
		select {
		case serverStreams <- stream:
		default:
			t.Log("serverStreams channel full")
		}
	})

	serverMux = NewMux(DefaultConfig(), false, func(data []byte) error {
		select {
		case serverToClient <- append([]byte(nil), data...):
		default:
			t.Log("serverToClient channel full")
		}
		return nil
	}, func(streamID uint32) {
		// onStreamData - nothing to do in tests
	}, func(stream *Stream) {
		// onNewStream - client opened a stream to us
		select {
		case clientStreams <- stream:
		default:
			t.Log("clientStreams channel full")
		}
	})

	// Packet forwarding and update goroutine
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case data := <-clientToServer:
				serverMux.Input(data)
			case data := <-serverToClient:
				clientMux.Input(data)
			case <-ticker.C:
				current := uint32(time.Now().UnixMilli())
				clientMux.Update(current)
				serverMux.Update(current)
			case <-clientMux.die:
				return
			case <-serverMux.die:
				return
			}
		}
	}()

	return &muxPair{
		client:        clientMux,
		server:        serverMux,
		clientStreams: clientStreams,
		serverStreams: serverStreams,
	}
}

func TestMuxOpenAccept(t *testing.T) {
	pair := newMuxPair(t)
	defer pair.client.Close()
	defer pair.server.Close()

	// Client opens a stream
	clientStream, err := pair.client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}

	// Server receives stream via callback
	var serverStream *Stream
	select {
	case serverStream = <-pair.clientStreams:
	case <-time.After(time.Second):
		t.Fatal("OnNewStream callback timeout")
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
	pair := newMuxPair(t)
	defer pair.client.Close()
	defer pair.server.Close()

	// Client opens stream
	clientStream, err := pair.client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}

	// Server receives stream via callback
	serverStream := <-pair.clientStreams

	// Client writes
	testData := []byte("hello from client")
	n, err := clientStream.Write(testData)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write() = %d, want %d", n, len(testData))
	}

	// Server reads (non-blocking, poll for data)
	received, err := readAllWithPoll(serverStream, len(testData), 2*time.Second)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if !bytes.Equal(received, testData) {
		t.Errorf("Read() = %q, want %q", received, testData)
	}
}

func TestMuxBidirectional(t *testing.T) {
	pair := newMuxPair(t)
	defer pair.client.Close()
	defer pair.server.Close()

	clientStream, _ := pair.client.OpenStream()
	serverStream := <-pair.clientStreams

	// Exchange messages
	clientMsg := []byte("client says hello")
	serverMsg := []byte("server says hello back")

	var wg sync.WaitGroup
	wg.Add(2)

	// Client sends, then reads
	go func() {
		defer wg.Done()
		clientStream.Write(clientMsg)

		received, _ := readAllWithPoll(clientStream, len(serverMsg), 2*time.Second)
		if !bytes.Equal(received, serverMsg) {
			t.Errorf("Client received %q, want %q", received, serverMsg)
		}
	}()

	// Server reads, then sends
	go func() {
		defer wg.Done()
		received, _ := readAllWithPoll(serverStream, len(clientMsg), 2*time.Second)
		if !bytes.Equal(received, clientMsg) {
			t.Errorf("Server received %q, want %q", received, clientMsg)
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
	case <-time.After(3 * time.Second):
		t.Fatal("Bidirectional test timeout")
	}
}

func TestMuxMultipleStreams(t *testing.T) {
	pair := newMuxPair(t)
	defer pair.client.Close()
	defer pair.server.Close()

	numStreams := 5
	var wg sync.WaitGroup
	wg.Add(numStreams * 2)

	// Open multiple streams
	for i := 0; i < numStreams; i++ {
		go func(idx int) {
			defer wg.Done()

			clientStream, err := pair.client.OpenStream()
			if err != nil {
				t.Errorf("Stream %d: OpenStream() error = %v", idx, err)
				return
			}

			// Write stream index
			msg := []byte{byte(idx)}
			clientStream.Write(msg)

			// Read echo (poll for data)
			received, err := readAllWithPoll(clientStream, 1, 2*time.Second)
			if err != nil {
				t.Errorf("Stream %d: Read() error = %v", idx, err)
				return
			}
			if len(received) != 1 || received[0] != byte(idx)+100 {
				t.Errorf("Stream %d: got %v, want [%d]", idx, received, idx+100)
			}
		}(i)
	}

	// Accept and echo via callback
	for i := 0; i < numStreams; i++ {
		go func() {
			defer wg.Done()

			serverStream := <-pair.clientStreams

			// Read (poll for data)
			received, err := readAllWithPoll(serverStream, 1, 2*time.Second)
			if err != nil {
				t.Errorf("Server Read() error = %v", err)
				return
			}

			// Echo with modification
			if len(received) > 0 {
				received[0] += 100
				serverStream.Write(received)
			}
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
	pair := newMuxPair(t)
	defer pair.client.Close()
	defer pair.server.Close()

	clientStream, _ := pair.client.OpenStream()
	serverStream := <-pair.clientStreams

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
	pair := newMuxPair(t)
	defer pair.client.Close()
	defer pair.server.Close()

	clientStream, _ := pair.client.OpenStream()
	serverStream := <-pair.clientStreams

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
	pair := newMuxPair(t)
	defer pair.client.Close()
	defer pair.server.Close()

	if n := pair.client.NumStreams(); n != 0 {
		t.Errorf("Initial NumStreams() = %d, want 0", n)
	}

	// Open streams
	stream1, _ := pair.client.OpenStream()
	<-pair.clientStreams

	stream2, _ := pair.client.OpenStream()
	<-pair.clientStreams

	if n := pair.client.NumStreams(); n != 2 {
		t.Errorf("After open NumStreams() = %d, want 2", n)
	}

	// Close one
	stream1.Close()
	time.Sleep(100 * time.Millisecond)

	if n := pair.client.NumStreams(); n != 1 {
		t.Errorf("After close NumStreams() = %d, want 1", n)
	}

	// Close another
	stream2.Close()
	time.Sleep(100 * time.Millisecond)

	if n := pair.client.NumStreams(); n != 0 {
		t.Errorf("After all close NumStreams() = %d, want 0", n)
	}
}

func TestMuxPacketLoss(t *testing.T) {
	// Simulate 10% packet loss
	var dropCount int64
	var totalCount int64

	clientToServer := make(chan []byte, 1000)
	serverToClient := make(chan []byte, 1000)
	newStreams := make(chan *Stream, 10)

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
	}, func(streamID uint32) {}, func(stream *Stream) {})
	defer clientMux.Close()

	serverMux := NewMux(DefaultConfig(), false, func(data []byte) error {
		select {
		case serverToClient <- append([]byte(nil), data...):
		default:
		}
		return nil
	}, func(streamID uint32) {}, func(stream *Stream) {
		newStreams <- stream
	})
	defer serverMux.Close()

	// Forwarding and update
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case data := <-clientToServer:
				serverMux.Input(data)
			case data := <-serverToClient:
				clientMux.Input(data)
			case <-ticker.C:
				current := uint32(time.Now().UnixMilli())
				clientMux.Update(current)
				serverMux.Update(current)
			}
		}
	}()

	clientStream, _ := clientMux.OpenStream()
	serverStream := <-newStreams

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
	newStreams := make(chan *Stream, 10000)

	clientMux := NewMux(DefaultConfig(), true, func(data []byte) error {
		select {
		case clientToServer <- append([]byte(nil), data...):
		default:
		}
		return nil
	}, func(streamID uint32) {}, func(stream *Stream) {})
	defer clientMux.Close()

	serverMux := NewMux(DefaultConfig(), false, func(data []byte) error {
		select {
		case serverToClient <- append([]byte(nil), data...):
		default:
		}
		return nil
	}, func(streamID uint32) {}, func(stream *Stream) {
		select {
		case newStreams <- stream:
		default:
		}
	})
	defer serverMux.Close()

	// Forwarding and update
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case data := <-clientToServer:
				serverMux.Input(data)
			case data := <-serverToClient:
				clientMux.Input(data)
			case <-ticker.C:
				current := uint32(time.Now().UnixMilli())
				clientMux.Update(current)
				serverMux.Update(current)
			}
		}
	}()

	// Drain new streams in parallel
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			select {
			case <-newStreams:
			case <-done:
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
	<-acceptDone
}

func BenchmarkMuxThroughput(b *testing.B) {
	clientToServer := make(chan []byte, 10000)
	serverToClient := make(chan []byte, 10000)
	newStreams := make(chan *Stream, 10)

	clientMux := NewMux(DefaultConfig(), true, func(data []byte) error {
		select {
		case clientToServer <- append([]byte(nil), data...):
		default:
		}
		return nil
	}, func(streamID uint32) {}, func(stream *Stream) {})
	defer clientMux.Close()

	serverMux := NewMux(DefaultConfig(), false, func(data []byte) error {
		select {
		case serverToClient <- append([]byte(nil), data...):
		default:
		}
		return nil
	}, func(streamID uint32) {}, func(stream *Stream) {
		newStreams <- stream
	})
	defer serverMux.Close()

	// Forwarding and update
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case data := <-clientToServer:
				serverMux.Input(data)
			case data := <-serverToClient:
				clientMux.Input(data)
			case <-ticker.C:
				current := uint32(time.Now().UnixMilli())
				clientMux.Update(current)
				serverMux.Update(current)
			}
		}
	}()

	clientStream, _ := clientMux.OpenStream()
	serverStream := <-newStreams

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
