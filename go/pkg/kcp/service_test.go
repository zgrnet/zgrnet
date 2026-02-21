package kcp

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// serviceMuxPair creates a connected pair of ServiceMux instances.
// Packets from client are delivered to server and vice versa.
// loss controls simulated packet drop rate (0.0 = no loss).
func serviceMuxPair(loss float64) (client, server *ServiceMux) {
	rng := newLCG(42)

	var clientMux, serverMux *ServiceMux

	clientMux = NewServiceMux(ServiceMuxConfig{
		IsClient: true,
		Output: func(service uint64, data []byte) error {
			if loss > 0 && rng.shouldDrop(loss) {
				return nil
			}
			return serverMux.Input(service, data)
		},
	})
	serverMux = NewServiceMux(ServiceMuxConfig{
		IsClient: false,
		Output: func(service uint64, data []byte) error {
			if loss > 0 && rng.shouldDrop(loss) {
				return nil
			}
			return clientMux.Input(service, data)
		},
	})
	return clientMux, serverMux
}

func readFull(conn net.Conn, size int, timeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})
	buf := make([]byte, size)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

// === Basic yamux tests ===

func TestYamux_OpenClose(t *testing.T) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	stream, err := client.OpenStream(1)
	if err != nil {
		t.Fatal(err)
	}

	// Accept on server side so yamux can process the SYN
	sStream, _, _ := server.AcceptStream()
	sStream.Close()
	stream.Close()

	// Wait for stream count to settle
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if client.NumStreams() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := client.NumStreams(); n != 0 {
		t.Errorf("client streams after close = %d, want 0", n)
	}
}

func TestYamux_Bidirectional(t *testing.T) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	cStream, err := client.OpenStream(1)
	if err != nil {
		t.Fatal(err)
	}
	defer cStream.Close()

	sStream, _, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	defer sStream.Close()

	cMsg := []byte("hello from client")
	sMsg := []byte("hello from server")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		cStream.Write(cMsg)
		got, err := readFull(cStream, len(sMsg), 5*time.Second)
		if err != nil {
			t.Errorf("client read: %v", err)
			return
		}
		if !bytes.Equal(got, sMsg) {
			t.Errorf("client got %q, want %q", got, sMsg)
		}
	}()

	go func() {
		defer wg.Done()
		got, err := readFull(sStream, len(cMsg), 5*time.Second)
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if !bytes.Equal(got, cMsg) {
			t.Errorf("server got %q, want %q", got, cMsg)
		}
		sStream.Write(sMsg)
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

func TestYamux_LargeData_32MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 32MB test in short mode")
	}

	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	const totalSize = 32 * 1024 * 1024
	const chunkSize = 32 * 1024

	cStream, _ := client.OpenStream(1)
	defer cStream.Close()
	sStream, _, _ := server.AcceptStream()
	defer sStream.Close()

	sendData := make([]byte, totalSize)
	for i := range sendData {
		sendData[i] = byte(i)
	}

	var recvData []byte
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		for len(recvData) < totalSize {
			n, err := sStream.Read(buf)
			if err != nil {
				return
			}
			recvData = append(recvData, buf[:n]...)
		}
	}()

	for w := 0; w < totalSize; {
		end := w + chunkSize
		if end > totalSize {
			end = totalSize
		}
		cStream.Write(sendData[w:end])
		w = end
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(120 * time.Second):
		t.Fatalf("timeout: received %d/%d", len(recvData), totalSize)
	}

	if !bytes.Equal(recvData, sendData) {
		t.Errorf("data mismatch: got %d bytes, want %d", len(recvData), totalSize)
	}
}

// === Concurrent stream tests ===

func testYamuxMultiStream(t *testing.T, numStreams int) {
	t.Helper()
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	var wg sync.WaitGroup
	wg.Add(numStreams * 2)

	for i := 0; i < numStreams; i++ {
		idx := i

		// Client side: open stream, write, read echo
		go func() {
			defer wg.Done()
			stream, err := client.OpenStream(1)
			if err != nil {
				t.Errorf("stream %d: open: %v", idx, err)
				return
			}
			defer stream.Close()

			msg := []byte(fmt.Sprintf("msg-%04d", idx))
			stream.Write(msg)

			got, err := readFull(stream, len(msg)+4, 10*time.Second)
			if err != nil {
				t.Errorf("stream %d: read echo: %v", idx, err)
				return
			}
			expected := append([]byte("echo"), msg...)
			if !bytes.Equal(got, expected) {
				t.Errorf("stream %d: got %q, want %q", idx, got, expected)
			}
		}()

		// Server side: accept, read, echo back with prefix
		go func() {
			defer wg.Done()
			stream, _, err := server.AcceptStream()
			if err != nil {
				t.Errorf("accept %d: %v", idx, err)
				return
			}
			defer stream.Close()

			buf := make([]byte, 256)
			stream.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := stream.Read(buf)
			if err != nil {
				t.Errorf("server read %d: %v", idx, err)
				return
			}
			stream.SetReadDeadline(time.Time{})

			echo := append([]byte("echo"), buf[:n]...)
			stream.Write(echo)
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout")
	}
}

func TestYamux_MultiStream_10(t *testing.T)  { testYamuxMultiStream(t, 10) }
func TestYamux_MultiStream_100(t *testing.T) { testYamuxMultiStream(t, 100) }
func TestYamux_MultiStream_1000(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-stream test in short mode")
	}
	testYamuxMultiStream(t, 1000)
}

func TestYamux_RapidOpenClose(t *testing.T) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	// Drain accepted streams
	go func() {
		for {
			s, _, err := server.AcceptStream()
			if err != nil {
				return
			}
			s.Close()
		}
	}()

	for i := 0; i < 500; i++ {
		s, err := client.OpenStream(1)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		s.Close()
	}

	time.Sleep(100 * time.Millisecond)
}

// === Flow control tests ===

func TestYamux_HalfClose(t *testing.T) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	cStream, _ := client.OpenStream(1)
	sStream, _, _ := server.AcceptStream()

	// Client writes then closes write side
	cStream.Write([]byte("final message"))
	cStream.Close()

	// Server should still be able to read the data
	got, err := readFull(sStream, len("final message"), 5*time.Second)
	if err != nil {
		t.Fatalf("server read after half-close: %v", err)
	}
	if !bytes.Equal(got, []byte("final message")) {
		t.Errorf("got %q", got)
	}

	// Server reads should eventually get EOF
	buf := make([]byte, 10)
	sStream.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = sStream.Read(buf)
	if err != io.EOF {
		t.Errorf("expected EOF after close, got %v", err)
	}

	sStream.Close()
}

func TestYamux_EOF(t *testing.T) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	cStream, _ := client.OpenStream(1)
	sStream, _, _ := server.AcceptStream()

	cStream.Close()

	buf := make([]byte, 10)
	sStream.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := sStream.Read(buf)
	if err != io.EOF {
		t.Errorf("Read after peer close = %v, want io.EOF", err)
	}
	sStream.Close()
}

func TestYamux_WriteAfterClose(t *testing.T) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	cStream, _ := client.OpenStream(1)
	sStream, _, _ := server.AcceptStream()
	defer sStream.Close()

	cStream.Close()

	_, err := cStream.Write([]byte("should fail"))
	if err == nil {
		t.Error("Write after Close should return error")
	}
}

// === Packet loss tests ===

func TestYamux_PacketLoss_1pct(t *testing.T) { testYamuxLoss(t, 0.01) }
func TestYamux_PacketLoss_5pct(t *testing.T) { testYamuxLoss(t, 0.05) }
func TestYamux_PacketLoss_10pct(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 10% loss test in short mode")
	}
	testYamuxLoss(t, 0.10)
}

func testYamuxLoss(t *testing.T, lossRate float64) {
	t.Helper()

	client, server := serviceMuxPair(lossRate)
	defer client.Close()
	defer server.Close()

	cStream, err := client.OpenStream(1)
	if err != nil {
		t.Fatal(err)
	}
	defer cStream.Close()

	sStream, _, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	defer sStream.Close()

	const dataSize = 32 * 1024
	sendData := make([]byte, dataSize)
	for i := range sendData {
		sendData[i] = byte(i)
	}

	var recvData []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		for len(recvData) < dataSize {
			n, err := sStream.Read(buf)
			if err != nil {
				return
			}
			recvData = append(recvData, buf[:n]...)
		}
	}()

	for w := 0; w < dataSize; {
		end := w + 1024
		if end > dataSize {
			end = dataSize
		}
		cStream.Write(sendData[w:end])
		w = end
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("timeout with %.0f%% loss: received %d/%d", lossRate*100, len(recvData), dataSize)
	}

	if !bytes.Equal(recvData, sendData) {
		t.Errorf("data mismatch with %.0f%% loss", lossRate*100)
	}
}

// === Deadline tests ===

func TestYamux_ReadDeadline(t *testing.T) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	cStream, _ := client.OpenStream(1)
	defer cStream.Close()
	sStream, _, _ := server.AcceptStream()
	defer sStream.Close()

	sStream.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 10)
	_, err := sStream.Read(buf)
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestYamux_WriteDeadline(t *testing.T) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	cStream, _ := client.OpenStream(1)
	defer cStream.Close()
	_, _, _ = server.AcceptStream()

	// Fill the write buffer to trigger deadline
	cStream.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	largeData := make([]byte, 10*1024*1024)
	for {
		_, err := cStream.Write(largeData)
		if err != nil {
			break
		}
	}
}

// === ServiceMux routing tests ===

func TestSmux_SingleService(t *testing.T) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	cStream, _ := client.OpenStream(1)
	defer cStream.Close()
	sStream, svc, _ := server.AcceptStream()
	defer sStream.Close()

	if svc != 1 {
		t.Errorf("accepted service = %d, want 1", svc)
	}

	cStream.Write([]byte("ping"))
	got, _ := readFull(sStream, 4, 5*time.Second)
	if !bytes.Equal(got, []byte("ping")) {
		t.Errorf("got %q", got)
	}
}

func TestSmux_MultiService_3(t *testing.T) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	services := []uint64{1, 2, 3}
	var wg sync.WaitGroup
	wg.Add(len(services) * 2)

	for _, svc := range services {
		svc := svc
		go func() {
			defer wg.Done()
			s, err := client.OpenStream(svc)
			if err != nil {
				t.Errorf("open service %d: %v", svc, err)
				return
			}
			defer s.Close()
			msg := fmt.Sprintf("svc%d", svc)
			s.Write([]byte(msg))
			got, _ := readFull(s, len(msg)+5, 5*time.Second)
			expected := fmt.Sprintf("echo-%s", msg)
			if !bytes.Equal(got, []byte(expected)) {
				t.Errorf("service %d: got %q, want %q", svc, got, expected)
			}
		}()

		go func() {
			defer wg.Done()
			s, gotSvc, err := server.AcceptStream()
			if err != nil {
				t.Errorf("accept: %v", err)
				return
			}
			defer s.Close()
			_ = gotSvc

			buf := make([]byte, 256)
			s.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := s.Read(buf)
			if err != nil {
				t.Errorf("read: %v", err)
				return
			}
			s.SetReadDeadline(time.Time{})
			echo := fmt.Sprintf("echo-%s", buf[:n])
			s.Write([]byte(echo))
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}

	if n := client.NumServices(); n != 3 {
		t.Errorf("client services = %d, want 3", n)
	}
	if n := server.NumServices(); n != 3 {
		t.Errorf("server services = %d, want 3", n)
	}
}

func TestSmux_UnknownService(t *testing.T) {
	client, server := serviceMuxPair(0)
	defer client.Close()

	// Server rejects service 99
	server.Close()
	serverWithFilter := NewServiceMux(ServiceMuxConfig{
		IsClient: false,
		Output: func(service uint64, data []byte) error {
			return client.Input(service, data)
		},
		OnNewService: func(service uint64) bool {
			return service != 99
		},
	})
	defer serverWithFilter.Close()

	// This should not crash even though server rejects the service
	err := serverWithFilter.Input(99, make([]byte, 100))
	if err != ErrServiceRejected {
		t.Errorf("Input to rejected service = %v, want ErrServiceRejected", err)
	}
}

func TestSmux_ServiceIsolation_Close(t *testing.T) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	// Open streams on service 1 and 2
	s1, _ := client.OpenStream(1)
	defer s1.Close()
	s2, _ := client.OpenStream(2)
	defer s2.Close()

	// Accept streams and match by service ID
	accepted := make(map[uint64]net.Conn)
	for i := 0; i < 2; i++ {
		s, svc, err := server.AcceptStream()
		if err != nil {
			t.Fatal(err)
		}
		accepted[svc] = s
	}
	ss1, ss2 := accepted[1], accepted[2]
	defer ss1.Close()
	defer ss2.Close()

	// Close service 1 streams
	s1.Close()
	ss1.Close()

	// Service 2 still works after service 1 is closed
	time.Sleep(50 * time.Millisecond)
	s2.Write([]byte("alive"))
	got, err := readFull(ss2, 5, 5*time.Second)
	if err != nil {
		t.Fatalf("service 2 read error: %v", err)
	}
	if !bytes.Equal(got, []byte("alive")) {
		t.Errorf("service 2 read: got %q, want %q", got, "alive")
	}
}

// === Benchmarks ===

func BenchmarkYamux_OpenClose(b *testing.B) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	go func() {
		for {
			s, _, err := server.AcceptStream()
			if err != nil {
				return
			}
			s.Close()
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, err := client.OpenStream(1)
		if err != nil {
			b.Fatal(err)
		}
		s.Close()
	}
}

func BenchmarkYamux_Throughput_1(b *testing.B) {
	benchYamuxThroughput(b, 1)
}

func BenchmarkYamux_Throughput_10(b *testing.B) {
	benchYamuxThroughput(b, 10)
}

func benchYamuxThroughput(b *testing.B, numStreams int) {
	b.Helper()
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	data := bytes.Repeat([]byte("X"), 8192)
	buf := make([]byte, 16384)

	type streamPair struct {
		c, s net.Conn
	}
	pairs := make([]streamPair, numStreams)
	for i := range pairs {
		c, _ := client.OpenStream(1)
		s, _, _ := server.AcceptStream()
		pairs[i] = streamPair{c, s}
	}

	b.SetBytes(int64(len(data)) * int64(numStreams))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		wg.Add(numStreams)
		for _, p := range pairs {
			p := p
			go func() {
				defer wg.Done()
				p.c.Write(data)
				total := 0
				for total < len(data) {
					n, _ := p.s.Read(buf)
					total += n
				}
			}()
		}
		wg.Wait()
	}

	for _, p := range pairs {
		p.c.Close()
		p.s.Close()
	}
}

func BenchmarkYamux_Fairness(b *testing.B) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	heavyC, _ := client.OpenStream(1)
	heavyS, _, _ := server.AcceptStream()
	lightC, _ := client.OpenStream(1)
	lightS, _, _ := server.AcceptStream()

	heavyData := bytes.Repeat([]byte("H"), 64*1024)
	lightData := []byte("L")

	b.ResetTimer()
	var lightLatencies []time.Duration

	for i := 0; i < b.N; i++ {
		// Heavy stream: blast large data
		go func() {
			heavyC.Write(heavyData)
		}()
		go func() {
			buf := make([]byte, 128*1024)
			heavyS.Read(buf)
		}()

		// Light stream: measure single-message latency
		start := time.Now()
		lightC.Write(lightData)
		buf := make([]byte, 10)
		lightS.Read(buf)
		lightLatencies = append(lightLatencies, time.Since(start))
	}

	if len(lightLatencies) > 0 {
		var total int64
		for _, d := range lightLatencies {
			total += d.Microseconds()
		}
		avg := total / int64(len(lightLatencies))
		b.ReportMetric(float64(avg), "μs/light-msg")
	}

	heavyC.Close()
	heavyS.Close()
	lightC.Close()
	lightS.Close()
}

// === Composite tests ===

func testComposite(t *testing.T, numServices, streamsPerService int) {
	t.Helper()
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	var totalStreams atomic.Int64
	var wg sync.WaitGroup

	// Server: accept all streams, echo back
	go func() {
		for {
			s, _, err := server.AcceptStream()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer s.Close()
				buf := make([]byte, 2048)
				s.SetReadDeadline(time.Now().Add(15 * time.Second))
				n, err := s.Read(buf)
				if err != nil {
					return
				}
				s.Write(buf[:n])
				totalStreams.Add(1)
			}()
		}
	}()

	// Client: open streams across services, write+read
	var clientWg sync.WaitGroup
	for svc := 0; svc < numServices; svc++ {
		for st := 0; st < streamsPerService; st++ {
			clientWg.Add(1)
			svc, st := uint64(svc), st
			go func() {
				defer clientWg.Done()
				s, err := client.OpenStream(svc)
				if err != nil {
					t.Errorf("svc=%d stream=%d: open: %v", svc, st, err)
					return
				}
				defer s.Close()

				msg := []byte(fmt.Sprintf("s%d-%d", svc, st))
				s.Write(msg)
				got, err := readFull(s, len(msg), 15*time.Second)
				if err != nil {
					t.Errorf("svc=%d stream=%d: read: %v", svc, st, err)
					return
				}
				if !bytes.Equal(got, msg) {
					t.Errorf("svc=%d stream=%d: got %q, want %q", svc, st, got, msg)
				}
			}()
		}
	}

	done := make(chan struct{})
	go func() { clientWg.Wait(); close(done) }()

	expected := numServices * streamsPerService
	select {
	case <-done:
		t.Logf("%d services × %d streams = %d total, completed %d",
			numServices, streamsPerService, expected, totalStreams.Load())
	case <-time.After(30 * time.Second):
		t.Fatalf("timeout: %d services × %d streams, completed %d/%d",
			numServices, streamsPerService, totalStreams.Load(), expected)
	}

	// Wait for server side to finish
	server.Close()
	wg.Wait()
}

func TestComposite_1x100(t *testing.T)  { testComposite(t, 1, 100) }
func TestComposite_10x10(t *testing.T)  { testComposite(t, 10, 10) }
func TestComposite_10x100(t *testing.T) { testComposite(t, 10, 100) }
func TestComposite_100x100(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 100x100 test in short mode")
	}
	testComposite(t, 100, 100)
}

// === BUG regression tests — these must FAIL before fix, PASS after ===

// TestServiceMux_BUG3_AcceptBackpressure verifies that when the accept queue
// is full, streams are NOT silently dropped. They should block until consumed.
// Before fix: streams beyond buffer capacity are Close()'d silently.
func TestServiceMux_BUG3_AcceptBackpressure(t *testing.T) {
	client, server := serviceMuxPair(0)
	defer client.Close()
	defer server.Close()

	const total = 5000

	var accepted atomic.Int64
	go func() {
		for {
			_, _, err := server.AcceptStream()
			if err != nil {
				return
			}
			accepted.Add(1)
		}
	}()

	opened := make([]net.Conn, 0, total)
	for i := 0; i < total; i++ {
		s, err := client.OpenStream(1)
		if err != nil {
			t.Fatalf("open stream %d: %v", i, err)
		}
		opened = append(opened, s)
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if accepted.Load() >= int64(total) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	got := accepted.Load()
	if got < int64(total) {
		t.Fatalf("BUG3: only accepted %d/%d streams — %d silently dropped!",
			got, total, int64(total)-got)
	}

	for _, s := range opened {
		s.Close()
	}

	t.Logf("all %d streams accepted (no drops)", total)
}

// ==================== Timeout / Dead Peer Tests ====================

func TestServiceMux_AcceptThenClose(t *testing.T) {
	_, server := serviceMuxPair(0)

	done := make(chan error, 1)
	go func() {
		_, _, err := server.AcceptStream()
		done <- err
	}()

	time.Sleep(100 * time.Millisecond)
	server.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("AcceptStream should return error after Close")
		}
		t.Logf("AcceptStream returned: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("AcceptStream didn't unblock after Close()")
	}
}

func TestYamux_KeepaliveTimeout(t *testing.T) {
	client, server := serviceMuxPair(0)

	// Server echo in background.
	go func() {
		for {
			s, _, err := server.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 4096)
				for {
					n, err := s.Read(buf)
					if err != nil || n == 0 {
						return
					}
					s.Write(buf[:n])
				}
			}()
		}
	}()

	// Open stream and exchange data.
	s, err := client.OpenStream(1)
	if err != nil {
		t.Fatal(err)
	}
	s.Write([]byte("hello yamux"))
	buf := make([]byte, 256)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello yamux" {
		t.Fatalf("echo mismatch: %q", buf[:n])
	}

	// Close server (simulates peer going away).
	server.Close()

	// NO SetDeadline — testing KCPConn self-timeout propagation through yamux.
	start := time.Now()
	_, err = s.Read(buf)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error after peer close, got nil")
	}
	if elapsed > 35*time.Second {
		t.Fatalf("Read took %v after peer close — no self-timeout", elapsed)
	}
	t.Logf("yamux read self-timed-out after %v: %v", elapsed, err)
	client.Close()
}

func TestServiceMux_OpenNoPeer(t *testing.T) {
	mux := NewServiceMux(ServiceMuxConfig{
		IsClient: true,
		Output: func(service uint64, data []byte) error {
			return nil
		},
	})
	defer mux.Close()

	// yamux optimistically creates the stream. But writing to it should
	// eventually fail when the KcpConn idle-times-out (no peer ACKs).
	s, err := mux.OpenStream(1)
	if err != nil {
		t.Logf("OpenStream failed immediately: %v (acceptable)", err)
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Write data — it goes into KCP but never gets ACKed.
		start := time.Now()
		buf := make([]byte, 256)
		for {
			_, err := s.Write([]byte("no peer"))
			if err != nil {
				t.Logf("Write failed after %v: %v", time.Since(start), err)
				return
			}
			_, err = s.Read(buf)
			if err != nil {
				t.Logf("Read failed after %v: %v", time.Since(start), err)
				return
			}
		}
	}()

	select {
	case <-done:
		// Good — stream eventually failed.
	case <-time.After(35 * time.Second):
		t.Fatal("Stream with no peer hung forever — no timeout")
	}
}
