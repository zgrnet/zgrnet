package kcp

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"
)

// connPair creates a connected pair of KCPConns for testing.
// Packets from A are delivered to B and vice versa.
// loss controls simulated packet drop rate (0.0 = no loss).
func connPair(loss float64) (*KCPConn, *KCPConn) {
	var a, b *KCPConn
	rng := newLCG(42)

	a = NewKCPConn(1, func(data []byte) {
		if loss > 0 && rng.shouldDrop(loss) {
			return
		}
		b.Input(data)
	})
	b = NewKCPConn(1, func(data []byte) {
		if loss > 0 && rng.shouldDrop(loss) {
			return
		}
		a.Input(data)
	})
	return a, b
}

// --- Basic tests ---

func TestKCPConn_WriteRead(t *testing.T) {
	a, b := connPair(0)
	defer a.Close()
	defer b.Close()

	msg := []byte("hello from A to B")
	if _, err := a.Write(msg); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 256)
	n, err := b.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("got %q, want %q", buf[:n], msg)
	}
}

func TestKCPConn_Bidirectional(t *testing.T) {
	a, b := connPair(0)
	defer a.Close()
	defer b.Close()

	msgA := []byte("from A")
	msgB := []byte("from B")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		a.Write(msgA)
		buf := make([]byte, 256)
		n, _ := a.Read(buf)
		if !bytes.Equal(buf[:n], msgB) {
			t.Errorf("A got %q, want %q", buf[:n], msgB)
		}
	}()

	go func() {
		defer wg.Done()
		b.Write(msgB)
		buf := make([]byte, 256)
		n, _ := b.Read(buf)
		if !bytes.Equal(buf[:n], msgA) {
			t.Errorf("B got %q, want %q", buf[:n], msgA)
		}
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestKCPConn_LargeData_32MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 32MB test in short mode")
	}

	a, b := connPair(0)
	defer a.Close()
	defer b.Close()

	const totalSize = 32 * 1024 * 1024
	const chunkSize = 8 * 1024
	sendData := make([]byte, totalSize)
	for i := range sendData {
		sendData[i] = byte(i)
	}

	var wg sync.WaitGroup
	var recvData []byte

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		for len(recvData) < totalSize {
			n, err := b.Read(buf)
			if err != nil {
				t.Errorf("Read error at %d bytes: %v", len(recvData), err)
				return
			}
			recvData = append(recvData, buf[:n]...)
		}
	}()

	written := 0
	for written < totalSize {
		end := written + chunkSize
		if end > totalSize {
			end = totalSize
		}
		if _, err := a.Write(sendData[written:end]); err != nil {
			t.Fatalf("Write error at %d: %v", written, err)
		}
		written += end - written
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatalf("timeout: sent %d, received %d", written, len(recvData))
	}

	if !bytes.Equal(recvData, sendData) {
		t.Errorf("data mismatch: sent %d bytes, received %d bytes", totalSize, len(recvData))
	}
}

func TestKCPConn_SmallMessages(t *testing.T) {
	a, b := connPair(0)
	defer a.Close()
	defer b.Close()

	const msgCount = 1000
	const msgSize = 64
	const totalExpected = msgCount * msgSize

	var wg sync.WaitGroup
	var totalReceived int

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		for totalReceived < totalExpected {
			n, err := b.Read(buf)
			if err != nil {
				return
			}
			totalReceived += n
		}
	}()

	for i := 0; i < msgCount; i++ {
		msg := bytes.Repeat([]byte{byte(i)}, msgSize)
		if _, err := a.Write(msg); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("timeout: received %d/%d bytes", totalReceived, totalExpected)
	}

	if totalReceived != totalExpected {
		t.Errorf("total bytes = %d, want %d", totalReceived, totalExpected)
	}
}

func TestKCPConn_ZeroLengthWrite(t *testing.T) {
	a, b := connPair(0)
	defer a.Close()
	defer b.Close()

	n, err := a.Write(nil)
	if err != nil {
		t.Fatalf("Write(nil) error: %v", err)
	}
	if n != 0 {
		t.Fatalf("Write(nil) = %d, want 0", n)
	}

	n, err = a.Write([]byte{})
	if err != nil {
		t.Fatalf("Write(empty) error: %v", err)
	}
	if n != 0 {
		t.Fatalf("Write(empty) = %d, want 0", n)
	}
}

// --- Lifecycle tests ---

func TestKCPConn_Close_ReadEOF(t *testing.T) {
	a, b := connPair(0)
	defer b.Close()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 10)
		_, err := a.Read(buf)
		readDone <- err
	}()

	time.Sleep(50 * time.Millisecond)
	a.Close()

	select {
	case err := <-readDone:
		if err != io.EOF {
			t.Errorf("Read after Close = %v, want io.EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not unblock after Close")
	}
}

func TestKCPConn_Close_WriteError(t *testing.T) {
	a, b := connPair(0)
	defer b.Close()

	a.Close()
	_, err := a.Write([]byte("test"))
	if err != ErrConnClosed {
		t.Errorf("Write after Close = %v, want ErrConnClosed", err)
	}
}

func TestKCPConn_DoubleClose(t *testing.T) {
	a, b := connPair(0)
	defer b.Close()

	if err := a.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestKCPConn_CloseWhileReading(t *testing.T) {
	a, b := connPair(0)
	defer b.Close()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 256)
		_, err := a.Read(buf)
		readDone <- err
	}()

	time.Sleep(50 * time.Millisecond)
	a.Close()

	select {
	case err := <-readDone:
		if err != io.EOF {
			t.Errorf("Read returned %v, want io.EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Read not unblocked by Close")
	}
}

func TestKCPConn_CloseWhileWriting(t *testing.T) {
	a, b := connPair(0)
	defer b.Close()

	a.Close()
	_, err := a.Write([]byte("data"))
	if err == nil {
		t.Error("Write after Close should return error")
	}
}

func TestKCPConn_GoroutineLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	const N = 100
	conns := make([]*KCPConn, N*2)
	for i := 0; i < N; i++ {
		a, b := connPair(0)
		conns[i*2] = a
		conns[i*2+1] = b
	}

	peak := runtime.NumGoroutine()
	if peak <= baseline {
		t.Fatalf("expected goroutine count to increase: baseline=%d, peak=%d", baseline, peak)
	}

	for _, c := range conns {
		c.Close()
	}

	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	after := runtime.NumGoroutine()
	leaked := after - baseline
	if leaked > 5 {
		t.Errorf("goroutine leak: baseline=%d, after=%d, leaked=%d", baseline, after, leaked)
	}
}

// --- Event-driven tests ---

func TestKCPConn_InputWakesRead(t *testing.T) {
	a, b := connPair(0)
	defer a.Close()
	defer b.Close()

	readDone := make(chan struct{})
	go func() {
		buf := make([]byte, 256)
		b.Read(buf)
		close(readDone)
	}()

	time.Sleep(50 * time.Millisecond)
	a.Write([]byte("wake up"))

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Read not woken by Input")
	}
}

func TestKCPConn_CheckTimer(t *testing.T) {
	a, b := connPair(0)
	defer a.Close()
	defer b.Close()

	a.Write([]byte("test data"))

	buf := make([]byte, 256)
	n, err := b.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], []byte("test data")) {
		t.Errorf("got %q", buf[:n])
	}
}

// --- Packet loss tests ---

func TestKCPConn_PacketLoss_1pct(t *testing.T) {
	testKCPConnLoss(t, 0.01, 64*1024)
}

func TestKCPConn_PacketLoss_5pct(t *testing.T) {
	testKCPConnLoss(t, 0.05, 64*1024)
}

func TestKCPConn_PacketLoss_20pct(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 20% loss test in short mode")
	}
	testKCPConnLoss(t, 0.20, 32*1024)
}

func testKCPConnLoss(t *testing.T, lossRate float64, dataSize int) {
	t.Helper()
	a, b := connPair(lossRate)
	defer a.Close()
	defer b.Close()

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
			n, err := b.Read(buf)
			if err != nil {
				return
			}
			recvData = append(recvData, buf[:n]...)
		}
	}()

	chunkSize := 1024
	for written := 0; written < dataSize; {
		end := written + chunkSize
		if end > dataSize {
			end = dataSize
		}
		a.Write(sendData[written:end])
		written = end
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

func TestKCPConn_ReorderPackets(t *testing.T) {
	var a, b *KCPConn
	var pending [][]byte
	var mu sync.Mutex

	rng := newLCG(99)

	a = NewKCPConn(1, func(data []byte) {
		cp := make([]byte, len(data))
		copy(cp, data)
		mu.Lock()
		pending = append(pending, cp)
		// Deliver in random order every 3 packets
		if len(pending) >= 3 {
			for i := len(pending) - 1; i > 0; i-- {
				j := int(rng.next() * float64(i+1))
				pending[i], pending[j] = pending[j], pending[i]
			}
			for _, p := range pending {
				b.Input(p)
			}
			pending = pending[:0]
		}
		mu.Unlock()
	})
	b = NewKCPConn(1, func(data []byte) {
		a.Input(data)
	})
	defer a.Close()
	defer b.Close()

	msg := bytes.Repeat([]byte("R"), 4096)
	a.Write(msg)

	// Flush remaining pending packets
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	for _, p := range pending {
		b.Input(p)
	}
	pending = pending[:0]
	mu.Unlock()

	buf := make([]byte, 8192)
	received := make([]byte, 0, len(msg))
	deadline := time.Now().Add(5 * time.Second)
	for len(received) < len(msg) && time.Now().Before(deadline) {
		n, err := b.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		received = append(received, buf[:n]...)
	}

	if !bytes.Equal(received, msg) {
		t.Errorf("reorder: got %d bytes, want %d", len(received), len(msg))
	}
}

func TestKCPConn_DuplicatePackets(t *testing.T) {
	var a, b *KCPConn

	a = NewKCPConn(1, func(data []byte) {
		cp := make([]byte, len(data))
		copy(cp, data)
		b.Input(cp)
		// Send duplicate
		cp2 := make([]byte, len(data))
		copy(cp2, data)
		b.Input(cp2)
	})
	b = NewKCPConn(1, func(data []byte) {
		a.Input(data)
	})
	defer a.Close()
	defer b.Close()

	msg := []byte("deduplicate me")
	a.Write(msg)

	buf := make([]byte, 256)
	n, err := b.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Errorf("got %q, want %q", buf[:n], msg)
	}
}

// --- Benchmarks ---

func BenchmarkKCPConn_Throughput(b *testing.B) {
	a, bConn := connPair(0)
	defer a.Close()
	defer bConn.Close()

	data := bytes.Repeat([]byte("X"), 8192)
	buf := make([]byte, 16384)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		a.Write(data)
		total := 0
		for total < len(data) {
			n, err := bConn.Read(buf)
			if err != nil {
				b.Fatal(err)
			}
			total += n
		}
	}
}

func BenchmarkKCPConn_Latency(b *testing.B) {
	a, bConn := connPair(0)
	defer a.Close()
	defer bConn.Close()

	msg := []byte("ping")
	buf := make([]byte, 64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Write(msg)
		bConn.Read(buf)
	}
}

func BenchmarkKCPConn_SmallMsg(b *testing.B) {
	a, bConn := connPair(0)
	defer a.Close()
	defer bConn.Close()

	msg := bytes.Repeat([]byte("M"), 64)
	buf := make([]byte, 128)

	b.SetBytes(64)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		a.Write(msg)
		total := 0
		for total < 64 {
			n, _ := bConn.Read(buf)
			total += n
		}
	}
}

func BenchmarkKCPConn_Throughput_Sizes(b *testing.B) {
	sizes := []int{64, 512, 1024, 4096, 8192, 32768}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			a, bConn := connPair(0)
			defer a.Close()
			defer bConn.Close()

			data := bytes.Repeat([]byte("X"), size)
			buf := make([]byte, size*2)

			b.SetBytes(int64(size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				a.Write(data)
				total := 0
				for total < size {
					n, _ := bConn.Read(buf)
					total += n
				}
			}
		})
	}
}

// === BUG regression tests — these must FAIL before fix, PASS after ===

// TestKCPConn_BUG1_ConcurrentWriteRace verifies that concurrent Write calls
// from multiple goroutines don't race with the internal runLoop.
// Run with -race to detect: go test -race -run BUG1
func TestKCPConn_BUG1_ConcurrentWriteRace(t *testing.T) {
	a, b := connPair(0)
	defer a.Close()
	defer b.Close()

	const numWriters = 10
	const writesPerGoroutine = 100
	msg := bytes.Repeat([]byte("R"), 128)

	var wg sync.WaitGroup

	// Multiple goroutines writing concurrently
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				a.Write(msg)
			}
		}()
	}

	// Reader consuming data on the other side
	totalExpected := numWriters * writesPerGoroutine * len(msg)
	received := 0
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 64*1024)
		for received < totalExpected {
			n, err := b.Read(buf)
			if err != nil {
				return
			}
			received += n
		}
	}()

	wg.Wait()

	select {
	case <-readDone:
	case <-time.After(10 * time.Second):
		t.Fatalf("timeout: received %d/%d bytes", received, totalExpected)
	}

	if received != totalExpected {
		t.Errorf("received %d bytes, want %d", received, totalExpected)
	}
}

// TestKCPConn_BUG2_ReadDeadline verifies that SetReadDeadline actually
// causes Read to return with a timeout error after the deadline.
// Before fix: Read blocks forever (SetDeadline was no-op).
func TestKCPConn_BUG2_ReadDeadline(t *testing.T) {
	a, b := connPair(0)
	defer a.Close()
	defer b.Close()

	b.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	buf := make([]byte, 10)
	readDone := make(chan error, 1)
	go func() {
		_, err := b.Read(buf)
		readDone <- err
	}()

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("expected deadline error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("BUG2: Read did not respect deadline — blocked for 2s (SetDeadline is no-op)")
	}
}

// TestKCPConn_BUG2_WriteDeadline verifies that SetWriteDeadline works.
func TestKCPConn_BUG2_WriteDeadline(t *testing.T) {
	a, b := connPair(0)
	defer a.Close()
	defer b.Close()

	a.SetWriteDeadline(time.Now().Add(-1 * time.Second)) // already expired
	_, err := a.Write([]byte("should fail"))
	if err != ErrConnTimeout {
		t.Errorf("Write with expired deadline: got %v, want ErrConnTimeout", err)
	}
}

// ==================== Timeout / Dead Peer Tests ====================
// These test KCPConn's own timeout behavior, not external wrappers.

func TestKCPConn_ReadPeerDead(t *testing.T) {
	a, b := connPair(0)

	// Exchange data to establish KCP state.
	a.Write([]byte("setup"))
	buf := make([]byte, 256)
	n, err := b.Read(buf)
	if err != nil || string(buf[:n]) != "setup" {
		t.Fatal("setup failed")
	}

	// Simulate peer crash: close A without graceful shutdown.
	a.Close()

	// B's Read should detect dead peer and return.
	// With KCP deadlink (20 retransmits) or read deadline, this should finish.
	b.SetReadDeadline(time.Now().Add(10 * time.Second))
	start := time.Now()
	_, err = b.Read(buf)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error after peer death, got nil")
	}
	if elapsed > 15*time.Second {
		t.Fatalf("Read took %v after peer death — too slow", elapsed)
	}
	t.Logf("Read returned after %v: %v", elapsed, err)
}

func TestKCPConn_WritePeerDead(t *testing.T) {
	a, b := connPair(0)

	a.Write([]byte("setup"))
	buf := make([]byte, 256)
	b.Read(buf)

	// Close B (peer dies). A's writes should eventually fail.
	b.Close()

	a.SetWriteDeadline(time.Now().Add(10 * time.Second))
	start := time.Now()
	chunk := make([]byte, 8192)
	var writeErr error
	for {
		_, writeErr = a.Write(chunk)
		if writeErr != nil {
			break
		}
		if time.Since(start) > 15*time.Second {
			t.Fatal("Write didn't fail after 15s — no dead peer detection")
		}
	}
	elapsed := time.Since(start)

	if elapsed > 15*time.Second {
		t.Fatalf("Write took %v to fail", elapsed)
	}
	t.Logf("Write failed after %v: %v", elapsed, writeErr)
	a.Close()
}

func TestKCPConn_CloseUnblocksRead(t *testing.T) {
	a, b := connPair(0)
	defer a.Close()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 256)
		b.Read(buf) // blocks — no data
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	b.Close()

	select {
	case <-done:
		// good — Read unblocked
	case <-time.After(5 * time.Second):
		t.Fatal("Read didn't unblock after Close()")
	}
}

func TestKCPConn_CloseUnblocksWrite(t *testing.T) {
	a, _ := connPair(0)

	done := make(chan struct{})
	go func() {
		chunk := make([]byte, 8192)
		for {
			if _, err := a.Write(chunk); err != nil {
				break
			}
		}
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	a.Close()

	select {
	case <-done:
		// good — Write unblocked
	case <-time.After(5 * time.Second):
		t.Fatal("Write didn't unblock after Close()")
	}
}
