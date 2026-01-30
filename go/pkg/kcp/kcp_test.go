package kcp

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestKCPBasic(t *testing.T) {
	// Create a pipe to connect two KCP instances
	var (
		outputA [][]byte
		outputB [][]byte
		muA     sync.Mutex
		muB     sync.Mutex
	)

	// Create two KCP instances with the same conv
	kcpA := NewKCP(1, func(data []byte) {
		muA.Lock()
		outputA = append(outputA, append([]byte(nil), data...))
		muA.Unlock()
	})
	defer kcpA.Release()

	kcpB := NewKCP(1, func(data []byte) {
		muB.Lock()
		outputB = append(outputB, append([]byte(nil), data...))
		muB.Unlock()
	})
	defer kcpB.Release()

	// Configure for fast mode
	kcpA.DefaultConfig()
	kcpB.DefaultConfig()

	// Send data from A
	testData := []byte("hello from A")
	n := kcpA.Send(testData)
	if n < 0 {
		t.Fatalf("Send() failed with %d", n)
	}

	// Update A to flush the data
	current := uint32(time.Now().UnixMilli())
	kcpA.Update(current)

	// Feed A's output to B
	muA.Lock()
	for _, pkt := range outputA {
		kcpB.Input(pkt)
	}
	outputA = nil
	muA.Unlock()

	// Update B
	kcpB.Update(current)

	// Receive at B
	buf := make([]byte, 1024)
	n = kcpB.Recv(buf)
	if n < 0 {
		t.Fatalf("Recv() failed with %d", n)
	}

	if !bytes.Equal(buf[:n], testData) {
		t.Errorf("Recv() = %q, want %q", buf[:n], testData)
	}
}

func TestKCPBidirectional(t *testing.T) {
	// Create channels for packet exchange
	aToB := make(chan []byte, 100)
	bToA := make(chan []byte, 100)

	kcpA := NewKCP(1, func(data []byte) {
		aToB <- append([]byte(nil), data...)
	})
	defer kcpA.Release()

	kcpB := NewKCP(1, func(data []byte) {
		bToA <- append([]byte(nil), data...)
	})
	defer kcpB.Release()

	kcpA.DefaultConfig()
	kcpB.DefaultConfig()

	// Start update loops
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				current := uint32(time.Now().UnixMilli())
				kcpA.Update(current)
				kcpB.Update(current)
			case pkt := <-aToB:
				kcpB.Input(pkt)
			case pkt := <-bToA:
				kcpA.Input(pkt)
			}
		}
	}()

	// Send from A to B
	testDataA := []byte("message from A")
	kcpA.Send(testDataA)

	// Send from B to A
	testDataB := []byte("message from B")
	kcpB.Send(testDataB)

	// Wait for delivery
	time.Sleep(100 * time.Millisecond)

	// Receive at B
	buf := make([]byte, 1024)
	n := kcpB.Recv(buf)
	if n < 0 || !bytes.Equal(buf[:n], testDataA) {
		t.Errorf("B received %q, want %q", buf[:n], testDataA)
	}

	// Receive at A
	n = kcpA.Recv(buf)
	if n < 0 || !bytes.Equal(buf[:n], testDataB) {
		t.Errorf("A received %q, want %q", buf[:n], testDataB)
	}

	close(done)
}

func TestKCPLargeData(t *testing.T) {
	// Use synchronous approach for reliable testing
	var aOutput, bOutput [][]byte
	var muA, muB sync.Mutex

	kcpA := NewKCP(1, func(data []byte) {
		muA.Lock()
		aOutput = append(aOutput, append([]byte(nil), data...))
		muA.Unlock()
	})
	defer kcpA.Release()

	kcpB := NewKCP(1, func(data []byte) {
		muB.Lock()
		bOutput = append(bOutput, append([]byte(nil), data...))
		muB.Unlock()
	})
	defer kcpB.Release()

	// Configure with larger windows for large data
	kcpA.SetNodelay(1, 10, 2, 1)
	kcpA.SetWndSize(256, 256)
	kcpA.SetMTU(1400)

	kcpB.SetNodelay(1, 10, 2, 1)
	kcpB.SetWndSize(256, 256)
	kcpB.SetMTU(1400)

	// Send large data (10KB)
	testData := bytes.Repeat([]byte("X"), 10*1024)
	n := kcpA.Send(testData)
	if n < 0 {
		t.Fatalf("Send() failed with %d", n)
	}

	// Run update/exchange loop synchronously
	received := make([]byte, 0, len(testData))
	buf := make([]byte, 64*1024) // Large enough for any message

	for i := 0; i < 500 && len(received) < len(testData); i++ {
		current := uint32(time.Now().UnixMilli())

		// Update A - this flushes send queue
		kcpA.Update(current)

		// Feed A's output to B
		muA.Lock()
		pktsA := aOutput
		aOutput = nil
		muA.Unlock()

		for _, pkt := range pktsA {
			kcpB.Input(pkt)
		}

		// Update B - this processes input and generates ACKs
		kcpB.Update(current)

		// Feed B's output (ACKs) to A
		muB.Lock()
		pktsB := bOutput
		bOutput = nil
		muB.Unlock()

		for _, pkt := range pktsB {
			kcpA.Input(pkt)
		}

		// Try to receive
		if kcpB.PeekSize() > 0 {
			n := kcpB.Recv(buf)
			if n > 0 {
				received = append(received, buf[:n]...)
			}
		}

		time.Sleep(2 * time.Millisecond)
	}

	if !bytes.Equal(received, testData) {
		t.Errorf("Received %d bytes, want %d", len(received), len(testData))
	}
}

func TestKCPPeekSize(t *testing.T) {
	var outputA [][]byte
	var mu sync.Mutex

	kcpA := NewKCP(1, func(data []byte) {
		mu.Lock()
		outputA = append(outputA, append([]byte(nil), data...))
		mu.Unlock()
	})
	defer kcpA.Release()

	kcpB := NewKCP(1, func(data []byte) {})
	defer kcpB.Release()

	kcpA.DefaultConfig()
	kcpB.DefaultConfig()

	// Send data
	testData := []byte("peek test data")
	kcpA.Send(testData)

	current := uint32(time.Now().UnixMilli())
	kcpA.Update(current)

	// Feed to B
	mu.Lock()
	for _, pkt := range outputA {
		kcpB.Input(pkt)
	}
	mu.Unlock()

	kcpB.Update(current)

	// Peek size
	size := kcpB.PeekSize()
	if size != len(testData) {
		t.Errorf("PeekSize() = %d, want %d", size, len(testData))
	}
}

func TestKCPWaitSnd(t *testing.T) {
	kcpA := NewKCP(1, func(data []byte) {})
	defer kcpA.Release()

	kcpA.DefaultConfig()

	// Initially empty
	if ws := kcpA.WaitSnd(); ws != 0 {
		t.Errorf("WaitSnd() = %d, want 0", ws)
	}

	// Send some data
	kcpA.Send(bytes.Repeat([]byte("X"), 5000))

	// Should have pending data
	if ws := kcpA.WaitSnd(); ws == 0 {
		t.Error("WaitSnd() = 0, want > 0")
	}
}

func TestGetConv(t *testing.T) {
	var output []byte

	kcp := NewKCP(12345, func(data []byte) {
		output = append([]byte(nil), data...)
	})
	defer kcp.Release()

	kcp.DefaultConfig()
	kcp.Send([]byte("test"))

	current := uint32(time.Now().UnixMilli())
	kcp.Update(current)

	if output == nil {
		t.Fatal("No output generated")
	}

	conv := GetConv(output)
	if conv != 12345 {
		t.Errorf("GetConv() = %d, want 12345", conv)
	}
}

func BenchmarkKCPSendRecv(b *testing.B) {
	// Synchronous benchmark - no goroutines, no sleep
	var packetsAtoB [][]byte
	var packetsBtoA [][]byte

	kcpA := NewKCP(1, func(data []byte) {
		packetsAtoB = append(packetsAtoB, append([]byte(nil), data...))
	})
	defer kcpA.Release()

	kcpB := NewKCP(1, func(data []byte) {
		packetsBtoA = append(packetsBtoA, append([]byte(nil), data...))
	})
	defer kcpB.Release()

	kcpA.DefaultConfig()
	kcpB.DefaultConfig()

	data := []byte("benchmark data payload 1234567890")
	buf := make([]byte, 1024)
	var current uint32 = 0

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packetsAtoB = packetsAtoB[:0]
		packetsBtoA = packetsBtoA[:0]

		kcpA.Send(data)
		kcpA.Update(current)
		kcpA.Flush()

		for _, pkt := range packetsAtoB {
			kcpB.Input(pkt)
		}
		kcpB.Update(current)

		for _, pkt := range packetsBtoA {
			kcpA.Input(pkt)
		}

		kcpB.Recv(buf)
		current += 10
	}
}
