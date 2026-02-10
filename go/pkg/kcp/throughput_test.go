package kcp

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestStreamThroughput measures async throughput through a Mux stream pair.
// Writer writes totalSize in chunkSize chunks, reader reads all, measures MB/s.
// This is NOT a Go benchmark (b.N) because we want a single run with a fixed data size.
func TestStreamThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping throughput test in short mode")
	}
	const totalSize = 32 * 1024 * 1024 // 32 MB
	const chunkSize = 8 * 1024         // 8 KB

	pair := newMuxPair(t)
	defer pair.client.Close()
	defer pair.server.Close()

	clientStream, err := pair.client.OpenStream(0, nil)
	if err != nil {
		t.Fatal(err)
	}

	var serverStream *Stream
	select {
	case serverStream = <-pair.clientStreams:
	case <-time.After(2 * time.Second):
		t.Fatal("accept timeout")
	}

	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(i & 0xFF)
	}

	var wg sync.WaitGroup
	var readBytes int

	// Reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		for readBytes < totalSize {
			n, err := serverStream.Read(buf)
			if err != nil {
				t.Errorf("read error: %v", err)
				return
			}
			readBytes += n
		}
	}()

	// Writer
	start := time.Now()
	written := 0
	for written < totalSize {
		n, err := clientStream.Write(chunk)
		if err != nil {
			t.Fatalf("write error at %d: %v", written, err)
		}
		written += n
	}

	// Wait for reader
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("timeout: wrote %d, read %d", written, readBytes)
	}

	elapsed := time.Since(start)
	mbps := float64(readBytes) / elapsed.Seconds() / (1024 * 1024)
	t.Logf("Layer 1 (pure Mux): %d bytes in %s = %.1f MB/s", readBytes, elapsed.Round(time.Millisecond), mbps)
	fmt.Printf("THROUGHPUT_MUX=%.1f\n", mbps)
}
