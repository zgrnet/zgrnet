// Package main demonstrates KCP stream multiplexing over Noise-encrypted connections.
// It creates two local peers, establishes a connection, opens/accepts streams,
// and measures throughput.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	znet "github.com/vibing/zgrnet/pkg/net"
	"github.com/vibing/zgrnet/pkg/noise"
)

var (
	dataSize   = flag.Int("size", 10, "Data size in MB for throughput test")
	chunkSize  = flag.Int("chunk", 32, "Chunk size in KB")
	echoTest   = flag.Bool("echo", true, "Run echo test before benchmark")
	rawMode    = flag.Bool("raw", false, "Use raw Write/Read instead of KCP stream")
	serverPort = flag.Int("server-port", 0, "Server port (0 for random)")
	clientPort = flag.Int("client-port", 0, "Client port (0 for random)")
)

func main() {
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// Generate keypairs
	serverKey, err := noise.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate server key: %v", err)
	}
	clientKey, err := noise.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate client key: %v", err)
	}

	// Create UDP instances
	serverBind := fmt.Sprintf("127.0.0.1:%d", *serverPort)
	clientBind := fmt.Sprintf("127.0.0.1:%d", *clientPort)

	server, err := znet.NewUDP(serverKey, znet.WithBindAddr(serverBind), znet.WithAllowUnknown(true))
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	client, err := znet.NewUDP(clientKey, znet.WithBindAddr(clientBind), znet.WithAllowUnknown(true))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	log.Printf("[server] Listening on %s", server.HostInfo().Addr)
	log.Printf("[client] Listening on %s", client.HostInfo().Addr)

	// Set up peer endpoints
	server.SetPeerEndpoint(clientKey.Public, client.HostInfo().Addr)
	client.SetPeerEndpoint(serverKey.Public, server.HostInfo().Addr)

	// Start receive loops to consume ReadFrom output
	// This is needed to prevent outputChan from filling up
	go receiveLoop(server, "server")
	go receiveLoop(client, "client")

	// Client connects to server
	log.Printf("[client] Connecting to server...")
	if err := client.Connect(serverKey.Public); err != nil {
		log.Fatalf("[client] Failed to connect: %v", err)
	}
	log.Printf("[client] Connected to server!")

	// Give time for handshake to complete on server side
	time.Sleep(100 * time.Millisecond)

	if *rawMode {
		// Raw mode: use Peer.Write/Read (no KCP, but with protocol routing)
		runRawBenchmark(client, server, clientKey, serverKey, *dataSize, *chunkSize)
	} else {
		// KCP stream mode
		runKCPBenchmark(client, server, clientKey, serverKey, *dataSize, *chunkSize)
	}

	log.Printf("[done] All tests completed successfully!")
}

func runKCPBenchmark(client, server *znet.UDP, clientKey, serverKey *noise.KeyPair, dataSizeMB, chunkSizeKB int) {
	// Server accepts stream in background
	var serverStream *znet.Stream
	var acceptErr error
	acceptDone := make(chan struct{})

	go func() {
		defer close(acceptDone)
		log.Printf("[server] Waiting to accept stream...")
		serverStream, acceptErr = server.AcceptStream(clientKey.Public)
		if acceptErr != nil {
			log.Printf("[server] AcceptStream failed: %v", acceptErr)
			return
		}
		log.Printf("[server] Accepted stream %d", serverStream.ID())
	}()

	// Client opens stream
	log.Printf("[client] Opening stream...")
	clientStream, err := client.OpenStream(serverKey.Public)
	if err != nil {
		log.Fatalf("[client] OpenStream failed: %v", err)
	}
	log.Printf("[client] Opened stream %d", clientStream.ID())
	defer clientStream.Close()

	// Wait for server to accept
	select {
	case <-acceptDone:
		if acceptErr != nil {
			log.Fatalf("Server failed to accept stream")
		}
	case <-time.After(5 * time.Second):
		log.Fatalf("Timeout waiting for server to accept stream")
	}
	defer serverStream.Close()

	// Run echo test
	if *echoTest {
		runEchoTest(clientStream, serverStream)
	}

	// Run throughput benchmark
	runStreamBenchmark(clientStream, serverStream, dataSizeMB, chunkSizeKB)
}

func runRawBenchmark(client, server *znet.UDP, clientKey, serverKey *noise.KeyPair, dataSizeMB, chunkSizeKB int) {
	chunkBytes := chunkSizeKB * 1024

	// Limit chunk size to safe UDP size (considering Noise overhead)
	maxChunk := 1200 // Safe size for UDP with encryption overhead
	if chunkBytes > maxChunk {
		chunkBytes = maxChunk
		log.Printf("[bench] Limiting chunk size to %d bytes for raw UDP", maxChunk)
	}

	// Calculate actual bytes to send (may be slightly less than requested due to integer division)
	iterations := (dataSizeMB * 1024 * 1024) / chunkBytes
	totalBytes := int64(iterations * chunkBytes)

	log.Printf("[bench] Starting RAW (Peer.Write/Read) throughput test: %d MB, chunk size %d bytes, iterations=%d", dataSizeMB, chunkBytes, iterations)

	// Generate random data
	chunk := make([]byte, chunkBytes)
	if _, err := rand.Read(chunk); err != nil {
		log.Fatalf("[bench] Failed to generate random data: %v", err)
	}

	// Server reads all data using Peer.Read
	var wg sync.WaitGroup
	var serverErr error
	var serverBytes int64
	var serverPackets int64

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		lastLog := time.Now()
		log.Printf("[recv] Starting receiver loop, waiting for data from %x...", clientKey.Public[:8])
		for serverBytes < totalBytes {
			proto, n, err := server.Read(clientKey.Public, buf)
			if err != nil {
				if err == znet.ErrClosed {
					log.Printf("[recv] Closed")
					return
				}
				serverErr = err
				log.Printf("[recv] Error: %v", err)
				return
			}
			if n > 0 {
				serverBytes += int64(n)
				serverPackets++
				if serverPackets == 1 {
					log.Printf("[recv] First packet: proto=%d, n=%d", proto, n)
				}
				if time.Since(lastLog) > 500*time.Millisecond {
					log.Printf("[recv] Progress: %d packets, %d bytes (%.1f MB)", serverPackets, serverBytes, float64(serverBytes)/1024/1024)
					lastLog = time.Now()
				}
			}
		}
		log.Printf("[recv] Complete: %d packets", serverPackets)
	}()

	// Client sends all data using Peer.Write
	start := time.Now()
	var sentBytes int64
	var sentPackets int64

	for i := 0; i < iterations; i++ {
		n, err := client.Write(serverKey.Public, noise.ProtocolChat, chunk)
		if err != nil {
			log.Fatalf("[bench] Write failed at iteration %d: %v", i, err)
		}
		sentBytes += int64(n)
		sentPackets++

		// Progress update every 10%
		if (i+1)%(iterations/10+1) == 0 {
			progress := float64(i+1) / float64(iterations) * 100
			log.Printf("[bench] Progress: %.0f%% (%d/%d MB)", progress, sentBytes/1024/1024, dataSizeMB)
		}
	}

	// Wait for server to receive all data (with timeout)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		log.Printf("[bench] Warning: Timeout waiting for server to receive all data")
	}

	elapsed := time.Since(start)

	if serverErr != nil {
		log.Fatalf("[bench] Server read error: %v", serverErr)
	}

	// Calculate throughput
	throughputMBps := float64(serverBytes) / elapsed.Seconds() / 1024 / 1024
	lossRate := float64(sentPackets-serverPackets) / float64(sentPackets) * 100

	log.Printf("[bench] ========== RAW (Peer.Write/Read) Results ==========")
	log.Printf("[bench] ReadFrom consumed: %d packets", atomic.LoadInt64(&readFromCount))
	log.Printf("[bench] Sent:       %d packets, %d bytes (%.2f MB)", sentPackets, sentBytes, float64(sentBytes)/1024/1024)
	log.Printf("[bench] Received:   %d packets, %d bytes (%.2f MB)", serverPackets, serverBytes, float64(serverBytes)/1024/1024)
	log.Printf("[bench] Loss:       %.2f%%", lossRate)
	log.Printf("[bench] Time:       %v", elapsed)
	log.Printf("[bench] Throughput: %.2f MB/s", throughputMBps)
	log.Printf("[bench] ==================================================")
}

var readFromCount int64

func receiveLoop(udp *znet.UDP, name string) {
	buf := make([]byte, 65535)
	for {
		_, n, err := udp.ReadFrom(buf)
		if err != nil {
			if err == znet.ErrClosed {
				return
			}
			// Ignore other errors, they're usually transient
			continue
		}
		if n > 0 {
			atomic.AddInt64(&readFromCount, 1)
		}
	}
}

func runEchoTest(clientStream, serverStream *znet.Stream) {
	log.Printf("[test] Running echo test...")

	testMsg := "Hello KCP Stream!"

	// Server reads in background
	var serverRecv string
	var serverErr error
	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)
		buf := make([]byte, 1024)
		// Wait a bit for data to arrive
		time.Sleep(100 * time.Millisecond)
		n, err := serverStream.Read(buf)
		if err != nil {
			serverErr = err
			return
		}
		serverRecv = string(buf[:n])
	}()

	// Client sends
	_, err := clientStream.Write([]byte(testMsg))
	if err != nil {
		log.Fatalf("[test] Client write failed: %v", err)
	}

	// Wait for server to receive
	select {
	case <-serverDone:
		if serverErr != nil {
			log.Fatalf("[test] Server read failed: %v", serverErr)
		}
	case <-time.After(5 * time.Second):
		log.Fatalf("[test] Timeout waiting for server to receive")
	}

	if serverRecv != testMsg {
		log.Fatalf("[test] Echo mismatch: got %q, expected %q", serverRecv, testMsg)
	}

	log.Printf("[test] Echo test passed: %q", testMsg)
}

func runStreamBenchmark(clientStream, serverStream *znet.Stream, dataSizeMB, chunkSizeKB int) {
	totalBytes := int64(dataSizeMB) * 1024 * 1024
	chunkBytes := chunkSizeKB * 1024

	log.Printf("[bench] Starting KCP BIDIRECTIONAL throughput test: %d MB each direction, chunk size %d KB", dataSizeMB, chunkSizeKB)

	// Generate random data
	chunk := make([]byte, chunkBytes)
	if _, err := rand.Read(chunk); err != nil {
		log.Fatalf("[bench] Failed to generate random data: %v", err)
	}

	var wg sync.WaitGroup
	var clientTxBytes, clientRxBytes, serverTxBytes, serverRxBytes int64

	start := time.Now()

	// Client writer (client -> server)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var sent int64
		iterations := int(totalBytes) / chunkBytes
		for i := 0; i < iterations; i++ {
			n, err := clientStream.Write(chunk)
			if err != nil {
				log.Printf("[client-tx] Write failed: %v", err)
				return
			}
			sent += int64(n)
		}
		atomic.StoreInt64(&clientTxBytes, sent)
	}()

	// Client reader (server -> client)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, chunkBytes)
		var recv int64
		for recv < totalBytes {
			n, err := clientStream.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				return
			}
			recv += int64(n)
		}
		atomic.StoreInt64(&clientRxBytes, recv)
	}()

	// Server writer (server -> client)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var sent int64
		iterations := int(totalBytes) / chunkBytes
		for i := 0; i < iterations; i++ {
			n, err := serverStream.Write(chunk)
			if err != nil {
				log.Printf("[server-tx] Write failed: %v", err)
				return
			}
			sent += int64(n)
		}
		atomic.StoreInt64(&serverTxBytes, sent)
	}()

	// Server reader (client -> server)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, chunkBytes)
		var recv int64
		for recv < totalBytes {
			n, err := serverStream.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				return
			}
			recv += int64(n)
		}
		atomic.StoreInt64(&serverRxBytes, recv)
	}()

	// Wait for all goroutines with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(120 * time.Second):
		log.Printf("[bench] Warning: Timeout waiting for completion")
	}

	elapsed := time.Since(start)

	// Calculate throughput
	totalTransfer := atomic.LoadInt64(&clientTxBytes) + atomic.LoadInt64(&clientRxBytes) +
		atomic.LoadInt64(&serverTxBytes) + atomic.LoadInt64(&serverRxBytes)
	throughputMBps := float64(totalTransfer) / elapsed.Seconds() / 1024 / 1024

	log.Printf("[bench] ========== KCP Bidirectional Results ==========")
	log.Printf("[bench] Client TX:  %d bytes (%.2f MB)", atomic.LoadInt64(&clientTxBytes), float64(atomic.LoadInt64(&clientTxBytes))/1024/1024)
	log.Printf("[bench] Client RX:  %d bytes (%.2f MB)", atomic.LoadInt64(&clientRxBytes), float64(atomic.LoadInt64(&clientRxBytes))/1024/1024)
	log.Printf("[bench] Server TX:  %d bytes (%.2f MB)", atomic.LoadInt64(&serverTxBytes), float64(atomic.LoadInt64(&serverTxBytes))/1024/1024)
	log.Printf("[bench] Server RX:  %d bytes (%.2f MB)", atomic.LoadInt64(&serverRxBytes), float64(atomic.LoadInt64(&serverRxBytes))/1024/1024)
	log.Printf("[bench] Total:      %d bytes (%.2f GB)", totalTransfer, float64(totalTransfer)/1024/1024/1024)
	log.Printf("[bench] Time:       %v", elapsed)
	log.Printf("[bench] Throughput: %.2f MB/s (bidirectional)", throughputMBps)
	log.Printf("[bench] ================================================")
}
