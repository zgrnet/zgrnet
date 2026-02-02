// Package main demonstrates UDP throughput testing with Noise encryption.
package main

import (
	"crypto/rand"
	"flag"
	"log"
	"sync"
	"sync/atomic"
	"time"

	znet "github.com/vibing/zgrnet/pkg/net"
	"github.com/vibing/zgrnet/pkg/noise"
)

var (
	dataSize = flag.Int("size", 100, "Data size in MB")
)

func main() {
	flag.Parse()

	log.Printf("=== Go UDP Throughput Test ===")

	// Generate keys
	serverKey, _ := noise.GenerateKeyPair()
	clientKey, _ := noise.GenerateKeyPair()

	// Create UDP instances
	server, err := znet.NewUDP(serverKey, znet.WithBindAddr("127.0.0.1:0"), znet.WithAllowUnknown(true))
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	client, err := znet.NewUDP(clientKey, znet.WithBindAddr("127.0.0.1:0"), znet.WithAllowUnknown(true))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	serverAddr := server.HostInfo().Addr
	clientAddr := client.HostInfo().Addr

	log.Printf("Server: %s", serverAddr)
	log.Printf("Client: %s", clientAddr)

	// Set peer endpoints
	client.SetPeerEndpoint(serverKey.Public, serverAddr)
	server.SetPeerEndpoint(clientKey.Public, clientAddr)

	// Connect
	log.Printf("Connecting...")
	if err := client.Connect(serverKey.Public); err != nil {
		log.Fatalf("Connect failed: %v", err)
	}
	log.Printf("Connected!")

	// Run benchmark
	runBenchmark(client, server, clientKey, serverKey, *dataSize)
}

func runBenchmark(client, server *znet.UDP, clientKey, serverKey *noise.KeyPair, dataSizeMB int) {
	chunkBytes := 1200 // Safe UDP size
	iterations := (dataSizeMB * 1024 * 1024) / chunkBytes
	totalBytes := int64(iterations * chunkBytes)

	log.Printf("Sending %d MB (%d packets)...", dataSizeMB, iterations)

	// Generate random data
	chunk := make([]byte, chunkBytes)
	rand.Read(chunk)

	// Receiver using ReadFrom (pipeline consumer)
	var wg sync.WaitGroup
	var serverBytes int64
	var serverPackets int64

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for serverBytes < totalBytes {
			_, n, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				atomic.AddInt64(&serverBytes, int64(n))
				atomic.AddInt64(&serverPackets, 1)
			}
		}
	}()

	// Sender
	start := time.Now()
	var sentBytes int64

	for i := 0; i < iterations; i++ {
		err := client.WriteTo(serverKey.Public, chunk)
		if err != nil {
			log.Fatalf("Write failed: %v", err)
		}
		sentBytes += int64(chunkBytes)
	}
	sendTime := time.Since(start)

	// Wait for receiver with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		log.Printf("Warning: Timeout")
	}
	totalTime := time.Since(start)

	// Results
	recvBytes := atomic.LoadInt64(&serverBytes)
	recvPackets := atomic.LoadInt64(&serverPackets)
	loss := float64(iterations-int(recvPackets)) / float64(iterations) * 100

	log.Printf("=== Results ===")
	log.Printf("Sent:     %d packets, %.2f MB", iterations, float64(sentBytes)/1024/1024)
	log.Printf("Received: %d packets, %.2f MB", recvPackets, float64(recvBytes)/1024/1024)
	log.Printf("Loss:     %.2f%%", loss)
	log.Printf("Send time: %v", sendTime)
	log.Printf("Total time: %v", totalTime)
	log.Printf("Throughput: %.2f MB/s", float64(recvBytes)/1024/1024/totalTime.Seconds())
}
