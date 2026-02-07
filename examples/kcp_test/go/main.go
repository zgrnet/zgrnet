// Package main demonstrates KCP stream interoperability between Go, Rust, and Zig.
//
// Usage:
//
//	go run . -name go -config ../config.json
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	znet "github.com/vibing/zgrnet/pkg/net"
	"github.com/vibing/zgrnet/pkg/noise"
)

// Config represents the test configuration.
type Config struct {
	Warning string     `json:"_WARNING"`
	Hosts   []HostInfo `json:"hosts"`
	Test    TestConfig `json:"test"`
}

// HostInfo represents a single host configuration.
type HostInfo struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	Port       int    `json:"port"`
	Role       string `json:"role"` // "opener" or "accepter"
}

// TestConfig represents test parameters.
type TestConfig struct {
	EchoMessage  string `json:"echo_message"`
	ThroughputMB int    `json:"throughput_mb"`
	ChunkKB      int    `json:"chunk_kb"`
}

var (
	name       = flag.String("name", "", "Host name (go, rust, or zig)")
	configPath = flag.String("config", "", "Path to config.json")
)

func main() {
	flag.Parse()

	if *name == "" {
		log.Fatal("Missing required flag: -name")
	}
	if *configPath == "" {
		log.Fatal("Missing required flag: -config")
	}

	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// Load configuration
	configData, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// Find our host info
	var myInfo *HostInfo
	for i := range config.Hosts {
		if config.Hosts[i].Name == *name {
			myInfo = &config.Hosts[i]
			break
		}
	}
	if myInfo == nil {
		log.Fatalf("Host '%s' not found in config", *name)
	}

	// Create keypair from private key seed
	privKeyBytes, err := hex.DecodeString(myInfo.PrivateKey)
	if err != nil {
		log.Fatalf("Invalid private key: %v", err)
	}
	var privKey noise.Key
	copy(privKey[:], privKeyBytes)
	keyPair, err := noise.NewKeyPair(privKey)
	if err != nil {
		log.Fatalf("Failed to create keypair: %v", err)
	}

	// Create UDP instance
	bindAddr := fmt.Sprintf(":%d", myInfo.Port)
	udp, err := znet.NewUDP(keyPair, znet.WithBindAddr(bindAddr), znet.WithAllowUnknown(true))
	if err != nil {
		log.Fatalf("Failed to create UDP: %v", err)
	}
	defer udp.Close()

	log.Printf("[%s] Listening on %s", *name, udp.HostInfo().Addr)
	log.Printf("[%s] Public key: %x", *name, keyPair.Public[:8])
	log.Printf("[%s] Role: %s", *name, myInfo.Role)

	// Find peer info (first host that is not us)
	var peerInfo *HostInfo
	for i := range config.Hosts {
		if config.Hosts[i].Name != *name {
			peerInfo = &config.Hosts[i]
			break
		}
	}
	if peerInfo == nil {
		log.Fatalf("No peer found in config")
	}

	peerKey, err := getPublicKeyFromInfo(*peerInfo)
	if err != nil {
		log.Fatalf("Invalid peer key: %v", err)
	}

	// Add peer endpoint
	endpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", peerInfo.Port))
	if err != nil {
		log.Fatalf("Failed to resolve peer address: %v", err)
	}
	udp.SetPeerEndpoint(peerKey, endpoint)
	log.Printf("[%s] Added peer %s at %s", *name, peerInfo.Name, endpoint)

	// Start receive loop in background (needed for handshake and transport)
	go receiveLoop(udp, *name)

	// Run KCP stream test based on role
	if myInfo.Role == "opener" {
		// Wait for peer to start
		log.Printf("[%s] Waiting for peer to start...", *name)
		time.Sleep(2 * time.Second)

		// Opener initiates connection
		log.Printf("[%s] Connecting to %s...", *name, peerInfo.Name)
		if err := udp.Connect(peerKey); err != nil {
			log.Fatalf("[%s] Failed to connect to %s: %v", *name, peerInfo.Name, err)
		}
		log.Printf("[%s] Connected to %s!", *name, peerInfo.Name)

		// Give time for mux initialization
		time.Sleep(100 * time.Millisecond)

		runOpenerTest(udp, peerKey, peerInfo.Name, config.Test)
	} else {
		// Accepter waits for incoming connection, then accepts stream
		log.Printf("[%s] Waiting for connection from %s...", *name, peerInfo.Name)
		runAccepterTest(udp, peerKey, peerInfo.Name, config.Test)
	}

	log.Printf("[%s] Test completed successfully!", *name)
}

func runOpenerTest(udp *znet.UDP, peerKey noise.PublicKey, peerName string, testCfg TestConfig) {
	log.Printf("[opener] Opening stream to %s with proto=TCP_PROXY(69)...", peerName)

	// Encode test Address as metadata: IPv4 127.0.0.1:8080
	testAddr := &noise.Address{Type: noise.AddressTypeIPv4, Host: "127.0.0.1", Port: 8080}
	metadata := testAddr.Encode()
	if metadata == nil {
		log.Fatalf("[opener] Failed to encode test address")
	}
	log.Printf("[opener] Metadata: %x (Address IPv4 127.0.0.1:8080)", metadata)

	stream, err := udp.OpenStream(peerKey, noise.ProtocolTCPProxy, metadata)
	if err != nil {
		log.Fatalf("[opener] Failed to open stream: %v", err)
	}
	defer stream.Close()

	log.Printf("[opener] Opened stream %d (proto=%d, metadata=%x)", stream.ID(), stream.Proto(), stream.Metadata())

	// Echo test
	log.Printf("[opener] Running echo test...")
	echoMsg := []byte(testCfg.EchoMessage)
	n, err := stream.Write(echoMsg)
	if err != nil {
		log.Fatalf("[opener] Failed to write echo: %v", err)
	}
	log.Printf("[opener] Sent %d bytes: %q", n, testCfg.EchoMessage)

	// Read echo response
	buf := make([]byte, 1024)
	n, err = readWithTimeout(stream, buf, 5*time.Second)
	if err != nil {
		log.Fatalf("[opener] Failed to read echo response: %v", err)
	}
	response := string(buf[:n])
	log.Printf("[opener] Received echo response: %q", response)

	// Bidirectional throughput test
	runBidirectionalTest(stream, "opener", testCfg)

	// Wait for peer to finish receiving
	time.Sleep(2 * time.Second)
}

func runAccepterTest(udp *znet.UDP, peerKey noise.PublicKey, peerName string, testCfg TestConfig) {
	// Wait for peer to connect and establish session
	log.Printf("[accepter] Waiting for %s to connect...", peerName)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		info := udp.PeerInfo(peerKey)
		if info != nil && info.State == znet.PeerStateEstablished {
			log.Printf("[accepter] Session established with %s", peerName)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Give mux time to initialize
	time.Sleep(100 * time.Millisecond)

	log.Printf("[accepter] Waiting to accept stream from %s...", peerName)

	stream, err := udp.AcceptStream(peerKey)
	if err != nil {
		log.Fatalf("[accepter] Failed to accept stream: %v", err)
	}
	defer stream.Close()

	log.Printf("[accepter] Accepted stream %d (proto=%d, metadata=%x)", stream.ID(), stream.Proto(), stream.Metadata())

	// Verify stream type: must be TCP_PROXY(69) with Address metadata
	if stream.Proto() != noise.ProtocolTCPProxy {
		log.Fatalf("[accepter] FAIL: expected proto=%d (TCP_PROXY), got %d", noise.ProtocolTCPProxy, stream.Proto())
	}
	addr, _, err := noise.DecodeAddress(stream.Metadata())
	if err != nil {
		log.Fatalf("[accepter] FAIL: failed to decode metadata as Address: %v", err)
	}
	if addr.Type != noise.AddressTypeIPv4 || addr.Host != "127.0.0.1" || addr.Port != 8080 {
		log.Fatalf("[accepter] FAIL: expected Address{IPv4, 127.0.0.1, 8080}, got {%d, %s, %d}", addr.Type, addr.Host, addr.Port)
	}
	log.Printf("[accepter] PASS: stream type verified (proto=TCP_PROXY, addr=127.0.0.1:8080)")

	// Echo test - receive and echo back
	buf := make([]byte, 1024)
	n, err := readWithTimeout(stream, buf, 5*time.Second)
	if err != nil {
		log.Fatalf("[accepter] Failed to read echo: %v", err)
	}
	received := string(buf[:n])
	log.Printf("[accepter] Received echo: %q", received)

	// Echo back with prefix
	response := fmt.Sprintf("Echo from %s: %s", "accepter", received)
	_, err = stream.Write([]byte(response))
	if err != nil {
		log.Fatalf("[accepter] Failed to write echo response: %v", err)
	}
	log.Printf("[accepter] Sent echo response: %q", response)

	// Bidirectional throughput test
	runBidirectionalTest(stream, "accepter", testCfg)
}

func runBidirectionalTest(stream *znet.Stream, role string, testCfg TestConfig) {
	totalBytes := int64(testCfg.ThroughputMB) * 1024 * 1024
	chunkSize := testCfg.ChunkKB * 1024

	log.Printf("[%s] Starting bidirectional test: %d MB each direction, %d KB chunks",
		role, testCfg.ThroughputMB, testCfg.ChunkKB)

	var wg sync.WaitGroup
	var sentBytes, recvBytes atomic.Int64
	start := time.Now()

	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		chunk := make([]byte, chunkSize)
		for i := range chunk {
			chunk[i] = byte(i % 256)
		}

		var sent int64
		for sent < totalBytes {
			n, err := stream.Write(chunk)
			if err != nil {
				log.Printf("[%s] Write error: %v", role, err)
				return
			}
			sent += int64(n)
			sentBytes.Store(sent)

			// Progress every 10%
			if sent%(totalBytes/10) < int64(chunkSize) {
				log.Printf("[%s] TX: %.1f%%", role, float64(sent)/float64(totalBytes)*100)
			}
		}
		log.Printf("[%s] TX complete: %d bytes", role, sent)
	}()

	// Reader goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, chunkSize*2)

		var recv int64
		for recv < totalBytes {
			n, err := stream.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Printf("[%s] Read error: %v", role, err)
				return
			}
			recv += int64(n)
			recvBytes.Store(recv)
		}
		log.Printf("[%s] RX complete: %d bytes", role, recv)
	}()

	wg.Wait()
	elapsed := time.Since(start)

	sent := sentBytes.Load()
	recv := recvBytes.Load()
	totalTransfer := sent + recv
	throughput := float64(totalTransfer) / elapsed.Seconds() / 1024 / 1024

	log.Printf("[%s] ========== Bidirectional Results ==========", role)
	log.Printf("[%s] Sent:       %d bytes (%.2f GB)", role, sent, float64(sent)/1024/1024/1024)
	log.Printf("[%s] Received:   %d bytes (%.2f GB)", role, recv, float64(recv)/1024/1024/1024)
	log.Printf("[%s] Total:      %d bytes (%.2f GB)", role, totalTransfer, float64(totalTransfer)/1024/1024/1024)
	log.Printf("[%s] Time:       %v", role, elapsed)
	log.Printf("[%s] Throughput: %.2f MB/s (bidirectional)", role, throughput)
	log.Printf("[%s] ============================================", role)
}

func readWithTimeout(stream *znet.Stream, buf []byte, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, err := stream.Read(buf)
		if err != nil {
			return 0, err
		}
		if n > 0 {
			return n, nil
		}
		time.Sleep(time.Millisecond)
	}
	return 0, fmt.Errorf("read timeout after %v", timeout)
}

func receiveLoop(udp *znet.UDP, name string) {
	buf := make([]byte, 65535)
	for {
		_, n, err := udp.ReadFrom(buf)
		if err != nil {
			if err == znet.ErrClosed {
				return
			}
			continue
		}
		// Silently consume non-KCP packets
		_ = n
	}
}

func getPublicKeyFromInfo(hi HostInfo) (noise.PublicKey, error) {
	privKeyBytes, err := hex.DecodeString(hi.PrivateKey)
	if err != nil {
		return noise.PublicKey{}, err
	}
	if len(privKeyBytes) != 32 {
		return noise.PublicKey{}, fmt.Errorf("private key must be 32 bytes, got %d", len(privKeyBytes))
	}
	var privKey noise.Key
	copy(privKey[:], privKeyBytes)
	kp, err := noise.NewKeyPair(privKey)
	if err != nil {
		return noise.PublicKey{}, err
	}
	return kp.Public, nil
}
