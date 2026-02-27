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
	Mode         string `json:"mode"` // "echo", "streaming", "multi_stream", "delayed_write"
	EchoMessage  string `json:"echo_message"`
	ThroughputMB int    `json:"throughput_mb"`
	ChunkKB      int    `json:"chunk_kb"`
	NumStreams   int    `json:"num_streams"`
	DelayMs      int    `json:"delay_ms"`
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
	mode := testCfg.Mode
	if mode == "" {
		mode = "echo"
	}

	stream, err := udp.OpenStream(peerKey, noise.ServiceProxy)
	if err != nil {
		log.Fatalf("[opener] Failed to open stream: %v", err)
	}
	defer stream.Close()
	log.Printf("[opener] Opened stream (mode=%s)", mode)

	switch mode {
	case "echo":
		msg := []byte(testCfg.EchoMessage)
		if _, err := stream.Write(msg); err != nil {
			log.Fatalf("[opener] write echo: %v", err)
		}
		log.Printf("[opener] Sent: %q", testCfg.EchoMessage)

		buf := make([]byte, 4096)
		n, err := readWithTimeout(stream, buf, 10*time.Second)
		if err != nil {
			log.Fatalf("[opener] read echo: %v", err)
		}
		log.Printf("[opener] Response: %q", string(buf[:n]))

	case "streaming":
		totalBytes := int64(testCfg.ThroughputMB) * 1024 * 1024
		chunkSize := testCfg.ChunkKB * 1024
		if chunkSize == 0 {
			chunkSize = 8192
		}
		chunk := make([]byte, chunkSize)
		for i := range chunk {
			chunk[i] = byte(i % 256)
		}

		var sent int64
		for sent < totalBytes {
			n, err := stream.Write(chunk)
			if err != nil {
				log.Fatalf("[opener] write: %v", err)
			}
			sent += int64(n)
		}
		log.Printf("[opener] Sent %d bytes", sent)

	case "multi_stream":
		numStreams := testCfg.NumStreams
		if numStreams == 0 {
			numStreams = 10
		}
		chunkSize := testCfg.ChunkKB * 1024
		if chunkSize == 0 {
			chunkSize = 8192
		}

		// First stream already open — write 100KB
		data := make([]byte, 100*1024)
		for i := range data {
			data[i] = byte(i % 256)
		}
		stream.Write(data)

		// Open additional streams
		var wg sync.WaitGroup
		for i := 1; i < numStreams; i++ {
			s, err := udp.OpenStream(peerKey, noise.ServiceProxy)
			if err != nil {
				log.Fatalf("[opener] open stream %d: %v", i, err)
			}
			wg.Add(1)
			go func(idx int, s net.Conn) {
				defer wg.Done()
				defer s.Close()
				s.Write(data)
				log.Printf("[opener] stream %d: sent %d bytes", idx, len(data))
			}(i, s)
		}
		wg.Wait()
		log.Printf("[opener] all %d streams done", numStreams)

	case "delayed_write":
		delayMs := testCfg.DelayMs
		if delayMs == 0 {
			delayMs = 2000
		}
		log.Printf("[opener] delaying %dms before writing...", delayMs)
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
		if _, err := stream.Write([]byte("delayed hello")); err != nil {
			log.Fatalf("[opener] delayed write: %v", err)
		}
		buf := make([]byte, 4096)
		n, err := readWithTimeout(stream, buf, 10*time.Second)
		if err != nil {
			log.Fatalf("[opener] delayed read: %v", err)
		}
		log.Printf("[opener] delayed response: %q", string(buf[:n]))
	}

	time.Sleep(time.Second)
}

func runAccepterTest(udp *znet.UDP, peerKey noise.PublicKey, peerName string, testCfg TestConfig) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		info := udp.PeerInfo(peerKey)
		if info != nil && info.State == znet.PeerStateEstablished {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)

	mode := testCfg.Mode
	if mode == "" {
		mode = "echo"
	}

	switch mode {
	case "echo", "delayed_write":
		stream, _, err := udp.AcceptStream(peerKey)
		if err != nil {
			log.Fatalf("[accepter] accept: %v", err)
		}
		defer stream.Close()

		buf := make([]byte, 4096)
		n, err := readWithTimeout(stream, buf, 30*time.Second)
		if err != nil {
			log.Fatalf("[accepter] read: %v", err)
		}
		log.Printf("[accepter] Received: %q", string(buf[:n]))

		response := fmt.Sprintf("Echo: %s", string(buf[:n]))
		stream.Write([]byte(response))
		log.Printf("[accepter] Sent: %q", response)

	case "streaming":
		stream, _, err := udp.AcceptStream(peerKey)
		if err != nil {
			log.Fatalf("[accepter] accept: %v", err)
		}
		defer stream.Close()

		totalBytes := int64(testCfg.ThroughputMB) * 1024 * 1024
		buf := make([]byte, 65536)
		var recv int64
		for recv < totalBytes {
			n, err := stream.Read(buf)
			if err != nil {
				break
			}
			recv += int64(n)
		}
		log.Printf("[accepter] Received %d / %d bytes", recv, totalBytes)
		if recv < totalBytes {
			log.Fatalf("[accepter] incomplete: got %d, want %d", recv, totalBytes)
		}

	case "multi_stream":
		numStreams := testCfg.NumStreams
		if numStreams == 0 {
			numStreams = 10
		}

		var wg sync.WaitGroup
		for i := 0; i < numStreams; i++ {
			stream, _, err := udp.AcceptStream(peerKey)
			if err != nil {
				log.Fatalf("[accepter] accept %d: %v", i, err)
			}
			wg.Add(1)
			go func(idx int, s net.Conn) {
				defer wg.Done()
				defer s.Close()
				buf := make([]byte, 65536)
				var total int64
				for {
					n, err := s.Read(buf)
					if err != nil || n == 0 {
						break
					}
					total += int64(n)
				}
				log.Printf("[accepter] stream %d: received %d bytes", idx, total)
			}(i, stream)
		}
		wg.Wait()
		log.Printf("[accepter] all %d streams done", numStreams)
	}

	time.Sleep(time.Second)
}

func readWithTimeout(stream io.Reader, buf []byte, timeout time.Duration) (int, error) {
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
