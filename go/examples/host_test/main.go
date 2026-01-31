// Package main demonstrates cross-language Host communication.
//
// Usage:
//
//	go run main.go -name go -port 10001 -peers peers.json
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	stdnet "net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vibing/zgrnet/net"
	"github.com/vibing/zgrnet/noise"
)

// Config is the test configuration.
type Config struct {
	Hosts []HostInfo `json:"hosts"`
}

// HostInfo describes a host in the test.
type HostInfo struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"` // hex encoded (32 bytes seed)
	Port       int    `json:"port"`
}

func main() {
	var (
		name       = flag.String("name", "", "Host name (go, rust, or zig)")
		port       = flag.Int("port", 0, "Port to listen on (overrides config)")
		configFile = flag.String("config", "config.json", "Config file path")
	)
	flag.Parse()

	if *name == "" {
		log.Fatal("Must specify -name")
	}

	// Load config
	config, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Find our host info
	var myHost *HostInfo
	for i := range config.Hosts {
		if config.Hosts[i].Name == *name {
			myHost = &config.Hosts[i]
			break
		}
	}
	if myHost == nil {
		log.Fatalf("Host %q not found in config", *name)
	}

	// Override port if specified
	if *port > 0 {
		myHost.Port = *port
	}

	// Parse private key
	keyPair, err := keyPairFromHex(myHost.PrivateKey)
	if err != nil {
		log.Fatalf("Failed to create key pair: %v", err)
	}

	log.Printf("[%s] Public key: %s", *name, hex.EncodeToString(keyPair.Public[:]))

	// Pre-calculate peer name map for efficient lookups
	peerNames := buildPeerNameMap(config)

	// Create UDP network
	bindAddr := fmt.Sprintf("127.0.0.1:%d", myHost.Port)
	udp, err := net.NewUDP(keyPair, net.WithBindAddr(bindAddr), net.WithAllowUnknown(true))
	if err != nil {
		log.Fatalf("Failed to create UDP: %v", err)
	}
	defer udp.Close()

	log.Printf("[%s] Listening on %s", *name, udp.HostInfo().Addr.String())

	// Add other hosts as peers
	for _, hi := range config.Hosts {
		if hi.Name == *name {
			continue // Skip self
		}

		peerKP, err := keyPairFromHex(hi.PrivateKey)
		if err != nil {
			log.Printf("Warning: failed to derive key for %s: %v", hi.Name, err)
			continue
		}

		addr := &stdnet.UDPAddr{
			IP:   stdnet.ParseIP("127.0.0.1"),
			Port: hi.Port,
		}

		udp.SetPeerEndpoint(peerKP.Public, addr)
		log.Printf("[%s] Added peer %s at port %d", *name, hi.Name, hi.Port)
	}

	// Handle incoming messages in background
	go func() {
		buf := make([]byte, 65535)
		for {
			pk, n, err := udp.ReadFrom(buf)
			if err != nil {
				if err == net.ErrClosed {
					return
				}
				continue
			}

			fromName := peerNames[pk]
			if fromName == "" {
				fromName = hex.EncodeToString(pk[:8]) + "..."
			}
			log.Printf("[%s] Received from %s: data=%q",
				*name, fromName, string(buf[:n]))

			// Only echo back if it's not already an ACK (avoid infinite loop)
			if n < 3 || string(buf[:3]) != "ACK" {
				reply := fmt.Sprintf("ACK from %s: %s", *name, string(buf[:n]))
				if err := udp.WriteTo(pk, []byte(reply)); err != nil {
					log.Printf("[%s] Failed to send reply: %v", *name, err)
				}
			}
		}
	}()

	// Wait a bit for other hosts to start
	log.Printf("[%s] Waiting 2 seconds for other hosts...", *name)
	time.Sleep(2 * time.Second)

	// Connect to and message other hosts
	for _, hi := range config.Hosts {
		if hi.Name == *name {
			continue
		}

		peerKP, err := keyPairFromHex(hi.PrivateKey)
		if err != nil {
			log.Printf("[%s] Failed to derive key for %s: %v", *name, hi.Name, err)
			continue
		}

		log.Printf("[%s] Connecting to %s...", *name, hi.Name)
		if err := udp.Connect(peerKP.Public); err != nil {
			log.Printf("[%s] Failed to connect to %s: %v", *name, hi.Name, err)
			continue
		}
		log.Printf("[%s] Connected to %s!", *name, hi.Name)

		// Send test message
		testMsg := fmt.Sprintf("Hello from %s to %s!", *name, hi.Name)
		if err := udp.WriteTo(peerKP.Public, []byte(testMsg)); err != nil {
			log.Printf("[%s] Failed to send to %s: %v", *name, hi.Name, err)
		} else {
			log.Printf("[%s] Sent message to %s", *name, hi.Name)
		}
	}

	// Wait for signal
	log.Printf("[%s] Running... Press Ctrl+C to exit", *name)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Printf("[%s] Shutting down...", *name)
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// keyPairFromHex creates a KeyPair from a hex-encoded private key seed.
func keyPairFromHex(privateKeyHex string) (*noise.KeyPair, error) {
	privKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	if len(privKeyBytes) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(privKeyBytes))
	}
	var privKey noise.Key
	copy(privKey[:], privKeyBytes)
	return noise.NewKeyPair(privKey)
}

// buildPeerNameMap creates a map of public keys to host names for efficient lookups.
func buildPeerNameMap(config *Config) map[noise.PublicKey]string {
	m := make(map[noise.PublicKey]string)
	for _, h := range config.Hosts {
		kp, err := keyPairFromHex(h.PrivateKey)
		if err != nil {
			continue
		}
		m[kp.Public] = h.Name
	}
	return m
}
