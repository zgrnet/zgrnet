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
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vibing/zgrnet/host"
	"github.com/vibing/zgrnet/noise"
	"github.com/vibing/zgrnet/transport"
)

// PeerInfo describes a peer to connect to.
type PeerInfo struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"` // hex encoded
	Address   string `json:"address"`    // host:port
}

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
	privKeyBytes, err := hex.DecodeString(myHost.PrivateKey)
	if err != nil {
		log.Fatalf("Invalid private key: %v", err)
	}
	if len(privKeyBytes) != 32 {
		log.Fatalf("Private key must be 32 bytes, got %d", len(privKeyBytes))
	}

	var privKey noise.Key
	copy(privKey[:], privKeyBytes)
	keyPair, err := noise.NewKeyPair(privKey)
	if err != nil {
		log.Fatalf("Failed to create key pair: %v", err)
	}

	log.Printf("[%s] Public key: %s", *name, hex.EncodeToString(keyPair.Public[:]))

	// Pre-calculate peer name map for efficient lookups
	peerNames := buildPeerNameMap(config)

	// Create UDP transport
	bindAddr := fmt.Sprintf(":%d", myHost.Port)
	udp, err := transport.NewUDPListener(bindAddr)
	if err != nil {
		log.Fatalf("Failed to create UDP listener: %v", err)
	}
	defer udp.Close()

	log.Printf("[%s] Listening on port %d", *name, udp.Port())

	// Create Host
	h, err := host.NewHost(host.HostConfig{
		PrivateKey:        keyPair,
		Transport:         udp,
		AllowUnknownPeers: true,
		MTU:               1280,
	})
	if err != nil {
		log.Fatalf("Failed to create host: %v", err)
	}
	defer h.Close()

	// Add other hosts as peers
	for _, hi := range config.Hosts {
		if hi.Name == *name {
			continue // Skip self
		}

		privKeySeedBytes, err := hex.DecodeString(hi.PrivateKey)
		if err != nil {
			log.Printf("Warning: invalid key for %s: %v", hi.Name, err)
			continue
		}
		var peerPrivKey noise.Key
		copy(peerPrivKey[:], privKeySeedBytes)
		peerKP, err := noise.NewKeyPair(peerPrivKey)
		if err != nil {
			log.Printf("Warning: failed to derive key for %s: %v", hi.Name, err)
			continue
		}

		addr := &transport.UDPAddr{
			UDPAddr: &net.UDPAddr{
				IP:   net.ParseIP("127.0.0.1"),
				Port: hi.Port,
			},
		}

		h.AddPeer(peerKP.Public, addr)
		log.Printf("[%s] Added peer %s at port %d", *name, hi.Name, hi.Port)
	}

	// Handle incoming messages in background
	go func() {
		for {
			msg, err := h.RecvTimeout(time.Second)
			if err != nil {
				if err == host.ErrHostClosed {
					return
				}
				continue
			}

			fromName := peerNames[msg.From]
			if fromName == "" {
				fromName = hex.EncodeToString(msg.From[:8]) + "..."
			}
			log.Printf("[%s] Received from %s: protocol=%d, data=%q",
				*name, fromName, msg.Protocol, string(msg.Data))

			// Only echo back if it's not already an ACK (avoid infinite loop)
			if len(msg.Data) < 3 || string(msg.Data[:3]) != "ACK" {
				reply := fmt.Sprintf("ACK from %s: %s", *name, string(msg.Data))
				if err := h.Send(msg.From, msg.Protocol, []byte(reply)); err != nil {
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

		privKeySeedBytes, err := hex.DecodeString(hi.PrivateKey)
		if err != nil {
			log.Printf("[%s] Failed to decode private key for %s: %v", *name, hi.Name, err)
			continue
		}
		var peerPrivKey noise.Key
		copy(peerPrivKey[:], privKeySeedBytes)
		peerKP, err := noise.NewKeyPair(peerPrivKey)
		if err != nil {
			log.Printf("[%s] Failed to derive key for %s: %v", *name, hi.Name, err)
			continue
		}

		log.Printf("[%s] Connecting to %s...", *name, hi.Name)
		if err := h.Connect(peerKP.Public); err != nil {
			log.Printf("[%s] Failed to connect to %s: %v", *name, hi.Name, err)
			continue
		}
		log.Printf("[%s] Connected to %s!", *name, hi.Name)

		// Send test message
		testMsg := fmt.Sprintf("Hello from %s to %s!", *name, hi.Name)
		if err := h.Send(peerKP.Public, noise.ProtocolChat, []byte(testMsg)); err != nil {
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

// buildPeerNameMap creates a map of public keys to host names for efficient lookups.
func buildPeerNameMap(config *Config) map[noise.PublicKey]string {
	m := make(map[noise.PublicKey]string)
	for _, h := range config.Hosts {
		pubKeyBytes, err := hex.DecodeString(h.PrivateKey)
		if err != nil {
			continue
		}
		var privKey noise.Key
		copy(privKey[:], pubKeyBytes)
		kp, err := noise.NewKeyPair(privKey)
		if err != nil {
			continue
		}
		m[kp.Public] = h.Name
	}
	return m
}
