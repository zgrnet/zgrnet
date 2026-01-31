// Package main demonstrates the net.UDP API for cross-language communication.
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

	znet "github.com/vibing/zgrnet/net"
	"github.com/vibing/zgrnet/noise"
)

// Config represents the test configuration.
type Config struct {
	Warning string     `json:"_WARNING"`
	Hosts   []HostInfo `json:"hosts"`
}

// HostInfo represents a single host configuration.
type HostInfo struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	Port       int    `json:"port"`
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

	// Build peer name map for logging
	peerNames := buildPeerNameMap(config.Hosts)

	// Add other hosts as peers
	for _, hi := range config.Hosts {
		if hi.Name == *name {
			continue
		}

		peerKey, err := getPublicKeyFromInfo(hi)
		if err != nil {
			log.Printf("[%s] Warning: invalid key for %s: %v", *name, hi.Name, err)
			continue
		}

		endpoint, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", hi.Port))
		udp.SetPeerEndpoint(peerKey, endpoint)
		log.Printf("[%s] Added peer %s at %s", *name, hi.Name, endpoint)
	}

	// Start receive loop in background
	go receiveLoop(udp, *name, peerNames)

	// Give time for other hosts to start
	time.Sleep(time.Second)

	// Connect to all peers
	for _, hi := range config.Hosts {
		if hi.Name == *name {
			continue
		}

		peerKey, err := getPublicKeyFromInfo(hi)
		if err != nil {
			continue
		}

		log.Printf("[%s] Connecting to %s...", *name, hi.Name)
		if err := udp.Connect(peerKey); err != nil {
			log.Printf("[%s] Failed to connect to %s: %v", *name, hi.Name, err)
			continue
		}
		log.Printf("[%s] Connected to %s!", *name, hi.Name)

		// Send a greeting
		msg := fmt.Sprintf("Hello from %s to %s!", *name, hi.Name)
		if err := udp.WriteTo(peerKey, []byte(msg)); err != nil {
			log.Printf("[%s] Failed to send to %s: %v", *name, hi.Name, err)
		} else {
			log.Printf("[%s] Sent message to %s", *name, hi.Name)
		}
	}

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Printf("[%s] Shutting down...", *name)
}

func receiveLoop(udp *znet.UDP, name string, peerNames map[noise.PublicKey]string) {
	buf := make([]byte, 65535)
	for {
		pk, n, err := udp.ReadFrom(buf)
		if err != nil {
			if err == znet.ErrClosed {
				return
			}
			continue
		}

		peerName := peerNames[pk]
		if peerName == "" {
			peerName = fmt.Sprintf("%x", pk[:8])
		}

		data := string(buf[:n])
		log.Printf("[%s] Received from %s: %q", name, peerName, data)

		// Send ACK
		ack := fmt.Sprintf("ACK from %s: %s", name, data)
		if err := udp.WriteTo(pk, []byte(ack)); err != nil {
			log.Printf("[%s] Failed to send ACK to %s: %v", name, peerName, err)
		}
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

func buildPeerNameMap(hosts []HostInfo) map[noise.PublicKey]string {
	m := make(map[noise.PublicKey]string)
	for _, hi := range hosts {
		pk, err := getPublicKeyFromInfo(hi)
		if err != nil {
			continue
		}
		m[pk] = hi.Name
	}
	return m
}
