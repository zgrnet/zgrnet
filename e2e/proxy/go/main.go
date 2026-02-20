// Package main tests cross-language proxy interoperability.
//
// Two roles:
//   - handler: echo TCP server + TCP_PROXY(69) KCP handler
//   - proxy:   opens KCP stream(proto=69) through tunnel, verifies echo
//
// Usage:
//
//	go run . -name handler -config ../config.json
//	go run . -name proxy   -config ../config.json
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
	"time"

	znet "github.com/vibing/zgrnet/pkg/net"
	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/proxy"
)

type Config struct {
	Hosts    []HostInfo `json:"hosts"`
	EchoPort int        `json:"echo_port"`
	Test     TestConfig `json:"test"`
}

type HostInfo struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	Port       int    `json:"port"`
	Role       string `json:"role"`
}

type TestConfig struct {
	Message string `json:"message"`
}

var (
	flagName   = flag.String("name", "", "Host name from config (matches name field)")
	flagConfig = flag.String("config", "", "Path to config.json")
)

func main() {
	flag.Parse()
	if *flagName == "" || *flagConfig == "" {
		log.Fatal("Usage: proxy_test -name <name> -config <config.json>")
	}
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	config := loadConfig(*flagConfig)
	myInfo := findHost(config, *flagName)
	myKey := loadKey(myInfo.PrivateKey)

	log.Printf("[%s] role=%s port=%d", myInfo.Name, myInfo.Role, myInfo.Port)

	switch myInfo.Role {
	case "handler":
		runHandler(config, myInfo, myKey)
	case "proxy":
		runProxy(config, myInfo, myKey)
	default:
		log.Fatalf("Unknown role: %s", myInfo.Role)
	}
}

func runHandler(config *Config, myInfo *HostInfo, myKey *noise.KeyPair) {
	// 1. Start TCP echo server
	echoAddr := fmt.Sprintf("127.0.0.1:%d", config.EchoPort)
	echoLn, err := net.Listen("tcp", echoAddr)
	if err != nil {
		log.Fatalf("[handler] Echo listen failed: %v", err)
	}
	defer echoLn.Close()
	log.Printf("[handler] Echo server on %s", echoAddr)

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	// 2. Create UDP
	bindAddr := fmt.Sprintf("127.0.0.1:%d", myInfo.Port)
	udp, err := znet.NewUDP(myKey, znet.WithBindAddr(bindAddr), znet.WithAllowUnknown(true))
	if err != nil {
		log.Fatalf("[handler] UDP failed: %v", err)
	}
	defer udp.Close()
	log.Printf("[handler] UDP on %s", udp.HostInfo().Addr)

	// Background ReadFrom consumer
	go func() {
		buf := make([]byte, 65535)
		for {
			_, _, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	// 3. Find proxy peer
	peerInfo := findRole(config, "proxy")
	peerKey := loadKey(peerInfo.PrivateKey)
	udp.SetPeerEndpoint(peerKey.Public, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: peerInfo.Port})

	// 4. Wait for session, then accept stream
	log.Printf("[handler] Waiting for session from proxy...")
	for i := 0; i < 100; i++ {
		info := udp.PeerInfo(peerKey.Public)
		if info != nil && info.State == znet.PeerStateEstablished {
			log.Printf("[handler] Session established!")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	log.Printf("[handler] Waiting for TCP_PROXY stream...")
	stream, err := udp.AcceptStream(peerKey.Public)
	if err != nil {
		log.Fatalf("[handler] AcceptStream failed: %v", err)
	}
	log.Printf("[handler] Got stream id=%d proto=%d metadata=%d bytes",
		stream.ID(), stream.Proto(), len(stream.Metadata()))

	if stream.Proto() != noise.ProtocolKCP {
		log.Fatalf("[handler] Expected proto=%d, got %d", noise.ProtocolKCP, stream.Proto())
	}

	// 5. Handle TCP_PROXY: decode address → dial echo server → relay
	if err := proxy.HandleTCPProxy(stream, stream.Metadata(), nil, nil); err != nil {
		log.Printf("[handler] HandleTCPProxy finished: %v", err)
	}

	log.Println("[handler] Done!")
}

func runProxy(config *Config, myInfo *HostInfo, myKey *noise.KeyPair) {
	// 1. Create UDP
	bindAddr := fmt.Sprintf("127.0.0.1:%d", myInfo.Port)
	udp, err := znet.NewUDP(myKey, znet.WithBindAddr(bindAddr), znet.WithAllowUnknown(true))
	if err != nil {
		log.Fatalf("[proxy] UDP failed: %v", err)
	}
	defer udp.Close()
	log.Printf("[proxy] UDP on %s", udp.HostInfo().Addr)

	// Background ReadFrom consumer
	go func() {
		buf := make([]byte, 65535)
		for {
			_, _, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	// 2. Find handler peer and connect
	handlerInfo := findRole(config, "handler")
	handlerKey := loadKey(handlerInfo.PrivateKey)
	udp.SetPeerEndpoint(handlerKey.Public, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: handlerInfo.Port})

	log.Println("[proxy] Connecting to handler...")
	if err := udp.Connect(handlerKey.Public); err != nil {
		log.Fatalf("[proxy] Connect failed: %v", err)
	}
	log.Println("[proxy] Connected!")
	time.Sleep(200 * time.Millisecond) // Let mux initialize

	// 3. Open stream with proto=69 targeting the echo server
	echoAddr := &noise.Address{
		Type: noise.AddressTypeIPv4,
		Host: "127.0.0.1",
		Port: uint16(config.EchoPort),
	}
	metadata := echoAddr.Encode()
	log.Printf("[proxy] Opening stream proto=%d target=%s:%d", noise.ProtocolKCP, echoAddr.Host, echoAddr.Port)

	stream, err := udp.OpenStream(handlerKey.Public, noise.ProtocolKCP, metadata)
	if err != nil {
		log.Fatalf("[proxy] OpenStream failed: %v", err)
	}
	defer stream.Close()
	log.Printf("[proxy] Stream opened id=%d", stream.ID())

	// Wait for stream to establish + handler to accept and connect
	time.Sleep(500 * time.Millisecond)

	// 4. Send test data and verify echo
	testMsg := config.Test.Message
	log.Printf("[proxy] Sending: %q", testMsg)
	if _, err := stream.Write([]byte(testMsg)); err != nil {
		log.Fatalf("[proxy] Write failed: %v", err)
	}

	buf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		log.Fatalf("[proxy] ReadFull failed: %v", err)
	}

	if string(buf) != testMsg {
		log.Fatalf("[proxy] FAIL: echo mismatch: got %q, want %q", string(buf), testMsg)
	}

	log.Printf("[proxy] Echo verified: %q", string(buf))
	log.Println("[proxy] PASS!")
}

// --- Helpers ---

func loadConfig(path string) *Config {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}
	return &config
}

func findHost(config *Config, name string) *HostInfo {
	for i := range config.Hosts {
		if config.Hosts[i].Name == name {
			return &config.Hosts[i]
		}
	}
	log.Fatalf("Host %q not found in config", name)
	return nil
}

func findRole(config *Config, role string) *HostInfo {
	for i := range config.Hosts {
		if config.Hosts[i].Role == role {
			return &config.Hosts[i]
		}
	}
	log.Fatalf("Role %q not found in config", role)
	return nil
}

func loadKey(hexKey string) *noise.KeyPair {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		log.Fatalf("Invalid hex key: %v", err)
	}
	if len(keyBytes) != noise.KeySize {
		log.Fatalf("Key must be %d bytes, got %d", noise.KeySize, len(keyBytes))
	}
	var privKey noise.Key
	copy(privKey[:], keyBytes)
	kp, err := noise.NewKeyPair(privKey)
	if err != nil {
		log.Fatalf("NewKeyPair failed: %v", err)
	}
	return kp
}
