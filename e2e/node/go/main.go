// Node SDK interoperability test between Go, Rust, and Zig.
//
// Each binary creates a Node, adds the peer, and based on role either
// opens a stream (opener) or accepts one (accepter). Validates echo
// round-trip and stream metadata.
//
// Usage:
//
//	go run . --name go --config ../config.json
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

	"github.com/vibing/zgrnet/pkg/node"
	"github.com/vibing/zgrnet/pkg/noise"
)

type Config struct {
	Hosts []HostInfo `json:"hosts"`
	Test  TestConfig `json:"test"`
}

type HostInfo struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	Port       int    `json:"port"`
	Role       string `json:"role"`
}

type TestConfig struct {
	EchoMessage string `json:"echo_message"`
}

var (
	name       = flag.String("name", "", "Host name (go, rust, or zig)")
	configPath = flag.String("config", "", "Path to config.json")
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if *name == "" || *configPath == "" {
		log.Fatal("Usage: --name <name> --config <path>")
	}

	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		log.Fatalf("parse config: %v", err)
	}

	// Find our host.
	var myInfo *HostInfo
	for i := range config.Hosts {
		if config.Hosts[i].Name == *name {
			myInfo = &config.Hosts[i]
			break
		}
	}
	if myInfo == nil {
		log.Fatalf("host %q not in config", *name)
	}

	// Create keypair.
	kp := keyFromHex(myInfo.PrivateKey)
	log.Printf("[%s] pubkey: %x", *name, kp.Public[:8])
	log.Printf("[%s] role: %s", *name, myInfo.Role)

	// Create Node.
	n, err := node.New(node.Config{
		PrivateKey:   kp,
		ListenPort:   myInfo.Port,
		AllowUnknown: true,
	})
	if err != nil {
		log.Fatalf("create node: %v", err)
	}
	defer n.Stop()
	log.Printf("[%s] listening on %s", *name, n.LocalAddr())

	// Find peer (first host that is not us).
	var peerInfo *HostInfo
	for i := range config.Hosts {
		if config.Hosts[i].Name != *name {
			peerInfo = &config.Hosts[i]
			break
		}
	}
	if peerInfo == nil {
		log.Fatal("no peer in config")
	}

	peerKP := keyFromHex(peerInfo.PrivateKey)
	peerEndpoint := fmt.Sprintf("127.0.0.1:%d", peerInfo.Port)

	n.AddPeer(node.PeerConfig{
		PublicKey: peerKP.Public,
		Endpoint:  peerEndpoint,
	})
	log.Printf("[%s] added peer %s at %s", *name, peerInfo.Name, peerEndpoint)

	if myInfo.Role == "opener" {
		// Wait for peer to start.
		time.Sleep(2 * time.Second)
		runOpener(n, peerKP.Public, peerInfo.Name, config.Test)
	} else {
		runAccepter(n, peerKP.Public, peerInfo.Name, config.Test)
	}

	log.Printf("[%s] test completed successfully!", *name)
}

func runOpener(n *node.Node, peerPK noise.PublicKey, peerName string, test TestConfig) {
	log.Printf("[opener] connecting to %s...", peerName)
	if err := n.Connect(peerPK); err != nil {
		log.Fatalf("[opener] connect: %v", err)
	}
	log.Printf("[opener] connected!")
	time.Sleep(100 * time.Millisecond)

	// Open stream via Dial.
	log.Printf("[opener] dialing %s service=%d...", peerName, noise.ServiceProxy)
	stream, err := n.Dial(peerPK, noise.ServiceProxy)
	if err != nil {
		log.Fatalf("[opener] dial: %v", err)
	}
	defer stream.Close()

	rpk := stream.RemotePubkey()
	log.Printf("[opener] stream opened: service=%d, remotePK=%x",
		stream.Service(), rpk[:8])

	// Echo test.
	msg := []byte(test.EchoMessage)
	if _, err := stream.Write(msg); err != nil {
		log.Fatalf("[opener] write: %v", err)
	}
	log.Printf("[opener] sent: %q", test.EchoMessage)

	buf := make([]byte, 1024)
	nr := readTimeout(stream, buf, 10*time.Second)
	if nr == 0 {
		log.Fatal("[opener] FAIL: read timeout")
	}
	log.Printf("[opener] received: %q", buf[:nr])

	// Verify echo.
	expected := "Echo from " + peerName + ": " + test.EchoMessage
	if string(buf[:nr]) != expected {
		log.Fatalf("[opener] FAIL: got %q, want %q", buf[:nr], expected)
	}
	log.Printf("[opener] PASS: echo verified")

	time.Sleep(500 * time.Millisecond)
}

func runAccepter(n *node.Node, peerPK noise.PublicKey, peerName string, test TestConfig) {
	log.Printf("[accepter] waiting for stream from %s...", peerName)

	stream, err := n.AcceptStream()
	if err != nil {
		log.Fatalf("[accepter] accept: %v", err)
	}
	defer stream.Close()

	arpk := stream.RemotePubkey()
	log.Printf("[accepter] accepted stream: service=%d, remotePK=%x",
		stream.Service(), arpk[:8])

	// Read echo.
	buf := make([]byte, 1024)
	nr := readTimeout(stream, buf, 10*time.Second)
	if nr == 0 {
		log.Fatal("[accepter] FAIL: read timeout")
	}
	log.Printf("[accepter] received: %q", buf[:nr])

	// Echo back with prefix.
	reply := fmt.Sprintf("Echo from %s: %s", *name, buf[:nr])
	if _, err := stream.Write([]byte(reply)); err != nil {
		log.Fatalf("[accepter] write: %v", err)
	}
	log.Printf("[accepter] sent: %q", reply)

	time.Sleep(500 * time.Millisecond)
}

func readTimeout(s *node.Stream, buf []byte, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, err := s.Read(buf)
		if err != nil && err != io.EOF {
			return 0
		}
		if n > 0 {
			return n
		}
		time.Sleep(time.Millisecond)
	}
	return 0
}

func keyFromHex(hexStr string) *noise.KeyPair {
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != 32 {
		log.Fatalf("invalid key hex: %s", hexStr)
	}
	var key noise.Key
	copy(key[:], b)
	kp, err := noise.NewKeyPair(key)
	if err != nil {
		log.Fatalf("keypair: %v", err)
	}
	return kp
}

func localAddr(n *node.Node) *net.UDPAddr {
	return n.LocalAddr().(*net.UDPAddr)
}
