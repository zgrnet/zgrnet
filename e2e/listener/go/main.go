// Node.Listen interop test binary (Go).
//
// Tests proto-specific stream routing across languages.
// The "opener" sends streams with two different protos (128=chat, 200=file).
// The "accepter" uses Listen(128) for chat and AcceptStream for file.
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
	"os"
	"time"

	"github.com/vibing/zgrnet/pkg/node"
	"github.com/vibing/zgrnet/pkg/noise"
)

const (
	protoChat byte = 128
	protoFile byte = 200
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
	name       = flag.String("name", "", "Host name")
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

	var myInfo, peerInfo *HostInfo
	for i := range config.Hosts {
		if config.Hosts[i].Name == *name {
			myInfo = &config.Hosts[i]
		} else {
			peerInfo = &config.Hosts[i]
		}
	}
	if myInfo == nil || peerInfo == nil {
		log.Fatal("host or peer not found")
	}

	kp := keyFromHex(myInfo.PrivateKey)
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

	peerKP := keyFromHex(peerInfo.PrivateKey)
	n.AddPeer(node.PeerConfig{
		PublicKey: peerKP.Public,
		Endpoint:  fmt.Sprintf("127.0.0.1:%d", peerInfo.Port),
	})

	if myInfo.Role == "opener" {
		time.Sleep(2 * time.Second)
		runOpener(n, peerKP.Public, config.Test)
	} else {
		runAccepter(n, peerKP.Public, config.Test)
	}

	log.Printf("[%s] test completed successfully!", *name)
}

func runOpener(n *node.Node, peerPK noise.PublicKey, test TestConfig) {
	log.Printf("[opener] connecting...")
	if err := n.Connect(peerPK); err != nil {
		log.Fatalf("[opener] connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Send chat stream (proto=128).
	chatStream, err := n.OpenStream(peerPK, protoChat, []byte("chat-meta"))
	if err != nil {
		log.Fatalf("[opener] open chat stream: %v", err)
	}
	defer chatStream.Close()

	// Send file stream (proto=200).
	fileStream, err := n.OpenStream(peerPK, protoFile, []byte("file-meta"))
	if err != nil {
		log.Fatalf("[opener] open file stream: %v", err)
	}
	defer fileStream.Close()

	// Echo test on chat.
	chatStream.Write([]byte(test.EchoMessage))
	log.Printf("[opener] sent chat: %q", test.EchoMessage)

	buf := make([]byte, 1024)
	nr := readTimeout(chatStream, buf, 10*time.Second)
	if nr == 0 {
		log.Fatal("[opener] chat read timeout")
	}
	expected := "chat-echo: " + test.EchoMessage
	if string(buf[:nr]) != expected {
		log.Fatalf("[opener] chat got %q, want %q", buf[:nr], expected)
	}
	log.Printf("[opener] PASS: chat echo verified")

	// Echo test on file.
	fileStream.Write([]byte("file-data"))
	log.Printf("[opener] sent file: %q", "file-data")

	nr = readTimeout(fileStream, buf, 10*time.Second)
	if nr == 0 {
		log.Fatal("[opener] file read timeout")
	}
	if string(buf[:nr]) != "file-echo: file-data" {
		log.Fatalf("[opener] file got %q, want %q", buf[:nr], "file-echo: file-data")
	}
	log.Printf("[opener] PASS: file echo verified")

	time.Sleep(500 * time.Millisecond)
}

func runAccepter(n *node.Node, peerPK noise.PublicKey, test TestConfig) {
	// Register listener for proto=128 (chat).
	chatLn, err := n.Listen(protoChat)
	if err != nil {
		log.Fatalf("[accepter] Listen(chat): %v", err)
	}
	defer chatLn.Close()
	log.Printf("[accepter] listening on proto=%d (chat)", protoChat)

	// Accept chat via Listen.
	chatDone := make(chan struct{})
	go func() {
		defer close(chatDone)
		stream, err := chatLn.Accept()
		if err != nil {
			log.Fatalf("[accepter] chatLn.Accept: %v", err)
		}
		defer stream.Close()

		if stream.Proto() != protoChat {
			log.Fatalf("[accepter] chat proto=%d, want %d", stream.Proto(), protoChat)
		}
		log.Printf("[accepter] accepted chat stream (proto=%d)", stream.Proto())

		buf := make([]byte, 1024)
		nr := readTimeout(stream, buf, 10*time.Second)
		if nr == 0 {
			log.Fatal("[accepter] chat read timeout")
		}
		log.Printf("[accepter] chat received: %q", buf[:nr])

		reply := "chat-echo: " + string(buf[:nr])
		stream.Write([]byte(reply))
		log.Printf("[accepter] chat sent: %q", reply)
		time.Sleep(200 * time.Millisecond)
	}()

	// Accept file via AcceptStream (no listener registered for proto=200).
	fileDone := make(chan struct{})
	go func() {
		defer close(fileDone)
		stream, err := n.AcceptStream()
		if err != nil {
			log.Fatalf("[accepter] AcceptStream: %v", err)
		}
		defer stream.Close()

		if stream.Proto() != protoFile {
			log.Fatalf("[accepter] file proto=%d, want %d", stream.Proto(), protoFile)
		}
		log.Printf("[accepter] accepted file stream (proto=%d)", stream.Proto())

		buf := make([]byte, 1024)
		nr := readTimeout(stream, buf, 10*time.Second)
		if nr == 0 {
			log.Fatal("[accepter] file read timeout")
		}
		log.Printf("[accepter] file received: %q", buf[:nr])

		reply := "file-echo: " + string(buf[:nr])
		stream.Write([]byte(reply))
		log.Printf("[accepter] file sent: %q", reply)
		time.Sleep(200 * time.Millisecond)
	}()

	<-chatDone
	<-fileDone
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
