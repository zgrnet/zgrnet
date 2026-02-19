package node

import (
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// genKey generates a deterministic keypair from a seed byte.
func genKey(t *testing.T, seed byte) *noise.KeyPair {
	t.Helper()
	var key noise.Key
	key[0] = seed
	kp, err := noise.NewKeyPair(key)
	if err != nil {
		t.Fatalf("NewKeyPair(%d): %v", seed, err)
	}
	return kp
}

// genRandomKey generates a random keypair.
func genRandomKey(t *testing.T) *noise.KeyPair {
	t.Helper()
	var key noise.Key
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		t.Fatal(err)
	}
	kp, err := noise.NewKeyPair(key)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestNewAndStop(t *testing.T) {
	kp := genRandomKey(t)
	n, err := New(Config{PrivateKey: kp, ListenPort: 0})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.Stop()

	if n.State() != StateRunning {
		t.Errorf("state = %v, want Running", n.State())
	}
	if n.PublicKey() != kp.Public {
		t.Errorf("PublicKey mismatch")
	}
	if n.LocalAddr() == nil {
		t.Error("LocalAddr is nil")
	}

	n.Stop()
	if n.State() != StateStopped {
		t.Errorf("state after Stop = %v, want Stopped", n.State())
	}
}

func TestNilPrivateKey(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("expected error for nil PrivateKey")
	}
}

func TestDoubleStop(t *testing.T) {
	kp := genRandomKey(t)
	n, err := New(Config{PrivateKey: kp})
	if err != nil {
		t.Fatal(err)
	}
	n.Stop()
	n.Stop() // should not panic
}

func TestAddPeerAndPeers(t *testing.T) {
	kp1 := genKey(t, 1)
	kp2 := genKey(t, 2)

	n, err := New(Config{PrivateKey: kp1, ListenPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Stop()

	if err := n.AddPeer(PeerConfig{PublicKey: kp2.Public, Endpoint: "127.0.0.1:19999"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	peers := n.Peers()
	if len(peers) != 1 {
		t.Fatalf("Peers len = %d, want 1", len(peers))
	}
	if peers[0].PublicKey != kp2.Public {
		t.Error("peer public key mismatch")
	}
}

func TestRemovePeer(t *testing.T) {
	kp1 := genKey(t, 1)
	kp2 := genKey(t, 2)

	n, err := New(Config{PrivateKey: kp1, ListenPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Stop()

	n.AddPeer(PeerConfig{PublicKey: kp2.Public, Endpoint: "127.0.0.1:19999"})
	n.RemovePeer(kp2.Public)

	peers := n.Peers()
	if len(peers) != 0 {
		t.Fatalf("Peers len = %d after remove, want 0", len(peers))
	}
}

func TestTwoNodesEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	kp1 := genKey(t, 1)
	kp2 := genKey(t, 2)

	// Create two nodes.
	n1, err := New(Config{PrivateKey: kp1, ListenPort: 0, AllowUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	defer n1.Stop()

	n2, err := New(Config{PrivateKey: kp2, ListenPort: 0, AllowUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	defer n2.Stop()

	// Add each other as peers.
	n1.AddPeer(PeerConfig{PublicKey: kp2.Public, Endpoint: n2.LocalAddr().String()})
	n2.AddPeer(PeerConfig{PublicKey: kp1.Public, Endpoint: n1.LocalAddr().String()})

	// n1 connects to n2.
	if err := n1.Connect(kp2.Public); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// Wait for mux initialization.
	time.Sleep(50 * time.Millisecond)

	// n1 dials n2.
	stream, err := n1.Dial(kp2.Public, 8080)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer stream.Close()

	// Verify stream metadata.
	if stream.Proto() != noise.ProtocolTCPProxy {
		t.Errorf("Proto = %d, want %d", stream.Proto(), noise.ProtocolTCPProxy)
	}
	if stream.RemotePubkey() != kp2.Public {
		t.Error("RemotePubkey mismatch on dialer side")
	}

	// n2 accepts the stream.
	accepted, err := n2.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	defer accepted.Close()

	if accepted.Proto() != noise.ProtocolTCPProxy {
		t.Errorf("accepted Proto = %d, want %d", accepted.Proto(), noise.ProtocolTCPProxy)
	}
	if accepted.RemotePubkey() != kp1.Public {
		t.Error("RemotePubkey mismatch on accepter side")
	}

	// Echo test: n1 writes, n2 reads and echoes back.
	msg := []byte("hello from node1")
	if _, err := stream.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, 256)
	n, readErr := readTimeout(accepted, buf, 5*time.Second)
	if readErr != nil {
		t.Fatalf("Read: %v", readErr)
	}
	if string(buf[:n]) != string(msg) {
		t.Errorf("got %q, want %q", buf[:n], msg)
	}

	// Echo back.
	reply := []byte("echo: " + string(buf[:n]))
	if _, err := accepted.Write(reply); err != nil {
		t.Fatalf("Write reply: %v", err)
	}

	n, readErr = readTimeout(stream, buf, 5*time.Second)
	if readErr != nil {
		t.Fatalf("Read reply: %v", readErr)
	}
	if string(buf[:n]) != string(reply) {
		t.Errorf("reply got %q, want %q", buf[:n], reply)
	}
}

func TestTwoNodesMultipleStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	kp1 := genKey(t, 10)
	kp2 := genKey(t, 20)

	n1, err := New(Config{PrivateKey: kp1, ListenPort: 0, AllowUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	defer n1.Stop()

	n2, err := New(Config{PrivateKey: kp2, ListenPort: 0, AllowUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	defer n2.Stop()

	n1.AddPeer(PeerConfig{PublicKey: kp2.Public, Endpoint: n2.LocalAddr().String()})
	n2.AddPeer(PeerConfig{PublicKey: kp1.Public, Endpoint: n1.LocalAddr().String()})

	if err := n1.Connect(kp2.Public); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	const numStreams = 5

	// Accept goroutine: collect accepted streams.
	accepted := make(chan *Stream, numStreams)
	go func() {
		for i := 0; i < numStreams; i++ {
			s, err := n2.AcceptStream()
			if err != nil {
				t.Errorf("AcceptStream %d: %v", i, err)
				return
			}
			accepted <- s
		}
	}()

	// Open multiple streams from n1 → n2.
	var opened []*Stream
	for i := 0; i < numStreams; i++ {
		s, err := n1.Dial(kp2.Public, uint16(8080+i))
		if err != nil {
			t.Fatalf("Dial stream %d: %v", i, err)
		}
		opened = append(opened, s)
	}

	// Verify all streams were accepted.
	for i := 0; i < numStreams; i++ {
		select {
		case s := <-accepted:
			if s.Proto() != noise.ProtocolTCPProxy {
				t.Errorf("stream %d: proto = %d, want %d", i, s.Proto(), noise.ProtocolTCPProxy)
			}
			if s.RemotePubkey() != kp1.Public {
				t.Errorf("stream %d: RemotePubkey mismatch", i)
			}
			t.Logf("accepted stream %d: proto=%d, metadata=%x", i, s.Proto(), s.Metadata())
			s.Close()
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for stream %d", i)
		}
	}

	// Clean up opened streams.
	for _, s := range opened {
		s.Close()
	}
}

func TestOperationsOnStoppedNode(t *testing.T) {
	kp := genRandomKey(t)
	n, err := New(Config{PrivateKey: kp})
	if err != nil {
		t.Fatal(err)
	}
	n.Stop()

	if err := n.AddPeer(PeerConfig{PublicKey: noise.PublicKey{}}); err != ErrNotRunning {
		t.Errorf("AddPeer on stopped: err = %v, want ErrNotRunning", err)
	}
	if err := n.Connect(noise.PublicKey{}); err != ErrNotRunning {
		t.Errorf("Connect on stopped: err = %v, want ErrNotRunning", err)
	}
	if _, err := n.Dial(noise.PublicKey{}, 80); err != ErrNotRunning {
		t.Errorf("Dial on stopped: err = %v, want ErrNotRunning", err)
	}
	if err := n.WriteTo(nil, 0, noise.PublicKey{}); err != ErrNotRunning {
		t.Errorf("WriteTo on stopped: err = %v, want ErrNotRunning", err)
	}
}

// TestDialRelayThreeNodes tests A → C (relay) → D with KCP stream echo.
// A and D have no direct connection. C is the relay that forwards traffic.
func TestDialRelayThreeNodes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	kpA := genKey(t, 0xA0)
	kpC := genKey(t, 0xC0)
	kpD := genKey(t, 0xD0)

	// Create 3 nodes. C allows unknown peers so it can accept relayed
	// handshakes for A from D.
	nodeA, err := New(Config{PrivateKey: kpA, ListenPort: 0, AllowUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Stop()

	nodeC, err := New(Config{PrivateKey: kpC, ListenPort: 0, AllowUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	defer nodeC.Stop()

	nodeD, err := New(Config{PrivateKey: kpD, ListenPort: 0, AllowUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	defer nodeD.Stop()

	// Set up direct connections: A↔C, C↔D
	nodeA.AddPeer(PeerConfig{PublicKey: kpC.Public, Endpoint: nodeC.LocalAddr().String()})
	nodeC.AddPeer(PeerConfig{PublicKey: kpA.Public, Endpoint: nodeA.LocalAddr().String()})

	nodeC.AddPeer(PeerConfig{PublicKey: kpD.Public, Endpoint: nodeD.LocalAddr().String()})
	nodeD.AddPeer(PeerConfig{PublicKey: kpC.Public, Endpoint: nodeC.LocalAddr().String()})

	// Establish A↔C session
	if err := nodeA.Connect(kpC.Public); err != nil {
		t.Fatalf("A→C Connect: %v", err)
	}
	// Establish C↔D session
	if err := nodeC.Connect(kpD.Public); err != nil {
		t.Fatalf("C→D Connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// D registers A as a relay-only peer (no endpoint) so its accept loop
	// is running when the relayed handshake completes.
	nodeD.AddPeer(PeerConfig{PublicKey: kpA.Public})

	// A dials D through relay C.
	// DialRelay adds route D → C, registers D as peer, then does handshake through relay.
	stream, err := nodeA.DialRelay(kpD.Public, kpC.Public, 8080)
	if err != nil {
		t.Fatalf("DialRelay: %v", err)
	}
	defer stream.Close()

	t.Logf("A opened stream to D through relay C: proto=%d", stream.Proto())

	// D should accept the stream from A.
	accepted, err := nodeD.AcceptStream()
	if err != nil {
		t.Fatalf("D AcceptStream: %v", err)
	}
	defer accepted.Close()

	rpk := accepted.RemotePubkey()
	if rpk != kpA.Public {
		t.Errorf("D accepted from wrong peer: got %x, want %x", rpk[:4], kpA.Public[:4])
	}
	t.Logf("D accepted stream from A: proto=%d", accepted.Proto())

	// Echo test: A writes, D reads and echoes back.
	msg := []byte("hello through relay!")
	if _, err := stream.Write(msg); err != nil {
		t.Fatalf("A Write: %v", err)
	}

	buf := make([]byte, 256)
	n, readErr := readTimeout(accepted, buf, 5*time.Second)
	if readErr != nil {
		t.Fatalf("D Read: %v", readErr)
	}
	if string(buf[:n]) != string(msg) {
		t.Errorf("D got %q, want %q", buf[:n], msg)
	}
	t.Logf("D received: %q", buf[:n])

	// D echoes back.
	reply := []byte("echo: " + string(buf[:n]))
	if _, err := accepted.Write(reply); err != nil {
		t.Fatalf("D Write: %v", err)
	}

	n, readErr = readTimeout(stream, buf, 5*time.Second)
	if readErr != nil {
		t.Fatalf("A Read reply: %v", readErr)
	}
	if string(buf[:n]) != string(reply) {
		t.Errorf("A got %q, want %q", buf[:n], reply)
	}
	t.Logf("A received reply: %q", buf[:n])
}

// TestListenProtoRouting verifies that Listen(proto) receives only matching
// streams while unmatched protos fall through to AcceptStream.
func TestListenProtoRouting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	kp1 := genKey(t, 0x30)
	kp2 := genKey(t, 0x40)

	n1, err := New(Config{PrivateKey: kp1, ListenPort: 0, AllowUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	defer n1.Stop()

	n2, err := New(Config{PrivateKey: kp2, ListenPort: 0, AllowUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	defer n2.Stop()

	n1.AddPeer(PeerConfig{PublicKey: kp2.Public, Endpoint: n2.LocalAddr().String()})
	n2.AddPeer(PeerConfig{PublicKey: kp1.Public, Endpoint: n1.LocalAddr().String()})

	if err := n1.Connect(kp2.Public); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	const protoChat byte = 128
	const protoFile byte = 200

	// n2 registers a listener for proto=128 (chat).
	chatLn, err := n2.Listen(protoChat)
	if err != nil {
		t.Fatalf("Listen(128): %v", err)
	}
	defer chatLn.Close()

	// Duplicate registration must fail.
	if _, err := n2.Listen(protoChat); err != ErrProtoRegistered {
		t.Fatalf("duplicate Listen: err = %v, want ErrProtoRegistered", err)
	}

	// n1 opens two streams: one with proto=128 (chat), one with proto=200 (file).
	chatStream, err := n1.OpenStream(kp2.Public, protoChat, []byte("chat-meta"))
	if err != nil {
		t.Fatalf("OpenStream(chat): %v", err)
	}
	defer chatStream.Close()

	fileStream, err := n1.OpenStream(kp2.Public, protoFile, []byte("file-meta"))
	if err != nil {
		t.Fatalf("OpenStream(file): %v", err)
	}
	defer fileStream.Close()

	// proto=128 should arrive at chatLn.Accept(), not AcceptStream().
	done := make(chan *Stream, 1)
	go func() {
		s, err := chatLn.Accept()
		if err != nil {
			t.Errorf("chatLn.Accept: %v", err)
			return
		}
		done <- s
	}()

	select {
	case s := <-done:
		if s.Proto() != protoChat {
			t.Errorf("chatLn got proto %d, want %d", s.Proto(), protoChat)
		}
		if s.RemotePubkey() != kp1.Public {
			t.Error("chatLn: RemotePubkey mismatch")
		}
		// Echo test.
		chatStream.Write([]byte("hello chat"))
		buf := make([]byte, 256)
		nr, err := readTimeout(s, buf, 5*time.Second)
		if err != nil {
			t.Fatalf("chatLn read: %v", err)
		}
		if string(buf[:nr]) != "hello chat" {
			t.Errorf("chatLn got %q, want %q", buf[:nr], "hello chat")
		}
		s.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for chatLn.Accept")
	}

	// proto=200 should arrive at AcceptStream() (no listener registered).
	accepted, err := n2.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	defer accepted.Close()
	if accepted.Proto() != protoFile {
		t.Errorf("AcceptStream got proto %d, want %d", accepted.Proto(), protoFile)
	}
}

// TestListenClose verifies that closing a StreamListener unregisters it,
// so subsequent streams fall through to AcceptStream.
func TestListenClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	kp1 := genKey(t, 0x50)
	kp2 := genKey(t, 0x60)

	n1, err := New(Config{PrivateKey: kp1, ListenPort: 0, AllowUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	defer n1.Stop()

	n2, err := New(Config{PrivateKey: kp2, ListenPort: 0, AllowUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	defer n2.Stop()

	n1.AddPeer(PeerConfig{PublicKey: kp2.Public, Endpoint: n2.LocalAddr().String()})
	n2.AddPeer(PeerConfig{PublicKey: kp1.Public, Endpoint: n1.LocalAddr().String()})

	if err := n1.Connect(kp2.Public); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	const proto byte = 150

	ln, err := n2.Listen(proto)
	if err != nil {
		t.Fatal(err)
	}

	// Close the listener — should unregister.
	ln.Close()

	// Now same proto should re-register successfully.
	ln2, err := n2.Listen(proto)
	if err != nil {
		t.Fatalf("re-Listen after close: %v", err)
	}
	defer ln2.Close()

	// Open a stream — should go to ln2.
	s1, err := n1.OpenStream(kp2.Public, proto, nil)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer s1.Close()

	accepted, err := ln2.Accept()
	if err != nil {
		t.Fatalf("ln2.Accept: %v", err)
	}
	if accepted.Proto() != proto {
		t.Errorf("proto = %d, want %d", accepted.Proto(), proto)
	}
	accepted.Close()
}

// readTimeout reads from a stream with a deadline.
func readTimeout(s *Stream, buf []byte, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, err := s.Read(buf)
		if err != nil {
			return 0, err
		}
		if n > 0 {
			return n, nil
		}
		time.Sleep(time.Millisecond)
	}
	return 0, io.ErrNoProgress
}
