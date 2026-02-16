// Node ↔ Host integration test.
//
// Creates one Host (with TUN, needs root) and one Node (no TUN),
// verifies that the Node can Dial the Host, exchange data over a
// KCP stream, and that the Host can AcceptStream from the Node.
//
// Usage:
//
//	bazel build //examples/node_host_test/go:run
//	sudo bazel-bin/examples/node_host_test/go/run_/run
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"io"

	"github.com/vibing/zgrnet/pkg/host"
	znet "github.com/vibing/zgrnet/pkg/net"
	"github.com/vibing/zgrnet/pkg/node"
	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/tun"
)

func main() {
	fmt.Println("=== Node ↔ Host Integration Test ===")
	fmt.Println()

	if os.Getuid() != 0 {
		fmt.Println("ERROR: This test requires root privileges (TUN device).")
		fmt.Println("  sudo bazel-bin/examples/node_host_test/go/run_/run")
		os.Exit(1)
	}

	passed := 0
	failed := 0
	total := 4

	// ── Setup ──────────────────────────────────────────────────────────

	// Generate keypairs.
	hostKey, err := noise.GenerateKeyPair()
	must(err, "generate host key")
	nodeKey, err := noise.GenerateKeyPair()
	must(err, "generate node key")
	fmt.Printf("Host pubkey: %s\n", hostKey.Public.ShortString())
	fmt.Printf("Node pubkey: %s\n", nodeKey.Public.ShortString())
	fmt.Println()

	// ── 1. Create Host with TUN ────────────────────────────────────────

	fmt.Println("[1/6] Creating Host with TUN device...")
	tunDev, err := tun.Create("")
	must(err, "create TUN")
	defer tunDev.Close()

	must(tunDev.SetMTU(1400), "set TUN MTU")
	must(tunDev.SetIPv4(net.IPv4(100, 64, 0, 1), net.CIDRMask(24, 32)), "set TUN IPv4")
	must(tunDev.Up(), "bring TUN up")
	fmt.Printf("  TUN: %s (100.64.0.1/24)\n", tunDev.Name())

	h, err := host.New(host.Config{
		PrivateKey: hostKey,
		TunIPv4:    net.IPv4(100, 64, 0, 1),
		MTU:        1400,
	}, tunDev)
	must(err, "create Host")
	defer h.Close()

	hostPort := h.LocalAddr().(*net.UDPAddr).Port
	fmt.Printf("  Host UDP: 127.0.0.1:%d\n", hostPort)
	fmt.Println()

	// ── 2. Create Node (no TUN) ────────────────────────────────────────

	fmt.Println("[2/6] Creating Node (no TUN)...")
	n, err := node.New(node.Config{
		PrivateKey:   nodeKey,
		ListenPort:   0,
		AllowUnknown: true,
	})
	must(err, "create Node")
	defer n.Stop()

	fmt.Printf("  Node UDP: %s\n", n.LocalAddr())
	fmt.Println()

	// ── 3. Register peers ──────────────────────────────────────────────

	fmt.Println("[3/6] Registering peers...")
	// Node knows about Host.
	err = n.AddPeer(node.PeerConfig{
		PublicKey: hostKey.Public,
		Endpoint:  fmt.Sprintf("127.0.0.1:%d", hostPort),
	})
	must(err, "Node.AddPeer(Host)")

	// Host knows about Node.
	nodePort := n.LocalAddr().(*net.UDPAddr).Port
	err = h.AddPeer(nodeKey.Public, fmt.Sprintf("127.0.0.1:%d", nodePort))
	must(err, "Host.AddPeer(Node)")
	fmt.Println("  OK")
	fmt.Println()

	// ── 4. Start Host forwarding ───────────────────────────────────────

	fmt.Println("[4/6] Starting Host forwarding loop...")
	go func() {
		if err := h.Run(); err != nil {
			fmt.Printf("  Host.Run error: %v\n", err)
		}
	}()
	fmt.Println("  OK")
	fmt.Println()

	// Start a receive loop on Host's UDP to drive handshakes.
	udpTransport := h.UDP()
	go func() {
		buf := make([]byte, 65535)
		for {
			_, _, err := udpTransport.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	// ── 5. Node connects to Host ───────────────────────────────────────

	fmt.Println("[5/6] Node connecting to Host (Noise IK handshake)...")
	if err := n.Connect(hostKey.Public); err != nil {
		fatal("handshake: %v", err)
	}
	fmt.Println("  Handshake complete!")
	fmt.Println()

	// Wait for mux initialization.
	time.Sleep(100 * time.Millisecond)

	// ── 6. Run tests ───────────────────────────────────────────────────

	fmt.Println("[6/6] Running tests...")
	fmt.Println()

	// Start accepting streams on Host side.
	hostStreams := make(chan *znet.Stream, 4)
	go func() {
		for {
			s, err := udpTransport.AcceptStream(nodeKey.Public)
			if err != nil {
				return
			}
			hostStreams <- s
		}
	}()

	// Test 1: Node.Dial → Host.AcceptStream
	{
		fmt.Println("--- Test 1: Node.Dial → Host.AcceptStream ---")
		stream, err := n.Dial(hostKey.Public, 8080)
		if err != nil {
			fmt.Printf("  FAIL: Dial: %v\n", err)
			failed++
		} else {
			select {
			case hs := <-hostStreams:
				if hs.Proto() == noise.ProtocolTCPProxy {
					fmt.Println("  Host accepted stream: proto=TCP_PROXY ✓")
					passed++
				} else {
					fmt.Printf("  FAIL: expected proto=%d, got %d\n", noise.ProtocolTCPProxy, hs.Proto())
					failed++
				}
				hs.Close()
			case <-time.After(5 * time.Second):
				fmt.Println("  FAIL: timeout waiting for Host.AcceptStream")
				failed++
			}
			stream.Close()
		}
	}

	// Test 2: Echo over KCP stream
	{
		fmt.Println("--- Test 2: Echo over KCP stream ---")
		stream, err := n.Dial(hostKey.Public, 9090)
		if err != nil {
			fmt.Printf("  FAIL: Dial: %v\n", err)
			failed++
		} else {
			var hs *znet.Stream
			select {
			case hs = <-hostStreams:
			case <-time.After(5 * time.Second):
				fmt.Println("  FAIL: timeout accepting")
				failed++
				goto test3
			}

			// Node writes, Host reads.
			msg := []byte("hello from Node!")
			stream.Write(msg)

			buf := make([]byte, 256)
			n2 := readTimeout(hs, buf, 5*time.Second)
			if n2 > 0 && string(buf[:n2]) == string(msg) {
				fmt.Printf("  Host received: %q ✓\n", buf[:n2])

				// Host echoes back.
				reply := []byte("echo: " + string(buf[:n2]))
				hs.Write(reply)

				n3 := readTimeout(stream, buf, 5*time.Second)
				if n3 > 0 && string(buf[:n3]) == string(reply) {
					fmt.Printf("  Node received: %q ✓\n", buf[:n3])
					passed++
				} else {
					fmt.Printf("  FAIL: Node received %q\n", buf[:n3])
					failed++
				}
			} else {
				fmt.Printf("  FAIL: Host received %d bytes\n", n2)
				failed++
			}
			hs.Close()
			stream.Close()
		}
	}

test3:
	// Test 3: Stream metadata (Address encoding)
	{
		fmt.Println("--- Test 3: Stream metadata (Address) ---")
		stream, err := n.Dial(hostKey.Public, 4321)
		if err != nil {
			fmt.Printf("  FAIL: Dial: %v\n", err)
			failed++
		} else {
			select {
			case hs := <-hostStreams:
				addr, _, err := noise.DecodeAddress(hs.Metadata())
				if err == nil && addr.Host == "127.0.0.1" && addr.Port == 4321 {
					fmt.Printf("  Address decoded: %s:%d ✓\n", addr.Host, addr.Port)
					passed++
				} else {
					fmt.Printf("  FAIL: decode address: err=%v host=%s port=%d\n", err, addr.Host, addr.Port)
					failed++
				}
				hs.Close()
			case <-time.After(5 * time.Second):
				fmt.Println("  FAIL: timeout")
				failed++
			}
			stream.Close()
		}
	}

	// Test 4: RemotePubkey on Node stream
	{
		fmt.Println("--- Test 4: RemotePubkey ---")
		stream, err := n.Dial(hostKey.Public, 5555)
		if err != nil {
			fmt.Printf("  FAIL: Dial: %v\n", err)
			failed++
		} else {
			if stream.RemotePubkey() == hostKey.Public {
				fmt.Println("  RemotePubkey matches Host ✓")
				passed++
			} else {
				fmt.Println("  FAIL: RemotePubkey mismatch")
				failed++
			}
			stream.Close()
			// Drain host side.
			select {
			case hs := <-hostStreams:
				hs.Close()
			case <-time.After(time.Second):
			}
		}
	}

	// ── Summary ────────────────────────────────────────────────────────

	fmt.Println()
	fmt.Println("=== Results ===")
	fmt.Printf("  Passed: %d/%d\n", passed, total)
	fmt.Printf("  Failed: %d/%d\n", failed, total)
	fmt.Println()

	if failed > 0 {
		fmt.Println("SOME TESTS FAILED")
		os.Exit(1)
	}
	fmt.Println("All tests passed!")
	os.Exit(0)
}

// reader is any type with a Read([]byte) (int, error) method (kcp.Stream, node.Stream).
type reader interface {
	Read([]byte) (int, error)
}

func readTimeout(s reader, buf []byte, timeout time.Duration) int {
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

func must(err error, msg string) {
	if err != nil {
		fatal("%s: %v", msg, err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}
