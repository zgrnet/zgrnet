// Host integration test with real TUN devices.
//
// Requires root/sudo to create TUN devices.
//
// Usage:
//
//	cd zig && zig build -Doptimize=ReleaseFast
//	cd go && go build -o /tmp/host_test ./examples/host_test/
//	sudo /tmp/host_test
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/vibing/zgrnet/pkg/host"
	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/tun"
)

func main() {
	fmt.Println("=== Host TUN Integration Test ===")
	fmt.Println()

	if os.Getuid() != 0 {
		fmt.Println("ERROR: This test requires root privileges.")
		fmt.Println("  sudo /tmp/host_test")
		os.Exit(1)
	}

	// Generate keypairs
	keyA, err := noise.GenerateKeyPair()
	must(err, "generate key A")
	keyB, err := noise.GenerateKeyPair()
	must(err, "generate key B")
	fmt.Printf("Host A pubkey: %s\n", keyA.Public.ShortString())
	fmt.Printf("Host B pubkey: %s\n", keyB.Public.ShortString())
	fmt.Println()

	// --- Create and configure TUN devices ---
	fmt.Println("[1/5] Creating TUN devices...")
	tunA, err := tun.Create("")
	if err != nil {
		fatal("create TUN A: %v", err)
	}
	defer tunA.Close()

	tunB, err := tun.Create("")
	if err != nil {
		fatal("create TUN B: %v", err)
	}
	defer tunB.Close()

	fmt.Printf("  TUN A: %s\n", tunA.Name())
	fmt.Printf("  TUN B: %s\n", tunB.Name())

	// Configure TUN A: 100.64.0.1/24
	must(tunA.SetMTU(1400), "set MTU A")
	must(tunA.SetIPv4(net.IPv4(100, 64, 0, 1), net.CIDRMask(24, 32)), "set IPv4 A")
	must(tunA.Up(), "up A")
	fmt.Println("  TUN A: 100.64.0.1/24 UP")

	// Configure TUN B: 100.64.1.1/24
	must(tunB.SetMTU(1400), "set MTU B")
	must(tunB.SetIPv4(net.IPv4(100, 64, 1, 1), net.CIDRMask(24, 32)), "set IPv4 B")
	must(tunB.Up(), "up B")
	fmt.Println("  TUN B: 100.64.1.1/24 UP")
	fmt.Println()

	// --- Create Hosts ---
	fmt.Println("[2/5] Creating Hosts...")
	hostA, err := host.New(host.Config{
		PrivateKey: keyA,
		TunIPv4:    net.IPv4(100, 64, 0, 1),
		MTU:        1400,
	}, tunA)
	if err != nil {
		fatal("create Host A: %v", err)
	}
	defer hostA.Close()

	hostB, err := host.New(host.Config{
		PrivateKey: keyB,
		TunIPv4:    net.IPv4(100, 64, 1, 1),
		MTU:        1400,
	}, tunB)
	if err != nil {
		fatal("create Host B: %v", err)
	}
	defer hostB.Close()

	portA := hostA.LocalAddr().(*net.UDPAddr).Port
	portB := hostB.LocalAddr().(*net.UDPAddr).Port
	fmt.Printf("  Host A: UDP :%d\n", portA)
	fmt.Printf("  Host B: UDP :%d\n", portB)

	// Add peers with static IPs
	must(hostA.AddPeerWithIP(keyB.Public, fmt.Sprintf("127.0.0.1:%d", portB), net.IPv4(100, 64, 0, 2)), "add peer B on A")
	must(hostB.AddPeerWithIP(keyA.Public, fmt.Sprintf("127.0.0.1:%d", portA), net.IPv4(100, 64, 1, 2)), "add peer A on B")

	fmt.Println("  Host A: peer B = 100.64.0.2")
	fmt.Println("  Host B: peer A = 100.64.1.2")
	fmt.Println()

	// --- Start forwarding ---
	fmt.Println("[3/5] Starting forwarding loops...")
	go hostA.Run()
	go hostB.Run()
	fmt.Println("  OK")
	fmt.Println()

	// --- Handshake ---
	fmt.Println("[4/5] Noise IK handshake (A -> B)...")
	if err := hostA.Connect(keyB.Public); err != nil {
		fatal("handshake: %v", err)
	}
	fmt.Println("  Handshake complete!")
	fmt.Println()

	// Small delay for routes to settle
	time.Sleep(200 * time.Millisecond)

	// --- Run tests ---
	fmt.Println("[5/5] Running tests...")
	fmt.Println()

	passed := 0
	failed := 0

	// Test 1: ping from A side to B (100.64.0.2)
	if runPingTest("A->B", "100.64.0.2") {
		passed++
	} else {
		failed++
	}

	// Test 2: ping from B side to A (100.64.1.2)
	if runPingTest("B->A", "100.64.1.2") {
		passed++
	} else {
		failed++
	}

	// Cleanup
	hostA.Close()
	hostB.Close()

	// Summary
	fmt.Println()
	fmt.Println("=== Results ===")
	fmt.Printf("  Passed: %d\n", passed)
	fmt.Printf("  Failed: %d\n", failed)
	fmt.Println()

	if failed > 0 {
		fmt.Println("SOME TESTS FAILED")
		os.Exit(1)
	}
	fmt.Println("All tests passed!")
	os.Exit(0)
}

// runPingTest runs `ping -c 3 -W 2 <target>` and checks if it succeeds.
func runPingTest(name, target string) bool {
	fmt.Printf("--- Test: %s (ping %s) ---\n", name, target)

	cmd := exec.Command("ping", "-c", "3", "-W", "2", target)
	output, err := cmd.CombinedOutput()
	out := string(output)

	// Print indented output
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fmt.Printf("  %s\n", line)
	}

	if err != nil {
		fmt.Printf("  RESULT: FAIL (%v)\n", err)
		return false
	}

	// Check for "0.0% packet loss" or "0% packet loss"
	if strings.Contains(out, "0.0% packet loss") || strings.Contains(out, " 0% packet loss") {
		fmt.Println("  RESULT: PASS")
		return true
	}

	fmt.Println("  RESULT: FAIL (packet loss)")
	return false
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
