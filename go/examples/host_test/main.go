// Host integration test with real TUN devices.
//
// Requires root/sudo to create TUN devices.
//
// Usage:
//   bazel build //go/examples/host_test
//   sudo bazel-bin/go/examples/host_test/host_test_/host_test
//
// Then in another terminal:
//   ping 100.64.0.2
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
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
		fmt.Println("  sudo ./host_test")
		os.Exit(1)
	}

	// Generate keypairs
	keyA, err := noise.GenerateKeyPair()
	if err != nil {
		fatal("generate key A: %v", err)
	}
	keyB, err := noise.GenerateKeyPair()
	if err != nil {
		fatal("generate key B: %v", err)
	}

	fmt.Printf("Host A pubkey: %s\n", keyA.Public.ShortString())
	fmt.Printf("Host B pubkey: %s\n", keyB.Public.ShortString())
	fmt.Println()

	// Create TUN devices
	fmt.Println("Creating TUN devices...")
	tunA, err := tun.Create("")
	if err != nil {
		fatal("create TUN A: %v", err)
	}
	tunB, err := tun.Create("")
	if err != nil {
		tunA.Close()
		fatal("create TUN B: %v", err)
	}

	fmt.Printf("  TUN A: %s\n", tunA.Name())
	fmt.Printf("  TUN B: %s\n", tunB.Name())

	// Configure TUN A: 100.64.0.1/24
	if err := tunA.SetMTU(1400); err != nil {
		cleanup(tunA, tunB)
		fatal("set MTU A: %v", err)
	}
	if err := tunA.SetIPv4(net.IPv4(100, 64, 0, 1), net.CIDRMask(24, 32)); err != nil {
		cleanup(tunA, tunB)
		fatal("set IPv4 A: %v", err)
	}
	if err := tunA.Up(); err != nil {
		cleanup(tunA, tunB)
		fatal("up A: %v", err)
	}
	fmt.Println("  TUN A: 100.64.0.1/24 UP")

	// Configure TUN B: 100.64.1.1/24
	if err := tunB.SetMTU(1400); err != nil {
		cleanup(tunA, tunB)
		fatal("set MTU B: %v", err)
	}
	if err := tunB.SetIPv4(net.IPv4(100, 64, 1, 1), net.CIDRMask(24, 32)); err != nil {
		cleanup(tunA, tunB)
		fatal("set IPv4 B: %v", err)
	}
	if err := tunB.Up(); err != nil {
		cleanup(tunA, tunB)
		fatal("up B: %v", err)
	}
	fmt.Println("  TUN B: 100.64.1.1/24 UP")
	fmt.Println()

	// Create Host A
	hostA, err := host.New(host.Config{
		PrivateKey: keyA,
		TunIPv4:    net.IPv4(100, 64, 0, 1),
		MTU:        1400,
	}, tunA)
	if err != nil {
		cleanup(tunA, tunB)
		fatal("create Host A: %v", err)
	}

	// Create Host B
	hostB, err := host.New(host.Config{
		PrivateKey: keyB,
		TunIPv4:    net.IPv4(100, 64, 1, 1),
		MTU:        1400,
	}, tunB)
	if err != nil {
		hostA.Close()
		fatal("create Host B: %v", err)
	}

	// Get actual UDP ports
	portA := hostA.LocalAddr().(*net.UDPAddr).Port
	portB := hostB.LocalAddr().(*net.UDPAddr).Port
	fmt.Printf("Host A listening on UDP port %d\n", portA)
	fmt.Printf("Host B listening on UDP port %d\n", portB)

	// Add peers with static IP assignments
	// Host A: peer B gets 100.64.0.2
	err = hostA.AddPeerWithIP(keyB.Public, fmt.Sprintf("127.0.0.1:%d", portB), net.IPv4(100, 64, 0, 2))
	if err != nil {
		hostA.Close()
		hostB.Close()
		fatal("Host A add peer B: %v", err)
	}

	// Host B: peer A gets 100.64.1.2
	err = hostB.AddPeerWithIP(keyA.Public, fmt.Sprintf("127.0.0.1:%d", portA), net.IPv4(100, 64, 1, 2))
	if err != nil {
		hostA.Close()
		hostB.Close()
		fatal("Host B add peer A: %v", err)
	}

	fmt.Println()
	fmt.Println("IP allocations:")
	fmt.Println("  Host A: TUN=100.64.0.1, peer B=100.64.0.2")
	fmt.Println("  Host B: TUN=100.64.1.1, peer A=100.64.1.2")
	fmt.Println()

	// Start forwarding loops
	go hostA.Run()
	go hostB.Run()

	// Perform handshake
	fmt.Println("Performing Noise IK handshake (A -> B)...")
	if err := hostA.Connect(keyB.Public); err != nil {
		hostA.Close()
		hostB.Close()
		fatal("handshake: %v", err)
	}
	fmt.Println("Handshake complete!")
	fmt.Println()

	// Print routing info
	fmt.Println("=== Routing ===")
	fmt.Printf("  %s: 100.64.0.0/24 -> TUN A -> Host A -> encrypt -> UDP :%d\n", tunA.Name(), portA)
	fmt.Printf("  %s: 100.64.1.0/24 -> TUN B -> Host B -> encrypt -> UDP :%d\n", tunB.Name(), portB)
	fmt.Println()
	fmt.Println("=== Test Commands (run in another terminal) ===")
	fmt.Println("  ping 100.64.0.2    # A's view of B, routes through TUN A -> TUN B")
	fmt.Println("  ping 100.64.1.2    # B's view of A, routes through TUN B -> TUN A")
	fmt.Println()
	fmt.Println("Press Ctrl+C to exit.")

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Print periodic status
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			fmt.Println("\nShutting down...")
			hostA.Close()
			hostB.Close()
			fmt.Println("Done.")
			return
		case <-ticker.C:
			// Still running
		}
	}
}

func cleanup(devs ...*tun.Device) {
	for _, d := range devs {
		if d != nil {
			d.Close()
		}
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}
