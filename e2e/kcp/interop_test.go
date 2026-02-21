// Cross-language KCP stream interop test.
//
// Tests Go ↔ Rust KCP+yamux interoperability using real UDP communication.
// Each test launches two independent binaries (opener + accepter) and
// validates that they complete successfully.
//
// Usage:
//
//	bazel test //e2e/kcp:interop_test
package kcp_e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type testConfig struct {
	Hosts []hostEntry `json:"hosts"`
	Test  testParams  `json:"test"`
}

type hostEntry struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	Port       int    `json:"port"`
	Role       string `json:"role"`
}

type testParams struct {
	Mode         string `json:"mode"` // "echo", "streaming", "multi_stream", "delayed_write"
	EchoMessage  string `json:"echo_message"`
	ThroughputMB int    `json:"throughput_mb"`
	ChunkKB      int    `json:"chunk_kb"`
	NumStreams   int    `json:"num_streams"`
	DelayMs      int    `json:"delay_ms"`
}

var portCounter int

func init() {
	portCounter = int(time.Now().UnixNano() % 20000)
}

func nextPorts() (int, int) {
	portCounter += 2
	base := 40000 + portCounter
	return base, base + 1
}

func findBinary(t *testing.T, relPath string) string {
	t.Helper()
	if srcdir := os.Getenv("TEST_SRCDIR"); srcdir != "" {
		p := filepath.Join(srcdir, "_main", relPath)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if _, err := os.Stat(relPath); err == nil {
		abs, _ := filepath.Abs(relPath)
		return abs
	}
	return ""
}

func goBin(t *testing.T) string {
	t.Helper()
	b := findBinary(t, "e2e/kcp/go/kcp_test_/kcp_test")
	if b == "" {
		t.Fatal("Go binary not found")
	}
	return b
}

func rustBin(t *testing.T) string {
	t.Helper()
	b := findBinary(t, "e2e/kcp/rust/kcp_test")
	if b == "" {
		t.Fatal("Rust binary not found")
	}
	return b
}

// === Go opener → Rust accepter ===

func TestInterop_GoOpener_RustAccepter_Echo(t *testing.T) {
	runInterop(t, goBin(t), rustBin(t), "go", "rust", testParams{
		Mode:        "echo",
		EchoMessage: "Hello KCP Interop!",
	})
}

func TestInterop_GoOpener_RustAccepter_Streaming(t *testing.T) {
	runInterop(t, goBin(t), rustBin(t), "go", "rust", testParams{
		Mode:         "streaming",
		ThroughputMB: 10,
		ChunkKB:      64,
	})
}

func TestInterop_GoOpener_RustAccepter_100MB(t *testing.T) {
	runInterop(t, goBin(t), rustBin(t), "go", "rust", testParams{
		Mode:         "streaming",
		ThroughputMB: 100,
		ChunkKB:      64,
	})
}

// === Rust opener → Go accepter ===

func TestInterop_RustOpener_GoAccepter_Echo(t *testing.T) {
	runInterop(t, rustBin(t), goBin(t), "rust", "go", testParams{
		Mode:        "echo",
		EchoMessage: "Hello from Rust!",
	})
}

func TestInterop_RustOpener_GoAccepter_Streaming(t *testing.T) {
	runInterop(t, rustBin(t), goBin(t), "rust", "go", testParams{
		Mode:         "streaming",
		ThroughputMB: 10,
		ChunkKB:      64,
	})
}

// === Multi-stream ===

func TestInterop_GoRust_MultiStream(t *testing.T) {
	runInterop(t, goBin(t), rustBin(t), "go", "rust", testParams{
		Mode:       "multi_stream",
		NumStreams: 10,
		ChunkKB:   64,
	})
}

// === SYN delay edge case ===

func TestInterop_RustOpener_NoImmediateWrite(t *testing.T) {
	runInterop(t, rustBin(t), goBin(t), "rust", "go", testParams{
		Mode:    "delayed_write",
		DelayMs: 2000,
	})
}

// === Zig placeholders ===

func TestInterop_GoZig(t *testing.T) {
	t.Skip("Zig Phase 6 not yet implemented")
}

func TestInterop_RustZig(t *testing.T) {
	t.Skip("Zig Phase 6 not yet implemented")
}

// === Infrastructure ===

func runInterop(t *testing.T, openerBin, accepterBin, openerName, accepterName string, params testParams) {
	t.Helper()

	openerPort, accepterPort := nextPorts()

	cfg := testConfig{
		Hosts: []hostEntry{
			{Name: openerName, PrivateKey: "0000000000000000000000000000000000000000000000000000000000000001", Port: openerPort, Role: "opener"},
			{Name: accepterName, PrivateKey: "0000000000000000000000000000000000000000000000000000000000000002", Port: accepterPort, Role: "accepter"},
		},
		Test: params,
	}
	cfgData, _ := json.Marshal(cfg)
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(cfgFile, cfgData, 0644)

	accepterCmd := exec.Command(accepterBin, "--name", accepterName, "--config", cfgFile)
	var accepterOut strings.Builder
	accepterCmd.Stdout = &accepterOut
	accepterCmd.Stderr = &accepterOut
	if err := accepterCmd.Start(); err != nil {
		t.Fatalf("start accepter: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	openerCmd := exec.Command(openerBin, "--name", openerName, "--config", cfgFile)
	var openerOut strings.Builder
	openerCmd.Stdout = &openerOut
	openerCmd.Stderr = &openerOut
	if err := openerCmd.Start(); err != nil {
		accepterCmd.Process.Kill()
		accepterCmd.Wait()
		t.Fatalf("start opener: %v", err)
	}

	timeout := 120 * time.Second
	var openerErr, accepterErr error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() { defer wg.Done(); openerErr = waitTimeout(openerCmd, timeout) }()
	go func() { defer wg.Done(); accepterErr = waitTimeout(accepterCmd, timeout) }()
	wg.Wait()

	if openerErr != nil {
		t.Errorf("opener (%s) failed: %v\n%s", openerName, openerErr, indent(openerOut.String()))
	}
	if accepterErr != nil {
		t.Errorf("accepter (%s) failed: %v\n%s", accepterName, accepterErr, indent(accepterOut.String()))
	}
	if openerErr == nil && accepterErr == nil {
		t.Logf("%s → %s [%s]: PASS", openerName, accepterName, params.Mode)
	}
}

func waitTimeout(cmd *exec.Cmd, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		cmd.Process.Kill()
		<-done
		return fmt.Errorf("timeout after %s", timeout)
	}
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		b.WriteString("    ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
