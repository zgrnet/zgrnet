// Cross-language Node.Listen interop test.
//
// Tests that proto-specific stream routing (Listen/AcceptStream) works
// correctly across all 3×3 language pairs: Go, Rust, Zig.
//
// The opener sends streams with proto=128 (chat) and proto=200 (file).
// The accepter uses Listen(128) for chat and AcceptStream for file.
// Both streams do echo round-trip verification.
package listener_e2e

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
	EchoMessage string `json:"echo_message"`
}

var portCounter int

func nextPorts() (int, int) {
	portCounter++
	return 22000 + portCounter*10, 23000 + portCounter*10
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
	return findBinary(t, "e2e/listener/go/listener_test_/listener_test")
}

func rustBin(t *testing.T) string {
	return findBinary(t, "e2e/listener/rust/listener_test")
}

func zigBin(t *testing.T) string {
	return findBinary(t, "e2e/listener/zig/listener_test")
}

// ─── Go ↔ Go ──────────────────────────────────────────────────────────

func TestGoOpener_GoAccepter(t *testing.T) {
	b := goBin(t)
	if b == "" {
		t.Fatal("Go binary not found")
	}
	runPairTest(t, b, b, "go-opener", "go-accepter")
}

// ─── Go ↔ Rust ────────────────────────────────────────────────────────

func TestGoOpener_RustAccepter(t *testing.T) {
	g, r := goBin(t), rustBin(t)
	if g == "" {
		t.Fatal("Go binary not found")
	}
	if r == "" {
		t.Fatal("Rust binary not found")
	}
	runPairTest(t, g, r, "go", "rust")
}

func TestRustOpener_GoAccepter(t *testing.T) {
	g, r := goBin(t), rustBin(t)
	if g == "" {
		t.Fatal("Go binary not found")
	}
	if r == "" {
		t.Fatal("Rust binary not found")
	}
	runPairTest(t, r, g, "rust", "go")
}

// ─── Go ↔ Zig ─────────────────────────────────────────────────────────

func TestGoOpener_ZigAccepter(t *testing.T) {
	g, z := goBin(t), zigBin(t)
	if g == "" {
		t.Fatal("Go binary not found")
	}
	if z == "" {
		t.Skip("Zig binary not available on this platform")
	}
	runPairTest(t, g, z, "go", "zig")
}

func TestZigOpener_GoAccepter(t *testing.T) {
	g, z := goBin(t), zigBin(t)
	if g == "" {
		t.Fatal("Go binary not found")
	}
	if z == "" {
		t.Skip("Zig binary not available on this platform")
	}
	runPairTest(t, z, g, "zig", "go")
}

// ─── Rust ↔ Rust ──────────────────────────────────────────────────────

func TestRustOpener_RustAccepter(t *testing.T) {
	r := rustBin(t)
	if r == "" {
		t.Fatal("Rust binary not found")
	}
	runPairTest(t, r, r, "rust-opener", "rust-accepter")
}

// ─── Rust ↔ Zig ───────────────────────────────────────────────────────

func TestRustOpener_ZigAccepter(t *testing.T) {
	r, z := rustBin(t), zigBin(t)
	if r == "" {
		t.Fatal("Rust binary not found")
	}
	if z == "" {
		t.Skip("Zig binary not available on this platform")
	}
	runPairTest(t, r, z, "rust", "zig")
}

func TestZigOpener_RustAccepter(t *testing.T) {
	r, z := rustBin(t), zigBin(t)
	if r == "" {
		t.Fatal("Rust binary not found")
	}
	if z == "" {
		t.Skip("Zig binary not available on this platform")
	}
	runPairTest(t, z, r, "zig", "rust")
}

// ─── Zig ↔ Zig ────────────────────────────────────────────────────────

func TestZigOpener_ZigAccepter(t *testing.T) {
	z := zigBin(t)
	if z == "" {
		t.Skip("Zig binary not available on this platform")
	}
	runPairTest(t, z, z, "zig-opener", "zig-accepter")
}

// ─── Runner ────────────────────────────────────────────────────────────

func runPairTest(t *testing.T, openerBin, accepterBin, openerName, accepterName string) {
	t.Helper()

	openerPort, accepterPort := nextPorts()

	cfg := testConfig{
		Hosts: []hostEntry{
			{Name: openerName, PrivateKey: "0000000000000000000000000000000000000000000000000000000000000001", Port: openerPort, Role: "opener"},
			{Name: accepterName, PrivateKey: "0000000000000000000000000000000000000000000000000000000000000002", Port: accepterPort, Role: "accepter"},
		},
		Test: testParams{EchoMessage: "Hello Listen Interop!"},
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

	timeout := 30 * time.Second
	var openerErr, accepterErr error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		openerErr = waitTimeout(openerCmd, timeout)
	}()
	go func() {
		defer wg.Done()
		accepterErr = waitTimeout(accepterCmd, timeout)
	}()
	wg.Wait()

	if openerErr != nil {
		t.Errorf("opener (%s) failed: %v", openerName, openerErr)
		t.Logf("opener output:\n%s", indent(openerOut.String()))
	}
	if accepterErr != nil {
		t.Errorf("accepter (%s) failed: %v", accepterName, accepterErr)
		t.Logf("accepter output:\n%s", indent(accepterOut.String()))
	}

	if openerErr == nil && accepterErr == nil {
		t.Logf("opener (%s) output:\n%s", openerName, indent(openerOut.String()))
		t.Logf("accepter (%s) output:\n%s", accepterName, indent(accepterOut.String()))
	}
}

func waitTimeout(cmd *exec.Cmd, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

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
