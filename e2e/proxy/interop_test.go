// Cross-language proxy interop test.
//
// Tests TCP_PROXY(69) KCP stream handling between Go, Rust, and Zig.
// Each pair: one "handler" (echo server + TCP_PROXY handler) and one
// "proxy" (opens KCP stream, sends data, verifies echo).
//
// Usage:
//
//	bazel test //e2e/proxy:interop_test
package proxy_e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type proxyConfig struct {
	Hosts    []hostEntry `json:"hosts"`
	EchoPort int         `json:"echo_port"`
	Test     testParams  `json:"test"`
}

type hostEntry struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	Port       int    `json:"port"`
	Role       string `json:"role"`
}

type testParams struct {
	Message string `json:"message"`
}

var portCounter int

func nextPorts() (int, int, int) {
	portCounter++
	handlerPort := 20000 + portCounter*10
	proxyPort := 21000 + portCounter*10
	echoPort := 22000 + portCounter*10
	return handlerPort, proxyPort, echoPort
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

func TestGoGoProxy(t *testing.T) {
	goBin := requireBin(t, "e2e/proxy/go/proxy_test_/proxy_test", "Go")
	runPairTest(t, goBin, goBin, "go", "go")
}

func TestGoRustProxy(t *testing.T) {
	goBin := requireBin(t, "e2e/proxy/go/proxy_test_/proxy_test", "Go")
	rustBin := requireBin(t, "e2e/proxy/rust/proxy_test", "Rust")
	runPairTest(t, goBin, rustBin, "go", "rust")
}

func TestRustGoProxy(t *testing.T) {
	rustBin := requireBin(t, "e2e/proxy/rust/proxy_test", "Rust")
	goBin := requireBin(t, "e2e/proxy/go/proxy_test_/proxy_test", "Go")
	runPairTest(t, rustBin, goBin, "rust", "go")
}

func TestRustRustProxy(t *testing.T) {
	rustBin := requireBin(t, "e2e/proxy/rust/proxy_test", "Rust")
	runPairTest(t, rustBin, rustBin, "rust", "rust")
}

func TestGoZigProxy(t *testing.T) {
	goBin := requireBin(t, "e2e/proxy/go/proxy_test_/proxy_test", "Go")
	zigBin := findBinary(t, "e2e/proxy/zig/proxy_test")
	if zigBin == "" {
		t.Skip("Zig binary not available on this platform")
	}
	runPairTest(t, goBin, zigBin, "go", "zig")
}

func TestZigGoProxy(t *testing.T) {
	zigBin := findBinary(t, "e2e/proxy/zig/proxy_test")
	if zigBin == "" {
		t.Skip("Zig binary not available on this platform")
	}
	goBin := requireBin(t, "e2e/proxy/go/proxy_test_/proxy_test", "Go")
	runPairTest(t, zigBin, goBin, "zig", "go")
}

func requireBin(t *testing.T, relPath, name string) string {
	t.Helper()
	bin := findBinary(t, relPath)
	if bin == "" {
		t.Fatalf("%s binary not found at %s", name, relPath)
	}
	return bin
}

func runPairTest(t *testing.T, handlerBin, proxyBin, handlerName, proxyName string) {
	t.Helper()

	handlerPort, proxyPort, echoPort := nextPorts()

	cfg := proxyConfig{
		Hosts: []hostEntry{
			{Name: "handler", PrivateKey: "0000000000000000000000000000000000000000000000000000000000000001", Port: handlerPort, Role: "handler"},
			{Name: "proxy", PrivateKey: "0000000000000000000000000000000000000000000000000000000000000002", Port: proxyPort, Role: "proxy"},
		},
		EchoPort: echoPort,
		Test:     testParams{Message: fmt.Sprintf("cross-lang proxy test %s->%s!", proxyName, handlerName)},
	}
	cfgData, _ := json.Marshal(cfg)
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(cfgFile, cfgData, 0644)

	// Start handler.
	handlerCmd := exec.Command(handlerBin, "--name", "handler", "--config", cfgFile)
	var handlerOut strings.Builder
	handlerCmd.Stdout = &handlerOut
	handlerCmd.Stderr = &handlerOut
	if err := handlerCmd.Start(); err != nil {
		t.Fatalf("start handler (%s): %v", handlerName, err)
	}

	time.Sleep(500 * time.Millisecond)

	// Start proxy (runs test internally, exits when done).
	proxyCmd := exec.Command(proxyBin, "--name", "proxy", "--config", cfgFile)
	var proxyOut strings.Builder
	proxyCmd.Stdout = &proxyOut
	proxyCmd.Stderr = &proxyOut
	if err := proxyCmd.Start(); err != nil {
		handlerCmd.Process.Kill()
		handlerCmd.Wait()
		t.Fatalf("start proxy (%s): %v", proxyName, err)
	}

	// Wait for proxy to finish with timeout.
	timeout := 30 * time.Second
	proxyErr := waitTimeout(proxyCmd, timeout)

	// Kill handler.
	handlerCmd.Process.Kill()
	handlerCmd.Wait()

	if proxyErr != nil {
		t.Errorf("%s proxy → %s handler: FAIL: %v", proxyName, handlerName, proxyErr)
		t.Logf("handler output:\n%s", indent(handlerOut.String()))
		t.Logf("proxy output:\n%s", indent(proxyOut.String()))
	} else {
		t.Logf("%s proxy → %s handler: PASS", proxyName, handlerName)
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
