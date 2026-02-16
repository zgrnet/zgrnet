// Node SDK cross-language interop test runner.
//
// Launches Go and Rust (and optionally Zig) node_test binaries in pairs
// and verifies that Dial + AcceptStream + echo works across languages.
//
// Usage:
//
//	bazel run //examples/node_test/runner -- \
//	  --go=path/to/go_binary --rust=path/to/rust_binary [--zig=path/to/zig_binary]
//
// Or via bazel test (binaries discovered from runfiles):
//
//	bazel test //examples/node_test:interop_test
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	goBin   = flag.String("go", "", "Path to Go node_test binary")
	rustBin = flag.String("rust", "", "Path to Rust node_test binary")
	zigBin  = flag.String("zig", "", "Path to Zig node_test binary (optional)")
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

type result struct {
	opener   string
	accepter string
	pass     bool
	output   string
	elapsed  time.Duration
}

var portCounter int

func nextPorts() (int, int) {
	portCounter++
	return 20000 + portCounter*10, 21000 + portCounter*10
}

func main() {
	flag.Parse()

	// Discover binaries from runfiles if not specified via flags.
	if *goBin == "" || *rustBin == "" {
		discoverBinaries()
	}

	if *goBin == "" || *rustBin == "" {
		fmt.Fprintln(os.Stderr, "error: --go and --rust are required")
		fmt.Fprintln(os.Stderr, "  or run via: bazel test //examples/node_test:interop_test")
		os.Exit(1)
	}

	bins := map[string]string{
		"go":   *goBin,
		"rust": *rustBin,
	}
	if *zigBin != "" {
		bins["zig"] = *zigBin
	}

	// Verify binaries exist.
	for name, path := range bins {
		if _, err := os.Stat(path); err != nil {
			fmt.Fprintf(os.Stderr, "binary not found: %s=%s\n", name, path)
			os.Exit(1)
		}
	}

	fmt.Println("=== ZGRNet Node SDK Interop Test ===")
	fmt.Println()

	pairs := []struct{ opener, accepter string }{
		{"go", "rust"},
	}
	if _, ok := bins["zig"]; ok {
		pairs = append(pairs, struct{ opener, accepter string }{"go", "zig"})
	}

	var results []result
	for _, p := range pairs {
		r := runPairTest(bins[p.opener], bins[p.accepter], p.opener, p.accepter)
		results = append(results, r)
	}

	// Summary.
	fmt.Println()
	fmt.Println("=== Results ===")
	passed, failed := 0, 0
	for _, r := range results {
		status := "PASS"
		if !r.pass {
			status = "FAIL"
			failed++
		} else {
			passed++
		}
		fmt.Printf("  %s ↔ %s: %s (%s)\n", r.opener, r.accepter, status, r.elapsed.Round(time.Millisecond))
	}
	fmt.Printf("\nPassed: %d/%d\n", passed, len(results))

	if failed > 0 {
		fmt.Println("\nSOME TESTS FAILED")
		os.Exit(1)
	}
	fmt.Println("\nAll tests passed!")
}

func runPairTest(openerBin, accepterBin, openerName, accepterName string) result {
	fmt.Printf("Test: %s ↔ %s\n", openerName, accepterName)
	start := time.Now()

	openerPort, accepterPort := nextPorts()

	// Write config to temp file.
	cfg := testConfig{
		Hosts: []hostEntry{
			{Name: openerName, PrivateKey: "0000000000000000000000000000000000000000000000000000000000000001", Port: openerPort, Role: "opener"},
			{Name: accepterName, PrivateKey: "0000000000000000000000000000000000000000000000000000000000000002", Port: accepterPort, Role: "accepter"},
		},
		Test: testParams{EchoMessage: "Hello Node Interop!"},
	}
	cfgData, _ := json.Marshal(cfg)
	cfgFile := filepath.Join(os.TempDir(), fmt.Sprintf("node_test_%s_%s.json", openerName, accepterName))
	os.WriteFile(cfgFile, cfgData, 0644)
	defer os.Remove(cfgFile)

	// Start accepter.
	accepterCmd := exec.Command(accepterBin, "--name", accepterName, "--config", cfgFile)
	var accepterOut strings.Builder
	accepterCmd.Stdout = &accepterOut
	accepterCmd.Stderr = &accepterOut
	if err := accepterCmd.Start(); err != nil {
		return result{openerName, accepterName, false, fmt.Sprintf("start accepter: %v", err), time.Since(start)}
	}

	// Give accepter time to bind.
	time.Sleep(500 * time.Millisecond)

	// Start opener.
	openerCmd := exec.Command(openerBin, "--name", openerName, "--config", cfgFile)
	var openerOut strings.Builder
	openerCmd.Stdout = &openerOut
	openerCmd.Stderr = &openerOut
	if err := openerCmd.Start(); err != nil {
		accepterCmd.Process.Kill()
		accepterCmd.Wait()
		return result{openerName, accepterName, false, fmt.Sprintf("start opener: %v", err), time.Since(start)}
	}

	// Wait for both with timeout.
	timeout := 30 * time.Second
	var openerErr, accepterErr error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		openerErr = waitWithTimeout(openerCmd, timeout)
	}()
	go func() {
		defer wg.Done()
		accepterErr = waitWithTimeout(accepterCmd, timeout)
	}()
	wg.Wait()

	elapsed := time.Since(start)
	pass := openerErr == nil && accepterErr == nil

	if !pass {
		fmt.Printf("  FAIL\n")
		if openerErr != nil {
			fmt.Printf("  opener error: %v\n", openerErr)
		}
		if accepterErr != nil {
			fmt.Printf("  accepter error: %v\n", accepterErr)
		}
		fmt.Printf("  opener output:\n")
		printIndented(openerOut.String(), 4)
		fmt.Printf("  accepter output:\n")
		printIndented(accepterOut.String(), 4)
	} else {
		fmt.Printf("  PASS (%s)\n", elapsed.Round(time.Millisecond))
	}

	return result{openerName, accepterName, pass, "", elapsed}
}

func waitWithTimeout(cmd *exec.Cmd, timeout time.Duration) error {
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

func printIndented(s string, indent int) {
	prefix := strings.Repeat(" ", indent)
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		fmt.Printf("%s%s\n", prefix, line)
	}
}

// discoverBinaries tries to find binaries from Bazel runfiles.
func discoverBinaries() {
	runfiles := os.Getenv("TEST_SRCDIR")
	if runfiles == "" {
		return
	}
	base := filepath.Join(runfiles, "_main")

	if *goBin == "" {
		p := filepath.Join(base, "examples/node_test/go/node_test_/node_test")
		if _, err := os.Stat(p); err == nil {
			*goBin = p
		}
	}
	if *rustBin == "" {
		p := filepath.Join(base, "examples/node_test/rust/node_test")
		if _, err := os.Stat(p); err == nil {
			*rustBin = p
		}
	}
	if *zigBin == "" {
		p := filepath.Join(base, "examples/node_test/zig/node_test")
		if _, err := os.Stat(p); err == nil {
			*zigBin = p
		}
	}
}
