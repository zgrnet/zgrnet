// Package zgrnet_e2e provides cross-language end-to-end tests for the zgrnet CLI.
//
// It runs the same test cases against Go, Rust, and Zig binaries, verifying
// that all three produce identical results for the same operations.
//
// Each test case runs in an isolated temp directory (HOME is overridden) so
// that ~/.config/zgrnet is sandboxed per test.
package zgrnet_e2e

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// ── Test case schema ────────────────────────────────────────────────────

type TestSuite []TestCase

type TestCase struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	SeedKey     bool     `json:"seed_key"`
	Steps       []Step   `json:"steps"`
	ExpectFiles []string `json:"expect_files"`
}

type Step struct {
	Args                       []string `json:"args"`
	ExpectExit                 int      `json:"expect_exit"`
	ExpectStdout               string   `json:"expect_stdout"`
	ExpectStdoutContains       []string `json:"expect_stdout_contains"`
	ExpectStdoutNotContains    []string `json:"expect_stdout_not_contains"`
	ExpectStdoutMatchSeedPK    bool     `json:"expect_stdout_match_seed_pubkey"`
	ExpectStdoutMatchSeedCfg   bool     `json:"expect_stdout_match_seed_config"`
}

// ── Binary registry ─────────────────────────────────────────────────────

type Binary struct {
	Name string
	Path string
}

func findBinaries(t *testing.T) []Binary {
	t.Helper()

	// Bazel puts test data/deps relative to the runfiles directory.
	// When running under `bazel test`, TEST_SRCDIR is set.
	// When running manually, fall back to workspace-relative paths.
	var bins []Binary

	candidates := []struct {
		name string
		// Paths to try, in order of preference
		paths []string
	}{
		{"go", []string{
			os.Getenv("GO_ZGRNET_BIN"),
			"go/cmd/zgrnet/zgrnet_/zgrnet",
		}},
		{"rust", []string{
			os.Getenv("RUST_ZGRNET_BIN"),
			"rust/zgrnet_bin",
		}},
		{"zig", []string{
			os.Getenv("ZIG_ZGRNET_BIN"),
			"zig/zgrnet_bin",
		}},
	}

	// Try to find the workspace root for fallback paths
	wsRoot := ""
	if srcDir := os.Getenv("TEST_SRCDIR"); srcDir != "" {
		wsRoot = filepath.Join(srcDir, os.Getenv("TEST_WORKSPACE"))
	}
	if wsRoot == "" {
		// Try to find bazel-bin relative to CWD
		if wd, err := os.Getwd(); err == nil {
			// Walk up looking for bazel-bin/
			for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
				bb := filepath.Join(dir, "bazel-bin")
				if fi, err := os.Stat(bb); err == nil && fi.IsDir() {
					wsRoot = bb
					break
				}
			}
		}
	}

	for _, c := range candidates {
		found := false
		for _, p := range c.paths {
			if p == "" {
				continue
			}
			// Try absolute path first
			if filepath.IsAbs(p) {
				if _, err := os.Stat(p); err == nil {
					bins = append(bins, Binary{Name: c.name, Path: p})
					found = true
					break
				}
			}
			// Try relative to workspace root
			if wsRoot != "" {
				abs := filepath.Join(wsRoot, p)
				if _, err := os.Stat(abs); err == nil {
					bins = append(bins, Binary{Name: c.name, Path: abs})
					found = true
					break
				}
			}
		}
		if !found {
			t.Logf("warning: %s binary not found, skipping", c.name)
		}
	}

	if len(bins) == 0 {
		t.Fatal("no zgrnet binaries found; build with: bazel build //go/cmd/zgrnet //rust:zgrnet_bin //zig:zgrnet_bin")
	}
	return bins
}

// ── Seed key handling ───────────────────────────────────────────────────

func loadSeedKey(t *testing.T) (privateHex string, publicHex string) {
	t.Helper()

	data, err := os.ReadFile(testdataPath(t, "seed_key.hex"))
	if err != nil {
		t.Fatalf("read seed key: %v", err)
	}
	privateHex = strings.TrimSpace(string(data))
	if len(privateHex) != 64 {
		t.Fatalf("seed key must be 64 hex chars, got %d", len(privateHex))
	}

	// Derive public key (same as Go/Rust/Zig implementations)
	privBytes, err := hex.DecodeString(privateHex)
	if err != nil {
		t.Fatalf("decode seed key: %v", err)
	}

	pub, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	publicHex = hex.EncodeToString(pub)
	return
}

func testdataPath(t *testing.T, name string) string {
	t.Helper()

	// Try relative to the test source
	candidates := []string{
		filepath.Join("e2e", "zgrnet", "testdata", name),
		filepath.Join("testdata", name),
	}

	// Bazel runfiles
	if srcDir := os.Getenv("TEST_SRCDIR"); srcDir != "" {
		ws := os.Getenv("TEST_WORKSPACE")
		candidates = append([]string{
			filepath.Join(srcDir, ws, "e2e", "zgrnet", "testdata", name),
		}, candidates...)
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatalf("testdata/%s not found", name)
	return ""
}

// ── Test runner ─────────────────────────────────────────────────────────

func TestCrossLanguage(t *testing.T) {
	bins := findBinaries(t)
	suite := loadTestSuite(t)
	seedPriv, seedPub := loadSeedKey(t)

	for _, tc := range suite {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			// Collect results from all languages for comparison
			type result struct {
				lang    string
				outputs []string // stdout for each step
				storeFS map[string]bool
			}
			var results []result

			for _, bin := range bins {
				bin := bin
				t.Run(bin.Name, func(t *testing.T) {
					r := runTestCase(t, bin, tc, seedPriv, seedPub)
					results = append(results, result{
						lang:    bin.Name,
						outputs: r.outputs,
						storeFS: r.storeFS,
					})
				})
			}

			// Cross-language comparison: verify all languages produced same results
			if len(results) < 2 {
				return
			}
			ref := results[0]
			for _, other := range results[1:] {
				// Compare step outputs that have exact expectations
				for i, step := range tc.Steps {
					if step.ExpectStdout != "" {
						if i < len(ref.outputs) && i < len(other.outputs) {
							if ref.outputs[i] != other.outputs[i] {
								t.Errorf("step %d stdout mismatch: %s=%q vs %s=%q",
									i, ref.lang, ref.outputs[i], other.lang, other.outputs[i])
							}
						}
					}
					if step.ExpectStdoutMatchSeedPK {
						if i < len(ref.outputs) && i < len(other.outputs) {
							if ref.outputs[i] != other.outputs[i] {
								t.Errorf("step %d key derivation mismatch: %s=%q vs %s=%q",
									i, ref.lang, ref.outputs[i], other.lang, other.outputs[i])
							}
						}
					}
					if step.ExpectStdoutMatchSeedCfg {
						if i < len(ref.outputs) && i < len(other.outputs) {
							refNorm := normalizeConfig(ref.outputs[i])
							otherNorm := normalizeConfig(other.outputs[i])
							if refNorm != otherNorm {
								t.Errorf("step %d config template mismatch: %s vs %s\n--- %s ---\n%s\n--- %s ---\n%s",
									i, ref.lang, other.lang, ref.lang, refNorm, other.lang, otherNorm)
							}
						}
					}
				}

				// Compare filesystem structure
				if tc.ExpectFiles != nil {
					for _, f := range tc.ExpectFiles {
						refHas := ref.storeFS[f]
						otherHas := other.storeFS[f]
						if refHas != otherHas {
							t.Errorf("filesystem mismatch for %q: %s=%v vs %s=%v",
								f, ref.lang, refHas, other.lang, otherHas)
						}
					}
				}
			}
		})
	}
}

type testResult struct {
	outputs []string
	storeFS map[string]bool
}

func runTestCase(t *testing.T, bin Binary, tc TestCase, seedPriv, seedPub string) testResult {
	t.Helper()

	// Create isolated HOME
	home := t.TempDir()
	storeRoot := filepath.Join(home, ".config", "zgrnet")

	var outputs []string

	for i, step := range tc.Steps {
		stdout, stderr, exitCode := runCmd(t, bin.Path, step.Args, home)

		// Check exit code
		if exitCode != step.ExpectExit {
			t.Errorf("step %d %v: exit=%d, want %d\nstdout: %s\nstderr: %s",
				i, step.Args, exitCode, step.ExpectExit, stdout, stderr)
		}

		// After context create + seed_key: inject known private key
		if tc.SeedKey && len(step.Args) >= 3 && step.Args[0] == "context" && step.Args[1] == "create" {
			ctxName := step.Args[2]
			keyPath := filepath.Join(storeRoot, ctxName, "private.key")
			if err := os.WriteFile(keyPath, []byte(seedPriv+"\n"), 0600); err != nil {
				t.Fatalf("inject seed key: %v", err)
			}
		}

		// Verify expectations
		if step.ExpectStdout != "" && stdout != step.ExpectStdout {
			t.Errorf("step %d %v: stdout=%q, want %q", i, step.Args, stdout, step.ExpectStdout)
		}

		for _, want := range step.ExpectStdoutContains {
			if !strings.Contains(stdout, want) {
				t.Errorf("step %d %v: stdout missing %q\nstdout: %s", i, step.Args, want, stdout)
			}
		}

		for _, reject := range step.ExpectStdoutNotContains {
			if strings.Contains(stdout, reject) {
				t.Errorf("step %d %v: stdout should not contain %q\nstdout: %s", i, step.Args, reject, stdout)
			}
		}

		if step.ExpectStdoutMatchSeedPK {
			got := strings.TrimSpace(stdout)
			if got != seedPub {
				t.Errorf("step %d %v: public key=%q, want %q", i, step.Args, got, seedPub)
			}
		}

		if step.ExpectStdoutMatchSeedCfg {
			// Verify "# Public key: <64 hex chars>" is on a single line (not split)
			found := false
			for _, line := range strings.Split(stdout, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "# Public key: ") {
					hexPart := strings.TrimPrefix(trimmed, "# Public key: ")
					if len(hexPart) == 64 && isHex(hexPart) {
						found = true
					} else {
						t.Errorf("step %d %v: malformed public key line: %q (hex part len=%d)",
							i, step.Args, line, len(hexPart))
					}
					break
				}
			}
			if !found {
				t.Errorf("step %d %v: config missing '# Public key: <64 hex>' on single line\nstdout:\n%s",
					i, step.Args, stdout)
			}
		}

		outputs = append(outputs, stdout)
	}

	// Collect filesystem state
	storeFS := make(map[string]bool)
	if tc.ExpectFiles != nil {
		for _, f := range tc.ExpectFiles {
			path := filepath.Join(storeRoot, f)
			_, err := os.Stat(path)
			storeFS[f] = err == nil
			if err != nil {
				t.Errorf("expected file/dir %q not found", f)
			}
		}
	}

	return testResult{outputs: outputs, storeFS: storeFS}
}

func runCmd(t *testing.T, binPath string, args []string, home string) (stdout, stderr string, exitCode int) {
	t.Helper()

	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HOME=%s", home),
		// Ensure consistent behavior across platforms
		"LANG=C",
		"LC_ALL=C",
	)

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("run %s %v: %v", binPath, args, err)
		}
	}
	return
}

func loadTestSuite(t *testing.T) TestSuite {
	t.Helper()
	data, err := os.ReadFile(testdataPath(t, "cases.json"))
	if err != nil {
		t.Fatalf("read test cases: %v", err)
	}
	var suite TestSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatalf("parse test cases: %v", err)
	}
	return suite
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// normalizeConfig replaces the public key hex in the config template with
// a placeholder so configs from different languages can be compared byte-for-byte.
func normalizeConfig(s string) string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# Public key: ") {
			lines = append(lines, "# Public key: <NORMALIZED>")
		} else {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}
