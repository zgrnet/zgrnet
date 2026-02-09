package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// testVectorDir returns the path to the test vectors directory.
// Works with both native `go test` and `bazel test`.
func testVectorDir(t *testing.T) string {
	t.Helper()

	// Try Bazel runfiles path first
	if wd, err := os.Getwd(); err == nil {
		bazelPath := filepath.Join(wd, "tests", "vectors")
		if _, err := os.Stat(bazelPath); err == nil {
			return bazelPath
		}
	}

	// Fallback: walk up from source file
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	root := filepath.Join(dir, "..", "..", "..", "tests", "vectors")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("test vectors not found at %s", root)
	}
	return root
}

func TestInterop_LoadFullConfig(t *testing.T) {
	vectorDir := testVectorDir(t)
	yamlPath := filepath.Join(vectorDir, "config_full.yaml")

	cfg, err := Load(yamlPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// Verify net
	if cfg.Net.PrivateKeyPath != "/etc/zgrnet/private.key" {
		t.Errorf("private_key = %q", cfg.Net.PrivateKeyPath)
	}
	if cfg.Net.TunIPv4 != "100.64.0.1" {
		t.Errorf("tun_ipv4 = %q", cfg.Net.TunIPv4)
	}
	if cfg.Net.TunMTU != 1400 {
		t.Errorf("tun_mtu = %d", cfg.Net.TunMTU)
	}
	if cfg.Net.ListenPort != 51820 {
		t.Errorf("listen_port = %d", cfg.Net.ListenPort)
	}

	// Verify lans
	if len(cfg.Lans) != 1 {
		t.Fatalf("lans count = %d, want 1", len(cfg.Lans))
	}
	if cfg.Lans[0].Domain != "company.zigor.net" {
		t.Errorf("lan domain = %q", cfg.Lans[0].Domain)
	}
	if cfg.Lans[0].Pubkey != "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" {
		t.Errorf("lan pubkey = %q", cfg.Lans[0].Pubkey)
	}

	// Verify peers
	if len(cfg.Peers) != 2 {
		t.Fatalf("peers count = %d, want 2", len(cfg.Peers))
	}

	us := cfg.Peers["abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa.zigor.net"]
	if us.Alias != "peer_us" {
		t.Errorf("peer_us alias = %q", us.Alias)
	}
	if len(us.Direct) != 2 {
		t.Errorf("peer_us direct count = %d, want 2", len(us.Direct))
	}

	jp := cfg.Peers["abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567bb.zigor.net"]
	if jp.Alias != "peer_jp" {
		t.Errorf("peer_jp alias = %q", jp.Alias)
	}
	if len(jp.Relay) != 1 {
		t.Errorf("peer_jp relay count = %d, want 1", len(jp.Relay))
	}

	// Verify inbound policy
	if cfg.InboundPolicy.Default != "deny" {
		t.Errorf("inbound default = %q", cfg.InboundPolicy.Default)
	}
	if cfg.InboundPolicy.RevalidateInterval != "5m" {
		t.Errorf("revalidate_interval = %q", cfg.InboundPolicy.RevalidateInterval)
	}
	if len(cfg.InboundPolicy.Rules) != 2 {
		t.Fatalf("inbound rules count = %d, want 2", len(cfg.InboundPolicy.Rules))
	}
	if cfg.InboundPolicy.Rules[0].Name != "trusted-users" {
		t.Errorf("rule[0] name = %q", cfg.InboundPolicy.Rules[0].Name)
	}
	if cfg.InboundPolicy.Rules[1].Match.Pubkey.Type != "zgrlan" {
		t.Errorf("rule[1] match type = %q", cfg.InboundPolicy.Rules[1].Match.Pubkey.Type)
	}

	// Verify route
	if len(cfg.Route.Rules) != 4 {
		t.Fatalf("route rules count = %d, want 4", len(cfg.Route.Rules))
	}
	if cfg.Route.Rules[0].Domain != "*.google.com" {
		t.Errorf("route[0] domain = %q", cfg.Route.Rules[0].Domain)
	}
	if cfg.Route.Rules[3].Domain != "example.com" {
		t.Errorf("route[3] domain = %q", cfg.Route.Rules[3].Domain)
	}
}
