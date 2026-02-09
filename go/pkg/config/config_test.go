package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse_Minimal(t *testing.T) {
	yaml := `
net:
  private_key: "private.key"
  tun_ipv4: "100.64.0.1"
  tun_mtu: 1400
  listen_port: 51820
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Net.PrivateKey != "private.key" {
		t.Errorf("private_key = %q, want %q", cfg.Net.PrivateKey, "private.key")
	}
	if cfg.Net.TunIPv4 != "100.64.0.1" {
		t.Errorf("tun_ipv4 = %q, want %q", cfg.Net.TunIPv4, "100.64.0.1")
	}
	if cfg.Net.TunMTU != 1400 {
		t.Errorf("tun_mtu = %d, want %d", cfg.Net.TunMTU, 1400)
	}
	if cfg.Net.ListenPort != 51820 {
		t.Errorf("listen_port = %d, want %d", cfg.Net.ListenPort, 51820)
	}
}

func TestParse_FullConfig(t *testing.T) {
	yaml := `
net:
  private_key: "/etc/zgrnet/private.key"
  tun_ipv4: "100.64.0.1"
  tun_mtu: 1400
  listen_port: 51820
  data_dir: "/var/lib/zgrnet"

peers:
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.zigor.net":
    alias: peer_us
    direct:
      - "us.example.com:51820"
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.zigor.net":
    alias: peer_jp
    relay:
      - "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.zigor.net"

inbound_policy:
  default: deny
  rules:
    - name: "trusted"
      match:
        pubkey:
          type: whitelist
          path: "/etc/zgrnet/trusted.txt"
      services:
        - proto: "*"
          port: "*"
      action: allow

route:
  rules:
    - domain: "*.google.com"
      peer: peer_us
    - domain_list: "/etc/zgrnet/gfwlist.txt"
      peer: peer_us
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Peers) != 2 {
		t.Fatalf("peers count = %d, want 2", len(cfg.Peers))
	}

	us := cfg.Peers["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.zigor.net"]
	if us.Alias != "peer_us" {
		t.Errorf("peer_us alias = %q", us.Alias)
	}
	if len(us.Direct) != 1 || us.Direct[0] != "us.example.com:51820" {
		t.Errorf("peer_us direct = %v", us.Direct)
	}

	jp := cfg.Peers["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.zigor.net"]
	if jp.Alias != "peer_jp" {
		t.Errorf("peer_jp alias = %q", jp.Alias)
	}
	if len(jp.Relay) != 1 {
		t.Errorf("peer_jp relay = %v", jp.Relay)
	}

	if cfg.InboundPolicy.Default != "deny" {
		t.Errorf("inbound default = %q", cfg.InboundPolicy.Default)
	}
	if len(cfg.InboundPolicy.Rules) != 1 {
		t.Fatalf("inbound rules count = %d", len(cfg.InboundPolicy.Rules))
	}
	if cfg.InboundPolicy.Rules[0].Name != "trusted" {
		t.Errorf("rule name = %q", cfg.InboundPolicy.Rules[0].Name)
	}

	if len(cfg.Route.Rules) != 2 {
		t.Fatalf("route rules count = %d", len(cfg.Route.Rules))
	}
	if cfg.Route.Rules[0].Domain != "*.google.com" {
		t.Errorf("route[0] domain = %q", cfg.Route.Rules[0].Domain)
	}
}

func TestParse_InvalidYAML(t *testing.T) {
	_, err := Parse([]byte("{{invalid"))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyDefaults()

	if cfg.Net.TunMTU != 1400 {
		t.Errorf("default tun_mtu = %d, want 1400", cfg.Net.TunMTU)
	}
	if cfg.Net.ListenPort != 51820 {
		t.Errorf("default listen_port = %d, want 51820", cfg.Net.ListenPort)
	}
	if cfg.Net.DataDir != "./data" {
		t.Errorf("default data_dir = %q, want %q", cfg.Net.DataDir, "./data")
	}
	if cfg.Net.PrivateKey != "private.key" {
		t.Errorf("default private_key = %q, want %q", cfg.Net.PrivateKey, "private.key")
	}
	if cfg.InboundPolicy.Default != "deny" {
		t.Errorf("default inbound = %q, want %q", cfg.InboundPolicy.Default, "deny")
	}
}

func TestApplyDefaults_NoOverwrite(t *testing.T) {
	cfg := &Config{
		Net: NetConfig{
			TunMTU:     1500,
			ListenPort: 12345,
			DataDir:    "/custom",
			PrivateKey: "/custom/key",
		},
		InboundPolicy: InboundPolicy{Default: "allow"},
	}
	cfg.ApplyDefaults()

	if cfg.Net.TunMTU != 1500 {
		t.Errorf("overwritten tun_mtu = %d", cfg.Net.TunMTU)
	}
	if cfg.Net.ListenPort != 12345 {
		t.Errorf("overwritten listen_port = %d", cfg.Net.ListenPort)
	}
	if cfg.Net.DataDir != "/custom" {
		t.Errorf("overwritten data_dir = %q", cfg.Net.DataDir)
	}
	if cfg.InboundPolicy.Default != "allow" {
		t.Errorf("overwritten inbound = %q", cfg.InboundPolicy.Default)
	}
}

func TestValidate_Valid(t *testing.T) {
	cfg := &Config{
		Net: NetConfig{
			PrivateKey: "/etc/zgrnet/private.key",
			TunIPv4:    "100.64.0.1",
			TunMTU:     1400,
			ListenPort: 51820,
		},
		InboundPolicy: InboundPolicy{Default: "deny"},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_MissingPrivateKey(t *testing.T) {
	cfg := &Config{
		Net: NetConfig{
			TunIPv4:    "100.64.0.1",
			TunMTU:     1400,
			ListenPort: 51820,
		},
		InboundPolicy: InboundPolicy{Default: "deny"},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "private_key") {
		t.Errorf("expected private_key error, got: %v", err)
	}
}

func TestValidate_MissingTunIPv4(t *testing.T) {
	cfg := &Config{
		Net: NetConfig{
			PrivateKey: "key",
			TunMTU:     1400,
			ListenPort: 51820,
		},
		InboundPolicy: InboundPolicy{Default: "deny"},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "tun_ipv4") {
		t.Errorf("expected tun_ipv4 error, got: %v", err)
	}
}

func TestValidate_InvalidCGNAT(t *testing.T) {
	tests := []struct {
		ip   string
		fail bool
	}{
		{"100.64.0.1", false},
		{"100.127.255.254", false},
		{"100.64.0.0", false},
		{"192.168.1.1", true},  // not CGNAT
		{"10.0.0.1", true},     // not CGNAT
		{"100.128.0.1", true},  // above CGNAT range
		{"100.63.255.1", true}, // below CGNAT range
		{"invalid", true},
		{"::1", true}, // IPv6
	}
	for _, tc := range tests {
		cfg := &Config{
			Net: NetConfig{
				PrivateKey: "key",
				TunIPv4:    tc.ip,
				TunMTU:     1400,
				ListenPort: 51820,
			},
			InboundPolicy: InboundPolicy{Default: "deny"},
		}
		err := cfg.Validate()
		if tc.fail && err == nil {
			t.Errorf("IP %q: expected validation error", tc.ip)
		}
		if !tc.fail && err != nil {
			t.Errorf("IP %q: unexpected error: %v", tc.ip, err)
		}
	}
}

func TestValidate_MTURange(t *testing.T) {
	base := func(mtu int) *Config {
		return &Config{
			Net: NetConfig{
				PrivateKey: "key",
				TunIPv4:    "100.64.0.1",
				TunMTU:     mtu,
				ListenPort: 51820,
			},
			InboundPolicy: InboundPolicy{Default: "deny"},
		}
	}

	if err := base(576).Validate(); err != nil {
		t.Errorf("MTU 576 should be valid: %v", err)
	}
	if err := base(65535).Validate(); err != nil {
		t.Errorf("MTU 65535 should be valid: %v", err)
	}
	if err := base(575).Validate(); err == nil {
		t.Error("MTU 575 should be invalid")
	}
	if err := base(65536).Validate(); err == nil {
		t.Error("MTU 65536 should be invalid")
	}
}

func TestValidate_InboundPolicyDefault(t *testing.T) {
	base := func(def string) *Config {
		return &Config{
			Net: NetConfig{
				PrivateKey: "key",
				TunIPv4:    "100.64.0.1",
				TunMTU:     1400,
				ListenPort: 51820,
			},
			InboundPolicy: InboundPolicy{Default: def},
		}
	}

	if err := base("allow").Validate(); err != nil {
		t.Errorf("allow should be valid: %v", err)
	}
	if err := base("deny").Validate(); err != nil {
		t.Errorf("deny should be valid: %v", err)
	}
	if err := base("drop").Validate(); err == nil {
		t.Error("drop should be invalid")
	}
}

func TestValidate_PeerDomain(t *testing.T) {
	validPeer := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.zigor.net"
	base := func(peers map[string]PeerConfig) *Config {
		return &Config{
			Net: NetConfig{
				PrivateKey: "key",
				TunIPv4:    "100.64.0.1",
				TunMTU:     1400,
				ListenPort: 51820,
			},
			Peers:         peers,
			InboundPolicy: InboundPolicy{Default: "deny"},
		}
	}

	// Valid peer domain
	if err := base(map[string]PeerConfig{
		validPeer: {Alias: "ok", Direct: []string{"1.2.3.4:51820"}},
	}).Validate(); err != nil {
		t.Errorf("valid peer: %v", err)
	}

	// Invalid peer domain
	if err := base(map[string]PeerConfig{
		"bad-domain": {Alias: "bad"},
	}).Validate(); err == nil {
		t.Error("invalid peer domain should fail")
	}

	// Invalid endpoint
	if err := base(map[string]PeerConfig{
		validPeer: {Alias: "ok", Direct: []string{"no-port"}},
	}).Validate(); err == nil {
		t.Error("invalid endpoint should fail")
	}
}

func TestValidate_RouteRules(t *testing.T) {
	base := func(rules []RouteRule) *Config {
		return &Config{
			Net: NetConfig{
				PrivateKey: "key",
				TunIPv4:    "100.64.0.1",
				TunMTU:     1400,
				ListenPort: 51820,
			},
			InboundPolicy: InboundPolicy{Default: "deny"},
			Route:         RouteConfig{Rules: rules},
		}
	}

	// Valid rules
	if err := base([]RouteRule{
		{Domain: "*.google.com", Peer: "peer_us"},
		{DomainList: "/etc/gfwlist.txt", Peer: "peer_us"},
	}).Validate(); err != nil {
		t.Errorf("valid routes: %v", err)
	}

	// Missing domain and domain_list
	if err := base([]RouteRule{
		{Peer: "peer_us"},
	}).Validate(); err == nil {
		t.Error("route without domain should fail")
	}

	// Missing peer
	if err := base([]RouteRule{
		{Domain: "*.google.com"},
	}).Validate(); err == nil {
		t.Error("route without peer should fail")
	}
}

func TestValidate_InboundRules(t *testing.T) {
	base := func(rules []InboundRule) *Config {
		return &Config{
			Net: NetConfig{
				PrivateKey: "key",
				TunIPv4:    "100.64.0.1",
				TunMTU:     1400,
				ListenPort: 51820,
			},
			InboundPolicy: InboundPolicy{
				Default: "deny",
				Rules:   rules,
			},
		}
	}

	// Missing name
	if err := base([]InboundRule{
		{Action: "allow"},
	}).Validate(); err == nil {
		t.Error("rule without name should fail")
	}

	// Invalid action
	if err := base([]InboundRule{
		{Name: "test", Action: "drop"},
	}).Validate(); err == nil {
		t.Error("invalid action should fail")
	}

	// Valid rule
	if err := base([]InboundRule{
		{Name: "test", Action: "allow"},
	}).Validate(); err != nil {
		t.Errorf("valid rule: %v", err)
	}
}

func TestResolveRelativePaths(t *testing.T) {
	cfg := &Config{
		Net: NetConfig{
			PrivateKey: "private.key",
			DataDir:    "./data",
		},
		InboundPolicy: InboundPolicy{
			Rules: []InboundRule{
				{Match: MatchConfig{Pubkey: PubkeyMatch{Path: "trusted.txt"}}},
			},
		},
		Route: RouteConfig{
			Rules: []RouteRule{
				{DomainList: "gfwlist.txt", Peer: "p"},
			},
		},
	}

	cfg.ResolveRelativePaths("/etc/zgrnet")

	if cfg.Net.PrivateKey != "/etc/zgrnet/private.key" {
		t.Errorf("private_key = %q", cfg.Net.PrivateKey)
	}
	if cfg.Net.DataDir != "/etc/zgrnet/data" {
		t.Errorf("data_dir = %q", cfg.Net.DataDir)
	}
	if cfg.InboundPolicy.Rules[0].Match.Pubkey.Path != "/etc/zgrnet/trusted.txt" {
		t.Errorf("pubkey path = %q", cfg.InboundPolicy.Rules[0].Match.Pubkey.Path)
	}
	if cfg.Route.Rules[0].DomainList != "/etc/zgrnet/gfwlist.txt" {
		t.Errorf("domain_list = %q", cfg.Route.Rules[0].DomainList)
	}
}

func TestResolveRelativePaths_AbsoluteUnchanged(t *testing.T) {
	cfg := &Config{
		Net: NetConfig{
			PrivateKey: "/abs/private.key",
			DataDir:    "/abs/data",
		},
	}
	cfg.ResolveRelativePaths("/context")

	if cfg.Net.PrivateKey != "/abs/private.key" {
		t.Errorf("absolute path changed: %q", cfg.Net.PrivateKey)
	}
	if cfg.Net.DataDir != "/abs/data" {
		t.Errorf("absolute path changed: %q", cfg.Net.DataDir)
	}
}

func TestPubkeyFromDomain(t *testing.T) {
	hex64 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	tests := []struct {
		domain  string
		want    string
		wantErr bool
	}{
		// Split format: first32.last32.zigor.net
		{hex64[:32] + "." + hex64[32:] + ".zigor.net", hex64, false},
		// Plain 64-char hex (no .zigor.net)
		{hex64, hex64, false},
		// Invalid
		{"bad.zigor.net", "", true},
		{"too-short.zigor.net", "", true},
		{"", "", true},
	}

	for _, tc := range tests {
		got, err := PubkeyFromDomain(tc.domain)
		if tc.wantErr {
			if err == nil {
				t.Errorf("PubkeyFromDomain(%q): expected error", tc.domain)
			}
			continue
		}
		if err != nil {
			t.Errorf("PubkeyFromDomain(%q): %v", tc.domain, err)
			continue
		}
		if got != tc.want {
			t.Errorf("PubkeyFromDomain(%q) = %q, want %q", tc.domain, got, tc.want)
		}
	}
}

func TestLoad_File(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `
net:
  private_key: "private.key"
  tun_ipv4: "100.64.0.1"
  tun_mtu: 1400
  listen_port: 51820
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}

	// private_key should be resolved relative to config dir
	want := filepath.Join(dir, "private.key")
	if cfg.Net.PrivateKey != want {
		t.Errorf("private_key = %q, want %q", cfg.Net.PrivateKey, want)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}
