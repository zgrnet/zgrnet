package config

import (
	"os"
	"path/filepath"
	"testing"
)

const validConfig = `
net:
  private_key: "/tmp/test.key"
  tun_ipv4: "100.64.0.1"
  tun_mtu: 1400
  listen_port: 51820

lans:
  - domain: "company.zigor.net"
    pubkey: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    endpoint: "1.2.3.4:51820"

peers:
  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa.zigor.net":
    alias: peer_us
    direct:
      - "us.example.com:51820"
  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567bb.zigor.net":
    alias: peer_jp
    relay:
      - "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa.zigor.net"

inbound_policy:
  default: deny
  revalidate_interval: "5m"
  rules:
    - name: "trusted"
      match:
        pubkey:
          type: any
      services:
        - proto: "*"
          port: "*"
      action: allow

route:
  rules:
    - domain: "*.google.com"
      peer: peer_us
    - domain: "*.nicovideo.jp"
      peer: peer_jp
`

func TestLoadFromBytes_Valid(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(validConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Net
	if cfg.Net.PrivateKeyPath != "/tmp/test.key" {
		t.Errorf("private_key = %q, want %q", cfg.Net.PrivateKeyPath, "/tmp/test.key")
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

	// Lans
	if len(cfg.Lans) != 1 {
		t.Fatalf("len(lans) = %d, want 1", len(cfg.Lans))
	}
	if cfg.Lans[0].Domain != "company.zigor.net" {
		t.Errorf("lan domain = %q", cfg.Lans[0].Domain)
	}

	// Peers
	if len(cfg.Peers) != 2 {
		t.Fatalf("len(peers) = %d, want 2", len(cfg.Peers))
	}
	us := cfg.Peers["abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa.zigor.net"]
	if us.Alias != "peer_us" {
		t.Errorf("peer_us alias = %q", us.Alias)
	}
	if len(us.Direct) != 1 || us.Direct[0] != "us.example.com:51820" {
		t.Errorf("peer_us direct = %v", us.Direct)
	}

	jp := cfg.Peers["abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567bb.zigor.net"]
	if jp.Alias != "peer_jp" {
		t.Errorf("peer_jp alias = %q", jp.Alias)
	}
	if len(jp.Relay) != 1 {
		t.Errorf("peer_jp relay = %v", jp.Relay)
	}

	// InboundPolicy
	if cfg.InboundPolicy.Default != "deny" {
		t.Errorf("inbound default = %q", cfg.InboundPolicy.Default)
	}
	if len(cfg.InboundPolicy.Rules) != 1 {
		t.Fatalf("len(inbound rules) = %d, want 1", len(cfg.InboundPolicy.Rules))
	}

	// Route
	if len(cfg.Route.Rules) != 2 {
		t.Fatalf("len(route rules) = %d, want 2", len(cfg.Route.Rules))
	}
}

func TestLoadFromBytes_InvalidYAML(t *testing.T) {
	_, err := LoadFromBytes([]byte("not: [valid: yaml"))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestValidation_NetConfig(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "missing private_key",
			yaml:    `net: {tun_ipv4: "100.64.0.1"}`,
			wantErr: "private_key is required",
		},
		{
			name:    "missing tun_ipv4",
			yaml:    `net: {private_key: "/tmp/k"}`,
			wantErr: "tun_ipv4 is required",
		},
		{
			name:    "invalid IP",
			yaml:    `net: {private_key: "/tmp/k", tun_ipv4: "not-an-ip"}`,
			wantErr: "not a valid IP",
		},
		{
			name:    "not CGNAT",
			yaml:    `net: {private_key: "/tmp/k", tun_ipv4: "192.168.1.1"}`,
			wantErr: "not in CGNAT range",
		},
		{
			name:    "IPv6 not allowed",
			yaml:    `net: {private_key: "/tmp/k", tun_ipv4: "::1"}`,
			wantErr: "not an IPv4 address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadFromBytes([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected error")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidation_PeerDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"valid", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.zigor.net", false},
		{"short hex", "abcd.zigor.net", false},
		{"not zigor.net", "abc.example.com", true},
		{"no prefix", ".zigor.net", true},
		{"invalid hex", "xyz123.zigor.net", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePeerDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePeerDomain(%q) = %v, wantErr %v", tt.domain, err, tt.wantErr)
			}
		})
	}
}

func TestValidation_InboundPolicy(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "invalid default",
			yaml: `
net: {private_key: "/tmp/k", tun_ipv4: "100.64.0.1"}
inbound_policy:
  default: maybe`,
			wantErr: "must be \"allow\" or \"deny\"",
		},
		{
			name: "rule missing name",
			yaml: `
net: {private_key: "/tmp/k", tun_ipv4: "100.64.0.1"}
inbound_policy:
  rules:
    - match: {pubkey: {type: any}}
      action: allow
      services: [{proto: "*", port: "*"}]`,
			wantErr: "name is required",
		},
		{
			name: "invalid match type",
			yaml: `
net: {private_key: "/tmp/k", tun_ipv4: "100.64.0.1"}
inbound_policy:
  rules:
    - name: test
      match: {pubkey: {type: magic}}
      action: allow
      services: [{proto: "*", port: "*"}]`,
			wantErr: "not supported",
		},
		{
			name: "whitelist missing path",
			yaml: `
net: {private_key: "/tmp/k", tun_ipv4: "100.64.0.1"}
inbound_policy:
  rules:
    - name: test
      match: {pubkey: {type: whitelist}}
      action: allow
      services: [{proto: "*", port: "*"}]`,
			wantErr: "path is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadFromBytes([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected error")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidation_Route(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "missing domain",
			yaml: `
net: {private_key: "/tmp/k", tun_ipv4: "100.64.0.1"}
route:
  rules:
    - peer: peer_us`,
			wantErr: "domain is required",
		},
		{
			name: "missing peer",
			yaml: `
net: {private_key: "/tmp/k", tun_ipv4: "100.64.0.1"}
route:
  rules:
    - domain: "google.com"`,
			wantErr: "peer is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadFromBytes([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected error")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoad_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(validConfig), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Net.TunIPv4 != "100.64.0.1" {
		t.Errorf("tun_ipv4 = %q", cfg.Net.TunIPv4)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && containsImpl(s, sub)
}

func containsImpl(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
