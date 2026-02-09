// Package config handles zgrnetd configuration file parsing and validation.
//
// The configuration is a YAML file with the following top-level sections:
//   - net: Global settings (private key, TUN IP, MTU, listen port)
//   - peers: Manually configured direct peers
//   - inbound_policy: Inbound access control rules
//   - route: Outbound routing rules (domain -> peer)
//
// Example:
//
//	net:
//	  private_key: "private.key"
//	  tun_ipv4: "100.64.0.1"
//	  tun_mtu: 1400
//	  listen_port: 51820
//	  data_dir: "./data"
//	peers:
//	  "abc123...zigor.net":
//	    alias: peer_us
//	    direct:
//	      - "us.example.com:51820"
package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for zgrnetd.
type Config struct {
	Net           NetConfig             `yaml:"net"`
	Peers         map[string]PeerConfig `yaml:"peers"`
	InboundPolicy InboundPolicy         `yaml:"inbound_policy"`
	Route         RouteConfig           `yaml:"route"`
}

// NetConfig holds global network settings.
type NetConfig struct {
	// PrivateKey is the path to the Noise private key file.
	// Relative paths are resolved against the config file's directory.
	PrivateKey string `yaml:"private_key"`

	// TunIPv4 is the local IPv4 address for the TUN device.
	// Must be in the CGNAT range (100.64.0.0/10).
	TunIPv4 string `yaml:"tun_ipv4"`

	// TunMTU is the Maximum Transmission Unit. Default: 1400.
	TunMTU int `yaml:"tun_mtu"`

	// ListenPort is the UDP port to listen on. Default: 51820.
	ListenPort int `yaml:"listen_port"`

	// DataDir is the directory for runtime data (state, cache).
	// Relative paths are resolved against the config file's directory.
	// Default: "./data"
	DataDir string `yaml:"data_dir"`
}

// PeerConfig holds configuration for a single peer.
type PeerConfig struct {
	// Alias is a short name for the peer (used in route rules).
	Alias string `yaml:"alias"`

	// Direct is a list of direct endpoint addresses ("host:port").
	Direct []string `yaml:"direct"`

	// Relay is a list of relay peer domains to use for this peer.
	Relay []string `yaml:"relay"`
}

// InboundPolicy controls which peers can connect and what services they can access.
type InboundPolicy struct {
	// Default is the default action: "allow" or "deny".
	Default string `yaml:"default"`

	// Rules is an ordered list of inbound rules.
	Rules []InboundRule `yaml:"rules"`
}

// InboundRule is a single inbound access control rule.
type InboundRule struct {
	Name     string          `yaml:"name"`
	Match    MatchConfig     `yaml:"match"`
	Services []ServiceConfig `yaml:"services"`
	Action   string          `yaml:"action"`
}

// MatchConfig defines how to match a peer for an inbound rule.
type MatchConfig struct {
	Pubkey PubkeyMatch `yaml:"pubkey"`
}

// PubkeyMatch specifies how to match peer public keys.
type PubkeyMatch struct {
	// Type is the match type: "whitelist" or "zgrlan".
	Type string `yaml:"type"`

	// Path is the path to a file containing allowed pubkeys (for "whitelist" type).
	// Relative paths are resolved against the config file's directory.
	Path string `yaml:"path"`

	// Peer is the zgrlan peer domain (for "zgrlan" type).
	Peer string `yaml:"peer"`
}

// ServiceConfig defines a service (protocol + port) for inbound rules.
type ServiceConfig struct {
	Proto string `yaml:"proto"`
	Port  string `yaml:"port"`
}

// RouteConfig holds outbound routing rules.
type RouteConfig struct {
	Rules []RouteRule `yaml:"rules"`
}

// RouteRule matches domains to a target peer for outbound routing.
type RouteRule struct {
	// Domain is a glob pattern (e.g., "*.google.com").
	Domain string `yaml:"domain"`

	// DomainList is a path to a file with one domain per line.
	// Relative paths are resolved against the config file's directory.
	DomainList string `yaml:"domain_list"`

	// Peer is the target peer alias or domain.
	Peer string `yaml:"peer"`
}

// Load reads and parses a YAML config file.
// Relative paths in the config are resolved against the config file's directory.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	// Resolve relative paths against config directory.
	dir := filepath.Dir(path)
	if absDir, err := filepath.Abs(dir); err == nil {
		dir = absDir
	}
	cfg.ResolveRelativePaths(dir)

	return cfg, nil
}

// Parse parses a YAML config from raw bytes.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	return &cfg, nil
}

// ResolveRelativePaths resolves relative file paths in the config
// against the given context directory (typically the config file's directory).
func (c *Config) ResolveRelativePaths(contextDir string) {
	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(contextDir, p)
	}

	c.Net.PrivateKey = resolve(c.Net.PrivateKey)
	c.Net.DataDir = resolve(c.Net.DataDir)

	for i := range c.InboundPolicy.Rules {
		r := &c.InboundPolicy.Rules[i]
		r.Match.Pubkey.Path = resolve(r.Match.Pubkey.Path)
	}

	for i := range c.Route.Rules {
		r := &c.Route.Rules[i]
		r.DomainList = resolve(r.DomainList)
	}
}

// ApplyDefaults fills in default values for unset fields.
func (c *Config) ApplyDefaults() {
	if c.Net.TunMTU == 0 {
		c.Net.TunMTU = 1400
	}
	if c.Net.ListenPort == 0 {
		c.Net.ListenPort = 51820
	}
	if c.Net.DataDir == "" {
		c.Net.DataDir = "./data"
	}
	if c.Net.PrivateKey == "" {
		c.Net.PrivateKey = "private.key"
	}
	if c.InboundPolicy.Default == "" {
		c.InboundPolicy.Default = "deny"
	}
}

// Validate checks the configuration for errors.
// Call ApplyDefaults before Validate if you want defaults to be set.
func (c *Config) Validate() error {
	// net.private_key must be set
	if c.Net.PrivateKey == "" {
		return fmt.Errorf("config: net.private_key is required")
	}

	// net.tun_ipv4 must be a valid CGNAT address
	if c.Net.TunIPv4 == "" {
		return fmt.Errorf("config: net.tun_ipv4 is required")
	}
	if err := validateCGNATAddress(c.Net.TunIPv4); err != nil {
		return fmt.Errorf("config: net.tun_ipv4: %w", err)
	}

	// net.tun_mtu range
	if c.Net.TunMTU < 576 || c.Net.TunMTU > 65535 {
		return fmt.Errorf("config: net.tun_mtu must be between 576 and 65535, got %d", c.Net.TunMTU)
	}

	// net.listen_port range
	if c.Net.ListenPort < 0 || c.Net.ListenPort > 65535 {
		return fmt.Errorf("config: net.listen_port must be between 0 and 65535, got %d", c.Net.ListenPort)
	}

	// Validate peers
	for domain, p := range c.Peers {
		if err := validatePeerDomain(domain); err != nil {
			return fmt.Errorf("config: peers[%q]: %w", domain, err)
		}
		for _, ep := range p.Direct {
			if _, _, err := net.SplitHostPort(ep); err != nil {
				return fmt.Errorf("config: peers[%q].direct: invalid endpoint %q: %w", domain, ep, err)
			}
		}
	}

	// Validate inbound_policy
	switch c.InboundPolicy.Default {
	case "allow", "deny":
		// ok
	default:
		return fmt.Errorf("config: inbound_policy.default must be \"allow\" or \"deny\", got %q", c.InboundPolicy.Default)
	}

	for i, r := range c.InboundPolicy.Rules {
		if r.Name == "" {
			return fmt.Errorf("config: inbound_policy.rules[%d]: name is required", i)
		}
		switch r.Action {
		case "allow", "deny":
			// ok
		default:
			return fmt.Errorf("config: inbound_policy.rules[%d] (%s): action must be \"allow\" or \"deny\"", i, r.Name)
		}
	}

	// Validate route rules
	for i, r := range c.Route.Rules {
		if r.Domain == "" && r.DomainList == "" {
			return fmt.Errorf("config: route.rules[%d]: domain or domain_list is required", i)
		}
		if r.Peer == "" {
			return fmt.Errorf("config: route.rules[%d]: peer is required", i)
		}
	}

	return nil
}

// PubkeyFromDomain extracts the hex-encoded public key from a peer domain.
// Format: "{first32hex}.{last32hex}.zigor.net" or plain 64-char hex.
func PubkeyFromDomain(domain string) (string, error) {
	domain = strings.ToLower(domain)

	// Strip .zigor.net suffix if present
	const suffix = ".zigor.net"
	subdomain := domain
	if strings.HasSuffix(domain, suffix) {
		subdomain = strings.TrimSuffix(domain, suffix)
	}

	// Try "first32.last32" format
	if parts := strings.SplitN(subdomain, ".", 2); len(parts) == 2 {
		combined := parts[0] + parts[1]
		if len(combined) == 64 && isHexString(combined) {
			return combined, nil
		}
	}

	// Try plain 64-char hex
	if len(subdomain) == 64 && isHexString(subdomain) {
		return subdomain, nil
	}

	return "", fmt.Errorf("config: invalid peer domain %q: expected hex pubkey", domain)
}

// validateCGNATAddress checks that the IP is in the CGNAT range (100.64.0.0/10).
func validateCGNATAddress(addr string) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", addr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv6 not supported for TUN IP: %s", addr)
	}
	// CGNAT range: 100.64.0.0/10 → first byte 100, second byte 64-127
	if ip4[0] != 100 || ip4[1] < 64 || ip4[1] > 127 {
		return fmt.Errorf("%s is not in CGNAT range (100.64.0.0/10)", addr)
	}
	return nil
}

// validatePeerDomain validates a peer domain key in the peers map.
// Accepts "{hex}.zigor.net" or plain 64-char hex pubkey strings.
func validatePeerDomain(domain string) error {
	_, err := PubkeyFromDomain(domain)
	return err
}

// isHexString returns true if s contains only hex characters.
func isHexString(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && len(s)%2 == 0
}
