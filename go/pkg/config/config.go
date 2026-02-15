// Package config provides configuration management for zgrnet.
//
// It handles parsing, validation, diffing, and hot-reloading of configuration
// files. The config describes the "desired state" of the system; consumers
// receive incremental diffs and reconcile accordingly.
//
// Go and Rust use YAML format; Zig uses JSON. The data structures are identical.
package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration structure.
type Config struct {
	Net           NetConfig             `yaml:"net" json:"net"`
	Lans          []LanConfig           `yaml:"lans" json:"lans"`
	Peers         map[string]PeerConfig `yaml:"peers" json:"peers"`
	InboundPolicy InboundPolicy         `yaml:"inbound_policy" json:"inbound_policy"`
	Route         RouteConfig           `yaml:"route" json:"route"`
}

// NetConfig holds global network settings. Changes require a restart.
type NetConfig struct {
	// PrivateKeyPath is the path to the Noise Protocol private key file.
	PrivateKeyPath string `yaml:"private_key" json:"private_key"`

	// TunIPv4 is the local TUN device IPv4 address.
	// Must be in the CGNAT range (100.64.0.0/10).
	TunIPv4 string `yaml:"tun_ipv4" json:"tun_ipv4"`

	// TunMTU is the TUN device MTU. Default: 1400.
	TunMTU int `yaml:"tun_mtu" json:"tun_mtu"`

	// ListenPort is the UDP listen port. 0 for random.
	ListenPort int `yaml:"listen_port" json:"listen_port"`
}

// LanConfig holds the configuration for a zgrlan node.
type LanConfig struct {
	Domain   string `yaml:"domain" json:"domain"`
	Pubkey   string `yaml:"pubkey" json:"pubkey"`
	Endpoint string `yaml:"endpoint" json:"endpoint"`
}

// PeerConfig holds the configuration for a manually configured peer.
type PeerConfig struct {
	Alias  string   `yaml:"alias" json:"alias"`
	Direct []string `yaml:"direct" json:"direct"`
	Relay  []string `yaml:"relay" json:"relay"`
	Labels []string `yaml:"labels" json:"labels"`
}

// InboundPolicy controls who can connect and what services they can access.
type InboundPolicy struct {
	// Default action when no rule matches: "allow" or "deny".
	Default string `yaml:"default" json:"default"`

	// RevalidateInterval is how often existing connections are re-checked.
	// Format: Go duration string (e.g., "5m", "1h").
	RevalidateInterval string `yaml:"revalidate_interval" json:"revalidate_interval"`

	// Rules are evaluated in order; first match wins.
	Rules []InboundRule `yaml:"rules" json:"rules"`
}

// InboundRule is a single inbound policy rule.
type InboundRule struct {
	Name     string          `yaml:"name" json:"name"`
	Match    MatchConfig     `yaml:"match" json:"match"`
	Services []ServiceConfig `yaml:"services" json:"services"`
	Action   string          `yaml:"action" json:"action"`
}

// MatchConfig defines how to match a peer's identity.
// A rule can match by pubkey (existing), by labels, or both.
// When both are specified, the peer must match the pubkey condition AND have matching labels.
type MatchConfig struct {
	Pubkey PubkeyMatch `yaml:"pubkey" json:"pubkey"`

	// Labels is a list of label patterns the peer must have at least one of.
	// Supports exact match ("host.zigor.net/trusted") and
	// wildcard match ("company.zigor.net/*").
	// Empty means no label matching (pubkey match only).
	Labels []string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// PubkeyMatch defines the pubkey matching strategy.
type PubkeyMatch struct {
	// Type is the matching strategy.
	// Supported: "whitelist", "zgrlan", "any".
	// Future: "solana", "database", "http".
	Type string `yaml:"type" json:"type"`

	// Path is the file path for whitelist type (one pubkey per line).
	Path string `yaml:"path,omitempty" json:"path,omitempty"`

	// Peer is the zgrlan peer domain for zgrlan type.
	Peer string `yaml:"peer,omitempty" json:"peer,omitempty"`
}

// ServiceConfig defines which network services are accessible.
type ServiceConfig struct {
	// Proto is the protocol: "*", "tcp", "udp", "icmp".
	Proto string `yaml:"proto" json:"proto"`

	// Port is the port specification: "*", "80", "80,443", "8000-9000".
	Port string `yaml:"port" json:"port"`
}

// RouteConfig holds outbound routing rules.
type RouteConfig struct {
	Rules []RouteRule `yaml:"rules" json:"rules"`
}

// RouteRule defines how traffic for specific domains is routed.
// All domain matching is suffix-based: "google.com" matches google.com
// and all its subdomains. "*.google.com" is accepted and treated identically.
// When multiple rules match, the longest suffix wins.
type RouteRule struct {
	// Domain is a domain suffix: "google.com", "*.google.com" (equivalent).
	Domain string `yaml:"domain" json:"domain"`

	// Peer is the target peer alias or domain.
	Peer string `yaml:"peer" json:"peer"`
}

// Load reads and parses a YAML config file from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read file %q: %w", path, err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes parses a YAML config from raw bytes.
func LoadFromBytes(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// CGNAT is the Carrier-Grade NAT range: 100.64.0.0/10.
var cgnatNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

// Validate checks the configuration for correctness.
func (c *Config) Validate() error {
	if err := c.Net.validate(); err != nil {
		return fmt.Errorf("config: net: %w", err)
	}
	for i, lan := range c.Lans {
		if err := lan.validate(); err != nil {
			return fmt.Errorf("config: lans[%d]: %w", i, err)
		}
	}
	for domain, peer := range c.Peers {
		if err := validatePeerDomain(domain); err != nil {
			return fmt.Errorf("config: peers[%q]: %w", domain, err)
		}
		if err := peer.validate(); err != nil {
			return fmt.Errorf("config: peers[%q]: %w", domain, err)
		}
	}
	if err := c.InboundPolicy.validate(); err != nil {
		return fmt.Errorf("config: inbound_policy: %w", err)
	}
	if err := c.Route.validate(); err != nil {
		return fmt.Errorf("config: route: %w", err)
	}
	return nil
}

func (n *NetConfig) validate() error {
	if n.PrivateKeyPath == "" {
		return fmt.Errorf("private_key is required")
	}
	if n.TunIPv4 == "" {
		return fmt.Errorf("tun_ipv4 is required")
	}
	ip := net.ParseIP(n.TunIPv4)
	if ip == nil {
		return fmt.Errorf("tun_ipv4 %q is not a valid IP address", n.TunIPv4)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("tun_ipv4 %q is not an IPv4 address", n.TunIPv4)
	}
	if !cgnatNet.Contains(ip4) {
		return fmt.Errorf("tun_ipv4 %q is not in CGNAT range (100.64.0.0/10)", n.TunIPv4)
	}
	if n.TunMTU < 0 || n.TunMTU > 65535 {
		return fmt.Errorf("tun_mtu %d is out of range [0, 65535]", n.TunMTU)
	}
	if n.ListenPort < 0 || n.ListenPort > 65535 {
		return fmt.Errorf("listen_port %d is out of range [0, 65535]", n.ListenPort)
	}
	return nil
}

func (l *LanConfig) validate() error {
	if l.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if l.Pubkey == "" {
		return fmt.Errorf("pubkey is required")
	}
	if err := validatePubkeyHex(l.Pubkey); err != nil {
		return err
	}
	if l.Endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}
	return nil
}

func (p *PeerConfig) validate() error {
	if len(p.Direct) == 0 && len(p.Relay) == 0 {
		return fmt.Errorf("at least one of direct or relay is required")
	}
	return nil
}

func (ip *InboundPolicy) validate() error {
	if ip.Default != "" && ip.Default != "allow" && ip.Default != "deny" {
		return fmt.Errorf("default must be \"allow\" or \"deny\", got %q", ip.Default)
	}
	for i, rule := range ip.Rules {
		if err := rule.validate(); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}

func (r *InboundRule) validate() error {
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	if err := r.Match.validate(); err != nil {
		return fmt.Errorf("match: %w", err)
	}
	if r.Action != "allow" && r.Action != "deny" {
		return fmt.Errorf("action must be \"allow\" or \"deny\", got %q", r.Action)
	}
	for i, svc := range r.Services {
		if err := svc.validate(); err != nil {
			return fmt.Errorf("services[%d]: %w", i, err)
		}
	}
	return nil
}

func (m *MatchConfig) validate() error {
	return m.Pubkey.validate()
}

var validMatchTypes = map[string]bool{
	"whitelist": true,
	"zgrlan":    true,
	"any":       true,
	// Future types:
	"solana":   true,
	"database": true,
	"http":     true,
}

func (p *PubkeyMatch) validate() error {
	if p.Type == "" {
		return fmt.Errorf("pubkey.type is required")
	}
	if !validMatchTypes[p.Type] {
		return fmt.Errorf("pubkey.type %q is not supported", p.Type)
	}
	switch p.Type {
	case "whitelist":
		if p.Path == "" {
			return fmt.Errorf("pubkey.path is required for type \"whitelist\"")
		}
	case "zgrlan":
		if p.Peer == "" {
			return fmt.Errorf("pubkey.peer is required for type \"zgrlan\"")
		}
	}
	return nil
}

func (s *ServiceConfig) validate() error {
	validProtos := map[string]bool{"*": true, "tcp": true, "udp": true, "icmp": true}
	if !validProtos[s.Proto] {
		return fmt.Errorf("proto must be one of *, tcp, udp, icmp; got %q", s.Proto)
	}
	if s.Port == "" {
		return fmt.Errorf("port is required")
	}
	return nil
}

func (r *RouteConfig) validate() error {
	for i, rule := range r.Rules {
		if err := rule.validate(); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}

func (r *RouteRule) validate() error {
	if r.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if r.Peer == "" {
		return fmt.Errorf("peer is required")
	}
	return nil
}

// validatePeerDomain checks that a peer key looks like "{hex}.zigor.net".
func validatePeerDomain(domain string) error {
	if !strings.HasSuffix(domain, ".zigor.net") {
		return fmt.Errorf("peer domain must end with .zigor.net")
	}
	prefix := strings.TrimSuffix(domain, ".zigor.net")
	if prefix == "" {
		return fmt.Errorf("peer domain must have a pubkey prefix")
	}
	// The prefix should be hex-encoded (up to 64 chars for a 32-byte key).
	if _, err := hex.DecodeString(prefix); err != nil {
		return fmt.Errorf("peer domain prefix %q is not valid hex: %w", prefix, err)
	}
	if len(prefix) > 64 {
		return fmt.Errorf("peer domain prefix is too long (%d > 64)", len(prefix))
	}
	return nil
}

// validatePubkeyHex checks that a string is valid hex-encoded 32-byte public key.
func validatePubkeyHex(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("pubkey must be 64 hex characters, got %d", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("pubkey is not valid hex: %w", err)
	}
	return nil
}
