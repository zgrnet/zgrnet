//! Configuration management for zgrnet.
//!
//! Handles parsing, validation, diffing, and hot-reloading of configuration files.
//! The config describes the "desired state" of the system; consumers receive
//! incremental diffs and reconcile accordingly.
//!
//! Go and Rust use YAML format; Zig uses JSON.

mod diff;
mod manager;
mod policy;
mod route;

pub use diff::{ConfigDiff, diff};
pub use manager::Manager;
pub use policy::{PolicyEngine, PolicyResult};
pub use route::{RouteMatcher, RouteResult};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

/// Top-level configuration structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub net: NetConfig,
    #[serde(default)]
    pub lans: Vec<LanConfig>,
    #[serde(default)]
    pub peers: HashMap<String, PeerConfig>,
    #[serde(default)]
    pub inbound_policy: InboundPolicy,
    #[serde(default)]
    pub route: RouteConfig,
}

/// Global network settings. Changes require a restart.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetConfig {
    /// Path to the Noise Protocol private key file.
    pub private_key: String,
    /// Local TUN device IPv4 address. Must be in CGNAT range (100.64.0.0/10).
    pub tun_ipv4: String,
    /// TUN device MTU. Default: 1400.
    #[serde(default)]
    pub tun_mtu: u16,
    /// UDP listen port. 0 for random.
    #[serde(default)]
    pub listen_port: u16,
}

/// Configuration for a zgrlan node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanConfig {
    pub domain: String,
    pub pubkey: String,
    pub endpoint: String,
}

/// Configuration for a manually configured peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerConfig {
    #[serde(default)]
    pub alias: String,
    #[serde(default)]
    pub direct: Vec<String>,
    #[serde(default)]
    pub relay: Vec<String>,
    #[serde(default)]
    pub labels: Vec<String>,
}

/// Controls who can connect and what services they can access.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct InboundPolicy {
    /// Default action when no rule matches: "allow" or "deny".
    #[serde(default)]
    pub default: String,
    /// How often existing connections are re-checked.
    #[serde(default)]
    pub revalidate_interval: String,
    /// Rules evaluated in order; first match wins.
    #[serde(default)]
    pub rules: Vec<InboundRule>,
}

/// A single inbound policy rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundRule {
    pub name: String,
    #[serde(rename = "match")]
    pub match_config: MatchConfig,
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    pub action: String,
}

/// Defines how to match a peer's identity.
/// A rule can match by pubkey, by labels, or both.
/// When both are specified, the peer must match the pubkey condition AND have matching labels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchConfig {
    pub pubkey: PubkeyMatch,
    /// Label patterns the peer must have at least one of.
    /// Supports exact match ("host.zigor.net/trusted") and
    /// wildcard match ("company.zigor.net/*").
    #[serde(default)]
    pub labels: Vec<String>,
}

/// Defines the pubkey matching strategy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PubkeyMatch {
    /// Matching strategy: "whitelist", "zgrlan", "any", "solana", "database", "http".
    #[serde(rename = "type")]
    pub match_type: String,
    /// File path for whitelist type (one pubkey per line).
    #[serde(default)]
    pub path: String,
    /// zgrlan peer domain for zgrlan type.
    #[serde(default)]
    pub peer: String,
}

/// Defines which network services are accessible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceConfig {
    /// Protocol: "*", "tcp", "udp", "icmp".
    pub proto: String,
    /// Port specification: "*", "80", "80,443", "8000-9000".
    pub port: String,
}

/// Outbound routing rules.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RouteConfig {
    #[serde(default)]
    pub rules: Vec<RouteRule>,
}

/// Defines how traffic for specific domains is routed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteRule {
    /// Glob pattern: "*.google.com", "google.com".
    #[serde(default)]
    pub domain: String,
    /// File path containing one domain per line.
    #[serde(default)]
    pub domain_list: String,
    /// Target peer alias or domain.
    pub peer: String,
}

/// Configuration error type.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config: read file: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: parse yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("config: {0}")]
    Validation(String),
}

/// Load and parse a YAML config file.
pub fn load<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
    let data = fs::read(path)?;
    load_from_bytes(&data)
}

/// Parse a YAML config from raw bytes.
pub fn load_from_bytes(data: &[u8]) -> Result<Config, ConfigError> {
    let cfg: Config = serde_yaml::from_slice(data)?;
    cfg.validate()?;
    Ok(cfg)
}

/// CGNAT range: 100.64.0.0/10 = 100.64.0.0 .. 100.127.255.255
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

const VALID_MATCH_TYPES: &[&str] = &["whitelist", "zgrlan", "any", "solana", "database", "http"];
const VALID_PROTOS: &[&str] = &["*", "tcp", "udp", "icmp"];

impl Config {
    /// Validate the configuration for correctness.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.net.validate().map_err(|e| ConfigError::Validation(format!("net: {e}")))?;

        for (i, lan) in self.lans.iter().enumerate() {
            lan.validate().map_err(|e| ConfigError::Validation(format!("lans[{i}]: {e}")))?;
        }

        for (domain, peer) in &self.peers {
            validate_peer_domain(domain).map_err(|e| ConfigError::Validation(format!("peers[{domain:?}]: {e}")))?;
            peer.validate().map_err(|e| ConfigError::Validation(format!("peers[{domain:?}]: {e}")))?;
        }

        self.inbound_policy.validate().map_err(|e| ConfigError::Validation(format!("inbound_policy: {e}")))?;
        self.route.validate().map_err(|e| ConfigError::Validation(format!("route: {e}")))?;

        Ok(())
    }
}

impl NetConfig {
    fn validate(&self) -> Result<(), String> {
        if self.private_key.is_empty() {
            return Err("private_key is required".into());
        }
        if self.tun_ipv4.is_empty() {
            return Err("tun_ipv4 is required".into());
        }
        let ip: Ipv4Addr = self.tun_ipv4.parse()
            .map_err(|_| format!("tun_ipv4 {:?} is not a valid IPv4 address", self.tun_ipv4))?;
        if !is_cgnat(ip) {
            return Err(format!("tun_ipv4 {:?} is not in CGNAT range (100.64.0.0/10)", self.tun_ipv4));
        }
        Ok(())
    }
}

impl LanConfig {
    fn validate(&self) -> Result<(), String> {
        if self.domain.is_empty() {
            return Err("domain is required".into());
        }
        if self.pubkey.is_empty() {
            return Err("pubkey is required".into());
        }
        validate_pubkey_hex(&self.pubkey)?;
        if self.endpoint.is_empty() {
            return Err("endpoint is required".into());
        }
        Ok(())
    }
}

impl PeerConfig {
    fn validate(&self) -> Result<(), String> {
        if self.direct.is_empty() && self.relay.is_empty() {
            return Err("at least one of direct or relay is required".into());
        }
        Ok(())
    }
}

impl InboundPolicy {
    fn validate(&self) -> Result<(), String> {
        if !self.default.is_empty() && self.default != "allow" && self.default != "deny" {
            return Err(format!("default must be \"allow\" or \"deny\", got {:?}", self.default));
        }
        for (i, rule) in self.rules.iter().enumerate() {
            rule.validate().map_err(|e| format!("rules[{i}]: {e}"))?;
        }
        Ok(())
    }
}

impl InboundRule {
    fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("name is required".into());
        }
        self.match_config.validate().map_err(|e| format!("match: {e}"))?;
        if self.action != "allow" && self.action != "deny" {
            return Err(format!("action must be \"allow\" or \"deny\", got {:?}", self.action));
        }
        for (i, svc) in self.services.iter().enumerate() {
            svc.validate().map_err(|e| format!("services[{i}]: {e}"))?;
        }
        Ok(())
    }
}

impl MatchConfig {
    fn validate(&self) -> Result<(), String> {
        self.pubkey.validate()
    }
}

impl PubkeyMatch {
    fn validate(&self) -> Result<(), String> {
        if self.match_type.is_empty() {
            return Err("pubkey.type is required".into());
        }
        if !VALID_MATCH_TYPES.contains(&self.match_type.as_str()) {
            return Err(format!("pubkey.type {:?} is not supported", self.match_type));
        }
        match self.match_type.as_str() {
            "whitelist" => {
                if self.path.is_empty() {
                    return Err("pubkey.path is required for type \"whitelist\"".into());
                }
            }
            "zgrlan" => {
                if self.peer.is_empty() {
                    return Err("pubkey.peer is required for type \"zgrlan\"".into());
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl ServiceConfig {
    fn validate(&self) -> Result<(), String> {
        if !VALID_PROTOS.contains(&self.proto.as_str()) {
            return Err(format!("proto must be one of *, tcp, udp, icmp; got {:?}", self.proto));
        }
        if self.port.is_empty() {
            return Err("port is required".into());
        }
        Ok(())
    }
}

impl RouteConfig {
    fn validate(&self) -> Result<(), String> {
        for (i, rule) in self.rules.iter().enumerate() {
            rule.validate().map_err(|e| format!("rules[{i}]: {e}"))?;
        }
        Ok(())
    }
}

impl RouteRule {
    fn validate(&self) -> Result<(), String> {
        if self.domain.is_empty() && self.domain_list.is_empty() {
            return Err("at least one of domain or domain_list is required".into());
        }
        if self.peer.is_empty() {
            return Err("peer is required".into());
        }
        Ok(())
    }
}

fn validate_peer_domain(domain: &str) -> Result<(), String> {
    if !domain.ends_with(".zigor.net") {
        return Err("peer domain must end with .zigor.net".into());
    }
    let prefix = &domain[..domain.len() - ".zigor.net".len()];
    if prefix.is_empty() {
        return Err("peer domain must have a pubkey prefix".into());
    }
    if hex::decode(prefix).is_err() {
        return Err(format!("peer domain prefix {:?} is not valid hex", prefix));
    }
    if prefix.len() > 64 {
        return Err(format!("peer domain prefix is too long ({} > 64)", prefix.len()));
    }
    Ok(())
}

fn validate_pubkey_hex(s: &str) -> Result<(), String> {
    if s.len() != 64 {
        return Err(format!("pubkey must be 64 hex characters, got {}", s.len()));
    }
    if hex::decode(s).is_err() {
        return Err("pubkey is not valid hex".into());
    }
    Ok(())
}

/// Extract hex-encoded public key from a peer domain.
/// Format: "{first32hex}.{last32hex}.zigor.net" or plain 64-char hex.
pub fn pubkey_from_domain(domain: &str) -> Result<String, ConfigError> {
    let domain = domain.to_lowercase();
    let subdomain = domain.strip_suffix(".zigor.net").unwrap_or(&domain);

    // Try "first32.last32" format
    if let Some((a, b)) = subdomain.split_once('.') {
        let combined = format!("{}{}", a, b);
        if combined.len() == 64 && combined.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(combined);
        }
    }

    // Try plain 64-char hex
    if subdomain.len() == 64 && subdomain.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(subdomain.to_string());
    }

    Err(ConfigError::Validation(
        format!("invalid peer domain {:?}: expected hex pubkey", domain)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONFIG: &str = r#"
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
    labels:
      - "host.zigor.net/trusted"
  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567bb.zigor.net":
    alias: peer_jp
    relay:
      - "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa.zigor.net"
    labels:
      - "host.zigor.net/friend"
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
"#;

    #[test]
    fn test_load_valid() {
        let cfg = load_from_bytes(VALID_CONFIG.as_bytes()).unwrap();
        assert_eq!(cfg.net.private_key, "/tmp/test.key");
        assert_eq!(cfg.net.tun_ipv4, "100.64.0.1");
        assert_eq!(cfg.net.tun_mtu, 1400);
        assert_eq!(cfg.net.listen_port, 51820);
        assert_eq!(cfg.lans.len(), 1);
        assert_eq!(cfg.peers.len(), 2);
        assert_eq!(cfg.inbound_policy.default, "deny");
        assert_eq!(cfg.route.rules.len(), 2);
    }

    #[test]
    fn test_load_invalid_yaml() {
        let result = load_from_bytes(b"not: [valid: yaml");
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_missing_private_key() {
        let yaml = b"net:\n  tun_ipv4: \"100.64.0.1\"";
        let err = load_from_bytes(yaml).unwrap_err().to_string();
        // serde catches missing required fields before custom validation
        assert!(err.contains("private_key"), "got: {err}");
    }

    #[test]
    fn test_validation_missing_tun_ipv4() {
        let yaml = b"net:\n  private_key: \"/tmp/k\"";
        let err = load_from_bytes(yaml).unwrap_err().to_string();
        assert!(err.contains("tun_ipv4"), "got: {err}");
    }

    #[test]
    fn test_validation_invalid_ip() {
        let yaml = b"net:\n  private_key: \"/tmp/k\"\n  tun_ipv4: \"not-an-ip\"";
        let err = load_from_bytes(yaml).unwrap_err().to_string();
        assert!(err.contains("not a valid IPv4"), "got: {err}");
    }

    #[test]
    fn test_validation_not_cgnat() {
        let yaml = b"net:\n  private_key: \"/tmp/k\"\n  tun_ipv4: \"192.168.1.1\"";
        let err = load_from_bytes(yaml).unwrap_err().to_string();
        assert!(err.contains("not in CGNAT range"), "got: {err}");
    }

    #[test]
    fn test_validation_peer_domain() {
        assert!(validate_peer_domain("abcd.zigor.net").is_ok());
        assert!(validate_peer_domain("abc.example.com").is_err());
        assert!(validate_peer_domain(".zigor.net").is_err());
        assert!(validate_peer_domain("xyz.zigor.net").is_err()); // odd-length hex is invalid
    }

    #[test]
    fn test_validation_inbound_invalid_default() {
        let yaml = b"net:\n  private_key: /tmp/k\n  tun_ipv4: \"100.64.0.1\"\ninbound_policy:\n  default: maybe";
        let err = load_from_bytes(yaml).unwrap_err().to_string();
        assert!(err.contains("must be \"allow\" or \"deny\""), "got: {err}");
    }

    #[test]
    fn test_validation_route_missing_domain() {
        let yaml = b"net:\n  private_key: /tmp/k\n  tun_ipv4: \"100.64.0.1\"\nroute:\n  rules:\n    - peer: peer_us";
        let err = load_from_bytes(yaml).unwrap_err().to_string();
        assert!(err.contains("at least one of domain or domain_list"), "got: {err}");
    }

    #[test]
    fn test_validation_route_missing_peer() {
        let yaml = b"net:\n  private_key: /tmp/k\n  tun_ipv4: \"100.64.0.1\"\nroute:\n  rules:\n    - domain: \"*.google.com\"";
        let err = load_from_bytes(yaml).unwrap_err().to_string();
        // serde catches missing required `peer` field
        assert!(err.contains("peer"), "got: {err}");
    }

    #[test]
    fn test_is_cgnat() {
        assert!(is_cgnat(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_cgnat(Ipv4Addr::new(100, 127, 255, 255)));
        assert!(!is_cgnat(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_cgnat(Ipv4Addr::new(100, 128, 0, 0)));
    }

    #[test]
    fn test_load_file() {
        let dir = std::env::temp_dir().join("zgrnet_config_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.yaml");
        std::fs::write(&path, VALID_CONFIG).unwrap();

        let cfg = load(&path).unwrap();
        assert_eq!(cfg.net.tun_ipv4, "100.64.0.1");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_file_not_found() {
        let result = load("/nonexistent/config.yaml");
        assert!(result.is_err());
    }
}
