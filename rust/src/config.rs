//! Configuration file parsing and validation for zgrnetd.
//!
//! The configuration is a YAML file with the following top-level sections:
//!   - net: Global settings (private key, TUN IP, MTU, listen port)
//!   - peers: Manually configured direct peers
//!   - inbound_policy: Inbound access control rules
//!   - route: Outbound routing rules (domain -> peer)

use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Top-level configuration for zgrnetd.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub net: NetConfig,
    #[serde(default)]
    pub peers: HashMap<String, PeerConfig>,
    #[serde(default)]
    pub inbound_policy: InboundPolicy,
    #[serde(default)]
    pub route: RouteConfig,
}

/// Global network settings.
#[derive(Debug, Deserialize)]
pub struct NetConfig {
    /// Path to the Noise private key file.
    /// Relative paths are resolved against the config file's directory.
    #[serde(default = "default_private_key")]
    pub private_key: String,

    /// Local IPv4 address for the TUN device. Must be in the CGNAT range (100.64.0.0/10).
    pub tun_ipv4: String,

    /// Maximum Transmission Unit. Default: 1400.
    #[serde(default = "default_mtu")]
    pub tun_mtu: u16,

    /// UDP port to listen on. Default: 51820.
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,

    /// Directory for runtime data (state, cache).
    /// Relative paths are resolved against the config file's directory.
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
}

/// Peer configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct PeerConfig {
    /// Short name for the peer (used in route rules).
    #[serde(default)]
    pub alias: String,
    /// Direct endpoint addresses ("host:port").
    #[serde(default)]
    pub direct: Vec<String>,
    /// Relay peer domains.
    #[serde(default)]
    pub relay: Vec<String>,
}

/// Inbound access control policy.
#[derive(Debug, Deserialize, Default)]
pub struct InboundPolicy {
    /// Default action: "allow" or "deny". Default: "deny".
    #[serde(default = "default_deny")]
    pub default: String,
    /// Ordered list of inbound rules.
    #[serde(default)]
    pub rules: Vec<InboundRule>,
}

/// Single inbound access control rule.
#[derive(Debug, Deserialize)]
pub struct InboundRule {
    pub name: String,
    #[serde(default)]
    pub r#match: MatchConfig,
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    #[serde(default)]
    pub action: String,
}

/// Match configuration for an inbound rule.
#[derive(Debug, Deserialize, Default)]
pub struct MatchConfig {
    #[serde(default)]
    pub pubkey: PubkeyMatch,
}

/// How to match peer public keys.
#[derive(Debug, Deserialize, Default)]
pub struct PubkeyMatch {
    /// Match type: "whitelist" or "zgrlan".
    #[serde(default, rename = "type")]
    pub match_type: String,
    /// File path for whitelist.
    #[serde(default)]
    pub path: String,
    /// zgrlan peer domain.
    #[serde(default)]
    pub peer: String,
}

/// Service (protocol + port) for inbound rules.
#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub port: String,
}

/// Outbound routing rules.
#[derive(Debug, Deserialize, Default)]
pub struct RouteConfig {
    #[serde(default)]
    pub rules: Vec<RouteRule>,
}

/// Single outbound route rule.
#[derive(Debug, Deserialize)]
pub struct RouteRule {
    /// Glob pattern (e.g., "*.google.com").
    #[serde(default)]
    pub domain: String,
    /// Path to a file with one domain per line.
    #[serde(default)]
    pub domain_list: String,
    /// Target peer alias or domain.
    #[serde(default)]
    pub peer: String,
}

// Default value functions for serde
fn default_private_key() -> String { "private.key".to_string() }
fn default_mtu() -> u16 { 1400 }
fn default_listen_port() -> u16 { 51820 }
fn default_data_dir() -> String { "./data".to_string() }
fn default_deny() -> String { "deny".to_string() }

impl Config {
    /// Load and parse a YAML config file.
    /// Relative paths are resolved against the config file's directory.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(path.to_path_buf(), e))?;
        let mut cfg: Config = serde_yaml::from_str(&data)
            .map_err(ConfigError::Yaml)?;

        // Resolve relative paths against config directory
        let dir = path.parent().unwrap_or(Path::new("."));
        let abs_dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
        cfg.resolve_relative_paths(&abs_dir);

        Ok(cfg)
    }

    /// Parse YAML from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ConfigError> {
        let s = std::str::from_utf8(data)
            .map_err(|e| ConfigError::Validation(format!("invalid UTF-8: {}", e)))?;
        serde_yaml::from_str(s).map_err(ConfigError::Yaml)
    }

    /// Resolve relative file paths against the given context directory.
    pub fn resolve_relative_paths(&mut self, context_dir: &Path) {
        let resolve = |p: &str| -> String {
            if p.is_empty() || Path::new(p).is_absolute() {
                return p.to_string();
            }
            context_dir.join(p).to_string_lossy().to_string()
        };

        self.net.private_key = resolve(&self.net.private_key);
        self.net.data_dir = resolve(&self.net.data_dir);

        for rule in &mut self.inbound_policy.rules {
            rule.r#match.pubkey.path = resolve(&rule.r#match.pubkey.path);
        }

        for rule in &mut self.route.rules {
            rule.domain_list = resolve(&rule.domain_list);
        }
    }

    /// Validate the configuration. Call after loading.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // net.private_key must be set
        if self.net.private_key.is_empty() {
            return Err(ConfigError::Validation("net.private_key is required".into()));
        }

        // net.tun_ipv4 must be a valid CGNAT address
        if self.net.tun_ipv4.is_empty() {
            return Err(ConfigError::Validation("net.tun_ipv4 is required".into()));
        }
        validate_cgnat_address(&self.net.tun_ipv4)?;

        // MTU range
        if self.net.tun_mtu < 576 {
            return Err(ConfigError::Validation(
                format!("net.tun_mtu must be >= 576, got {}", self.net.tun_mtu)));
        }

        // Validate peers
        for (domain, peer) in &self.peers {
            pubkey_from_domain(domain)?;
            for ep in &peer.direct {
                if ep.split(':').count() != 2 {
                    return Err(ConfigError::Validation(
                        format!("peers[{}].direct: invalid endpoint {:?}", domain, ep)));
                }
            }
        }

        // Validate inbound_policy
        match self.inbound_policy.default.as_str() {
            "allow" | "deny" => {}
            other => return Err(ConfigError::Validation(
                format!("inbound_policy.default must be \"allow\" or \"deny\", got {:?}", other))),
        }
        for (i, rule) in self.inbound_policy.rules.iter().enumerate() {
            if rule.name.is_empty() {
                return Err(ConfigError::Validation(
                    format!("inbound_policy.rules[{}]: name is required", i)));
            }
            match rule.action.as_str() {
                "allow" | "deny" => {}
                other => return Err(ConfigError::Validation(
                    format!("inbound_policy.rules[{}] ({}): action must be \"allow\" or \"deny\", got {:?}",
                            i, rule.name, other))),
            }
        }

        // Validate route rules
        for (i, rule) in self.route.rules.iter().enumerate() {
            if rule.domain.is_empty() && rule.domain_list.is_empty() {
                return Err(ConfigError::Validation(
                    format!("route.rules[{}]: domain or domain_list is required", i)));
            }
            if rule.peer.is_empty() {
                return Err(ConfigError::Validation(
                    format!("route.rules[{}]: peer is required", i)));
            }
        }

        Ok(())
    }
}

/// Extract hex-encoded public key from a peer domain.
/// Format: "{first32hex}.{last32hex}.zigor.net" or plain 64-char hex.
pub fn pubkey_from_domain(domain: &str) -> Result<String, ConfigError> {
    let domain = domain.to_lowercase();
    let subdomain = domain.strip_suffix(".zigor.net").unwrap_or(&domain);

    // Try "first32.last32" format
    if let Some((a, b)) = subdomain.split_once('.') {
        let combined = format!("{}{}", a, b);
        if combined.len() == 64 && is_hex_string(&combined) {
            return Ok(combined);
        }
    }

    // Try plain 64-char hex
    if subdomain.len() == 64 && is_hex_string(subdomain) {
        return Ok(subdomain.to_string());
    }

    Err(ConfigError::Validation(
        format!("invalid peer domain {:?}: expected hex pubkey", domain)))
}

/// Check that the IP is in the CGNAT range (100.64.0.0/10).
fn validate_cgnat_address(addr: &str) -> Result<(), ConfigError> {
    let ip: Ipv4Addr = addr.parse().map_err(|_|
        ConfigError::Validation(format!("invalid IP address: {}", addr)))?;
    let octets = ip.octets();
    if octets[0] != 100 || octets[1] < 64 || octets[1] > 127 {
        return Err(ConfigError::Validation(
            format!("{} is not in CGNAT range (100.64.0.0/10)", addr)));
    }
    Ok(())
}

fn is_hex_string(s: &str) -> bool {
    s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Config errors.
#[derive(Debug)]
pub enum ConfigError {
    Io(PathBuf, std::io::Error),
    Yaml(serde_yaml::Error),
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(path, e) => write!(f, "config: read {}: {}", path.display(), e),
            ConfigError::Yaml(e) => write!(f, "config: yaml: {}", e),
            ConfigError::Validation(msg) => write!(f, "config: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let yaml = r#"
net:
  tun_ipv4: "100.64.0.1"
"#;
        let cfg = Config::parse(yaml.as_bytes()).unwrap();
        assert_eq!(cfg.net.tun_ipv4, "100.64.0.1");
        assert_eq!(cfg.net.tun_mtu, 1400);
        assert_eq!(cfg.net.listen_port, 51820);
        assert_eq!(cfg.net.private_key, "private.key");
    }

    #[test]
    fn test_validate_cgnat() {
        assert!(validate_cgnat_address("100.64.0.1").is_ok());
        assert!(validate_cgnat_address("100.127.255.254").is_ok());
        assert!(validate_cgnat_address("192.168.1.1").is_err());
        assert!(validate_cgnat_address("10.0.0.1").is_err());
        assert!(validate_cgnat_address("invalid").is_err());
    }

    #[test]
    fn test_pubkey_from_domain() {
        let hex64 = "a".repeat(64);
        // Split format
        let domain = format!("{}.{}.zigor.net", &hex64[..32], &hex64[32..]);
        assert_eq!(pubkey_from_domain(&domain).unwrap(), hex64);
        // Plain hex
        assert_eq!(pubkey_from_domain(&hex64).unwrap(), hex64);
        // Invalid
        assert!(pubkey_from_domain("bad.zigor.net").is_err());
    }

    #[test]
    fn test_validate_valid() {
        let yaml = r#"
net:
  private_key: "key"
  tun_ipv4: "100.64.0.1"
  tun_mtu: 1400
  listen_port: 51820
inbound_policy:
  default: deny
"#;
        let cfg = Config::parse(yaml.as_bytes()).unwrap();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_missing_tun_ip() {
        let yaml = r#"
net:
  private_key: "key"
  tun_ipv4: ""
"#;
        let cfg = Config::parse(yaml.as_bytes()).unwrap();
        assert!(cfg.validate().is_err());
    }
}
