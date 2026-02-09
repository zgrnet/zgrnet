use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead};
use std::sync::RwLock;

use super::{InboundPolicy, InboundRule, ServiceConfig};

/// Result of checking inbound access for a peer.
#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub action: String,
    pub services: Vec<ServiceConfig>,
    pub rule_name: String,
    pub needs_zgrlan_verify: bool,
    pub zgrlan_peer: String,
}

struct CompiledEntry {
    rule: InboundRule,
    whitelist: HashSet<String>,
    list_path: String,
}

/// Evaluates inbound policy rules against peer public keys.
/// Thread-safe for concurrent reads.
pub struct PolicyEngine {
    default_action: String,
    entries: RwLock<Vec<CompiledEntry>>,
}

impl PolicyEngine {
    /// Create a PolicyEngine from an InboundPolicy.
    /// Whitelist files are loaded eagerly.
    pub fn new(policy: &InboundPolicy) -> io::Result<Self> {
        let entries = Self::compile(&policy.rules)?;
        let default_action = if policy.default.is_empty() {
            "deny".to_string()
        } else {
            policy.default.clone()
        };
        Ok(Self {
            default_action,
            entries: RwLock::new(entries),
        })
    }

    fn compile(rules: &[InboundRule]) -> io::Result<Vec<CompiledEntry>> {
        let mut entries = Vec::with_capacity(rules.len());
        for rule in rules {
            let mut entry = CompiledEntry {
                rule: rule.clone(),
                whitelist: HashSet::new(),
                list_path: String::new(),
            };
            if rule.match_config.pubkey.match_type == "whitelist" {
                let path = &rule.match_config.pubkey.path;
                entry.whitelist = load_pubkey_list(path)?;
                entry.list_path = path.clone();
            }
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Evaluate the inbound policy for the given peer public key (raw 32 bytes).
    pub fn check(&self, pubkey: &[u8; 32]) -> PolicyResult {
        let pubkey_hex = hex::encode(pubkey);

        let entries = self.entries.read().unwrap();
        for entry in entries.iter() {
            let rule = &entry.rule;
            match rule.match_config.pubkey.match_type.as_str() {
                "any" => {
                    return PolicyResult {
                        action: rule.action.clone(),
                        services: rule.services.clone(),
                        rule_name: rule.name.clone(),
                        needs_zgrlan_verify: false,
                        zgrlan_peer: String::new(),
                    };
                }
                "whitelist" => {
                    if entry.whitelist.contains(&pubkey_hex) {
                        return PolicyResult {
                            action: rule.action.clone(),
                            services: rule.services.clone(),
                            rule_name: rule.name.clone(),
                            needs_zgrlan_verify: false,
                            zgrlan_peer: String::new(),
                        };
                    }
                }
                "zgrlan" => {
                    return PolicyResult {
                        action: rule.action.clone(),
                        services: rule.services.clone(),
                        rule_name: rule.name.clone(),
                        needs_zgrlan_verify: true,
                        zgrlan_peer: rule.match_config.pubkey.peer.clone(),
                    };
                }
                _ => continue,
            }
        }

        PolicyResult {
            action: self.default_action.clone(),
            services: vec![],
            rule_name: "default".into(),
            needs_zgrlan_verify: false,
            zgrlan_peer: String::new(),
        }
    }

    /// Reload whitelist files from disk.
    pub fn reload(&self) -> io::Result<()> {
        let mut entries = self.entries.write().unwrap();
        for entry in entries.iter_mut() {
            if !entry.list_path.is_empty() {
                entry.whitelist = load_pubkey_list(&entry.list_path)?;
            }
        }
        Ok(())
    }
}

fn load_pubkey_list(path: &str) -> io::Result<HashSet<String>> {
    let data = fs::read(path)?;
    let mut keys = HashSet::new();
    for (line_num, line) in data.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let lower = trimmed.to_lowercase();
        if lower.len() != 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {}: expected 64 hex chars, got {}", line_num + 1, lower.len()),
            ));
        }
        if hex::decode(&lower).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {}: invalid hex", line_num + 1),
            ));
        }
        keys.insert(lower);
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{MatchConfig, PubkeyMatch};

    fn hex_key(hex_str: &str) -> [u8; 32] {
        let mut key = [0u8; 32];
        let bytes = hex::decode(hex_str).unwrap();
        key[..bytes.len()].copy_from_slice(&bytes);
        key
    }

    fn make_policy(default: &str, rules: Vec<InboundRule>) -> InboundPolicy {
        InboundPolicy {
            default: default.into(),
            revalidate_interval: String::new(),
            rules,
        }
    }

    fn any_rule(name: &str, action: &str) -> InboundRule {
        InboundRule {
            name: name.into(),
            match_config: MatchConfig { pubkey: PubkeyMatch {
                match_type: "any".into(), path: String::new(), peer: String::new(),
            }},
            services: vec![ServiceConfig { proto: "*".into(), port: "*".into() }],
            action: action.into(),
        }
    }

    #[test]
    fn test_any_match() {
        let policy = make_policy("deny", vec![any_rule("allow-all", "allow")]);
        let pe = PolicyEngine::new(&policy).unwrap();

        let result = pe.check(&hex_key("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"));
        assert_eq!(result.action, "allow");
        assert_eq!(result.rule_name, "allow-all");
    }

    #[test]
    fn test_whitelist() {
        let dir = std::env::temp_dir().join("zgrnet_policy_test");
        let _ = std::fs::create_dir_all(&dir);
        let list_path = dir.join("trusted.txt");
        let trusted_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        std::fs::write(&list_path, format!("# Trusted\n{trusted_key}\n")).unwrap();

        let policy = make_policy("deny", vec![InboundRule {
            name: "trusted".into(),
            match_config: MatchConfig { pubkey: PubkeyMatch {
                match_type: "whitelist".into(),
                path: list_path.to_str().unwrap().into(),
                peer: String::new(),
            }},
            services: vec![ServiceConfig { proto: "tcp".into(), port: "80,443".into() }],
            action: "allow".into(),
        }]);
        let pe = PolicyEngine::new(&policy).unwrap();

        let result = pe.check(&hex_key(trusted_key));
        assert_eq!(result.action, "allow");

        let result = pe.check(&hex_key("0000000000000000000000000000000000000000000000000000000000000001"));
        assert_eq!(result.action, "deny");
        assert_eq!(result.rule_name, "default");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_zgrlan() {
        let policy = make_policy("deny", vec![InboundRule {
            name: "company".into(),
            match_config: MatchConfig { pubkey: PubkeyMatch {
                match_type: "zgrlan".into(),
                path: String::new(),
                peer: "company.zigor.net".into(),
            }},
            services: vec![ServiceConfig { proto: "tcp".into(), port: "80,443".into() }],
            action: "allow".into(),
        }]);
        let pe = PolicyEngine::new(&policy).unwrap();

        let result = pe.check(&hex_key("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"));
        assert_eq!(result.action, "allow");
        assert!(result.needs_zgrlan_verify);
        assert_eq!(result.zgrlan_peer, "company.zigor.net");
    }

    #[test]
    fn test_default_allow() {
        let policy = make_policy("allow", vec![]);
        let pe = PolicyEngine::new(&policy).unwrap();
        let result = pe.check(&[0u8; 32]);
        assert_eq!(result.action, "allow");
    }

    #[test]
    fn test_default_deny() {
        let policy = make_policy("deny", vec![]);
        let pe = PolicyEngine::new(&policy).unwrap();
        let result = pe.check(&[0u8; 32]);
        assert_eq!(result.action, "deny");
    }

    #[test]
    fn test_priority() {
        let dir = std::env::temp_dir().join("zgrnet_policy_prio_test");
        let _ = std::fs::create_dir_all(&dir);
        let list_path = dir.join("trusted.txt");
        let key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        std::fs::write(&list_path, format!("{key}\n")).unwrap();

        let policy = make_policy("deny", vec![
            InboundRule {
                name: "trusted-full".into(),
                match_config: MatchConfig { pubkey: PubkeyMatch {
                    match_type: "whitelist".into(),
                    path: list_path.to_str().unwrap().into(),
                    peer: String::new(),
                }},
                services: vec![ServiceConfig { proto: "*".into(), port: "*".into() }],
                action: "allow".into(),
            },
            any_rule("any-limited", "allow"),
        ]);
        let pe = PolicyEngine::new(&policy).unwrap();

        let result = pe.check(&hex_key(key));
        assert_eq!(result.rule_name, "trusted-full");

        let result = pe.check(&hex_key("0000000000000000000000000000000000000000000000000000000000000001"));
        assert_eq!(result.rule_name, "any-limited");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reload() {
        let dir = std::env::temp_dir().join("zgrnet_policy_reload_test");
        let _ = std::fs::create_dir_all(&dir);
        let list_path = dir.join("trusted.txt");
        let key1 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let key2 = "0000000000000000000000000000000000000000000000000000000000000001";
        std::fs::write(&list_path, format!("{key1}\n")).unwrap();

        let policy = make_policy("deny", vec![InboundRule {
            name: "trusted".into(),
            match_config: MatchConfig { pubkey: PubkeyMatch {
                match_type: "whitelist".into(),
                path: list_path.to_str().unwrap().into(),
                peer: String::new(),
            }},
            services: vec![ServiceConfig { proto: "*".into(), port: "*".into() }],
            action: "allow".into(),
        }]);
        let pe = PolicyEngine::new(&policy).unwrap();

        assert_eq!(pe.check(&hex_key(key2)).action, "deny");

        std::fs::write(&list_path, format!("{key1}\n{key2}\n")).unwrap();
        pe.reload().unwrap();

        assert_eq!(pe.check(&hex_key(key2)).action, "allow");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
