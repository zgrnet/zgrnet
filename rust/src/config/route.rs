use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead};
use std::sync::RwLock;

use super::RouteConfig;

/// Returned when a domain matches a route rule.
#[derive(Debug, Clone)]
pub struct RouteResult {
    pub peer: String,
    pub rule_name: String,
}

struct CompiledRule {
    peer: String,
    // For domain patterns
    pattern: String,
    is_suffix: bool,
    // For domain list files
    list_path: String,
    domains: HashSet<String>,
}

/// Provides domain-to-peer route matching.
///
/// Supports exact match, wildcard suffix match (`*.example.com`),
/// and domain list files. Thread-safe for concurrent reads.
pub struct RouteMatcher {
    rules: RwLock<Vec<CompiledRule>>,
}

impl RouteMatcher {
    /// Create a RouteMatcher from a RouteConfig.
    /// Domain list files are loaded eagerly.
    pub fn new(cfg: &RouteConfig) -> io::Result<Self> {
        let rules = Self::compile(cfg)?;
        Ok(Self { rules: RwLock::new(rules) })
    }

    fn compile(cfg: &RouteConfig) -> io::Result<Vec<CompiledRule>> {
        let mut rules = Vec::with_capacity(cfg.rules.len());
        for r in &cfg.rules {
            let mut cr = CompiledRule {
                peer: r.peer.clone(),
                pattern: String::new(),
                is_suffix: false,
                list_path: String::new(),
                domains: HashSet::new(),
            };

            if !r.domain.is_empty() {
                let domain = r.domain.to_lowercase();
                if let Some(suffix) = domain.strip_prefix("*.") {
                    cr.is_suffix = true;
                    cr.pattern = format!(".{suffix}");
                } else {
                    cr.pattern = domain;
                }
            }

            if !r.domain_list.is_empty() {
                cr.list_path = r.domain_list.clone();
                cr.domains = load_domain_list(&r.domain_list)?;
            }

            rules.push(cr);
        }
        Ok(rules)
    }

    /// Check if a domain matches any route rule.
    pub fn match_domain(&self, domain: &str) -> Option<RouteResult> {
        let domain = domain.to_lowercase();
        let domain = domain.strip_suffix('.').unwrap_or(&domain);

        let rules = self.rules.read().unwrap();
        for r in rules.iter() {
            // Check domain pattern
            if !r.pattern.is_empty() {
                if r.is_suffix {
                    // "*.google.com" matches "google.com" and "www.google.com"
                    let base = &r.pattern[1..]; // ".google.com" -> "google.com"
                    if domain == base || domain.ends_with(&r.pattern) {
                        return Some(RouteResult {
                            peer: r.peer.clone(),
                            rule_name: format!("domain:*{}", r.pattern),
                        });
                    }
                } else if domain == r.pattern {
                    return Some(RouteResult {
                        peer: r.peer.clone(),
                        rule_name: format!("domain:{}", r.pattern),
                    });
                }
            }

            // Check domain list
            if !r.domains.is_empty() && match_domain_list(domain, &r.domains) {
                return Some(RouteResult {
                    peer: r.peer.clone(),
                    rule_name: format!("domain_list:{}", r.list_path),
                });
            }
        }

        None
    }

    /// Reload domain list files from disk.
    pub fn reload(&self) -> io::Result<()> {
        let mut rules = self.rules.write().unwrap();
        for r in rules.iter_mut() {
            if !r.list_path.is_empty() {
                r.domains = load_domain_list(&r.list_path)?;
            }
        }
        Ok(())
    }
}

/// Check if the domain or any parent domain appears in the set.
fn match_domain_list(domain: &str, domains: &HashSet<String>) -> bool {
    if domains.contains(domain) {
        return true;
    }
    let mut d = domain;
    while let Some(idx) = d.find('.') {
        d = &d[idx + 1..];
        if domains.contains(d) {
            return true;
        }
    }
    false
}

fn load_domain_list(path: &str) -> io::Result<HashSet<String>> {
    let data = fs::read(path)?;
    let mut domains = HashSet::new();
    for line in data.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        domains.insert(trimmed.to_lowercase());
    }
    Ok(domains)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::RouteRule;
    use std::io::Write;

    fn cfg_with_rules(rules: Vec<RouteRule>) -> RouteConfig {
        RouteConfig { rules }
    }

    #[test]
    fn test_exact_match() {
        let cfg = cfg_with_rules(vec![RouteRule {
            domain: "google.com".into(), domain_list: String::new(), peer: "peer_us".into(),
        }]);
        let rm = RouteMatcher::new(&cfg).unwrap();

        assert!(rm.match_domain("google.com").is_some());
        assert!(rm.match_domain("www.google.com").is_none());
    }

    #[test]
    fn test_wildcard_match() {
        let cfg = cfg_with_rules(vec![RouteRule {
            domain: "*.google.com".into(), domain_list: String::new(), peer: "peer_us".into(),
        }]);
        let rm = RouteMatcher::new(&cfg).unwrap();

        assert!(rm.match_domain("www.google.com").is_some());
        assert!(rm.match_domain("mail.google.com").is_some());
        assert!(rm.match_domain("deep.sub.google.com").is_some());
        assert!(rm.match_domain("google.com").is_some());
        assert!(rm.match_domain("notgoogle.com").is_none());
    }

    #[test]
    fn test_domain_list() {
        let dir = std::env::temp_dir().join("zgrnet_route_test");
        let _ = fs::create_dir_all(&dir);
        let list_path = dir.join("domains.txt");
        let mut f = fs::File::create(&list_path).unwrap();
        writeln!(f, "# GFW list").unwrap();
        writeln!(f, "google.com").unwrap();
        writeln!(f, "youtube.com").unwrap();

        let cfg = cfg_with_rules(vec![RouteRule {
            domain: String::new(),
            domain_list: list_path.to_str().unwrap().into(),
            peer: "peer_us".into(),
        }]);
        let rm = RouteMatcher::new(&cfg).unwrap();

        assert!(rm.match_domain("google.com").is_some());
        assert!(rm.match_domain("www.google.com").is_some());
        assert!(rm.match_domain("youtube.com").is_some());
        assert!(rm.match_domain("facebook.com").is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_case_insensitive() {
        let cfg = cfg_with_rules(vec![RouteRule {
            domain: "*.Google.COM".into(), domain_list: String::new(), peer: "p".into(),
        }]);
        let rm = RouteMatcher::new(&cfg).unwrap();
        assert!(rm.match_domain("WWW.GOOGLE.COM").is_some());
    }

    #[test]
    fn test_trailing_dot() {
        let cfg = cfg_with_rules(vec![RouteRule {
            domain: "*.google.com".into(), domain_list: String::new(), peer: "p".into(),
        }]);
        let rm = RouteMatcher::new(&cfg).unwrap();
        assert!(rm.match_domain("www.google.com.").is_some());
    }

    #[test]
    fn test_priority() {
        let cfg = cfg_with_rules(vec![
            RouteRule { domain: "*.google.com".into(), domain_list: String::new(), peer: "peer_us".into() },
            RouteRule { domain: "*.google.com".into(), domain_list: String::new(), peer: "peer_jp".into() },
        ]);
        let rm = RouteMatcher::new(&cfg).unwrap();
        let result = rm.match_domain("www.google.com").unwrap();
        assert_eq!(result.peer, "peer_us");
    }

    #[test]
    fn test_no_match() {
        let cfg = cfg_with_rules(vec![RouteRule {
            domain: "*.google.com".into(), domain_list: String::new(), peer: "p".into(),
        }]);
        let rm = RouteMatcher::new(&cfg).unwrap();
        assert!(rm.match_domain("example.com").is_none());
    }

    #[test]
    fn test_empty_rules() {
        let cfg = RouteConfig::default();
        let rm = RouteMatcher::new(&cfg).unwrap();
        assert!(rm.match_domain("google.com").is_none());
    }

    #[test]
    fn test_reload() {
        let dir = std::env::temp_dir().join("zgrnet_route_reload_test");
        let _ = fs::create_dir_all(&dir);
        let list_path = dir.join("domains.txt");
        fs::write(&list_path, "google.com\n").unwrap();

        let cfg = cfg_with_rules(vec![RouteRule {
            domain: String::new(),
            domain_list: list_path.to_str().unwrap().into(),
            peer: "p".into(),
        }]);
        let rm = RouteMatcher::new(&cfg).unwrap();

        assert!(rm.match_domain("twitter.com").is_none());

        fs::write(&list_path, "google.com\ntwitter.com\n").unwrap();
        rm.reload().unwrap();

        assert!(rm.match_domain("twitter.com").is_some());

        let _ = fs::remove_dir_all(&dir);
    }
}
