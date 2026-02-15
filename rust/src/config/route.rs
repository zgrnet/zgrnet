//! Route matching engine: matches domains to peers via longest suffix match.
//!
//! All rules are suffix-based: "google.com" matches google.com and all
//! subdomains. When multiple rules match, the longest suffix wins.

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
    suffix: String, // lowercase domain suffix
}

/// Provides domain-to-peer route matching using longest suffix match.
///
/// All rules are suffix matches: "google.com" matches "google.com" and
/// "www.google.com". When multiple rules match, the longest suffix wins.
/// Thread-safe for concurrent reads.
pub struct RouteMatcher {
    rules: RwLock<Vec<CompiledRule>>,
}

impl RouteMatcher {
    /// Create a RouteMatcher from a RouteConfig.
    pub fn new(cfg: &RouteConfig) -> Self {
        let rules = Self::compile(cfg);
        Self { rules: RwLock::new(rules) }
    }

    fn compile(cfg: &RouteConfig) -> Vec<CompiledRule> {
        cfg.rules.iter().filter_map(|r| {
            if r.domain.is_empty() {
                return None;
            }
            let mut domain = r.domain.to_lowercase();
            // Strip "*." prefix — all matches are suffix-based
            if let Some(stripped) = domain.strip_prefix("*.") {
                domain = stripped.to_string();
            }
            if domain.is_empty() {
                return None; // skip bare "*." without a domain component
            }
            Some(CompiledRule {
                peer: r.peer.clone(),
                suffix: domain,
            })
        }).collect()
    }

    /// Check if a domain matches any route rule.
    /// Returns the result with the longest matching suffix.
    pub fn match_domain(&self, domain: &str) -> Option<RouteResult> {
        let domain = domain.to_lowercase();
        let domain = domain.strip_suffix('.').unwrap_or(&domain);

        let rules = self.rules.read().unwrap();
        let mut best: Option<&CompiledRule> = None;

        for r in rules.iter() {
            if match_suffix(domain, &r.suffix)
                && (best.is_none() || r.suffix.len() > best.unwrap().suffix.len())
            {
                best = Some(r);
            }
        }

        best.map(|r| RouteResult {
            peer: r.peer.clone(),
            rule_name: r.suffix.clone(),
        })
    }
}

/// Check if domain equals suffix or is a subdomain of suffix.
fn match_suffix(domain: &str, suffix: &str) -> bool {
    if domain == suffix {
        return true;
    }
    // domain must be longer and end with ".suffix"
    if domain.len() > suffix.len() + 1 {
        let prefix_end = domain.len() - suffix.len() - 1;
        if domain.as_bytes()[prefix_end] == b'.'
            && &domain[prefix_end + 1..] == suffix
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::RouteRule;

    fn cfg_with_rules(rules: Vec<RouteRule>) -> RouteConfig {
        RouteConfig { rules }
    }

    fn rule(domain: &str, peer: &str) -> RouteRule {
        RouteRule {
            domain: domain.into(),
            peer: peer.into(),
        }
    }

    #[test]
    fn test_suffix_match() {
        let cfg = cfg_with_rules(vec![rule("google.com", "peer_us")]);
        let rm = RouteMatcher::new(&cfg);

        assert!(rm.match_domain("google.com").is_some());
        assert!(rm.match_domain("www.google.com").is_some());
        assert!(rm.match_domain("mail.google.com").is_some());
        assert!(rm.match_domain("deep.sub.google.com").is_some());
        assert!(rm.match_domain("notgoogle.com").is_none());
        assert!(rm.match_domain("google.com.evil.com").is_none());
    }

    #[test]
    fn test_wildcard_prefix_stripped() {
        // "*.google.com" behaves identically to "google.com"
        let cfg = cfg_with_rules(vec![rule("*.google.com", "peer_us")]);
        let rm = RouteMatcher::new(&cfg);

        assert!(rm.match_domain("google.com").is_some());
        assert!(rm.match_domain("www.google.com").is_some());
        assert!(rm.match_domain("notgoogle.com").is_none());
    }

    #[test]
    fn test_longest_suffix_wins() {
        let cfg = cfg_with_rules(vec![
            rule("google.com", "peer_us"),
            rule("cn.google.com", "peer_cn"),
        ]);
        let rm = RouteMatcher::new(&cfg);

        assert_eq!(rm.match_domain("www.google.com").unwrap().peer, "peer_us");
        assert_eq!(rm.match_domain("cn.google.com").unwrap().peer, "peer_cn");
        assert_eq!(rm.match_domain("www.cn.google.com").unwrap().peer, "peer_cn");
        assert_eq!(rm.match_domain("google.com").unwrap().peer, "peer_us");
    }

    #[test]
    fn test_longest_suffix_order_independent() {
        // Order in config should not matter
        let cfg = cfg_with_rules(vec![
            rule("cn.google.com", "peer_cn"),
            rule("google.com", "peer_us"),
        ]);
        let rm = RouteMatcher::new(&cfg);

        assert_eq!(rm.match_domain("www.cn.google.com").unwrap().peer, "peer_cn");
    }

    #[test]
    fn test_case_insensitive() {
        let cfg = cfg_with_rules(vec![rule("Google.COM", "p")]);
        let rm = RouteMatcher::new(&cfg);
        assert!(rm.match_domain("WWW.GOOGLE.COM").is_some());
    }

    #[test]
    fn test_trailing_dot() {
        let cfg = cfg_with_rules(vec![rule("google.com", "p")]);
        let rm = RouteMatcher::new(&cfg);
        assert!(rm.match_domain("www.google.com.").is_some());
    }

    #[test]
    fn test_no_match() {
        let cfg = cfg_with_rules(vec![rule("google.com", "p")]);
        let rm = RouteMatcher::new(&cfg);
        assert!(rm.match_domain("example.com").is_none());
    }

    #[test]
    fn test_empty_rules() {
        let cfg = RouteConfig::default();
        let rm = RouteMatcher::new(&cfg);
        assert!(rm.match_domain("google.com").is_none());
    }
}
