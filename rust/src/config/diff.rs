use std::collections::HashMap;

use super::{Config, LanConfig, PeerConfig};

/// Represents the differences between two configurations.
#[derive(Debug, Default)]
pub struct ConfigDiff {
    pub peers_added: HashMap<String, PeerConfig>,
    pub peers_removed: Vec<String>,
    pub peers_changed: HashMap<String, PeerConfig>,
    pub lans_added: Vec<LanConfig>,
    pub lans_removed: Vec<LanConfig>,
    pub inbound_changed: bool,
    pub route_changed: bool,
}

impl ConfigDiff {
    /// Returns true if there are no differences.
    pub fn is_empty(&self) -> bool {
        self.peers_added.is_empty()
            && self.peers_removed.is_empty()
            && self.peers_changed.is_empty()
            && self.lans_added.is_empty()
            && self.lans_removed.is_empty()
            && !self.inbound_changed
            && !self.route_changed
    }
}

/// Compute the differences between two configurations.
/// Net config changes are not tracked (require restart).
pub fn diff(old: &Config, new: &Config) -> ConfigDiff {
    let mut d = ConfigDiff::default();

    diff_peers(&old.peers, &new.peers, &mut d);
    diff_lans(&old.lans, &new.lans, &mut d);
    d.inbound_changed = old.inbound_policy != new.inbound_policy;
    d.route_changed = old.route != new.route;

    d
}

fn diff_peers(old: &HashMap<String, PeerConfig>, new: &HashMap<String, PeerConfig>, d: &mut ConfigDiff) {
    // Find added and changed
    for (domain, new_peer) in new {
        match old.get(domain) {
            None => { d.peers_added.insert(domain.clone(), new_peer.clone()); }
            Some(old_peer) if old_peer != new_peer => { d.peers_changed.insert(domain.clone(), new_peer.clone()); }
            _ => {}
        }
    }
    // Find removed
    for domain in old.keys() {
        if !new.contains_key(domain) {
            d.peers_removed.push(domain.clone());
        }
    }
}

fn diff_lans(old: &[LanConfig], new: &[LanConfig], d: &mut ConfigDiff) {
    let old_set: HashMap<&str, &LanConfig> = old.iter().map(|l| (l.domain.as_str(), l)).collect();
    let new_set: HashMap<&str, &LanConfig> = new.iter().map(|l| (l.domain.as_str(), l)).collect();

    for lan in new {
        if !old_set.contains_key(lan.domain.as_str()) {
            d.lans_added.push(lan.clone());
        }
    }
    for lan in old {
        if !new_set.contains_key(lan.domain.as_str()) {
            d.lans_removed.push(lan.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peers_added() {
        let old = Config::default();
        let mut new = Config::default();
        new.peers.insert("aabb.zigor.net".into(), PeerConfig {
            alias: "new".into(),
            direct: vec!["1.2.3.4:51820".into()],
            relay: vec![],
        });

        let d = diff(&old, &new);
        assert_eq!(d.peers_added.len(), 1);
        assert!(d.peers_added.contains_key("aabb.zigor.net"));
        assert!(d.peers_removed.is_empty());
    }

    #[test]
    fn test_peers_removed() {
        let mut old = Config::default();
        old.peers.insert("aabb.zigor.net".into(), PeerConfig {
            alias: "old".into(), direct: vec![], relay: vec!["r".into()],
        });
        let new = Config::default();

        let d = diff(&old, &new);
        assert_eq!(d.peers_removed.len(), 1);
    }

    #[test]
    fn test_peers_changed() {
        let mut old = Config::default();
        old.peers.insert("aabb.zigor.net".into(), PeerConfig {
            alias: "p".into(), direct: vec!["1.1.1.1:51820".into()], relay: vec![],
        });
        let mut new = Config::default();
        new.peers.insert("aabb.zigor.net".into(), PeerConfig {
            alias: "p".into(), direct: vec!["2.2.2.2:51820".into()], relay: vec![],
        });

        let d = diff(&old, &new);
        assert_eq!(d.peers_changed.len(), 1);
    }

    #[test]
    fn test_identical() {
        let cfg = Config::default();
        let d = diff(&cfg, &cfg);
        assert!(d.is_empty());
    }

    #[test]
    fn test_lans_added() {
        let old = Config::default();
        let mut new = Config::default();
        new.lans.push(LanConfig {
            domain: "new.zigor.net".into(),
            pubkey: "abc".into(),
            endpoint: "1.2.3.4:51820".into(),
        });

        let d = diff(&old, &new);
        assert_eq!(d.lans_added.len(), 1);
    }

    #[test]
    fn test_inbound_changed() {
        let mut old = Config::default();
        old.inbound_policy.default = "deny".into();
        let mut new = Config::default();
        new.inbound_policy.default = "allow".into();

        let d = diff(&old, &new);
        assert!(d.inbound_changed);
    }

    #[test]
    fn test_route_changed() {
        let old = Config::default();
        let mut new = Config::default();
        new.route.rules.push(super::super::RouteRule {
            domain: "*.google.com".into(),
            domain_list: String::new(),
            peer: "p".into(),
        });

        let d = diff(&old, &new);
        assert!(d.route_changed);
    }
}
