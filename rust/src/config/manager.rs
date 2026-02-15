use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use super::{
    Config, ConfigError, InboundPolicy, LanConfig, PeerConfig, RouteConfig,
    diff::{ConfigDiff, diff},
    labels::LabelStore,
    policy::{PolicyEngine, PolicyResult},
    route::{RouteMatcher, RouteResult},
};

/// Receives notifications when configuration changes.
pub trait Watcher: Send + Sync {
    fn on_peers_changed(
        &self,
        added: &HashMap<String, PeerConfig>,
        removed: &[String],
        changed: &HashMap<String, PeerConfig>,
    );
    fn on_lans_changed(&self, added: &[LanConfig], removed: &[LanConfig]);
    fn on_inbound_policy_changed(&self, policy: &InboundPolicy);
    fn on_route_changed(&self, route: &RouteConfig);
}

/// Manages the lifecycle of a configuration file:
/// loading, validation, hot-reloading, diffing, and change notification.
pub struct Manager {
    path: PathBuf,
    inner: Arc<RwLock<ManagerInner>>,
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

struct ManagerInner {
    current: Config,
    route: RouteMatcher,
    policy: PolicyEngine,
    label_store: Arc<LabelStore>,
    watchers: Vec<Arc<dyn Watcher>>,
    config_mtime: SystemTime,
    ext_files: HashMap<String, SystemTime>,
}

/// Error returned by Manager operations.
#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("config: {0}")]
    Io(#[from] std::io::Error),
}

impl Manager {
    /// Create a new Manager by loading the config file at the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, ManagerError> {
        let path = path.as_ref().to_path_buf();
        let cfg = super::load(&path)?;
        let route = RouteMatcher::new(&cfg.route);

        let label_store = Arc::new(LabelStore::new());
        label_store.load_from_config(&cfg.peers);

        let policy = PolicyEngine::with_label_store(
            &cfg.inbound_policy, Arc::clone(&label_store))?;

        let mut ext_files = HashMap::new();
        track_external_files(&cfg, &mut ext_files);

        let inner = ManagerInner {
            current: cfg,
            route,
            policy,
            label_store,
            watchers: Vec::new(),
            config_mtime: file_mtime(&path),
            ext_files,
        };

        Ok(Self {
            path,
            inner: Arc::new(RwLock::new(inner)),
            stop_tx: None,
        })
    }

    /// Get the current configuration (read-only).
    pub fn current(&self) -> Config {
        self.inner.read().unwrap().current.clone()
    }

    /// Check if a domain matches any outbound route rule.
    pub fn match_route(&self, domain: &str) -> Option<RouteResult> {
        self.inner.read().unwrap().route.match_domain(domain)
    }

    /// Evaluate inbound policy for a peer's public key.
    pub fn check_inbound(&self, pubkey: &[u8; 32]) -> PolicyResult {
        self.inner.read().unwrap().policy.check(pubkey)
    }

    /// Register a watcher to receive change notifications.
    pub fn watch(&self, w: Arc<dyn Watcher>) {
        self.inner.write().unwrap().watchers.push(w);
    }

    /// Start periodic polling for configuration changes.
    /// Uses tokio runtime. Non-blocking.
    pub fn start(&mut self, poll_interval: Duration) {
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        self.stop_tx = Some(tx);

        let path = self.path.clone();
        let inner = Arc::clone(&self.inner);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(poll_interval);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if config_file_changed(&path, &inner) || ext_files_changed(&inner) {
                            if let Err(e) = reload_inner(&path, &inner) {
                                eprintln!("config: reload error: {e}");
                            }
                        }
                    }
                    _ = &mut rx => break,
                }
            }
        });
    }

    /// Stop the polling loop.
    pub fn stop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
    }

    /// Manually reload the configuration from disk.
    pub fn reload(&self) -> Result<Option<ConfigDiff>, ManagerError> {
        reload_inner(&self.path, &self.inner)
    }
}

fn reload_inner(path: &Path, inner: &Arc<RwLock<ManagerInner>>) -> Result<Option<ConfigDiff>, ManagerError> {
    let new_cfg = super::load(path)?;

    let old_cfg = {
        let guard = inner.read().unwrap();
        guard.current.clone()
    };

    let mut d = diff(&old_cfg, &new_cfg);

    // Check external file changes
    let ext_changed = {
        let guard = inner.read().unwrap();
        check_ext_files_changed(&guard.ext_files)
    };

    if ext_changed {
        // Only policy has external files (whitelist), route rules are inline.
        // Just mark inbound changed — a new PolicyEngine will be created below
        // which loads the updated whitelist files.
        d.inbound_changed = true;
    }

    if d.is_empty() && !ext_changed {
        return Ok(None);
    }

    // Rebuild route/policy if sections changed
    let new_route = if d.route_changed {
        Some(RouteMatcher::new(&new_cfg.route))
    } else {
        None
    };

    // Refresh labels from config peers on any peer change
    let peers_changed = !d.peers_added.is_empty() || !d.peers_removed.is_empty() || !d.peers_changed.is_empty();
    let label_store = {
        let guard = inner.read().unwrap();
        Arc::clone(&guard.label_store)
    };
    if peers_changed {
        // Clean up host labels for removed peers
        for domain in &d.peers_removed {
            if let Some(pk) = super::labels::pubkey_hex_from_domain(domain) {
                label_store.remove_labels(&pk, "host.zigor.net");
            }
        }
        label_store.load_from_config(&new_cfg.peers);
    }

    let new_policy = if d.inbound_changed {
        Some(PolicyEngine::with_label_store(
            &new_cfg.inbound_policy, Arc::clone(&label_store))?)
    } else {
        None
    };

    // Update inner state
    let watchers = {
        let mut guard = inner.write().unwrap();
        guard.current = new_cfg.clone();
        guard.config_mtime = file_mtime(path);
        track_external_files(&new_cfg, &mut guard.ext_files);
        if let Some(r) = new_route {
            guard.route = r;
        }
        if let Some(p) = new_policy {
            guard.policy = p;
        }
        guard.watchers.clone()
    };

    // Notify watchers
    notify_watchers(&watchers, &d, &new_cfg);

    Ok(Some(d))
}

fn notify_watchers(watchers: &[Arc<dyn Watcher>], diff: &ConfigDiff, cfg: &Config) {
    for w in watchers {
        if !diff.peers_added.is_empty() || !diff.peers_removed.is_empty() || !diff.peers_changed.is_empty() {
            w.on_peers_changed(&diff.peers_added, &diff.peers_removed, &diff.peers_changed);
        }
        if !diff.lans_added.is_empty() || !diff.lans_removed.is_empty() {
            w.on_lans_changed(&diff.lans_added, &diff.lans_removed);
        }
        if diff.inbound_changed {
            w.on_inbound_policy_changed(&cfg.inbound_policy);
        }
        if diff.route_changed {
            w.on_route_changed(&cfg.route);
        }
    }
}

fn config_file_changed(path: &Path, inner: &Arc<RwLock<ManagerInner>>) -> bool {
    let last = inner.read().unwrap().config_mtime;
    let current = file_mtime(path);
    current != last
}

fn ext_files_changed(inner: &Arc<RwLock<ManagerInner>>) -> bool {
    let guard = inner.read().unwrap();
    check_ext_files_changed(&guard.ext_files)
}

fn check_ext_files_changed(ext_files: &HashMap<String, SystemTime>) -> bool {
    for (path, last_mtime) in ext_files {
        let current = file_mtime(Path::new(path));
        if current != *last_mtime {
            return true;
        }
    }
    false
}

fn track_external_files(cfg: &Config, ext_files: &mut HashMap<String, SystemTime>) {
    ext_files.clear();
    for rule in &cfg.inbound_policy.rules {
        if rule.match_config.pubkey.match_type == "whitelist" && !rule.match_config.pubkey.path.is_empty() {
            let p = &rule.match_config.pubkey.path;
            ext_files.insert(p.clone(), file_mtime(Path::new(p)));
        }
    }
}

fn file_mtime(path: &Path) -> SystemTime {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    const MINIMAL_CONFIG: &str = r#"
net:
  private_key: "/tmp/test.key"
  tun_ipv4: "100.64.0.1"
  tun_mtu: 1400
  listen_port: 51820
"#;

    struct TestWatcher {
        peers_count: AtomicU32,
        route_count: AtomicU32,
    }

    impl TestWatcher {
        fn new() -> Self {
            Self {
                peers_count: AtomicU32::new(0),
                route_count: AtomicU32::new(0),
            }
        }
    }

    impl Watcher for TestWatcher {
        fn on_peers_changed(&self, _: &HashMap<String, PeerConfig>, _: &[String], _: &HashMap<String, PeerConfig>) {
            self.peers_count.fetch_add(1, Ordering::Relaxed);
        }
        fn on_lans_changed(&self, _: &[LanConfig], _: &[LanConfig]) {}
        fn on_inbound_policy_changed(&self, _: &InboundPolicy) {}
        fn on_route_changed(&self, _: &RouteConfig) {
            self.route_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_new_and_current() {
        let dir = std::env::temp_dir().join("zgrnet_mgr_test_new");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.yaml");
        std::fs::write(&path, MINIMAL_CONFIG).unwrap();

        let m = Manager::new(&path).unwrap();
        assert_eq!(m.current().net.tun_ipv4, "100.64.0.1");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reload_with_change() {
        let dir = std::env::temp_dir().join("zgrnet_mgr_test_reload");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.yaml");
        std::fs::write(&path, MINIMAL_CONFIG).unwrap();

        let m = Manager::new(&path).unwrap();

        let new_config = format!("{MINIMAL_CONFIG}\npeers:\n  \"abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa.zigor.net\":\n    alias: peer_us\n    direct:\n      - \"1.2.3.4:51820\"\n");
        std::fs::write(&path, &new_config).unwrap();

        let diff = m.reload().unwrap();
        assert!(diff.is_some());
        let d = diff.unwrap();
        assert_eq!(d.peers_added.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reload_no_change() {
        let dir = std::env::temp_dir().join("zgrnet_mgr_test_nochange");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.yaml");
        std::fs::write(&path, MINIMAL_CONFIG).unwrap();

        let m = Manager::new(&path).unwrap();
        let diff = m.reload().unwrap();
        assert!(diff.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_watcher_notification() {
        let dir = std::env::temp_dir().join("zgrnet_mgr_test_watcher");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.yaml");
        std::fs::write(&path, MINIMAL_CONFIG).unwrap();

        let m = Manager::new(&path).unwrap();
        let w = Arc::new(TestWatcher::new());
        m.watch(w.clone());

        let new_config = format!("{MINIMAL_CONFIG}\npeers:\n  \"abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa.zigor.net\":\n    alias: peer_us\n    direct:\n      - \"1.2.3.4:51820\"\n");
        std::fs::write(&path, &new_config).unwrap();

        m.reload().unwrap();
        assert_eq!(w.peers_count.load(Ordering::Relaxed), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_route_match() {
        let dir = std::env::temp_dir().join("zgrnet_mgr_test_route");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.yaml");
        let config = format!("{MINIMAL_CONFIG}\nroute:\n  rules:\n    - domain: \"*.google.com\"\n      peer: peer_us\n");
        std::fs::write(&path, &config).unwrap();

        let m = Manager::new(&path).unwrap();
        assert!(m.match_route("www.google.com").is_some());
        assert!(m.match_route("example.com").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_policy_check() {
        let dir = std::env::temp_dir().join("zgrnet_mgr_test_policy");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.yaml");
        let config = format!("{MINIMAL_CONFIG}\ninbound_policy:\n  default: deny\n  rules:\n    - name: open\n      match:\n        pubkey:\n          type: any\n      services:\n        - proto: \"*\"\n          port: \"*\"\n      action: allow\n");
        std::fs::write(&path, &config).unwrap();

        let m = Manager::new(&path).unwrap();
        let result = m.check_inbound(&[1u8; 32]);
        assert_eq!(result.action, "allow");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
