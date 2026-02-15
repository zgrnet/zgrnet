package config

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// Watcher receives notifications when configuration changes.
// Implementations must be safe for concurrent calls.
type Watcher interface {
	OnPeersChanged(added map[string]PeerConfig, removed []string, changed map[string]PeerConfig)
	OnLansChanged(added []LanConfig, removed []LanConfig)
	OnInboundPolicyChanged(policy *InboundPolicy)
	OnRouteChanged(route *RouteConfig)
}

// Manager manages the lifecycle of a configuration file:
// loading, validation, hot-reloading, diffing, and change notification.
//
// Thread-safe for concurrent access.
type Manager struct {
	path string

	mu       sync.RWMutex
	current  *Config
	watchers []Watcher

	route      *RouteMatcher
	policy     *PolicyEngine
	labelStore *LabelStore

	// File modification tracking
	configMtime time.Time
	extFiles    map[string]time.Time // external file path -> last known mtime

	stopChan chan struct{}
	stopped  bool
}

// NewManager creates a new config Manager by loading the config file at path.
// Returns an error if the file cannot be read or the config is invalid.
func NewManager(path string) (*Manager, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}

	route, err := NewRouteMatcher(&cfg.Route)
	if err != nil {
		return nil, fmt.Errorf("config: build route matcher: %w", err)
	}

	labelStore := NewLabelStore()
	labelStore.LoadFromConfig(cfg.Peers)

	policy, err := NewPolicyEngine(&cfg.InboundPolicy, labelStore)
	if err != nil {
		return nil, fmt.Errorf("config: build policy engine: %w", err)
	}

	m := &Manager{
		path:       path,
		current:    cfg,
		route:      route,
		policy:     policy,
		labelStore: labelStore,
		extFiles:   make(map[string]time.Time),
		stopChan:   make(chan struct{}),
	}

	// Track config file mtime
	m.configMtime = fileMtime(path)

	// Track external files referenced in config
	m.trackExternalFiles(cfg)

	return m, nil
}

// Current returns the current configuration. The returned pointer is
// read-only — callers must not modify it.
func (m *Manager) Current() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// MatchRoute checks if a domain matches any outbound route rule.
func (m *Manager) MatchRoute(domain string) (RouteResult, bool) {
	m.mu.RLock()
	route := m.route
	m.mu.RUnlock()
	return route.Match(domain)
}

// CheckInbound evaluates inbound policy for a peer's public key.
func (m *Manager) CheckInbound(pubkey [32]byte) *PolicyResult {
	m.mu.RLock()
	policy := m.policy
	m.mu.RUnlock()
	return policy.Check(pubkey)
}

// LabelStore returns the label store used for label-based policy matching.
func (m *Manager) LabelStore() *LabelStore {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.labelStore
}

// Watch registers a watcher to receive change notifications.
// Must be called before Start().
func (m *Manager) Watch(w Watcher) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.watchers = append(m.watchers, w)
}

// Start begins periodic polling for configuration changes.
// The poll interval is how often the manager checks for file modifications.
// This call is non-blocking; use Stop() to terminate.
func (m *Manager) Start(pollInterval time.Duration) {
	go m.pollLoop(pollInterval)
}

// Stop terminates the polling loop.
func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.stopped {
		m.stopped = true
		close(m.stopChan)
	}
	m.mu.Unlock()
}

// Reload manually reloads the configuration from disk.
// If the config changed, watchers are notified.
// Returns the diff, or nil if nothing changed.
func (m *Manager) Reload() (*ConfigDiff, error) {
	newCfg, err := Load(m.path)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	oldCfg := m.current
	m.mu.Unlock()

	diff := Diff(oldCfg, newCfg)

	// Also check if external files changed
	extChanged := m.checkExternalFilesChanged()
	if extChanged {
		// Mark these sections as changed so watchers get notified
		diff.RouteChanged = true
		diff.InboundChanged = true
	}

	if diff.IsEmpty() && !extChanged {
		return nil, nil
	}

	// Build new route/policy BEFORE acquiring the lock (avoid holding lock during I/O).
	// Build first, swap later — if init fails, old state is preserved.
	var newRoute *RouteMatcher
	var newPolicy *PolicyEngine
	if diff.RouteChanged {
		r, err := NewRouteMatcher(&newCfg.Route)
		if err != nil {
			return nil, fmt.Errorf("config: rebuild route matcher: %w", err)
		}
		newRoute = r
	}

	// Refresh labels from config peers on any peer or inbound change
	peersChanged := len(diff.PeersAdded) > 0 || len(diff.PeersRemoved) > 0 || len(diff.PeersChanged) > 0
	if peersChanged {
		// Clean up host labels for removed peers
		for _, domain := range diff.PeersRemoved {
			pubkeyHex := pubkeyHexFromDomain(domain)
			if pubkeyHex != "" {
				m.labelStore.RemoveLabels(pubkeyHex, "host.zigor.net")
			}
		}
		m.labelStore.LoadFromConfig(newCfg.Peers)
	}

	if diff.InboundChanged {
		p, err := NewPolicyEngine(&newCfg.InboundPolicy, m.labelStore)
		if err != nil {
			return nil, fmt.Errorf("config: rebuild policy engine: %w", err)
		}
		newPolicy = p
	}

	// Swap everything under the lock
	m.mu.Lock()
	m.current = newCfg
	m.configMtime = fileMtime(m.path)
	m.trackExternalFiles(newCfg)
	if newRoute != nil {
		m.route = newRoute
	}
	if newPolicy != nil {
		m.policy = newPolicy
	}
	watchers := make([]Watcher, len(m.watchers))
	copy(watchers, m.watchers)
	m.mu.Unlock()

	// Notify watchers
	m.notifyWatchers(watchers, diff, newCfg)

	return diff, nil
}

func (m *Manager) pollLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			if m.configFileChanged() || m.checkExternalFilesChanged() {
				if _, err := m.Reload(); err != nil {
					log.Printf("config: reload error: %v", err)
				}
			}
		}
	}
}

func (m *Manager) configFileChanged() bool {
	m.mu.RLock()
	lastMtime := m.configMtime
	m.mu.RUnlock()

	currentMtime := fileMtime(m.path)
	return !currentMtime.Equal(lastMtime)
}

func (m *Manager) checkExternalFilesChanged() bool {
	m.mu.RLock()
	files := make(map[string]time.Time, len(m.extFiles))
	for k, v := range m.extFiles {
		files[k] = v
	}
	m.mu.RUnlock()

	for path, lastMtime := range files {
		currentMtime := fileMtime(path)
		if !currentMtime.Equal(lastMtime) {
			return true
		}
	}
	return false
}

func (m *Manager) trackExternalFiles(cfg *Config) {
	m.extFiles = make(map[string]time.Time)

	// Track whitelist files
	for _, rule := range cfg.InboundPolicy.Rules {
		if rule.Match.Pubkey.Type == "whitelist" && rule.Match.Pubkey.Path != "" {
			m.extFiles[rule.Match.Pubkey.Path] = fileMtime(rule.Match.Pubkey.Path)
		}
	}
}

func (m *Manager) notifyWatchers(watchers []Watcher, diff *ConfigDiff, cfg *Config) {
	for _, w := range watchers {
		if len(diff.PeersAdded) > 0 || len(diff.PeersRemoved) > 0 || len(diff.PeersChanged) > 0 {
			w.OnPeersChanged(diff.PeersAdded, diff.PeersRemoved, diff.PeersChanged)
		}
		if len(diff.LansAdded) > 0 || len(diff.LansRemoved) > 0 {
			w.OnLansChanged(diff.LansAdded, diff.LansRemoved)
		}
		if diff.InboundChanged {
			w.OnInboundPolicyChanged(&cfg.InboundPolicy)
		}
		if diff.RouteChanged {
			w.OnRouteChanged(&cfg.Route)
		}
	}
}

// fileMtime returns the modification time of a file, or zero time if the file
// doesn't exist or can't be stat'd.
func fileMtime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
