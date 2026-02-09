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

	route  *RouteMatcher
	policy *PolicyEngine

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

	policy, err := NewPolicyEngine(&cfg.InboundPolicy)
	if err != nil {
		return nil, fmt.Errorf("config: build policy engine: %w", err)
	}

	m := &Manager{
		path:     path,
		current:  cfg,
		route:    route,
		policy:   policy,
		extFiles: make(map[string]time.Time),
		stopChan: make(chan struct{}),
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
	return m.route.Match(domain)
}

// CheckInbound evaluates inbound policy for a peer's public key.
func (m *Manager) CheckInbound(pubkey [32]byte) *PolicyResult {
	return m.policy.Check(pubkey)
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
		// Reload external file data in route/policy
		if err := m.route.Reload(); err != nil {
			log.Printf("config: route reload error: %v", err)
		}
		if err := m.policy.Reload(); err != nil {
			log.Printf("config: policy reload error: %v", err)
		}
		// Mark these sections as changed so watchers get notified
		diff.RouteChanged = true
		diff.InboundChanged = true
	}

	if diff.IsEmpty() && !extChanged {
		return nil, nil
	}

	// Rebuild route/policy if the config sections changed
	if diff.RouteChanged {
		newRoute, err := NewRouteMatcher(&newCfg.Route)
		if err != nil {
			return nil, fmt.Errorf("config: rebuild route matcher: %w", err)
		}
		m.route = newRoute
	}
	if diff.InboundChanged {
		newPolicy, err := NewPolicyEngine(&newCfg.InboundPolicy)
		if err != nil {
			return nil, fmt.Errorf("config: rebuild policy engine: %w", err)
		}
		m.policy = newPolicy
	}

	// Update current config
	m.mu.Lock()
	m.current = newCfg
	m.configMtime = fileMtime(m.path)
	m.trackExternalFiles(newCfg)
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

	// Track domain list files
	for _, rule := range cfg.Route.Rules {
		if rule.DomainList != "" {
			m.extFiles[rule.DomainList] = fileMtime(rule.DomainList)
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
