package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func writeTestConfig(t *testing.T, dir string, content string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// minimalConfig is the simplest valid config for testing the manager.
const minimalConfig = `
net:
  private_key: "/tmp/test.key"
  tun_ipv4: "100.64.0.1"
  tun_mtu: 1400
  listen_port: 51820
`

func TestManager_NewAndCurrent(t *testing.T) {
	dir := t.TempDir()
	path := writeTestConfig(t, dir, minimalConfig)

	m, err := NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	cfg := m.Current()
	if cfg.Net.TunIPv4 != "100.64.0.1" {
		t.Errorf("tun_ipv4 = %q", cfg.Net.TunIPv4)
	}
}

func TestManager_Reload(t *testing.T) {
	dir := t.TempDir()
	path := writeTestConfig(t, dir, minimalConfig)

	m, err := NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	// Update config with a peer
	newConfig := minimalConfig + `
peers:
  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa.zigor.net":
    alias: peer_us
    direct:
      - "1.2.3.4:51820"
`
	if err := os.WriteFile(path, []byte(newConfig), 0644); err != nil {
		t.Fatal(err)
	}

	diff, err := m.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if diff == nil {
		t.Fatal("expected non-nil diff")
	}
	if len(diff.PeersAdded) != 1 {
		t.Errorf("PeersAdded = %d, want 1", len(diff.PeersAdded))
	}

	// Current should reflect new config
	cfg := m.Current()
	if len(cfg.Peers) != 1 {
		t.Errorf("len(peers) = %d, want 1", len(cfg.Peers))
	}
}

func TestManager_ReloadNoChange(t *testing.T) {
	dir := t.TempDir()
	path := writeTestConfig(t, dir, minimalConfig)

	m, err := NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	diff, err := m.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if diff != nil {
		t.Error("expected nil diff for unchanged config")
	}
}

// testWatcher records all change notifications for verification.
type testWatcher struct {
	mu              sync.Mutex
	peersChangeCnt  int
	lansChangeCnt   int
	inboundChangeCnt int
	routeChangeCnt  int
}

func (w *testWatcher) OnPeersChanged(added map[string]PeerConfig, removed []string, changed map[string]PeerConfig) {
	w.mu.Lock()
	w.peersChangeCnt++
	w.mu.Unlock()
}

func (w *testWatcher) OnLansChanged(added []LanConfig, removed []LanConfig) {
	w.mu.Lock()
	w.lansChangeCnt++
	w.mu.Unlock()
}

func (w *testWatcher) OnInboundPolicyChanged(policy *InboundPolicy) {
	w.mu.Lock()
	w.inboundChangeCnt++
	w.mu.Unlock()
}

func (w *testWatcher) OnRouteChanged(route *RouteConfig) {
	w.mu.Lock()
	w.routeChangeCnt++
	w.mu.Unlock()
}

func TestManager_WatcherNotification(t *testing.T) {
	dir := t.TempDir()
	path := writeTestConfig(t, dir, minimalConfig)

	m, err := NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	w := &testWatcher{}
	m.Watch(w)

	// Add a peer
	newConfig := minimalConfig + `
peers:
  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa.zigor.net":
    alias: peer_us
    direct:
      - "1.2.3.4:51820"
`
	if err := os.WriteFile(path, []byte(newConfig), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := m.Reload(); err != nil {
		t.Fatal(err)
	}

	w.mu.Lock()
	if w.peersChangeCnt != 1 {
		t.Errorf("peers change count = %d, want 1", w.peersChangeCnt)
	}
	w.mu.Unlock()
}

func TestManager_HotReload(t *testing.T) {
	dir := t.TempDir()
	path := writeTestConfig(t, dir, minimalConfig)

	m, err := NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	w := &testWatcher{}
	m.Watch(w)

	// Start polling with short interval
	m.Start(50 * time.Millisecond)

	// Wait a bit, then modify config
	time.Sleep(100 * time.Millisecond)

	newConfig := minimalConfig + `
peers:
  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa.zigor.net":
    alias: peer_us
    direct:
      - "1.2.3.4:51820"
route:
  rules:
    - domain: "*.google.com"
      peer: peer_us
`
	if err := os.WriteFile(path, []byte(newConfig), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait for polling to pick up the change
	time.Sleep(200 * time.Millisecond)

	w.mu.Lock()
	peersChanged := w.peersChangeCnt
	routeChanged := w.routeChangeCnt
	w.mu.Unlock()

	if peersChanged < 1 {
		t.Errorf("peers change count = %d, want >= 1", peersChanged)
	}
	if routeChanged < 1 {
		t.Errorf("route change count = %d, want >= 1", routeChanged)
	}

	// Current config should have the peer
	cfg := m.Current()
	if len(cfg.Peers) != 1 {
		t.Errorf("len(peers) = %d, want 1", len(cfg.Peers))
	}
}

func TestManager_RouteMatch(t *testing.T) {
	dir := t.TempDir()
	config := minimalConfig + `
route:
  rules:
    - domain: "*.google.com"
      peer: peer_us
    - domain: "*.nicovideo.jp"
      peer: peer_jp
`
	path := writeTestConfig(t, dir, config)

	m, err := NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	result, ok := m.MatchRoute("www.google.com")
	if !ok {
		t.Fatal("expected match for www.google.com")
	}
	if result.Peer != "peer_us" {
		t.Errorf("peer = %q, want peer_us", result.Peer)
	}

	_, ok = m.MatchRoute("example.com")
	if ok {
		t.Error("expected no match for example.com")
	}
}

func TestManager_PolicyCheck(t *testing.T) {
	dir := t.TempDir()
	config := minimalConfig + `
inbound_policy:
  default: deny
  rules:
    - name: "open"
      match:
        pubkey:
          type: any
      services:
        - proto: "*"
          port: "*"
      action: allow
`
	path := writeTestConfig(t, dir, config)

	m, err := NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	result := m.CheckInbound([32]byte{1, 2, 3})
	if result.Action != "allow" {
		t.Errorf("action = %q, want allow", result.Action)
	}
}
