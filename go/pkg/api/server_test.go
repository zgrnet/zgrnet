package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/vibing/zgrnet/pkg/config"
	"github.com/vibing/zgrnet/pkg/host"
	"github.com/vibing/zgrnet/pkg/noise"
)

// mockTUN implements host.TunDevice for testing.
type mockTUN struct {
	readCh  chan []byte
	closeCh chan struct{}
	closed  atomic.Bool
}

func newMockTUN() *mockTUN {
	return &mockTUN{
		readCh:  make(chan []byte, 16),
		closeCh: make(chan struct{}),
	}
}

func (m *mockTUN) Read(buf []byte) (int, error) {
	select {
	case pkt := <-m.readCh:
		return copy(buf, pkt), nil
	case <-m.closeCh:
		return 0, io.ErrClosedPipe
	}
}

func (m *mockTUN) Write(buf []byte) (int, error) {
	if m.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return len(buf), nil
}

func (m *mockTUN) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	close(m.closeCh)
	return nil
}

// testEnv bundles test dependencies.
type testEnv struct {
	Server  *Server
	Host    *host.Host
	CfgMgr *config.Manager
	CfgPath string
	TmpDir  string
	KeyA    *noise.KeyPair // local host key
	KeyB    *noise.KeyPair // test peer key
}

const minimalConfig = `net:
  private_key: "private.key"
  tun_ipv4: "100.64.0.1"
  tun_mtu: 1400
  listen_port: 0
`

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(minimalConfig), 0644); err != nil {
		t.Fatal(err)
	}

	cfgMgr, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	keyA, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	h, err := host.New(host.Config{
		PrivateKey: keyA,
		TunIPv4:    net.IPv4(100, 64, 0, 1),
		MTU:        1400,
	}, newMockTUN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })

	srv := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		Host:       h,
		ConfigMgr:  cfgMgr,
	})

	return &testEnv{
		Server:  srv,
		Host:    h,
		CfgMgr:  cfgMgr,
		CfgPath: cfgPath,
		TmpDir:  dir,
		KeyA:    keyA,
		KeyB:    keyB,
	}
}

// doRequest sends an HTTP request to the API server handler and returns the response.
func (e *testEnv) doRequest(method, path string, body interface{}) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	e.Server.server.Handler.ServeHTTP(rr, req)
	return rr
}

// decodeJSON decodes the response body into the target.
func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder, target interface{}) {
	t.Helper()
	if err := json.NewDecoder(rr.Body).Decode(target); err != nil {
		t.Fatalf("decode JSON: %v (body: %s)", err, rr.Body.String())
	}
}

// ─── Tests ──────────────────────────────────────────────────────────────────

func TestWhoAmI(t *testing.T) {
	env := newTestEnv(t)

	rr := env.doRequest("GET", "/api/whoami", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	decodeJSON(t, rr, &resp)

	if resp["pubkey"] == nil || resp["pubkey"] == "" {
		t.Error("missing pubkey")
	}
	if resp["tun_ip"] != "100.64.0.1" {
		t.Errorf("expected tun_ip=100.64.0.1, got %v", resp["tun_ip"])
	}
	if resp["uptime_sec"] == nil {
		t.Error("missing uptime_sec")
	}
}

func TestConfigNet(t *testing.T) {
	env := newTestEnv(t)

	rr := env.doRequest("GET", "/api/config/net", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp config.NetConfig
	decodeJSON(t, rr, &resp)

	if resp.TunIPv4 != "100.64.0.1" {
		t.Errorf("expected tun_ipv4=100.64.0.1, got %s", resp.TunIPv4)
	}
	if resp.TunMTU != 1400 {
		t.Errorf("expected tun_mtu=1400, got %d", resp.TunMTU)
	}
}

func TestPeersCRUD(t *testing.T) {
	env := newTestEnv(t)
	peerPK := env.KeyB.Public.String()

	// ── List: initially empty ──
	rr := env.doRequest("GET", "/api/peers", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rr.Code)
	}
	var peers []map[string]interface{}
	decodeJSON(t, rr, &peers)
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers, got %d", len(peers))
	}

	// ── Add peer ──
	rr = env.doRequest("POST", "/api/peers", map[string]interface{}{
		"pubkey":   peerPK,
		"alias":    "test-peer",
		"endpoint": "127.0.0.1:51820",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("add: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var addResp map[string]interface{}
	decodeJSON(t, rr, &addResp)
	if addResp["pubkey"] != peerPK {
		t.Errorf("add: pubkey mismatch: got %v", addResp["pubkey"])
	}
	if addResp["alias"] != "test-peer" {
		t.Errorf("add: alias mismatch: got %v", addResp["alias"])
	}

	// ── List: should have 1 peer ──
	rr = env.doRequest("GET", "/api/peers", nil)
	decodeJSON(t, rr, &peers)
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}

	// ── Get single peer ──
	rr = env.doRequest("GET", "/api/peers/"+peerPK, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var getPeer map[string]interface{}
	decodeJSON(t, rr, &getPeer)
	if getPeer["alias"] != "test-peer" {
		t.Errorf("get: alias mismatch: got %v", getPeer["alias"])
	}

	// ── Update peer ──
	newAlias := "updated-peer"
	rr = env.doRequest("PUT", "/api/peers/"+peerPK, map[string]interface{}{
		"alias": newAlias,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("update: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var updateResp map[string]interface{}
	decodeJSON(t, rr, &updateResp)
	if updateResp["alias"] != newAlias {
		t.Errorf("update: alias not updated: got %v", updateResp["alias"])
	}

	// ── Verify update persisted ──
	rr = env.doRequest("GET", "/api/peers/"+peerPK, nil)
	decodeJSON(t, rr, &getPeer)
	if getPeer["alias"] != newAlias {
		t.Errorf("verify update: alias=%v, want %s", getPeer["alias"], newAlias)
	}

	// ── Add duplicate peer should fail ──
	rr = env.doRequest("POST", "/api/peers", map[string]interface{}{
		"pubkey": peerPK,
		"alias":  "dup",
	})
	if rr.Code != http.StatusConflict {
		t.Fatalf("dup add: expected 409, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── Delete peer ──
	rr = env.doRequest("DELETE", "/api/peers/"+peerPK, nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── List: should be empty again ──
	rr = env.doRequest("GET", "/api/peers", nil)
	decodeJSON(t, rr, &peers)
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers after delete, got %d", len(peers))
	}

	// ── Get deleted peer should 404 ──
	rr = env.doRequest("GET", "/api/peers/"+peerPK, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("get deleted: expected 404, got %d", rr.Code)
	}

	// ── Delete nonexistent should 404 ──
	rr = env.doRequest("DELETE", "/api/peers/"+peerPK, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("delete again: expected 404, got %d", rr.Code)
	}
}

func TestPeersPersistence(t *testing.T) {
	env := newTestEnv(t)
	peerPK := env.KeyB.Public.String()

	// Add a peer
	rr := env.doRequest("POST", "/api/peers", map[string]interface{}{
		"pubkey":   peerPK,
		"alias":    "persist-test",
		"endpoint": "1.2.3.4:51820",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("add: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// Read config file from disk and verify it was saved
	data, err := os.ReadFile(env.CfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	cfg, err := config.LoadFromBytes(data)
	if err != nil {
		t.Fatalf("parse saved config: %v", err)
	}

	domain := pubkeyToDomain(peerPK)
	pc, ok := cfg.Peers[domain]
	if !ok {
		t.Fatalf("peer not found in saved config (domain=%s)", domain)
	}
	if pc.Alias != "persist-test" {
		t.Errorf("saved alias=%q, want persist-test", pc.Alias)
	}
	if len(pc.Direct) == 0 || pc.Direct[0] != "1.2.3.4:51820" {
		t.Errorf("saved direct=%v, want [1.2.3.4:51820]", pc.Direct)
	}
}

func TestLansCRUD(t *testing.T) {
	env := newTestEnv(t)

	// ── List: initially empty ──
	rr := env.doRequest("GET", "/api/lans", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rr.Code)
	}
	var lans []config.LanConfig
	decodeJSON(t, rr, &lans)
	if len(lans) != 0 {
		t.Fatalf("expected 0 lans, got %d", len(lans))
	}

	// ── Add lan ──
	lanPK := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	rr = env.doRequest("POST", "/api/lans", map[string]interface{}{
		"domain":   "test.zigor.net",
		"pubkey":   lanPK,
		"endpoint": "10.0.0.1:51820",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("add: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── List: should have 1 ──
	rr = env.doRequest("GET", "/api/lans", nil)
	decodeJSON(t, rr, &lans)
	if len(lans) != 1 {
		t.Fatalf("expected 1 lan, got %d", len(lans))
	}
	if lans[0].Domain != "test.zigor.net" {
		t.Errorf("domain mismatch: %s", lans[0].Domain)
	}

	// ── Add duplicate should fail ──
	rr = env.doRequest("POST", "/api/lans", map[string]interface{}{
		"domain":   "test.zigor.net",
		"pubkey":   lanPK,
		"endpoint": "10.0.0.2:51820",
	})
	if rr.Code != http.StatusConflict {
		t.Fatalf("dup add: expected 409, got %d", rr.Code)
	}

	// ── Delete lan ──
	rr = env.doRequest("DELETE", "/api/lans/test.zigor.net", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── List: should be empty ──
	rr = env.doRequest("GET", "/api/lans", nil)
	decodeJSON(t, rr, &lans)
	if len(lans) != 0 {
		t.Fatalf("expected 0 lans after delete, got %d", len(lans))
	}

	// ── Delete nonexistent should 404 ──
	rr = env.doRequest("DELETE", "/api/lans/nope.zigor.net", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("delete nonexistent: expected 404, got %d", rr.Code)
	}
}

func TestPolicyCRUD(t *testing.T) {
	env := newTestEnv(t)

	// ── Get: initially empty rules ──
	rr := env.doRequest("GET", "/api/policy", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", rr.Code)
	}
	var policy config.InboundPolicy
	decodeJSON(t, rr, &policy)
	if len(policy.Rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(policy.Rules))
	}

	// ── Add rule ──
	rr = env.doRequest("POST", "/api/policy/rules", map[string]interface{}{
		"name": "test-rule",
		"match": map[string]interface{}{
			"pubkey": map[string]interface{}{
				"type": "any",
			},
		},
		"services": []map[string]interface{}{
			{"proto": "*", "port": "*"},
		},
		"action": "allow",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("add rule: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── Get: should have 1 rule ──
	rr = env.doRequest("GET", "/api/policy", nil)
	decodeJSON(t, rr, &policy)
	if len(policy.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(policy.Rules))
	}
	if policy.Rules[0].Name != "test-rule" {
		t.Errorf("rule name mismatch: %s", policy.Rules[0].Name)
	}

	// ── Add duplicate should fail ──
	rr = env.doRequest("POST", "/api/policy/rules", map[string]interface{}{
		"name":   "test-rule",
		"match":  map[string]interface{}{"pubkey": map[string]interface{}{"type": "any"}},
		"action": "deny",
	})
	if rr.Code != http.StatusConflict {
		t.Fatalf("dup rule: expected 409, got %d", rr.Code)
	}

	// ── Delete rule ──
	rr = env.doRequest("DELETE", "/api/policy/rules/test-rule", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete rule: expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── Get: should be empty ──
	rr = env.doRequest("GET", "/api/policy", nil)
	decodeJSON(t, rr, &policy)
	if len(policy.Rules) != 0 {
		t.Fatalf("expected 0 rules after delete, got %d", len(policy.Rules))
	}

	// ── Delete nonexistent should 404 ──
	rr = env.doRequest("DELETE", "/api/policy/rules/nope", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("delete nonexistent: expected 404, got %d", rr.Code)
	}
}

func TestRoutesCRUD(t *testing.T) {
	env := newTestEnv(t)

	// ── List: initially empty ──
	rr := env.doRequest("GET", "/api/routes", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rr.Code)
	}
	var rules []config.RouteRule
	decodeJSON(t, rr, &rules)
	if len(rules) != 0 {
		t.Fatalf("expected 0 routes, got %d", len(rules))
	}

	// ── Add route ──
	rr = env.doRequest("POST", "/api/routes", map[string]interface{}{
		"domain": "*.google.com",
		"peer":   "exit-us",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("add: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── Add another ──
	rr = env.doRequest("POST", "/api/routes", map[string]interface{}{
		"domain": "*.example.com",
		"peer":   "exit-jp",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("add 2: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── List: should have 2 ──
	rr = env.doRequest("GET", "/api/routes", nil)
	decodeJSON(t, rr, &rules)
	if len(rules) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(rules))
	}

	// ── Delete by index 0 ──
	rr = env.doRequest("DELETE", "/api/routes/0", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── List: should have 1, and it should be the second one ──
	rr = env.doRequest("GET", "/api/routes", nil)
	decodeJSON(t, rr, &rules)
	if len(rules) != 1 {
		t.Fatalf("expected 1 route, got %d", len(rules))
	}
	if rules[0].Domain != "*.example.com" {
		t.Errorf("wrong route remaining: %s", rules[0].Domain)
	}

	// ── Delete out of range should 404 ──
	rr = env.doRequest("DELETE", "/api/routes/5", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("delete out of range: expected 404, got %d", rr.Code)
	}

	// ── Delete with invalid id should 400 ──
	rr = env.doRequest("DELETE", "/api/routes/abc", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("delete invalid: expected 400, got %d", rr.Code)
	}
}

func TestIdentity(t *testing.T) {
	env := newTestEnv(t)
	peerPK := env.KeyB.Public.String()

	// Add a peer so it gets an IP
	rr := env.doRequest("POST", "/api/peers", map[string]interface{}{
		"pubkey": peerPK,
		"alias":  "id-test",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("add peer: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// Look up peer's allocated TUN IP
	ip, ok := env.Host.IPAlloc().LookupByPubkey(env.KeyB.Public)
	if !ok {
		t.Fatal("peer has no allocated IP")
	}

	// ── Identity lookup by IP ──
	rr = env.doRequest("GET", "/internal/identity?ip="+ip.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("identity: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var idResp map[string]interface{}
	decodeJSON(t, rr, &idResp)
	if idResp["pubkey"] != peerPK {
		t.Errorf("identity pubkey mismatch: got %v", idResp["pubkey"])
	}

	// ── Missing ip param should 400 ──
	rr = env.doRequest("GET", "/internal/identity", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("no ip: expected 400, got %d", rr.Code)
	}

	// ── Unknown IP should 404 ──
	rr = env.doRequest("GET", "/internal/identity?ip=100.64.99.99", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown ip: expected 404, got %d", rr.Code)
	}
}

func TestConfigReload(t *testing.T) {
	env := newTestEnv(t)

	rr := env.doRequest("POST", "/api/config/reload", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("reload: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	decodeJSON(t, rr, &resp)
	if resp["status"] != "no changes" {
		t.Errorf("expected 'no changes', got %v", resp["status"])
	}
}

func TestAddPeerBadRequests(t *testing.T) {
	env := newTestEnv(t)

	// Missing pubkey
	rr := env.doRequest("POST", "/api/peers", map[string]string{
		"alias": "no-key",
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("no pubkey: expected 400, got %d", rr.Code)
	}

	// Invalid pubkey
	rr = env.doRequest("POST", "/api/peers", map[string]string{
		"pubkey": "not-hex",
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad pubkey: expected 400, got %d", rr.Code)
	}

	// Invalid JSON
	req := httptest.NewRequest("POST", "/api/peers", bytes.NewReader([]byte("{")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.Server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad json: expected 400, got %d", w.Code)
	}
}

func TestUpdatePeerNotFound(t *testing.T) {
	env := newTestEnv(t)
	fakePK := "0000000000000000000000000000000000000000000000000000000000000000"

	rr := env.doRequest("PUT", "/api/peers/"+fakePK, map[string]string{
		"alias": "ghost",
	})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}
