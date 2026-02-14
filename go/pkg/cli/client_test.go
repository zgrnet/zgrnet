package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockAPI creates an httptest.Server that simulates the zgrnetd API.
func mockAPI(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// Read-only
	mux.HandleFunc("GET /api/whoami", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"pubkey":"aabb","tun_ip":"100.64.0.1","uptime_sec":42}`))
	})
	mux.HandleFunc("GET /api/config/net", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tun_ipv4":"100.64.0.1","tun_mtu":1400}`))
	})

	// Peers
	mux.HandleFunc("GET /api/peers", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"pubkey":"aa","alias":"peer1"}]`))
	})
	mux.HandleFunc("GET /api/peers/{pubkey}", func(w http.ResponseWriter, r *http.Request) {
		pk := r.PathValue("pubkey")
		if pk == "notfound" {
			http.Error(w, `{"error":"peer not found"}`, http.StatusNotFound)
			return
		}
		w.Write([]byte(`{"pubkey":"` + pk + `","alias":"peer1"}`))
	})
	mux.HandleFunc("POST /api/peers", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		json.Unmarshal(body, &m)
		if m["pubkey"] == nil || m["pubkey"] == "" {
			http.Error(w, `{"error":"pubkey is required"}`, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write(body)
	})
	mux.HandleFunc("PUT /api/peers/{pubkey}", func(w http.ResponseWriter, r *http.Request) {
		pk := r.PathValue("pubkey")
		if pk == "notfound" {
			http.Error(w, `{"error":"peer not found"}`, http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	})
	mux.HandleFunc("DELETE /api/peers/{pubkey}", func(w http.ResponseWriter, r *http.Request) {
		pk := r.PathValue("pubkey")
		if pk == "notfound" {
			http.Error(w, `{"error":"peer not found"}`, http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Lans
	mux.HandleFunc("GET /api/lans", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"domain":"test.zigor.net"}]`))
	})
	mux.HandleFunc("POST /api/lans", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write(body)
	})
	mux.HandleFunc("DELETE /api/lans/{domain}", func(w http.ResponseWriter, r *http.Request) {
		d := r.PathValue("domain")
		if d == "notfound" {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Policy
	mux.HandleFunc("GET /api/policy", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"default":"allow","rules":[]}`))
	})
	mux.HandleFunc("POST /api/policy/rules", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write(body)
	})
	mux.HandleFunc("DELETE /api/policy/rules/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name == "notfound" {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Routes
	mux.HandleFunc("GET /api/routes", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"domain":"*.google.com","peer":"us"}]`))
	})
	mux.HandleFunc("POST /api/routes", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write(body)
	})
	mux.HandleFunc("DELETE /api/routes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "99" {
			http.Error(w, `{"error":"out of range"}`, http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Config reload
	mux.HandleFunc("POST /api/config/reload", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"no changes"}`))
	})

	return httptest.NewServer(mux)
}

func TestClientStatus(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	data, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "pubkey") {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestClientConfigNet(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	data, err := c.ConfigNet()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "tun_ipv4") {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestClientConfigReload(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	data, err := c.ConfigReload()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "no changes") {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestClientPeersList(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	data, err := c.PeersList()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "peer1") {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestClientPeersGet(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	data, err := c.PeersGet("aabbcc")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "aabbcc") {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestClientPeersGetNotFound(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.PeersGet("notfound")
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected 404, got: %v", err)
	}
}

func TestClientPeersAdd(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	data, err := c.PeersAdd("aabb", "test-peer", "1.2.3.4:51820")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "aabb") {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestClientPeersUpdate(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	data, err := c.PeersUpdate("aabb", map[string]interface{}{"alias": "updated"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "updated") {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestClientPeersUpdateNotFound(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.PeersUpdate("notfound", map[string]interface{}{"alias": "x"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClientPeersRemove(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	if err := c.PeersRemove("aabb"); err != nil {
		t.Fatal(err)
	}
}

func TestClientPeersRemoveNotFound(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	err := c.PeersRemove("notfound")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClientLansList(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	data, err := c.LansList()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "test.zigor.net") {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestClientLansJoin(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	data, err := c.LansJoin("new.zigor.net", "aabb", "1.2.3.4:51820")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "new.zigor.net") {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestClientLansLeave(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	if err := c.LansLeave("test.zigor.net"); err != nil {
		t.Fatal(err)
	}
}

func TestClientLansLeaveNotFound(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	err := c.LansLeave("notfound")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClientPolicyShow(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	data, err := c.PolicyShow()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "allow") {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestClientPolicyAddRule(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	rule := []byte(`{"name":"test","match":{"pubkey":{"type":"any"}},"action":"allow"}`)
	data, err := c.PolicyAddRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "test") {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestClientPolicyRemoveRule(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	if err := c.PolicyRemoveRule("test"); err != nil {
		t.Fatal(err)
	}
}

func TestClientPolicyRemoveRuleNotFound(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	err := c.PolicyRemoveRule("notfound")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClientRoutesList(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	data, err := c.RoutesList()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "google.com") {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestClientRoutesAdd(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	data, err := c.RoutesAdd("*.example.com", "jp")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "example.com") {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestClientRoutesRemove(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	if err := c.RoutesRemove("0"); err != nil {
		t.Fatal(err)
	}
}

func TestClientRoutesRemoveNotFound(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	c := NewClient(srv.URL)
	err := c.RoutesRemove("99")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClientConnectionError(t *testing.T) {
	c := NewClient("http://127.0.0.1:1") // unlikely to be listening
	_, err := c.Status()
	if err == nil {
		t.Fatal("expected connection error")
	}
}

func TestExtractError(t *testing.T) {
	// JSON with error field
	msg := extractError([]byte(`{"error":"something broke"}`))
	if msg != "something broke" {
		t.Fatalf("expected 'something broke', got %q", msg)
	}

	// Plain text
	msg = extractError([]byte("just text"))
	if msg != "just text" {
		t.Fatalf("expected 'just text', got %q", msg)
	}

	// Long text truncated
	long := strings.Repeat("x", 300)
	msg = extractError([]byte(long))
	if len(msg) > 210 {
		t.Fatalf("expected truncation, got len=%d", len(msg))
	}
}

func TestNewClientHttpPrefix(t *testing.T) {
	// Should add http:// prefix
	c := NewClient("127.0.0.1:8080")
	if c.baseURL != "http://127.0.0.1:8080" {
		t.Fatalf("expected http prefix, got %q", c.baseURL)
	}

	// Should not double-add
	c = NewClient("http://127.0.0.1:8080")
	if c.baseURL != "http://127.0.0.1:8080" {
		t.Fatalf("expected no double prefix, got %q", c.baseURL)
	}
}
