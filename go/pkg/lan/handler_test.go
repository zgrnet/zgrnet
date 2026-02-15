package lan

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vibing/zgrnet/pkg/noise"
)

// testIdentity creates an IdentityFunc that maps a fixed IP to a fixed pubkey.
func testIdentity(pk noise.PublicKey) IdentityFunc {
	return func(ip net.IP) (noise.PublicKey, []string, error) {
		return pk, nil, nil
	}
}

// testServer creates a Server with OpenAuth and a test identity.
func testServer(t *testing.T, pk noise.PublicKey) *Server {
	t.Helper()

	store, err := NewStore("")
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(Config{
		Domain:      "test.zigor.net",
		Description: "Test LAN",
		IdentityFn:  testIdentity(pk),
	}, store)

	srv.RegisterAuth(NewOpenAuth())
	return srv
}

func doRequest(t *testing.T, handler http.Handler, method, path, body string) *http.Response {
	t.Helper()

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	// Set a remote address so identity can be resolved.
	req.RemoteAddr = "100.64.0.5:12345"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Result()
}

func readBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return result
}

func TestHandler_Info(t *testing.T) {
	pk := genKey(t)
	srv := testServer(t, pk)
	h := srv.Handler()

	resp := doRequest(t, h, "GET", "/api/lan/info", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body := readBody(t, resp)
	if body["domain"] != "test.zigor.net" {
		t.Fatalf("expected domain test.zigor.net, got %v", body["domain"])
	}

	methods, ok := body["auth_methods"].([]any)
	if !ok || len(methods) != 1 || methods[0] != "open" {
		t.Fatalf("expected auth_methods [open], got %v", body["auth_methods"])
	}
}

func TestHandler_JoinAndPeers(t *testing.T) {
	pk := genKey(t)
	srv := testServer(t, pk)
	h := srv.Handler()

	// Join.
	resp := doRequest(t, h, "POST", "/api/lan/join", `{"auth":{"method":"open"}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("join: expected 200, got %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	if body["added"] != true {
		t.Fatalf("expected added=true, got %v", body["added"])
	}

	// Join again — no-op.
	resp = doRequest(t, h, "POST", "/api/lan/join", `{"auth":{"method":"open"}}`)
	body = readBody(t, resp)
	if body["added"] != false {
		t.Fatalf("expected added=false on duplicate, got %v", body["added"])
	}

	// Peers.
	resp = doRequest(t, h, "GET", "/api/lan/peers", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("peers: expected 200, got %d", resp.StatusCode)
	}
	body = readBody(t, resp)
	peers, ok := body["peers"].([]any)
	if !ok || len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %v", body["peers"])
	}
}

func TestHandler_JoinWithPassword(t *testing.T) {
	pk := genKey(t)

	store, err := NewStore("")
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(Config{
		Domain:     "pw.zigor.net",
		IdentityFn: testIdentity(pk),
	}, store)

	pwAuth, err := NewPasswordAuthFromPlaintext("secret", 4)
	if err != nil {
		t.Fatal(err)
	}
	srv.RegisterAuth(pwAuth)

	h := srv.Handler()

	// Wrong password → 401.
	resp := doRequest(t, h, "POST", "/api/lan/join",
		`{"auth":{"method":"password","credential":{"password":"wrong"}}}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong password, got %d", resp.StatusCode)
	}

	// Correct password → 200.
	resp = doRequest(t, h, "POST", "/api/lan/join",
		`{"auth":{"method":"password","credential":{"password":"secret"}}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with correct password, got %d", resp.StatusCode)
	}

	// Unsupported method → 400.
	resp = doRequest(t, h, "POST", "/api/lan/join",
		`{"auth":{"method":"oauth"}}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 with unsupported method, got %d", resp.StatusCode)
	}
}

func TestHandler_Leave(t *testing.T) {
	pk := genKey(t)
	srv := testServer(t, pk)
	h := srv.Handler()

	// Join first.
	doRequest(t, h, "POST", "/api/lan/join", `{"auth":{"method":"open"}}`)

	// Leave.
	resp := doRequest(t, h, "POST", "/api/lan/leave", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("leave: expected 200, got %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	if body["removed"] != true {
		t.Fatalf("expected removed=true, got %v", body["removed"])
	}

	// Leave again — already gone.
	resp = doRequest(t, h, "POST", "/api/lan/leave", "")
	body = readBody(t, resp)
	if body["removed"] != false {
		t.Fatalf("expected removed=false, got %v", body["removed"])
	}
}

func TestHandler_Query(t *testing.T) {
	pk := genKey(t)
	srv := testServer(t, pk)
	h := srv.Handler()

	// Join.
	doRequest(t, h, "POST", "/api/lan/join", `{"auth":{"method":"open"}}`)

	// Query existing member.
	resp := doRequest(t, h, "GET", "/api/lan/query/"+pk.String(), "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("query: expected 200, got %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	if body["member"] != true {
		t.Fatalf("expected member=true, got %v", body["member"])
	}

	// Query non-member.
	other := genKey(t)
	resp = doRequest(t, h, "GET", "/api/lan/query/"+other.String(), "")
	body = readBody(t, resp)
	if body["member"] != false {
		t.Fatalf("expected member=false for non-member, got %v", body["member"])
	}

	// Invalid pubkey.
	resp = doRequest(t, h, "GET", "/api/lan/query/notahexkey", "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid pubkey, got %d", resp.StatusCode)
	}
}

func TestHandler_Labels(t *testing.T) {
	pk := genKey(t)
	srv := testServer(t, pk)
	h := srv.Handler()

	// Join.
	doRequest(t, h, "POST", "/api/lan/join", `{"auth":{"method":"open"}}`)

	// Set labels.
	resp := doRequest(t, h, "POST", "/api/lan/labels/"+pk.String(),
		`{"labels":["admin","dev"]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set labels: expected 200, got %d", resp.StatusCode)
	}

	// Verify labels via query.
	resp = doRequest(t, h, "GET", "/api/lan/query/"+pk.String(), "")
	body := readBody(t, resp)
	labels, ok := body["labels"].([]any)
	if !ok || len(labels) != 2 {
		t.Fatalf("expected 2 labels, got %v", body["labels"])
	}

	// Delete one label.
	resp = doRequest(t, h, "DELETE", "/api/lan/labels/"+pk.String(),
		`{"labels":["admin"]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete labels: expected 200, got %d", resp.StatusCode)
	}

	// Verify.
	resp = doRequest(t, h, "GET", "/api/lan/query/"+pk.String(), "")
	body = readBody(t, resp)
	labels, ok = body["labels"].([]any)
	if !ok || len(labels) != 1 || labels[0] != "dev" {
		t.Fatalf("expected [dev], got %v", body["labels"])
	}

	// Set labels on non-member → 404.
	other := genKey(t)
	resp = doRequest(t, h, "POST", "/api/lan/labels/"+other.String(),
		`{"labels":["x"]}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for non-member, got %d", resp.StatusCode)
	}
}

func TestHandler_NoIdentity(t *testing.T) {
	store, _ := NewStore("")
	srv := NewServer(Config{
		Domain: "test.zigor.net",
		// No IdentityFn — should fail.
	}, store)
	srv.RegisterAuth(NewOpenAuth())
	h := srv.Handler()

	resp := doRequest(t, h, "GET", "/api/lan/peers", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without identity, got %d", resp.StatusCode)
	}
}
