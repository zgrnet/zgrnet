//go:build darwin || linux

// Command apitest is an end-to-end test for the zgrnetd REST API.
//
// It tests all API endpoints against a running zgrnetd instance.
// The default API address is http://100.64.0.1:80, override with -addr flag.
//
// Usage:
//
//	apitest [-addr http://100.64.0.1:80]
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	addr = flag.String("addr", "http://127.0.0.1:19280", "zgrnetd API address")
)

// result tracks a single test outcome.
type result struct {
	name   string
	passed bool
	detail string
}

var results []result

func main() {
	flag.Parse()

	client := &http.Client{Timeout: 5 * time.Second}

	fmt.Printf("=== zgrnetd API e2e test ===\n")
	fmt.Printf("target: %s\n\n", *addr)

	// ── Connectivity ────────────────────────────────────────────────────
	testAdminUI(client)

	// ── Read-only endpoints ─────────────────────────────────────────────
	testWhoAmI(client)
	testConfigNet(client)
	testConfigRaw(client)
	testDNSStats(client)
	testProxyStats(client)

	// ── Peers CRUD ──────────────────────────────────────────────────────
	testPeersList(client)
	testPeerCRUD(client)

	// ── Lans CRUD ───────────────────────────────────────────────────────
	testLansList(client)
	testLanCRUD(client)

	// ── Policy CRUD ─────────────────────────────────────────────────────
	testPolicyShow(client)
	testPolicyRuleCRUD(client)

	// ── Routes CRUD ─────────────────────────────────────────────────────
	testRoutesList(client)
	testRouteCRUD(client)

	// ── Identity ────────────────────────────────────────────────────────
	testIdentity(client)

	// ── Config reload ───────────────────────────────────────────────────
	testConfigReload(client)

	// ── Summary ─────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("=== Summary ===")
	passed, failed := 0, 0
	for _, r := range results {
		if r.passed {
			passed++
		} else {
			failed++
			fmt.Printf("  FAIL: %s — %s\n", r.name, r.detail)
		}
	}
	fmt.Printf("\n%d passed, %d failed, %d total\n", passed, failed, len(results))
	if failed > 0 {
		os.Exit(1)
	}
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func pass(name string) {
	fmt.Printf("  PASS  %s\n", name)
	results = append(results, result{name, true, ""})
}

func fail(name, detail string) {
	fmt.Printf("  FAIL  %s — %s\n", name, detail)
	results = append(results, result{name, false, detail})
}

func doGet(client *http.Client, path string) (int, map[string]any, []byte, error) {
	resp, err := client.Get(*addr + path)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			// Try as array — return nil map but body is available
			return resp.StatusCode, nil, body, nil
		}
		return resp.StatusCode, m, body, nil
	}
	return resp.StatusCode, nil, body, nil
}

func doJSON(client *http.Client, method, path string, payload any) (int, map[string]any, []byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		data, _ := json.Marshal(payload)
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, *addr+path, bodyReader)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var m map[string]any
	_ = json.Unmarshal(body, &m)
	return resp.StatusCode, m, body, nil
}

// ─── Tests ──────────────────────────────────────────────────────────────────

func testAdminUI(c *http.Client) {
	const name = "GET / (admin UI)"
	resp, err := c.Get(*addr + "/")
	if err != nil {
		fail(name, fmt.Sprintf("connection failed: %v", err))
		fmt.Println("\nCannot reach zgrnetd. Is it running?")
		fmt.Println("Start with: sudo /tmp/zgrnetd -c default")
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		fail(name, fmt.Sprintf("status %d", resp.StatusCode))
		return
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		fail(name, fmt.Sprintf("content-type %q, want text/html", ct))
		return
	}
	if !strings.Contains(string(body), "zgrnet") {
		fail(name, "body does not contain 'zgrnet'")
		return
	}
	pass(name)
}

func testWhoAmI(c *http.Client) {
	const name = "GET /api/whoami"
	code, m, _, err := doGet(c, "/api/whoami")
	if err != nil {
		fail(name, err.Error())
		return
	}
	if code != 200 {
		fail(name, fmt.Sprintf("status %d", code))
		return
	}
	// Must have pubkey and tun_ip
	for _, key := range []string{"pubkey", "tun_ip"} {
		if _, ok := m[key]; !ok {
			fail(name, fmt.Sprintf("missing field %q", key))
			return
		}
	}
	pk, _ := m["pubkey"].(string)
	if len(pk) != 64 {
		fail(name, fmt.Sprintf("pubkey length %d, want 64", len(pk)))
		return
	}
	pass(name)
}

func testConfigNet(c *http.Client) {
	const name = "GET /api/config/net"
	code, m, _, err := doGet(c, "/api/config/net")
	if err != nil {
		fail(name, err.Error())
		return
	}
	if code != 200 {
		fail(name, fmt.Sprintf("status %d", code))
		return
	}
	if _, ok := m["tun_ipv4"]; !ok {
		fail(name, "missing field tun_ipv4")
		return
	}
	pass(name)
}

func testConfigRaw(c *http.Client) {
	const name = "GET /api/config/raw"
	code, m, _, err := doGet(c, "/api/config/raw")
	if err != nil {
		fail(name, err.Error())
		return
	}
	if code != 200 {
		fail(name, fmt.Sprintf("status %d", code))
		return
	}
	content, _ := m["content"].(string)
	if content == "" {
		fail(name, "empty content")
		return
	}
	if !strings.Contains(content, "net:") {
		fail(name, "content does not look like YAML config")
		return
	}
	pass(name)
}

func testDNSStats(c *http.Client) {
	const name = "GET /api/dns/stats"
	code, m, _, err := doGet(c, "/api/dns/stats")
	if err != nil {
		fail(name, err.Error())
		return
	}
	if code != 200 {
		fail(name, fmt.Sprintf("status %d", code))
		return
	}
	// Should have total_queries field
	if _, ok := m["total_queries"]; !ok {
		fail(name, "missing field total_queries")
		return
	}
	pass(name)
}

func testProxyStats(c *http.Client) {
	const name = "GET /api/proxy/stats"
	code, m, _, err := doGet(c, "/api/proxy/stats")
	if err != nil {
		fail(name, err.Error())
		return
	}
	if code != 200 {
		fail(name, fmt.Sprintf("status %d", code))
		return
	}
	if _, ok := m["total_connections"]; !ok {
		fail(name, "missing field total_connections")
		return
	}
	pass(name)
}

func testPeersList(c *http.Client) {
	const name = "GET /api/peers (list)"
	code, _, body, err := doGet(c, "/api/peers")
	if err != nil {
		fail(name, err.Error())
		return
	}
	if code != 200 {
		fail(name, fmt.Sprintf("status %d", code))
		return
	}
	// Should be a JSON array
	var arr []any
	if err := json.Unmarshal(body, &arr); err != nil {
		fail(name, fmt.Sprintf("response is not array: %v", err))
		return
	}
	pass(name)
}

func testPeerCRUD(c *http.Client) {
	// Use a deterministic test pubkey (64 hex chars)
	testPK := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// CREATE
	{
		const name = "POST /api/peers (add)"
		code, m, _, err := doJSON(c, "POST", "/api/peers", map[string]string{
			"pubkey": testPK,
			"alias":  "e2e-test-peer",
		})
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 && code != 201 {
			errMsg, _ := m["error"].(string)
			fail(name, fmt.Sprintf("status %d: %s", code, errMsg))
			return
		}
		pass(name)
	}

	// READ
	{
		const name = "GET /api/peers/{pk} (get)"
		code, m, _, err := doGet(c, "/api/peers/"+testPK)
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 {
			fail(name, fmt.Sprintf("status %d", code))
			return
		}
		alias, _ := m["alias"].(string)
		if alias != "e2e-test-peer" {
			fail(name, fmt.Sprintf("alias %q, want %q", alias, "e2e-test-peer"))
			return
		}
		pass(name)
	}

	// UPDATE
	{
		const name = "PUT /api/peers/{pk} (update)"
		code, _, _, err := doJSON(c, "PUT", "/api/peers/"+testPK, map[string]string{
			"alias": "e2e-updated",
		})
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 {
			fail(name, fmt.Sprintf("status %d", code))
			return
		}
		pass(name)
	}

	// Verify update
	{
		const name = "GET /api/peers/{pk} (verify update)"
		code, m, _, err := doGet(c, "/api/peers/"+testPK)
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 {
			fail(name, fmt.Sprintf("status %d", code))
			return
		}
		alias, _ := m["alias"].(string)
		if alias != "e2e-updated" {
			fail(name, fmt.Sprintf("alias %q, want %q", alias, "e2e-updated"))
			return
		}
		pass(name)
	}

	// DELETE
	{
		const name = "DELETE /api/peers/{pk} (remove)"
		code, _, _, err := doJSON(c, "DELETE", "/api/peers/"+testPK, nil)
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 && code != 204 {
			fail(name, fmt.Sprintf("status %d", code))
			return
		}
		pass(name)
	}

	// Verify delete — should 404
	{
		const name = "GET /api/peers/{pk} (verify delete = 404)"
		code, _, _, err := doGet(c, "/api/peers/"+testPK)
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 404 {
			fail(name, fmt.Sprintf("status %d, want 404", code))
			return
		}
		pass(name)
	}
}

func testLansList(c *http.Client) {
	const name = "GET /api/lans (list)"
	code, _, body, err := doGet(c, "/api/lans")
	if err != nil {
		fail(name, err.Error())
		return
	}
	if code != 200 {
		fail(name, fmt.Sprintf("status %d", code))
		return
	}
	var arr []any
	if err := json.Unmarshal(body, &arr); err != nil {
		fail(name, fmt.Sprintf("not array: %v", err))
		return
	}
	pass(name)
}

func testLanCRUD(c *http.Client) {
	testPK := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	// ADD
	{
		const name = "POST /api/lans (join)"
		code, _, _, err := doJSON(c, "POST", "/api/lans", map[string]string{
			"domain":   "e2e-test.lan",
			"pubkey":   testPK,
			"endpoint": "192.168.1.1:51820",
		})
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 && code != 201 {
			fail(name, fmt.Sprintf("status %d", code))
			return
		}
		pass(name)
	}

	// Verify in list
	{
		const name = "GET /api/lans (verify add)"
		code, _, body, err := doGet(c, "/api/lans")
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 {
			fail(name, fmt.Sprintf("status %d", code))
			return
		}
		if !strings.Contains(string(body), "e2e-test.lan") {
			fail(name, "added LAN not found in list")
			return
		}
		pass(name)
	}

	// DELETE
	{
		const name = "DELETE /api/lans/{domain} (leave)"
		code, _, _, err := doJSON(c, "DELETE", "/api/lans/e2e-test.lan", nil)
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 && code != 204 {
			fail(name, fmt.Sprintf("status %d", code))
			return
		}
		pass(name)
	}
}

func testPolicyShow(c *http.Client) {
	const name = "GET /api/policy"
	code, m, _, err := doGet(c, "/api/policy")
	if err != nil {
		fail(name, err.Error())
		return
	}
	if code != 200 {
		fail(name, fmt.Sprintf("status %d", code))
		return
	}
	// Should have default_action
	if _, ok := m["default_action"]; !ok {
		// might be "default" key
		if _, ok := m["default"]; !ok {
			fail(name, "missing default_action or default field")
			return
		}
	}
	pass(name)
}

func testPolicyRuleCRUD(c *http.Client) {
	// ADD — must include match.pubkey.type for validation
	{
		const name = "POST /api/policy/rules (add)"
		code, _, _, err := doJSON(c, "POST", "/api/policy/rules", map[string]any{
			"name":   "e2e-test-rule",
			"match":  map[string]any{"pubkey": map[string]any{"type": "any"}},
			"action": "allow",
		})
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 && code != 201 {
			fail(name, fmt.Sprintf("status %d", code))
			return
		}
		pass(name)
	}

	// Verify in policy
	{
		const name = "GET /api/policy (verify rule added)"
		code, _, body, err := doGet(c, "/api/policy")
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 {
			fail(name, fmt.Sprintf("status %d", code))
			return
		}
		if !strings.Contains(string(body), "e2e-test-rule") {
			fail(name, "added rule not found in policy")
			return
		}
		pass(name)
	}

	// DELETE
	{
		const name = "DELETE /api/policy/rules/{name} (remove)"
		code, _, _, err := doJSON(c, "DELETE", "/api/policy/rules/e2e-test-rule", nil)
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 && code != 204 {
			fail(name, fmt.Sprintf("status %d", code))
			return
		}
		pass(name)
	}
}

func testRoutesList(c *http.Client) {
	const name = "GET /api/routes (list)"
	code, _, body, err := doGet(c, "/api/routes")
	if err != nil {
		fail(name, err.Error())
		return
	}
	if code != 200 {
		fail(name, fmt.Sprintf("status %d", code))
		return
	}
	var arr []any
	if err := json.Unmarshal(body, &arr); err != nil {
		fail(name, fmt.Sprintf("not array: %v", err))
		return
	}
	pass(name)
}

func testRouteCRUD(c *http.Client) {
	// ADD
	{
		const name = "POST /api/routes (add)"
		code, _, _, err := doJSON(c, "POST", "/api/routes", map[string]string{
			"domain": "e2e-test.example.com",
			"peer":   "e2e-exit",
		})
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 && code != 201 {
			fail(name, fmt.Sprintf("status %d", code))
			return
		}
		pass(name)
	}

	// Verify in list
	{
		const name = "GET /api/routes (verify add)"
		code, _, body, err := doGet(c, "/api/routes")
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 {
			fail(name, fmt.Sprintf("status %d", code))
			return
		}
		if !strings.Contains(string(body), "e2e-test.example.com") {
			fail(name, "added route not found in list")
			return
		}
		pass(name)
	}

	// DELETE (index 0 — the one we just added, or last)
	{
		const name = "DELETE /api/routes/{id} (remove)"
		// Find the index of our route
		_, _, body, _ := doGet(c, "/api/routes")
		var arr []map[string]any
		json.Unmarshal(body, &arr)
		idx := -1
		for i, r := range arr {
			if d, _ := r["domain"].(string); d == "e2e-test.example.com" {
				idx = i
				break
			}
		}
		if idx < 0 {
			fail(name, "could not find test route to delete")
			return
		}
		code, _, _, err := doJSON(c, "DELETE", fmt.Sprintf("/api/routes/%d", idx), nil)
		if err != nil {
			fail(name, err.Error())
			return
		}
		if code != 200 && code != 204 {
			fail(name, fmt.Sprintf("status %d", code))
			return
		}
		pass(name)
	}
}

func testIdentity(c *http.Client) {
	const name = "GET /internal/identity?ip=100.64.0.1"
	code, m, _, err := doGet(c, "/internal/identity?ip=100.64.0.1")
	if err != nil {
		fail(name, err.Error())
		return
	}
	// 200 with pubkey, or 404 if not found
	if code == 200 {
		if _, ok := m["pubkey"]; !ok {
			fail(name, "missing pubkey in response")
			return
		}
		pass(name)
	} else if code == 404 {
		// Not found is acceptable for self IP
		pass(name + " (404 ok)")
	} else {
		fail(name, fmt.Sprintf("status %d", code))
	}
}

func testConfigReload(c *http.Client) {
	const name = "POST /api/config/reload"
	code, _, _, err := doJSON(c, "POST", "/api/config/reload", nil)
	if err != nil {
		fail(name, err.Error())
		return
	}
	if code != 200 && code != 204 {
		fail(name, fmt.Sprintf("status %d", code))
		return
	}
	pass(name)
}
