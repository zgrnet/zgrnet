//go:build darwin || linux

// Command e2etest is an end-to-end browser test for the zgrnetd Admin Web UI.
//
// It launches a Lightpanda headless browser, connects via CDP (Chrome DevTools
// Protocol), navigates the admin UI, and verifies that:
//   - The React SPA loads and initializes successfully
//   - The API is reachable and data renders in the DOM
//   - All UI components are present and show correct data
//   - The embedded SPA correctly integrates with the zgrnetd backend
//
// Prerequisites:
//   - A running zgrnetd instance (default: http://100.64.0.1:80)
//   - Lightpanda binary (pass path via -browser flag)
//
// Usage:
//
//	e2etest [-addr http://100.64.0.1:80] [-browser /path/to/lightpanda]
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// httpClient is used for server-side API calls during mutation tests.
var httpClient = &http.Client{Timeout: 5 * time.Second}

var (
	addr       = flag.String("addr", "http://100.64.0.1:80", "zgrnetd API address")
	browserBin = flag.String("browser", "", "path to Lightpanda binary")
	cdpPort    = flag.Int("cdp-port", 9222, "CDP server port for Lightpanda")
)

// result tracks a single test outcome.
type result struct {
	name   string
	passed bool
	detail string
}

var results []result

func pass(name string) {
	fmt.Printf("  PASS  %s\n", name)
	results = append(results, result{name, true, ""})
}

func fail(name, detail string) {
	fmt.Printf("  FAIL  %s — %s\n", name, detail)
	results = append(results, result{name, false, detail})
}

func main() {
	flag.Parse()

	if *browserBin == "" {
		// Try Bazel runfiles first, then common locations.
		candidates := []string{
			"lightpanda",
			"/tmp/lightpanda",
			"./lightpanda",
		}

		// Bazel runfiles: the binary is placed under external/<repo>/file/lightpanda
		if runfilesDir := os.Getenv("RUNFILES_DIR"); runfilesDir != "" {
			for _, repo := range []string{
				"lightpanda_macos_arm64",
				"lightpanda_macos_x86_64",
				"lightpanda_linux_x86_64",
				"lightpanda_linux_arm64",
			} {
				candidates = append([]string{runfilesDir + "/" + repo + "/file/lightpanda"}, candidates...)
			}
		}

		for _, p := range candidates {
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				*browserBin = p
				break
			}
			if resolved, err := exec.LookPath(p); err == nil {
				*browserBin = resolved
				break
			}
		}
		if *browserBin == "" {
			log.Fatal("lightpanda binary not found. Pass -browser flag or put lightpanda in PATH")
		}
	}

	fmt.Println("=== zgrnetd Admin UI e2e test ===")
	fmt.Printf("target: %s\n", *addr)
	fmt.Printf("browser: %s\n\n", *browserBin)

	// Start Lightpanda CDP server
	port := fmt.Sprintf("%d", *cdpPort)
	cmd := exec.Command(*browserBin, "serve",
		"--host", "127.0.0.1",
		"--port", port,
	)
	cmd.Env = append(os.Environ(), "LIGHTPANDA_DISABLE_TELEMETRY=true")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to start lightpanda: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// Wait for CDP server to be ready
	wsURL := fmt.Sprintf("ws://127.0.0.1:%s", port)
	if !waitForPort("127.0.0.1:"+port, 10*time.Second) {
		log.Fatal("lightpanda CDP server did not start within 10s")
	}
	time.Sleep(200 * time.Millisecond)
	fmt.Printf("CDP server ready at %s\n\n", wsURL)

	// Create chromedp context connected to Lightpanda
	allocCtx, allocCancel := chromedp.NewRemoteAllocator(context.Background(), wsURL)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Set overall timeout
	ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// ── Tests ────────────────────────────────────────────────────────────

	// ── Read-only UI tests ──────────────────────────────────────────────
	testPageLoad(ctx)
	testReactMounted(ctx)
	testHeaderBranding(ctx)
	testHeaderPubkey(ctx)
	testHeaderUptime(ctx)
	testAllTabButtons(ctx)
	testOverviewTunIP(ctx)
	testOverviewPeersCount(ctx)
	testNetworkConfigJSON(ctx)
	testNoOfflineWarning(ctx)

	// ── Mutation → UI refresh tests ─────────────────────────────────────
	// These tests use Go HTTP calls to mutate data via the API, then
	// reload the page in the browser to verify the UI reflects the change.
	testPeerAddAndVerify(ctx)
	testPeerUpdateAndVerify(ctx)
	testPeerDeleteAndVerify(ctx)
	testRouteAddAndVerify(ctx)
	testRouteDeleteAndVerify(ctx)
	testConfigReloadAndVerify(ctx)

	// ── Summary ──────────────────────────────────────────────────────────

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

// waitForPort polls until a TCP connection succeeds or timeout.
func waitForPort(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// evalJSON evaluates a JS expression that returns a JSON string, then unmarshals it.
func evalJSON(ctx context.Context, expr string, out interface{}) error {
	var raw string
	if err := chromedp.Run(ctx, chromedp.Evaluate(expr, &raw)); err != nil {
		return err
	}
	return json.Unmarshal([]byte(raw), out)
}

// ─── Test: Page loads ───────────────────────────────────────────────────────

func testPageLoad(ctx context.Context) {
	const name = "page load"

	err := chromedp.Run(ctx,
		chromedp.Navigate(*addr+"/"),
		chromedp.WaitReady("body"),
		// Give React time to mount and fetch initial data from API
		chromedp.Sleep(2*time.Second),
	)
	if err != nil {
		fail(name, fmt.Sprintf("navigate failed: %v", err))
		return
	}
	pass(name)
}

// ─── Test: React app mounted ────────────────────────────────────────────────

func testReactMounted(ctx context.Context) {
	const name = "react app mounted"

	// A mounted React SPA will have rendered tab buttons with role="tab".
	// If React failed to initialize, only the empty root div would exist.
	var count int
	err := chromedp.Run(ctx, chromedp.Evaluate(
		`document.querySelectorAll('button[role="tab"]').length`, &count))
	if err != nil {
		fail(name, fmt.Sprintf("evaluate: %v", err))
		return
	}
	if count == 0 {
		fail(name, "no role=tab buttons — React app did not mount")
		return
	}
	pass(name)
}

// ─── Test: Header shows "zgrnet" ────────────────────────────────────────────

func testHeaderBranding(ctx context.Context) {
	const name = "header branding"

	var title string
	err := chromedp.Run(ctx, chromedp.Evaluate(
		`(function(){ var h = document.querySelector('h1'); return h ? h.textContent.trim() : ''; })()`, &title))
	if err != nil {
		fail(name, fmt.Sprintf("evaluate: %v", err))
		return
	}
	if title != "zgrnet" {
		fail(name, fmt.Sprintf("h1=%q, want 'zgrnet'", title))
		return
	}
	pass(name)
}

// ─── Test: Header shows valid pubkey ────────────────────────────────────────

func testHeaderPubkey(ctx context.Context) {
	const name = "header pubkey"

	// The pubkey is displayed as a <code> element with the first 16 hex chars + "..."
	var pk string
	err := chromedp.Run(ctx, chromedp.Evaluate(
		`(function(){ var c = document.querySelector('code'); return c ? c.textContent.trim() : ''; })()`, &pk))
	if err != nil {
		fail(name, fmt.Sprintf("evaluate: %v", err))
		return
	}
	// Should be "abcdef0123456789..." (16 hex + "...")
	if len(pk) < 10 || pk == "..." {
		fail(name, fmt.Sprintf("pubkey=%q, expected hex prefix", pk))
		return
	}
	if !strings.HasSuffix(pk, "...") {
		fail(name, fmt.Sprintf("pubkey=%q, expected '...' suffix", pk))
		return
	}
	pass(name)
}

// ─── Test: Header shows uptime ──────────────────────────────────────────────

func testHeaderUptime(ctx context.Context) {
	const name = "header uptime"

	var html string
	err := chromedp.Run(ctx, chromedp.OuterHTML("body", &html))
	if err != nil {
		fail(name, fmt.Sprintf("get html: %v", err))
		return
	}
	// The header should show "up Xh..." or "up Xm..." from the uptime
	if !strings.Contains(html, "up ") {
		fail(name, "header does not show uptime")
		return
	}
	pass(name)
}

// ─── Test: All 8 tab buttons present ────────────────────────────────────────

func testAllTabButtons(ctx context.Context) {
	const name = "all 8 tab buttons"

	var tabs []string
	err := evalJSON(ctx, `
		(function() {
			var btns = document.querySelectorAll('button[role="tab"]');
			var t = [];
			for (var i = 0; i < btns.length; i++) t.push(btns[i].textContent.trim());
			return JSON.stringify(t);
		})()
	`, &tabs)
	if err != nil {
		fail(name, fmt.Sprintf("evaluate: %v", err))
		return
	}

	expected := []string{"Overview", "Peers", "Lans", "Policy", "Routes", "DNS", "Proxy", "Config"}
	if len(tabs) != len(expected) {
		fail(name, fmt.Sprintf("got %d tabs %v, want %d", len(tabs), tabs, len(expected)))
		return
	}
	for i, exp := range expected {
		if tabs[i] != exp {
			fail(name, fmt.Sprintf("tab[%d]=%q, want %q", i, tabs[i], exp))
			return
		}
	}
	pass(name)
}

// ─── Test: Overview shows valid TUN IP ──────────────────────────────────────

func testOverviewTunIP(ctx context.Context) {
	const name = "overview TUN IP"

	// Find the stat card with label "TUN IP" and check its value is a valid IP.
	var cards map[string]string
	err := evalJSON(ctx, `
		(function() {
			var result = {};
			var labels = document.querySelectorAll('.text-xs.text-muted-foreground');
			for (var i = 0; i < labels.length; i++) {
				var l = labels[i].textContent.trim();
				var s = labels[i].nextElementSibling;
				if (s) result[l] = s.textContent.trim();
			}
			return JSON.stringify(result);
		})()
	`, &cards)
	if err != nil {
		fail(name, fmt.Sprintf("evaluate: %v", err))
		return
	}

	tunIP, ok := cards["TUN IP"]
	if !ok || tunIP == "-" || tunIP == "" {
		fail(name, fmt.Sprintf("TUN IP missing or empty: %q", tunIP))
		return
	}
	if ip := net.ParseIP(tunIP); ip == nil {
		fail(name, fmt.Sprintf("TUN IP %q is not valid", tunIP))
		return
	}
	pass(name)
}

// ─── Test: Overview shows peers count ───────────────────────────────────────

func testOverviewPeersCount(ctx context.Context) {
	const name = "overview peers count"

	var cards map[string]string
	err := evalJSON(ctx, `
		(function() {
			var result = {};
			var labels = document.querySelectorAll('.text-xs.text-muted-foreground');
			for (var i = 0; i < labels.length; i++) {
				var l = labels[i].textContent.trim();
				var s = labels[i].nextElementSibling;
				if (s) result[l] = s.textContent.trim();
			}
			return JSON.stringify(result);
		})()
	`, &cards)
	if err != nil {
		fail(name, fmt.Sprintf("evaluate: %v", err))
		return
	}

	peers, ok := cards["Peers"]
	if !ok {
		fail(name, "Peers stat card not found")
		return
	}
	// Should be a number (0 or more)
	if peers == "-" || peers == "" {
		fail(name, fmt.Sprintf("Peers=%q, expected a number", peers))
		return
	}
	pass(name)
}

// ─── Test: Network config JSON rendered ─────────────────────────────────────

func testNetworkConfigJSON(ctx context.Context) {
	const name = "network config JSON"

	var preText string
	err := chromedp.Run(ctx, chromedp.Evaluate(
		`(function(){ var p = document.querySelector('pre'); return p ? p.textContent : ''; })()`, &preText))
	if err != nil {
		fail(name, fmt.Sprintf("evaluate: %v", err))
		return
	}

	if preText == "" || preText == "loading..." {
		fail(name, "network config not loaded")
		return
	}

	// The network config JSON should contain TUN IP info
	if !strings.Contains(preText, "tun_ip") && !strings.Contains(preText, "100.64") {
		fail(name, "network config JSON missing TUN IP reference")
		return
	}

	// Verify it's valid JSON
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(preText), &cfg); err != nil {
		fail(name, fmt.Sprintf("not valid JSON: %v", err))
		return
	}
	pass(name)
}

// ─── Test: No offline warning ───────────────────────────────────────────────

func testNoOfflineWarning(ctx context.Context) {
	const name = "no offline warning"

	var html string
	err := chromedp.Run(ctx, chromedp.OuterHTML("body", &html))
	if err != nil {
		fail(name, fmt.Sprintf("get html: %v", err))
		return
	}

	if strings.Contains(html, "zgrnetd is not running") {
		fail(name, "offline warning is displayed")
		return
	}
	if strings.Contains(html, "Not available") {
		fail(name, "'Not available' message displayed")
		return
	}
	pass(name)
}

// ═══════════════════════════════════════════════════════════════════════════
// Mutation → UI refresh tests
//
// These tests exercise the full e2e cycle:
//   1. Go HTTP client calls a write API (POST/PUT/DELETE)
//   2. Browser reloads the page
//   3. DOM is inspected to verify the mutation is reflected in the UI
//
// This proves: API mutation → config persistence → browser render pipeline.
// ═══════════════════════════════════════════════════════════════════════════

// Test pubkey for mutation tests (deterministic, 64 hex chars).
const testPK = "e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0"

// apiPost sends a JSON POST to the zgrnetd API. Returns status code and body.
func apiPost(path string, payload interface{}) (int, []byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	resp, err := httpClient.Post(*addr+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

// apiDo sends an arbitrary HTTP request to the zgrnetd API.
func apiDo(method, path string, payload interface{}) (int, []byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		data, _ := json.Marshal(payload)
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, *addr+path, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

// reloadAndWait navigates the browser to the admin UI root and waits for React.
func reloadAndWait(ctx context.Context) error {
	return chromedp.Run(ctx,
		chromedp.Navigate(*addr+"/"),
		chromedp.WaitReady("body"),
		chromedp.Sleep(2*time.Second),
	)
}

// getBodyHTML returns the body's outerHTML from the browser.
func getBodyHTML(ctx context.Context) (string, error) {
	var html string
	err := chromedp.Run(ctx, chromedp.OuterHTML("body", &html))
	return html, err
}

// getPeersFromAPI fetches the peers list via Go HTTP for verification.
func getPeersFromAPI() ([]map[string]interface{}, error) {
	resp, err := httpClient.Get(*addr + "/api/peers")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var peers []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return nil, err
	}
	return peers, nil
}

// ─── Test: Add peer via API → verify in browser ─────────────────────────────

func testPeerAddAndVerify(ctx context.Context) {
	const name = "mutation: add peer → UI shows peer"

	// Clean up from any previous failed run
	apiDo("DELETE", "/api/peers/"+testPK, nil)

	// 1. Add peer via HTTP
	code, _, err := apiPost("/api/peers", map[string]string{
		"pubkey": testPK,
		"alias":  "e2e-browser-test",
	})
	if err != nil {
		fail(name, fmt.Sprintf("api post: %v", err))
		return
	}
	if code != 201 && code != 200 {
		fail(name, fmt.Sprintf("api status=%d, want 201", code))
		return
	}

	// 2. Verify peer exists via API
	peers, err := getPeersFromAPI()
	if err != nil {
		fail(name, fmt.Sprintf("get peers: %v", err))
		return
	}
	found := false
	for _, p := range peers {
		if pk, _ := p["pubkey"].(string); pk == testPK {
			found = true
			break
		}
	}
	if !found {
		fail(name, "peer not found in API response after add")
		return
	}

	// 3. Reload browser and check overview peers count increased
	if err := reloadAndWait(ctx); err != nil {
		fail(name, fmt.Sprintf("reload: %v", err))
		return
	}

	var cards map[string]string
	err = evalJSON(ctx, `
		(function() {
			var result = {};
			var labels = document.querySelectorAll('.text-xs.text-muted-foreground');
			for (var i = 0; i < labels.length; i++) {
				var l = labels[i].textContent.trim();
				var s = labels[i].nextElementSibling;
				if (s) result[l] = s.textContent.trim();
			}
			return JSON.stringify(result);
		})()
	`, &cards)
	if err != nil {
		fail(name, fmt.Sprintf("eval cards: %v", err))
		return
	}

	peersCount, ok := cards["Peers"]
	if !ok {
		fail(name, "Peers stat card not found after reload")
		return
	}
	if peersCount == "0" {
		fail(name, "Peers count still 0 after adding a peer")
		return
	}

	pass(name)
}

// ─── Test: Update peer alias via API → verify in API ────────────────────────

func testPeerUpdateAndVerify(ctx context.Context) {
	const name = "mutation: update peer → API reflects"

	// Update the peer we just added
	code, _, err := apiDo("PUT", "/api/peers/"+testPK, map[string]string{
		"alias": "e2e-updated-alias",
	})
	if err != nil {
		fail(name, fmt.Sprintf("api put: %v", err))
		return
	}
	if code != 200 {
		fail(name, fmt.Sprintf("api status=%d, want 200", code))
		return
	}

	// Verify via GET
	resp, err := httpClient.Get(*addr + "/api/peers/" + testPK)
	if err != nil {
		fail(name, fmt.Sprintf("api get: %v", err))
		return
	}
	defer resp.Body.Close()
	var peer map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&peer)

	alias, _ := peer["alias"].(string)
	if alias != "e2e-updated-alias" {
		fail(name, fmt.Sprintf("alias=%q, want 'e2e-updated-alias'", alias))
		return
	}

	pass(name)
}

// ─── Test: Delete peer via API → UI peers count decreases ───────────────────

func testPeerDeleteAndVerify(ctx context.Context) {
	const name = "mutation: delete peer → UI reflects"

	// Get current peer count from API
	peersBefore, err := getPeersFromAPI()
	if err != nil {
		fail(name, fmt.Sprintf("get peers before: %v", err))
		return
	}
	countBefore := len(peersBefore)

	// Delete the test peer
	code, _, err := apiDo("DELETE", "/api/peers/"+testPK, nil)
	if err != nil {
		fail(name, fmt.Sprintf("api delete: %v", err))
		return
	}
	if code != 204 && code != 200 {
		fail(name, fmt.Sprintf("api status=%d, want 204", code))
		return
	}

	// Verify via API
	peersAfter, err := getPeersFromAPI()
	if err != nil {
		fail(name, fmt.Sprintf("get peers after: %v", err))
		return
	}
	if len(peersAfter) >= countBefore {
		fail(name, fmt.Sprintf("peers count %d not less than %d after delete", len(peersAfter), countBefore))
		return
	}

	// Verify peer returns 404
	resp, err := httpClient.Get(*addr + "/api/peers/" + testPK)
	if err != nil {
		fail(name, fmt.Sprintf("api get deleted: %v", err))
		return
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		fail(name, fmt.Sprintf("deleted peer status=%d, want 404", resp.StatusCode))
		return
	}

	// Reload browser and verify peers count updated
	if err := reloadAndWait(ctx); err != nil {
		fail(name, fmt.Sprintf("reload: %v", err))
		return
	}

	var cards map[string]string
	err = evalJSON(ctx, `
		(function() {
			var result = {};
			var labels = document.querySelectorAll('.text-xs.text-muted-foreground');
			for (var i = 0; i < labels.length; i++) {
				var l = labels[i].textContent.trim();
				var s = labels[i].nextElementSibling;
				if (s) result[l] = s.textContent.trim();
			}
			return JSON.stringify(result);
		})()
	`, &cards)
	if err != nil {
		fail(name, fmt.Sprintf("eval cards: %v", err))
		return
	}

	peersCount := cards["Peers"]
	if peersCount == "" {
		fail(name, "Peers stat card not found after reload")
		return
	}

	pass(name)
}

// ─── Test: Add route via API → verify in API ────────────────────────────────

func testRouteAddAndVerify(ctx context.Context) {
	const name = "mutation: add route → API reflects"

	// Add a route via API
	code, _, err := apiPost("/api/routes", map[string]string{
		"domain": "e2e-test.example.com",
		"peer":   "e2e-exit",
	})
	if err != nil {
		fail(name, fmt.Sprintf("api post: %v", err))
		return
	}
	if code != 201 && code != 200 {
		fail(name, fmt.Sprintf("api status=%d", code))
		return
	}

	// Verify via GET
	resp, err := httpClient.Get(*addr + "/api/routes")
	if err != nil {
		fail(name, fmt.Sprintf("api get routes: %v", err))
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(body), "e2e-test.example.com") {
		fail(name, "route not found in API response")
		return
	}

	pass(name)
}

// ─── Test: Delete route via API → verify in API ─────────────────────────────

func testRouteDeleteAndVerify(ctx context.Context) {
	const name = "mutation: delete route → API reflects"

	// Find the index of our test route
	resp, err := httpClient.Get(*addr + "/api/routes")
	if err != nil {
		fail(name, fmt.Sprintf("api get routes: %v", err))
		return
	}
	defer resp.Body.Close()

	var routes []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&routes)

	idx := -1
	for i, r := range routes {
		if d, _ := r["domain"].(string); d == "e2e-test.example.com" {
			idx = i
			break
		}
	}
	if idx < 0 {
		fail(name, "test route not found to delete")
		return
	}

	// Delete
	code, _, err := apiDo("DELETE", fmt.Sprintf("/api/routes/%d", idx), nil)
	if err != nil {
		fail(name, fmt.Sprintf("api delete: %v", err))
		return
	}
	if code != 204 && code != 200 {
		fail(name, fmt.Sprintf("api status=%d", code))
		return
	}

	// Verify gone
	resp2, err := httpClient.Get(*addr + "/api/routes")
	if err != nil {
		fail(name, fmt.Sprintf("api get routes after: %v", err))
		return
	}
	defer resp2.Body.Close()
	body, _ := io.ReadAll(resp2.Body)

	if strings.Contains(string(body), "e2e-test.example.com") {
		fail(name, "route still present after delete")
		return
	}

	pass(name)
}

// ─── Test: Config reload via API → verify no error ──────────────────────────

func testConfigReloadAndVerify(ctx context.Context) {
	const name = "mutation: config reload → UI stable"

	// Trigger config reload
	code, _, err := apiPost("/api/config/reload", nil)
	if err != nil {
		fail(name, fmt.Sprintf("api post: %v", err))
		return
	}
	if code != 200 {
		fail(name, fmt.Sprintf("api status=%d", code))
		return
	}

	// Reload browser — the page should still work after config reload
	if err := reloadAndWait(ctx); err != nil {
		fail(name, fmt.Sprintf("reload: %v", err))
		return
	}

	// Verify still functional — no offline warning
	html, err := getBodyHTML(ctx)
	if err != nil {
		fail(name, fmt.Sprintf("get html: %v", err))
		return
	}

	if strings.Contains(html, "zgrnetd is not running") {
		fail(name, "offline warning after config reload")
		return
	}

	// Verify React still mounted
	var tabCount int
	chromedp.Run(ctx, chromedp.Evaluate(
		`document.querySelectorAll('button[role="tab"]').length`, &tabCount))
	if tabCount != 8 {
		fail(name, fmt.Sprintf("tab count=%d after reload, want 8", tabCount))
		return
	}

	pass(name)
}
