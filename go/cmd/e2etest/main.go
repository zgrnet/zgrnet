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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

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
