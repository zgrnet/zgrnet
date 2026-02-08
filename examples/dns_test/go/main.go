// Magic DNS integration test.
//
// Starts a DNS server, runs direct query tests (pure Go, no dig dependency),
// configures OS resolver on supported platforms, then cleans up.
//
// Usage:
//   cd go && go build -o dns_test ../examples/dns_test/go/main.go
//   sudo ./dns_test       # macOS/Linux
//   .\dns_test.exe        # Windows (run as Administrator)
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/vibing/zgrnet/pkg/dns"
)

const (
	listenAddr = "127.0.0.1:15353"
	tunIPv4    = "100.64.0.1"
	tunIPv6    = "fd00::1"
)

var passed, failed int

func main() {
	// Check privileges (not needed on Windows for basic DNS test)
	if os.Getuid() != 0 && runtime.GOOS != "windows" {
		fmt.Println("ERROR: requires root/sudo")
		fmt.Println("Usage: sudo ./dns_test")
		os.Exit(1)
	}

	fmt.Printf("=== Magic DNS Integration Test (%s/%s) ===\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()

	// 1. Start DNS server
	srv := dns.NewServer(dns.ServerConfig{
		ListenAddr: listenAddr,
		TunIPv4:    net.ParseIP(tunIPv4),
		TunIPv6:    net.ParseIP(tunIPv6),
	})

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			fmt.Printf("[dns] Server error: %v\n", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)
	fmt.Printf("[dns] Server listening on %s\n", listenAddr)
	fmt.Println()

	defer cleanup(srv)

	// 2. Phase 1: Direct queries using pure Go DNS client (no dig needed)
	fmt.Println("--- Phase 1: Direct DNS queries (pure Go client) ---")
	fmt.Println()

	queryA("localhost.zigor.net A", "localhost.zigor.net", dns.TypeA,
		expectIP(tunIPv4))

	queryA("localhost.zigor.net AAAA", "localhost.zigor.net", dns.TypeAAAA,
		expectIP(tunIPv6))

	queryA("unknown.zigor.net -> NXDOMAIN", "unknown.zigor.net", dns.TypeA,
		expectRCode(dns.RCodeNXDomain))

	queryA("google.com -> upstream forward", "google.com", dns.TypeA,
		expectAnyAnswer())

	fmt.Println()

	// 3. Phase 2: OS resolver integration (platform-specific)
	fmt.Printf("--- Phase 2: OS resolver integration (%s) ---\n", runtime.GOOS)
	fmt.Println()

	if err := setupOSResolver(); err != nil {
		fmt.Printf("[resolver] Setup: %v\n", err)
		fmt.Println("[resolver] Skipping OS resolver tests")
	} else {
		// Wait for OS to pick up new config
		flushDNSCache()
		time.Sleep(1 * time.Second)

		testLookupHost("localhost.zigor.net (getaddrinfo)",
			"localhost.zigor.net", tunIPv4)

		if runtime.GOOS == "darwin" {
			testDscacheutil("localhost.zigor.net (dscacheutil)",
				"localhost.zigor.net", tunIPv4)
		}
	}

	fmt.Println()

	// 4. Summary
	fmt.Println("--- Results ---")
	fmt.Println()
	total := passed + failed
	fmt.Printf("  %d/%d passed", passed, total)
	if failed > 0 {
		fmt.Printf(", %d FAILED", failed)
	}
	fmt.Println()
	fmt.Println()

	if failed > 0 {
		os.Exit(1)
	}
}

// ============================================================================
// Phase 1: Pure Go DNS client (works everywhere, no external tools)
// ============================================================================

type expectFunc func(resp *dns.Message) (ok bool, detail string)

func expectIP(ip string) expectFunc {
	return func(resp *dns.Message) (bool, string) {
		if resp.Header.RCode() != dns.RCodeNoError {
			return false, fmt.Sprintf("rcode=%d", resp.Header.RCode())
		}
		for _, ans := range resp.Answers {
			resolved := formatRData(ans.Type, ans.RData)
			if resolved == ip {
				return true, resolved
			}
		}
		return false, fmt.Sprintf("no matching answer (got %d answers)", len(resp.Answers))
	}
}

func expectRCode(rcode uint16) expectFunc {
	names := map[uint16]string{
		dns.RCodeNoError:  "NOERROR",
		dns.RCodeNXDomain: "NXDOMAIN",
		dns.RCodeServFail: "SERVFAIL",
		dns.RCodeFormErr:  "FORMERR",
	}
	return func(resp *dns.Message) (bool, string) {
		name := names[resp.Header.RCode()]
		if name == "" {
			name = fmt.Sprintf("RCODE_%d", resp.Header.RCode())
		}
		return resp.Header.RCode() == rcode, name
	}
}

func expectAnyAnswer() expectFunc {
	return func(resp *dns.Message) (bool, string) {
		if resp.Header.RCode() != dns.RCodeNoError {
			return false, fmt.Sprintf("rcode=%d", resp.Header.RCode())
		}
		if len(resp.Answers) > 0 {
			return true, formatRData(resp.Answers[0].Type, resp.Answers[0].RData)
		}
		return false, "no answers"
	}
}

func queryA(name, domain string, qtype uint16, check expectFunc) {
	// Build DNS query
	msg := &dns.Message{
		Header: dns.Header{
			ID:    uint16(time.Now().UnixNano() & 0xFFFF),
			Flags: dns.FlagRD,
		},
		Questions: []dns.Question{
			{Name: domain, Type: qtype, Class: dns.ClassIN},
		},
	}
	data, err := dns.EncodeMessage(msg)
	if err != nil {
		fmt.Printf("  [FAIL] %s -> encode error: %v\n", name, err)
		failed++
		return
	}

	// Send UDP query
	conn, err := net.DialTimeout("udp", listenAddr, 3*time.Second)
	if err != nil {
		fmt.Printf("  [FAIL] %s -> dial error: %v\n", name, err)
		failed++
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(data); err != nil {
		fmt.Printf("  [FAIL] %s -> write error: %v\n", name, err)
		failed++
		return
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("  [FAIL] %s -> read error: %v\n", name, err)
		failed++
		return
	}

	resp, err := dns.DecodeMessage(buf[:n])
	if err != nil {
		fmt.Printf("  [FAIL] %s -> decode error: %v\n", name, err)
		failed++
		return
	}

	ok, detail := check(resp)
	if ok {
		fmt.Printf("  [PASS] %s -> %s\n", name, detail)
		passed++
	} else {
		fmt.Printf("  [FAIL] %s -> %s\n", name, detail)
		failed++
	}
}

func formatRData(qtype uint16, rdata []byte) string {
	switch qtype {
	case dns.TypeA:
		if len(rdata) == 4 {
			return net.IP(rdata).String()
		}
	case dns.TypeAAAA:
		if len(rdata) == 16 {
			return net.IP(rdata).String()
		}
	}
	return fmt.Sprintf("(%d bytes)", len(rdata))
}

// ============================================================================
// Phase 2: OS resolver integration
// ============================================================================

func testLookupHost(name, domain, expect string) {
	addrs, err := net.LookupHost(domain)
	if err != nil {
		fmt.Printf("  [FAIL] %s -> lookup error: %v\n", name, err)
		failed++
		return
	}
	for _, addr := range addrs {
		if addr == expect {
			fmt.Printf("  [PASS] %s -> %s\n", name, addr)
			passed++
			return
		}
	}
	fmt.Printf("  [FAIL] %s -> expected %s, got: %v\n", name, expect, addrs)
	failed++
}

func testDscacheutil(name, domain, expect string) {
	cmd := exec.Command("dscacheutil", "-q", "host", "-a", "name", domain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("  [FAIL] %s -> dscacheutil error: %v\n", name, err)
		failed++
		return
	}
	if strings.Contains(string(output), expect) {
		fmt.Printf("  [PASS] %s -> contains %s\n", name, expect)
		passed++
	} else {
		fmt.Printf("  [FAIL] %s -> expected %s in output:\n         %s\n",
			name, expect, strings.TrimSpace(string(output)))
		failed++
	}
}

// ============================================================================
// OS resolver setup/cleanup (platform-specific)
// ============================================================================

func setupOSResolver() error {
	switch runtime.GOOS {
	case "darwin":
		return setupDarwinResolver()
	case "linux":
		return setupLinuxResolver()
	case "windows":
		return setupWindowsResolver()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func setupDarwinResolver() error {
	if err := os.MkdirAll("/etc/resolver", 0755); err != nil {
		return err
	}
	content := "# Added by zgrnet dns_test\nnameserver 127.0.0.1\nport 15353\n"
	fmt.Println("[resolver] Created /etc/resolver/zigor.net")
	return os.WriteFile("/etc/resolver/zigor.net", []byte(content), 0644)
}

func setupLinuxResolver() error {
	// On Linux, we can't easily do split DNS without systemd-resolved.
	// For CI, just test direct queries (Phase 1).
	// TODO: detect systemd-resolved and use resolvectl
	return fmt.Errorf("Linux OS resolver integration not yet implemented (Phase 1 tests sufficient for CI)")
}

func setupWindowsResolver() error {
	// Windows: use PowerShell NRPT rule
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Add-DnsClientNrptRule -Namespace ".zigor.net" -NameServers "127.0.0.1" -Comment "zgrnet-test"`)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("NRPT rule failed: %v\n%s", err, string(output))
	}
	fmt.Println("[resolver] Added NRPT rule for .zigor.net -> 127.0.0.1")
	// Note: NRPT rules use port 53 by default. Our server is on 15353.
	// For Windows, we need to listen on port 53 or change the approach.
	// For now, Phase 1 direct queries validate the server works.
	return fmt.Errorf("Windows NRPT uses port 53, our test server is on 15353 (Phase 1 tests sufficient)")
}

func cleanup(srv *dns.Server) {
	fmt.Println()
	fmt.Println("[cleanup] Stopping DNS server...")
	srv.Close()

	switch runtime.GOOS {
	case "darwin":
		if _, err := os.Stat("/etc/resolver/zigor.net"); err == nil {
			os.Remove("/etc/resolver/zigor.net")
			fmt.Println("[cleanup] Removed /etc/resolver/zigor.net")
		}
		flushDNSCache()
	case "windows":
		// Remove NRPT rules
		exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			`Get-DnsClientNrptRule | Where-Object { $_.Comment -eq "zgrnet-test" } | Remove-DnsClientNrptRule -Force`).Run()
		flushDNSCache()
		fmt.Println("[cleanup] Removed NRPT rules")
	}

	fmt.Println("[done]")
}

func flushDNSCache() {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("dscacheutil", "-flushcache").Run()
		exec.Command("killall", "-HUP", "mDNSResponder").Run()
		fmt.Println("[cleanup] Flushed DNS cache")
	case "windows":
		exec.Command("ipconfig", "/flushdns").Run()
		fmt.Println("[cleanup] Flushed DNS cache")
	case "linux":
		exec.Command("resolvectl", "flush-caches").Run()
	}
}

// Needed for dns package but not used directly — suppress unused import
var _ = binary.BigEndian
