// Magic DNS integration test.
//
// Starts a DNS server, configures macOS to route *.zigor.net queries to it,
// runs verification tests automatically, then cleans up.
//
// Usage:
//   cd go && go build -o dns_test ../examples/dns_test/go/main.go
//   sudo ./dns_test
package main

import (
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
	listenAddr   = "127.0.0.1:15353"
	tunIPv4      = "100.64.0.1"
	tunIPv6      = "fd00::1"
	resolverDir  = "/etc/resolver"
	resolverFile = "/etc/resolver/zigor.net"
)

var passed, failed int

func main() {
	if os.Getuid() != 0 && runtime.GOOS != "windows" {
		fmt.Println("ERROR: requires root/sudo")
		fmt.Println("Usage: sudo ./dns_test")
		os.Exit(1)
	}

	fmt.Println("=== Magic DNS Integration Test ===")
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
	// Wait for server to start
	time.Sleep(100 * time.Millisecond)
	fmt.Printf("[dns] Server listening on %s\n", listenAddr)
	fmt.Println()

	// Ensure cleanup on any exit path
	defer cleanup(srv)

	// 2. Test direct queries (no OS config needed)
	fmt.Println("--- Phase 1: Direct queries (@127.0.0.1 -p 15353) ---")
	fmt.Println()

	testDig("localhost.zigor.net A (direct)",
		"localhost.zigor.net", "A", true, tunIPv4)

	testDig("localhost.zigor.net AAAA (direct)",
		"localhost.zigor.net", "AAAA", true, "fd00::1")

	testDig("unknown.zigor.net A -> NXDOMAIN (direct)",
		"unknown.zigor.net", "A", true, "NXDOMAIN")

	testDig("google.com A -> upstream forward (direct)",
		"google.com", "A", true, "") // any answer is fine

	fmt.Println()

	// 3. Configure OS resolver (macOS only)
	// Note: dig does NOT use /etc/resolver/ — it reads /etc/resolv.conf directly.
	// macOS apps use mDNSResponder (via getaddrinfo), which reads /etc/resolver/.
	// So we test with Go's net.LookupHost (which calls getaddrinfo) and dscacheutil.
	if runtime.GOOS == "darwin" {
		fmt.Println("--- Phase 2: OS resolver integration (/etc/resolver/) ---")
		fmt.Println()

		if err := setupDarwinResolver(); err != nil {
			fmt.Printf("[SKIP] Failed to configure OS resolver: %v\n", err)
		} else {
			fmt.Println("[resolver] Created /etc/resolver/zigor.net")

			// Flush cache and wait for mDNSResponder to pick up new file
			exec.Command("dscacheutil", "-flushcache").Run()
			exec.Command("killall", "-HUP", "mDNSResponder").Run()
			time.Sleep(1 * time.Second)

			testLookupHost("localhost.zigor.net (via getaddrinfo)",
				"localhost.zigor.net", tunIPv4)

			testDscacheutil("localhost.zigor.net (via dscacheutil)",
				"localhost.zigor.net", tunIPv4)
		}
		fmt.Println()
	}

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

func cleanup(srv *dns.Server) {
	fmt.Println("[cleanup] Stopping DNS server...")
	srv.Close()

	if runtime.GOOS == "darwin" {
		if _, err := os.Stat(resolverFile); err == nil {
			fmt.Println("[cleanup] Removing /etc/resolver/zigor.net...")
			os.Remove(resolverFile)
		}
	}

	// Flush DNS cache
	if runtime.GOOS == "darwin" {
		exec.Command("dscacheutil", "-flushcache").Run()
		exec.Command("killall", "-HUP", "mDNSResponder").Run()
		fmt.Println("[cleanup] Flushed DNS cache")
	}

	fmt.Println("[done]")
}

// testDig runs dig and checks if the expected string appears in the output.
// If direct=true, queries @127.0.0.1 -p 15353. Otherwise uses OS resolver.
// If expect="" any successful response is accepted.
func testDig(name, domain, qtype string, direct bool, expect string) {
	args := []string{domain, qtype, "+short", "+timeout=3", "+tries=1"}
	if direct {
		args = append(args, "@127.0.0.1", "-p", "15353")
	}

	cmd := exec.Command("dig", args...)
	output, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(output))

	if expect == "NXDOMAIN" {
		// For NXDOMAIN, dig +short returns empty, check with +noall +comments
		args2 := []string{domain, qtype, "+timeout=3", "+tries=1"}
		if direct {
			args2 = append(args2, "@127.0.0.1", "-p", "15353")
		}
		cmd2 := exec.Command("dig", args2...)
		out2, _ := cmd2.CombinedOutput()
		if strings.Contains(string(out2), "NXDOMAIN") {
			fmt.Printf("  [PASS] %s -> NXDOMAIN\n", name)
			passed++
			return
		}
		fmt.Printf("  [FAIL] %s -> expected NXDOMAIN, got:\n         %s\n", name, result)
		failed++
		return
	}

	if err != nil {
		fmt.Printf("  [FAIL] %s -> dig error: %v\n", name, err)
		failed++
		return
	}

	if expect == "" {
		// Any response is fine
		if result != "" {
			fmt.Printf("  [PASS] %s -> %s\n", name, firstLine(result))
			passed++
		} else {
			fmt.Printf("  [FAIL] %s -> empty response\n", name)
			failed++
		}
		return
	}

	if strings.Contains(result, expect) {
		fmt.Printf("  [PASS] %s -> %s\n", name, result)
		passed++
	} else {
		fmt.Printf("  [FAIL] %s -> expected %s, got: %s\n", name, expect, result)
		failed++
	}
}

// testLookupHost uses Go's net.LookupHost which calls getaddrinfo,
// going through macOS's mDNSResponder and /etc/resolver/.
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

// testDscacheutil uses macOS dscacheutil to verify resolver integration.
func testDscacheutil(name, domain, expect string) {
	cmd := exec.Command("dscacheutil", "-q", "host", "-a", "name", domain)
	output, err := cmd.CombinedOutput()
	result := string(output)

	if err != nil {
		fmt.Printf("  [FAIL] %s -> dscacheutil error: %v\n", name, err)
		failed++
		return
	}

	if strings.Contains(result, expect) {
		fmt.Printf("  [PASS] %s -> contains %s\n", name, expect)
		passed++
	} else {
		fmt.Printf("  [FAIL] %s -> expected %s in output:\n         %s\n", name, expect, strings.TrimSpace(result))
		failed++
	}
}

func setupDarwinResolver() error {
	if err := os.MkdirAll(resolverDir, 0755); err != nil {
		return err
	}
	content := "# Added by zgrnet dns_test\nnameserver 127.0.0.1\nport 15353\n"
	return os.WriteFile(resolverFile, []byte(content), 0644)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
