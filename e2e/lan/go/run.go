//go:build darwin || linux

// Command lan-e2e runs an end-to-end test of the LAN service over real
// TUN devices and Noise-encrypted UDP transport.
//
// Requires root/sudo for TUN device creation.
//
// What it does:
//  1. Creates two hosts (A and B) with TUN devices on 100.64.0.1 and 100.64.0.2
//  2. Host A runs a LAN server with bearer token auth on TUN_A:80
//  3. Host B connects to A, then calls the LAN API through the encrypted tunnel
//  4. Tests: info, join, peers, query, labels, leave
//
// Usage:
//
//	sudo bazel run //e2e/lan/go:lan_e2e
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/vibing/zgrnet/pkg/host"
	"github.com/vibing/zgrnet/pkg/lan"
	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/tun"
)

const (
	token   = "e2e-test-token-2026"
	tunIPa  = "100.64.0.1"
	tunIPb  = "100.64.0.2"
	tunMask = 10
	mtu     = 1400
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "error: this test requires root (sudo)\n")
		os.Exit(1)
	}

	if err := run(); err != nil {
		log.Fatalf("FAIL: %v", err)
	}
	log.Printf("ALL TESTS PASSED")
}

func run() error {
	// ── 1. Generate key pairs ───────────────────────────────────────────
	kpA, err := noise.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate key A: %w", err)
	}
	kpB, err := noise.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate key B: %w", err)
	}
	log.Printf("Host A pubkey: %s", kpA.Public.ShortString())
	log.Printf("Host B pubkey: %s", kpB.Public.ShortString())

	// ── 2. Create TUN devices ───────────────────────────────────────────
	tunA, err := tun.Create("")
	if err != nil {
		return fmt.Errorf("create TUN A: %w", err)
	}
	tunB, err := tun.Create("")
	if err != nil {
		tunA.Close()
		return fmt.Errorf("create TUN B: %w", err)
	}

	ipA := net.ParseIP(tunIPa).To4()
	tunA.SetMTU(mtu)
	tunA.SetIPv4(ipA, net.CIDRMask(tunMask, 32))
	tunA.Up()
	log.Printf("TUN A: %s = %s/10", tunA.Name(), tunIPa)

	ipB := net.ParseIP(tunIPb).To4()
	tunB.SetMTU(mtu)
	tunB.SetIPv4(ipB, net.CIDRMask(tunMask, 32))
	tunB.Up()
	log.Printf("TUN B: %s = %s/10", tunB.Name(), tunIPb)

	// ── 3. Create hosts ─────────────────────────────────────────────────
	hostA, err := host.New(host.Config{
		PrivateKey: kpA, TunIPv4: ipA, MTU: mtu, ListenPort: 0,
	}, tunA)
	if err != nil {
		return fmt.Errorf("create host A: %w", err)
	}
	hostB, err := host.New(host.Config{
		PrivateKey: kpB, TunIPv4: ipB, MTU: mtu, ListenPort: 0,
	}, tunB)
	if err != nil {
		hostA.Close()
		return fmt.Errorf("create host B: %w", err)
	}
	log.Printf("Host A on %s, Host B on %s", hostA.LocalAddr(), hostB.LocalAddr())

	// ── 4. Add peers ────────────────────────────────────────────────────
	// Use 127.0.0.1 explicitly — [::] may not route on macOS loopback.
	aPort := hostA.LocalAddr().(*net.UDPAddr).Port
	bPort := hostB.LocalAddr().(*net.UDPAddr).Port

	aEndpoint := fmt.Sprintf("127.0.0.1:%d", aPort)
	bEndpoint := fmt.Sprintf("127.0.0.1:%d", bPort)

	if err := hostA.AddPeerWithIP(kpB.Public, bEndpoint, ipB); err != nil {
		return fmt.Errorf("A add peer B: %w", err)
	}
	if err := hostB.AddPeerWithIP(kpA.Public, aEndpoint, ipA); err != nil {
		return fmt.Errorf("B add peer A: %w", err)
	}
	log.Printf("peers added: A→B=%s, B→A=%s", bEndpoint, aEndpoint)

	// ── 5. Start forwarding loops ───────────────────────────────────────
	go hostA.Run()
	go hostB.Run()
	time.Sleep(100 * time.Millisecond) // let goroutines start

	// ── 6. Noise handshake B → A ────────────────────────────────────────
	log.Printf("connecting B → A...")
	if err := hostB.Connect(kpA.Public); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	log.Printf("handshake complete")

	// ── 7. LAN server on Host A ─────────────────────────────────────────
	lanServer := lan.NewServer(lan.Config{
		Domain:      "e2e-test.zigor.net",
		Description: "E2E Test LAN",
		IdentityFn: func(ip net.IP) (noise.PublicKey, []string, error) {
			pk, ok := hostA.IPAlloc().LookupByIP(ip)
			if !ok {
				return noise.PublicKey{}, nil, fmt.Errorf("unknown IP: %s", ip)
			}
			return pk, nil, nil
		},
	}, lan.NewMemStore())
	lanServer.RegisterAuth(lan.NewBearerTokenAuth(token))

	httpMux := http.NewServeMux()
	httpMux.Handle("/api/lan/", lanServer.Handler())

	httpAddr := net.JoinHostPort(tunIPa, "80")
	httpLn, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", httpAddr, err)
	}
	go http.Serve(httpLn, httpMux)
	log.Printf("LAN server on %s", httpAddr)
	time.Sleep(200 * time.Millisecond)

	// ── 8. HTTP client from Host B (traffic through tunnel) ─────────────
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				LocalAddr: &net.TCPAddr{IP: ipB},
				Timeout:   5 * time.Second,
			}).DialContext,
		},
	}
	base := "http://" + httpAddr

	// ── Tests ───────────────────────────────────────────────────────────
	passed := 0
	total := 10

	// 1. info
	passed += check("info", func() error {
		body, st, err := httpGet(client, base+"/api/lan/info")
		if err != nil {
			return err
		}
		if st != 200 {
			return fmt.Errorf("status %d: %s", st, body)
		}
		m := parse(body)
		if m["domain"] != "e2e-test.zigor.net" {
			return fmt.Errorf("domain=%v", m["domain"])
		}
		return nil
	})

	// 2. join (correct token)
	passed += check("join", func() error {
		body, st, err := httpPost(client, base+"/api/lan/join",
			`{"auth":{"method":"bearer_token","credential":{"token":"`+token+`"}}}`)
		if err != nil {
			return err
		}
		if st != 200 {
			return fmt.Errorf("status %d: %s", st, body)
		}
		if parse(body)["added"] != true {
			return fmt.Errorf("added=%v", parse(body)["added"])
		}
		return nil
	})

	// 3. join duplicate
	passed += check("join_dup", func() error {
		body, _, _ := httpPost(client, base+"/api/lan/join",
			`{"auth":{"method":"bearer_token","credential":{"token":"`+token+`"}}}`)
		if parse(body)["added"] != false {
			return fmt.Errorf("expected added=false")
		}
		return nil
	})

	// 4. join wrong token
	passed += check("join_bad_token", func() error {
		_, st, _ := httpPost(client, base+"/api/lan/join",
			`{"auth":{"method":"bearer_token","credential":{"token":"wrong"}}}`)
		if st != 401 {
			return fmt.Errorf("expected 401, got %d", st)
		}
		return nil
	})

	// 5. peers
	passed += check("peers", func() error {
		body, st, err := httpGet(client, base+"/api/lan/peers")
		if err != nil {
			return err
		}
		if st != 200 {
			return fmt.Errorf("status %d", st)
		}
		peers, ok := parse(body)["peers"].([]any)
		if !ok || len(peers) != 1 {
			return fmt.Errorf("expected 1 peer, got %v", parse(body)["peers"])
		}
		return nil
	})

	// 6. query member
	passed += check("query_member", func() error {
		body, _, err := httpGet(client, base+"/api/lan/query/"+kpB.Public.String())
		if err != nil {
			return err
		}
		if parse(body)["member"] != true {
			return fmt.Errorf("member=%v", parse(body)["member"])
		}
		return nil
	})

	// 7. set labels
	passed += check("set_labels", func() error {
		_, st, _ := httpPost(client, base+"/api/lan/labels/"+kpB.Public.String(),
			`{"labels":["admin","dev"]}`)
		if st != 200 {
			return fmt.Errorf("status %d", st)
		}
		body, _, _ := httpGet(client, base+"/api/lan/query/"+kpB.Public.String())
		labels, _ := parse(body)["labels"].([]any)
		if len(labels) != 2 {
			return fmt.Errorf("expected 2 labels, got %v", labels)
		}
		return nil
	})

	// 8. delete labels
	passed += check("del_labels", func() error {
		_, st, _ := httpDo(client, "DELETE", base+"/api/lan/labels/"+kpB.Public.String(),
			`{"labels":["admin"]}`)
		if st != 200 {
			return fmt.Errorf("status %d", st)
		}
		body, _, _ := httpGet(client, base+"/api/lan/query/"+kpB.Public.String())
		labels, _ := parse(body)["labels"].([]any)
		if len(labels) != 1 {
			return fmt.Errorf("expected 1 label, got %v", labels)
		}
		return nil
	})

	// 9. leave
	passed += check("leave", func() error {
		body, st, _ := httpPost(client, base+"/api/lan/leave", "")
		if st != 200 {
			return fmt.Errorf("status %d", st)
		}
		if parse(body)["removed"] != true {
			return fmt.Errorf("removed=%v", parse(body)["removed"])
		}
		return nil
	})

	// 10. verify empty after leave
	passed += check("empty_after_leave", func() error {
		body, _, _ := httpGet(client, base+"/api/lan/info")
		if parse(body)["members"].(float64) != 0 {
			return fmt.Errorf("members=%v", parse(body)["members"])
		}
		return nil
	})

	log.Printf("────────────────────────────────")
	log.Printf("RESULT: %d/%d passed", passed, total)

	// Shutdown
	httpLn.Close()
	client.CloseIdleConnections()
	hostB.Close()
	hostA.Close()

	if passed < total {
		return fmt.Errorf("%d tests failed", total-passed)
	}
	return nil
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func check(name string, fn func() error) int {
	log.Printf("TEST: %s", name)
	if err := fn(); err != nil {
		log.Printf("  FAIL: %v", err)
		return 0
	}
	log.Printf("  PASS")
	return 1
}

func httpGet(c *http.Client, url string) (string, int, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode, nil
}

func httpPost(c *http.Client, url, body string) (string, int, error) {
	return httpDo(c, "POST", url, body)
}

func httpDo(c *http.Client, method, url, body string) (string, int, error) {
	var r io.Reader
	if body != "" {
		r = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode, nil
}

func parse(s string) map[string]any {
	var m map[string]any
	json.Unmarshal([]byte(s), &m)
	return m
}
