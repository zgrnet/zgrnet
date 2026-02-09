// Command smoketest runs a full-stack integration test of two zgrnetd instances.
//
// It creates two TUN devices, two Hosts, two DNS servers, and two SOCKS5 proxies,
// then verifies they can communicate through the encrypted Noise Protocol tunnel.
//
// Requires root/sudo:
//
//	bazel build //go/cmd/smoketest
//	sudo bazel-bin/go/cmd/smoketest/smoketest_/smoketest
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/vibing/zgrnet/pkg/dns"
	"github.com/vibing/zgrnet/pkg/host"
	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/proxy"
	"github.com/vibing/zgrnet/pkg/tun"
)

const (
	// Host A: 100.64.0.1, assigns peer B as 100.64.0.2
	tunAIP   = "100.64.0.1"
	tunAMask = 24 // /24 for local subnet

	// Host B: 100.64.1.1, assigns peer A as 100.64.1.2
	tunBIP   = "100.64.1.1"
	tunBMask = 24

	mtu = 1400
)

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║           zgrnetd Full-Stack Smoke Test                 ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()

	if os.Getuid() != 0 {
		fatal("requires root. Run with: sudo %s", os.Args[0])
	}

	passed, failed := 0, 0
	report := func(name string, ok bool) {
		if ok {
			passed++
			fmt.Printf("  ✅ PASS: %s\n", name)
		} else {
			failed++
			fmt.Printf("  ❌ FAIL: %s\n", name)
		}
	}

	// ── Generate Keys ────────────────────────────────────────────────────
	step("Generating keypairs")
	keyA, err := noise.GenerateKeyPair()
	must(err, "keygen A")
	keyB, err := noise.GenerateKeyPair()
	must(err, "keygen B")
	info("A pubkey: %s", keyA.Public.ShortString())
	info("B pubkey: %s", keyB.Public.ShortString())

	// ── Create TUN Devices ───────────────────────────────────────────────
	step("Creating TUN devices")
	tunA, err := tun.Create("")
	must(err, "create TUN A")
	defer tunA.Close()

	tunB, err := tun.Create("")
	must(err, "create TUN B")
	defer tunB.Close()

	must(tunA.SetMTU(mtu), "MTU A")
	must(tunA.SetIPv4(net.ParseIP(tunAIP), net.CIDRMask(tunAMask, 32)), "IPv4 A")
	must(tunA.Up(), "up A")
	info("TUN A: %s (%s/%d)", tunA.Name(), tunAIP, tunAMask)

	must(tunB.SetMTU(mtu), "MTU B")
	must(tunB.SetIPv4(net.ParseIP(tunBIP), net.CIDRMask(tunBMask, 32)), "IPv4 B")
	must(tunB.Up(), "up B")
	info("TUN B: %s (%s/%d)", tunB.Name(), tunBIP, tunBMask)

	// ── Create Hosts ─────────────────────────────────────────────────────
	step("Creating Hosts (TUN + encrypted UDP)")
	hostA, err := host.New(host.Config{
		PrivateKey: keyA,
		TunIPv4:    net.ParseIP(tunAIP),
		MTU:        mtu,
	}, tunA)
	must(err, "host A")
	defer hostA.Close()

	hostB, err := host.New(host.Config{
		PrivateKey: keyB,
		TunIPv4:    net.ParseIP(tunBIP),
		MTU:        mtu,
	}, tunB)
	must(err, "host B")
	defer hostB.Close()

	portA := hostA.LocalAddr().(*net.UDPAddr).Port
	portB := hostB.LocalAddr().(*net.UDPAddr).Port
	info("Host A: UDP :%d", portA)
	info("Host B: UDP :%d", portB)

	// Add peers with static IPs
	must(hostA.AddPeerWithIP(keyB.Public, fmt.Sprintf("127.0.0.1:%d", portB),
		net.ParseIP("100.64.0.2")), "add peer B→A")
	must(hostB.AddPeerWithIP(keyA.Public, fmt.Sprintf("127.0.0.1:%d", portA),
		net.ParseIP("100.64.1.2")), "add peer A→B")
	info("A knows B as 100.64.0.2")
	info("B knows A as 100.64.1.2")

	// ── Start Host forwarding ────────────────────────────────────────────
	step("Starting Host forwarding loops")
	go hostA.Run()
	go hostB.Run()
	info("OK")

	// ── Noise Handshake ──────────────────────────────────────────────────
	step("Noise IK handshake (A → B)")
	must(hostA.Connect(keyB.Public), "handshake A→B")
	info("Handshake complete!")
	time.Sleep(200 * time.Millisecond) // let routes settle

	// ── Start DNS Servers ────────────────────────────────────────────────
	// NOTE: On macOS, utun is point-to-point — packets TO the TUN IP go
	// into the TUN device (read by Host), not to local sockets. So we
	// listen on 127.0.0.1 for testing. In production, dnsmgr configures
	// /etc/resolver/ to route queries correctly.
	step("Starting Magic DNS servers")

	dnsA := dns.NewServer(dns.ServerConfig{
		ListenAddr: "127.0.0.1:0", // OS picks port
		TunIPv4:    net.ParseIP(tunAIP),
		Upstream:   "8.8.8.8:53",
	})
	go dnsA.ListenAndServe()
	defer dnsA.Close()

	dnsB := dns.NewServer(dns.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TunIPv4:    net.ParseIP(tunBIP),
		Upstream:   "8.8.8.8:53",
	})
	go dnsB.ListenAndServe()
	defer dnsB.Close()

	dnsAAddr := waitForDNSAddr(dnsA, "DNS A")
	dnsBAddr := waitForDNSAddr(dnsB, "DNS B")

	// ── Start Proxy Servers (tunnel mode) ────────────────────────────────
	// Proxy A dials through KCP tunnel to B; B accepts and does real TCP dial.
	step("Starting SOCKS5 proxy + TCP_PROXY accept loops")

	udpA := hostA.UDP()
	udpB := hostB.UDP()

	// Proxy A: SOCKS5 → KCP stream (proto=69) → B
	proxyA := proxy.NewServer("127.0.0.1:0", func(addr *noise.Address) (io.ReadWriteCloser, error) {
		metadata := addr.Encode()
		stream, err := udpA.OpenStream(keyB.Public, noise.ProtocolTCPProxy, metadata)
		if err != nil {
			return nil, fmt.Errorf("open stream: %w", err)
		}
		return &proxy.BlockingStream{S: stream}, nil
	})
	go proxyA.ListenAndServe()
	defer proxyA.Close()

	// B accepts TCP_PROXY streams and dials real targets
	go func() {
		for {
			stream, err := udpB.AcceptStream(keyA.Public)
			if err != nil {
				return
			}
			if stream.Proto() != noise.ProtocolTCPProxy {
				stream.Close()
				continue
			}
			go func() {
				bs := &proxy.BlockingStream{S: stream}
				if err := proxy.HandleTCPProxy(bs, stream.Metadata(), nil, nil); err != nil {
					log.Printf("tcp_proxy: %v", err)
				}
			}()
		}
	}()

	// Proxy B: SOCKS5 → KCP stream (proto=69) → A
	proxyB := proxy.NewServer("127.0.0.1:0", func(addr *noise.Address) (io.ReadWriteCloser, error) {
		metadata := addr.Encode()
		stream, err := udpB.OpenStream(keyA.Public, noise.ProtocolTCPProxy, metadata)
		if err != nil {
			return nil, fmt.Errorf("open stream: %w", err)
		}
		return &proxy.BlockingStream{S: stream}, nil
	})
	go proxyB.ListenAndServe()
	defer proxyB.Close()

	// A accepts TCP_PROXY streams and dials real targets
	go func() {
		for {
			stream, err := udpA.AcceptStream(keyB.Public)
			if err != nil {
				return
			}
			if stream.Proto() != noise.ProtocolTCPProxy {
				stream.Close()
				continue
			}
			go func() {
				bs := &proxy.BlockingStream{S: stream}
				if err := proxy.HandleTCPProxy(bs, stream.Metadata(), nil, nil); err != nil {
					log.Printf("tcp_proxy: %v", err)
				}
			}()
		}
	}()

	proxyAAddr := waitForProxyAddr(proxyA, "Proxy A (→ tunnel → B)")
	proxyBAddr := waitForProxyAddr(proxyB, "Proxy B (→ tunnel → A)")

	// ══════════════════════════════════════════════════════════════════════
	//  TESTS
	// ══════════════════════════════════════════════════════════════════════
	fmt.Println()
	fmt.Println("── Tests ──────────────────────────────────────────────────")

	// Test 1: Ping A → B (through tunnel)
	fmt.Println()
	fmt.Println("[Test 1] Ping A→B (100.64.0.2) via encrypted tunnel")
	report("Ping A→B", runPing("100.64.0.2"))

	// Test 2: Ping B → A (through tunnel)
	fmt.Println()
	fmt.Println("[Test 2] Ping B→A (100.64.1.2) via encrypted tunnel")
	report("Ping B→A", runPing("100.64.1.2"))

	// Test 3: DNS query — localhost.zigor.net on DNS A
	fmt.Println()
	fmt.Println("[Test 3] DNS: localhost.zigor.net → TUN A IP")
	report("DNS localhost.zigor.net", testDNS(dnsAAddr, "localhost.zigor.net", tunAIP))

	// Test 4: DNS query — localhost.zigor.net on DNS B
	fmt.Println()
	fmt.Println("[Test 4] DNS: localhost.zigor.net → TUN B IP")
	report("DNS localhost.zigor.net (B)", testDNS(dnsBAddr, "localhost.zigor.net", tunBIP))

	// Test 5: SOCKS5 proxy — A → tunnel → B → TCP target
	fmt.Println()
	fmt.Println("[Test 5] SOCKS5 Proxy: curl → A → KCP tunnel → B → HTTP target")
	report("Proxy A→tunnel→B", testSOCKS5Proxy(proxyAAddr))

	// Test 6: SOCKS5 proxy — B → tunnel → A → TCP target
	fmt.Println()
	fmt.Println("[Test 6] SOCKS5 Proxy: curl → B → KCP tunnel → A → HTTP target")
	report("Proxy B→tunnel→A", testSOCKS5Proxy(proxyBAddr))

	// ── Summary ──────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Printf("  Results: %d passed, %d failed (total %d)\n", passed, failed, passed+failed)
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println()

	if failed > 0 {
		fmt.Println("SOME TESTS FAILED")
		os.Exit(1)
	}
	fmt.Println("ALL TESTS PASSED!")
	// Force exit to avoid blocking on TUN reads (see host_test/main.go)
	os.Exit(0)
}

// runPing runs `ping -c 3 -W 2 <target>` and returns true on success.
func runPing(target string) bool {
	cmd := exec.Command("ping", "-c", "3", "-W", "2", target)
	output, err := cmd.CombinedOutput()
	out := string(output)

	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fmt.Printf("    %s\n", line)
	}

	if err != nil {
		fmt.Printf("    error: %v\n", err)
		return false
	}
	return strings.Contains(out, "0.0% packet loss") ||
		strings.Contains(out, " 0% packet loss")
}

// testDNS sends an A query to the given DNS server and checks the response IP.
func testDNS(serverAddr, domain, expectedIP string) bool {
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		fmt.Printf("    resolve DNS server addr: %v\n", err)
		return false
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Printf("    dial DNS: %v\n", err)
		return false
	}
	defer conn.Close()

	query := buildDNSQuery(domain)
	if _, err := conn.Write(query); err != nil {
		fmt.Printf("    write: %v\n", err)
		return false
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("    read: %v\n", err)
		return false
	}

	ip, err := parseDNSResponseIP(buf[:n])
	if err != nil {
		fmt.Printf("    parse response: %v\n", err)
		return false
	}

	fmt.Printf("    %s → %s\n", domain, ip)
	if ip != expectedIP {
		fmt.Printf("    expected %s\n", expectedIP)
		return false
	}
	return true
}

// testSOCKS5Proxy starts a temporary HTTP server on 127.0.0.1, then connects
// through the SOCKS5 proxy and verifies the SOCKS5 handshake + relay works.
func testSOCKS5Proxy(proxyAddr string) bool {
	// Start a temporary HTTP server on loopback
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("    listen HTTP: %v\n", err)
		return false
	}
	defer ln.Close()

	httpPort := ln.Addr().(*net.TCPAddr).Port
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("zgrnet-ok"))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	targetURL := fmt.Sprintf("http://127.0.0.1:%d/health", httpPort)
	fmt.Printf("    HTTP server: %s\n", targetURL)
	fmt.Printf("    via proxy:   %s\n", proxyAddr)

	// Connect through SOCKS5 proxy
	proxyDialer, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		fmt.Printf("    connect proxy: %v\n", err)
		return false
	}
	defer proxyDialer.Close()

	// SOCKS5 handshake
	targetHost := fmt.Sprintf("127.0.0.1:%d", httpPort)
	if err := socks5Handshake(proxyDialer, targetHost); err != nil {
		fmt.Printf("    socks5 handshake: %v\n", err)
		return false
	}

	// Send HTTP GET
	httpReq := fmt.Sprintf("GET /health HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetHost)
	if _, err := proxyDialer.Write([]byte(httpReq)); err != nil {
		fmt.Printf("    write HTTP: %v\n", err)
		return false
	}

	proxyDialer.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := io.ReadAll(proxyDialer)
	if err != nil && len(resp) == 0 {
		fmt.Printf("    read HTTP: %v\n", err)
		return false
	}

	body := string(resp)
	fmt.Printf("    response: %s\n", strings.TrimSpace(strings.Split(body, "\r\n")[0]))

	if !strings.Contains(body, "zgrnet-ok") {
		fmt.Printf("    expected body containing 'zgrnet-ok'\n")
		return false
	}
	return true
}

// socks5Handshake performs a SOCKS5 CONNECT through the given TCP connection.
func socks5Handshake(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	// Auth: version 5, 1 method (no auth)
	conn.Write([]byte{0x05, 0x01, 0x00})

	var authResp [2]byte
	if _, err := io.ReadFull(conn, authResp[:]); err != nil {
		return fmt.Errorf("auth response: %w", err)
	}
	if authResp[1] != 0x00 {
		return fmt.Errorf("auth rejected: 0x%02x", authResp[1])
	}

	// Connect request
	ip := net.ParseIP(host).To4()
	req := []byte{0x05, 0x01, 0x00, 0x01} // VER CMD RSV ATYP(IPv4)
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port))
	conn.Write(req)

	// Read reply (at least 10 bytes for IPv4)
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("connect reply: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("connect failed: 0x%02x", reply[1])
	}

	return nil
}

// buildDNSQuery builds a minimal DNS A query for the given domain.
func buildDNSQuery(domain string) []byte {
	buf := make([]byte, 0, 512)

	// Header: ID=0x1234, flags=RD, QDCOUNT=1
	buf = append(buf, 0x12, 0x34) // ID
	buf = append(buf, 0x01, 0x00) // Flags: RD=1
	buf = append(buf, 0x00, 0x01) // QDCOUNT
	buf = append(buf, 0x00, 0x00) // ANCOUNT
	buf = append(buf, 0x00, 0x00) // NSCOUNT
	buf = append(buf, 0x00, 0x00) // ARCOUNT

	// Question: encode domain name
	for _, label := range strings.Split(domain, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // root label

	// Type A, Class IN
	buf = append(buf, 0x00, 0x01) // QTYPE = A
	buf = append(buf, 0x00, 0x01) // QCLASS = IN

	return buf
}

// parseDNSResponseIP extracts the first A record IP from a DNS response.
func parseDNSResponseIP(data []byte) (string, error) {
	if len(data) < 12 {
		return "", fmt.Errorf("response too short")
	}

	ancount := binary.BigEndian.Uint16(data[6:8])
	if ancount == 0 {
		rcode := data[3] & 0x0F
		return "", fmt.Errorf("no answers (RCODE=%d)", rcode)
	}

	// Skip header (12 bytes) + question section
	off := 12
	// Skip QNAME
	for off < len(data) {
		l := int(data[off])
		if l == 0 {
			off++
			break
		}
		if l >= 192 { // pointer
			off += 2
			break
		}
		off += 1 + l
	}
	off += 4 // QTYPE + QCLASS

	// Parse first answer
	// Skip NAME (may be pointer)
	if off >= len(data) {
		return "", fmt.Errorf("truncated answer")
	}
	if data[off] >= 192 { // pointer
		off += 2
	} else {
		for off < len(data) {
			l := int(data[off])
			if l == 0 {
				off++
				break
			}
			off += 1 + l
		}
	}

	if off+10 > len(data) {
		return "", fmt.Errorf("truncated RR")
	}

	rdlen := binary.BigEndian.Uint16(data[off+8 : off+10])
	off += 10

	if off+int(rdlen) > len(data) || rdlen != 4 {
		return "", fmt.Errorf("invalid A record (rdlen=%d)", rdlen)
	}

	ip := net.IPv4(data[off], data[off+1], data[off+2], data[off+3])
	return ip.String(), nil
}

// waitForDNSAddr polls the DNS server until its conn is ready, returns "host:port".
func waitForDNSAddr(srv *dns.Server, label string) string {
	for i := 0; i < 50; i++ {
		if addr := srv.Addr(); addr != nil {
			a := addr.String()
			info("%s: %s", label, a)
			return a
		}
		time.Sleep(20 * time.Millisecond)
	}
	fatal("%s: did not start in time", label)
	return ""
}

// waitForProxyAddr polls the proxy server until its listener is ready.
func waitForProxyAddr(srv *proxy.Server, label string) string {
	for i := 0; i < 50; i++ {
		if addr := srv.Addr(); addr != nil {
			a := addr.String()
			info("%s: %s", label, a)
			return a
		}
		time.Sleep(20 * time.Millisecond)
	}
	fatal("%s: did not start in time", label)
	return ""
}

func step(msg string) {
	fmt.Printf("\n── %s ──\n", msg)
}

func info(format string, args ...any) {
	fmt.Printf("  %s\n", fmt.Sprintf(format, args...))
}

func must(err error, msg string) {
	if err != nil {
		fatal("%s: %v", msg, err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nFATAL: "+format+"\n", args...)
	os.Exit(1)
}
