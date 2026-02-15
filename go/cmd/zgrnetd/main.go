//go:build darwin || linux

// Command zgrnetd is the zgrnet daemon.
//
// It loads a config file and starts:
//   - TUN device with a CGNAT IP
//   - Noise Protocol encrypted UDP transport
//   - Host (bridges TUN ↔ UDP, routes IP packets to/from peers)
//   - Magic DNS server (resolves *.zigor.net → TUN IPs)
//   - SOCKS5/HTTP CONNECT proxy server
//
// Usage:
//
//	zgrnetd -c /path/to/config.yaml
//	zgrnetd -c /path/to/config.yaml -d   # (daemon mode, future)
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/vibing/zgrnet/pkg/api"
	"github.com/vibing/zgrnet/pkg/config"
	"github.com/vibing/zgrnet/pkg/dns"
	"github.com/vibing/zgrnet/pkg/dnsmgr"
	"github.com/vibing/zgrnet/pkg/host"
	znet "github.com/vibing/zgrnet/pkg/net"
	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/proxy"
	"github.com/vibing/zgrnet/pkg/tun"
)

var (
	contextName = flag.String("c", "", "Context name or config file path")
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	cfgPath, err := resolveConfigPath(*contextName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Usage: zgrnetd [-c <context>]\n")
		os.Exit(1)
	}

	if err := run(cfgPath); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

// resolveConfigPath resolves a context name or file path to a config file path.
// - Empty: use current context from ~/.config/zgrnet/current
// - Contains '/' or ends with '.yaml'/'.json': treat as file path
// - Otherwise: treat as context name → ~/.config/zgrnet/<name>/config.yaml
func resolveConfigPath(input string) (string, error) {
	if input == "" {
		// Use current context
		baseDir, err := defaultConfigDir()
		if err != nil {
			return "", err
		}
		name, err := readCurrentContext(baseDir)
		if err != nil {
			return "", fmt.Errorf("no context specified and %w", err)
		}
		path := filepath.Join(baseDir, name, "config.yaml")
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("context %q config not found: %s", name, path)
		}
		return path, nil
	}

	// If it looks like a file path, use directly
	if strings.Contains(input, "/") || strings.HasSuffix(input, ".yaml") || strings.HasSuffix(input, ".json") {
		if _, err := os.Stat(input); err != nil {
			return "", fmt.Errorf("config file not found: %s", input)
		}
		return input, nil
	}

	// Treat as context name
	baseDir, err := defaultConfigDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(baseDir, input, "config.yaml")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("context %q not found (looked for %s)", input, path)
	}
	return path, nil
}

func defaultConfigDir() (string, error) {
	if dir := os.Getenv("ZGRNET_HOME"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".config", "zgrnet"), nil
}

func readCurrentContext(baseDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(baseDir, "current"))
	if err != nil {
		return "", fmt.Errorf("no current context set (run: zgrnet context create <name>)")
	}
	name := strings.TrimSpace(string(data))
	if name == "" {
		return "", fmt.Errorf("current context file is empty")
	}
	return name, nil
}

func run(cfgPath string) error {
	// ── 1. Load and validate config via Manager ─────────────────────────
	log.Printf("loading config: %s", cfgPath)

	cfgMgr, err := config.NewManager(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg := cfgMgr.Current()

	// Apply defaults for optional fields
	if cfg.Net.TunMTU == 0 {
		cfg.Net.TunMTU = 1400
	}
	if cfg.Net.ListenPort == 0 {
		cfg.Net.ListenPort = 51820
	}
	if cfg.Net.PrivateKeyPath == "" {
		cfg.Net.PrivateKeyPath = "private.key"
	}

	// ── 2. Load or generate private key ──────────────────────────────────
	keyPair, err := loadOrGenerateKey(cfg.Net.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	log.Printf("public key: %s", keyPair.Public)

	// ── 3. Create data directory ─────────────────────────────────────────
	dataDir := filepath.Join(filepath.Dir(string(cfgPath)), "data")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("create data dir %s: %w", dataDir, err)
	}

	// ── 4. Create and configure TUN device ───────────────────────────────
	log.Printf("creating TUN device...")
	tunDev, err := tun.Create("")
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	defer tunDev.Close()

	tunIP := net.ParseIP(cfg.Net.TunIPv4).To4()
	if tunIP == nil {
		return fmt.Errorf("invalid TUN IP: %s", cfg.Net.TunIPv4)
	}

	if err := tunDev.SetMTU(cfg.Net.TunMTU); err != nil {
		return fmt.Errorf("set TUN MTU: %w", err)
	}
	// /10 netmask for CGNAT range (100.64.0.0/10)
	if err := tunDev.SetIPv4(tunIP, net.CIDRMask(10, 32)); err != nil {
		return fmt.Errorf("set TUN IPv4: %w", err)
	}
	if err := tunDev.Up(); err != nil {
		return fmt.Errorf("bring TUN up: %w", err)
	}

	// Fix macOS utun routing.
	//
	// macOS utun is point-to-point: the OS only creates a host route for the
	// peer address, ignoring the subnet mask. We need two explicit routes:
	//
	//   1. Host route for our own TUN IP → lo0 (so local TCP connections work)
	//   2. Subnet route for the CGNAT /10 range → utun (so peer traffic goes
	//      through TUN instead of the default route)
	//
	// On Linux, the kernel handles both automatically.
	if err := addTUNRoutes(tunIP, tunDev.Name()); err != nil {
		log.Printf("warning: add TUN routes: %v", err)
	}

	log.Printf("TUN %s: %s/10, MTU %d", tunDev.Name(), tunIP, cfg.Net.TunMTU)

	// ── 5-6. Create Host (TUN + UDP + IP Allocator) ─────────────────────
	hostCfg := host.Config{
		PrivateKey: keyPair,
		TunIPv4:    tunIP,
		MTU:        cfg.Net.TunMTU,
		ListenPort: cfg.Net.ListenPort,
	}
	h, err := host.New(hostCfg, tunDev)
	if err != nil {
		return fmt.Errorf("create host: %w", err)
	}
	defer h.Close()
	log.Printf("host listening on %s", h.LocalAddr())

	// ── 7. Add peers from config ─────────────────────────────────────────
	for domain, peerCfg := range cfg.Peers {
		hexPubkey, err := pubkeyFromDomain(domain)
		if err != nil {
			return fmt.Errorf("peer %s: %w", domain, err)
		}
		pk, err := noise.KeyFromHex(hexPubkey)
		if err != nil {
			return fmt.Errorf("peer %s: invalid pubkey: %w", domain, err)
		}

		endpoint := ""
		if len(peerCfg.Direct) > 0 {
			endpoint = peerCfg.Direct[0] // use first direct endpoint
		}

		if err := h.AddPeer(pk, endpoint); err != nil {
			return fmt.Errorf("add peer %s (%s): %w", peerCfg.Alias, domain, err)
		}
		log.Printf("peer added: %s (%s) endpoint=%s",
			peerCfg.Alias, pk.ShortString(), endpoint)
	}

	// ── 8. Start Magic DNS ───────────────────────────────────────────────
	dnsAddr := net.JoinHostPort(tunIP.String(), "53")
	dnsServer := dns.NewServer(dns.ServerConfig{
		ListenAddr: dnsAddr,
		TunIPv4:    tunIP,
		Upstream:   "8.8.8.8:53",
	})

	go func() {
		log.Printf("dns listening on %s", dnsAddr)
		if err := dnsServer.ListenAndServe(); err != nil {
			log.Printf("dns error: %v", err)
		}
	}()
	defer dnsServer.Close()

	// Configure OS to route *.zigor.net DNS queries to our server
	dnsMgr, err := dnsmgr.New(tunDev.Name())
	if err != nil {
		log.Printf("warning: dnsmgr init failed (split DNS will not work): %v", err)
	} else {
		defer dnsMgr.Close()
		if err := dnsMgr.SetDNS(tunIP.String(), []string{"zigor.net"}); err != nil {
			log.Printf("warning: dnsmgr set DNS failed: %v", err)
		} else {
			log.Printf("dns: OS configured to resolve *.zigor.net via %s", tunIP)
		}
	}

	// ── 9. Build peer alias → pubkey lookup for route matching ──────────
	aliasToPubkey := make(map[string]noise.PublicKey)
	for domain, peerCfg := range cfg.Peers {
		hexPK, _ := pubkeyFromDomain(domain)
		pk, _ := noise.KeyFromHex(hexPK)
		if peerCfg.Alias != "" {
			aliasToPubkey[peerCfg.Alias] = pk
		}
		aliasToPubkey[domain] = pk
	}

	// ── 10. Start SOCKS5 Proxy (dials through KCP tunnel) ───────────────
	proxyAddr := net.JoinHostPort(tunIP.String(), "1080")
	udpTransport := h.UDP()

	// The proxy's DialFunc opens a KCP stream to the first available peer.
	// TODO: route matching — pick peer based on config route rules + domain.
	proxyDial := func(addr *noise.Address) (io.ReadWriteCloser, error) {
		// Find an established peer to tunnel through
		var targetPK noise.PublicKey
		found := false
		for peer := range udpTransport.Peers() {
			if peer.Info.State.String() == "established" {
				targetPK = peer.Info.PublicKey
				found = true
				break
			}
		}
		if !found {
			// Fallback: direct TCP if no tunnel peer available
			target := net.JoinHostPort(addr.Host, fmt.Sprintf("%d", addr.Port))
			log.Printf("proxy: no tunnel peer, direct dial %s", target)
			return net.DialTimeout("tcp", target, 10*time.Second)
		}

		// Open KCP stream with TCP_PROXY proto + target address as metadata
		metadata := addr.Encode()
		stream, err := udpTransport.OpenStream(targetPK, noise.ProtocolTCPProxy, metadata)
		if err != nil {
			return nil, fmt.Errorf("open stream to %s: %w", targetPK.ShortString(), err)
		}
		log.Printf("proxy: tunnel %s:%d via %s", addr.Host, addr.Port, targetPK.ShortString())
		return stream, nil
	}
	proxySrv := proxy.NewServer(proxyAddr, proxyDial)

	go func() {
		log.Printf("proxy listening on %s (SOCKS5 + HTTP CONNECT → tunnel)", proxyAddr)
		if err := proxySrv.ListenAndServe(); err != nil {
			log.Printf("proxy error: %v", err)
		}
	}()
	defer proxySrv.Close()

	// ── 11. Accept incoming TCP_PROXY streams (exit node) ────────────────
	// For each peer, accept KCP streams with proto=69 and handle them
	// by dialing the real TCP target and relaying.
	for domain := range cfg.Peers {
		hexPK, _ := pubkeyFromDomain(domain)
		pk, _ := noise.KeyFromHex(hexPK)
		go acceptTCPProxyStreams(udpTransport, pk)
	}

	// ── 12. Start RESTful API server ─────────────────────────────────────
	apiAddr := net.JoinHostPort(tunIP.String(), "80")
	apiSrv := api.NewServer(api.ServerConfig{
		ListenAddr:  apiAddr,
		Host:        h,
		ConfigMgr:   cfgMgr,
		DNSServer:   dnsServer,
		ProxyServer: proxySrv,
	})

	go func() {
		log.Printf("api listening on %s", apiAddr)
		if err := apiSrv.ListenAndServe(); err != nil {
			log.Printf("api error: %v", err)
		}
	}()
	defer apiSrv.Close()

	// Start config hot-reload watcher (check every 30s)
	cfgMgr.Start(30 * time.Second)
	defer cfgMgr.Stop()

	// ── 13. Start Host forwarding + wait for signal ──────────────────────
	go func() {
		if err := h.Run(); err != nil {
			log.Printf("host error: %v", err)
		}
	}()

	log.Printf("zgrnetd running (pid %d)", os.Getpid())
	log.Printf("  TUN:   %s (%s/10)", tunDev.Name(), tunIP)
	log.Printf("  UDP:   %s", h.LocalAddr())
	log.Printf("  DNS:   %s", dnsAddr)
	log.Printf("  Proxy: %s", proxyAddr)
	log.Printf("  API:   %s", apiAddr)
	log.Printf("  Peers: %d", len(cfg.Peers))

	// Wait for SIGINT or SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("received %s, shutting down...", sig)

	// Force exit on second signal or after timeout.
	// Deferred Close() calls (proxy, dns, host) may block on wg.Wait()
	// if there are active connections with in-flight io.Copy.
	go func() {
		select {
		case s := <-sigCh:
			log.Printf("received %s again, force exit", s)
			os.Exit(1)
		case <-time.After(5 * time.Second):
			log.Printf("shutdown timeout (5s), force exit")
			os.Exit(1)
		}
	}()

	// Graceful shutdown order: Proxy → DNS → Host → TUN
	// (deferred calls execute in reverse order)
	return nil
}

// acceptTCPProxyStreams accepts incoming KCP streams from a peer and handles
// TCP_PROXY (proto=69) by dialing the real target and relaying traffic.
// This makes this node an "exit node" for the peer's proxy traffic.
func acceptTCPProxyStreams(udp *znet.UDP, pk noise.PublicKey) {
	for {
		stream, err := udp.AcceptStream(pk)
		if err != nil {
			return // peer gone or UDP closed
		}
		if stream.Proto() != noise.ProtocolTCPProxy {
			stream.Close()
			continue
		}
		go func() {
			if err := proxy.HandleTCPProxy(stream, stream.Metadata(), nil, nil); err != nil {
				log.Printf("tcp_proxy from %s: %v", pk.ShortString(), err)
			}
		}()
	}
}

// loadOrGenerateKey reads a Noise private key from file, or generates one
// if the file doesn't exist. The key is stored as 64 hex characters.
func loadOrGenerateKey(path string) (*noise.KeyPair, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		// File exists — parse hex private key
		hexStr := trimKey(string(data))
		if len(hexStr) != 64 {
			return nil, fmt.Errorf("invalid key file %s: expected 64 hex chars, got %d", path, len(hexStr))
		}
		keyBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("invalid hex in %s: %w", path, err)
		}
		var key noise.Key
		copy(key[:], keyBytes)
		return noise.NewKeyPair(key)
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}

	// File doesn't exist — generate new key
	log.Printf("generating new private key: %s", path)

	var key noise.Key
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}
	kp, err := noise.NewKeyPair(key)
	if err != nil {
		return nil, err
	}

	// Write hex-encoded private key
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}
	hexKey := hex.EncodeToString(kp.Private[:]) + "\n"
	if err := os.WriteFile(path, []byte(hexKey), 0600); err != nil {
		return nil, fmt.Errorf("write key %s: %w", path, err)
	}

	return kp, nil
}

// pubkeyFromDomain extracts hex pubkey from "{first32}.{last32}.zigor.net" or plain 64-char hex.
func pubkeyFromDomain(domain string) (string, error) {
	domain = strings.ToLower(domain)
	subdomain := strings.TrimSuffix(domain, ".zigor.net")
	if parts := strings.SplitN(subdomain, ".", 2); len(parts) == 2 {
		combined := parts[0] + parts[1]
		if len(combined) == 64 && isHexString(combined) {
			return combined, nil
		}
	}
	if len(subdomain) == 64 && isHexString(subdomain) {
		return subdomain, nil
	}
	return "", fmt.Errorf("invalid peer domain %q", domain)
}

func isHexString(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && len(s)%2 == 0
}

// trimKey removes whitespace and newlines from a key string.
func trimKey(s string) string {
	var result []byte
	for _, c := range []byte(s) {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			result = append(result, c)
		}
	}
	return string(result)
}

// addTUNRoutes sets up macOS routing for the TUN device.
//
// macOS utun is point-to-point: the kernel only creates a host route for the
// peer address, ignoring the /10 subnet mask. We add two routes:
//
//  1. Host route: TUN_IP → lo0 (local TCP connections to our own IP)
//  2. Subnet route: 100.64.0.0/10 → utunN (peer traffic through TUN)
//
// On Linux, the kernel handles both automatically, so this is a no-op.
func addTUNRoutes(ip net.IP, tunName string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}

	// 1. Host route for local IP → lo0
	if out, err := exec.Command("/sbin/route", "add", "-host", ip.String(), "-interface", "lo0").CombinedOutput(); err != nil {
		return fmt.Errorf("host route %s → lo0: %s: %w", ip, strings.TrimSpace(string(out)), err)
	}
	log.Printf("route: %s → lo0 (local)", ip)

	// 2. Subnet route for CGNAT range → utun
	// The /10 mask covers 100.64.0.0 – 100.127.255.255 (all peer IPs).
	if out, err := exec.Command("/sbin/route", "add", "-net", "100.64.0.0/10", "-interface", tunName).CombinedOutput(); err != nil {
		log.Printf("warning: subnet route 100.64.0.0/10 → %s: %s: %v", tunName, strings.TrimSpace(string(out)), err)
		// Non-fatal: local access still works via host route
	} else {
		log.Printf("route: 100.64.0.0/10 → %s (peers)", tunName)
	}

	return nil
}

// TUN routes are not explicitly removed on shutdown: when the TUN device
// is destroyed (process exit), the kernel automatically cleans up all
// routes bound to that interface.
