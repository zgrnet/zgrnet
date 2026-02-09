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
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/vibing/zgrnet/pkg/config"
	"github.com/vibing/zgrnet/pkg/dns"
	"github.com/vibing/zgrnet/pkg/dnsmgr"
	"github.com/vibing/zgrnet/pkg/host"
	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/proxy"
	"github.com/vibing/zgrnet/pkg/tun"
)

var (
	configPath = flag.String("c", "", "Path to config file (required)")
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if *configPath == "" {
		fmt.Fprintf(os.Stderr, "Usage: zgrnetd -c <config.yaml>\n")
		os.Exit(1)
	}

	if err := run(*configPath); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run(cfgPath string) error {
	// ── 1. Load and validate config ──────────────────────────────────────
	log.Printf("loading config: %s", cfgPath)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	// ── 2. Load or generate private key ──────────────────────────────────
	keyPair, err := loadOrGenerateKey(cfg.Net.PrivateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	log.Printf("public key: %s", keyPair.Public)

	// ── 3. Create data directory ─────────────────────────────────────────
	if err := os.MkdirAll(cfg.Net.DataDir, 0700); err != nil {
		return fmt.Errorf("create data dir %s: %w", cfg.Net.DataDir, err)
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
		hexPubkey, err := config.PubkeyFromDomain(domain)
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

	// ── 9. Start SOCKS5 Proxy ────────────────────────────────────────────
	proxyAddr := net.JoinHostPort(tunIP.String(), "1080")
	proxyDial := func(addr *noise.Address) (io.ReadWriteCloser, error) {
		target := net.JoinHostPort(addr.Host, fmt.Sprintf("%d", addr.Port))
		return net.DialTimeout("tcp", target, proxyDialTimeout)
	}
	proxySrv := proxy.NewServer(proxyAddr, proxyDial)

	go func() {
		log.Printf("proxy listening on %s (SOCKS5 + HTTP CONNECT)", proxyAddr)
		if err := proxySrv.ListenAndServe(); err != nil {
			log.Printf("proxy error: %v", err)
		}
	}()
	defer proxySrv.Close()

	// ── 10. Start Host forwarding + wait for signal ──────────────────────
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
	log.Printf("  Peers: %d", len(cfg.Peers))

	// Wait for SIGINT or SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("received %s, shutting down...", sig)

	// Graceful shutdown order: Proxy → DNS → Host → TUN
	// (deferred calls execute in reverse order)
	return nil
}

// proxyDialTimeout is the TCP dial timeout for the SOCKS5 proxy.
const proxyDialTimeout = 10 * 1e9 // 10 seconds (time.Duration)

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
