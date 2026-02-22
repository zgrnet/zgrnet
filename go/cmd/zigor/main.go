//go:build darwin || linux

// Command zigor is the unified zgrnet management tool.
//
// It replaces both zgrnet (CLI) and zgrnetd (daemon) with a single binary.
//
// Usage:
//
//	zigor ctx list|create|delete|show|use
//	zigor key show|generate
//	zigor config show|path|edit|net|reload
//	zigor [--ctx <name>] host up [-d]
//	zigor [--ctx <name>] host down
//	zigor [--ctx <name>] host status
//	zigor [--ctx <name>] host peers
//	zigor peers list|add|get|update|remove
//	zigor lans list|join|leave
//	zigor policy show|add-rule|remove-rule
//	zigor routes list|add|remove
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/vibing/zgrnet/pkg/cli"
	"github.com/vibing/zgrnet/pkg/config"
	"github.com/vibing/zgrnet/pkg/dns"
	"github.com/vibing/zgrnet/pkg/dnsmgr"
	"github.com/vibing/zgrnet/pkg/host"
	"github.com/vibing/zgrnet/pkg/lan"
	znet "github.com/vibing/zgrnet/pkg/net"
	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/proxy"
	"github.com/vibing/zgrnet/pkg/tun"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	var apiAddr string
	var ctxOverride string
	var jsonOutput bool
	filtered := args[:0:0]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--api":
			if i+1 < len(args) {
				apiAddr = args[i+1]
				i++
			}
		case "--ctx":
			if i+1 < len(args) {
				ctxOverride = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		default:
			filtered = append(filtered, args[i])
		}
	}
	args = filtered
	if len(args) == 0 {
		printUsage()
		return nil
	}

	baseDir, err := cli.DefaultConfigDir()
	if err != nil {
		return err
	}

	switch args[0] {
	case "ctx":
		return runCtx(baseDir, args[1:])
	case "key":
		return runKey(baseDir, ctxOverride, args[1:])
	case "config":
		return runConfig(baseDir, ctxOverride, apiAddr, jsonOutput, args[1:])
	case "host":
		return runHost(baseDir, ctxOverride, apiAddr, jsonOutput, args[1:])
	case "peers":
		return runOnlineCmd(baseDir, ctxOverride, apiAddr, jsonOutput, args)
	case "lans":
		return runOnlineCmd(baseDir, ctxOverride, apiAddr, jsonOutput, args)
	case "policy":
		return runOnlineCmd(baseDir, ctxOverride, apiAddr, jsonOutput, args)
	case "routes":
		return runOnlineCmd(baseDir, ctxOverride, apiAddr, jsonOutput, args)
	case "help", "-h", "--help":
		printUsage()
		return nil
	case "version", "--version":
		fmt.Printf("zigor %s\n", version)
		return nil
	default:
		return fmt.Errorf("unknown command %q (run 'zigor help' for usage)", args[0])
	}
}

// ─── ctx ────────────────────────────────────────────────────────────────────

func runCtx(baseDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zigor ctx <list|create|delete|show|use>")
	}

	switch args[0] {
	case "list":
		names, err := cli.ListContexts(baseDir)
		if err != nil {
			return err
		}
		current, _ := cli.CurrentContextName(baseDir)
		for _, name := range names {
			marker := "  "
			if name == current {
				marker = "* "
			}
			fmt.Printf("%s%s\n", marker, name)
		}
		if len(names) == 0 {
			fmt.Println("(no contexts — run: zigor ctx create <name>)")
		}

	case "show":
		name, err := cli.CurrentContextName(baseDir)
		if err != nil {
			return err
		}
		fmt.Println(name)

	case "use":
		if len(args) < 2 {
			return fmt.Errorf("usage: zigor ctx use <name>")
		}
		if err := cli.SetCurrentContext(baseDir, args[1]); err != nil {
			return err
		}
		fmt.Printf("switched to context %q\n", args[1])

	case "create":
		if len(args) < 2 {
			return fmt.Errorf("usage: zigor ctx create <name>")
		}
		name := args[1]
		if err := cli.CreateContext(baseDir, name); err != nil {
			return err
		}
		names, _ := cli.ListContexts(baseDir)
		if len(names) == 1 {
			cli.SetCurrentContext(baseDir, name)
		}
		pubkey, _ := cli.ShowPublicKey(baseDir, name)
		fmt.Printf("created context %q\n", name)
		fmt.Printf("public key: %s\n", pubkey)

	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("usage: zigor ctx delete <name>")
		}
		if err := cli.DeleteContext(baseDir, args[1]); err != nil {
			return err
		}
		fmt.Printf("deleted context %q\n", args[1])

	default:
		return fmt.Errorf("unknown ctx subcommand %q", args[0])
	}
	return nil
}

// ─── key ────────────────────────────────────────────────────────────────────

func runKey(baseDir, ctxName string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zigor key <generate|show>")
	}

	switch args[0] {
	case "show":
		pubkey, err := cli.ShowPublicKey(baseDir, ctxName)
		if err != nil {
			return err
		}
		fmt.Println(pubkey)

	case "generate":
		pubkey, err := cli.GenerateKey(baseDir, ctxName)
		if err != nil {
			return err
		}
		fmt.Printf("new public key: %s\n", pubkey)

	default:
		return fmt.Errorf("unknown key subcommand %q", args[0])
	}
	return nil
}

// ─── config ─────────────────────────────────────────────────────────────────

func runConfig(baseDir, ctxName, apiAddr string, jsonOutput bool, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zigor config <show|path|edit|net|reload>")
	}

	switch args[0] {
	case "show":
		content, err := cli.ShowConfig(baseDir, ctxName)
		if err != nil {
			return err
		}
		fmt.Print(content)
	case "path":
		path, err := cli.ContextConfigPath(baseDir, ctxName)
		if err != nil {
			return err
		}
		fmt.Println(path)
	case "edit":
		path, err := cli.ContextConfigPath(baseDir, ctxName)
		if err != nil {
			return err
		}
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "vi"
		}
		cmd := exec.Command(editor, path)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	case "net":
		addr := cli.ResolveAPIAddr(baseDir, ctxName, apiAddr)
		c := cli.NewClient(addr)
		data, err := c.ConfigNet()
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)
	case "reload":
		addr := cli.ResolveAPIAddr(baseDir, ctxName, apiAddr)
		c := cli.NewClient(addr)
		data, err := c.ConfigReload()
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)
	default:
		return fmt.Errorf("unknown config subcommand %q", args[0])
	}
	return nil
}

// ─── host ───────────────────────────────────────────────────────────────────

func runHost(baseDir, ctxName, apiAddr string, jsonOutput bool, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zigor host <up|down|status|peers>")
	}

	switch args[0] {
	case "up":
		daemon := false
		for _, a := range args[1:] {
			if a == "-d" || a == "--daemon" {
				daemon = true
			}
		}
		return hostUp(baseDir, ctxName, daemon)

	case "down":
		return hostDown(baseDir, ctxName)

	case "status":
		return hostStatus(baseDir, ctxName, apiAddr, jsonOutput)

	case "peers":
		return hostPeers(baseDir, ctxName, apiAddr, jsonOutput)

	default:
		return fmt.Errorf("unknown host subcommand %q", args[0])
	}
}

func hostUp(baseDir, ctxName string, daemon bool) error {
	cfgPath, err := cli.ContextConfigPath(baseDir, ctxName)
	if err != nil {
		return err
	}

	if ctxName == "" {
		ctxName, _ = cli.CurrentContextName(baseDir)
	}

	if daemon {
		return hostUpDaemon(baseDir, ctxName)
	}

	return hostUpForeground(baseDir, ctxName, cfgPath)
}

func hostUpDaemon(baseDir, ctxName string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find self: %w", err)
	}

	cmd := exec.Command(self, "--ctx", ctxName, "host", "up")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}

	if err := cli.WritePidfile(baseDir, ctxName, cmd.Process.Pid); err != nil {
		cmd.Process.Kill()
		return fmt.Errorf("write pidfile: %w", err)
	}

	fmt.Printf("host started in background (pid %d)\n", cmd.Process.Pid)
	return nil
}

func hostUpForeground(baseDir, ctxName, cfgPath string) error {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Printf("loading config: %s", cfgPath)

	cfgMgr, err := config.NewManager(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg := cfgMgr.Current()

	if cfg.Net.TunMTU == 0 {
		cfg.Net.TunMTU = 1400
	}
	if cfg.Net.ListenPort == 0 {
		cfg.Net.ListenPort = 51820
	}
	if cfg.Net.PrivateKeyPath == "" {
		cfg.Net.PrivateKeyPath = "private.key"
	}

	keyPair, err := loadOrGenerateKey(cfg.Net.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	log.Printf("public key: %s", keyPair.Public)

	dataDir := filepath.Join(filepath.Dir(cfgPath), "data")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("create data dir %s: %w", dataDir, err)
	}

	myPid := os.Getpid()
	if err := cli.WritePidfile(baseDir, ctxName, myPid); err != nil {
		log.Printf("warning: write pidfile: %v", err)
	}
	defer cli.RemovePidfileIfOwner(baseDir, ctxName, myPid)

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
	if err := tunDev.SetIPv4(tunIP, net.CIDRMask(10, 32)); err != nil {
		return fmt.Errorf("set TUN IPv4: %w", err)
	}
	if err := tunDev.Up(); err != nil {
		return fmt.Errorf("bring TUN up: %w", err)
	}

	if err := addTUNRoutes(tunIP, tunDev.Name()); err != nil {
		log.Printf("warning: add TUN routes: %v", err)
	}

	log.Printf("TUN %s: %s/10, MTU %d", tunDev.Name(), tunIP, cfg.Net.TunMTU)

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
			endpoint = peerCfg.Direct[0]
		}
		if err := h.AddPeer(pk, endpoint); err != nil {
			return fmt.Errorf("add peer %s (%s): %w", peerCfg.Alias, domain, err)
		}
		log.Printf("peer added: %s (%s) endpoint=%s", peerCfg.Alias, pk.ShortString(), endpoint)
	}

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

	dnsMgr, err := dnsmgr.New(tunDev.Name())
	if err != nil {
		log.Printf("warning: dnsmgr init failed: %v", err)
	} else {
		defer dnsMgr.Close()
		if err := dnsMgr.SetDNS(tunIP.String(), []string{"zigor.net"}); err != nil {
			log.Printf("warning: dnsmgr set DNS failed: %v", err)
		} else {
			log.Printf("dns: OS configured to resolve *.zigor.net via %s", tunIP)
		}
	}

	proxyAddr := net.JoinHostPort(tunIP.String(), "1080")
	udpTransport := h.UDP()

	proxyDial := func(addr *noise.Address) (io.ReadWriteCloser, error) {
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
			target := net.JoinHostPort(addr.Host, fmt.Sprintf("%d", addr.Port))
			log.Printf("proxy: no tunnel peer, direct dial %s", target)
			return net.DialTimeout("tcp", target, 10*time.Second)
		}
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
		log.Printf("proxy listening on %s", proxyAddr)
		if err := proxySrv.ListenAndServe(); err != nil {
			log.Printf("proxy error: %v", err)
		}
	}()
	defer proxySrv.Close()

	for domain := range cfg.Peers {
		hexPK, _ := pubkeyFromDomain(domain)
		pk, _ := noise.KeyFromHex(hexPK)
		go acceptTCPProxyStreams(udpTransport, pk)
	}

	lanStore, err := lan.NewFileStore(filepath.Join(dataDir, "lan"))
	if err != nil {
		return fmt.Errorf("create lan store: %w", err)
	}

	ipAlloc := h.IPAlloc()
	lanServer := lan.NewServer(lan.Config{
		Domain:      "host.zigor.net",
		Description: "Local LAN",
		IdentityFn: func(ip net.IP) (noise.PublicKey, []string, error) {
			pk, ok := ipAlloc.LookupByIP(ip)
			if !ok {
				return noise.PublicKey{}, nil, fmt.Errorf("unknown IP: %s", ip)
			}
			return pk, nil, nil
		},
	}, lanStore)
	lanServer.RegisterAuth(lan.NewOpenAuth())

	apiAddr := net.JoinHostPort(tunIP.String(), "80")
	apiSrv := api.NewServer(api.ServerConfig{
		ListenAddr:  apiAddr,
		Host:        h,
		ConfigMgr:   cfgMgr,
		DNSServer:   dnsServer,
		ProxyServer: proxySrv,
		LanHandler:  lanServer.Handler(),
	})
	go func() {
		log.Printf("api listening on %s", apiAddr)
		if err := apiSrv.ListenAndServe(); err != nil {
			log.Printf("api error: %v", err)
		}
	}()
	defer apiSrv.Close()

	cfgMgr.Start(30 * time.Second)
	defer cfgMgr.Stop()

	go func() {
		if err := h.Run(); err != nil {
			log.Printf("host error: %v", err)
		}
	}()

	log.Printf("zigor host running (pid %d)", os.Getpid())
	log.Printf("  TUN:   %s (%s/10)", tunDev.Name(), tunIP)
	log.Printf("  UDP:   %s", h.LocalAddr())
	log.Printf("  DNS:   %s", dnsAddr)
	log.Printf("  Proxy: %s", proxyAddr)
	log.Printf("  API:   %s", apiAddr)
	log.Printf("  Peers: %d", len(cfg.Peers))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("received %s, shutting down...", sig)

	go func() {
		select {
		case s := <-sigCh:
			log.Printf("received %s again, force exit", s)
			cli.RemovePidfileIfOwner(baseDir, ctxName, myPid)
			os.Exit(1)
		case <-time.After(5 * time.Second):
			log.Printf("shutdown timeout (5s), force exit")
			cli.RemovePidfileIfOwner(baseDir, ctxName, myPid)
			os.Exit(1)
		}
	}()

	return nil
}

func hostDown(baseDir, ctxName string) error {
	if err := cli.Down(baseDir, ctxName); err != nil {
		return err
	}
	fmt.Println("host stopped")
	return nil
}

func hostStatus(baseDir, ctxName, apiAddr string, jsonOutput bool) error {
	if ctxName == "" {
		var err error
		ctxName, err = cli.CurrentContextName(baseDir)
		if err != nil {
			return err
		}
	}

	pid, err := cli.ReadPidfile(baseDir, ctxName)
	if err != nil {
		fmt.Printf("host is not running (context %q)\n", ctxName)
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Printf("host is not running (stale pidfile, pid %d)\n", pid)
		cli.RemovePidfile(baseDir, ctxName)
		return nil
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			fmt.Printf("host is not running (stale pidfile, pid %d)\n", pid)
			cli.RemovePidfile(baseDir, ctxName)
			return nil
		}
	}

	addr := cli.ResolveAPIAddr(baseDir, ctxName, apiAddr)
	c := cli.NewClient(addr)
	data, err := c.Status()
	if err != nil {
		fmt.Printf("host is running (pid %d) but API unreachable: %v\n", pid, err)
		return nil
	}
	printJSON(data, jsonOutput)
	return nil
}

func hostPeers(baseDir, ctxName, apiAddr string, jsonOutput bool) error {
	addr := cli.ResolveAPIAddr(baseDir, ctxName, apiAddr)
	c := cli.NewClient(addr)
	data, err := c.PeersList()
	if err != nil {
		return err
	}
	printJSON(data, jsonOutput)
	return nil
}

// ─── Online commands (peers/lans/policy/routes) ─────────────────────────────

func runOnlineCmd(baseDir, ctxName, apiAddr string, jsonOutput bool, args []string) error {
	addr := cli.ResolveAPIAddr(baseDir, ctxName, apiAddr)
	c := cli.NewClient(addr)

	switch args[0] {
	case "peers":
		return runPeers(c, jsonOutput, args[1:])
	case "lans":
		return runLans(c, jsonOutput, args[1:])
	case "policy":
		return runPolicy(c, jsonOutput, args[1:])
	case "routes":
		return runRoutes(c, jsonOutput, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runPeers(c *cli.Client, jsonOutput bool, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zigor peers <list|add|get|update|remove>")
	}
	switch args[0] {
	case "list":
		data, err := c.PeersList()
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)
	case "get":
		if len(args) < 2 {
			return fmt.Errorf("usage: zigor peers get <pubkey>")
		}
		data, err := c.PeersGet(args[1])
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)
	case "add":
		pubkey, alias, endpoint := "", "", ""
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--alias":
				if i+1 < len(args) {
					alias = args[i+1]
					i++
				}
			case "--endpoint":
				if i+1 < len(args) {
					endpoint = args[i+1]
					i++
				}
			default:
				if pubkey == "" {
					pubkey = args[i]
				}
			}
		}
		if pubkey == "" {
			return fmt.Errorf("usage: zigor peers add <pubkey> [--alias <a>] [--endpoint <e>]")
		}
		data, err := c.PeersAdd(pubkey, alias, endpoint)
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)
	case "update":
		if len(args) < 2 {
			return fmt.Errorf("usage: zigor peers update <pubkey> [--alias <a>] [--endpoint <e>]")
		}
		pubkey := args[1]
		fields := make(map[string]interface{})
		for i := 2; i < len(args); i++ {
			switch args[i] {
			case "--alias":
				if i+1 < len(args) {
					fields["alias"] = args[i+1]
					i++
				}
			case "--endpoint":
				if i+1 < len(args) {
					fields["endpoint"] = args[i+1]
					i++
				}
			}
		}
		data, err := c.PeersUpdate(pubkey, fields)
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)
	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("usage: zigor peers remove <pubkey>")
		}
		if err := c.PeersRemove(args[1]); err != nil {
			return err
		}
		fmt.Println("peer removed")
	default:
		return fmt.Errorf("unknown peers subcommand %q", args[0])
	}
	return nil
}

func runLans(c *cli.Client, jsonOutput bool, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zigor lans <list|join|leave>")
	}
	switch args[0] {
	case "list":
		data, err := c.LansList()
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)
	case "join":
		domain, pubkey, endpoint := "", "", ""
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--domain":
				if i+1 < len(args) {
					domain = args[i+1]
					i++
				}
			case "--pubkey":
				if i+1 < len(args) {
					pubkey = args[i+1]
					i++
				}
			case "--endpoint":
				if i+1 < len(args) {
					endpoint = args[i+1]
					i++
				}
			}
		}
		if domain == "" || pubkey == "" || endpoint == "" {
			return fmt.Errorf("usage: zigor lans join --domain <d> --pubkey <pk> --endpoint <e>")
		}
		data, err := c.LansJoin(domain, pubkey, endpoint)
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)
	case "leave":
		if len(args) < 2 {
			return fmt.Errorf("usage: zigor lans leave <domain>")
		}
		if err := c.LansLeave(args[1]); err != nil {
			return err
		}
		fmt.Println("lan left")
	default:
		return fmt.Errorf("unknown lans subcommand %q", args[0])
	}
	return nil
}

func runPolicy(c *cli.Client, jsonOutput bool, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zigor policy <show|add-rule|remove-rule>")
	}
	switch args[0] {
	case "show":
		data, err := c.PolicyShow()
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)
	case "add-rule":
		if len(args) < 2 {
			return fmt.Errorf("usage: zigor policy add-rule '<json>'")
		}
		ruleJSON := []byte(strings.Join(args[1:], " "))
		data, err := c.PolicyAddRule(ruleJSON)
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)
	case "remove-rule":
		if len(args) < 2 {
			return fmt.Errorf("usage: zigor policy remove-rule <name>")
		}
		if err := c.PolicyRemoveRule(args[1]); err != nil {
			return err
		}
		fmt.Println("rule removed")
	default:
		return fmt.Errorf("unknown policy subcommand %q", args[0])
	}
	return nil
}

func runRoutes(c *cli.Client, jsonOutput bool, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zigor routes <list|add|remove>")
	}
	switch args[0] {
	case "list":
		data, err := c.RoutesList()
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)
	case "add":
		domain, peer := "", ""
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--domain":
				if i+1 < len(args) {
					domain = args[i+1]
					i++
				}
			case "--peer":
				if i+1 < len(args) {
					peer = args[i+1]
					i++
				}
			}
		}
		if domain == "" || peer == "" {
			return fmt.Errorf("usage: zigor routes add --domain <pattern> --peer <alias>")
		}
		data, err := c.RoutesAdd(domain, peer)
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)
	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("usage: zigor routes remove <id>")
		}
		if err := c.RoutesRemove(args[1]); err != nil {
			return err
		}
		fmt.Println("route removed")
	default:
		return fmt.Errorf("unknown routes subcommand %q", args[0])
	}
	return nil
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func printJSON(data []byte, raw bool) {
	if raw {
		fmt.Println(string(data))
		return
	}
	var v interface{}
	if json.Unmarshal(data, &v) == nil {
		pretty, err := json.MarshalIndent(v, "", "  ")
		if err == nil {
			fmt.Println(string(pretty))
			return
		}
	}
	fmt.Println(string(data))
}

func printUsage() {
	fmt.Print(`zigor — zgrnet management tool

Usage: zigor [--ctx <name>] <command> [options]

Context management (offline):
  ctx list                     List all contexts
  ctx create <name>            Create a new context (generates keypair)
  ctx delete <name>            Delete a context
  ctx show                     Show current context name
  ctx use <name>               Switch to a context

Host control:
  host up [-d]                 Start host (-d for background)
  host down                    Stop running host
  host status                  Show host status
  host peers                   List connected peers

Key management:
  key show                     Show public key of current context
  key generate                 Generate a new keypair (overwrites existing)

Config management:
  config show                  Print config.yaml contents
  config path                  Print config.yaml file path
  config edit                  Open config in $EDITOR
  config net                   Show network config (via API)
  config reload                Reload config from disk (via API)

Peer management (via API):
  peers list                   List all peers
  peers get <pubkey>           Show peer details
  peers add <pubkey> [--alias <a>] [--endpoint <e>]
  peers update <pubkey> [--alias <a>] [--endpoint <e>]
  peers remove <pubkey>        Remove a peer

Lan management (via API):
  lans list                    List all lans
  lans join --domain <d> --pubkey <pk> --endpoint <e>
  lans leave <domain>          Leave a lan

Policy management (via API):
  policy show                  Show inbound policy
  policy add-rule '<json>'     Add an inbound rule
  policy remove-rule <name>    Remove an inbound rule

Route management (via API):
  routes list                  List route rules
  routes add --domain <pattern> --peer <alias>
  routes remove <id>           Remove a route by index

Global flags:
  --ctx <name>                 Override context
  --api <addr>                 Override API address (default: from config)
  --json                       Output raw JSON
  --version                    Show version
`)
}

// ─── Daemon internals (from zgrnetd) ────────────────────────────────────────

func acceptTCPProxyStreams(udp *znet.UDP, pk noise.PublicKey) {
	for {
		stream, err := udp.AcceptStream(pk)
		if err != nil {
			return
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

func loadOrGenerateKey(path string) (*noise.KeyPair, error) {
	data, err := os.ReadFile(path)
	if err == nil {
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

	log.Printf("generating new private key: %s", path)
	var key noise.Key
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}
	kp, err := noise.NewKeyPair(key)
	if err != nil {
		return nil, err
	}

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

func trimKey(s string) string {
	var result []byte
	for _, c := range []byte(s) {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			result = append(result, c)
		}
	}
	return string(result)
}

func addTUNRoutes(ip net.IP, tunName string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	if out, err := exec.Command("/sbin/route", "add", "-net", "100.64.0.0/10", "-interface", tunName).CombinedOutput(); err != nil {
		return fmt.Errorf("subnet route 100.64.0.0/10 → %s: %s: %w", tunName, strings.TrimSpace(string(out)), err)
	}
	log.Printf("route: 100.64.0.0/10 → %s", tunName)
	return nil
}
