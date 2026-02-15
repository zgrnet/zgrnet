//go:build darwin || linux

// Command zgrnet is the zgrnet management tool.
//
// It provides offline context/config management and online API commands
// for interacting with a running zgrnetd daemon.
//
// Usage:
//
//	zgrnet context list|use|create|current|delete
//	zgrnet key generate|show
//	zgrnet config show|path|edit|net|reload
//	zgrnet up [--context <name>] [-d]
//	zgrnet down
//	zgrnet status
//	zgrnet peers list|add|get|update|remove
//	zgrnet lans list|join|leave
//	zgrnet policy show|add-rule|remove-rule
//	zgrnet routes list|add|remove
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/vibing/zgrnet/pkg/cli"
)

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

	// Parse global flags
	var apiAddr string
	var ctxOverride string
	var jsonOutput bool
	filtered := args[:0]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--api":
			if i+1 < len(args) {
				apiAddr = args[i+1]
				i++
			}
		case "--context":
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
	case "context":
		return runContext(baseDir, args[1:])
	case "key":
		return runKey(baseDir, ctxOverride, args[1:])
	case "config":
		return runConfig(baseDir, ctxOverride, apiAddr, jsonOutput, args[1:])
	case "up":
		return runUp(baseDir, ctxOverride, args[1:])
	case "down":
		return runDown(baseDir, ctxOverride)
	case "status":
		return runOnlineCmd(baseDir, ctxOverride, apiAddr, jsonOutput, args)
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
	default:
		return fmt.Errorf("unknown command %q (run 'zgrnet help' for usage)", args[0])
	}
}

// ─── Context ────────────────────────────────────────────────────────────────

func runContext(baseDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zgrnet context <list|use|create|current|delete>")
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
			fmt.Println("(no contexts — run: zgrnet context create <name>)")
		}

	case "current":
		name, err := cli.CurrentContextName(baseDir)
		if err != nil {
			return err
		}
		fmt.Println(name)

	case "use":
		if len(args) < 2 {
			return fmt.Errorf("usage: zgrnet context use <name>")
		}
		if err := cli.SetCurrentContext(baseDir, args[1]); err != nil {
			return err
		}
		fmt.Printf("switched to context %q\n", args[1])

	case "create":
		if len(args) < 2 {
			return fmt.Errorf("usage: zgrnet context create <name>")
		}
		name := args[1]
		if err := cli.CreateContext(baseDir, name); err != nil {
			return err
		}
		// Auto-set as current if it's the first context
		names, _ := cli.ListContexts(baseDir)
		if len(names) == 1 {
			cli.SetCurrentContext(baseDir, name)
		}
		pubkey, _ := cli.ShowPublicKey(baseDir, name)
		fmt.Printf("created context %q\n", name)
		fmt.Printf("public key: %s\n", pubkey)

	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("usage: zgrnet context delete <name>")
		}
		if err := cli.DeleteContext(baseDir, args[1]); err != nil {
			return err
		}
		fmt.Printf("deleted context %q\n", args[1])

	default:
		return fmt.Errorf("unknown context subcommand %q", args[0])
	}
	return nil
}

// ─── Key ────────────────────────────────────────────────────────────────────

func runKey(baseDir, ctxName string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zgrnet key <generate|show>")
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

// ─── Config ─────────────────────────────────────────────────────────────────

func runConfig(baseDir, ctxName, apiAddr string, jsonOutput bool, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zgrnet config <show|path|edit|net|reload>")
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
		return cli.EditConfig(baseDir, ctxName)

	case "net":
		// Online: call API
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

// ─── Up / Down ──────────────────────────────────────────────────────────────

func runUp(baseDir, ctxName string, args []string) error {
	daemon := false
	for _, a := range args {
		switch a {
		case "-d", "--daemon":
			daemon = true
		}
	}
	if err := cli.Up(baseDir, ctxName, daemon); err != nil {
		return err
	}
	if daemon {
		fmt.Println("zgrnetd started in background")
	}
	return nil
}

func runDown(baseDir, ctxName string) error {
	if err := cli.Down(baseDir, ctxName); err != nil {
		return err
	}
	fmt.Println("zgrnetd stopped")
	return nil
}

// ─── Online commands ────────────────────────────────────────────────────────

func runOnlineCmd(baseDir, ctxName, apiAddr string, jsonOutput bool, args []string) error {
	addr := cli.ResolveAPIAddr(baseDir, ctxName, apiAddr)
	c := cli.NewClient(addr)

	switch args[0] {
	case "status":
		data, err := c.Status()
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)

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
	return nil
}

func runPeers(c *cli.Client, jsonOutput bool, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zgrnet peers <list|add|get|update|remove>")
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
			return fmt.Errorf("usage: zgrnet peers get <pubkey>")
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
			return fmt.Errorf("usage: zgrnet peers add <pubkey> [--alias <a>] [--endpoint <e>]")
		}
		data, err := c.PeersAdd(pubkey, alias, endpoint)
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)

	case "update":
		if len(args) < 2 {
			return fmt.Errorf("usage: zgrnet peers update <pubkey> [--alias <a>] [--endpoint <e>]")
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
			return fmt.Errorf("usage: zgrnet peers remove <pubkey>")
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
		return fmt.Errorf("usage: zgrnet lans <list|join|leave>")
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
			return fmt.Errorf("usage: zgrnet lans join --domain <d> --pubkey <pk> --endpoint <e>")
		}
		data, err := c.LansJoin(domain, pubkey, endpoint)
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)

	case "leave":
		if len(args) < 2 {
			return fmt.Errorf("usage: zgrnet lans leave <domain>")
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
		return fmt.Errorf("usage: zgrnet policy <show|add-rule|remove-rule>")
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
			return fmt.Errorf("usage: zgrnet policy add-rule '<json>'")
		}
		ruleJSON := []byte(strings.Join(args[1:], " "))
		data, err := c.PolicyAddRule(ruleJSON)
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)

	case "remove-rule":
		if len(args) < 2 {
			return fmt.Errorf("usage: zgrnet policy remove-rule <name>")
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
		return fmt.Errorf("usage: zgrnet routes <list|add|remove>")
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
			return fmt.Errorf("usage: zgrnet routes add --domain <pattern> --peer <alias>")
		}
		data, err := c.RoutesAdd(domain, peer)
		if err != nil {
			return err
		}
		printJSON(data, jsonOutput)

	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("usage: zgrnet routes remove <id>")
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
	// Pretty-print JSON
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
	fmt.Print(`zgrnet — zgrnet management tool

Usage: zgrnet <command> [options]

Context management (offline):
  context list                 List all contexts
  context use <name>           Switch to a context
  context create <name>        Create a new context (generates keypair)
  context current              Show current context name
  context delete <name>        Delete a context

Key management:
  key show                     Show public key of current context
  key generate                 Generate a new keypair (overwrites existing)

Config management:
  config show                  Print config.yaml contents
  config path                  Print config.yaml file path
  config edit                  Open config in $EDITOR
  config net                   Show network config (via API)
  config reload                Reload config from disk (via API)

Daemon control:
  up [--context <name>] [-d]   Start zgrnetd (-d for background)
  down                         Stop running zgrnetd

Status (via API):
  status                       Show node info (pubkey, TUN IP, uptime)

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
  --api <addr>                 Override API address (default: from config)
  --context <name>             Override context
  --json                       Output raw JSON
`)
}
