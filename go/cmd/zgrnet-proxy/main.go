//go:build darwin || linux

// Command zgrnet-proxy is an external proxy handler for zgrnetd.
//
// It registers as a handler for TCP_PROXY (proto=69) and UDP_PROXY (proto=65)
// via the Listener SDK, then accepts incoming streams from zgrnetd and
// proxies them to real TCP/UDP targets.
//
// Usage:
//
//	zgrnet-proxy -control /path/to/control.sock
//	zgrnet-proxy -control /path/to/control.sock -listen 127.0.0.1:1080
//
// The -listen flag optionally starts a local SOCKS5/HTTP CONNECT server
// that tunnels through the zgrnet mesh (requires a running zgrnetd).
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/vibing/zgrnet/pkg/listener"
	"github.com/vibing/zgrnet/pkg/noise"
)

var (
	controlSock = flag.String("control", "", "Path to zgrnetd control socket")
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if *controlSock == "" {
		// Try default locations
		candidates := []string{
			"/run/zgrnet/control.sock",
			os.ExpandEnv("$HOME/.config/zgrnet/data/control.sock"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				*controlSock = c
				break
			}
		}
		if *controlSock == "" {
			fmt.Fprintf(os.Stderr, "error: control socket not found\n")
			fmt.Fprintf(os.Stderr, "Usage: zgrnet-proxy -control <path>\n")
			os.Exit(1)
		}
	}

	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	ln := listener.New(*controlSock)
	defer ln.Close()

	// Register TCP_PROXY handler (proto=69).
	tcpHandler, err := ln.Register(listener.Config{
		Proto: noise.ProtocolTCPProxy,
		Name:  "tcp-proxy",
		Mode:  listener.ModeStream,
	})
	if err != nil {
		return fmt.Errorf("register tcp-proxy: %w", err)
	}
	log.Printf("registered tcp-proxy (proto=%d)", noise.ProtocolTCPProxy)

	// Accept TCP_PROXY streams.
	go func() {
		for {
			conn, err := tcpHandler.Accept()
			if err != nil {
				log.Printf("tcp-proxy accept: %v", err)
				return
			}
			go handleTCPProxy(conn)
		}
	}()

	log.Printf("zgrnet-proxy running (control=%s)", *controlSock)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("received %s, shutting down...", sig)

	return nil
}

// handleTCPProxy handles a single TCP_PROXY stream relayed from zgrnetd.
// The connection already has the StreamHeader parsed by Accept().
func handleTCPProxy(conn *listener.Conn) {
	defer conn.Close()

	addr, _, err := noise.DecodeAddress(conn.Meta.Metadata)
	if err != nil {
		log.Printf("tcp-proxy: decode address: %v", err)
		return
	}

	target := net.JoinHostPort(addr.Host, strconv.Itoa(int(addr.Port)))
	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("tcp-proxy: dial %s: %v", target, err)
		return
	}
	defer remote.Close()

	log.Printf("tcp-proxy: %x → %s", conn.Meta.RemotePubkey[:4], target)

	relay(conn, remote)
}

func relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	<-done
}
