// Command proxy starts a SOCKS5/HTTP CONNECT proxy server.
//
// Supports both SOCKS5 and HTTP CONNECT on the same port (auto-detected).
// Dials targets directly via TCP — no zgrnet tunnel.
//
// Usage:
//
//	go run . -listen 127.0.0.1:5432
//	curl -x socks5://127.0.0.1:5432 https://example.com
//	curl -x http://127.0.0.1:5432 https://example.com
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/proxy"
)

var listenAddr = flag.String("listen", "127.0.0.1:5432", "Listen address")

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	dial := func(addr *noise.Address) (io.ReadWriteCloser, error) {
		target := net.JoinHostPort(addr.Host, fmt.Sprintf("%d", addr.Port))
		log.Printf("CONNECT → %s", target)
		return net.Dial("tcp", target)
	}

	srv := proxy.NewServer(*listenAddr, dial)
	log.Printf("proxy listening on %s (SOCKS5 + HTTP CONNECT)", *listenAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
