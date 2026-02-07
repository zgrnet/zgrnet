package proxy

import (
	"io"
	"net"
	"strconv"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// HandleTCPProxy handles an incoming TCP_PROXY (proto=69) KCP stream.
//
// It decodes the target address from the stream's metadata (SYN frame),
// dials the real TCP target using the provided DialFunc, and relays data
// bidirectionally between the stream and the target connection.
//
// The stream should have blocking Read semantics. For kcp.Stream, wrap
// with BlockingStream before calling this function.
//
// If dial is nil, DefaultDial is used (direct TCP connection).
func HandleTCPProxy(stream io.ReadWriteCloser, metadata []byte, dial DialFunc) error {
	addr, _, err := noise.DecodeAddress(metadata)
	if err != nil {
		stream.Close()
		return err
	}

	if dial == nil {
		dial = DefaultDial
	}

	remote, err := dial(addr)
	if err != nil {
		stream.Close()
		return err
	}
	defer remote.Close()

	Relay(stream, remote)
	return nil
}

// DefaultDial connects to the target address via TCP.
// Used as the default DialFunc for HandleTCPProxy when running as an
// exit node that connects to real internet targets.
func DefaultDial(addr *noise.Address) (io.ReadWriteCloser, error) {
	target := net.JoinHostPort(addr.Host, strconv.Itoa(int(addr.Port)))
	return net.DialTimeout("tcp", target, 10*time.Second)
}
