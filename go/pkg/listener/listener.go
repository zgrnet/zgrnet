package listener

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
)

// Errors returned by the Listener SDK.
var (
	ErrClosed = errors.New("listener: closed")
)

// Conn wraps a net.Conn with stream metadata parsed from the header.
type Conn struct {
	net.Conn
	Meta StreamMeta
}

// Config is the configuration for registering a handler.
type Config struct {
	Proto byte   `json:"proto"`
	Name  string `json:"name"`
	Mode  Mode   `json:"mode"`
}

// registerRequest is the JSON payload sent to the control socket.
type registerRequest struct {
	Proto byte   `json:"proto"`
	Name  string `json:"name"`
	Mode  Mode   `json:"mode"`
}

// registerResponse is the JSON payload received from the control socket.
type registerResponse struct {
	Proto byte   `json:"proto"`
	Name  string `json:"name"`
	Sock  string `json:"sock"`
	Error string `json:"error,omitempty"`
}

// Listener connects to zgrnetd's control socket to register proto handlers.
// External programs use this to plug into zgrnetd's stream dispatch.
type Listener struct {
	controlAddr string
	handlers    []*StreamHandler
	mu          sync.Mutex
	closed      atomic.Bool
}

// New creates a Listener that connects to zgrnetd via the control socket.
// controlAddr is the path to the Unix socket (e.g., "/run/zgrnet/control.sock").
func New(controlAddr string) *Listener {
	return &Listener{
		controlAddr: controlAddr,
	}
}

// Register registers a handler for the given proto with zgrnetd.
// zgrnetd creates a Unix socket and returns its path. This Listener
// then listens on that socket for incoming connections.
func (l *Listener) Register(cfg Config) (*StreamHandler, error) {
	if l.closed.Load() {
		return nil, ErrClosed
	}

	// Connect to control socket and send registration.
	conn, err := net.Dial("unix", l.controlAddr)
	if err != nil {
		return nil, fmt.Errorf("connect control socket %s: %w", l.controlAddr, err)
	}

	req := registerRequest{
		Proto: cfg.Proto,
		Name:  cfg.Name,
		Mode:  cfg.Mode,
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send registration: %w", err)
	}

	var resp registerResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read registration response: %w", err)
	}
	conn.Close()

	if resp.Error != "" {
		return nil, fmt.Errorf("registration rejected: %s", resp.Error)
	}

	// Listen on the handler socket that zgrnetd created.
	os.Remove(resp.Sock) // clean up stale socket
	ln, err := net.Listen("unix", resp.Sock)
	if err != nil {
		return nil, fmt.Errorf("listen on handler socket %s: %w", resp.Sock, err)
	}

	h := &StreamHandler{
		proto:    cfg.Proto,
		name:     cfg.Name,
		mode:     cfg.Mode,
		sockPath: resp.Sock,
		listener: ln,
		done:     make(chan struct{}),
	}

	l.mu.Lock()
	l.handlers = append(l.handlers, h)
	l.mu.Unlock()

	return h, nil
}

// Close closes all registered handlers and the listener.
func (l *Listener) Close() error {
	if l.closed.Swap(true) {
		return nil
	}

	l.mu.Lock()
	handlers := l.handlers
	l.handlers = nil
	l.mu.Unlock()

	for _, h := range handlers {
		h.Close()
	}
	return nil
}

// StreamHandler accepts incoming streams for a registered proto.
// Each accepted connection has a StreamMeta header that identifies the
// remote peer and carries the stream's metadata.
type StreamHandler struct {
	proto    byte
	name     string
	mode     Mode
	sockPath string
	listener net.Listener
	closed   atomic.Bool
	done     chan struct{}
}

// Accept waits for the next incoming connection from zgrnetd.
// The connection's first bytes are the StreamHeader, which is parsed
// and returned as StreamMeta. The Conn is ready for application data.
func (h *StreamHandler) Accept() (*Conn, error) {
	raw, err := h.listener.Accept()
	if err != nil {
		if h.closed.Load() {
			return nil, ErrClosed
		}
		return nil, err
	}

	meta, err := ReadStreamHeader(raw)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("read header: %w", err)
	}

	return &Conn{Conn: raw, Meta: *meta}, nil
}

// Proto returns the protocol byte this handler accepts.
func (h *StreamHandler) Proto() byte {
	return h.proto
}

// Name returns the handler's registered name.
func (h *StreamHandler) Name() string {
	return h.name
}

// Close stops accepting connections and removes the socket.
func (h *StreamHandler) Close() error {
	if h.closed.Swap(true) {
		return nil
	}
	close(h.done)
	err := h.listener.Close()
	os.Remove(h.sockPath)
	return err
}

// DgramHandler receives raw datagrams for a registered proto.
// Each datagram has a header prefix with the sender's pubkey.
type DgramHandler struct {
	proto byte
	name  string
	conn  *net.UnixConn
}

// ReadFrom reads the next datagram. Each datagram is prefixed with
// the stream header (pubkey + proto + metadata_len + metadata),
// followed by the payload.
func (h *DgramHandler) ReadFrom(buf []byte) (int, *StreamMeta, error) {
	n, err := h.conn.Read(buf)
	if err != nil {
		return 0, nil, err
	}

	if n < StreamHeaderSize {
		return 0, nil, io.ErrShortBuffer
	}

	meta := &StreamMeta{
		Proto: buf[32],
	}
	copy(meta.RemotePubkey[:], buf[:32])

	metaLen := int(buf[33])<<8 | int(buf[34])
	headerTotal := StreamHeaderSize + metaLen
	if n < headerTotal {
		return 0, nil, io.ErrShortBuffer
	}
	if metaLen > 0 {
		meta.Metadata = make([]byte, metaLen)
		copy(meta.Metadata, buf[StreamHeaderSize:headerTotal])
	}

	payload := n - headerTotal
	if payload > 0 {
		copy(buf, buf[headerTotal:n])
	}
	return payload, meta, nil
}

// Close closes the dgram handler.
func (h *DgramHandler) Close() error {
	return h.conn.Close()
}
