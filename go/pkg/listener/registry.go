// Package listener provides the Listener API for zgrnetd.
//
// The registry maps proto bytes to handler sockets. When zgrnetd receives
// a KCP stream, it looks up the proto in the registry and connects to the
// handler's Unix socket, forwarding the stream with a header containing
// the remote peer's pubkey, proto, and metadata.
//
// Two usage modes:
//
//   - Mode A (SDK): External program uses [Listener] to register via control
//     socket. zgrnetd creates handler sockets under /run/zgrnet/handlers/.
//
//   - Mode B (raw): External program is a plain TCP/Unix server. Registered
//     via HTTP API with a "target" field pointing to the server's address.
package listener

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// Errors returned by the registry.
var (
	ErrProtoRegistered = errors.New("listener: proto already registered")
	ErrProtoNotFound   = errors.New("listener: proto not found")
	ErrHandlerNotFound = errors.New("listener: handler not found")
)

// Mode is the handler connection mode.
type Mode string

const (
	ModeStream Mode = "stream" // KCP stream → one TCP/Unix connection per stream
	ModeDgram  Mode = "dgram"  // UDP packet → sendto on dgram socket
)

// Handler represents a registered protocol handler.
type Handler struct {
	Proto  byte   `json:"proto"`
	Name   string `json:"name"`
	Mode   Mode   `json:"mode"`
	Target string `json:"target,omitempty"` // Mode B: external server address
	Sock   string `json:"sock,omitempty"`   // Mode A: zgrnetd-created socket path
	active atomic.Int64
}

// Active returns the number of active connections being relayed.
func (h *Handler) Active() int64 {
	return h.active.Load()
}

// HandlerInfo is the JSON-friendly view of a handler.
type HandlerInfo struct {
	Proto  byte   `json:"proto"`
	Name   string `json:"name"`
	Mode   Mode   `json:"mode"`
	Active int64  `json:"active"`
}

// Registry maps proto bytes to handlers. Thread-safe.
type Registry struct {
	mu       sync.RWMutex
	byProto  map[byte]*Handler
	byName   map[string]*Handler
	sockDir  string // directory for handler sockets
	onChange func() // optional callback on register/unregister
}

// NewRegistry creates a new handler registry.
// sockDir is the directory where handler sockets are created (e.g., /run/zgrnet/handlers).
func NewRegistry(sockDir string) *Registry {
	return &Registry{
		byProto: make(map[byte]*Handler),
		byName:  make(map[string]*Handler),
		sockDir: sockDir,
	}
}

// SetOnChange sets a callback invoked after register/unregister.
func (r *Registry) SetOnChange(fn func()) {
	r.mu.Lock()
	r.onChange = fn
	r.mu.Unlock()
}

// Register adds a handler to the registry.
func (r *Registry) Register(proto byte, name string, mode Mode, target string) (*Handler, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byProto[proto]; exists {
		return nil, fmt.Errorf("%w: proto %d", ErrProtoRegistered, proto)
	}
	if _, exists := r.byName[name]; exists {
		return nil, fmt.Errorf("%w: name %q", ErrProtoRegistered, name)
	}

	h := &Handler{
		Proto:  proto,
		Name:   name,
		Mode:   mode,
		Target: target,
	}

	if target == "" {
		h.Sock = fmt.Sprintf("%s/%s.sock", r.sockDir, name)
	}

	r.byProto[proto] = h
	r.byName[name] = h

	if r.onChange != nil {
		r.onChange()
	}

	return h, nil
}

// Unregister removes a handler by name.
func (r *Registry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	h, ok := r.byName[name]
	if !ok {
		return fmt.Errorf("%w: %q", ErrHandlerNotFound, name)
	}
	delete(r.byProto, h.Proto)
	delete(r.byName, name)

	if r.onChange != nil {
		r.onChange()
	}

	return nil
}

// Lookup returns the handler for the given proto, or nil.
func (r *Registry) Lookup(proto byte) *Handler {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byProto[proto]
}

// LookupByName returns the handler with the given name, or nil.
func (r *Registry) LookupByName(name string) *Handler {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byName[name]
}

// List returns info about all registered handlers.
func (r *Registry) List() []HandlerInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]HandlerInfo, 0, len(r.byName))
	for _, h := range r.byName {
		result = append(result, HandlerInfo{
			Proto:  h.Proto,
			Name:   h.Name,
			Mode:   h.Mode,
			Active: h.active.Load(),
		})
	}
	return result
}

// StreamHeader is sent at the beginning of each relayed connection.
// It tells the handler who sent the stream and what metadata is attached.
//
// Wire format:
//
//	[pubkey: 32 bytes] [proto: 1 byte] [metadata_len: 2 bytes big-endian] [metadata: N bytes]
const StreamHeaderSize = 32 + 1 + 2 // minimum header size without metadata

// WriteStreamHeader writes a stream header to w.
func WriteStreamHeader(w io.Writer, pubkey [32]byte, proto byte, metadata []byte) error {
	var hdr [StreamHeaderSize]byte
	copy(hdr[:32], pubkey[:])
	hdr[32] = proto
	binary.BigEndian.PutUint16(hdr[33:35], uint16(len(metadata)))

	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(metadata) > 0 {
		if _, err := w.Write(metadata); err != nil {
			return err
		}
	}
	return nil
}

// StreamMeta is the parsed stream header.
type StreamMeta struct {
	RemotePubkey [32]byte
	Proto        byte
	Metadata     []byte
}

// ReadStreamHeader reads a stream header from r.
func ReadStreamHeader(r io.Reader) (*StreamMeta, error) {
	var hdr [StreamHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read stream header: %w", err)
	}

	meta := &StreamMeta{
		Proto: hdr[32],
	}
	copy(meta.RemotePubkey[:], hdr[:32])

	metaLen := binary.BigEndian.Uint16(hdr[33:35])
	if metaLen > 0 {
		meta.Metadata = make([]byte, metaLen)
		if _, err := io.ReadFull(r, meta.Metadata); err != nil {
			return nil, fmt.Errorf("read stream metadata: %w", err)
		}
	}

	return meta, nil
}

// ConnectHandler connects to a handler's socket and returns the connection.
// For Mode A (SDK): connects to the handler's Unix socket.
// For Mode B (raw): connects to the handler's target address.
func ConnectHandler(h *Handler) (net.Conn, error) {
	addr := h.Target
	if addr == "" {
		addr = h.Sock
	}

	if addr == "" {
		return nil, fmt.Errorf("handler %q has no target or socket", h.Name)
	}

	// Unix socket path (no scheme or starts with /)
	if len(addr) > 0 && addr[0] == '/' {
		return net.Dial("unix", addr)
	}

	// Explicit unix:// scheme
	if len(addr) > 7 && addr[:7] == "unix://" {
		return net.Dial("unix", addr[7:])
	}

	// TCP target
	return net.Dial("tcp", addr)
}
