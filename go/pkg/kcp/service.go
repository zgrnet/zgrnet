package kcp

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

var (
	ErrServiceMuxClosed  = errors.New("kcp: service mux closed")
	ErrServiceNotFound   = errors.New("kcp: service not found")
	ErrServiceRejected   = errors.New("kcp: service rejected")
	ErrAcceptQueueClosed = errors.New("kcp: accept queue closed")
)

// ServiceMuxConfig holds configuration for ServiceMux.
type ServiceMuxConfig struct {
	// IsClient determines yamux role. Client initiates streams with odd IDs.
	IsClient bool

	// Output is called to send KCP packets over the wire.
	// The service ID is included so the caller can prepend it to the packet.
	Output func(service uint64, data []byte) error

	// OnNewService is called when a new service is seen for the first time
	// (from incoming data). Return true to accept, false to reject.
	// If nil, all services are accepted.
	OnNewService func(service uint64) bool

	// YamuxConfig is the yamux session configuration. nil uses defaults.
	YamuxConfig *yamux.Config
}

// serviceEntry holds one service's KCPConn + yamux session.
type serviceEntry struct {
	conn    *KCPConn
	session *yamux.Session
	pipe    *kcpPipe
}

// ServiceMux manages per-service KCP instances and yamux sessions for a peer.
//
// Each service gets its own KCPConn (reliable byte stream with independent
// goroutine) and yamux.Session (stream multiplexing over the KCPConn).
// Different services are completely isolated at the KCP level.
type ServiceMux struct {
	config ServiceMuxConfig

	services   map[uint64]*serviceEntry
	servicesMu sync.RWMutex

	acceptCh chan acceptResult
	closeCh  chan struct{}

	closed    bool
	closeMu   sync.RWMutex
	closeOnce sync.Once
}

type acceptResult struct {
	conn    net.Conn
	service uint64
}

// NewServiceMux creates a new ServiceMux.
func NewServiceMux(cfg ServiceMuxConfig) *ServiceMux {
	return &ServiceMux{
		config:   cfg,
		services: make(map[uint64]*serviceEntry),
		acceptCh: make(chan acceptResult, 4096),
		closeCh:  make(chan struct{}),
	}
}

// Input routes an incoming KCP packet to the correct service's KCPConn.
// If the service doesn't exist and OnNewService allows it, creates it.
func (m *ServiceMux) Input(service uint64, data []byte) error {
	m.closeMu.RLock()
	if m.closed {
		m.closeMu.RUnlock()
		return ErrServiceMuxClosed
	}
	m.closeMu.RUnlock()

	entry, err := m.getOrCreateService(service)
	if err != nil {
		return err
	}
	return entry.conn.Input(data)
}

// OpenStream opens a new yamux stream on the given service.
// If the service doesn't exist yet, creates KCPConn + yamux session.
func (m *ServiceMux) OpenStream(service uint64) (net.Conn, error) {
	m.closeMu.RLock()
	if m.closed {
		m.closeMu.RUnlock()
		return nil, ErrServiceMuxClosed
	}
	m.closeMu.RUnlock()

	entry, err := m.getOrCreateService(service)
	if err != nil {
		return nil, err
	}
	return entry.session.Open()
}

// AcceptStream accepts the next incoming yamux stream from any service.
// Returns the stream and its service ID.
func (m *ServiceMux) AcceptStream() (net.Conn, uint64, error) {
	m.closeMu.RLock()
	if m.closed {
		m.closeMu.RUnlock()
		return nil, 0, ErrServiceMuxClosed
	}
	m.closeMu.RUnlock()

	result, ok := <-m.acceptCh
	if !ok {
		return nil, 0, ErrAcceptQueueClosed
	}
	return result.conn, result.service, nil
}

// AcceptStreamOn accepts the next incoming yamux stream on a specific service.
func (m *ServiceMux) AcceptStreamOn(service uint64) (net.Conn, error) {
	m.closeMu.RLock()
	if m.closed {
		m.closeMu.RUnlock()
		return nil, ErrServiceMuxClosed
	}
	m.closeMu.RUnlock()

	entry, err := m.getOrCreateService(service)
	if err != nil {
		return nil, err
	}
	return entry.session.Accept()
}

// Close closes all services, KCPConns, and yamux sessions.
func (m *ServiceMux) Close() error {
	m.closeOnce.Do(func() {
		m.closeMu.Lock()
		m.closed = true
		m.closeMu.Unlock()

		close(m.closeCh)
		close(m.acceptCh)

		m.servicesMu.Lock()
		entries := make([]*serviceEntry, 0, len(m.services))
		for _, e := range m.services {
			entries = append(entries, e)
		}
		m.services = make(map[uint64]*serviceEntry)
		m.servicesMu.Unlock()

		for _, e := range entries {
			e.session.Close()
			e.pipe.Close()
			e.conn.Close()
		}
	})
	return nil
}

// NumServices returns the number of active services.
func (m *ServiceMux) NumServices() int {
	m.servicesMu.RLock()
	defer m.servicesMu.RUnlock()
	return len(m.services)
}

// NumStreams returns the total number of active yamux streams across all services.
func (m *ServiceMux) NumStreams() int {
	m.servicesMu.RLock()
	defer m.servicesMu.RUnlock()
	total := 0
	for _, e := range m.services {
		total += e.session.NumStreams()
	}
	return total
}

// getOrCreateService returns an existing service entry or creates a new one.
func (m *ServiceMux) getOrCreateService(service uint64) (*serviceEntry, error) {
	m.servicesMu.RLock()
	entry, ok := m.services[service]
	m.servicesMu.RUnlock()
	if ok {
		return entry, nil
	}

	m.servicesMu.Lock()
	defer m.servicesMu.Unlock()

	// Double-check after acquiring write lock.
	if entry, ok := m.services[service]; ok {
		return entry, nil
	}

	if m.closed {
		return nil, ErrServiceMuxClosed
	}

	if m.config.OnNewService != nil && !m.config.OnNewService(service) {
		return nil, ErrServiceRejected
	}

	entry, err := m.createServiceLocked(service)
	if err != nil {
		return nil, err
	}
	m.services[service] = entry
	return entry, nil
}

// createServiceLocked creates a new service entry. Must hold servicesMu write lock.
func (m *ServiceMux) createServiceLocked(service uint64) (*serviceEntry, error) {
	conn := NewKCPConn(uint32(service), func(data []byte) {
		m.config.Output(service, data)
	})

	pipe := newKCPPipe(conn)

	var session *yamux.Session
	var err error
	if m.config.IsClient {
		session, err = yamux.Client(pipe, m.config.YamuxConfig)
	} else {
		session, err = yamux.Server(pipe, m.config.YamuxConfig)
	}
	if err != nil {
		pipe.Close()
		conn.Close()
		return nil, err
	}

	entry := &serviceEntry{
		conn:    conn,
		session: session,
		pipe:    pipe,
	}

	// Start accept loop for this service's yamux session.
	go m.serviceAcceptLoop(service, session)

	return entry, nil
}

// serviceAcceptLoop accepts yamux streams and forwards them to the global accept queue.
func (m *ServiceMux) serviceAcceptLoop(service uint64, session *yamux.Session) {
	for {
		stream, err := session.Accept()
		if err != nil {
			return
		}

		select {
		case m.acceptCh <- acceptResult{conn: stream, service: service}:
		case <-m.closeCh:
			stream.Close()
			return
		}
	}
}

// kcpPipe adapts KCPConn to net.Conn for yamux.
// Forwards deadline calls to the underlying KCPConn so yamux's
// keepalive and timeout detection work correctly.
type kcpPipe struct {
	conn *KCPConn
}

func newKCPPipe(conn *KCPConn) *kcpPipe {
	return &kcpPipe{conn: conn}
}

func (p *kcpPipe) Read(b []byte) (int, error)         { return p.conn.Read(b) }
func (p *kcpPipe) Write(b []byte) (int, error)        { return p.conn.Write(b) }
func (p *kcpPipe) Close() error                       { return p.conn.Close() }
func (p *kcpPipe) LocalAddr() net.Addr                { return pipeAddr{} }
func (p *kcpPipe) RemoteAddr() net.Addr               { return pipeAddr{} }
func (p *kcpPipe) SetDeadline(t time.Time) error      { return p.conn.SetDeadline(t) }
func (p *kcpPipe) SetReadDeadline(t time.Time) error  { return p.conn.SetReadDeadline(t) }
func (p *kcpPipe) SetWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "kcp" }
func (pipeAddr) String() string  { return "kcp-pipe" }

var _ net.Conn = (*kcpPipe)(nil)
