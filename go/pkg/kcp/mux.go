package kcp

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds the configuration for a Mux.
type Config struct {
	// MaxFrameSize is the maximum frame payload size.
	MaxFrameSize int

	// MaxReceiveBuffer is the maximum receive buffer per stream.
	MaxReceiveBuffer int

	// KeepAliveInterval is the interval between keepalive frames.
	KeepAliveInterval time.Duration

	// KeepAliveTimeout is the timeout for keepalive.
	KeepAliveTimeout time.Duration

	// AcceptBacklog is the size of the accept queue.
	AcceptBacklog int
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		MaxFrameSize:      32 * 1024,
		MaxReceiveBuffer:  256 * 1024,
		KeepAliveInterval: 10 * time.Second,
		KeepAliveTimeout:  30 * time.Second,
		AcceptBacklog:     256,
	}
}

// OutputFunc is the callback for sending frames.
type OutputFunc func(data []byte) error

// Mux multiplexes multiple streams over a single connection.
type Mux struct {
	config   *Config
	output   OutputFunc
	isClient bool

	// Streams
	streams   map[uint32]*Stream
	streamsMu sync.RWMutex

	// Stream ID allocation
	nextID   uint32
	nextIDMu sync.Mutex

	// Accept queue
	accepts chan *Stream

	// Lifecycle
	die       chan struct{}
	dieOnce   sync.Once
	closed    atomic.Bool
	closeErr  error
	closeOnce sync.Once

	// Update loop
	updateTicker *time.Ticker
	updateDone   chan struct{}
}

// NewMux creates a new multiplexer.
// isClient determines stream ID allocation: client uses odd IDs, server uses even.
// output is called to send frames over the underlying connection.
func NewMux(config *Config, isClient bool, output OutputFunc) *Mux {
	if config == nil {
		config = DefaultConfig()
	}

	m := &Mux{
		config:     config,
		output:     output,
		isClient:   isClient,
		streams:    make(map[uint32]*Stream),
		accepts:    make(chan *Stream, config.AcceptBacklog),
		die:        make(chan struct{}),
		updateDone: make(chan struct{}),
	}

	// Initialize stream ID
	if isClient {
		m.nextID = 1 // Client uses odd: 1, 3, 5, ...
	} else {
		m.nextID = 2 // Server uses even: 2, 4, 6, ...
	}

	// Start update loop
	m.updateTicker = time.NewTicker(10 * time.Millisecond)
	go m.updateLoop()

	return m
}

// OpenStream opens a new stream.
func (m *Mux) OpenStream() (*Stream, error) {
	if m.IsClosed() {
		return nil, ErrMuxClosed
	}

	// Allocate stream ID
	m.nextIDMu.Lock()
	id := m.nextID
	m.nextID += 2 // Skip to next ID (odd or even)
	m.nextIDMu.Unlock()

	// Create stream
	stream := newStream(id, m)

	// Register stream
	m.streamsMu.Lock()
	m.streams[id] = stream
	m.streamsMu.Unlock()

	// Send SYN
	if err := m.sendSYN(id); err != nil {
		m.streamsMu.Lock()
		delete(m.streams, id)
		m.streamsMu.Unlock()
		return nil, err
	}

	return stream, nil
}

// AcceptStream accepts an incoming stream.
func (m *Mux) AcceptStream() (*Stream, error) {
	select {
	case stream := <-m.accepts:
		return stream, nil
	case <-m.die:
		return nil, ErrMuxClosed
	}
}

// NumStreams returns the number of active streams.
func (m *Mux) NumStreams() int {
	m.streamsMu.RLock()
	defer m.streamsMu.RUnlock()
	return len(m.streams)
}

// Close closes the mux and all streams.
func (m *Mux) Close() error {
	m.closeOnce.Do(func() {
		m.closed.Store(true)

		// Stop update loop
		m.updateTicker.Stop()
		close(m.die)
		<-m.updateDone

		// Collect streams to close
		m.streamsMu.Lock()
		streams := make([]*Stream, 0, len(m.streams))
		for _, s := range m.streams {
			streams = append(streams, s)
		}
		m.streams = make(map[uint32]*Stream)
		m.streamsMu.Unlock()

		// Close streams outside of lock
		for _, s := range streams {
			s.closeInternal()
		}
	})
	return nil
}

// IsClosed returns true if the mux is closed.
func (m *Mux) IsClosed() bool {
	return m.closed.Load()
}

// Input processes an incoming frame.
func (m *Mux) Input(data []byte) error {
	if m.IsClosed() {
		return ErrMuxClosed
	}

	frame, err := DecodeFrame(data)
	if err != nil {
		return err
	}

	switch frame.Cmd {
	case CmdSYN:
		return m.handleSYN(frame.StreamID)
	case CmdFIN:
		return m.handleFIN(frame.StreamID)
	case CmdPSH:
		return m.handlePSH(frame.StreamID, frame.Payload)
	case CmdNOP:
		// Keepalive, nothing to do
		return nil
	case CmdUPD:
		return m.handleUPD(frame.StreamID, frame.Payload)
	default:
		return ErrInvalidCmd
	}
}

// handleSYN handles a SYN frame (stream open request).
func (m *Mux) handleSYN(id uint32) error {
	m.streamsMu.Lock()
	defer m.streamsMu.Unlock()

	// Check if stream already exists
	if _, ok := m.streams[id]; ok {
		return nil // Duplicate SYN, ignore
	}

	// Create new stream
	stream := newStream(id, m)
	m.streams[id] = stream

	// Queue for accept
	select {
	case m.accepts <- stream:
	default:
		// Accept queue full, close the stream
		stream.Close()
		return ErrAcceptQueueFull
	}

	return nil
}

// handleFIN handles a FIN frame (stream close).
func (m *Mux) handleFIN(id uint32) error {
	m.streamsMu.RLock()
	stream, ok := m.streams[id]
	m.streamsMu.RUnlock()

	if !ok {
		return nil // Stream not found, ignore
	}

	stream.fin()
	return nil
}

// handlePSH handles a PSH frame (data).
func (m *Mux) handlePSH(id uint32, payload []byte) error {
	m.streamsMu.RLock()
	stream, ok := m.streams[id]
	m.streamsMu.RUnlock()

	if !ok {
		return nil // Stream not found, ignore
	}

	// Feed to KCP
	stream.kcpInput(payload)

	// Try to receive from KCP
	stream.kcpRecv()

	return nil
}

// handleUPD handles a UPD frame (window update).
func (m *Mux) handleUPD(id uint32, payload []byte) error {
	// TODO: Implement flow control
	return nil
}

// sendFrame sends a frame through the output callback.
func (m *Mux) sendFrame(f *Frame) error {
	if m.IsClosed() {
		return ErrMuxClosed
	}
	return m.output(f.Encode())
}

// sendSYN sends a SYN frame.
func (m *Mux) sendSYN(id uint32) error {
	return m.sendFrame(&Frame{
		Cmd:      CmdSYN,
		StreamID: id,
	})
}

// sendFIN sends a FIN frame.
func (m *Mux) sendFIN(id uint32) error {
	return m.sendFrame(&Frame{
		Cmd:      CmdFIN,
		StreamID: id,
	})
}

// sendPSH sends a PSH frame.
func (m *Mux) sendPSH(id uint32, payload []byte) error {
	return m.sendFrame(&Frame{
		Cmd:      CmdPSH,
		StreamID: id,
		Payload:  payload,
	})
}

// sendNOP sends a NOP frame (keepalive).
func (m *Mux) sendNOP() error {
	return m.sendFrame(&Frame{
		Cmd: CmdNOP,
	})
}

// removeStream removes a stream from the mux.
func (m *Mux) removeStream(id uint32) {
	m.streamsMu.Lock()
	delete(m.streams, id)
	m.streamsMu.Unlock()
}

// updateLoop periodically updates all KCP instances.
// Uses kcp.Check() to determine optimal update timing.
func (m *Mux) updateLoop() {
	defer close(m.updateDone)

	for {
		select {
		case <-m.die:
			return
		case <-m.updateTicker.C:
			current := uint32(time.Now().UnixMilli())
			nextUpdate := current + 100 // Default: 100ms max interval

			m.streamsMu.RLock()
			for _, s := range m.streams {
				s.kcpUpdate(current)
				s.kcpRecv() // Check if KCP has data ready

				// Find earliest next update time
				if check := s.kcp.Check(current); check < nextUpdate {
					nextUpdate = check
				}
			}
			m.streamsMu.RUnlock()

			// Adjust ticker for next interval (min 1ms, max 100ms)
			interval := nextUpdate - current
			if interval < 1 {
				interval = 1
			} else if interval > 100 {
				interval = 100
			}
			m.updateTicker.Reset(time.Duration(interval) * time.Millisecond)
		}
	}
}

// Mux errors.
var (
	ErrMuxClosed       = errors.New("kcp: mux closed")
	ErrAcceptQueueFull = errors.New("kcp: accept queue full")
)

// Ensure Stream implements io.ReadWriteCloser
var _ io.ReadWriteCloser = (*Stream)(nil)
