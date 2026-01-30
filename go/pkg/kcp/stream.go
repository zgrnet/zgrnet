package kcp

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// bufferPool is a pool of 64KB buffers for KCP recv operations.
var bufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 64*1024)
		return &buf
	},
}

// StreamState represents the state of a stream.
type StreamState uint32

const (
	StreamStateInit StreamState = iota
	StreamStateOpen
	StreamStateLocalClose  // We sent FIN
	StreamStateRemoteClose // We received FIN
	StreamStateClosed
)

func (s StreamState) String() string {
	switch s {
	case StreamStateInit:
		return "init"
	case StreamStateOpen:
		return "open"
	case StreamStateLocalClose:
		return "local_close"
	case StreamStateRemoteClose:
		return "remote_close"
	case StreamStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// Stream represents a multiplexed stream over KCP.
// It implements io.ReadWriteCloser.
type Stream struct {
	id  uint32
	mux *Mux
	kcp *KCP

	// Receive buffer
	recvBuf []byte
	recvMu  sync.Mutex

	// State
	state     atomic.Uint32
	closeOnce sync.Once
	closeCh   chan struct{}

	// Deadlines
	readDeadline  atomic.Value // time.Time
	writeDeadline atomic.Value // time.Time
}

// newStream creates a new stream.
func newStream(id uint32, mux *Mux) *Stream {
	s := &Stream{
		id:      id,
		mux:     mux,
		closeCh: make(chan struct{}),
	}

	// Create KCP instance
	s.kcp = NewKCP(id, func(data []byte) {
		// Send KCP packet through mux
		s.mux.sendPSH(s.id, data)
	})

	// Configure KCP for fast mode
	s.kcp.DefaultConfig()

	s.state.Store(uint32(StreamStateOpen))
	return s
}

// ID returns the stream ID.
func (s *Stream) ID() uint32 {
	return s.id
}

// State returns the current stream state.
func (s *Stream) State() StreamState {
	return StreamState(s.state.Load())
}

// Read reads data from the stream (non-blocking).
// Returns 0, nil if no data is available.
// Returns 0, io.EOF if the stream is closed.
func (s *Stream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	if len(s.recvBuf) == 0 {
		state := s.State()
		if state == StreamStateClosed || state == StreamStateRemoteClose {
			return 0, io.EOF
		}

		select {
		case <-s.closeCh:
			return 0, io.EOF
		default:
		}

		return 0, nil // No data available
	}

	// Copy data
	n := copy(b, s.recvBuf)
	s.recvBuf = s.recvBuf[n:]

	return n, nil
}

// Write writes data to the stream.
// Implements io.Writer.
func (s *Stream) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	state := s.State()
	if state == StreamStateClosed || state == StreamStateLocalClose {
		return 0, ErrStreamClosed
	}

	// Check deadline
	if deadline, ok := s.writeDeadline.Load().(time.Time); ok && !deadline.IsZero() {
		if time.Now().After(deadline) {
			return 0, ErrTimeout
		}
	}

	// Send through KCP
	n := s.kcp.Send(b)
	if n < 0 {
		return 0, ErrKCPSendFailed
	}

	return n, nil
}

// Close closes the stream.
// Implements io.Closer.
func (s *Stream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.doClose(true)
	})
	return err
}

// closeInternal closes the stream without removing from mux.
// Used when mux is closing all streams.
func (s *Stream) closeInternal() {
	s.closeOnce.Do(func() {
		s.doClose(false)
	})
}

// doClose performs the actual close logic.
func (s *Stream) doClose(removeFromMux bool) error {
	state := s.State()
	if state == StreamStateClosed {
		return nil
	}

	// Mark as closing
	if state == StreamStateOpen {
		s.state.Store(uint32(StreamStateLocalClose))
	} else {
		s.state.Store(uint32(StreamStateClosed))
	}

	// Send FIN (ignore error if mux is closed)
	var err error
	if !s.mux.IsClosed() {
		err = s.mux.sendFIN(s.id)
	}

	// Signal close
	close(s.closeCh)

	// Release KCP
	s.kcp.Release()

	// Remove from mux
	if removeFromMux {
		s.mux.removeStream(s.id)
	}

	return err
}

// SetReadDeadline sets the read deadline.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline sets the write deadline.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Store(t)
	return nil
}

// SetDeadline sets both read and write deadlines.
func (s *Stream) SetDeadline(t time.Time) error {
	s.SetReadDeadline(t)
	s.SetWriteDeadline(t)
	return nil
}

// kcpInput processes incoming KCP data.
func (s *Stream) kcpInput(data []byte) {
	if s.State() == StreamStateClosed {
		return
	}

	s.kcp.Input(data)
}

// kcpRecv tries to receive data from KCP and buffer it.
// Returns true if any data was received.
func (s *Stream) kcpRecv() bool {
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool.Put(bufPtr)

	received := false
	for {
		size := s.kcp.PeekSize()
		if size <= 0 {
			break
		}

		n := s.kcp.Recv(buf)
		if n <= 0 {
			break
		}

		s.recvMu.Lock()
		s.recvBuf = append(s.recvBuf, buf[:n]...)
		s.recvMu.Unlock()
		received = true
	}
	return received
}

// kcpUpdate updates the KCP state.
func (s *Stream) kcpUpdate(current uint32) {
	if s.State() == StreamStateClosed {
		return
	}
	s.kcp.Update(current)
}

// fin handles receiving FIN from remote.
func (s *Stream) fin() {
	state := s.State()
	if state == StreamStateLocalClose {
		// Both sides closed
		s.state.Store(uint32(StreamStateClosed))
	} else if state == StreamStateOpen {
		s.state.Store(uint32(StreamStateRemoteClose))
	}
}

// Stream errors.
var (
	ErrStreamClosed  = errors.New("kcp: stream closed")
	ErrKCPSendFailed = errors.New("kcp: send failed")
	ErrTimeout       = errors.New("kcp: timeout")
)
