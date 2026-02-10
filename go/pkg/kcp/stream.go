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
// It implements io.ReadWriteCloser with blocking Read semantics.
type Stream struct {
	id       uint32
	mux      *Mux
	kcp      *KCP
	proto    byte   // Stream protocol type (from SYN payload)
	metadata []byte // Stream metadata (from SYN payload)

	// Receive buffer (protected by recvMu, which also backs recvCond)
	recvBuf  []byte
	recvMu   sync.Mutex
	recvCond *sync.Cond // signaled when data arrives or stream closes

	// State
	state     atomic.Uint32
	closeOnce sync.Once
	closeCh   chan struct{}

	// Deadlines
	readDeadline  atomic.Value // time.Time
	writeDeadline atomic.Value // time.Time
}

// newStream creates a new stream with protocol type and metadata.
func newStream(id uint32, mux *Mux, proto byte, metadata []byte) *Stream {
	s := &Stream{
		id:       id,
		mux:      mux,
		proto:    proto,
		metadata: metadata,
		closeCh:  make(chan struct{}),
	}
	s.recvCond = sync.NewCond(&s.recvMu)

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

// Proto returns the stream protocol type (from SYN payload).
// Returns 0 (RAW) if no protocol was specified.
func (s *Stream) Proto() byte {
	return s.proto
}

// Metadata returns the stream metadata (from SYN payload).
// Returns nil if no metadata was specified.
func (s *Stream) Metadata() []byte {
	return s.metadata
}

// State returns the current stream state.
func (s *Stream) State() StreamState {
	return StreamState(s.state.Load())
}

// Read reads data from the stream. Blocks until data is available,
// the stream is closed, or the read deadline expires.
// Returns 0, io.EOF when the stream is closed.
func (s *Stream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	for len(s.recvBuf) == 0 {
		// Check terminal states
		state := s.State()
		if state == StreamStateClosed || state == StreamStateRemoteClose {
			return 0, io.EOF
		}
		select {
		case <-s.closeCh:
			return 0, io.EOF
		default:
		}

		// Check read deadline
		if deadline, ok := s.readDeadline.Load().(time.Time); ok && !deadline.IsZero() {
			if time.Now().After(deadline) {
				return 0, ErrTimeout
			}
			// Use timed wait: spawn a goroutine to signal after timeout
			done := make(chan struct{})
			go func() {
				timer := time.NewTimer(time.Until(deadline))
				defer timer.Stop()
				select {
				case <-timer.C:
					s.recvCond.Broadcast()
				case <-done:
				}
			}()
			s.recvCond.Wait()
			close(done)
			continue
		}

		// Block until data arrives or stream closes
		s.recvCond.Wait()
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

	// Flush immediately for better throughput
	s.kcp.Flush()

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

	// Signal close — wake blocked readers
	close(s.closeCh)
	s.recvCond.Broadcast()

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
// Signals recvCond to wake any blocked Read calls.
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
	if received {
		s.recvCond.Broadcast()
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
	// Wake blocked readers so they see EOF
	s.recvCond.Broadcast()
}

// Stream errors.
var (
	ErrStreamClosed  = errors.New("kcp: stream closed")
	ErrKCPSendFailed = errors.New("kcp: send failed")
	ErrTimeout       = errors.New("kcp: timeout")
)
