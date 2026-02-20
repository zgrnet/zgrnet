package kcp

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrConnClosed  = errors.New("kcp: conn closed")
	ErrConnTimeout = errors.New("kcp: timeout")
)

var bufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 64*1024)
		return &buf
	},
}

type writeReq struct {
	data   []byte
	result chan writeResult
}

type writeResult struct {
	n   int
	err error
}

// KCPConn wraps a KCP instance as io.ReadWriteCloser + net.Conn.
//
// ALL KCP operations (Send, Recv, Input, Update, Flush) execute exclusively
// in the runLoop goroutine. This eliminates any concurrency issues with the
// KCP C library. Write() and Input() communicate with runLoop via channels.
//
// Supports read/write deadlines for yamux compatibility.
type KCPConn struct {
	kcp    *KCP
	output func([]byte)

	inputCh chan []byte
	writeCh chan writeReq

	// Receive buffer: runLoop writes, Read() reads.
	recvBuf  []byte
	recvMu   sync.Mutex
	recvCond *sync.Cond

	// Deadlines (atomic for lock-free access from Read/Write)
	readDeadline  atomic.Value // time.Time
	writeDeadline atomic.Value // time.Time

	closeCh   chan struct{}
	closeOnce sync.Once
	closed    atomic.Bool

	wg sync.WaitGroup
}

// NewKCPConn creates a KCPConn with the given conversation ID and output function.
// output is called when KCP wants to send a packet over the wire.
// The internal goroutine starts immediately.
func NewKCPConn(conv uint32, output func([]byte)) *KCPConn {
	c := &KCPConn{
		output:  output,
		inputCh: make(chan []byte, 256),
		writeCh: make(chan writeReq, 64),
		closeCh: make(chan struct{}),
	}
	c.recvCond = sync.NewCond(&c.recvMu)

	c.kcp = NewKCP(conv, func(data []byte) {
		out := make([]byte, len(data))
		copy(out, data)
		c.output(out)
	})
	c.kcp.DefaultConfig()

	c.wg.Add(1)
	go c.runLoop()

	return c
}

// Input feeds an incoming KCP packet from the network layer.
// Non-blocking: data is queued to the internal goroutine via channel.
func (c *KCPConn) Input(data []byte) error {
	if c.closed.Load() {
		return ErrConnClosed
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case c.inputCh <- cp:
		return nil
	case <-c.closeCh:
		return ErrConnClosed
	}
}

// Read reads reassembled data from KCP. Blocks until data is available,
// the deadline expires, or the conn is closed.
func (c *KCPConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	for len(c.recvBuf) == 0 {
		if c.closed.Load() {
			return 0, io.EOF
		}

		if dl, ok := c.readDeadline.Load().(time.Time); ok && !dl.IsZero() {
			if time.Now().After(dl) {
				return 0, ErrConnTimeout
			}
			done := make(chan struct{})
			go func() {
				timer := time.NewTimer(time.Until(dl))
				defer timer.Stop()
				select {
				case <-timer.C:
					c.recvCond.Broadcast()
				case <-done:
				}
			}()
			c.recvCond.Wait()
			close(done)
			continue
		}

		c.recvCond.Wait()
	}

	n := copy(b, c.recvBuf)
	c.recvBuf = c.recvBuf[n:]
	return n, nil
}

// Write sends data through KCP. The data is forwarded to the runLoop
// goroutine which exclusively owns all KCP operations.
func (c *KCPConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	if c.closed.Load() {
		return 0, ErrConnClosed
	}

	cp := make([]byte, len(b))
	copy(cp, b)

	req := writeReq{
		data:   cp,
		result: make(chan writeResult, 1),
	}

	// Check write deadline
	var deadline <-chan time.Time
	if dl, ok := c.writeDeadline.Load().(time.Time); ok && !dl.IsZero() {
		if time.Now().After(dl) {
			return 0, ErrConnTimeout
		}
		timer := time.NewTimer(time.Until(dl))
		defer timer.Stop()
		deadline = timer.C
	}

	// Send request to runLoop
	select {
	case c.writeCh <- req:
	case <-c.closeCh:
		return 0, ErrConnClosed
	case <-deadline:
		return 0, ErrConnTimeout
	}

	// Wait for result
	select {
	case result := <-req.result:
		return result.n, result.err
	case <-c.closeCh:
		return 0, ErrConnClosed
	case <-deadline:
		return 0, ErrConnTimeout
	}
}

// Close shuts down the KCPConn and its internal goroutine.
func (c *KCPConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closeCh)
		c.recvCond.Broadcast()
		c.wg.Wait()
		c.kcp.Release()
	})
	return nil
}

// SetReadDeadline sets the read deadline.
func (c *KCPConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.recvCond.Broadcast()
	return nil
}

// SetWriteDeadline sets the write deadline.
func (c *KCPConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}

// SetDeadline sets both read and write deadlines.
func (c *KCPConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

// runLoop is the internal goroutine that exclusively owns all KCP operations.
// No other goroutine touches the KCP instance directly.
func (c *KCPConn) runLoop() {
	defer c.wg.Done()

	for {
		now := uint32(time.Now().UnixMilli())
		nextUpdate := c.kcp.Check(now)

		var delay time.Duration
		if nextUpdate <= now {
			delay = time.Millisecond
		} else {
			delay = time.Duration(nextUpdate-now) * time.Millisecond
		}

		timer := time.NewTimer(delay)

		select {
		case data := <-c.inputCh:
			timer.Stop()
			c.kcp.Input(data)
			c.drainInputCh()
			c.kcp.Update(uint32(time.Now().UnixMilli()))
			c.drainRecv()

		case req := <-c.writeCh:
			timer.Stop()
			ret := c.kcp.Send(req.data)
			if ret < 0 {
				req.result <- writeResult{0, errors.New("kcp: send failed")}
			} else {
				c.kcp.Flush()
				req.result <- writeResult{len(req.data), nil}
			}
			c.drainRecv()

		case <-timer.C:
			c.kcp.Update(uint32(time.Now().UnixMilli()))
			c.drainRecv()

		case <-c.closeCh:
			timer.Stop()
			return
		}
	}
}

// drainInputCh processes all queued packets in inputCh without blocking.
func (c *KCPConn) drainInputCh() {
	for {
		select {
		case data := <-c.inputCh:
			c.kcp.Input(data)
		default:
			return
		}
	}
}

// drainRecv moves all available data from KCP recv queue into recvBuf.
func (c *KCPConn) drainRecv() {
	buf := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(buf)

	received := false
	for {
		size := c.kcp.PeekSize()
		if size <= 0 {
			break
		}
		n := c.kcp.Recv(*buf)
		if n <= 0 {
			break
		}

		c.recvMu.Lock()
		c.recvBuf = append(c.recvBuf, (*buf)[:n]...)
		c.recvMu.Unlock()
		received = true
	}
	if received {
		c.recvCond.Broadcast()
	}
}

var _ io.ReadWriteCloser = (*KCPConn)(nil)
