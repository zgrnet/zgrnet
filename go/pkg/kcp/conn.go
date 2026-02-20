package kcp

import (
	"errors"
	"io"
	"sync"
	"time"
)

var (
	ErrConnClosed = errors.New("kcp: conn closed")
)

// KCPConn wraps a KCP instance as an io.ReadWriteCloser.
//
// It runs an internal goroutine for event-driven KCP processing:
//   - Incoming data via Input() → channel → goroutine → KCP.Input + KCP.Recv
//   - KCP.Update driven by KCP.Check() (adaptive timer, not fixed ticker)
//   - Read() blocks until data is available from KCP recv buffer
//   - Write() feeds data into KCP.Send + KCP.Flush
//
// One goroutine per KCPConn. When the conn is idle (no data, no pending
// retransmissions), the goroutine sleeps on the timer — zero CPU cost.
type KCPConn struct {
	kcp    *KCP
	output func([]byte)

	// Input channel: network layer feeds incoming KCP packets here.
	inputCh chan []byte

	// Receive buffer: goroutine writes, Read() reads.
	recvBuf  []byte
	recvMu   sync.Mutex
	recvCond *sync.Cond

	// Close management.
	closeCh   chan struct{}
	closeOnce sync.Once
	closed    bool
	closeMu   sync.RWMutex

	// goroutine lifecycle
	wg sync.WaitGroup
}

// NewKCPConn creates a KCPConn with the given conversation ID and output function.
// output is called when KCP wants to send a packet over the wire.
// The internal goroutine starts immediately.
func NewKCPConn(conv uint32, output func([]byte)) *KCPConn {
	c := &KCPConn{
		output:  output,
		inputCh: make(chan []byte, 256),
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
// Returns ErrConnClosed if the conn has been closed.
func (c *KCPConn) Input(data []byte) error {
	c.closeMu.RLock()
	if c.closed {
		c.closeMu.RUnlock()
		return ErrConnClosed
	}
	c.closeMu.RUnlock()

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
// the conn is closed, or EOF.
func (c *KCPConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	for len(c.recvBuf) == 0 {
		c.closeMu.RLock()
		closed := c.closed
		c.closeMu.RUnlock()
		if closed {
			return 0, io.EOF
		}
		c.recvCond.Wait()
	}

	n := copy(b, c.recvBuf)
	c.recvBuf = c.recvBuf[n:]
	return n, nil
}

// Write sends data through KCP.
func (c *KCPConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	c.closeMu.RLock()
	if c.closed {
		c.closeMu.RUnlock()
		return 0, ErrConnClosed
	}
	c.closeMu.RUnlock()

	ret := c.kcp.Send(b)
	if ret < 0 {
		return 0, errors.New("kcp: send failed")
	}
	c.kcp.Flush()

	return len(b), nil
}

// Close shuts down the KCPConn and its internal goroutine.
func (c *KCPConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeMu.Lock()
		c.closed = true
		c.closeMu.Unlock()

		close(c.closeCh)
		c.recvCond.Broadcast()
		c.wg.Wait()
		c.kcp.Release()
	})
	return nil
}

// runLoop is the internal goroutine that drives KCP.
//
// It processes incoming packets, runs KCP.Update on an adaptive timer
// (using KCP.Check()), and drains received data into recvBuf.
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
			c.kcp.Update(uint32(time.Now().UnixMilli()))
			c.drainRecv()

			// Batch drain: process any queued packets without blocking
			c.drainInputCh()

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
	// Single update after batch input
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
