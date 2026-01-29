package noise

import (
	"errors"
	"sync"
)

// Listener listens for incoming connections on a transport.
// It handles the handshake process for incoming connections
// and provides accepted connections through the Accept() method.
type Listener struct {
	mu sync.Mutex

	localKey  *KeyPair
	transport Transport

	// Active connections indexed by local session index
	conns map[uint32]*Conn

	// Completed connections ready to be accepted
	ready chan *Conn

	// Session manager for established sessions
	manager *SessionManager

	// Closed flag
	closed bool
	done   chan struct{}
}

// ListenerConfig contains the configuration for creating a listener.
type ListenerConfig struct {
	// LocalKey is the local static key pair.
	LocalKey *KeyPair
	// Transport is the underlying datagram transport.
	Transport Transport
	// AcceptQueueSize is the size of the accept queue (default: 16).
	AcceptQueueSize int
}

// NewListener creates a new listener with the given configuration.
func NewListener(cfg ListenerConfig) (*Listener, error) {
	if cfg.LocalKey == nil {
		return nil, ErrMissingLocalKey
	}
	if cfg.Transport == nil {
		return nil, ErrMissingTransport
	}

	queueSize := cfg.AcceptQueueSize
	if queueSize <= 0 {
		queueSize = 16
	}

	l := &Listener{
		localKey:  cfg.LocalKey,
		transport: cfg.Transport,
		conns:     make(map[uint32]*Conn),
		ready:     make(chan *Conn, queueSize),
		manager:   NewSessionManager(),
		done:      make(chan struct{}),
	}

	// Start the receive loop
	go l.receiveLoop()

	return l, nil
}

// Accept waits for and returns the next incoming connection.
// This is a blocking call.
func (l *Listener) Accept() (*Conn, error) {
	select {
	case conn := <-l.ready:
		return conn, nil
	case <-l.done:
		return nil, ErrListenerClosed
	}
}

// Close closes the listener.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}

	l.closed = true
	close(l.done)

	// Close all connections
	for idx, conn := range l.conns {
		if conn.inbound != nil {
			close(conn.inbound)
		}
		conn.Close()
		delete(l.conns, idx)
	}
	l.mu.Unlock()

	return l.transport.Close()
}

// RemoveConn removes a connection from the listener.
// This should be called when a connection is closed.
func (l *Listener) RemoveConn(localIdx uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.conns, localIdx)
}

// LocalAddr returns the local address of the listener.
func (l *Listener) LocalAddr() Addr {
	return l.transport.LocalAddr()
}

// LocalPublicKey returns the local public key.
func (l *Listener) LocalPublicKey() PublicKey {
	return l.localKey.Public
}

// SessionManager returns the session manager.
func (l *Listener) SessionManager() *SessionManager {
	return l.manager
}

// receiveLoop handles incoming packets.
func (l *Listener) receiveLoop() {
	buf := make([]byte, MaxPacketSize)

	for {
		select {
		case <-l.done:
			return
		default:
		}

		n, addr, err := l.transport.RecvFrom(buf)
		if err != nil {
			// Check if closed
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed {
				return
			}
			continue
		}

		if n < 1 {
			continue
		}

		msgType := buf[0]

		switch msgType {
		case MessageTypeHandshakeInit:
			l.handleHandshakeInit(buf[:n], addr)

		case MessageTypeTransport:
			l.handleTransport(buf[:n], addr)

		// TODO: Handle other message types
		default:
			// Unknown message type, ignore
		}
	}
}

// handleHandshakeInit processes an incoming handshake initiation.
func (l *Listener) handleHandshakeInit(data []byte, addr Addr) {
	msg, err := ParseHandshakeInit(data)
	if err != nil {
		return
	}

	// Create a new connection for this peer
	conn, err := NewConn(ConnConfig{
		LocalKey:   l.localKey,
		Transport:  l.transport,
		RemoteAddr: addr,
	})
	if err != nil {
		return
	}

	// Set up inbound channel for the connection
	inbound := make(chan inboundPacket, 64)
	conn.setInbound(inbound)

	// Process the handshake
	resp, err := conn.Accept(msg)
	if err != nil {
		close(inbound)
		return
	}

	// Send the response
	if err := l.transport.SendTo(resp, addr); err != nil {
		close(inbound)
		return
	}

	// Register the connection and session
	l.mu.Lock()
	l.conns[conn.LocalIndex()] = conn
	l.mu.Unlock()

	if conn.Session() != nil {
		l.manager.RegisterSession(conn.Session())
	}

	// Queue the connection for acceptance
	select {
	case l.ready <- conn:
	default:
		// Accept queue full, drop connection
		l.mu.Lock()
		delete(l.conns, conn.LocalIndex())
		l.mu.Unlock()
		close(inbound)
		conn.Close()
	}
}

// handleTransport processes an incoming transport message.
func (l *Listener) handleTransport(data []byte, addr Addr) {
	msg, err := ParseTransportMessage(data)
	if err != nil {
		return
	}

	// Look up connection by receiver index
	l.mu.Lock()
	conn := l.conns[msg.ReceiverIndex]
	l.mu.Unlock()

	if conn == nil {
		return // Unknown connection
	}

	// Route the packet to the connection
	// Make a copy of the data since the buffer may be reused
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	conn.deliverPacket(dataCopy, addr)
}

// SendTo sends data through the listener's transport.
// This is useful for sending responses without a Conn.
func (l *Listener) SendTo(data []byte, addr Addr) error {
	return l.transport.SendTo(data, addr)
}

// Listener errors.
var (
	ErrListenerClosed = errors.New("noise: listener closed")
)
