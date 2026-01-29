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

	// Pending handshakes indexed by remote address string
	pending map[string]*Conn

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
		pending:   make(map[string]*Conn),
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
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}

	l.closed = true
	close(l.done)

	return l.transport.Close()
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

	// Process the handshake
	resp, err := conn.Accept(msg)
	if err != nil {
		return
	}

	// Send the response
	if err := l.transport.SendTo(resp, addr); err != nil {
		return
	}

	// Register the session
	if conn.Session() != nil {
		l.manager.RegisterSession(conn.Session())
	}

	// Queue the connection for acceptance
	select {
	case l.ready <- conn:
	default:
		// Accept queue full, drop connection
		conn.Close()
	}
}

// handleTransport processes an incoming transport message.
func (l *Listener) handleTransport(data []byte, addr Addr) {
	msg, err := ParseTransportMessage(data)
	if err != nil {
		return
	}

	// Look up session by receiver index
	session := l.manager.GetByIndex(msg.ReceiverIndex)
	if session == nil {
		return // Unknown session
	}

	// Update remote address if changed (NAT rebinding)
	// This would require associating Conn with Session
	// For now, just ignore - the Conn handles its own receives

	// Note: In the current design, the Conn.Recv() handles its own receives.
	// This handler is for cases where we need to route packets to the right Conn.
	// A more complete implementation would maintain a map of Conn by session index.
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
