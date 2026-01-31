//! Listener for accepting incoming connections.
//!
//! This module provides a `Listener` type that accepts incoming connections
//! on a transport and provides established connections through `accept()`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};

use crate::noise::{
    parse_handshake_init, parse_transport_message, Addr, KeyPair, Transport, MAX_PACKET_SIZE,
    message::message_type,
};

use super::conn::{Conn, ConnConfig, ConnError, ConnState, InboundPacket};
use super::manager::SessionManager;

/// Result type for listener operations.
pub type Result<T> = std::result::Result<T, ListenerError>;

/// Listener errors.
#[derive(Debug)]
pub enum ListenerError {
    /// Missing local key pair.
    MissingLocalKey,
    /// Missing transport.
    MissingTransport,
    /// Listener is closed.
    Closed,
    /// Connection error.
    Conn(ConnError),
}

impl std::fmt::Display for ListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingLocalKey => write!(f, "missing local key pair"),
            Self::MissingTransport => write!(f, "missing transport"),
            Self::Closed => write!(f, "listener closed"),
            Self::Conn(e) => write!(f, "connection error: {}", e),
        }
    }
}

impl std::error::Error for ListenerError {}

impl From<ConnError> for ListenerError {
    fn from(e: ConnError) -> Self {
        Self::Conn(e)
    }
}

/// Configuration for creating a listener.
pub struct ListenerConfig<T: Transport + 'static> {
    /// Local static key pair.
    pub local_key: KeyPair,
    /// Underlying datagram transport.
    pub transport: T,
    /// Size of the accept queue (default: 16).
    pub accept_queue_size: Option<usize>,
}

/// A listener that accepts incoming connections.
///
/// The listener handles the handshake process for incoming connections
/// and provides accepted connections through the `accept()` method.
///
/// # Example
///
/// ```ignore
/// let listener = Listener::new(ListenerConfig {
///     local_key,
///     transport,
///     accept_queue_size: None,
/// })?;
///
/// // Start the receive loop in a background thread
/// listener.start();
///
/// // Accept connections
/// loop {
///     let conn = listener.accept()?;
///     // Handle connection...
/// }
/// ```
pub struct Listener<T: Transport + Send + Sync + 'static> {
    local_key: KeyPair,
    transport: Arc<T>,

    // Active connections indexed by local session index
    conns: Arc<RwLock<HashMap<u32, Arc<Conn<Arc<T>>>>>>,

    // Completed connections ready to be accepted
    ready_tx: Sender<Arc<Conn<Arc<T>>>>,
    ready_rx: Mutex<Receiver<Arc<Conn<Arc<T>>>>>,

    // Session manager
    manager: Arc<SessionManager>,

    // Closed flag (atomic for thread-safe access)
    closed: Arc<AtomicBool>,

    // Receive loop thread handle
    recv_thread: Mutex<Option<JoinHandle<()>>>,
}

impl<T: Transport + Send + Sync + 'static> Listener<T> {
    /// Creates a new listener with the given configuration.
    /// Call `start()` to begin accepting connections.
    pub fn new(cfg: ListenerConfig<T>) -> Result<Arc<Self>> {
        let (tx, rx) = channel();

        Ok(Arc::new(Self {
            local_key: cfg.local_key,
            transport: Arc::new(cfg.transport),
            conns: Arc::new(RwLock::new(HashMap::new())),
            ready_tx: tx,
            ready_rx: Mutex::new(rx),
            manager: Arc::new(SessionManager::new()),
            closed: Arc::new(AtomicBool::new(false)),
            recv_thread: Mutex::new(None),
        }))
    }

    /// Starts the receive loop in a background thread.
    /// This must be called after creating the listener.
    pub fn start(self: &Arc<Self>) {
        let listener = Arc::clone(self);
        let handle = thread::spawn(move || {
            listener.receive_loop();
        });
        *self.recv_thread.lock().unwrap() = Some(handle);
    }

    /// Accepts the next incoming connection.
    /// This is a blocking call.
    pub fn accept(&self) -> Result<Arc<Conn<Arc<T>>>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(ListenerError::Closed);
        }

        let rx = self.ready_rx.lock().unwrap();
        rx.recv().map_err(|_| ListenerError::Closed)
    }

    /// Closes the listener and stops the receive loop.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return; // Already closed
        }

        // Close all connections
        let mut conns = self.conns.write().unwrap();
        for (_, conn) in conns.drain() {
            let _ = conn.close();
        }

        // Note: The receive loop will exit when it checks the closed flag
    }

    /// Removes a connection from the listener.
    /// This should be called when a connection is closed.
    pub fn remove_conn(&self, local_idx: u32) {
        self.conns.write().unwrap().remove(&local_idx);
    }

    /// Returns the local key pair.
    pub fn local_key(&self) -> &KeyPair {
        &self.local_key
    }

    /// Returns the local public key.
    pub fn local_public_key(&self) -> crate::noise::Key {
        self.local_key.public
    }

    /// Returns the session manager.
    pub fn session_manager(&self) -> &SessionManager {
        &self.manager
    }

    /// Returns whether the listener is closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// The main receive loop that handles incoming packets.
    fn receive_loop(&self) {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            // Check if closed
            if self.closed.load(Ordering::SeqCst) {
                return;
            }

            // Receive packet
            let (n, addr) = match self.transport.recv_from(&mut buf) {
                Ok(result) => result,
                Err(_) => {
                    // Check if closed during recv
                    if self.closed.load(Ordering::SeqCst) {
                        return;
                    }
                    continue;
                }
            };

            if n < 1 {
                continue;
            }

            let msg_type = buf[0];

            match msg_type {
                message_type::HANDSHAKE_INIT => {
                    self.handle_handshake_init(&buf[..n], addr);
                }
                message_type::TRANSPORT => {
                    self.handle_transport(&buf[..n], addr);
                }
                // TODO: Handle other message types (HandshakeResp for rekey)
                _ => {
                    // Unknown message type, ignore
                }
            }
        }
    }

    /// Processes an incoming handshake initiation.
    fn handle_handshake_init(&self, data: &[u8], addr: Box<dyn Addr>) {
        // Parse handshake init
        let msg = match parse_handshake_init(data) {
            Ok(msg) => msg,
            Err(_) => return,
        };

        // Create a new connection for this peer
        let conn = match Conn::new(ConnConfig {
            local_key: self.local_key.clone(),
            remote_pk: None, // Will be set during accept
            transport: Arc::clone(&self.transport),
            remote_addr: Some(addr.clone_box()),
        }) {
            Ok(conn) => Arc::new(conn),
            Err(_) => return,
        };

        // Set up inbound channel for the connection
        let _inbound_tx = conn.setup_inbound();

        // Process the handshake
        let resp = match conn.accept(&msg) {
            Ok(resp) => resp,
            Err(_) => return,
        };

        // Send the response
        if self.transport.send_to(&resp, addr.as_ref()).is_err() {
            return;
        }

        // Register the connection
        let local_idx = conn.local_index();
        self.conns.write().unwrap().insert(local_idx, Arc::clone(&conn));

        // Note: Session registration in manager is skipped for now
        // The Conn stores Session directly while manager expects Arc<Session>
        // This can be addressed in a future refactoring

        // Queue the connection for acceptance
        if self.ready_tx.send(conn).is_err() {
            // Accept queue full or closed, clean up
            self.conns.write().unwrap().remove(&local_idx);
        }
    }

    /// Processes an incoming transport message.
    fn handle_transport(&self, data: &[u8], addr: Box<dyn Addr>) {
        // Parse transport message
        let msg = match parse_transport_message(data) {
            Ok(msg) => msg,
            Err(_) => return,
        };

        // Look up connection by receiver index
        let conn = {
            let conns = self.conns.read().unwrap();
            conns.get(&msg.receiver_index).cloned()
        };

        let conn = match conn {
            Some(c) => c,
            None => return, // Unknown connection
        };

        // Create owned InboundPacket (copy ciphertext since buffer will be reused)
        let pkt = InboundPacket {
            receiver_index: msg.receiver_index,
            counter: msg.counter,
            ciphertext: msg.ciphertext.to_vec(),
            addr,
        };

        // Deliver to connection
        conn.deliver_packet(pkt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::dial::{dial, DialOptions};
    use crate::net::UdpTransport;
    use std::thread;

    #[test]
    fn test_listener_new() {
        let key = KeyPair::generate();
        let transport = UdpTransport::bind("127.0.0.1:0").unwrap();

        let listener = Listener::new(ListenerConfig {
            local_key: key,
            transport,
            accept_queue_size: None,
        })
        .unwrap();

        assert!(!listener.is_closed());
    }

    #[test]
    fn test_listener_close() {
        let key = KeyPair::generate();
        let transport = UdpTransport::bind("127.0.0.1:0").unwrap();

        let listener = Listener::new(ListenerConfig {
            local_key: key,
            transport,
            accept_queue_size: None,
        })
        .unwrap();

        listener.close();
        assert!(listener.is_closed());

        // Double close should be safe
        listener.close();
        assert!(listener.is_closed());
    }

    #[test]
    fn test_listener_accept_connection() {
        // Create server with real UDP
        let server_key = KeyPair::generate();
        let server_transport = UdpTransport::bind("127.0.0.1:0").unwrap();
        let server_addr = server_transport.local_address().clone();

        let listener = Listener::new(ListenerConfig {
            local_key: server_key.clone(),
            transport: server_transport,
            accept_queue_size: None,
        })
        .unwrap();

        // Start the listener
        listener.start();

        // Create client with real UDP
        let client_key = KeyPair::generate();
        let client_transport = UdpTransport::bind("127.0.0.1:0").unwrap();

        // Spawn client dial in separate thread
        let server_pk = server_key.public;
        let client_handle = thread::spawn(move || {
            dial(DialOptions {
                local_key: client_key,
                remote_pk: server_pk,
                transport: client_transport,
                remote_addr: Box::new(server_addr),
                deadline: None,
            })
        });

        // Accept connection on server
        let server_conn = listener.accept().expect("Accept should succeed");

        // Wait for client dial to complete
        let client_conn = client_handle.join().unwrap().expect("Dial should succeed");

        // Verify both sides are established
        assert_eq!(server_conn.state(), ConnState::Established);
        assert_eq!(client_conn.state(), ConnState::Established);

        // Clean up
        listener.close();
    }

    #[test]
    fn test_listener_bidirectional_communication() {
        // Create server with real UDP
        let server_key = KeyPair::generate();
        let server_transport = UdpTransport::bind("127.0.0.1:0").unwrap();
        let server_addr = server_transport.local_address().clone();

        let listener = Listener::new(ListenerConfig {
            local_key: server_key.clone(),
            transport: server_transport,
            accept_queue_size: None,
        })
        .unwrap();

        listener.start();

        // Create client with real UDP
        let client_key = KeyPair::generate();
        let client_transport = UdpTransport::bind("127.0.0.1:0").unwrap();

        // Dial from client
        let server_pk = server_key.public;
        let client_handle = thread::spawn(move || {
            dial(DialOptions {
                local_key: client_key,
                remote_pk: server_pk,
                transport: client_transport,
                remote_addr: Box::new(server_addr),
                deadline: None,
            })
        });

        // Accept on server
        let server_conn = listener.accept().expect("Accept should succeed");
        let client_conn = client_handle.join().unwrap().expect("Dial should succeed");

        // Test client -> server communication
        client_conn
            .send(crate::noise::protocol::CHAT, b"Hello from client!")
            .expect("Client send should succeed");

        let (proto, payload) = server_conn.recv().expect("Server recv should succeed");
        assert_eq!(proto, crate::noise::protocol::CHAT);
        assert_eq!(payload, b"Hello from client!");

        // Test server -> client communication
        server_conn
            .send(crate::noise::protocol::RPC, b"Hello from server!")
            .expect("Server send should succeed");

        let (proto, payload) = client_conn.recv().expect("Client recv should succeed");
        assert_eq!(proto, crate::noise::protocol::RPC);
        assert_eq!(payload, b"Hello from server!");

        // Clean up
        listener.close();
    }
}
