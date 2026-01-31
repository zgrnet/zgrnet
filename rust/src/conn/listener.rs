//! Listener for accepting incoming connections.
//!
//! This module provides a `Listener` type that accepts incoming connections
//! on a transport and provides established connections through `accept()`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::mpsc::{channel, Receiver, Sender};

use crate::noise::{KeyPair, Key, Transport, Addr, Session};
use super::conn::{Conn, ConnConfig, ConnState, ConnError};
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
pub struct Listener<T: Transport + 'static> {
    local_key: KeyPair,
    transport: T,
    
    // Active connections indexed by local session index
    conns: RwLock<HashMap<u32, Arc<Conn<T>>>>,
    
    // Completed connections ready to be accepted
    ready_tx: Sender<Arc<Conn<T>>>,
    ready_rx: Mutex<Receiver<Arc<Conn<T>>>>,
    
    // Session manager
    manager: SessionManager,
    
    // Closed flag
    closed: RwLock<bool>,
}

impl<T: Transport + Clone + 'static> Listener<T> {
    /// Creates a new listener with the given configuration.
    pub fn new(cfg: ListenerConfig<T>) -> Result<Self> {
        let queue_size = cfg.accept_queue_size.unwrap_or(16);
        let (tx, rx) = channel();
        
        Ok(Self {
            local_key: cfg.local_key,
            transport: cfg.transport,
            conns: RwLock::new(HashMap::new()),
            ready_tx: tx,
            ready_rx: Mutex::new(rx),
            manager: SessionManager::new(),
            closed: RwLock::new(false),
        })
    }
    
    /// Accepts the next incoming connection.
    /// This is a blocking call.
    pub fn accept(&self) -> Result<Arc<Conn<T>>> {
        if *self.closed.read().unwrap() {
            return Err(ListenerError::Closed);
        }
        
        let rx = self.ready_rx.lock().unwrap();
        rx.recv().map_err(|_| ListenerError::Closed)
    }
    
    /// Closes the listener.
    pub fn close(&self) {
        let mut closed = self.closed.write().unwrap();
        if *closed {
            return;
        }
        
        *closed = true;
        
        // Close all connections
        let mut conns = self.conns.write().unwrap();
        for (_, conn) in conns.drain() {
            let _ = conn.close();
        }
    }
    
    /// Returns the local key pair.
    pub fn local_key(&self) -> &KeyPair {
        &self.local_key
    }
    
    /// Returns the session manager.
    pub fn session_manager(&self) -> &SessionManager {
        &self.manager
    }
    
    /// Returns whether the listener is closed.
    pub fn is_closed(&self) -> bool {
        *self.closed.read().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::MockTransport;
    use std::sync::Arc;

    #[test]
    fn test_listener_new() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        
        let listener = Listener::new(ListenerConfig {
            local_key: key,
            transport: Arc::clone(&transport),
            accept_queue_size: None,
        }).unwrap();
        
        assert!(!listener.is_closed());
    }
    
    #[test]
    fn test_listener_close() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        
        let listener = Listener::new(ListenerConfig {
            local_key: key,
            transport: Arc::clone(&transport),
            accept_queue_size: None,
        }).unwrap();
        
        listener.close();
        assert!(listener.is_closed());
        
        // Double close should be safe
        listener.close();
        assert!(listener.is_closed());
    }
}
