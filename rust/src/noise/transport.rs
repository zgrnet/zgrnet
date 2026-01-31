//! Transport abstraction for datagram-based communication.
//!
//! This module provides a unified interface for sending and receiving packets,
//! regardless of the underlying protocol (UDP, QUIC, etc.).

use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Address trait for transport-layer addresses.
pub trait Addr: Send + Sync + std::fmt::Debug {
    /// Returns the name of the network (e.g., "udp", "quic").
    fn network(&self) -> &str;
    /// Returns a string representation of the address.
    fn addr_string(&self) -> String;
    /// Clone into a boxed trait object.
    fn clone_box(&self) -> Box<dyn Addr>;
    /// Downcast to concrete type for comparison.
    fn as_any(&self) -> &dyn std::any::Any;
}

impl Clone for Box<dyn Addr> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// Transport error types.
#[derive(Debug)]
pub enum TransportError {
    /// I/O error.
    Io(io::Error),
    /// Invalid address type.
    InvalidAddress,
    /// Transport is closed.
    Closed,
    /// No peer connected (for mock transport).
    NoPeer,
    /// Inbox full (for mock transport).
    InboxFull,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::InvalidAddress => write!(f, "invalid address type"),
            Self::Closed => write!(f, "transport closed"),
            Self::NoPeer => write!(f, "no peer connected"),
            Self::InboxFull => write!(f, "inbox full"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Result type for transport operations.
pub type Result<T> = std::result::Result<T, TransportError>;

/// Transport trait for datagram-based communication.
pub trait Transport: Send + Sync {
    /// Sends data to the specified address.
    fn send_to(&self, data: &[u8], addr: &dyn Addr) -> Result<()>;

    /// Receives data into the provided buffer.
    /// Returns the number of bytes read and the sender's address.
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Box<dyn Addr>)>;

    /// Closes the transport.
    fn close(&self) -> Result<()>;

    /// Returns the local address.
    fn local_addr(&self) -> Box<dyn Addr>;

    /// Sets the deadline for future recv_from calls.
    /// None means recv_from will not time out.
    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()>;

    /// Sets the deadline for future send_to calls.
    /// None means send_to will not time out.
    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()>;
}

/// Implement Transport for Arc<T> where T: Transport.
impl<T: Transport> Transport for Arc<T> {
    fn send_to(&self, data: &[u8], addr: &dyn Addr) -> Result<()> {
        (**self).send_to(data, addr)
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Box<dyn Addr>)> {
        (**self).recv_from(buf)
    }

    fn close(&self) -> Result<()> {
        (**self).close()
    }

    fn local_addr(&self) -> Box<dyn Addr> {
        (**self).local_addr()
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        (**self).set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        (**self).set_write_deadline(deadline)
    }
}

// =============================================================================
// Mock Transport (for testing)
// =============================================================================

/// Mock address for testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockAddr(pub String);

impl MockAddr {
    /// Creates a new mock address.
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }
}

impl Addr for MockAddr {
    fn network(&self) -> &str {
        "mock"
    }

    fn addr_string(&self) -> String {
        self.0.clone()
    }

    fn clone_box(&self) -> Box<dyn Addr> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A packet in the mock transport.
struct MockPacket {
    data: Vec<u8>,
    from: MockAddr,
}

/// Mock transport for testing.
/// Two mock transports can be connected to simulate a network.
pub struct MockTransport {
    local_addr: MockAddr,
    peer: Mutex<Option<Arc<MockTransport>>>,
    inbox: Mutex<Receiver<MockPacket>>,
    sender: Mutex<Option<Sender<MockPacket>>>,
    closed: Mutex<bool>,
}

impl MockTransport {
    /// Creates a new mock transport.
    pub fn new(name: &str) -> Arc<Self> {
        let (sender, receiver) = mpsc::channel();
        Arc::new(Self {
            local_addr: MockAddr::new(name),
            peer: Mutex::new(None),
            inbox: Mutex::new(receiver),
            sender: Mutex::new(Some(sender)),
            closed: Mutex::new(false),
        })
    }

    /// Connects two mock transports together.
    pub fn connect(a: &Arc<Self>, b: &Arc<Self>) {
        *a.peer.lock().unwrap() = Some(Arc::clone(b));
        *b.peer.lock().unwrap() = Some(Arc::clone(a));
    }

    /// Injects a packet directly into this transport's inbox.
    pub fn inject_packet(&self, data: &[u8], from: &str) -> Result<()> {
        if *self.closed.lock().unwrap() {
            return Err(TransportError::Closed);
        }
        let sender = self.sender.lock().unwrap();
        sender
            .as_ref()
            .ok_or(TransportError::Closed)?
            .send(MockPacket {
                data: data.to_vec(),
                from: MockAddr::new(from),
            })
            .map_err(|_| TransportError::InboxFull)
    }
}

impl Transport for MockTransport {
    fn send_to(&self, data: &[u8], _addr: &dyn Addr) -> Result<()> {
        if *self.closed.lock().unwrap() {
            return Err(TransportError::Closed);
        }
        let peer = self.peer.lock().unwrap();
        let peer = peer.as_ref().ok_or(TransportError::NoPeer)?;

        if *peer.closed.lock().unwrap() {
            return Err(TransportError::Closed);
        }

        let sender = peer.sender.lock().unwrap();
        sender
            .as_ref()
            .ok_or(TransportError::Closed)?
            .send(MockPacket {
                data: data.to_vec(),
                from: self.local_addr.clone(),
            })
            .map_err(|_| TransportError::InboxFull)
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Box<dyn Addr>)> {
        // Don't hold the lock while blocking on recv
        {
            if *self.closed.lock().unwrap() {
                return Err(TransportError::Closed);
            }
        }
        let inbox = self.inbox.lock().unwrap();
        let packet = inbox.recv().map_err(|_| TransportError::Closed)?;
        let n = std::cmp::min(buf.len(), packet.data.len());
        buf[..n].copy_from_slice(&packet.data[..n]);
        Ok((n, Box::new(packet.from)))
    }

    fn close(&self) -> Result<()> {
        let mut closed = self.closed.lock().unwrap();
        if *closed {
            return Ok(());
        }
        *closed = true;
        // Drop the sender to unblock any recv() calls
        let mut sender = self.sender.lock().unwrap();
        *sender = None;
        Ok(())
    }

    fn local_addr(&self) -> Box<dyn Addr> {
        Box::new(self.local_addr.clone())
    }

    fn set_read_deadline(&self, _deadline: Option<Instant>) -> Result<()> {
        // No-op for mock transport
        Ok(())
    }

    fn set_write_deadline(&self, _deadline: Option<Instant>) -> Result<()> {
        // No-op for mock transport
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_addr() {
        let addr = MockAddr::new("test-addr");
        assert_eq!(addr.network(), "mock");
        assert_eq!(addr.addr_string(), "test-addr");
    }

    #[test]
    fn test_mock_transport_send_recv() {
        let t1 = MockTransport::new("peer1");
        let t2 = MockTransport::new("peer2");
        MockTransport::connect(&t1, &t2);

        // Send from t1 to t2
        let data = b"hello world";
        t1.send_to(data, &MockAddr::new("peer2")).unwrap();

        // Receive on t2
        let mut buf = [0u8; 1024];
        let (n, from) = t2.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], data);
        assert_eq!(from.addr_string(), "peer1");

        // Send back from t2 to t1
        t2.send_to(b"reply", &MockAddr::new("peer1")).unwrap();
        let (n, from) = t1.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"reply");
        assert_eq!(from.addr_string(), "peer2");
    }

    #[test]
    fn test_mock_transport_no_peer() {
        let t = MockTransport::new("alone");
        let err = t.send_to(b"test", &MockAddr::new("nobody")).unwrap_err();
        assert!(matches!(err, TransportError::NoPeer));
    }

    #[test]
    fn test_mock_transport_inject() {
        let t = MockTransport::new("test");
        t.inject_packet(b"injected", "sender").unwrap();

        let mut buf = [0u8; 1024];
        let (n, from) = t.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"injected");
        assert_eq!(from.addr_string(), "sender");
    }

}
