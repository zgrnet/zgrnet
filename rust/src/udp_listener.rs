//! UDP Listener Transport implementation.
//!
//! Provides an unconnected UDP transport that can send to and receive from
//! multiple remote addresses. Suitable for Host which manages multiple peers.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::transport::{Addr, Result, Transport, TransportError};
use crate::udp::UdpAddr;

/// UDP Listener over an unconnected UDP socket.
///
/// Can send to and receive from multiple remote addresses.
/// Suitable for Host which manages multiple peers on a single port.
pub struct UdpListener {
    socket: UdpSocket,
    local_addr: UdpAddr,
    closed: AtomicBool,
    // Mutex for thread-safe close
    close_lock: Mutex<()>,
}

impl UdpListener {
    /// Create a new UDP listener bound to the specified address.
    ///
    /// Use "0.0.0.0:0" to let the OS assign an available port.
    /// Use "0.0.0.0:51820" to bind to a specific port.
    pub fn bind(bind_addr: &str) -> io::Result<Self> {
        let addr = bind_addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address found"))?;

        let socket = UdpSocket::bind(addr)?;
        let local_addr = UdpAddr::new(socket.local_addr()?);

        Ok(Self {
            socket,
            local_addr,
            closed: AtomicBool::new(false),
            close_lock: Mutex::new(()),
        })
    }

    /// Get the local address.
    pub fn local_addr_udp(&self) -> &UdpAddr {
        &self.local_addr
    }

    /// Get the local port.
    pub fn port(&self) -> u16 {
        self.local_addr.socket_addr().port()
    }

    /// Set read timeout.
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    /// Set write timeout.
    pub fn set_write_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(timeout)
    }

    /// Check if closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

impl Transport for UdpListener {
    fn send_to(&self, data: &[u8], addr: &dyn Addr) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(TransportError::Closed);
        }

        // Convert to SocketAddr
        let socket_addr: SocketAddr = if let Some(udp_addr) = addr.as_any().downcast_ref::<UdpAddr>()
        {
            udp_addr.socket_addr()
        } else {
            // Try to parse from string
            addr.addr_string()
                .parse()
                .map_err(|_| TransportError::InvalidAddress)?
        };

        self.socket
            .send_to(data, socket_addr)
            .map_err(TransportError::Io)?;
        Ok(())
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Box<dyn Addr>)> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(TransportError::Closed);
        }

        let (n, addr) = self.socket.recv_from(buf).map_err(TransportError::Io)?;
        Ok((n, Box::new(UdpAddr::new(addr))))
    }

    fn local_addr(&self) -> Box<dyn Addr> {
        Box::new(self.local_addr.clone())
    }

    fn close(&self) -> Result<()> {
        let _lock = self.close_lock.lock().unwrap();
        self.closed.store(true, Ordering::SeqCst);
        // Note: UdpSocket doesn't have a close method in std
        // The socket will be closed when dropped
        Ok(())
    }
}

// Allow cloning the address for injection (testing)
impl UdpListener {
    /// Inject a packet (for testing). Not supported for real UDP.
    pub fn inject_packet(&self, _data: &[u8], _from: &dyn Addr) {
        // No-op for real UDP transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_listener_bind() {
        let listener = UdpListener::bind("127.0.0.1:0").unwrap();
        assert!(listener.port() > 0);
        assert!(!listener.is_closed());
    }

    #[test]
    fn test_udp_listener_send_recv() {
        let listener1 = UdpListener::bind("127.0.0.1:0").unwrap();
        let listener2 = UdpListener::bind("127.0.0.1:0").unwrap();

        let addr2 = listener2.local_addr();

        // Send from listener1 to listener2
        let data = b"hello world";
        listener1.send_to(data, addr2.as_ref()).unwrap();

        // Receive on listener2
        let mut buf = [0u8; 1024];
        let (n, from) = listener2.recv_from(&mut buf).unwrap();

        assert_eq!(&buf[..n], data);
        assert_eq!(from.addr_string(), listener1.local_addr().addr_string());
    }

    #[test]
    fn test_udp_listener_multiple_peers() {
        let server = UdpListener::bind("127.0.0.1:0").unwrap();
        let client1 = UdpListener::bind("127.0.0.1:0").unwrap();
        let client2 = UdpListener::bind("127.0.0.1:0").unwrap();

        let server_addr = server.local_addr();

        // Both clients send to server
        client1.send_to(b"from client1", server_addr.as_ref()).unwrap();
        client2.send_to(b"from client2", server_addr.as_ref()).unwrap();

        // Server receives both
        let mut buf = [0u8; 1024];
        let mut received = Vec::new();

        for _ in 0..2 {
            let (n, _from) = server.recv_from(&mut buf).unwrap();
            received.push(String::from_utf8_lossy(&buf[..n]).to_string());
        }

        assert!(received.contains(&"from client1".to_string()));
        assert!(received.contains(&"from client2".to_string()));
    }

    #[test]
    fn test_udp_listener_close() {
        let listener = UdpListener::bind("127.0.0.1:0").unwrap();
        assert!(!listener.is_closed());

        listener.close().unwrap();
        assert!(listener.is_closed());

        // Operations should fail after close
        let result = listener.send_to(b"test", &UdpAddr::parse("127.0.0.1:1234").unwrap());
        assert!(matches!(result, Err(TransportError::Closed)));
    }
}
