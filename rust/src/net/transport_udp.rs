//! UDP Transport implementation.
//!
//! Provides a simple UDP transport that connects to a fixed remote address.
//! Does not support roaming - suitable for direct P2P connections.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Instant;

use crate::noise::transport::{Addr, Result, Transport, TransportError};

/// UDP address wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UdpAddr {
    addr: SocketAddr,
}

impl UdpAddr {
    /// Create a new UDP address.
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// Parse from string.
    pub fn parse(s: &str) -> io::Result<Self> {
        let addr = s
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address found"))?;
        Ok(Self { addr })
    }

    /// Get the underlying socket address.
    pub fn socket_addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Addr for UdpAddr {
    fn network(&self) -> &str {
        "udp"
    }

    fn addr_string(&self) -> String {
        self.addr.to_string()
    }

    fn clone_box(&self) -> Box<dyn Addr> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Unconnected UDP Transport.
///
/// This transport can send/receive to/from any address, suitable for
/// servers or listeners that need to communicate with multiple peers.
pub struct UdpTransport {
    socket: UdpSocket,
    local_addr: UdpAddr,
}

impl UdpTransport {
    /// Bind to a local address.
    ///
    /// # Arguments
    /// * `addr` - Local address to bind to (e.g., "127.0.0.1:0" for any available port)
    ///
    /// # Example
    /// ```ignore
    /// use zgrnet::net::transport_udp::UdpTransport;
    /// let transport = UdpTransport::bind("127.0.0.1:0").unwrap();
    /// ```
    pub fn bind(addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        let bound_addr = UdpAddr::new(socket.local_addr()?);

        Ok(Self {
            socket,
            local_addr: bound_addr,
        })
    }

    /// Get the local address.
    pub fn local_address(&self) -> &UdpAddr {
        &self.local_addr
    }

    /// Set read timeout.
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    /// Set write timeout.
    pub fn set_write_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(timeout)
    }

    /// Get underlying socket (for advanced configuration).
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

impl Transport for UdpTransport {
    fn send_to(&self, data: &[u8], addr: &dyn Addr) -> Result<()> {
        let socket_addr: SocketAddr = if let Some(udp_addr) = addr.as_any().downcast_ref::<UdpAddr>() {
            udp_addr.socket_addr()
        } else {
            addr.addr_string()
                .parse()
                .map_err(|_| TransportError::InvalidAddress)?
        };
        self.socket.send_to(data, socket_addr).map_err(TransportError::Io)?;
        Ok(())
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Box<dyn Addr>)> {
        let (n, addr) = self.socket.recv_from(buf).map_err(TransportError::Io)?;
        Ok((n, Box::new(UdpAddr::new(addr))))
    }

    fn local_addr(&self) -> Box<dyn Addr> {
        Box::new(self.local_addr.clone())
    }

    fn close(&self) -> Result<()> {
        // UDP sockets don't need explicit close in Rust
        Ok(())
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        let timeout = deadline.map(|d| d.saturating_duration_since(Instant::now()));
        self.socket
            .set_read_timeout(timeout)
            .map_err(TransportError::Io)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        let timeout = deadline.map(|d| d.saturating_duration_since(Instant::now()));
        self.socket
            .set_write_timeout(timeout)
            .map_err(TransportError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_addr_parse() {
        let addr = UdpAddr::parse("127.0.0.1:8080").unwrap();
        assert_eq!(addr.network(), "udp");
        assert_eq!(addr.addr_string(), "127.0.0.1:8080");
    }

}
