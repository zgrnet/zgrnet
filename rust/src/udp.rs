//! UDP Transport implementation.
//!
//! Provides a simple UDP transport that connects to a fixed remote address.
//! Does not support roaming - suitable for direct P2P connections.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

use crate::transport::{Addr, Transport, TransportError, Result};

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

/// UDP Transport over a connected UDP socket.
///
/// This transport connects to a fixed remote address and does not support
/// roaming. Suitable for simple P2P connections where the remote endpoint
/// has a stable address.
pub struct Udp {
    socket: UdpSocket,
    local_addr: UdpAddr,
    remote_addr: UdpAddr,
}

impl Udp {
    /// Create a new UDP transport.
    ///
    /// # Arguments
    /// * `local_addr` - Local address to bind to (e.g., "0.0.0.0:0" for any)
    /// * `remote_addr` - Remote address to connect to
    ///
    /// # Example
    /// ```no_run
    /// use noise::udp::Udp;
    /// let transport = Udp::new("0.0.0.0:0", "192.168.1.100:51820").unwrap();
    /// ```
    pub fn new(local_addr: &str, remote_addr: &str) -> io::Result<Self> {
        let local = UdpAddr::parse(local_addr)?;
        let remote = UdpAddr::parse(remote_addr)?;

        let socket = UdpSocket::bind(local.socket_addr())?;
        socket.connect(remote.socket_addr())?;

        // Get actual bound address
        let bound_addr = UdpAddr::new(socket.local_addr()?);

        Ok(Self {
            socket,
            local_addr: bound_addr,
            remote_addr: remote,
        })
    }

    /// Create from an existing socket.
    pub fn from_socket(socket: UdpSocket, remote_addr: SocketAddr) -> io::Result<Self> {
        socket.connect(remote_addr)?;
        let local_addr = UdpAddr::new(socket.local_addr()?);
        let remote_addr = UdpAddr::new(remote_addr);

        Ok(Self {
            socket,
            local_addr,
            remote_addr,
        })
    }

    /// Get the local address.
    pub fn local_addr(&self) -> &UdpAddr {
        &self.local_addr
    }

    /// Get the remote address.
    pub fn remote_addr(&self) -> &UdpAddr {
        &self.remote_addr
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

impl Transport for Udp {
    fn send_to(&self, data: &[u8], _addr: &dyn Addr) -> Result<()> {
        // Ignore addr parameter - we're connected to a fixed remote
        self.socket.send(data).map_err(TransportError::Io)?;
        Ok(())
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Box<dyn Addr>)> {
        let n = self.socket.recv(buf).map_err(TransportError::Io)?;
        Ok((n, Box::new(self.remote_addr.clone())))
    }

    fn local_addr(&self) -> Box<dyn Addr> {
        Box::new(self.local_addr.clone())
    }

    fn close(&self) -> Result<()> {
        // UDP sockets don't need explicit close in Rust
        // Drop will handle it
        Ok(())
    }
}

impl Udp {
    /// Send data (convenience method).
    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        self.socket.send(data)
    }

    /// Receive data (convenience method).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
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

    #[test]
    fn test_udp_new() {
        // Create server
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        // Create client transport
        let client = Udp::new("127.0.0.1:0", &server_addr.to_string()).unwrap();

        assert_eq!(client.remote_addr().socket_addr(), server_addr);
        assert_eq!(client.local_addr().network(), "udp");
    }

    #[test]
    fn test_udp_send_recv() {
        // Create two transports
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let client = Udp::new("127.0.0.1:0", &server_addr.to_string()).unwrap();
        let client_addr = client.local_addr().socket_addr();

        // Connect server to client
        server_socket.connect(client_addr).unwrap();

        // Send from client
        let data = b"hello world";
        client.send(data).unwrap();

        // Receive on server
        let mut buf = [0u8; 1024];
        let n = server_socket.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &data[..]);

        // Send from server
        let response = b"goodbye";
        server_socket.send(response).unwrap();

        // Receive on client
        let n = client.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &response[..]);
    }

    #[test]
    fn test_udp_implements_transport() {
        fn assert_transport<T: Transport>() {}
        assert_transport::<Udp>();
    }
}
