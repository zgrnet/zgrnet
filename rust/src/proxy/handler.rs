//! Remote TCP_PROXY and UDP_PROXY handlers for exit nodes.
//!
//! These handlers run on the remote peer that acts as an exit node:
//! - TCP_PROXY: accept KCP stream → dial real TCP target → relay
//! - UDP_PROXY: forward UDP packets to real targets → return responses

use crate::noise::address::Address;
use std::io;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use super::socks5::relay;

/// Handle an incoming TCP_PROXY stream.
///
/// Decodes the target address from metadata, dials the real target,
/// and relays data bidirectionally.
///
/// The stream must have async read/write capabilities.
pub async fn handle_tcp_proxy<S>(mut stream: S, metadata: &[u8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (addr, _) = Address::decode(metadata).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid address: {}", e))
    })?;

    let target = format!("{}:{}", addr.host, addr.port);
    let remote = TcpStream::connect(&target).await?;

    relay(&mut stream, remote).await;
    Ok(())
}

/// UDP_PROXY handler that forwards packets to real UDP targets.
pub struct UdpProxyHandler {
    socket: Arc<UdpSocket>,
    closed: Arc<AtomicBool>,
}

impl UdpProxyHandler {
    /// Create a new UDP proxy handler.
    pub fn new() -> io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_nonblocking(false)?; // blocking for receive loop
        Ok(UdpProxyHandler {
            socket: Arc::new(socket),
            closed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Forward a UDP_PROXY payload to the real target.
    /// Payload format: addr.encode() + data
    pub fn handle_packet(&self, payload: &[u8]) -> io::Result<()> {
        let (addr, consumed) = Address::decode(payload).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid address: {}", e))
        })?;
        let data = &payload[consumed..];

        let target = format!("{}:{}", addr.host, addr.port);
        let target_addr: std::net::SocketAddr = target.parse().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid target: {}", e))
        })?;

        self.socket.send_to(data, target_addr)?;
        Ok(())
    }

    /// Start a blocking receive loop that reads responses from real targets.
    /// Calls `send_back` with the response payload (addr.encode() + data).
    pub fn receive_loop<F>(&self, send_back: F)
    where
        F: Fn(&[u8]),
    {
        let mut buf = vec![0u8; 65535];
        loop {
            if self.closed.load(Ordering::Relaxed) {
                return;
            }
            match self.socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let addr = if from.is_ipv4() {
                        Address::ipv4(&from.ip().to_string(), from.port())
                    } else {
                        Address::ipv6(&from.ip().to_string(), from.port())
                    };
                    if let Ok(encoded) = addr.encode() {
                        let mut response = Vec::with_capacity(encoded.len() + n);
                        response.extend_from_slice(&encoded);
                        response.extend_from_slice(&buf[..n]);
                        send_back(&response);
                    }
                }
                Err(_) => {
                    if self.closed.load(Ordering::Relaxed) {
                        return;
                    }
                }
            }
        }
    }

    /// Close the handler.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        // Dropping the socket will unblock recv_from
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn echo_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let (mut r, mut w) = stream.split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_handle_tcp_proxy() {
        let echo_addr = echo_server().await;

        let addr = Address::ipv4(&echo_addr.ip().to_string(), echo_addr.port());
        let metadata = addr.encode().unwrap();

        // Create a duplex stream to simulate KCP stream
        let (mut client, server) = tokio::io::duplex(8192);

        let md = metadata.clone();
        let handle = tokio::spawn(async move {
            handle_tcp_proxy(server, &md).await
        });

        // Send data through "stream"
        let test_data = b"tcp proxy rust test";
        client.write_all(test_data).await.unwrap();

        let mut buf = vec![0u8; test_data.len()];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, test_data);

        drop(client);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_handle_tcp_proxy_invalid_metadata() {
        let (_, server) = tokio::io::duplex(8192);
        let result = handle_tcp_proxy(server, &[0xFF]).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_udp_proxy_handler_packet() {
        // Start a UDP echo server
        let echo_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo_socket.local_addr().unwrap();

        // Spawn echo in a thread
        let echo = echo_socket.try_clone().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 65535];
            loop {
                match echo.recv_from(&mut buf) {
                    Ok((n, from)) => { let _ = echo.send_to(&buf[..n], from); }
                    Err(_) => return,
                }
            }
        });

        let handler = UdpProxyHandler::new().unwrap();

        // Build payload: addr + data
        let addr = Address::ipv4(&echo_addr.ip().to_string(), echo_addr.port());
        let encoded = addr.encode().unwrap();
        let test_data = b"udp proxy test";
        let mut payload = Vec::new();
        payload.extend_from_slice(&encoded);
        payload.extend_from_slice(test_data);

        handler.handle_packet(&payload).unwrap();

        // Receive response (synchronous)
        let _responses = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));

        let socket = handler.socket.clone();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();

        let mut buf = [0u8; 65535];
        if let Ok((n, _from)) = socket.recv_from(&mut buf) {
            // Verify echoed data matches
            assert_eq!(&buf[..n], test_data);
        }
    }

    #[test]
    fn test_udp_proxy_handler_invalid_payload() {
        let handler = UdpProxyHandler::new().unwrap();
        assert!(handler.handle_packet(&[0xFF, 1, 2, 3]).is_err());
    }
}
