//! ServiceMux — per-service KCP + yamux stream multiplexing.
//!
//! Each service gets its own KcpConn (independent thread) + yamux Connection
//! (stream multiplexing). Different services are fully isolated at the KCP level.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio_util::compat::TokioAsyncReadCompatExt;
use yamux;

use super::conn::KcpConn;
use super::async_conn::AsyncKcpConn;

/// Output function: called to send KCP packets for a specific service.
pub type ServiceOutputFn = Arc<dyn Fn(u64, &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> + Send + Sync>;

/// Configuration for ServiceMux.
pub struct ServiceMuxConfig {
    pub is_client: bool,
    pub output: ServiceOutputFn,
}

struct ServiceEntry {
    conn: Arc<KcpConn>,
    open_tx: tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<Result<yamux::Stream, String>>>,
}

/// ServiceMux manages per-service KCP instances and yamux sessions for a peer.
pub struct ServiceMux {
    config: ServiceMuxConfig,
    services: RwLock<HashMap<u64, ServiceEntry>>,
    accept_tx: tokio::sync::mpsc::Sender<(yamux::Stream, u64)>,
    accept_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(yamux::Stream, u64)>>,
    closed: AtomicBool,
}

impl ServiceMux {
    pub fn new(config: ServiceMuxConfig) -> Arc<Self> {
        let (accept_tx, accept_rx) = tokio::sync::mpsc::channel(4096);
        Arc::new(ServiceMux {
            config,
            services: RwLock::new(HashMap::new()),
            accept_tx,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            closed: AtomicBool::new(false),
        })
    }

    /// Feed an incoming KCP packet to the correct service.
    pub fn input(&self, service: u64, data: &[u8]) -> Result<(), String> {
        if self.closed.load(Ordering::Relaxed) {
            return Err("service mux closed".into());
        }

        {
            let services = self.services.read().unwrap();
            if let Some(entry) = services.get(&service) {
                return entry.conn.input(data).map_err(|e| e.to_string());
            }
        }

        self.create_service(service)?;
        let services = self.services.read().unwrap();
        if let Some(entry) = services.get(&service) {
            entry.conn.input(data).map_err(|e| e.to_string())
        } else {
            Err("failed to create service".into())
        }
    }

    /// Open a yamux stream on the given service.
    pub async fn open_stream(&self, service: u64) -> Result<yamux::Stream, String> {
        if self.closed.load(Ordering::Relaxed) {
            return Err("service mux closed".into());
        }

        self.ensure_service(service)?;

        let open_tx = {
            let services = self.services.read().unwrap();
            services.get(&service)
                .ok_or_else(|| "service not found".to_string())?
                .open_tx.clone()
        };

        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        open_tx.send(result_tx).await.map_err(|_| "open channel closed".to_string())?;
        result_rx.await.map_err(|_| "open result cancelled".to_string())?
    }

    /// Accept the next yamux stream from any service.
    pub async fn accept_stream(&self) -> Result<(yamux::Stream, u64), String> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv().await.ok_or_else(|| "accept channel closed".into())
    }

    /// Close all services.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let mut services = self.services.write().unwrap();
        services.clear();
    }

    /// Number of active services.
    pub fn num_services(&self) -> usize {
        self.services.read().unwrap().len()
    }

    fn ensure_service(&self, service: u64) -> Result<(), String> {
        {
            let services = self.services.read().unwrap();
            if services.contains_key(&service) {
                return Ok(());
            }
        }
        self.create_service(service)
    }

    fn create_service(&self, service: u64) -> Result<(), String> {
        let mut services = self.services.write().unwrap();
        if services.contains_key(&service) {
            return Ok(());
        }

        if self.closed.load(Ordering::Relaxed) {
            return Err("service mux closed".into());
        }

        let output = self.config.output.clone();
        let svc = service;
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel(256);

        let conn = Arc::new(KcpConn::new(
            service as u32,
            Box::new(move |data: &[u8]| {
                let _ = output(svc, data);
            }),
            recv_tx,
        ));

        let async_conn = AsyncKcpConn::new(conn.clone(), recv_rx);
        let compat_conn = async_conn.compat();

        let yamux_config = yamux::Config::default();
        let mode = if self.config.is_client {
            yamux::Mode::Client
        } else {
            yamux::Mode::Server
        };

        let connection = yamux::Connection::new(compat_conn, yamux_config, mode);

        let (open_tx, open_rx) = tokio::sync::mpsc::channel(64);
        let accept_tx = self.accept_tx.clone();

        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| "no tokio runtime available".to_string())?;
        handle.spawn(yamux_driver(connection, service, open_rx, accept_tx));

        services.insert(service, ServiceEntry { conn, open_tx });
        Ok(())
    }
}

/// Drives a yamux Connection in a single task.
/// Handles both inbound stream acceptance and outbound stream opening.
async fn yamux_driver(
    mut connection: yamux::Connection<tokio_util::compat::Compat<AsyncKcpConn>>,
    service: u64,
    mut open_rx: tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<Result<yamux::Stream, String>>>,
    accept_tx: tokio::sync::mpsc::Sender<(yamux::Stream, u64)>,
) {
    use std::task::Poll;

    loop {
        // Create a future that polls both inbound and open requests
        let result = YamuxPollFuture {
            connection: &mut connection,
            open_rx: &mut open_rx,
        }.await;

        match result {
            YamuxEvent::Inbound(Ok(stream)) => {
                let _ = accept_tx.send((stream, service)).await;
            }
            YamuxEvent::Inbound(Err(_)) => return,
            YamuxEvent::InboundDone => return,
            YamuxEvent::OpenRequest(result_tx) => {
                let poll_result = std::future::poll_fn(|cx| {
                    connection.poll_new_outbound(cx)
                }).await;
                let _ = result_tx.send(poll_result.map_err(|e| e.to_string()));
            }
            YamuxEvent::OpenChannelClosed => return,
        }
    }
}

enum YamuxEvent {
    Inbound(Result<yamux::Stream, yamux::ConnectionError>),
    InboundDone,
    OpenRequest(tokio::sync::oneshot::Sender<Result<yamux::Stream, String>>),
    OpenChannelClosed,
}

struct YamuxPollFuture<'a, T> {
    connection: &'a mut yamux::Connection<T>,
    open_rx: &'a mut tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<Result<yamux::Stream, String>>>,
}

impl<'a, T> Future for YamuxPollFuture<'a, T>
where
    T: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    type Output = YamuxEvent;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<YamuxEvent> {
        // Check for inbound streams
        match self.connection.poll_next_inbound(cx) {
            Poll::Ready(Some(result)) => return Poll::Ready(YamuxEvent::Inbound(result)),
            Poll::Ready(None) => return Poll::Ready(YamuxEvent::InboundDone),
            Poll::Pending => {}
        }

        // Check for open requests
        match self.open_rx.poll_recv(cx) {
            Poll::Ready(Some(tx)) => return Poll::Ready(YamuxEvent::OpenRequest(tx)),
            Poll::Ready(None) => return Poll::Ready(YamuxEvent::OpenChannelClosed),
            Poll::Pending => {}
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::{AsyncReadExt, AsyncWriteExt};

    fn service_mux_pair() -> (Arc<ServiceMux>, Arc<ServiceMux>) {
        use std::sync::Mutex;
        let server_mux_slot: Arc<Mutex<Option<Arc<ServiceMux>>>> = Arc::new(Mutex::new(None));
        let client_mux_slot: Arc<Mutex<Option<Arc<ServiceMux>>>> = Arc::new(Mutex::new(None));

        let s_slot = server_mux_slot.clone();
        let client = ServiceMux::new(ServiceMuxConfig {
            is_client: true,
            output: Arc::new(move |service, data| {
                if let Some(ref s) = *s_slot.lock().unwrap() {
                    s.input(service, data)?;
                }
                Ok(())
            }),
        });

        let c_slot = client_mux_slot.clone();
        let server = ServiceMux::new(ServiceMuxConfig {
            is_client: false,
            output: Arc::new(move |service, data| {
                if let Some(ref c) = *c_slot.lock().unwrap() {
                    c.input(service, data)?;
                }
                Ok(())
            }),
        });

        *server_mux_slot.lock().unwrap() = Some(server.clone());
        *client_mux_slot.lock().unwrap() = Some(client.clone());

        (client, server)
    }

    #[tokio::test]
    async fn test_yamux_open_close() {
        let (client, server) = service_mux_pair();

        let mut stream = client.open_stream(1).await.unwrap();
        let (mut accepted, svc) = server.accept_stream().await.unwrap();
        assert_eq!(svc, 1);

        stream.close().await.unwrap();
        accepted.close().await.unwrap();
        client.close();
        server.close();
    }

    #[tokio::test]
    async fn test_yamux_bidirectional() {
        let (client, server) = service_mux_pair();

        let mut c_stream = client.open_stream(1).await.unwrap();
        let (mut s_stream, _) = server.accept_stream().await.unwrap();

        c_stream.write_all(b"from client").await.unwrap();
        s_stream.write_all(b"from server").await.unwrap();

        let mut buf = vec![0u8; 256];
        let n = s_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from client");

        let n = c_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from server");

        c_stream.close().await.unwrap();
        s_stream.close().await.unwrap();
        client.close();
        server.close();
    }

    #[tokio::test]
    async fn test_yamux_multi_stream_10() {
        let (client, server) = service_mux_pair();

        let server2 = server.clone();
        let accept_handle = tokio::spawn(async move {
            for _ in 0..10 {
                let (mut s, _) = server2.accept_stream().await.unwrap();
                let mut buf = vec![0u8; 256];
                let n = s.read(&mut buf).await.unwrap();
                s.write_all(&buf[..n]).await.unwrap();
                s.close().await.unwrap();
            }
        });

        for i in 0..10 {
            let mut s = client.open_stream(1).await.unwrap();
            let msg = format!("msg-{}", i);
            s.write_all(msg.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; 256];
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
            s.close().await.unwrap();
        }

        accept_handle.await.unwrap();
        client.close();
        server.close();
    }

    #[tokio::test]
    async fn test_smux_multi_service_3() {
        let (client, server) = service_mux_pair();

        let server2 = server.clone();
        let accept_handle = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut s, svc) = server2.accept_stream().await.unwrap();
                let echo = format!("echo-svc{}", svc);
                s.write_all(echo.as_bytes()).await.unwrap();
                s.close().await.unwrap();
            }
        });

        for svc in [1u64, 2, 3] {
            let mut s = client.open_stream(svc).await.unwrap();
            let mut buf = vec![0u8; 256];
            let n = s.read(&mut buf).await.unwrap();
            let response = std::str::from_utf8(&buf[..n]).unwrap();
            assert!(response.starts_with("echo-svc"), "got: {}", response);
            s.close().await.unwrap();
        }

        accept_handle.await.unwrap();
        assert_eq!(client.num_services(), 3);
        assert_eq!(server.num_services(), 3);

        client.close();
        server.close();
    }

    #[tokio::test]
    async fn test_composite_1x100() {
        let (client, server) = service_mux_pair();

        let server2 = server.clone();
        let accept_handle = tokio::spawn(async move {
            for _ in 0..100 {
                let (mut s, _) = server2.accept_stream().await.unwrap();
                let mut buf = vec![0u8; 256];
                let n = s.read(&mut buf).await.unwrap();
                s.write_all(&buf[..n]).await.unwrap();
                s.close().await.unwrap();
            }
        });

        for i in 0..100 {
            let mut s = client.open_stream(1).await.unwrap();
            let msg = format!("s{}", i);
            s.write_all(msg.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; 256];
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
            s.close().await.unwrap();
        }

        accept_handle.await.unwrap();
        client.close();
        server.close();
    }
}
