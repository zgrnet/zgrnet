//! ServiceMux — per-service KCP + yamux stream multiplexing.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

use futures::TryStreamExt;

use super::conn::KcpConn;

pub type ServiceOutputFn = Arc<dyn Fn(u64, &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> + Send + Sync>;

pub struct ServiceMuxConfig {
    pub is_client: bool,
    pub output: ServiceOutputFn,
}

struct ServiceEntry {
    input_conn: KcpConn,
    open_tx: tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<yamux::Stream>>,
}

pub struct ServiceMux {
    config: ServiceMuxConfig,
    services: RwLock<HashMap<u64, Arc<ServiceEntry>>>,
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

    pub fn input(&self, service: u64, data: &[u8]) {
        if self.closed.load(Ordering::Relaxed) { return; }
        let entry = {
            let s = self.services.read().unwrap();
            s.get(&service).cloned()
        };
        if let Some(e) = entry {
            e.input_conn.input(data);
        } else if let Ok(e) = self.create_service(service) {
            e.input_conn.input(data);
        }
    }

    pub async fn open_stream(&self, service: u64) -> Result<yamux::Stream, String> {
        if self.closed.load(Ordering::Relaxed) { return Err("closed".into()); }
        let entry = self.ensure_service(service)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        entry.open_tx.send(tx).await.map_err(|_| "channel closed".to_string())?;
        rx.await.map_err(|_| "cancelled".to_string())
    }

    pub async fn accept_stream(&self) -> Result<(yamux::Stream, u64), String> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv().await.ok_or_else(|| "closed".into())
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.services.write().unwrap().clear();
    }

    pub fn num_services(&self) -> usize {
        self.services.read().unwrap().len()
    }

    fn ensure_service(&self, service: u64) -> Result<Arc<ServiceEntry>, String> {
        {
            let s = self.services.read().unwrap();
            if let Some(e) = s.get(&service) { return Ok(e.clone()); }
        }
        self.create_service(service)
    }

    fn create_service(&self, service: u64) -> Result<Arc<ServiceEntry>, String> {
        let mut services = self.services.write().unwrap();
        if let Some(e) = services.get(&service) { return Ok(e.clone()); }
        if self.closed.load(Ordering::Relaxed) { return Err("closed".into()); }

        let output = self.config.output.clone();
        let svc = service;
        let conn = KcpConn::new(service as u32, Arc::new(move |data: &[u8]| {
            let _ = output(svc, data);
        }));

        let inner_ref = conn.inner_ref();
        let closed_ref = conn.closed_ref();
        let notifier_ref = conn.notifier_ref();

        let mode = if self.config.is_client { yamux::Mode::Client } else { yamux::Mode::Server };
        let yamux_conn = yamux::Connection::new(conn, yamux::Config::default(), mode);

        let (open_tx, open_rx) = tokio::sync::mpsc::channel(64);
        let accept_tx = self.accept_tx.clone();
        let is_client = self.config.is_client;

        if is_client {
            // Client: driver pattern with open requests + poll_next_inbound
            tokio::spawn(client_driver(yamux_conn, open_rx, accept_tx, service));
        } else {
            // Server: stream::poll_fn + try_for_each_concurrent
            tokio::spawn(server_driver(yamux_conn, accept_tx, service));
        }

        let input_conn = KcpConn::from_parts(inner_ref, closed_ref, notifier_ref);
        let entry = Arc::new(ServiceEntry { input_conn, open_tx });
        services.insert(service, entry.clone());
        Ok(entry)
    }
}

/// Client driver: verified pattern from TCP test.
/// Drives yamux Connection: handles open requests and inbound streams.
async fn client_driver(
    mut conn: yamux::Connection<KcpConn>,
    mut open_rx: tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<yamux::Stream>>,
    accept_tx: tokio::sync::mpsc::Sender<(yamux::Stream, u64)>,
    service: u64,
) {
    let mut pending: Vec<tokio::sync::oneshot::Sender<yamux::Stream>> = Vec::new();

    futures::future::poll_fn(|cx| {
        loop {
            let mut progress = false;

            while let Poll::Ready(Some(tx)) = open_rx.poll_recv(cx) {
                pending.push(tx);
                progress = true;
            }

            while !pending.is_empty() {
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(Ok(s)) => { let _ = pending.remove(0).send(s); progress = true; }
                    Poll::Ready(Err(_)) => { pending.remove(0); progress = true; }
                    Poll::Pending => break,
                }
            }

            match conn.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(s))) => {
                    let _ = accept_tx.try_send((s, service));
                    progress = true;
                    continue;
                }
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => {}
            }

            if !progress { return Poll::Pending; }
        }
    }).await;
}

/// Server driver: accepts inbound yamux streams.
async fn server_driver(
    mut conn: yamux::Connection<KcpConn>,
    accept_tx: tokio::sync::mpsc::Sender<(yamux::Stream, u64)>,
    service: u64,
) {
    futures::stream::poll_fn(|cx| conn.poll_next_inbound(cx))
        .try_for_each_concurrent(None, |stream| {
            let accept_tx = accept_tx.clone();
            async move {
                let _ = accept_tx.send((stream, service)).await;
                Ok(())
            }
        }).await.ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use futures::io::{AsyncReadExt, AsyncWriteExt};

    fn service_mux_pair() -> (Arc<ServiceMux>, Arc<ServiceMux>) {
        // Use channels to avoid SpinMutex AB-BA deadlock in output callbacks
        let (c_to_s_tx, mut c_to_s_rx) = tokio::sync::mpsc::unbounded_channel::<(u64, Vec<u8>)>();
        let (s_to_c_tx, mut s_to_c_rx) = tokio::sync::mpsc::unbounded_channel::<(u64, Vec<u8>)>();

        let client = ServiceMux::new(ServiceMuxConfig {
            is_client: true,
            output: Arc::new(move |service, data| {
                let _ = c_to_s_tx.send((service, data.to_vec()));
                Ok(())
            }),
        });

        let server = ServiceMux::new(ServiceMuxConfig {
            is_client: false,
            output: Arc::new(move |service, data| {
                let _ = s_to_c_tx.send((service, data.to_vec()));
                Ok(())
            }),
        });

        // Bridge tasks
        let s = server.clone();
        tokio::spawn(async move {
            while let Some((svc, data)) = c_to_s_rx.recv().await {
                s.input(svc, &data);
            }
        });

        let c = client.clone();
        tokio::spawn(async move {
            while let Some((svc, data)) = s_to_c_rx.recv().await {
                c.input(svc, &data);
            }
        });

        (client, server)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_service_mux_open_accept() {
        let (client, server) = service_mux_pair();

        // yamux defers SYN until first write, so we must write concurrently with accept.
        let server2 = server.clone();
        let accept_task = tokio::spawn(async move {
            server2.accept_stream().await.unwrap()
        });

        let mut cs = client.open_stream(1).await.unwrap();
        cs.write_all(b"hello service").await.unwrap();

        let (mut ss, svc) = tokio::time::timeout(
            std::time::Duration::from_secs(5), accept_task
        ).await.expect("accept timed out").unwrap();

        assert_eq!(svc, 1);
        let mut buf = vec![0u8; 256];
        let n = ss.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello service");
        cs.close().await.unwrap();
        ss.close().await.unwrap();
        client.close();
        server.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_service_mux_multi_service() {
        let (client, server) = service_mux_pair();

        let server2 = server.clone();
        let accept = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut s, _svc) = server2.accept_stream().await.unwrap();
                let mut buf = vec![0u8; 256];
                let n = s.read(&mut buf).await.unwrap();
                s.write_all(&buf[..n]).await.unwrap();
                s.close().await.unwrap();
            }
        });

        // yamux defers SYN until first write, so each stream must write first.
        for svc in [1u64, 2, 3] {
            let mut s = client.open_stream(svc).await.unwrap();
            let msg = format!("svc-{}", svc);
            s.write_all(msg.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; 256];
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
            s.close().await.unwrap();
        }

        accept.await.unwrap();
        assert_eq!(client.num_services(), 3);
        client.close();
        server.close();
    }

    /// PM Review BUG 3: accept backpressure — streams must not be silently dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_service_mux_accept_backpressure() {
        let (client, server) = service_mux_pair();

        let n_streams = 20;

        // Open many streams concurrently without accepting on server.
        let client2 = client.clone();
        let opener = tokio::spawn(async move {
            let mut streams = Vec::new();
            for i in 0..n_streams {
                let mut s = client2.open_stream(1).await.unwrap();
                let msg = format!("stream-{}", i);
                s.write_all(msg.as_bytes()).await.unwrap();
                streams.push(s);
            }
            streams
        });

        // Wait a bit, then accept all streams.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let mut received = 0;
        let server2 = server.clone();
        let acceptor = tokio::spawn(async move {
            let mut count = 0;
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    server2.accept_stream(),
                ).await {
                    Ok(Ok((_s, _svc))) => { count += 1; }
                    _ => break,
                }
            }
            count
        });

        let mut client_streams = opener.await.unwrap();
        for s in &mut client_streams { s.close().await.ok(); }

        received = acceptor.await.unwrap();
        assert!(received >= n_streams, "expected {} streams, got {}", n_streams, received);

        client.close();
        server.close();
    }

    /// PM Review issue 7: graceful shutdown with active streams.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_service_mux_shutdown_graceful() {
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (client, server) = service_mux_pair();

            let server2 = server.clone();
            let accept_task = tokio::spawn(async move {
                server2.accept_stream().await.unwrap()
            });

            let mut cs = client.open_stream(1).await.unwrap();
            cs.write_all(b"active stream").await.unwrap();

            let (mut ss, _svc) = accept_task.await.unwrap();
            let mut buf = vec![0u8; 256];
            let n = ss.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"active stream");

            // Close with active streams
            client.close();
            server.close();
        }).await;
        assert!(result.is_ok(), "graceful shutdown should complete within 5 seconds");
    }

    /// Bidirectional data on same service, multiple streams.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_service_mux_bidirectional_streams() {
        let (client, server) = service_mux_pair();

        let server2 = server.clone();
        let accept = tokio::spawn(async move {
            for _ in 0..5 {
                let (mut s, _svc) = server2.accept_stream().await.unwrap();
                let mut buf = vec![0u8; 1024];
                let n = s.read(&mut buf).await.unwrap();
                let response = format!("reply:{}", std::str::from_utf8(&buf[..n]).unwrap());
                s.write_all(response.as_bytes()).await.unwrap();
                s.close().await.unwrap();
            }
        });

        for i in 0..5 {
            let mut s = client.open_stream(1).await.unwrap();
            let msg = format!("msg-{}", i);
            s.write_all(msg.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            let expected = format!("reply:{}", msg);
            assert_eq!(&buf[..n], expected.as_bytes());
            s.close().await.unwrap();
        }

        accept.await.unwrap();
        client.close();
        server.close();
    }
}
