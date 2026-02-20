//! ServiceMux — per-service KCP + yamux stream multiplexing.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::conn::KcpConn;

/// Output function for ServiceMux.
pub type ServiceOutputFn = Arc<dyn Fn(u64, &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> + Send + Sync>;

/// Configuration for ServiceMux.
pub struct ServiceMuxConfig {
    pub is_client: bool,
    pub output: ServiceOutputFn,
}

struct ServiceEntry {
    conn: KcpConn,
    open_tx: tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<Result<yamux::Stream, String>>>,
}

/// ServiceMux manages per-service KCP + yamux sessions.
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

    /// Feed incoming KCP packet to the correct service.
    pub fn input(&self, service: u64, data: &[u8]) {
        if self.closed.load(Ordering::Relaxed) { return; }

        let entry = {
            let services = self.services.read().unwrap();
            services.get(&service).cloned()
        };

        if let Some(entry) = entry {
            entry.conn.queue_input(data);
        } else {
            if let Ok(entry) = self.create_service(service) {
                entry.conn.queue_input(data);
            }
        }
    }

    pub async fn open_stream(&self, service: u64) -> Result<yamux::Stream, String> {
        if self.closed.load(Ordering::Relaxed) {
            return Err("closed".into());
        }

        let entry = self.ensure_service(service)?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        entry.open_tx.send(tx).await.map_err(|_| "channel closed".to_string())?;
        rx.await.map_err(|_| "cancelled".to_string())?
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
            let services = self.services.read().unwrap();
            if let Some(e) = services.get(&service) {
                return Ok(e.clone());
            }
        }
        self.create_service(service)
    }

    fn create_service(&self, service: u64) -> Result<Arc<ServiceEntry>, String> {
        let mut services = self.services.write().unwrap();
        if let Some(e) = services.get(&service) {
            return Ok(e.clone());
        }
        if self.closed.load(Ordering::Relaxed) {
            return Err("closed".into());
        }

        let output = self.config.output.clone();
        let svc = service;
        let conn = KcpConn::new(service as u32, Arc::new(move |data: &[u8]| {
            let _ = output(svc, data);
        }));

        let mode = if self.config.is_client {
            yamux::Mode::Client
        } else {
            yamux::Mode::Server
        };

        let yamux_conn = yamux::Connection::new(conn, yamux::Config::default(), mode);

        let (open_tx, open_rx) = tokio::sync::mpsc::channel(64);
        let accept_tx = self.accept_tx.clone();

        tokio::spawn(yamux_driver(yamux_conn, service, open_rx, accept_tx));

        let entry = Arc::new(ServiceEntry { conn: KcpConn::new(service as u32, Arc::new(|_: &[u8]| {})), open_tx });

        // We need to create the conn once and share it. The conn was moved into yamux.
        // Rethink: we need the conn for input(), but yamux owns it.
        // Solution: the conn's output function sends via the outer output.
        // For input, we access the KcpInner directly.

        // Actually, the KcpConn was moved into yamux::Connection. We can't call
        // try_input on it anymore. We need to keep a reference to the inner.
        drop(services);
        drop(entry);

        // Redesign: create KcpConn, get its inner Arc, then move the conn into yamux.
        self.create_service_v2(service)
    }

    fn create_service_v2(&self, service: u64) -> Result<Arc<ServiceEntry>, String> {
        let mut services = self.services.write().unwrap();
        if let Some(e) = services.get(&service) {
            return Ok(e.clone());
        }

        let output = self.config.output.clone();
        let svc = service;
        let conn = KcpConn::new(service as u32, Arc::new(move |data: &[u8]| {
            let _ = output(svc, data);
        }));

        // Keep a reference to the inner for input()
        let inner_ref = conn.inner();

        let mode = if self.config.is_client {
            yamux::Mode::Client
        } else {
            yamux::Mode::Server
        };

        let yamux_conn = yamux::Connection::new(conn, yamux::Config::default(), mode);

        let (open_tx, open_rx) = tokio::sync::mpsc::channel(64);
        let accept_tx = self.accept_tx.clone();

        tokio::spawn(yamux_driver(yamux_conn, service, open_rx, accept_tx));

        // Create a "shell" KcpConn that shares the same inner for input()
        let input_conn = KcpConn::from_inner(inner_ref);

        let entry = Arc::new(ServiceEntry { conn: input_conn, open_tx });
        services.insert(service, entry.clone());
        Ok(entry)
    }
}

async fn yamux_driver(
    mut connection: yamux::Connection<KcpConn>,
    service: u64,
    mut open_rx: tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<Result<yamux::Stream, String>>>,
    accept_tx: tokio::sync::mpsc::Sender<(yamux::Stream, u64)>,
) {
    // Use separate tasks for inbound and outbound since yamux
    // poll_new_outbound and poll_next_inbound both need &mut self.
    // Drive them in a single task alternating via poll_fn.
    loop {
        tokio::select! {
            result = futures::future::poll_fn(|cx| connection.poll_next_inbound(cx)) => {
                match result {
                    Some(Ok(stream)) => {
                        let _ = accept_tx.send((stream, service)).await;
                    }
                    _ => return,
                }
            }
            Some(tx) = open_rx.recv() => {
                let result = futures::future::poll_fn(|cx| connection.poll_new_outbound(cx)).await;
                let _ = tx.send(result.map_err(|e| e.to_string()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use futures::io::{AsyncReadExt, AsyncWriteExt};

    fn service_mux_pair() -> (Arc<ServiceMux>, Arc<ServiceMux>) {
        let server_slot: Arc<Mutex<Option<Arc<ServiceMux>>>> = Arc::new(Mutex::new(None));
        let client_slot: Arc<Mutex<Option<Arc<ServiceMux>>>> = Arc::new(Mutex::new(None));

        let s_ref = server_slot.clone();
        let client = ServiceMux::new(ServiceMuxConfig {
            is_client: true,
            output: Arc::new(move |service, data| {
                if let Some(ref s) = *s_ref.lock().unwrap() {
                    s.input(service, data);
                }
                Ok(())
            }),
        });

        let c_ref = client_slot.clone();
        let server = ServiceMux::new(ServiceMuxConfig {
            is_client: false,
            output: Arc::new(move |service, data| {
                if let Some(ref c) = *c_ref.lock().unwrap() {
                    c.input(service, data);
                }
                Ok(())
            }),
        });

        *server_slot.lock().unwrap() = Some(server.clone());
        *client_slot.lock().unwrap() = Some(client.clone());

        (client, server)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_yamux_bidirectional() {
        let (client, server) = service_mux_pair();

        let mut cs = client.open_stream(1).await.unwrap();
        let (mut ss, _) = server.accept_stream().await.unwrap();

        cs.write_all(b"from client").await.unwrap();
        ss.write_all(b"from server").await.unwrap();

        let mut buf = vec![0u8; 256];
        let n = ss.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from client");

        let n = cs.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from server");

        cs.close().await.unwrap();
        ss.close().await.unwrap();
        client.close();
        server.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_smux_multi_service_3() {
        let (client, server) = service_mux_pair();

        let server2 = server.clone();
        let accept = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut s, svc) = server2.accept_stream().await.unwrap();
                let echo = format!("echo-{}", svc);
                s.write_all(echo.as_bytes()).await.unwrap();
                s.close().await.unwrap();
            }
        });

        for svc in [1u64, 2, 3] {
            let mut s = client.open_stream(svc).await.unwrap();
            let mut buf = vec![0u8; 256];
            let n = s.read(&mut buf).await.unwrap();
            assert!(std::str::from_utf8(&buf[..n]).unwrap().starts_with("echo-"));
            s.close().await.unwrap();
        }

        accept.await.unwrap();
        assert_eq!(client.num_services(), 3);
        client.close();
        server.close();
    }
}
