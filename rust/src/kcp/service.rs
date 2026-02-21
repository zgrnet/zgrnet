//! ServiceMux — per-service KCP + yamux stream multiplexing.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

use futures::TryStreamExt;

use super::conn::{KcpConn, KcpInput};

pub type ServiceOutputFn = Arc<dyn Fn(u64, &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> + Send + Sync>;

pub struct ServiceMuxConfig {
    pub is_client: bool,
    pub output: ServiceOutputFn,
    /// Tokio runtime handle. If None, uses Handle::try_current().
    pub runtime: Option<tokio::runtime::Handle>,
}

struct ServiceEntry {
    input_handle: KcpInput,
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
        let _guard = self.config.runtime.as_ref().map(|h| h.enter());
        let entry = {
            let s = self.services.read().unwrap();
            s.get(&service).cloned()
        };
        if let Some(e) = entry {
            e.input_handle.input(data);
        } else if let Ok(e) = self.create_service(service) {
            e.input_handle.input(data);
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
        let (conn, input_handle) = KcpConn::new(service as u32, Arc::new(move |data: &[u8]| {
            let _ = output(svc, data);
        }));

        let mode = if self.config.is_client { yamux::Mode::Client } else { yamux::Mode::Server };
        let yamux_conn = yamux::Connection::new(conn, yamux::Config::default(), mode);

        let (open_tx, open_rx) = tokio::sync::mpsc::channel(64);
        let accept_tx = self.accept_tx.clone();

        if self.config.is_client {
            tokio::spawn(client_driver(yamux_conn, open_rx, accept_tx, service));
        } else {
            tokio::spawn(server_driver(yamux_conn, accept_tx, service));
        }

        let entry = Arc::new(ServiceEntry { input_handle, open_tx });
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
            runtime: None,
            output: Arc::new(move |service, data| {
                let _ = c_to_s_tx.send((service, data.to_vec()));
                Ok(())
            }),
        });

        let server = ServiceMux::new(ServiceMuxConfig {
            is_client: false,
            runtime: None,
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

    /// Isolation: service A has slow consumer, service B throughput unaffected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_smux_isolation_slow() {
        let (client, server) = service_mux_pair();

        let server2 = server.clone();
        let accept = tokio::spawn(async move {
            let mut count = 0;
            loop {
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(8),
                    server2.accept_stream(),
                ).await;
                match result {
                    Ok(Ok((mut s, svc))) => {
                        count += 1;
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 4096];
                            if svc == 1 {
                                // Service 1: slow consumer — sleep between reads.
                                loop {
                                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                                    let n = s.read(&mut buf).await.unwrap_or(0);
                                    if n == 0 { break; }
                                }
                            } else {
                                // Service 2: fast echo.
                                loop {
                                    let n = s.read(&mut buf).await.unwrap_or(0);
                                    if n == 0 { break; }
                                    s.write_all(&buf[..n]).await.ok();
                                }
                                s.close().await.ok();
                            }
                        });
                    }
                    _ => break,
                }
            }
            count
        });

        // Service 1: write data that piles up (slow consumer on server).
        let client2 = client.clone();
        let slow_task = tokio::spawn(async move {
            let mut s = client2.open_stream(1).await.unwrap();
            for _ in 0..20 {
                s.write_all(&[0xAA; 512]).await.unwrap();
            }
            s.close().await.ok();
        });

        // Service 2: fast echo — measure round-trip time.
        let start = std::time::Instant::now();
        let mut s2 = client.open_stream(2).await.unwrap();
        s2.write_all(b"fast-ping").await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5), s2.read(&mut buf)
        ).await.expect("service 2 read timed out — isolation failure").unwrap();
        let rtt = start.elapsed();
        assert_eq!(&buf[..n], b"fast-ping");
        s2.close().await.ok();

        // Service 2 should respond fast even though service 1 is slow.
        assert!(rtt < std::time::Duration::from_secs(2),
            "service 2 RTT {:?} too slow — isolation failure", rtt);

        slow_task.await.unwrap();
        client.close();
        server.close();
        accept.abort();
    }

    /// Composite: 10 services × 10 streams = 100 concurrent streams.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_composite_10x10() {
        let (client, server) = service_mux_pair();

        let server2 = server.clone();
        let accept = tokio::spawn(async move {
            for _ in 0..100 {
                let (mut s, _svc) = server2.accept_stream().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n > 0 { s.write_all(&buf[..n]).await.ok(); }
                    s.close().await.ok();
                });
            }
        });

        let mut handles = Vec::new();
        for svc in 0..10u64 {
            for stream_idx in 0..10 {
                let c = client.clone();
                handles.push(tokio::spawn(async move {
                    let mut s = c.open_stream(svc).await.unwrap();
                    let msg = format!("svc{}-s{}", svc, stream_idx);
                    s.write_all(msg.as_bytes()).await.unwrap();
                    let mut buf = vec![0u8; 256];
                    let n = tokio::time::timeout(
                        std::time::Duration::from_secs(10), s.read(&mut buf)
                    ).await.expect("read timed out").unwrap();
                    assert_eq!(&buf[..n], msg.as_bytes());
                    s.close().await.ok();
                }));
            }
        }

        for h in handles { h.await.unwrap(); }
        assert_eq!(client.num_services(), 10);
        accept.abort();
        client.close();
        server.close();
    }

    /// Long-running stability: 10 seconds of continuous send/receive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_composite_long_running_10s() {
        let (client, server) = service_mux_pair();

        let server2 = server.clone();
        let accept = tokio::spawn(async move {
            loop {
                match server2.accept_stream().await {
                    Ok((mut s, _svc)) => {
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 4096];
                            loop {
                                let n = s.read(&mut buf).await.unwrap_or(0);
                                if n == 0 { break; }
                                s.write_all(&buf[..n]).await.ok();
                            }
                            s.close().await.ok();
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut total_bytes = 0u64;
        let mut stream_count = 0u32;

        while std::time::Instant::now() < deadline {
            let svc = (stream_count % 3) as u64 + 1;
            let mut s = client.open_stream(svc).await.unwrap();
            let msg = vec![0xBB; 256];
            s.write_all(&msg).await.unwrap();
            let mut buf = vec![0u8; 512];
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(5), s.read(&mut buf)
            ).await.expect("read timed out in long-running").unwrap();
            assert_eq!(n, 256);
            total_bytes += n as u64;
            stream_count += 1;
            s.close().await.ok();
        }

        eprintln!("[long_running] {} streams, {} bytes in 10s", stream_count, total_bytes);
        assert!(stream_count > 10, "should complete many streams in 10s, got {}", stream_count);
        accept.abort();
        client.close();
        server.close();
    }

    /// Benchmark: 100 services × 100 yamux streams = 10,000 concurrent echo round-trips.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_bench_100x100() {
        let (client, server) = service_mux_pair();

        let total_services: u64 = 100;
        let streams_per_svc: usize = 100;
        let total_streams = total_services as usize * streams_per_svc;

        // Server: accept all streams, echo back.
        let server2 = server.clone();
        let accept = tokio::spawn(async move {
            let mut count = 0usize;
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    server2.accept_stream(),
                ).await {
                    Ok(Ok((mut s, _svc))) => {
                        count += 1;
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 1024];
                            loop {
                                let n = s.read(&mut buf).await.unwrap_or(0);
                                if n == 0 { break; }
                                s.write_all(&buf[..n]).await.ok();
                            }
                            s.close().await.ok();
                        });
                    }
                    _ => break,
                }
            }
            count
        });

        let start = std::time::Instant::now();

        // Launch all 10,000 streams concurrently.
        let mut handles = Vec::with_capacity(total_streams);
        for svc in 0..total_services {
            for si in 0..streams_per_svc {
                let c = client.clone();
                handles.push(tokio::spawn(async move {
                    let mut s = c.open_stream(svc).await.map_err(|e| {
                        format!("svc={} si={}: open failed: {}", svc, si, e)
                    })?;
                    let msg = format!("s{:03}x{:03}", svc, si);
                    s.write_all(msg.as_bytes()).await.map_err(|e| format!("write: {}", e))?;
                    let mut buf = vec![0u8; 256];
                    let n = tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        s.read(&mut buf),
                    ).await
                        .map_err(|_| format!("svc={} si={}: read timed out", svc, si))?
                        .map_err(|e| format!("read: {}", e))?;
                    if &buf[..n] != msg.as_bytes() {
                        return Err(format!("svc={} si={}: echo mismatch", svc, si));
                    }
                    s.close().await.ok();
                    Ok::<(), String>(())
                }));
            }
        }

        let mut ok = 0usize;
        let mut fail = 0usize;
        for h in handles {
            match h.await {
                Ok(Ok(())) => ok += 1,
                Ok(Err(e)) => { eprintln!("[100x100] FAIL: {}", e); fail += 1; }
                Err(e) => { eprintln!("[100x100] JOIN ERR: {}", e); fail += 1; }
            }
        }

        let elapsed = start.elapsed();
        let rate = ok as f64 / elapsed.as_secs_f64();

        eprintln!("=== 100x100 Benchmark ===");
        eprintln!("  services:      {}", total_services);
        eprintln!("  streams/svc:   {}", streams_per_svc);
        eprintln!("  total streams: {}", total_streams);
        eprintln!("  ok:            {}", ok);
        eprintln!("  fail:          {}", fail);
        eprintln!("  elapsed:       {:.2?}", elapsed);
        eprintln!("  rate:          {:.0} streams/sec", rate);
        eprintln!("  num_services:  {}", client.num_services());

        assert_eq!(fail, 0, "{} streams failed out of {}", fail, total_streams);
        assert_eq!(ok, total_streams);
        assert_eq!(client.num_services(), total_services as usize);

        accept.abort();
        client.close();
        server.close();
    }
}
