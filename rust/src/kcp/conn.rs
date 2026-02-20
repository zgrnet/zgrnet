//! KcpConn — async KCP connection using pure Rust KCP + SpinMutex + Notify.
//!
//! Architecture based on tokio_kcp:
//! - Pure Rust KCP (kcp crate) instead of C ikcp.c FFI
//! - SpinMutex for lock-free access from poll context
//! - tokio::sync::Notify to wake update loop on send
//! - Manual Waker storage for poll_read/poll_write

use std::io::{self, Cursor, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use spin::Mutex as SpinMutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

/// Output function: called when KCP wants to send a packet over the wire.
pub type OutputFn = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// KCP output adapter implementing std::io::Write.
struct KcpOutput {
    output_fn: OutputFn,
}

impl Write for KcpOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (self.output_fn)(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

/// Internal KCP state protected by SpinMutex.
pub(crate) struct KcpInner {
    kcp: kcp::Kcp<KcpOutput>,
    pending_reader: Option<Waker>,
    pending_writer: Option<Waker>,
    closed: bool,
    start: Instant,
}

impl KcpInner {
    fn now_ms(&self) -> u32 {
        self.start.elapsed().as_millis() as u32
    }

    fn try_wake_pending(&mut self) {
        // Always wake reader when new data arrives — yamux may need
        // to re-poll even if KCP recv queue is empty (internal yamux state).
        if let Some(w) = self.pending_reader.take() {
            w.wake();
        }
        if let Some(w) = self.pending_writer.take() {
            w.wake();
        }
    }

    fn wake_all(&mut self) {
        if let Some(w) = self.pending_reader.take() { w.wake(); }
        if let Some(w) = self.pending_writer.take() { w.wake(); }
    }
}

/// Async KCP connection.
pub struct KcpConn {
    inner: Arc<SpinMutex<KcpInner>>,
    closed: Arc<AtomicBool>,
    notifier: Arc<Notify>,
    recv_buf: Vec<u8>,
}

impl KcpConn {
    /// Create a new KcpConn with the given conv and output function.
    pub fn new(conv: u32, output: OutputFn) -> Self {
        let kcp_output = KcpOutput { output_fn: output };
        let mut kcp_instance = kcp::Kcp::new(conv, kcp_output);
        kcp_instance.set_nodelay(true, 1, 2, true);
        kcp_instance.set_wndsize(4096, 4096);
        let _ = kcp_instance.set_mtu(1400);

        let start = Instant::now();
        let _ = kcp_instance.update(start.elapsed().as_millis() as u32);

        let inner = Arc::new(SpinMutex::new(KcpInner {
            kcp: kcp_instance,
            pending_reader: None,
            pending_writer: None,
            closed: false,
            start,
        }));

        let closed = Arc::new(AtomicBool::new(false));
        let notifier = Arc::new(Notify::new());

        // Spawn update loop
        {
            let inner = inner.clone();
            let closed = closed.clone();
            let notifier = notifier.clone();
            tokio::spawn(async move {
                update_loop(inner, closed, notifier).await;
            });
        }

        KcpConn {
            inner,
            closed,
            notifier,
            recv_buf: Vec::new(),
        }
    }

    pub fn tag(&self) -> usize {
        Arc::as_ptr(&self.inner) as usize % 10000
    }

    /// Feed incoming data from the network.
    pub fn input(&self, data: &[u8]) {
        if self.closed.load(Ordering::Relaxed) { return; }
        let mut inner = self.inner.lock();
        let _ = inner.kcp.input(data);
        inner.try_wake_pending();
        drop(inner);
        self.notifier.notify_one();
    }

    /// Get a clone of the inner for sharing (used by ServiceMux).
    pub fn inner_ref(&self) -> Arc<SpinMutex<KcpInner>> {
        self.inner.clone()
    }

    /// Get the notifier (used by ServiceMux).
    pub fn notifier_ref(&self) -> Arc<Notify> {
        self.notifier.clone()
    }

    /// Get the closed flag.
    pub fn closed_ref(&self) -> Arc<AtomicBool> {
        self.closed.clone()
    }

    /// Create a KcpConn from existing inner (for ServiceMux input handle).
    pub fn from_parts(
        inner: Arc<SpinMutex<KcpInner>>,
        closed: Arc<AtomicBool>,
        notifier: Arc<Notify>,
    ) -> Self {
        KcpConn { inner, closed, notifier, recv_buf: Vec::new() }
    }
}

impl AsyncRead for KcpConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.recv_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), self.recv_buf.len());
            buf.put_slice(&self.recv_buf[..n]);
            self.recv_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        let mut inner = self.inner.lock();
        if inner.closed { return Poll::Ready(Ok(())); }

        match inner.kcp.peeksize() {
            Ok(peek) if peek > 0 => {
                let mut tmp = vec![0u8; peek];
                match inner.kcp.recv(&mut tmp) {
                    Ok(n) => {
                        drop(inner);
                        let data = &tmp[..n];
                        let copy_n = std::cmp::min(buf.remaining(), data.len());
                        buf.put_slice(&data[..copy_n]);
                        if copy_n < data.len() {
                            self.recv_buf.extend_from_slice(&data[copy_n..]);
                        }
                        Poll::Ready(Ok(()))
                    }
                    Err(_) => {
                        inner.pending_reader = Some(cx.waker().clone());
                        Poll::Pending
                    }
                }
            }
            _ => {
                inner.pending_reader = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for KcpConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner.lock();
        if inner.closed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")));
        }

        match inner.kcp.send(buf) {
            Ok(n) => {
                drop(inner);
                self.notifier.notify_one();
                Poll::Ready(Ok(n))
            }
            Err(_) => {
                inner.pending_writer = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock();
        let _ = inner.kcp.flush();
        drop(inner);
        self.notifier.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed.store(true, Ordering::Relaxed);
        let mut inner = self.inner.lock();
        inner.closed = true;
        inner.wake_all();
        Poll::Ready(Ok(()))
    }
}

// futures::io traits for yamux compatibility
impl futures::io::AsyncRead for KcpConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.recv_buf.is_empty() {
            let n = std::cmp::min(buf.len(), self.recv_buf.len());
            buf[..n].copy_from_slice(&self.recv_buf[..n]);
            self.recv_buf.drain(..n);
            return Poll::Ready(Ok(n));
        }

        let mut inner = self.inner.lock();
        if inner.closed { return Poll::Ready(Ok(0)); }

        match inner.kcp.peeksize() {
            Ok(peek) if peek > 0 => {
                let mut tmp = vec![0u8; peek];
                match inner.kcp.recv(&mut tmp) {
                    Ok(n) => {
                        drop(inner);
                        let data = &tmp[..n];
                        let cn = std::cmp::min(buf.len(), data.len());
                        buf[..cn].copy_from_slice(&data[..cn]);
                        if cn < data.len() {
                            self.recv_buf.extend_from_slice(&data[cn..]);
                        }
                        Poll::Ready(Ok(cn))
                    }
                    Err(_) => {
                        inner.pending_reader = Some(cx.waker().clone());
                        Poll::Pending
                    }
                }
            }
            _ => {
                inner.pending_reader = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl futures::io::AsyncWrite for KcpConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner.lock();
        if inner.closed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")));
        }
        match inner.kcp.send(buf) {
            Ok(n) => {
                drop(inner);
                self.notifier.notify_one();
                Poll::Ready(Ok(n))
            }
            Err(_) => {
                inner.pending_writer = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock();
        let _ = inner.kcp.flush();
        drop(inner);
        self.notifier.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed.store(true, Ordering::Relaxed);
        let mut inner = self.inner.lock();
        inner.closed = true;
        inner.wake_all();
        Poll::Ready(Ok(()))
    }
}

impl Unpin for KcpConn {}

/// Background task that periodically calls KCP update.
async fn update_loop(
    inner: Arc<SpinMutex<KcpInner>>,
    closed: Arc<AtomicBool>,
    notifier: Arc<Notify>,
) {
    loop {
        if closed.load(Ordering::Relaxed) { return; }

        let next = {
            let mut kcp = inner.lock();
            if kcp.closed { return; }

            let now = kcp.now_ms();
            let wait_before = kcp.kcp.wait_snd();
            match kcp.kcp.update(now) {
                Ok(()) => {}
                Err(_) => {}
            }
            let wait_after = kcp.kcp.wait_snd();

            // Only wake pending writer if send queue drained (backpressure relief).
            // Never spuriously wake pending reader — that causes hot loops.
            if wait_after < wait_before {
                if let Some(w) = kcp.pending_writer.take() {
                    w.wake();
                }
            }

            let check = kcp.kcp.check(now);
            let delay = if check <= now { 1 } else { (check - now).min(100) };
            Duration::from_millis(delay as u64)
        };

        tokio::select! {
            _ = tokio::time::sleep(next) => {}
            _ = notifier.notified() => {}
        }
    }
}

// --- Test infrastructure ---

#[cfg(test)]
pub fn conn_pair() -> (KcpConn, KcpConn) {
    use tokio::sync::mpsc;
    use std::sync::Mutex as StdMutex;

    // Use channels to avoid SpinMutex AB-BA deadlock in output callbacks.
    // Output callback sends data to channel → bridge task inputs to the other side.
    let (a_to_b_tx, mut a_to_b_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (b_to_a_tx, mut b_to_a_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let a = KcpConn::new(1, Arc::new(move |data: &[u8]| {
        let _ = a_to_b_tx.send(data.to_vec());
    }));

    let b = KcpConn::new(1, Arc::new(move |data: &[u8]| {
        let _ = b_to_a_tx.send(data.to_vec());
    }));

    let b_inner = b.inner_ref();
    let b_notify = b.notifier_ref();
    tokio::spawn(async move {
        while let Some(data) = a_to_b_rx.recv().await {
            let mut kcp = b_inner.lock();
            let _ = kcp.kcp.input(&data);
            kcp.try_wake_pending();
            drop(kcp);
            b_notify.notify_one();
        }
    });

    let a_inner = a.inner_ref();
    let a_notify = a.notifier_ref();
    tokio::spawn(async move {
        while let Some(data) = b_to_a_rx.recv().await {
            let mut kcp = a_inner.lock();
            let _ = kcp.kcp.input(&data);
            kcp.try_wake_pending();
            drop(kcp);
            a_notify.notify_one();
        }
    });

    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_kcpconn_write_read() {
        let (mut a, mut b) = conn_pair();
        a.write_all(b"hello").await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn test_kcpconn_bidirectional() {
        let (mut a, mut b) = conn_pair();
        a.write_all(b"from A").await.unwrap();
        b.write_all(b"from B").await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from A");
        let n = a.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from B");
    }

    #[tokio::test]
    async fn test_kcpconn_large_data() {
        let (mut a, mut b) = conn_pair();
        let data: Vec<u8> = (0..32768).map(|i| (i & 0xFF) as u8).collect();
        let data2 = data.clone();
        let writer = tokio::spawn(async move {
            for chunk in data2.chunks(1024) {
                a.write_all(chunk).await.unwrap();
            }
        });
        let mut received = Vec::new();
        let mut buf = vec![0u8; 4096];
        while received.len() < data.len() {
            let n = b.read(&mut buf).await.unwrap();
            if n == 0 { break; }
            received.extend_from_slice(&buf[..n]);
        }
        writer.await.unwrap();
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn test_kcpconn_shutdown() {
        let (mut a, mut _b) = conn_pair();
        a.shutdown().await.unwrap();
        let result = a.write_all(b"fail").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_kcpconn_data_integrity_1mb() {
        let (mut a, mut b) = conn_pair();
        let size = 1024 * 1024;
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let data2 = data.clone();

        let writer = tokio::spawn(async move {
            for chunk in data2.chunks(8192) {
                a.write_all(chunk).await.unwrap();
            }
        });

        let mut received = Vec::with_capacity(size);
        let mut buf = vec![0u8; 16384];
        while received.len() < size {
            let n = b.read(&mut buf).await.unwrap();
            if n == 0 { break; }
            received.extend_from_slice(&buf[..n]);
        }
        writer.await.unwrap();
        assert_eq!(received.len(), size);
        assert_eq!(received, data, "1MB data integrity check failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_kcpconn_concurrent_writers() {
        let (a, mut b) = conn_pair();
        let a = Arc::new(tokio::sync::Mutex::new(a));

        let num_writers = 10;
        let msgs_per_writer = 50;
        let msg_size = 64;

        let mut handles = Vec::new();
        for w in 0..num_writers {
            let a = a.clone();
            handles.push(tokio::spawn(async move {
                for m in 0..msgs_per_writer {
                    let msg = vec![(w * 37 + m) as u8; msg_size];
                    let mut conn = a.lock().await;
                    conn.write_all(&msg).await.unwrap();
                }
            }));
        }

        let expected = num_writers * msgs_per_writer * msg_size;
        let mut received = 0usize;
        let mut buf = vec![0u8; 16384];
        while received < expected {
            let n = b.read(&mut buf).await.unwrap();
            if n == 0 { break; }
            received += n;
        }

        for h in handles { h.await.unwrap(); }
        assert_eq!(received, expected, "concurrent writers: got {} expected {}", received, expected);
    }

    #[tokio::test]
    async fn test_kcpconn_throughput() {
        let (mut a, mut b) = conn_pair();
        let size = 4 * 1024 * 1024; // 4MB
        let data = vec![0xABu8; size];
        let data2 = data.clone();

        let start = std::time::Instant::now();

        let writer = tokio::spawn(async move {
            for chunk in data2.chunks(32768) {
                a.write_all(chunk).await.unwrap();
            }
        });

        let mut received = 0;
        let mut buf = vec![0u8; 65536];
        while received < size {
            let n = b.read(&mut buf).await.unwrap();
            if n == 0 { break; }
            received += n;
        }
        writer.await.unwrap();

        let elapsed = start.elapsed();
        let mbps = received as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
        eprintln!("[throughput] {} bytes in {:?} = {:.1} MB/s", received, elapsed, mbps);
        assert_eq!(received, size);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_kcpconn_yamux_echo() {
        use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use futures::TryStreamExt;

        let (a, b) = conn_pair();

        let mut server_conn = yamux::Connection::new(b, yamux::Config::default(), yamux::Mode::Server);
        let mut client_conn = yamux::Connection::new(a, yamux::Config::default(), yamux::Mode::Client);

        // Server: echo each inbound stream (exact yamux test-harness pattern)
        let server = tokio::spawn(async move {
            futures::stream::poll_fn(|cx| server_conn.poll_next_inbound(cx))
                .try_for_each_concurrent(None, |mut stream| async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        let n = stream.read(&mut buf).await?;
                        if n == 0 { break; }
                        stream.write_all(&buf[..n]).await?;
                    }
                    stream.close().await?;
                    Ok(())
                }).await.ok();
        });

        // Client driver: loop with progress tracking (verified pattern from TCP test)
        let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<yamux::Stream>>(8);

        let driver = tokio::spawn(async move {
            let mut pending_opens: Vec<tokio::sync::oneshot::Sender<yamux::Stream>> = Vec::new();

            futures::future::poll_fn(|cx| {
                loop {
                    let mut progress = false;

                    while let std::task::Poll::Ready(Some(tx)) = open_rx.poll_recv(cx) {
                        pending_opens.push(tx);
                        progress = true;
                    }

                    while !pending_opens.is_empty() {
                        match client_conn.poll_new_outbound(cx) {
                            std::task::Poll::Ready(Ok(stream)) => {
                                let tx = pending_opens.remove(0);
                                let _ = tx.send(stream);
                                progress = true;
                            }
                            std::task::Poll::Ready(Err(_)) => { pending_opens.remove(0); progress = true; }
                            std::task::Poll::Pending => break,
                        }
                    }

                    match client_conn.poll_next_inbound(cx) {
                        std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => {
                            return std::task::Poll::Ready(());
                        }
                        std::task::Poll::Ready(Some(Ok(_))) => { progress = true; continue; }
                        std::task::Poll::Pending => {}
                    }

                    if !progress { return std::task::Poll::Pending; }
                }
            }).await;
        });

        // Test: open stream, echo
        let (tx, rx) = tokio::sync::oneshot::channel();
        open_tx.send(tx).await.unwrap();
        let mut s = tokio::time::timeout(Duration::from_secs(5), rx).await
            .expect("open timed out").unwrap();

        s.write_all(b"yamux over kcp!").await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"yamux over kcp!");
        s.close().await.unwrap();

        driver.abort();
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_kcpconn_yamux_10_streams() {
        use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use futures::TryStreamExt;

        let (a, b) = conn_pair();

        let mut server_conn = yamux::Connection::new(b, yamux::Config::default(), yamux::Mode::Server);
        let mut client_conn = yamux::Connection::new(a, yamux::Config::default(), yamux::Mode::Client);

        let server = tokio::spawn(async move {
            futures::stream::poll_fn(|cx| server_conn.poll_next_inbound(cx))
                .try_for_each_concurrent(None, |mut stream| async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        let n = stream.read(&mut buf).await?;
                        if n == 0 { break; }
                        stream.write_all(&buf[..n]).await?;
                    }
                    stream.close().await?;
                    Ok(())
                }).await.ok();
        });

        let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<yamux::Stream>>(8);

        let driver = tokio::spawn(async move {
            let mut pending_opens: Vec<tokio::sync::oneshot::Sender<yamux::Stream>> = Vec::new();
            futures::future::poll_fn(|cx| {
                loop {
                    let mut progress = false;
                    while let std::task::Poll::Ready(Some(tx)) = open_rx.poll_recv(cx) {
                        pending_opens.push(tx);
                        progress = true;
                    }
                    while !pending_opens.is_empty() {
                        match client_conn.poll_new_outbound(cx) {
                            std::task::Poll::Ready(Ok(s)) => { let _ = pending_opens.remove(0).send(s); progress = true; }
                            std::task::Poll::Ready(Err(_)) => { pending_opens.remove(0); progress = true; }
                            std::task::Poll::Pending => break,
                        }
                    }
                    match client_conn.poll_next_inbound(cx) {
                        std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => return std::task::Poll::Ready(()),
                        std::task::Poll::Ready(Some(Ok(_))) => { progress = true; continue; }
                        std::task::Poll::Pending => {}
                    }
                    if !progress { return std::task::Poll::Pending; }
                }
            }).await;
        });

        for i in 0..10 {
            let (tx, rx) = tokio::sync::oneshot::channel();
            open_tx.send(tx).await.unwrap();
            let mut s = tokio::time::timeout(Duration::from_secs(5), rx).await
                .expect(&format!("open {} timed out", i)).unwrap();
            let msg = format!("stream-{}", i);
            s.write_all(msg.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; 256];
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
            s.close().await.unwrap();
        }

        driver.abort();
        server.abort();
    }

    /// PM Review BUG 1 equivalent: concurrent write + input must not panic or corrupt data.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_kcpconn_concurrent_write_and_input() {
        let (a, mut b) = conn_pair();
        let a = Arc::new(tokio::sync::Mutex::new(a));

        let num_tasks = 8;
        let msgs_per_task = 100;
        let msg_size = 32;

        let mut handles = Vec::new();
        for t in 0..num_tasks {
            let a = a.clone();
            handles.push(tokio::spawn(async move {
                for m in 0..msgs_per_task {
                    let msg = vec![(t * 31 + m) as u8; msg_size];
                    let mut conn = a.lock().await;
                    conn.write_all(&msg).await.unwrap();
                }
            }));
        }

        let expected = num_tasks * msgs_per_task * msg_size;
        let mut received = 0usize;
        let mut buf = vec![0u8; 16384];
        while received < expected {
            let n = b.read(&mut buf).await.unwrap();
            if n == 0 { break; }
            received += n;
        }
        for h in handles { h.await.unwrap(); }
        assert_eq!(received, expected);
    }

    /// PM Review BUG 2 equivalent: read with timeout must not hang forever.
    #[tokio::test]
    async fn test_kcpconn_read_timeout() {
        let (_a, mut b) = conn_pair();
        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            b.read(&mut [0u8; 256]),
        ).await;
        let elapsed = start.elapsed();
        assert!(result.is_err(), "read should time out");
        assert!(elapsed >= Duration::from_millis(150), "timeout too early: {:?}", elapsed);
        assert!(elapsed < Duration::from_millis(500), "timeout too late: {:?}", elapsed);
    }

    /// PM Review issue 5: write backpressure — kcp.send() should eventually return Err when
    /// send buffer is full, causing poll_write to return Pending (not silently drop data).
    #[tokio::test]
    async fn test_kcpconn_write_backpressure() {
        let (mut a, mut b) = conn_pair();
        let total = 2 * 1024 * 1024; // 2MB
        let chunk = vec![0xCDu8; 8192];

        let writer = tokio::spawn(async move {
            let mut written = 0usize;
            while written < total {
                a.write_all(&chunk).await.unwrap();
                written += chunk.len();
            }
            written
        });

        let mut received = 0usize;
        let mut buf = vec![0u8; 32768];
        while received < total {
            let n = b.read(&mut buf).await.unwrap();
            if n == 0 { break; }
            received += n;
        }

        let written = writer.await.unwrap();
        assert_eq!(written, total);
        assert_eq!(received, total, "all written data must arrive (no silent drops)");
    }

    /// Verify shutdown + drop completes within bounded time (no hangs).
    #[tokio::test]
    async fn test_kcpconn_shutdown_and_drop() {
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let (mut a, mut b) = conn_pair();
            a.write_all(b"before shutdown").await.unwrap();
            let mut buf = vec![0u8; 256];
            let n = b.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"before shutdown");

            a.shutdown().await.unwrap();
            let result = a.write_all(b"fail").await;
            assert!(result.is_err());

            // b should see EOF after a is shut down
            b.shutdown().await.unwrap();
        }).await;
        assert!(result.is_ok(), "shutdown should complete within 2 seconds");
    }
}
