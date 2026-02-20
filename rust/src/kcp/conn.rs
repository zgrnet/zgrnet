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
        if self.pending_reader.is_some() {
            if let Ok(peek) = self.kcp.peeksize() {
                if peek > 0 {
                    if let Some(w) = self.pending_reader.take() {
                        w.wake();
                    }
                }
            }
        }
        if self.pending_writer.is_some() {
            if let Some(w) = self.pending_writer.take() {
                w.wake();
            }
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
            match kcp.kcp.update(now) {
                Ok(()) => {}
                Err(_) => {}
            }
            kcp.try_wake_pending();

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
        eprintln!("[output a→b] {} bytes", data.len());
        let _ = a_to_b_tx.send(data.to_vec());
    }));

    let b = KcpConn::new(1, Arc::new(move |data: &[u8]| {
        eprintln!("[output b→a] {} bytes", data.len());
        let _ = b_to_a_tx.send(data.to_vec());
    }));

    // Bridge tasks: read from channel → input to the other side's KcpConn
    let b_inner = b.inner_ref();
    let b_notify = b.notifier_ref();
    tokio::spawn(async move {
        while let Some(data) = a_to_b_rx.recv().await {
            eprintln!("[bridge a→b] {} bytes", data.len());
            let mut kcp = b_inner.lock();
            let _ = kcp.kcp.input(&data);
            let peek = kcp.kcp.peeksize().unwrap_or(0);
            let has_reader = kcp.pending_reader.is_some();
            eprintln!("[bridge a→b] after input: peek={}, has_reader={}", peek, has_reader);
            kcp.try_wake_pending();
            drop(kcp);
            b_notify.notify_one();
        }
    });

    let a_inner = a.inner_ref();
    let a_notify = a.notifier_ref();
    tokio::spawn(async move {
        while let Some(data) = b_to_a_rx.recv().await {
            eprintln!("[bridge b→a] {} bytes", data.len());
            let mut kcp = a_inner.lock();
            let _ = kcp.kcp.input(&data);
            let peek = kcp.kcp.peeksize().unwrap_or(0);
            let has_reader = kcp.pending_reader.is_some();
            eprintln!("[bridge b→a] after input: peek={}, has_reader={}", peek, has_reader);
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_kcpconn_yamux_basic() {
        use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (a, b) = conn_pair();

        let mut client = yamux::Connection::new(a, yamux::Config::default(), yamux::Mode::Client);
        let mut server = yamux::Connection::new(b, yamux::Config::default(), yamux::Mode::Server);

        let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>>(1);
        let (accept_tx, mut accept_rx) = tokio::sync::mpsc::channel::<yamux::Stream>(1);

        // Client driver: polls both inbound (to flush) and processes open requests
        let client_task = tokio::spawn(async move {
            let mut pending: Option<tokio::sync::oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>> = None;
            loop {
                let now = std::time::Instant::now();
                    let _: Option<()> = futures::future::poll_fn(|cx| {
                    match client.poll_next_inbound(cx) {
                        std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => {
                            return std::task::Poll::Ready(None);
                        }
                        _ => {}
                    }
                    // Check open requests
                    if pending.is_none() {
                        if let std::task::Poll::Ready(Some(tx)) = open_rx.poll_recv(cx) {
                            pending = Some(tx);
                        }
                    }
                    // Try outbound
                    if pending.is_some() {
                        if let std::task::Poll::Ready(result) = client.poll_new_outbound(cx) {
                            if let Some(tx) = pending.take() {
                                let _ = tx.send(result);
                            }
                        }
                    }
                    std::task::Poll::Pending
                }).await;
            }
        });

        // Server driver: keep polling to process all yamux protocol frames
        let server_task = tokio::spawn(async move {
            loop {
                let result = futures::future::poll_fn(|cx| server.poll_next_inbound(cx)).await;
                match result {
                    Some(Ok(s)) => { let _ = accept_tx.send(s).await; }
                    _ => return,
                }
            }
        });

        // Open stream via client driver
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        open_tx.send(result_tx).await.unwrap();

        let client_stream = tokio::time::timeout(Duration::from_secs(5), result_rx).await;
        assert!(client_stream.is_ok(), "client open timed out");
        let mut client_stream = client_stream.unwrap().unwrap().unwrap();

        let server_stream = tokio::time::timeout(Duration::from_secs(5), accept_rx.recv()).await;
        assert!(server_stream.is_ok(), "server accept timed out");
        let mut server_stream = server_stream.unwrap().unwrap();

        client_stream.write_all(b"yamux over kcp!").await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = server_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"yamux over kcp!");

        client_stream.close().await.unwrap();
        server_stream.close().await.unwrap();
    }
}
