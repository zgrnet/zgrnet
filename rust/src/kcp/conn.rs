//! KcpConn — async KCP connection using Mutex + manual Waker.
//!
//! Inspired by tokio-kcp: KCP operations are protected by a Mutex,
//! poll_read/poll_write directly lock and operate on KCP. Wakers are
//! stored manually and fired when input() or update() produces readable data.
//! No std::thread, no channel bridging — everything runs in tokio.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

use super::kcp::Kcp;

/// Output function: called when KCP wants to send a packet over the wire.
pub type OutputFn = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Internal KCP state protected by Mutex.
pub(crate) struct KcpInner {
    kcp: Kcp,
    input_queue: Vec<Vec<u8>>,
    pending_reader: Option<Waker>,
    pending_writer: Option<Waker>,
    closed: bool,
    start: Instant,
}

impl KcpInner {
    fn now_ms(&self) -> u32 {
        self.start.elapsed().as_millis() as u32
    }

    fn try_wake_reader(&mut self) {
        if self.pending_reader.is_some() && self.kcp.peek_size() > 0 {
            if let Some(w) = self.pending_reader.take() {
                w.wake();
            }
        }
    }

    fn try_wake_writer(&mut self) {
        if let Some(w) = self.pending_writer.take() {
            w.wake();
        }
    }

    fn wake_all(&mut self) {
        if let Some(w) = self.pending_reader.take() { w.wake(); }
        if let Some(w) = self.pending_writer.take() { w.wake(); }
    }
}

/// KcpConn is an async KCP connection.
///
/// All KCP operations go through `Arc<Mutex<KcpInner>>`. poll_read/poll_write
/// lock the mutex, operate on KCP, and store Wakers for later notification.
/// A background tokio task calls update() periodically.
pub struct KcpConn {
    inner: Arc<Mutex<KcpInner>>,
    recv_buf: Vec<u8>,
}

impl KcpConn {
    /// Create a new KcpConn.
    ///
    /// Spawns a background tokio task for KCP update() driven by check().
    pub fn new(conv: u32, output: OutputFn) -> Self {
        let output_fn: super::kcp::OutputFn = Box::new(move |data: &[u8]| {
            output(data);
        });
        let mut kcp = Kcp::new(conv, output_fn);
        kcp.set_default_config();

        let inner = Arc::new(Mutex::new(KcpInner {
            kcp,
            input_queue: Vec::new(),
            pending_reader: None,
            pending_writer: None,
            closed: false,
            start: Instant::now(),
        }));

        // Spawn update task
        let inner_ref = inner.clone();
        tokio::spawn(async move {
            update_loop(inner_ref).await;
        });

        KcpConn {
            inner,
            recv_buf: Vec::new(),
        }
    }

    /// Feed incoming data from the network.
    pub async fn input(&self, data: &[u8]) {
        let mut inner = self.inner.lock().await;
        if inner.closed { return; }
        inner.kcp.input(data);
        let now = inner.now_ms();
        inner.kcp.update(now);
        inner.try_wake_reader();
    }

    /// Queue incoming data for processing by the update loop.
    /// Safe to call from KCP output callbacks (won't deadlock).
    pub fn queue_input(&self, data: &[u8]) {
        if let Ok(mut inner) = self.inner.try_lock() {
            if inner.closed { return; }
            inner.input_queue.push(data.to_vec());
            // Wake the reader so the update loop processes the queue
            if let Some(w) = inner.pending_reader.take() {
                w.wake();
            }
        } else {
            // Can't lock — this happens when called from output callback.
            // Use a separate queue that doesn't need the main lock.
            // For now, spawn a task to input later.
            let inner = self.inner.clone();
            let data = data.to_vec();
            tokio::spawn(async move {
                let mut kcp = inner.lock().await;
                if !kcp.closed {
                    kcp.input_queue.push(data);
                    if let Some(w) = kcp.pending_reader.take() {
                        w.wake();
                    }
                }
            });
        }
    }

    /// Close the connection.
    pub async fn close(&self) {
        let mut inner = self.inner.lock().await;
        inner.closed = true;
        inner.wake_all();
    }

    /// Check if closed.
    pub fn is_closed(&self) -> bool {
        self.inner.try_lock().map(|i| i.closed).unwrap_or(false)
    }

    /// Get a clone of the inner Arc for sharing.
    pub fn inner(&self) -> Arc<Mutex<KcpInner>> {
        self.inner.clone()
    }

    /// Create a KcpConn from an existing inner. Used by ServiceMux to keep
    /// a handle for input() after moving the original into yamux.
    pub fn from_inner(inner: Arc<Mutex<KcpInner>>) -> Self {
        KcpConn {
            inner,
            recv_buf: Vec::new(),
        }
    }
}

impl AsyncRead for KcpConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain local buffer first
        if !self.recv_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), self.recv_buf.len());
            buf.put_slice(&self.recv_buf[..n]);
            self.recv_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        // Try to lock and read from KCP
        let mut inner = match self.inner.try_lock() {
            Ok(inner) => inner,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if inner.closed {
            return Poll::Ready(Ok(())); // EOF
        }

        let peek = inner.kcp.peek_size();
        if peek <= 0 {
            inner.pending_reader = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let mut tmp = vec![0u8; peek as usize];
        let n = inner.kcp.recv(&mut tmp);
        drop(inner); // Release lock before copying

        if n <= 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        let data = &tmp[..n as usize];
        let copy_n = std::cmp::min(buf.remaining(), data.len());
        buf.put_slice(&data[..copy_n]);
        if copy_n < data.len() {
            self.recv_buf.extend_from_slice(&data[copy_n..]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for KcpConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = match self.inner.try_lock() {
            Ok(inner) => inner,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if inner.closed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")));
        }

        let ret = inner.kcp.send(buf);
        if ret < 0 {
            inner.pending_writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        inner.kcp.flush();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.kcp.flush();
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.closed = true;
            inner.wake_all();
        }
        Poll::Ready(Ok(()))
    }
}

// Also implement futures::io traits for yamux compatibility
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

        let mut inner = match self.inner.try_lock() {
            Ok(inner) => inner,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if inner.closed {
            return Poll::Ready(Ok(0));
        }

        let peek = inner.kcp.peek_size();
        if peek <= 0 {
            inner.pending_reader = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let mut tmp = vec![0u8; peek as usize];
        let n = inner.kcp.recv(&mut tmp);
        drop(inner);

        if n <= 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        let data = &tmp[..n as usize];
        let copy_n = std::cmp::min(buf.len(), data.len());
        buf[..copy_n].copy_from_slice(&data[..copy_n]);
        if copy_n < data.len() {
            self.recv_buf.extend_from_slice(&data[copy_n..]);
        }
        Poll::Ready(Ok(copy_n))
    }
}

impl futures::io::AsyncWrite for KcpConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = match self.inner.try_lock() {
            Ok(inner) => inner,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if inner.closed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")));
        }

        let ret = inner.kcp.send(buf);
        if ret < 0 {
            inner.pending_writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        inner.kcp.flush();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.kcp.flush();
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.closed = true;
            inner.wake_all();
        }
        Poll::Ready(Ok(()))
    }
}

impl Unpin for KcpConn {}

/// Background task that periodically calls KCP update.
async fn update_loop(inner: Arc<Mutex<KcpInner>>) {
    let mut interval = tokio::time::interval(Duration::from_millis(1));
    loop {
        interval.tick().await;

        let mut kcp = inner.lock().await;
        if kcp.closed {
            return;
        }

        // Drain input queue
        let queue: Vec<Vec<u8>> = kcp.input_queue.drain(..).collect();
        for data in &queue {
            kcp.kcp.input(data);
        }

        let now = kcp.now_ms();
        kcp.kcp.update(now);
        kcp.try_wake_reader();
        kcp.try_wake_writer();

        // Adaptive interval based on check()
        let next = kcp.kcp.check(now);
        let delay = if next <= now { 1 } else { (next - now).min(10) };
        drop(kcp);
        interval = tokio::time::interval(Duration::from_millis(delay as u64));
    }
}

#[cfg(test)]
pub fn conn_pair() -> (KcpConn, KcpConn) {
    use std::sync::Mutex as StdMutex;

    let b_conn: Arc<StdMutex<Option<Arc<tokio::sync::Mutex<KcpInner>>>>> =
        Arc::new(StdMutex::new(None));
    let a_conn: Arc<StdMutex<Option<Arc<tokio::sync::Mutex<KcpInner>>>>> =
        Arc::new(StdMutex::new(None));

    let b_ref = b_conn.clone();
    let a = KcpConn::new(1, Arc::new(move |data: &[u8]| {
        if let Some(ref inner) = *b_ref.lock().unwrap() {
            // Queue data — don't try to lock KcpInner directly
            // (we might be inside a KCP output callback with the lock held)
            let data = data.to_vec();
            let inner = inner.clone();
            tokio::spawn(async move {
                let mut kcp = inner.lock().await;
                kcp.input_queue.push(data);
                if let Some(w) = kcp.pending_reader.take() {
                    w.wake();
                }
            });
        }
    }));

    let a_ref = a_conn.clone();
    let b = KcpConn::new(1, Arc::new(move |data: &[u8]| {
        if let Some(ref inner) = *a_ref.lock().unwrap() {
            let data = data.to_vec();
            let inner = inner.clone();
            tokio::spawn(async move {
                let mut kcp = inner.lock().await;
                kcp.input_queue.push(data);
                if let Some(w) = kcp.pending_reader.take() {
                    w.wake();
                }
            });
        }
    }));

    *b_conn.lock().unwrap() = Some(b.inner.clone());
    *a_conn.lock().unwrap() = Some(a.inner.clone());

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

        let client_task = tokio::spawn(async move {
            eprintln!("[yamux-test] client: polling poll_new_outbound...");
            let r = futures::future::poll_fn(|cx| client.poll_new_outbound(cx)).await;
            eprintln!("[yamux-test] client: poll_new_outbound returned {:?}", r.is_ok());
            r
        });

        let server_task = tokio::spawn(async move {
            eprintln!("[yamux-test] server: polling poll_next_inbound...");
            let r = futures::future::poll_fn(|cx| server.poll_next_inbound(cx)).await;
            eprintln!("[yamux-test] server: poll_next_inbound returned");
            r
        });

        let (c, s) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(3), client_task),
            tokio::time::timeout(Duration::from_secs(3), server_task),
        );

        let client_ok = c.is_ok();
        let server_ok = s.is_ok();
        eprintln!("[yamux-test] client_ok={}, server_ok={}", client_ok, server_ok);

        assert!(client_ok, "client timed out");
        assert!(server_ok, "server timed out");

        let mut client_stream = c.unwrap().unwrap().unwrap();
        let mut server_stream = s.unwrap().unwrap().unwrap().unwrap();

        client_stream.write_all(b"yamux over kcp!").await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = server_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"yamux over kcp!");

        client_stream.close().await.unwrap();
        server_stream.close().await.unwrap();
    }
}
