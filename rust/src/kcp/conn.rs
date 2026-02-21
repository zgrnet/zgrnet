//! KcpConn — async KCP connection with write coalescing.
//!
//! Architecture:
//! - One tokio task exclusively owns the KCP instance (the run loop)
//! - poll_write appends to a shared BytesMut buffer (Mutex, O(1) memcpy)
//!   and conditionally notifies the run loop (only when buffer was empty)
//! - poll_read receives from unbounded channel ← run loop drains kcp.recv()
//! - input() sends raw packets via unbounded channel → run loop calls kcp.input()
//! - Write coalescing: N small writes become 1 kcp.send() call per update cycle

use std::io::{self, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

/// Output function: called when KCP wants to send a packet over the wire.
pub type OutputFn = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// KCP output adapter implementing std::io::Write.
pub(crate) struct KcpOutput {
    pub(crate) output_fn: OutputFn,
}

impl Write for KcpOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (self.output_fn)(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

const MAX_WRITE_BUF: usize = 256 * 1024; // 256KB backpressure threshold

struct WriteBuffer {
    data: BytesMut,
    waker: Option<Waker>,
}

/// Handle for feeding raw network packets into a KcpConn's run loop.
#[derive(Clone)]
pub struct KcpInput {
    input_tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
}

impl KcpInput {
    pub fn input(&self, data: &[u8]) {
        let _ = self.input_tx.send(Bytes::copy_from_slice(data));
    }
}

/// Async KCP connection. Implements futures::io::AsyncRead/AsyncWrite for yamux.
pub struct KcpConn {
    write_buf: Arc<std::sync::Mutex<WriteBuffer>>,
    write_notify: Arc<Notify>,
    read_rx: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    closed: Arc<AtomicBool>,
    recv_buf: BytesMut,
}

impl KcpConn {
    pub fn new(conv: u32, output: OutputFn) -> (Self, KcpInput) {
        let kcp_output = KcpOutput { output_fn: output };
        let mut kcp_instance = kcp::Kcp::new(conv, kcp_output);
        kcp_instance.set_nodelay(true, 1, 2, true);
        kcp_instance.set_wndsize(4096, 4096);
        let _ = kcp_instance.set_mtu(1400);

        let write_buf = Arc::new(std::sync::Mutex::new(WriteBuffer {
            data: BytesMut::with_capacity(8192),
            waker: None,
        }));
        let write_notify = Arc::new(Notify::new());
        let (read_tx, read_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
        let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
        let closed = Arc::new(AtomicBool::new(false));

        {
            let wb = write_buf.clone();
            let wn = write_notify.clone();
            let closed = closed.clone();
            tokio::spawn(run_loop(kcp_instance, wb, wn, read_tx, input_rx, closed));
        }

        let conn = KcpConn {
            write_buf,
            write_notify,
            read_rx,
            closed,
            recv_buf: BytesMut::new(),
        };
        let input = KcpInput { input_tx };
        (conn, input)
    }

    pub fn tag(&self) -> usize { 0 }
}

// Shared write logic: append to coalescing buffer, conditionally notify run loop.
fn do_write(
    write_buf: &std::sync::Mutex<WriteBuffer>,
    write_notify: &Notify,
    closed: &AtomicBool,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<io::Result<usize>> {
    if closed.load(Ordering::Relaxed) {
        return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")));
    }
    let mut wb = write_buf.lock().unwrap();
    if wb.data.len() >= MAX_WRITE_BUF {
        wb.waker = Some(cx.waker().clone());
        return Poll::Pending;
    }
    let was_empty = wb.data.is_empty();
    wb.data.extend_from_slice(buf);
    drop(wb);
    if was_empty {
        write_notify.notify_one();
    }
    Poll::Ready(Ok(buf.len()))
}

fn do_flush(write_notify: &Notify) -> Poll<io::Result<()>> {
    write_notify.notify_one();
    Poll::Ready(Ok(()))
}

fn do_close(closed: &AtomicBool) -> Poll<io::Result<()>> {
    closed.store(true, Ordering::Relaxed);
    Poll::Ready(Ok(()))
}

// Shared read logic: drain from recv_buf, then poll read channel.
fn do_read(
    recv_buf: &mut BytesMut,
    read_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
) -> Poll<io::Result<usize>> {
    if !recv_buf.is_empty() {
        let n = std::cmp::min(buf.len(), recv_buf.len());
        buf[..n].copy_from_slice(&recv_buf[..n]);
        recv_buf.advance(n);
        return Poll::Ready(Ok(n));
    }
    match read_rx.poll_recv(cx) {
        Poll::Ready(Some(data)) => {
            let n = std::cmp::min(buf.len(), data.len());
            buf[..n].copy_from_slice(&data[..n]);
            if n < data.len() {
                recv_buf.extend_from_slice(&data[n..]);
            }
            Poll::Ready(Ok(n))
        }
        Poll::Ready(None) => Poll::Ready(Ok(0)),
        Poll::Pending => Poll::Pending,
    }
}

// tokio::io traits
impl AsyncRead for KcpConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if !me.recv_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), me.recv_buf.len());
            buf.put_slice(&me.recv_buf[..n]);
            me.recv_buf.advance(n);
            return Poll::Ready(Ok(()));
        }
        match me.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    me.recv_buf.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for KcpConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        do_write(&self.write_buf, &self.write_notify, &self.closed, cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        do_flush(&self.write_notify)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        do_close(&self.closed)
    }
}

// futures::io traits for yamux compatibility
impl futures::io::AsyncRead for KcpConn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        do_read(&mut me.recv_buf, &mut me.read_rx, cx, buf)
    }
}

impl futures::io::AsyncWrite for KcpConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        do_write(&self.write_buf, &self.write_notify, &self.closed, cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        do_flush(&self.write_notify)
    }
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        do_close(&self.closed)
    }
}

impl Unpin for KcpConn {}

/// Run loop: exclusively owns the KCP instance. Drains coalesced write buffer
/// and input channel, forwards recv data to read channel.
async fn run_loop(
    mut kcp: kcp::Kcp<KcpOutput>,
    write_buf: Arc<std::sync::Mutex<WriteBuffer>>,
    write_notify: Arc<Notify>,
    read_tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
    mut input_rx: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    closed: Arc<AtomicBool>,
) {
    let start = Instant::now();
    let now_ms = || start.elapsed().as_millis() as u32;
    let _ = kcp.update(now_ms());

    loop {
        if closed.load(Ordering::Relaxed) { return; }

        let now = now_ms();
        let check = kcp.check(now);
        let delay = if check <= now { 1 } else { (check - now).min(50) };

        tokio::select! {
            biased;

            _ = write_notify.notified() => {
                drain_write_buf(&write_buf, &mut kcp);
                let _ = kcp.flush();
                drain_recv(&mut kcp, &read_tx);
            }

            Some(data) = input_rx.recv() => {
                let _ = kcp.input(&data);
                while let Ok(more) = input_rx.try_recv() {
                    let _ = kcp.input(&more);
                }
                drain_write_buf(&write_buf, &mut kcp);
                let _ = kcp.flush();
                drain_recv(&mut kcp, &read_tx);
            }

            _ = tokio::time::sleep(Duration::from_millis(delay as u64)) => {
                drain_write_buf(&write_buf, &mut kcp);
                let _ = kcp.update(now_ms());
                drain_recv(&mut kcp, &read_tx);
            }
        }
    }
}

/// Drain coalesced write buffer into KCP send queue.
/// Sends in 8KB chunks so each is an independent KCP message that can be
/// received incrementally (not one giant message requiring full reassembly).
fn drain_write_buf(
    write_buf: &std::sync::Mutex<WriteBuffer>,
    kcp: &mut kcp::Kcp<KcpOutput>,
) {
    let mut wb = write_buf.lock().unwrap();
    if wb.data.is_empty() { return; }
    let data = wb.data.split();
    let waker = wb.waker.take();
    drop(wb);
    for chunk in data.chunks(8192) {
        let _ = kcp.send(chunk);
    }
    if let Some(w) = waker { w.wake(); }
}

/// Drain all available data from KCP recv queue and forward to the read channel.
fn drain_recv(kcp: &mut kcp::Kcp<KcpOutput>, read_tx: &tokio::sync::mpsc::UnboundedSender<Bytes>) {
    loop {
        match kcp.peeksize() {
            Ok(n) if n > 0 => {
                let mut buf = BytesMut::zeroed(n);
                match kcp.recv(&mut buf) {
                    Ok(sz) => {
                        buf.truncate(sz);
                        if read_tx.send(buf.freeze()).is_err() { return; }
                    }
                    Err(_) => return,
                }
            }
            _ => return,
        }
    }
}

// --- Test infrastructure ---

#[cfg(test)]
fn lossy_bridge(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    input: KcpInput,
    loss_pct: u8,
    reorder: bool,
) {
    tokio::spawn(async move {
        let mut rng_state: u64 = 12345;
        let mut delayed: Option<Bytes> = None;
        while let Some(data) = rx.recv().await {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let r = ((rng_state >> 33) % 100) as u8;

            if r < loss_pct { continue; }

            if reorder && r % 10 == 0 && delayed.is_none() {
                delayed = Some(Bytes::from(data));
                continue;
            }

            input.input(&data);
            if let Some(d) = delayed.take() {
                input.input(&d);
            }
        }
    });
}

#[cfg(test)]
pub fn conn_pair() -> (KcpConn, KcpConn) {
    lossy_conn_pair(0, false)
}

#[cfg(test)]
pub fn lossy_conn_pair(loss_pct: u8, reorder: bool) -> (KcpConn, KcpConn) {
    let (a_to_b_tx, a_to_b_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (b_to_a_tx, b_to_a_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    let (a, a_input) = KcpConn::new(1, Arc::new(move |data: &[u8]| {
        let _ = a_to_b_tx.send(data.to_vec());
    }));

    let (b, b_input) = KcpConn::new(1, Arc::new(move |data: &[u8]| {
        let _ = b_to_a_tx.send(data.to_vec());
    }));

    lossy_bridge(a_to_b_rx, b_input, loss_pct, reorder);
    lossy_bridge(b_to_a_rx, a_input, loss_pct, reorder);

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

    /// Verify KCP wire format matches C ikcp.c: conv(4B LE) + cmd(1B) + frg(1B) +
    /// wnd(2B LE) + ts(4B LE) + sn(4B LE) + una(4B LE) + len(4B LE) = 24B header.
    #[tokio::test]
    async fn test_kcp_wire_format_c_compat() {
        let captured = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let cap = captured.clone();
        let mut kcp_instance = kcp::Kcp::new(0x12345678, super::KcpOutput {
            output_fn: Arc::new(move |data: &[u8]| {
                cap.lock().unwrap().push(data.to_vec());
            }),
        });
        kcp_instance.set_nodelay(true, 1, 2, true);
        kcp_instance.set_wndsize(128, 128);

        kcp_instance.send(b"hello").unwrap();
        let _ = kcp_instance.update(0);
        let _ = kcp_instance.flush();

        let frames = captured.lock().unwrap();
        assert!(!frames.is_empty(), "must produce at least one frame");

        let frame = &frames[0];
        assert!(frame.len() >= 24, "frame must be at least 24 bytes (KCP_OVERHEAD), got {}", frame.len());

        // Decode header fields per C ikcp wire format.
        let conv = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
        let cmd = frame[4];
        let _frg = frame[5];
        let _wnd = u16::from_le_bytes([frame[6], frame[7]]);
        let _ts = u32::from_le_bytes([frame[8], frame[9], frame[10], frame[11]]);
        let sn = u32::from_le_bytes([frame[12], frame[13], frame[14], frame[15]]);
        let _una = u32::from_le_bytes([frame[16], frame[17], frame[18], frame[19]]);
        let len = u32::from_le_bytes([frame[20], frame[21], frame[22], frame[23]]);

        assert_eq!(conv, 0x12345678, "conv must match");
        assert_eq!(cmd, 81, "cmd=81 is PUSH (data segment) in both C and Rust KCP");
        assert_eq!(sn, 0, "first segment sn must be 0");
        assert_eq!(len as usize, 5, "payload len must be 5 (\"hello\")");
        assert_eq!(frame.len(), 24 + 5, "total frame = 24B header + 5B data");
        assert_eq!(&frame[24..], b"hello");
    }

    /// 5% packet loss — KCP must deliver all data via retransmission.
    #[tokio::test]
    async fn test_kcpconn_loss_5pct() {
        let (mut a, mut b) = lossy_conn_pair(5, false);
        let size = 64 * 1024;
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let data2 = data.clone();

        let writer = tokio::spawn(async move {
            for chunk in data2.chunks(1024) {
                a.write_all(chunk).await.unwrap();
            }
        });

        let mut received = Vec::with_capacity(size);
        let mut buf = vec![0u8; 8192];
        while received.len() < size {
            match tokio::time::timeout(Duration::from_secs(10), b.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => received.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
        writer.await.unwrap();
        assert_eq!(received.len(), size, "5% loss: all data must arrive");
        assert_eq!(received, data);
    }

    /// 20% packet loss — extreme but KCP should still deliver.
    #[tokio::test]
    async fn test_kcpconn_loss_20pct() {
        let (mut a, mut b) = lossy_conn_pair(20, false);
        let size = 32 * 1024;
        let data: Vec<u8> = (0..size).map(|i| (i % 199) as u8).collect();
        let data2 = data.clone();

        let writer = tokio::spawn(async move {
            for chunk in data2.chunks(512) {
                a.write_all(chunk).await.unwrap();
            }
        });

        let mut received = Vec::with_capacity(size);
        let mut buf = vec![0u8; 8192];
        while received.len() < size {
            match tokio::time::timeout(Duration::from_secs(30), b.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => received.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
        writer.await.unwrap();
        assert_eq!(received.len(), size, "20% loss: all data must arrive");
        assert_eq!(received, data);
    }

    /// Packet reorder — KCP must reassemble in correct order.
    #[tokio::test]
    async fn test_kcpconn_reorder() {
        let (mut a, mut b) = lossy_conn_pair(0, true);
        let size = 32 * 1024;
        let data: Vec<u8> = (0..size).map(|i| (i % 173) as u8).collect();
        let data2 = data.clone();

        let writer = tokio::spawn(async move {
            for chunk in data2.chunks(256) {
                a.write_all(chunk).await.unwrap();
            }
        });

        let mut received = Vec::with_capacity(size);
        let mut buf = vec![0u8; 8192];
        while received.len() < size {
            match tokio::time::timeout(Duration::from_secs(10), b.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => received.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
        writer.await.unwrap();
        assert_eq!(received.len(), size, "reorder: all data must arrive");
        assert_eq!(received, data);
    }

    /// yamux over KCP with 5% loss — multi-stream data integrity.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_yamux_loss_5pct() {
        use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use futures::TryStreamExt;

        let (a, b) = lossy_conn_pair(5, false);

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
            let mut pending: Vec<tokio::sync::oneshot::Sender<yamux::Stream>> = Vec::new();
            futures::future::poll_fn(|cx| {
                loop {
                    let mut progress = false;
                    while let std::task::Poll::Ready(Some(tx)) = open_rx.poll_recv(cx) {
                        pending.push(tx); progress = true;
                    }
                    while !pending.is_empty() {
                        match client_conn.poll_new_outbound(cx) {
                            std::task::Poll::Ready(Ok(s)) => { let _ = pending.remove(0).send(s); progress = true; }
                            std::task::Poll::Ready(Err(_)) => { pending.remove(0); progress = true; }
                            std::task::Poll::Pending => break,
                        }
                    }
                    match client_conn.poll_next_inbound(cx) {
                        std::task::Poll::Ready(Some(Ok(_))) => { progress = true; continue; }
                        std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => return std::task::Poll::Ready(()),
                        std::task::Poll::Pending => {}
                    }
                    if !progress { return std::task::Poll::Pending; }
                }
            }).await;
        });

        for i in 0..5 {
            let (tx, rx) = tokio::sync::oneshot::channel();
            open_tx.send(tx).await.unwrap();
            let mut s = tokio::time::timeout(Duration::from_secs(10), rx).await
                .expect(&format!("open {} timed out", i)).unwrap();
            let msg = format!("loss-stream-{}-data-payload", i);
            s.write_all(msg.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; 256];
            let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf)).await
                .expect("read timed out").unwrap();
            assert_eq!(&buf[..n], msg.as_bytes(), "stream {} echo mismatch", i);
            s.close().await.unwrap();
        }

        driver.abort();
        server.abort();
    }

    /// 100 concurrent yamux streams — scale test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_yamux_multi_stream_100() {
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

        let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<yamux::Stream>>(64);
        let driver = tokio::spawn(async move {
            let mut pending: Vec<tokio::sync::oneshot::Sender<yamux::Stream>> = Vec::new();
            futures::future::poll_fn(|cx| {
                loop {
                    let mut progress = false;
                    while let std::task::Poll::Ready(Some(tx)) = open_rx.poll_recv(cx) {
                        pending.push(tx); progress = true;
                    }
                    while !pending.is_empty() {
                        match client_conn.poll_new_outbound(cx) {
                            std::task::Poll::Ready(Ok(s)) => { let _ = pending.remove(0).send(s); progress = true; }
                            std::task::Poll::Ready(Err(_)) => { pending.remove(0); progress = true; }
                            std::task::Poll::Pending => break,
                        }
                    }
                    match client_conn.poll_next_inbound(cx) {
                        std::task::Poll::Ready(Some(Ok(_))) => { progress = true; continue; }
                        std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => return std::task::Poll::Ready(()),
                        std::task::Poll::Pending => {}
                    }
                    if !progress { return std::task::Poll::Pending; }
                }
            }).await;
        });

        let mut handles = Vec::new();
        let open = open_tx.clone();
        for i in 0..100 {
            let open = open.clone();
            handles.push(tokio::spawn(async move {
                let (tx, rx) = tokio::sync::oneshot::channel();
                open.send(tx).await.unwrap();
                let mut s = tokio::time::timeout(Duration::from_secs(10), rx).await
                    .expect(&format!("open {} timed out", i)).unwrap();
                let msg = format!("s{:03}", i);
                s.write_all(msg.as_bytes()).await.unwrap();
                let mut buf = vec![0u8; 256];
                let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf)).await
                    .expect("read timed out").unwrap();
                assert_eq!(&buf[..n], msg.as_bytes());
                s.close().await.unwrap();
            }));
        }
        for h in handles { h.await.unwrap(); }

        driver.abort();
        server.abort();
    }

    /// Throughput benchmark: single direction, varying chunk sizes.
    #[tokio::test]
    async fn test_bench_throughput_sizes() {
        for &chunk_size in &[64usize, 512, 1024, 4096, 8192, 32768] {
            let (mut a, mut b) = conn_pair();
            let total = std::cmp::max(chunk_size * 500, 256 * 1024);
            let data = vec![0x58u8; chunk_size];

            let writer = tokio::spawn(async move {
                let mut written = 0;
                while written < total {
                    a.write_all(&data).await.unwrap();
                    written += data.len();
                }
            });

            let start = std::time::Instant::now();
            let mut received = 0usize;
            let mut buf = vec![0u8; 65536];
            while received < total {
                let n = b.read(&mut buf).await.unwrap();
                if n == 0 { break; }
                received += n;
            }
            let elapsed = start.elapsed();
            writer.await.unwrap();

            let mbps = received as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
            eprintln!("[throughput] chunk={:>5}B  total={:>7}B  elapsed={:>8.2?}  {:.1} MB/s",
                chunk_size, received, elapsed, mbps);
        }
    }

    /// Yamux throughput: 1 stream, single direction echo.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_bench_yamux_throughput_1() {
        use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use futures::TryStreamExt;

        let (a, b) = conn_pair();
        let mut server_conn = yamux::Connection::new(b, yamux::Config::default(), yamux::Mode::Server);
        let mut client_conn = yamux::Connection::new(a, yamux::Config::default(), yamux::Mode::Client);

        let server = tokio::spawn(async move {
            futures::stream::poll_fn(|cx| server_conn.poll_next_inbound(cx))
                .try_for_each_concurrent(None, |mut stream| async move {
                    let mut buf = vec![0u8; 65536];
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
            let mut pending: Vec<tokio::sync::oneshot::Sender<yamux::Stream>> = Vec::new();
            futures::future::poll_fn(|cx| {
                loop {
                    let mut progress = false;
                    while let std::task::Poll::Ready(Some(tx)) = open_rx.poll_recv(cx) {
                        pending.push(tx); progress = true;
                    }
                    while !pending.is_empty() {
                        match client_conn.poll_new_outbound(cx) {
                            std::task::Poll::Ready(Ok(s)) => { let _ = pending.remove(0).send(s); progress = true; }
                            std::task::Poll::Ready(Err(_)) => { pending.remove(0); progress = true; }
                            std::task::Poll::Pending => break,
                        }
                    }
                    match client_conn.poll_next_inbound(cx) {
                        std::task::Poll::Ready(Some(Ok(_))) => { progress = true; continue; }
                        std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => return std::task::Poll::Ready(()),
                        std::task::Poll::Pending => {}
                    }
                    if !progress { return std::task::Poll::Pending; }
                }
            }).await;
        });

        let iterations = 500;
        let chunk_size = 8192;
        let chunk = vec![0x58u8; chunk_size];
        let (tx, rx) = tokio::sync::oneshot::channel();
        open_tx.send(tx).await.unwrap();
        let mut s = rx.await.unwrap();

        let start = std::time::Instant::now();
        let mut total_bytes = 0usize;
        let mut buf = vec![0u8; 65536];
        for _ in 0..iterations {
            s.write_all(&chunk).await.unwrap();
            let mut got = 0;
            while got < chunk_size {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 { break; }
                got += n;
            }
            total_bytes += got;
        }
        let elapsed = start.elapsed();

        let mbps = total_bytes as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
        eprintln!("[yamux throughput 1-stream] {} iters, {} bytes in {:?} = {:.1} MB/s",
            iterations, total_bytes, elapsed, mbps);
        s.close().await.ok();

        driver.abort();
        server.abort();
    }

    /// Yamux throughput: 10 concurrent streams, single direction echo.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_bench_yamux_throughput_10() {
        use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use futures::TryStreamExt;

        let (a, b) = conn_pair();
        let mut server_conn = yamux::Connection::new(b, yamux::Config::default(), yamux::Mode::Server);
        let mut client_conn = yamux::Connection::new(a, yamux::Config::default(), yamux::Mode::Client);

        let server = tokio::spawn(async move {
            futures::stream::poll_fn(|cx| server_conn.poll_next_inbound(cx))
                .try_for_each_concurrent(None, |mut stream| async move {
                    let mut buf = vec![0u8; 65536];
                    loop {
                        let n = stream.read(&mut buf).await?;
                        if n == 0 { break; }
                        stream.write_all(&buf[..n]).await?;
                    }
                    stream.close().await?;
                    Ok(())
                }).await.ok();
        });

        let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<yamux::Stream>>(16);
        let driver = tokio::spawn(async move {
            let mut pending: Vec<tokio::sync::oneshot::Sender<yamux::Stream>> = Vec::new();
            futures::future::poll_fn(|cx| {
                loop {
                    let mut progress = false;
                    while let std::task::Poll::Ready(Some(tx)) = open_rx.poll_recv(cx) {
                        pending.push(tx); progress = true;
                    }
                    while !pending.is_empty() {
                        match client_conn.poll_new_outbound(cx) {
                            std::task::Poll::Ready(Ok(s)) => { let _ = pending.remove(0).send(s); progress = true; }
                            std::task::Poll::Ready(Err(_)) => { pending.remove(0); progress = true; }
                            std::task::Poll::Pending => break,
                        }
                    }
                    match client_conn.poll_next_inbound(cx) {
                        std::task::Poll::Ready(Some(Ok(_))) => { progress = true; continue; }
                        std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => return std::task::Poll::Ready(()),
                        std::task::Poll::Pending => {}
                    }
                    if !progress { return std::task::Poll::Pending; }
                }
            }).await;
        });

        let iterations = 100;
        let chunk_size = 8192;
        let chunk = vec![0x58u8; chunk_size];
        let start = std::time::Instant::now();

        // Open all 10 streams first.
        let mut streams = Vec::new();
        for _ in 0..10 {
            let (tx, rx) = tokio::sync::oneshot::channel();
            open_tx.send(tx).await.unwrap();
            let s = rx.await.unwrap();
            streams.push(s);
        }

        // Run all 10 in parallel: write chunk → read echo → repeat.
        let mut handles = Vec::new();
        for mut s in streams {
            let chunk = chunk.clone();
            handles.push(tokio::spawn(async move {
                let mut total_bytes = 0usize;
                let mut buf = vec![0u8; 65536];
                for _ in 0..iterations {
                    s.write_all(&chunk).await.unwrap();
                    let mut got = 0;
                    while got < chunk_size {
                        let n = s.read(&mut buf).await.unwrap();
                        if n == 0 { break; }
                        got += n;
                    }
                    total_bytes += got;
                }
                s.close().await.ok();
                total_bytes
            }));
        }

        let mut total = 0usize;
        for h in handles { total += h.await.unwrap(); }
        let elapsed = start.elapsed();
        let mbps = total as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
        eprintln!("[yamux throughput 10-stream] {} bytes in {:?} = {:.1} MB/s", total, elapsed, mbps);

        driver.abort();
        server.abort();
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
