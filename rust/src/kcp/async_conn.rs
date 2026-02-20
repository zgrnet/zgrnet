//! AsyncKcpConn — async adapter for KcpConn.
//!
//! Implements `tokio::io::AsyncRead + AsyncWrite` by bridging to the
//! sync KCP thread via tokio mpsc channels.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::conn::{KcpConn, OutputFn, WriteError};

/// AsyncKcpConn provides AsyncRead + AsyncWrite over a KcpConn.
pub struct AsyncKcpConn {
    conn: Arc<KcpConn>,
    recv_rx: futures::channel::mpsc::Receiver<Vec<u8>>,
    recv_buf: Vec<u8>,
    closed: bool,
}

impl AsyncKcpConn {
    pub fn new(conn: Arc<KcpConn>, recv_rx: futures::channel::mpsc::Receiver<Vec<u8>>) -> Self {
        AsyncKcpConn {
            conn,
            recv_rx,
            recv_buf: Vec::new(),
            closed: false,
        }
    }

    pub fn input(&self, data: &[u8]) -> Result<(), &'static str> {
        self.conn.input(data)
    }

    pub fn kcp_conn(&self) -> &Arc<KcpConn> {
        &self.conn
    }
}

impl AsyncRead for AsyncKcpConn {
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

        if self.closed {
            return Poll::Ready(Ok(()));
        }

        use futures::Stream;
        match Pin::new(&mut self.recv_rx).poll_next(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.recv_buf.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AsyncKcpConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed || self.conn.is_closed() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")));
        }

        match self.conn.try_write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(WriteError::Full) => {
                // Backpressure: schedule a wake and return Pending.
                // The KCP thread will drain the channel, making space.
                let waker = cx.waker().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    waker.wake();
                });
                Poll::Pending
            }
            Err(WriteError::Closed) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

impl Unpin for AsyncKcpConn {}

impl futures::io::AsyncRead for AsyncKcpConn {
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

        if self.closed {
            return Poll::Ready(Ok(0));
        }

        use futures::Stream;
        match Pin::new(&mut self.recv_rx).poll_next(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.len(), data.len());
                buf[..n].copy_from_slice(&data[..n]);
                if n < data.len() {
                    self.recv_buf.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(Ok(0))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl futures::io::AsyncWrite for AsyncKcpConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed || self.conn.is_closed() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")));
        }

        match self.conn.try_write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(super::conn::WriteError::Full) => {
                let waker = cx.waker().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    waker.wake();
                });
                Poll::Pending
            }
            Err(super::conn::WriteError::Closed) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
pub fn async_conn_pair() -> (AsyncKcpConn, AsyncKcpConn) {
    use std::sync::Mutex;

    let b_conn_slot: Arc<Mutex<Option<Arc<KcpConn>>>> = Arc::new(Mutex::new(None));
    let a_conn_slot: Arc<Mutex<Option<Arc<KcpConn>>>> = Arc::new(Mutex::new(None));

    let (a_recv_tx, a_recv_rx) = futures::channel::mpsc::channel(256);
    let (b_recv_tx, b_recv_rx) = futures::channel::mpsc::channel(256);

    let b_slot = b_conn_slot.clone();
    let a_conn = Arc::new(KcpConn::new(
        1,
        Box::new(move |data: &[u8]| {
            if let Some(ref b) = *b_slot.lock().unwrap() {
                let r = b.input(data);
                if r.is_err() {
                    eprintln!("[a→b] input failed: {:?}, {} bytes", r, data.len());
                }
            }
        }),
        a_recv_tx,
    ));

    let a_slot = a_conn_slot.clone();
    let b_conn = Arc::new(KcpConn::new(
        1,
        Box::new(move |data: &[u8]| {
            if let Some(ref a) = *a_slot.lock().unwrap() {
                let r = a.input(data);
                if r.is_err() {
                    eprintln!("[b→a] input failed: {:?}, {} bytes", r, data.len());
                }
            }
        }),
        b_recv_tx,
    ));

    *b_conn_slot.lock().unwrap() = Some(b_conn.clone());
    *a_conn_slot.lock().unwrap() = Some(a_conn.clone());

    let a = AsyncKcpConn::new(a_conn, a_recv_rx);
    let b = AsyncKcpConn::new(b_conn, b_recv_rx);
    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_async_kcpconn_write_read() {
        let (mut a, mut b) = async_conn_pair();
        a.write_all(b"hello from A").await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from A");
    }

    #[tokio::test]
    async fn test_async_kcpconn_bidirectional() {
        let (mut a, mut b) = async_conn_pair();
        a.write_all(b"from A").await.unwrap();
        b.write_all(b"from B").await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from A");
        let n = a.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from B");
    }

    #[tokio::test]
    async fn test_async_kcpconn_large_data() {
        let (mut a, mut b) = async_conn_pair();
        let send_data: Vec<u8> = (0..32768).map(|i| (i & 0xFF) as u8).collect();
        let send_data2 = send_data.clone();
        let writer = tokio::spawn(async move {
            for chunk in send_data2.chunks(1024) {
                a.write_all(chunk).await.unwrap();
            }
        });
        let mut received = Vec::new();
        let mut buf = vec![0u8; 4096];
        while received.len() < send_data.len() {
            let n = b.read(&mut buf).await.unwrap();
            if n == 0 { break; }
            received.extend_from_slice(&buf[..n]);
        }
        writer.await.unwrap();
        assert_eq!(received, send_data);
    }

    #[tokio::test]
    async fn test_async_kcpconn_shutdown() {
        let (mut a, mut _b) = async_conn_pair();
        a.shutdown().await.unwrap();
        let result = a.write_all(b"should fail").await;
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_yamux_simplest() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let mut client_conn = yamux::Connection::new(
            tokio_util::compat::TokioAsyncReadCompatExt::compat(client_io),
            yamux::Config::default(), yamux::Mode::Client);
        let mut server_conn = yamux::Connection::new(
            tokio_util::compat::TokioAsyncReadCompatExt::compat(server_io),
            yamux::Config::default(), yamux::Mode::Server);

        let client_task = tokio::spawn(async move {
            futures::future::poll_fn(|cx| client_conn.poll_new_outbound(cx)).await
        });

        let server_task = tokio::spawn(async move {
            futures::future::poll_fn(|cx| server_conn.poll_next_inbound(cx)).await
        });

        let (client_result, server_result) = tokio::join!(
            tokio::time::timeout(std::time::Duration::from_secs(3), client_task),
            tokio::time::timeout(std::time::Duration::from_secs(3), server_task),
        );

        assert!(client_result.is_ok(), "client open timed out");
        assert!(server_result.is_ok(), "server accept timed out");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_yamux_over_duplex() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let client_conn = yamux::Connection::new(
            tokio_util::compat::TokioAsyncReadCompatExt::compat(client_io),
            yamux::Config::default(), yamux::Mode::Client);
        let server_conn = yamux::Connection::new(
            tokio_util::compat::TokioAsyncReadCompatExt::compat(server_io),
            yamux::Config::default(), yamux::Mode::Server);

        let (accept_tx, mut accept_rx) = tokio::sync::mpsc::channel::<yamux::Stream>(1);
        let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<Result<yamux::Stream, String>>>(1);

        // Server: just drive poll_next_inbound
        let server_task = tokio::spawn(async move {
            let mut conn = server_conn;
            loop {
                let stream = futures::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await;
                match stream {
                    Some(Ok(s)) => { let _ = accept_tx.send(s).await; }
                    _ => return,
                }
            }
        });

        // Client: drive poll_next_inbound (which processes ALL protocol),
        // and handle open requests by interleaving poll_new_outbound.
        let client_task = tokio::spawn(async move {
            let mut conn = client_conn;
            let mut pending: Option<tokio::sync::oneshot::Sender<Result<yamux::Stream, String>>> = None;

            futures::future::poll_fn(|cx| {
                loop {
                    let mut progress = false;

                    // ALWAYS drive the connection (processes reads, writes, ACKs)
                    match conn.poll_next_inbound(cx) {
                        std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => {
                            return std::task::Poll::Ready(());
                        }
                        std::task::Poll::Ready(Some(Ok(_))) => { progress = true; }
                        std::task::Poll::Pending => {}
                    }

                    // Check for open requests
                    if pending.is_none() {
                        match open_rx.poll_recv(cx) {
                            std::task::Poll::Ready(Some(tx)) => {
                                pending = Some(tx);
                                progress = true;
                            }
                            std::task::Poll::Ready(None) => return std::task::Poll::Ready(()),
                            std::task::Poll::Pending => {}
                        }
                    }

                    // Process outbound open
                    if pending.is_some() {
                        match conn.poll_new_outbound(cx) {
                            std::task::Poll::Ready(result) => {
                                if let Some(tx) = pending.take() {
                                    let _ = tx.send(result.map_err(|e| e.to_string()));
                                }
                                progress = true;
                            }
                            std::task::Poll::Pending => {}
                        }
                    }

                    if !progress {
                        return std::task::Poll::Pending;
                    }
                }
            }).await;
        });

        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        open_tx.send(result_tx).await.unwrap();

        let stream = tokio::time::timeout(std::time::Duration::from_secs(3), result_rx).await;
        assert!(stream.is_ok(), "yamux over duplex: open timed out");

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(3), accept_rx.recv()).await;
        assert!(accepted.is_ok(), "yamux over duplex: accept timed out");

        client_task.abort();
        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_yamux_over_kcpconn_simplest() {
        let (a, b) = async_conn_pair();

        let mut client_conn = yamux::Connection::new(a, yamux::Config::default(), yamux::Mode::Client);
        let mut server_conn = yamux::Connection::new(b, yamux::Config::default(), yamux::Mode::Server);

        // Both in same task, polling alternately with yields
        use futures::FutureExt;

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut client_stream = None;
            let mut server_stream = None;

            for _ in 0..1000 {
                if client_stream.is_none() {
                    let result = futures::future::poll_fn(|cx| {
                        client_conn.poll_new_outbound(cx)
                    }).now_or_never();
                    if let Some(Ok(s)) = result {
                        client_stream = Some(s);
                    }
                }

                if server_stream.is_none() {
                    let result = futures::future::poll_fn(|cx| {
                        server_conn.poll_next_inbound(cx)
                    }).now_or_never();
                    if let Some(Some(Ok(s))) = result {
                        server_stream = Some(s);
                    }
                }

                if client_stream.is_some() && server_stream.is_some() {
                    return;
                }

                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }

            panic!("failed: client={}, server={}", client_stream.is_some(), server_stream.is_some());
        }).await;

        assert!(result.is_ok(), "yamux over kcpconn: timed out");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_async_kcpconn_yamux_basic() {
        use futures::io::{AsyncReadExt as FutAsyncReadExt, AsyncWriteExt as FutAsyncWriteExt};

        let (a, b) = async_conn_pair();

        let client_conn = yamux::Connection::new(a, yamux::Config::default(), yamux::Mode::Client);
        let server_conn = yamux::Connection::new(b, yamux::Config::default(), yamux::Mode::Server);

        eprintln!("[test] yamux basic: starting");

        let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<Result<yamux::Stream, String>>>(1);
        let (accept_tx, mut accept_rx) = tokio::sync::mpsc::channel::<yamux::Stream>(1);

        let client_task = tokio::spawn(async move {
            let mut conn = client_conn;
            let mut pending: Option<tokio::sync::oneshot::Sender<Result<yamux::Stream, String>>> = None;

            futures::future::poll_fn(|cx| {
                // Inbound (shouldn't get any as client, but drive state machine)
                match conn.poll_next_inbound(cx) {
                    std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => return std::task::Poll::Ready(()),
                    _ => {}
                }
                // Open requests
                if pending.is_none() {
                    match open_rx.poll_recv(cx) {
                        std::task::Poll::Ready(Some(tx)) => { pending = Some(tx); }
                        std::task::Poll::Ready(None) => return std::task::Poll::Ready(()),
                        std::task::Poll::Pending => {}
                    }
                }
                if pending.is_some() {
                    match conn.poll_new_outbound(cx) {
                        std::task::Poll::Ready(result) => {
                            let tx = pending.take().unwrap();
                            let _ = tx.send(result.map_err(|e| e.to_string()));
                        }
                        std::task::Poll::Pending => {}
                    }
                }
                std::task::Poll::Pending
            }).await;
        });

        let server_task = tokio::spawn(async move {
            let mut conn = server_conn;
            loop {
                let result = futures::future::poll_fn(|cx| {
                    match conn.poll_next_inbound(cx) {
                        std::task::Poll::Ready(r) => std::task::Poll::Ready(r),
                        std::task::Poll::Pending => {
                            // Force re-poll after a short delay
                            let waker = cx.waker().clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                                waker.wake();
                            });
                            std::task::Poll::Pending
                        }
                    }
                }).await;
                match result {
                    Some(Ok(s)) => {
                        let _ = accept_tx.send(s).await;
                    }
                    _ => return,
                }
            }
        });

        eprintln!("[test] yamux basic: requesting open");
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        open_tx.send(result_tx).await.unwrap();

        eprintln!("[test] yamux basic: waiting for open result");
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), result_rx).await;
        match result {
            Ok(Ok(Ok(mut stream))) => {
                eprintln!("[test] yamux basic: stream opened!");
                stream.close().await.unwrap();
            }
            Ok(Ok(Err(e))) => panic!("open_stream error: {}", e),
            Ok(Err(_)) => panic!("oneshot cancelled"),
            Err(_) => panic!("TIMEOUT: yamux open_stream took >5s"),
        }

        eprintln!("[test] yamux basic: waiting for accept");
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), accept_rx.recv()).await;
        match result {
            Ok(Some(mut stream)) => {
                eprintln!("[test] yamux basic: stream accepted!");
                stream.close().await.unwrap();
            }
            Ok(None) => panic!("accept channel closed"),
            Err(_) => panic!("TIMEOUT: yamux accept took >5s"),
        }

        eprintln!("[test] yamux basic: PASS");
        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn test_recv_channel_direct() {
        let (mut tx, mut rx) = futures::channel::mpsc::channel::<Vec<u8>>(256);
        tx.try_send(b"hello".to_vec()).unwrap();

        use futures::Stream;
        let result = futures::future::poll_fn(|cx| {
            Pin::new(&mut rx).poll_next(cx)
        }).await;
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn test_async_kcpconn_small_messages() {
        let (mut a, mut b) = async_conn_pair();
        let total_msgs = 100;
        let msg_size = 64;
        for i in 0..total_msgs {
            let msg = vec![i as u8; msg_size];
            a.write_all(&msg).await.unwrap();
        }
        let expected_total = total_msgs * msg_size;
        let mut received = 0;
        let mut buf = vec![0u8; 4096];
        while received < expected_total {
            let n = b.read(&mut buf).await.unwrap();
            if n == 0 { break; }
            received += n;
        }
        assert_eq!(received, expected_total);
    }
}
