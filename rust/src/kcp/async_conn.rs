//! AsyncKcpConn — async adapter for KcpConn.
//!
//! Implements `tokio::io::AsyncRead + AsyncWrite` by bridging to the
//! sync KCP thread via tokio mpsc channels.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::conn::KcpConn;

/// AsyncKcpConn provides AsyncRead + AsyncWrite over a KcpConn.
pub struct AsyncKcpConn {
    conn: Arc<KcpConn>,
    recv_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    recv_buf: Vec<u8>,
    closed: bool,
}

impl AsyncKcpConn {
    /// Create an AsyncKcpConn from a KcpConn and its recv channel.
    pub fn new(conn: Arc<KcpConn>, recv_rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        AsyncKcpConn {
            conn,
            recv_rx,
            recv_buf: Vec::new(),
            closed: false,
        }
    }

    /// Feed an incoming packet to the underlying KcpConn.
    pub fn input(&self, data: &[u8]) -> Result<(), &'static str> {
        self.conn.input(data)
    }

    /// Get a reference to the underlying KcpConn.
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

        match self.recv_rx.poll_recv(cx) {
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
        if self.closed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")));
        }

        match self.conn.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.contains("full") => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
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

/// Creates a connected pair of AsyncKcpConns for testing.
/// Packets from A's output are fed to B's input and vice versa.
#[cfg(test)]
pub fn async_conn_pair() -> (AsyncKcpConn, AsyncKcpConn) {
    use std::sync::Mutex;

    let b_conn_slot: Arc<Mutex<Option<Arc<KcpConn>>>> = Arc::new(Mutex::new(None));
    let a_conn_slot: Arc<Mutex<Option<Arc<KcpConn>>>> = Arc::new(Mutex::new(None));

    let (a_recv_tx, a_recv_rx) = tokio::sync::mpsc::channel(256);
    let (b_recv_tx, b_recv_rx) = tokio::sync::mpsc::channel(256);

    let b_slot = b_conn_slot.clone();
    let a_conn = Arc::new(KcpConn::new(
        1,
        Box::new(move |data: &[u8]| {
            if let Some(ref b) = *b_slot.lock().unwrap() {
                let _ = b.input(data);
            }
        }),
        a_recv_tx,
    ));

    let a_slot = a_conn_slot.clone();
    let b_conn = Arc::new(KcpConn::new(
        1,
        Box::new(move |data: &[u8]| {
            if let Some(ref a) = *a_slot.lock().unwrap() {
                let _ = a.input(data);
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
            if n == 0 {
                break;
            }
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
            if n == 0 {
                break;
            }
            received += n;
        }
        assert_eq!(received, expected_total);
    }
}
