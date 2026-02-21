//! Sync compatibility layer for yamux::Stream.
//!
//! Provides std::io::Read + Write wrappers around async yamux::Stream,
//! bridging sync upper layers (node.rs, zgrnetd.rs) to the async KCP/yamux stack.

use std::io;
use std::sync::Arc;

use futures::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

/// A synchronous wrapper around yamux::Stream.
/// Implements std::io::Read and std::io::Write by blocking on the async operations.
/// Must be used from outside a tokio async context (e.g., from std::thread).
pub struct SyncStream {
    inner: Arc<Mutex<yamux::Stream>>,
    rt: tokio::runtime::Handle,
}

impl SyncStream {
    pub fn new(stream: yamux::Stream, rt: tokio::runtime::Handle) -> Self {
        SyncStream {
            inner: Arc::new(Mutex::new(stream)),
            rt,
        }
    }

    pub fn close(&self) {
        let inner = self.inner.clone();
        let rt = self.rt.clone();
        let _ = tokio::task::block_in_place(|| {
            rt.block_on(async {
                let mut s = inner.lock().await;
                s.close().await
            })
        });
    }
}

impl Clone for SyncStream {
    fn clone(&self) -> Self {
        SyncStream {
            inner: self.inner.clone(),
            rt: self.rt.clone(),
        }
    }
}

impl io::Read for SyncStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let inner = self.inner.clone();
        let rt = self.rt.clone();
        tokio::task::block_in_place(|| {
            rt.block_on(async {
                let mut s = inner.lock().await;
                s.read(buf).await
            })
        })
    }
}

impl io::Write for SyncStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let inner = self.inner.clone();
        let rt = self.rt.clone();
        tokio::task::block_in_place(|| {
            rt.block_on(async {
                let mut s = inner.lock().await;
                s.write(buf).await
            })
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        let inner = self.inner.clone();
        let rt = self.rt.clone();
        tokio::task::block_in_place(|| {
            rt.block_on(async {
                let mut s = inner.lock().await;
                s.flush().await
            })
        })
    }
}
