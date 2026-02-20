//! KcpConn — wraps KCP as a reliable byte stream with an internal thread.
//!
//! All KCP operations (send, recv, input, update, flush) execute exclusively
//! in the internal thread. External callers communicate via channels.

use super::kcp::Kcp;
use crossbeam_channel::{self, Receiver, Sender, TryRecvError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Output function: called when KCP wants to send a packet over the wire.
pub type OutputFn = Box<dyn Fn(&[u8]) + Send + Sync>;


/// KcpConn wraps a KCP instance with a dedicated thread for all KCP operations.
///
/// The thread handles: Input (incoming packets), Write (outgoing data),
/// Update (KCP timer driven by Check()), and Recv (reassembled data).
///
/// Received data is pushed to `recv_tx` (tokio mpsc) for the async side.
pub struct KcpConn {
    input_tx: Sender<Vec<u8>>,
    write_tx: Sender<Vec<u8>>,
    recv_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    closed: Arc<AtomicBool>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl KcpConn {
    /// Create a new KcpConn.
    ///
    /// - `conv`: KCP conversation ID
    /// - `output`: called when KCP sends packets over the wire
    /// - `recv_tx`: tokio mpsc sender for delivering received data to async side
    pub fn new(
        conv: u32,
        output: OutputFn,
        recv_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let (input_tx, input_rx) = crossbeam_channel::bounded(256);
        let (write_tx, write_rx) = crossbeam_channel::bounded::<Vec<u8>>(64);
        let closed = Arc::new(AtomicBool::new(false));
        let closed2 = closed.clone();
        let recv_tx2 = recv_tx.clone();

        let handle = thread::spawn(move || {
            run_loop(conv, output, input_rx, write_rx, recv_tx2, closed2);
        });

        KcpConn {
            input_tx,
            write_tx,
            recv_tx,
            closed,
            join_handle: Some(handle),
        }
    }

    /// Feed an incoming KCP packet from the network layer.
    pub fn input(&self, data: &[u8]) -> Result<(), &'static str> {
        if self.closed.load(Ordering::Relaxed) {
            return Err("kcp conn closed");
        }
        self.input_tx
            .try_send(data.to_vec())
            .map_err(|_| "input channel full or closed")
    }

    /// Send data through KCP (fire-and-forget, non-blocking).
    /// Data is queued to the KCP thread which will call kcp.send + flush.
    pub fn write(&self, data: &[u8]) -> Result<usize, String> {
        if self.closed.load(Ordering::Relaxed) {
            return Err("kcp conn closed".into());
        }
        let len = data.len();
        self.write_tx
            .try_send(data.to_vec())
            .map_err(|_| "write channel full or closed".to_string())?;
        Ok(len)
    }

    /// Close the connection and join the internal thread.
    pub fn close(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        // Drop channels to unblock the thread
        drop(self.input_tx.clone()); // Keep original alive until struct drops
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for KcpConn {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_loop(
    conv: u32,
    output: OutputFn,
    input_rx: Receiver<Vec<u8>>,
    write_rx: Receiver<Vec<u8>>,
    recv_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    closed: Arc<AtomicBool>,
) {
    let output_fn: super::kcp::OutputFn = Box::new(move |data: &[u8]| {
        output(data);
    });
    let mut kcp = Kcp::new(conv, output_fn);
    kcp.set_default_config();

    let start = Instant::now();
    let mut recv_buf = vec![0u8; 64 * 1024];

    loop {
        if closed.load(Ordering::Relaxed) {
            return;
        }

        let now_ms = start.elapsed().as_millis() as u32;
        let next_update = kcp.check(now_ms);
        let delay = if next_update <= now_ms {
            Duration::from_millis(1)
        } else {
            Duration::from_millis((next_update - now_ms) as u64)
        };

        // Wait for input, write request, or timer
        crossbeam_channel::select! {
            recv(input_rx) -> msg => {
                match msg {
                    Ok(data) => {
                        kcp.input(&data);
                        drain_input(&input_rx, &mut kcp);
                        let now_ms = start.elapsed().as_millis() as u32;
                        kcp.update(now_ms);
                        drain_recv(&mut kcp, &mut recv_buf, &recv_tx);
                    }
                    Err(_) => return, // channel closed
                }
            }
            recv(write_rx) -> msg => {
                match msg {
                    Ok(data) => {
                        kcp.send(&data);
                        kcp.flush();
                        drain_recv(&mut kcp, &mut recv_buf, &recv_tx);
                    }
                    Err(_) => return,
                }
            }
            default(delay) => {
                let now_ms = start.elapsed().as_millis() as u32;
                kcp.update(now_ms);
                drain_recv(&mut kcp, &mut recv_buf, &recv_tx);
            }
        }
    }
}

fn drain_input(rx: &Receiver<Vec<u8>>, kcp: &mut Kcp) {
    loop {
        match rx.try_recv() {
            Ok(data) => { kcp.input(&data); }
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => return,
        }
    }
}

fn drain_recv(
    kcp: &mut Kcp,
    buf: &mut [u8],
    tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    loop {
        let size = kcp.peek_size();
        if size <= 0 {
            return;
        }
        let n = kcp.recv(buf);
        if n <= 0 {
            return;
        }
        let _ = tx.try_send(buf[..n as usize].to_vec());
    }
}
