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
pub struct KcpConn {
    input_tx: Sender<Vec<u8>>,
    write_tx: Sender<Vec<u8>>,
    closed: Arc<AtomicBool>,
    join_handle: std::sync::Mutex<Option<thread::JoinHandle<()>>>,
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
        recv_tx: futures::channel::mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let (input_tx, input_rx) = crossbeam_channel::bounded(256);
        let (write_tx, write_rx) = crossbeam_channel::bounded::<Vec<u8>>(256);
        let closed = Arc::new(AtomicBool::new(false));
        let closed2 = closed.clone();

        let handle = thread::spawn(move || {
            run_loop(conv, output, input_rx, write_rx, recv_tx, closed2);
        });

        KcpConn {
            input_tx,
            write_tx,
            closed,
            join_handle: std::sync::Mutex::new(Some(handle)),
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

    /// Send data through KCP (blocks if write channel is full — backpressure).
    pub fn write_blocking(&self, data: &[u8]) -> Result<usize, String> {
        if self.closed.load(Ordering::Relaxed) {
            return Err("kcp conn closed".into());
        }
        let len = data.len();
        self.write_tx
            .send(data.to_vec())
            .map_err(|_| "write channel closed".to_string())?;
        Ok(len)
    }

    /// Try to send data without blocking. Returns Err if channel is full.
    pub fn try_write(&self, data: &[u8]) -> Result<usize, WriteError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(WriteError::Closed);
        }
        let len = data.len();
        self.write_tx.try_send(data.to_vec()).map_err(|e| match e {
            crossbeam_channel::TrySendError::Full(_) => WriteError::Full,
            crossbeam_channel::TrySendError::Disconnected(_) => WriteError::Closed,
        })?;
        Ok(len)
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

/// Write errors.
#[derive(Debug)]
pub enum WriteError {
    Full,
    Closed,
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteError::Full => write!(f, "write channel full"),
            WriteError::Closed => write!(f, "kcp conn closed"),
        }
    }
}

impl Drop for KcpConn {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        if let Some(handle) = self.join_handle.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

fn run_loop(
    conv: u32,
    output: OutputFn,
    input_rx: Receiver<Vec<u8>>,
    write_rx: Receiver<Vec<u8>>,
    recv_tx: futures::channel::mpsc::Sender<Vec<u8>>,
    closed: Arc<AtomicBool>,
) {
    let output_fn: super::kcp::OutputFn = Box::new(move |data: &[u8]| {
        output(data);
    });
    let mut kcp = Kcp::new(conv, output_fn);
    kcp.set_default_config();

    let start = Instant::now();
    let mut recv_buf = vec![0u8; 64 * 1024];
    let mut recv_tx = recv_tx;

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

        crossbeam_channel::select! {
            recv(input_rx) -> msg => {
                match msg {
                    Ok(data) => {
                        kcp.input(&data);
                        drain_input(&input_rx, &mut kcp);
                        let now_ms = start.elapsed().as_millis() as u32;
                        kcp.update(now_ms);
                        drain_recv(&mut kcp, &mut recv_buf, &mut recv_tx);
                    }
                    Err(_) => return,
                }
            }
            recv(write_rx) -> msg => {
                match msg {
                    Ok(data) => {
                        kcp.send(&data);
                        loop {
                            match write_rx.try_recv() {
                                Ok(more) => { kcp.send(&more); }
                                Err(_) => break,
                            }
                        }
                        kcp.flush();
                        drain_recv(&mut kcp, &mut recv_buf, &mut recv_tx);
                    }
                    Err(_) => return,
                }
            }
            default(delay) => {
                let now_ms = start.elapsed().as_millis() as u32;
                kcp.update(now_ms);
                drain_recv(&mut kcp, &mut recv_buf, &mut recv_tx);
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
    tx: &mut futures::channel::mpsc::Sender<Vec<u8>>,
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
        let data = buf[..n as usize].to_vec();
        let _ = tx.try_send(data);
    }
}
