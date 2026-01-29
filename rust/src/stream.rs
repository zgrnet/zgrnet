//! Stream - A multiplexed reliable stream over KCP.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::{Arc, Mutex, RwLock};

use crate::kcp::{Cmd, Frame, Kcp};

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Init,
    Open,
    LocalClose,  // We sent FIN
    RemoteClose, // We received FIN
    Closed,
}

/// Stream errors
#[derive(Debug)]
pub enum StreamError {
    StreamClosed,
    KcpSendFailed,
    Timeout,
    IoError(io::Error),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::StreamClosed => write!(f, "stream closed"),
            StreamError::KcpSendFailed => write!(f, "KCP send failed"),
            StreamError::Timeout => write!(f, "timeout"),
            StreamError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<io::Error> for StreamError {
    fn from(e: io::Error) -> Self {
        StreamError::IoError(e)
    }
}

/// Stream represents a multiplexed stream over KCP.
pub struct Stream {
    id: u32,
    kcp: Mutex<Kcp>,
    state: RwLock<StreamState>,
    recv_buf: Mutex<VecDeque<u8>>, // O(1) head removal
}

impl Stream {
    /// Create a new stream.
    #[allow(clippy::type_complexity)]
    pub(crate) fn new(id: u32, output: Box<dyn Fn(&[u8]) + Send + Sync>) -> Self {
        let mut kcp = Kcp::new(id, output);
        kcp.set_default_config();

        Stream {
            id,
            kcp: Mutex::new(kcp),
            state: RwLock::new(StreamState::Open),
            recv_buf: Mutex::new(VecDeque::new()),
        }
    }

    /// Get stream ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Get stream state.
    pub fn state(&self) -> StreamState {
        *self.state.read().unwrap()
    }

    /// Write data to the stream.
    pub fn write_data(&self, data: &[u8]) -> Result<usize, StreamError> {
        let state = self.state();
        if state == StreamState::Closed || state == StreamState::LocalClose {
            return Err(StreamError::StreamClosed);
        }

        let mut kcp = self.kcp.lock().unwrap();
        let n = kcp.send(data);
        if n < 0 {
            return Err(StreamError::KcpSendFailed);
        }

        Ok(n as usize)
    }

    /// Read data from the stream.
    pub fn read_data(&self, buf: &mut [u8]) -> Result<usize, StreamError> {
        let mut recv_buf = self.recv_buf.lock().unwrap();

        if recv_buf.is_empty() {
            let state = self.state();
            if state == StreamState::Closed || state == StreamState::RemoteClose {
                return Ok(0); // EOF
            }
            return Ok(0); // No data available
        }

        // Use as_slices() for efficient bulk copy instead of byte-by-byte
        let (s1, s2) = recv_buf.as_slices();
        let n1 = std::cmp::min(buf.len(), s1.len());
        buf[..n1].copy_from_slice(&s1[..n1]);

        let n2 = std::cmp::min(buf.len().saturating_sub(n1), s2.len());
        if n2 > 0 {
            buf[n1..n1 + n2].copy_from_slice(&s2[..n2]);
        }

        let total_read = n1 + n2;
        recv_buf.drain(..total_read);

        Ok(total_read)
    }

    /// Close the stream.
    pub fn close(&self) {
        let mut state = self.state.write().unwrap();
        if *state == StreamState::Closed {
            return;
        }

        if *state == StreamState::Open {
            *state = StreamState::LocalClose;
        } else {
            *state = StreamState::Closed;
        }
    }

    /// Input data from KCP.
    pub(crate) fn kcp_input(&self, data: &[u8]) {
        if self.state() == StreamState::Closed {
            return;
        }

        let mut kcp = self.kcp.lock().unwrap();
        kcp.input(data);
    }

    /// Receive data from KCP and buffer it.
    pub(crate) fn kcp_recv(&self) {
        let mut kcp = self.kcp.lock().unwrap();
        let mut recv_buf = self.recv_buf.lock().unwrap();

        loop {
            let size = kcp.peek_size();
            if size <= 0 {
                break;
            }

            // Allocate buffer on heap based on actual message size
            let mut buf = vec![0u8; size as usize];
            let n = kcp.recv(&mut buf);
            if n <= 0 {
                break;
            }

            recv_buf.extend(&buf[..n as usize]);
        }
    }

    /// Receive data directly from KCP into user-provided buffer (zero-copy fast path).
    /// Returns the number of bytes received, or 0 if no data available.
    /// This bypasses the internal recv_buf for lower latency when caller can process immediately.
    pub fn recv_into_buffer(&self, buf: &mut [u8]) -> Result<usize, StreamError> {
        // First drain any buffered data
        {
            let mut recv_buf = self.recv_buf.lock().unwrap();
            if !recv_buf.is_empty() {
                let (s1, s2) = recv_buf.as_slices();
                let n1 = std::cmp::min(buf.len(), s1.len());
                buf[..n1].copy_from_slice(&s1[..n1]);

                let n2 = std::cmp::min(buf.len().saturating_sub(n1), s2.len());
                if n2 > 0 {
                    buf[n1..n1 + n2].copy_from_slice(&s2[..n2]);
                }

                let total_read = n1 + n2;
                recv_buf.drain(..total_read);
                return Ok(total_read);
            }
        }

        // No buffered data, try direct receive from KCP
        let mut kcp = self.kcp.lock().unwrap();
        let size = kcp.peek_size();
        if size <= 0 {
            let state = self.state();
            if state == StreamState::Closed || state == StreamState::RemoteClose {
                return Ok(0); // EOF
            }
            return Ok(0); // No data available
        }

        // Direct receive into user buffer if it fits
        if buf.len() >= size as usize {
            let n = kcp.recv(buf);
            if n > 0 {
                return Ok(n as usize);
            }
        } else {
            // Buffer too small, need intermediate allocation
            let mut tmp = vec![0u8; size as usize];
            let n = kcp.recv(&mut tmp);
            if n > 0 {
                let copy_len = std::cmp::min(buf.len(), n as usize);
                buf[..copy_len].copy_from_slice(&tmp[..copy_len]);
                // Buffer remaining data
                if n as usize > copy_len {
                    let mut recv_buf = self.recv_buf.lock().unwrap();
                    recv_buf.extend(&tmp[copy_len..n as usize]);
                }
                return Ok(copy_len);
            }
        }

        Ok(0)
    }

    /// Update KCP state.
    pub(crate) fn kcp_update(&self, current: u32) {
        if self.state() == StreamState::Closed {
            return;
        }

        let mut kcp = self.kcp.lock().unwrap();
        kcp.update(current);
    }

    /// Handle FIN from remote.
    pub(crate) fn handle_fin(&self) {
        let mut state = self.state.write().unwrap();
        if *state == StreamState::LocalClose {
            *state = StreamState::Closed;
        } else if *state == StreamState::Open {
            *state = StreamState::RemoteClose;
        }
    }
}

/// Mux configuration
#[derive(Debug, Clone)]
pub struct MuxConfig {
    pub max_frame_size: usize,
    pub max_receive_buffer: usize,
    pub accept_backlog: usize,
}

impl Default for MuxConfig {
    fn default() -> Self {
        MuxConfig {
            max_frame_size: 32 * 1024,
            max_receive_buffer: 256 * 1024,
            accept_backlog: 256,
        }
    }
}

/// Output function type for Mux
pub type OutputFn = Box<dyn Fn(&[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> + Send + Sync>;

/// Mux multiplexes multiple streams over a single connection.
pub struct Mux {
    #[allow(dead_code)]
    config: MuxConfig,
    output: Arc<OutputFn>,
    #[allow(dead_code)]
    is_client: bool,
    streams: RwLock<HashMap<u32, Arc<Stream>>>,
    next_id: Mutex<u32>,
    accept_queue: Mutex<Vec<Arc<Stream>>>,
    closed: RwLock<bool>,
}

impl Mux {
    /// Create a new Mux.
    pub fn new(config: MuxConfig, is_client: bool, output: OutputFn) -> Self {
        Mux {
            config,
            output: Arc::new(output),
            is_client,
            streams: RwLock::new(HashMap::new()),
            next_id: Mutex::new(if is_client { 1 } else { 2 }),
            accept_queue: Mutex::new(Vec::new()),
            closed: RwLock::new(false),
        }
    }

    /// Open a new stream.
    pub fn open_stream(&self) -> Result<Arc<Stream>, MuxError> {
        if self.is_closed() {
            return Err(MuxError::MuxClosed);
        }

        let id = {
            let mut next_id = self.next_id.lock().unwrap();
            let id = *next_id;
            *next_id += 2;
            id
        };

        let output = self.output.clone();
        let stream = Arc::new(Stream::new(
            id,
            Box::new(move |data| {
                // Use encode_with_payload to avoid intermediate allocations
                let encoded = Frame::encode_with_payload(Cmd::Psh, id, data);
                if let Err(e) = output(&encoded) {
                    eprintln!("Mux output error: {}", e);
                }
            }),
        ));

        self.streams.write().unwrap().insert(id, stream.clone());

        // Send SYN
        self.send_syn(id)?;

        Ok(stream)
    }

    /// Accept an incoming stream.
    pub fn accept_stream(&self) -> Result<Arc<Stream>, MuxError> {
        if self.is_closed() {
            return Err(MuxError::MuxClosed);
        }

        let mut queue = self.accept_queue.lock().unwrap();
        if queue.is_empty() {
            return Err(MuxError::NoStreamAvailable);
        }

        Ok(queue.remove(0))
    }

    /// Get number of active streams.
    pub fn num_streams(&self) -> usize {
        self.streams.read().unwrap().len()
    }

    /// Check if closed.
    pub fn is_closed(&self) -> bool {
        *self.closed.read().unwrap()
    }

    /// Close the Mux.
    pub fn close(&self) {
        *self.closed.write().unwrap() = true;
    }

    /// Input a frame.
    pub fn input(&self, data: &[u8]) -> Result<(), MuxError> {
        if self.is_closed() {
            return Err(MuxError::MuxClosed);
        }

        let frame = Frame::decode(data).map_err(|_| MuxError::InvalidFrame)?;

        match frame.cmd {
            Cmd::Syn => self.handle_syn(frame.stream_id)?,
            Cmd::Fin => self.handle_fin(frame.stream_id),
            Cmd::Psh => self.handle_psh(frame.stream_id, &frame.payload),
            Cmd::Nop => {} // Keepalive
            Cmd::Upd => {} // TODO: Flow control
        }

        Ok(())
    }

    fn handle_syn(&self, id: u32) -> Result<(), MuxError> {
        if self.streams.read().unwrap().contains_key(&id) {
            return Ok(()); // Duplicate SYN
        }

        let output = self.output.clone();
        let stream = Arc::new(Stream::new(
            id,
            Box::new(move |data| {
                // Use encode_with_payload to avoid intermediate allocations
                let encoded = Frame::encode_with_payload(Cmd::Psh, id, data);
                if let Err(e) = output(&encoded) {
                    eprintln!("Mux output error: {}", e);
                }
            }),
        ));

        self.streams.write().unwrap().insert(id, stream.clone());
        self.accept_queue.lock().unwrap().push(stream);

        Ok(())
    }

    fn handle_fin(&self, id: u32) {
        if let Some(stream) = self.streams.read().unwrap().get(&id) {
            stream.handle_fin();
        }
    }

    fn handle_psh(&self, id: u32, payload: &[u8]) {
        if let Some(stream) = self.streams.read().unwrap().get(&id) {
            stream.kcp_input(payload);
            stream.kcp_recv();
        }
    }

    fn send_syn(&self, id: u32) -> Result<(), MuxError> {
        self.send_frame(Frame::new(Cmd::Syn, id, vec![]))
    }

    pub fn send_fin(&self, id: u32) -> Result<(), MuxError> {
        self.send_frame(Frame::new(Cmd::Fin, id, vec![]))
    }

    fn send_frame(&self, frame: Frame) -> Result<(), MuxError> {
        if self.is_closed() {
            return Err(MuxError::MuxClosed);
        }

        (self.output)(&frame.encode()).map_err(|_| MuxError::OutputFailed)?;
        Ok(())
    }

    /// Remove a stream.
    pub fn remove_stream(&self, id: u32) {
        self.streams.write().unwrap().remove(&id);
    }

    /// Update all streams.
    pub fn update(&self, current: u32) {
        for stream in self.streams.read().unwrap().values() {
            stream.kcp_update(current);
            stream.kcp_recv();
        }
    }
}

/// Mux errors
#[derive(Debug)]
pub enum MuxError {
    MuxClosed,
    NoStreamAvailable,
    InvalidFrame,
    OutputFailed,
}

impl std::fmt::Display for MuxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MuxError::MuxClosed => write!(f, "mux closed"),
            MuxError::NoStreamAvailable => write!(f, "no stream available"),
            MuxError::InvalidFrame => write!(f, "invalid frame"),
            MuxError::OutputFailed => write!(f, "output failed"),
        }
    }
}

impl std::error::Error for MuxError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_mux_init() {
        let mux = Mux::new(
            MuxConfig::default(),
            true,
            Box::new(|_| Ok(())),
        );

        assert!(!mux.is_closed());
        assert_eq!(mux.num_streams(), 0);
    }

    #[test]
    fn test_mux_open_stream() {
        let output_count = Arc::new(AtomicUsize::new(0));
        let output_count_clone = output_count.clone();

        let mux = Mux::new(
            MuxConfig::default(),
            true,
            Box::new(move |_| {
                output_count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        );

        let stream = mux.open_stream().unwrap();
        assert_eq!(stream.id(), 1); // Client uses odd IDs
        assert_eq!(mux.num_streams(), 1);
        assert!(output_count.load(Ordering::SeqCst) > 0); // SYN was sent
    }

    #[test]
    fn test_stream_state() {
        let mux = Mux::new(
            MuxConfig::default(),
            true,
            Box::new(|_| Ok(())),
        );

        let stream = mux.open_stream().unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        stream.close();
        assert_eq!(stream.state(), StreamState::LocalClose);
    }
}
