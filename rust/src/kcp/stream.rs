//! Stream - A multiplexed reliable stream over KCP.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::{Arc, Condvar, Mutex, RwLock};

use super::kcp::{Cmd, Frame, Kcp, FRAME_HEADER_SIZE};

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
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
    proto: u8,           // Stream protocol type (from SYN payload)
    metadata: Vec<u8>,   // Stream metadata (from SYN payload)
    kcp: Mutex<Kcp>,
    state: RwLock<StreamState>,
    recv_buf: Mutex<VecDeque<u8>>, // O(1) head removal
    recv_cond: Condvar,            // Signaled when data arrives or stream closes
    fin_sender: Option<Box<dyn Fn() + Send + Sync>>, // Callback to send FIN frame
    output_error: Arc<std::sync::atomic::AtomicBool>, // Set on transport output error
}

impl Stream {
    /// Create a new stream with protocol type and metadata.
    pub(crate) fn new(
        id: u32,
        proto: u8,
        metadata: Vec<u8>,
        output: super::kcp::OutputFn,
        fin_sender: Option<Box<dyn Fn() + Send + Sync>>,
        output_error: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        let mut kcp = Kcp::new(id, output);
        kcp.set_default_config();

        Stream {
            id,
            proto,
            metadata,
            kcp: Mutex::new(kcp),
            state: RwLock::new(StreamState::Open),
            recv_buf: Mutex::new(VecDeque::new()),
            recv_cond: Condvar::new(),
            fin_sender,
            output_error,
        }
    }

    /// Get stream ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Get stream protocol type (from SYN payload).
    /// Returns 0 (RAW) if no protocol was specified.
    pub fn proto(&self) -> u8 {
        self.proto
    }

    /// Get stream metadata (from SYN payload).
    /// Returns empty slice if no metadata was specified.
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    /// Get stream state.
    pub fn state(&self) -> StreamState {
        *self.state.read().unwrap()
    }

    /// Check if a transport output error has occurred.
    /// This can be used to detect underlying connection issues.
    pub fn has_output_error(&self) -> bool {
        self.output_error.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Write data to the stream.
    /// Returns the number of bytes written on success.
    pub fn write_data(&self, data: &[u8]) -> Result<usize, StreamError> {
        let state = self.state();
        if state == StreamState::Closed || state == StreamState::LocalClose {
            return Err(StreamError::StreamClosed);
        }

        let mut kcp = self.kcp.lock().unwrap();
        let ret = kcp.send(data);
        if ret < 0 {
            return Err(StreamError::KcpSendFailed);
        }

        // Flush immediately for better throughput (same as Go)
        kcp.flush();

        // kcp.send returns 0 on success, so return data.len() as bytes written
        Ok(data.len())
    }

    /// Read data from the stream (non-blocking).
    /// Returns immediately with 0 if no data is available.
    pub fn read_data(&self, buf: &mut [u8]) -> Result<usize, StreamError> {
        let mut recv_buf = self.recv_buf.lock().unwrap();

        if recv_buf.is_empty() {
            let state = self.state();
            if state == StreamState::Closed || state == StreamState::RemoteClose {
                return Ok(0); // EOF
            }
            return Ok(0); // No data available
        }

        Ok(Self::drain_recv_buf(&mut recv_buf, buf))
    }

    /// Read data from the stream (blocking).
    /// Blocks until data is available or the stream is closed/EOF.
    pub fn read_blocking(&self, buf: &mut [u8]) -> Result<usize, StreamError> {
        let mut recv_buf = self.recv_buf.lock().unwrap();
        loop {
            if !recv_buf.is_empty() {
                return Ok(Self::drain_recv_buf(&mut recv_buf, buf));
            }
            let state = self.state();
            if state == StreamState::Closed || state == StreamState::RemoteClose {
                return Ok(0); // EOF
            }
            recv_buf = self.recv_cond.wait(recv_buf).unwrap();
        }
    }

    /// Helper: drain data from recv_buf into user buffer (DRY).
    /// Returns number of bytes copied.
    #[inline]
    fn drain_recv_buf(recv_buf: &mut VecDeque<u8>, buf: &mut [u8]) -> usize {
        let (s1, s2) = recv_buf.as_slices();
        let n1 = std::cmp::min(buf.len(), s1.len());
        buf[..n1].copy_from_slice(&s1[..n1]);

        let n2 = std::cmp::min(buf.len().saturating_sub(n1), s2.len());
        if n2 > 0 {
            buf[n1..n1 + n2].copy_from_slice(&s2[..n2]);
        }

        let total = n1 + n2;
        recv_buf.drain(..total);
        total
    }

    /// Shutdown the write-half of the stream.
    /// 
    /// Sends a FIN frame to the remote peer and transitions to `LocalClose` state.
    /// The stream can still receive data until a FIN is received from the peer.
    /// For full close, wait for `state()` to become `Closed` after receiving remote FIN.
    pub fn shutdown(&self) {
        let mut state = self.state.write().unwrap();
        if *state == StreamState::Closed || *state == StreamState::LocalClose {
            return;
        }

        // Only send FIN when transitioning from Open to LocalClose
        let should_send_fin = *state == StreamState::Open;

        if *state == StreamState::Open {
            *state = StreamState::LocalClose;
        } else {
            *state = StreamState::Closed;
        }

        drop(state);

        // Send FIN frame to notify remote peer (only once)
        if should_send_fin {
            if let Some(ref fin_sender) = self.fin_sender {
                fin_sender();
            }
        }

        // Wake blocked readers
        self.recv_cond.notify_all();
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
    /// Returns true if any data was received.
    pub(crate) fn kcp_recv(&self) -> bool {
        let mut kcp = self.kcp.lock().unwrap();
        let mut recv_buf = self.recv_buf.lock().unwrap();
        let mut received_data = false;

        // Stack buffer for common MTU-sized messages, avoiding heap allocation
        const MTU: usize = 1500;
        let mut stack_buf = [0u8; MTU];
        let mut heap_buf: Option<Vec<u8>> = None;

        loop {
            let size = kcp.peek_size();
            if size <= 0 {
                break;
            }

            // Use stack buffer for small messages, heap for larger
            let buf: &mut [u8] = if (size as usize) <= MTU {
                &mut stack_buf[..size as usize]
            } else {
                // Reuse or grow heap buffer as needed
                let hb = heap_buf.get_or_insert_with(|| vec![0u8; size as usize]);
                if hb.len() < size as usize {
                    hb.resize(size as usize, 0);
                }
                &mut hb[..size as usize]
            };

            let n = kcp.recv(buf);
            if n <= 0 {
                break;
            }

            recv_buf.extend(&buf[..n as usize]);
            received_data = true;
        }

        // Wake blocked readers
        if received_data {
            self.recv_cond.notify_all();
        }

        received_data
    }

    /// Receive data directly from KCP into user-provided buffer (zero-copy fast path).
    /// Returns the number of bytes received, or 0 if no data available.
    /// This bypasses the internal recv_buf for lower latency when caller can process immediately.
    pub fn recv_into_buffer(&self, buf: &mut [u8]) -> Result<usize, StreamError> {
        // First drain any buffered data
        {
            let mut recv_buf = self.recv_buf.lock().unwrap();
            if !recv_buf.is_empty() {
                return Ok(Self::drain_recv_buf(&mut recv_buf, buf));
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
        drop(state);
        // Wake blocked readers so they see EOF
        self.recv_cond.notify_all();
    }
}

/// Mux configuration
#[derive(Debug, Clone)]
pub struct MuxConfig {
    pub max_frame_size: usize,
    pub max_receive_buffer: usize,
}

impl Default for MuxConfig {
    fn default() -> Self {
        MuxConfig {
            max_frame_size: 32 * 1024,
            max_receive_buffer: 256 * 1024,
        }
    }
}

/// Output function type for Mux
pub type OutputFn = Box<dyn Fn(&[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> + Send + Sync>;

/// Callback when stream has data available to read.
/// Called with stream ID when new data arrives.
pub type OnStreamDataFn = Box<dyn Fn(u32) + Send + Sync>;

/// Callback when a new stream is accepted.
/// Called with the new stream when a SYN is received from the remote.
pub type OnNewStreamFn = Box<dyn Fn(Arc<Stream>) + Send + Sync>;

/// Mux multiplexes multiple streams over a single connection.
pub struct Mux {
    #[allow(dead_code)]
    config: MuxConfig,
    output: Arc<OutputFn>,
    on_stream_data: Arc<OnStreamDataFn>,
    on_new_stream: Arc<OnNewStreamFn>,
    #[allow(dead_code)]
    is_client: bool,
    streams: RwLock<HashMap<u32, Arc<Stream>>>,
    next_id: Mutex<u32>,
    closed: RwLock<bool>,
}

impl Mux {
    /// Create a new Mux.
    /// 
    /// - `config`: Mux configuration
    /// - `is_client`: true for client (odd stream IDs), false for server (even stream IDs)
    /// - `output`: Callback to send data to the network
    /// - `on_stream_data`: Callback when a stream has data available to read (required)
    /// - `on_new_stream`: Callback when a new stream is accepted (required)
    pub fn new(
        config: MuxConfig,
        is_client: bool,
        output: OutputFn,
        on_stream_data: OnStreamDataFn,
        on_new_stream: OnNewStreamFn,
    ) -> Self {
        Mux {
            config,
            output: Arc::new(output),
            on_stream_data: Arc::new(on_stream_data),
            on_new_stream: Arc::new(on_new_stream),
            is_client,
            streams: RwLock::new(HashMap::new()),
            next_id: Mutex::new(if is_client { 1 } else { 2 }),
            closed: RwLock::new(false),
        }
    }

    /// Create a stream with given ID, protocol type, and metadata (helper to reduce duplication).
    fn create_stream(&self, id: u32, proto: u8, metadata: Vec<u8>) -> Arc<Stream> {
        let output = self.output.clone();
        let fin_output = self.output.clone();
        let output_error = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let output_error_cb = output_error.clone();
        let output_error_fin = output_error.clone();

        Arc::new(Stream::new(
            id,
            proto,
            metadata,
            Box::new(move |data| {
                // Use encode_with_payload to avoid intermediate allocations
                let encoded = Frame::encode_with_payload(Cmd::Psh, id, data);
                if let Err(e) = output(&encoded) {
                    output_error_cb.store(true, std::sync::atomic::Ordering::Relaxed);
                    eprintln!("Mux output error on stream {}: {}", id, e);
                }
            }),
            Some(Box::new(move || {
                // Send FIN frame when stream is closed
                let encoded = Frame::encode_with_payload(Cmd::Fin, id, &[]);
                if let Err(e) = fin_output(&encoded) {
                    output_error_fin.store(true, std::sync::atomic::Ordering::Relaxed);
                    eprintln!("Mux FIN output error on stream {}: {}", id, e);
                }
            })),
            output_error,
        ))
    }

    /// Open a new stream with protocol type and metadata.
    /// The proto and metadata are sent in the SYN frame payload so the remote
    /// side can identify the stream type upon acceptance.
    /// Use proto=0 (RAW) and metadata=&[] for untyped streams.
    pub fn open_stream(&self, proto: u8, metadata: &[u8]) -> Result<Arc<Stream>, MuxError> {
        if self.is_closed() {
            return Err(MuxError::MuxClosed);
        }

        let id = {
            let mut next_id = self.next_id.lock().unwrap();
            let id = *next_id;
            *next_id += 2;
            id
        };

        let stream = self.create_stream(id, proto, metadata.to_vec());
        self.streams.write().unwrap().insert(id, stream.clone());

        // Send SYN with proto + metadata - remove from map on failure
        if let Err(e) = self.send_syn(id, proto, metadata) {
            self.streams.write().unwrap().remove(&id);
            return Err(e);
        }

        Ok(stream)
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
            Cmd::Syn => self.handle_syn(frame.stream_id, &frame.payload)?,
            Cmd::Fin => self.handle_fin(frame.stream_id),
            Cmd::Psh => self.handle_psh(frame.stream_id, &frame.payload),
            Cmd::Nop => {} // Keepalive
        }

        Ok(())
    }

    fn handle_syn(&self, id: u32, payload: &[u8]) -> Result<(), MuxError> {
        if self.streams.read().unwrap().contains_key(&id) {
            return Ok(()); // Duplicate SYN
        }

        // Parse proto + metadata from SYN payload
        let (proto, metadata) = if !payload.is_empty() {
            (payload[0], payload[1..].to_vec())
        } else {
            (0, Vec::new()) // Default: RAW, no metadata
        };

        let stream = self.create_stream(id, proto, metadata);
        self.streams.write().unwrap().insert(id, stream.clone());

        // Notify via callback
        (self.on_new_stream)(stream);

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
            if stream.kcp_recv() {
                // Data received, notify callback
                (self.on_stream_data)(id);
            }
        }
    }

    fn send_syn(&self, id: u32, proto: u8, metadata: &[u8]) -> Result<(), MuxError> {
        let payload = if proto != 0 || !metadata.is_empty() {
            let mut p = Vec::with_capacity(1 + metadata.len());
            p.push(proto);
            p.extend_from_slice(metadata);
            p
        } else {
            vec![]
        };
        self.send_frame(Frame::new(Cmd::Syn, id, payload))
    }

    pub fn send_fin(&self, id: u32) -> Result<(), MuxError> {
        self.send_frame(Frame::new(Cmd::Fin, id, vec![]))
    }

    fn send_frame(&self, frame: Frame) -> Result<(), MuxError> {
        if self.is_closed() {
            return Err(MuxError::MuxClosed);
        }

        const MTU_SIZE: usize = 1500;
        let required_size = FRAME_HEADER_SIZE + frame.payload.len();

        if required_size <= MTU_SIZE {
            // Use stack buffer for typical small frames
            let mut buf = [0u8; MTU_SIZE];
            let len = frame.encode_to(&mut buf).map_err(|_| MuxError::InvalidFrame)?;
            (self.output)(&buf[..len]).map_err(|_| MuxError::OutputFailed)?;
        } else {
            // Fallback to heap allocation for large frames
            (self.output)(&frame.encode()).map_err(|_| MuxError::OutputFailed)?;
        }
        Ok(())
    }

    /// Remove a stream.
    pub fn remove_stream(&self, id: u32) {
        self.streams.write().unwrap().remove(&id);
    }

    /// Update all streams.
    pub fn update(&self, current: u32) {
        for (id, stream) in self.streams.read().unwrap().iter() {
            stream.kcp_update(current);
            if stream.kcp_recv() {
                // Data received, notify callback
                (self.on_stream_data)(*id);
            }
        }
    }
}

/// Mux errors
#[derive(Debug)]
pub enum MuxError {
    MuxClosed,
    InvalidFrame,
    OutputFailed,
}

impl std::fmt::Display for MuxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MuxError::MuxClosed => write!(f, "mux closed"),
            MuxError::InvalidFrame => write!(f, "invalid frame"),
            MuxError::OutputFailed => write!(f, "output failed"),
        }
    }
}

impl std::error::Error for MuxError {}

/// Wrapper providing std::io::Read + Write for a KCP Stream.
/// Uses blocking read semantics (waits via Condvar for data).
pub struct StreamIo(pub Arc<Stream>);

impl io::Read for StreamIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0
            .read_blocking(buf)
            .map_err(|e| io::Error::other(format!("{}", e)))
    }
}

impl io::Write for StreamIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .write_data(buf)
            .map_err(|e| io::Error::other(format!("{}", e)))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

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
            Box::new(|_| {}),
            Box::new(|_| {}),
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
            Box::new(|_| {}),
            Box::new(|_| {}),
        );

        let stream = mux.open_stream(0, &[]).unwrap();
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
            Box::new(|_| {}),
            Box::new(|_| {}),
        );

        let stream = mux.open_stream(0, &[]).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        stream.shutdown();
        assert_eq!(stream.state(), StreamState::LocalClose);
    }
}
