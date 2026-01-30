//! KCP - A Fast and Reliable ARQ Protocol
//!
//! Rust bindings for the KCP C library.

use std::ffi::c_void;
use std::os::raw::{c_char, c_int, c_long, c_uint};
use std::sync::{Arc, Mutex};

/// KCP C library types
#[repr(C)]
#[allow(clippy::upper_case_acronyms)]
struct IKCPCB {
    _private: [u8; 0],
}

type OutputCallback = extern "C" fn(*const c_char, c_int, *mut IKCPCB, *mut c_void) -> c_int;

extern "C" {
    fn ikcp_create(conv: c_uint, user: *mut c_void) -> *mut IKCPCB;
    fn ikcp_release(kcp: *mut IKCPCB);
    fn ikcp_setoutput(kcp: *mut IKCPCB, output: OutputCallback);
    fn ikcp_recv(kcp: *mut IKCPCB, buffer: *mut c_char, len: c_int) -> c_int;
    fn ikcp_send(kcp: *mut IKCPCB, buffer: *const c_char, len: c_int) -> c_int;
    fn ikcp_update(kcp: *mut IKCPCB, current: c_uint);
    fn ikcp_check(kcp: *mut IKCPCB, current: c_uint) -> c_uint;
    fn ikcp_input(kcp: *mut IKCPCB, data: *const c_char, size: c_long) -> c_int;
    fn ikcp_flush(kcp: *mut IKCPCB);
    fn ikcp_peeksize(kcp: *mut IKCPCB) -> c_int;
    fn ikcp_waitsnd(kcp: *mut IKCPCB) -> c_int;
    fn ikcp_nodelay(kcp: *mut IKCPCB, nodelay: c_int, interval: c_int, resend: c_int, nc: c_int) -> c_int;
    fn ikcp_wndsize(kcp: *mut IKCPCB, sndwnd: c_int, rcvwnd: c_int) -> c_int;
    fn ikcp_setmtu(kcp: *mut IKCPCB, mtu: c_int) -> c_int;
}

/// Output function type for KCP
pub type OutputFn = Box<dyn Fn(&[u8]) + Send + Sync>;

/// Internal context for KCP output callback
struct KcpContext {
    output_fn: Option<OutputFn>,
}

/// KCP control block wrapper
pub struct Kcp {
    kcp: *mut IKCPCB,
    conv: u32,
    /// Raw pointer to the Arc passed to C, for cleanup in Drop
    context_ptr: *const Mutex<KcpContext>,
}

// SAFETY: Kcp is Send because we properly synchronize access to the C library
unsafe impl Send for Kcp {}

impl Kcp {
    /// Create a new KCP control block.
    ///
    /// # Arguments
    /// * `conv` - Connection ID (must be the same on both sides)
    /// * `output` - Callback function for sending data
    pub fn new(conv: u32, output: OutputFn) -> Self {
        let context = Arc::new(Mutex::new(KcpContext {
            output_fn: Some(output),
        }));

        // Convert Arc to raw pointer - we'll reclaim it in Drop
        let context_ptr = Arc::into_raw(context);

        let kcp = unsafe { ikcp_create(conv, context_ptr as *mut c_void) };
        assert!(!kcp.is_null(), "Failed to create KCP instance");

        unsafe {
            ikcp_setoutput(kcp, kcp_output_callback);
        }

        Kcp { kcp, conv, context_ptr }
    }

    /// Set nodelay mode for fast transmission.
    ///
    /// # Arguments
    /// * `nodelay` - 0 = disable, 1 = enable
    /// * `interval` - Internal update interval in ms (10-100ms recommended)
    /// * `resend` - Fast resend trigger (0 = disable, 2 = recommended)
    /// * `nc` - Disable congestion control (0 = enable, 1 = disable)
    pub fn set_nodelay(&mut self, nodelay: i32, interval: i32, resend: i32, nc: i32) {
        unsafe {
            ikcp_nodelay(self.kcp, nodelay, interval, resend, nc);
        }
    }

    /// Set window size.
    ///
    /// # Arguments
    /// * `sndwnd` - Send window size
    /// * `rcvwnd` - Receive window size
    pub fn set_wndsize(&mut self, sndwnd: i32, rcvwnd: i32) {
        unsafe {
            ikcp_wndsize(self.kcp, sndwnd, rcvwnd);
        }
    }

    /// Set MTU (Maximum Transmission Unit).
    pub fn set_mtu(&mut self, mtu: i32) {
        unsafe {
            ikcp_setmtu(self.kcp, mtu);
        }
    }

    /// Apply default fast mode configuration.
    pub fn set_default_config(&mut self) {
        self.set_nodelay(1, 10, 2, 1);
        self.set_wndsize(128, 128);
        self.set_mtu(1400);
    }

    /// Send data through KCP.
    ///
    /// Returns number of bytes queued, or negative on error.
    pub fn send(&mut self, data: &[u8]) -> i32 {
        unsafe { ikcp_send(self.kcp, data.as_ptr() as *const c_char, data.len() as c_int) }
    }

    /// Receive data from KCP.
    ///
    /// Returns number of bytes received, or negative if no data available.
    pub fn recv(&mut self, buffer: &mut [u8]) -> i32 {
        unsafe { ikcp_recv(self.kcp, buffer.as_mut_ptr() as *mut c_char, buffer.len() as c_int) }
    }

    /// Input data from lower layer (e.g., UDP).
    ///
    /// Returns 0 on success, negative on error.
    pub fn input(&mut self, data: &[u8]) -> i32 {
        unsafe { ikcp_input(self.kcp, data.as_ptr() as *const c_char, data.len() as c_long) }
    }

    /// Update KCP state. Should be called periodically.
    ///
    /// # Arguments
    /// * `current` - Current time in milliseconds
    pub fn update(&mut self, current: u32) {
        unsafe {
            ikcp_update(self.kcp, current);
        }
    }

    /// Check when to call update next.
    ///
    /// Returns next update time in milliseconds.
    pub fn check(&self, current: u32) -> u32 {
        unsafe { ikcp_check(self.kcp, current) }
    }

    /// Flush pending data immediately.
    pub fn flush(&mut self) {
        unsafe {
            ikcp_flush(self.kcp);
        }
    }

    /// Get number of bytes waiting to be sent.
    pub fn wait_snd(&self) -> i32 {
        unsafe { ikcp_waitsnd(self.kcp) }
    }

    /// Peek at the size of the next available message.
    ///
    /// Returns size in bytes, or negative if no message available.
    pub fn peek_size(&self) -> i32 {
        unsafe { ikcp_peeksize(self.kcp) }
    }

    /// Get the connection ID.
    pub fn conv(&self) -> u32 {
        self.conv
    }
}

impl Drop for Kcp {
    fn drop(&mut self) {
        unsafe {
            // Release KCP first
            ikcp_release(self.kcp);
            // Reclaim the Arc from raw pointer to properly drop it
            if !self.context_ptr.is_null() {
                let _ = Arc::from_raw(self.context_ptr);
            }
        }
    }
}

/// KCP output callback (called by C library)
/// Uses catch_unwind to prevent panics from crossing FFI boundary (which is UB).
extern "C" fn kcp_output_callback(
    buf: *const c_char,
    len: c_int,
    _kcp: *mut IKCPCB,
    user: *mut c_void,
) -> c_int {
    if user.is_null() || len <= 0 {
        return 0;
    }

    // The `user` pointer points to the Mutex inside the Arc held by Kcp struct.
    // Its lifetime is guaranteed by the Kcp struct, so we can safely use a reference
    // instead of Arc::from_raw (which would leak memory due to refcount increment).
    let context = unsafe { &*(user as *const Mutex<KcpContext>) };

    // Wrap in catch_unwind to prevent panic from crossing FFI boundary
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let data = unsafe { std::slice::from_raw_parts(buf as *const u8, len as usize) };
        if let Ok(ctx) = context.lock() {
            if let Some(ref output_fn) = ctx.output_fn {
                output_fn(data);
            }
        }
    }));

    if result.is_err() {
        // Panic occurred - abort to prevent UB from unwinding across FFI
        eprintln!("FATAL: Panic in KCP output callback, aborting to prevent UB");
        std::process::abort();
    }

    0
}

/// Frame command types for multiplexing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cmd {
    Syn = 0x01, // Stream open
    Fin = 0x02, // Stream close
    Psh = 0x03, // Data
    Nop = 0x04, // Keepalive
    Upd = 0x05, // Window update
}

impl Cmd {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Cmd::Syn),
            0x02 => Some(Cmd::Fin),
            0x03 => Some(Cmd::Psh),
            0x04 => Some(Cmd::Nop),
            0x05 => Some(Cmd::Upd),
            _ => None,
        }
    }
}

/// Frame header size: cmd(1) + stream_id(4) + length(2) = 7 bytes
pub const FRAME_HEADER_SIZE: usize = 7;

/// Maximum payload size
pub const MAX_PAYLOAD_SIZE: usize = 65535;

/// Frame represents a multiplexed stream frame.
#[derive(Debug, Clone)]
pub struct Frame {
    pub cmd: Cmd,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new frame.
    pub fn new(cmd: Cmd, stream_id: u32, payload: Vec<u8>) -> Self {
        Frame {
            cmd,
            stream_id,
            payload,
        }
    }

    /// Encode frame to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + self.payload.len());
        buf.push(self.cmd as u8);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Encode frame to existing buffer.
    pub fn encode_to(&self, buf: &mut [u8]) -> Result<usize, FrameError> {
        let total_len = FRAME_HEADER_SIZE + self.payload.len();
        if buf.len() < total_len {
            return Err(FrameError::BufferTooSmall);
        }
        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge);
        }

        buf[0] = self.cmd as u8;
        buf[1..5].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[5..7].copy_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf[FRAME_HEADER_SIZE..total_len].copy_from_slice(&self.payload);

        Ok(total_len)
    }

    /// Encode frame to existing buffer (unchecked, fast path).
    /// 
    /// # Safety
    /// Caller must ensure buffer is at least `FRAME_HEADER_SIZE + payload.len()` bytes.
    #[inline(always)]
    pub unsafe fn encode_to_unchecked(&self, buf: &mut [u8]) -> usize {
        let total_len = FRAME_HEADER_SIZE + self.payload.len();
        unsafe {
            let ptr = buf.as_mut_ptr();
            *ptr = self.cmd as u8;
            std::ptr::write_unaligned(ptr.add(1) as *mut u32, self.stream_id.to_be());
            std::ptr::write_unaligned(ptr.add(5) as *mut u16, (self.payload.len() as u16).to_be());
            std::ptr::copy_nonoverlapping(
                self.payload.as_ptr(),
                ptr.add(FRAME_HEADER_SIZE),
                self.payload.len(),
            );
        }
        total_len
    }

    /// Encode a frame directly from payload slice (zero-copy).
    /// Avoids creating intermediate Frame struct and Vec allocation.
    #[inline]
    pub fn encode_with_payload(cmd: Cmd, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let total_len = FRAME_HEADER_SIZE + payload.len();
        let mut buf = Vec::with_capacity(total_len);
        buf.push(cmd as u8);
        buf.extend_from_slice(&stream_id.to_be_bytes());
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// Encode a frame directly to buffer from payload slice (zero-copy).
    /// Returns the number of bytes written.
    #[inline]
    pub fn encode_with_payload_to(cmd: Cmd, stream_id: u32, payload: &[u8], buf: &mut [u8]) -> Result<usize, FrameError> {
        let total_len = FRAME_HEADER_SIZE + payload.len();
        if buf.len() < total_len {
            return Err(FrameError::BufferTooSmall);
        }
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge);
        }

        buf[0] = cmd as u8;
        buf[1..5].copy_from_slice(&stream_id.to_be_bytes());
        buf[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        buf[FRAME_HEADER_SIZE..total_len].copy_from_slice(payload);

        Ok(total_len)
    }

    /// Decode frame from bytes.
    pub fn decode(data: &[u8]) -> Result<Frame, FrameError> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err(FrameError::FrameTooShort);
        }

        let cmd = Cmd::from_byte(data[0]).ok_or(FrameError::InvalidCmd)?;
        let stream_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let payload_len = u16::from_be_bytes([data[5], data[6]]) as usize;

        if data.len() < FRAME_HEADER_SIZE + payload_len {
            return Err(FrameError::FrameTooShort);
        }

        let payload = data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len].to_vec();

        Ok(Frame {
            cmd,
            stream_id,
            payload,
        })
    }

    /// Decode only the header.
    pub fn decode_header(data: &[u8]) -> Result<(Cmd, u32, u16), FrameError> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err(FrameError::FrameTooShort);
        }

        let cmd = Cmd::from_byte(data[0]).ok_or(FrameError::InvalidCmd)?;
        let stream_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let payload_len = u16::from_be_bytes([data[5], data[6]]);

        Ok((cmd, stream_id, payload_len))
    }
}

/// UpdatePayload for flow control (UPD frames)
#[derive(Debug, Clone, Copy)]
pub struct UpdatePayload {
    pub consumed: u32,
    pub window: u32,
}

impl UpdatePayload {
    pub const SIZE: usize = 8;

    pub fn encode(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&self.consumed.to_be_bytes());
        buf[4..8].copy_from_slice(&self.window.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() < Self::SIZE {
            return Err(FrameError::PayloadTooShort);
        }

        Ok(UpdatePayload {
            consumed: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            window: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        })
    }
}

/// Frame errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    FrameTooShort,
    InvalidCmd,
    BufferTooSmall,
    PayloadTooLarge,
    PayloadTooShort,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::FrameTooShort => write!(f, "frame too short"),
            FrameError::InvalidCmd => write!(f, "invalid command"),
            FrameError::BufferTooSmall => write!(f, "buffer too small"),
            FrameError::PayloadTooLarge => write!(f, "payload too large"),
            FrameError::PayloadTooShort => write!(f, "payload too short"),
        }
    }
}

impl std::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_kcp_basic() {
        let output_count = Arc::new(AtomicUsize::new(0));
        let output_count_clone = output_count.clone();

        let mut kcp = Kcp::new(123, Box::new(move |_data| {
            output_count_clone.fetch_add(1, Ordering::SeqCst);
        }));

        kcp.set_default_config();

        assert_eq!(kcp.conv(), 123);
        assert_eq!(kcp.wait_snd(), 0);
    }

    #[test]
    fn test_kcp_send_recv() {
        let packets_a = Arc::new(Mutex::new(Vec::new()));
        let packets_b = Arc::new(Mutex::new(Vec::new()));

        let packets_a_clone = packets_a.clone();
        let packets_b_clone = packets_b.clone();

        let mut kcp_a = Kcp::new(1, Box::new(move |data| {
            packets_a_clone.lock().unwrap().push(data.to_vec());
        }));

        let mut kcp_b = Kcp::new(1, Box::new(move |data| {
            packets_b_clone.lock().unwrap().push(data.to_vec());
        }));

        kcp_a.set_default_config();
        kcp_b.set_default_config();

        // Send data from A
        let test_data = b"Hello, KCP!";
        let ret = kcp_a.send(test_data);
        assert!(ret >= 0);

        // Update and exchange packets
        let current = 0u32;
        kcp_a.update(current);

        // Feed A's output to B
        for pkt in packets_a.lock().unwrap().drain(..) {
            kcp_b.input(&pkt);
        }

        kcp_b.update(current);

        // Try to receive
        let mut buf = [0u8; 1024];
        let n = kcp_b.recv(&mut buf);

        assert!(n > 0);
        assert_eq!(&buf[..n as usize], test_data);
    }

    #[test]
    fn test_frame_encode_decode() {
        let frame = Frame::new(Cmd::Psh, 42, b"hello".to_vec());
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).unwrap();

        assert_eq!(decoded.cmd, Cmd::Psh);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.payload, b"hello");

        // Test encode_with_payload produces same result
        let encoded2 = Frame::encode_with_payload(Cmd::Psh, 42, b"hello");
        assert_eq!(encoded, encoded2);

        // Test encode_with_payload_to
        let mut buf = [0u8; 128];
        let len = Frame::encode_with_payload_to(Cmd::Psh, 42, b"hello", &mut buf).unwrap();
        assert_eq!(&buf[..len], &encoded[..]);
    }

    #[test]
    fn test_frame_header_decode() {
        let frame = Frame::new(Cmd::Syn, 100, vec![]);
        let encoded = frame.encode();
        let (cmd, stream_id, payload_len) = Frame::decode_header(&encoded).unwrap();

        assert_eq!(cmd, Cmd::Syn);
        assert_eq!(stream_id, 100);
        assert_eq!(payload_len, 0);
    }

    #[test]
    fn test_update_payload() {
        let update = UpdatePayload {
            consumed: 1024,
            window: 65536,
        };

        let encoded = update.encode();
        let decoded = UpdatePayload::decode(&encoded).unwrap();

        assert_eq!(decoded.consumed, 1024);
        assert_eq!(decoded.window, 65536);
    }

    #[test]
    fn test_cmd_from_byte() {
        assert_eq!(Cmd::from_byte(0x01), Some(Cmd::Syn));
        assert_eq!(Cmd::from_byte(0x02), Some(Cmd::Fin));
        assert_eq!(Cmd::from_byte(0x03), Some(Cmd::Psh));
        assert_eq!(Cmd::from_byte(0x04), Some(Cmd::Nop));
        assert_eq!(Cmd::from_byte(0x05), Some(Cmd::Upd));
        assert_eq!(Cmd::from_byte(0x00), None);
        assert_eq!(Cmd::from_byte(0xFF), None);
    }

    #[test]
    fn bench_frame_encode_inline() {
        use std::time::Instant;
        use std::hint::black_box;

        let iterations = 100_000_000u64; // 100M for accurate timing
        let payload: &[u8] = b"hello world benchmark payload data";
        let frame_size = FRAME_HEADER_SIZE + payload.len();
        let mut buf = [0u8; 128];

        // Benchmark checked version (with Frame struct)
        let frame = Frame::new(Cmd::Psh, 12345, payload.to_vec());
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(frame.encode_to(black_box(&mut buf)).unwrap());
        }
        let elapsed = start.elapsed();
        let ns_per_op = elapsed.as_nanos() as f64 / iterations as f64;
        let throughput_gbps = (frame_size as f64 * 8.0 * iterations as f64) / elapsed.as_secs_f64() / 1e9;
        println!("\nRust Frame encode_to (checked): {:.2} ns/op, {:.2} Gbps ({}ms)", ns_per_op, throughput_gbps, elapsed.as_millis());

        // Benchmark unchecked BE (matching implementation) version with volatile
        let start2 = Instant::now();
        let mut stream_id = 12345u32;
        for _ in 0..iterations {
            unsafe {
                let ptr = buf.as_mut_ptr();
                std::ptr::write_volatile(ptr, Cmd::Psh as u8);
                std::ptr::write_unaligned(ptr.add(1) as *mut u32, stream_id.to_be()); // BE like implementation
                std::ptr::write_unaligned(ptr.add(5) as *mut u16, (payload.len() as u16).to_be());
                std::ptr::copy_nonoverlapping(payload.as_ptr(), ptr.add(FRAME_HEADER_SIZE), payload.len());
                stream_id = stream_id.wrapping_add(std::ptr::read_volatile(ptr.add(1)) as u32);
            }
        }
        let elapsed2 = start2.elapsed();
        black_box(stream_id);
        let ns_per_op2 = elapsed2.as_nanos() as f64 / iterations as f64;
        let throughput_gbps2 = (frame_size as f64 * 8.0 * iterations as f64) / elapsed2.as_secs_f64() / 1e9;
        println!("Rust Frame encode_to (unchecked BE): {:.2} ns/op, {:.2} Gbps ({}ms, {} bytes/frame)", 
                 ns_per_op2, throughput_gbps2, elapsed2.as_millis(), frame_size);
    }

    #[test]
    fn bench_frame_decode_inline() {
        use std::time::Instant;
        use std::hint::black_box;

        let iterations = 10_000_000u64;
        let payload = b"hello world benchmark payload data".to_vec();
        let frame = Frame::new(Cmd::Psh, 12345, payload);
        let mut buf = [0u8; 128];
        let len = frame.encode_to(&mut buf).unwrap();
        let encoded = &buf[..len];
        let frame_size = len;

        let start = Instant::now();
        for _ in 0..iterations {
            black_box(Frame::decode_header(black_box(encoded)).unwrap());
        }
        let elapsed = start.elapsed();
        let ns_per_op = elapsed.as_nanos() / iterations as u128;
        let throughput_gbps = (frame_size as f64 * 8.0 * iterations as f64) / elapsed.as_secs_f64() / 1e9;
        println!("\nRust Frame decode_header: {} ns/op, {:.2} Gbps ({} ops, {} bytes/frame)", 
                 ns_per_op, throughput_gbps, iterations, frame_size);
    }

    #[test]
    fn bench_kcp_send_recv_inline() {
        use std::time::Instant;
        use std::hint::black_box;

        let iterations = 10_000u64;
        let data = b"benchmark data payload 1234567890";
        let data_size = data.len();

        let packets_a = Arc::new(Mutex::new(Vec::new()));
        let packets_b = Arc::new(Mutex::new(Vec::new()));

        let packets_a_clone = packets_a.clone();
        let packets_b_clone = packets_b.clone();

        let mut kcp_a = Kcp::new(1, Box::new(move |d| {
            packets_a_clone.lock().unwrap().push(d.to_vec());
        }));

        let mut kcp_b = Kcp::new(1, Box::new(move |d| {
            packets_b_clone.lock().unwrap().push(d.to_vec());
        }));

        kcp_a.set_default_config();
        kcp_b.set_default_config();

        let mut recv_buf = [0u8; 1024];
        let mut current = 0u32;

        let start = Instant::now();
        for _ in 0..iterations {
            packets_a.lock().unwrap().clear();
            packets_b.lock().unwrap().clear();

            kcp_a.send(black_box(data));
            kcp_a.update(current);
            kcp_a.flush();

            for pkt in packets_a.lock().unwrap().drain(..) {
                kcp_b.input(&pkt);
            }
            kcp_b.update(current);

            for pkt in packets_b.lock().unwrap().drain(..) {
                kcp_a.input(&pkt);
            }

            black_box(kcp_b.recv(&mut recv_buf));
            current += 10;
        }
        let elapsed = start.elapsed();
        let us_per_op = elapsed.as_micros() as f64 / iterations as f64;
        let throughput_mbps = (data_size as f64 * 8.0 * iterations as f64) / elapsed.as_secs_f64() / 1e6;
        println!("\nRust KCP send/recv: {:.2} us/op, {:.1} Mbps ({} bytes/msg)", us_per_op, throughput_mbps, data_size);
    }
}
