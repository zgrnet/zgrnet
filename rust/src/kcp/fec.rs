//! FEC - Forward Error Correction for KCP packet loss resilience.
//!
//! XOR-based parity encoding that adds redundancy to KCP output packets.
//! For a group of N data packets, produces 1 parity packet (XOR of all N).
//! If any single packet in the group is lost, it can be reconstructed from
//! the remaining N-1 data packets and the parity.
//!
//! Overhead: 1/N (e.g., N=3 → 33% overhead for single-loss recovery per group).
//!
//! ## Wire format
//!
//! Each FEC-wrapped packet has a 6-byte header:
//!
//! ```text
//! [group_id: u16 LE][index: u8][count: u8][payload_len: u16 LE][payload...]
//! ```
//!
//! - group_id: Monotonically increasing group counter (wraps at u16 max)
//! - index: Packet index within the group (0..count-1 for data, count for parity)
//! - count: Number of data packets in the group (N)
//! - payload_len: Actual data length (before padding, for parity reconstruction)

/// FEC packet header size: group_id(2) + index(1) + count(1) + payload_len(2) = 6 bytes.
pub const HEADER_SIZE: usize = 6;

/// Maximum supported MTU for FEC packets.
pub const MAX_MTU: usize = 1500;

/// Maximum number of data packets per FEC group.
const MAX_GROUP_SIZE: usize = 16;

/// Circular buffer size for tracking groups in the decoder.
const DECODER_WINDOW_SIZE: usize = 64;

/// Decoded FEC packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub group_id: u16,
    pub index: u8,
    pub count: u8,
    pub payload_len: u16,
}

/// FEC errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecError {
    PacketTooShort,
}

impl std::fmt::Display for FecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FecError::PacketTooShort => write!(f, "FEC packet too short"),
        }
    }
}

impl std::error::Error for FecError {}

/// Output callback type for FEC encoder/decoder.
pub type OutputFn = Box<dyn FnMut(&[u8]) + Send>;

/// Encode a FEC header into the buffer (must be >= HEADER_SIZE).
pub fn encode_header(buf: &mut [u8], group_id: u16, index: u8, count: u8, payload_len: u16) {
    buf[0..2].copy_from_slice(&group_id.to_le_bytes());
    buf[2] = index;
    buf[3] = count;
    buf[4..6].copy_from_slice(&payload_len.to_le_bytes());
}

/// Decode a FEC header from a buffer.
pub fn decode_header(buf: &[u8]) -> Result<Header, FecError> {
    if buf.len() < HEADER_SIZE {
        return Err(FecError::PacketTooShort);
    }
    Ok(Header {
        group_id: u16::from_le_bytes([buf[0], buf[1]]),
        index: buf[2],
        count: buf[3],
        payload_len: u16::from_le_bytes([buf[4], buf[5]]),
    })
}

/// XOR src into dst (dst ^= src) for min(dst.len(), src.len()) bytes.
fn xor_bytes(dst: &mut [u8], src: &[u8]) {
    let len = dst.len().min(src.len());
    for i in 0..len {
        dst[i] ^= src[i];
    }
}

// =============================================================================
// FEC Encoder
// =============================================================================

/// FEC Encoder — buffers output packets and emits groups with parity.
///
/// Usage:
///   1. Call `add_packet()` for each KCP output packet
///   2. When group_size packets accumulate, the encoder emits N+1 packets
///      (N data + 1 parity) via the output callback
///   3. Call `flush_partial()` to emit a partial group (e.g., on timer)
pub struct Encoder {
    group_size: u8,
    group_id: u16,
    buffered: u8,

    /// Buffered packet data.
    packet_buf: [[u8; MAX_MTU]; MAX_GROUP_SIZE],
    packet_lens: [u16; MAX_GROUP_SIZE],

    /// Parity accumulator (running XOR).
    parity_buf: [u8; MAX_MTU],
    max_payload_len: u16,

    /// Output callback: called with each FEC-wrapped packet.
    output_fn: OutputFn,
}

impl Encoder {
    /// Create a new FEC encoder with the given group size.
    pub fn new(group_size: u8, output_fn: OutputFn) -> Self {
        Encoder {
            group_size: group_size.clamp(1, MAX_GROUP_SIZE as u8),
            group_id: 0,
            buffered: 0,
            packet_buf: [[0u8; MAX_MTU]; MAX_GROUP_SIZE],
            packet_lens: [0u16; MAX_GROUP_SIZE],
            parity_buf: [0u8; MAX_MTU],
            max_payload_len: 0,
            output_fn,
        }
    }

    /// Add a packet to the current group. Emits the group when full.
    pub fn add_packet(&mut self, data: &[u8]) {
        if data.len() > MAX_MTU {
            return; // Drop oversized packets
        }
        if self.buffered >= self.group_size {
            self.emit_group();
        }

        let idx = self.buffered as usize;

        // Store packet data
        self.packet_buf[idx][..data.len()].copy_from_slice(data);
        // Zero-pad remainder for XOR
        self.packet_buf[idx][data.len()..].fill(0);
        self.packet_lens[idx] = data.len() as u16;

        // Update parity (running XOR)
        xor_bytes(&mut self.parity_buf, &self.packet_buf[idx]);
        if data.len() as u16 > self.max_payload_len {
            self.max_payload_len = data.len() as u16;
        }

        self.buffered += 1;

        if self.buffered >= self.group_size {
            self.emit_group();
        }
    }

    /// Flush a partial group (fewer than group_size packets).
    /// Call this on a timer to avoid indefinite buffering.
    pub fn flush_partial(&mut self) {
        if self.buffered > 0 {
            self.emit_group();
        }
    }

    fn emit_group(&mut self) {
        let count = self.buffered;
        if count == 0 {
            return;
        }

        let mut emit_buf = [0u8; HEADER_SIZE + MAX_MTU];

        // Emit data packets with FEC header
        for i in 0..count as usize {
            let plen = self.packet_lens[i] as usize;
            let total = HEADER_SIZE + plen;
            encode_header(&mut emit_buf, self.group_id, i as u8, count, self.packet_lens[i]);
            emit_buf[HEADER_SIZE..HEADER_SIZE + plen].copy_from_slice(&self.packet_buf[i][..plen]);
            (self.output_fn)(&emit_buf[..total]);
        }

        // Emit parity packet
        let parity_len = self.max_payload_len as usize;
        let parity_total = HEADER_SIZE + parity_len;
        encode_header(&mut emit_buf, self.group_id, count, count, self.max_payload_len);
        emit_buf[HEADER_SIZE..HEADER_SIZE + parity_len].copy_from_slice(&self.parity_buf[..parity_len]);
        (self.output_fn)(&emit_buf[..parity_total]);

        // Reset for next group
        self.group_id = self.group_id.wrapping_add(1);
        self.buffered = 0;
        self.max_payload_len = 0;
        self.parity_buf = [0u8; MAX_MTU];
    }
}

// =============================================================================
// FEC Decoder
// =============================================================================

/// Per-group tracking state.
struct Group {
    received: u32,       // Bitmask of received packet indices
    parity_received: bool,
    count: u8,
    packets: [[u8; MAX_MTU]; MAX_GROUP_SIZE + 1],
    packet_lens: [u16; MAX_GROUP_SIZE + 1],
}

impl Default for Group {
    fn default() -> Self {
        Group {
            received: 0,
            parity_received: false,
            count: 0,
            packets: [[0u8; MAX_MTU]; MAX_GROUP_SIZE + 1],
            packet_lens: [0u16; MAX_GROUP_SIZE + 1],
        }
    }
}

impl Group {
    fn reset(&mut self) {
        self.received = 0;
        self.parity_received = false;
        self.count = 0;
    }
}

/// FEC Decoder — receives FEC-wrapped packets and reconstructs lost data.
///
/// Tracks packet groups and attempts reconstruction when a single packet
/// is missing from a group (using XOR parity).
pub struct Decoder {
    groups: Vec<Group>,
    group_ids: [u16; DECODER_WINDOW_SIZE],
    group_active: [bool; DECODER_WINDOW_SIZE],

    /// Output callback: called with each recovered/received data packet.
    output_fn: OutputFn,
}

impl Decoder {
    /// Create a new FEC decoder.
    pub fn new(output_fn: OutputFn) -> Self {
        let mut groups = Vec::with_capacity(DECODER_WINDOW_SIZE);
        for _ in 0..DECODER_WINDOW_SIZE {
            groups.push(Group::default());
        }
        Decoder {
            groups,
            group_ids: [0u16; DECODER_WINDOW_SIZE],
            group_active: [false; DECODER_WINDOW_SIZE],
            output_fn,
        }
    }

    /// Process a received FEC packet. Emits recovered data packets via output callback.
    pub fn add_packet(&mut self, data: &[u8]) {
        let hdr = match decode_header(data) {
            Ok(h) => h,
            Err(_) => return,
        };
        if hdr.payload_len as usize > MAX_MTU {
            return;
        }
        if data.len() < HEADER_SIZE + hdr.payload_len as usize {
            return;
        }

        // Validate untrusted wire values against array bounds.
        if hdr.count == 0 || hdr.count as usize > MAX_GROUP_SIZE {
            return;
        }
        if hdr.index > hdr.count {
            return;
        }

        let payload = &data[HEADER_SIZE..HEADER_SIZE + hdr.payload_len as usize];
        let slot = hdr.group_id as usize % DECODER_WINDOW_SIZE;

        // Initialize or validate group slot
        if !self.group_active[slot] || self.group_ids[slot] != hdr.group_id {
            self.groups[slot].reset();
            self.group_ids[slot] = hdr.group_id;
            self.group_active[slot] = true;
        }

        let is_parity = hdr.index == hdr.count;

        if is_parity {
            if self.groups[slot].parity_received {
                return; // Duplicate
            }
            self.groups[slot].parity_received = true;
            let ci = hdr.count as usize;
            self.groups[slot].packets[ci][..hdr.payload_len as usize].copy_from_slice(payload);
            self.groups[slot].packets[ci][hdr.payload_len as usize..].fill(0);
            self.groups[slot].packet_lens[ci] = hdr.payload_len;
        } else {
            if hdr.index >= hdr.count {
                return; // Invalid index
            }
            let bit: u32 = 1 << hdr.index;
            if self.groups[slot].received & bit != 0 {
                return; // Duplicate
            }
            self.groups[slot].received |= bit;
            let ii = hdr.index as usize;
            self.groups[slot].packets[ii][..hdr.payload_len as usize].copy_from_slice(payload);
            self.groups[slot].packets[ii][hdr.payload_len as usize..].fill(0);
            self.groups[slot].packet_lens[ii] = hdr.payload_len;

            self.groups[slot].count = hdr.count;

            // Emit this data packet immediately (don't wait for group completion)
            (self.output_fn)(payload);
        }

        self.groups[slot].count = hdr.count;

        // Check if we can recover a missing packet
        self.try_recover(slot);
    }

    fn try_recover(&mut self, slot: usize) {
        let group = &self.groups[slot];
        if !group.parity_received {
            return;
        }

        let count = group.count;
        let all_received: u32 = (1u32 << count) - 1;
        let received = group.received & all_received;
        let missing = all_received ^ received;

        // Can only recover exactly 1 missing packet
        if missing == 0 || missing.count_ones() != 1 {
            return;
        }

        // Find the missing index
        let missing_idx = missing.trailing_zeros() as usize;

        // Reconstruct: XOR parity with all other received data packets
        let mut recovered = [0u8; MAX_MTU];
        let parity_len = group.packet_lens[count as usize] as usize;
        recovered[..parity_len].copy_from_slice(&group.packets[count as usize][..parity_len]);

        for i in 0..count as usize {
            if i == missing_idx {
                continue;
            }
            let plen = group.packet_lens[i] as usize;
            let max_len = plen.max(parity_len);
            xor_bytes(&mut recovered[..max_len], &group.packets[i][..max_len]);
        }

        self.groups[slot].received |= 1 << missing_idx;

        // Emit recovered packet
        (self.output_fn)(&recovered[..parity_len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_header_encode_decode_roundtrip() {
        let mut buf = [0u8; HEADER_SIZE];
        encode_header(&mut buf, 42, 2, 3, 1400);
        let hdr = decode_header(&buf).unwrap();
        assert_eq!(hdr.group_id, 42);
        assert_eq!(hdr.index, 2);
        assert_eq!(hdr.count, 3);
        assert_eq!(hdr.payload_len, 1400);
    }

    #[test]
    fn test_header_decode_too_short() {
        assert_eq!(decode_header(&[0, 1, 2]), Err(FecError::PacketTooShort));
    }

    #[test]
    fn test_xor_bytes() {
        let mut a = [0xAAu8, 0xBB, 0xCC];
        let b = [0x55u8, 0x44, 0x33];
        xor_bytes(&mut a, &b);
        assert_eq!(a, [0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_encoder_produces_n_plus_1_packets() {
        let count = Arc::new(Mutex::new(0usize));
        let count_clone = count.clone();

        let mut enc = Encoder::new(3, Box::new(move |_| {
            *count_clone.lock().unwrap() += 1;
        }));

        enc.add_packet(b"packet1");
        enc.add_packet(b"packet2");
        enc.add_packet(b"packet3");

        assert_eq!(*count.lock().unwrap(), 4);
    }

    #[test]
    fn test_encoder_decoder_roundtrip_no_loss() {
        let fec_packets = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let fec_clone = fec_packets.clone();

        let mut enc = Encoder::new(3, Box::new(move |data| {
            fec_clone.lock().unwrap().push(data.to_vec());
        }));

        enc.add_packet(b"hello");
        enc.add_packet(b"world");
        enc.add_packet(b"test!");

        let packets = fec_packets.lock().unwrap().clone();
        assert_eq!(packets.len(), 4);

        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let recv_clone = received.clone();

        let mut dec = Decoder::new(Box::new(move |data| {
            recv_clone.lock().unwrap().push(data.to_vec());
        }));

        for pkt in &packets {
            dec.add_packet(pkt);
        }

        let recv = received.lock().unwrap();
        assert_eq!(recv.len(), 3);
        assert_eq!(&recv[0], b"hello");
        assert_eq!(&recv[1], b"world");
        assert_eq!(&recv[2], b"test!");
    }

    #[test]
    fn test_recover_single_lost_data_packet() {
        let fec_packets = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let fec_clone = fec_packets.clone();

        let mut enc = Encoder::new(3, Box::new(move |data| {
            fec_clone.lock().unwrap().push(data.to_vec());
        }));

        enc.add_packet(b"AAA");
        enc.add_packet(b"BBB");
        enc.add_packet(b"CCC");

        let packets = fec_packets.lock().unwrap().clone();
        assert_eq!(packets.len(), 4);

        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let recv_clone = received.clone();

        let mut dec = Decoder::new(Box::new(move |data| {
            recv_clone.lock().unwrap().push(data.to_vec());
        }));

        dec.add_packet(&packets[0]); // "AAA"
        // skip packets[1] "BBB"
        dec.add_packet(&packets[2]); // "CCC"
        dec.add_packet(&packets[3]); // parity

        let recv = received.lock().unwrap();
        assert_eq!(recv.len(), 3);
        assert_eq!(&recv[0], b"AAA");
        assert_eq!(&recv[1], b"CCC");
        assert_eq!(&recv[2], b"BBB"); // recovered
    }

    #[test]
    fn test_recover_first_packet() {
        let fec_packets = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let fec_clone = fec_packets.clone();

        let mut enc = Encoder::new(3, Box::new(move |data| {
            fec_clone.lock().unwrap().push(data.to_vec());
        }));

        enc.add_packet(b"AAA");
        enc.add_packet(b"BBB");
        enc.add_packet(b"CCC");

        let packets = fec_packets.lock().unwrap().clone();

        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let recv_clone = received.clone();

        let mut dec = Decoder::new(Box::new(move |data| {
            recv_clone.lock().unwrap().push(data.to_vec());
        }));

        // Skip first packet
        dec.add_packet(&packets[1]); // "BBB"
        dec.add_packet(&packets[2]); // "CCC"
        dec.add_packet(&packets[3]); // parity

        let recv = received.lock().unwrap();
        assert_eq!(recv.len(), 3);
        assert_eq!(&recv[0], b"BBB");
        assert_eq!(&recv[1], b"CCC");
        assert_eq!(&recv[2], b"AAA"); // recovered
    }

    #[test]
    fn test_multiple_groups() {
        let fec_packets = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let fec_clone = fec_packets.clone();

        let mut enc = Encoder::new(2, Box::new(move |data| {
            fec_clone.lock().unwrap().push(data.to_vec());
        }));

        // Group 0: 2 data + 1 parity = 3
        enc.add_packet(b"A1");
        enc.add_packet(b"A2");
        // Group 1: 2 data + 1 parity = 3
        enc.add_packet(b"B1");
        enc.add_packet(b"B2");

        let packets = fec_packets.lock().unwrap().clone();
        assert_eq!(packets.len(), 6);

        // Verify group IDs
        let hdr0 = decode_header(&packets[0]).unwrap();
        let hdr3 = decode_header(&packets[3]).unwrap();
        assert_eq!(hdr0.group_id, 0);
        assert_eq!(hdr3.group_id, 1);

        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let recv_clone = received.clone();

        let mut dec = Decoder::new(Box::new(move |data| {
            recv_clone.lock().unwrap().push(data.to_vec());
        }));

        // Group 0: skip A1 (index 0)
        dec.add_packet(&packets[1]); // A2
        dec.add_packet(&packets[2]); // parity → recovers A1
        // Group 1: skip B2 (index 1)
        dec.add_packet(&packets[3]); // B1
        dec.add_packet(&packets[5]); // parity → recovers B2

        assert_eq!(received.lock().unwrap().len(), 4);
    }

    #[test]
    fn test_flush_partial() {
        let count = Arc::new(Mutex::new(0usize));
        let count_clone = count.clone();

        let mut enc = Encoder::new(5, Box::new(move |_| {
            *count_clone.lock().unwrap() += 1;
        }));

        enc.add_packet(b"one");
        enc.add_packet(b"two");
        assert_eq!(*count.lock().unwrap(), 0);

        enc.flush_partial();
        // 2 data + 1 parity = 3
        assert_eq!(*count.lock().unwrap(), 3);
    }

    #[test]
    fn test_decoder_rejects_invalid_packets() {
        let received = Arc::new(Mutex::new(0usize));
        let recv_clone = received.clone();

        let mut dec = Decoder::new(Box::new(move |_| {
            *recv_clone.lock().unwrap() += 1;
        }));

        // count=255 (> MAX_GROUP_SIZE) — silently dropped
        let mut bad1 = [0u8; HEADER_SIZE + 4];
        encode_header(&mut bad1, 0, 0, 255, 4);
        bad1[HEADER_SIZE..].copy_from_slice(b"XXXX");
        dec.add_packet(&bad1);

        // count=0 — invalid
        let mut bad2 = [0u8; HEADER_SIZE + 4];
        encode_header(&mut bad2, 0, 0, 0, 4);
        bad2[HEADER_SIZE..].copy_from_slice(b"XXXX");
        dec.add_packet(&bad2);

        // index > count
        let mut bad3 = [0u8; HEADER_SIZE + 4];
        encode_header(&mut bad3, 0, 5, 3, 4);
        bad3[HEADER_SIZE..].copy_from_slice(b"XXXX");
        dec.add_packet(&bad3);

        assert_eq!(*received.lock().unwrap(), 0);
    }

    #[test]
    fn test_cannot_recover_two_lost() {
        let fec_packets = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let fec_clone = fec_packets.clone();

        let mut enc = Encoder::new(3, Box::new(move |data| {
            fec_clone.lock().unwrap().push(data.to_vec());
        }));

        enc.add_packet(b"AAA");
        enc.add_packet(b"BBB");
        enc.add_packet(b"CCC");

        let packets = fec_packets.lock().unwrap().clone();

        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let recv_clone = received.clone();

        let mut dec = Decoder::new(Box::new(move |data| {
            recv_clone.lock().unwrap().push(data.to_vec());
        }));

        // Only 1 data + parity — 2 lost, cannot recover
        dec.add_packet(&packets[0]); // "AAA"
        dec.add_packet(&packets[3]); // parity

        assert_eq!(received.lock().unwrap().len(), 1);
    }
}
