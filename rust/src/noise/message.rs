//! Wire protocol message types and parsing.
//!
//! This module defines the message formats for the Noise-based protocol,
//! including handshake messages and transport messages.

use super::keypair::Key;
use super::cipher::TAG_SIZE;

/// Message type constants for the wire protocol.
pub mod message_type {
    /// Handshake initiation message (Type 1).
    pub const HANDSHAKE_INIT: u8 = 1;
    /// Handshake response message (Type 2).
    pub const HANDSHAKE_RESP: u8 = 2;
    /// Cookie reply for DoS protection (Type 3).
    pub const COOKIE_REPLY: u8 = 3;
    /// Encrypted transport message (Type 4).
    pub const TRANSPORT: u8 = 4;
}

/// Protocol field values (inside encrypted payload).
pub mod protocol {
    // Transport layer protocols (0-63, matching IP protocol numbers)
    /// ICMP in ZigNet (no IP header)
    pub const ICMP: u8 = 1;
    /// IP in ZigNet (complete IP packet)
    pub const IP: u8 = 4;
    /// TCP in ZigNet (no IP header)
    pub const TCP: u8 = 6;
    /// UDP in ZigNet (no IP header)
    pub const UDP: u8 = 17;

    // ZigNet extension protocols (64-127)
    /// KCP reliable UDP
    pub const KCP: u8 = 64;
    /// UDP proxy
    pub const UDP_PROXY: u8 = 65;
    /// Relay first hop
    pub const RELAY_0: u8 = 66;
    /// Relay middle hop
    pub const RELAY_1: u8 = 67;
    /// Relay last hop
    pub const RELAY_2: u8 = 68;
    /// TCP proxy via KCP stream
    pub const TCP_PROXY: u8 = 69;
    /// Ping probe request
    pub const PING: u8 = 70;
    /// Pong probe response
    pub const PONG: u8 = 71;

    // Application layer protocols (128-255)
    /// Chat messages
    pub const CHAT: u8 = 128;
    /// File transfer
    pub const FILE: u8 = 129;
    /// Audio/video streams
    pub const MEDIA: u8 = 130;
    /// Signaling (WebRTC, etc.)
    pub const SIGNAL: u8 = 131;
    /// Remote procedure calls
    pub const RPC: u8 = 132;
}

/// Key size in bytes.
pub const KEY_SIZE: usize = 32;

/// Handshake initiation message size.
/// type(1) + sender_idx(4) + ephemeral(32) + static_enc(48) = 85
pub const HANDSHAKE_INIT_SIZE: usize = 1 + 4 + 32 + 48;

/// Handshake response message size.
/// type(1) + sender_idx(4) + receiver_idx(4) + ephemeral(32) + encrypted_empty(16) = 57
pub const HANDSHAKE_RESP_SIZE: usize = 1 + 4 + 4 + 32 + 16;

/// Transport message header size.
/// type(1) + receiver_idx(4) + counter(8) = 13
pub const TRANSPORT_HEADER_SIZE: usize = 1 + 4 + 8;

/// Maximum payload size (64KB - headers - tag - protocol byte).
pub const MAX_PAYLOAD_SIZE: usize = 65535 - TRANSPORT_HEADER_SIZE - TAG_SIZE - 1;

/// Maximum packet size we accept.
pub const MAX_PACKET_SIZE: usize = 65535;

/// Message parsing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// Message is too short.
    TooShort,
    /// Invalid message type.
    InvalidType,
}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "message too short"),
            Self::InvalidType => write!(f, "invalid message type"),
        }
    }
}

impl std::error::Error for MessageError {}

/// A parsed handshake initiation message (Type 1).
#[derive(Debug, Clone)]
pub struct HandshakeInit {
    /// Sender's session index.
    pub sender_index: u32,
    /// Ephemeral public key.
    pub ephemeral: Key,
    /// Encrypted static key (48 bytes = 32B key + 16B tag).
    pub static_encrypted: [u8; 48],
}

/// A parsed handshake response message (Type 2).
#[derive(Debug, Clone)]
pub struct HandshakeResp {
    /// Sender's session index.
    pub sender_index: u32,
    /// Receiver's session index (from initiation).
    pub receiver_index: u32,
    /// Ephemeral public key.
    pub ephemeral: Key,
    /// Encrypted empty payload (16 bytes, just tag).
    pub empty_encrypted: [u8; 16],
}

/// A parsed transport message (Type 4).
#[derive(Debug, Clone)]
pub struct TransportMessage<'a> {
    /// Receiver's session index.
    pub receiver_index: u32,
    /// Counter/nonce.
    pub counter: u64,
    /// Ciphertext (includes 16-byte auth tag).
    pub ciphertext: &'a [u8],
}

/// Parse a handshake initiation message.
pub fn parse_handshake_init(data: &[u8]) -> Result<HandshakeInit, MessageError> {
    if data.len() < HANDSHAKE_INIT_SIZE {
        return Err(MessageError::TooShort);
    }
    if data[0] != message_type::HANDSHAKE_INIT {
        return Err(MessageError::InvalidType);
    }

    let sender_index = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    
    let mut ephemeral = Key::default();
    ephemeral.0.copy_from_slice(&data[5..37]);
    
    let mut static_encrypted = [0u8; 48];
    static_encrypted.copy_from_slice(&data[37..85]);

    Ok(HandshakeInit {
        sender_index,
        ephemeral,
        static_encrypted,
    })
}

/// Build a handshake initiation message.
pub fn build_handshake_init(sender_index: u32, ephemeral: &Key, static_encrypted: &[u8]) -> Vec<u8> {
    let mut msg = vec![0u8; HANDSHAKE_INIT_SIZE];
    msg[0] = message_type::HANDSHAKE_INIT;
    msg[1..5].copy_from_slice(&sender_index.to_le_bytes());
    msg[5..37].copy_from_slice(ephemeral.as_bytes());
    msg[37..85].copy_from_slice(&static_encrypted[..48]);
    msg
}

/// Parse a handshake response message.
pub fn parse_handshake_resp(data: &[u8]) -> Result<HandshakeResp, MessageError> {
    if data.len() < HANDSHAKE_RESP_SIZE {
        return Err(MessageError::TooShort);
    }
    if data[0] != message_type::HANDSHAKE_RESP {
        return Err(MessageError::InvalidType);
    }

    let sender_index = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let receiver_index = u32::from_le_bytes([data[5], data[6], data[7], data[8]]);
    
    let mut ephemeral = Key::default();
    ephemeral.0.copy_from_slice(&data[9..41]);
    
    let mut empty_encrypted = [0u8; 16];
    empty_encrypted.copy_from_slice(&data[41..57]);

    Ok(HandshakeResp {
        sender_index,
        receiver_index,
        ephemeral,
        empty_encrypted,
    })
}

/// Build a handshake response message.
pub fn build_handshake_resp(
    sender_index: u32,
    receiver_index: u32,
    ephemeral: &Key,
    empty_encrypted: &[u8],
) -> Vec<u8> {
    let mut msg = vec![0u8; HANDSHAKE_RESP_SIZE];
    msg[0] = message_type::HANDSHAKE_RESP;
    msg[1..5].copy_from_slice(&sender_index.to_le_bytes());
    msg[5..9].copy_from_slice(&receiver_index.to_le_bytes());
    msg[9..41].copy_from_slice(ephemeral.as_bytes());
    msg[41..57].copy_from_slice(&empty_encrypted[..16]);
    msg
}

/// Parse a transport message.
pub fn parse_transport_message(data: &[u8]) -> Result<TransportMessage<'_>, MessageError> {
    if data.len() < TRANSPORT_HEADER_SIZE + TAG_SIZE {
        return Err(MessageError::TooShort);
    }
    if data[0] != message_type::TRANSPORT {
        return Err(MessageError::InvalidType);
    }

    let receiver_index = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let counter = u64::from_le_bytes([
        data[5], data[6], data[7], data[8],
        data[9], data[10], data[11], data[12],
    ]);

    Ok(TransportMessage {
        receiver_index,
        counter,
        ciphertext: &data[13..],
    })
}

/// Build a transport message.
pub fn build_transport_message(receiver_index: u32, counter: u64, ciphertext: &[u8]) -> Vec<u8> {
    let mut msg = vec![0u8; TRANSPORT_HEADER_SIZE + ciphertext.len()];
    msg[0] = message_type::TRANSPORT;
    msg[1..5].copy_from_slice(&receiver_index.to_le_bytes());
    msg[5..13].copy_from_slice(&counter.to_le_bytes());
    msg[13..].copy_from_slice(ciphertext);
    msg
}

/// Encode a payload with protocol byte.
pub fn encode_payload(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; 1 + payload.len()];
    result[0] = protocol;
    result[1..].copy_from_slice(payload);
    result
}

/// Decode a payload to extract protocol and data.
pub fn decode_payload(data: &[u8]) -> Result<(u8, &[u8]), MessageError> {
    if data.is_empty() {
        return Err(MessageError::TooShort);
    }
    Ok((data[0], &data[1..]))
}

/// Get the message type from raw data.
pub fn get_message_type(data: &[u8]) -> Result<u8, MessageError> {
    if data.is_empty() {
        return Err(MessageError::TooShort);
    }
    Ok(data[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_init_roundtrip() {
        let sender_index = 12345u32;
        let ephemeral = Key([0xAA; 32]);
        let static_encrypted = [0xBB; 48];

        let msg = build_handshake_init(sender_index, &ephemeral, &static_encrypted);
        assert_eq!(msg.len(), HANDSHAKE_INIT_SIZE);

        let parsed = parse_handshake_init(&msg).unwrap();
        assert_eq!(parsed.sender_index, sender_index);
        assert_eq!(parsed.ephemeral, ephemeral);
        assert_eq!(parsed.static_encrypted, static_encrypted);
    }

    #[test]
    fn test_handshake_resp_roundtrip() {
        let sender_index = 11111u32;
        let receiver_index = 22222u32;
        let ephemeral = Key([0xCC; 32]);
        let empty_encrypted = [0xDD; 16];

        let msg = build_handshake_resp(sender_index, receiver_index, &ephemeral, &empty_encrypted);
        assert_eq!(msg.len(), HANDSHAKE_RESP_SIZE);

        let parsed = parse_handshake_resp(&msg).unwrap();
        assert_eq!(parsed.sender_index, sender_index);
        assert_eq!(parsed.receiver_index, receiver_index);
        assert_eq!(parsed.ephemeral, ephemeral);
        assert_eq!(parsed.empty_encrypted, empty_encrypted);
    }

    #[test]
    fn test_transport_message_roundtrip() {
        let receiver_index = 33333u32;
        let counter = 44444u64;
        let ciphertext = vec![0xEE; 100];

        let msg = build_transport_message(receiver_index, counter, &ciphertext);
        assert_eq!(msg.len(), TRANSPORT_HEADER_SIZE + ciphertext.len());

        let parsed = parse_transport_message(&msg).unwrap();
        assert_eq!(parsed.receiver_index, receiver_index);
        assert_eq!(parsed.counter, counter);
        assert_eq!(parsed.ciphertext, &ciphertext[..]);
    }

    #[test]
    fn test_payload_roundtrip() {
        let protocol = protocol::CHAT;
        let payload = b"hello world";

        let encoded = encode_payload(protocol, payload);
        assert_eq!(encoded.len(), 1 + payload.len());

        let (decoded_proto, decoded_payload) = decode_payload(&encoded).unwrap();
        assert_eq!(decoded_proto, protocol);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_message_too_short() {
        assert_eq!(parse_handshake_init(&[1, 2, 3]).unwrap_err(), MessageError::TooShort);
        assert_eq!(parse_handshake_resp(&[1, 2, 3]).unwrap_err(), MessageError::TooShort);
        assert_eq!(parse_transport_message(&[1, 2, 3]).unwrap_err(), MessageError::TooShort);
        assert_eq!(decode_payload(&[]).unwrap_err(), MessageError::TooShort);
        assert_eq!(get_message_type(&[]).unwrap_err(), MessageError::TooShort);
    }

    #[test]
    fn test_invalid_message_type() {
        let mut msg = vec![0u8; HANDSHAKE_INIT_SIZE];
        msg[0] = message_type::TRANSPORT; // Wrong type
        assert_eq!(parse_handshake_init(&msg).unwrap_err(), MessageError::InvalidType);

        let mut msg = vec![0u8; HANDSHAKE_RESP_SIZE];
        msg[0] = message_type::HANDSHAKE_INIT; // Wrong type
        assert_eq!(parse_handshake_resp(&msg).unwrap_err(), MessageError::InvalidType);

        let mut msg = vec![0u8; TRANSPORT_HEADER_SIZE + TAG_SIZE];
        msg[0] = message_type::HANDSHAKE_INIT; // Wrong type
        assert_eq!(parse_transport_message(&msg).unwrap_err(), MessageError::InvalidType);
    }

    #[test]
    fn test_protocol_constants() {
        assert_eq!(protocol::ICMP, 1);
        assert_eq!(protocol::IP, 4);
        assert_eq!(protocol::TCP, 6);
        assert_eq!(protocol::UDP, 17);
        assert_eq!(protocol::KCP, 64);
        assert_eq!(protocol::CHAT, 128);
    }
}
