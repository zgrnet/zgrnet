//! Minimal DNS protocol parser (encode/decode).
//!
//! Supports A (1) and AAAA (28) query/response types.
//! Handles DNS name compression for decoding.

use std::fmt;

/// DNS record types.
pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

/// DNS header flag bits.
pub const FLAG_QR: u16 = 1 << 15; // Query/Response
pub const FLAG_AA: u16 = 1 << 10; // Authoritative Answer
pub const FLAG_TC: u16 = 1 << 9; // Truncated
pub const FLAG_RD: u16 = 1 << 8; // Recursion Desired
pub const FLAG_RA: u16 = 1 << 7; // Recursion Available
pub const MASK_RCODE: u16 = 0x000F;

/// DNS response codes.
pub const RCODE_NOERROR: u16 = 0;
pub const RCODE_FORMERR: u16 = 1;
pub const RCODE_SERVFAIL: u16 = 2;
pub const RCODE_NXDOMAIN: u16 = 3;

/// DNS errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    Truncated,
    InvalidHeader,
    InvalidName,
    NameTooLong,
    LabelTooLong,
    PointerLoop,
    InvalidRData,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::Truncated => write!(f, "dns: message truncated"),
            DnsError::InvalidHeader => write!(f, "dns: invalid header"),
            DnsError::InvalidName => write!(f, "dns: invalid name"),
            DnsError::NameTooLong => write!(f, "dns: name too long"),
            DnsError::LabelTooLong => write!(f, "dns: label too long (max 63)"),
            DnsError::PointerLoop => write!(f, "dns: compression pointer loop"),
            DnsError::InvalidRData => write!(f, "dns: invalid rdata"),
        }
    }
}

impl std::error::Error for DnsError {}

/// DNS message header (12 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl Header {
    pub fn is_response(&self) -> bool {
        self.flags & FLAG_QR != 0
    }

    pub fn rcode(&self) -> u16 {
        self.flags & MASK_RCODE
    }
}

/// DNS question entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

/// Complete DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    /// Decode a DNS message from wire format.
    pub fn decode(data: &[u8]) -> Result<Message, DnsError> {
        if data.len() < 12 {
            return Err(DnsError::InvalidHeader);
        }

        let header = Header {
            id: u16::from_be_bytes([data[0], data[1]]),
            flags: u16::from_be_bytes([data[2], data[3]]),
            qd_count: u16::from_be_bytes([data[4], data[5]]),
            an_count: u16::from_be_bytes([data[6], data[7]]),
            ns_count: u16::from_be_bytes([data[8], data[9]]),
            ar_count: u16::from_be_bytes([data[10], data[11]]),
        };

        let mut offset = 12;

        // Decode questions
        let mut questions = Vec::new();
        for _ in 0..header.qd_count {
            let (name, consumed) = decode_name(data, offset)?;
            offset += consumed;
            if offset + 4 > data.len() {
                return Err(DnsError::Truncated);
            }
            questions.push(Question {
                name,
                qtype: u16::from_be_bytes([data[offset], data[offset + 1]]),
                qclass: u16::from_be_bytes([data[offset + 2], data[offset + 3]]),
            });
            offset += 4;
        }

        let (answers, new_off) = decode_rrs(data, offset, header.an_count as usize)?;
        offset = new_off;
        let (authorities, new_off) = decode_rrs(data, offset, header.ns_count as usize)?;
        offset = new_off;
        let (additionals, _) = decode_rrs(data, offset, header.ar_count as usize)?;

        Ok(Message {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// Encode a DNS message to wire format.
    pub fn encode(&self) -> Result<Vec<u8>, DnsError> {
        let mut buf = Vec::with_capacity(512);

        // Header
        buf.extend_from_slice(&self.header.id.to_be_bytes());
        buf.extend_from_slice(&self.header.flags.to_be_bytes());
        buf.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.authorities.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.additionals.len() as u16).to_be_bytes());

        // Questions
        for q in &self.questions {
            buf.extend_from_slice(&encode_name(&q.name)?);
            buf.extend_from_slice(&q.qtype.to_be_bytes());
            buf.extend_from_slice(&q.qclass.to_be_bytes());
        }

        // Resource records
        for rr in &self.answers {
            encode_rr(&mut buf, rr)?;
        }
        for rr in &self.authorities {
            encode_rr(&mut buf, rr)?;
        }
        for rr in &self.additionals {
            encode_rr(&mut buf, rr)?;
        }

        Ok(buf)
    }

    /// Create a response message for the given query.
    pub fn new_response(query: &Message, rcode: u16) -> Message {
        Message {
            header: Header {
                id: query.header.id,
                flags: FLAG_QR | FLAG_AA | (query.header.flags & FLAG_RD) | rcode,
                qd_count: query.questions.len() as u16,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: query.questions.clone(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }
}

/// Create an A resource record.
pub fn new_a_record(name: &str, ttl: u32, ip: [u8; 4]) -> ResourceRecord {
    ResourceRecord {
        name: name.to_string(),
        rtype: TYPE_A,
        rclass: CLASS_IN,
        ttl,
        rdata: ip.to_vec(),
    }
}

/// Create an AAAA resource record.
pub fn new_aaaa_record(name: &str, ttl: u32, ip: [u8; 16]) -> ResourceRecord {
    ResourceRecord {
        name: name.to_string(),
        rtype: TYPE_AAAA,
        rclass: CLASS_IN,
        ttl,
        rdata: ip.to_vec(),
    }
}

/// Encode a domain name to wire format.
pub fn encode_name(name: &str) -> Result<Vec<u8>, DnsError> {
    if name.is_empty() || name == "." {
        return Ok(vec![0]);
    }

    let name = name.trim_end_matches('.');
    let mut buf = Vec::new();
    let mut total_len = 0;

    for label in name.split('.') {
        if label.is_empty() {
            return Err(DnsError::InvalidName);
        }
        if label.len() > 63 {
            return Err(DnsError::LabelTooLong);
        }
        total_len += 1 + label.len();
        if total_len > 253 {
            return Err(DnsError::NameTooLong);
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // Root label
    Ok(buf)
}

/// Decode a domain name from wire format with compression pointer support.
/// Returns (name, bytes_consumed_from_offset).
pub fn decode_name(data: &[u8], offset: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut consumed = 0;
    let mut jumped = false;
    let mut pos = offset;
    let mut seen = std::collections::HashSet::new();

    loop {
        if pos >= data.len() {
            return Err(DnsError::Truncated);
        }

        let length = data[pos] as usize;

        if length == 0 {
            if !jumped {
                consumed = pos - offset + 1;
            }
            break;
        }

        // Compression pointer
        if length & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return Err(DnsError::Truncated);
            }
            if !jumped {
                consumed = pos - offset + 2;
            }
            let ptr = ((data[pos] as usize & 0x3F) << 8) | data[pos + 1] as usize;
            if seen.contains(&ptr) {
                return Err(DnsError::PointerLoop);
            }
            seen.insert(ptr);
            pos = ptr;
            jumped = true;
            continue;
        }

        // Regular label
        pos += 1;
        if pos + length > data.len() {
            return Err(DnsError::Truncated);
        }
        labels.push(String::from_utf8_lossy(&data[pos..pos + length]).into_owned());
        pos += length;
    }

    if labels.is_empty() {
        Ok((".".to_string(), consumed))
    } else {
        Ok((labels.join("."), consumed))
    }
}

fn decode_rrs(
    data: &[u8],
    mut offset: usize,
    count: usize,
) -> Result<(Vec<ResourceRecord>, usize), DnsError> {
    let mut rrs = Vec::new();
    for _ in 0..count {
        let (name, consumed) = decode_name(data, offset)?;
        offset += consumed;

        if offset + 10 > data.len() {
            return Err(DnsError::Truncated);
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
        let rd_len = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if offset + rd_len > data.len() {
            return Err(DnsError::Truncated);
        }

        let rdata = data[offset..offset + rd_len].to_vec();
        offset += rd_len;

        rrs.push(ResourceRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        });
    }
    Ok((rrs, offset))
}

fn encode_rr(buf: &mut Vec<u8>, rr: &ResourceRecord) -> Result<(), DnsError> {
    buf.extend_from_slice(&encode_name(&rr.name)?);
    buf.extend_from_slice(&rr.rtype.to_be_bytes());
    buf.extend_from_slice(&rr.rclass.to_be_bytes());
    buf.extend_from_slice(&rr.ttl.to_be_bytes());
    buf.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
    buf.extend_from_slice(&rr.rdata);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_name() {
        let encoded = encode_name("example.com").unwrap();
        assert_eq!(
            encoded,
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );

        assert_eq!(encode_name(".").unwrap(), vec![0]);
        assert_eq!(encode_name("").unwrap(), vec![0]);
        assert_eq!(encode_name("example.com.").unwrap(), encode_name("example.com").unwrap());
    }

    #[test]
    fn test_encode_name_errors() {
        // Label too long
        let long_label = "a".repeat(64) + ".com";
        assert_eq!(encode_name(&long_label).unwrap_err(), DnsError::LabelTooLong);

        // Double dot
        assert_eq!(encode_name("example..com").unwrap_err(), DnsError::InvalidName);
    }

    #[test]
    fn test_decode_name() {
        let data = vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
        let (name, consumed) = decode_name(&data, 0).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(consumed, 13);
    }

    #[test]
    fn test_decode_name_compression() {
        let mut data = vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
        data.extend_from_slice(&[0xC0, 0x00]); // pointer to offset 0

        let (name, consumed) = decode_name(&data, 13).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_decode_name_pointer_loop() {
        let data = vec![0xC0, 0x00]; // self-referencing pointer
        assert_eq!(decode_name(&data, 0).unwrap_err(), DnsError::PointerLoop);
    }

    #[test]
    fn test_message_roundtrip() {
        let query = Message {
            header: Header {
                id: 0x1234,
                flags: FLAG_RD,
                qd_count: 1,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![Question {
                name: "example.com".to_string(),
                qtype: TYPE_A,
                qclass: CLASS_IN,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };

        let encoded = query.encode().unwrap();
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(decoded.header.id, 0x1234);
        assert_eq!(decoded.header.flags, FLAG_RD);
        assert_eq!(decoded.questions.len(), 1);
        assert_eq!(decoded.questions[0].name, "example.com");
        assert_eq!(decoded.questions[0].qtype, TYPE_A);
    }

    #[test]
    fn test_response_roundtrip() {
        let query = Message {
            header: Header {
                id: 0xABCD,
                flags: FLAG_RD,
                qd_count: 1,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![Question {
                name: "localhost.zigor.net".to_string(),
                qtype: TYPE_A,
                qclass: CLASS_IN,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };

        let mut resp = Message::new_response(&query, RCODE_NOERROR);
        resp.answers.push(new_a_record("localhost.zigor.net", 60, [100, 64, 0, 1]));

        let encoded = resp.encode().unwrap();
        let decoded = Message::decode(&encoded).unwrap();

        assert!(decoded.header.is_response());
        assert_eq!(decoded.header.id, 0xABCD);
        assert_eq!(decoded.header.rcode(), RCODE_NOERROR);
        assert_eq!(decoded.answers.len(), 1);
        assert_eq!(decoded.answers[0].name, "localhost.zigor.net");
        assert_eq!(decoded.answers[0].rtype, TYPE_A);
        assert_eq!(decoded.answers[0].ttl, 60);
        assert_eq!(decoded.answers[0].rdata, vec![100, 64, 0, 1]);
    }

    #[test]
    fn test_aaaa_record_roundtrip() {
        let query = Message {
            header: Header {
                id: 0x5678,
                flags: FLAG_RD,
                qd_count: 1, an_count: 0, ns_count: 0, ar_count: 0,
            },
            questions: vec![Question {
                name: "test.zigor.net".to_string(),
                qtype: TYPE_AAAA,
                qclass: CLASS_IN,
            }],
            answers: vec![], authorities: vec![], additionals: vec![],
        };

        let ipv6 = [0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut resp = Message::new_response(&query, RCODE_NOERROR);
        resp.answers.push(new_aaaa_record("test.zigor.net", 60, ipv6));

        let encoded = resp.encode().unwrap();
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(decoded.answers.len(), 1);
        assert_eq!(decoded.answers[0].rtype, TYPE_AAAA);
        assert_eq!(decoded.answers[0].rdata, ipv6.to_vec());
    }

    #[test]
    fn test_nxdomain_response() {
        let query = Message {
            header: Header {
                id: 0x9999, flags: FLAG_RD,
                qd_count: 1, an_count: 0, ns_count: 0, ar_count: 0,
            },
            questions: vec![Question {
                name: "nonexistent.zigor.net".to_string(),
                qtype: TYPE_A, qclass: CLASS_IN,
            }],
            answers: vec![], authorities: vec![], additionals: vec![],
        };

        let resp = Message::new_response(&query, RCODE_NXDOMAIN);
        let encoded = resp.encode().unwrap();
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(decoded.header.rcode(), RCODE_NXDOMAIN);
        assert!(decoded.answers.is_empty());
    }

    #[test]
    fn test_decode_truncated() {
        assert_eq!(Message::decode(&[0, 1, 2]).unwrap_err(), DnsError::InvalidHeader);

        // Header says 1 question but no data
        let mut data = vec![0u8; 12];
        data[5] = 1; // qd_count = 1
        assert!(Message::decode(&data).is_err());
    }
}
