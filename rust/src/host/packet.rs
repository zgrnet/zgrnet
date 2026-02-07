//! IP packet parsing and building.
//!
//! Functions to parse IPv4/IPv6 headers and to build new IP packets
//! with correct checksum recalculation (IP header, TCP/UDP pseudo-header).

use std::net::Ipv4Addr;

// ============================================================================
// Errors
// ============================================================================

/// Errors for packet parsing/building.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    TooShort,
    TooLarge,
    InvalidVersion,
    InvalidAddress,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::TooShort => write!(f, "packet too short"),
            PacketError::TooLarge => write!(f, "packet too large"),
            PacketError::InvalidVersion => write!(f, "invalid IP version"),
            PacketError::InvalidAddress => write!(f, "invalid IP address"),
        }
    }
}

impl std::error::Error for PacketError {}

// ============================================================================
// PacketInfo
// ============================================================================

/// Parsed information from an IP packet.
pub struct PacketInfo<'a> {
    /// IP version (4 or 6).
    pub version: u8,
    /// IP protocol number (1=ICMP, 6=TCP, 17=UDP).
    pub protocol: u8,
    /// Source IP address (4 bytes for IPv4, 16 bytes for IPv6).
    pub src_ip: &'a [u8],
    /// Destination IP address.
    pub dst_ip: &'a [u8],
    /// Transport layer payload (after IP header).
    pub payload: &'a [u8],
    /// IP header length in bytes.
    pub header_len: usize,
}

impl<'a> PacketInfo<'a> {
    /// Returns the destination IP as Ipv4Addr (only valid for IPv4 packets).
    pub fn dst_ip_v4(&self) -> Option<Ipv4Addr> {
        if self.version == 4 && self.dst_ip.len() == 4 {
            Some(Ipv4Addr::new(
                self.dst_ip[0],
                self.dst_ip[1],
                self.dst_ip[2],
                self.dst_ip[3],
            ))
        } else {
            None
        }
    }

    /// Returns the source IP as Ipv4Addr (only valid for IPv4 packets).
    pub fn src_ip_v4(&self) -> Option<Ipv4Addr> {
        if self.version == 4 && self.src_ip.len() == 4 {
            Some(Ipv4Addr::new(
                self.src_ip[0],
                self.src_ip[1],
                self.src_ip[2],
                self.src_ip[3],
            ))
        } else {
            None
        }
    }
}

// ============================================================================
// Parse
// ============================================================================

/// Parses an IP packet and extracts header info.
/// Handles both IPv4 and IPv6 based on the version nibble.
pub fn parse_ip_packet(pkt: &[u8]) -> Result<PacketInfo<'_>, PacketError> {
    if pkt.is_empty() {
        return Err(PacketError::TooShort);
    }

    let version = pkt[0] >> 4;
    match version {
        4 => parse_ipv4(pkt),
        6 => parse_ipv6(pkt),
        _ => Err(PacketError::InvalidVersion),
    }
}

fn parse_ipv4(pkt: &[u8]) -> Result<PacketInfo<'_>, PacketError> {
    if pkt.len() < 20 {
        return Err(PacketError::TooShort);
    }

    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return Err(PacketError::TooShort);
    }

    Ok(PacketInfo {
        version: 4,
        protocol: pkt[9],
        src_ip: &pkt[12..16],
        dst_ip: &pkt[16..20],
        payload: &pkt[ihl..],
        header_len: ihl,
    })
}

fn parse_ipv6(pkt: &[u8]) -> Result<PacketInfo<'_>, PacketError> {
    if pkt.len() < 40 {
        return Err(PacketError::TooShort);
    }

    Ok(PacketInfo {
        version: 6,
        protocol: pkt[6], // Next Header
        src_ip: &pkt[8..24],
        dst_ip: &pkt[24..40],
        payload: &pkt[40..],
        header_len: 40,
    })
}

// ============================================================================
// Build
// ============================================================================

/// Creates an IPv4 packet from components.
///
/// Constructs a minimal 20-byte IPv4 header and appends the transport payload.
/// Recalculates both IP header checksum and transport checksums (TCP/UDP).
pub fn build_ipv4_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
) -> Result<Vec<u8>, PacketError> {
    const HEADER_LEN: usize = 20;
    let total_len = HEADER_LEN + payload.len();
    if total_len > 65535 {
        return Err(PacketError::TooLarge);
    }

    let mut pkt = vec![0u8; total_len];

    // IPv4 header
    pkt[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    pkt[1] = 0x00; // DSCP / ECN
    pkt[2] = (total_len >> 8) as u8;
    pkt[3] = total_len as u8;
    // Identification [4:6] = 0
    pkt[6] = 0x40; // Don't Fragment flag
    pkt[7] = 0x00; // Fragment offset
    pkt[8] = 64; // TTL
    pkt[9] = protocol;
    // Header checksum [10:12] = 0, computed below
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    // Compute IP header checksum
    let cksum = ip_checksum(&pkt[..HEADER_LEN]);
    pkt[10] = (cksum >> 8) as u8;
    pkt[11] = cksum as u8;

    // Copy transport payload
    pkt[HEADER_LEN..].copy_from_slice(payload);

    // Fix transport layer checksum (TCP/UDP use pseudo-header with IPs)
    fix_transport_checksum(
        &mut pkt[HEADER_LEN..],
        &src_ip.octets(),
        &dst_ip.octets(),
        protocol,
    );

    Ok(pkt)
}

/// Creates an IPv6 packet from components.
pub fn build_ipv6_packet(
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    protocol: u8,
    payload: &[u8],
) -> Result<Vec<u8>, PacketError> {
    const HEADER_LEN: usize = 40;
    let payload_len = payload.len();
    if payload_len > 65535 {
        return Err(PacketError::TooLarge);
    }

    let mut pkt = vec![0u8; HEADER_LEN + payload_len];

    // IPv6 header
    pkt[0] = 0x60; // Version 6
    // Traffic class and flow label [1:4] = 0
    pkt[4] = (payload_len >> 8) as u8;
    pkt[5] = payload_len as u8;
    pkt[6] = protocol; // Next Header
    pkt[7] = 64; // Hop Limit
    pkt[8..24].copy_from_slice(src_ip);
    pkt[24..40].copy_from_slice(dst_ip);

    // Copy transport payload
    pkt[HEADER_LEN..].copy_from_slice(payload);

    // Fix transport layer checksum
    fix_transport_checksum_v6(
        &mut pkt[HEADER_LEN..],
        src_ip,
        dst_ip,
        protocol,
    );

    Ok(pkt)
}

// ============================================================================
// Checksum helpers
// ============================================================================

/// Recalculates TCP/UDP checksums for IPv4.
fn fix_transport_checksum(transport: &mut [u8], src_ip: &[u8; 4], dst_ip: &[u8; 4], protocol: u8) {
    match protocol {
        6 => {
            // TCP
            if transport.len() < 20 {
                return;
            }
            // Zero out existing checksum
            transport[16] = 0;
            transport[17] = 0;
            let cs = pseudo_header_checksum(src_ip, dst_ip, protocol, transport);
            transport[16] = (cs >> 8) as u8;
            transport[17] = cs as u8;
        }
        17 => {
            // UDP
            if transport.len() < 8 {
                return;
            }
            // In IPv4, UDP checksum 0 means "not computed" - leave as is
            if transport[6] == 0 && transport[7] == 0 {
                return;
            }
            transport[6] = 0;
            transport[7] = 0;
            let mut cs = pseudo_header_checksum(src_ip, dst_ip, protocol, transport);
            if cs == 0 {
                cs = 0xFFFF; // RFC 768: transmitted as all ones
            }
            transport[6] = (cs >> 8) as u8;
            transport[7] = cs as u8;
        }
        // ICMP (protocol 1): checksum doesn't use pseudo-header, no fix needed
        _ => {}
    }
}

/// Recalculates TCP/UDP/ICMPv6 checksums for IPv6.
fn fix_transport_checksum_v6(
    transport: &mut [u8],
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    protocol: u8,
) {
    match protocol {
        6 => {
            // TCP
            if transport.len() < 20 {
                return;
            }
            transport[16] = 0;
            transport[17] = 0;
            let cs = pseudo_header_checksum_v6(src_ip, dst_ip, protocol, transport);
            transport[16] = (cs >> 8) as u8;
            transport[17] = cs as u8;
        }
        17 => {
            // UDP
            if transport.len() < 8 {
                return;
            }
            transport[6] = 0;
            transport[7] = 0;
            let mut cs = pseudo_header_checksum_v6(src_ip, dst_ip, protocol, transport);
            if cs == 0 {
                cs = 0xFFFF;
            }
            transport[6] = (cs >> 8) as u8;
            transport[7] = cs as u8;
        }
        58 => {
            // ICMPv6 (uses pseudo-header, unlike ICMPv4)
            if transport.len() < 8 {
                return;
            }
            transport[2] = 0;
            transport[3] = 0;
            let cs = pseudo_header_checksum_v6(src_ip, dst_ip, protocol, transport);
            transport[2] = (cs >> 8) as u8;
            transport[3] = cs as u8;
        }
        _ => {}
    }
}

/// Computes the TCP/UDP checksum including IPv4 pseudo-header.
fn pseudo_header_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], protocol: u8, data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src IP (4 bytes)
    sum += ((src_ip[0] as u32) << 8) | (src_ip[1] as u32);
    sum += ((src_ip[2] as u32) << 8) | (src_ip[3] as u32);
    // Pseudo-header: dst IP (4 bytes)
    sum += ((dst_ip[0] as u32) << 8) | (dst_ip[1] as u32);
    sum += ((dst_ip[2] as u32) << 8) | (dst_ip[3] as u32);
    // Pseudo-header: zero + protocol (2 bytes)
    sum += protocol as u32;
    // Pseudo-header: TCP/UDP length (2 bytes)
    sum += data.len() as u32;

    // Data
    sum = checksum_data(sum, data);

    checksum_fold(sum)
}

/// Computes the checksum including IPv6 pseudo-header.
fn pseudo_header_checksum_v6(
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    protocol: u8,
    data: &[u8],
) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src IP (16 bytes)
    for i in (0..16).step_by(2) {
        sum += ((src_ip[i] as u32) << 8) | (src_ip[i + 1] as u32);
    }
    // Pseudo-header: dst IP (16 bytes)
    for i in (0..16).step_by(2) {
        sum += ((dst_ip[i] as u32) << 8) | (dst_ip[i + 1] as u32);
    }
    // Pseudo-header: upper-layer length (4 bytes)
    sum += data.len() as u32;
    // Pseudo-header: zero + next header (4 bytes)
    sum += protocol as u32;

    // Data
    sum = checksum_data(sum, data);

    checksum_fold(sum)
}

/// Computes the IPv4 header checksum.
fn ip_checksum(header: &[u8]) -> u16 {
    let sum = checksum_data(0, header);
    checksum_fold(sum)
}

/// Adds data bytes to a running checksum sum.
fn checksum_data(mut sum: u32, data: &[u8]) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }
    sum
}

/// Folds a 32-bit sum into a 16-bit one's complement checksum.
fn checksum_fold(mut sum: u32) -> u16 {
    while sum > 0xFFFF {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !sum as u16
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_icmp() {
        // Minimal ICMP echo request
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // Version 4, IHL 5
        pkt[1] = 0x00;
        pkt[2] = 0x00;
        pkt[3] = 28;
        pkt[8] = 64; // TTL
        pkt[9] = 1; // ICMP
        pkt[12..16].copy_from_slice(&[100, 64, 0, 1]); // src
        pkt[16..20].copy_from_slice(&[100, 64, 0, 2]); // dst
        pkt[20] = 8; // ICMP echo request

        let info = parse_ip_packet(&pkt).unwrap();
        assert_eq!(info.version, 4);
        assert_eq!(info.protocol, 1);
        assert_eq!(info.src_ip, &[100, 64, 0, 1]);
        assert_eq!(info.dst_ip, &[100, 64, 0, 2]);
        assert_eq!(info.payload.len(), 8);
        assert_eq!(info.header_len, 20);
        assert_eq!(
            info.dst_ip_v4(),
            Some(Ipv4Addr::new(100, 64, 0, 2))
        );
    }

    #[test]
    fn test_parse_ipv6() {
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x60; // Version 6
        pkt[4] = 0;
        pkt[5] = 8; // Payload length = 8
        pkt[6] = 58; // ICMPv6
        pkt[7] = 64; // Hop limit
        // src: fd00::1
        pkt[8] = 0xfd;
        pkt[9] = 0x00;
        pkt[23] = 0x01;
        // dst: fd00::2
        pkt[24] = 0xfd;
        pkt[25] = 0x00;
        pkt[39] = 0x02;

        let info = parse_ip_packet(&pkt).unwrap();
        assert_eq!(info.version, 6);
        assert_eq!(info.protocol, 58);
        assert_eq!(info.src_ip.len(), 16);
        assert_eq!(info.payload.len(), 8);
    }

    #[test]
    fn test_parse_errors() {
        assert!(parse_ip_packet(&[]).is_err());
        assert!(parse_ip_packet(&[0x30]).is_err()); // version 3
        assert!(parse_ip_packet(&[0x45]).is_err()); // too short for IPv4
        assert!(parse_ip_packet(&[0x60]).is_err()); // too short for IPv6
    }

    #[test]
    fn test_build_ipv4_icmp() {
        let src = Ipv4Addr::new(100, 64, 0, 1);
        let dst = Ipv4Addr::new(100, 64, 0, 2);

        // ICMP echo payload (type=8, code=0, checksum, id, seq)
        let payload = vec![8, 0, 0, 0, 0, 1, 0, 1];

        let pkt = build_ipv4_packet(src, dst, 1, &payload).unwrap();
        assert_eq!(pkt.len(), 28);

        // Parse back
        let info = parse_ip_packet(&pkt).unwrap();
        assert_eq!(info.version, 4);
        assert_eq!(info.protocol, 1);
        assert_eq!(info.dst_ip_v4(), Some(dst));
        assert_eq!(info.src_ip_v4(), Some(src));
        assert_eq!(info.payload, &payload[..]);

        // Verify IP header checksum
        let cksum = ip_checksum(&pkt[..20]);
        assert_eq!(cksum, 0); // valid checksum should fold to 0 when verified
    }

    #[test]
    fn test_build_ipv4_tcp_checksum() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);

        // Minimal TCP header (20 bytes) with non-zero checksum
        let mut tcp = vec![0u8; 20];
        tcp[0] = 0x00; // src port high
        tcp[1] = 80; // src port low
        tcp[2] = 0xC0; // dst port high
        tcp[3] = 0x00; // dst port low
        tcp[12] = 0x50; // data offset 5 (20 bytes)
        tcp[13] = 0x02; // SYN flag
        // Set a dummy checksum to verify it gets recalculated
        tcp[16] = 0xFF;
        tcp[17] = 0xFF;

        let pkt = build_ipv4_packet(src, dst, 6, &tcp).unwrap();

        // The TCP checksum should have been recalculated
        assert!(pkt[36] != 0xFF || pkt[37] != 0xFF);
    }

    #[test]
    fn test_build_roundtrip() {
        let src = Ipv4Addr::new(100, 64, 0, 1);
        let dst = Ipv4Addr::new(100, 64, 0, 2);
        let payload = b"hello world";

        let pkt = build_ipv4_packet(src, dst, 1, payload).unwrap();
        let info = parse_ip_packet(&pkt).unwrap();

        assert_eq!(info.version, 4);
        assert_eq!(info.protocol, 1);
        assert_eq!(info.src_ip_v4(), Some(src));
        assert_eq!(info.dst_ip_v4(), Some(dst));
        assert_eq!(info.payload, payload);
    }

    #[test]
    fn test_build_too_large() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let payload = vec![0u8; 65536]; // too large
        assert!(build_ipv4_packet(src, dst, 1, &payload).is_err());
    }
}
