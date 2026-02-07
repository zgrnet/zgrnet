package host

import (
	"encoding/binary"
	"errors"
	"net"
)

// Errors for packet parsing.
var (
	ErrPacketTooShort = errors.New("host: packet too short")
	ErrPacketTooLarge = errors.New("host: packet too large")
	ErrInvalidVersion = errors.New("host: invalid IP version")
	ErrInvalidAddress = errors.New("host: invalid IP address")
)

// PacketInfo contains parsed information from an IP packet.
type PacketInfo struct {
	Version   byte   // 4 or 6
	Protocol  byte   // IP protocol number (1=ICMP, 6=TCP, 17=UDP)
	SrcIP     net.IP // source IP address
	DstIP     net.IP // destination IP address
	Payload   []byte // transport layer payload (after IP header)
	HeaderLen int    // IP header length in bytes
}

// ParseIPPacket parses an IP packet and extracts header info.
// Handles both IPv4 and IPv6 based on the version nibble.
func ParseIPPacket(pkt []byte) (*PacketInfo, error) {
	if len(pkt) < 1 {
		return nil, ErrPacketTooShort
	}

	version := pkt[0] >> 4
	switch version {
	case 4:
		return parseIPv4(pkt)
	case 6:
		return parseIPv6(pkt)
	default:
		return nil, ErrInvalidVersion
	}
}

// parseIPv4 parses an IPv4 packet header.
func parseIPv4(pkt []byte) (*PacketInfo, error) {
	if len(pkt) < 20 {
		return nil, ErrPacketTooShort
	}

	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return nil, ErrPacketTooShort
	}

	// Copy IP addresses to avoid referencing the original buffer
	srcIP := make(net.IP, 4)
	dstIP := make(net.IP, 4)
	copy(srcIP, pkt[12:16])
	copy(dstIP, pkt[16:20])

	return &PacketInfo{
		Version:   4,
		Protocol:  pkt[9],
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Payload:   pkt[ihl:],
		HeaderLen: ihl,
	}, nil
}

// parseIPv6 parses an IPv6 packet header.
func parseIPv6(pkt []byte) (*PacketInfo, error) {
	if len(pkt) < 40 {
		return nil, ErrPacketTooShort
	}

	// Copy IP addresses to avoid referencing the original buffer
	srcIP := make(net.IP, 16)
	dstIP := make(net.IP, 16)
	copy(srcIP, pkt[8:24])
	copy(dstIP, pkt[24:40])

	return &PacketInfo{
		Version:   6,
		Protocol:  pkt[6], // Next Header
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Payload:   pkt[40:],
		HeaderLen: 40,
	}, nil
}

// BuildIPv4Packet creates an IPv4 packet from components.
// Constructs a minimal 20-byte IPv4 header and appends the transport payload.
// Recalculates both IP header checksum and transport checksums (TCP/UDP).
func BuildIPv4Packet(srcIP, dstIP net.IP, protocol byte, payload []byte) ([]byte, error) {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return nil, ErrInvalidAddress
	}

	const headerLen = 20
	totalLen := headerLen + len(payload)
	if totalLen > 65535 {
		return nil, ErrPacketTooLarge
	}

	pkt := make([]byte, totalLen)

	// IPv4 header
	pkt[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	pkt[1] = 0x00 // DSCP / ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	// Identification (pkt[4:6]) = 0
	pkt[6] = 0x40 // Don't Fragment flag
	pkt[7] = 0x00 // Fragment offset
	pkt[8] = 64   // TTL
	pkt[9] = protocol
	// Header checksum (pkt[10:12]) = 0, computed below
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)

	// Compute IP header checksum
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:headerLen]))

	// Copy transport payload
	copy(pkt[headerLen:], payload)

	// Fix transport layer checksum (TCP/UDP use pseudo-header with IPs)
	fixTransportChecksum(pkt[headerLen:], src4, dst4, protocol)

	return pkt, nil
}

// BuildIPv6Packet creates an IPv6 packet from components.
func BuildIPv6Packet(srcIP, dstIP net.IP, protocol byte, payload []byte) ([]byte, error) {
	src16 := srcIP.To16()
	dst16 := dstIP.To16()
	if src16 == nil || dst16 == nil {
		return nil, ErrInvalidAddress
	}

	const headerLen = 40
	payloadLen := len(payload)
	if payloadLen > 65535 {
		return nil, ErrPacketTooLarge
	}

	pkt := make([]byte, headerLen+payloadLen)

	// IPv6 header
	pkt[0] = 0x60 // Version 6
	// Traffic class and flow label (pkt[1:4]) = 0
	binary.BigEndian.PutUint16(pkt[4:6], uint16(payloadLen))
	pkt[6] = protocol // Next Header
	pkt[7] = 64       // Hop Limit
	copy(pkt[8:24], src16)
	copy(pkt[24:40], dst16)

	// Copy transport payload
	copy(pkt[headerLen:], payload)

	// Fix transport layer checksum (TCP/UDP/ICMPv6 use pseudo-header)
	fixTransportChecksumV6(pkt[headerLen:], src16, dst16, protocol, payloadLen)

	return pkt, nil
}

// fixTransportChecksum recalculates TCP/UDP checksums for IPv4.
// The checksum includes a pseudo-header with source/destination IPs,
// so it must be recalculated when IP addresses change.
func fixTransportChecksum(transport []byte, srcIP, dstIP net.IP, protocol byte) {
	switch protocol {
	case 6: // TCP
		if len(transport) < 20 {
			return
		}
		// Zero out existing checksum
		transport[16] = 0
		transport[17] = 0
		cs := pseudoHeaderChecksum(srcIP, dstIP, protocol, transport)
		binary.BigEndian.PutUint16(transport[16:18], cs)

	case 17: // UDP
		if len(transport) < 8 {
			return
		}
		// In IPv4, UDP checksum 0 means "not computed" - leave as is
		if transport[6] == 0 && transport[7] == 0 {
			return
		}
		transport[6] = 0
		transport[7] = 0
		cs := pseudoHeaderChecksum(srcIP, dstIP, protocol, transport)
		if cs == 0 {
			cs = 0xFFFF // RFC 768: transmitted as all ones
		}
		binary.BigEndian.PutUint16(transport[6:8], cs)

	// ICMP (protocol 1): checksum doesn't use pseudo-header, no fix needed
	}
}

// fixTransportChecksumV6 recalculates TCP/UDP/ICMPv6 checksums for IPv6.
func fixTransportChecksumV6(transport []byte, srcIP, dstIP net.IP, protocol byte, payloadLen int) {
	switch protocol {
	case 6: // TCP
		if len(transport) < 20 {
			return
		}
		transport[16] = 0
		transport[17] = 0
		cs := pseudoHeaderChecksumV6(srcIP, dstIP, protocol, transport)
		binary.BigEndian.PutUint16(transport[16:18], cs)

	case 17: // UDP
		if len(transport) < 8 {
			return
		}
		transport[6] = 0
		transport[7] = 0
		cs := pseudoHeaderChecksumV6(srcIP, dstIP, protocol, transport)
		if cs == 0 {
			cs = 0xFFFF
		}
		binary.BigEndian.PutUint16(transport[6:8], cs)

	case 58: // ICMPv6 (uses pseudo-header, unlike ICMPv4)
		if len(transport) < 8 {
			return
		}
		transport[2] = 0
		transport[3] = 0
		cs := pseudoHeaderChecksumV6(srcIP, dstIP, protocol, transport)
		binary.BigEndian.PutUint16(transport[2:4], cs)
	}
}

// pseudoHeaderChecksum computes the TCP/UDP checksum including IPv4 pseudo-header.
func pseudoHeaderChecksum(srcIP, dstIP net.IP, protocol byte, data []byte) uint16 {
	var sum uint32

	src4 := srcIP.To4()
	dst4 := dstIP.To4()

	// Pseudo-header: src IP (4 bytes)
	sum += uint32(src4[0])<<8 | uint32(src4[1])
	sum += uint32(src4[2])<<8 | uint32(src4[3])
	// Pseudo-header: dst IP (4 bytes)
	sum += uint32(dst4[0])<<8 | uint32(dst4[1])
	sum += uint32(dst4[2])<<8 | uint32(dst4[3])
	// Pseudo-header: zero + protocol (2 bytes)
	sum += uint32(protocol)
	// Pseudo-header: TCP/UDP length (2 bytes)
	sum += uint32(len(data))

	// Data
	sum = checksumData(sum, data)

	return checksumFold(sum)
}

// pseudoHeaderChecksumV6 computes the checksum including IPv6 pseudo-header.
func pseudoHeaderChecksumV6(srcIP, dstIP net.IP, protocol byte, data []byte) uint16 {
	var sum uint32

	// Pseudo-header: src IP (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
	}
	// Pseudo-header: dst IP (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
	}
	// Pseudo-header: upper-layer length (4 bytes, big-endian)
	sum += uint32(len(data))
	// Pseudo-header: zero + next header (4 bytes)
	sum += uint32(protocol)

	// Data
	sum = checksumData(sum, data)

	return checksumFold(sum)
}

// ipChecksum computes the IPv4 header checksum.
func ipChecksum(header []byte) uint16 {
	var sum uint32
	sum = checksumData(sum, header)
	return checksumFold(sum)
}

// checksumData adds data bytes to a running checksum sum.
func checksumData(sum uint32, data []byte) uint32 {
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

// checksumFold folds a 32-bit sum into a 16-bit one's complement checksum.
func checksumFold(sum uint32) uint16 {
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}
