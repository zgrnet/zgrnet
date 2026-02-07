package host

import (
	"encoding/binary"
	"net"
	"testing"
)

// makeTestIPv4Packet creates a minimal IPv4 packet with the given parameters.
func makeTestIPv4Packet(srcIP, dstIP net.IP, protocol byte, payload []byte) []byte {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	headerLen := 20
	totalLen := headerLen + len(payload)

	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64       // TTL
	pkt[9] = protocol // Protocol
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)

	// Compute header checksum
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:headerLen]))

	copy(pkt[headerLen:], payload)
	return pkt
}

// makeTestIPv6Packet creates a minimal IPv6 packet with the given parameters.
func makeTestIPv6Packet(srcIP, dstIP net.IP, nextHeader byte, payload []byte) []byte {
	src16 := srcIP.To16()
	dst16 := dstIP.To16()

	pkt := make([]byte, 40+len(payload))
	pkt[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload)))
	pkt[6] = nextHeader // Next Header
	pkt[7] = 64         // Hop Limit
	copy(pkt[8:24], src16)
	copy(pkt[24:40], dst16)
	copy(pkt[40:], payload)
	return pkt
}

func TestParseIPv4(t *testing.T) {
	srcIP := net.IPv4(10, 0, 0, 1)
	dstIP := net.IPv4(10, 0, 0, 2)
	payload := []byte("hello")

	pkt := makeTestIPv4Packet(srcIP, dstIP, 6, payload) // TCP

	info, err := ParseIPPacket(pkt)
	if err != nil {
		t.Fatalf("ParseIPPacket failed: %v", err)
	}

	if info.Version != 4 {
		t.Errorf("Version = %d, want 4", info.Version)
	}
	if info.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6", info.Protocol)
	}
	if !info.SrcIP.Equal(srcIP) {
		t.Errorf("SrcIP = %s, want %s", info.SrcIP, srcIP)
	}
	if !info.DstIP.Equal(dstIP) {
		t.Errorf("DstIP = %s, want %s", info.DstIP, dstIP)
	}
	if string(info.Payload) != "hello" {
		t.Errorf("Payload = %q, want %q", info.Payload, "hello")
	}
	if info.HeaderLen != 20 {
		t.Errorf("HeaderLen = %d, want 20", info.HeaderLen)
	}
}

func TestParseIPv6(t *testing.T) {
	srcIP := net.ParseIP("fd00::1")
	dstIP := net.ParseIP("fd00::2")
	payload := []byte("world")

	pkt := makeTestIPv6Packet(srcIP, dstIP, 17, payload) // UDP

	info, err := ParseIPPacket(pkt)
	if err != nil {
		t.Fatalf("ParseIPPacket failed: %v", err)
	}

	if info.Version != 6 {
		t.Errorf("Version = %d, want 6", info.Version)
	}
	if info.Protocol != 17 {
		t.Errorf("Protocol = %d, want 17", info.Protocol)
	}
	if !info.SrcIP.Equal(srcIP) {
		t.Errorf("SrcIP = %s, want %s", info.SrcIP, srcIP)
	}
	if !info.DstIP.Equal(dstIP) {
		t.Errorf("DstIP = %s, want %s", info.DstIP, dstIP)
	}
	if string(info.Payload) != "world" {
		t.Errorf("Payload = %q, want %q", info.Payload, "world")
	}
	if info.HeaderLen != 40 {
		t.Errorf("HeaderLen = %d, want 40", info.HeaderLen)
	}
}

func TestParseIPPacket_Errors(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
	}{
		{"empty", nil},
		{"too short", []byte{0x45}},
		{"ipv4 too short", make([]byte, 10)},
		{"bad version", []byte{0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseIPPacket(tt.pkt)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestBuildIPv4Packet(t *testing.T) {
	srcIP := net.IPv4(100, 64, 0, 2)
	dstIP := net.IPv4(100, 64, 0, 1)
	payload := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01} // ICMP echo

	pkt, err := BuildIPv4Packet(srcIP, dstIP, 1, payload)
	if err != nil {
		t.Fatalf("BuildIPv4Packet failed: %v", err)
	}

	// Verify we can parse back what we built
	info, err := ParseIPPacket(pkt)
	if err != nil {
		t.Fatalf("ParseIPPacket failed: %v", err)
	}

	if info.Version != 4 {
		t.Errorf("Version = %d, want 4", info.Version)
	}
	if info.Protocol != 1 {
		t.Errorf("Protocol = %d, want 1 (ICMP)", info.Protocol)
	}
	if !info.SrcIP.Equal(srcIP) {
		t.Errorf("SrcIP = %s, want %s", info.SrcIP, srcIP)
	}
	if !info.DstIP.Equal(dstIP) {
		t.Errorf("DstIP = %s, want %s", info.DstIP, dstIP)
	}
	if len(info.Payload) != len(payload) {
		t.Errorf("Payload len = %d, want %d", len(info.Payload), len(payload))
	}

	// Verify IP header checksum is valid
	if ipChecksum(pkt[:20]) != 0 {
		t.Error("IP header checksum invalid")
	}

	// Verify TTL
	if pkt[8] != 64 {
		t.Errorf("TTL = %d, want 64", pkt[8])
	}

	// Verify Don't Fragment flag
	if pkt[6] != 0x40 {
		t.Errorf("Flags = 0x%02x, want 0x40 (DF)", pkt[6])
	}
}

func TestBuildIPv4Packet_TCPChecksum(t *testing.T) {
	srcIP := net.IPv4(100, 64, 0, 2)
	dstIP := net.IPv4(100, 64, 0, 1)

	// Minimal TCP header (20 bytes) with data
	tcpPayload := make([]byte, 24)
	binary.BigEndian.PutUint16(tcpPayload[0:2], 12345)  // src port
	binary.BigEndian.PutUint16(tcpPayload[2:4], 80)      // dst port
	binary.BigEndian.PutUint32(tcpPayload[4:8], 1)       // seq
	binary.BigEndian.PutUint32(tcpPayload[8:12], 0)      // ack
	tcpPayload[12] = 0x50                                 // data offset = 5 (20 bytes)
	tcpPayload[13] = 0x02                                 // SYN flag
	binary.BigEndian.PutUint16(tcpPayload[14:16], 65535)  // window
	// checksum at [16:18] = 0 (will be set by BuildIPv4Packet)
	copy(tcpPayload[20:24], []byte("test"))

	pkt, err := BuildIPv4Packet(srcIP, dstIP, 6, tcpPayload)
	if err != nil {
		t.Fatalf("BuildIPv4Packet failed: %v", err)
	}

	// Verify TCP checksum: parse and verify checksum manually
	info, _ := ParseIPPacket(pkt)
	tcpData := info.Payload

	// Compute expected checksum
	cs := pseudoHeaderChecksum(srcIP.To4(), dstIP.To4(), 6, tcpData)
	// If the checksum is correct, computing over the data WITH the checksum should yield 0
	if cs != 0 {
		// Actually, the checksum field is already included in tcpData,
		// so re-computing should give 0 if correct
		var sum uint32
		sum += uint32(srcIP.To4()[0])<<8 | uint32(srcIP.To4()[1])
		sum += uint32(srcIP.To4()[2])<<8 | uint32(srcIP.To4()[3])
		sum += uint32(dstIP.To4()[0])<<8 | uint32(dstIP.To4()[1])
		sum += uint32(dstIP.To4()[2])<<8 | uint32(dstIP.To4()[3])
		sum += uint32(6) // protocol
		sum += uint32(len(tcpData))
		sum = checksumData(sum, tcpData)
		result := checksumFold(sum)
		if result != 0 {
			t.Errorf("TCP checksum verification failed: got 0x%04x, want 0", result)
		}
	}
}

func TestBuildIPv4Packet_UDPChecksum(t *testing.T) {
	srcIP := net.IPv4(100, 64, 0, 2)
	dstIP := net.IPv4(100, 64, 0, 1)

	// UDP header (8 bytes) with data
	udpPayload := make([]byte, 12)
	binary.BigEndian.PutUint16(udpPayload[0:2], 5000)  // src port
	binary.BigEndian.PutUint16(udpPayload[2:4], 53)     // dst port
	binary.BigEndian.PutUint16(udpPayload[4:6], 12)     // length
	// Set non-zero checksum to trigger recalculation
	udpPayload[6] = 0xFF
	udpPayload[7] = 0xFF
	copy(udpPayload[8:12], []byte("dns!"))

	pkt, err := BuildIPv4Packet(srcIP, dstIP, 17, udpPayload)
	if err != nil {
		t.Fatalf("BuildIPv4Packet failed: %v", err)
	}

	// Verify UDP checksum
	info, _ := ParseIPPacket(pkt)
	udpData := info.Payload

	var sum uint32
	sum += uint32(srcIP.To4()[0])<<8 | uint32(srcIP.To4()[1])
	sum += uint32(srcIP.To4()[2])<<8 | uint32(srcIP.To4()[3])
	sum += uint32(dstIP.To4()[0])<<8 | uint32(dstIP.To4()[1])
	sum += uint32(dstIP.To4()[2])<<8 | uint32(dstIP.To4()[3])
	sum += uint32(17) // protocol
	sum += uint32(len(udpData))
	sum = checksumData(sum, udpData)
	result := checksumFold(sum)
	if result != 0 {
		t.Errorf("UDP checksum verification failed: got 0x%04x, want 0", result)
	}
}

func TestBuildIPv4Packet_UDPZeroChecksum(t *testing.T) {
	srcIP := net.IPv4(100, 64, 0, 2)
	dstIP := net.IPv4(100, 64, 0, 1)

	// UDP header with zero checksum (means "not computed" in IPv4)
	udpPayload := make([]byte, 12)
	binary.BigEndian.PutUint16(udpPayload[0:2], 5000)
	binary.BigEndian.PutUint16(udpPayload[2:4], 53)
	binary.BigEndian.PutUint16(udpPayload[4:6], 12)
	// checksum = 0 (not computed)
	udpPayload[6] = 0
	udpPayload[7] = 0
	copy(udpPayload[8:12], []byte("dns!"))

	pkt, err := BuildIPv4Packet(srcIP, dstIP, 17, udpPayload)
	if err != nil {
		t.Fatalf("BuildIPv4Packet failed: %v", err)
	}

	// Verify UDP checksum is still 0
	info, _ := ParseIPPacket(pkt)
	udpData := info.Payload
	cs := binary.BigEndian.Uint16(udpData[6:8])
	if cs != 0 {
		t.Errorf("UDP checksum should stay 0 when original is 0, got 0x%04x", cs)
	}
}

func TestBuildIPv6Packet(t *testing.T) {
	srcIP := net.ParseIP("fd00::2")
	dstIP := net.ParseIP("fd00::1")
	payload := []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01} // ICMPv6 echo

	pkt, err := BuildIPv6Packet(srcIP, dstIP, 58, payload)
	if err != nil {
		t.Fatalf("BuildIPv6Packet failed: %v", err)
	}

	info, err := ParseIPPacket(pkt)
	if err != nil {
		t.Fatalf("ParseIPPacket failed: %v", err)
	}

	if info.Version != 6 {
		t.Errorf("Version = %d, want 6", info.Version)
	}
	if info.Protocol != 58 {
		t.Errorf("Protocol = %d, want 58 (ICMPv6)", info.Protocol)
	}
	if !info.SrcIP.Equal(srcIP) {
		t.Errorf("SrcIP = %s, want %s", info.SrcIP, srcIP)
	}
	if !info.DstIP.Equal(dstIP) {
		t.Errorf("DstIP = %s, want %s", info.DstIP, dstIP)
	}
}

func TestBuildIPv4Packet_Errors(t *testing.T) {
	// Invalid src IP
	_, err := BuildIPv4Packet(net.ParseIP("::1"), net.IPv4(10, 0, 0, 1), 1, nil)
	if err == nil {
		t.Error("expected error for IPv6 src")
	}

	// Invalid dst IP
	_, err = BuildIPv4Packet(net.IPv4(10, 0, 0, 1), nil, 1, nil)
	if err == nil {
		t.Error("expected error for nil dst")
	}
}

func TestRoundtrip_ParseBuild(t *testing.T) {
	// Build a packet, parse it, and verify all fields match
	srcIP := net.IPv4(100, 64, 0, 5)
	dstIP := net.IPv4(100, 64, 0, 1)
	icmpData := []byte{
		0x08, 0x00, // Type: Echo Request, Code: 0
		0x00, 0x00, // Checksum (placeholder)
		0x00, 0x01, // Identifier
		0x00, 0x01, // Sequence
		'p', 'i', 'n', 'g', // Data
	}
	// Compute ICMP checksum
	cs := ipChecksum(icmpData)
	binary.BigEndian.PutUint16(icmpData[2:4], cs)

	pkt, err := BuildIPv4Packet(srcIP, dstIP, 1, icmpData)
	if err != nil {
		t.Fatalf("BuildIPv4Packet failed: %v", err)
	}

	info, err := ParseIPPacket(pkt)
	if err != nil {
		t.Fatalf("ParseIPPacket failed: %v", err)
	}

	if info.Version != 4 {
		t.Errorf("Version = %d, want 4", info.Version)
	}
	if info.Protocol != 1 {
		t.Errorf("Protocol = %d, want 1", info.Protocol)
	}
	if !info.SrcIP.Equal(srcIP) {
		t.Errorf("SrcIP = %s, want %s", info.SrcIP, srcIP)
	}
	if !info.DstIP.Equal(dstIP) {
		t.Errorf("DstIP = %s, want %s", info.DstIP, dstIP)
	}
	if len(info.Payload) != len(icmpData) {
		t.Errorf("Payload len = %d, want %d", len(info.Payload), len(icmpData))
	}

	// Verify ICMP checksum is preserved (ICMP doesn't use pseudo-header)
	if info.Payload[2] != icmpData[2] || info.Payload[3] != icmpData[3] {
		t.Error("ICMP checksum was modified (should be preserved)")
	}
}
