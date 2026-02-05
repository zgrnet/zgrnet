package tun

import (
	"net"
	"os"
	"runtime"
	"testing"
)

func needsRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 && runtime.GOOS != "windows" {
		t.Skip("test requires root privileges")
	}
}

func TestCreateClose(t *testing.T) {
	needsRoot(t)

	dev, err := Create("")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	name := dev.Name()
	if name == "" {
		t.Error("device name is empty")
	}
	t.Logf("Created TUN device: %s", name)

	// First close should succeed
	err = dev.Close()
	if err != nil {
		t.Errorf("First close failed: %v", err)
	}

	// Second close should return ErrAlreadyClosed
	err = dev.Close()
	if err != ErrAlreadyClosed {
		t.Errorf("Second close returned: %v (expected %v)", err, ErrAlreadyClosed)
	}
}

func TestHandle(t *testing.T) {
	needsRoot(t)

	dev, err := Create("")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer dev.Close()

	handle := dev.Handle()
	if handle < 0 {
		t.Errorf("invalid handle: %d", handle)
	}
	t.Logf("TUN handle: %d", handle)
}

func TestMTU(t *testing.T) {
	needsRoot(t)

	dev, err := Create("")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer dev.Close()

	mtu, err := dev.MTU()
	if err != nil {
		t.Errorf("MTU failed: %v", err)
	}
	t.Logf("Default MTU: %d", mtu)

	// MTU should be reasonable (typically 1500 or higher)
	if mtu < 576 || mtu > 65535 {
		t.Errorf("unexpected MTU: %d", mtu)
	}
}

func TestSetNonblocking(t *testing.T) {
	needsRoot(t)

	dev, err := Create("")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer dev.Close()

	// Enable non-blocking
	err = dev.SetNonblocking(true)
	if err != nil {
		t.Errorf("SetNonblocking(true) failed: %v", err)
	}

	// Disable non-blocking
	err = dev.SetNonblocking(false)
	if err != nil {
		t.Errorf("SetNonblocking(false) failed: %v", err)
	}
}

func TestSetIPv4(t *testing.T) {
	needsRoot(t)

	dev, err := Create("")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer dev.Close()

	ip := net.IPv4(10, 0, 100, 1)
	mask := net.IPv4Mask(255, 255, 255, 0)

	err = dev.SetIPv4(ip, mask)
	if err != nil {
		t.Errorf("SetIPv4 failed: %v", err)
	}
	t.Logf("TUN %s configured with IP %s/%s", dev.Name(), ip, mask)
}

func TestSetIPv6(t *testing.T) {
	needsRoot(t)

	dev, err := Create("")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer dev.Close()

	ip := net.ParseIP("fd00::1")
	if ip == nil {
		t.Fatal("failed to parse IPv6 address")
	}

	err = dev.SetIPv6(ip, 64)
	if err != nil {
		t.Errorf("SetIPv6 failed: %v", err)
	}
	t.Logf("TUN %s configured with IPv6 %s/64", dev.Name(), ip)
}

func TestUpDown(t *testing.T) {
	needsRoot(t)

	dev, err := Create("")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer dev.Close()

	// Set IP first (required before bringing up on some systems)
	ip := net.IPv4(10, 0, 101, 1)
	mask := net.IPv4Mask(255, 255, 255, 0)
	_ = dev.SetIPv4(ip, mask)

	// Bring up
	err = dev.Up()
	if err != nil {
		t.Errorf("Up failed: %v", err)
	}

	// Bring down
	err = dev.Down()
	if err != nil {
		t.Errorf("Down failed: %v", err)
	}
}

func TestReadWriteWithTwoDevices(t *testing.T) {
	needsRoot(t)

	// Create two TUN devices
	dev1, err := Create("")
	if err != nil {
		t.Fatalf("Create dev1 failed: %v", err)
	}
	defer dev1.Close()

	dev2, err := Create("")
	if err != nil {
		t.Fatalf("Create dev2 failed: %v", err)
	}
	defer dev2.Close()

	t.Logf("Created TUN devices: %s and %s", dev1.Name(), dev2.Name())

	// Configure dev1: 10.0.50.1/24
	ip1 := net.IPv4(10, 0, 50, 1)
	mask := net.IPv4Mask(255, 255, 255, 0)
	if err := dev1.SetIPv4(ip1, mask); err != nil {
		t.Fatalf("SetIPv4 dev1 failed: %v", err)
	}

	// Configure dev2: 10.0.51.1/24
	ip2 := net.IPv4(10, 0, 51, 1)
	if err := dev2.SetIPv4(ip2, mask); err != nil {
		t.Fatalf("SetIPv4 dev2 failed: %v", err)
	}

	// Set both to non-blocking mode for the read test
	if err := dev1.SetNonblocking(true); err != nil {
		t.Fatalf("SetNonblocking dev1 failed: %v", err)
	}
	if err := dev2.SetNonblocking(true); err != nil {
		t.Fatalf("SetNonblocking dev2 failed: %v", err)
	}

	// Create a simple ICMP echo request packet
	// This is a minimal test - in practice routing would need to be configured
	icmpPacket := makeICMPEchoRequest(ip1, ip2)
	t.Logf("Created %d byte ICMP packet", len(icmpPacket))

	// Write to dev1
	n, err := dev1.Write(icmpPacket)
	if err != nil {
		t.Logf("Write failed (expected without routing): %v", err)
	} else {
		t.Logf("Wrote %d bytes to %s", n, dev1.Name())
	}

	// Try to read from dev1 (non-blocking)
	buf := make([]byte, 1500)
	n, err = dev1.Read(buf)
	if err == ErrWouldBlock {
		t.Log("No packet received (routing may not be configured)")
	} else if err != nil {
		t.Logf("Read error: %v", err)
	} else {
		t.Logf("Read %d bytes from %s", n, dev1.Name())
	}
}

func TestReadWriteIPv6(t *testing.T) {
	needsRoot(t)

	// Create two TUN devices
	dev1, err := Create("")
	if err != nil {
		t.Fatalf("Create dev1 failed: %v", err)
	}
	defer dev1.Close()

	dev2, err := Create("")
	if err != nil {
		t.Fatalf("Create dev2 failed: %v", err)
	}
	defer dev2.Close()

	t.Logf("Created TUN devices: %s and %s", dev1.Name(), dev2.Name())

	// Configure dev1: fd00::1/64
	ip1 := net.ParseIP("fd00::1")
	if err := dev1.SetIPv6(ip1, 64); err != nil {
		t.Fatalf("SetIPv6 dev1 failed: %v", err)
	}

	// Configure dev2: fd00:0:0:1::1/64
	ip2 := net.ParseIP("fd00:0:0:1::1")
	if err := dev2.SetIPv6(ip2, 64); err != nil {
		t.Fatalf("SetIPv6 dev2 failed: %v", err)
	}

	// Set both to non-blocking mode for the read test
	if err := dev1.SetNonblocking(true); err != nil {
		t.Fatalf("SetNonblocking dev1 failed: %v", err)
	}
	if err := dev2.SetNonblocking(true); err != nil {
		t.Fatalf("SetNonblocking dev2 failed: %v", err)
	}

	// Create a simple ICMPv6 echo request packet
	icmpv6Packet := makeICMPv6EchoRequest(ip1, ip2)
	t.Logf("Created %d byte ICMPv6 packet", len(icmpv6Packet))

	// Write to dev1
	n, err := dev1.Write(icmpv6Packet)
	if err != nil {
		t.Logf("Write failed (expected without routing): %v", err)
	} else {
		t.Logf("Wrote %d bytes to %s", n, dev1.Name())
	}

	// Try to read from dev1 (non-blocking)
	buf := make([]byte, 1500)
	n, err = dev1.Read(buf)
	if err == ErrWouldBlock {
		t.Log("No packet received (routing may not be configured)")
	} else if err != nil {
		t.Logf("Read error: %v", err)
	} else {
		t.Logf("Read %d bytes from %s", n, dev1.Name())
	}
}

// makeICMPv6EchoRequest creates a simple ICMPv6 echo request packet
func makeICMPv6EchoRequest(src, dst net.IP) []byte {
	src16 := src.To16()
	dst16 := dst.To16()
	if src16 == nil || dst16 == nil {
		return nil
	}

	// IPv6 header (40 bytes) + ICMPv6 header (8 bytes) = 48 bytes
	packet := make([]byte, 48)

	// IPv6 header
	packet[0] = 0x60           // Version 6
	packet[1] = 0x00           // Traffic class
	packet[2] = 0x00           // Flow label
	packet[3] = 0x00           // Flow label
	packet[4] = 0x00           // Payload length high byte
	packet[5] = 8              // Payload length low byte (ICMPv6 = 8 bytes)
	packet[6] = 58             // Next header: ICMPv6
	packet[7] = 64             // Hop limit
	copy(packet[8:24], src16)  // Source IPv6
	copy(packet[24:40], dst16) // Dest IPv6

	// ICMPv6 Echo Request header
	packet[40] = 128 // Type: Echo Request
	packet[41] = 0   // Code
	packet[42] = 0   // Checksum (will calculate)
	packet[43] = 0   // Checksum
	packet[44] = 0   // Identifier high
	packet[45] = 1   // Identifier low
	packet[46] = 0   // Sequence high
	packet[47] = 1   // Sequence low

	// Calculate ICMPv6 checksum (includes pseudo-header)
	icmpv6Checksum := calculateICMPv6Checksum(src16, dst16, packet[40:])
	packet[42] = byte(icmpv6Checksum >> 8)
	packet[43] = byte(icmpv6Checksum)

	return packet
}

// calculateICMPv6Checksum calculates ICMPv6 checksum including pseudo-header
func calculateICMPv6Checksum(src, dst net.IP, icmpData []byte) uint16 {
	var sum uint32

	// Pseudo-header: source address
	for i := 0; i < 16; i += 2 {
		sum += uint32(src[i])<<8 | uint32(src[i+1])
	}
	// Pseudo-header: destination address
	for i := 0; i < 16; i += 2 {
		sum += uint32(dst[i])<<8 | uint32(dst[i+1])
	}
	// Pseudo-header: ICMPv6 length
	sum += uint32(len(icmpData))
	// Pseudo-header: Next header (ICMPv6 = 58)
	sum += 58

	// ICMPv6 data
	for i := 0; i < len(icmpData)-1; i += 2 {
		sum += uint32(icmpData[i])<<8 | uint32(icmpData[i+1])
	}
	if len(icmpData)%2 == 1 {
		sum += uint32(icmpData[len(icmpData)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// makeICMPEchoRequest creates a simple ICMP echo request packet
func makeICMPEchoRequest(src, dst net.IP) []byte {
	src4 := src.To4()
	dst4 := dst.To4()
	if src4 == nil || dst4 == nil {
		return nil
	}

	// IP header (20 bytes) + ICMP header (8 bytes) = 28 bytes
	packet := make([]byte, 28)

	// IP header
	packet[0] = 0x45          // Version 4, IHL 5
	packet[1] = 0x00          // TOS
	packet[2] = 0x00          // Total length high byte
	packet[3] = 28            // Total length low byte
	packet[4] = 0x00          // ID high
	packet[5] = 0x01          // ID low
	packet[6] = 0x00          // Flags and fragment offset
	packet[7] = 0x00          // Fragment offset
	packet[8] = 64            // TTL
	packet[9] = 1             // Protocol (ICMP)
	packet[10] = 0x00         // Checksum (will calculate)
	packet[11] = 0x00         // Checksum
	copy(packet[12:16], src4) // Source IP
	copy(packet[16:20], dst4) // Dest IP

	// Calculate IP header checksum
	ipChecksum := calculateChecksum(packet[:20])
	packet[10] = byte(ipChecksum >> 8)
	packet[11] = byte(ipChecksum)

	// ICMP header
	packet[20] = 8 // Type: Echo request
	packet[21] = 0 // Code
	packet[22] = 0 // Checksum (will calculate)
	packet[23] = 0 // Checksum
	packet[24] = 0 // ID high
	packet[25] = 1 // ID low
	packet[26] = 0 // Sequence high
	packet[27] = 1 // Sequence low

	// Calculate ICMP checksum
	icmpChecksum := calculateChecksum(packet[20:])
	packet[22] = byte(icmpChecksum >> 8)
	packet[23] = byte(icmpChecksum)

	return packet
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

func TestCodeToErrorMapping(t *testing.T) {
	// Test that error codes map to correct Go errors
	err := codeToError(-8)
	if err != ErrInvalidArgument {
		t.Errorf("expected ErrInvalidArgument, got %v", err)
	}
}
