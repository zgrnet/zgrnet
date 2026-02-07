package host

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// mockTUN simulates a TUN device using channels.
type mockTUN struct {
	readCh  chan []byte    // packets to be "read" by the host (injected by test)
	writeCh chan []byte    // packets "written" by the host (captured by test)
	closeCh chan struct{}
	closed  atomic.Bool
}

func newMockTUN() *mockTUN {
	return &mockTUN{
		readCh:  make(chan []byte, 256),
		writeCh: make(chan []byte, 256),
		closeCh: make(chan struct{}),
	}
}

func (m *mockTUN) Read(buf []byte) (int, error) {
	select {
	case pkt := <-m.readCh:
		n := copy(buf, pkt)
		return n, nil
	case <-m.closeCh:
		return 0, io.ErrClosedPipe
	}
}

func (m *mockTUN) Write(buf []byte) (int, error) {
	if m.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	pkt := make([]byte, len(buf))
	copy(pkt, buf)
	select {
	case m.writeCh <- pkt:
		return len(buf), nil
	case <-m.closeCh:
		return 0, io.ErrClosedPipe
	}
}

func (m *mockTUN) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	close(m.closeCh)
	return nil
}

// inject sends a packet into the mock TUN's read side (simulating app traffic).
func (m *mockTUN) inject(pkt []byte) {
	m.readCh <- pkt
}

// receive waits for a packet on the mock TUN's write side (capturing host output).
func (m *mockTUN) receive(timeout time.Duration) ([]byte, bool) {
	select {
	case pkt := <-m.writeCh:
		return pkt, true
	case <-time.After(timeout):
		return nil, false
	}
}

func TestHost_New(t *testing.T) {
	key, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	tun := newMockTUN()
	h, err := New(Config{
		PrivateKey: key,
		TunIPv4:    net.IPv4(100, 64, 0, 1),
		MTU:        1400,
	}, tun)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer h.Close()

	if h.PublicKey() != key.Public {
		t.Error("PublicKey mismatch")
	}

	addr := h.LocalAddr()
	if addr == nil {
		t.Error("LocalAddr is nil")
	}
	t.Logf("Host listening on %s", addr)
}

func TestHost_New_MissingKey(t *testing.T) {
	_, err := New(Config{
		TunIPv4: net.IPv4(100, 64, 0, 1),
	}, newMockTUN())
	if err == nil {
		t.Error("expected error for missing private key")
	}
}

func TestHost_New_MissingTunIP(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	_, err := New(Config{
		PrivateKey: key,
	}, newMockTUN())
	if err == nil {
		t.Error("expected error for missing TUN IP")
	}
}

func TestHost_AddPeer(t *testing.T) {
	keyA, _ := noise.GenerateKeyPair()
	keyB, _ := noise.GenerateKeyPair()

	h, err := New(Config{
		PrivateKey: keyA,
		TunIPv4:    net.IPv4(100, 64, 0, 1),
	}, newMockTUN())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	err = h.AddPeer(keyB.Public, "127.0.0.1:12345")
	if err != nil {
		t.Fatalf("AddPeer failed: %v", err)
	}

	// Verify IP allocation
	ip, ok := h.ipAlloc.LookupByPubkey(keyB.Public)
	if !ok {
		t.Fatal("peer IP not found")
	}
	t.Logf("Peer B allocated IP: %s", ip)
}

func TestHost_ICMPForwarding(t *testing.T) {
	// Create two hosts that will communicate via localhost UDP
	keyA, _ := noise.GenerateKeyPair()
	keyB, _ := noise.GenerateKeyPair()

	tunA := newMockTUN()
	tunB := newMockTUN()

	// Create Host A
	hostA, err := New(Config{
		PrivateKey: keyA,
		TunIPv4:    net.IPv4(100, 64, 0, 1),
		MTU:        1400,
	}, tunA)
	if err != nil {
		t.Fatalf("Create Host A failed: %v", err)
	}
	defer hostA.Close()

	// Create Host B
	hostB, err := New(Config{
		PrivateKey: keyB,
		TunIPv4:    net.IPv4(100, 64, 0, 1),
		MTU:        1400,
	}, tunB)
	if err != nil {
		t.Fatalf("Create Host B failed: %v", err)
	}
	defer hostB.Close()

	// Add each other as peers using localhost with actual ports
	portA := hostA.LocalAddr().(*net.UDPAddr).Port
	portB := hostB.LocalAddr().(*net.UDPAddr).Port

	if err := hostA.AddPeer(keyB.Public, fmt.Sprintf("127.0.0.1:%d", portB)); err != nil {
		t.Fatalf("Host A add peer B failed: %v", err)
	}
	if err := hostB.AddPeer(keyA.Public, fmt.Sprintf("127.0.0.1:%d", portA)); err != nil {
		t.Fatalf("Host B add peer A failed: %v", err)
	}

	// Get allocated IPs
	ipBonA, _ := hostA.ipAlloc.LookupByPubkey(keyB.Public) // B's IP as seen by A
	ipAonB, _ := hostB.ipAlloc.LookupByPubkey(keyA.Public) // A's IP as seen by B

	t.Logf("Host A: TUN=100.64.0.1, peer B=%s", ipBonA)
	t.Logf("Host B: TUN=100.64.0.1, peer A=%s", ipAonB)

	// Start forwarding loops in background
	go hostA.Run()
	go hostB.Run()

	// Perform handshake (A connects to B)
	if err := hostA.Connect(keyB.Public); err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Small delay for goroutines to start
	time.Sleep(50 * time.Millisecond)

	// Build an ICMP echo request: A -> B
	// From A's perspective: src=100.64.0.1 (A's TUN), dst=ipBonA (B's allocated IP)
	icmpPayload := makeICMPEcho(8, 0, 1, 1, []byte("ping")) // type=8 (request), code=0
	srcIPonA := net.IPv4(100, 64, 0, 1)
	ipPkt, err := BuildIPv4Packet(srcIPonA, ipBonA, 1, icmpPayload)
	if err != nil {
		t.Fatalf("BuildIPv4Packet failed: %v", err)
	}

	// Inject the packet into Host A's TUN (simulating an app sending ping)
	tunA.inject(ipPkt)

	// Wait for the packet to arrive at Host B's TUN
	received, ok := tunB.receive(3 * time.Second)
	if !ok {
		t.Fatal("timeout waiting for packet at Host B")
	}

	// Parse the received packet
	info, err := ParseIPPacket(received)
	if err != nil {
		t.Fatalf("ParseIPPacket at B failed: %v", err)
	}

	// Verify: src should be A's IP as seen by B, dst should be B's TUN IP
	if !info.SrcIP.Equal(ipAonB) {
		t.Errorf("received src IP = %s, want %s (A's IP on B)", info.SrcIP, ipAonB)
	}
	if !info.DstIP.Equal(net.IPv4(100, 64, 0, 1)) {
		t.Errorf("received dst IP = %s, want 100.64.0.1 (B's TUN)", info.DstIP)
	}
	if info.Protocol != 1 {
		t.Errorf("received protocol = %d, want 1 (ICMP)", info.Protocol)
	}

	// Verify ICMP payload content
	if len(info.Payload) < 8 {
		t.Fatalf("ICMP payload too short: %d bytes", len(info.Payload))
	}
	if info.Payload[0] != 8 { // ICMP Echo Request
		t.Errorf("ICMP type = %d, want 8", info.Payload[0])
	}

	t.Logf("ICMP forwarding test passed: %d bytes forwarded", len(received))
}

func TestHost_TCPForwarding(t *testing.T) {
	keyA, _ := noise.GenerateKeyPair()
	keyB, _ := noise.GenerateKeyPair()

	tunA := newMockTUN()
	tunB := newMockTUN()

	hostA, err := New(Config{
		PrivateKey: keyA,
		TunIPv4:    net.IPv4(100, 64, 0, 1),
	}, tunA)
	if err != nil {
		t.Fatal(err)
	}
	defer hostA.Close()

	hostB, err := New(Config{
		PrivateKey: keyB,
		TunIPv4:    net.IPv4(100, 64, 0, 1),
	}, tunB)
	if err != nil {
		t.Fatal(err)
	}
	defer hostB.Close()

	hostA.AddPeer(keyB.Public, fmt.Sprintf("127.0.0.1:%d", hostB.LocalAddr().(*net.UDPAddr).Port))
	hostB.AddPeer(keyA.Public, fmt.Sprintf("127.0.0.1:%d", hostA.LocalAddr().(*net.UDPAddr).Port))

	ipBonA, _ := hostA.ipAlloc.LookupByPubkey(keyB.Public)

	go hostA.Run()
	go hostB.Run()

	if err := hostA.Connect(keyB.Public); err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Build a TCP SYN packet
	tcpPayload := makeTCPSYN(12345, 80)
	ipPkt, err := BuildIPv4Packet(net.IPv4(100, 64, 0, 1), ipBonA, 6, tcpPayload)
	if err != nil {
		t.Fatal(err)
	}

	tunA.inject(ipPkt)

	received, ok := tunB.receive(3 * time.Second)
	if !ok {
		t.Fatal("timeout waiting for TCP packet at Host B")
	}

	info, err := ParseIPPacket(received)
	if err != nil {
		t.Fatal(err)
	}

	if info.Protocol != 6 {
		t.Errorf("protocol = %d, want 6 (TCP)", info.Protocol)
	}

	// Verify TCP checksum is valid after rebuild
	tcpData := info.Payload
	var sum uint32
	src4 := info.SrcIP.To4()
	dst4 := info.DstIP.To4()
	sum += uint32(src4[0])<<8 | uint32(src4[1])
	sum += uint32(src4[2])<<8 | uint32(src4[3])
	sum += uint32(dst4[0])<<8 | uint32(dst4[1])
	sum += uint32(dst4[2])<<8 | uint32(dst4[3])
	sum += uint32(6)
	sum += uint32(len(tcpData))
	sum = checksumData(sum, tcpData)
	cs := checksumFold(sum)
	if cs != 0 {
		t.Errorf("TCP checksum invalid after forwarding: 0x%04x", cs)
	}

	t.Logf("TCP forwarding test passed: %d bytes forwarded", len(received))
}

func TestHost_Bidirectional(t *testing.T) {
	keyA, _ := noise.GenerateKeyPair()
	keyB, _ := noise.GenerateKeyPair()

	tunA := newMockTUN()
	tunB := newMockTUN()

	hostA, err := New(Config{
		PrivateKey: keyA,
		TunIPv4:    net.IPv4(100, 64, 0, 1),
	}, tunA)
	if err != nil {
		t.Fatal(err)
	}
	defer hostA.Close()

	hostB, err := New(Config{
		PrivateKey: keyB,
		TunIPv4:    net.IPv4(100, 64, 0, 1),
	}, tunB)
	if err != nil {
		t.Fatal(err)
	}
	defer hostB.Close()

	hostA.AddPeer(keyB.Public, fmt.Sprintf("127.0.0.1:%d", hostB.LocalAddr().(*net.UDPAddr).Port))
	hostB.AddPeer(keyA.Public, fmt.Sprintf("127.0.0.1:%d", hostA.LocalAddr().(*net.UDPAddr).Port))

	ipBonA, _ := hostA.ipAlloc.LookupByPubkey(keyB.Public)
	ipAonB, _ := hostB.ipAlloc.LookupByPubkey(keyA.Public)

	go hostA.Run()
	go hostB.Run()

	if err := hostA.Connect(keyB.Public); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	// A -> B
	icmpReq := makeICMPEcho(8, 0, 1, 1, []byte("ping"))
	pktAtoB, _ := BuildIPv4Packet(net.IPv4(100, 64, 0, 1), ipBonA, 1, icmpReq)
	tunA.inject(pktAtoB)

	if _, ok := tunB.receive(3 * time.Second); !ok {
		t.Fatal("A->B: timeout")
	}

	// B -> A
	icmpReply := makeICMPEcho(0, 0, 1, 1, []byte("pong"))
	pktBtoA, _ := BuildIPv4Packet(net.IPv4(100, 64, 0, 1), ipAonB, 1, icmpReply)
	tunB.inject(pktBtoA)

	received, ok := tunA.receive(3 * time.Second)
	if !ok {
		t.Fatal("B->A: timeout")
	}

	info, _ := ParseIPPacket(received)
	if info.Protocol != 1 {
		t.Errorf("B->A protocol = %d, want 1", info.Protocol)
	}

	t.Log("Bidirectional forwarding test passed")
}

func TestHost_Close(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	tun := newMockTUN()

	h, err := New(Config{
		PrivateKey: key,
		TunIPv4:    net.IPv4(100, 64, 0, 1),
	}, tun)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		h.Run()
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Close should unblock Run
	h.Close()

	select {
	case <-done:
		// OK
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock Run")
	}

	// Double close should not panic
	h.Close()
}

// makeICMPEcho creates an ICMP echo request/reply payload.
func makeICMPEcho(typ, code byte, id, seq uint16, data []byte) []byte {
	pkt := make([]byte, 8+len(data))
	pkt[0] = typ
	pkt[1] = code
	// checksum at [2:4] = 0 for now
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)
	copy(pkt[8:], data)

	// Compute ICMP checksum
	cs := ipChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[2:4], cs)
	return pkt
}

// makeTCPSYN creates a minimal TCP SYN segment.
func makeTCPSYN(srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], srcPort)
	binary.BigEndian.PutUint16(pkt[2:4], dstPort)
	binary.BigEndian.PutUint32(pkt[4:8], 1000)  // seq
	binary.BigEndian.PutUint32(pkt[8:12], 0)     // ack
	pkt[12] = 0x50                                // data offset = 5 (20 bytes)
	pkt[13] = 0x02                                // SYN flag
	binary.BigEndian.PutUint16(pkt[14:16], 65535) // window
	// checksum at [16:18] starts as 0, will be set by BuildIPv4Packet
	return pkt
}
