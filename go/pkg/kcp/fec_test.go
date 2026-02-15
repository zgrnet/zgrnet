package kcp

import (
	"bytes"
	"testing"
)

func TestFECHeaderEncodeDecode(t *testing.T) {
	var buf [FECHeaderSize]byte
	EncodeFECHeader(buf[:], 42, 2, 3, 1400)
	hdr, err := DecodeFECHeader(buf[:])
	if err != nil {
		t.Fatalf("DecodeFECHeader: %v", err)
	}
	if hdr.GroupID != 42 {
		t.Errorf("GroupID = %d, want 42", hdr.GroupID)
	}
	if hdr.Index != 2 {
		t.Errorf("Index = %d, want 2", hdr.Index)
	}
	if hdr.Count != 3 {
		t.Errorf("Count = %d, want 3", hdr.Count)
	}
	if hdr.PayloadLen != 1400 {
		t.Errorf("PayloadLen = %d, want 1400", hdr.PayloadLen)
	}
}

func TestFECHeaderDecodeTooShort(t *testing.T) {
	_, err := DecodeFECHeader([]byte{0, 1, 2})
	if err != ErrFECPacketTooShort {
		t.Errorf("expected ErrFECPacketTooShort, got %v", err)
	}
}

func TestXorBytes(t *testing.T) {
	a := []byte{0xAA, 0xBB, 0xCC}
	b := []byte{0x55, 0x44, 0x33}
	xorBytes(a, b)
	expected := []byte{0xFF, 0xFF, 0xFF}
	if !bytes.Equal(a, expected) {
		t.Errorf("xorBytes = %x, want %x", a, expected)
	}
}

func TestFECEncoderProducesNPlus1Packets(t *testing.T) {
	count := 0
	enc := NewFECEncoder(3, func(data []byte) {
		count++
	})

	// Add 3 packets → should emit 4 (3 data + 1 parity)
	enc.AddPacket([]byte("packet1"))
	enc.AddPacket([]byte("packet2"))
	enc.AddPacket([]byte("packet3"))

	if count != 4 {
		t.Errorf("output count = %d, want 4", count)
	}
}

func TestFECEncoderDecoderRoundtripNoLoss(t *testing.T) {
	type packet struct {
		data []byte
	}

	var fecPackets [][]byte
	enc := NewFECEncoder(3, func(data []byte) {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		fecPackets = append(fecPackets, pkt)
	})

	enc.AddPacket([]byte("hello"))
	enc.AddPacket([]byte("world"))
	enc.AddPacket([]byte("test!"))

	if len(fecPackets) != 4 {
		t.Fatalf("encoder produced %d packets, want 4", len(fecPackets))
	}

	// Decoder: feed all 4 FEC packets
	var received [][]byte
	dec := NewFECDecoder(func(data []byte) {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		received = append(received, pkt)
	})
	for _, pkt := range fecPackets {
		dec.AddPacket(pkt)
	}

	// Should receive 3 data packets
	if len(received) != 3 {
		t.Fatalf("received %d packets, want 3", len(received))
	}
	if !bytes.Equal(received[0], []byte("hello")) {
		t.Errorf("packet 0 = %q, want %q", received[0], "hello")
	}
	if !bytes.Equal(received[1], []byte("world")) {
		t.Errorf("packet 1 = %q, want %q", received[1], "world")
	}
	if !bytes.Equal(received[2], []byte("test!")) {
		t.Errorf("packet 2 = %q, want %q", received[2], "test!")
	}
}

func TestFECRecoverSingleLostDataPacket(t *testing.T) {
	var fecPackets [][]byte
	enc := NewFECEncoder(3, func(data []byte) {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		fecPackets = append(fecPackets, pkt)
	})

	// All packets same length for clean XOR recovery
	enc.AddPacket([]byte("AAA"))
	enc.AddPacket([]byte("BBB"))
	enc.AddPacket([]byte("CCC"))

	if len(fecPackets) != 4 {
		t.Fatalf("encoder produced %d packets, want 4", len(fecPackets))
	}

	// Feed to decoder, SKIP packet index 1 ("BBB")
	var received [][]byte
	dec := NewFECDecoder(func(data []byte) {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		received = append(received, pkt)
	})

	dec.AddPacket(fecPackets[0]) // "AAA"
	// skip fecPackets[1] "BBB"
	dec.AddPacket(fecPackets[2]) // "CCC"
	dec.AddPacket(fecPackets[3]) // parity

	// Should receive 3 packets: "AAA", "CCC" (immediate), and "BBB" (recovered)
	if len(received) != 3 {
		t.Fatalf("received %d packets, want 3", len(received))
	}

	// First two are immediate emissions: "AAA" and "CCC"
	if !bytes.Equal(received[0], []byte("AAA")) {
		t.Errorf("packet 0 = %q, want %q", received[0], "AAA")
	}
	if !bytes.Equal(received[1], []byte("CCC")) {
		t.Errorf("packet 1 = %q, want %q", received[1], "CCC")
	}
	// Third is recovered "BBB"
	if !bytes.Equal(received[2], []byte("BBB")) {
		t.Errorf("packet 2 = %q, want %q", received[2], "BBB")
	}
}

func TestFECRecoverFirstPacket(t *testing.T) {
	var fecPackets [][]byte
	enc := NewFECEncoder(3, func(data []byte) {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		fecPackets = append(fecPackets, pkt)
	})

	enc.AddPacket([]byte("AAA"))
	enc.AddPacket([]byte("BBB"))
	enc.AddPacket([]byte("CCC"))

	var received [][]byte
	dec := NewFECDecoder(func(data []byte) {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		received = append(received, pkt)
	})

	// Skip first packet
	dec.AddPacket(fecPackets[1]) // "BBB"
	dec.AddPacket(fecPackets[2]) // "CCC"
	dec.AddPacket(fecPackets[3]) // parity

	if len(received) != 3 {
		t.Fatalf("received %d packets, want 3", len(received))
	}
	if !bytes.Equal(received[0], []byte("BBB")) {
		t.Errorf("packet 0 = %q, want %q", received[0], "BBB")
	}
	if !bytes.Equal(received[1], []byte("CCC")) {
		t.Errorf("packet 1 = %q, want %q", received[1], "CCC")
	}
	if !bytes.Equal(received[2], []byte("AAA")) {
		t.Errorf("packet 2 = %q, want %q", received[2], "AAA")
	}
}

func TestFECRecoverLastPacket(t *testing.T) {
	var fecPackets [][]byte
	enc := NewFECEncoder(3, func(data []byte) {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		fecPackets = append(fecPackets, pkt)
	})

	enc.AddPacket([]byte("AAA"))
	enc.AddPacket([]byte("BBB"))
	enc.AddPacket([]byte("CCC"))

	var received [][]byte
	dec := NewFECDecoder(func(data []byte) {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		received = append(received, pkt)
	})

	dec.AddPacket(fecPackets[0]) // "AAA"
	dec.AddPacket(fecPackets[1]) // "BBB"
	// skip fecPackets[2] "CCC"
	dec.AddPacket(fecPackets[3]) // parity

	if len(received) != 3 {
		t.Fatalf("received %d packets, want 3", len(received))
	}
	if !bytes.Equal(received[2], []byte("CCC")) {
		t.Errorf("recovered packet = %q, want %q", received[2], "CCC")
	}
}

func TestFECMultipleGroups(t *testing.T) {
	var fecPackets [][]byte
	enc := NewFECEncoder(2, func(data []byte) {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		fecPackets = append(fecPackets, pkt)
	})

	// Group 0: 2 data + 1 parity = 3
	enc.AddPacket([]byte("A1"))
	enc.AddPacket([]byte("A2"))
	// Group 1: 2 data + 1 parity = 3
	enc.AddPacket([]byte("B1"))
	enc.AddPacket([]byte("B2"))

	if len(fecPackets) != 6 {
		t.Fatalf("encoder produced %d packets, want 6", len(fecPackets))
	}

	// Verify group IDs increment
	hdr0, _ := DecodeFECHeader(fecPackets[0])
	hdr3, _ := DecodeFECHeader(fecPackets[3])
	if hdr0.GroupID != 0 {
		t.Errorf("group 0 ID = %d, want 0", hdr0.GroupID)
	}
	if hdr3.GroupID != 1 {
		t.Errorf("group 1 ID = %d, want 1", hdr3.GroupID)
	}

	// Feed all to decoder, skip one from each group
	var received [][]byte
	dec := NewFECDecoder(func(data []byte) {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		received = append(received, pkt)
	})

	// Group 0: skip A1 (index 0)
	dec.AddPacket(fecPackets[1]) // A2
	dec.AddPacket(fecPackets[2]) // parity → recovers A1
	// Group 1: skip B2 (index 1)
	dec.AddPacket(fecPackets[3]) // B1
	dec.AddPacket(fecPackets[5]) // parity → recovers B2

	if len(received) != 4 {
		t.Fatalf("received %d packets, want 4", len(received))
	}
}

func TestFECFlushPartial(t *testing.T) {
	count := 0
	enc := NewFECEncoder(5, func(data []byte) {
		count++
	})

	// Add only 2 of 5, then flush
	enc.AddPacket([]byte("one"))
	enc.AddPacket([]byte("two"))
	if count != 0 {
		t.Errorf("premature emit: count = %d, want 0", count)
	}

	enc.FlushPartial()
	// Should emit 2 data + 1 parity = 3
	if count != 3 {
		t.Errorf("after flush: count = %d, want 3", count)
	}
}

func TestFECDecoderRejectsInvalidPackets(t *testing.T) {
	received := 0
	dec := NewFECDecoder(func(data []byte) {
		received++
	})

	// count=255 (> max_group_size=16) — must be silently dropped
	var bad1 [FECHeaderSize + 4]byte
	EncodeFECHeader(bad1[:], 0, 0, 255, 4)
	copy(bad1[FECHeaderSize:], []byte("XXXX"))
	dec.AddPacket(bad1[:])

	// count=0 — invalid, must be dropped
	var bad2 [FECHeaderSize + 4]byte
	EncodeFECHeader(bad2[:], 0, 0, 0, 4)
	copy(bad2[FECHeaderSize:], []byte("XXXX"))
	dec.AddPacket(bad2[:])

	// index > count — must be dropped
	var bad3 [FECHeaderSize + 4]byte
	EncodeFECHeader(bad3[:], 0, 5, 3, 4)
	copy(bad3[FECHeaderSize:], []byte("XXXX"))
	dec.AddPacket(bad3[:])

	if received != 0 {
		t.Errorf("received %d packets from invalid input, want 0", received)
	}
}

func TestFECDecoderDuplicatePackets(t *testing.T) {
	var fecPackets [][]byte
	enc := NewFECEncoder(2, func(data []byte) {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		fecPackets = append(fecPackets, pkt)
	})

	enc.AddPacket([]byte("XX"))
	enc.AddPacket([]byte("YY"))

	received := 0
	dec := NewFECDecoder(func(data []byte) {
		received++
	})

	// Feed same data packet twice — second should be ignored
	dec.AddPacket(fecPackets[0])
	dec.AddPacket(fecPackets[0]) // duplicate
	dec.AddPacket(fecPackets[1])

	if received != 2 {
		t.Errorf("received %d, want 2 (duplicate should be ignored)", received)
	}
}

func TestFECCannotRecoverTwoLost(t *testing.T) {
	var fecPackets [][]byte
	enc := NewFECEncoder(3, func(data []byte) {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		fecPackets = append(fecPackets, pkt)
	})

	enc.AddPacket([]byte("AAA"))
	enc.AddPacket([]byte("BBB"))
	enc.AddPacket([]byte("CCC"))

	var received [][]byte
	dec := NewFECDecoder(func(data []byte) {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		received = append(received, pkt)
	})

	// Only deliver 1 data packet + parity — 2 lost, cannot recover
	dec.AddPacket(fecPackets[0]) // "AAA"
	dec.AddPacket(fecPackets[3]) // parity

	// Should only have the 1 immediate data emission
	if len(received) != 1 {
		t.Errorf("received %d packets, want 1 (cannot recover 2 lost)", len(received))
	}
}

func TestPopcount(t *testing.T) {
	tests := []struct {
		x    uint32
		want int
	}{
		{0, 0},
		{1, 1},
		{0xFF, 8},
		{0xFFFFFFFF, 32},
		{0b10101010, 4},
	}
	for _, tt := range tests {
		if got := popcount(tt.x); got != tt.want {
			t.Errorf("popcount(%d) = %d, want %d", tt.x, got, tt.want)
		}
	}
}

func TestCtz(t *testing.T) {
	tests := []struct {
		x    uint32
		want uint8
	}{
		{0, 32},
		{1, 0},
		{2, 1},
		{4, 2},
		{0b1000, 3},
		{0b10100, 2},
	}
	for _, tt := range tests {
		if got := ctz(tt.x); got != tt.want {
			t.Errorf("ctz(%d) = %d, want %d", tt.x, got, tt.want)
		}
	}
}
