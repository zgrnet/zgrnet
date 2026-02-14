package kcp

import (
	"encoding/binary"
	"errors"
)

// FEC - Forward Error Correction for KCP packet loss resilience.
//
// XOR-based parity encoding that adds redundancy to KCP output packets.
// For a group of N data packets, produces 1 parity packet (XOR of all N).
// If any single packet in the group is lost, it can be reconstructed from
// the remaining N-1 data packets and the parity.
//
// Overhead: 1/N (e.g., N=3 → 33% overhead for single-loss recovery per group).
//
// Wire format:
//
//	[group_id: u16 LE][index: u8][count: u8][payload_len: u16 LE][payload...]
//
//	- group_id: Monotonically increasing group counter (wraps at u16 max)
//	- index: Packet index within the group (0..count-1 for data, count for parity)
//	- count: Number of data packets in the group (N)
//	- payload_len: Actual data length (before padding, for parity reconstruction)

// ErrFECPacketTooShort is returned when a FEC packet is shorter than FECHeaderSize.
var ErrFECPacketTooShort = errors.New("kcp: FEC packet too short")

const (
	// FECHeaderSize is the FEC packet header: group_id(2) + index(1) + count(1) + payload_len(2) = 6 bytes.
	FECHeaderSize = 6

	// FECMaxMTU is the maximum supported MTU for FEC packets.
	FECMaxMTU = 1500

	// fecMaxGroupSize is the maximum number of data packets per FEC group.
	fecMaxGroupSize = 16

	// fecDecoderWindowSize is the circular buffer size for tracking groups.
	fecDecoderWindowSize = 64
)

// FECHeader represents a decoded FEC packet header.
type FECHeader struct {
	GroupID    uint16
	Index      uint8
	Count      uint8
	PayloadLen uint16
}

// EncodeFECHeader writes a FEC header into buf (must be >= FECHeaderSize).
func EncodeFECHeader(buf []byte, groupID uint16, index, count uint8, payloadLen uint16) {
	binary.LittleEndian.PutUint16(buf[0:2], groupID)
	buf[2] = index
	buf[3] = count
	binary.LittleEndian.PutUint16(buf[4:6], payloadLen)
}

// DecodeFECHeader reads a FEC header from buf.
func DecodeFECHeader(buf []byte) (FECHeader, error) {
	if len(buf) < FECHeaderSize {
		return FECHeader{}, ErrFECPacketTooShort
	}
	return FECHeader{
		GroupID:    binary.LittleEndian.Uint16(buf[0:2]),
		Index:      buf[2],
		Count:      buf[3],
		PayloadLen: binary.LittleEndian.Uint16(buf[4:6]),
	}, nil
}

// xorBytes performs dst ^= src for min(len(dst), len(src)) bytes.
func xorBytes(dst, src []byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	for i := 0; i < n; i++ {
		dst[i] ^= src[i]
	}
}

// FECEncoder buffers output packets and emits groups with parity.
//
// Usage:
//  1. Call AddPacket() for each KCP output packet
//  2. When groupSize packets accumulate, the encoder emits N+1 packets
//     (N data + 1 parity) via the output callback
//  3. Call FlushPartial() to emit a partial group (e.g., on timer)
type FECEncoder struct {
	groupSize uint8
	groupID   uint16
	buffered  uint8

	// Buffered packet data.
	packetBuf  [fecMaxGroupSize][FECMaxMTU]byte
	packetLens [fecMaxGroupSize]uint16

	// Parity accumulator (running XOR).
	parityBuf     [FECMaxMTU]byte
	maxPayloadLen uint16

	// Output callback: called with each FEC-wrapped packet.
	outputFn func([]byte)
}

// NewFECEncoder creates a FEC encoder with the given group size and output callback.
func NewFECEncoder(groupSize uint8, outputFn func([]byte)) *FECEncoder {
	if groupSize > fecMaxGroupSize {
		groupSize = fecMaxGroupSize
	}
	return &FECEncoder{
		groupSize: groupSize,
		outputFn:  outputFn,
	}
}

// AddPacket adds a packet to the current group. Emits the group when full.
func (e *FECEncoder) AddPacket(data []byte) {
	if len(data) > FECMaxMTU {
		return // Drop oversized packets
	}
	if e.buffered >= e.groupSize {
		e.emitGroup()
	}

	idx := e.buffered

	// Store packet data
	copy(e.packetBuf[idx][:len(data)], data)
	// Zero-pad remainder for XOR
	for i := len(data); i < FECMaxMTU; i++ {
		e.packetBuf[idx][i] = 0
	}
	e.packetLens[idx] = uint16(len(data))

	// Update parity (running XOR)
	xorBytes(e.parityBuf[:], e.packetBuf[idx][:])
	if uint16(len(data)) > e.maxPayloadLen {
		e.maxPayloadLen = uint16(len(data))
	}

	e.buffered++

	if e.buffered >= e.groupSize {
		e.emitGroup()
	}
}

// FlushPartial flushes a partial group (fewer than groupSize packets).
// Call this on a timer to avoid indefinite buffering.
func (e *FECEncoder) FlushPartial() {
	if e.buffered > 0 {
		e.emitGroup()
	}
}

func (e *FECEncoder) emitGroup() {
	count := e.buffered
	if count == 0 {
		return
	}

	var emitBuf [FECHeaderSize + FECMaxMTU]byte

	// Emit data packets with FEC header
	for i := uint8(0); i < count; i++ {
		plen := e.packetLens[i]
		total := FECHeaderSize + int(plen)
		EncodeFECHeader(emitBuf[:], e.groupID, i, count, plen)
		copy(emitBuf[FECHeaderSize:], e.packetBuf[i][:plen])
		e.outputFn(emitBuf[:total])
	}

	// Emit parity packet
	parityLen := e.maxPayloadLen
	parityTotal := FECHeaderSize + int(parityLen)
	EncodeFECHeader(emitBuf[:], e.groupID, count, count, parityLen)
	copy(emitBuf[FECHeaderSize:], e.parityBuf[:parityLen])
	e.outputFn(emitBuf[:parityTotal])

	// Reset for next group
	e.groupID++
	e.buffered = 0
	e.maxPayloadLen = 0
	e.parityBuf = [FECMaxMTU]byte{}
}

// FECDecoder receives FEC-wrapped packets and reconstructs lost data.
//
// Tracks packet groups and attempts reconstruction when a single packet
// is missing from a group (using XOR parity).
type FECDecoder struct {
	groups      [fecDecoderWindowSize]fecGroup
	groupIDs    [fecDecoderWindowSize]uint16
	groupActive [fecDecoderWindowSize]bool

	// Output callback: called with each recovered/received data packet.
	outputFn func([]byte)
}

type fecGroup struct {
	received       uint32 // Bitmask of received packet indices
	parityReceived bool
	count          uint8
	packets        [fecMaxGroupSize + 1][FECMaxMTU]byte
	packetLens     [fecMaxGroupSize + 1]uint16
}

func (g *fecGroup) reset() {
	g.received = 0
	g.parityReceived = false
	g.count = 0
}

// NewFECDecoder creates a FEC decoder with the given output callback.
func NewFECDecoder(outputFn func([]byte)) *FECDecoder {
	return &FECDecoder{
		outputFn: outputFn,
	}
}

// AddPacket processes a received FEC packet. Emits recovered data packets via output callback.
func (d *FECDecoder) AddPacket(data []byte) {
	hdr, err := DecodeFECHeader(data)
	if err != nil {
		return
	}
	if len(data) < FECHeaderSize+int(hdr.PayloadLen) {
		return
	}

	// Validate untrusted wire values against array bounds.
	if hdr.Count == 0 || hdr.Count > fecMaxGroupSize {
		return
	}
	if hdr.Index > hdr.Count {
		return
	}

	payload := data[FECHeaderSize : FECHeaderSize+int(hdr.PayloadLen)]
	slot := hdr.GroupID % fecDecoderWindowSize

	// Initialize or validate group slot
	if !d.groupActive[slot] || d.groupIDs[slot] != hdr.GroupID {
		d.groups[slot].reset()
		d.groupIDs[slot] = hdr.GroupID
		d.groupActive[slot] = true
	}

	group := &d.groups[slot]
	group.count = hdr.Count

	isParity := hdr.Index == hdr.Count

	if isParity {
		if group.parityReceived {
			return // Duplicate
		}
		group.parityReceived = true
		copy(group.packets[hdr.Count][:hdr.PayloadLen], payload)
		for i := int(hdr.PayloadLen); i < FECMaxMTU; i++ {
			group.packets[hdr.Count][i] = 0
		}
		group.packetLens[hdr.Count] = hdr.PayloadLen
	} else {
		if hdr.Index >= hdr.Count {
			return // Invalid index
		}
		bit := uint32(1) << hdr.Index
		if group.received&bit != 0 {
			return // Duplicate
		}
		group.received |= bit
		copy(group.packets[hdr.Index][:hdr.PayloadLen], payload)
		for i := int(hdr.PayloadLen); i < FECMaxMTU; i++ {
			group.packets[hdr.Index][i] = 0
		}
		group.packetLens[hdr.Index] = hdr.PayloadLen

		// Emit this data packet immediately (don't wait for group completion)
		d.outputFn(payload)
	}

	// Check if we can recover a missing packet
	d.tryRecover(group)
}

func (d *FECDecoder) tryRecover(group *fecGroup) {
	if !group.parityReceived {
		return
	}

	count := group.count
	allReceived := uint32((1 << count) - 1)
	received := group.received & allReceived
	missing := allReceived ^ received

	// Can only recover exactly 1 missing packet
	if missing == 0 || popcount(missing) != 1 {
		return
	}

	// Find the missing index
	missingIdx := ctz(missing)

	// Reconstruct: XOR parity with all other received data packets
	var recovered [FECMaxMTU]byte
	parityLen := group.packetLens[count]
	copy(recovered[:parityLen], group.packets[count][:parityLen])
	for i := int(parityLen); i < FECMaxMTU; i++ {
		recovered[i] = 0
	}

	for i := uint8(0); i < count; i++ {
		if i == missingIdx {
			continue
		}
		plen := group.packetLens[i]
		maxLen := plen
		if parityLen > maxLen {
			maxLen = parityLen
		}
		xorBytes(recovered[:maxLen], group.packets[i][:maxLen])
	}

	group.received |= 1 << missingIdx

	// Emit recovered packet
	d.outputFn(recovered[:parityLen])
}

// popcount returns the number of set bits in x.
func popcount(x uint32) int {
	n := 0
	for x != 0 {
		n++
		x &= x - 1
	}
	return n
}

// ctz returns the count of trailing zeros in x (index of lowest set bit).
func ctz(x uint32) uint8 {
	if x == 0 {
		return 32
	}
	n := uint8(0)
	for x&1 == 0 {
		n++
		x >>= 1
	}
	return n
}
