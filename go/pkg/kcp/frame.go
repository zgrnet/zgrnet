// Package kcp provides KCP reliable transport and stream multiplexing.
package kcp

import (
	"encoding/binary"
	"errors"
)

// Frame commands for KCP mux protocol.
// Values start at 1 to match Rust/Zig implementations.
const (
	_      byte = iota // skip 0
	CmdSYN             // Stream open (0x01)
	CmdFIN             // Stream close (EOF) (0x02)
	CmdPSH             // Data push (0x03)
	CmdNOP             // No operation (keepalive) (0x04)
)

// Frame header size: cmd(1) + stream_id(4) + length(2) = 7 bytes
const (
	FrameHeaderSize = 7
	MaxFrameSize    = 65535
)

// Frame represents a multiplexed frame.
//
// Wire format:
//
//	+-------+------------+--------+---------+
//	| cmd   | stream_id  | length | payload |
//	| (1B)  | (4B LE)    | (2B LE)| (var)   |
//	+-------+------------+--------+---------+
type Frame struct {
	Cmd      byte   // Command type
	StreamID uint32 // Stream identifier
	Payload  []byte // Frame payload
}

// Encode serializes the frame to bytes.
func (f *Frame) Encode() []byte {
	buf := make([]byte, FrameHeaderSize+len(f.Payload))
	buf[0] = f.Cmd
	binary.LittleEndian.PutUint32(buf[1:5], f.StreamID)
	binary.LittleEndian.PutUint16(buf[5:7], uint16(len(f.Payload)))
	copy(buf[7:], f.Payload)
	return buf
}

// EncodeTo serializes the frame to the given buffer.
// Returns the number of bytes written.
// The buffer must be at least FrameHeaderSize + len(f.Payload) bytes.
func (f *Frame) EncodeTo(buf []byte) int {
	buf[0] = f.Cmd
	binary.LittleEndian.PutUint32(buf[1:5], f.StreamID)
	binary.LittleEndian.PutUint16(buf[5:7], uint16(len(f.Payload)))
	copy(buf[7:], f.Payload)
	return FrameHeaderSize + len(f.Payload)
}

// DecodeFrame parses a frame from bytes.
func DecodeFrame(data []byte) (*Frame, error) {
	if len(data) < FrameHeaderSize {
		return nil, ErrFrameTooShort
	}

	length := binary.LittleEndian.Uint16(data[5:7])
	if len(data) < FrameHeaderSize+int(length) {
		return nil, ErrFrameTooShort
	}

	f := &Frame{
		Cmd:      data[0],
		StreamID: binary.LittleEndian.Uint32(data[1:5]),
	}

	if length > 0 {
		f.Payload = make([]byte, length)
		copy(f.Payload, data[7:7+length])
	}

	return f, nil
}

// DecodeFrameHeader parses only the frame header.
// Returns cmd, streamID, payloadLength, error.
func DecodeFrameHeader(data []byte) (cmd byte, streamID uint32, length uint16, err error) {
	if len(data) < FrameHeaderSize {
		return 0, 0, 0, ErrFrameTooShort
	}
	return data[0], binary.LittleEndian.Uint32(data[1:5]), binary.LittleEndian.Uint16(data[5:7]), nil
}

// Frame errors.
var (
	ErrFrameTooShort = errors.New("kcp: frame too short")
	ErrInvalidCmd    = errors.New("kcp: invalid command")
)
