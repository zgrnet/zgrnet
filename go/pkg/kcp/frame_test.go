package kcp

import (
	"bytes"
	"testing"
)

func TestFrameEncodeDecode(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
	}{
		{
			name: "SYN frame",
			frame: Frame{
				Cmd:      CmdSYN,
				StreamID: 1,
				Payload:  nil,
			},
		},
		{
			name: "FIN frame",
			frame: Frame{
				Cmd:      CmdFIN,
				StreamID: 12345,
				Payload:  nil,
			},
		},
		{
			name: "PSH frame with data",
			frame: Frame{
				Cmd:      CmdPSH,
				StreamID: 100,
				Payload:  []byte("hello world"),
			},
		},
		{
			name: "NOP frame",
			frame: Frame{
				Cmd:      CmdNOP,
				StreamID: 0,
				Payload:  nil,
			},
		},
		{
			name: "UPD frame",
			frame: Frame{
				Cmd:      CmdUPD,
				StreamID: 42,
				Payload:  (&UpdatePayload{Consumed: 1024, Window: 65536}).Encode(),
			},
		},
		{
			name: "PSH frame with large payload",
			frame: Frame{
				Cmd:      CmdPSH,
				StreamID: 999,
				Payload:  bytes.Repeat([]byte{0xAB}, 1000),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded := tt.frame.Encode()

			// Decode
			decoded, err := DecodeFrame(encoded)
			if err != nil {
				t.Fatalf("DecodeFrame() error = %v", err)
			}

			// Verify
			if decoded.Cmd != tt.frame.Cmd {
				t.Errorf("Cmd = %d, want %d", decoded.Cmd, tt.frame.Cmd)
			}
			if decoded.StreamID != tt.frame.StreamID {
				t.Errorf("StreamID = %d, want %d", decoded.StreamID, tt.frame.StreamID)
			}
			if !bytes.Equal(decoded.Payload, tt.frame.Payload) {
				t.Errorf("Payload mismatch")
			}
		})
	}
}

func TestFrameEncodeTo(t *testing.T) {
	frame := Frame{
		Cmd:      CmdPSH,
		StreamID: 123,
		Payload:  []byte("test data"),
	}

	buf := make([]byte, FrameHeaderSize+len(frame.Payload))
	n := frame.EncodeTo(buf)

	if n != FrameHeaderSize+len(frame.Payload) {
		t.Errorf("EncodeTo() returned %d, want %d", n, FrameHeaderSize+len(frame.Payload))
	}

	// Verify it matches Encode()
	encoded := frame.Encode()
	if !bytes.Equal(buf[:n], encoded) {
		t.Errorf("EncodeTo() result differs from Encode()")
	}
}

func TestDecodeFrameHeader(t *testing.T) {
	frame := Frame{
		Cmd:      CmdPSH,
		StreamID: 456,
		Payload:  []byte("payload"),
	}

	encoded := frame.Encode()
	cmd, streamID, length, err := DecodeFrameHeader(encoded)

	if err != nil {
		t.Fatalf("DecodeFrameHeader() error = %v", err)
	}
	if cmd != CmdPSH {
		t.Errorf("cmd = %d, want %d", cmd, CmdPSH)
	}
	if streamID != 456 {
		t.Errorf("streamID = %d, want 456", streamID)
	}
	if length != uint16(len(frame.Payload)) {
		t.Errorf("length = %d, want %d", length, len(frame.Payload))
	}
}

func TestDecodeFrameTooShort(t *testing.T) {
	// Too short for header
	_, err := DecodeFrame([]byte{0, 1, 2})
	if err != ErrFrameTooShort {
		t.Errorf("DecodeFrame() error = %v, want ErrFrameTooShort", err)
	}

	// Header says 100 bytes payload, but only 5 bytes available
	data := make([]byte, FrameHeaderSize+5)
	data[5] = 100 // length = 100
	data[6] = 0
	_, err = DecodeFrame(data)
	if err != ErrFrameTooShort {
		t.Errorf("DecodeFrame() error = %v, want ErrFrameTooShort", err)
	}
}

func TestUpdatePayload(t *testing.T) {
	upd := UpdatePayload{
		Consumed: 12345,
		Window:   65536,
	}

	encoded := upd.Encode()
	if len(encoded) != UpdatePayloadSize {
		t.Errorf("Encode() length = %d, want %d", len(encoded), UpdatePayloadSize)
	}

	decoded, err := DecodeUpdatePayload(encoded)
	if err != nil {
		t.Fatalf("DecodeUpdatePayload() error = %v", err)
	}

	if decoded.Consumed != upd.Consumed {
		t.Errorf("Consumed = %d, want %d", decoded.Consumed, upd.Consumed)
	}
	if decoded.Window != upd.Window {
		t.Errorf("Window = %d, want %d", decoded.Window, upd.Window)
	}
}

func TestUpdatePayloadTooShort(t *testing.T) {
	_, err := DecodeUpdatePayload([]byte{1, 2, 3})
	if err != ErrFrameTooShort {
		t.Errorf("DecodeUpdatePayload() error = %v, want ErrFrameTooShort", err)
	}
}

func TestCmdConstants(t *testing.T) {
	// Verify command constants match expected values
	if CmdSYN != 0 {
		t.Errorf("CmdSYN = %d, want 0", CmdSYN)
	}
	if CmdFIN != 1 {
		t.Errorf("CmdFIN = %d, want 1", CmdFIN)
	}
	if CmdPSH != 2 {
		t.Errorf("CmdPSH = %d, want 2", CmdPSH)
	}
	if CmdNOP != 3 {
		t.Errorf("CmdNOP = %d, want 3", CmdNOP)
	}
	if CmdUPD != 4 {
		t.Errorf("CmdUPD = %d, want 4", CmdUPD)
	}
}

func BenchmarkFrameEncode(b *testing.B) {
	frame := Frame{
		Cmd:      CmdPSH,
		StreamID: 12345,
		Payload:  []byte("hello world benchmark payload data"),
	}
	frameSize := FrameHeaderSize + len(frame.Payload)
	b.SetBytes(int64(frameSize))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = frame.Encode()
	}
}

func BenchmarkFrameEncodeTo(b *testing.B) {
	frame := Frame{
		Cmd:      CmdPSH,
		StreamID: 12345,
		Payload:  []byte("hello world benchmark payload data"),
	}
	frameSize := FrameHeaderSize + len(frame.Payload)
	buf := make([]byte, frameSize)
	b.SetBytes(int64(frameSize))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame.EncodeTo(buf)
	}
}

func BenchmarkFrameDecode(b *testing.B) {
	frame := Frame{
		Cmd:      CmdPSH,
		StreamID: 12345,
		Payload:  []byte("hello world benchmark payload data"),
	}
	encoded := frame.Encode()
	b.SetBytes(int64(len(encoded)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeFrame(encoded)
	}
}

func BenchmarkFrameDecodeHeader(b *testing.B) {
	frame := Frame{
		Cmd:      CmdPSH,
		StreamID: 12345,
		Payload:  []byte("hello world benchmark payload data"),
	}
	encoded := frame.Encode()
	b.SetBytes(int64(len(encoded)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = DecodeFrameHeader(encoded)
	}
}
