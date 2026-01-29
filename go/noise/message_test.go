package noise

import (
	"bytes"
	"testing"
)

func TestTransportMessage(t *testing.T) {
	// Build a transport message
	receiverIdx := uint32(12345)
	counter := uint64(67890)
	ciphertext := []byte("encrypted data here!!")

	msg := BuildTransportMessage(receiverIdx, counter, ciphertext)

	// Parse it back
	parsed, err := ParseTransportMessage(msg)
	if err != nil {
		t.Fatalf("ParseTransportMessage() error = %v", err)
	}

	if parsed.ReceiverIndex != receiverIdx {
		t.Errorf("ReceiverIndex = %d, want %d", parsed.ReceiverIndex, receiverIdx)
	}

	if parsed.Counter != counter {
		t.Errorf("Counter = %d, want %d", parsed.Counter, counter)
	}

	if !bytes.Equal(parsed.Ciphertext, ciphertext) {
		t.Errorf("Ciphertext mismatch")
	}
}

func TestTransportMessageTooShort(t *testing.T) {
	// Too short message
	_, err := ParseTransportMessage([]byte{MessageTypeTransport, 1, 2, 3})
	if err != ErrMessageTooShort {
		t.Errorf("ParseTransportMessage() error = %v, want ErrMessageTooShort", err)
	}
}

func TestTransportMessageWrongType(t *testing.T) {
	// Build with wrong type
	msg := make([]byte, TransportHeaderSize+TagSize)
	msg[0] = MessageTypeHandshakeInit // Wrong type

	_, err := ParseTransportMessage(msg)
	if err != ErrInvalidMessageType {
		t.Errorf("ParseTransportMessage() error = %v, want ErrInvalidMessageType", err)
	}
}

func TestPayloadEncodeDecode(t *testing.T) {
	protocol := ProtocolUDP
	payload := []byte("hello world")

	encoded := EncodePayload(protocol, payload)

	if encoded[0] != protocol {
		t.Errorf("encoded[0] = %d, want %d", encoded[0], protocol)
	}

	if !bytes.Equal(encoded[1:], payload) {
		t.Errorf("encoded payload mismatch")
	}

	// Decode
	decodedProto, decodedPayload, err := DecodePayload(encoded)
	if err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}

	if decodedProto != protocol {
		t.Errorf("decoded protocol = %d, want %d", decodedProto, protocol)
	}

	if !bytes.Equal(decodedPayload, payload) {
		t.Errorf("decoded payload mismatch")
	}
}

func TestPayloadDecodeEmpty(t *testing.T) {
	_, _, err := DecodePayload([]byte{})
	if err != ErrMessageTooShort {
		t.Errorf("DecodePayload() error = %v, want ErrMessageTooShort", err)
	}
}

func TestPayloadDecodeProtocolOnly(t *testing.T) {
	proto, payload, err := DecodePayload([]byte{ProtocolTCP})
	if err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}

	if proto != ProtocolTCP {
		t.Errorf("protocol = %d, want %d", proto, ProtocolTCP)
	}

	if len(payload) != 0 {
		t.Errorf("payload length = %d, want 0", len(payload))
	}
}

func TestHandshakeInitMessage(t *testing.T) {
	senderIdx := uint32(11111)
	var ephemeral Key
	copy(ephemeral[:], bytes.Repeat([]byte{0xAA}, KeySize))
	staticEnc := bytes.Repeat([]byte{0xBB}, 48)

	msg := BuildHandshakeInit(senderIdx, ephemeral, staticEnc)

	// Check length
	if len(msg) != HandshakeInitSize {
		t.Errorf("message length = %d, want %d", len(msg), HandshakeInitSize)
	}

	// Parse it back
	parsed, err := ParseHandshakeInit(msg)
	if err != nil {
		t.Fatalf("ParseHandshakeInit() error = %v", err)
	}

	if parsed.SenderIndex != senderIdx {
		t.Errorf("SenderIndex = %d, want %d", parsed.SenderIndex, senderIdx)
	}

	if parsed.Ephemeral != ephemeral {
		t.Errorf("Ephemeral mismatch")
	}

	if !bytes.Equal(parsed.Static, staticEnc) {
		t.Errorf("Static mismatch")
	}
}

func TestHandshakeInitTooShort(t *testing.T) {
	_, err := ParseHandshakeInit([]byte{MessageTypeHandshakeInit, 1, 2, 3})
	if err != ErrMessageTooShort {
		t.Errorf("ParseHandshakeInit() error = %v, want ErrMessageTooShort", err)
	}
}

func TestHandshakeInitWrongType(t *testing.T) {
	msg := make([]byte, HandshakeInitSize)
	msg[0] = MessageTypeTransport // Wrong type

	_, err := ParseHandshakeInit(msg)
	if err != ErrInvalidMessageType {
		t.Errorf("ParseHandshakeInit() error = %v, want ErrInvalidMessageType", err)
	}
}

func TestHandshakeRespMessage(t *testing.T) {
	senderIdx := uint32(22222)
	receiverIdx := uint32(33333)
	var ephemeral Key
	copy(ephemeral[:], bytes.Repeat([]byte{0xDD}, KeySize))
	empty := bytes.Repeat([]byte{0xEE}, 16)

	msg := BuildHandshakeResp(senderIdx, receiverIdx, ephemeral, empty)

	// Check length
	if len(msg) != HandshakeRespSize {
		t.Errorf("message length = %d, want %d", len(msg), HandshakeRespSize)
	}

	// Parse it back
	parsed, err := ParseHandshakeResp(msg)
	if err != nil {
		t.Fatalf("ParseHandshakeResp() error = %v", err)
	}

	if parsed.SenderIndex != senderIdx {
		t.Errorf("SenderIndex = %d, want %d", parsed.SenderIndex, senderIdx)
	}

	if parsed.ReceiverIndex != receiverIdx {
		t.Errorf("ReceiverIndex = %d, want %d", parsed.ReceiverIndex, receiverIdx)
	}

	if parsed.Ephemeral != ephemeral {
		t.Errorf("Ephemeral mismatch")
	}

	if !bytes.Equal(parsed.Empty, empty) {
		t.Errorf("Empty mismatch")
	}
}

func TestHandshakeRespTooShort(t *testing.T) {
	_, err := ParseHandshakeResp([]byte{MessageTypeHandshakeResp, 1, 2, 3})
	if err != ErrMessageTooShort {
		t.Errorf("ParseHandshakeResp() error = %v, want ErrMessageTooShort", err)
	}
}

func TestHandshakeRespWrongType(t *testing.T) {
	msg := make([]byte, HandshakeRespSize)
	msg[0] = MessageTypeTransport // Wrong type

	_, err := ParseHandshakeResp(msg)
	if err != ErrInvalidMessageType {
		t.Errorf("ParseHandshakeResp() error = %v, want ErrInvalidMessageType", err)
	}
}

func TestGetMessageType(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    byte
		wantErr error
	}{
		{"handshake init", []byte{MessageTypeHandshakeInit}, MessageTypeHandshakeInit, nil},
		{"handshake resp", []byte{MessageTypeHandshakeResp}, MessageTypeHandshakeResp, nil},
		{"transport", []byte{MessageTypeTransport}, MessageTypeTransport, nil},
		{"empty", []byte{}, 0, ErrMessageTooShort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetMessageType(tt.data)
			if err != tt.wantErr {
				t.Errorf("GetMessageType() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("GetMessageType() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestProtocolConstants(t *testing.T) {
	// Verify protocol constants match expected values
	tests := []struct {
		name     string
		protocol byte
		want     byte
	}{
		{"ICMP", ProtocolICMP, 1},
		{"IP", ProtocolIP, 4},
		{"TCP", ProtocolTCP, 6},
		{"UDP", ProtocolUDP, 17},
		{"KCP", ProtocolKCP, 64},
		{"UDPProxy", ProtocolUDPProxy, 65},
		{"Relay0", ProtocolRelay0, 66},
		{"Relay1", ProtocolRelay1, 67},
		{"Relay2", ProtocolRelay2, 68},
		{"Chat", ProtocolChat, 128},
		{"File", ProtocolFile, 129},
		{"Media", ProtocolMedia, 130},
		{"Signal", ProtocolSignal, 131},
		{"RPC", ProtocolRPC, 132},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.protocol != tt.want {
				t.Errorf("Protocol%s = %d, want %d", tt.name, tt.protocol, tt.want)
			}
		})
	}
}

func TestMessageTypeConstants(t *testing.T) {
	if MessageTypeHandshakeInit != 1 {
		t.Errorf("MessageTypeHandshakeInit = %d, want 1", MessageTypeHandshakeInit)
	}
	if MessageTypeHandshakeResp != 2 {
		t.Errorf("MessageTypeHandshakeResp = %d, want 2", MessageTypeHandshakeResp)
	}
	if MessageTypeCookieReply != 3 {
		t.Errorf("MessageTypeCookieReply = %d, want 3", MessageTypeCookieReply)
	}
	if MessageTypeTransport != 4 {
		t.Errorf("MessageTypeTransport = %d, want 4", MessageTypeTransport)
	}
}
