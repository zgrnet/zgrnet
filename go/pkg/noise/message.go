package noise

import (
	"encoding/binary"
	"errors"
)

// Message types for the wire protocol.
const (
	// MessageTypeHandshakeInit is a handshake initiation message (Type 1).
	MessageTypeHandshakeInit byte = 1
	// MessageTypeHandshakeResp is a handshake response message (Type 2).
	MessageTypeHandshakeResp byte = 2
	// MessageTypeCookieReply is a cookie reply for DoS protection (Type 3).
	MessageTypeCookieReply byte = 3
	// MessageTypeTransport is an encrypted transport message (Type 4).
	MessageTypeTransport byte = 4
)

// Protocol field values (inside encrypted payload).
const (
	// Transport layer protocols (0-63, matching IP protocol numbers)
	ProtocolRaw  byte = 0  // Raw data (default for WriteTo)
	ProtocolICMP byte = 1  // ICMP in ZigNet (no IP header)
	ProtocolIP   byte = 4  // IP in ZigNet (complete IP packet)
	ProtocolTCP  byte = 6  // TCP in ZigNet (no IP header)
	ProtocolUDP  byte = 17 // UDP in ZigNet (no IP header)

	// ZigNet extension protocols (64-127)
	ProtocolKCP      byte = 64 // KCP reliable UDP
	ProtocolUDPProxy byte = 65 // UDP proxy
	ProtocolRelay0   byte = 66 // Relay first hop
	ProtocolRelay1   byte = 67 // Relay middle hop
	ProtocolRelay2   byte = 68 // Relay last hop
	ProtocolTCPProxy byte = 69 // TCP proxy via KCP stream
	ProtocolPing     byte = 70 // Ping probe request
	ProtocolPong     byte = 71 // Pong probe response

	// Application layer protocols (128-255)
	ProtocolChat   byte = 128 // Chat messages
	ProtocolFile   byte = 129 // File transfer
	ProtocolMedia  byte = 130 // Audio/video streams
	ProtocolSignal byte = 131 // Signaling (WebRTC, etc.)
	ProtocolRPC    byte = 132 // Remote procedure calls
)

// Message size constants.
const (
	// HandshakeInitSize is the size of a handshake initiation message.
	// type(1) + sender_idx(4) + ephemeral(32) + static_enc(48) = 85
	// Note: Noise IK first message = e(32) + encrypted_s(32+16) = 80 bytes
	// Payload encryption only happens on the last message of handshake.
	HandshakeInitSize = 1 + 4 + 32 + 48

	// HandshakeRespSize is the size of a handshake response message.
	// type(1) + sender_idx(4) + receiver_idx(4) + ephemeral(32) + encrypted_empty(16) = 57
	// Note: Noise IK second (last) message = e(32) + encrypted_empty(0+16) = 48 bytes
	HandshakeRespSize = 1 + 4 + 4 + 32 + 16

	// TransportHeaderSize is the size of the transport message header.
	// type(1) + receiver_idx(4) + counter(8) = 13
	TransportHeaderSize = 1 + 4 + 8

	// MaxPayloadSize is the maximum payload size (64KB - headers - tag).
	MaxPayloadSize = 65535 - TransportHeaderSize - TagSize - 1 // -1 for protocol byte

	// MaxPacketSize is the maximum packet size we accept.
	MaxPacketSize = 65535
)

// TransportMessage represents a parsed transport message (Type 4).
type TransportMessage struct {
	ReceiverIndex uint32
	Counter       uint64
	Ciphertext    []byte // Includes the 16-byte auth tag
}

// ParseTransportMessage parses a raw transport message.
func ParseTransportMessage(data []byte) (*TransportMessage, error) {
	if len(data) < TransportHeaderSize+TagSize {
		return nil, ErrMessageTooShort
	}

	if data[0] != MessageTypeTransport {
		return nil, ErrInvalidMessageType
	}

	return &TransportMessage{
		ReceiverIndex: binary.LittleEndian.Uint32(data[1:5]),
		Counter:       binary.LittleEndian.Uint64(data[5:13]),
		Ciphertext:    data[13:],
	}, nil
}

// BuildTransportMessage builds a transport message from components.
func BuildTransportMessage(receiverIndex uint32, counter uint64, ciphertext []byte) []byte {
	msg := make([]byte, TransportHeaderSize+len(ciphertext))
	msg[0] = MessageTypeTransport
	binary.LittleEndian.PutUint32(msg[1:5], receiverIndex)
	binary.LittleEndian.PutUint64(msg[5:13], counter)
	copy(msg[13:], ciphertext)
	return msg
}

// EncodePayload prepends the protocol byte to the payload.
func EncodePayload(protocol byte, payload []byte) []byte {
	result := make([]byte, 1+len(payload))
	result[0] = protocol
	copy(result[1:], payload)
	return result
}

// DecodePayload extracts the protocol byte and payload.
func DecodePayload(data []byte) (protocol byte, payload []byte, err error) {
	if len(data) < 1 {
		return 0, nil, ErrMessageTooShort
	}
	return data[0], data[1:], nil
}

// HandshakeInitMessage represents a parsed handshake initiation (Type 1).
type HandshakeInitMessage struct {
	SenderIndex uint32
	Ephemeral   Key
	Static      []byte // Encrypted static key (48 bytes = 32B key + 16B tag)
}

// ParseHandshakeInit parses a handshake initiation message.
func ParseHandshakeInit(data []byte) (*HandshakeInitMessage, error) {
	if len(data) < HandshakeInitSize {
		return nil, ErrMessageTooShort
	}

	if data[0] != MessageTypeHandshakeInit {
		return nil, ErrInvalidMessageType
	}

	msg := &HandshakeInitMessage{
		SenderIndex: binary.LittleEndian.Uint32(data[1:5]),
	}
	copy(msg.Ephemeral[:], data[5:37])
	msg.Static = make([]byte, 48)
	copy(msg.Static, data[37:85])

	return msg, nil
}

// BuildHandshakeInit builds a handshake initiation message.
func BuildHandshakeInit(senderIndex uint32, ephemeral Key, staticEnc []byte) []byte {
	msg := make([]byte, HandshakeInitSize)
	msg[0] = MessageTypeHandshakeInit
	binary.LittleEndian.PutUint32(msg[1:5], senderIndex)
	copy(msg[5:37], ephemeral[:])
	copy(msg[37:85], staticEnc)
	return msg
}

// HandshakeRespMessage represents a parsed handshake response (Type 2).
type HandshakeRespMessage struct {
	SenderIndex   uint32
	ReceiverIndex uint32
	Ephemeral     Key
	Empty         []byte // Encrypted empty (16 bytes, just tag)
}

// ParseHandshakeResp parses a handshake response message.
func ParseHandshakeResp(data []byte) (*HandshakeRespMessage, error) {
	if len(data) < HandshakeRespSize {
		return nil, ErrMessageTooShort
	}

	if data[0] != MessageTypeHandshakeResp {
		return nil, ErrInvalidMessageType
	}

	msg := &HandshakeRespMessage{
		SenderIndex:   binary.LittleEndian.Uint32(data[1:5]),
		ReceiverIndex: binary.LittleEndian.Uint32(data[5:9]),
	}
	copy(msg.Ephemeral[:], data[9:41])
	msg.Empty = make([]byte, 16)
	copy(msg.Empty, data[41:57])

	return msg, nil
}

// BuildHandshakeResp builds a handshake response message.
func BuildHandshakeResp(senderIndex, receiverIndex uint32, ephemeral Key, empty []byte) []byte {
	msg := make([]byte, HandshakeRespSize)
	msg[0] = MessageTypeHandshakeResp
	binary.LittleEndian.PutUint32(msg[1:5], senderIndex)
	binary.LittleEndian.PutUint32(msg[5:9], receiverIndex)
	copy(msg[9:41], ephemeral[:])
	copy(msg[41:57], empty)
	return msg
}

// GetMessageType returns the message type from a raw packet.
func GetMessageType(data []byte) (byte, error) {
	if len(data) < 1 {
		return 0, ErrMessageTooShort
	}
	return data[0], nil
}

// Message errors.
var (
	ErrMessageTooShort    = errors.New("noise: message too short")
	ErrInvalidMessageType = errors.New("noise: invalid message type")
	ErrInvalidAddress     = errors.New("noise: invalid address type")
)
