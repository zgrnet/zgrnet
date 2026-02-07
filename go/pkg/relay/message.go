// Package relay implements the Relay protocol for multi-hop forwarding.
//
// Relay messages travel inside encrypted Noise payloads. The protocol byte
// (66/67/68) is already stripped by noise.DecodePayload before these
// functions are called, so encode/decode only handle the fields after it.
package relay

import (
	"encoding/binary"
	"errors"
)

// Relay message header sizes (excluding the protocol byte which is handled by noise).
const (
	// Relay0HeaderSize: ttl(1) + strategy(1) + dst_key(32) = 34
	Relay0HeaderSize = 1 + 1 + 32

	// Relay1HeaderSize: ttl(1) + strategy(1) + src_key(32) + dst_key(32) = 66
	Relay1HeaderSize = 1 + 1 + 32 + 32

	// Relay2HeaderSize: src_key(32) = 32
	Relay2HeaderSize = 32
)

// Relay0 is the first-hop relay message (protocol 66).
// Sent by the originator to the first relay node.
// The source is implicit (the sender of the Noise session).
type Relay0 struct {
	TTL      byte
	Strategy Strategy
	DstKey   [32]byte
	Payload  []byte // End-to-end encrypted payload (A-B session)
}

// Relay1 is the middle-hop relay message (protocol 67).
// Forwarded between relay nodes. Carries both src and dst.
type Relay1 struct {
	TTL      byte
	Strategy Strategy
	SrcKey   [32]byte
	DstKey   [32]byte
	Payload  []byte // End-to-end encrypted payload (A-B session)
}

// Relay2 is the last-hop relay message (protocol 68).
// Sent by the last relay to the final destination.
// The destination is implicit (the receiver of the Noise session).
type Relay2 struct {
	SrcKey  [32]byte
	Payload []byte // End-to-end encrypted payload (A-B session)
}

// EncodeRelay0 serializes a Relay0 message.
func EncodeRelay0(r *Relay0) []byte {
	buf := make([]byte, Relay0HeaderSize+len(r.Payload))
	buf[0] = r.TTL
	buf[1] = byte(r.Strategy)
	copy(buf[2:34], r.DstKey[:])
	copy(buf[34:], r.Payload)
	return buf
}

// DecodeRelay0 deserializes a Relay0 message.
func DecodeRelay0(data []byte) (*Relay0, error) {
	if len(data) < Relay0HeaderSize {
		return nil, ErrTooShort
	}
	r := &Relay0{
		TTL:      data[0],
		Strategy: Strategy(data[1]),
	}
	copy(r.DstKey[:], data[2:34])
	r.Payload = data[34:]
	return r, nil
}

// EncodeRelay1 serializes a Relay1 message.
func EncodeRelay1(r *Relay1) []byte {
	buf := make([]byte, Relay1HeaderSize+len(r.Payload))
	buf[0] = r.TTL
	buf[1] = byte(r.Strategy)
	copy(buf[2:34], r.SrcKey[:])
	copy(buf[34:66], r.DstKey[:])
	copy(buf[66:], r.Payload)
	return buf
}

// DecodeRelay1 deserializes a Relay1 message.
func DecodeRelay1(data []byte) (*Relay1, error) {
	if len(data) < Relay1HeaderSize {
		return nil, ErrTooShort
	}
	r := &Relay1{
		TTL:      data[0],
		Strategy: Strategy(data[1]),
	}
	copy(r.SrcKey[:], data[2:34])
	copy(r.DstKey[:], data[34:66])
	r.Payload = data[66:]
	return r, nil
}

// EncodeRelay2 serializes a Relay2 message.
func EncodeRelay2(r *Relay2) []byte {
	buf := make([]byte, Relay2HeaderSize+len(r.Payload))
	copy(buf[0:32], r.SrcKey[:])
	copy(buf[32:], r.Payload)
	return buf
}

// DecodeRelay2 deserializes a Relay2 message.
func DecodeRelay2(data []byte) (*Relay2, error) {
	if len(data) < Relay2HeaderSize {
		return nil, ErrTooShort
	}
	r := &Relay2{}
	copy(r.SrcKey[:], data[0:32])
	r.Payload = data[32:]
	return r, nil
}

// Errors.
var (
	ErrTooShort   = errors.New("relay: message too short")
	ErrTTLExpired = errors.New("relay: TTL expired")
	ErrNoRoute    = errors.New("relay: no route to destination")
)

// DefaultTTL is the default time-to-live for relay messages.
const DefaultTTL byte = 8

// PingSize is the size of a Ping message body (excluding protocol byte).
// ping_id(4) + timestamp(8) = 12
const PingSize = 4 + 8

// PongSize is the size of a Pong message body (excluding protocol byte).
// ping_id(4) + timestamp(8) + load(1) + relay_count(2) + bw_avail(2) + price(4) = 21
const PongSize = 4 + 8 + 1 + 2 + 2 + 4

// Ping is a probe request message (protocol 70).
type Ping struct {
	PingID    uint32
	Timestamp uint64 // Nanoseconds
}

// Pong is a probe response message (protocol 71).
type Pong struct {
	PingID     uint32
	Timestamp  uint64 // Echoed from Ping
	Load       byte   // 0-255 (0=idle, 255=full)
	RelayCount uint16 // Active relay connections
	BwAvail    uint16 // Available bandwidth KB/s
	Price      uint32 // Price per MB in token smallest unit, 0=free
}

// EncodePing serializes a Ping message.
func EncodePing(p *Ping) []byte {
	buf := make([]byte, PingSize)
	binary.LittleEndian.PutUint32(buf[0:4], p.PingID)
	binary.LittleEndian.PutUint64(buf[4:12], p.Timestamp)
	return buf
}

// DecodePing deserializes a Ping message.
func DecodePing(data []byte) (*Ping, error) {
	if len(data) < PingSize {
		return nil, ErrTooShort
	}
	return &Ping{
		PingID:    binary.LittleEndian.Uint32(data[0:4]),
		Timestamp: binary.LittleEndian.Uint64(data[4:12]),
	}, nil
}

// EncodePong serializes a Pong message.
func EncodePong(p *Pong) []byte {
	buf := make([]byte, PongSize)
	binary.LittleEndian.PutUint32(buf[0:4], p.PingID)
	binary.LittleEndian.PutUint64(buf[4:12], p.Timestamp)
	buf[12] = p.Load
	binary.LittleEndian.PutUint16(buf[13:15], p.RelayCount)
	binary.LittleEndian.PutUint16(buf[15:17], p.BwAvail)
	binary.LittleEndian.PutUint32(buf[17:21], p.Price)
	return buf
}

// DecodePong deserializes a Pong message.
func DecodePong(data []byte) (*Pong, error) {
	if len(data) < PongSize {
		return nil, ErrTooShort
	}
	return &Pong{
		PingID:     binary.LittleEndian.Uint32(data[0:4]),
		Timestamp:  binary.LittleEndian.Uint64(data[4:12]),
		Load:       data[12],
		RelayCount: binary.LittleEndian.Uint16(data[13:15]),
		BwAvail:    binary.LittleEndian.Uint16(data[15:17]),
		Price:      binary.LittleEndian.Uint32(data[17:21]),
	}, nil
}
