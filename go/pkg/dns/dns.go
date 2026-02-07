// Package dns implements a minimal DNS protocol parser and Magic DNS server.
//
// This package provides DNS message encode/decode for A and AAAA queries,
// a Magic DNS server that resolves *.zigor.net domains, upstream forwarding,
// and a Fake IP pool for route-matched domains.
package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// DNS record types.
const (
	TypeA     uint16 = 1  // IPv4 address
	TypeAAAA  uint16 = 28 // IPv6 address
	ClassIN   uint16 = 1  // Internet class
	MaxUDPLen        = 512 // Max UDP DNS message size (without EDNS)
)

// DNS header flag bits.
const (
	FlagQR     uint16 = 1 << 15 // Query/Response
	FlagAA     uint16 = 1 << 10 // Authoritative Answer
	FlagTC     uint16 = 1 << 9  // Truncated
	FlagRD     uint16 = 1 << 8  // Recursion Desired
	FlagRA     uint16 = 1 << 7  // Recursion Available
	MaskOpcode uint16 = 0x7800  // Opcode bits [14:11]
	MaskRCode  uint16 = 0x000F  // Response code bits [3:0]
)

// DNS response codes.
const (
	RCodeNoError  uint16 = 0 // No error
	RCodeFormErr  uint16 = 1 // Format error
	RCodeServFail uint16 = 2 // Server failure
	RCodeNXDomain uint16 = 3 // Non-existent domain
	RCodeNotImpl  uint16 = 4 // Not implemented
	RCodeRefused  uint16 = 5 // Query refused
)

// Errors.
var (
	ErrTruncated     = errors.New("dns: message truncated")
	ErrInvalidHeader = errors.New("dns: invalid header")
	ErrInvalidName   = errors.New("dns: invalid name")
	ErrNameTooLong   = errors.New("dns: name too long")
	ErrLabelTooLong  = errors.New("dns: label too long (max 63)")
	ErrPointerLoop   = errors.New("dns: compression pointer loop")
	ErrInvalidRData  = errors.New("dns: invalid rdata")
)

// Header represents a DNS message header (12 bytes).
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16 // Number of questions
	ANCount uint16 // Number of answers
	NSCount uint16 // Number of authority records
	ARCount uint16 // Number of additional records
}

// IsResponse returns true if this is a response message.
func (h *Header) IsResponse() bool { return h.Flags&FlagQR != 0 }

// Opcode returns the opcode field.
func (h *Header) Opcode() uint16 { return (h.Flags & MaskOpcode) >> 11 }

// RCode returns the response code.
func (h *Header) RCode() uint16 { return h.Flags & MaskRCode }

// Question represents a DNS question entry.
type Question struct {
	Name  string // Fully qualified domain name
	Type  uint16 // QTYPE (TypeA, TypeAAAA, etc.)
	Class uint16 // QCLASS (ClassIN)
}

// ResourceRecord represents a DNS resource record.
type ResourceRecord struct {
	Name  string // Domain name
	Type  uint16 // Record type
	Class uint16 // Record class
	TTL   uint32 // Time to live (seconds)
	RData []byte // Record data (4 bytes for A, 16 bytes for AAAA)
}

// Message represents a complete DNS message.
type Message struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additionals []ResourceRecord
}

// DecodeMessage decodes a DNS message from wire format.
func DecodeMessage(data []byte) (*Message, error) {
	if len(data) < 12 {
		return nil, ErrInvalidHeader
	}

	msg := &Message{}
	msg.Header = Header{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}

	offset := 12

	// Decode questions
	for i := 0; i < int(msg.Header.QDCount); i++ {
		name, n, err := decodeName(data, offset)
		if err != nil {
			return nil, err
		}
		offset += n
		if offset+4 > len(data) {
			return nil, ErrTruncated
		}
		q := Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
			Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
		}
		offset += 4
		msg.Questions = append(msg.Questions, q)
	}

	// Decode answers
	var err error
	msg.Answers, offset, err = decodeRRs(data, offset, int(msg.Header.ANCount))
	if err != nil {
		return nil, err
	}

	// Decode authorities
	msg.Authorities, offset, err = decodeRRs(data, offset, int(msg.Header.NSCount))
	if err != nil {
		return nil, err
	}

	// Decode additionals
	msg.Additionals, _, err = decodeRRs(data, offset, int(msg.Header.ARCount))
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// EncodeMessage encodes a DNS message to wire format.
func EncodeMessage(msg *Message) ([]byte, error) {
	buf := make([]byte, 12, 512) // Start with header, grow as needed

	// Encode header
	binary.BigEndian.PutUint16(buf[0:2], msg.Header.ID)
	binary.BigEndian.PutUint16(buf[2:4], msg.Header.Flags)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(msg.Questions)))
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(msg.Answers)))
	binary.BigEndian.PutUint16(buf[8:10], uint16(len(msg.Authorities)))
	binary.BigEndian.PutUint16(buf[10:12], uint16(len(msg.Additionals)))

	// Encode questions
	for _, q := range msg.Questions {
		nameBytes, err := encodeName(q.Name)
		if err != nil {
			return nil, err
		}
		buf = append(buf, nameBytes...)
		buf = binary.BigEndian.AppendUint16(buf, q.Type)
		buf = binary.BigEndian.AppendUint16(buf, q.Class)
	}

	// Encode resource records
	for _, rr := range msg.Answers {
		b, err := encodeRR(&rr)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	for _, rr := range msg.Authorities {
		b, err := encodeRR(&rr)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	for _, rr := range msg.Additionals {
		b, err := encodeRR(&rr)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}

	return buf, nil
}

// NewResponse creates a response message for the given query.
func NewResponse(query *Message, rcode uint16) *Message {
	return &Message{
		Header: Header{
			ID:    query.Header.ID,
			Flags: FlagQR | FlagAA | (query.Header.Flags & FlagRD) | rcode,
		},
		Questions: query.Questions,
	}
}

// NewARecord creates an A resource record.
func NewARecord(name string, ttl uint32, ip [4]byte) ResourceRecord {
	return ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   ttl,
		RData: ip[:],
	}
}

// NewAAAARecord creates an AAAA resource record.
func NewAAAARecord(name string, ttl uint32, ip [16]byte) ResourceRecord {
	return ResourceRecord{
		Name:  name,
		Type:  TypeAAAA,
		Class: ClassIN,
		TTL:   ttl,
		RData: ip[:],
	}
}

// encodeName encodes a domain name to wire format.
// Example: "example.com" -> [7]example[3]com[0]
func encodeName(name string) ([]byte, error) {
	if name == "" || name == "." {
		return []byte{0}, nil
	}

	// Remove trailing dot if present
	name = strings.TrimSuffix(name, ".")

	labels := strings.Split(name, ".")
	var buf []byte
	totalLen := 0

	for _, label := range labels {
		if len(label) == 0 {
			return nil, ErrInvalidName
		}
		if len(label) > 63 {
			return nil, ErrLabelTooLong
		}
		totalLen += 1 + len(label)
		if totalLen > 253 {
			return nil, ErrNameTooLong
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0) // Root label
	return buf, nil
}

// decodeName decodes a domain name from wire format, handling compression pointers.
// Returns the name, number of bytes consumed from offset, and any error.
func decodeName(data []byte, offset int) (string, int, error) {
	var labels []string
	consumed := 0
	jumped := false
	pos := offset
	seen := make(map[int]bool) // Detect pointer loops

	for {
		if pos >= len(data) {
			return "", 0, ErrTruncated
		}

		length := int(data[pos])

		if length == 0 {
			// Root label - end of name
			if !jumped {
				consumed = pos - offset + 1
			}
			break
		}

		// Check for compression pointer (top 2 bits set)
		if length&0xC0 == 0xC0 {
			if pos+1 >= len(data) {
				return "", 0, ErrTruncated
			}
			if !jumped {
				consumed = pos - offset + 2
			}
			ptr := int(binary.BigEndian.Uint16(data[pos:pos+2]) & 0x3FFF)
			if seen[ptr] {
				return "", 0, ErrPointerLoop
			}
			seen[ptr] = true
			pos = ptr
			jumped = true
			continue
		}

		// Regular label
		pos++
		if pos+length > len(data) {
			return "", 0, ErrTruncated
		}
		labels = append(labels, string(data[pos:pos+length]))
		pos += length
	}

	if len(labels) == 0 {
		return ".", consumed, nil
	}
	return strings.Join(labels, "."), consumed, nil
}

// decodeRRs decodes a slice of resource records.
func decodeRRs(data []byte, offset int, count int) ([]ResourceRecord, int, error) {
	var rrs []ResourceRecord
	for i := 0; i < count; i++ {
		name, n, err := decodeName(data, offset)
		if err != nil {
			return nil, offset, err
		}
		offset += n

		if offset+10 > len(data) {
			return nil, offset, ErrTruncated
		}

		rr := ResourceRecord{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
			Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
			TTL:   binary.BigEndian.Uint32(data[offset+4 : offset+8]),
		}
		rdLen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if offset+int(rdLen) > len(data) {
			return nil, offset, ErrTruncated
		}
		rr.RData = make([]byte, rdLen)
		copy(rr.RData, data[offset:offset+int(rdLen)])
		offset += int(rdLen)

		rrs = append(rrs, rr)
	}
	return rrs, offset, nil
}

// encodeRR encodes a resource record to wire format.
func encodeRR(rr *ResourceRecord) ([]byte, error) {
	nameBytes, err := encodeName(rr.Name)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, len(nameBytes)+10+len(rr.RData))
	buf = append(buf, nameBytes...)
	buf = binary.BigEndian.AppendUint16(buf, rr.Type)
	buf = binary.BigEndian.AppendUint16(buf, rr.Class)
	buf = binary.BigEndian.AppendUint32(buf, rr.TTL)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(rr.RData)))
	buf = append(buf, rr.RData...)
	return buf, nil
}


// FormatQuestion returns a human-readable representation of a question.
func (q *Question) String() string {
	typeName := fmt.Sprintf("TYPE%d", q.Type)
	switch q.Type {
	case TypeA:
		typeName = "A"
	case TypeAAAA:
		typeName = "AAAA"
	}
	return fmt.Sprintf("%s %s", q.Name, typeName)
}
