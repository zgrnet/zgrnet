package dns

import (
	"bytes"
	"testing"
)

func TestEncodeName(t *testing.T) {
	tests := []struct {
		name    string
		want    []byte
		wantErr bool
	}{
		{"example.com", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, false},
		{"a.b.c", []byte{1, 'a', 1, 'b', 1, 'c', 0}, false},
		{".", []byte{0}, false},
		{"", []byte{0}, false},
		{"example.com.", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeName(tt.name)
			if (err != nil) != tt.wantErr {
				t.Fatalf("encodeName(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("encodeName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestEncodeNameErrors(t *testing.T) {
	// Label too long (66 chars > 63 max)
	_, err := encodeName("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com")
	if err != ErrLabelTooLong {
		t.Errorf("expected ErrLabelTooLong, got %v", err)
	}

	// Empty label (double dot)
	_, err = encodeName("example..com")
	if err != ErrInvalidName {
		t.Errorf("expected ErrInvalidName for double dot, got %v", err)
	}
}

func TestDecodeName(t *testing.T) {
	// Simple name: example.com
	data := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	name, consumed, err := decodeName(data, 0)
	if err != nil {
		t.Fatalf("decodeName error: %v", err)
	}
	if name != "example.com" {
		t.Errorf("got %q, want %q", name, "example.com")
	}
	if consumed != 13 {
		t.Errorf("consumed = %d, want 13", consumed)
	}

	// Root label
	data = []byte{0}
	name, consumed, err = decodeName(data, 0)
	if err != nil {
		t.Fatalf("decodeName error: %v", err)
	}
	if name != "." {
		t.Errorf("got %q, want %q", name, ".")
	}
	if consumed != 1 {
		t.Errorf("consumed = %d, want 1", consumed)
	}
}

func TestDecodeNameCompression(t *testing.T) {
	// Build a packet with compression:
	// offset 0: "example.com" (13 bytes)
	// offset 13: pointer to offset 0 (2 bytes)
	data := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // offset 0-12
		0xC0, 0x00, // pointer to offset 0
	}

	name, consumed, err := decodeName(data, 13)
	if err != nil {
		t.Fatalf("decodeName with pointer: %v", err)
	}
	if name != "example.com" {
		t.Errorf("got %q, want %q", name, "example.com")
	}
	if consumed != 2 {
		t.Errorf("consumed = %d, want 2", consumed)
	}
}

func TestDecodeNamePointerLoop(t *testing.T) {
	// Self-referencing pointer at offset 0
	data := []byte{0xC0, 0x00}
	_, _, err := decodeName(data, 0)
	if err != ErrPointerLoop {
		t.Errorf("expected ErrPointerLoop, got %v", err)
	}
}

func TestMessageRoundtrip(t *testing.T) {
	// Build a query
	query := &Message{
		Header: Header{
			ID:    0x1234,
			Flags: FlagRD,
		},
		Questions: []Question{
			{Name: "example.com", Type: TypeA, Class: ClassIN},
		},
	}

	encoded, err := EncodeMessage(query)
	if err != nil {
		t.Fatalf("EncodeMessage: %v", err)
	}

	decoded, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	if decoded.Header.ID != 0x1234 {
		t.Errorf("ID = 0x%04x, want 0x1234", decoded.Header.ID)
	}
	if decoded.Header.Flags != FlagRD {
		t.Errorf("Flags = 0x%04x, want 0x%04x", decoded.Header.Flags, FlagRD)
	}
	if len(decoded.Questions) != 1 {
		t.Fatalf("len(Questions) = %d, want 1", len(decoded.Questions))
	}
	if decoded.Questions[0].Name != "example.com" {
		t.Errorf("Name = %q, want %q", decoded.Questions[0].Name, "example.com")
	}
	if decoded.Questions[0].Type != TypeA {
		t.Errorf("Type = %d, want %d", decoded.Questions[0].Type, TypeA)
	}
}

func TestResponseRoundtrip(t *testing.T) {
	query := &Message{
		Header: Header{
			ID:    0xABCD,
			Flags: FlagRD,
		},
		Questions: []Question{
			{Name: "localhost.zigor.net", Type: TypeA, Class: ClassIN},
		},
	}

	resp := NewResponse(query, RCodeNoError)
	resp.Answers = []ResourceRecord{
		NewARecord("localhost.zigor.net", 60, [4]byte{100, 64, 0, 1}),
	}

	encoded, err := EncodeMessage(resp)
	if err != nil {
		t.Fatalf("EncodeMessage response: %v", err)
	}

	decoded, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeMessage response: %v", err)
	}

	if !decoded.Header.IsResponse() {
		t.Error("expected response flag set")
	}
	if decoded.Header.ID != 0xABCD {
		t.Errorf("ID = 0x%04x, want 0xABCD", decoded.Header.ID)
	}
	if decoded.Header.RCode() != RCodeNoError {
		t.Errorf("RCode = %d, want %d", decoded.Header.RCode(), RCodeNoError)
	}
	if len(decoded.Answers) != 1 {
		t.Fatalf("len(Answers) = %d, want 1", len(decoded.Answers))
	}

	ans := decoded.Answers[0]
	if ans.Name != "localhost.zigor.net" {
		t.Errorf("Answer Name = %q, want %q", ans.Name, "localhost.zigor.net")
	}
	if ans.Type != TypeA {
		t.Errorf("Answer Type = %d, want %d", ans.Type, TypeA)
	}
	if ans.TTL != 60 {
		t.Errorf("Answer TTL = %d, want 60", ans.TTL)
	}
	if !bytes.Equal(ans.RData, []byte{100, 64, 0, 1}) {
		t.Errorf("Answer RData = %v, want [100 64 0 1]", ans.RData)
	}
}

func TestAAAARecordRoundtrip(t *testing.T) {
	query := &Message{
		Header: Header{ID: 0x5678, Flags: FlagRD},
		Questions: []Question{
			{Name: "test.zigor.net", Type: TypeAAAA, Class: ClassIN},
		},
	}

	resp := NewResponse(query, RCodeNoError)
	ipv6 := [16]byte{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	resp.Answers = []ResourceRecord{
		NewAAAARecord("test.zigor.net", 60, ipv6),
	}

	encoded, err := EncodeMessage(resp)
	if err != nil {
		t.Fatalf("EncodeMessage AAAA: %v", err)
	}

	decoded, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeMessage AAAA: %v", err)
	}

	if len(decoded.Answers) != 1 {
		t.Fatalf("len(Answers) = %d, want 1", len(decoded.Answers))
	}
	ans := decoded.Answers[0]
	if ans.Type != TypeAAAA {
		t.Errorf("Type = %d, want %d", ans.Type, TypeAAAA)
	}
	if !bytes.Equal(ans.RData, ipv6[:]) {
		t.Errorf("RData = %v, want %v", ans.RData, ipv6[:])
	}
}

func TestNXDomainResponse(t *testing.T) {
	query := &Message{
		Header: Header{ID: 0x9999, Flags: FlagRD},
		Questions: []Question{
			{Name: "nonexistent.zigor.net", Type: TypeA, Class: ClassIN},
		},
	}

	resp := NewResponse(query, RCodeNXDomain)

	encoded, err := EncodeMessage(resp)
	if err != nil {
		t.Fatalf("EncodeMessage NXDOMAIN: %v", err)
	}

	decoded, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeMessage NXDOMAIN: %v", err)
	}

	if decoded.Header.RCode() != RCodeNXDomain {
		t.Errorf("RCode = %d, want %d", decoded.Header.RCode(), RCodeNXDomain)
	}
	if len(decoded.Answers) != 0 {
		t.Errorf("len(Answers) = %d, want 0", len(decoded.Answers))
	}
}

func TestDecodeMessageTruncated(t *testing.T) {
	// Too short for header
	_, err := DecodeMessage([]byte{0, 1, 2})
	if err != ErrInvalidHeader {
		t.Errorf("expected ErrInvalidHeader, got %v", err)
	}

	// Header says 1 question but no data follows
	data := make([]byte, 12)
	data[4] = 0 // QDCount high
	data[5] = 1 // QDCount low
	_, err = DecodeMessage(data)
	if err == nil {
		t.Error("expected error for truncated question section")
	}
}

func TestMultipleQuestions(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 0x1111, Flags: FlagRD},
		Questions: []Question{
			{Name: "a.com", Type: TypeA, Class: ClassIN},
			{Name: "b.com", Type: TypeAAAA, Class: ClassIN},
		},
	}

	encoded, err := EncodeMessage(msg)
	if err != nil {
		t.Fatalf("EncodeMessage: %v", err)
	}

	decoded, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	if len(decoded.Questions) != 2 {
		t.Fatalf("len(Questions) = %d, want 2", len(decoded.Questions))
	}
	if decoded.Questions[0].Name != "a.com" {
		t.Errorf("Q0.Name = %q, want %q", decoded.Questions[0].Name, "a.com")
	}
	if decoded.Questions[1].Name != "b.com" {
		t.Errorf("Q1.Name = %q, want %q", decoded.Questions[1].Name, "b.com")
	}
	if decoded.Questions[1].Type != TypeAAAA {
		t.Errorf("Q1.Type = %d, want %d", decoded.Questions[1].Type, TypeAAAA)
	}
}

func TestQuestionString(t *testing.T) {
	q := Question{Name: "example.com", Type: TypeA, Class: ClassIN}
	if q.String() != "example.com A" {
		t.Errorf("String() = %q, want %q", q.String(), "example.com A")
	}

	q2 := Question{Name: "example.com", Type: TypeAAAA, Class: ClassIN}
	if q2.String() != "example.com AAAA" {
		t.Errorf("String() = %q, want %q", q2.String(), "example.com AAAA")
	}
}
