package relay

import (
	"bytes"
	"testing"
)

func TestRelay0Roundtrip(t *testing.T) {
	var dstKey [32]byte
	for i := range dstKey {
		dstKey[i] = byte(i)
	}
	payload := []byte("hello relay world")

	orig := &Relay0{
		TTL:      8,
		Strategy: StrategyFastest,
		DstKey:   dstKey,
		Payload:  payload,
	}

	encoded := EncodeRelay0(orig)
	if len(encoded) != Relay0HeaderSize+len(payload) {
		t.Fatalf("encoded length: got %d, want %d", len(encoded), Relay0HeaderSize+len(payload))
	}

	decoded, err := DecodeRelay0(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.TTL != orig.TTL {
		t.Errorf("TTL: got %d, want %d", decoded.TTL, orig.TTL)
	}
	if decoded.Strategy != orig.Strategy {
		t.Errorf("Strategy: got %d, want %d", decoded.Strategy, orig.Strategy)
	}
	if decoded.DstKey != orig.DstKey {
		t.Errorf("DstKey mismatch")
	}
	if !bytes.Equal(decoded.Payload, orig.Payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestRelay0TooShort(t *testing.T) {
	_, err := DecodeRelay0(make([]byte, Relay0HeaderSize-1))
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestRelay0EmptyPayload(t *testing.T) {
	orig := &Relay0{TTL: 3, Strategy: StrategyAuto, DstKey: [32]byte{0xAA}}
	encoded := EncodeRelay0(orig)
	decoded, err := DecodeRelay0(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(decoded.Payload))
	}
}

func TestRelay1Roundtrip(t *testing.T) {
	var srcKey, dstKey [32]byte
	for i := range srcKey {
		srcKey[i] = byte(i)
		dstKey[i] = byte(i + 100)
	}
	payload := []byte("relay1 payload data")

	orig := &Relay1{
		TTL:      7,
		Strategy: StrategyCheapest,
		SrcKey:   srcKey,
		DstKey:   dstKey,
		Payload:  payload,
	}

	encoded := EncodeRelay1(orig)
	if len(encoded) != Relay1HeaderSize+len(payload) {
		t.Fatalf("encoded length: got %d, want %d", len(encoded), Relay1HeaderSize+len(payload))
	}

	decoded, err := DecodeRelay1(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.TTL != orig.TTL {
		t.Errorf("TTL: got %d, want %d", decoded.TTL, orig.TTL)
	}
	if decoded.Strategy != orig.Strategy {
		t.Errorf("Strategy: got %d, want %d", decoded.Strategy, orig.Strategy)
	}
	if decoded.SrcKey != orig.SrcKey {
		t.Errorf("SrcKey mismatch")
	}
	if decoded.DstKey != orig.DstKey {
		t.Errorf("DstKey mismatch")
	}
	if !bytes.Equal(decoded.Payload, orig.Payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestRelay1TooShort(t *testing.T) {
	_, err := DecodeRelay1(make([]byte, Relay1HeaderSize-1))
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestRelay2Roundtrip(t *testing.T) {
	var srcKey [32]byte
	for i := range srcKey {
		srcKey[i] = byte(i + 50)
	}
	payload := []byte("final hop payload")

	orig := &Relay2{
		SrcKey:  srcKey,
		Payload: payload,
	}

	encoded := EncodeRelay2(orig)
	if len(encoded) != Relay2HeaderSize+len(payload) {
		t.Fatalf("encoded length: got %d, want %d", len(encoded), Relay2HeaderSize+len(payload))
	}

	decoded, err := DecodeRelay2(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.SrcKey != orig.SrcKey {
		t.Errorf("SrcKey mismatch")
	}
	if !bytes.Equal(decoded.Payload, orig.Payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestRelay2TooShort(t *testing.T) {
	_, err := DecodeRelay2(make([]byte, Relay2HeaderSize-1))
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestPingRoundtrip(t *testing.T) {
	orig := &Ping{
		PingID:    12345,
		Timestamp: 9876543210,
	}

	encoded := EncodePing(orig)
	if len(encoded) != PingSize {
		t.Fatalf("encoded length: got %d, want %d", len(encoded), PingSize)
	}

	decoded, err := DecodePing(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.PingID != orig.PingID {
		t.Errorf("PingID: got %d, want %d", decoded.PingID, orig.PingID)
	}
	if decoded.Timestamp != orig.Timestamp {
		t.Errorf("Timestamp: got %d, want %d", decoded.Timestamp, orig.Timestamp)
	}
}

func TestPingTooShort(t *testing.T) {
	_, err := DecodePing(make([]byte, PingSize-1))
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestPongRoundtrip(t *testing.T) {
	orig := &Pong{
		PingID:     12345,
		Timestamp:  9876543210,
		Load:       128,
		RelayCount: 42,
		BwAvail:    1024,
		Price:      500,
	}

	encoded := EncodePong(orig)
	if len(encoded) != PongSize {
		t.Fatalf("encoded length: got %d, want %d", len(encoded), PongSize)
	}

	decoded, err := DecodePong(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.PingID != orig.PingID {
		t.Errorf("PingID: got %d, want %d", decoded.PingID, orig.PingID)
	}
	if decoded.Timestamp != orig.Timestamp {
		t.Errorf("Timestamp: got %d, want %d", decoded.Timestamp, orig.Timestamp)
	}
	if decoded.Load != orig.Load {
		t.Errorf("Load: got %d, want %d", decoded.Load, orig.Load)
	}
	if decoded.RelayCount != orig.RelayCount {
		t.Errorf("RelayCount: got %d, want %d", decoded.RelayCount, orig.RelayCount)
	}
	if decoded.BwAvail != orig.BwAvail {
		t.Errorf("BwAvail: got %d, want %d", decoded.BwAvail, orig.BwAvail)
	}
	if decoded.Price != orig.Price {
		t.Errorf("Price: got %d, want %d", decoded.Price, orig.Price)
	}
}

func TestPongTooShort(t *testing.T) {
	_, err := DecodePong(make([]byte, PongSize-1))
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestPongZeroPrice(t *testing.T) {
	orig := &Pong{
		PingID:    1,
		Timestamp: 2,
		Load:      0,
		Price:     0, // Free node
	}
	encoded := EncodePong(orig)
	decoded, err := DecodePong(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Price != 0 {
		t.Errorf("Price: got %d, want 0", decoded.Price)
	}
}

func TestStrategyConstants(t *testing.T) {
	if StrategyAuto != 0 {
		t.Errorf("StrategyAuto: got %d, want 0", StrategyAuto)
	}
	if StrategyFastest != 1 {
		t.Errorf("StrategyFastest: got %d, want 1", StrategyFastest)
	}
	if StrategyCheapest != 2 {
		t.Errorf("StrategyCheapest: got %d, want 2", StrategyCheapest)
	}
}

func TestRelay0BindRoundtrip(t *testing.T) {
	var dstKey [32]byte
	for i := range dstKey {
		dstKey[i] = byte(i)
	}
	orig := &Relay0Bind{RelayID: 0x1234, DstKey: dstKey}
	encoded := EncodeRelay0Bind(orig)
	if len(encoded) != Relay0BindSize {
		t.Fatalf("len: got %d, want %d", len(encoded), Relay0BindSize)
	}
	decoded, err := DecodeRelay0Bind(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RelayID != 0x1234 {
		t.Errorf("RelayID: got %d, want %d", decoded.RelayID, 0x1234)
	}
	if decoded.DstKey != dstKey {
		t.Error("DstKey mismatch")
	}
}

func TestRelay0BindTooShort(t *testing.T) {
	_, err := DecodeRelay0Bind(make([]byte, Relay0BindSize-1))
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestRelay0AliasRoundtrip(t *testing.T) {
	payload := []byte("alias payload data")
	orig := &Relay0Alias{RelayID: 0xABCD, Payload: payload}
	encoded := EncodeRelay0Alias(orig)
	if len(encoded) != 4+len(payload) {
		t.Fatalf("len: got %d, want %d", len(encoded), 4+len(payload))
	}
	decoded, err := DecodeRelay0Alias(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RelayID != 0xABCD {
		t.Errorf("RelayID: got %d, want %d", decoded.RelayID, 0xABCD)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Error("Payload mismatch")
	}
}

func TestRelay0AliasTooShort(t *testing.T) {
	_, err := DecodeRelay0Alias(make([]byte, 3))
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestRelay1BindRoundtrip(t *testing.T) {
	var srcKey, dstKey [32]byte
	for i := range srcKey {
		srcKey[i] = byte(i)
		dstKey[i] = byte(i + 100)
	}
	orig := &Relay1Bind{RelayID: 0x5678, SrcKey: srcKey, DstKey: dstKey}
	encoded := EncodeRelay1Bind(orig)
	if len(encoded) != Relay1BindSize {
		t.Fatalf("len: got %d, want %d", len(encoded), Relay1BindSize)
	}
	decoded, err := DecodeRelay1Bind(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RelayID != 0x5678 {
		t.Errorf("RelayID: got %d, want %d", decoded.RelayID, 0x5678)
	}
	if decoded.SrcKey != srcKey {
		t.Error("SrcKey mismatch")
	}
	if decoded.DstKey != dstKey {
		t.Error("DstKey mismatch")
	}
}

func TestRelay1BindTooShort(t *testing.T) {
	_, err := DecodeRelay1Bind(make([]byte, Relay1BindSize-1))
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestRelay1AliasRoundtrip(t *testing.T) {
	payload := []byte("relay1 alias data")
	orig := &Relay1Alias{RelayID: 0xFF00, Payload: payload}
	encoded := EncodeRelay1Alias(orig)
	decoded, err := DecodeRelay1Alias(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RelayID != 0xFF00 {
		t.Errorf("RelayID mismatch")
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Error("Payload mismatch")
	}
}

func TestRelay2BindRoundtrip(t *testing.T) {
	var srcKey [32]byte
	for i := range srcKey {
		srcKey[i] = byte(i + 50)
	}
	orig := &Relay2Bind{RelayID: 0x9ABC, SrcKey: srcKey}
	encoded := EncodeRelay2Bind(orig)
	if len(encoded) != Relay2BindSize {
		t.Fatalf("len: got %d, want %d", len(encoded), Relay2BindSize)
	}
	decoded, err := DecodeRelay2Bind(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RelayID != 0x9ABC {
		t.Errorf("RelayID mismatch")
	}
	if decoded.SrcKey != srcKey {
		t.Error("SrcKey mismatch")
	}
}

func TestRelay2BindTooShort(t *testing.T) {
	_, err := DecodeRelay2Bind(make([]byte, Relay2BindSize-1))
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestRelay2AliasRoundtrip(t *testing.T) {
	payload := []byte("relay2 alias final")
	orig := &Relay2Alias{RelayID: 0xDEAD, Payload: payload}
	encoded := EncodeRelay2Alias(orig)
	decoded, err := DecodeRelay2Alias(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RelayID != 0xDEAD {
		t.Errorf("RelayID mismatch")
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Error("Payload mismatch")
	}
}

func TestRelay2AliasTooShort(t *testing.T) {
	_, err := DecodeRelay2Alias(make([]byte, 3))
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestAliasEmptyPayload(t *testing.T) {
	orig := &Relay0Alias{RelayID: 42, Payload: nil}
	encoded := EncodeRelay0Alias(orig)
	if len(encoded) != 4 {
		t.Fatalf("len: got %d, want 4", len(encoded))
	}
	decoded, err := DecodeRelay0Alias(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RelayID != 42 {
		t.Errorf("RelayID: got %d, want 42", decoded.RelayID)
	}
	if len(decoded.Payload) != 0 {
		t.Errorf("Payload len: got %d, want 0", len(decoded.Payload))
	}
}
