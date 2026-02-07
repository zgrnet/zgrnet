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
