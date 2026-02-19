package relay

import (
	"bytes"
	"testing"
	"time"
)

func TestBindTable_AllocateAndLookup(t *testing.T) {
	bt := NewBindTable()

	src := keyFromByte(0x0A)
	dst := keyFromByte(0x0D)
	nextHop := keyFromByte(0x0C)

	id := bt.Allocate(src, dst, nextHop)
	if id == 0 {
		t.Fatal("expected non-zero relay_id")
	}

	entry := bt.Lookup(id)
	if entry == nil {
		t.Fatal("expected entry")
	}
	if entry.SrcKey != src {
		t.Error("SrcKey mismatch")
	}
	if entry.DstKey != dst {
		t.Error("DstKey mismatch")
	}
	if entry.NextHop != nextHop {
		t.Error("NextHop mismatch")
	}
}

func TestBindTable_LookupMissing(t *testing.T) {
	bt := NewBindTable()
	if bt.Lookup(999) != nil {
		t.Error("expected nil for missing relay_id")
	}
}

func TestBindTable_UniqueIDs(t *testing.T) {
	bt := NewBindTable()
	ids := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		id := bt.Allocate(keyFromByte(byte(i)), keyFromByte(0xFF), keyFromByte(0xFE))
		if ids[id] {
			t.Fatalf("duplicate relay_id: %d", id)
		}
		ids[id] = true
	}
	if bt.Len() != 100 {
		t.Errorf("Len: got %d, want 100", bt.Len())
	}
}

func TestBindTable_Remove(t *testing.T) {
	bt := NewBindTable()
	id := bt.Allocate(keyFromByte(0x01), keyFromByte(0x02), keyFromByte(0x03))
	if bt.Len() != 1 {
		t.Fatalf("Len: got %d, want 1", bt.Len())
	}

	bt.Remove(id)
	if bt.Len() != 0 {
		t.Fatalf("Len after remove: got %d, want 0", bt.Len())
	}
	if bt.Lookup(id) != nil {
		t.Error("expected nil after remove")
	}
}

func TestBindTable_Expire(t *testing.T) {
	bt := NewBindTable()

	bt.Allocate(keyFromByte(0x01), keyFromByte(0x02), keyFromByte(0x03))
	bt.Allocate(keyFromByte(0x04), keyFromByte(0x05), keyFromByte(0x06))

	// No expiry at 0 age (entries just created)
	removed := bt.Expire(time.Hour)
	if removed != 0 {
		t.Errorf("Expire(1h): removed %d, want 0", removed)
	}
	if bt.Len() != 2 {
		t.Errorf("Len: got %d, want 2", bt.Len())
	}

	// Expire everything — 1ms sleep ensures entries are older than maxAge=0
	time.Sleep(time.Millisecond)
	removed = bt.Expire(0)
	if removed != 2 {
		t.Errorf("Expire(0): removed %d, want 2", removed)
	}
	if bt.Len() != 0 {
		t.Errorf("Len after expire: got %d, want 0", bt.Len())
	}
}

func TestHandleRelay0WithBind_Direct(t *testing.T) {
	keyA := keyFromByte(0x0A)
	keyB := keyFromByte(0x0B)
	payload := []byte("test payload")

	router := &staticRouter{routes: map[[32]byte][32]byte{keyB: keyB}}
	bt := NewBindTable()

	r0Data := EncodeRelay0(&Relay0{
		TTL: 8, Strategy: StrategyAuto, DstKey: keyB, Payload: payload,
	})

	fwd, bind, err := HandleRelay0WithBind(router, bt, keyA, r0Data)
	if err != nil {
		t.Fatal(err)
	}

	// Forward: RELAY_2 to B
	if fwd.Dst != keyB {
		t.Errorf("forward dst: got %x, want %x", fwd.Dst[0], keyB[0])
	}
	if fwd.Protocol != 68 {
		t.Errorf("forward protocol: got %d, want 68", fwd.Protocol)
	}
	r2, _ := DecodeRelay2(fwd.Data)
	if !bytes.Equal(r2.Payload, payload) {
		t.Error("forward payload mismatch")
	}

	// Bind: RELAY_0_BIND back to A
	if bind == nil {
		t.Fatal("expected bind action")
	}
	if bind.Dst != keyA {
		t.Errorf("bind dst: got %x, want %x", bind.Dst[0], keyA[0])
	}
	if bind.Protocol != 72 {
		t.Errorf("bind protocol: got %d, want 72", bind.Protocol)
	}

	b, _ := DecodeRelay0Bind(bind.Data)
	if b.DstKey != keyB {
		t.Error("bind DstKey mismatch")
	}

	// BindTable has the entry
	if bt.Len() != 1 {
		t.Fatalf("BindTable.Len: got %d, want 1", bt.Len())
	}
}

func TestHandleRelay0Alias(t *testing.T) {
	keyA := keyFromByte(0x0A)
	keyB := keyFromByte(0x0B)
	keyC := keyFromByte(0x0C)
	payload := []byte("alias payload")

	bt := NewBindTable()
	relayID := bt.Allocate(keyA, keyB, keyC) // A→B via C

	aliasData := EncodeRelay0Alias(&Relay0Alias{
		RelayID: relayID, Payload: payload,
	})

	action, err := HandleRelay0Alias(bt, keyA, aliasData)
	if err != nil {
		t.Fatal(err)
	}

	// Should forward RELAY_1 to C (since nextHop != dst)
	if action.Dst != keyC {
		t.Errorf("dst: got %x, want %x", action.Dst[0], keyC[0])
	}
	if action.Protocol != 67 {
		t.Errorf("protocol: got %d, want 67 (RELAY_1)", action.Protocol)
	}

	r1, _ := DecodeRelay1(action.Data)
	if r1.SrcKey != keyA {
		t.Error("SrcKey mismatch")
	}
	if r1.DstKey != keyB {
		t.Error("DstKey mismatch")
	}
	if !bytes.Equal(r1.Payload, payload) {
		t.Error("Payload mismatch")
	}
}

func TestHandleRelay0Alias_Direct(t *testing.T) {
	keyA := keyFromByte(0x0A)
	keyB := keyFromByte(0x0B)
	payload := []byte("direct alias")

	bt := NewBindTable()
	relayID := bt.Allocate(keyA, keyB, keyB) // A→B, nextHop==B (direct)

	aliasData := EncodeRelay0Alias(&Relay0Alias{
		RelayID: relayID, Payload: payload,
	})

	action, err := HandleRelay0Alias(bt, keyA, aliasData)
	if err != nil {
		t.Fatal(err)
	}

	// Should produce RELAY_2 to B
	if action.Protocol != 68 {
		t.Errorf("protocol: got %d, want 68 (RELAY_2)", action.Protocol)
	}
	if action.Dst != keyB {
		t.Errorf("dst: got %x, want %x", action.Dst[0], keyB[0])
	}
}

func TestHandleRelay0Alias_UnknownID(t *testing.T) {
	bt := NewBindTable()
	aliasData := EncodeRelay0Alias(&Relay0Alias{RelayID: 999})
	_, err := HandleRelay0Alias(bt, keyFromByte(0x0A), aliasData)
	if err != ErrNoRoute {
		t.Errorf("expected ErrNoRoute, got %v", err)
	}
}

func TestHandleRelay0Alias_WrongSender(t *testing.T) {
	bt := NewBindTable()
	relayID := bt.Allocate(keyFromByte(0x0A), keyFromByte(0x0B), keyFromByte(0x0C))

	aliasData := EncodeRelay0Alias(&Relay0Alias{RelayID: relayID})
	_, err := HandleRelay0Alias(bt, keyFromByte(0xFF), aliasData) // wrong sender
	if err != ErrNoRoute {
		t.Errorf("expected ErrNoRoute for wrong sender, got %v", err)
	}
}
