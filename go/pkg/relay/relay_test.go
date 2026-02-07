package relay

import (
	"bytes"
	"testing"

	"github.com/vibing/zgrnet/pkg/noise"
)

// staticRouter is a simple Router for testing with a static map.
type staticRouter struct {
	routes map[[32]byte][32]byte // dst -> nextHop
}

func (r *staticRouter) NextHop(dst [32]byte, _ Strategy) ([32]byte, error) {
	if next, ok := r.routes[dst]; ok {
		return next, nil
	}
	return [32]byte{}, ErrNoRoute
}

// keyFromByte creates a [32]byte key with the given byte in position 0.
func keyFromByte(b byte) [32]byte {
	var k [32]byte
	k[0] = b
	return k
}

func TestHandleRelay0_Direct(t *testing.T) {
	keyA := keyFromByte(0x0A) // sender
	keyB := keyFromByte(0x0B) // destination
	payload := []byte("secret payload from A to B")

	router := &staticRouter{routes: map[[32]byte][32]byte{
		keyB: keyB, // B is direct
	}}

	// Build RELAY_0
	r0Data := EncodeRelay0(&Relay0{
		TTL:      8,
		Strategy: StrategyAuto,
		DstKey:   keyB,
		Payload:  payload,
	})

	action, err := HandleRelay0(router, keyA, r0Data)
	if err != nil {
		t.Fatal(err)
	}

	// Should produce RELAY_2 to B
	if action.Dst != keyB {
		t.Errorf("Dst: got %x, want %x", action.Dst[0], keyB[0])
	}
	if action.Protocol != noise.ProtocolRelay2 {
		t.Errorf("Protocol: got %d, want %d", action.Protocol, noise.ProtocolRelay2)
	}

	// Decode the RELAY_2
	r2, err := DecodeRelay2(action.Data)
	if err != nil {
		t.Fatal(err)
	}
	if r2.SrcKey != keyA {
		t.Errorf("SrcKey: got %x, want %x", r2.SrcKey[0], keyA[0])
	}
	if !bytes.Equal(r2.Payload, payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestHandleRelay0_Forward(t *testing.T) {
	keyA := keyFromByte(0x0A) // sender
	keyB := keyFromByte(0x0B) // destination
	keyC := keyFromByte(0x0C) // next hop relay
	payload := []byte("secret payload from A to B")

	router := &staticRouter{routes: map[[32]byte][32]byte{
		keyB: keyC, // B is reachable via C
	}}

	r0Data := EncodeRelay0(&Relay0{
		TTL:      8,
		Strategy: StrategyFastest,
		DstKey:   keyB,
		Payload:  payload,
	})

	action, err := HandleRelay0(router, keyA, r0Data)
	if err != nil {
		t.Fatal(err)
	}

	// Should produce RELAY_1 to C
	if action.Dst != keyC {
		t.Errorf("Dst: got %x, want %x", action.Dst[0], keyC[0])
	}
	if action.Protocol != noise.ProtocolRelay1 {
		t.Errorf("Protocol: got %d, want %d", action.Protocol, noise.ProtocolRelay1)
	}

	// Decode the RELAY_1
	r1, err := DecodeRelay1(action.Data)
	if err != nil {
		t.Fatal(err)
	}
	if r1.TTL != 7 { // TTL decremented
		t.Errorf("TTL: got %d, want 7", r1.TTL)
	}
	if r1.Strategy != StrategyFastest {
		t.Errorf("Strategy: got %d, want %d", r1.Strategy, StrategyFastest)
	}
	if r1.SrcKey != keyA {
		t.Errorf("SrcKey: got %x, want %x", r1.SrcKey[0], keyA[0])
	}
	if r1.DstKey != keyB {
		t.Errorf("DstKey: got %x, want %x", r1.DstKey[0], keyB[0])
	}
	if !bytes.Equal(r1.Payload, payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestHandleRelay0_TTLExpired(t *testing.T) {
	keyA := keyFromByte(0x0A)
	keyB := keyFromByte(0x0B)

	router := &staticRouter{routes: map[[32]byte][32]byte{keyB: keyB}}

	r0Data := EncodeRelay0(&Relay0{
		TTL:    0, // Expired
		DstKey: keyB,
	})

	_, err := HandleRelay0(router, keyA, r0Data)
	if err != ErrTTLExpired {
		t.Errorf("expected ErrTTLExpired, got %v", err)
	}
}

func TestHandleRelay0_NoRoute(t *testing.T) {
	keyA := keyFromByte(0x0A)
	keyB := keyFromByte(0x0B)

	router := &staticRouter{routes: map[[32]byte][32]byte{}} // empty

	r0Data := EncodeRelay0(&Relay0{
		TTL:    8,
		DstKey: keyB,
	})

	_, err := HandleRelay0(router, keyA, r0Data)
	if err != ErrNoRoute {
		t.Errorf("expected ErrNoRoute, got %v", err)
	}
}

func TestHandleRelay1_Direct(t *testing.T) {
	keyA := keyFromByte(0x0A)
	keyB := keyFromByte(0x0B)
	payload := []byte("relay1 payload")

	router := &staticRouter{routes: map[[32]byte][32]byte{
		keyB: keyB, // B is direct
	}}

	r1Data := EncodeRelay1(&Relay1{
		TTL:      5,
		Strategy: StrategyCheapest,
		SrcKey:   keyA,
		DstKey:   keyB,
		Payload:  payload,
	})

	action, err := HandleRelay1(router, r1Data)
	if err != nil {
		t.Fatal(err)
	}

	// Should produce RELAY_2 to B
	if action.Dst != keyB {
		t.Errorf("Dst: got %x, want %x", action.Dst[0], keyB[0])
	}
	if action.Protocol != noise.ProtocolRelay2 {
		t.Errorf("Protocol: got %d, want %d", action.Protocol, noise.ProtocolRelay2)
	}

	r2, err := DecodeRelay2(action.Data)
	if err != nil {
		t.Fatal(err)
	}
	if r2.SrcKey != keyA {
		t.Errorf("SrcKey preserved: got %x, want %x", r2.SrcKey[0], keyA[0])
	}
	if !bytes.Equal(r2.Payload, payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestHandleRelay1_Forward(t *testing.T) {
	keyA := keyFromByte(0x0A)
	keyB := keyFromByte(0x0B)
	keyD := keyFromByte(0x0D) // next hop
	payload := []byte("relay1 multi-hop")

	router := &staticRouter{routes: map[[32]byte][32]byte{
		keyB: keyD, // B is reachable via D
	}}

	r1Data := EncodeRelay1(&Relay1{
		TTL:      5,
		Strategy: StrategyAuto,
		SrcKey:   keyA,
		DstKey:   keyB,
		Payload:  payload,
	})

	action, err := HandleRelay1(router, r1Data)
	if err != nil {
		t.Fatal(err)
	}

	// Should forward RELAY_1 to D
	if action.Dst != keyD {
		t.Errorf("Dst: got %x, want %x", action.Dst[0], keyD[0])
	}
	if action.Protocol != noise.ProtocolRelay1 {
		t.Errorf("Protocol: got %d, want %d", action.Protocol, noise.ProtocolRelay1)
	}

	fwd, err := DecodeRelay1(action.Data)
	if err != nil {
		t.Fatal(err)
	}
	if fwd.TTL != 4 { // TTL decremented
		t.Errorf("TTL: got %d, want 4", fwd.TTL)
	}
	if fwd.SrcKey != keyA {
		t.Errorf("SrcKey: got %x, want %x", fwd.SrcKey[0], keyA[0])
	}
	if fwd.DstKey != keyB {
		t.Errorf("DstKey: got %x, want %x", fwd.DstKey[0], keyB[0])
	}
}

func TestHandleRelay1_TTLExpired(t *testing.T) {
	router := &staticRouter{routes: map[[32]byte][32]byte{}}

	r1Data := EncodeRelay1(&Relay1{
		TTL:    0,
		DstKey: keyFromByte(0x0B),
	})

	_, err := HandleRelay1(router, r1Data)
	if err != ErrTTLExpired {
		t.Errorf("expected ErrTTLExpired, got %v", err)
	}
}

func TestHandleRelay2(t *testing.T) {
	keyA := keyFromByte(0x0A)
	payload := []byte("final payload for destination")

	r2Data := EncodeRelay2(&Relay2{
		SrcKey:  keyA,
		Payload: payload,
	})

	src, innerPayload, err := HandleRelay2(r2Data)
	if err != nil {
		t.Fatal(err)
	}

	if src != keyA {
		t.Errorf("src: got %x, want %x", src[0], keyA[0])
	}
	if !bytes.Equal(innerPayload, payload) {
		t.Errorf("payload mismatch")
	}
}

func TestHandleRelay2_TooShort(t *testing.T) {
	_, _, err := HandleRelay2(make([]byte, 31))
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestHandlePing(t *testing.T) {
	from := keyFromByte(0x0A)
	pingData := EncodePing(&Ping{
		PingID:    42,
		Timestamp: 1234567890,
	})

	metrics := NodeMetrics{
		Load:       50,
		RelayCount: 10,
		BwAvail:    2048,
		Price:      100,
	}

	action, err := HandlePing(from, pingData, metrics)
	if err != nil {
		t.Fatal(err)
	}

	// Should produce PONG back to sender
	if action.Dst != from {
		t.Errorf("Dst: got %x, want %x", action.Dst[0], from[0])
	}
	if action.Protocol != noise.ProtocolPong {
		t.Errorf("Protocol: got %d, want %d", action.Protocol, noise.ProtocolPong)
	}

	pong, err := DecodePong(action.Data)
	if err != nil {
		t.Fatal(err)
	}
	if pong.PingID != 42 {
		t.Errorf("PingID: got %d, want 42", pong.PingID)
	}
	if pong.Timestamp != 1234567890 {
		t.Errorf("Timestamp: got %d, want 1234567890", pong.Timestamp)
	}
	if pong.Load != 50 {
		t.Errorf("Load: got %d, want 50", pong.Load)
	}
	if pong.RelayCount != 10 {
		t.Errorf("RelayCount: got %d, want 10", pong.RelayCount)
	}
	if pong.BwAvail != 2048 {
		t.Errorf("BwAvail: got %d, want 2048", pong.BwAvail)
	}
	if pong.Price != 100 {
		t.Errorf("Price: got %d, want 100", pong.Price)
	}
}

func TestHandlePing_TooShort(t *testing.T) {
	from := keyFromByte(0x0A)
	_, err := HandlePing(from, make([]byte, PingSize-1), NodeMetrics{})
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

// TestMultiHopRelay tests A -> C -> D -> B relay chain.
func TestMultiHopRelay(t *testing.T) {
	keyA := keyFromByte(0x0A)
	keyB := keyFromByte(0x0B)
	_ = keyFromByte(0x0C) // C is the first relay (caller context)
	keyD := keyFromByte(0x0D)
	payload := []byte("end-to-end encrypted data")

	// C's router: B is reachable via D
	routerC := &staticRouter{routes: map[[32]byte][32]byte{keyB: keyD}}
	// D's router: B is direct
	routerD := &staticRouter{routes: map[[32]byte][32]byte{keyB: keyB}}

	// Step 1: A sends RELAY_0 to C
	r0Data := EncodeRelay0(&Relay0{
		TTL:      8,
		Strategy: StrategyAuto,
		DstKey:   keyB,
		Payload:  payload,
	})

	// Step 2: C handles RELAY_0 -> produces RELAY_1 to D
	action1, err := HandleRelay0(routerC, keyA, r0Data)
	if err != nil {
		t.Fatal("step 2:", err)
	}
	if action1.Protocol != noise.ProtocolRelay1 {
		t.Fatalf("step 2: expected RELAY_1, got protocol %d", action1.Protocol)
	}
	if action1.Dst != keyD {
		t.Fatalf("step 2: expected dst=D, got %x", action1.Dst[0])
	}

	// Step 3: D handles RELAY_1 -> produces RELAY_2 to B
	action2, err := HandleRelay1(routerD, action1.Data)
	if err != nil {
		t.Fatal("step 3:", err)
	}
	if action2.Protocol != noise.ProtocolRelay2 {
		t.Fatalf("step 3: expected RELAY_2, got protocol %d", action2.Protocol)
	}
	if action2.Dst != keyB {
		t.Fatalf("step 3: expected dst=B, got %x", action2.Dst[0])
	}

	// Step 4: B handles RELAY_2 -> extracts src and payload
	src, innerPayload, err := HandleRelay2(action2.Data)
	if err != nil {
		t.Fatal("step 4:", err)
	}
	if src != keyA {
		t.Errorf("step 4: src got %x, want %x (A)", src[0], keyA[0])
	}
	if !bytes.Equal(innerPayload, payload) {
		t.Errorf("step 4: payload mismatch")
	}
}

// TestTTLDecrementChain verifies TTL decrements through a chain.
func TestTTLDecrementChain(t *testing.T) {
	keyA := keyFromByte(0x0A)
	keyB := keyFromByte(0x0B)
	_ = keyFromByte(0x0C) // C is first relay (caller context)
	keyD := keyFromByte(0x0D)
	keyE := keyFromByte(0x0E)

	// Chain: C -> D -> E (each knows next hop, none direct to B)
	routerC := &staticRouter{routes: map[[32]byte][32]byte{keyB: keyD}}
	routerD := &staticRouter{routes: map[[32]byte][32]byte{keyB: keyE}}
	routerE := &staticRouter{routes: map[[32]byte][32]byte{keyB: keyB}} // E is direct to B

	r0 := EncodeRelay0(&Relay0{TTL: 3, DstKey: keyB, Payload: []byte("x")})

	// C: TTL=3 -> RELAY_1 TTL=2
	a1, err := HandleRelay0(routerC, keyA, r0)
	if err != nil {
		t.Fatal(err)
	}
	r1, _ := DecodeRelay1(a1.Data)
	if r1.TTL != 2 {
		t.Errorf("after C: TTL got %d, want 2", r1.TTL)
	}

	// D: TTL=2 -> RELAY_1 TTL=1
	a2, err := HandleRelay1(routerD, a1.Data)
	if err != nil {
		t.Fatal(err)
	}
	r1b, _ := DecodeRelay1(a2.Data)
	if r1b.TTL != 1 {
		t.Errorf("after D: TTL got %d, want 1", r1b.TTL)
	}

	// E: TTL=1 -> RELAY_2 (direct to B)
	a3, err := HandleRelay1(routerE, a2.Data)
	if err != nil {
		t.Fatal(err)
	}
	if a3.Protocol != noise.ProtocolRelay2 {
		t.Errorf("after E: expected RELAY_2, got protocol %d", a3.Protocol)
	}
}
