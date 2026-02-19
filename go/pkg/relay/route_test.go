package relay

import (
	"sync"
	"testing"

	"github.com/vibing/zgrnet/pkg/noise"
)

func pkFromByte(b byte) noise.PublicKey {
	var pk noise.PublicKey
	pk[0] = b
	return pk
}

func TestRouteTable_AddAndLookup(t *testing.T) {
	rt := NewRouteTable()

	dst := pkFromByte(0x0D)
	relay := pkFromByte(0x0C)

	rt.AddRoute(dst, relay)

	// NextHop should return the relay
	nh, err := rt.NextHop([32]byte(dst), StrategyAuto)
	if err != nil {
		t.Fatal(err)
	}
	if noise.PublicKey(nh) != relay {
		t.Errorf("NextHop: got %x, want %x", nh[0], relay[0])
	}

	// RelayFor should return the relay
	r := rt.RelayFor(dst)
	if r == nil {
		t.Fatal("RelayFor: expected non-nil")
	}
	if *r != relay {
		t.Errorf("RelayFor: got %x, want %x", r[0], relay[0])
	}
}

func TestRouteTable_DirectRoute(t *testing.T) {
	rt := NewRouteTable()

	dst := pkFromByte(0x0D)
	// Route where nextHop == dst means direct
	rt.AddRoute(dst, dst)

	nh, err := rt.NextHop([32]byte(dst), StrategyAuto)
	if err != nil {
		t.Fatal(err)
	}
	if noise.PublicKey(nh) != dst {
		t.Errorf("NextHop: got %x, want %x", nh[0], dst[0])
	}

	// RelayFor should return nil for direct route
	r := rt.RelayFor(dst)
	if r != nil {
		t.Errorf("RelayFor: expected nil for direct route, got %x", r[0])
	}
}

func TestRouteTable_NoRoute(t *testing.T) {
	rt := NewRouteTable()

	dst := pkFromByte(0x0D)

	// NextHop returns dst itself when no route
	nh, err := rt.NextHop([32]byte(dst), StrategyAuto)
	if err != nil {
		t.Fatal(err)
	}
	if noise.PublicKey(nh) != dst {
		t.Errorf("NextHop: got %x, want %x (self)", nh[0], dst[0])
	}

	// RelayFor returns nil when no route
	r := rt.RelayFor(dst)
	if r != nil {
		t.Errorf("RelayFor: expected nil, got %x", r[0])
	}
}

func TestRouteTable_Remove(t *testing.T) {
	rt := NewRouteTable()

	dst := pkFromByte(0x0D)
	relay := pkFromByte(0x0C)

	rt.AddRoute(dst, relay)
	if rt.Len() != 1 {
		t.Fatalf("Len: got %d, want 1", rt.Len())
	}

	rt.RemoveRoute(dst)
	if rt.Len() != 0 {
		t.Fatalf("Len after remove: got %d, want 0", rt.Len())
	}

	// Should behave as no route
	r := rt.RelayFor(dst)
	if r != nil {
		t.Errorf("RelayFor after remove: expected nil")
	}
}

func TestRouteTable_Overwrite(t *testing.T) {
	rt := NewRouteTable()

	dst := pkFromByte(0x0D)
	relay1 := pkFromByte(0x0C)
	relay2 := pkFromByte(0x0B)

	rt.AddRoute(dst, relay1)
	rt.AddRoute(dst, relay2)

	r := rt.RelayFor(dst)
	if r == nil || *r != relay2 {
		t.Errorf("RelayFor: expected relay2 after overwrite")
	}
	if rt.Len() != 1 {
		t.Fatalf("Len: got %d, want 1", rt.Len())
	}
}

func TestRouteTable_HasRoute(t *testing.T) {
	rt := NewRouteTable()

	dst := pkFromByte(0x0D)
	relay := pkFromByte(0x0C)

	if rt.HasRoute(dst) {
		t.Error("HasRoute: expected false before add")
	}

	rt.AddRoute(dst, relay)
	if !rt.HasRoute(dst) {
		t.Error("HasRoute: expected true after add")
	}

	rt.RemoveRoute(dst)
	if rt.HasRoute(dst) {
		t.Error("HasRoute: expected false after remove")
	}
}

func TestRouteTable_Routes(t *testing.T) {
	rt := NewRouteTable()

	a := pkFromByte(0x0A)
	b := pkFromByte(0x0B)
	c := pkFromByte(0x0C)

	rt.AddRoute(a, c)
	rt.AddRoute(b, c)

	snap := rt.Routes()
	if len(snap) != 2 {
		t.Fatalf("Routes: got %d entries, want 2", len(snap))
	}
	if snap[a] != c || snap[b] != c {
		t.Error("Routes: wrong entries")
	}

	// Mutating snapshot doesn't affect original
	delete(snap, a)
	if rt.Len() != 2 {
		t.Error("Routes snapshot mutation affected original")
	}
}

func TestRouteTable_ImplementsRouter(t *testing.T) {
	rt := NewRouteTable()

	dst := pkFromByte(0x0D)
	relay := pkFromByte(0x0C)
	rt.AddRoute(dst, relay)

	// Use as Router interface
	var router Router = rt
	nh, err := router.NextHop([32]byte(dst), StrategyFastest)
	if err != nil {
		t.Fatal(err)
	}
	if noise.PublicKey(nh) != relay {
		t.Errorf("Router.NextHop: got %x, want %x", nh[0], relay[0])
	}
}

func TestRouteTable_MultipleDestinations(t *testing.T) {
	rt := NewRouteTable()

	relay1 := pkFromByte(0x01)
	relay2 := pkFromByte(0x02)

	for i := byte(10); i < 20; i++ {
		dst := pkFromByte(i)
		if i%2 == 0 {
			rt.AddRoute(dst, relay1)
		} else {
			rt.AddRoute(dst, relay2)
		}
	}

	if rt.Len() != 10 {
		t.Fatalf("Len: got %d, want 10", rt.Len())
	}

	for i := byte(10); i < 20; i++ {
		dst := pkFromByte(i)
		r := rt.RelayFor(dst)
		if r == nil {
			t.Fatalf("RelayFor(%d): expected non-nil", i)
		}
		if i%2 == 0 && *r != relay1 {
			t.Errorf("RelayFor(%d): got %x, want relay1", i, r[0])
		}
		if i%2 != 0 && *r != relay2 {
			t.Errorf("RelayFor(%d): got %x, want relay2", i, r[0])
		}
	}
}

func TestRouteTable_ConcurrentAccess(t *testing.T) {
	rt := NewRouteTable()

	var wg sync.WaitGroup
	for i := byte(0); i < 100; i++ {
		wg.Add(1)
		go func(b byte) {
			defer wg.Done()
			dst := pkFromByte(b)
			relay := pkFromByte(b + 100)
			rt.AddRoute(dst, relay)
			rt.RelayFor(dst)
			rt.NextHop([32]byte(dst), StrategyAuto)
			rt.HasRoute(dst)
			rt.Routes()
			rt.Len()
		}(i)
	}
	wg.Wait()

	if rt.Len() != 100 {
		t.Errorf("Len after concurrent adds: got %d, want 100", rt.Len())
	}
}
