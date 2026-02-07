package host

import (
	"net"
	"sync"
	"testing"

	"github.com/vibing/zgrnet/pkg/noise"
)

func makeTestKey(b byte) noise.PublicKey {
	var pk noise.PublicKey
	pk[0] = b
	return pk
}

func TestIPAllocator_Assign(t *testing.T) {
	alloc := NewIPAllocator()

	pkA := makeTestKey(1)
	pkB := makeTestKey(2)

	ipA, err := alloc.Assign(pkA)
	if err != nil {
		t.Fatalf("Assign(A) failed: %v", err)
	}
	if !ipA.Equal(net.IPv4(100, 64, 0, 2)) {
		t.Errorf("Assign(A) = %s, want 100.64.0.2", ipA)
	}

	ipB, err := alloc.Assign(pkB)
	if err != nil {
		t.Fatalf("Assign(B) failed: %v", err)
	}
	if !ipB.Equal(net.IPv4(100, 64, 0, 3)) {
		t.Errorf("Assign(B) = %s, want 100.64.0.3", ipB)
	}

	// Re-assign same key should return same IP
	ipA2, err := alloc.Assign(pkA)
	if err != nil {
		t.Fatalf("Assign(A) second call failed: %v", err)
	}
	if !ipA2.Equal(ipA) {
		t.Errorf("Assign(A) second = %s, want %s", ipA2, ipA)
	}

	if alloc.Count() != 2 {
		t.Errorf("Count() = %d, want 2", alloc.Count())
	}
}

func TestIPAllocator_AssignStatic(t *testing.T) {
	alloc := NewIPAllocator()

	pkA := makeTestKey(1)
	pkB := makeTestKey(2)

	// Assign static IP
	staticIP := net.IPv4(100, 100, 0, 5)
	if err := alloc.AssignStatic(pkA, staticIP); err != nil {
		t.Fatalf("AssignStatic failed: %v", err)
	}

	// Verify lookup
	ip, ok := alloc.LookupByPubkey(pkA)
	if !ok {
		t.Fatal("LookupByPubkey(A) not found")
	}
	if !ip.Equal(staticIP) {
		t.Errorf("LookupByPubkey(A) = %s, want %s", ip, staticIP)
	}

	// Same key, same IP is fine
	if err := alloc.AssignStatic(pkA, staticIP); err != nil {
		t.Errorf("AssignStatic same key+IP should succeed: %v", err)
	}

	// Different key, same IP should fail
	if err := alloc.AssignStatic(pkB, staticIP); err == nil {
		t.Error("AssignStatic different key same IP should fail")
	}
}

func TestIPAllocator_LookupByIP(t *testing.T) {
	alloc := NewIPAllocator()

	pkA := makeTestKey(1)
	ip, _ := alloc.Assign(pkA)

	// Lookup should work
	pk, ok := alloc.LookupByIP(ip)
	if !ok {
		t.Fatal("LookupByIP not found")
	}
	if pk != pkA {
		t.Errorf("LookupByIP = %v, want %v", pk, pkA)
	}

	// Unknown IP
	_, ok = alloc.LookupByIP(net.IPv4(10, 0, 0, 1))
	if ok {
		t.Error("LookupByIP should not find unknown IP")
	}

	// IPv6 address should return false
	_, ok = alloc.LookupByIP(net.ParseIP("::1"))
	if ok {
		t.Error("LookupByIP should not find IPv6 address")
	}
}

func TestIPAllocator_LookupByPubkey(t *testing.T) {
	alloc := NewIPAllocator()

	pkA := makeTestKey(1)
	expectedIP, _ := alloc.Assign(pkA)

	ip, ok := alloc.LookupByPubkey(pkA)
	if !ok {
		t.Fatal("LookupByPubkey not found")
	}
	if !ip.Equal(expectedIP) {
		t.Errorf("LookupByPubkey = %s, want %s", ip, expectedIP)
	}

	// Unknown key
	_, ok = alloc.LookupByPubkey(makeTestKey(99))
	if ok {
		t.Error("LookupByPubkey should not find unknown key")
	}
}

func TestIPAllocator_Remove(t *testing.T) {
	alloc := NewIPAllocator()

	pkA := makeTestKey(1)
	ip, _ := alloc.Assign(pkA)

	if alloc.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", alloc.Count())
	}

	alloc.Remove(pkA)

	if alloc.Count() != 0 {
		t.Errorf("Count() after remove = %d, want 0", alloc.Count())
	}

	_, ok := alloc.LookupByPubkey(pkA)
	if ok {
		t.Error("LookupByPubkey should not find removed key")
	}

	_, ok = alloc.LookupByIP(ip)
	if ok {
		t.Error("LookupByIP should not find removed IP")
	}

	// Remove non-existent key should not panic
	alloc.Remove(makeTestKey(99))
}

func TestIPAllocator_Concurrent(t *testing.T) {
	alloc := NewIPAllocator()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			pk := makeTestKey(byte(i))
			ip, err := alloc.Assign(pk)
			if err != nil {
				t.Errorf("Assign(%d) failed: %v", i, err)
				return
			}

			// Verify lookup
			gotPK, ok := alloc.LookupByIP(ip)
			if !ok {
				t.Errorf("LookupByIP(%s) not found", ip)
				return
			}
			if gotPK != pk {
				t.Errorf("LookupByIP(%s) = %v, want %v", ip, gotPK, pk)
			}
		}(i)
	}

	wg.Wait()

	if alloc.Count() != goroutines {
		t.Errorf("Count() = %d, want %d", alloc.Count(), goroutines)
	}
}

func TestIPAllocator_InvalidIPv4(t *testing.T) {
	alloc := NewIPAllocator()

	pk := makeTestKey(1)

	// IPv6 as static IPv4 should fail
	err := alloc.AssignStatic(pk, net.ParseIP("::1"))
	if err == nil {
		t.Error("AssignStatic with IPv6 should fail")
	}
}
