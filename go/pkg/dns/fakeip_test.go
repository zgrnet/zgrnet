package dns

import (
	"net"
	"testing"
)

func TestFakeIPPool_Assign(t *testing.T) {
	pool := NewFakeIPPool(100)

	ip1 := pool.Assign("example.com")
	if ip1 == nil {
		t.Fatal("Assign returned nil")
	}

	// Verify it's in the fake range 198.18.0.0/15
	ip4 := ip1.To4()
	if ip4 == nil {
		t.Fatal("expected IPv4")
	}
	if ip4[0] != 198 || ip4[1] != 18 {
		t.Errorf("IP = %v, want 198.18.x.x", ip1)
	}

	// Same domain returns same IP
	ip2 := pool.Assign("example.com")
	if !ip1.Equal(ip2) {
		t.Errorf("same domain returned different IPs: %v vs %v", ip1, ip2)
	}

	// Different domain returns different IP
	ip3 := pool.Assign("other.com")
	if ip1.Equal(ip3) {
		t.Errorf("different domains returned same IP: %v", ip1)
	}
}

func TestFakeIPPool_Lookup(t *testing.T) {
	pool := NewFakeIPPool(100)

	ip := pool.Assign("test.example.com")

	domain, ok := pool.Lookup(ip)
	if !ok {
		t.Fatal("Lookup failed for assigned IP")
	}
	if domain != "test.example.com" {
		t.Errorf("Lookup = %q, want %q", domain, "test.example.com")
	}

	// Lookup unknown IP
	_, ok = pool.Lookup(net.ParseIP("1.2.3.4"))
	if ok {
		t.Error("Lookup should fail for unknown IP")
	}
}

func TestFakeIPPool_LookupDomain(t *testing.T) {
	pool := NewFakeIPPool(100)

	_, ok := pool.LookupDomain("notassigned.com")
	if ok {
		t.Error("LookupDomain should fail for unassigned domain")
	}

	expected := pool.Assign("test.com")
	ip, ok := pool.LookupDomain("test.com")
	if !ok {
		t.Fatal("LookupDomain failed for assigned domain")
	}
	if !ip.Equal(expected) {
		t.Errorf("LookupDomain = %v, want %v", ip, expected)
	}
}

func TestFakeIPPool_LRUEviction(t *testing.T) {
	pool := NewFakeIPPool(3)

	pool.Assign("a.com")
	pool.Assign("b.com")
	pool.Assign("c.com")

	if pool.Size() != 3 {
		t.Fatalf("Size = %d, want 3", pool.Size())
	}

	// Adding a 4th should evict "a.com" (LRU)
	pool.Assign("d.com")

	if pool.Size() != 3 {
		t.Fatalf("Size = %d, want 3 after eviction", pool.Size())
	}

	_, ok := pool.LookupDomain("a.com")
	if ok {
		t.Error("a.com should have been evicted")
	}

	_, ok = pool.LookupDomain("b.com")
	if !ok {
		t.Error("b.com should still exist")
	}
	_, ok = pool.LookupDomain("d.com")
	if !ok {
		t.Error("d.com should exist")
	}
}

func TestFakeIPPool_LRUTouch(t *testing.T) {
	pool := NewFakeIPPool(3)

	pool.Assign("a.com")
	pool.Assign("b.com")
	pool.Assign("c.com")

	// Touch a.com (moves to MRU end)
	pool.Assign("a.com")

	// Now add d.com -- should evict b.com (the new LRU)
	pool.Assign("d.com")

	_, ok := pool.LookupDomain("a.com")
	if !ok {
		t.Error("a.com should still exist (was touched)")
	}
	_, ok = pool.LookupDomain("b.com")
	if ok {
		t.Error("b.com should have been evicted (LRU after a.com was touched)")
	}
}

func TestFakeIPPool_LookupIPv6(t *testing.T) {
	pool := NewFakeIPPool(100)

	// Lookup with an IPv6 address should return false
	_, ok := pool.Lookup(net.ParseIP("::1"))
	if ok {
		t.Error("Lookup should fail for IPv6 address")
	}
}

func TestFakeIPPool_DefaultSize(t *testing.T) {
	pool := NewFakeIPPool(0)
	// Should default to 65536
	if pool.maxSize != 65536 {
		t.Errorf("default maxSize = %d, want 65536", pool.maxSize)
	}
}

func TestFakeIPPool_IPRange(t *testing.T) {
	pool := NewFakeIPPool(1000)

	// Assign many and verify all are in range
	for i := 0; i < 100; i++ {
		domain := "test" + string(rune('a'+i%26)) + ".example.com"
		ip := pool.Assign(domain)
		ip4 := ip.To4()
		if ip4 == nil {
			t.Fatalf("non-IPv4 from Fake IP pool")
		}
		// Should be 198.18.x.x or 198.19.x.x
		if ip4[0] != 198 || (ip4[1] != 18 && ip4[1] != 19) {
			t.Errorf("IP %v out of range 198.18.0.0/15", ip)
		}
	}
}
