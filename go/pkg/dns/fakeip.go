package dns

import (
	"container/list"
	"encoding/binary"
	"net"
	"sync"
)

// FakeIPPool manages a pool of fake IPs for route-matched domains.
// Range: 198.18.0.0/15 (RFC 5737 benchmarking range, 131072 IPs).
// Provides bidirectional domain <-> IP mapping with O(1) LRU eviction.
type FakeIPPool struct {
	mu sync.Mutex

	// Forward mapping: domain -> IP
	domainToIP map[string]net.IP
	// Reverse mapping: IP (as uint32) -> domain
	ipToDomain map[uint32]string

	// O(1) LRU: doubly linked list (front=LRU, back=MRU) + element map
	lruList    *list.List
	lruElement map[string]*list.Element // domain -> list element
	maxSize    int

	// IP allocation state
	baseIP  uint32 // 198.18.0.0 = 0xC6120000
	nextOff uint32 // Next offset to allocate
	maxOff  uint32 // Max offset (131072 for /15)
}

// NewFakeIPPool creates a new Fake IP pool.
// Range: 198.18.0.0/15 (198.18.0.0 - 198.19.255.255)
// maxSize limits the number of entries; when exceeded, LRU eviction kicks in.
// If maxSize <= 0, defaults to 65536.
func NewFakeIPPool(maxSize int) *FakeIPPool {
	if maxSize <= 0 {
		maxSize = 65536
	}
	return &FakeIPPool{
		domainToIP: make(map[string]net.IP),
		ipToDomain: make(map[uint32]string),
		lruList:    list.New(),
		lruElement: make(map[string]*list.Element),
		maxSize:    maxSize,
		baseIP:     0xC6120000, // 198.18.0.0
		nextOff:    1,          // Skip .0.0
		maxOff:     131072 - 1, // 198.19.255.255
	}
}

// Assign returns the Fake IP for the given domain.
// If the domain already has an IP, it's returned and the entry is moved to
// the back of the LRU list. Otherwise, a new IP is allocated.
func (p *FakeIPPool) Assign(domain string) net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Already assigned?
	if ip, ok := p.domainToIP[domain]; ok {
		p.touchLRU(domain)
		return ip
	}

	// Evict if at capacity
	if len(p.domainToIP) >= p.maxSize {
		p.evictLRU()
	}

	// Allocate next IP
	ip := p.allocIP()
	ipKey := ipToUint32(ip)

	p.domainToIP[domain] = ip
	p.ipToDomain[ipKey] = domain
	// Push to back (MRU end)
	elem := p.lruList.PushBack(domain)
	p.lruElement[domain] = elem

	return ip
}

// Lookup returns the domain associated with the given Fake IP.
func (p *FakeIPPool) Lookup(ip net.IP) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ip4 := ip.To4()
	if ip4 == nil {
		return "", false
	}

	domain, ok := p.ipToDomain[ipToUint32(ip4)]
	return domain, ok
}

// LookupDomain returns the Fake IP for the given domain without allocating.
func (p *FakeIPPool) LookupDomain(domain string) (net.IP, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ip, ok := p.domainToIP[domain]
	return ip, ok
}

// Size returns the number of entries in the pool.
func (p *FakeIPPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.domainToIP)
}

// allocIP returns the next available IP and advances the offset.
// Wraps around if the range is exhausted.
func (p *FakeIPPool) allocIP() net.IP {
	ipVal := p.baseIP + p.nextOff
	p.nextOff++
	if p.nextOff > p.maxOff {
		p.nextOff = 1 // Wrap around
	}

	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipVal)
	return ip
}

// touchLRU moves a domain to the back of the LRU list (most recently used). O(1).
func (p *FakeIPPool) touchLRU(domain string) {
	if elem, ok := p.lruElement[domain]; ok {
		p.lruList.MoveToBack(elem)
	}
}

// evictLRU removes the least recently used entry. O(1).
func (p *FakeIPPool) evictLRU() {
	front := p.lruList.Front()
	if front == nil {
		return
	}

	victim := p.lruList.Remove(front).(string)
	delete(p.lruElement, victim)

	if ip, ok := p.domainToIP[victim]; ok {
		delete(p.ipToDomain, ipToUint32(ip))
		delete(p.domainToIP, victim)
	}
}

// ipToUint32 converts an IPv4 address to a uint32.
func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}
