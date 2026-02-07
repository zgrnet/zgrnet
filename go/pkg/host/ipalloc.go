// Package host provides the Host that bridges TUN and encrypted UDP transport.
package host

import (
	"fmt"
	"net"
	"sync"

	"github.com/vibing/zgrnet/pkg/noise"
)

// CGNAT IPv4 range: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
// This range is reserved for Carrier-Grade NAT and won't conflict with public IPs.
const (
	cgnatBase uint32 = 0x64400000 // 100.64.0.0
	cgnatMask uint32 = 0xFFC00000 // /10 = 255.192.0.0
	cgnatSize uint32 = 0x003FFFFF // 4,194,303 usable addresses
)

// AllocatedIP holds the allocated IP addresses for a peer.
type AllocatedIP struct {
	IPv4 net.IP
}

// IPAllocator manages bidirectional pubkey <-> IP address mappings.
// It allocates IPs from the CGNAT range (100.64.0.0/10) for IPv4.
// Thread-safe for concurrent use.
type IPAllocator struct {
	mu       sync.RWMutex
	nextIPv4 uint32 // offset from cgnatBase for next allocation
	byPubkey map[noise.PublicKey]AllocatedIP
	byIPv4   map[[4]byte]noise.PublicKey
}

// NewIPAllocator creates a new IP allocator.
// Addresses are allocated starting from 100.64.0.2 (skipping .0 network and .1 reserved).
func NewIPAllocator() *IPAllocator {
	return &IPAllocator{
		nextIPv4: 2, // start from 100.64.0.2
		byPubkey: make(map[noise.PublicKey]AllocatedIP),
		byIPv4:   make(map[[4]byte]noise.PublicKey),
	}
}

// Assign allocates an IPv4 address for the given public key.
// If the key already has an allocation, returns the existing IP.
func (a *IPAllocator) Assign(pk noise.PublicKey) (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Return existing allocation
	if alloc, ok := a.byPubkey[pk]; ok {
		return alloc.IPv4, nil
	}

	// Check pool exhaustion
	if a.nextIPv4 > cgnatSize {
		return nil, fmt.Errorf("host: IP address pool exhausted")
	}

	// Allocate next address
	ip := uint32ToIPv4(cgnatBase + a.nextIPv4)
	a.nextIPv4++

	key4 := ipv4Key(ip)
	alloc := AllocatedIP{IPv4: ip}
	a.byPubkey[pk] = alloc
	a.byIPv4[key4] = pk

	return ip, nil
}

// AssignStatic assigns a specific IPv4 address to the given public key.
// Returns error if the IP is already assigned to a different key.
func (a *IPAllocator) AssignStatic(pk noise.PublicKey, ipv4 net.IP) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	ip4 := ipv4.To4()
	if ip4 == nil {
		return fmt.Errorf("host: invalid IPv4 address: %s", ipv4)
	}

	key4 := ipv4Key(ip4)

	// Check for conflict
	if existing, ok := a.byIPv4[key4]; ok && existing != pk {
		return fmt.Errorf("host: IP %s already assigned to different peer", ipv4)
	}

	alloc := AllocatedIP{IPv4: ip4}
	a.byPubkey[pk] = alloc
	a.byIPv4[key4] = pk

	return nil
}

// LookupByIP returns the public key associated with the given IP address.
func (a *IPAllocator) LookupByIP(ip net.IP) (noise.PublicKey, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ip4 := ip.To4()
	if ip4 == nil {
		return noise.PublicKey{}, false
	}

	key4 := ipv4Key(ip4)
	pk, ok := a.byIPv4[key4]
	return pk, ok
}

// LookupByPubkey returns the IPv4 address associated with the given public key.
func (a *IPAllocator) LookupByPubkey(pk noise.PublicKey) (net.IP, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	alloc, ok := a.byPubkey[pk]
	if !ok {
		return nil, false
	}
	return alloc.IPv4, true
}

// Remove removes the allocation for the given public key.
func (a *IPAllocator) Remove(pk noise.PublicKey) {
	a.mu.Lock()
	defer a.mu.Unlock()

	alloc, ok := a.byPubkey[pk]
	if !ok {
		return
	}

	key4 := ipv4Key(alloc.IPv4)
	delete(a.byIPv4, key4)
	delete(a.byPubkey, pk)
}

// Count returns the number of allocated addresses.
func (a *IPAllocator) Count() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.byPubkey)
}

// uint32ToIPv4 converts a uint32 to a 4-byte IPv4 address.
func uint32ToIPv4(n uint32) net.IP {
	return net.IPv4(
		byte(n>>24),
		byte(n>>16),
		byte(n>>8),
		byte(n),
	).To4()
}

// ipv4Key converts an IPv4 address to a [4]byte key for map lookups.
func ipv4Key(ip net.IP) [4]byte {
	ip4 := ip.To4()
	if ip4 == nil {
		return [4]byte{}
	}
	return [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
}
