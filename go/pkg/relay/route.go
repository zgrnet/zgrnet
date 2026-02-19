package relay

import (
	"sync"

	"github.com/vibing/zgrnet/pkg/noise"
)

// RouteTable provides next-hop routing decisions for relay forwarding and
// outbound relay wrapping. It implements the Router interface so it can be
// used by the relay engine for RELAY_0/1 forwarding, and also provides
// RelayFor for the UDP layer to decide whether to wrap outbound packets
// in RELAY_0.
//
// Thread-safe: all methods are safe for concurrent use.
type RouteTable struct {
	mu     sync.RWMutex
	routes map[noise.PublicKey]noise.PublicKey // dst → nextHop
}

// NewRouteTable creates an empty route table.
func NewRouteTable() *RouteTable {
	return &RouteTable{
		routes: make(map[noise.PublicKey]noise.PublicKey),
	}
}

// AddRoute sets the next-hop for reaching dst. If dst == nextHop, the route
// is treated as direct (equivalent to no route). To remove a route, use
// RemoveRoute.
func (rt *RouteTable) AddRoute(dst, nextHop noise.PublicKey) {
	rt.mu.Lock()
	rt.routes[dst] = nextHop
	rt.mu.Unlock()
}

// RemoveRoute removes the route for dst. After removal, dst is treated as
// directly reachable (NextHop returns dst, RelayFor returns nil).
func (rt *RouteTable) RemoveRoute(dst noise.PublicKey) {
	rt.mu.Lock()
	delete(rt.routes, dst)
	rt.mu.Unlock()
}

// NextHop returns the next peer to forward to for reaching dst.
// If a route exists and nextHop != dst, the destination is reached via relay.
// If no route exists OR nextHop == dst, the destination is directly reachable.
// Returns ErrNoRoute only if the caller explicitly needs route-not-found
// semantics — for the common case, no route means "try direct".
//
// Implements the Router interface for relay engine forwarding.
func (rt *RouteTable) NextHop(dst [32]byte, _ Strategy) (nextHop [32]byte, err error) {
	pk := noise.PublicKey(dst)
	rt.mu.RLock()
	nh, ok := rt.routes[pk]
	rt.mu.RUnlock()

	if ok {
		return [32]byte(nh), nil
	}
	// No explicit route: treat as direct (return dst itself).
	return dst, nil
}

// RelayFor returns the relay peer's public key if dst should be sent through
// a relay, or nil if dst is directly reachable.
//
// A destination is relayed when a route exists AND the next-hop differs from dst.
// A route where nextHop == dst is treated as direct.
func (rt *RouteTable) RelayFor(dst noise.PublicKey) *noise.PublicKey {
	rt.mu.RLock()
	nh, ok := rt.routes[dst]
	rt.mu.RUnlock()

	if !ok || nh == dst {
		return nil
	}
	relay := nh
	return &relay
}

// HasRoute returns whether an explicit route exists for dst.
func (rt *RouteTable) HasRoute(dst noise.PublicKey) bool {
	rt.mu.RLock()
	_, ok := rt.routes[dst]
	rt.mu.RUnlock()
	return ok
}

// Len returns the number of routes.
func (rt *RouteTable) Len() int {
	rt.mu.RLock()
	n := len(rt.routes)
	rt.mu.RUnlock()
	return n
}

// Routes returns a snapshot copy of all routes. The caller owns the returned
// map and may mutate it freely.
func (rt *RouteTable) Routes() map[noise.PublicKey]noise.PublicKey {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	snap := make(map[noise.PublicKey]noise.PublicKey, len(rt.routes))
	for k, v := range rt.routes {
		snap[k] = v
	}
	return snap
}
