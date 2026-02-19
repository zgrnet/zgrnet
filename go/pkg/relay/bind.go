package relay

import (
	"sync"
	"sync/atomic"
	"time"
)

// BindEntry records a relay_id → (src, dst, nextHop) mapping used by ALIAS mode.
type BindEntry struct {
	SrcKey  [32]byte
	DstKey  [32]byte
	NextHop [32]byte
	Created time.Time
}

// BindTable manages relay_id allocations for the BIND/ALIAS short mode.
// Each relay node maintains its own BindTable. When a RELAY_0/1/2 message
// is forwarded, the relay allocates a relay_id, stores the routing info,
// and sends a BIND message back to the sender. Subsequent messages can
// use ALIAS (relay_id + payload) instead of full pubkeys.
//
// Thread-safe: all methods are safe for concurrent use.
type BindTable struct {
	mu      sync.RWMutex
	entries map[uint32]*BindEntry
	nextID  atomic.Uint32
}

// NewBindTable creates an empty bind table.
func NewBindTable() *BindTable {
	bt := &BindTable{
		entries: make(map[uint32]*BindEntry),
	}
	bt.nextID.Store(1) // IDs start at 1; 0 is reserved
	return bt
}

// Allocate creates a new relay_id for the given routing triplet.
// Returns the allocated relay_id.
func (bt *BindTable) Allocate(src, dst, nextHop [32]byte) uint32 {
	id := bt.nextID.Add(1) - 1
	entry := &BindEntry{
		SrcKey:  src,
		DstKey:  dst,
		NextHop: nextHop,
		Created: time.Now(),
	}
	bt.mu.Lock()
	bt.entries[id] = entry
	bt.mu.Unlock()
	return id
}

// Lookup returns the BindEntry for a relay_id, or nil if not found.
func (bt *BindTable) Lookup(relayID uint32) *BindEntry {
	bt.mu.RLock()
	entry := bt.entries[relayID]
	bt.mu.RUnlock()
	return entry
}

// Remove removes a relay_id entry.
func (bt *BindTable) Remove(relayID uint32) {
	bt.mu.Lock()
	delete(bt.entries, relayID)
	bt.mu.Unlock()
}

// Len returns the number of active entries.
func (bt *BindTable) Len() int {
	bt.mu.RLock()
	n := len(bt.entries)
	bt.mu.RUnlock()
	return n
}

// Expire removes all entries older than maxAge. Returns the number removed.
func (bt *BindTable) Expire(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	bt.mu.Lock()
	defer bt.mu.Unlock()

	removed := 0
	for id, entry := range bt.entries {
		if !entry.Created.After(cutoff) {
			delete(bt.entries, id)
			removed++
		}
	}
	return removed
}

// HandleRelay0WithBind processes a RELAY_0 message, forwards it, and
// optionally returns a BIND action to send back to the sender.
// This replaces HandleRelay0 when BIND/ALIAS is enabled.
//
// Returns: forwardAction (to next hop), bindAction (to sender, may be nil), error.
func HandleRelay0WithBind(router Router, bt *BindTable, from [32]byte, data []byte) (forward *Action, bind *Action, err error) {
	r0, err := DecodeRelay0(data)
	if err != nil {
		return nil, nil, err
	}

	if r0.TTL == 0 {
		return nil, nil, ErrTTLExpired
	}

	nextHop, err := router.NextHop(r0.DstKey, r0.Strategy)
	if err != nil {
		return nil, nil, err
	}

	if nextHop == r0.DstKey {
		r2 := &Relay2{SrcKey: from, Payload: r0.Payload}
		forward = &Action{
			Dst:      nextHop,
			Protocol: 68, // ProtocolRelay2
			Data:     EncodeRelay2(r2),
		}
	} else {
		r1 := &Relay1{
			TTL: r0.TTL - 1, Strategy: r0.Strategy,
			SrcKey: from, DstKey: r0.DstKey, Payload: r0.Payload,
		}
		forward = &Action{
			Dst:      nextHop,
			Protocol: 67, // ProtocolRelay1
			Data:     EncodeRelay1(r1),
		}
	}

	// Allocate relay_id and produce BIND action back to sender
	if bt != nil {
		relayID := bt.Allocate(from, r0.DstKey, nextHop)
		bindMsg := EncodeRelay0Bind(&Relay0Bind{
			RelayID: relayID,
			DstKey:  r0.DstKey,
		})
		bind = &Action{
			Dst:      from,
			Protocol: 72, // ProtocolRelay0Bind
			Data:     bindMsg,
		}
	}

	return forward, bind, nil
}

// HandleRelay0Alias processes a RELAY_0_ALIAS message by looking up the
// relay_id in the BindTable, reconstituting the full routing info, and
// producing a forward action.
func HandleRelay0Alias(bt *BindTable, from [32]byte, data []byte) (*Action, error) {
	alias, err := DecodeRelay0Alias(data)
	if err != nil {
		return nil, err
	}

	entry := bt.Lookup(alias.RelayID)
	if entry == nil {
		return nil, ErrNoRoute
	}

	// Verify sender matches
	if entry.SrcKey != from {
		return nil, ErrNoRoute
	}

	if entry.NextHop == entry.DstKey {
		r2 := &Relay2{SrcKey: from, Payload: alias.Payload}
		return &Action{
			Dst:      entry.NextHop,
			Protocol: 68, // ProtocolRelay2
			Data:     EncodeRelay2(r2),
		}, nil
	}

	r1 := &Relay1{
		TTL: DefaultTTL, Strategy: StrategyAuto,
		SrcKey: from, DstKey: entry.DstKey, Payload: alias.Payload,
	}
	return &Action{
		Dst:      entry.NextHop,
		Protocol: 67, // ProtocolRelay1
		Data:     EncodeRelay1(r1),
	}, nil
}
