// Package lan provides a composable LAN service for zgrnet.
//
// A LAN is a group of peers that share membership, labels, and events.
// The lan package exposes an HTTP handler that implements the zgrlan API:
//
//	GET    /api/lan/peers           — list online members + labels
//	POST   /api/lan/join            — join the LAN (requires authentication)
//	POST   /api/lan/leave           — leave the LAN
//	GET    /api/lan/query/:pubkey   — query a specific member
//	POST   /api/lan/labels/:pubkey  — set labels (admin only)
//	DELETE /api/lan/labels/:pubkey  — remove labels (admin only)
//	GET    /api/lan/events          — SSE event stream
//
// Both authentication and storage are pluggable:
//   - Register [Authenticator] implementations for join methods
//   - Provide a [Store] implementation for membership persistence
//
// The package includes built-in stores ([MemStore], [FileStore]) and
// authenticators (open, password, invite code, pubkey whitelist).
//
// Identity resolution (IP → pubkey) is injected via [IdentityFunc], so the
// package has no dependency on the host or transport layer.
package lan

import (
	"net"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// IdentityFunc resolves a remote IP address to its cryptographic identity.
// This is typically backed by the host's IP allocator (IP → pubkey).
// Returns the peer's public key and accumulated labels from all LANs.
type IdentityFunc func(ip net.IP) (pubkey noise.PublicKey, labels []string, err error)

// Member represents a peer that has joined the LAN.
type Member struct {
	// Pubkey is the member's Curve25519 public key (hex-encoded in JSON).
	Pubkey noise.PublicKey `json:"-"`

	// PubkeyHex is the hex-encoded public key for JSON serialization.
	PubkeyHex string `json:"pubkey"`

	// Labels are tags assigned to this member (e.g., "admin", "dev-team").
	Labels []string `json:"labels"`

	// JoinedAt is when the member joined.
	JoinedAt time.Time `json:"joined_at"`
}

// Event is a change notification pushed to subscribers.
type Event struct {
	// Type is the event kind: "join", "leave", "labels".
	Type string `json:"type"`

	// Pubkey is the affected member (hex-encoded).
	Pubkey string `json:"pubkey"`

	// Labels is set for "labels" events (new label set).
	Labels []string `json:"labels,omitempty"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`
}

// Config holds the configuration for creating a LAN server.
type Config struct {
	// Domain is the LAN's domain (e.g., "company.zigor.net").
	Domain string

	// Description is a human-readable description of the LAN.
	Description string

	// IdentityFn resolves IP → (pubkey, labels). Required.
	IdentityFn IdentityFunc
}

// Store is the interface for LAN membership persistence.
// Implementations must be safe for concurrent use.
type Store interface {
	// Add adds a member. Returns true if newly added.
	Add(pk noise.PublicKey) (bool, error)

	// Remove removes a member. Returns true if the member existed.
	Remove(pk noise.PublicKey) (bool, error)

	// Get returns a member by public key. Returns nil if not found.
	Get(pk noise.PublicKey) *Member

	// IsMember returns true if the public key is a member.
	IsMember(pk noise.PublicKey) bool

	// List returns all members as a snapshot.
	List() []*Member

	// SetLabels replaces the labels for the given member.
	SetLabels(pk noise.PublicKey, labels []string) error

	// RemoveLabels removes specific labels from the given member.
	RemoveLabels(pk noise.PublicKey, toRemove []string) error

	// Count returns the number of members.
	Count() int
}
