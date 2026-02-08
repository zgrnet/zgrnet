package proxy

import (
	"errors"
	"net"

	"github.com/vibing/zgrnet/pkg/noise"
)

// Policy controls which target addresses are allowed for proxying.
// Used on exit nodes to prevent SSRF attacks, and on proxy servers
// to enforce access control rules.
//
// Implementations can enforce allow-lists, deny-lists, or custom logic.
// A nil Policy means allow all (for tests and trusted environments).
type Policy interface {
	// Allow checks if a connection to the given address is permitted.
	Allow(addr *noise.Address) bool
}

// ErrPolicyDenied is returned when the policy denies a connection.
var ErrPolicyDenied = errors.New("proxy: connection denied by policy")

// checkPolicy returns true if the address is allowed (nil policy = allow all).
func checkPolicy(p Policy, addr *noise.Address) bool {
	return p == nil || p.Allow(addr)
}

// AllowAllPolicy permits all addresses. Use for testing only.
type AllowAllPolicy struct{}

func (p *AllowAllPolicy) Allow(_ *noise.Address) bool { return true }

// DenyPrivatePolicy blocks connections to private, loopback, and
// link-local IP addresses. This prevents SSRF attacks where a client
// tries to reach internal services (169.254.169.254, 127.0.0.1, etc.)
// through the exit node.
//
// Domain names are allowed — they resolve on the exit node.
type DenyPrivatePolicy struct{}

func (p *DenyPrivatePolicy) Allow(addr *noise.Address) bool {
	if addr.Type == noise.AddressTypeDomain {
		return true
	}

	ip := net.ParseIP(addr.Host)
	if ip == nil {
		return false // Unparseable = deny
	}

	if ip.IsLoopback() {
		return false
	}
	if ip.IsPrivate() {
		return false
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsUnspecified() {
		return false
	}

	return true
}
