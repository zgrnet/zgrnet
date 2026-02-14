package config

import "slices"

// ConfigDiff represents the differences between two configurations.
// Used by consumers to perform incremental reconciliation.
type ConfigDiff struct {
	// Peers
	PeersAdded   map[string]PeerConfig // domain -> config
	PeersRemoved []string              // domains
	PeersChanged map[string]PeerConfig // domain -> new config

	// Lans
	LansAdded   []LanConfig
	LansRemoved []LanConfig

	// Flags for sections that changed (consumers re-read the full section)
	InboundChanged bool
	RouteChanged   bool
}

// IsEmpty returns true if there are no differences.
func (d *ConfigDiff) IsEmpty() bool {
	return len(d.PeersAdded) == 0 &&
		len(d.PeersRemoved) == 0 &&
		len(d.PeersChanged) == 0 &&
		len(d.LansAdded) == 0 &&
		len(d.LansRemoved) == 0 &&
		!d.InboundChanged &&
		!d.RouteChanged
}

// Diff computes the differences between two configurations.
// Net config changes are not tracked (require restart).
func Diff(old, new *Config) *ConfigDiff {
	d := &ConfigDiff{
		PeersAdded:   make(map[string]PeerConfig),
		PeersChanged: make(map[string]PeerConfig),
	}

	diffPeers(old.Peers, new.Peers, d)
	diffLans(old.Lans, new.Lans, d)
	d.InboundChanged = !inboundPolicyEqual(&old.InboundPolicy, &new.InboundPolicy)
	d.RouteChanged = !routeConfigEqual(&old.Route, &new.Route)

	return d
}

func diffPeers(old, new map[string]PeerConfig, d *ConfigDiff) {
	// Find added and changed peers
	for domain, newPeer := range new {
		oldPeer, exists := old[domain]
		if !exists {
			d.PeersAdded[domain] = newPeer
		} else if !peerConfigEqual(&oldPeer, &newPeer) {
			d.PeersChanged[domain] = newPeer
		}
	}
	// Find removed peers
	for domain := range old {
		if _, exists := new[domain]; !exists {
			d.PeersRemoved = append(d.PeersRemoved, domain)
		}
	}
}

func diffLans(old, new []LanConfig, d *ConfigDiff) {
	oldMap := make(map[string]LanConfig, len(old))
	for _, l := range old {
		oldMap[l.Domain] = l
	}
	newMap := make(map[string]LanConfig, len(new))
	for _, l := range new {
		newMap[l.Domain] = l
	}

	// Added
	for _, l := range new {
		if _, exists := oldMap[l.Domain]; !exists {
			d.LansAdded = append(d.LansAdded, l)
		}
	}
	// Removed
	for _, l := range old {
		if _, exists := newMap[l.Domain]; !exists {
			d.LansRemoved = append(d.LansRemoved, l)
		}
	}
}

func peerConfigEqual(a, b *PeerConfig) bool {
	if a.Alias != b.Alias {
		return false
	}
	if !slices.Equal(a.Direct, b.Direct) {
		return false
	}
	if !slices.Equal(a.Relay, b.Relay) {
		return false
	}
	if !slices.Equal(a.Labels, b.Labels) {
		return false
	}
	return true
}

func inboundPolicyEqual(a, b *InboundPolicy) bool {
	if a.Default != b.Default {
		return false
	}
	if a.RevalidateInterval != b.RevalidateInterval {
		return false
	}
	if len(a.Rules) != len(b.Rules) {
		return false
	}
	for i := range a.Rules {
		if !inboundRuleEqual(&a.Rules[i], &b.Rules[i]) {
			return false
		}
	}
	return true
}

func inboundRuleEqual(a, b *InboundRule) bool {
	if a.Name != b.Name || a.Action != b.Action {
		return false
	}
	if a.Match.Pubkey.Type != b.Match.Pubkey.Type ||
		a.Match.Pubkey.Path != b.Match.Pubkey.Path ||
		a.Match.Pubkey.Peer != b.Match.Pubkey.Peer {
		return false
	}
	if !slices.Equal(a.Match.Labels, b.Match.Labels) {
		return false
	}
	if len(a.Services) != len(b.Services) {
		return false
	}
	for i := range a.Services {
		if a.Services[i] != b.Services[i] {
			return false
		}
	}
	return true
}

func routeConfigEqual(a, b *RouteConfig) bool {
	if len(a.Rules) != len(b.Rules) {
		return false
	}
	for i := range a.Rules {
		if a.Rules[i] != b.Rules[i] {
			return false
		}
	}
	return true
}
