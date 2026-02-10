package config

import (
	"testing"
)

func TestDiff_PeersAdded(t *testing.T) {
	old := &Config{Peers: map[string]PeerConfig{}}
	new := &Config{Peers: map[string]PeerConfig{
		"aabb.zigor.net": {Alias: "new_peer", Direct: []string{"1.2.3.4:51820"}},
	}}

	d := Diff(old, new)
	if len(d.PeersAdded) != 1 {
		t.Fatalf("PeersAdded = %d, want 1", len(d.PeersAdded))
	}
	if _, ok := d.PeersAdded["aabb.zigor.net"]; !ok {
		t.Error("expected aabb.zigor.net in PeersAdded")
	}
	if len(d.PeersRemoved) != 0 {
		t.Errorf("PeersRemoved = %d, want 0", len(d.PeersRemoved))
	}
}

func TestDiff_PeersRemoved(t *testing.T) {
	old := &Config{Peers: map[string]PeerConfig{
		"aabb.zigor.net": {Alias: "old_peer"},
	}}
	new := &Config{Peers: map[string]PeerConfig{}}

	d := Diff(old, new)
	if len(d.PeersRemoved) != 1 {
		t.Fatalf("PeersRemoved = %d, want 1", len(d.PeersRemoved))
	}
	if d.PeersRemoved[0] != "aabb.zigor.net" {
		t.Errorf("PeersRemoved[0] = %q", d.PeersRemoved[0])
	}
}

func TestDiff_PeersChanged(t *testing.T) {
	old := &Config{Peers: map[string]PeerConfig{
		"aabb.zigor.net": {Alias: "peer", Direct: []string{"1.1.1.1:51820"}},
	}}
	new := &Config{Peers: map[string]PeerConfig{
		"aabb.zigor.net": {Alias: "peer", Direct: []string{"2.2.2.2:51820"}},
	}}

	d := Diff(old, new)
	if len(d.PeersChanged) != 1 {
		t.Fatalf("PeersChanged = %d, want 1", len(d.PeersChanged))
	}
	changed := d.PeersChanged["aabb.zigor.net"]
	if changed.Direct[0] != "2.2.2.2:51820" {
		t.Errorf("changed direct = %v", changed.Direct)
	}
}

func TestDiff_PeersUnchanged(t *testing.T) {
	peers := map[string]PeerConfig{
		"aabb.zigor.net": {Alias: "peer", Direct: []string{"1.1.1.1:51820"}},
	}
	old := &Config{Peers: peers}
	new := &Config{Peers: peers}

	d := Diff(old, new)
	if !d.IsEmpty() {
		t.Error("expected empty diff for identical configs")
	}
}

func TestDiff_LansAdded(t *testing.T) {
	old := &Config{}
	new := &Config{Lans: []LanConfig{
		{Domain: "new.zigor.net", Pubkey: "abc", Endpoint: "1.2.3.4:51820"},
	}}

	d := Diff(old, new)
	if len(d.LansAdded) != 1 {
		t.Fatalf("LansAdded = %d, want 1", len(d.LansAdded))
	}
}

func TestDiff_LansRemoved(t *testing.T) {
	old := &Config{Lans: []LanConfig{
		{Domain: "old.zigor.net", Pubkey: "abc", Endpoint: "1.2.3.4:51820"},
	}}
	new := &Config{}

	d := Diff(old, new)
	if len(d.LansRemoved) != 1 {
		t.Fatalf("LansRemoved = %d, want 1", len(d.LansRemoved))
	}
}

func TestDiff_InboundChanged(t *testing.T) {
	old := &Config{InboundPolicy: InboundPolicy{Default: "deny"}}
	new := &Config{InboundPolicy: InboundPolicy{Default: "allow"}}

	d := Diff(old, new)
	if !d.InboundChanged {
		t.Error("expected InboundChanged = true")
	}
}

func TestDiff_RouteChanged(t *testing.T) {
	old := &Config{Route: RouteConfig{Rules: []RouteRule{
		{Domain: "*.google.com", Peer: "peer_us"},
	}}}
	new := &Config{Route: RouteConfig{Rules: []RouteRule{
		{Domain: "*.google.com", Peer: "peer_jp"},
	}}}

	d := Diff(old, new)
	if !d.RouteChanged {
		t.Error("expected RouteChanged = true")
	}
}

func TestDiff_Empty(t *testing.T) {
	cfg := &Config{
		InboundPolicy: InboundPolicy{Default: "deny"},
		Route:         RouteConfig{Rules: []RouteRule{{Domain: "*.google.com", Peer: "p"}}},
	}
	d := Diff(cfg, cfg)
	if !d.IsEmpty() {
		t.Error("expected empty diff for identical configs")
	}
}
