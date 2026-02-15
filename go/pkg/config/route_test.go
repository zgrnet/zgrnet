package config

import (
	"testing"
)

func TestRouteMatcher_SuffixMatch(t *testing.T) {
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "google.com", Peer: "peer_us"},
	}}
	rm := NewRouteMatcher(cfg)

	tests := []struct {
		domain string
		match  bool
	}{
		{"google.com", true},
		{"www.google.com", true},
		{"mail.google.com", true},
		{"deep.sub.google.com", true},
		{"notgoogle.com", false},
		{"google.com.evil.com", false},
		{"example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			_, ok := rm.Match(tt.domain)
			if ok != tt.match {
				t.Errorf("Match(%q) = %v, want %v", tt.domain, ok, tt.match)
			}
		})
	}
}

func TestRouteMatcher_WildcardPrefixStripped(t *testing.T) {
	// "*.google.com" behaves identically to "google.com"
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "*.google.com", Peer: "peer_us"},
	}}
	rm := NewRouteMatcher(cfg)

	tests := []struct {
		domain string
		match  bool
	}{
		{"google.com", true},
		{"www.google.com", true},
		{"notgoogle.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			_, ok := rm.Match(tt.domain)
			if ok != tt.match {
				t.Errorf("Match(%q) = %v, want %v", tt.domain, ok, tt.match)
			}
		})
	}
}

func TestRouteMatcher_LongestSuffixWins(t *testing.T) {
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "google.com", Peer: "peer_us"},
		{Domain: "cn.google.com", Peer: "peer_cn"},
	}}
	rm := NewRouteMatcher(cfg)

	tests := []struct {
		domain string
		peer   string
	}{
		{"www.google.com", "peer_us"},
		{"cn.google.com", "peer_cn"},
		{"www.cn.google.com", "peer_cn"},
		{"google.com", "peer_us"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result, ok := rm.Match(tt.domain)
			if !ok {
				t.Fatalf("Match(%q) = false, want true", tt.domain)
			}
			if result.Peer != tt.peer {
				t.Errorf("Match(%q).Peer = %q, want %q", tt.domain, result.Peer, tt.peer)
			}
		})
	}
}

func TestRouteMatcher_LongestSuffixWins_OrderIndependent(t *testing.T) {
	// Order in config should not matter — longest suffix always wins
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "cn.google.com", Peer: "peer_cn"}, // more specific first
		{Domain: "google.com", Peer: "peer_us"},
	}}
	rm := NewRouteMatcher(cfg)

	result, ok := rm.Match("www.cn.google.com")
	if !ok {
		t.Fatal("expected match")
	}
	if result.Peer != "peer_cn" {
		t.Errorf("peer = %q, want peer_cn", result.Peer)
	}
}

func TestRouteMatcher_CaseInsensitive(t *testing.T) {
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "Google.COM", Peer: "peer_us"},
	}}
	rm := NewRouteMatcher(cfg)

	_, ok := rm.Match("WWW.GOOGLE.COM")
	if !ok {
		t.Error("expected case-insensitive match")
	}
}

func TestRouteMatcher_TrailingDot(t *testing.T) {
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "google.com", Peer: "peer_us"},
	}}
	rm := NewRouteMatcher(cfg)

	_, ok := rm.Match("www.google.com.")
	if !ok {
		t.Error("expected match with trailing dot")
	}
}

func TestRouteMatcher_NoMatch(t *testing.T) {
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "google.com", Peer: "peer_us"},
	}}
	rm := NewRouteMatcher(cfg)

	_, ok := rm.Match("example.com")
	if ok {
		t.Error("expected no match")
	}
}

func TestRouteMatcher_EmptyRules(t *testing.T) {
	cfg := &RouteConfig{}
	rm := NewRouteMatcher(cfg)

	_, ok := rm.Match("google.com")
	if ok {
		t.Error("expected no match with empty rules")
	}
}

func TestRouteMatcher_MatchRoute(t *testing.T) {
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "google.com", Peer: "peer_us"},
	}}
	rm := NewRouteMatcher(cfg)

	peer, ok := rm.MatchRoute("www.google.com")
	if !ok {
		t.Fatal("expected match")
	}
	if peer != "peer_us" {
		t.Errorf("peer = %q, want peer_us", peer)
	}

	_, ok = rm.MatchRoute("example.com")
	if ok {
		t.Error("expected no match")
	}
}
