package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRouteMatcher_ExactMatch(t *testing.T) {
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "google.com", Peer: "peer_us"},
	}}
	rm, err := NewRouteMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	result, ok := rm.Match("google.com")
	if !ok {
		t.Fatal("expected match")
	}
	if result.Peer != "peer_us" {
		t.Errorf("peer = %q, want peer_us", result.Peer)
	}

	_, ok = rm.Match("www.google.com")
	if ok {
		t.Error("exact match should not match subdomain")
	}
}

func TestRouteMatcher_WildcardMatch(t *testing.T) {
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "*.google.com", Peer: "peer_us"},
	}}
	rm, err := NewRouteMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		domain string
		match  bool
	}{
		{"www.google.com", true},
		{"mail.google.com", true},
		{"deep.sub.google.com", true},
		{"google.com", true},          // *.google.com also matches google.com
		{"notgoogle.com", false},       // should not match
		{"google.com.evil.com", false}, // should not match
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

func TestRouteMatcher_DomainList(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "domains.txt")
	content := "# GFW list\ngoogle.com\nyoutube.com\n\n# Social\ntwitter.com\n"
	if err := os.WriteFile(listPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &RouteConfig{Rules: []RouteRule{
		{DomainList: listPath, Peer: "peer_us"},
	}}
	rm, err := NewRouteMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		domain string
		match  bool
	}{
		{"google.com", true},
		{"www.google.com", true},    // parent domain match
		{"youtube.com", true},
		{"m.youtube.com", true},
		{"twitter.com", true},
		{"facebook.com", false},
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

func TestRouteMatcher_CaseInsensitive(t *testing.T) {
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "*.Google.COM", Peer: "peer_us"},
	}}
	rm, err := NewRouteMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := rm.Match("WWW.GOOGLE.COM")
	if !ok {
		t.Error("expected case-insensitive match")
	}
}

func TestRouteMatcher_TrailingDot(t *testing.T) {
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "*.google.com", Peer: "peer_us"},
	}}
	rm, err := NewRouteMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// DNS queries sometimes include trailing dot
	_, ok := rm.Match("www.google.com.")
	if !ok {
		t.Error("expected match with trailing dot")
	}
}

func TestRouteMatcher_Priority(t *testing.T) {
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "*.google.com", Peer: "peer_us"},
		{Domain: "*.google.com", Peer: "peer_jp"}, // lower priority
	}}
	rm, err := NewRouteMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	result, ok := rm.Match("www.google.com")
	if !ok {
		t.Fatal("expected match")
	}
	if result.Peer != "peer_us" {
		t.Errorf("peer = %q, want peer_us (first match wins)", result.Peer)
	}
}

func TestRouteMatcher_NoMatch(t *testing.T) {
	cfg := &RouteConfig{Rules: []RouteRule{
		{Domain: "*.google.com", Peer: "peer_us"},
	}}
	rm, err := NewRouteMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := rm.Match("example.com")
	if ok {
		t.Error("expected no match")
	}
}

func TestRouteMatcher_EmptyRules(t *testing.T) {
	cfg := &RouteConfig{}
	rm, err := NewRouteMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := rm.Match("google.com")
	if ok {
		t.Error("expected no match with empty rules")
	}
}

func TestRouteMatcher_Reload(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "domains.txt")

	// Initial: only google.com
	if err := os.WriteFile(listPath, []byte("google.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &RouteConfig{Rules: []RouteRule{
		{DomainList: listPath, Peer: "peer_us"},
	}}
	rm, err := NewRouteMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := rm.Match("twitter.com"); ok {
		t.Error("twitter.com should not match initially")
	}

	// Update file: add twitter.com
	if err := os.WriteFile(listPath, []byte("google.com\ntwitter.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := rm.Reload(); err != nil {
		t.Fatal(err)
	}

	if _, ok := rm.Match("twitter.com"); !ok {
		t.Error("twitter.com should match after reload")
	}
}

func TestRouteMatcher_DomainListFileNotFound(t *testing.T) {
	cfg := &RouteConfig{Rules: []RouteRule{
		{DomainList: "/nonexistent/domains.txt", Peer: "peer_us"},
	}}
	_, err := NewRouteMatcher(cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent domain list file")
	}
}
