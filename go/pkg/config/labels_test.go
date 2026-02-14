package config

import (
	"testing"
)

func TestLabelStore_BasicOperations(t *testing.T) {
	store := NewLabelStore()

	pk := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	// Initially empty
	if labels := store.Labels(pk); labels != nil {
		t.Errorf("expected nil labels, got %v", labels)
	}
	if store.Count() != 0 {
		t.Errorf("expected count 0, got %d", store.Count())
	}

	// Add labels
	store.AddLabels(pk, []string{"host.zigor.net/trusted", "host.zigor.net/friend"})
	labels := store.Labels(pk)
	if len(labels) != 2 {
		t.Fatalf("expected 2 labels, got %d", len(labels))
	}
	if labels[0] != "host.zigor.net/trusted" || labels[1] != "host.zigor.net/friend" {
		t.Errorf("labels = %v", labels)
	}
	if store.Count() != 1 {
		t.Errorf("expected count 1, got %d", store.Count())
	}
}

func TestLabelStore_AddDuplicates(t *testing.T) {
	store := NewLabelStore()
	pk := "0000000000000000000000000000000000000000000000000000000000000001"

	store.AddLabels(pk, []string{"host.zigor.net/trusted"})
	store.AddLabels(pk, []string{"host.zigor.net/trusted", "host.zigor.net/friend"})

	labels := store.Labels(pk)
	if len(labels) != 2 {
		t.Errorf("expected 2 labels (no dup), got %d: %v", len(labels), labels)
	}
}

func TestLabelStore_SetLabels(t *testing.T) {
	store := NewLabelStore()
	pk := "0000000000000000000000000000000000000000000000000000000000000001"

	store.AddLabels(pk, []string{"host.zigor.net/old"})
	store.SetLabels(pk, []string{"host.zigor.net/new"})

	labels := store.Labels(pk)
	if len(labels) != 1 || labels[0] != "host.zigor.net/new" {
		t.Errorf("expected [host.zigor.net/new], got %v", labels)
	}

	// SetLabels with empty removes the peer
	store.SetLabels(pk, nil)
	if labels := store.Labels(pk); labels != nil {
		t.Errorf("expected nil after SetLabels(nil), got %v", labels)
	}
	if store.Count() != 0 {
		t.Errorf("expected count 0, got %d", store.Count())
	}
}

func TestLabelStore_RemoveByLanDomain(t *testing.T) {
	store := NewLabelStore()
	pk := "0000000000000000000000000000000000000000000000000000000000000001"

	store.AddLabels(pk, []string{
		"host.zigor.net/trusted",
		"company.zigor.net/employee",
		"company.zigor.net/dev-team",
	})

	// Remove company labels
	store.RemoveLabels(pk, "company.zigor.net")

	labels := store.Labels(pk)
	if len(labels) != 1 || labels[0] != "host.zigor.net/trusted" {
		t.Errorf("expected [host.zigor.net/trusted], got %v", labels)
	}
}

func TestLabelStore_RemovePeer(t *testing.T) {
	store := NewLabelStore()
	pk := "0000000000000000000000000000000000000000000000000000000000000001"

	store.AddLabels(pk, []string{"host.zigor.net/trusted"})
	store.RemovePeer(pk)

	if labels := store.Labels(pk); labels != nil {
		t.Errorf("expected nil, got %v", labels)
	}
}

func TestLabelStore_LoadFromConfig(t *testing.T) {
	store := NewLabelStore()
	pk := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa"
	domain := pk + ".zigor.net"

	// Pre-populate with remote lan labels
	store.AddLabels(pk, []string{"company.zigor.net/employee"})

	peers := map[string]PeerConfig{
		domain: {
			Alias:  "peer_us",
			Direct: []string{"1.2.3.4:51820"},
			Labels: []string{"host.zigor.net/trusted", "host.zigor.net/exit-node"},
		},
	}

	store.LoadFromConfig(peers)

	labels := store.Labels(pk)
	if len(labels) != 3 {
		t.Fatalf("expected 3 labels, got %d: %v", len(labels), labels)
	}
	// company label should be preserved, host labels added from config
	found := map[string]bool{}
	for _, l := range labels {
		found[l] = true
	}
	if !found["company.zigor.net/employee"] {
		t.Error("missing company.zigor.net/employee")
	}
	if !found["host.zigor.net/trusted"] {
		t.Error("missing host.zigor.net/trusted")
	}
	if !found["host.zigor.net/exit-node"] {
		t.Error("missing host.zigor.net/exit-node")
	}
}

func TestMatchLabel_Exact(t *testing.T) {
	labels := []string{"host.zigor.net/trusted", "company.zigor.net/employee"}

	if !MatchLabel(labels, "host.zigor.net/trusted") {
		t.Error("expected match for exact label")
	}
	if MatchLabel(labels, "host.zigor.net/friend") {
		t.Error("expected no match for non-existent label")
	}
}

func TestMatchLabel_Wildcard(t *testing.T) {
	labels := []string{"company.zigor.net/employee", "company.zigor.net/dev-team"}

	if !MatchLabel(labels, "company.zigor.net/*") {
		t.Error("expected wildcard match")
	}
	if MatchLabel(labels, "other.zigor.net/*") {
		t.Error("expected no wildcard match for different domain")
	}
}

func TestMatchLabels(t *testing.T) {
	labels := []string{"host.zigor.net/trusted"}
	patterns := []string{"company.zigor.net/*", "host.zigor.net/trusted"}

	if !MatchLabels(labels, patterns) {
		t.Error("expected match with one of the patterns")
	}

	patterns2 := []string{"company.zigor.net/*", "other.zigor.net/admin"}
	if MatchLabels(labels, patterns2) {
		t.Error("expected no match")
	}
}

func TestMatchLabels_Empty(t *testing.T) {
	if MatchLabels(nil, []string{"host.zigor.net/trusted"}) {
		t.Error("nil labels should not match")
	}
	if MatchLabels([]string{"host.zigor.net/trusted"}, nil) {
		t.Error("nil patterns should not match")
	}
}

func TestPubkeyHexFromDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"abcdef01.zigor.net", "abcdef01"},
		{"ABCDEF01.zigor.net", "abcdef01"},
		{"abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa.zigor.net",
			"abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa"},
		{"not-hex.zigor.net", ""},
		{"example.com", ""},
		{".zigor.net", ""},
	}

	for _, tt := range tests {
		got := pubkeyHexFromDomain(tt.domain)
		if got != tt.want {
			t.Errorf("pubkeyHexFromDomain(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}
