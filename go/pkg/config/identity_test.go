package config

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockIPAllocator implements IPAllocator for testing.
type mockIPAllocator struct {
	byIP map[[4]byte][32]byte
}

func (m *mockIPAllocator) LookupByIP(ip net.IP) ([32]byte, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return [32]byte{}, false
	}
	key := [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
	pk, ok := m.byIP[key]
	return pk, ok
}

func TestIdentityHandler_Success(t *testing.T) {
	pk := hexKey("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	alloc := &mockIPAllocator{
		byIP: map[[4]byte][32]byte{
			{100, 64, 0, 5}: pk,
		},
	}

	store := NewLabelStore()
	store.SetLabels(
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		[]string{"host.zigor.net/trusted", "company.zigor.net/employee"},
	)

	handler := IdentityHandler(alloc, store)

	req := httptest.NewRequest("GET", "/internal/identity?ip=100.64.0.5", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp IdentityResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Pubkey != "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" {
		t.Errorf("pubkey = %q", resp.Pubkey)
	}
	if len(resp.Labels) != 2 {
		t.Errorf("labels count = %d, want 2", len(resp.Labels))
	}
	if resp.Labels[0] != "host.zigor.net/trusted" {
		t.Errorf("labels[0] = %q", resp.Labels[0])
	}
}

func TestIdentityHandler_UnknownIP(t *testing.T) {
	alloc := &mockIPAllocator{byIP: map[[4]byte][32]byte{}}
	store := NewLabelStore()
	handler := IdentityHandler(alloc, store)

	req := httptest.NewRequest("GET", "/internal/identity?ip=100.64.0.99", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestIdentityHandler_NoLabels(t *testing.T) {
	pk := hexKey("0000000000000000000000000000000000000000000000000000000000000001")
	alloc := &mockIPAllocator{
		byIP: map[[4]byte][32]byte{
			{100, 64, 0, 2}: pk,
		},
	}
	store := NewLabelStore()
	handler := IdentityHandler(alloc, store)

	req := httptest.NewRequest("GET", "/internal/identity?ip=100.64.0.2", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp IdentityResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Labels) != 0 {
		t.Errorf("expected empty labels, got %v", resp.Labels)
	}
}

func TestIdentityHandler_MissingIP(t *testing.T) {
	alloc := &mockIPAllocator{byIP: map[[4]byte][32]byte{}}
	store := NewLabelStore()
	handler := IdentityHandler(alloc, store)

	req := httptest.NewRequest("GET", "/internal/identity", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestIdentityHandler_InvalidIP(t *testing.T) {
	alloc := &mockIPAllocator{byIP: map[[4]byte][32]byte{}}
	store := NewLabelStore()
	handler := IdentityHandler(alloc, store)

	req := httptest.NewRequest("GET", "/internal/identity?ip=not-an-ip", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestIdentityHandler_MethodNotAllowed(t *testing.T) {
	alloc := &mockIPAllocator{byIP: map[[4]byte][32]byte{}}
	store := NewLabelStore()
	handler := IdentityHandler(alloc, store)

	req := httptest.NewRequest("POST", "/internal/identity?ip=100.64.0.1", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}
