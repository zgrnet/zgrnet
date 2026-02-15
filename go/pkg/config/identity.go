package config

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
)

// IdentityResponse is the JSON response for the Identity API.
type IdentityResponse struct {
	Pubkey string   `json:"pubkey"`
	Labels []string `json:"labels"`
}

// IPAllocator provides IP-to-pubkey lookups for the Identity API.
// This interface decouples the config package from the host package.
type IPAllocator interface {
	// LookupByIP returns the 32-byte public key for the given IPv4 address.
	LookupByIP(ip net.IP) ([32]byte, bool)
}

// IdentityHandler creates an HTTP handler for the Identity API.
//
//	GET /internal/identity?ip=100.64.0.5
//	→ { "pubkey": "abc123...", "labels": ["host.zigor.net/trusted", ...] }
//
// The handler queries:
//  1. IPAllocator: ip → pubkey
//  2. LabelStore: pubkey → labels
func IdentityHandler(ipAlloc IPAllocator, labelStore *LabelStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ipStr := r.URL.Query().Get("ip")
		if ipStr == "" {
			http.Error(w, "missing ip parameter", http.StatusBadRequest)
			return
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			http.Error(w, "invalid ip parameter", http.StatusBadRequest)
			return
		}

		pubkey, ok := ipAlloc.LookupByIP(ip)
		if !ok {
			http.Error(w, "unknown ip", http.StatusNotFound)
			return
		}

		pubkeyHex := hex.EncodeToString(pubkey[:])
		var labels []string
		if labelStore != nil {
			labels = labelStore.Labels(pubkeyHex)
		}
		if labels == nil {
			labels = []string{}
		}

		resp := IdentityResponse{
			Pubkey: pubkeyHex,
			Labels: labels,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("identity: encode response: %v", err)
		}
	}
}
