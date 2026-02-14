// Package api provides the zgrnetd RESTful API server.
//
// The API server listens on the TUN IP (typically localhost.zigor.net)
// and provides endpoints for querying node status, managing peers,
// editing inbound policy/routes, and performing identity lookups.
//
// Read-only endpoints:
//
//	GET  /api/whoami            → node info (pubkey, TUN IP, uptime)
//	GET  /api/config/net        → network config (read-only section)
//
// Peers CRUD:
//
//	GET    /api/peers           → list all peers
//	GET    /api/peers/{pubkey}  → peer detail
//	POST   /api/peers           → add peer
//	PUT    /api/peers/{pubkey}  → update peer
//	DELETE /api/peers/{pubkey}  → remove peer
//
// Lans:
//
//	GET    /api/lans            → list lans
//	POST   /api/lans            → join lan
//	DELETE /api/lans/{domain}   → leave lan
//
// Policy:
//
//	GET    /api/policy              → current inbound policy
//	POST   /api/policy/rules       → add policy rule
//	DELETE /api/policy/rules/{name} → remove policy rule
//
// Routes:
//
//	GET    /api/routes          → list route rules
//	POST   /api/routes          → add route rule
//	DELETE /api/routes/{id}     → remove route rule (by index)
//
// Identity (internal):
//
//	GET  /internal/identity?ip=x → pubkey + IP for the given address
//
// Config operations:
//
//	POST /api/config/reload     → reload config from disk
package api

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vibing/zgrnet/pkg/config"
	"github.com/vibing/zgrnet/pkg/dns"
	"github.com/vibing/zgrnet/pkg/host"
	"github.com/vibing/zgrnet/pkg/noise"
	"github.com/vibing/zgrnet/pkg/proxy"
)

//go:embed admin.html
var adminHTML []byte

// Server is the zgrnetd RESTful API server.
// It provides HTTP endpoints for managing peers, lans, policy, routes,
// and querying node status. Write operations persist changes to config.yaml
// and update the runtime state immediately.
type Server struct {
	host      *host.Host
	cfgMgr    *config.Manager
	dnsSrv    *dns.Server
	proxySrv  *proxy.Server
	startTime time.Time
	server    *http.Server
}

// ServerConfig holds parameters for creating an API server.
type ServerConfig struct {
	// ListenAddr is the address to listen on (e.g., "100.64.0.1:80").
	ListenAddr string

	// Host is the running Host instance (TUN + UDP + IP allocator).
	Host *host.Host

	// ConfigMgr is the config manager for reading/writing config.
	ConfigMgr *config.Manager

	// DNSServer is the running DNS server (optional, for stats).
	DNSServer *dns.Server

	// ProxyServer is the running SOCKS5 proxy server (optional, for stats).
	ProxyServer *proxy.Server
}

// NewServer creates a new API server with all routes registered.
func NewServer(cfg ServerConfig) *Server {
	s := &Server{
		host:      cfg.Host,
		cfgMgr:    cfg.ConfigMgr,
		dnsSrv:    cfg.DNSServer,
		proxySrv:  cfg.ProxyServer,
		startTime: time.Now(),
	}

	mux := http.NewServeMux()

	// Read-only
	mux.HandleFunc("GET /api/whoami", s.handleWhoAmI)
	mux.HandleFunc("GET /api/config/net", s.handleConfigNet)
	mux.HandleFunc("GET /api/dns/stats", s.handleDNSStats)
	mux.HandleFunc("GET /api/proxy/stats", s.handleProxyStats)

	// Peers CRUD
	mux.HandleFunc("GET /api/peers", s.handleListPeers)
	mux.HandleFunc("GET /api/peers/{pubkey}", s.handleGetPeer)
	mux.HandleFunc("POST /api/peers", s.handleAddPeer)
	mux.HandleFunc("PUT /api/peers/{pubkey}", s.handleUpdatePeer)
	mux.HandleFunc("DELETE /api/peers/{pubkey}", s.handleDeletePeer)

	// Lans
	mux.HandleFunc("GET /api/lans", s.handleListLans)
	mux.HandleFunc("POST /api/lans", s.handleAddLan)
	mux.HandleFunc("DELETE /api/lans/{domain}", s.handleDeleteLan)

	// Policy
	mux.HandleFunc("GET /api/policy", s.handleGetPolicy)
	mux.HandleFunc("POST /api/policy/rules", s.handleAddPolicyRule)
	mux.HandleFunc("DELETE /api/policy/rules/{name}", s.handleDeletePolicyRule)

	// Routes
	mux.HandleFunc("GET /api/routes", s.handleListRoutes)
	mux.HandleFunc("POST /api/routes", s.handleAddRoute)
	mux.HandleFunc("DELETE /api/routes/{id}", s.handleDeleteRoute)

	// Identity (internal)
	mux.HandleFunc("GET /internal/identity", s.handleIdentity)

	// Config operations
	mux.HandleFunc("POST /api/config/reload", s.handleConfigReload)

	// Admin Web UI
	mux.HandleFunc("GET /", s.handleAdminUI)

	s.server = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return s
}

// ListenAndServe starts the HTTP server. Blocks until Close() is called.
func (s *Server) ListenAndServe() error {
	return s.server.ListenAndServe()
}

// Close gracefully shuts down the HTTP server.
func (s *Server) Close() error {
	return s.server.Close()
}

// ─── Admin Web UI ───────────────────────────────────────────────────────────

func (s *Server) handleAdminUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(adminHTML)
}

// ─── JSON helpers ───────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("api: json encode error: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ─── GET /api/whoami ────────────────────────────────────────────────────────

func (s *Server) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	pk := s.host.PublicKey()
	cfg := s.cfgMgr.Current()
	uptime := time.Since(s.startTime)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pubkey":     hex.EncodeToString(pk[:]),
		"tun_ip":     cfg.Net.TunIPv4,
		"uptime":     uptime.Truncate(time.Second).String(),
		"uptime_sec": int64(uptime.Seconds()),
	})
}

// ─── GET /api/config/net ────────────────────────────────────────────────────

func (s *Server) handleConfigNet(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgMgr.Current()
	writeJSON(w, http.StatusOK, cfg.Net)
}

// ─── GET /api/dns/stats ─────────────────────────────────────────────────────

func (s *Server) handleDNSStats(w http.ResponseWriter, r *http.Request) {
	if s.dnsSrv == nil {
		writeJSON(w, http.StatusOK, dns.Stats{})
		return
	}
	writeJSON(w, http.StatusOK, s.dnsSrv.GetStats())
}

// ─── GET /api/proxy/stats ───────────────────────────────────────────────────

func (s *Server) handleProxyStats(w http.ResponseWriter, r *http.Request) {
	if s.proxySrv == nil {
		writeJSON(w, http.StatusOK, proxy.ProxyStats{})
		return
	}
	writeJSON(w, http.StatusOK, s.proxySrv.GetStats())
}

// ─── Peers ──────────────────────────────────────────────────────────────────

// peerResponse builds a JSON-friendly peer object by merging config and runtime state.
func (s *Server) peerResponse(domain string, pc config.PeerConfig) map[string]interface{} {
	hexPK := domainToPubkey(domain)
	resp := map[string]interface{}{
		"pubkey": hexPK,
		"domain": domain,
		"alias":  pc.Alias,
		"direct": pc.Direct,
		"relay":  pc.Relay,
	}

	// Enrich with runtime state from UDP transport
	pk, err := noise.KeyFromHex(hexPK)
	if err != nil {
		return resp
	}

	if info := s.host.UDP().PeerInfo(pk); info != nil {
		resp["state"] = info.State.String()
		resp["rx_bytes"] = info.RxBytes
		resp["tx_bytes"] = info.TxBytes
		if info.Endpoint != nil {
			resp["endpoint"] = info.Endpoint.String()
		}
		if !info.LastSeen.IsZero() {
			resp["last_seen"] = info.LastSeen.Format(time.RFC3339)
		}
	}

	if ip, ok := s.host.IPAlloc().LookupByPubkey(pk); ok {
		resp["tun_ip"] = ip.String()
	}

	return resp
}

func (s *Server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgMgr.Current()
	peers := make([]map[string]interface{}, 0, len(cfg.Peers))
	for domain, pc := range cfg.Peers {
		peers = append(peers, s.peerResponse(domain, pc))
	}
	writeJSON(w, http.StatusOK, peers)
}

func (s *Server) handleGetPeer(w http.ResponseWriter, r *http.Request) {
	hexPK := r.PathValue("pubkey")
	domain := pubkeyToDomain(hexPK)

	cfg := s.cfgMgr.Current()
	pc, ok := cfg.Peers[domain]
	if !ok {
		writeError(w, http.StatusNotFound, "peer not found")
		return
	}
	writeJSON(w, http.StatusOK, s.peerResponse(domain, pc))
}

func (s *Server) handleAddPeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey string   `json:"pubkey"`
		Alias    string   `json:"alias"`
		Endpoint string   `json:"endpoint"`
		Direct   []string `json:"direct"`
		Relay    []string `json:"relay"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "pubkey is required")
		return
	}
	pk, err := noise.KeyFromHex(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pubkey: "+err.Error())
		return
	}

	domain := pubkeyToDomain(req.PublicKey)

	// Build config entry — endpoint goes into direct[0] if direct is empty
	direct := req.Direct
	if req.Endpoint != "" && len(direct) == 0 {
		direct = []string{req.Endpoint}
	}
	pc := config.PeerConfig{
		Alias:  req.Alias,
		Direct: direct,
		Relay:  req.Relay,
	}

	// Persist to config file
	if err := s.cfgMgr.ModifyAndSave(func(cfg *config.Config) error {
		if cfg.Peers == nil {
			cfg.Peers = make(map[string]config.PeerConfig)
		}
		if _, exists := cfg.Peers[domain]; exists {
			return fmt.Errorf("peer %s already exists", req.PublicKey[:16])
		}
		cfg.Peers[domain] = pc
		return nil
	}); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	// Update runtime — add peer to Host
	endpoint := req.Endpoint
	if endpoint == "" && len(direct) > 0 {
		endpoint = direct[0]
	}
	if err := s.host.AddPeer(pk, endpoint); err != nil {
		log.Printf("api: peer saved but runtime add failed: %v", err)
	}

	writeJSON(w, http.StatusCreated, s.peerResponse(domain, pc))
}

func (s *Server) handleUpdatePeer(w http.ResponseWriter, r *http.Request) {
	hexPK := r.PathValue("pubkey")
	domain := pubkeyToDomain(hexPK)

	var req struct {
		Alias    *string  `json:"alias"`
		Endpoint *string  `json:"endpoint"`
		Direct   []string `json:"direct"`
		Relay    []string `json:"relay"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	var updatedPC config.PeerConfig
	if err := s.cfgMgr.ModifyAndSave(func(cfg *config.Config) error {
		pc, ok := cfg.Peers[domain]
		if !ok {
			return fmt.Errorf("peer not found")
		}
		if req.Alias != nil {
			pc.Alias = *req.Alias
		}
		if req.Direct != nil {
			pc.Direct = req.Direct
		}
		if req.Relay != nil {
			pc.Relay = req.Relay
		}
		if req.Endpoint != nil && *req.Endpoint != "" {
			if len(pc.Direct) == 0 {
				pc.Direct = []string{*req.Endpoint}
			} else {
				pc.Direct[0] = *req.Endpoint
			}
		}
		cfg.Peers[domain] = pc
		updatedPC = pc
		return nil
	}); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	// Update runtime endpoint if changed
	if req.Endpoint != nil || req.Direct != nil {
		if pk, err := noise.KeyFromHex(hexPK); err == nil {
			endpoint := ""
			if len(updatedPC.Direct) > 0 {
				endpoint = updatedPC.Direct[0]
			}
			if endpoint != "" {
				if addr, err := net.ResolveUDPAddr("udp", endpoint); err == nil {
					s.host.UDP().SetPeerEndpoint(pk, addr)
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, s.peerResponse(domain, updatedPC))
}

func (s *Server) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	hexPK := r.PathValue("pubkey")
	domain := pubkeyToDomain(hexPK)

	if err := s.cfgMgr.ModifyAndSave(func(cfg *config.Config) error {
		if _, ok := cfg.Peers[domain]; !ok {
			return fmt.Errorf("peer not found")
		}
		delete(cfg.Peers, domain)
		return nil
	}); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	// Update runtime — disconnect and release IP
	if pk, err := noise.KeyFromHex(hexPK); err == nil {
		s.host.RemovePeer(pk)
	}

	w.WriteHeader(http.StatusNoContent)
}

// ─── Lans ───────────────────────────────────────────────────────────────────

func (s *Server) handleListLans(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgMgr.Current()
	writeJSON(w, http.StatusOK, cfg.Lans)
}

func (s *Server) handleAddLan(w http.ResponseWriter, r *http.Request) {
	var req config.LanConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if err := s.cfgMgr.ModifyAndSave(func(cfg *config.Config) error {
		for _, lan := range cfg.Lans {
			if lan.Domain == req.Domain {
				return fmt.Errorf("lan %q already exists", req.Domain)
			}
		}
		cfg.Lans = append(cfg.Lans, req)
		return nil
	}); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, req)
}

func (s *Server) handleDeleteLan(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")

	if err := s.cfgMgr.ModifyAndSave(func(cfg *config.Config) error {
		for i, lan := range cfg.Lans {
			if lan.Domain == domain {
				cfg.Lans = append(cfg.Lans[:i], cfg.Lans[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("lan %q not found", domain)
	}); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ─── Policy ─────────────────────────────────────────────────────────────────

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgMgr.Current()
	writeJSON(w, http.StatusOK, cfg.InboundPolicy)
}

func (s *Server) handleAddPolicyRule(w http.ResponseWriter, r *http.Request) {
	var req config.InboundRule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if err := s.cfgMgr.ModifyAndSave(func(cfg *config.Config) error {
		for _, rule := range cfg.InboundPolicy.Rules {
			if rule.Name == req.Name {
				return fmt.Errorf("rule %q already exists", req.Name)
			}
		}
		cfg.InboundPolicy.Rules = append(cfg.InboundPolicy.Rules, req)
		return nil
	}); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, req)
}

func (s *Server) handleDeletePolicyRule(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if err := s.cfgMgr.ModifyAndSave(func(cfg *config.Config) error {
		for i, rule := range cfg.InboundPolicy.Rules {
			if rule.Name == name {
				cfg.InboundPolicy.Rules = append(cfg.InboundPolicy.Rules[:i], cfg.InboundPolicy.Rules[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("rule %q not found", name)
	}); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ─── Routes ─────────────────────────────────────────────────────────────────

func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgMgr.Current()
	writeJSON(w, http.StatusOK, cfg.Route.Rules)
}

func (s *Server) handleAddRoute(w http.ResponseWriter, r *http.Request) {
	var req config.RouteRule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if err := s.cfgMgr.ModifyAndSave(func(cfg *config.Config) error {
		cfg.Route.Rules = append(cfg.Route.Rules, req)
		return nil
	}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, req)
}

func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid route id: must be an integer")
		return
	}

	if err := s.cfgMgr.ModifyAndSave(func(cfg *config.Config) error {
		if id < 0 || id >= len(cfg.Route.Rules) {
			return fmt.Errorf("route index %d out of range (have %d rules)", id, len(cfg.Route.Rules))
		}
		cfg.Route.Rules = append(cfg.Route.Rules[:id], cfg.Route.Rules[id+1:]...)
		return nil
	}); err != nil {
		if strings.Contains(err.Error(), "out of range") {
			writeError(w, http.StatusNotFound, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ─── Identity ───────────────────────────────────────────────────────────────

func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request) {
	ipStr := r.URL.Query().Get("ip")
	if ipStr == "" {
		writeError(w, http.StatusBadRequest, "ip parameter is required")
		return
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}

	pk, ok := s.host.IPAlloc().LookupByIP(ip)
	if !ok {
		writeError(w, http.StatusNotFound, "no peer found for IP")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pubkey": hex.EncodeToString(pk[:]),
		"ip":     ipStr,
	})
}

// ─── Config Reload ──────────────────────────────────────────────────────────

func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	diff, err := s.cfgMgr.Reload()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reload failed: "+err.Error())
		return
	}

	if diff == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "no changes"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":          "reloaded",
		"peers_added":     len(diff.PeersAdded),
		"peers_removed":   len(diff.PeersRemoved),
		"peers_changed":   len(diff.PeersChanged),
		"inbound_changed": diff.InboundChanged,
		"route_changed":   diff.RouteChanged,
	})
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// pubkeyToDomain converts a hex pubkey string to the config domain format.
func pubkeyToDomain(hexPK string) string {
	return strings.ToLower(hexPK) + ".zigor.net"
}

// domainToPubkey extracts the hex pubkey from a ".zigor.net" domain.
func domainToPubkey(domain string) string {
	return strings.TrimSuffix(strings.ToLower(domain), ".zigor.net")
}
