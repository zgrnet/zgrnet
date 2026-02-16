package lan

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// Server is the LAN service. It holds the store, authenticators, and event
// subscribers. Use [NewServer] to create one, register authenticators with
// [Server.RegisterAuth], then mount [Server.Handler] on an HTTP mux.
type Server struct {
	cfg   Config
	store Store

	mu    sync.RWMutex
	auths map[string]Authenticator

	// Event subscribers (WebSocket or polling).
	subMu   sync.Mutex
	subs    map[uint64]chan Event
	nextSub uint64
}

// NewServer creates a new LAN server with the given Store implementation.
// cfg.IdentityFn is required.
func NewServer(cfg Config, store Store) *Server {
	return &Server{
		cfg:   cfg,
		store: store,
		auths: make(map[string]Authenticator),
		subs:  make(map[uint64]chan Event),
	}
}

// RegisterAuth registers an authenticator for the given method.
// If an authenticator with the same method is already registered,
// it is replaced.
func (s *Server) RegisterAuth(auth Authenticator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auths[auth.Method()] = auth
}

// Store returns the underlying store for direct access.
func (s *Server) Store() Store {
	return s.store
}

// Handler returns an http.Handler that serves the LAN API.
// All paths are under /api/lan/.
//
// The handler extracts the requester's identity from the remote IP
// using the configured IdentityFunc.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/lan/peers", s.handlePeers)
	mux.HandleFunc("POST /api/lan/join", s.handleJoin)
	mux.HandleFunc("POST /api/lan/leave", s.handleLeave)
	mux.HandleFunc("GET /api/lan/query/{pubkey}", s.handleQuery)
	mux.HandleFunc("POST /api/lan/labels/{pubkey}", s.handleSetLabels)
	mux.HandleFunc("DELETE /api/lan/labels/{pubkey}", s.handleDeleteLabels)
	mux.HandleFunc("GET /api/lan/events", s.handleEvents)
	mux.HandleFunc("GET /api/lan/info", s.handleInfo)

	return mux
}

// ── API handlers ────────────────────────────────────────────────────────────

// handleInfo returns LAN metadata.
//
//	GET /api/lan/info
//	→ {"domain": "...", "description": "...", "members": 5, "auth_methods": ["open", ...]}
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	methods := make([]string, 0, len(s.auths))
	for m := range s.auths {
		methods = append(methods, m)
	}
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"domain":       s.cfg.Domain,
		"description":  s.cfg.Description,
		"members":      s.store.Count(),
		"auth_methods": methods,
	})
}

// handlePeers returns all LAN members.
//
//	GET /api/lan/peers
//	→ {"peers": [{pubkey, labels, joined_at}, ...]}
func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	_, err := s.identify(r)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	members := s.store.List()
	writeJSON(w, http.StatusOK, map[string]any{
		"peers": members,
	})
}

// joinRequest is the body for POST /api/lan/join.
type joinRequest struct {
	Auth AuthRequest `json:"auth"`
}

// handleJoin processes a join request.
//
//	POST /api/lan/join
//	{"auth": {"method": "open"}}
//	{"auth": {"method": "password", "credential": {"password": "secret"}}}
//	{"auth": {"method": "invite_code", "credential": {"code": "abc123"}}}
func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	pubkey, err := s.identify(r)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	var req joinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Look up the authenticator for the requested method.
	s.mu.RLock()
	auth, ok := s.auths[req.Auth.Method]
	s.mu.RUnlock()

	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported auth method: %q", req.Auth.Method))
		return
	}

	// Authenticate.
	if err := auth.Authenticate(pubkey, req.Auth.Credential); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Add to store.
	added, err := s.store.Add(pubkey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		log.Printf("lan: store add %s: %v", pubkey.ShortString(), err)
		return
	}

	if added {
		s.broadcast(Event{
			Type:      "join",
			Pubkey:    pubkey.String(),
			Timestamp: time.Now().UTC(),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"added": added,
	})
}

// handleLeave processes a leave request.
//
//	POST /api/lan/leave
func (s *Server) handleLeave(w http.ResponseWriter, r *http.Request) {
	pubkey, err := s.identify(r)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	removed, err := s.store.Remove(pubkey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		log.Printf("lan: store remove %s: %v", pubkey.ShortString(), err)
		return
	}

	if removed {
		s.broadcast(Event{
			Type:      "leave",
			Pubkey:    pubkey.String(),
			Timestamp: time.Now().UTC(),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"removed": removed,
	})
}

// handleQuery looks up a specific member.
//
//	GET /api/lan/query/{pubkey}
func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	_, err := s.identify(r)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	hexPK := r.PathValue("pubkey")
	pk, err := noise.KeyFromHex(hexPK)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pubkey")
		return
	}

	m := s.store.Get(pk)
	if m == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"member": false,
			"pubkey": hexPK,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"member":    true,
		"pubkey":    m.PubkeyHex,
		"labels":    m.Labels,
		"joined_at": m.JoinedAt,
	})
}

// labelsRequest is the body for POST /api/lan/labels/:pubkey.
type labelsRequest struct {
	Labels []string `json:"labels"`
}

// handleSetLabels sets labels for a member.
//
// Authorization is the caller's responsibility (e.g., via HTTP middleware
// or inbound policy). This handler only verifies the requester's identity.
//
//	POST /api/lan/labels/{pubkey}
//	{"labels": ["admin", "dev-team"]}
func (s *Server) handleSetLabels(w http.ResponseWriter, r *http.Request) {
	_, err := s.identify(r)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	hexPK := r.PathValue("pubkey")
	pk, err := noise.KeyFromHex(hexPK)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pubkey")
		return
	}

	var req labelsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.store.SetLabels(pk, req.Labels); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	s.broadcast(Event{
		Type:      "labels",
		Pubkey:    pk.String(),
		Labels:    req.Labels,
		Timestamp: time.Now().UTC(),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
	})
}

// handleDeleteLabels removes labels from a member.
//
// Authorization is the caller's responsibility (e.g., via HTTP middleware
// or inbound policy). This handler only verifies the requester's identity.
//
//	DELETE /api/lan/labels/{pubkey}
//	{"labels": ["admin"]}
func (s *Server) handleDeleteLabels(w http.ResponseWriter, r *http.Request) {
	_, err := s.identify(r)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	hexPK := r.PathValue("pubkey")
	pk, err := noise.KeyFromHex(hexPK)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pubkey")
		return
	}

	var req labelsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.store.RemoveLabels(pk, req.Labels); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	// Fetch updated labels for the event.
	m := s.store.Get(pk)
	var newLabels []string
	if m != nil {
		newLabels = m.Labels
	}

	s.broadcast(Event{
		Type:      "labels",
		Pubkey:    pk.String(),
		Labels:    newLabels,
		Timestamp: time.Now().UTC(),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
	})
}

// handleEvents serves Server-Sent Events (SSE) for LAN changes.
// SSE is simpler than WebSocket and works over standard HTTP — no upgrade
// needed, no extra dependencies, and it's supported by all modern clients.
//
//	GET /api/lan/events
//	← event: join
//	← data: {"pubkey":"abc...","timestamp":"..."}
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	_, err := s.identify(r)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch := s.subscribe()
	defer s.unsubscribe(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case evt := <-ch:
			data, _ := json.Marshal(evt)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Type, data)
			flusher.Flush()
		}
	}
}

// ── Identity resolution ─────────────────────────────────────────────────────

// identify extracts the caller's pubkey from their remote IP.
func (s *Server) identify(r *http.Request) (noise.PublicKey, error) {
	if s.cfg.IdentityFn == nil {
		return noise.PublicKey{}, fmt.Errorf("identity resolution not configured")
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return noise.PublicKey{}, fmt.Errorf("cannot parse remote IP: %s", host)
	}

	pubkey, _, err := s.cfg.IdentityFn(ip)
	if err != nil {
		return noise.PublicKey{}, fmt.Errorf("unknown identity for %s: %w", ip, err)
	}

	return pubkey, nil
}

// ── Event pub/sub ───────────────────────────────────────────────────────────

// subscribe creates a new event channel. The caller must call unsubscribe
// when done.
func (s *Server) subscribe() chan Event {
	s.subMu.Lock()
	defer s.subMu.Unlock()

	ch := make(chan Event, 64)
	s.nextSub++
	s.subs[s.nextSub] = ch
	return ch
}

// unsubscribe removes a subscriber channel.
func (s *Server) unsubscribe(ch chan Event) {
	s.subMu.Lock()
	defer s.subMu.Unlock()

	for id, c := range s.subs {
		if c == ch {
			delete(s.subs, id)
			close(ch)
			return
		}
	}
}

// broadcast sends an event to all subscribers. Non-blocking: if a subscriber's
// channel is full, the event is dropped for that subscriber.
func (s *Server) broadcast(evt Event) {
	s.subMu.Lock()
	defer s.subMu.Unlock()

	for _, ch := range s.subs {
		select {
		case ch <- evt:
		default:
			// Slow subscriber — drop event to avoid blocking.
		}
	}
}

// ── JSON helpers ────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
