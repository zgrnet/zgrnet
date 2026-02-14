package config

import (
	"strings"
	"sync"
)

// RouteResult is returned when a domain matches a route rule.
type RouteResult struct {
	Peer     string // target peer alias or domain
	RuleName string // the matching domain suffix
}

// RouteMatcher provides domain-to-peer route matching using suffix matching.
// All rules are suffix matches: "google.com" matches "google.com" and all
// subdomains (www.google.com, mail.google.com, etc.).
//
// When multiple rules match, the longest suffix wins.
// Thread-safe for concurrent reads.
type RouteMatcher struct {
	mu    sync.RWMutex
	rules []compiledRouteRule
}

type compiledRouteRule struct {
	peer   string
	suffix string // lowercase domain suffix (e.g., "google.com")
}

// NewRouteMatcher creates a RouteMatcher from a RouteConfig.
func NewRouteMatcher(cfg *RouteConfig) (*RouteMatcher, error) {
	rm := &RouteMatcher{}
	rm.build(cfg)
	return rm, nil
}

func (rm *RouteMatcher) build(cfg *RouteConfig) {
	rules := make([]compiledRouteRule, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		if r.Domain == "" {
			continue
		}
		domain := strings.ToLower(r.Domain)
		// Strip "*." prefix if present — all matches are suffix-based
		domain = strings.TrimPrefix(domain, "*.")
		rules = append(rules, compiledRouteRule{
			peer:   r.Peer,
			suffix: domain,
		})
	}

	rm.mu.Lock()
	rm.rules = rules
	rm.mu.Unlock()
}

// Match checks if a domain matches any route rule.
// Returns the result with the longest matching suffix, or false if no match.
func (rm *RouteMatcher) Match(domain string) (RouteResult, bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var best *compiledRouteRule
	for i := range rm.rules {
		r := &rm.rules[i]
		if matchSuffix(domain, r.suffix) {
			if best == nil || len(r.suffix) > len(best.suffix) {
				best = r
			}
		}
	}

	if best == nil {
		return RouteResult{}, false
	}
	return RouteResult{
		Peer:     best.peer,
		RuleName: best.suffix,
	}, true
}

// MatchRoute implements the dns.RouteMatcher interface.
func (rm *RouteMatcher) MatchRoute(domain string) (string, bool) {
	result, ok := rm.Match(domain)
	if !ok {
		return "", false
	}
	return result.Peer, true
}

// matchSuffix checks if domain equals suffix or is a subdomain of suffix.
// E.g., matchSuffix("www.google.com", "google.com") == true
//
//	matchSuffix("google.com", "google.com") == true
//	matchSuffix("notgoogle.com", "google.com") == false
func matchSuffix(domain, suffix string) bool {
	if domain == suffix {
		return true
	}
	// domain must be longer and end with ".suffix"
	if len(domain) > len(suffix)+1 &&
		domain[len(domain)-len(suffix)-1] == '.' &&
		domain[len(domain)-len(suffix):] == suffix {
		return true
	}
	return false
}
