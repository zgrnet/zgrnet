package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// RouteResult is returned when a domain matches a route rule.
type RouteResult struct {
	Peer     string // target peer alias or domain
	RuleName string // description of the matching rule
}

// RouteMatcher provides domain-to-peer route matching.
// It is built from a RouteConfig and supports exact match,
// wildcard suffix match (*.example.com), and domain list files.
//
// Thread-safe for concurrent reads after Build().
type RouteMatcher struct {
	mu    sync.RWMutex
	rules []compiledRouteRule
}

type compiledRouteRule struct {
	peer string

	// For domain patterns (e.g., "*.google.com" or "google.com")
	pattern string
	isSuffix bool // true if pattern starts with "*."

	// For domain list files
	listPath string
	domains  map[string]bool // loaded from file
}

// NewRouteMatcher creates a RouteMatcher from a RouteConfig.
// Domain list files are loaded eagerly.
func NewRouteMatcher(cfg *RouteConfig) (*RouteMatcher, error) {
	rm := &RouteMatcher{}
	if err := rm.build(cfg); err != nil {
		return nil, err
	}
	return rm, nil
}

func (rm *RouteMatcher) build(cfg *RouteConfig) error {
	rules := make([]compiledRouteRule, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		cr := compiledRouteRule{peer: r.Peer}

		if r.Domain != "" {
			domain := strings.ToLower(r.Domain)
			if strings.HasPrefix(domain, "*.") {
				cr.isSuffix = true
				// Store the suffix without "*" — e.g., ".google.com"
				cr.pattern = domain[1:]
			} else {
				cr.pattern = domain
			}
		}

		if r.DomainList != "" {
			cr.listPath = r.DomainList
			domains, err := loadDomainList(r.DomainList)
			if err != nil {
				return fmt.Errorf("route: load domain list %q: %w", r.DomainList, err)
			}
			cr.domains = domains
		}

		rules = append(rules, cr)
	}

	rm.mu.Lock()
	rm.rules = rules
	rm.mu.Unlock()
	return nil
}

// Match checks if a domain matches any route rule.
// Returns the matching result and true, or zero value and false if no match.
func (rm *RouteMatcher) Match(domain string) (RouteResult, bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	rm.mu.RLock()
	defer rm.mu.RUnlock()

	for i := range rm.rules {
		r := &rm.rules[i]

		// Check domain pattern match
		if r.pattern != "" {
			if r.isSuffix {
				// "*.google.com" matches "google.com" and "www.google.com"
				if domain == r.pattern[1:] || strings.HasSuffix(domain, r.pattern) {
					return RouteResult{
						Peer:     r.peer,
						RuleName: "domain:" + "*" + r.pattern,
					}, true
				}
			} else {
				// Exact match
				if domain == r.pattern {
					return RouteResult{
						Peer:     r.peer,
						RuleName: "domain:" + r.pattern,
					}, true
				}
			}
		}

		// Check domain list match
		if r.domains != nil {
			if matchDomainList(domain, r.domains) {
				return RouteResult{
					Peer:     r.peer,
					RuleName: "domain_list:" + r.listPath,
				}, true
			}
		}
	}

	return RouteResult{}, false
}

// Reload reloads domain list files from disk.
// Called when external files change.
func (rm *RouteMatcher) Reload() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i := range rm.rules {
		r := &rm.rules[i]
		if r.listPath != "" {
			domains, err := loadDomainList(r.listPath)
			if err != nil {
				return fmt.Errorf("route: reload domain list %q: %w", r.listPath, err)
			}
			r.domains = domains
		}
	}
	return nil
}

// matchDomainList checks if the domain or any of its parent domains
// appear in the domain set.
// E.g., "www.google.com" matches if "google.com" is in the set.
func matchDomainList(domain string, domains map[string]bool) bool {
	// Check exact match first
	if domains[domain] {
		return true
	}
	// Walk up parent domains
	for {
		idx := strings.IndexByte(domain, '.')
		if idx < 0 {
			break
		}
		domain = domain[idx+1:]
		if domains[domain] {
			return true
		}
	}
	return false
}

// loadDomainList reads a domain list file. Each line is a domain name.
// Empty lines and lines starting with '#' are ignored.
func loadDomainList(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	domains := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains[strings.ToLower(line)] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}
