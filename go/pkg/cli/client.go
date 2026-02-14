package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is an HTTP client for the zgrnetd RESTful API.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient creates a new API client targeting the given address (host:port).
func NewClient(addr string) *Client {
	if !strings.HasPrefix(addr, "http://") {
		addr = "http://" + addr
	}
	return &Client{
		baseURL: strings.TrimRight(addr, "/"),
		http: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// get performs a GET request and returns the response body.
func (c *Client) get(path string) ([]byte, error) {
	resp, err := c.http.Get(c.baseURL + path)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GET %s: %s — %s", path, resp.Status, extractError(body))
	}
	return body, nil
}

// post performs a POST request with a JSON body.
func (c *Client) post(path string, payload interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(data)
	} else {
		bodyReader = strings.NewReader("")
	}

	resp, err := c.http.Post(c.baseURL+path, "application/json", bodyReader)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("POST %s: %s — %s", path, resp.Status, extractError(body))
	}
	return body, nil
}

// put performs a PUT request with a JSON body.
func (c *Client) put(path string, payload interface{}) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PUT %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("PUT %s: %s — %s", path, resp.Status, extractError(body))
	}
	return body, nil
}

// del performs a DELETE request.
func (c *Client) del(path string) error {
	req, err := http.NewRequest("DELETE", c.baseURL+path, nil)
	if err != nil {
		return err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DELETE %s: %s — %s", path, resp.Status, extractError(body))
	}
	return nil
}

// extractError attempts to pull an "error" field from a JSON body.
func extractError(body []byte) string {
	var m map[string]interface{}
	if json.Unmarshal(body, &m) == nil {
		if msg, ok := m["error"].(string); ok {
			return msg
		}
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// ─── Status ─────────────────────────────────────────────────────────────────

// Status calls GET /api/whoami.
func (c *Client) Status() ([]byte, error) {
	return c.get("/api/whoami")
}

// ─── Config ─────────────────────────────────────────────────────────────────

// ConfigNet calls GET /api/config/net.
func (c *Client) ConfigNet() ([]byte, error) {
	return c.get("/api/config/net")
}

// ConfigReload calls POST /api/config/reload.
func (c *Client) ConfigReload() ([]byte, error) {
	return c.post("/api/config/reload", nil)
}

// ─── Peers ──────────────────────────────────────────────────────────────────

// PeersList calls GET /api/peers.
func (c *Client) PeersList() ([]byte, error) {
	return c.get("/api/peers")
}

// PeersGet calls GET /api/peers/:pubkey.
func (c *Client) PeersGet(pubkey string) ([]byte, error) {
	return c.get("/api/peers/" + pubkey)
}

// PeersAdd calls POST /api/peers.
func (c *Client) PeersAdd(pubkey, alias, endpoint string) ([]byte, error) {
	payload := map[string]string{
		"pubkey": pubkey,
	}
	if alias != "" {
		payload["alias"] = alias
	}
	if endpoint != "" {
		payload["endpoint"] = endpoint
	}
	return c.post("/api/peers", payload)
}

// PeersUpdate calls PUT /api/peers/:pubkey.
func (c *Client) PeersUpdate(pubkey string, fields map[string]interface{}) ([]byte, error) {
	return c.put("/api/peers/"+pubkey, fields)
}

// PeersRemove calls DELETE /api/peers/:pubkey.
func (c *Client) PeersRemove(pubkey string) error {
	return c.del("/api/peers/" + pubkey)
}

// ─── Lans ───────────────────────────────────────────────────────────────────

// LansList calls GET /api/lans.
func (c *Client) LansList() ([]byte, error) {
	return c.get("/api/lans")
}

// LansJoin calls POST /api/lans.
func (c *Client) LansJoin(domain, pubkey, endpoint string) ([]byte, error) {
	return c.post("/api/lans", map[string]string{
		"domain":   domain,
		"pubkey":   pubkey,
		"endpoint": endpoint,
	})
}

// LansLeave calls DELETE /api/lans/:domain.
func (c *Client) LansLeave(domain string) error {
	return c.del("/api/lans/" + domain)
}

// ─── Policy ─────────────────────────────────────────────────────────────────

// PolicyShow calls GET /api/policy.
func (c *Client) PolicyShow() ([]byte, error) {
	return c.get("/api/policy")
}

// PolicyAddRule calls POST /api/policy/rules.
func (c *Client) PolicyAddRule(ruleJSON []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", c.baseURL+"/api/policy/rules", bytes.NewReader(ruleJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST /api/policy/rules: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("POST /api/policy/rules: %s — %s", resp.Status, extractError(body))
	}
	return body, nil
}

// PolicyRemoveRule calls DELETE /api/policy/rules/:name.
func (c *Client) PolicyRemoveRule(name string) error {
	return c.del("/api/policy/rules/" + name)
}

// ─── Routes ─────────────────────────────────────────────────────────────────

// RoutesList calls GET /api/routes.
func (c *Client) RoutesList() ([]byte, error) {
	return c.get("/api/routes")
}

// RoutesAdd calls POST /api/routes.
func (c *Client) RoutesAdd(domain, peer string) ([]byte, error) {
	return c.post("/api/routes", map[string]string{
		"domain": domain,
		"peer":   peer,
	})
}

// RoutesRemove calls DELETE /api/routes/:id.
func (c *Client) RoutesRemove(id string) error {
	return c.del("/api/routes/" + id)
}
