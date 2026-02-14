//! RESTful API server for zgrnetd.
//!
//! Provides HTTP endpoints for managing peers, lans, inbound policy, routes,
//! and querying node status. Write operations persist changes to config.yaml
//! and update the runtime state immediately.
//!
//! Uses a minimal HTTP/1.1 parser (no external HTTP crate dependencies).

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::config;
use crate::host::Host;
use crate::noise::Key;

const ADMIN_HTML: &str = include_str!("admin.html");

// ============================================================================
// Server
// ============================================================================

/// Configuration for creating an API server.
pub struct ServerConfig {
    /// Address to listen on (e.g., "100.64.0.1:80").
    pub listen_addr: String,
    /// Running Host instance.
    pub host: Arc<Host>,
    /// Config manager for reading/writing config.
    pub config_mgr: Arc<config::Manager>,
    /// DNS server for stats (optional).
    pub dns_server: Option<Arc<crate::dns::Server>>,
}

/// The zgrnetd RESTful API server.
pub struct Server {
    host: Arc<Host>,
    config_mgr: Arc<config::Manager>,
    dns_server: Option<Arc<crate::dns::Server>>,
    start_time: Instant,
    listener: Option<TcpListener>,
}

impl Server {
    /// Creates a new API server.
    pub fn new(cfg: ServerConfig) -> Result<Self, String> {
        let listener = TcpListener::bind(&cfg.listen_addr)
            .map_err(|e| format!("api: bind {}: {}", cfg.listen_addr, e))?;
        // Non-blocking not needed — we accept in a dedicated thread
        Ok(Self {
            host: cfg.host,
            config_mgr: cfg.config_mgr,
            dns_server: cfg.dns_server,
            start_time: Instant::now(),
            listener: Some(listener),
        })
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.listener.as_ref().and_then(|l| l.local_addr().ok())
    }

    /// Starts accepting connections. Blocks until the listener is closed.
    pub fn serve(&self) {
        let listener = match &self.listener {
            Some(l) => l,
            None => return,
        };
        for stream in listener.incoming() {
            match stream {
                Ok(conn) => {
                    let host = Arc::clone(&self.host);
                    let cfg_mgr = Arc::clone(&self.config_mgr);
                    let dns_srv = self.dns_server.clone();
                    let start_time = self.start_time;
                    thread::spawn(move || {
                        let ctx = RequestContext {
                            host: &host,
                            config_mgr: &cfg_mgr,
                            dns_server: dns_srv.as_deref(),
                            start_time,
                        };
                        if let Err(e) = handle_connection(conn, &ctx) {
                            if e.kind() != io::ErrorKind::BrokenPipe
                                && e.kind() != io::ErrorKind::ConnectionReset
                            {
                                eprintln!("api: connection error: {e}");
                            }
                        }
                    });
                }
                Err(_) => return, // listener closed
            }
        }
    }

    /// Closes the server by dropping the listener.
    pub fn close(&mut self) {
        self.listener.take();
    }
}

// ============================================================================
// Minimal HTTP/1.1 handling
// ============================================================================

struct HttpRequest {
    method: String,
    path: String,
    query: HashMap<String, String>,
    body: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    status_text: &'static str,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(status: u16, status_text: &'static str, body: &str) -> Self {
        Self {
            status,
            status_text,
            body: body.as_bytes().to_vec(),
        }
    }

    fn ok(body: &str) -> Self {
        Self::json(200, "OK", body)
    }

    fn created(body: &str) -> Self {
        Self::json(201, "Created", body)
    }

    fn no_content() -> Self {
        Self {
            status: 204,
            status_text: "No Content",
            body: Vec::new(),
        }
    }

    fn bad_request(msg: &str) -> Self {
        Self::json(400, "Bad Request", &format!(r#"{{"error":"{}"}}"#, escape_json(msg)))
    }

    fn not_found(msg: &str) -> Self {
        Self::json(404, "Not Found", &format!(r#"{{"error":"{}"}}"#, escape_json(msg)))
    }

    fn conflict(msg: &str) -> Self {
        Self::json(409, "Conflict", &format!(r#"{{"error":"{}"}}"#, escape_json(msg)))
    }

    fn internal_error(msg: &str) -> Self {
        Self::json(500, "Internal Server Error", &format!(r#"{{"error":"{}"}}"#, escape_json(msg)))
    }

    fn write_to(&self, stream: &mut TcpStream) -> io::Result<()> {
        let content_type = if self.body.starts_with(b"<!DOCTYPE") || self.body.starts_with(b"<html") {
            "text/html; charset=utf-8"
        } else {
            "application/json"
        };
        let header = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.status, self.status_text, content_type, self.body.len()
        );
        stream.write_all(header.as_bytes())?;
        if !self.body.is_empty() {
            stream.write_all(&self.body)?;
        }
        stream.flush()
    }
}

fn parse_request(stream: &mut TcpStream) -> io::Result<HttpRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);

    // Read request line
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "malformed request line"));
    }
    let method = parts[0].to_string();
    let full_path = parts[1].to_string();

    // Split path and query
    let (path, query) = if let Some(idx) = full_path.find('?') {
        let q = parse_query(&full_path[idx + 1..]);
        (full_path[..idx].to_string(), q)
    } else {
        (full_path, HashMap::new())
    };

    // Read headers
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(val) = trimmed.strip_prefix("Content-Length:") {
            if let Ok(n) = val.trim().parse() {
                content_length = n;
            }
        }
        if let Some(val) = trimmed.strip_prefix("content-length:") {
            if let Ok(n) = val.trim().parse() {
                content_length = n;
            }
        }
    }

    // Read body
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(HttpRequest {
        method,
        path,
        query,
        body,
    })
}

fn parse_query(q: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

// ============================================================================
// Request handling
// ============================================================================

struct RequestContext<'a> {
    host: &'a Host,
    config_mgr: &'a config::Manager,
    dns_server: Option<&'a crate::dns::Server>,
    start_time: Instant,
}

fn handle_connection(mut stream: TcpStream, ctx: &RequestContext) -> io::Result<()> {
    let req = parse_request(&mut stream)?;
    let resp = route(&req, ctx);
    resp.write_to(&mut stream)
}

fn route(req: &HttpRequest, ctx: &RequestContext) -> HttpResponse {
    let path = req.path.as_str();
    let method = req.method.as_str();

    match (method, path) {
        // Read-only
        ("GET", "/api/whoami") => handle_whoami(ctx),
        ("GET", "/api/config/net") => handle_config_net(ctx),
        ("GET", "/api/dns/stats") => handle_dns_stats(ctx),
        ("GET", "/api/proxy/stats") => handle_proxy_stats(),

        // Peers
        ("GET", "/api/peers") => handle_list_peers(ctx),
        ("POST", "/api/peers") => handle_add_peer(req, ctx),

        // Identity
        ("GET", "/internal/identity") => handle_identity(req, ctx),

        // Lans
        ("GET", "/api/lans") => handle_list_lans(ctx),
        ("POST", "/api/lans") => handle_add_lan(req, ctx),

        // Policy
        ("GET", "/api/policy") => handle_get_policy(ctx),
        ("POST", "/api/policy/rules") => handle_add_policy_rule(req, ctx),

        // Routes
        ("GET", "/api/routes") => handle_list_routes(ctx),
        ("POST", "/api/routes") => handle_add_route(req, ctx),

        // Config
        ("POST", "/api/config/reload") => handle_config_reload(ctx),

        // Admin Web UI
        ("GET", "/") => {
            HttpResponse {
                status: 200,
                status_text: "OK",
                body: ADMIN_HTML.as_bytes().to_vec(),
            }
        }

        _ => {
            // Check for path-parameter routes
            if method == "GET" && path.starts_with("/api/peers/") {
                let pk = &path["/api/peers/".len()..];
                return handle_get_peer(pk, ctx);
            }
            if method == "PUT" && path.starts_with("/api/peers/") {
                let pk = &path["/api/peers/".len()..];
                return handle_update_peer(pk, req, ctx);
            }
            if method == "DELETE" && path.starts_with("/api/peers/") {
                let pk = &path["/api/peers/".len()..];
                return handle_delete_peer(pk, ctx);
            }
            if method == "DELETE" && path.starts_with("/api/lans/") {
                let domain = &path["/api/lans/".len()..];
                return handle_delete_lan(domain, ctx);
            }
            if method == "DELETE" && path.starts_with("/api/policy/rules/") {
                let name = &path["/api/policy/rules/".len()..];
                return handle_delete_policy_rule(name, ctx);
            }
            if method == "DELETE" && path.starts_with("/api/routes/") {
                let id = &path["/api/routes/".len()..];
                return handle_delete_route(id, ctx);
            }
            HttpResponse::not_found("not found")
        }
    }
}

// ============================================================================
// Handlers
// ============================================================================

fn handle_whoami(ctx: &RequestContext) -> HttpResponse {
    let pk = ctx.host.public_key();
    let cfg = ctx.config_mgr.current();
    let uptime = ctx.start_time.elapsed();

    HttpResponse::ok(&format!(
        r#"{{"pubkey":"{}","tun_ip":"{}","uptime":"{}s","uptime_sec":{}}}"#,
        hex::encode(pk),
        cfg.net.tun_ipv4,
        uptime.as_secs(),
        uptime.as_secs(),
    ))
}

fn handle_config_net(ctx: &RequestContext) -> HttpResponse {
    let cfg = ctx.config_mgr.current();
    let json = serde_json::to_string(&cfg.net).unwrap_or_default();
    HttpResponse::ok(&json)
}

fn handle_dns_stats(ctx: &RequestContext) -> HttpResponse {
    match ctx.dns_server {
        Some(srv) => {
            let stats = srv.get_stats();
            let json = serde_json::to_string(&stats).unwrap_or_default();
            HttpResponse::ok(&json)
        }
        None => HttpResponse::ok(r#"{"total_queries":0,"zigor_net_hits":0,"fake_ip_hits":0,"upstream_forwards":0,"upstream_errors":0,"errors":0}"#),
    }
}

fn handle_proxy_stats() -> HttpResponse {
    // Proxy stats not yet integrated — return zeros
    HttpResponse::ok(r#"{"total_connections":0,"active_connections":0,"bytes_sent":0,"bytes_received":0,"errors":0}"#)
}

fn handle_list_peers(ctx: &RequestContext) -> HttpResponse {
    let cfg = ctx.config_mgr.current();
    let mut peers = Vec::new();
    for (domain, pc) in &cfg.peers {
        peers.push(peer_to_json(domain, pc, ctx));
    }
    let json = format!("[{}]", peers.join(","));
    HttpResponse::ok(&json)
}

fn handle_get_peer(hex_pk: &str, ctx: &RequestContext) -> HttpResponse {
    let domain = pubkey_to_domain(hex_pk);
    let cfg = ctx.config_mgr.current();
    match cfg.peers.get(&domain) {
        Some(pc) => HttpResponse::ok(&peer_to_json(&domain, pc, ctx)),
        None => HttpResponse::not_found("peer not found"),
    }
}

fn handle_add_peer(req: &HttpRequest, ctx: &RequestContext) -> HttpResponse {
    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(e) => return HttpResponse::bad_request(&format!("invalid JSON: {e}")),
    };

    let pubkey = match body["pubkey"].as_str() {
        Some(pk) if !pk.is_empty() => pk.to_string(),
        _ => return HttpResponse::bad_request("pubkey is required"),
    };

    let pk = match Key::from_hex(&pubkey) {
        Ok(k) => k,
        Err(e) => return HttpResponse::bad_request(&format!("invalid pubkey: {e}")),
    };

    let alias = body["alias"].as_str().unwrap_or("").to_string();
    let endpoint = body["endpoint"].as_str().unwrap_or("").to_string();

    let mut direct: Vec<String> = body["direct"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let relay: Vec<String> = body["relay"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    if !endpoint.is_empty() && direct.is_empty() {
        direct = vec![endpoint.clone()];
    }

    let domain = pubkey_to_domain(&pubkey);
    let pc = config::PeerConfig {
        alias: alias.clone(),
        direct: direct.clone(),
        relay: relay.clone(),
    };

    // Persist to config
    let domain2 = domain.clone();
    let pc2 = pc.clone();
    if let Err(e) = ctx.config_mgr.modify_and_save(move |cfg| {
        if cfg.peers.contains_key(&domain2) {
            return Err(format!("peer {} already exists", &pubkey[..16.min(pubkey.len())]));
        }
        cfg.peers.insert(domain2, pc2);
        Ok(())
    }) {
        return HttpResponse::conflict(&e.to_string());
    }

    // Update runtime
    let ep = if endpoint.is_empty() && !direct.is_empty() {
        &direct[0]
    } else {
        &endpoint
    };
    if let Err(e) = ctx.host.add_peer(pk, ep) {
        eprintln!("api: peer saved but runtime add failed: {e}");
    }

    let resp_json = peer_to_json(&domain, &pc, ctx);
    HttpResponse::created(&resp_json)
}

fn handle_update_peer(hex_pk: &str, req: &HttpRequest, ctx: &RequestContext) -> HttpResponse {
    let domain = pubkey_to_domain(hex_pk);

    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(e) => return HttpResponse::bad_request(&format!("invalid JSON: {e}")),
    };

    let domain2 = domain.clone();
    let body2 = body.clone();

    if let Err(e) = ctx.config_mgr.modify_and_save(move |cfg| {
        let pc = cfg.peers.get_mut(&domain2).ok_or("peer not found")?;
        if let Some(alias) = body2["alias"].as_str() {
            pc.alias = alias.to_string();
        }
        if let Some(arr) = body2["direct"].as_array() {
            pc.direct = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect();
        }
        if let Some(arr) = body2["relay"].as_array() {
            pc.relay = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect();
        }
        if let Some(ep) = body2["endpoint"].as_str() {
            if !ep.is_empty() {
                if pc.direct.is_empty() {
                    pc.direct = vec![ep.to_string()];
                } else {
                    pc.direct[0] = ep.to_string();
                }
            }
        }
        Ok(())
    }) {
        let msg = e.to_string();
        if msg.contains("not found") {
            return HttpResponse::not_found(&msg);
        }
        return HttpResponse::bad_request(&msg);
    }

    // Read updated config
    let cfg = ctx.config_mgr.current();
    let updated_pc = match cfg.peers.get(&domain) {
        Some(pc) => pc.clone(),
        None => return HttpResponse::internal_error("peer disappeared after update"),
    };

    // Update runtime endpoint if changed
    if body["endpoint"].is_string() || body["direct"].is_array() {
        if let Ok(pk) = Key::from_hex(hex_pk) {
            if let Some(ep) = updated_pc.direct.first() {
                if let Ok(addr) = ep.parse::<SocketAddr>() {
                    ctx.host.udp().set_peer_endpoint(pk, addr);
                }
            }
        }
    }

    let resp_json = peer_to_json(&domain, &updated_pc, ctx);
    HttpResponse::ok(&resp_json)
}

fn handle_delete_peer(hex_pk: &str, ctx: &RequestContext) -> HttpResponse {
    let domain = pubkey_to_domain(hex_pk);

    let domain2 = domain.clone();
    if let Err(e) = ctx.config_mgr.modify_and_save(move |cfg| {
        if !cfg.peers.contains_key(&domain2) {
            return Err("peer not found".to_string());
        }
        cfg.peers.remove(&domain2);
        Ok(())
    }) {
        let msg = e.to_string();
        if msg.contains("not found") {
            return HttpResponse::not_found(&msg);
        }
        return HttpResponse::internal_error(&msg);
    }

    if let Ok(pk) = Key::from_hex(hex_pk) {
        ctx.host.remove_peer(&pk);
    }

    HttpResponse::no_content()
}

// ── Lans ────────────────────────────────────────────────────────────────────

fn handle_list_lans(ctx: &RequestContext) -> HttpResponse {
    let cfg = ctx.config_mgr.current();
    let json = serde_json::to_string(&cfg.lans).unwrap_or_default();
    HttpResponse::ok(&json)
}

fn handle_add_lan(req: &HttpRequest, ctx: &RequestContext) -> HttpResponse {
    let lan: config::LanConfig = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(e) => return HttpResponse::bad_request(&format!("invalid JSON: {e}")),
    };

    let lan2 = lan.clone();
    if let Err(e) = ctx.config_mgr.modify_and_save(move |cfg| {
        if cfg.lans.iter().any(|l| l.domain == lan2.domain) {
            return Err(format!("lan {:?} already exists", lan2.domain));
        }
        cfg.lans.push(lan2);
        Ok(())
    }) {
        return HttpResponse::conflict(&e.to_string());
    }

    let json = serde_json::to_string(&lan).unwrap_or_default();
    HttpResponse::created(&json)
}

fn handle_delete_lan(domain: &str, ctx: &RequestContext) -> HttpResponse {
    let domain = domain.to_string();
    let domain2 = domain.clone();
    if let Err(e) = ctx.config_mgr.modify_and_save(move |cfg| {
        let before = cfg.lans.len();
        cfg.lans.retain(|l| l.domain != domain2);
        if cfg.lans.len() == before {
            return Err(format!("lan {:?} not found", domain2));
        }
        Ok(())
    }) {
        let msg = e.to_string();
        if msg.contains("not found") {
            return HttpResponse::not_found(&msg);
        }
        return HttpResponse::internal_error(&msg);
    }

    HttpResponse::no_content()
}

// ── Policy ──────────────────────────────────────────────────────────────────

fn handle_get_policy(ctx: &RequestContext) -> HttpResponse {
    let cfg = ctx.config_mgr.current();
    let json = serde_json::to_string(&cfg.inbound_policy).unwrap_or_default();
    HttpResponse::ok(&json)
}

fn handle_add_policy_rule(req: &HttpRequest, ctx: &RequestContext) -> HttpResponse {
    let rule: config::InboundRule = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(e) => return HttpResponse::bad_request(&format!("invalid JSON: {e}")),
    };

    let rule2 = rule.clone();
    if let Err(e) = ctx.config_mgr.modify_and_save(move |cfg| {
        if cfg.inbound_policy.rules.iter().any(|r| r.name == rule2.name) {
            return Err(format!("rule {:?} already exists", rule2.name));
        }
        cfg.inbound_policy.rules.push(rule2);
        Ok(())
    }) {
        return HttpResponse::conflict(&e.to_string());
    }

    let json = serde_json::to_string(&rule).unwrap_or_default();
    HttpResponse::created(&json)
}

fn handle_delete_policy_rule(name: &str, ctx: &RequestContext) -> HttpResponse {
    let name = name.to_string();
    let name2 = name.clone();
    if let Err(e) = ctx.config_mgr.modify_and_save(move |cfg| {
        let before = cfg.inbound_policy.rules.len();
        cfg.inbound_policy.rules.retain(|r| r.name != name2);
        if cfg.inbound_policy.rules.len() == before {
            return Err(format!("rule {:?} not found", name2));
        }
        Ok(())
    }) {
        let msg = e.to_string();
        if msg.contains("not found") {
            return HttpResponse::not_found(&msg);
        }
        return HttpResponse::internal_error(&msg);
    }

    HttpResponse::no_content()
}

// ── Routes ──────────────────────────────────────────────────────────────────

fn handle_list_routes(ctx: &RequestContext) -> HttpResponse {
    let cfg = ctx.config_mgr.current();
    let json = serde_json::to_string(&cfg.route.rules).unwrap_or_default();
    HttpResponse::ok(&json)
}

fn handle_add_route(req: &HttpRequest, ctx: &RequestContext) -> HttpResponse {
    let rule: config::RouteRule = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(e) => return HttpResponse::bad_request(&format!("invalid JSON: {e}")),
    };

    let rule2 = rule.clone();
    if let Err(e) = ctx.config_mgr.modify_and_save(move |cfg| {
        cfg.route.rules.push(rule2);
        Ok(())
    }) {
        return HttpResponse::bad_request(&e.to_string());
    }

    let json = serde_json::to_string(&rule).unwrap_or_default();
    HttpResponse::created(&json)
}

fn handle_delete_route(id_str: &str, ctx: &RequestContext) -> HttpResponse {
    let id: usize = match id_str.parse() {
        Ok(n) => n,
        Err(_) => return HttpResponse::bad_request("invalid route id: must be an integer"),
    };

    if let Err(e) = ctx.config_mgr.modify_and_save(move |cfg| {
        if id >= cfg.route.rules.len() {
            return Err(format!(
                "route index {} out of range (have {} rules)",
                id,
                cfg.route.rules.len()
            ));
        }
        cfg.route.rules.remove(id);
        Ok(())
    }) {
        let msg = e.to_string();
        if msg.contains("out of range") {
            return HttpResponse::not_found(&msg);
        }
        return HttpResponse::internal_error(&msg);
    }

    HttpResponse::no_content()
}

// ── Identity ────────────────────────────────────────────────────────────────

fn handle_identity(req: &HttpRequest, ctx: &RequestContext) -> HttpResponse {
    let ip_str = match req.query.get("ip") {
        Some(ip) => ip.clone(),
        None => return HttpResponse::bad_request("ip parameter is required"),
    };

    let ip: Ipv4Addr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return HttpResponse::bad_request("invalid IP address"),
    };

    match ctx.host.ip_alloc().lookup_by_ip(ip) {
        Some(pk) => HttpResponse::ok(&format!(
            r#"{{"pubkey":"{}","ip":"{}"}}"#,
            hex::encode(pk),
            ip_str
        )),
        None => HttpResponse::not_found("no peer found for IP"),
    }
}

// ── Config Reload ───────────────────────────────────────────────────────────

fn handle_config_reload(ctx: &RequestContext) -> HttpResponse {
    match ctx.config_mgr.reload() {
        Ok(None) => HttpResponse::ok(r#"{"status":"no changes"}"#),
        Ok(Some(d)) => HttpResponse::ok(&format!(
            r#"{{"status":"reloaded","peers_added":{},"peers_removed":{},"peers_changed":{},"inbound_changed":{},"route_changed":{}}}"#,
            d.peers_added.len(),
            d.peers_removed.len(),
            d.peers_changed.len(),
            d.inbound_changed,
            d.route_changed,
        )),
        Err(e) => HttpResponse::internal_error(&format!("reload failed: {e}")),
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn pubkey_to_domain(hex_pk: &str) -> String {
    format!("{}.zigor.net", hex_pk.to_lowercase())
}

fn domain_to_pubkey(domain: &str) -> String {
    domain
        .to_lowercase()
        .strip_suffix(".zigor.net")
        .unwrap_or(domain)
        .to_string()
}

fn peer_to_json(domain: &str, pc: &config::PeerConfig, ctx: &RequestContext) -> String {
    let hex_pk = domain_to_pubkey(domain);
    let direct_json = serde_json::to_string(&pc.direct).unwrap_or_default();
    let relay_json = serde_json::to_string(&pc.relay).unwrap_or_default();

    let mut extra = String::new();

    // Enrich with runtime state
    if let Ok(pk) = Key::from_hex(&hex_pk) {
        if let Some(info) = ctx.host.udp().peer_info(&pk) {
            extra.push_str(&format!(
                r#","state":"{}","rx_bytes":{},"tx_bytes":{}"#,
                info.state,
                info.rx_bytes,
                info.tx_bytes,
            ));
            if let Some(ep) = &info.endpoint {
                extra.push_str(&format!(r#","endpoint":"{}""#, ep));
            }
        }
        if let Some(ip) = ctx.host.ip_alloc().lookup_by_pubkey(&pk) {
            extra.push_str(&format!(r#","tun_ip":"{}""#, ip));
        }
    }

    format!(
        r#"{{"pubkey":"{}","domain":"{}","alias":"{}","direct":{},"relay":{}{}}}"#,
        escape_json(&hex_pk),
        escape_json(domain),
        escape_json(&pc.alias),
        direct_json,
        relay_json,
        extra,
    )
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;

    fn minimal_config(dir: &std::path::Path) -> String {
        let path = dir.join("config.yaml");
        std::fs::write(
            &path,
            "net:\n  private_key: \"private.key\"\n  tun_ipv4: \"100.64.0.1\"\n  tun_mtu: 1400\n  listen_port: 0\n",
        ).unwrap();
        path.to_string_lossy().to_string()
    }

    struct MockTun;
    impl crate::host::TunDevice for MockTun {
        fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
            std::thread::sleep(Duration::from_secs(60));
            Ok(0)
        }
        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    // setup_named() is used instead — each test gets a unique temp dir.

    fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        write!(stream, "GET {} HTTP/1.1\r\nHost: test\r\n\r\n", path).unwrap();
        stream.flush().unwrap();
        read_response(&mut stream)
    }

    fn http_post(addr: SocketAddr, path: &str, body: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        write!(
            stream,
            "POST {} HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            path,
            body.len(),
            body
        )
        .unwrap();
        stream.flush().unwrap();
        read_response(&mut stream)
    }

    fn http_delete(addr: SocketAddr, path: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        write!(stream, "DELETE {} HTTP/1.1\r\nHost: test\r\n\r\n", path).unwrap();
        stream.flush().unwrap();
        read_response(&mut stream)
    }

    fn read_response(stream: &mut TcpStream) -> (u16, String) {
        let mut buf = vec![0u8; 8192];
        let mut total = 0;
        loop {
            match stream.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => break,
                Err(_) => break,
            }
        }
        let resp = String::from_utf8_lossy(&buf[..total]).to_string();
        let status = resp
            .lines()
            .next()
            .and_then(|l| l.split(' ').nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = resp
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or("")
            .to_string();
        (status, body)
    }

    fn http_put(addr: SocketAddr, path: &str, body: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        write!(
            stream,
            "PUT {} HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            path,
            body.len(),
            body
        ).unwrap();
        stream.flush().unwrap();
        read_response(&mut stream)
    }

    // Use unique temp dirs per test to avoid conflicts in parallel runs.
    fn setup_named(name: &str) -> (Server, Arc<Host>, Arc<config::Manager>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("zgrnet_api_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let cfg_path = minimal_config(&dir);
        let cfg_mgr = Arc::new(config::Manager::new(&cfg_path).unwrap());

        let kp = crate::noise::KeyPair::generate();
        let host = Host::new(
            crate::host::Config {
                private_key: kp,
                tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
                mtu: 1400,
                listen_port: 0,
                peers: Vec::new(),
            },
            Arc::new(MockTun),
        ).unwrap();

        let srv = Server::new(ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            host: Arc::clone(&host),
            config_mgr: Arc::clone(&cfg_mgr),
            dns_server: None,
        }).unwrap();

        (srv, host, cfg_mgr, dir)
    }

    #[test]
    fn test_whoami() {
        let (srv, _host, _cfg, dir) = setup_named("whoami");
        let addr = srv.local_addr().unwrap();
        let _h = thread::spawn(move || srv.serve());

        let (status, body) = http_get(addr, "/api/whoami");
        assert_eq!(status, 200);
        assert!(body.contains("pubkey"), "body: {body}");
        assert!(body.contains("100.64.0.1"), "body: {body}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_config_net() {
        let (srv, _host, _cfg, dir) = setup_named("cfgnet");
        let addr = srv.local_addr().unwrap();
        let _h = thread::spawn(move || srv.serve());

        let (status, body) = http_get(addr, "/api/config/net");
        assert_eq!(status, 200);
        assert!(body.contains("tun_ipv4"), "body: {body}");
        assert!(body.contains("100.64.0.1"), "body: {body}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_peers_crud() {
        let (srv, _host, _cfg, dir) = setup_named("peers_crud");
        let addr = srv.local_addr().unwrap();
        let _h = thread::spawn(move || srv.serve());

        let pk = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        // List — empty
        let (status, body) = http_get(addr, "/api/peers");
        assert_eq!(status, 200);
        assert_eq!(body.trim(), "[]");

        // Add peer
        let (status, body) = http_post(addr, "/api/peers",
            &format!(r#"{{"pubkey":"{}","alias":"peer1","endpoint":"127.0.0.1:51820"}}"#, pk));
        assert_eq!(status, 201, "body: {body}");
        assert!(body.contains("peer1"));

        // List — has 1
        let (status, body) = http_get(addr, "/api/peers");
        assert_eq!(status, 200);
        assert!(body.contains(pk));

        // Get single
        let (status, body) = http_get(addr, &format!("/api/peers/{pk}"));
        assert_eq!(status, 200);
        assert!(body.contains("peer1"));

        // Update peer
        let (status, body) = http_put(addr, &format!("/api/peers/{pk}"),
            r#"{"alias":"updated"}"#);
        assert_eq!(status, 200, "body: {body}");
        assert!(body.contains("updated"));

        // Verify update persisted
        let (status, body) = http_get(addr, &format!("/api/peers/{pk}"));
        assert_eq!(status, 200);
        assert!(body.contains("updated"));

        // Add duplicate should fail
        let (status, _) = http_post(addr, "/api/peers",
            &format!(r#"{{"pubkey":"{}","alias":"dup"}}"#, pk));
        assert_eq!(status, 409);

        // Delete
        let (status, _) = http_delete(addr, &format!("/api/peers/{pk}"));
        assert_eq!(status, 204);

        // List — empty again
        let (status, body) = http_get(addr, "/api/peers");
        assert_eq!(status, 200);
        assert_eq!(body.trim(), "[]");

        // Get deleted — 404
        let (status, _) = http_get(addr, &format!("/api/peers/{pk}"));
        assert_eq!(status, 404);

        // Delete nonexistent — 404
        let (status, _) = http_delete(addr, &format!("/api/peers/{pk}"));
        assert_eq!(status, 404);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_peers_bad_requests() {
        let (srv, _host, _cfg, dir) = setup_named("peers_bad");
        let addr = srv.local_addr().unwrap();
        let _h = thread::spawn(move || srv.serve());

        // Missing pubkey
        let (status, _) = http_post(addr, "/api/peers", r#"{"alias":"no-key"}"#);
        assert_eq!(status, 400);

        // Invalid pubkey
        let (status, _) = http_post(addr, "/api/peers", r#"{"pubkey":"xyz"}"#);
        assert_eq!(status, 400);

        // Invalid JSON
        let (status, _) = http_post(addr, "/api/peers", "{bad");
        assert_eq!(status, 400);

        // Update nonexistent
        let fake = "0000000000000000000000000000000000000000000000000000000000000000";
        let (status, _) = http_put(addr, &format!("/api/peers/{fake}"), r#"{"alias":"x"}"#);
        assert_eq!(status, 404);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_lans_crud() {
        let (srv, _host, _cfg, dir) = setup_named("lans_crud");
        let addr = srv.local_addr().unwrap();
        let _h = thread::spawn(move || srv.serve());

        let lan_pk = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        // List — empty
        let (status, body) = http_get(addr, "/api/lans");
        assert_eq!(status, 200);
        assert_eq!(body.trim(), "[]");

        // Add
        let (status, body) = http_post(addr, "/api/lans",
            &format!(r#"{{"domain":"test.zigor.net","pubkey":"{}","endpoint":"1.2.3.4:51820"}}"#, lan_pk));
        assert_eq!(status, 201, "body: {body}");
        assert!(body.contains("test.zigor.net"));

        // List — has 1
        let (status, body) = http_get(addr, "/api/lans");
        assert_eq!(status, 200);
        assert!(body.contains("test.zigor.net"));

        // Add duplicate
        let (status, _) = http_post(addr, "/api/lans",
            &format!(r#"{{"domain":"test.zigor.net","pubkey":"{}","endpoint":"5.6.7.8:51820"}}"#, lan_pk));
        assert_eq!(status, 409);

        // Delete
        let (status, _) = http_delete(addr, "/api/lans/test.zigor.net");
        assert_eq!(status, 204);

        // Delete nonexistent
        let (status, _) = http_delete(addr, "/api/lans/nope.zigor.net");
        assert_eq!(status, 404);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_policy_crud() {
        let (srv, _host, _cfg, dir) = setup_named("policy_crud");
        let addr = srv.local_addr().unwrap();
        let _h = thread::spawn(move || srv.serve());

        // Show — empty
        let (status, body) = http_get(addr, "/api/policy");
        assert_eq!(status, 200);
        assert!(body.contains("rules"));

        // Add rule
        let rule = r#"{"name":"open","match":{"pubkey":{"type":"any"}},"services":[{"proto":"*","port":"*"}],"action":"allow"}"#;
        let (status, body) = http_post(addr, "/api/policy/rules", rule);
        assert_eq!(status, 201, "body: {body}");
        assert!(body.contains("open"));

        // Show — has rule
        let (status, body) = http_get(addr, "/api/policy");
        assert_eq!(status, 200);
        assert!(body.contains("open"));

        // Add duplicate
        let (status, _) = http_post(addr, "/api/policy/rules", rule);
        assert_eq!(status, 409);

        // Delete
        let (status, _) = http_delete(addr, "/api/policy/rules/open");
        assert_eq!(status, 204);

        // Delete nonexistent
        let (status, _) = http_delete(addr, "/api/policy/rules/nope");
        assert_eq!(status, 404);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_routes_crud() {
        let (srv, _host, _cfg, dir) = setup_named("routes_crud");
        let addr = srv.local_addr().unwrap();
        let _h = thread::spawn(move || srv.serve());

        // List — empty
        let (status, body) = http_get(addr, "/api/routes");
        assert_eq!(status, 200);
        assert_eq!(body.trim(), "[]");

        // Add
        let (status, body) = http_post(addr, "/api/routes",
            r#"{"domain":"*.google.com","peer":"us"}"#);
        assert_eq!(status, 201, "body: {body}");
        assert!(body.contains("google.com"));

        // Add another
        let (status, _) = http_post(addr, "/api/routes",
            r#"{"domain":"*.example.com","peer":"jp"}"#);
        assert_eq!(status, 201);

        // List — has 2
        let (status, body) = http_get(addr, "/api/routes");
        assert_eq!(status, 200);
        assert!(body.contains("google.com"));
        assert!(body.contains("example.com"));

        // Delete index 0
        let (status, _) = http_delete(addr, "/api/routes/0");
        assert_eq!(status, 204);

        // List — has 1 (example.com)
        let (status, body) = http_get(addr, "/api/routes");
        assert_eq!(status, 200);
        assert!(body.contains("example.com"));
        assert!(!body.contains("google.com"));

        // Delete out of range
        let (status, _) = http_delete(addr, "/api/routes/99");
        assert_eq!(status, 404);

        // Delete invalid id
        let (status, _) = http_delete(addr, "/api/routes/abc");
        assert_eq!(status, 400);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_identity() {
        let (srv, host, _cfg, dir) = setup_named("identity");
        let addr = srv.local_addr().unwrap();
        let _h = thread::spawn(move || srv.serve());

        let pk = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        // Add peer to get IP allocated
        let (status, _) = http_post(addr, "/api/peers",
            &format!(r#"{{"pubkey":"{}","alias":"id-test"}}"#, pk));
        assert_eq!(status, 201);

        // Look up peer's IP
        let pk_key = crate::noise::Key::from_hex(pk).unwrap();
        let ip = host.ip_alloc().lookup_by_pubkey(&pk_key).unwrap();

        // Identity lookup
        let (status, body) = http_get(addr, &format!("/internal/identity?ip={}", ip));
        assert_eq!(status, 200);
        assert!(body.contains(pk), "body: {body}");

        // Missing ip param
        let (status, _) = http_get(addr, "/internal/identity");
        assert_eq!(status, 400);

        // Unknown IP
        let (status, _) = http_get(addr, "/internal/identity?ip=100.64.99.99");
        assert_eq!(status, 404);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_config_reload() {
        let (srv, _host, _cfg, dir) = setup_named("reload");
        let addr = srv.local_addr().unwrap();
        let _h = thread::spawn(move || srv.serve());

        let (status, body) = http_post(addr, "/api/config/reload", "");
        assert_eq!(status, 200);
        assert!(body.contains("no changes"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_not_found() {
        let (srv, _host, _cfg, dir) = setup_named("notfound");
        let addr = srv.local_addr().unwrap();
        let _h = thread::spawn(move || srv.serve());

        let (status, _) = http_get(addr, "/api/nonexistent");
        assert_eq!(status, 404);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_peers_persistence() {
        let (srv, _host, cfg_mgr, dir) = setup_named("persist");
        let addr = srv.local_addr().unwrap();
        let _h = thread::spawn(move || srv.serve());

        let pk = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let (status, _) = http_post(addr, "/api/peers",
            &format!(r#"{{"pubkey":"{}","alias":"saved","endpoint":"1.2.3.4:51820"}}"#, pk));
        assert_eq!(status, 201);

        // Read config from disk
        let saved = cfg_mgr.current();
        let domain = format!("{}.zigor.net", pk);
        let peer = saved.peers.get(&domain);
        assert!(peer.is_some(), "peer not found in saved config");
        assert_eq!(peer.unwrap().alias, "saved");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
