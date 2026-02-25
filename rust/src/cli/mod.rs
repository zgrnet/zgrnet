//! zgrnet CLI: offline context management and online API client.
//!
//! Offline operations (no zgrnetd needed):
//! - context list/use/create/current/delete
//! - key generate/show
//! - config show/path/edit
//! - up/down
//!
//! Online operations (calls zgrnetd REST API):
//! - status, peers, lans, policy, routes, config net/reload

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::noise::KeyPair;

// ============================================================================
// Context management
// ============================================================================

/// Returns the default zigor config directory.
/// Uses $ZIGOR_CONFIG_DIR if set, otherwise ~/.config/zigor.
pub fn default_config_dir() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var("ZIGOR_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var("HOME")
        .map_err(|_| "cannot determine home directory".to_string())?;
    Ok(PathBuf::from(home).join(".config").join("zigor"))
}

/// Returns the path to a specific context directory.
pub fn context_dir(base_dir: &Path, name: &str) -> PathBuf {
    base_dir.join(name)
}

/// Reads the current context name from the "current" file.
pub fn current_context_name(base_dir: &Path) -> Result<String, String> {
    let path = base_dir.join("current");
    let data = fs::read_to_string(&path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                "no current context set (run: zigor ctx create <name>)".to_string()
            } else {
                format!("read current context: {e}")
            }
        })?;
    let name = data.trim().to_string();
    if name.is_empty() {
        return Err("current context file is empty".to_string());
    }
    Ok(name)
}

/// Sets the current context.
pub fn set_current_context(base_dir: &Path, name: &str) -> Result<(), String> {
    validate_context_name(name)?;
    let dir = context_dir(base_dir, name);
    if !dir.exists() {
        return Err(format!("context {:?} does not exist", name));
    }
    fs::write(base_dir.join("current"), format!("{name}\n"))
        .map_err(|e| format!("write current: {e}"))
}

/// Lists all context names sorted alphabetically.
pub fn list_contexts(base_dir: &Path) -> Result<Vec<String>, String> {
    if !base_dir.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(base_dir)
        .map_err(|e| format!("read dir: {e}"))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        // A valid context has a private.key file (language-agnostic marker).
        // Config format varies by language (config.yaml for Go/Rust, config.json for Zig).
        let key = base_dir.join(&name).join("private.key");
        if key.exists() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

const CONTEXT_TEMPLATE: &str = "net:\n  private_key: \"private.key\"\n  tun_ipv4: \"100.64.0.1\"\n  tun_mtu: 1400\n  listen_port: 51820\n";

/// Validates that a context name is safe for use as a directory name.
pub fn validate_context_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("context name cannot be empty".to_string());
    }
    if name == "current" {
        return Err(format!("context name {:?} is reserved", name));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(format!("context name {:?} contains path separator", name));
    }
    if name.contains("..") {
        return Err(format!("context name {:?} contains path traversal", name));
    }
    if name.chars().any(|c| c.is_whitespace()) {
        return Err(format!("context name {:?} contains whitespace", name));
    }
    if name.starts_with('.') {
        return Err(format!("context name {:?} cannot start with dot", name));
    }
    Ok(())
}

/// Creates a new context with a generated keypair and template config.
pub fn create_context(base_dir: &Path, name: &str) -> Result<(), String> {
    validate_context_name(name)?;
    let dir = context_dir(base_dir, name);
    if dir.exists() {
        return Err(format!("context {:?} already exists", name));
    }

    fs::create_dir_all(dir.join("data"))
        .map_err(|e| format!("create context dir: {e}"))?;

    // Generate keypair
    let kp = KeyPair::generate();
    let key_hex = format!("{}\n", hex::encode(kp.private));
    fs::write(dir.join("private.key"), &key_hex)
        .map_err(|e| format!("write private key: {e}"))?;

    // Set permissions (best effort on unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir.join("private.key"),
            fs::Permissions::from_mode(0o600));
    }

    fs::write(dir.join("config.yaml"), CONTEXT_TEMPLATE)
        .map_err(|e| format!("write config: {e}"))?;

    Ok(())
}

/// Deletes a context. Refuses to delete the current context.
pub fn delete_context(base_dir: &Path, name: &str) -> Result<(), String> {
    validate_context_name(name)?;
    if let Ok(current) = current_context_name(base_dir) {
        if current == name {
            return Err(format!("cannot delete the current context {:?} (switch to another first)", name));
        }
    }
    let dir = context_dir(base_dir, name);
    if !dir.exists() {
        return Err(format!("context {:?} does not exist", name));
    }
    fs::remove_dir_all(&dir)
        .map_err(|e| format!("delete context: {e}"))
}

/// Returns the config.yaml path for the given or current context.
pub fn context_config_path(base_dir: &Path, name: &str) -> Result<PathBuf, String> {
    let ctx = if name.is_empty() {
        current_context_name(base_dir)?
    } else {
        name.to_string()
    };
    let path = context_dir(base_dir, &ctx).join("config.yaml");
    if !path.exists() {
        return Err(format!("config not found for context {:?}", ctx));
    }
    Ok(path)
}

/// Shows the public key for the given or current context.
pub fn show_public_key(base_dir: &Path, name: &str) -> Result<String, String> {
    let ctx = if name.is_empty() {
        current_context_name(base_dir)?
    } else {
        name.to_string()
    };
    let key_path = context_dir(base_dir, &ctx).join("private.key");
    let data = fs::read_to_string(&key_path)
        .map_err(|e| format!("read private key: {e}"))?;
    let hex_str = data.trim();
    let key = crate::noise::Key::from_hex(hex_str)
        .map_err(|e| format!("parse private key: {e}"))?;
    let kp = KeyPair::from_private(key);
    Ok(hex::encode(kp.public))
}

/// Generates a new keypair and writes it. Returns the hex-encoded public key.
pub fn generate_key(base_dir: &Path, name: &str) -> Result<String, String> {
    let ctx = if name.is_empty() {
        current_context_name(base_dir)?
    } else {
        name.to_string()
    };
    let kp = KeyPair::generate();
    let key_path = context_dir(base_dir, &ctx).join("private.key");
    let key_hex = format!("{}\n", hex::encode(kp.private));
    fs::write(&key_path, &key_hex)
        .map_err(|e| format!("write private key: {e}"))?;
    Ok(hex::encode(kp.public))
}

/// Shows the config.yaml contents.
pub fn show_config(base_dir: &Path, name: &str) -> Result<String, String> {
    let path = context_config_path(base_dir, name)?;
    fs::read_to_string(&path)
        .map_err(|e| format!("read config: {e}"))
}

/// Opens the config in $EDITOR.
pub fn edit_config(base_dir: &Path, name: &str) -> Result<(), String> {
    let path = context_config_path(base_dir, name)?;
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    Command::new(&editor)
        .arg(path)
        .status()
        .map_err(|e| format!("run editor: {e}"))?;
    Ok(())
}

/// Resolves the API address from context config or override.
pub fn resolve_api_addr(base_dir: &Path, name: &str, override_addr: &str) -> String {
    if !override_addr.is_empty() {
        return override_addr.to_string();
    }
    if let Ok(path) = context_config_path(base_dir, name) {
        if let Ok(data) = fs::read_to_string(&path) {
            for line in data.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("tun_ipv4:") {
                    let ip = rest.trim().trim_matches('"').trim_matches('\'');
                    if !ip.is_empty() {
                        return format!("{ip}:80");
                    }
                }
            }
        }
    }
    "100.64.0.1:80".to_string()
}

// ============================================================================
// HTTP API Client
// ============================================================================

/// Minimal HTTP client for the zgrnetd REST API.
pub struct Client {
    addr: String,
}

impl Client {
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
        }
    }

    fn request(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<(u16, String), String> {
        let mut stream = TcpStream::connect(&self.addr)
            .map_err(|e| format!("connect to {}: {e}", self.addr))?;
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

        let body_bytes = body.unwrap_or(&[]);
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.addr,
            body_bytes.len(),
        );
        stream.write_all(req.as_bytes())
            .map_err(|e| format!("write request: {e}"))?;
        if !body_bytes.is_empty() {
            stream.write_all(body_bytes)
                .map_err(|e| format!("write body: {e}"))?;
        }
        stream.flush().map_err(|e| format!("flush: {e}"))?;

        // Read response
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        let resp = String::from_utf8_lossy(&buf).to_string();

        let status: u16 = resp.lines().next()
            .and_then(|l| l.split(' ').nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let body_str = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();

        if status >= 400 {
            // Extract error message
            let msg = extract_error(&body_str);
            return Err(format!("{method} {path}: {status} — {msg}"));
        }

        Ok((status, body_str))
    }

    pub fn get(&self, path: &str) -> Result<String, String> {
        let (_, body) = self.request("GET", path, None)?;
        Ok(body)
    }

    pub fn post(&self, path: &str, body: &str) -> Result<String, String> {
        let (_, resp) = self.request("POST", path, Some(body.as_bytes()))?;
        Ok(resp)
    }

    pub fn put(&self, path: &str, body: &str) -> Result<String, String> {
        let (_, resp) = self.request("PUT", path, Some(body.as_bytes()))?;
        Ok(resp)
    }

    pub fn delete(&self, path: &str) -> Result<(), String> {
        self.request("DELETE", path, None)?;
        Ok(())
    }

    // Convenience methods
    pub fn status(&self) -> Result<String, String> { self.get("/api/whoami") }
    pub fn config_net(&self) -> Result<String, String> { self.get("/api/config/net") }
    pub fn config_reload(&self) -> Result<String, String> { self.post("/api/config/reload", "") }
    pub fn peers_list(&self) -> Result<String, String> { self.get("/api/peers") }
    pub fn peers_get(&self, pk: &str) -> Result<String, String> { self.get(&format!("/api/peers/{pk}")) }
    pub fn peers_add(&self, body: &str) -> Result<String, String> { self.post("/api/peers", body) }
    pub fn peers_update(&self, pk: &str, body: &str) -> Result<String, String> { self.put(&format!("/api/peers/{pk}"), body) }
    pub fn peers_remove(&self, pk: &str) -> Result<(), String> { self.delete(&format!("/api/peers/{pk}")) }
    pub fn lans_list(&self) -> Result<String, String> { self.get("/api/lans") }
    pub fn lans_join(&self, body: &str) -> Result<String, String> { self.post("/api/lans", body) }
    pub fn lans_leave(&self, domain: &str) -> Result<(), String> { self.delete(&format!("/api/lans/{domain}")) }
    pub fn policy_show(&self) -> Result<String, String> { self.get("/api/policy") }
    pub fn policy_add_rule(&self, body: &str) -> Result<String, String> { self.post("/api/policy/rules", body) }
    pub fn policy_remove_rule(&self, name: &str) -> Result<(), String> { self.delete(&format!("/api/policy/rules/{name}")) }
    pub fn routes_list(&self) -> Result<String, String> { self.get("/api/routes") }
    pub fn routes_add(&self, body: &str) -> Result<String, String> { self.post("/api/routes", body) }
    pub fn routes_remove(&self, id: &str) -> Result<(), String> { self.delete(&format!("/api/routes/{id}")) }
}

/// Returns the pidfile path for the given context.
pub fn pidfile_path(base_dir: &Path, name: &str) -> Result<PathBuf, String> {
    let ctx = if name.is_empty() {
        current_context_name(base_dir)?
    } else {
        name.to_string()
    };
    Ok(context_dir(base_dir, &ctx).join("data").join("zigor.pid"))
}

/// Reads the PID from the context's pidfile.
pub fn read_pidfile(base_dir: &Path, name: &str) -> Result<i32, String> {
    let path = pidfile_path(base_dir, name)?;
    let data = fs::read_to_string(&path)
        .map_err(|_| format!("host is not running for context {:?} (no pidfile)", name))?;
    data.trim().parse::<i32>()
        .map_err(|_| "invalid pidfile content".to_string())
}

/// Writes the PID to the context's pidfile.
pub fn write_pidfile(base_dir: &Path, name: &str, pid: u32) -> Result<(), String> {
    let path = pidfile_path(base_dir, name)?;
    let _ = fs::create_dir_all(path.parent().unwrap());
    fs::write(&path, format!("{pid}\n"))
        .map_err(|e| format!("write pidfile: {e}"))
}

/// Removes the context's pidfile.
pub fn remove_pidfile(base_dir: &Path, name: &str) {
    if let Ok(path) = pidfile_path(base_dir, name) {
        let _ = fs::remove_file(path);
    }
}

fn extract_error(body: &str) -> String {
    // Try to extract "error" field from JSON
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(msg) = v["error"].as_str() {
            return msg.to_string();
        }
    }
    let s = body.trim();
    if s.len() > 200 { s[..200].to_string() } else { s.to_string() }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_dir() -> TempDir {
        TempDir::new().expect("failed to create temp dir")
    }

    #[test]
    fn test_create_and_list() {
        let td = test_dir();
        let dir = td.path();
        assert!(list_contexts(dir).unwrap().is_empty());

        create_context(dir, "work").unwrap();

        let names = list_contexts(dir).unwrap();
        assert_eq!(names, vec!["work"]);

        assert!(dir.join("work/config.yaml").exists());
        assert!(dir.join("work/private.key").exists());
        assert!(dir.join("work/data").exists());
    }

    #[test]
    fn test_create_duplicate() {
        let td = test_dir();
        let dir = td.path();
        create_context(dir, "dup").unwrap();
        assert!(create_context(dir, "dup").is_err());
    }

    #[test]
    fn test_current_context() {
        let td = test_dir();
        let dir = td.path();
        assert!(current_context_name(dir).is_err());

        create_context(dir, "default").unwrap();
        set_current_context(dir, "default").unwrap();

        assert_eq!(current_context_name(dir).unwrap(), "default");
    }

    #[test]
    fn test_set_current_nonexistent() {
        let td = test_dir();
        assert!(set_current_context(td.path(), "nope").is_err());
    }

    #[test]
    fn test_delete_context() {
        let td = test_dir();
        let dir = td.path();
        create_context(dir, "temp").unwrap();
        delete_context(dir, "temp").unwrap();
        assert!(!dir.join("temp").exists());
    }

    #[test]
    fn test_delete_current_blocked() {
        let td = test_dir();
        let dir = td.path();
        create_context(dir, "active").unwrap();
        set_current_context(dir, "active").unwrap();
        assert!(delete_context(dir, "active").is_err());
    }

    #[test]
    fn test_show_public_key() {
        let td = test_dir();
        let dir = td.path();
        create_context(dir, "keytest").unwrap();
        let pk = show_public_key(dir, "keytest").unwrap();
        assert_eq!(pk.len(), 64);
    }

    #[test]
    fn test_generate_key() {
        let td = test_dir();
        let dir = td.path();
        create_context(dir, "regen").unwrap();
        let pk1 = show_public_key(dir, "regen").unwrap();
        let pk2 = generate_key(dir, "regen").unwrap();
        assert_ne!(pk1, pk2);
        assert_eq!(pk2.len(), 64);
    }

    #[test]
    fn test_resolve_api_addr() {
        let td = test_dir();
        let dir = td.path();
        assert_eq!(resolve_api_addr(dir, "", "10.0.0.1:8080"), "10.0.0.1:8080");
        assert_eq!(resolve_api_addr(dir, "", ""), "100.64.0.1:80");
        create_context(dir, "apitest").unwrap();
        set_current_context(dir, "apitest").unwrap();
        assert_eq!(resolve_api_addr(dir, "", ""), "100.64.0.1:80");
    }

    #[test]
    fn test_multiple_contexts_sorted() {
        let td = test_dir();
        let dir = td.path();
        for name in &["charlie", "alpha", "bravo"] {
            create_context(dir, name).unwrap();
        }
        let names = list_contexts(dir).unwrap();
        assert_eq!(names, vec!["alpha", "bravo", "charlie"]);
    }

    #[test]
    fn test_show_config() {
        let td = test_dir();
        let dir = td.path();
        create_context(dir, "show").unwrap();
        let content = show_config(dir, "show").unwrap();
        assert!(content.contains("tun_ipv4"));
    }

    #[test]
    fn test_config_path() {
        let td = test_dir();
        let dir = td.path();
        create_context(dir, "pathtest").unwrap();
        set_current_context(dir, "pathtest").unwrap();
        let path = context_config_path(dir, "").unwrap();
        assert!(path.ends_with("pathtest/config.yaml"));
    }

    #[test]
    fn test_validate_context_name() {
        assert!(validate_context_name("prod").is_ok());
        assert!(validate_context_name("dev").is_ok());
        assert!(validate_context_name("my-ctx").is_ok());

        assert!(validate_context_name("").is_err());
        assert!(validate_context_name("current").is_err());
        assert!(validate_context_name("a/b").is_err());
        assert!(validate_context_name("a\\b").is_err());
        assert!(validate_context_name("../evil").is_err());
        assert!(validate_context_name("a b").is_err());
        assert!(validate_context_name(".hidden").is_err());
    }

    #[test]
    fn test_create_invalid_name() {
        let td = test_dir();
        let dir = td.path();
        assert!(create_context(dir, "").is_err());
        assert!(create_context(dir, "a/b").is_err());
        assert!(create_context(dir, "../evil").is_err());
        assert!(create_context(dir, "a b").is_err());
        assert!(create_context(dir, ".hidden").is_err());
    }

    #[test]
    fn test_key_uniqueness() {
        let td = test_dir();
        let dir = td.path();
        create_context(dir, "k1").unwrap();
        create_context(dir, "k2").unwrap();
        let pk1 = show_public_key(dir, "k1").unwrap();
        let pk2 = show_public_key(dir, "k2").unwrap();
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn test_delete_nonexistent() {
        let td = test_dir();
        assert!(delete_context(td.path(), "ghost").is_err());
    }

    #[test]
    fn test_pidfile_roundtrip() {
        let td = test_dir();
        let dir = td.path();
        create_context(dir, "pidtest").unwrap();
        write_pidfile(dir, "pidtest", 12345).unwrap();
        let pid = read_pidfile(dir, "pidtest").unwrap();
        assert_eq!(pid, 12345);
        remove_pidfile(dir, "pidtest");
        assert!(read_pidfile(dir, "pidtest").is_err());
    }
}
