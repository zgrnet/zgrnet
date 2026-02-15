//! zgrnet — management tool for zgrnet.
//!
//! Provides offline context/config management and online API commands
//! for interacting with a running zgrnetd daemon.

use std::path::PathBuf;
use zgrnet::cli;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    // Parse global flags
    let mut api_addr = String::new();
    let mut ctx_override = String::new();
    let mut json_output = false;
    let mut filtered = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--api" => {
                if i + 1 < args.len() {
                    api_addr = args[i + 1].clone();
                    i += 2;
                    continue;
                }
                i += 1;
            }
            "--context" => {
                if i + 1 < args.len() {
                    ctx_override = args[i + 1].clone();
                    i += 2;
                    continue;
                }
                i += 1;
            }
            "--json" => {
                json_output = true;
                i += 1;
            }
            _ => {
                filtered.push(args[i].clone());
                i += 1;
            }
        }
    }

    let base_dir = cli::default_config_dir()?;

    match filtered[0].as_str() {
        "context" => run_context(&base_dir, &filtered[1..]),
        "key" => run_key(&base_dir, &ctx_override, &filtered[1..]),
        "config" => run_config(&base_dir, &ctx_override, &api_addr, json_output, &filtered[1..]),
        "up" => run_up(&base_dir, &ctx_override, &filtered[1..]),
        "down" => run_down(&base_dir, &ctx_override),
        "status" | "peers" | "lans" | "policy" | "routes" => {
            run_online(&base_dir, &ctx_override, &api_addr, json_output, &filtered)
        }
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        cmd => Err(format!("unknown command {cmd:?} (run 'zgrnet help' for usage)")),
    }
}

// ── Context ─────────────────────────────────────────────────────────────────

fn run_context(base_dir: &PathBuf, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zgrnet context <list|use|create|current|delete>".into());
    }
    match args[0].as_str() {
        "list" => {
            let names = cli::list_contexts(base_dir)?;
            let current = cli::current_context_name(base_dir).unwrap_or_default();
            for name in &names {
                let marker = if *name == current { "* " } else { "  " };
                println!("{marker}{name}");
            }
            if names.is_empty() {
                println!("(no contexts — run: zgrnet context create <name>)");
            }
            Ok(())
        }
        "current" => {
            let name = cli::current_context_name(base_dir)?;
            println!("{name}");
            Ok(())
        }
        "use" => {
            let name = args.get(1).ok_or("usage: zgrnet context use <name>")?;
            cli::set_current_context(base_dir, name)?;
            println!("switched to context {name:?}");
            Ok(())
        }
        "create" => {
            let name = args.get(1).ok_or("usage: zgrnet context create <name>")?;
            cli::create_context(base_dir, name)?;
            let names = cli::list_contexts(base_dir)?;
            if names.len() == 1 {
                let _ = cli::set_current_context(base_dir, name);
            }
            let pk = cli::show_public_key(base_dir, name).unwrap_or_default();
            println!("created context {name:?}");
            println!("public key: {pk}");
            Ok(())
        }
        "delete" => {
            let name = args.get(1).ok_or("usage: zgrnet context delete <name>")?;
            cli::delete_context(base_dir, name)?;
            println!("deleted context {name:?}");
            Ok(())
        }
        cmd => Err(format!("unknown context subcommand {cmd:?}")),
    }
}

// ── Key ─────────────────────────────────────────────────────────────────────

fn run_key(base_dir: &PathBuf, ctx: &str, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zgrnet key <generate|show>".into());
    }
    match args[0].as_str() {
        "show" => {
            let pk = cli::show_public_key(base_dir, ctx)?;
            println!("{pk}");
            Ok(())
        }
        "generate" => {
            let pk = cli::generate_key(base_dir, ctx)?;
            println!("new public key: {pk}");
            Ok(())
        }
        cmd => Err(format!("unknown key subcommand {cmd:?}")),
    }
}

// ── Config ──────────────────────────────────────────────────────────────────

fn run_config(base_dir: &PathBuf, ctx: &str, api_addr: &str, json_output: bool, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zgrnet config <show|path|edit|net|reload>".into());
    }
    match args[0].as_str() {
        "show" => {
            let content = cli::show_config(base_dir, ctx)?;
            print!("{content}");
            Ok(())
        }
        "path" => {
            let path = cli::context_config_path(base_dir, ctx)?;
            println!("{}", path.display());
            Ok(())
        }
        "edit" => cli::edit_config(base_dir, ctx),
        "net" => {
            let addr = cli::resolve_api_addr(base_dir, ctx, api_addr);
            let c = cli::Client::new(&addr);
            let data = c.config_net()?;
            print_json(&data, json_output);
            Ok(())
        }
        "reload" => {
            let addr = cli::resolve_api_addr(base_dir, ctx, api_addr);
            let c = cli::Client::new(&addr);
            let data = c.config_reload()?;
            print_json(&data, json_output);
            Ok(())
        }
        cmd => Err(format!("unknown config subcommand {cmd:?}")),
    }
}

// ── Up / Down ───────────────────────────────────────────────────────────────

fn run_up(base_dir: &PathBuf, ctx: &str, args: &[String]) -> Result<(), String> {
    let daemon = args.iter().any(|a| a == "-d" || a == "--daemon");
    let cfg_path = cli::context_config_path(base_dir, ctx)?;

    // Find zgrnetd binary
    let zgrnetd = which_zgrnetd()?;

    if daemon {
        let mut cmd = std::process::Command::new(&zgrnetd);
        cmd.arg("-c").arg(&cfg_path);
        let child = cmd.spawn().map_err(|e| format!("start zgrnetd: {e}"))?;

        // Write PID file
        let ctx_name = if ctx.is_empty() {
            cli::current_context_name(base_dir)?
        } else {
            ctx.to_string()
        };
        let pid_dir = cli::context_dir(base_dir, &ctx_name).join("data");
        let _ = std::fs::create_dir_all(&pid_dir);
        let _ = std::fs::write(pid_dir.join("zgrnetd.pid"), format!("{}\n", child.id()));

        println!("zgrnetd started in background (pid {})", child.id());
    } else {
        // Foreground: exec
        let err = exec_replace(&zgrnetd, &["-c", &cfg_path.to_string_lossy()]);
        return Err(format!("exec zgrnetd: {err}"));
    }
    Ok(())
}

fn run_down(base_dir: &PathBuf, ctx: &str) -> Result<(), String> {
    let ctx_name = if ctx.is_empty() {
        cli::current_context_name(base_dir)?
    } else {
        ctx.to_string()
    };

    let pid_path = cli::context_dir(base_dir, &ctx_name).join("data").join("zgrnetd.pid");
    let data = std::fs::read_to_string(&pid_path)
        .map_err(|_| format!("no running zgrnetd found for context {ctx_name:?} (no pid file)"))?;
    let pid: i32 = data.trim().parse()
        .map_err(|_| "invalid pid file".to_string())?;

    #[cfg(unix)]
    unsafe {
        if libc::kill(pid, libc::SIGTERM) != 0 {
            return Err(format!("send SIGTERM to pid {pid}: {}", std::io::Error::last_os_error()));
        }
    }
    #[cfg(windows)]
    {
        // On Windows, use taskkill to terminate the process
        let status = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status()
            .map_err(|e| format!("taskkill failed: {e}"))?;
        if !status.success() {
            return Err(format!("taskkill failed for pid {pid}"));
        }
    }
    let _ = std::fs::remove_file(&pid_path);
    println!("zgrnetd stopped");
    Ok(())
}

fn which_zgrnetd() -> Result<String, String> {
    // Try PATH
    if let Ok(output) = std::process::Command::new("which").arg("zgrnetd").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(path);
            }
        }
    }
    // Try next to self
    if let Ok(self_path) = std::env::current_exe() {
        let candidate = self_path.parent().unwrap().join("zgrnetd");
        if candidate.exists() {
            return Ok(candidate.to_string_lossy().to_string());
        }
    }
    Err("zgrnetd not found in PATH or alongside this binary".to_string())
}

#[cfg(unix)]
fn exec_replace(program: &str, args: &[&str]) -> String {
    use std::ffi::CString;
    let c_prog = CString::new(program).unwrap();
    let mut c_args: Vec<CString> = vec![CString::new("zgrnetd").unwrap()];
    for a in args {
        c_args.push(CString::new(*a).unwrap());
    }
    let c_ptrs: Vec<*const libc::c_char> = c_args.iter().map(|a| a.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();
    unsafe { libc::execvp(c_prog.as_ptr(), c_ptrs.as_ptr()) };
    std::io::Error::last_os_error().to_string()
}

#[cfg(not(unix))]
fn exec_replace(program: &str, args: &[&str]) -> String {
    "exec not supported on this platform".to_string()
}

// ── Online commands ─────────────────────────────────────────────────────────

fn run_online(base_dir: &PathBuf, ctx: &str, api_addr: &str, json_output: bool, args: &[String]) -> Result<(), String> {
    let addr = cli::resolve_api_addr(base_dir, ctx, api_addr);
    let c = cli::Client::new(&addr);

    match args[0].as_str() {
        "status" => {
            let data = c.status()?;
            print_json(&data, json_output);
        }
        "peers" => run_peers(&c, json_output, &args[1..])?,
        "lans" => run_lans(&c, json_output, &args[1..])?,
        "policy" => run_policy(&c, json_output, &args[1..])?,
        "routes" => run_routes(&c, json_output, &args[1..])?,
        _ => return Err(format!("unknown command {:?}", args[0])),
    }
    Ok(())
}

fn run_peers(c: &cli::Client, json_output: bool, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zgrnet peers <list|add|get|update|remove>".into());
    }
    match args[0].as_str() {
        "list" => { print_json(&c.peers_list()?, json_output); }
        "get" => {
            let pk = args.get(1).ok_or("usage: zgrnet peers get <pubkey>")?;
            print_json(&c.peers_get(pk)?, json_output);
        }
        "add" => {
            let (mut pk, mut alias, mut endpoint) = (String::new(), String::new(), String::new());
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--alias" => { alias = args.get(i+1).cloned().unwrap_or_default(); i += 2; }
                    "--endpoint" => { endpoint = args.get(i+1).cloned().unwrap_or_default(); i += 2; }
                    _ => { if pk.is_empty() { pk = args[i].clone(); } i += 1; }
                }
            }
            if pk.is_empty() {
                return Err("usage: zgrnet peers add <pubkey> [--alias <a>] [--endpoint <e>]".into());
            }
            let body = format!(r#"{{"pubkey":"{}","alias":"{}","endpoint":"{}"}}"#, pk, alias, endpoint);
            print_json(&c.peers_add(&body)?, json_output);
        }
        "update" => {
            let pk = args.get(1).ok_or("usage: zgrnet peers update <pubkey> [--alias <a>] [--endpoint <e>]")?;
            let mut fields = Vec::new();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--alias" => { fields.push(format!(r#""alias":"{}""#, args.get(i+1).cloned().unwrap_or_default())); i += 2; }
                    "--endpoint" => { fields.push(format!(r#""endpoint":"{}""#, args.get(i+1).cloned().unwrap_or_default())); i += 2; }
                    _ => { i += 1; }
                }
            }
            let body = format!("{{{}}}", fields.join(","));
            print_json(&c.peers_update(pk, &body)?, json_output);
        }
        "remove" => {
            let pk = args.get(1).ok_or("usage: zgrnet peers remove <pubkey>")?;
            c.peers_remove(pk)?;
            println!("peer removed");
        }
        cmd => return Err(format!("unknown peers subcommand {cmd:?}")),
    }
    Ok(())
}

fn run_lans(c: &cli::Client, json_output: bool, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zgrnet lans <list|join|leave>".into());
    }
    match args[0].as_str() {
        "list" => { print_json(&c.lans_list()?, json_output); }
        "join" => {
            let (mut domain, mut pubkey, mut endpoint) = (String::new(), String::new(), String::new());
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--domain" => { domain = args.get(i+1).cloned().unwrap_or_default(); i += 2; }
                    "--pubkey" => { pubkey = args.get(i+1).cloned().unwrap_or_default(); i += 2; }
                    "--endpoint" => { endpoint = args.get(i+1).cloned().unwrap_or_default(); i += 2; }
                    _ => { i += 1; }
                }
            }
            if domain.is_empty() || pubkey.is_empty() || endpoint.is_empty() {
                return Err("usage: zgrnet lans join --domain <d> --pubkey <pk> --endpoint <e>".into());
            }
            let body = format!(r#"{{"domain":"{}","pubkey":"{}","endpoint":"{}"}}"#, domain, pubkey, endpoint);
            print_json(&c.lans_join(&body)?, json_output);
        }
        "leave" => {
            let domain = args.get(1).ok_or("usage: zgrnet lans leave <domain>")?;
            c.lans_leave(domain)?;
            println!("lan left");
        }
        cmd => return Err(format!("unknown lans subcommand {cmd:?}")),
    }
    Ok(())
}

fn run_policy(c: &cli::Client, json_output: bool, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zgrnet policy <show|add-rule|remove-rule>".into());
    }
    match args[0].as_str() {
        "show" => { print_json(&c.policy_show()?, json_output); }
        "add-rule" => {
            if args.len() < 2 {
                return Err("usage: zgrnet policy add-rule '<json>'".into());
            }
            let json = args[1..].join(" ");
            print_json(&c.policy_add_rule(&json)?, json_output);
        }
        "remove-rule" => {
            let name = args.get(1).ok_or("usage: zgrnet policy remove-rule <name>")?;
            c.policy_remove_rule(name)?;
            println!("rule removed");
        }
        cmd => return Err(format!("unknown policy subcommand {cmd:?}")),
    }
    Ok(())
}

fn run_routes(c: &cli::Client, json_output: bool, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zgrnet routes <list|add|remove>".into());
    }
    match args[0].as_str() {
        "list" => { print_json(&c.routes_list()?, json_output); }
        "add" => {
            let (mut domain, mut peer) = (String::new(), String::new());
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--domain" => { domain = args.get(i+1).cloned().unwrap_or_default(); i += 2; }
                    "--peer" => { peer = args.get(i+1).cloned().unwrap_or_default(); i += 2; }
                    _ => { i += 1; }
                }
            }
            if domain.is_empty() || peer.is_empty() {
                return Err("usage: zgrnet routes add --domain <pattern> --peer <alias>".into());
            }
            let body = format!(r#"{{"domain":"{}","peer":"{}"}}"#, domain, peer);
            print_json(&c.routes_add(&body)?, json_output);
        }
        "remove" => {
            let id = args.get(1).ok_or("usage: zgrnet routes remove <id>")?;
            c.routes_remove(id)?;
            println!("route removed");
        }
        cmd => return Err(format!("unknown routes subcommand {cmd:?}")),
    }
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn print_json(data: &str, raw: bool) {
    if raw {
        println!("{data}");
        return;
    }
    // Pretty-print
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) {
        if let Ok(pretty) = serde_json::to_string_pretty(&v) {
            println!("{pretty}");
            return;
        }
    }
    println!("{data}");
}

fn print_usage() {
    eprintln!(r#"zgrnet — zgrnet management tool

Usage: zgrnet <command> [options]

Context management (offline):
  context list                 List all contexts
  context use <name>           Switch to a context
  context create <name>        Create a new context (generates keypair)
  context current              Show current context name
  context delete <name>        Delete a context

Key management:
  key show                     Show public key of current context
  key generate                 Generate a new keypair (overwrites existing)

Config management:
  config show                  Print config.yaml contents
  config path                  Print config.yaml file path
  config edit                  Open config in $EDITOR
  config net                   Show network config (via API)
  config reload                Reload config from disk (via API)

Daemon control:
  up [--context <name>] [-d]   Start zgrnetd (-d for background)
  down                         Stop running zgrnetd

Status (via API):
  status                       Show node info (pubkey, TUN IP, uptime)

Peer management (via API):
  peers list                   List all peers
  peers get <pubkey>           Show peer details
  peers add <pubkey> [--alias <a>] [--endpoint <e>]
  peers update <pubkey> [--alias <a>] [--endpoint <e>]
  peers remove <pubkey>        Remove a peer

Lan management (via API):
  lans list                    List all lans
  lans join --domain <d> --pubkey <pk> --endpoint <e>
  lans leave <domain>          Leave a lan

Policy management (via API):
  policy show                  Show inbound policy
  policy add-rule '<json>'     Add an inbound rule
  policy remove-rule <name>    Remove an inbound rule

Route management (via API):
  routes list                  List route rules
  routes add --domain <pattern> --peer <alias>
  routes remove <id>           Remove a route by index

Global flags:
  --api <addr>                 Override API address (default: from config)
  --context <name>             Override context
  --json                       Output raw JSON
"#);
}
