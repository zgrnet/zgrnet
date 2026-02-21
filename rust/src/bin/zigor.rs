//! zigor — unified zgrnet management tool (Rust).
//!
//! Replaces both zgrnet (CLI) and zgrnetd (daemon) with a single binary.

use std::path::Path;
use zgrnet::cli;

const VERSION: &str = "0.1.0";

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
            "--ctx" => {
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

    if filtered.is_empty() {
        print_usage();
        return Ok(());
    }

    let base_dir = cli::default_config_dir()?;

    match filtered[0].as_str() {
        "ctx" => run_ctx(&base_dir, &filtered[1..]),
        "key" => run_key(&base_dir, &ctx_override, &filtered[1..]),
        "config" => run_config(&base_dir, &ctx_override, &api_addr, json_output, &filtered[1..]),
        "host" => run_host(&base_dir, &ctx_override, &api_addr, json_output, &filtered[1..]),
        "peers" | "lans" | "policy" | "routes" => {
            run_online(&base_dir, &ctx_override, &api_addr, json_output, &filtered)
        }
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        "version" | "--version" => {
            println!("zigor {VERSION}");
            Ok(())
        }
        cmd => Err(format!("unknown command {cmd:?} (run 'zigor help' for usage)")),
    }
}

// ── ctx ─────────────────────────────────────────────────────────────────────

fn run_ctx(base_dir: &Path, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zigor ctx <list|create|delete|show|use>".into());
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
                println!("(no contexts — run: zigor ctx create <name>)");
            }
            Ok(())
        }
        "show" => {
            let name = cli::current_context_name(base_dir)?;
            println!("{name}");
            Ok(())
        }
        "use" => {
            let name = args.get(1).ok_or("usage: zigor ctx use <name>")?;
            cli::set_current_context(base_dir, name)?;
            println!("switched to context {name:?}");
            Ok(())
        }
        "create" => {
            let name = args.get(1).ok_or("usage: zigor ctx create <name>")?;
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
            let name = args.get(1).ok_or("usage: zigor ctx delete <name>")?;
            cli::delete_context(base_dir, name)?;
            println!("deleted context {name:?}");
            Ok(())
        }
        cmd => Err(format!("unknown ctx subcommand {cmd:?}")),
    }
}

// ── key ─────────────────────────────────────────────────────────────────────

fn run_key(base_dir: &Path, ctx: &str, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zigor key <generate|show>".into());
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

// ── config ──────────────────────────────────────────────────────────────────

fn run_config(base_dir: &Path, ctx: &str, api_addr: &str, json_output: bool, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zigor config <show|path|edit|net|reload>".into());
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

// ── host ────────────────────────────────────────────────────────────────────

fn run_host(base_dir: &Path, ctx: &str, api_addr: &str, json_output: bool, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zigor host <up|down|status|peers>".into());
    }
    match args[0].as_str() {
        "up" => {
            Err("host up not implemented in Rust build (use Go build)".into())
        }
        "down" => {
            let ctx_name = if ctx.is_empty() {
                cli::current_context_name(base_dir)?
            } else {
                ctx.to_string()
            };
            let pid = cli::read_pidfile(base_dir, &ctx_name)?;

            #[cfg(unix)]
            unsafe {
                if libc::kill(pid, libc::SIGTERM) != 0 {
                    return Err(format!("send SIGTERM to pid {pid}: {}", std::io::Error::last_os_error()));
                }
            }
            #[cfg(windows)]
            {
                let status = std::process::Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .status()
                    .map_err(|e| format!("taskkill failed: {e}"))?;
                if !status.success() {
                    return Err(format!("taskkill failed for pid {pid}"));
                }
            }
            cli::remove_pidfile(base_dir, &ctx_name);
            println!("host stopped");
            Ok(())
        }
        "status" => {
            let ctx_name = if ctx.is_empty() {
                cli::current_context_name(base_dir)?
            } else {
                ctx.to_string()
            };
            match cli::read_pidfile(base_dir, &ctx_name) {
                Ok(pid) => {
                    #[cfg(unix)]
                    let dead = unsafe {
                        if libc::kill(pid, 0) != 0 {
                            std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                        } else {
                            false
                        }
                    };
                    #[cfg(not(unix))]
                    let dead = false;

                    if dead {
                        println!("host is not running (stale pidfile, pid {pid})");
                        cli::remove_pidfile(base_dir, &ctx_name);
                    } else {
                        let addr = cli::resolve_api_addr(base_dir, &ctx_name, api_addr);
                        let c = cli::Client::new(&addr);
                        match c.status() {
                            Ok(data) => print_json(&data, json_output),
                            Err(e) => println!("host is running (pid {pid}) but API unreachable: {e}"),
                        }
                    }
                }
                Err(_) => println!("host is not running (context {ctx_name:?})"),
            }
            Ok(())
        }
        "peers" => {
            let addr = cli::resolve_api_addr(base_dir, ctx, api_addr);
            let c = cli::Client::new(&addr);
            let data = c.peers_list()?;
            print_json(&data, json_output);
            Ok(())
        }
        cmd => Err(format!("unknown host subcommand {cmd:?}")),
    }
}

// ── Online commands ─────────────────────────────────────────────────────────

fn run_online(base_dir: &Path, ctx: &str, api_addr: &str, json_output: bool, args: &[String]) -> Result<(), String> {
    let addr = cli::resolve_api_addr(base_dir, ctx, api_addr);
    let c = cli::Client::new(&addr);

    match args[0].as_str() {
        "peers" => run_peers(&c, json_output, &args[1..]),
        "lans" => run_lans(&c, json_output, &args[1..]),
        "policy" => run_policy(&c, json_output, &args[1..]),
        "routes" => run_routes(&c, json_output, &args[1..]),
        _ => Err(format!("unknown command {:?}", args[0])),
    }
}

fn run_peers(c: &cli::Client, json_output: bool, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zigor peers <list|add|get|update|remove>".into());
    }
    match args[0].as_str() {
        "list" => { print_json(&c.peers_list()?, json_output); }
        "get" => {
            let pk = args.get(1).ok_or("usage: zigor peers get <pubkey>")?;
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
                return Err("usage: zigor peers add <pubkey> [--alias <a>] [--endpoint <e>]".into());
            }
            let body = serde_json::json!({"pubkey": pk, "alias": alias, "endpoint": endpoint}).to_string();
            print_json(&c.peers_add(&body)?, json_output);
        }
        "update" => {
            let pk = args.get(1).ok_or("usage: zigor peers update <pubkey> [--alias <a>] [--endpoint <e>]")?;
            let mut fields = serde_json::Map::new();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--alias" => { fields.insert("alias".into(), serde_json::Value::String(args.get(i+1).cloned().unwrap_or_default())); i += 2; }
                    "--endpoint" => { fields.insert("endpoint".into(), serde_json::Value::String(args.get(i+1).cloned().unwrap_or_default())); i += 2; }
                    _ => { i += 1; }
                }
            }
            let body = serde_json::Value::Object(fields).to_string();
            print_json(&c.peers_update(pk, &body)?, json_output);
        }
        "remove" => {
            let pk = args.get(1).ok_or("usage: zigor peers remove <pubkey>")?;
            c.peers_remove(pk)?;
            println!("peer removed");
        }
        cmd => return Err(format!("unknown peers subcommand {cmd:?}")),
    }
    Ok(())
}

fn run_lans(c: &cli::Client, json_output: bool, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zigor lans <list|join|leave>".into());
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
                return Err("usage: zigor lans join --domain <d> --pubkey <pk> --endpoint <e>".into());
            }
            let body = serde_json::json!({"domain": domain, "pubkey": pubkey, "endpoint": endpoint}).to_string();
            print_json(&c.lans_join(&body)?, json_output);
        }
        "leave" => {
            let domain = args.get(1).ok_or("usage: zigor lans leave <domain>")?;
            c.lans_leave(domain)?;
            println!("lan left");
        }
        cmd => return Err(format!("unknown lans subcommand {cmd:?}")),
    }
    Ok(())
}

fn run_policy(c: &cli::Client, json_output: bool, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zigor policy <show|add-rule|remove-rule>".into());
    }
    match args[0].as_str() {
        "show" => { print_json(&c.policy_show()?, json_output); }
        "add-rule" => {
            if args.len() < 2 {
                return Err("usage: zigor policy add-rule '<json>'".into());
            }
            let json = args[1..].join(" ");
            print_json(&c.policy_add_rule(&json)?, json_output);
        }
        "remove-rule" => {
            let name = args.get(1).ok_or("usage: zigor policy remove-rule <name>")?;
            c.policy_remove_rule(name)?;
            println!("rule removed");
        }
        cmd => return Err(format!("unknown policy subcommand {cmd:?}")),
    }
    Ok(())
}

fn run_routes(c: &cli::Client, json_output: bool, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: zigor routes <list|add|remove>".into());
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
                return Err("usage: zigor routes add --domain <pattern> --peer <alias>".into());
            }
            let body = serde_json::json!({"domain": domain, "peer": peer}).to_string();
            print_json(&c.routes_add(&body)?, json_output);
        }
        "remove" => {
            let id = args.get(1).ok_or("usage: zigor routes remove <id>")?;
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
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) {
        if let Ok(pretty) = serde_json::to_string_pretty(&v) {
            println!("{pretty}");
            return;
        }
    }
    println!("{data}");
}

fn print_usage() {
    eprintln!(r#"zigor — zgrnet management tool

Usage: zigor [--ctx <name>] <command> [options]

Context management (offline):
  ctx list                     List all contexts
  ctx create <name>            Create a new context (generates keypair)
  ctx delete <name>            Delete a context
  ctx show                     Show current context name
  ctx use <name>               Switch to a context

Host control:
  host up [-d]                 Start host (-d for background)
  host down                    Stop running host
  host status                  Show host status
  host peers                   List connected peers

Key management:
  key show                     Show public key of current context
  key generate                 Generate a new keypair (overwrites existing)

Global flags:
  --ctx <name>                 Override context
  --api <addr>                 Override API address
  --json                       Output raw JSON
  --version                    Show version
"#);
}
