use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

const KCP_VERSION: &str = "1.7";
const KCP_URL: &str = "https://raw.githubusercontent.com/skywind3000/kcp/1.7/ikcp.c";
const KCP_HEADER_URL: &str = "https://raw.githubusercontent.com/skywind3000/kcp/1.7/ikcp.h";

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let kcp_dir = out_dir.join("kcp");
    
    // Create KCP directory
    fs::create_dir_all(&kcp_dir).unwrap();
    
    let ikcp_c = kcp_dir.join("ikcp.c");
    let ikcp_h = kcp_dir.join("ikcp.h");
    
    // Download KCP source files if they don't exist
    if !ikcp_c.exists() {
        download_file(KCP_URL, &ikcp_c);
    }
    if !ikcp_h.exists() {
        download_file(KCP_HEADER_URL, &ikcp_h);
    }
    
    // Compile KCP
    cc::Build::new()
        .file(&ikcp_c)
        .include(&kcp_dir)
        .opt_level(3)
        .define("NDEBUG", None)
        .compile("kcp");
    
    // Generate bindings header path for reference
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-lib=static=kcp");
    
    // Output include path for potential use
    println!("cargo:include={}", kcp_dir.display());
}

fn download_file(url: &str, dest: &PathBuf) {
    // Use a simple HTTP client approach - try curl first
    let output = std::process::Command::new("curl")
        .args(["-sL", url])
        .output()
        .expect("Failed to execute curl");
    
    if output.status.success() {
        let mut file = fs::File::create(dest).unwrap();
        file.write_all(&output.stdout).unwrap();
    } else {
        panic!("Failed to download {}: {:?}", url, String::from_utf8_lossy(&output.stderr));
    }
}
