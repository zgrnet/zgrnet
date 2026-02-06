fn main() {
    // Compile KCP from vendored sources
    cc::Build::new()
        .file("kcp/ikcp.c")
        .include("kcp")
        .opt_level(3)
        .define("NDEBUG", None)
        .compile("kcp");

    // Rerun if build script or KCP sources change
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=kcp/ikcp.c");
    println!("cargo:rerun-if-changed=kcp/ikcp.h");

    // Link the compiled static library
    println!("cargo:rustc-link-lib=static=kcp");

    // Link the Zig TUN library
    // The library should be built first with: cd ../zig && zig build
    let zig_lib_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("zig")
        .join("zig-out")
        .join("lib");

    if zig_lib_path.exists() {
        println!("cargo:rustc-link-search=native={}", zig_lib_path.display());
        println!("cargo:rustc-link-lib=static=tun");

        // Platform-specific frameworks/libraries
        #[cfg(target_os = "macos")]
        {
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            println!("cargo:rustc-link-lib=framework=SystemConfiguration");
        }

        #[cfg(target_os = "windows")]
        {
            println!("cargo:rustc-link-lib=ws2_32");
            println!("cargo:rustc-link-lib=iphlpapi");
        }
    }

    // Rerun if TUN library changes
    println!("cargo:rerun-if-changed=../zig/zig-out/lib/libtun.a");
}
