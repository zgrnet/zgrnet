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
}
