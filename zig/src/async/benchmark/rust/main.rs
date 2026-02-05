//! Rust Async Runtime Benchmarks
//!
//! Compares performance of different async runtime implementations:
//! - Thread-based (std::thread + crossbeam-channel)
//! - Tokio-based (tokio async runtime)
//!
//! Run with: cargo run --bin async_bench

mod thread;
mod tokio_bench;

fn main() {
    println!();
    println!("Async Runtime Benchmarks (Rust)");
    println!("===============================");
    println!();

    // Run thread-based benchmarks
    thread::run_all();

    // Run tokio benchmarks
    tokio_bench::run_all();

    println!();
}
