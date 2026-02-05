//! Tokio-based async runtime benchmarks (Rust)
//!
//! Benchmarks using tokio async runtime.

use std::time::Instant;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

/// Number of iterations for benchmarks
pub const ITERATIONS: usize = 1_000_000;

/// Benchmark tokio::spawn task throughput
pub fn bench_spawn_tasks() {
    let rt = Runtime::new().unwrap();

    let task_count: usize = 100_000; // Fewer due to async overhead

    let start = Instant::now();

    rt.block_on(async {
        let mut handles = Vec::with_capacity(task_count);

        for _ in 0..task_count {
            handles.push(tokio::spawn(async {}));
        }

        for handle in handles {
            handle.await.unwrap();
        }
    });

    let elapsed = start.elapsed();
    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
    let tasks_per_sec = task_count as f64 / elapsed.as_secs_f64();

    println!(
        "Tokio spawn throughput:     {:.2} M tasks/sec ({:.0}ms, {} tasks)",
        tasks_per_sec / 1_000_000.0,
        elapsed_ms,
        task_count
    );
}

/// Benchmark tokio mpsc channel throughput
pub fn bench_mpsc_channel() {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        let (tx, mut rx) = mpsc::unbounded_channel::<u64>();

        let start = Instant::now();

        // Send all messages
        for i in 0..ITERATIONS {
            tx.send(i as u64).unwrap();
        }

        // Receive all messages
        let mut count = 0u64;
        while let Ok(val) = rx.try_recv() {
            count += 1;
            std::hint::black_box(val);
        }

        let elapsed = start.elapsed();
        let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
        let msgs_per_sec = count as f64 / elapsed.as_secs_f64();

        println!(
            "Tokio mpsc throughput:      {:.2} M msgs/sec ({:.0}ms, {} msgs)",
            msgs_per_sec / 1_000_000.0,
            elapsed_ms,
            count
        );
    });
}

/// Benchmark tokio timer throughput
pub fn bench_timers() {
    let rt = Runtime::new().unwrap();

    let timer_count: usize = 10_000; // Timers are more expensive

    rt.block_on(async {
        let start = Instant::now();

        let mut handles = Vec::with_capacity(timer_count);

        for _ in 0..timer_count {
            handles.push(tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let elapsed = start.elapsed();
        let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
        let timers_per_sec = timer_count as f64 / elapsed.as_secs_f64();

        println!(
            "Tokio timer throughput:     {:.2} K timers/sec ({:.1}ms, {} timers)",
            timers_per_sec / 1_000.0,
            elapsed_ms,
            timer_count
        );
    });
}

/// Benchmark tokio yield_now (context switch)
pub fn bench_yield() {
    let rt = Runtime::new().unwrap();

    let yield_count: usize = 100_000;

    rt.block_on(async {
        let start = Instant::now();

        for _ in 0..yield_count {
            tokio::task::yield_now().await;
        }

        let elapsed = start.elapsed();
        let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
        let yields_per_sec = yield_count as f64 / elapsed.as_secs_f64();

        println!(
            "Tokio yield throughput:     {:.2} M yields/sec ({:.1}ms, {} yields)",
            yields_per_sec / 1_000_000.0,
            elapsed_ms,
            yield_count
        );
    });
}

/// Run all tokio benchmarks
pub fn run_all() {
    println!("\n[Tokio Backend]");
    bench_spawn_tasks();
    bench_mpsc_channel();
    bench_timers();
    bench_yield();
}
