//! Thread-based async runtime benchmarks (Rust)
//!
//! Benchmarks using std::thread and crossbeam-channel.

use crossbeam_channel::{bounded, unbounded};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Number of iterations for benchmarks
pub const ITERATIONS: usize = 1_000_000;

/// Number of warmup iterations
pub const WARMUP: usize = 10_000;

/// Benchmark crossbeam channel task throughput (single-threaded dispatch + consume)
pub fn bench_channel_tasks() {
    let (tx, rx) = unbounded::<Box<dyn FnOnce() + Send>>();

    let counter = Arc::new(AtomicU64::new(0));

    // Warmup
    for _ in 0..WARMUP {
        let counter = Arc::clone(&counter);
        tx.send(Box::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        }))
        .unwrap();
    }
    while let Ok(task) = rx.try_recv() {
        task();
    }
    counter.store(0, Ordering::Relaxed);

    // Benchmark: send + receive
    let start = Instant::now();

    for _ in 0..ITERATIONS {
        let counter = Arc::clone(&counter);
        tx.send(Box::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        }))
        .unwrap();
    }

    // Process all tasks
    while let Ok(task) = rx.try_recv() {
        task();
    }

    let elapsed = start.elapsed();
    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
    let tasks_per_sec = ITERATIONS as f64 / elapsed.as_secs_f64();

    println!(
        "Channel task throughput:    {:.2} M tasks/sec ({:.0}ms, {} tasks)",
        tasks_per_sec / 1_000_000.0,
        elapsed_ms,
        counter.load(Ordering::Relaxed)
    );
}

/// Benchmark task closure creation overhead
pub fn bench_task_creation() {
    let mut dummy: u64 = 0;

    // Warmup
    for _ in 0..WARMUP {
        let task: Box<dyn FnOnce()> = Box::new(|| {
            dummy += 1;
        });
        let _ = std::hint::black_box(task);
    }

    let start = Instant::now();

    for _ in 0..ITERATIONS {
        let task: Box<dyn FnOnce()> = Box::new(|| {
            dummy += 1;
        });
        let _ = std::hint::black_box(task);
    }

    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() as f64 / ITERATIONS as f64;

    println!("Task creation overhead:     {:.1} ns/task", ns_per_op);
}

/// Benchmark std::thread spawn throughput
pub fn bench_thread_spawn() {
    let spawn_count: usize = 1_000; // Threads are expensive

    let start = Instant::now();

    let handles: Vec<_> = (0..spawn_count)
        .map(|_| std::thread::spawn(|| {}))
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = start.elapsed();
    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
    let spawns_per_sec = spawn_count as f64 / elapsed.as_secs_f64();

    println!(
        "Thread spawn throughput:    {:.2} K threads/sec ({:.1}ms, {} spawns)",
        spawns_per_sec / 1_000.0,
        elapsed_ms,
        spawn_count
    );
}

/// Benchmark bounded channel send/recv cycles (context switch simulation)
pub fn bench_channel_pingpong() {
    let cycles: usize = 100_000;
    let (tx1, rx1) = bounded::<u64>(1);
    let (tx2, rx2) = bounded::<u64>(1);

    let handle = std::thread::spawn(move || {
        for _ in 0..cycles {
            let val = rx1.recv().unwrap();
            tx2.send(val + 1).unwrap();
        }
    });

    let start = Instant::now();

    for i in 0..cycles {
        tx1.send(i as u64).unwrap();
        let _ = rx2.recv().unwrap();
    }

    let elapsed = start.elapsed();
    handle.join().unwrap();

    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
    let cycles_per_sec = cycles as f64 / elapsed.as_secs_f64();

    println!(
        "Channel ping-pong:          {:.2} M cycles/sec ({:.1}ms, {} cycles)",
        cycles_per_sec / 1_000_000.0,
        elapsed_ms,
        cycles
    );
}

/// Run all thread-based benchmarks
pub fn run_all() {
    println!("[Thread Backend - crossbeam]");
    bench_channel_tasks();
    bench_task_creation();
    bench_thread_spawn();
    bench_channel_pingpong();
}
