// Async Runtime Benchmarks (Go)
//
// Benchmarks for goroutine and channel performance.
//
// Run with: go run zig/src/async/benchmark/go/main.go

package main

import (
	"fmt"
	"sync"
	"time"
)

const (
	// Number of iterations for benchmarks
	ITERATIONS = 1_000_000

	// Number of warmup iterations
	WARMUP = 10_000
)

func main() {
	fmt.Println()
	fmt.Println("Async Runtime Benchmarks (Go)")
	fmt.Println("=============================")
	fmt.Println()

	fmt.Println("[Goroutine + Channel]")
	benchChannelTasks()
	benchTaskCreation()
	benchGoroutineSpawn()
	benchChannelPingPong()
	benchTimers()

	fmt.Println()
}

// benchChannelTasks benchmarks channel task throughput (single-threaded)
func benchChannelTasks() {
	ch := make(chan func(), ITERATIONS)

	counter := 0

	// Warmup
	for i := 0; i < WARMUP; i++ {
		ch <- func() { counter++ }
	}
	for i := 0; i < WARMUP; i++ {
		(<-ch)()
	}
	counter = 0

	// Benchmark
	start := time.Now()

	// Send all tasks
	for i := 0; i < ITERATIONS; i++ {
		ch <- func() { counter++ }
	}

	// Process all tasks
	for i := 0; i < ITERATIONS; i++ {
		(<-ch)()
	}

	elapsed := time.Since(start)
	elapsedMs := float64(elapsed.Nanoseconds()) / 1_000_000.0
	tasksPerSec := float64(ITERATIONS) / elapsed.Seconds()

	fmt.Printf("Channel task throughput:    %.2f M tasks/sec (%.0fms, %d tasks)\n",
		tasksPerSec/1_000_000.0, elapsedMs, counter)
}

// benchTaskCreation benchmarks closure creation overhead
func benchTaskCreation() {
	dummy := 0

	// Warmup
	for i := 0; i < WARMUP; i++ {
		task := func() { dummy++ }
		_ = task
	}

	start := time.Now()

	for i := 0; i < ITERATIONS; i++ {
		task := func() { dummy++ }
		_ = task
	}

	elapsed := time.Since(start)
	nsPerOp := float64(elapsed.Nanoseconds()) / float64(ITERATIONS)

	fmt.Printf("Task creation overhead:     %.1f ns/task\n", nsPerOp)
}

// benchGoroutineSpawn benchmarks goroutine spawn throughput
func benchGoroutineSpawn() {
	spawnCount := 100_000

	var wg sync.WaitGroup
	wg.Add(spawnCount)

	start := time.Now()

	for i := 0; i < spawnCount; i++ {
		go func() {
			wg.Done()
		}()
	}

	wg.Wait()

	elapsed := time.Since(start)
	elapsedMs := float64(elapsed.Nanoseconds()) / 1_000_000.0
	spawnsPerSec := float64(spawnCount) / elapsed.Seconds()

	fmt.Printf("Goroutine spawn throughput: %.2f M goroutines/sec (%.1fms, %d spawns)\n",
		spawnsPerSec/1_000_000.0, elapsedMs, spawnCount)
}

// benchChannelPingPong benchmarks channel context switch (ping-pong)
func benchChannelPingPong() {
	cycles := 100_000
	ch1 := make(chan int, 1)
	ch2 := make(chan int, 1)

	go func() {
		for i := 0; i < cycles; i++ {
			val := <-ch1
			ch2 <- val + 1
		}
	}()

	start := time.Now()

	for i := 0; i < cycles; i++ {
		ch1 <- i
		<-ch2
	}

	elapsed := time.Since(start)
	elapsedMs := float64(elapsed.Nanoseconds()) / 1_000_000.0
	cyclesPerSec := float64(cycles) / elapsed.Seconds()

	fmt.Printf("Channel ping-pong:          %.2f M cycles/sec (%.1fms, %d cycles)\n",
		cyclesPerSec/1_000_000.0, elapsedMs, cycles)
}

// benchTimers benchmarks timer creation and firing
func benchTimers() {
	timerCount := 100_000

	var wg sync.WaitGroup
	wg.Add(timerCount)

	start := time.Now()

	for i := 0; i < timerCount; i++ {
		time.AfterFunc(time.Nanosecond, func() {
			wg.Done()
		})
	}

	wg.Wait()

	elapsed := time.Since(start)
	elapsedMs := float64(elapsed.Nanoseconds()) / 1_000_000.0
	timersPerSec := float64(timerCount) / elapsed.Seconds()

	fmt.Printf("Timer throughput:           %.2f M timers/sec (%.1fms, %d timers)\n",
		timersPerSec/1_000_000.0, elapsedMs, timerCount)
}
