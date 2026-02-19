// Relay throughput benchmark — direct vs single-hop relay.
//
// Measures KCP stream throughput in KB/s for:
// 1. Direct connection (A ↔ D)
// 2. Single-hop relay (A → C → D)
//
// Run:  bazel test //e2e/benchmark/relay:relay_bench_test --test_arg=-test.bench=. --test_arg=-test.benchtime=3s
package relay_bench_test

import (
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/vibing/zgrnet/pkg/node"
	"github.com/vibing/zgrnet/pkg/noise"
)

func genKey(t testing.TB) *noise.KeyPair {
	t.Helper()
	var key noise.Key
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		t.Fatal(err)
	}
	kp, err := noise.NewKeyPair(key)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func readTimeout(s *node.Stream, buf []byte, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, err := s.Read(buf)
		if err != nil {
			return 0, err
		}
		if n > 0 {
			return n, nil
		}
		time.Sleep(time.Millisecond)
	}
	return 0, io.ErrNoProgress
}

type testNode struct {
	*node.Node
	key *noise.KeyPair
}

func newNode(t testing.TB) *testNode {
	t.Helper()
	kp := genKey(t)
	n, err := node.New(node.Config{PrivateKey: kp, ListenPort: 0, AllowUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	return &testNode{Node: n, key: kp}
}

func connectDirect(t testing.TB, a, b *testNode) {
	t.Helper()
	a.AddPeer(node.PeerConfig{PublicKey: b.key.Public, Endpoint: b.LocalAddr().String()})
	b.AddPeer(node.PeerConfig{PublicKey: a.key.Public, Endpoint: a.LocalAddr().String()})
	if err := a.Connect(b.key.Public); err != nil {
		t.Fatalf("connect: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
}

// measureThroughput sends totalBytes from opener to accepter and returns KB/s.
func measureThroughput(b *testing.B, opener *node.Stream, accepter *node.Stream, chunkSize int) float64 {
	b.Helper()

	chunk := make([]byte, chunkSize)
	rand.Read(chunk)
	buf := make([]byte, chunkSize*2)

	totalBytes := 0
	start := time.Now()

	// Send and receive in a tight loop
	done := make(chan int64)
	go func() {
		var received int64
		for received < int64(b.N)*int64(chunkSize) {
			n, err := readTimeout(accepter, buf, 10*time.Second)
			if err != nil {
				break
			}
			received += int64(n)
		}
		done <- received
	}()

	for i := 0; i < b.N; i++ {
		if _, err := opener.Write(chunk); err != nil {
			b.Fatalf("write: %v", err)
		}
		totalBytes += chunkSize
	}

	received := <-done
	elapsed := time.Since(start)

	kbps := float64(received) / 1024.0 / elapsed.Seconds()
	return kbps
}

func BenchmarkDirectThroughput(b *testing.B) {
	a := newNode(b)
	defer a.Stop()
	d := newNode(b)
	defer d.Stop()

	connectDirect(b, a, d)

	stream, err := a.Dial(d.key.Public, 8080)
	if err != nil {
		b.Fatal(err)
	}
	defer stream.Close()

	accepted, err := d.AcceptStream()
	if err != nil {
		b.Fatal(err)
	}
	defer accepted.Close()

	b.ResetTimer()
	kbps := measureThroughput(b, stream, accepted, 1024)
	b.ReportMetric(kbps, "KB/s")
}

func BenchmarkSingleHopRelayThroughput(b *testing.B) {
	a := newNode(b)
	defer a.Stop()
	c := newNode(b)
	defer c.Stop()
	d := newNode(b)
	defer d.Stop()

	connectDirect(b, a, c)
	connectDirect(b, c, d)
	d.AddPeer(node.PeerConfig{PublicKey: a.key.Public})

	stream, err := a.DialRelay(d.key.Public, c.key.Public, 8080)
	if err != nil {
		b.Fatal(err)
	}
	defer stream.Close()

	accepted, err := d.AcceptStream()
	if err != nil {
		b.Fatal(err)
	}
	defer accepted.Close()

	b.ResetTimer()
	kbps := measureThroughput(b, stream, accepted, 1024)
	b.ReportMetric(kbps, "KB/s")
}

func BenchmarkRelayOverhead(b *testing.B) {
	for _, chunkSize := range []int{64, 1024, 8192} {
		b.Run(fmt.Sprintf("chunk_%dB", chunkSize), func(b *testing.B) {
			a := newNode(b)
			defer a.Stop()
			c := newNode(b)
			defer c.Stop()
			d := newNode(b)
			defer d.Stop()

			connectDirect(b, a, c)
			connectDirect(b, c, d)
			d.AddPeer(node.PeerConfig{PublicKey: a.key.Public})

			stream, err := a.DialRelay(d.key.Public, c.key.Public, 8080)
			if err != nil {
				b.Fatal(err)
			}
			defer stream.Close()

			accepted, err := d.AcceptStream()
			if err != nil {
				b.Fatal(err)
			}
			defer accepted.Close()

			b.ResetTimer()
			kbps := measureThroughput(b, stream, accepted, chunkSize)
			b.ReportMetric(kbps, "KB/s")
		})
	}
}
