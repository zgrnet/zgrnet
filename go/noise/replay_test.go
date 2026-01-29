package noise

import (
	"sync"
	"testing"
)

func TestReplayFilter_Sequential(t *testing.T) {
	rf := NewReplayFilter()

	// Sequential nonces should all be accepted
	for i := uint64(0); i < 100; i++ {
		if !rf.CheckAndUpdate(i) {
			t.Errorf("nonce %d should be accepted", i)
		}
	}
}

func TestReplayFilter_Duplicate(t *testing.T) {
	rf := NewReplayFilter()

	// First time should succeed
	if !rf.CheckAndUpdate(42) {
		t.Error("first nonce 42 should be accepted")
	}

	// Second time should fail (duplicate)
	if rf.CheckAndUpdate(42) {
		t.Error("duplicate nonce 42 should be rejected")
	}
}

func TestReplayFilter_OutOfOrder(t *testing.T) {
	rf := NewReplayFilter()

	// Accept some nonces out of order within the window
	nonces := []uint64{100, 50, 75, 25, 99, 1}
	for _, n := range nonces {
		if !rf.CheckAndUpdate(n) {
			t.Errorf("nonce %d should be accepted (first time)", n)
		}
	}

	// All should be rejected now
	for _, n := range nonces {
		if rf.CheckAndUpdate(n) {
			t.Errorf("nonce %d should be rejected (duplicate)", n)
		}
	}
}

func TestReplayFilter_WindowBoundary(t *testing.T) {
	rf := NewReplayFilter()

	// Accept nonce at the high end
	if !rf.CheckAndUpdate(ReplayWindowSize + 100) {
		t.Error("high nonce should be accepted")
	}

	// Nonce just within window should be accepted
	withinWindow := uint64(101) // ReplayWindowSize + 100 - (ReplayWindowSize - 1) = 101
	if !rf.CheckAndUpdate(withinWindow) {
		t.Errorf("nonce %d should be within window", withinWindow)
	}

	// Nonce outside window should be rejected
	outsideWindow := uint64(100) // Just outside the window
	if rf.CheckAndUpdate(outsideWindow) {
		t.Errorf("nonce %d should be outside window", outsideWindow)
	}
}

func TestReplayFilter_TooOld(t *testing.T) {
	rf := NewReplayFilter()

	// Set a high max nonce
	if !rf.CheckAndUpdate(5000) {
		t.Error("nonce 5000 should be accepted")
	}

	// Window covers [5000 - 2047, 5000] = [2953, 5000]
	// Old nonces outside window should be rejected
	for _, n := range []uint64{0, 1, 100, 2952} { // 2952 is just outside the window
		if rf.CheckAndUpdate(n) {
			t.Errorf("old nonce %d should be rejected", n)
		}
	}

	// Nonces within window should still be accepted
	for _, n := range []uint64{2953, 3000, 4000, 4999} {
		if !rf.CheckAndUpdate(n) {
			t.Errorf("nonce %d should be within window", n)
		}
	}
}

func TestReplayFilter_LargeJump(t *testing.T) {
	rf := NewReplayFilter()

	// Start with some nonces
	for i := uint64(0); i < 10; i++ {
		rf.CheckAndUpdate(i)
	}

	// Jump far ahead (beyond window size)
	if !rf.CheckAndUpdate(10000) {
		t.Error("large jump nonce should be accepted")
	}

	// Old nonces should be rejected
	for i := uint64(0); i < 10; i++ {
		if rf.CheckAndUpdate(i) {
			t.Errorf("old nonce %d should be rejected after large jump", i)
		}
	}
}

func TestReplayFilter_MaxNonce(t *testing.T) {
	rf := NewReplayFilter()

	if rf.MaxNonce() != 0 {
		t.Error("initial max nonce should be 0")
	}

	rf.CheckAndUpdate(100)
	if rf.MaxNonce() != 100 {
		t.Errorf("max nonce should be 100, got %d", rf.MaxNonce())
	}

	rf.CheckAndUpdate(50)
	if rf.MaxNonce() != 100 {
		t.Errorf("max nonce should still be 100, got %d", rf.MaxNonce())
	}

	rf.CheckAndUpdate(200)
	if rf.MaxNonce() != 200 {
		t.Errorf("max nonce should be 200, got %d", rf.MaxNonce())
	}
}

func TestReplayFilter_Reset(t *testing.T) {
	rf := NewReplayFilter()

	// Add some nonces
	for i := uint64(0); i < 100; i++ {
		rf.CheckAndUpdate(i)
	}

	// Reset
	rf.Reset()

	// Should accept all again
	for i := uint64(0); i < 100; i++ {
		if !rf.CheckAndUpdate(i) {
			t.Errorf("nonce %d should be accepted after reset", i)
		}
	}
}

func TestReplayFilter_CheckWithoutUpdate(t *testing.T) {
	rf := NewReplayFilter()

	// Check should not update state
	if !rf.Check(100) {
		t.Error("check should return true for new nonce")
	}
	if !rf.Check(100) {
		t.Error("check should still return true (not updated)")
	}

	// Now update
	rf.Update(100)

	// Check should return false now
	if rf.Check(100) {
		t.Error("check should return false after update")
	}
}

func TestReplayFilter_Concurrent(t *testing.T) {
	rf := NewReplayFilter()
	var wg sync.WaitGroup

	// Run multiple goroutines trying to add the same nonces
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := uint64(0); n < 1000; n++ {
				rf.CheckAndUpdate(n)
			}
		}()
	}

	wg.Wait()

	// All nonces should have been recorded
	for n := uint64(0); n < 1000; n++ {
		if rf.Check(n) {
			t.Errorf("nonce %d should be recorded after concurrent access", n)
		}
	}
}

func TestReplayFilter_BitBoundaries(t *testing.T) {
	rf := NewReplayFilter()

	// Test at 64-bit boundaries
	boundaries := []uint64{63, 64, 65, 127, 128, 129, 2047}
	for _, n := range boundaries {
		if !rf.CheckAndUpdate(n) {
			t.Errorf("nonce %d at boundary should be accepted", n)
		}
	}

	// Verify they were recorded
	for _, n := range boundaries {
		if rf.CheckAndUpdate(n) {
			t.Errorf("nonce %d should be rejected as duplicate", n)
		}
	}
}

func BenchmarkReplayFilter_CheckAndUpdate(b *testing.B) {
	rf := NewReplayFilter()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rf.CheckAndUpdate(uint64(i))
	}
}

func BenchmarkReplayFilter_CheckAndUpdate_OutOfOrder(b *testing.B) {
	rf := NewReplayFilter()
	// Pre-populate with high nonce
	rf.CheckAndUpdate(uint64(b.N) + 1000)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rf.CheckAndUpdate(uint64(i % 1000))
	}
}
