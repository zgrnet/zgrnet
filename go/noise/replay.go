package noise

import (
	"sync"
)

const (
	// ReplayWindowSize is the size of the sliding window in bits.
	// This allows for packets arriving out of order within this window.
	ReplayWindowSize = 2048

	// replayWindowWords is the number of uint64 words needed for the bitmap.
	replayWindowWords = ReplayWindowSize / 64
)

// ReplayFilter implements a sliding window algorithm for replay protection.
// It tracks received nonces and rejects duplicates or nonces that are too old.
//
// The filter maintains a bitmap of size ReplayWindowSize bits, where each bit
// represents whether a particular nonce has been seen. The window slides
// forward as higher nonces are received.
type ReplayFilter struct {
	mu       sync.Mutex
	bitmap   [replayWindowWords]uint64
	maxNonce uint64
}

// NewReplayFilter creates a new replay filter.
func NewReplayFilter() *ReplayFilter {
	return &ReplayFilter{}
}

// Check tests whether a nonce is valid (not a replay).
// Returns true if the nonce is valid and should be accepted.
// Returns false if the nonce is a replay or too old.
//
// This method does NOT update the filter state. Call Update() after
// successfully processing the packet.
func (rf *ReplayFilter) Check(nonce uint64) bool {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	return rf.checkLocked(nonce)
}

// checkLocked performs the check without acquiring the lock.
func (rf *ReplayFilter) checkLocked(nonce uint64) bool {
	// If this is the first nonce or a new high watermark, always accept
	if nonce > rf.maxNonce {
		return true
	}

	// Calculate how far back this nonce is from the current max
	delta := rf.maxNonce - nonce

	// If the nonce is too old (outside the window), reject
	if delta >= ReplayWindowSize {
		return false
	}

	// Check if this nonce has already been seen in the bitmap
	wordIndex := delta / 64
	bitIndex := delta % 64
	return rf.bitmap[wordIndex]&(1<<bitIndex) == 0
}

// Update marks a nonce as received.
// This should be called after a packet has been successfully authenticated.
//
// The nonce must have passed Check() first. Calling Update() with an
// invalid nonce may corrupt the filter state.
func (rf *ReplayFilter) Update(nonce uint64) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	rf.updateLocked(nonce)
}

// updateLocked performs the update without acquiring the lock.
func (rf *ReplayFilter) updateLocked(nonce uint64) {
	if nonce > rf.maxNonce {
		// Slide the window forward
		shift := nonce - rf.maxNonce
		rf.slideWindow(shift)
		rf.maxNonce = nonce
		// Mark the new nonce as seen (it's now at position 0)
		rf.bitmap[0] |= 1
	} else {
		// Mark an older nonce as seen within the window
		delta := rf.maxNonce - nonce
		if delta < ReplayWindowSize {
			wordIndex := delta / 64
			bitIndex := delta % 64
			rf.bitmap[wordIndex] |= 1 << bitIndex
		}
	}
}

// CheckAndUpdate atomically checks and updates the filter.
// Returns true if the nonce is valid and was recorded.
// Returns false if the nonce is a replay or too old.
//
// This is the recommended method for most use cases as it prevents
// race conditions between Check() and Update().
func (rf *ReplayFilter) CheckAndUpdate(nonce uint64) bool {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	if !rf.checkLocked(nonce) {
		return false
	}
	rf.updateLocked(nonce)
	return true
}

// slideWindow shifts the bitmap by the given number of positions.
// When maxNonce increases, older nonces move to higher bit positions (higher indices).
// bit 0 always represents maxNonce, bit n represents maxNonce - n.
func (rf *ReplayFilter) slideWindow(shift uint64) {
	if shift >= ReplayWindowSize {
		// Clear the entire bitmap
		for i := range rf.bitmap {
			rf.bitmap[i] = 0
		}
		return
	}

	// Calculate word and bit shifts
	wordShift := shift / 64
	bitShift := shift % 64

	// First handle word shifts (move entire words to higher indices)
	if wordShift > 0 {
		for i := replayWindowWords - 1; i >= int(wordShift); i-- {
			rf.bitmap[i] = rf.bitmap[i-int(wordShift)]
		}
		for i := 0; i < int(wordShift); i++ {
			rf.bitmap[i] = 0
		}
	}

	// Then handle bit shifts within words (shift left, carry to next word)
	if bitShift > 0 {
		var carry uint64
		for i := 0; i < replayWindowWords; i++ {
			newCarry := rf.bitmap[i] >> (64 - bitShift)
			rf.bitmap[i] = (rf.bitmap[i] << bitShift) | carry
			carry = newCarry
		}
	}
}

// Reset clears the replay filter state.
func (rf *ReplayFilter) Reset() {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	for i := range rf.bitmap {
		rf.bitmap[i] = 0
	}
	rf.maxNonce = 0
}

// MaxNonce returns the highest nonce seen so far.
func (rf *ReplayFilter) MaxNonce() uint64 {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	return rf.maxNonce
}
