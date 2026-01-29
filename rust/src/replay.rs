//! Replay protection using sliding window.

use std::sync::Mutex;

/// Size of the sliding window in bits.
pub const REPLAY_WINDOW_SIZE: usize = 2048;

/// Number of u64 words needed for the bitmap.
const REPLAY_WINDOW_WORDS: usize = REPLAY_WINDOW_SIZE / 64;

/// Replay filter using sliding window algorithm.
///
/// Tracks received nonces and rejects duplicates or nonces that are too old.
pub struct ReplayFilter {
    inner: Mutex<ReplayFilterInner>,
}

struct ReplayFilterInner {
    bitmap: [u64; REPLAY_WINDOW_WORDS],
    max_nonce: u64,
}

impl ReplayFilter {
    /// Creates a new replay filter.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ReplayFilterInner {
                bitmap: [0; REPLAY_WINDOW_WORDS],
                max_nonce: 0,
            }),
        }
    }

    /// Checks if a nonce is valid (not a replay).
    /// Returns true if valid, false if replay.
    pub fn check(&self, nonce: u64) -> bool {
        let inner = self.inner.lock().unwrap();
        Self::check_inner(&inner, nonce)
    }

    fn check_inner(inner: &ReplayFilterInner, nonce: u64) -> bool {
        if nonce > inner.max_nonce {
            return true;
        }

        let delta = inner.max_nonce - nonce;
        if delta >= REPLAY_WINDOW_SIZE as u64 {
            return false;
        }

        let word_index = (delta / 64) as usize;
        let bit_index = delta % 64;
        (inner.bitmap[word_index] & (1 << bit_index)) == 0
    }

    /// Updates the filter with a nonce.
    pub fn update(&self, nonce: u64) {
        let mut inner = self.inner.lock().unwrap();
        Self::update_inner(&mut inner, nonce);
    }

    fn update_inner(inner: &mut ReplayFilterInner, nonce: u64) {
        if nonce > inner.max_nonce {
            let shift = nonce - inner.max_nonce;
            Self::slide_window(inner, shift);
            inner.max_nonce = nonce;
            inner.bitmap[0] |= 1;
        } else {
            let delta = inner.max_nonce - nonce;
            if delta < REPLAY_WINDOW_SIZE as u64 {
                let word_index = (delta / 64) as usize;
                let bit_index = delta % 64;
                inner.bitmap[word_index] |= 1 << bit_index;
            }
        }
    }

    /// Atomically checks and updates.
    /// Returns true if nonce is valid and was recorded.
    pub fn check_and_update(&self, nonce: u64) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if !Self::check_inner(&inner, nonce) {
            return false;
        }
        Self::update_inner(&mut inner, nonce);
        true
    }

    fn slide_window(inner: &mut ReplayFilterInner, shift: u64) {
        if shift >= REPLAY_WINDOW_SIZE as u64 {
            inner.bitmap = [0; REPLAY_WINDOW_WORDS];
            return;
        }

        let word_shift = (shift / 64) as usize;
        let bit_shift = (shift % 64) as u32;

        // First handle word shifts using copy_within for efficiency
        if word_shift > 0 {
            inner.bitmap.copy_within(..REPLAY_WINDOW_WORDS - word_shift, word_shift);
            inner.bitmap[..word_shift].fill(0);
        }

        // Then handle bit shifts
        if bit_shift > 0 {
            let mut carry: u64 = 0;
            for i in 0..REPLAY_WINDOW_WORDS {
                let new_carry = inner.bitmap[i] >> (64 - bit_shift);
                inner.bitmap[i] = (inner.bitmap[i] << bit_shift) | carry;
                carry = new_carry;
            }
        }
    }

    /// Resets the filter.
    pub fn reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.bitmap = [0; REPLAY_WINDOW_WORDS];
        inner.max_nonce = 0;
    }

    /// Returns the highest nonce seen.
    pub fn max_nonce(&self) -> u64 {
        self.inner.lock().unwrap().max_nonce
    }
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequential() {
        let rf = ReplayFilter::new();
        for i in 0..100 {
            assert!(rf.check_and_update(i), "nonce {} should be accepted", i);
        }
    }

    #[test]
    fn test_duplicate() {
        let rf = ReplayFilter::new();
        assert!(rf.check_and_update(42));
        assert!(!rf.check_and_update(42), "duplicate should be rejected");
    }

    #[test]
    fn test_out_of_order() {
        let rf = ReplayFilter::new();
        let nonces = [100u64, 50, 75, 25, 99, 1];
        
        for n in nonces {
            assert!(rf.check_and_update(n), "nonce {} should be accepted", n);
        }
        
        for n in nonces {
            assert!(!rf.check_and_update(n), "nonce {} should be rejected", n);
        }
    }

    #[test]
    fn test_window_boundary() {
        let rf = ReplayFilter::new();
        
        assert!(rf.check_and_update(REPLAY_WINDOW_SIZE as u64 + 100));
        
        // Just within window
        assert!(rf.check_and_update(101));
        
        // Outside window
        assert!(!rf.check_and_update(100));
    }

    #[test]
    fn test_too_old() {
        let rf = ReplayFilter::new();
        assert!(rf.check_and_update(5000));
        
        // Outside window (5000 - 2047 = 2953)
        for n in [0u64, 1, 100, 2952] {
            assert!(!rf.check_and_update(n), "nonce {} should be rejected", n);
        }
        
        // Within window
        for n in [2953u64, 3000, 4000, 4999] {
            assert!(rf.check_and_update(n), "nonce {} should be accepted", n);
        }
    }

    #[test]
    fn test_large_jump() {
        let rf = ReplayFilter::new();
        
        for i in 0..10 {
            rf.check_and_update(i);
        }
        
        assert!(rf.check_and_update(10000));
        
        for i in 0..10 {
            assert!(!rf.check_and_update(i), "nonce {} should be rejected", i);
        }
    }

    #[test]
    fn test_max_nonce() {
        let rf = ReplayFilter::new();
        assert_eq!(rf.max_nonce(), 0);
        
        rf.check_and_update(100);
        assert_eq!(rf.max_nonce(), 100);
        
        rf.check_and_update(50);
        assert_eq!(rf.max_nonce(), 100);
        
        rf.check_and_update(200);
        assert_eq!(rf.max_nonce(), 200);
    }

    #[test]
    fn test_reset() {
        let rf = ReplayFilter::new();
        
        for i in 0..100 {
            rf.check_and_update(i);
        }
        
        rf.reset();
        
        for i in 0..100 {
            assert!(rf.check_and_update(i), "nonce {} should be accepted after reset", i);
        }
    }

    #[test]
    fn test_check_without_update() {
        let rf = ReplayFilter::new();
        
        assert!(rf.check(100));
        assert!(rf.check(100)); // Still true, not updated
        
        rf.update(100);
        assert!(!rf.check(100)); // Now false
    }

    #[test]
    fn test_bit_boundaries() {
        let rf = ReplayFilter::new();
        
        let boundaries = [63u64, 64, 65, 127, 128, 129, 2047];
        for n in boundaries {
            assert!(rf.check_and_update(n), "nonce {} should be accepted", n);
        }
        
        for n in boundaries {
            assert!(!rf.check_and_update(n), "nonce {} should be rejected", n);
        }
    }
}
