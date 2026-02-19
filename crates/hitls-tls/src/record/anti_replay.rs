//! DTLS anti-replay sliding window (RFC 6347 §4.1.2.6).
//!
//! Uses a 64-bit bitmap to track received sequence numbers.
//! Records with sequence numbers older than `max_seq - WINDOW_SIZE`
//! are rejected. Duplicate records are also rejected.

use hitls_types::TlsError;

/// Window size (number of sequence numbers tracked).
const WINDOW_SIZE: u64 = 64;

/// Sliding window anti-replay protection.
///
/// Call `check()` before decryption to reject obvious replays/old records.
/// Call `accept()` after successful decryption to update the window.
pub struct AntiReplayWindow {
    bitmap: u64,
    max_seq: u64,
    initialized: bool,
}

impl AntiReplayWindow {
    pub fn new() -> Self {
        Self {
            bitmap: 0,
            max_seq: 0,
            initialized: false,
        }
    }

    /// Check whether a record with this sequence number should be accepted.
    ///
    /// Returns `true` if acceptable (not a replay, not too old).
    /// Does NOT update the window — call `accept()` after successful decryption.
    pub fn check(&self, seq: u64) -> bool {
        if !self.initialized {
            return true;
        }

        if seq > self.max_seq {
            // New record ahead of the window — always accept
            return true;
        }

        if self.max_seq >= WINDOW_SIZE && seq < self.max_seq - WINDOW_SIZE + 1 {
            // Too old — outside the window
            return false;
        }

        // Check the bitmap for duplicates
        let index = self.max_seq - seq;
        if self.bitmap & (1u64 << index) != 0 {
            // Already received
            return false;
        }

        true
    }

    /// Mark a sequence number as received. Call after successful decryption.
    pub fn accept(&mut self, seq: u64) {
        if !self.initialized {
            self.max_seq = seq;
            self.bitmap = 1; // bit 0 = current max_seq
            self.initialized = true;
            return;
        }

        if seq > self.max_seq {
            let shift = seq - self.max_seq;
            if shift >= WINDOW_SIZE {
                self.bitmap = 1;
            } else {
                self.bitmap <<= shift;
                self.bitmap |= 1;
            }
            self.max_seq = seq;
        } else {
            let index = self.max_seq - seq;
            if index < WINDOW_SIZE {
                self.bitmap |= 1u64 << index;
            }
        }
    }

    /// Reset the window (on epoch change).
    pub fn reset(&mut self) {
        self.bitmap = 0;
        self.max_seq = 0;
        self.initialized = false;
    }

    /// Check and accept in one step. Returns error if replay detected.
    pub fn check_and_accept(&mut self, seq: u64) -> Result<(), TlsError> {
        if !self.check(seq) {
            return Err(TlsError::RecordError("DTLS replay detected".into()));
        }
        self.accept(seq);
        Ok(())
    }
}

impl Default for AntiReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_replay_accept_sequential() {
        let mut w = AntiReplayWindow::new();
        for i in 0..10 {
            assert!(w.check(i));
            w.accept(i);
        }
        assert_eq!(w.max_seq, 9);
    }

    #[test]
    fn test_anti_replay_reject_duplicate() {
        let mut w = AntiReplayWindow::new();
        w.accept(0);
        w.accept(1);
        w.accept(2);
        // Duplicate seq=1
        assert!(!w.check(1));
        // Duplicate seq=0
        assert!(!w.check(0));
        // New seq=3 is fine
        assert!(w.check(3));
    }

    #[test]
    fn test_anti_replay_accept_out_of_order() {
        let mut w = AntiReplayWindow::new();
        w.accept(0);
        w.accept(5); // jump ahead
                     // seq=3 is within window and not seen
        assert!(w.check(3));
        w.accept(3);
        // seq=1 also within window and not seen
        assert!(w.check(1));
        w.accept(1);
        // seq=3 now seen
        assert!(!w.check(3));
    }

    #[test]
    fn test_anti_replay_reject_too_old() {
        let mut w = AntiReplayWindow::new();
        // Accept seq 0..100
        for i in 0..100 {
            w.accept(i);
        }
        // max_seq = 99, window covers 99 - 63 = 36 .. 99
        // seq=35 is too old
        assert!(!w.check(35));
        // seq=36 was already seen (it's within window)
        assert!(!w.check(36));
        // seq=100 is new
        assert!(w.check(100));
    }

    #[test]
    fn test_anti_replay_reset() {
        let mut w = AntiReplayWindow::new();
        w.accept(0);
        w.accept(1);
        w.accept(2);
        w.reset();
        // After reset, all seqs are accepted again
        assert!(w.check(0));
        assert!(w.check(1));
        assert!(w.check(2));
    }

    #[test]
    fn test_anti_replay_window_boundary_exact() {
        let mut w = AntiReplayWindow::new();
        // Accept 0..64
        for i in 0..64 {
            w.accept(i);
        }
        // max_seq = 63, window covers 0..63
        // seq=0 is at exact edge (index = 63), should be seen → reject
        assert!(!w.check(0));
        // seq=63 was seen → reject
        assert!(!w.check(63));
        // seq=64 is new → accept
        assert!(w.check(64));

        // Now accept 64, window shifts: covers 1..64
        w.accept(64);
        // seq=0 is now too old (outside window)
        assert!(!w.check(0));
        // seq=1 was seen and is at edge → reject
        assert!(!w.check(1));
    }

    #[test]
    fn test_anti_replay_large_forward_jump() {
        let mut w = AntiReplayWindow::new();
        w.accept(0);
        // Jump ahead by 10000
        w.accept(10000);
        // seq=0 is now far too old
        assert!(!w.check(0));
        // seq=9937 = 10000 - 63 = at the edge of the window, but never seen → accept
        assert!(w.check(9937));
        // seq=9936 is too old (outside window)
        assert!(!w.check(9936));
        // seq=9999 is within window and not seen → accept
        assert!(w.check(9999));
    }

    #[test]
    fn test_anti_replay_check_and_accept_combined() {
        let mut w = AntiReplayWindow::new();
        // First call should succeed
        assert!(w.check_and_accept(0).is_ok());
        // Second call with same seq should fail (replay)
        assert!(w.check_and_accept(0).is_err());
        // New seq should succeed
        assert!(w.check_and_accept(1).is_ok());
        // Replay of 1 should fail
        assert!(w.check_and_accept(1).is_err());
    }

    #[test]
    fn test_anti_replay_default_impl_equivalent() {
        let w1 = AntiReplayWindow::new();
        let w2 = AntiReplayWindow::default();
        // Both should accept seq=0
        assert!(w1.check(0));
        assert!(w2.check(0));
    }

    #[test]
    fn test_anti_replay_check_and_accept_error_message() {
        let mut w = AntiReplayWindow::new();
        w.accept(5);
        let err = w.check_and_accept(5).unwrap_err();
        assert!(
            err.to_string().contains("replay"),
            "Error should mention 'replay': {}",
            err
        );
    }

    #[test]
    fn test_anti_replay_sliding_window_after_gap() {
        let mut w = AntiReplayWindow::new();
        // Accept 0, then jump to 100
        w.accept(0);
        w.accept(100);
        // Window now covers 37..100 (100-63=37)
        // seq=37 was never seen → should accept
        assert!(w.check(37));
        // seq=36 is too old → should reject
        assert!(!w.check(36));
        // seq=50 never seen → should accept
        assert!(w.check(50));
        w.accept(50);
        // seq=50 now seen → should reject
        assert!(!w.check(50));
    }

    #[test]
    fn test_anti_replay_interleaved_check_and_accept() {
        let mut w = AntiReplayWindow::new();
        // Interleaved sequence: 0, 3, 1, 4, 2
        assert!(w.check_and_accept(0).is_ok());
        assert!(w.check_and_accept(3).is_ok());
        assert!(w.check_and_accept(1).is_ok());
        assert!(w.check_and_accept(4).is_ok());
        assert!(w.check_and_accept(2).is_ok());
        // All should now be rejected
        for i in 0..5 {
            assert!(w.check_and_accept(i).is_err());
        }
        // Next new seq should succeed
        assert!(w.check_and_accept(5).is_ok());
    }
}
