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
}
