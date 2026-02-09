//! DTLS flight retransmission timer (RFC 6347 §4.2.4).
//!
//! Implements exponential backoff: 1s → 2s → 4s → ... → 60s max.
//! A flight is a group of handshake messages retransmitted together.

use std::time::{Duration, Instant};

/// Default initial timeout (1 second).
const INITIAL_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum timeout (60 seconds).
const MAX_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of retransmissions before giving up.
const MAX_RETRANSMISSIONS: u32 = 12;

/// DTLS flight retransmission timer.
pub struct RetransmitTimer {
    initial_timeout: Duration,
    max_timeout: Duration,
    current_timeout: Duration,
    deadline: Option<Instant>,
    retransmit_count: u32,
}

impl RetransmitTimer {
    pub fn new() -> Self {
        Self {
            initial_timeout: INITIAL_TIMEOUT,
            max_timeout: MAX_TIMEOUT,
            current_timeout: INITIAL_TIMEOUT,
            deadline: None,
            retransmit_count: 0,
        }
    }

    /// Record that we just sent a flight. Starts the timer.
    pub fn start(&mut self) {
        self.deadline = Some(Instant::now() + self.current_timeout);
    }

    /// Check if a retransmission is due.
    pub fn is_expired(&self) -> bool {
        match self.deadline {
            Some(d) => Instant::now() >= d,
            None => false,
        }
    }

    /// Advance to the next timeout (exponential backoff).
    /// Called after retransmitting.
    pub fn backoff(&mut self) {
        self.retransmit_count += 1;
        self.current_timeout = std::cmp::min(self.current_timeout * 2, self.max_timeout);
        self.deadline = Some(Instant::now() + self.current_timeout);
    }

    /// Reset the timer (when the expected flight is received).
    pub fn reset(&mut self) {
        self.current_timeout = self.initial_timeout;
        self.deadline = None;
        self.retransmit_count = 0;
    }

    /// Get the current timeout duration (for use with socket timeouts).
    pub fn timeout(&self) -> Duration {
        self.current_timeout
    }

    /// Get the number of retransmissions performed.
    pub fn retransmit_count(&self) -> u32 {
        self.retransmit_count
    }

    /// Check if the maximum number of retransmissions has been reached.
    pub fn is_exhausted(&self) -> bool {
        self.retransmit_count >= MAX_RETRANSMISSIONS
    }
}

impl Default for RetransmitTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// A stored flight (group of serialized DTLS records to retransmit together).
#[derive(Debug, Clone)]
pub struct Flight {
    /// The serialized DTLS records for this flight.
    pub records: Vec<Vec<u8>>,
}

impl Flight {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn push(&mut self, record: Vec<u8>) {
        self.records.push(record);
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn clear(&mut self) {
        self.records.clear();
    }
}

impl Default for Flight {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retransmit_timer_exponential_backoff() {
        let mut timer = RetransmitTimer::new();
        assert_eq!(timer.timeout(), Duration::from_secs(1));

        timer.backoff();
        assert_eq!(timer.timeout(), Duration::from_secs(2));
        assert_eq!(timer.retransmit_count(), 1);

        timer.backoff();
        assert_eq!(timer.timeout(), Duration::from_secs(4));

        timer.backoff();
        assert_eq!(timer.timeout(), Duration::from_secs(8));

        timer.backoff();
        assert_eq!(timer.timeout(), Duration::from_secs(16));

        timer.backoff();
        assert_eq!(timer.timeout(), Duration::from_secs(32));

        timer.backoff();
        // 64 > max(60), capped at 60
        assert_eq!(timer.timeout(), Duration::from_secs(60));

        timer.backoff();
        // Still capped at 60
        assert_eq!(timer.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn test_retransmit_timer_reset() {
        let mut timer = RetransmitTimer::new();
        timer.backoff();
        timer.backoff();
        assert_eq!(timer.timeout(), Duration::from_secs(4));
        assert_eq!(timer.retransmit_count(), 2);

        timer.reset();
        assert_eq!(timer.timeout(), Duration::from_secs(1));
        assert_eq!(timer.retransmit_count(), 0);
        assert!(!timer.is_expired());
    }
}
