//! Entropy health tests per NIST SP 800-90B §4.4.
//!
//! Provides two continuous health tests for noise sources:
//! - **Repetition Count Test (RCT)** — detects stuck noise sources
//! - **Adaptive Proportion Test (APT)** — detects biased noise sources

use hitls_types::CryptoError;

/// Repetition Count Test (NIST SP 800-90B §4.4.1).
///
/// Detects when a noise source produces the same sample too many
/// consecutive times. The cutoff parameter C is calculated as:
///   C = 1 + ⌈-log₂(α) / H⌉
/// where α = 2⁻²⁰ (false positive probability) and H = min-entropy per sample.
pub struct RctTest {
    /// Cutoff threshold C — failure if count reaches this value.
    cutoff: u32,
    /// Current consecutive repetition count (B parameter).
    count: u32,
    /// Previous sample value (A parameter).
    last_sample: u64,
    /// Whether the first sample has been seen.
    initialized: bool,
}

impl RctTest {
    /// Create a new RCT with the given cutoff threshold.
    ///
    /// For min-entropy H=1.0 bit/sample and α=2⁻²⁰: cutoff = 21.
    pub fn new(cutoff: u32) -> Self {
        RctTest {
            cutoff,
            count: 0,
            last_sample: 0,
            initialized: false,
        }
    }

    /// Test a single sample. Returns `Ok(())` if the test passes,
    /// or `Err(EntropyRctFailure)` if the noise source appears stuck.
    pub fn test(&mut self, sample: u64) -> Result<(), CryptoError> {
        if !self.initialized {
            self.last_sample = sample;
            self.count = 1;
            self.initialized = true;
            return Ok(());
        }

        if sample == self.last_sample {
            self.count += 1;
            if self.count >= self.cutoff {
                return Err(CryptoError::EntropyRctFailure);
            }
        } else {
            self.last_sample = sample;
            self.count = 1;
        }

        Ok(())
    }

    /// Reset the test state.
    pub fn reset(&mut self) {
        self.count = 0;
        self.last_sample = 0;
        self.initialized = false;
    }
}

/// Adaptive Proportion Test (NIST SP 800-90B §4.4.2).
///
/// Detects non-uniform distribution of samples within a sliding window.
/// The first sample in each window becomes the "base value"; the test
/// counts how many times that value appears in the rest of the window.
pub struct AptTest {
    /// Window size W — number of samples per observation window.
    window_size: u32,
    /// Cutoff threshold C — failure if count reaches this value within a window.
    cutoff: u32,
    /// Current count of base_value occurrences in the window (B parameter).
    count: u32,
    /// Current position within the window.
    index: u32,
    /// The base value for the current window (A parameter).
    base_value: u64,
    /// Whether the base value has been set for the current window.
    base_set: bool,
}

impl AptTest {
    /// Create a new APT with the given window size and cutoff threshold.
    ///
    /// For min-entropy H=1.0 bit/sample, W=512, α=2⁻²⁰: cutoff ≈ 410.
    pub fn new(window_size: u32, cutoff: u32) -> Self {
        AptTest {
            window_size,
            cutoff,
            count: 0,
            index: 0,
            base_value: 0,
            base_set: false,
        }
    }

    /// Test a single sample. Returns `Ok(())` if the test passes,
    /// or `Err(EntropyAptFailure)` if the noise source appears biased.
    pub fn test(&mut self, sample: u64) -> Result<(), CryptoError> {
        if !self.base_set {
            // First sample in new window — set as base value
            self.base_value = sample;
            self.base_set = true;
            self.count = 1;
            self.index = 1;
            return Ok(());
        }

        if sample == self.base_value {
            self.count += 1;
            if self.count >= self.cutoff {
                return Err(CryptoError::EntropyAptFailure);
            }
        }

        self.index += 1;

        // Window complete — reset for next window
        if self.index >= self.window_size {
            self.base_set = false;
            self.count = 0;
            self.index = 0;
        }

        Ok(())
    }

    /// Reset the test state.
    pub fn reset(&mut self) {
        self.count = 0;
        self.index = 0;
        self.base_value = 0;
        self.base_set = false;
    }
}

/// Combined health test that runs both RCT and APT on each sample.
pub struct HealthTest {
    pub rct: RctTest,
    pub apt: AptTest,
}

/// Default RCT cutoff for H=1.0, α=2⁻²⁰: C = 1 + ⌈20/1.0⌉ = 21.
pub const DEFAULT_RCT_CUTOFF: u32 = 21;

/// Default APT window size.
pub const DEFAULT_APT_WINDOW: u32 = 512;

/// Default APT cutoff for H=1.0, W=512, α=2⁻²⁰.
pub const DEFAULT_APT_CUTOFF: u32 = 410;

/// Number of startup test samples (NIST SP 800-90B §4.3).
pub const STARTUP_TEST_SAMPLES: usize = 1024;

impl HealthTest {
    /// Create a combined health test with specified parameters.
    pub fn new(rct_cutoff: u32, apt_window: u32, apt_cutoff: u32) -> Self {
        HealthTest {
            rct: RctTest::new(rct_cutoff),
            apt: AptTest::new(apt_window, apt_cutoff),
        }
    }

    /// Create a combined health test with default NIST parameters.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_RCT_CUTOFF, DEFAULT_APT_WINDOW, DEFAULT_APT_CUTOFF)
    }

    /// Test a single sample against both RCT and APT.
    pub fn test_sample(&mut self, sample: u64) -> Result<(), CryptoError> {
        self.rct.test(sample)?;
        self.apt.test(sample)?;
        Ok(())
    }

    /// Reset both tests.
    pub fn reset(&mut self) {
        self.rct.reset();
        self.apt.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rct_passes_varying_data() {
        let mut rct = RctTest::new(21);
        for i in 0u64..100 {
            rct.test(i).unwrap();
        }
    }

    #[test]
    fn test_rct_fails_on_stuck_source() {
        let mut rct = RctTest::new(5);
        // First 4 repeats are ok (count goes 1,2,3,4)
        for _ in 0..4 {
            rct.test(42).unwrap();
        }
        // 5th repeat triggers failure (count = 5 >= cutoff 5)
        let result = rct.test(42);
        assert!(matches!(result, Err(CryptoError::EntropyRctFailure)));
    }

    #[test]
    fn test_rct_resets_on_change() {
        let mut rct = RctTest::new(5);
        // 4 repeats of value 1
        for _ in 0..4 {
            rct.test(1).unwrap();
        }
        // Change value — resets count
        rct.test(2).unwrap();
        // 4 more repeats of value 2 should be fine
        for _ in 0..3 {
            rct.test(2).unwrap();
        }
        // 5th repeat of value 2 triggers failure
        let result = rct.test(2);
        assert!(matches!(result, Err(CryptoError::EntropyRctFailure)));
    }

    #[test]
    fn test_apt_passes_uniform_data() {
        let mut apt = AptTest::new(512, 410);
        // Feed sequential values (each unique) — should pass easily
        for i in 0u64..1024 {
            apt.test(i).unwrap();
        }
    }

    #[test]
    fn test_apt_fails_on_biased_source() {
        let mut apt = AptTest::new(100, 50);
        // First sample sets base value to 42
        apt.test(42).unwrap();
        // Feed 48 more identical samples (count → 49, still < 50)
        for _ in 0..48 {
            apt.test(42).unwrap();
        }
        // 50th occurrence → count=50 >= cutoff=50 → fail
        let result = apt.test(42);
        assert!(matches!(result, Err(CryptoError::EntropyAptFailure)));
    }

    #[test]
    fn test_apt_window_resets() {
        let mut apt = AptTest::new(10, 8);
        // Fill first window: base=0, then 9 different values
        apt.test(0).unwrap(); // base set, count=1, index=1
        for i in 1u64..10 {
            apt.test(i).unwrap();
        }
        // Window should have reset. New window starts.
        // Feed another round — should not accumulate from previous window.
        apt.test(100).unwrap(); // new base=100
        for i in 101u64..109 {
            apt.test(i).unwrap();
        }
    }

    #[test]
    fn test_combined_health_test() {
        let mut ht = HealthTest::with_defaults();
        for i in 0u64..2000 {
            ht.test_sample(i).unwrap();
        }
    }

    #[test]
    fn test_rct_reset_prevents_failure() {
        let mut rct = RctTest::new(5);
        // Feed stuck data cutoff-2 times (count → 3)
        for _ in 0..3 {
            rct.test(42).unwrap();
        }
        // Reset — count goes back to 0
        rct.reset();
        // Feed same stuck data again — should not fail (count restarts)
        for _ in 0..3 {
            rct.test(42).unwrap();
        }
        // Still under cutoff — no failure
    }

    #[test]
    fn test_health_test_reset() {
        let mut ht = HealthTest::new(5, 10, 8);
        // Feed some data
        for i in 0u64..5 {
            ht.test_sample(i).unwrap();
        }
        // Reset
        ht.reset();
        // Should work fresh again
        for i in 0u64..5 {
            ht.test_sample(i).unwrap();
        }
    }
}
