//! Entropy source with health testing (NIST SP 800-90B).
//!
//! Provides a health-tested entropy pipeline:
//! 1. Raw noise bytes from a pluggable [`NoiseSource`]
//! 2. Per-byte health testing (RCT + APT)
//! 3. Hash-based conditioning (SHA-256) to produce full-entropy output
//! 4. Entropy pool (circular buffer) for buffering
//!
//! # Example
//!
//! ```
//! use hitls_crypto::entropy::{EntropySource, EntropyConfig};
//!
//! let mut es = EntropySource::new(EntropyConfig::default());
//! let mut buf = [0u8; 32];
//! es.get_entropy(&mut buf).expect("entropy acquisition failed");
//! ```

pub mod conditioning;
pub mod health;
pub mod pool;

pub use conditioning::HashConditioner;
pub use health::{AptTest, HealthTest, RctTest};
pub use pool::EntropyPool;

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// Trait for pluggable entropy noise sources.
///
/// Implementors provide raw noise bytes that will be health-tested
/// and conditioned before use.
pub trait NoiseSource: Send {
    /// Human-readable name of the noise source.
    fn name(&self) -> &str;

    /// Minimum entropy per byte in bits (1–8).
    ///
    /// A value of 8 means full entropy (e.g., OS-provided randomness).
    /// Lower values indicate raw physical noise that needs conditioning.
    fn min_entropy_per_byte(&self) -> u32;

    /// Read raw noise bytes into `buf`. Returns the number of bytes written.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CryptoError>;
}

/// System entropy source wrapping `getrandom`.
///
/// This is the default noise source. The OS guarantees full entropy
/// (8 bits per byte) from `/dev/urandom`, `getentropy()`, etc.
pub struct SystemNoiseSource;

impl NoiseSource for SystemNoiseSource {
    fn name(&self) -> &str {
        "system"
    }

    fn min_entropy_per_byte(&self) -> u32 {
        8
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CryptoError> {
        getrandom::getrandom(buf).map_err(|_| CryptoError::DrbgEntropyFail)?;
        Ok(buf.len())
    }
}

/// Configuration for the entropy source.
#[derive(Debug, Clone)]
pub struct EntropyConfig {
    /// Capacity of the entropy pool in bytes. Default: 4096.
    pub pool_capacity: usize,
    /// Whether to run health tests on each noise sample. Default: true.
    pub enable_health_tests: bool,
    /// RCT cutoff threshold. Default: 21 (H=1.0, α=2⁻²⁰).
    pub rct_cutoff: u32,
    /// APT window size. Default: 512.
    pub apt_window_size: u32,
    /// APT cutoff threshold. Default: 410.
    pub apt_cutoff: u32,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        EntropyConfig {
            pool_capacity: pool::DEFAULT_POOL_CAPACITY,
            enable_health_tests: true,
            rct_cutoff: health::DEFAULT_RCT_CUTOFF,
            apt_window_size: health::DEFAULT_APT_WINDOW,
            apt_cutoff: health::DEFAULT_APT_CUTOFF,
        }
    }
}

/// Main entropy source coordinator.
///
/// Orchestrates noise collection, health testing, conditioning,
/// and entropy pooling to deliver high-quality randomness.
pub struct EntropySource {
    pool: EntropyPool,
    health: Option<HealthTest>,
    conditioner: HashConditioner,
    source: Box<dyn NoiseSource>,
}

impl EntropySource {
    /// Create a new entropy source with the system noise source.
    pub fn new(config: EntropyConfig) -> Self {
        Self::with_source(config, Box::new(SystemNoiseSource))
    }

    /// Create a new entropy source with a custom noise source.
    pub fn with_source(config: EntropyConfig, source: Box<dyn NoiseSource>) -> Self {
        let health = if config.enable_health_tests {
            Some(HealthTest::new(
                config.rct_cutoff,
                config.apt_window_size,
                config.apt_cutoff,
            ))
        } else {
            None
        };

        EntropySource {
            pool: EntropyPool::new(config.pool_capacity),
            health,
            conditioner: HashConditioner::new(),
            source,
        }
    }

    /// Get `buf.len()` bytes of health-tested, conditioned entropy.
    ///
    /// The pipeline:
    /// 1. Check if the pool has enough bytes; if so, pop directly.
    /// 2. Otherwise, collect raw noise from the source.
    /// 3. Run health tests on each byte (if enabled).
    /// 4. Condition the raw noise via SHA-256 derivation function.
    /// 5. Push conditioned bytes into the pool.
    /// 6. Pop the requested amount from the pool.
    pub fn get_entropy(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {
        // Try to serve from pool first
        if self.pool.len() >= buf.len() {
            let read = self.pool.pop(buf);
            if read == buf.len() {
                return Ok(());
            }
        }

        // Need more entropy — gather, test, condition, and fill pool
        while self.pool.len() < buf.len() {
            self.gather_conditioned_block()?;
        }

        let read = self.pool.pop(buf);
        debug_assert_eq!(read, buf.len());
        Ok(())
    }

    /// Run the startup health test (NIST SP 800-90B §4.3).
    ///
    /// Collects and tests `STARTUP_TEST_SAMPLES` noise samples
    /// to verify the noise source is functioning correctly.
    /// The collected entropy is discarded.
    pub fn startup_test(&mut self) -> Result<(), CryptoError> {
        let mut sample_buf = [0u8; 1];
        for _ in 0..health::STARTUP_TEST_SAMPLES {
            self.source.read(&mut sample_buf)?;
            if let Some(ref mut ht) = self.health {
                ht.test_sample(sample_buf[0] as u64)?;
            }
        }
        // Reset health tests after startup (don't carry startup state)
        if let Some(ref mut ht) = self.health {
            ht.reset();
        }
        Ok(())
    }

    /// Gather one block of conditioned entropy and push to pool.
    fn gather_conditioned_block(&mut self) -> Result<(), CryptoError> {
        let min_entropy = self.source.min_entropy_per_byte();
        let needed = self.conditioner.needed_input_len(min_entropy);

        // Allocate and read raw noise
        let mut raw = vec![0u8; needed];
        let mut offset = 0;
        while offset < needed {
            let read = self.source.read(&mut raw[offset..])?;
            if read == 0 {
                return Err(CryptoError::DrbgEntropyFail);
            }

            // Health-test each byte
            if let Some(ref mut ht) = self.health {
                for &byte in &raw[offset..offset + read] {
                    ht.test_sample(byte as u64)?;
                }
            }

            offset += read;
        }

        // Condition raw noise into full-entropy output
        let conditioned = self.conditioner.condition(&raw)?;
        raw.zeroize();

        // Push to pool
        self.pool.push(&conditioned);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_source_get_entropy() {
        let mut es = EntropySource::new(EntropyConfig::default());
        let mut buf = [0u8; 64];
        es.get_entropy(&mut buf).unwrap();
        // Output should not be all zeros
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_entropy_source_startup_test() {
        let mut es = EntropySource::new(EntropyConfig::default());
        es.startup_test().unwrap();
        // After startup test, should still work
        let mut buf = [0u8; 32];
        es.get_entropy(&mut buf).unwrap();
    }

    /// A deterministic noise source for testing.
    struct CountingNoiseSource {
        counter: u8,
    }

    impl CountingNoiseSource {
        fn new() -> Self {
            CountingNoiseSource { counter: 0 }
        }
    }

    impl NoiseSource for CountingNoiseSource {
        fn name(&self) -> &str {
            "counting"
        }
        fn min_entropy_per_byte(&self) -> u32 {
            8
        }
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, CryptoError> {
            for b in buf.iter_mut() {
                *b = self.counter;
                self.counter = self.counter.wrapping_add(1);
            }
            Ok(buf.len())
        }
    }

    #[test]
    fn test_entropy_source_custom_noise() {
        let config = EntropyConfig {
            enable_health_tests: false,
            ..Default::default()
        };
        let mut es = EntropySource::with_source(config, Box::new(CountingNoiseSource::new()));
        let mut buf = [0u8; 32];
        es.get_entropy(&mut buf).unwrap();
        // With conditioning, output won't match raw counter bytes
        // but should be deterministic
        let mut buf2 = [0u8; 32];
        let mut es2 = EntropySource::with_source(
            EntropyConfig {
                enable_health_tests: false,
                ..Default::default()
            },
            Box::new(CountingNoiseSource::new()),
        );
        es2.get_entropy(&mut buf2).unwrap();
        assert_eq!(buf, buf2);
    }

    /// A noise source that always returns the same byte — should fail health tests.
    struct StuckNoiseSource;

    impl NoiseSource for StuckNoiseSource {
        fn name(&self) -> &str {
            "stuck"
        }
        fn min_entropy_per_byte(&self) -> u32 {
            8
        }
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, CryptoError> {
            buf.fill(0x42);
            Ok(buf.len())
        }
    }

    #[test]
    fn test_entropy_source_health_test_catches_bad_source() {
        let config = EntropyConfig {
            rct_cutoff: 5, // Low threshold for quick failure
            ..Default::default()
        };
        let mut es = EntropySource::with_source(config, Box::new(StuckNoiseSource));
        let mut buf = [0u8; 32];
        let result = es.get_entropy(&mut buf);
        assert!(result.is_err());
    }
}
