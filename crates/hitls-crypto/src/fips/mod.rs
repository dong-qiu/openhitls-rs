//! FIPS 140-3 / CMVP compliance framework.
//!
//! Provides a self-test infrastructure for FIPS module validation:
//! - **State machine**: PreOperational → SelfTesting → Operational / Error
//! - **KAT**: Known Answer Tests for approved algorithms
//! - **PCT**: Pairwise Consistency Tests for asymmetric key generation
//! - **Integrity**: HMAC-based library integrity verification
//!
//! All functionality is gated behind `#[cfg(feature = "fips")]`.

mod integrity;
mod kat;
mod pct;

use hitls_types::CmvpError;

/// FIPS module operational states (FIPS 140-3 §10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsState {
    /// Initial state before self-tests have been run.
    PreOperational,
    /// Self-tests are currently executing.
    SelfTesting,
    /// All self-tests passed; module is ready for use.
    Operational,
    /// A self-test failed; module must not be used.
    Error,
}

/// FIPS module that manages self-test state and execution.
///
/// # Usage
///
/// ```no_run
/// use hitls_crypto::fips::FipsModule;
///
/// let mut module = FipsModule::new();
/// module.run_self_tests().expect("FIPS self-tests failed");
/// assert!(module.is_operational());
/// ```
pub struct FipsModule {
    state: FipsState,
}

impl FipsModule {
    /// Create a new FIPS module in `PreOperational` state.
    pub fn new() -> Self {
        FipsModule {
            state: FipsState::PreOperational,
        }
    }

    /// Return the current module state.
    pub fn state(&self) -> FipsState {
        self.state
    }

    /// Return true if the module is in the `Operational` state.
    pub fn is_operational(&self) -> bool {
        self.state == FipsState::Operational
    }

    /// Run all FIPS self-tests: KAT + PCT.
    ///
    /// On success, transitions to `Operational`.
    /// On failure, transitions to `Error` and returns the first failure.
    pub fn run_self_tests(&mut self) -> Result<(), CmvpError> {
        if self.state == FipsState::Error {
            return Err(CmvpError::InvalidState);
        }

        self.state = FipsState::SelfTesting;

        // Run Known Answer Tests
        if let Err(e) = kat::run_all_kat() {
            self.state = FipsState::Error;
            return Err(e);
        }

        // Run Pairwise Consistency Tests
        if let Err(e) = pct::run_all_pct() {
            self.state = FipsState::Error;
            return Err(e);
        }

        self.state = FipsState::Operational;
        Ok(())
    }

    /// Run HMAC-based integrity check against a library file.
    ///
    /// Computes HMAC-SHA256 of the file at `lib_path` with the given `key`,
    /// and compares against `expected_hmac`.
    pub fn check_integrity(
        &mut self,
        lib_path: &str,
        key: &[u8],
        expected_hmac: &[u8],
    ) -> Result<(), CmvpError> {
        integrity::check_integrity(lib_path, key, expected_hmac)
    }
}

impl Default for FipsModule {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_module_initial_state() {
        let module = FipsModule::new();
        assert_eq!(module.state(), FipsState::PreOperational);
        assert!(!module.is_operational());
    }

    #[test]
    fn test_fips_module_default() {
        let module = FipsModule::default();
        assert_eq!(module.state(), FipsState::PreOperational);
    }

    #[test]
    fn test_fips_module_self_tests_pass() {
        let mut module = FipsModule::new();
        module
            .run_self_tests()
            .expect("FIPS self-tests should pass");
        assert_eq!(module.state(), FipsState::Operational);
        assert!(module.is_operational());
    }

    #[test]
    fn test_fips_module_error_state_is_permanent() {
        let mut module = FipsModule::new();
        module.state = FipsState::Error;
        let result = module.run_self_tests();
        assert!(result.is_err());
        assert_eq!(module.state(), FipsState::Error);
    }

    #[test]
    fn test_fips_state_display() {
        assert_eq!(format!("{:?}", FipsState::PreOperational), "PreOperational");
        assert_eq!(format!("{:?}", FipsState::SelfTesting), "SelfTesting");
        assert_eq!(format!("{:?}", FipsState::Operational), "Operational");
        assert_eq!(format!("{:?}", FipsState::Error), "Error");
    }
}
