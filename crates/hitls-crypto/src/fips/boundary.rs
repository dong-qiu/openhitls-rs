//! FIPS 140-3 module boundary enforcement.
//!
//! Provides a global FIPS mode singleton that gates cryptographic operations:
//! - When FIPS mode is active, only approved algorithms may execute
//! - All crypto operations must check `require_operational()` before proceeding
//! - The module transitions to `Operational` only after KAT+PCT pass
//!
//! # Usage
//!
//! ```no_run
//! use hitls_crypto::fips::{FipsModule, boundary};
//!
//! // Initialize and activate FIPS mode
//! let mut module = FipsModule::new();
//! module.run_self_tests().unwrap();
//! boundary::activate_fips_mode();
//!
//! // Now all crypto operations will check FIPS state
//! assert!(boundary::is_fips_active());
//! boundary::require_operational().unwrap();
//! ```

use super::FipsState;
use hitls_types::CmvpError;
use std::sync::atomic::{AtomicU8, Ordering};

/// Global FIPS mode flag.
///
/// 0 = inactive (non-FIPS mode, no enforcement)
/// 1 = active (FIPS mode, all operations checked)
static FIPS_MODE: AtomicU8 = AtomicU8::new(0);

/// Global FIPS module state.
///
/// Mirrors `FipsState` as an atomic value:
/// 0 = PreOperational, 1 = SelfTesting, 2 = Operational, 3 = Error
static FIPS_STATE: AtomicU8 = AtomicU8::new(0);

fn state_to_u8(state: FipsState) -> u8 {
    match state {
        FipsState::PreOperational => 0,
        FipsState::SelfTesting => 1,
        FipsState::Operational => 2,
        FipsState::Error => 3,
    }
}

fn u8_to_state(val: u8) -> FipsState {
    match val {
        0 => FipsState::PreOperational,
        1 => FipsState::SelfTesting,
        2 => FipsState::Operational,
        3 => FipsState::Error,
        _ => FipsState::Error,
    }
}

/// Activate FIPS mode globally.
///
/// Once activated, all cryptographic operations will check that the module
/// is in `Operational` state before proceeding.
pub fn activate_fips_mode() {
    FIPS_MODE.store(1, Ordering::SeqCst);
}

/// Deactivate FIPS mode globally (for testing only).
///
/// In production, FIPS mode should never be deactivated once enabled.
#[cfg(test)]
pub fn deactivate_fips_mode() {
    FIPS_MODE.store(0, Ordering::SeqCst);
}

/// Check whether FIPS mode is currently active.
pub fn is_fips_active() -> bool {
    FIPS_MODE.load(Ordering::SeqCst) != 0
}

/// Update the global FIPS module state.
///
/// Called by `FipsModule::run_self_tests()` to synchronize state.
pub(crate) fn set_global_state(state: FipsState) {
    FIPS_STATE.store(state_to_u8(state), Ordering::SeqCst);
}

/// Get the current global FIPS module state.
pub fn global_state() -> FipsState {
    u8_to_state(FIPS_STATE.load(Ordering::SeqCst))
}

/// Require the FIPS module to be in `Operational` state.
///
/// If FIPS mode is not active, this is a no-op (returns `Ok`).
/// If FIPS mode is active but the module is not `Operational`, returns
/// `CmvpError::InvalidState`.
///
/// Call this at the entry point of every cryptographic operation when
/// FIPS compliance is needed.
pub fn require_operational() -> Result<(), CmvpError> {
    if !is_fips_active() {
        return Ok(());
    }
    if global_state() != FipsState::Operational {
        return Err(CmvpError::InvalidState);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Approved algorithm enforcement
// ---------------------------------------------------------------------------

/// Algorithm identifiers for FIPS approval checking.
///
/// This is a simplified representation — in practice, the check also considers
/// key sizes and parameter constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsAlgorithm {
    // Approved hash algorithms
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,

    // Approved symmetric ciphers
    Aes128,
    Aes192,
    Aes256,

    // Approved modes
    Gcm,
    Ccm,
    Cbc,
    Ctr,
    Xts,
    Ecb,

    // Approved MACs
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    CmacAes,

    // Approved asymmetric algorithms
    RsaPkcs1v15,
    RsaPss,
    RsaOaep,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519,
    Ed448,
    Dh,

    // Approved KDFs
    HkdfSha256,
    HkdfSha384,
    Pbkdf2,

    // Approved DRBGs
    HmacDrbg,
    CtrDrbg,

    // Approved PQC
    MlKem512,
    MlKem768,
    MlKem1024,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsa,

    // Non-approved (blocked in FIPS mode)
    Md5,
    Sm3,
    Sm4,
    Sm2,
    Sm9,
    ChaCha20,
    Poly1305,
    ChaCha20Poly1305,
    Rc4,
    Des,
    TripleDes,
    Dsa,
    SipHash,
}

/// Check whether an algorithm is approved for use in FIPS mode.
///
/// Returns `true` if the algorithm is on the FIPS 140-3 approved list.
/// Non-approved algorithms return `false`.
pub fn is_approved(alg: FipsAlgorithm) -> bool {
    use FipsAlgorithm::*;
    matches!(
        alg,
        Sha1
            | Sha224
            | Sha256
            | Sha384
            | Sha512
            | Sha3_224
            | Sha3_256
            | Sha3_384
            | Sha3_512
            | Shake128
            | Shake256
            | Aes128
            | Aes192
            | Aes256
            | Gcm
            | Ccm
            | Cbc
            | Ctr
            | Xts
            | Ecb
            | HmacSha1
            | HmacSha224
            | HmacSha256
            | HmacSha384
            | HmacSha512
            | CmacAes
            | RsaPkcs1v15
            | RsaPss
            | RsaOaep
            | EcdsaP256
            | EcdsaP384
            | EcdsaP521
            | Ed25519
            | Ed448
            | Dh
            | HkdfSha256
            | HkdfSha384
            | Pbkdf2
            | HmacDrbg
            | CtrDrbg
            | MlKem512
            | MlKem768
            | MlKem1024
            | MlDsa44
            | MlDsa65
            | MlDsa87
            | SlhDsa
    )
}

/// Require that an algorithm is approved for FIPS mode.
///
/// If FIPS mode is not active, this is a no-op.
/// If FIPS mode is active and the algorithm is not approved, returns an error.
pub fn require_approved(alg: FipsAlgorithm) -> Result<(), CmvpError> {
    if !is_fips_active() {
        return Ok(());
    }
    require_operational()?;
    if !is_approved(alg) {
        return Err(CmvpError::ParamCheckError(format!(
            "algorithm {:?} is not approved in FIPS mode",
            alg
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approved_algorithms() {
        assert!(is_approved(FipsAlgorithm::Sha256));
        assert!(is_approved(FipsAlgorithm::Aes128));
        assert!(is_approved(FipsAlgorithm::EcdsaP256));
        assert!(is_approved(FipsAlgorithm::RsaPss));
        assert!(is_approved(FipsAlgorithm::HmacDrbg));
        assert!(is_approved(FipsAlgorithm::MlKem768));
        assert!(is_approved(FipsAlgorithm::MlDsa65));
        assert!(is_approved(FipsAlgorithm::Ed25519));
    }

    #[test]
    fn test_non_approved_algorithms() {
        assert!(!is_approved(FipsAlgorithm::Md5));
        assert!(!is_approved(FipsAlgorithm::Sm3));
        assert!(!is_approved(FipsAlgorithm::Sm4));
        assert!(!is_approved(FipsAlgorithm::Sm2));
        assert!(!is_approved(FipsAlgorithm::Sm9));
        assert!(!is_approved(FipsAlgorithm::ChaCha20));
        assert!(!is_approved(FipsAlgorithm::Poly1305));
        assert!(!is_approved(FipsAlgorithm::ChaCha20Poly1305));
        assert!(!is_approved(FipsAlgorithm::Rc4));
        assert!(!is_approved(FipsAlgorithm::Des));
        assert!(!is_approved(FipsAlgorithm::TripleDes));
        assert!(!is_approved(FipsAlgorithm::Dsa));
        assert!(!is_approved(FipsAlgorithm::SipHash));
    }

    /// Single test for all global-state-dependent operations.
    /// Must run in a single test to avoid parallel test races on global atomics.
    #[test]
    fn test_fips_boundary_global_state() {
        // --- require_operational when inactive ---
        deactivate_fips_mode();
        assert!(!is_fips_active());
        assert!(require_operational().is_ok());
        // Non-approved succeeds when inactive
        assert!(require_approved(FipsAlgorithm::Md5).is_ok());
        assert!(require_approved(FipsAlgorithm::Sm4).is_ok());

        // --- activate and check state transitions ---
        activate_fips_mode();
        assert!(is_fips_active());

        // PreOperational — should fail
        set_global_state(FipsState::PreOperational);
        assert_eq!(global_state(), FipsState::PreOperational);
        assert!(require_operational().is_err());
        // Even approved algorithms fail if not operational
        let err = require_approved(FipsAlgorithm::Sha256).unwrap_err();
        assert!(matches!(err, CmvpError::InvalidState));

        // SelfTesting — should fail
        set_global_state(FipsState::SelfTesting);
        assert_eq!(global_state(), FipsState::SelfTesting);
        assert!(require_operational().is_err());

        // Operational — should pass
        set_global_state(FipsState::Operational);
        assert_eq!(global_state(), FipsState::Operational);
        assert!(require_operational().is_ok());
        // Approved algorithms succeed
        assert!(require_approved(FipsAlgorithm::Sha256).is_ok());
        assert!(require_approved(FipsAlgorithm::Aes128).is_ok());
        // Non-approved algorithms fail
        assert!(require_approved(FipsAlgorithm::Md5).is_err());
        assert!(require_approved(FipsAlgorithm::Sm4).is_err());
        assert!(require_approved(FipsAlgorithm::ChaCha20Poly1305).is_err());

        // Error state — should fail
        set_global_state(FipsState::Error);
        assert_eq!(global_state(), FipsState::Error);
        assert!(require_operational().is_err());

        // Cleanup
        deactivate_fips_mode();
        set_global_state(FipsState::PreOperational);
    }
}
