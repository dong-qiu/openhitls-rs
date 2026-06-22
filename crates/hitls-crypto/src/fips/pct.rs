//! Pairwise Consistency Tests (PCT) for FIPS 140-3.
//!
//! PCT verifies that asymmetric key generation produces valid key pairs by
//! performing a sign-verify cycle after key generation. This catches
//! catastrophic key generation failures.

use hitls_types::CmvpError;

/// Run all pairwise consistency tests.
pub(crate) fn run_all_pct() -> Result<(), CmvpError> {
    pct_ecdsa_p256()?;
    pct_ed25519()?;
    pct_rsa_sign_verify()?;
    // PQC keygen PCTs — exercise the (randomised) key-generation path that the
    // verify/decaps KATs cannot, by round-tripping a freshly generated key.
    #[cfg(feature = "mlkem")]
    pct_mlkem()?;
    #[cfg(feature = "mldsa")]
    pct_mldsa()?;
    #[cfg(feature = "slh-dsa")]
    pct_slhdsa()?;
    Ok(())
}

/// PCT for ML-KEM-768: generate, encapsulate, decapsulate — the recovered
/// shared secret must equal the one produced by encapsulation.
#[cfg(feature = "mlkem")]
fn pct_mlkem() -> Result<(), CmvpError> {
    use crate::mlkem::MlKemKeyPair;
    let kp = MlKemKeyPair::generate(768)
        .map_err(|e| CmvpError::PairwiseTestError(format!("ML-KEM keygen: {e}")))?;
    let (ss_enc, ct) = kp
        .encapsulate()
        .map_err(|e| CmvpError::PairwiseTestError(format!("ML-KEM encaps: {e}")))?;
    let ss_dec = kp
        .decapsulate(&ct)
        .map_err(|e| CmvpError::PairwiseTestError(format!("ML-KEM decaps: {e}")))?;
    if ss_enc != ss_dec {
        return Err(CmvpError::PairwiseTestError(
            "ML-KEM-768 PCT shared-secret mismatch".into(),
        ));
    }
    Ok(())
}

/// PCT for ML-DSA-65: generate, sign, verify.
#[cfg(feature = "mldsa")]
fn pct_mldsa() -> Result<(), CmvpError> {
    use crate::mldsa::MlDsaKeyPair;
    let msg = b"\x01\x02\x03\x04";
    let kp = MlDsaKeyPair::generate(65)
        .map_err(|e| CmvpError::PairwiseTestError(format!("ML-DSA keygen: {e}")))?;
    let sig = kp
        .sign(msg)
        .map_err(|e| CmvpError::PairwiseTestError(format!("ML-DSA sign: {e}")))?;
    let valid = kp
        .verify(msg, &sig)
        .map_err(|e| CmvpError::PairwiseTestError(format!("ML-DSA verify: {e}")))?;
    if !valid {
        return Err(CmvpError::PairwiseTestError("ML-DSA-65 PCT failed".into()));
    }
    Ok(())
}

/// PCT for SLH-DSA (SHA2-128s): generate, sign, verify.
#[cfg(feature = "slh-dsa")]
fn pct_slhdsa() -> Result<(), CmvpError> {
    use crate::slh_dsa::SlhDsaKeyPair;
    use hitls_types::SlhDsaParamId;
    let msg = b"\x01\x02\x03\x04";
    let kp = SlhDsaKeyPair::generate(SlhDsaParamId::Sha2128s)
        .map_err(|e| CmvpError::PairwiseTestError(format!("SLH-DSA keygen: {e}")))?;
    let sig = kp
        .sign(msg)
        .map_err(|e| CmvpError::PairwiseTestError(format!("SLH-DSA sign: {e}")))?;
    let valid = kp
        .verify(msg, &sig)
        .map_err(|e| CmvpError::PairwiseTestError(format!("SLH-DSA verify: {e}")))?;
    if !valid {
        return Err(CmvpError::PairwiseTestError(
            "SLH-DSA-128s PCT failed".into(),
        ));
    }
    Ok(())
}

/// PCT for ECDSA P-256: generate key pair, sign, verify.
fn pct_ecdsa_p256() -> Result<(), CmvpError> {
    use crate::ecdsa::EcdsaKeyPair;
    use crate::sha2::Sha256;
    use hitls_types::EccCurveId;

    let msg = b"\x01\x02\x03\x04";

    let mut hasher = Sha256::new();
    hasher
        .update(msg)
        .map_err(|e| CmvpError::PairwiseTestError(format!("ECDSA-P256 hash: {e}")))?;
    let digest = hasher
        .finish()
        .map_err(|e| CmvpError::PairwiseTestError(format!("ECDSA-P256 hash finish: {e}")))?;

    let kp = EcdsaKeyPair::generate(EccCurveId::NistP256)
        .map_err(|e| CmvpError::PairwiseTestError(format!("ECDSA-P256 keygen: {e}")))?;

    let sig = kp
        .sign(&digest)
        .map_err(|e| CmvpError::PairwiseTestError(format!("ECDSA-P256 sign: {e}")))?;

    let valid = kp
        .verify(&digest, &sig)
        .map_err(|e| CmvpError::PairwiseTestError(format!("ECDSA-P256 verify: {e}")))?;

    if !valid {
        return Err(CmvpError::PairwiseTestError(
            "ECDSA P-256 PCT failed".into(),
        ));
    }
    Ok(())
}

/// PCT for Ed25519: generate key pair, sign, verify.
fn pct_ed25519() -> Result<(), CmvpError> {
    use crate::ed25519::Ed25519KeyPair;

    let msg = b"\x01\x02\x03\x04";

    let kp = Ed25519KeyPair::generate()
        .map_err(|e| CmvpError::PairwiseTestError(format!("Ed25519 keygen: {e}")))?;

    let sig = kp
        .sign(msg)
        .map_err(|e| CmvpError::PairwiseTestError(format!("Ed25519 sign: {e}")))?;

    let valid = kp
        .verify(msg, &sig)
        .map_err(|e| CmvpError::PairwiseTestError(format!("Ed25519 verify: {e}")))?;

    if !valid {
        return Err(CmvpError::PairwiseTestError("Ed25519 PCT failed".into()));
    }
    Ok(())
}

/// PCT for RSA-2048: generate key pair, sign (PSS), verify.
fn pct_rsa_sign_verify() -> Result<(), CmvpError> {
    use crate::rsa::{RsaPadding, RsaPrivateKey};
    use crate::sha2::Sha256;

    let msg = b"\x01\x02\x03\x04";

    // Hash the message
    let mut hasher = Sha256::new();
    hasher
        .update(msg)
        .map_err(|e| CmvpError::PairwiseTestError(format!("RSA hash: {e}")))?;
    let digest = hasher
        .finish()
        .map_err(|e| CmvpError::PairwiseTestError(format!("RSA hash finish: {e}")))?;

    // Generate RSA-2048 key pair
    let kp = RsaPrivateKey::generate(2048)
        .map_err(|e| CmvpError::PairwiseTestError(format!("RSA keygen: {e}")))?;

    // Sign with PSS
    let sig = kp
        .sign(RsaPadding::Pss, &digest)
        .map_err(|e| CmvpError::PairwiseTestError(format!("RSA PSS sign: {e}")))?;

    // Verify with public key
    let pk = kp.public_key();
    let valid = pk
        .verify(RsaPadding::Pss, &digest, &sig)
        .map_err(|e| CmvpError::PairwiseTestError(format!("RSA PSS verify: {e}")))?;

    if !valid {
        return Err(CmvpError::PairwiseTestError(
            "RSA-2048 PSS PCT failed".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pct_ecdsa_p256() {
        pct_ecdsa_p256().unwrap();
    }

    #[test]
    fn test_pct_ed25519() {
        pct_ed25519().unwrap();
    }

    #[test]
    fn test_pct_rsa_sign_verify() {
        pct_rsa_sign_verify().unwrap();
    }

    #[test]
    fn test_run_all_pct() {
        run_all_pct().unwrap();
    }

    /// Run PCT twice to verify deterministic stability.
    #[test]
    fn test_pct_ecdsa_p256_deterministic() {
        pct_ecdsa_p256().unwrap();
        pct_ecdsa_p256().unwrap();
    }

    /// Full PCT chain runs without interference between subtests.
    #[test]
    fn test_pct_run_all_coverage() {
        // Run all PCT tests multiple times to exercise all pct_* sub-functions
        run_all_pct().unwrap();
        run_all_pct().unwrap();
    }
}
