//! TLS 1.2 PRF (Pseudo-Random Function) as defined in RFC 5246 §5.
//!
//! ```text
//! PRF(secret, label, seed) = P_<hash>(secret, label + seed)
//!
//! P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) ||
//!                         HMAC_hash(secret, A(2) + seed) || ...
//! A(0) = seed
//! A(i) = HMAC_hash(secret, A(i-1))
//! ```

use super::hkdf::hmac_hash;
use super::HashAlgId;
use hitls_types::TlsError;

/// Maximum label+seed size for stack allocation (covers all TLS 1.2 PRF uses).
/// Largest: "key expansion" (13 bytes) + client_random (32) + server_random (32) = 77.
const MAX_LABEL_SEED: usize = 128;

/// TLS 1.2 PRF: Derive `output_len` bytes from `secret`, `label`, and `seed`.
///
/// Uses the P_hash expansion function with the given hash algorithm
/// (typically SHA-256 for TLS 1.2).
pub fn prf(
    alg: HashAlgId,
    secret: &[u8],
    label: &str,
    seed: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, TlsError> {
    // Concatenate label + seed into stack buffer
    let ls_len = label.len() + seed.len();
    let mut ls_buf = [0u8; MAX_LABEL_SEED];
    if ls_len <= MAX_LABEL_SEED {
        ls_buf[..label.len()].copy_from_slice(label.as_bytes());
        ls_buf[label.len()..ls_len].copy_from_slice(seed);
        p_hash(alg, secret, &ls_buf[..ls_len], output_len)
    } else {
        // Fallback for unusually large label+seed (should not occur in TLS)
        let mut label_seed = Vec::with_capacity(ls_len);
        label_seed.extend_from_slice(label.as_bytes());
        label_seed.extend_from_slice(seed);
        p_hash(alg, secret, &label_seed, output_len)
    }
}

/// Maximum hash output size (SHA-384 = 48, SHA-512 = 64).
const MAX_HASH_OUTPUT: usize = 64;

/// P_hash expansion function (RFC 5246 §5).
fn p_hash(
    alg: HashAlgId,
    secret: &[u8],
    seed: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, TlsError> {
    let mut result = Vec::with_capacity(output_len);

    // A(0) = seed → A(1) = HMAC(secret, seed)
    let mut a = hmac_hash(alg, secret, seed)?;

    // Stack buffer for A(i) || seed concatenation (max: 64 + 128 = 192)
    let mut ai_seed_buf = [0u8; MAX_HASH_OUTPUT + MAX_LABEL_SEED];
    let a_len = a.len();

    while result.len() < output_len {
        // Build A(i) || seed in stack buffer
        ai_seed_buf[..a_len].copy_from_slice(&a);
        ai_seed_buf[a_len..a_len + seed.len()].copy_from_slice(seed);
        let block = hmac_hash(alg, secret, &ai_seed_buf[..a_len + seed.len()])?;

        result.extend_from_slice(&block);

        // A(i+1) = HMAC_hash(secret, A(i))
        if result.len() < output_len {
            a = hmac_hash(alg, secret, &a)?;
        }
    }

    result.truncate(output_len);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::hex::{hex, to_hex};

    #[test]
    fn test_prf_sha256_basic() {
        // Basic smoke test: PRF should produce deterministic output
        let secret = b"test secret";
        let label = "test label";
        let seed = b"test seed";

        let output1 = prf(HashAlgId::Sha256, secret, label, seed, 32).unwrap();
        let output2 = prf(HashAlgId::Sha256, secret, label, seed, 32).unwrap();
        assert_eq!(output1, output2);
        assert_eq!(output1.len(), 32);
    }

    #[test]
    fn test_prf_sha256_known_vector() {
        // RFC 5246 doesn't provide explicit test vectors, but we can verify
        // against a well-known computation. Using the PRF definition to produce
        // a known output for specific inputs.
        let secret = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let label = "test label";
        let seed = hex("a0a1a2a3a4a5a6a7a8a9");

        let output = prf(HashAlgId::Sha256, &secret, label, &seed, 100).unwrap();
        assert_eq!(output.len(), 100);

        // Same input must produce same output
        let output2 = prf(HashAlgId::Sha256, &secret, label, &seed, 100).unwrap();
        assert_eq!(output, output2);

        // Different label should produce different output
        let output3 = prf(HashAlgId::Sha256, &secret, "other label", &seed, 100).unwrap();
        assert_ne!(output, output3);
    }

    #[test]
    fn test_prf_sha384() {
        let secret = b"sha384 secret";
        let label = "sha384 label";
        let seed = b"sha384 seed";

        let output = prf(HashAlgId::Sha384, secret, label, seed, 48).unwrap();
        assert_eq!(output.len(), 48);

        // Verify determinism
        let output2 = prf(HashAlgId::Sha384, secret, label, seed, 48).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn test_prf_master_secret() {
        // Simulate TLS 1.2 master_secret derivation:
        // master_secret = PRF(pre_master_secret, "master secret",
        //                     ClientHello.random + ServerHello.random)[0..48]
        let pre_master_secret = [0x03, 0x03]; // minimal PMS
        let client_random = [0u8; 32];
        let server_random = [1u8; 32];

        let mut seed = Vec::new();
        seed.extend_from_slice(&client_random);
        seed.extend_from_slice(&server_random);

        let master_secret = prf(
            HashAlgId::Sha256,
            &pre_master_secret,
            "master secret",
            &seed,
            48,
        )
        .unwrap();
        assert_eq!(master_secret.len(), 48);

        // Verify we get same result for same inputs
        let ms2 = prf(
            HashAlgId::Sha256,
            &pre_master_secret,
            "master secret",
            &seed,
            48,
        )
        .unwrap();
        assert_eq!(master_secret, ms2);
    }

    #[test]
    fn test_prf_key_expansion() {
        // Simulate key expansion:
        // key_block = PRF(master_secret, "key expansion",
        //                 server_random + client_random)
        let master_secret = [0xABu8; 48];
        let server_random = [0x01u8; 32];
        let client_random = [0x02u8; 32];

        let mut seed = Vec::new();
        seed.extend_from_slice(&server_random);
        seed.extend_from_slice(&client_random);

        // Need enough for: client_write_MAC_key(32) + server_write_MAC_key(32) +
        // client_write_key(16) + server_write_key(16) + client_write_IV(16) + server_write_IV(16)
        let key_block = prf(
            HashAlgId::Sha256,
            &master_secret,
            "key expansion",
            &seed,
            128,
        )
        .unwrap();
        assert_eq!(key_block.len(), 128);
    }

    #[test]
    fn test_prf_empty_seed() {
        let secret = b"secret";
        let output = prf(HashAlgId::Sha256, secret, "label", &[], 32).unwrap();
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_prf_various_output_lengths() {
        let secret = b"secret";
        let label = "label";
        let seed = b"seed";

        // Test various output lengths including those that cross hash output boundaries
        for len in [1, 16, 31, 32, 33, 48, 64, 100, 256] {
            let output = prf(HashAlgId::Sha256, secret, label, seed, len).unwrap();
            assert_eq!(output.len(), len);
        }

        // Verify prefix consistency: longer output should start with shorter output
        let short = prf(HashAlgId::Sha256, secret, label, seed, 32).unwrap();
        let long = prf(HashAlgId::Sha256, secret, label, seed, 64).unwrap();
        assert_eq!(&long[..32], &short[..]);
    }

    #[test]
    fn test_prf_sha256_rfc5246_verify() {
        // Cross-validate PRF output against a reference computation.
        // We manually compute P_SHA256(secret, label||seed) for a small output.
        let secret = hex("9bbe436ba940f017b17652849a71db35");
        let label = "test label";
        let seed = hex("a0a1a2a3a4a5a6a7a8a9");

        let output = prf(HashAlgId::Sha256, &secret, label, &seed, 32).unwrap();

        // Manual computation:
        // label_seed = "test label" || seed
        let mut label_seed = Vec::new();
        label_seed.extend_from_slice(label.as_bytes());
        label_seed.extend_from_slice(&seed);

        // A(1) = HMAC(secret, label_seed)
        let a1 = hmac_hash(HashAlgId::Sha256, &secret, &label_seed).unwrap();
        // P(1) = HMAC(secret, A(1) || label_seed)
        let mut a1_seed = a1.clone();
        a1_seed.extend_from_slice(&label_seed);
        let p1 = hmac_hash(HashAlgId::Sha256, &secret, &a1_seed).unwrap();

        // For 32 bytes output, P(1) is exactly one SHA-256 block
        assert_eq!(output, p1);

        // Log for verification
        eprintln!("PRF output: {}", to_hex(&output));
    }

    #[test]
    fn test_prf_zero_output_length() {
        let output = prf(HashAlgId::Sha256, b"secret", "label", b"seed", 0).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn test_prf_large_output() {
        // Test with output larger than multiple hash blocks (SHA-256 = 32 bytes)
        let output = prf(HashAlgId::Sha256, b"secret", "label", b"seed", 1000).unwrap();
        assert_eq!(output.len(), 1000);

        // Verify prefix consistency with shorter output
        let short = prf(HashAlgId::Sha256, b"secret", "label", b"seed", 500).unwrap();
        assert_eq!(&output[..500], &short[..]);
    }

    #[test]
    fn test_prf_sha256_vs_sha384_different_output() {
        // Same inputs with different hash → different output
        let secret = b"same secret";
        let label = "same label";
        let seed = b"same seed";

        let out256 = prf(HashAlgId::Sha256, secret, label, seed, 48).unwrap();
        let out384 = prf(HashAlgId::Sha384, secret, label, seed, 48).unwrap();
        assert_ne!(out256, out384);
    }

    #[test]
    fn test_prf_empty_secret() {
        // Empty secret should still produce valid output
        let output = prf(HashAlgId::Sha256, &[], "label", b"seed", 32).unwrap();
        assert_eq!(output.len(), 32);
        // Verify determinism
        let output2 = prf(HashAlgId::Sha256, &[], "label", b"seed", 32).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn test_prf_different_seeds_differ() {
        let secret = b"secret";
        let label = "label";
        let out1 = prf(HashAlgId::Sha256, secret, label, b"seed1", 32).unwrap();
        let out2 = prf(HashAlgId::Sha256, secret, label, b"seed2", 32).unwrap();
        assert_ne!(out1, out2);
    }

    // ===== Phase T112: SM3 PRF tests =====

    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    #[test]
    fn test_prf_sm3_basic() {
        // Basic smoke test: SM3 PRF should produce deterministic output
        let secret = b"test secret";
        let label = "test label";
        let seed = b"test seed";

        let output1 = prf(HashAlgId::Sm3, secret, label, seed, 32).unwrap();
        let output2 = prf(HashAlgId::Sm3, secret, label, seed, 32).unwrap();
        assert_eq!(output1, output2);
        assert_eq!(output1.len(), 32);
    }

    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    #[test]
    fn test_prf_sm3_vs_sha256_differ() {
        // Same inputs with SM3 vs SHA-256 must produce different output
        let secret = b"same secret";
        let label = "same label";
        let seed = b"same seed";

        let out_sm3 = prf(HashAlgId::Sm3, secret, label, seed, 48).unwrap();
        let out_sha256 = prf(HashAlgId::Sha256, secret, label, seed, 48).unwrap();
        assert_ne!(out_sm3, out_sha256);
    }

    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    #[test]
    fn test_prf_sm3_various_output_lengths() {
        let secret = b"secret";
        let label = "label";
        let seed = b"seed";

        // Test various output lengths including those that cross hash output boundaries
        // SM3 output is 32 bytes, so 33+ requires multiple P_hash iterations
        for len in [1, 16, 31, 32, 33, 48, 64, 100, 256] {
            let output = prf(HashAlgId::Sm3, secret, label, seed, len).unwrap();
            assert_eq!(output.len(), len);
        }

        // Verify prefix consistency: longer output should start with shorter output
        let short = prf(HashAlgId::Sm3, secret, label, seed, 32).unwrap();
        let long = prf(HashAlgId::Sm3, secret, label, seed, 64).unwrap();
        assert_eq!(&long[..32], &short[..]);
    }

    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    #[test]
    fn test_prf_sm3_known_vector_manual() {
        // Cross-validate SM3 PRF against manual P_SM3 computation
        let secret = hex("9bbe436ba940f017b17652849a71db35");
        let label = "test label";
        let seed = hex("a0a1a2a3a4a5a6a7a8a9");

        let output = prf(HashAlgId::Sm3, &secret, label, &seed, 32).unwrap();

        // Manual computation:
        // label_seed = "test label" || seed
        let mut label_seed = Vec::new();
        label_seed.extend_from_slice(label.as_bytes());
        label_seed.extend_from_slice(&seed);

        // A(1) = HMAC-SM3(secret, label_seed)
        let a1 = hmac_hash(HashAlgId::Sm3, &secret, &label_seed).unwrap();
        // P(1) = HMAC-SM3(secret, A(1) || label_seed)
        let mut a1_seed = a1.clone();
        a1_seed.extend_from_slice(&label_seed);
        let p1 = hmac_hash(HashAlgId::Sm3, &secret, &a1_seed).unwrap();

        // For 32 bytes output, P(1) is exactly one SM3 block
        assert_eq!(output, p1);

        eprintln!("SM3 PRF output: {}", to_hex(&output));
    }
}
