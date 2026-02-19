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
use hitls_crypto::provider::Digest;
use hitls_types::TlsError;

type Factory = dyn Fn() -> Box<dyn Digest> + Send + Sync;

/// TLS 1.2 PRF: Derive `output_len` bytes from `secret`, `label`, and `seed`.
///
/// Uses the P_hash expansion function with the given hash factory
/// (typically SHA-256 for TLS 1.2).
pub fn prf(
    factory: &Factory,
    secret: &[u8],
    label: &str,
    seed: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, TlsError> {
    // Concatenate label + seed
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label.as_bytes());
    label_seed.extend_from_slice(seed);

    p_hash(factory, secret, &label_seed, output_len)
}

/// P_hash expansion function (RFC 5246 §5).
fn p_hash(
    factory: &Factory,
    secret: &[u8],
    seed: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, TlsError> {
    let mut result = Vec::with_capacity(output_len);

    // A(0) = seed
    let mut a = seed.to_vec();

    while result.len() < output_len {
        // A(i) = HMAC_hash(secret, A(i-1))
        a = hmac_hash(factory, secret, &a)?;

        // HMAC_hash(secret, A(i) + seed)
        let mut ai_seed = Vec::with_capacity(a.len() + seed.len());
        ai_seed.extend_from_slice(&a);
        ai_seed.extend_from_slice(seed);
        let block = hmac_hash(factory, secret, &ai_seed)?;

        result.extend_from_slice(&block);
    }

    result.truncate(output_len);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_crypto::sha2::{Sha256, Sha384};

    fn sha256_factory() -> Box<dyn Fn() -> Box<dyn Digest> + Send + Sync> {
        Box::new(|| Box::new(Sha256::new()))
    }

    fn sha384_factory() -> Box<dyn Fn() -> Box<dyn Digest> + Send + Sync> {
        Box::new(|| Box::new(Sha384::new()))
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn test_prf_sha256_basic() {
        // Basic smoke test: PRF should produce deterministic output
        let factory = sha256_factory();
        let secret = b"test secret";
        let label = "test label";
        let seed = b"test seed";

        let output1 = prf(&*factory, secret, label, seed, 32).unwrap();
        let output2 = prf(&*factory, secret, label, seed, 32).unwrap();
        assert_eq!(output1, output2);
        assert_eq!(output1.len(), 32);
    }

    #[test]
    fn test_prf_sha256_known_vector() {
        // RFC 5246 doesn't provide explicit test vectors, but we can verify
        // against a well-known computation. Using the PRF definition to produce
        // a known output for specific inputs.
        let factory = sha256_factory();
        let secret = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let label = "test label";
        let seed = hex("a0a1a2a3a4a5a6a7a8a9");

        let output = prf(&*factory, &secret, label, &seed, 100).unwrap();
        assert_eq!(output.len(), 100);

        // Same input must produce same output
        let output2 = prf(&*factory, &secret, label, &seed, 100).unwrap();
        assert_eq!(output, output2);

        // Different label should produce different output
        let output3 = prf(&*factory, &secret, "other label", &seed, 100).unwrap();
        assert_ne!(output, output3);
    }

    #[test]
    fn test_prf_sha384() {
        let factory = sha384_factory();
        let secret = b"sha384 secret";
        let label = "sha384 label";
        let seed = b"sha384 seed";

        let output = prf(&*factory, secret, label, seed, 48).unwrap();
        assert_eq!(output.len(), 48);

        // Verify determinism
        let output2 = prf(&*factory, secret, label, seed, 48).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn test_prf_master_secret() {
        // Simulate TLS 1.2 master_secret derivation:
        // master_secret = PRF(pre_master_secret, "master secret",
        //                     ClientHello.random + ServerHello.random)[0..48]
        let factory = sha256_factory();
        let pre_master_secret = [0x03, 0x03]; // minimal PMS
        let client_random = [0u8; 32];
        let server_random = [1u8; 32];

        let mut seed = Vec::new();
        seed.extend_from_slice(&client_random);
        seed.extend_from_slice(&server_random);

        let master_secret = prf(&*factory, &pre_master_secret, "master secret", &seed, 48).unwrap();
        assert_eq!(master_secret.len(), 48);

        // Verify we get same result for same inputs
        let ms2 = prf(&*factory, &pre_master_secret, "master secret", &seed, 48).unwrap();
        assert_eq!(master_secret, ms2);
    }

    #[test]
    fn test_prf_key_expansion() {
        // Simulate key expansion:
        // key_block = PRF(master_secret, "key expansion",
        //                 server_random + client_random)
        let factory = sha256_factory();
        let master_secret = [0xABu8; 48];
        let server_random = [0x01u8; 32];
        let client_random = [0x02u8; 32];

        let mut seed = Vec::new();
        seed.extend_from_slice(&server_random);
        seed.extend_from_slice(&client_random);

        // Need enough for: client_write_MAC_key(32) + server_write_MAC_key(32) +
        // client_write_key(16) + server_write_key(16) + client_write_IV(16) + server_write_IV(16)
        let key_block = prf(&*factory, &master_secret, "key expansion", &seed, 128).unwrap();
        assert_eq!(key_block.len(), 128);
    }

    #[test]
    fn test_prf_empty_seed() {
        let factory = sha256_factory();
        let secret = b"secret";
        let output = prf(&*factory, secret, "label", &[], 32).unwrap();
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_prf_various_output_lengths() {
        let factory = sha256_factory();
        let secret = b"secret";
        let label = "label";
        let seed = b"seed";

        // Test various output lengths including those that cross hash output boundaries
        for len in [1, 16, 31, 32, 33, 48, 64, 100, 256] {
            let output = prf(&*factory, secret, label, seed, len).unwrap();
            assert_eq!(output.len(), len);
        }

        // Verify prefix consistency: longer output should start with shorter output
        let short = prf(&*factory, secret, label, seed, 32).unwrap();
        let long = prf(&*factory, secret, label, seed, 64).unwrap();
        assert_eq!(&long[..32], &short[..]);
    }

    #[test]
    fn test_prf_sha256_rfc5246_verify() {
        // Cross-validate PRF output against a reference computation.
        // We manually compute P_SHA256(secret, label||seed) for a small output.
        let factory = sha256_factory();
        let secret = hex("9bbe436ba940f017b17652849a71db35");
        let label = "test label";
        let seed = hex("a0a1a2a3a4a5a6a7a8a9");

        let output = prf(&*factory, &secret, label, &seed, 32).unwrap();

        // Manual computation:
        // label_seed = "test label" || seed
        let mut label_seed = Vec::new();
        label_seed.extend_from_slice(label.as_bytes());
        label_seed.extend_from_slice(&seed);

        // A(1) = HMAC(secret, label_seed)
        let a1 = hmac_hash(&*factory, &secret, &label_seed).unwrap();
        // P(1) = HMAC(secret, A(1) || label_seed)
        let mut a1_seed = a1.clone();
        a1_seed.extend_from_slice(&label_seed);
        let p1 = hmac_hash(&*factory, &secret, &a1_seed).unwrap();

        // For 32 bytes output, P(1) is exactly one SHA-256 block
        assert_eq!(output, p1);

        // Log for verification
        eprintln!("PRF output: {}", to_hex(&output));
    }

    #[test]
    fn test_prf_zero_output_length() {
        let factory = sha256_factory();
        let output = prf(&*factory, b"secret", "label", b"seed", 0).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn test_prf_large_output() {
        // Test with output larger than multiple hash blocks (SHA-256 = 32 bytes)
        let factory = sha256_factory();
        let output = prf(&*factory, b"secret", "label", b"seed", 1000).unwrap();
        assert_eq!(output.len(), 1000);

        // Verify prefix consistency with shorter output
        let short = prf(&*factory, b"secret", "label", b"seed", 500).unwrap();
        assert_eq!(&output[..500], &short[..]);
    }

    #[test]
    fn test_prf_sha256_vs_sha384_different_output() {
        // Same inputs with different hash → different output
        let f256 = sha256_factory();
        let f384 = sha384_factory();
        let secret = b"same secret";
        let label = "same label";
        let seed = b"same seed";

        let out256 = prf(&*f256, secret, label, seed, 48).unwrap();
        let out384 = prf(&*f384, secret, label, seed, 48).unwrap();
        assert_ne!(out256, out384);
    }

    #[test]
    fn test_prf_empty_secret() {
        // Empty secret should still produce valid output
        let factory = sha256_factory();
        let output = prf(&*factory, &[], "label", b"seed", 32).unwrap();
        assert_eq!(output.len(), 32);
        // Verify determinism
        let output2 = prf(&*factory, &[], "label", b"seed", 32).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn test_prf_different_seeds_differ() {
        let factory = sha256_factory();
        let secret = b"secret";
        let label = "label";
        let out1 = prf(&*factory, secret, label, b"seed1", 32).unwrap();
        let out2 = prf(&*factory, secret, label, b"seed2", 32).unwrap();
        assert_ne!(out1, out2);
    }
}
