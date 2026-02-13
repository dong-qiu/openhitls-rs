//! DH (Diffie-Hellman) key exchange over finite fields.
//!
//! Provides classic Diffie-Hellman key agreement using MODP groups as
//! defined in RFC 3526 and RFC 7919. Supports both predefined groups
//! (ffdhe2048, ffdhe3072, etc.) and custom parameters.

mod groups;

use hitls_bignum::BigNum;
use hitls_types::{CryptoError, DhParamId};
use zeroize::Zeroize;

/// Diffie-Hellman domain parameters (p, g).
#[derive(Debug, Clone)]
pub struct DhParams {
    /// The prime modulus p.
    p: BigNum,
    /// The generator g.
    g: BigNum,
}

impl DhParams {
    /// Create DH parameters from big-endian byte arrays for prime and generator.
    pub fn new(p: &[u8], g: &[u8]) -> Result<Self, CryptoError> {
        if p.is_empty() || g.is_empty() {
            return Err(CryptoError::InvalidArg);
        }

        let p_bn = BigNum::from_bytes_be(p);
        let g_bn = BigNum::from_bytes_be(g);

        // Basic validation: p must be > 2 and odd, g must be > 1
        if p_bn.bit_len() < 2 || p_bn.is_even() {
            return Err(CryptoError::InvalidArg);
        }
        if g_bn <= BigNum::from_u64(1) {
            return Err(CryptoError::InvalidArg);
        }

        Ok(DhParams { p: p_bn, g: g_bn })
    }

    /// Create DH parameters from a predefined RFC 7919 group.
    pub fn from_group(id: DhParamId) -> Result<Self, CryptoError> {
        match groups::get_ffdhe_params(id) {
            Some((p, g)) => Ok(DhParams { p, g }),
            None => Err(CryptoError::InvalidArg),
        }
    }

    /// Return the size of the prime in bytes.
    pub fn prime_size(&self) -> usize {
        self.p.bit_len().div_ceil(8)
    }

    /// Return the prime modulus p as big-endian bytes.
    pub fn p_bytes(&self) -> Vec<u8> {
        self.p.to_bytes_be()
    }

    /// Return the generator g as big-endian bytes.
    pub fn g_bytes(&self) -> Vec<u8> {
        self.g.to_bytes_be()
    }
}

/// A Diffie-Hellman key pair.
#[derive(Clone)]
pub struct DhKeyPair {
    /// The private exponent x.
    private_key: BigNum,
    /// The public value y = g^x mod p.
    public_key: BigNum,
}

impl Drop for DhKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl DhKeyPair {
    /// Generate a new DH key pair from the given parameters.
    ///
    /// Private key x is random in [2, p-2], public key y = g^x mod p.
    /// Retries if y falls outside the valid range [2, p-2].
    pub fn generate(params: &DhParams) -> Result<Self, CryptoError> {
        let two = BigNum::from_u64(2);
        let p_minus_1 = params.p.sub(&BigNum::from_u64(1));
        let p_minus_2 = params.p.sub(&two);

        for _ in 0..100 {
            let mut x = BigNum::random_range(&p_minus_2)?;
            if x < two {
                x = BigNum::from_u64(2);
            }

            let y = params.g.mod_exp(&x, &params.p)?;

            // Ensure y is in valid range [2, p-2] (reject 0, 1, p-1)
            if y > BigNum::from_u64(1) && y < p_minus_1 {
                return Ok(DhKeyPair {
                    private_key: x,
                    public_key: y,
                });
            }
        }

        Err(CryptoError::BnRandGenFail)
    }

    /// Compute the shared secret from the peer's public value.
    ///
    /// Returns s = peer_public^x mod p in big-endian, padded to prime_size.
    pub fn compute_shared_secret(
        &self,
        params: &DhParams,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let peer_pub = BigNum::from_bytes_be(peer_public_key);

        // Validate peer public key: 2 <= peer_pub <= p-2
        if peer_pub <= BigNum::from_u64(1) || peer_pub >= params.p.sub(&BigNum::from_u64(1)) {
            return Err(CryptoError::InvalidArg);
        }

        let shared = peer_pub.mod_exp(&self.private_key, &params.p)?;
        shared.to_bytes_be_padded(params.prime_size())
    }

    /// Return the public value in big-endian bytes, padded to prime_size.
    pub fn public_key_bytes(&self, params: &DhParams) -> Result<Vec<u8>, CryptoError> {
        self.public_key.to_bytes_be_padded(params.prime_size())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_ffdhe2048_key_exchange() {
        let params = DhParams::from_group(DhParamId::Rfc7919_2048).unwrap();

        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();

        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();

        let secret_alice = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let secret_bob = bob.compute_shared_secret(&params, &alice_pub).unwrap();

        assert_eq!(secret_alice, secret_bob);
        assert_eq!(secret_alice.len(), params.prime_size());
    }

    #[test]
    fn test_dh_custom_params() {
        // Small DH group for fast testing: p=23, g=5
        let params = DhParams::new(&[23], &[5]).unwrap();

        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();

        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();

        let secret_alice = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let secret_bob = bob.compute_shared_secret(&params, &alice_pub).unwrap();

        assert_eq!(secret_alice, secret_bob);
    }

    #[test]
    fn test_dh_from_group() {
        let params = DhParams::from_group(DhParamId::Rfc7919_2048).unwrap();
        assert_eq!(params.prime_size(), 256); // 2048 bits = 256 bytes

        let params3072 = DhParams::from_group(DhParamId::Rfc7919_3072).unwrap();
        assert_eq!(params3072.prime_size(), 384); // 3072 bits = 384 bytes
    }

    // --- All 13 DH groups: prime size validation ---

    #[test]
    fn test_all_groups_prime_sizes() {
        let cases: &[(DhParamId, usize)] = &[
            (DhParamId::Rfc2409_768, 96),    // 768 bits = 96 bytes
            (DhParamId::Rfc2409_1024, 128),  // 1024 bits = 128 bytes
            (DhParamId::Rfc3526_1536, 192),  // 1536 bits = 192 bytes
            (DhParamId::Rfc3526_2048, 256),  // 2048 bits = 256 bytes
            (DhParamId::Rfc3526_3072, 384),  // 3072 bits = 384 bytes
            (DhParamId::Rfc3526_4096, 512),  // 4096 bits = 512 bytes
            (DhParamId::Rfc3526_6144, 768),  // 6144 bits = 768 bytes
            (DhParamId::Rfc3526_8192, 1024), // 8192 bits = 1024 bytes
            (DhParamId::Rfc7919_2048, 256),
            (DhParamId::Rfc7919_3072, 384),
            (DhParamId::Rfc7919_4096, 512),
            (DhParamId::Rfc7919_6144, 768),
            (DhParamId::Rfc7919_8192, 1024),
        ];
        for &(id, expected_bytes) in cases {
            let params = DhParams::from_group(id)
                .unwrap_or_else(|e| panic!("from_group({id:?}) failed: {e}"));
            assert_eq!(
                params.prime_size(),
                expected_bytes,
                "prime size mismatch for {id:?}"
            );
            // All groups use g=2
            assert_eq!(
                params.g_bytes(),
                vec![2u8],
                "generator should be 2 for {id:?}"
            );
        }
    }

    // --- Key exchange roundtrip tests for RFC 2409 groups ---

    #[test]
    fn test_dh_rfc2409_768_key_exchange() {
        let params = DhParams::from_group(DhParamId::Rfc2409_768).unwrap();
        assert_eq!(params.prime_size(), 96);
        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();
        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();
        let sa = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let sb = bob.compute_shared_secret(&params, &alice_pub).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 96);
    }

    #[test]
    fn test_dh_rfc2409_1024_key_exchange() {
        let params = DhParams::from_group(DhParamId::Rfc2409_1024).unwrap();
        assert_eq!(params.prime_size(), 128);
        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();
        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();
        let sa = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let sb = bob.compute_shared_secret(&params, &alice_pub).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 128);
    }

    // --- Key exchange roundtrip tests for RFC 3526 groups ---

    #[test]
    fn test_dh_rfc3526_1536_key_exchange() {
        let params = DhParams::from_group(DhParamId::Rfc3526_1536).unwrap();
        assert_eq!(params.prime_size(), 192);
        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();
        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();
        let sa = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let sb = bob.compute_shared_secret(&params, &alice_pub).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 192);
    }

    #[test]
    fn test_dh_rfc3526_2048_key_exchange() {
        let params = DhParams::from_group(DhParamId::Rfc3526_2048).unwrap();
        assert_eq!(params.prime_size(), 256);
        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();
        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();
        let sa = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let sb = bob.compute_shared_secret(&params, &alice_pub).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 256);
    }

    #[test]
    fn test_dh_rfc3526_3072_key_exchange() {
        let params = DhParams::from_group(DhParamId::Rfc3526_3072).unwrap();
        assert_eq!(params.prime_size(), 384);
        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();
        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();
        let sa = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let sb = bob.compute_shared_secret(&params, &alice_pub).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 384);
    }

    #[test]
    #[ignore] // slow: 4096-bit modexp
    fn test_dh_rfc3526_4096_key_exchange() {
        let params = DhParams::from_group(DhParamId::Rfc3526_4096).unwrap();
        assert_eq!(params.prime_size(), 512);
        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();
        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();
        let sa = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let sb = bob.compute_shared_secret(&params, &alice_pub).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 512);
    }

    #[test]
    #[ignore] // slow: 6144-bit modexp
    fn test_dh_rfc3526_6144_key_exchange() {
        let params = DhParams::from_group(DhParamId::Rfc3526_6144).unwrap();
        assert_eq!(params.prime_size(), 768);
        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();
        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();
        let sa = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let sb = bob.compute_shared_secret(&params, &alice_pub).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 768);
    }

    #[test]
    #[ignore] // slow: 8192-bit modexp
    fn test_dh_rfc3526_8192_key_exchange() {
        let params = DhParams::from_group(DhParamId::Rfc3526_8192).unwrap();
        assert_eq!(params.prime_size(), 1024);
        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();
        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();
        let sa = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let sb = bob.compute_shared_secret(&params, &alice_pub).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 1024);
    }

    // --- Key exchange roundtrip tests for RFC 7919 groups ---

    #[test]
    fn test_dh_rfc7919_3072_key_exchange() {
        let params = DhParams::from_group(DhParamId::Rfc7919_3072).unwrap();
        assert_eq!(params.prime_size(), 384);
        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();
        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();
        let sa = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let sb = bob.compute_shared_secret(&params, &alice_pub).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 384);
    }

    #[test]
    #[ignore] // slow: 4096-bit modexp
    fn test_dh_rfc7919_4096_key_exchange() {
        let params = DhParams::from_group(DhParamId::Rfc7919_4096).unwrap();
        assert_eq!(params.prime_size(), 512);
        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();
        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();
        let sa = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let sb = bob.compute_shared_secret(&params, &alice_pub).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 512);
    }

    #[test]
    #[ignore] // slow: 6144-bit modexp
    fn test_dh_rfc7919_6144_key_exchange() {
        let params = DhParams::from_group(DhParamId::Rfc7919_6144).unwrap();
        assert_eq!(params.prime_size(), 768);
        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();
        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();
        let sa = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let sb = bob.compute_shared_secret(&params, &alice_pub).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 768);
    }

    #[test]
    #[ignore] // slow: 8192-bit modexp
    fn test_dh_rfc7919_8192_key_exchange() {
        let params = DhParams::from_group(DhParamId::Rfc7919_8192).unwrap();
        assert_eq!(params.prime_size(), 1024);
        let alice = DhKeyPair::generate(&params).unwrap();
        let bob = DhKeyPair::generate(&params).unwrap();
        let alice_pub = alice.public_key_bytes(&params).unwrap();
        let bob_pub = bob.public_key_bytes(&params).unwrap();
        let sa = alice.compute_shared_secret(&params, &bob_pub).unwrap();
        let sb = bob.compute_shared_secret(&params, &alice_pub).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 1024);
    }

    #[test]
    fn test_dh_invalid_peer_public_key() {
        let params = DhParams::from_group(DhParamId::Rfc7919_2048).unwrap();
        let alice = DhKeyPair::generate(&params).unwrap();
        // peer public key = 0 should be rejected
        let zero = vec![0u8; 256];
        assert!(alice.compute_shared_secret(&params, &zero).is_err());
        // peer public key = 1 should be rejected
        let mut one = vec![0u8; 256];
        one[255] = 1;
        assert!(alice.compute_shared_secret(&params, &one).is_err());
    }
}
