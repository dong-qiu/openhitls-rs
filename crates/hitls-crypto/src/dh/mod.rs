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
    pub fn generate(params: &DhParams) -> Result<Self, CryptoError> {
        let p_minus_2 = params.p.sub(&BigNum::from_u64(2));
        let mut x = BigNum::random_range(&p_minus_2)?;
        if x < BigNum::from_u64(2) {
            x = BigNum::from_u64(2);
        }

        let y = params.g.mod_exp(&x, &params.p)?;

        Ok(DhKeyPair {
            private_key: x,
            public_key: y,
        })
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
}
