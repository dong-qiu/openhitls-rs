//! DSA (Digital Signature Algorithm) implementation.
//!
//! Provides DSA key generation, signing, and verification as defined in
//! FIPS 186-4. DSA operates over a prime-order subgroup of Z_p^* and
//! produces DER-encoded signatures consisting of (r, s) pairs.

use hitls_bignum::BigNum;
use hitls_types::CryptoError;
use hitls_utils::asn1::{Decoder, Encoder};
use zeroize::Zeroize;

/// DSA domain parameters (p, q, g).
#[derive(Debug, Clone)]
pub struct DsaParams {
    /// The prime modulus p.
    p: BigNum,
    /// The subgroup order q (prime divisor of p-1).
    q: BigNum,
    /// The generator g of the order-q subgroup.
    g: BigNum,
}

impl DsaParams {
    /// Create DSA parameters from big-endian byte arrays.
    pub fn new(p: &[u8], q: &[u8], g: &[u8]) -> Result<Self, CryptoError> {
        if p.is_empty() || q.is_empty() || g.is_empty() {
            return Err(CryptoError::InvalidArg);
        }

        let p_bn = BigNum::from_bytes_be(p);
        let q_bn = BigNum::from_bytes_be(q);
        let g_bn = BigNum::from_bytes_be(g);

        // Basic validation
        if p_bn.is_even() || p_bn.bit_len() < 2 {
            return Err(CryptoError::InvalidArg);
        }
        if q_bn.is_even() || q_bn.bit_len() < 2 {
            return Err(CryptoError::InvalidArg);
        }
        if g_bn <= BigNum::from_u64(1) || g_bn >= p_bn {
            return Err(CryptoError::InvalidArg);
        }

        Ok(DsaParams {
            p: p_bn,
            q: q_bn,
            g: g_bn,
        })
    }

    /// Return the bit length of p.
    pub fn p_bits(&self) -> usize {
        self.p.bit_len()
    }

    /// Return the bit length of q.
    pub fn q_bits(&self) -> usize {
        self.q.bit_len()
    }
}

/// A DSA key pair for signing and verification.
#[derive(Clone)]
pub struct DsaKeyPair {
    params: DsaParams,
    /// The private key x (1 <= x < q).
    private_key: BigNum,
    /// The public key y = g^x mod p.
    public_key: BigNum,
}

impl Drop for DsaKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl DsaKeyPair {
    /// Generate a new DSA key pair with the given parameters.
    pub fn generate(params: DsaParams) -> Result<Self, CryptoError> {
        // x = random in [1, q-1]
        let x = loop {
            let x = BigNum::random_range(&params.q)?;
            if !x.is_zero() {
                break x;
            }
        };

        // y = g^x mod p
        let y = params.g.mod_exp(&x, &params.p)?;

        Ok(DsaKeyPair {
            params,
            private_key: x,
            public_key: y,
        })
    }

    /// Create a DSA key pair from existing private key bytes.
    pub fn from_private_key(params: DsaParams, private_key: &[u8]) -> Result<Self, CryptoError> {
        let x = BigNum::from_bytes_be(private_key);

        if x.is_zero() || x >= params.q {
            return Err(CryptoError::InvalidArg);
        }

        let y = params.g.mod_exp(&x, &params.p)?;

        Ok(DsaKeyPair {
            params,
            private_key: x,
            public_key: y,
        })
    }

    /// Create a DSA verifier from a public key (verify-only).
    pub fn from_public_key(params: DsaParams, public_key: &[u8]) -> Result<Self, CryptoError> {
        let y = BigNum::from_bytes_be(public_key);

        if y <= BigNum::from_u64(1) || y >= params.p {
            return Err(CryptoError::InvalidArg);
        }

        Ok(DsaKeyPair {
            params,
            private_key: BigNum::zero(),
            public_key: y,
        })
    }

    /// Sign a message digest, returning a DER-encoded (r, s) signature.
    pub fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.private_key.is_zero() {
            return Err(CryptoError::InvalidArg);
        }

        let q = &self.params.q;
        let p = &self.params.p;
        let g = &self.params.g;
        let x = &self.private_key;

        let e = digest_to_bignum(digest, q.bit_len());

        for _ in 0..100 {
            // k = random in [1, q-1]
            let k = BigNum::random_range(q)?;
            if k.is_zero() {
                continue;
            }

            // r = (g^k mod p) mod q
            let g_k = g.mod_exp(&k, p)?;
            let r = g_k.mod_reduce(q)?;
            if r.is_zero() {
                continue;
            }

            // s = k^(-1) * (e + x*r) mod q
            let k_inv = k.mod_inv(q)?;
            let xr = x.mod_mul(&r, q)?;
            let e_plus_xr = e.mod_add(&xr, q)?;
            let s = k_inv.mod_mul(&e_plus_xr, q)?;
            if s.is_zero() {
                continue;
            }

            return encode_der_signature(&r, &s);
        }

        Err(CryptoError::BnRandGenFail)
    }

    /// Verify a DER-encoded signature against a message digest.
    pub fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let q = &self.params.q;
        let p = &self.params.p;
        let g = &self.params.g;
        let y = &self.public_key;

        let (r, s) = decode_der_signature(signature)?;

        let one = BigNum::from_u64(1);
        if r < one || r >= *q || s < one || s >= *q {
            return Ok(false);
        }

        let e = digest_to_bignum(digest, q.bit_len());

        // w = s^(-1) mod q
        let w = s.mod_inv(q)?;

        // u1 = e*w mod q, u2 = r*w mod q
        let u1 = e.mod_mul(&w, q)?;
        let u2 = r.mod_mul(&w, q)?;

        // v = (g^u1 * y^u2 mod p) mod q
        let g_u1 = g.mod_exp(&u1, p)?;
        let y_u2 = y.mod_exp(&u2, p)?;
        let product = g_u1.mod_mul(&y_u2, p)?;
        let v = product.mod_reduce(q)?;

        Ok(v == r)
    }

    /// Return the public key in big-endian bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes_be()
    }
}

/// Truncate digest to match the bit length of q.
fn digest_to_bignum(digest: &[u8], q_bits: usize) -> BigNum {
    let e = BigNum::from_bytes_be(digest);
    let digest_bits = digest.len() * 8;
    if digest_bits > q_bits {
        e.shr(digest_bits - q_bits)
    } else {
        e
    }
}

/// DER-encode a DSA/ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }.
fn encode_der_signature(r: &BigNum, s: &BigNum) -> Result<Vec<u8>, CryptoError> {
    let r_bytes = r.to_bytes_be();
    let s_bytes = s.to_bytes_be();

    let mut inner = Encoder::new();
    inner.write_integer(&r_bytes).write_integer(&s_bytes);
    let inner_bytes = inner.finish();

    let mut outer = Encoder::new();
    outer.write_sequence(&inner_bytes);
    Ok(outer.finish())
}

/// DER-decode a DSA/ECDSA signature.
fn decode_der_signature(data: &[u8]) -> Result<(BigNum, BigNum), CryptoError> {
    let mut decoder = Decoder::new(data);
    let mut seq = decoder
        .read_sequence()
        .map_err(|_| CryptoError::InvalidArg)?;

    let r_bytes = seq.read_integer().map_err(|_| CryptoError::InvalidArg)?;
    let s_bytes = seq.read_integer().map_err(|_| CryptoError::InvalidArg)?;

    Ok((
        BigNum::from_bytes_be(r_bytes),
        BigNum::from_bytes_be(s_bytes),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create small DSA parameters for fast testing.
    /// p = 23, q = 11, g = 4 (4^11 mod 23 = 1, so g has order 11 mod 23)
    fn small_params() -> DsaParams {
        DsaParams::new(&[23], &[11], &[4]).unwrap()
    }

    #[test]
    fn test_dsa_sign_verify() {
        let params = small_params();
        let key = DsaKeyPair::generate(params).unwrap();

        let digest = [0x42u8; 32]; // simulated SHA-256 digest
        let sig = key.sign(&digest).unwrap();
        let valid = key.verify(&digest, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_dsa_tamper_detection() {
        let params = small_params();
        let key = DsaKeyPair::generate(params).unwrap();

        // q=11 has bit_len=4, so digest_to_bignum shifts 1-byte digests right by 4.
        // The top nibble survives; use values 0x10..0x90 so e ∈ {1..9}.
        let digest = [0x10]; // e = 1 after truncation
        let sig = key.sign(&digest).unwrap();

        // With small q=11, a single tampered digest has ~1/11 chance of
        // accidentally verifying. Test multiple for statistical reliability.
        let tampered: &[&[u8]] = &[&[0x20], &[0x30], &[0x50], &[0x90]];
        let rejects = tampered
            .iter()
            .filter(|t| !key.verify(t, &sig).unwrap())
            .count();
        assert!(rejects > 0, "at least one tampered digest must fail");
    }

    #[test]
    fn test_dsa_public_key_only_verify() {
        let params = small_params();
        let key = DsaKeyPair::generate(params.clone()).unwrap();

        let digest = [0xABu8; 32];
        let sig = key.sign(&digest).unwrap();

        let verifier = DsaKeyPair::from_public_key(params, &key.public_key_bytes()).unwrap();
        assert!(verifier.verify(&digest, &sig).unwrap());
    }

    #[test]
    fn test_dsa_der_roundtrip() {
        let r = BigNum::from_u64(12345);
        let s = BigNum::from_u64(67890);

        let encoded = encode_der_signature(&r, &s).unwrap();
        let (r2, s2) = decode_der_signature(&encoded).unwrap();

        assert_eq!(r, r2);
        assert_eq!(s, s2);
    }

    #[test]
    fn test_dsa_invalid_params() {
        // g must be > 1
        assert!(DsaParams::new(&[23], &[11], &[1]).is_err());
        // p must be odd
        assert!(DsaParams::new(&[24], &[11], &[4]).is_err());
    }

    #[test]
    fn test_dsa_verify_with_wrong_key() {
        let params = small_params();
        // Two keypairs with explicit private keys: x=3 and x=7
        let kp1 = DsaKeyPair::from_private_key(params.clone(), &[3]).unwrap();
        let kp2 = DsaKeyPair::from_private_key(params, &[7]).unwrap();

        let digest = [0x50]; // e after truncation: non-zero
        let sig = kp1.sign(&digest).unwrap();
        // Verify with wrong key — should fail (possibly Ok(false))
        let result = kp2.verify(&digest, &sig).unwrap();
        assert!(!result, "signature verified with wrong key");
    }

    #[test]
    fn test_dsa_sign_with_public_only_key() {
        let params = small_params();
        let kp = DsaKeyPair::generate(params.clone()).unwrap();
        let pub_bytes = kp.public_key_bytes();

        // Create a verify-only key (no private key)
        let verifier = DsaKeyPair::from_public_key(params, &pub_bytes).unwrap();
        // Signing should fail — private_key is zero
        let result = verifier.sign(&[0x42]);
        assert!(result.is_err(), "signing with public-only key should fail");
    }

    #[test]
    fn test_dsa_different_digest_verify() {
        let params = small_params();
        let kp = DsaKeyPair::from_private_key(params, &[5]).unwrap();

        let digest1 = [0x10]; // e=1 after truncation
        let sig = kp.sign(&digest1).unwrap();

        // Verify with a different digest
        let digest2 = [0x40]; // e=4 after truncation
        let result = kp.verify(&digest2, &sig).unwrap();
        assert!(!result, "signature should not verify with different digest");
    }
}
