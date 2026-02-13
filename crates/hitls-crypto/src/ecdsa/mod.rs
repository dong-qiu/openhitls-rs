//! ECDSA (Elliptic Curve Digital Signature Algorithm) implementation.
//!
//! Provides ECDSA key generation, signing, and verification as defined in
//! FIPS 186-4 and ANSI X9.62. Operates over NIST P-256 and P-384 curves.

use hitls_bignum::BigNum;
use hitls_types::{CryptoError, EccCurveId};
use hitls_utils::asn1::{Decoder, Encoder};
use zeroize::Zeroize;

use crate::ecc::{EcGroup, EcPoint};

/// An ECDSA key pair for signing and verification.
#[derive(Clone)]
pub struct EcdsaKeyPair {
    group: EcGroup,
    /// The private scalar d (1 <= d < n).
    private_key: BigNum,
    /// The public point Q = d*G.
    public_key: EcPoint,
}

impl Drop for EcdsaKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl EcdsaKeyPair {
    /// Generate a new ECDSA key pair for the given curve.
    pub fn generate(curve_id: EccCurveId) -> Result<Self, CryptoError> {
        let group = EcGroup::new(curve_id)?;
        let n = group.order();

        // Generate random d in [1, n-1]
        let d = BigNum::random_range(n)?;
        let d = if d.is_zero() { BigNum::from_u64(1) } else { d };

        let q = group.scalar_mul_base(&d)?;

        Ok(EcdsaKeyPair {
            group,
            private_key: d,
            public_key: q,
        })
    }

    /// Create an ECDSA key pair from existing private key bytes.
    pub fn from_private_key(curve_id: EccCurveId, private_key: &[u8]) -> Result<Self, CryptoError> {
        let group = EcGroup::new(curve_id)?;
        let d = BigNum::from_bytes_be(private_key);

        if d.is_zero() || d >= *group.order() {
            return Err(CryptoError::EccInvalidPrivateKey);
        }

        let q = group.scalar_mul_base(&d)?;

        Ok(EcdsaKeyPair {
            group,
            private_key: d,
            public_key: q,
        })
    }

    /// Create an ECDSA verifier (public key only) from uncompressed point bytes.
    pub fn from_public_key(curve_id: EccCurveId, public_key: &[u8]) -> Result<Self, CryptoError> {
        let group = EcGroup::new(curve_id)?;
        let q = EcPoint::from_uncompressed(&group, public_key)?;

        Ok(EcdsaKeyPair {
            group,
            private_key: BigNum::zero(),
            public_key: q,
        })
    }

    /// Return the private key scalar as big-endian bytes.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.private_key.to_bytes_be()
    }

    /// Sign a message digest, returning the DER-encoded (r, s) signature.
    ///
    /// The digest should be the hash of the message (e.g., SHA-256 for P-256).
    pub fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.private_key.is_zero() {
            return Err(CryptoError::EccInvalidPrivateKey);
        }

        let n = self.group.order();
        let n_bits = n.bit_len();

        // Convert digest to integer, truncated to bit length of n
        let e = truncate_digest(digest, n_bits);

        // Retry loop for generating valid (r, s)
        for _ in 0..100 {
            // Generate random k in [1, n-1]
            let k = BigNum::random_range(n)?;
            if k.is_zero() {
                continue;
            }

            // (x1, _) = k * G
            let kg = self.group.scalar_mul_base(&k)?;
            if kg.is_infinity() {
                continue;
            }

            // r = x1 mod n
            let r = kg.x().mod_reduce(n)?;
            if r.is_zero() {
                continue;
            }

            // s = k^(-1) * (e + d*r) mod n
            let k_inv = k.mod_inv(n)?;
            let dr = self.private_key.mod_mul(&r, n)?;
            let e_plus_dr = e.mod_add(&dr, n)?;
            let s = k_inv.mod_mul(&e_plus_dr, n)?;
            if s.is_zero() {
                continue;
            }

            return encode_der_signature(&r, &s);
        }

        Err(CryptoError::BnRandGenFail)
    }

    /// Verify a DER-encoded signature against a message digest.
    pub fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let n = self.group.order();
        let n_bits = n.bit_len();

        // Decode DER signature
        let (r, s) = decode_der_signature(signature)?;

        // Check r, s in [1, n-1]
        let one = BigNum::from_u64(1);
        if r < one || r >= *n || s < one || s >= *n {
            return Ok(false);
        }

        // e = truncate(digest, bit_len(n))
        let e = truncate_digest(digest, n_bits);

        // w = s^(-1) mod n
        let w = match s.mod_inv(n) {
            Ok(w) => w,
            Err(_) => return Ok(false),
        };

        // u1 = e*w mod n, u2 = r*w mod n
        let u1 = e.mod_mul(&w, n)?;
        let u2 = r.mod_mul(&w, n)?;

        // (x1, y1) = u1*G + u2*Q
        let point = self.group.scalar_mul_add(&u1, &u2, &self.public_key)?;

        if point.is_infinity() {
            return Ok(false);
        }

        // Check x1 mod n == r
        let x1_mod_n = point.x().mod_reduce(n)?;
        Ok(x1_mod_n == r)
    }

    /// Return the public key in uncompressed point encoding.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.public_key.to_uncompressed(&self.group)
    }

    /// Return a reference to the public point.
    pub fn public_key(&self) -> &EcPoint {
        &self.public_key
    }

    /// Return the curve identifier.
    pub fn curve_id(&self) -> EccCurveId {
        self.group.curve_id()
    }
}

/// Truncate a message digest to the bit length of the curve order.
fn truncate_digest(digest: &[u8], n_bits: usize) -> BigNum {
    let e = BigNum::from_bytes_be(digest);
    let digest_bits = digest.len() * 8;
    if digest_bits > n_bits {
        e.shr(digest_bits - n_bits)
    } else {
        e
    }
}

/// DER-encode an ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }.
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

/// DER-decode an ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }.
fn decode_der_signature(data: &[u8]) -> Result<(BigNum, BigNum), CryptoError> {
    let mut decoder = Decoder::new(data);
    let mut seq = decoder.read_sequence()?;

    let r_bytes = seq.read_integer()?;
    let s_bytes = seq.read_integer()?;

    // Reject trailing data inside the SEQUENCE
    if !seq.is_empty() {
        return Err(CryptoError::EcdsaVerifyFail);
    }

    // Reject trailing data after the SEQUENCE
    if !decoder.is_empty() {
        return Err(CryptoError::EcdsaVerifyFail);
    }

    // Strip leading zeros (ASN.1 INTEGER may have a leading 0x00 for positive sign)
    let r = BigNum::from_bytes_be(r_bytes);
    let s = BigNum::from_bytes_be(s_bytes);

    Ok((r, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_sign_verify_p256() {
        let key = EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();

        // SHA-256("hello")
        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        let sig = key.sign(&digest).unwrap();
        let valid = key.verify(&digest, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_ecdsa_sign_verify_p384() {
        let key = EcdsaKeyPair::generate(EccCurveId::NistP384).unwrap();

        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        let sig = key.sign(&digest).unwrap();
        let valid = key.verify(&digest, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_ecdsa_tamper_detection() {
        let key = EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();

        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        let sig = key.sign(&digest).unwrap();

        // Tamper with digest
        let mut bad_digest = digest.clone();
        bad_digest[0] ^= 0x01;
        let invalid = key.verify(&bad_digest, &sig).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_ecdsa_verify_with_public_key_only() {
        let key = EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();
        let pub_bytes = key.public_key_bytes().unwrap();

        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        let sig = key.sign(&digest).unwrap();

        // Verify using public key only
        let verifier = EcdsaKeyPair::from_public_key(EccCurveId::NistP256, &pub_bytes).unwrap();
        let valid = verifier.verify(&digest, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_ecdsa_der_roundtrip() {
        let r = BigNum::from_bytes_be(&hex(
            "d73cd3722bae6cc0b39065bb4003d8ece1ef2f7a8a55bfd677234b0b3b902650",
        ));
        let s = BigNum::from_bytes_be(&hex(
            "8d5e4e04b9a95a4029e55cf8fd7c93d77abe41beab1a4c55dd23b3e06eeaf5e3",
        ));

        let der = encode_der_signature(&r, &s).unwrap();
        let (r2, s2) = decode_der_signature(&der).unwrap();
        assert_eq!(r, r2);
        assert_eq!(s, s2);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_ecdsa_sign_verify_p192() {
        let key = EcdsaKeyPair::generate(EccCurveId::NistP192).unwrap();
        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e");
        let sig = key.sign(&digest).unwrap();
        assert!(key.verify(&digest, &sig).unwrap());
    }

    #[test]
    fn test_ecdsa_sign_verify_p224() {
        let key = EcdsaKeyPair::generate(EccCurveId::NistP224).unwrap();
        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362");
        let sig = key.sign(&digest).unwrap();
        assert!(key.verify(&digest, &sig).unwrap());
    }

    #[test]
    fn test_ecdsa_sign_verify_p521() {
        let key = EcdsaKeyPair::generate(EccCurveId::NistP521).unwrap();
        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        let sig = key.sign(&digest).unwrap();
        assert!(key.verify(&digest, &sig).unwrap());
    }

    #[test]
    fn test_ecdsa_sign_verify_brainpool_p256r1() {
        let key = EcdsaKeyPair::generate(EccCurveId::BrainpoolP256r1).unwrap();
        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        let sig = key.sign(&digest).unwrap();
        assert!(key.verify(&digest, &sig).unwrap());
    }

    #[test]
    fn test_ecdsa_sign_verify_brainpool_p384r1() {
        let key = EcdsaKeyPair::generate(EccCurveId::BrainpoolP384r1).unwrap();
        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        let sig = key.sign(&digest).unwrap();
        assert!(key.verify(&digest, &sig).unwrap());
    }

    #[test]
    fn test_ecdsa_sign_verify_brainpool_p512r1() {
        let key = EcdsaKeyPair::generate(EccCurveId::BrainpoolP512r1).unwrap();
        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        let sig = key.sign(&digest).unwrap();
        assert!(key.verify(&digest, &sig).unwrap());
    }
}
