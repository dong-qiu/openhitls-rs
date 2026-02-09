//! SM2 elliptic curve public-key cryptography.
//!
//! SM2 is a Chinese national standard (GB/T 32918) for elliptic curve
//! cryptography. It supports digital signatures and public-key encryption,
//! based on the SM2P256V1 curve over a 256-bit prime field.

use hitls_bignum::BigNum;
use hitls_types::{CryptoError, EccCurveId};
use hitls_utils::asn1::{Decoder, Encoder};
use zeroize::Zeroize;

use crate::ecc::{EcGroup, EcPoint};
use crate::sm3::{Sm3, SM3_OUTPUT_SIZE};

/// Default user ID for SM2 (16-byte ASCII string per GB/T 32918).
const SM2_DEFAULT_ID: &[u8] = b"1234567812345678";

/// An SM2 key pair for signing, verification, encryption, and decryption.
#[derive(Clone)]
pub struct Sm2KeyPair {
    group: EcGroup,
    /// The private scalar d (1 <= d < n).
    private_key: BigNum,
    /// The public point P = d*G.
    public_key: EcPoint,
}

impl Drop for Sm2KeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl Sm2KeyPair {
    /// Generate a new SM2 key pair on the SM2P256V1 curve.
    pub fn generate() -> Result<Self, CryptoError> {
        let group = EcGroup::new(EccCurveId::Sm2Prime256)?;
        let n = group.order();

        let d = loop {
            let d = BigNum::random_range(n)?;
            if !d.is_zero() {
                break d;
            }
        };

        let p = group.scalar_mul_base(&d)?;

        Ok(Sm2KeyPair {
            group,
            private_key: d,
            public_key: p,
        })
    }

    /// Create an SM2 key pair from existing private key bytes (big-endian).
    pub fn from_private_key(private_key: &[u8]) -> Result<Self, CryptoError> {
        let group = EcGroup::new(EccCurveId::Sm2Prime256)?;
        let d = BigNum::from_bytes_be(private_key);

        if d.is_zero() || d >= *group.order() {
            return Err(CryptoError::EccInvalidPrivateKey);
        }

        let p = group.scalar_mul_base(&d)?;

        Ok(Sm2KeyPair {
            group,
            private_key: d,
            public_key: p,
        })
    }

    /// Create an SM2 verifier/encryptor from a public key (uncompressed encoding).
    pub fn from_public_key(public_key: &[u8]) -> Result<Self, CryptoError> {
        let group = EcGroup::new(EccCurveId::Sm2Prime256)?;
        let p = EcPoint::from_uncompressed(&group, public_key)?;

        Ok(Sm2KeyPair {
            group,
            private_key: BigNum::zero(),
            public_key: p,
        })
    }

    /// Sign a message using the default user ID.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.sign_with_id(SM2_DEFAULT_ID, message)
    }

    /// Sign a message with a custom user ID.
    pub fn sign_with_id(&self, user_id: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.private_key.is_zero() {
            return Err(CryptoError::EccInvalidPrivateKey);
        }

        let za = compute_za(user_id, &self.public_key, &self.group)?;

        // e = SM3(ZA || M)
        let mut hasher = Sm3::new();
        hasher.update(&za)?;
        hasher.update(message)?;
        let digest = hasher.finish()?;
        let e = BigNum::from_bytes_be(&digest);

        let n = self.group.order();
        let d = &self.private_key;

        for _ in 0..100 {
            let k = BigNum::random_range(n)?;
            if k.is_zero() {
                continue;
            }

            let kg = self.group.scalar_mul_base(&k)?;
            if kg.is_infinity() {
                continue;
            }

            // r = (e + x1) mod n
            let r = e.mod_add(kg.x(), n)?;
            if r.is_zero() {
                continue;
            }

            // Check r + k != n
            let r_plus_k = r.add(&k);
            if r_plus_k == *n {
                continue;
            }

            // s = (1+d)^(-1) * (k - r*d) mod n
            let d_plus_1 = d.mod_add(&BigNum::from_u64(1), n)?;
            let d_plus_1_inv = d_plus_1.mod_inv(n)?;
            let rd = r.mod_mul(d, n)?;
            // k - r*d mod n: add n to avoid underflow
            let k_minus_rd = k.mod_add(&n.sub(&rd), n)?;
            let s = d_plus_1_inv.mod_mul(&k_minus_rd, n)?;
            if s.is_zero() {
                continue;
            }

            return encode_der_signature(&r, &s);
        }

        Err(CryptoError::BnRandGenFail)
    }

    /// Verify a signature against a message using the default user ID.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        self.verify_with_id(SM2_DEFAULT_ID, message, signature)
    }

    /// Verify a signature with a custom user ID.
    pub fn verify_with_id(
        &self,
        user_id: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let (r, s) = decode_der_signature(signature)?;

        let n = self.group.order();
        let one = BigNum::from_u64(1);
        if r < one || r >= *n || s < one || s >= *n {
            return Ok(false);
        }

        let za = compute_za(user_id, &self.public_key, &self.group)?;

        // e = SM3(ZA || M)
        let mut hasher = Sm3::new();
        hasher.update(&za)?;
        hasher.update(message)?;
        let digest = hasher.finish()?;
        let e = BigNum::from_bytes_be(&digest);

        // t = (r + s) mod n
        let t = r.mod_add(&s, n)?;
        if t.is_zero() {
            return Ok(false);
        }

        // (x1', y1') = s*G + t*PA
        let point = self.group.scalar_mul_add(&s, &t, &self.public_key)?;
        if point.is_infinity() {
            return Ok(false);
        }

        // R' = (e + x1') mod n
        let r_prime = e.mod_add(point.x(), n)?;

        Ok(r_prime == r)
    }

    /// Encrypt plaintext using SM2 public key encryption.
    ///
    /// Returns ciphertext in new format: C1 || C3 || C2 (GB/T 32918.4-2016).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.is_empty() {
            return Err(CryptoError::InvalidArg);
        }

        let n = self.group.order();
        let fs = self.group.field_size();

        for _ in 0..100 {
            let k = BigNum::random_range(n)?;
            if k.is_zero() {
                continue;
            }

            // C1 = k * G
            let c1_point = self.group.scalar_mul_base(&k)?;
            if c1_point.is_infinity() {
                continue;
            }
            let c1 = c1_point.to_uncompressed(&self.group)?;

            // (x2, y2) = k * PB
            let s_point = self.group.scalar_mul(&k, &self.public_key)?;
            if s_point.is_infinity() {
                continue;
            }

            let x2 = s_point.x().to_bytes_be_padded(fs)?;
            let y2 = s_point.y().to_bytes_be_padded(fs)?;

            // t = KDF(x2 || y2, len)
            let t = sm2_kdf(&x2, &y2, plaintext.len())?;
            if t.iter().all(|&b| b == 0) {
                continue;
            }

            // C2 = M XOR t
            let mut c2 = vec![0u8; plaintext.len()];
            for i in 0..plaintext.len() {
                c2[i] = plaintext[i] ^ t[i];
            }

            // C3 = SM3(x2 || M || y2)
            let mut hasher = Sm3::new();
            hasher.update(&x2)?;
            hasher.update(plaintext)?;
            hasher.update(&y2)?;
            let c3 = hasher.finish()?;

            // Output: C1 || C3 || C2
            let mut ciphertext = Vec::with_capacity(c1.len() + SM3_OUTPUT_SIZE + c2.len());
            ciphertext.extend_from_slice(&c1);
            ciphertext.extend_from_slice(&c3);
            ciphertext.extend_from_slice(&c2);

            return Ok(ciphertext);
        }

        Err(CryptoError::BnRandGenFail)
    }

    /// Decrypt ciphertext using SM2 private key.
    ///
    /// Expects new format: C1 || C3 || C2.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.private_key.is_zero() {
            return Err(CryptoError::EccInvalidPrivateKey);
        }

        let fs = self.group.field_size();
        let c1_len = 1 + 2 * fs; // 0x04 || x || y

        if ciphertext.len() < c1_len + SM3_OUTPUT_SIZE + 1 {
            return Err(CryptoError::Sm2DecryptFail);
        }

        let c1_bytes = &ciphertext[..c1_len];
        let c3 = &ciphertext[c1_len..c1_len + SM3_OUTPUT_SIZE];
        let c2 = &ciphertext[c1_len + SM3_OUTPUT_SIZE..];

        let c1_point = EcPoint::from_uncompressed(&self.group, c1_bytes)?;

        // (x2, y2) = dB * C1
        let s_point = self.group.scalar_mul(&self.private_key, &c1_point)?;
        if s_point.is_infinity() {
            return Err(CryptoError::Sm2DecryptFail);
        }

        let x2 = s_point.x().to_bytes_be_padded(fs)?;
        let y2 = s_point.y().to_bytes_be_padded(fs)?;

        // t = KDF(x2 || y2, len(C2))
        let t = sm2_kdf(&x2, &y2, c2.len())?;

        // M = C2 XOR t
        let mut plaintext = vec![0u8; c2.len()];
        for i in 0..c2.len() {
            plaintext[i] = c2[i] ^ t[i];
        }

        // u = SM3(x2 || M || y2)
        let mut hasher = Sm3::new();
        hasher.update(&x2)?;
        hasher.update(&plaintext)?;
        hasher.update(&y2)?;
        let u = hasher.finish()?;

        // Constant-time comparison
        use subtle::ConstantTimeEq;
        if u.ct_eq(c3).into() {
            Ok(plaintext)
        } else {
            Err(CryptoError::Sm2DecryptFail)
        }
    }

    /// Return the public key in uncompressed encoding.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.public_key.to_uncompressed(&self.group)
    }

    /// Return the private key as 32-byte big-endian.
    pub fn private_key_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        if self.private_key.is_zero() {
            return Err(CryptoError::EccInvalidPrivateKey);
        }
        let mut bytes = self.private_key.to_bytes_be();
        // Pad to 32 bytes for SM2P256
        while bytes.len() < 32 {
            bytes.insert(0, 0);
        }
        Ok(bytes)
    }
}

/// Compute ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA).
fn compute_za(
    user_id: &[u8],
    public_key: &EcPoint,
    group: &EcGroup,
) -> Result<[u8; SM3_OUTPUT_SIZE], CryptoError> {
    let params = group.params();
    let fs = group.field_size();

    let mut hasher = Sm3::new();

    // ENTLA: bit length of IDA as 2-byte big-endian
    let entla = (user_id.len() * 8) as u16;
    hasher.update(&entla.to_be_bytes())?;

    // IDA
    hasher.update(user_id)?;

    // Curve parameters: a, b, xG, yG
    hasher.update(&params.a.to_bytes_be_padded(fs)?)?;
    hasher.update(&params.b.to_bytes_be_padded(fs)?)?;
    hasher.update(&params.gx.to_bytes_be_padded(fs)?)?;
    hasher.update(&params.gy.to_bytes_be_padded(fs)?)?;

    // Public key coordinates: xA, yA
    hasher.update(&public_key.x().to_bytes_be_padded(fs)?)?;
    hasher.update(&public_key.y().to_bytes_be_padded(fs)?)?;

    hasher.finish()
}

/// SM2 Key Derivation Function (GB/T 32918.4 Section 5.4.3).
fn sm2_kdf(x2: &[u8], y2: &[u8], klen: usize) -> Result<Vec<u8>, CryptoError> {
    let mut output = Vec::with_capacity(klen);
    let mut counter: u32 = 1;

    while output.len() < klen {
        let mut hasher = Sm3::new();
        hasher.update(x2)?;
        hasher.update(y2)?;
        hasher.update(&counter.to_be_bytes())?;
        let digest = hasher.finish()?;
        output.extend_from_slice(&digest);
        counter += 1;
    }

    output.truncate(klen);
    Ok(output)
}

/// DER-encode an SM2 signature: SEQUENCE { INTEGER r, INTEGER s }.
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

/// DER-decode an SM2 signature.
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

    #[test]
    fn test_sm2_sign_verify() {
        let key = Sm2KeyPair::generate().unwrap();
        let message = b"SM2 signature test message";

        let sig = key.sign(message).unwrap();
        let valid = key.verify(message, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sm2_sign_verify_custom_id() {
        let key = Sm2KeyPair::generate().unwrap();
        let user_id = b"custom_user_id";
        let message = b"test message";

        let sig = key.sign_with_id(user_id, message).unwrap();
        let valid = key.verify_with_id(user_id, message, &sig).unwrap();
        assert!(valid);

        // Wrong ID should fail
        let wrong = key.verify_with_id(b"wrong_id", message, &sig).unwrap();
        assert!(!wrong);
    }

    #[test]
    fn test_sm2_tamper_detection() {
        let key = Sm2KeyPair::generate().unwrap();
        let message = b"original message";
        let sig = key.sign(message).unwrap();

        assert!(!key.verify(b"tampered message", &sig).unwrap());
    }

    #[test]
    fn test_sm2_public_key_only_verify() {
        let key = Sm2KeyPair::generate().unwrap();
        let message = b"verify with pubkey only";
        let sig = key.sign(message).unwrap();

        let verifier = Sm2KeyPair::from_public_key(&key.public_key_bytes().unwrap()).unwrap();
        assert!(verifier.verify(message, &sig).unwrap());
    }

    #[test]
    fn test_sm2_encrypt_decrypt() {
        let key = Sm2KeyPair::generate().unwrap();
        let plaintext = b"SM2 encryption test message";

        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), &decrypted[..]);
    }

    #[test]
    fn test_sm2_decrypt_tampered_fails() {
        let key = Sm2KeyPair::generate().unwrap();
        let plaintext = b"test message for tampering";

        let mut ciphertext = key.encrypt(plaintext).unwrap();
        // Tamper with the last byte of C2
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0x01;

        assert!(key.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_sm2_encrypt_decrypt_short() {
        let key = Sm2KeyPair::generate().unwrap();
        let plaintext = b"x"; // single byte

        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), &decrypted[..]);
    }
}
