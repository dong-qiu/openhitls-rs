//! Ed448 digital signature algorithm (RFC 8032 §5.2).
//!
//! Ed448 (Goldilocks) is an EdDSA signature scheme using SHAKE256 and Curve448,
//! providing ~224-bit security. It uses the dom4 prefix for all operations.

use hitls_bignum::BigNum;
use hitls_types::CryptoError;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::curve448::edwards::{point_add, scalar_mul, scalar_mul_base, GeExtended448, L_BYTES_LE};
use crate::sha3::Shake256;

/// Ed448 key size in bytes (57-byte public key, 57-byte seed).
pub const ED448_KEY_SIZE: usize = 57;

/// Ed448 signature size in bytes (R || S, 57 + 57 = 114).
pub const ED448_SIGNATURE_SIZE: usize = 114;

/// An Ed448 key pair for signing and verification.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Ed448KeyPair {
    /// The 57-byte private seed.
    private_key: [u8; ED448_KEY_SIZE],
    /// The 57-byte public key.
    public_key: [u8; ED448_KEY_SIZE],
}

impl Ed448KeyPair {
    /// Generate a new random Ed448 key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; ED448_KEY_SIZE];
        getrandom::getrandom(&mut seed).map_err(|_| CryptoError::BnRandGenFail)?;
        Self::from_seed(&seed)
    }

    /// Return a reference to the 57-byte private seed.
    pub fn seed(&self) -> &[u8; ED448_KEY_SIZE] {
        &self.private_key
    }

    /// Create an Ed448 key pair from a 57-byte private seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        if seed.len() != 57 {
            return Err(CryptoError::InvalidArg);
        }

        let mut private_key = [0u8; 57];
        private_key.copy_from_slice(seed);

        // Derive public key: SHAKE256(seed, 114) → first 57 bytes = scalar (clamped)
        let h = shake256_114(&private_key);
        let mut a = [0u8; 57];
        a.copy_from_slice(&h[..57]);
        clamp(&mut a);

        let public_point = scalar_mul_base(&a);
        let public_key = public_point.to_bytes();

        Ok(Ed448KeyPair {
            private_key,
            public_key,
        })
    }

    /// Create an Ed448 verifier from a 57-byte public key (verify-only).
    pub fn from_public_key(public_key: &[u8]) -> Result<Self, CryptoError> {
        if public_key.len() != 57 {
            return Err(CryptoError::InvalidArg);
        }

        // Validate the public key can be decoded as a point
        let mut pk = [0u8; 57];
        pk.copy_from_slice(public_key);
        GeExtended448::from_bytes(&pk)?;

        Ok(Ed448KeyPair {
            private_key: [0u8; 57],
            public_key: pk,
        })
    }

    /// Sign a message, returning the 114-byte signature.
    ///
    /// Implements RFC 8032 §5.2.6 with empty context.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; ED448_SIGNATURE_SIZE], CryptoError> {
        self.sign_with_context(message, &[])
    }

    /// Sign a message with an explicit context string (0..255 bytes).
    pub fn sign_with_context(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> Result<[u8; ED448_SIGNATURE_SIZE], CryptoError> {
        if self.private_key == [0u8; 57] {
            return Err(CryptoError::EccInvalidPrivateKey);
        }
        if context.len() > 255 {
            return Err(CryptoError::InvalidArg);
        }

        // Step 1: h = SHAKE256(seed, 114); a = clamp(h[0..57]); prefix = h[57..114]
        let h = shake256_114(&self.private_key);
        let mut a = [0u8; 57];
        a.copy_from_slice(&h[..57]);
        clamp(&mut a);
        let prefix = &h[57..114];

        let dom4 = dom4_prefix(0, context); // flag=0 for Ed448

        // Step 2: r = SHAKE256(dom4 || prefix || message, 114) mod L
        let mut hasher = Shake256::new();
        hasher.update(&dom4).map_err(|_| CryptoError::InvalidArg)?;
        hasher.update(prefix).map_err(|_| CryptoError::InvalidArg)?;
        hasher
            .update(message)
            .map_err(|_| CryptoError::InvalidArg)?;
        let r_hash = hasher.squeeze(114).map_err(|_| CryptoError::InvalidArg)?;
        let r_scalar = reduce_scalar_wide_114(&r_hash);

        // Step 3: R = r * B
        let r_point = scalar_mul_base(&r_scalar);
        let r_bytes = r_point.to_bytes();

        // Step 4: k = SHAKE256(dom4 || R || public_key || message, 114) mod L
        let mut hasher = Shake256::new();
        hasher.update(&dom4).map_err(|_| CryptoError::InvalidArg)?;
        hasher
            .update(&r_bytes)
            .map_err(|_| CryptoError::InvalidArg)?;
        hasher
            .update(&self.public_key)
            .map_err(|_| CryptoError::InvalidArg)?;
        hasher
            .update(message)
            .map_err(|_| CryptoError::InvalidArg)?;
        let k_hash = hasher.squeeze(114).map_err(|_| CryptoError::InvalidArg)?;
        let k_scalar = reduce_scalar_wide_114(&k_hash);

        // Step 5: S = (r + k * a) mod L
        let s_scalar = scalar_muladd(&k_scalar, &a, &r_scalar);

        // Step 6: signature = R(57) || S(57)
        let mut sig = [0u8; 114];
        sig[..57].copy_from_slice(&r_bytes);
        sig[57..].copy_from_slice(&s_scalar);
        Ok(sig)
    }

    /// Verify a signature against a message.
    ///
    /// Implements RFC 8032 §5.2.7 with empty context.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        self.verify_with_context(message, signature, &[])
    }

    /// Verify a signature with an explicit context string.
    pub fn verify_with_context(
        &self,
        message: &[u8],
        signature: &[u8],
        context: &[u8],
    ) -> Result<bool, CryptoError> {
        if signature.len() != 114 {
            return Ok(false);
        }
        if context.len() > 255 {
            return Err(CryptoError::InvalidArg);
        }

        // Parse signature: R = sig[0..57], S = sig[57..114]
        let mut r_bytes = [0u8; 57];
        r_bytes.copy_from_slice(&signature[..57]);
        let mut s_bytes = [0u8; 57];
        s_bytes.copy_from_slice(&signature[57..]);

        // Check S < L
        if !scalar_is_canonical_57(&s_bytes) {
            return Ok(false);
        }

        // Decode R
        let r_point = match GeExtended448::from_bytes(&r_bytes) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };

        // Decode public key A
        let a_point = match GeExtended448::from_bytes(&self.public_key) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };

        let dom4 = dom4_prefix(0, context);

        // k = SHAKE256(dom4 || R || A || message, 114) mod L
        let mut hasher = Shake256::new();
        hasher.update(&dom4).map_err(|_| CryptoError::InvalidArg)?;
        hasher
            .update(&r_bytes)
            .map_err(|_| CryptoError::InvalidArg)?;
        hasher
            .update(&self.public_key)
            .map_err(|_| CryptoError::InvalidArg)?;
        hasher
            .update(message)
            .map_err(|_| CryptoError::InvalidArg)?;
        let k_hash = hasher.squeeze(114).map_err(|_| CryptoError::InvalidArg)?;
        let k_scalar = reduce_scalar_wide_114(&k_hash);

        // Verify: [S]B == R + [k]A
        let sb = scalar_mul_base(&s_bytes);
        let ka = scalar_mul(&k_scalar, &a_point);
        let rka = point_add(&r_point, &ka);

        Ok(sb.to_bytes().ct_eq(&rka.to_bytes()).into())
    }

    /// Sign a message using Ed448ph (prehashed variant).
    /// The message is first hashed with SHAKE256(msg, 64).
    pub fn sign_ph(&self, message: &[u8]) -> Result<[u8; ED448_SIGNATURE_SIZE], CryptoError> {
        let ph = prehash(message)?;
        self.sign_ph_internal(&ph, &[])
    }

    /// Verify using Ed448ph (prehashed variant).
    pub fn verify_ph(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let ph = prehash(message)?;
        self.verify_ph_internal(&ph, signature, &[])
    }

    /// Internal Ed448ph sign with pre-hashed data.
    fn sign_ph_internal(
        &self,
        ph_msg: &[u8; 64],
        context: &[u8],
    ) -> Result<[u8; ED448_SIGNATURE_SIZE], CryptoError> {
        if self.private_key == [0u8; 57] {
            return Err(CryptoError::EccInvalidPrivateKey);
        }
        if context.len() > 255 {
            return Err(CryptoError::InvalidArg);
        }

        let h = shake256_114(&self.private_key);
        let mut a = [0u8; 57];
        a.copy_from_slice(&h[..57]);
        clamp(&mut a);
        let prefix = &h[57..114];

        let dom4 = dom4_prefix(1, context); // flag=1 for Ed448ph

        let mut hasher = Shake256::new();
        hasher.update(&dom4).map_err(|_| CryptoError::InvalidArg)?;
        hasher.update(prefix).map_err(|_| CryptoError::InvalidArg)?;
        hasher.update(ph_msg).map_err(|_| CryptoError::InvalidArg)?;
        let r_hash = hasher.squeeze(114).map_err(|_| CryptoError::InvalidArg)?;
        let r_scalar = reduce_scalar_wide_114(&r_hash);

        let r_point = scalar_mul_base(&r_scalar);
        let r_bytes = r_point.to_bytes();

        let mut hasher = Shake256::new();
        hasher.update(&dom4).map_err(|_| CryptoError::InvalidArg)?;
        hasher
            .update(&r_bytes)
            .map_err(|_| CryptoError::InvalidArg)?;
        hasher
            .update(&self.public_key)
            .map_err(|_| CryptoError::InvalidArg)?;
        hasher.update(ph_msg).map_err(|_| CryptoError::InvalidArg)?;
        let k_hash = hasher.squeeze(114).map_err(|_| CryptoError::InvalidArg)?;
        let k_scalar = reduce_scalar_wide_114(&k_hash);

        let s_scalar = scalar_muladd(&k_scalar, &a, &r_scalar);

        let mut sig = [0u8; 114];
        sig[..57].copy_from_slice(&r_bytes);
        sig[57..].copy_from_slice(&s_scalar);
        Ok(sig)
    }

    /// Internal Ed448ph verify with pre-hashed data.
    fn verify_ph_internal(
        &self,
        ph_msg: &[u8; 64],
        signature: &[u8],
        context: &[u8],
    ) -> Result<bool, CryptoError> {
        if signature.len() != 114 {
            return Ok(false);
        }

        let mut r_bytes = [0u8; 57];
        r_bytes.copy_from_slice(&signature[..57]);
        let mut s_bytes = [0u8; 57];
        s_bytes.copy_from_slice(&signature[57..]);

        if !scalar_is_canonical_57(&s_bytes) {
            return Ok(false);
        }

        let r_point = match GeExtended448::from_bytes(&r_bytes) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        let a_point = match GeExtended448::from_bytes(&self.public_key) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };

        let dom4 = dom4_prefix(1, context);

        let mut hasher = Shake256::new();
        hasher.update(&dom4).map_err(|_| CryptoError::InvalidArg)?;
        hasher
            .update(&r_bytes)
            .map_err(|_| CryptoError::InvalidArg)?;
        hasher
            .update(&self.public_key)
            .map_err(|_| CryptoError::InvalidArg)?;
        hasher.update(ph_msg).map_err(|_| CryptoError::InvalidArg)?;
        let k_hash = hasher.squeeze(114).map_err(|_| CryptoError::InvalidArg)?;
        let k_scalar = reduce_scalar_wide_114(&k_hash);

        let sb = scalar_mul_base(&s_bytes);
        let ka = scalar_mul(&k_scalar, &a_point);
        let rka = point_add(&r_point, &ka);

        Ok(sb.to_bytes().ct_eq(&rka.to_bytes()).into())
    }

    /// Return the 57-byte public key.
    pub fn public_key(&self) -> &[u8; ED448_KEY_SIZE] {
        &self.public_key
    }
}

/// dom4 prefix: "SigEd448" || octet(flag) || octet(len(ctx)) || ctx
fn dom4_prefix(flag: u8, context: &[u8]) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(10 + context.len());
    prefix.extend_from_slice(b"SigEd448");
    prefix.push(flag);
    prefix.push(context.len() as u8);
    prefix.extend_from_slice(context);
    prefix
}

/// SHAKE256 helper: hash data and squeeze 114 bytes.
fn shake256_114(data: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::new();
    hasher.update(data).unwrap();
    hasher.squeeze(114).unwrap()
}

/// Prehash for Ed448ph: SHAKE256(msg, 64).
fn prehash(message: &[u8]) -> Result<[u8; 64], CryptoError> {
    let mut hasher = Shake256::new();
    hasher
        .update(message)
        .map_err(|_| CryptoError::InvalidArg)?;
    let result = hasher.squeeze(64).map_err(|_| CryptoError::InvalidArg)?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Clamp a 57-byte scalar for Ed448 (RFC 8032 §5.2.5).
/// Cofactor = 4, so clear 2 LSBs. Set bit 447. Clear byte 56.
fn clamp(a: &mut [u8; 57]) {
    a[0] &= 252; // Clear bits 0 and 1
    a[55] |= 128; // Set bit 447
    a[56] = 0; // Clear top byte
}

/// Reduce a 114-byte (912-bit) hash to a 57-byte scalar mod L using BigNum.
fn reduce_scalar_wide_114(hash: &[u8]) -> [u8; 57] {
    // Convert from little-endian to BigNum (big-endian)
    let len = hash.len();
    let mut be_bytes = vec![0u8; len];
    for i in 0..len {
        be_bytes[len - 1 - i] = hash[i];
    }
    let val = BigNum::from_bytes_be(&be_bytes);

    // L in big-endian
    let mut l_be = [0u8; 57];
    for i in 0..57 {
        l_be[56 - i] = L_BYTES_LE[i];
    }
    let l = BigNum::from_bytes_be(&l_be);

    // val mod L
    let result = val.mod_reduce(&l).unwrap();
    let result_be = result.to_bytes_be();

    // Convert back to little-endian 57 bytes
    let mut out = [0u8; 57];
    let rlen = result_be.len().min(57);
    for i in 0..rlen {
        out[i] = result_be[result_be.len() - 1 - i];
    }
    out
}

/// Compute (a * b + c) mod L using BigNum. All inputs are 57-byte little-endian scalars.
fn scalar_muladd(a: &[u8; 57], b: &[u8; 57], c: &[u8; 57]) -> [u8; 57] {
    let to_be = |le: &[u8; 57]| -> [u8; 57] {
        let mut be = [0u8; 57];
        for i in 0..57 {
            be[56 - i] = le[i];
        }
        be
    };

    let a_bn = BigNum::from_bytes_be(&to_be(a));
    let b_bn = BigNum::from_bytes_be(&to_be(b));
    let c_bn = BigNum::from_bytes_be(&to_be(c));

    let mut l_be = [0u8; 57];
    for i in 0..57 {
        l_be[56 - i] = L_BYTES_LE[i];
    }
    let l = BigNum::from_bytes_be(&l_be);

    // (a * b + c) mod L
    let ab = a_bn.mul(&b_bn);
    let abc = ab.add(&c_bn);
    let result = abc.mod_reduce(&l).unwrap();
    let result_be = result.to_bytes_be();

    // Convert back to LE 57 bytes
    let mut out = [0u8; 57];
    let len = result_be.len().min(57);
    for i in 0..len {
        out[i] = result_be[result_be.len() - 1 - i];
    }
    out
}

/// Check if a 57-byte scalar is canonical (< L).
fn scalar_is_canonical_57(s: &[u8; 57]) -> bool {
    for i in (0..57).rev() {
        if s[i] < L_BYTES_LE[i] {
            return true;
        }
        if s[i] > L_BYTES_LE[i] {
            return false;
        }
    }
    // s == L is not canonical
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032 §7.4 Test Vector: Ed448, blank message.
    #[test]
    fn test_ed448_rfc8032_blank() {
        let seed = hex("6c82a562cb808d10d632be89c8513ebf\
             6c929f34ddfa8c9f63c9960ef6e348a3\
             528c8a3fcc2f044e39a3fc5b94492f8f\
             032e7549a20098f95b");
        let expected_pub = hex("5fd7449b59b461fd2ce787ec616ad46a\
             1da1342485a70e1f8a0ea75d80e96778\
             edf124769b46c7061bd6783df1e50f6c\
             d1fa1abeafe8256180");
        let expected_sig = hex("533a37f6bbe457251f023c0d88f976ae\
             2dfb504a843e34d2074fd823d41a591f\
             2b233f034f628281f2fd7a22ddd47d78\
             28c59bd0a21bfd3980ff0d2028d4b18a\
             9df63e006c5d1c2d345b925d8dc00b41\
             04852db99ac5c7cdda8530a113a0f4db\
             b61149f05a7363268c71d95808ff2e65\
             2600");

        let key = Ed448KeyPair::from_seed(&seed).unwrap();
        assert_eq!(key.public_key().as_slice(), &expected_pub);

        let sig = key.sign(b"").unwrap();
        assert_eq!(sig.as_slice(), &expected_sig);

        let valid = key.verify(b"", &sig).unwrap();
        assert!(valid);
    }

    /// RFC 8032 §7.4 Test Vector: Ed448, 1 byte message (0x03).
    #[test]
    fn test_ed448_rfc8032_1byte() {
        let seed = hex("c4eab05d357007c632f3dbb48489924d\
             552b08fe0c353a0d4a1f00acda2c463a\
             fbea67c5e8d2877c5e3bc397a659949e\
             f8021e954e0a12274e");
        let expected_pub = hex("43ba28f430cdff456ae531545f7ecd0a\
             c834a55d9358c0372bfa0c6c6798c086\
             6aea01eb00742802b8438ea4cb82169c\
             235160627b4c3a9480");
        let expected_sig = hex("26b8f91727bd62897af15e41eb43c377\
             efb9c610d48f2335cb0bd0087810f435\
             2541b143c4b981b7e18f62de8ccdf633\
             fc1bf037ab7cd779805e0dbcc0aae1cb\
             cee1afb2e027df36bc04dcecbf154336\
             c19f0af7e0a6472905e799f1953d2a0f\
             f3348ab21aa4adafd1d234441cf807c0\
             3a00");

        let key = Ed448KeyPair::from_seed(&seed).unwrap();
        assert_eq!(key.public_key().as_slice(), &expected_pub);

        let sig = key.sign(&[0x03]).unwrap();
        assert_eq!(sig.as_slice(), &expected_sig);

        let valid = key.verify(&[0x03], &sig).unwrap();
        assert!(valid);
    }

    /// RFC 8032 §7.4 Test Vector: Ed448, "abc" (3 bytes, 0x61 0x62 0x63)
    /// with context = "foo"
    #[test]
    fn test_ed448_rfc8032_context() {
        let seed = hex("c4eab05d357007c632f3dbb48489924d\
             552b08fe0c353a0d4a1f00acda2c463a\
             fbea67c5e8d2877c5e3bc397a659949e\
             f8021e954e0a12274e");
        let expected_sig = hex("d4f8f6131770dd46f40867d6fd5d5055\
             de43541f8c5e35abbcd001b32a89f7d2\
             151f7647f11d8ca2ae279fb842d60721\
             7fce6e042f6815ea000c85741de5c8da\
             1144a6a1aba7f96de42505d7a7298524\
             fda538fccbbb754f578c1cad10d54d0d\
             5428407e85dcbc98a49155c13764e66c\
             3c00");

        let key = Ed448KeyPair::from_seed(&seed).unwrap();
        let sig = key.sign_with_context(b"\x03", b"foo").unwrap();
        assert_eq!(sig.as_slice(), &expected_sig);

        let valid = key.verify_with_context(b"\x03", &sig, b"foo").unwrap();
        assert!(valid);
    }

    /// RFC 8032 §7.4: Ed448ph test vector.
    #[test]
    fn test_ed448ph_rfc8032() {
        let seed = hex("833fe62409237b9d62ec77587520911e\
             9a759cec1d19755b7da901b96dca3d42\
             ef7822e0d5104127dc05d6dbefde69e3\
             ab2cec7c867c6e2c49");
        let expected_pub = hex("259b71c19f83ef77a7abd26524cbdb31\
             61b590a48f7d17de3ee0ba9c52beb743\
             c09428a131d6b1b57303d90d8132c276\
             d5ed3d5d01c0f53880");
        let msg = hex("616263"); // "abc"

        let expected_sig = hex("822f6901f7480f3d5f562c592994d969\
             3602875614483256505600bbc281ae38\
             1f54d6bce2ea911574932f52a4e6cadd\
             78769375ec3ffd1b801a0d9b3f4030cd\
             433964b6457ea39476511214f97469b5\
             7dd32dbc560a9a94d00bff07620464a3\
             ad203df7dc7ce360c3cd3696d9d9fab9\
             0f00");

        let key = Ed448KeyPair::from_seed(&seed).unwrap();
        assert_eq!(key.public_key().as_slice(), &expected_pub);

        let sig = key.sign_ph(&msg).unwrap();
        assert_eq!(sig.as_slice(), &expected_sig);

        let valid = key.verify_ph(&msg, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_ed448_sign_verify_roundtrip() {
        let key = Ed448KeyPair::generate().unwrap();
        let msg = b"Hello, Ed448!";
        let sig = key.sign(msg).unwrap();
        assert!(key.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_ed448_tamper_detection() {
        let key = Ed448KeyPair::generate().unwrap();
        let msg = b"original message";
        let sig = key.sign(msg).unwrap();
        assert!(!key.verify(b"tampered message", &sig).unwrap());
    }

    #[test]
    fn test_ed448_invalid_signature() {
        let key = Ed448KeyPair::generate().unwrap();
        let msg = b"test message";
        let mut sig = key.sign(msg).unwrap();
        sig[0] ^= 0x01; // tamper with R
        assert!(!key.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_ed448_context_mismatch() {
        let key = Ed448KeyPair::generate().unwrap();
        let msg = b"context test";
        let sig = key.sign_with_context(msg, b"ctx1").unwrap();
        // Same context should verify
        assert!(key.verify_with_context(msg, &sig, b"ctx1").unwrap());
        // Different context should fail
        assert!(!key.verify_with_context(msg, &sig, b"ctx2").unwrap());
        // Empty context should fail
        assert!(!key.verify(msg, &sig).unwrap());
    }
}
