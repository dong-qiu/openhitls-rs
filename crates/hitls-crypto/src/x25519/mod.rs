//! X25519 Diffie-Hellman key exchange.
//!
//! X25519 is an elliptic-curve Diffie-Hellman function using Curve25519,
//! as defined in RFC 7748. It provides fast key agreement with 128-bit security.

use hitls_types::CryptoError;
use zeroize::Zeroize;

use crate::curve25519::field::Fe25519;

/// X25519 key size in bytes (256 bits).
pub const X25519_KEY_SIZE: usize = 32;

/// The u-coordinate of the base point (= 9).
const BASEPOINT_U: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// An X25519 private key (scalar).
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct X25519PrivateKey {
    /// The 32-byte private scalar.
    key: [u8; X25519_KEY_SIZE],
}

/// An X25519 public key (u-coordinate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519PublicKey {
    /// The 32-byte public key (u-coordinate on Curve25519).
    key: [u8; X25519_KEY_SIZE],
}

impl X25519PrivateKey {
    /// Generate a new random X25519 private key.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|_| CryptoError::BnRandGenFail)?;
        clamp_scalar(&mut key);
        Ok(X25519PrivateKey { key })
    }

    /// Create an X25519 private key from 32 raw bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidArg);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        clamp_scalar(&mut key);
        Ok(X25519PrivateKey { key })
    }

    /// Compute the corresponding public key.
    pub fn public_key(&self) -> X25519PublicKey {
        let result = x25519_scalar_mul(&self.key, &BASEPOINT_U);
        X25519PublicKey { key: result }
    }

    /// Perform the X25519 Diffie-Hellman function with a peer's public key.
    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> Result<Vec<u8>, CryptoError> {
        let shared = x25519_scalar_mul(&self.key, &peer_public.key);
        // Check for all-zero output (invalid shared secret)
        if shared.iter().all(|&b| b == 0) {
            return Err(CryptoError::EccPointAtInfinity);
        }
        Ok(shared.to_vec())
    }
}

impl X25519PublicKey {
    /// Create an X25519 public key from 32 raw bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidArg);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(X25519PublicKey { key })
    }

    /// Return the raw 32-byte public key.
    pub fn as_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.key
    }
}

/// Clamp a 32-byte scalar for X25519 (RFC 7748 §5).
fn clamp_scalar(k: &mut [u8; 32]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

/// X25519 scalar multiplication using the Montgomery ladder.
///
/// Implements RFC 7748 §5.
fn x25519_scalar_mul(scalar: &[u8; 32], u_bytes: &[u8; 32]) -> [u8; 32] {
    // Decode u-coordinate (mask top bit per RFC 7748)
    let mut u_in = *u_bytes;
    u_in[31] &= 0x7f;
    let u = Fe25519::from_bytes(&u_in);

    let mut x_2 = Fe25519::one();
    let mut z_2 = Fe25519::zero();
    let mut x_3 = u;
    let mut z_3 = Fe25519::one();
    let mut swap: u8 = 0;

    // Montgomery ladder: iterate from bit 254 down to 0
    for t in (0..=254).rev() {
        let k_t = (scalar[t / 8] >> (t % 8)) & 1;
        swap ^= k_t;
        x_2.conditional_swap(&mut x_3, swap);
        z_2.conditional_swap(&mut z_3, swap);
        swap = k_t;

        let a = x_2.add(&z_2);
        let aa = a.square();
        let b = x_2.sub(&z_2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x_3.add(&z_3);
        let d = x_3.sub(&z_3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x_3 = da.add(&cb).square();
        z_3 = u.mul(&da.sub(&cb).square());
        x_2 = aa.mul(&bb);
        z_2 = e.mul(&bb.add(&e.mul121666()));
    }

    x_2.conditional_swap(&mut x_3, swap);
    z_2.conditional_swap(&mut z_3, swap);

    // Return x_2 / z_2
    let result = x_2.mul(&z_2.invert());
    result.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    /// RFC 7748 §6.1 test vector.
    #[test]
    fn test_x25519_rfc7748_vector() {
        let alice_prv =
            hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub_expected =
            hex_to_bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

        let bob_prv =
            hex_to_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pub_expected =
            hex_to_bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

        let shared_expected =
            hex_to_bytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        let alice = X25519PrivateKey::new(&alice_prv).unwrap();
        let alice_pub = alice.public_key();
        assert_eq!(alice_pub.as_bytes(), &alice_pub_expected);

        let bob = X25519PrivateKey::new(&bob_prv).unwrap();
        let bob_pub = bob.public_key();
        assert_eq!(bob_pub.as_bytes(), &bob_pub_expected);

        let shared_alice = alice.diffie_hellman(&bob_pub).unwrap();
        let shared_bob = bob.diffie_hellman(&alice_pub).unwrap();
        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.as_slice(), &shared_expected);
    }

    #[test]
    fn test_x25519_key_exchange_symmetry() {
        let alice = X25519PrivateKey::generate().unwrap();
        let bob = X25519PrivateKey::generate().unwrap();

        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();

        let shared_alice = alice.diffie_hellman(&bob_pub).unwrap();
        let shared_bob = bob.diffie_hellman(&alice_pub).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 32);
    }

    #[test]
    fn test_x25519_basepoint_scalar_mul() {
        // scalar = 1 (after clamping: 0x40 in byte 31, 0 in byte 0 low bits already 0)
        // Actually just test that public_key derivation is deterministic
        let key1 = X25519PrivateKey::new(&[1u8; 32]).unwrap();
        let key2 = X25519PrivateKey::new(&[1u8; 32]).unwrap();
        assert_eq!(key1.public_key(), key2.public_key());
    }

    /// RFC 7748 §5.2: After 1 iteration, k should match the published vector.
    #[test]
    fn test_x25519_rfc7748_iterated_1() {
        // Initial state: k = u = basepoint (9)
        let mut k = [0u8; 32];
        k[0] = 9;
        let mut u = k;

        // 1 iteration: k, u = X25519(k, u), k_old
        let old_k = k;
        let prv = X25519PrivateKey::new(&k).unwrap();
        let pub_key = X25519PublicKey::new(&u).unwrap();
        let result = prv.diffie_hellman(&pub_key).unwrap();
        k.copy_from_slice(&result);
        u = old_k;
        let _ = u; // suppress unused warning

        let expected =
            hex_to_bytes("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        assert_eq!(k, expected);
    }

    /// RFC 7748 §5.2: After 1000 iterations, k should match the published vector.
    #[test]
    fn test_x25519_rfc7748_iterated_1000() {
        let mut k = [0u8; 32];
        k[0] = 9;
        let mut u = k;

        for _ in 0..1000 {
            let old_k = k;
            // X25519 applies clamping internally via X25519PrivateKey::new
            let prv = X25519PrivateKey::new(&k).unwrap();
            let pub_key = X25519PublicKey::new(&u).unwrap();
            let result = prv.diffie_hellman(&pub_key).unwrap();
            k.copy_from_slice(&result);
            u = old_k;
        }

        let expected =
            hex_to_bytes("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
        assert_eq!(k, expected);
    }

    #[test]
    fn test_x25519_low_order_all_zero() {
        let prv = X25519PrivateKey::generate().unwrap();
        let zero_pub = X25519PublicKey::new(&[0u8; 32]).unwrap();
        // All-zero public key should produce all-zero shared secret → error
        assert!(prv.diffie_hellman(&zero_pub).is_err());
    }

    #[test]
    fn test_x25519_wrong_key_size() {
        assert!(X25519PrivateKey::new(&[0u8; 31]).is_err());
        assert!(X25519PrivateKey::new(&[0u8; 33]).is_err());
        assert!(X25519PublicKey::new(&[0u8; 31]).is_err());
        assert!(X25519PublicKey::new(&[0u8; 33]).is_err());
    }
}
