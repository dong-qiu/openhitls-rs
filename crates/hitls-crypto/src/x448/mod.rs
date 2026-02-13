//! X448 Diffie-Hellman key exchange.
//!
//! X448 is an elliptic-curve Diffie-Hellman function using Curve448 (Goldilocks),
//! as defined in RFC 7748. It provides fast key agreement with 224-bit security.

use hitls_types::CryptoError;
use zeroize::Zeroize;

use crate::curve448::field::Fe448;

/// X448 key size in bytes (448 bits).
pub const X448_KEY_SIZE: usize = 56;

/// The u-coordinate of the base point (= 5).
const BASEPOINT_U: [u8; 56] = {
    let mut b = [0u8; 56];
    b[0] = 5;
    b
};

/// An X448 private key (scalar).
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct X448PrivateKey {
    /// The 56-byte private scalar.
    key: [u8; X448_KEY_SIZE],
}

/// An X448 public key (u-coordinate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X448PublicKey {
    /// The 56-byte public key (u-coordinate on Curve448).
    key: [u8; X448_KEY_SIZE],
}

impl X448PrivateKey {
    /// Generate a new random X448 private key.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = [0u8; 56];
        getrandom::getrandom(&mut key).map_err(|_| CryptoError::BnRandGenFail)?;
        clamp_scalar(&mut key);
        Ok(X448PrivateKey { key })
    }

    /// Create an X448 private key from 56 raw bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 56 {
            return Err(CryptoError::InvalidArg);
        }
        let mut key = [0u8; 56];
        key.copy_from_slice(bytes);
        clamp_scalar(&mut key);
        Ok(X448PrivateKey { key })
    }

    /// Compute the corresponding public key.
    pub fn public_key(&self) -> X448PublicKey {
        let result = x448_scalar_mul(&self.key, &BASEPOINT_U);
        X448PublicKey { key: result }
    }

    /// Perform the X448 Diffie-Hellman function with a peer's public key.
    pub fn diffie_hellman(&self, peer_public: &X448PublicKey) -> Result<Vec<u8>, CryptoError> {
        let shared = x448_scalar_mul(&self.key, &peer_public.key);
        // Check for all-zero output (invalid shared secret)
        if shared.iter().all(|&b| b == 0) {
            return Err(CryptoError::EccPointAtInfinity);
        }
        Ok(shared.to_vec())
    }
}

impl X448PublicKey {
    /// Create an X448 public key from 56 raw bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 56 {
            return Err(CryptoError::InvalidArg);
        }
        let mut key = [0u8; 56];
        key.copy_from_slice(bytes);
        Ok(X448PublicKey { key })
    }

    /// Return the raw 56-byte public key.
    pub fn as_bytes(&self) -> &[u8; X448_KEY_SIZE] {
        &self.key
    }
}

/// Clamp a 56-byte scalar for X448 (RFC 7748 §5).
/// Cofactor is 4, so clear 2 bits. Set bit 447.
fn clamp_scalar(k: &mut [u8; 56]) {
    k[0] &= 252; // Clear bits 0 and 1
    k[55] |= 128; // Set bit 447 (top bit of byte 55)
}

/// X448 scalar multiplication using the Montgomery ladder.
///
/// Implements RFC 7748 §5 for Curve448.
/// a24 = 39081 (A = 156326, a24 = (A−2)/4 = 39081).
///
/// Applies scalar decoding (clamping) per RFC 7748: clear bits 0,1 of
/// first byte and set bit 447 of last byte.
fn x448_scalar_mul(scalar: &[u8; 56], u_bytes: &[u8; 56]) -> [u8; 56] {
    let u = Fe448::from_bytes(u_bytes);

    // Decode scalar (RFC 7748 §5): clamp
    let mut k = *scalar;
    clamp_scalar(&mut k);

    let mut x_2 = Fe448::one();
    let mut z_2 = Fe448::zero();
    let mut x_3 = u;
    let mut z_3 = Fe448::one();
    let mut swap: u8 = 0;

    // Montgomery ladder: iterate from bit 447 down to 0
    for t in (0..=447).rev() {
        let k_t = (k[t / 8] >> (t % 8)) & 1;
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
        z_2 = e.mul(&aa.add(&e.mul_small(39081)));
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

    fn hex_to_56(s: &str) -> [u8; 56] {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        let mut out = [0u8; 56];
        out.copy_from_slice(&bytes);
        out
    }

    /// RFC 7748 §5.2 test vector 1: scalar × u-coordinate.
    #[test]
    fn test_x448_rfc7748_vector1() {
        // RFC 7748 §5.2, first X448 test vector
        let scalar = hex_to_56(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0\
             d1aae121700a779c984c24f8cdd78fbff44943eba368f54b\
             29259a4f1c600ad3",
        );
        let u_coord = hex_to_56(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f\
             020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada1\
             8aa7a7fb4ef8a086",
        );
        let expected = hex_to_56(
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d754\
             6d5f239fe14fbaadeb445fc66a01b0779d98223961111e21\
             766282f73dd96b6f",
        );
        let result = x448_scalar_mul(&scalar, &u_coord);
        assert_eq!(result, expected);
    }

    /// RFC 7748 §5.2 test vector 2: scalar × u-coordinate.
    #[test]
    fn test_x448_rfc7748_vector2() {
        // RFC 7748 §5.2, second X448 test vector
        let scalar = hex_to_56(
            "203d494428b8399352665ddca42f9de8fef600908e0d461c\
             b021f8c538345dd77c3e4806e25f46d3315c44e0a5b43712\
             82dd2c8d5be3095f",
        );
        let u_coord = hex_to_56(
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1\
             e9b6201b165d015894e56c4d3570bee52fe205e28a78b91c\
             dfbde71ce8d157db",
        );
        let expected = hex_to_56(
            "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30\
             fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c9\
             54514e99da7c179d",
        );
        let result = x448_scalar_mul(&scalar, &u_coord);
        assert_eq!(result, expected);
    }

    /// RFC 7748 §6.2 full Alice/Bob DH exchange.
    #[test]
    fn test_x448_dh_rfc7748() {
        // RFC 7748 §6.2 DH key exchange test vector
        let alice_prv = hex_to_56(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565\
             d498c28dd9c9baf574a9419744897391006382a6f127ab1d\
             9ac2d8c0a598726b",
        );
        let alice_pub_expected = hex_to_56(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63\
             faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53\
             177f80e532c41fa0",
        );

        let bob_prv = hex_to_56(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d\
             8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0\
             366f10b65173992d",
        );
        let bob_pub_expected = hex_to_56(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4\
             f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae\
             07bdc1c67bf33609",
        );

        let shared_expected = hex_to_56(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552\
             281d282bb60c0b56fd2464c335543936521c24403085d59a\
             449a5037514a879d",
        );

        // Alice computes her public key
        let alice_pub = x448_scalar_mul(&alice_prv, &BASEPOINT_U);
        assert_eq!(alice_pub, alice_pub_expected);

        // Bob computes his public key
        let bob_pub = x448_scalar_mul(&bob_prv, &BASEPOINT_U);
        assert_eq!(bob_pub, bob_pub_expected);

        // Shared secrets must match
        let shared_alice = x448_scalar_mul(&alice_prv, &bob_pub);
        let shared_bob = x448_scalar_mul(&bob_prv, &alice_pub);
        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice, shared_expected);
    }

    #[test]
    fn test_x448_key_exchange_symmetry() {
        let alice = X448PrivateKey::generate().unwrap();
        let bob = X448PrivateKey::generate().unwrap();

        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();

        let shared_alice = alice.diffie_hellman(&bob_pub).unwrap();
        let shared_bob = bob.diffie_hellman(&alice_pub).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 56);
    }

    /// RFC 7748 §6.2 iterated test (1000 iterations).
    #[test]
    #[ignore] // Slow: ~1000 scalar muls
    fn test_x448_iterated_1000() {
        let mut k = [0u8; 56];
        k[0] = 5;
        let mut u = [0u8; 56];
        u[0] = 5;

        for _ in 0..1000 {
            let new_k = x448_scalar_mul(&k, &u);
            u = k;
            k = new_k;
        }

        let expected = hex_to_56(
            "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4\
             af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38",
        );
        assert_eq!(k, expected);
    }
}
