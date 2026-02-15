//! ElGamal encryption scheme.
//!
//! ElGamal is a public-key encryption scheme based on the Diffie-Hellman
//! key exchange. It provides semantic security under the DDH assumption
//! and is multiplicatively homomorphic.
//!
//! Ciphertext format: 4-byte big-endian length of c1, then c1 bytes, then c2 bytes.

use hitls_bignum::BigNum;
use hitls_types::CryptoError;
use zeroize::Zeroize;

/// An ElGamal key pair for encryption and decryption.
pub struct ElGamalKeyPair {
    /// The prime modulus p.
    p: BigNum,
    /// The generator g.
    g: BigNum,
    /// The private key x (random in [2, p-2]).
    x: BigNum,
    /// The public key y = g^x mod p.
    y: BigNum,
}

impl Drop for ElGamalKeyPair {
    fn drop(&mut self) {
        self.x.zeroize();
    }
}

impl ElGamalKeyPair {
    /// Create an ElGamal key pair from given parameters (p, g).
    ///
    /// Generates a random private key x and computes y = g^x mod p.
    pub fn from_params(p: &BigNum, g: &BigNum) -> Result<Self, CryptoError> {
        let one = BigNum::from_u64(1);
        let two = BigNum::from_u64(2);

        // p must be > 2
        if p.cmp_abs(&two) != std::cmp::Ordering::Greater {
            return Err(CryptoError::InvalidArg);
        }

        // x ∈ [2, p-2]: random in [0, p-3) then add 2
        let p_minus_2 = p.sub(&two);
        let p_minus_3 = p_minus_2.sub(&one);
        let x = BigNum::random_range(&p_minus_3)?.add(&two);

        let y = g.mod_exp(&x, p)?;

        Ok(Self {
            p: p.clone(),
            g: g.clone(),
            x,
            y,
        })
    }

    /// Create an ElGamal key pair from known private key (for testing).
    pub fn from_private_key(p: &BigNum, g: &BigNum, x: &BigNum) -> Result<Self, CryptoError> {
        let y = g.mod_exp(x, p)?;
        Ok(Self {
            p: p.clone(),
            g: g.clone(),
            x: x.clone(),
            y,
        })
    }

    /// Generate a new ElGamal key pair with the given modulus bit size.
    ///
    /// Generates a safe prime p = 2q + 1 and uses g = 4 as a generator
    /// of the order-q subgroup. This is slow for large bit sizes.
    pub fn generate(bits: usize) -> Result<Self, CryptoError> {
        if bits < 32 {
            return Err(CryptoError::InvalidArg);
        }

        let p = generate_safe_prime(bits)?;
        let g = BigNum::from_u64(4); // g=4 generates the quadratic residues subgroup

        Self::from_params(&p, &g)
    }

    /// Encrypt a plaintext message (big-endian integer bytes).
    ///
    /// The plaintext must represent a positive integer less than p.
    /// Returns ciphertext as: 4-byte c1_len || c1 || c2.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let m = BigNum::from_bytes_be(plaintext);

        // Verify 0 < m < p (m = 0 would lose information)
        if m.is_zero() || m.cmp_abs(&self.p) != std::cmp::Ordering::Less {
            return Err(CryptoError::InvalidArg);
        }

        // Random k ∈ [1, p-2]
        let one = BigNum::from_u64(1);
        let p_minus_1 = self.p.sub(&one);
        let k = loop {
            let k = BigNum::random_range(&p_minus_1)?;
            if k.is_zero() {
                continue;
            }
            let g = k.gcd(&p_minus_1)?;
            if g.is_one() {
                break k;
            }
        };

        // c1 = g^k mod p
        let c1 = self.g.mod_exp(&k, &self.p)?;
        // s = y^k mod p
        let s = self.y.mod_exp(&k, &self.p)?;
        // c2 = m * s mod p
        let c2 = m.mul(&s).mod_reduce(&self.p)?;

        // Serialize: 4-byte c1_len || c1 || c2
        let c1_bytes = c1.to_bytes_be();
        let c2_bytes = c2.to_bytes_be();
        let mut output = Vec::with_capacity(4 + c1_bytes.len() + c2_bytes.len());
        output.extend_from_slice(&(c1_bytes.len() as u32).to_be_bytes());
        output.extend_from_slice(&c1_bytes);
        output.extend_from_slice(&c2_bytes);

        Ok(output)
    }

    /// Decrypt a ciphertext, recovering the plaintext integer bytes.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 5 {
            return Err(CryptoError::InvalidArg);
        }

        // Parse: 4-byte c1_len || c1 || c2
        let c1_len =
            u32::from_be_bytes([ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3]])
                as usize;
        if ciphertext.len() < 4 + c1_len + 1 {
            return Err(CryptoError::InvalidArg);
        }

        let c1 = BigNum::from_bytes_be(&ciphertext[4..4 + c1_len]);
        let c2 = BigNum::from_bytes_be(&ciphertext[4 + c1_len..]);

        // s = c1^x mod p
        let s = c1.mod_exp(&self.x, &self.p)?;
        // s_inv = s^{-1} mod p
        let s_inv = s.mod_inv(&self.p)?;
        // m = c2 * s_inv mod p
        let m = c2.mul(&s_inv).mod_reduce(&self.p)?;

        Ok(m.to_bytes_be())
    }

    /// Return the public key y = g^x mod p (big-endian bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.y.to_bytes_be()
    }
}

/// Generate a safe prime p = 2q + 1 where q is also prime.
fn generate_safe_prime(bits: usize) -> Result<BigNum, CryptoError> {
    let one = BigNum::from_u64(1);
    let two = BigNum::from_u64(2);
    let mr_rounds = if bits >= 512 { 5 } else { 10 };

    for _ in 0..10000 {
        // Generate candidate q
        let mut q = BigNum::random(bits - 1, true)?;
        q.set_bit(bits - 2);

        if !q.is_probably_prime(mr_rounds)? {
            continue;
        }

        // p = 2q + 1
        let p = q.mul(&two).add(&one);
        if p.is_probably_prime(mr_rounds)? {
            return Ok(p);
        }
    }

    Err(CryptoError::BnRandGenFail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elgamal_small_params() {
        // p = 23 (prime), g = 5 (generator of Z*_23)
        let p = BigNum::from_u64(23);
        let g = BigNum::from_u64(5);
        let x = BigNum::from_u64(7); // private key

        let kp = ElGamalKeyPair::from_private_key(&p, &g, &x).unwrap();

        // y = 5^7 mod 23 = 78125 mod 23 = 17
        assert_eq!(
            BigNum::from_bytes_be(&kp.public_key_bytes()).to_bytes_be(),
            BigNum::from_u64(17).to_bytes_be()
        );

        // Encrypt m = 10
        let m = BigNum::from_u64(10);
        let ct = kp.encrypt(&m.to_bytes_be()).unwrap();
        let pt = kp.decrypt(&ct).unwrap();
        let recovered = BigNum::from_bytes_be(&pt);
        assert_eq!(recovered.to_bytes_be(), m.to_bytes_be());
    }

    #[test]
    fn test_elgamal_random_params() {
        // Use a larger prime for more randomness
        let p = BigNum::from_u64(104729); // prime
        let g = BigNum::from_u64(2);

        let kp = ElGamalKeyPair::from_params(&p, &g).unwrap();

        let m = BigNum::from_u64(42);
        let ct = kp.encrypt(&m.to_bytes_be()).unwrap();
        let pt = kp.decrypt(&ct).unwrap();
        let recovered = BigNum::from_bytes_be(&pt);
        assert_eq!(recovered.to_bytes_be(), m.to_bytes_be());
    }

    #[test]
    fn test_elgamal_message_one() {
        let p = BigNum::from_u64(23);
        let g = BigNum::from_u64(5);
        let kp = ElGamalKeyPair::from_params(&p, &g).unwrap();

        let m = BigNum::from_u64(1);
        let ct = kp.encrypt(&m.to_bytes_be()).unwrap();
        let pt = kp.decrypt(&ct).unwrap();
        let recovered = BigNum::from_bytes_be(&pt);
        assert_eq!(recovered.to_bytes_be(), m.to_bytes_be());
    }

    #[test]
    fn test_elgamal_large_message() {
        let p = BigNum::from_u64(104729);
        let g = BigNum::from_u64(2);
        let kp = ElGamalKeyPair::from_params(&p, &g).unwrap();

        // Message close to p
        let m = BigNum::from_u64(104728); // p - 1
        let ct = kp.encrypt(&m.to_bytes_be()).unwrap();
        let pt = kp.decrypt(&ct).unwrap();
        let recovered = BigNum::from_bytes_be(&pt);
        assert_eq!(recovered.to_bytes_be(), m.to_bytes_be());
    }

    #[test]
    fn test_elgamal_invalid_message() {
        let p = BigNum::from_u64(23);
        let g = BigNum::from_u64(5);
        let kp = ElGamalKeyPair::from_params(&p, &g).unwrap();

        // m = 0 should fail
        let m0 = BigNum::from_u64(0);
        assert!(kp.encrypt(&m0.to_bytes_be()).is_err());

        // m >= p should fail
        let m_big = BigNum::from_u64(23);
        assert!(kp.encrypt(&m_big.to_bytes_be()).is_err());
    }

    #[test]
    fn test_elgamal_public_key_deterministic() {
        let p = BigNum::from_u64(23);
        let g = BigNum::from_u64(5);
        let x = BigNum::from_u64(3);

        let kp1 = ElGamalKeyPair::from_private_key(&p, &g, &x).unwrap();
        let kp2 = ElGamalKeyPair::from_private_key(&p, &g, &x).unwrap();
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    #[ignore] // Slow: safe prime generation
    fn test_elgamal_generate() {
        let kp = ElGamalKeyPair::generate(256).unwrap();
        let m = BigNum::from_u64(12345);
        let ct = kp.encrypt(&m.to_bytes_be()).unwrap();
        let pt = kp.decrypt(&ct).unwrap();
        assert_eq!(BigNum::from_bytes_be(&pt).to_bytes_be(), m.to_bytes_be());
    }

    #[test]
    fn test_elgamal_truncated_ciphertext() {
        let p = BigNum::from_u64(23);
        let g = BigNum::from_u64(5);
        let x = BigNum::from_u64(7);
        let kp = ElGamalKeyPair::from_private_key(&p, &g, &x).unwrap();

        let m = BigNum::from_u64(10);
        let ct = kp.encrypt(&m.to_bytes_be()).unwrap();
        assert!(ct.len() > 4);

        // Truncate to 4 bytes → should fail to decrypt
        assert!(kp.decrypt(&ct[..4]).is_err());
    }

    #[test]
    fn test_elgamal_ciphertext_tampering() {
        let p = BigNum::from_u64(23);
        let g = BigNum::from_u64(5);
        let x = BigNum::from_u64(7);
        let kp = ElGamalKeyPair::from_private_key(&p, &g, &x).unwrap();

        let m = BigNum::from_u64(10);
        let mut ct = kp.encrypt(&m.to_bytes_be()).unwrap();

        // Format: 4-byte c1_len || c1 || c2
        // Flip a byte in the c2 portion (last byte)
        let last = ct.len() - 1;
        ct[last] ^= 0x01;

        let pt = kp.decrypt(&ct).unwrap();
        let recovered = BigNum::from_bytes_be(&pt);
        assert_ne!(
            recovered.to_bytes_be(),
            m.to_bytes_be(),
            "tampered ciphertext should decrypt to different value"
        );
    }
}
