//! Paillier partially homomorphic encryption.
//!
//! The Paillier cryptosystem is an additive homomorphic encryption scheme.
//! Given ciphertexts E(m1) and E(m2), one can compute E(m1 + m2) without
//! decrypting, by multiplying ciphertexts modulo n^2.
//!
//! Uses g = n + 1 simplification: L(g^lambda mod n^2) = lambda mod n,
//! so mu = lambda^{-1} mod n.

use hitls_bignum::BigNum;
use hitls_types::CryptoError;

/// A Paillier key pair (public key n, private key lambda/mu).
pub struct PaillierKeyPair {
    /// The public modulus n = p * q.
    n: BigNum,
    /// n^2 (cached for convenience).
    n_sq: BigNum,
    /// The private key component lambda = lcm(p-1, q-1).
    lambda: BigNum,
    /// The private key component mu = lambda^{-1} mod n.
    mu: BigNum,
}

impl PaillierKeyPair {
    /// Generate a new Paillier key pair with the given modulus bit size.
    ///
    /// This is slow for large bit sizes (>= 1024). For testing, prefer
    /// `from_primes` with known small primes.
    pub fn generate(bits: usize) -> Result<Self, CryptoError> {
        if bits < 64 {
            return Err(CryptoError::InvalidArg);
        }

        let half_bits = bits / 2;
        let p = generate_prime(half_bits)?;
        let q = generate_prime(half_bits)?;

        Self::from_primes(&p, &q)
    }

    /// Create a Paillier key pair from two primes p and q.
    pub fn from_primes(p: &BigNum, q: &BigNum) -> Result<Self, CryptoError> {
        let one = BigNum::from_u64(1);
        let n = p.mul(q);
        let n_sq = n.mul(&n);

        let p_minus_1 = p.sub(&one);
        let q_minus_1 = q.sub(&one);

        // lambda = lcm(p-1, q-1) = (p-1)*(q-1) / gcd(p-1, q-1)
        let g = p_minus_1.gcd(&q_minus_1)?;
        let (lambda, _) = p_minus_1.mul(&q_minus_1).div_rem(&g)?;

        // mu = lambda^{-1} mod n
        let mu = lambda.mod_inv(&n)?;

        Ok(Self {
            n,
            n_sq,
            lambda,
            mu,
        })
    }

    /// Return the public modulus n (big-endian bytes).
    pub fn public_key(&self) -> Vec<u8> {
        self.n.to_bytes_be()
    }

    /// Encrypt a plaintext message (big-endian integer bytes).
    ///
    /// The plaintext must represent a non-negative integer less than n.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let m = BigNum::from_bytes_be(plaintext);

        // Verify 0 <= m < n
        if m.cmp_abs(&self.n) != std::cmp::Ordering::Less {
            return Err(CryptoError::InvalidArg);
        }

        // Generate random r in [1, n-1] with gcd(r, n) = 1
        let r = random_coprime(&self.n)?;

        // c = (1 + m*n) * r^n mod n^2
        // Using binomial theorem: (n+1)^m mod n^2 = 1 + m*n mod n^2
        let one = BigNum::from_u64(1);
        let gm = one.add(&m.mul(&self.n)).mod_reduce(&self.n_sq)?;
        let rn = r.mod_exp(&self.n, &self.n_sq)?;
        let c = gm.mul(&rn).mod_reduce(&self.n_sq)?;

        Ok(c.to_bytes_be())
    }

    /// Decrypt a ciphertext, recovering the plaintext integer bytes.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let c = BigNum::from_bytes_be(ciphertext);

        // c^lambda mod n^2
        let cl = c.mod_exp(&self.lambda, &self.n_sq)?;

        // L(cl) = (cl - 1) / n
        let one = BigNum::from_u64(1);
        let (l_val, rem) = cl.sub(&one).div_rem(&self.n)?;
        if !rem.is_zero() {
            return Err(CryptoError::InvalidArg);
        }

        // m = L(cl) * mu mod n
        let m = l_val.mul(&self.mu).mod_reduce(&self.n)?;

        Ok(m.to_bytes_be())
    }

    /// Homomorphic addition: E(m1 + m2 mod n) = E(m1) * E(m2) mod n^2.
    pub fn add_ciphertexts(&self, ct1: &[u8], ct2: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let c1 = BigNum::from_bytes_be(ct1);
        let c2 = BigNum::from_bytes_be(ct2);
        let result = c1.mul(&c2).mod_reduce(&self.n_sq)?;
        Ok(result.to_bytes_be())
    }
}

/// Generate a random prime of the given bit size.
fn generate_prime(bits: usize) -> Result<BigNum, CryptoError> {
    let mr_rounds = if bits >= 512 { 5 } else { 10 };

    for _ in 0..5000 {
        let mut candidate = BigNum::random(bits, true)?;
        candidate.set_bit(bits - 1);

        if candidate.is_probably_prime(mr_rounds)? {
            return Ok(candidate);
        }
    }

    Err(CryptoError::BnRandGenFail)
}

/// Generate a random r in [1, n-1] coprime to n.
fn random_coprime(n: &BigNum) -> Result<BigNum, CryptoError> {
    let one = BigNum::from_u64(1);
    for _ in 0..1000 {
        let r = BigNum::random_range(n)?;
        if r.is_zero() {
            continue;
        }
        let g = r.gcd(n)?;
        if g.is_one() {
            return Ok(r);
        }
    }
    Err(CryptoError::BnRandGenFail)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small test primes for fast tests
    fn small_primes() -> (BigNum, BigNum) {
        // p = 1000000007 (10-digit prime), q = 1000000009 (10-digit prime)
        let p = BigNum::from_u64(1_000_000_007);
        let q = BigNum::from_u64(1_000_000_009);
        (p, q)
    }

    #[test]
    fn test_paillier_encrypt_decrypt() {
        let (p, q) = small_primes();
        let kp = PaillierKeyPair::from_primes(&p, &q).unwrap();

        let m = BigNum::from_u64(42);
        let ct = kp.encrypt(&m.to_bytes_be()).unwrap();
        let pt = kp.decrypt(&ct).unwrap();
        let recovered = BigNum::from_bytes_be(&pt);
        assert_eq!(recovered.to_bytes_be(), m.to_bytes_be());
    }

    #[test]
    fn test_paillier_encrypt_zero() {
        let (p, q) = small_primes();
        let kp = PaillierKeyPair::from_primes(&p, &q).unwrap();

        let m = BigNum::from_u64(0);
        let ct = kp.encrypt(&m.to_bytes_be()).unwrap();
        let pt = kp.decrypt(&ct).unwrap();
        let recovered = BigNum::from_bytes_be(&pt);
        assert!(recovered.is_zero());
    }

    #[test]
    fn test_paillier_homomorphic_add() {
        let (p, q) = small_primes();
        let kp = PaillierKeyPair::from_primes(&p, &q).unwrap();

        let m1 = BigNum::from_u64(3);
        let m2 = BigNum::from_u64(5);

        let ct1 = kp.encrypt(&m1.to_bytes_be()).unwrap();
        let ct2 = kp.encrypt(&m2.to_bytes_be()).unwrap();

        let ct_sum = kp.add_ciphertexts(&ct1, &ct2).unwrap();
        let pt_sum = kp.decrypt(&ct_sum).unwrap();
        let sum = BigNum::from_bytes_be(&pt_sum);

        let expected = BigNum::from_u64(8);
        assert_eq!(sum.to_bytes_be(), expected.to_bytes_be());
    }

    #[test]
    fn test_paillier_large_message() {
        let (p, q) = small_primes();
        let kp = PaillierKeyPair::from_primes(&p, &q).unwrap();

        // n = p * q ≈ 10^18, use a message close to n
        let m = BigNum::from_u64(999_999_999_000_000_000);
        let ct = kp.encrypt(&m.to_bytes_be()).unwrap();
        let pt = kp.decrypt(&ct).unwrap();
        let recovered = BigNum::from_bytes_be(&pt);
        assert_eq!(recovered.to_bytes_be(), m.to_bytes_be());
    }

    #[test]
    fn test_paillier_message_too_large() {
        let (p, q) = small_primes();
        let kp = PaillierKeyPair::from_primes(&p, &q).unwrap();

        // Message >= n should fail
        let n = p.mul(&q);
        assert!(kp.encrypt(&n.to_bytes_be()).is_err());
    }

    #[test]
    #[ignore] // Slow: prime generation in debug mode
    fn test_paillier_generate_512bit() {
        let kp = PaillierKeyPair::generate(512).unwrap();
        let m = BigNum::from_u64(12345);
        let ct = kp.encrypt(&m.to_bytes_be()).unwrap();
        let pt = kp.decrypt(&ct).unwrap();
        assert_eq!(BigNum::from_bytes_be(&pt).to_bytes_be(), m.to_bytes_be());
    }
}
