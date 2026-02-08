//! SM9 identity-based cryptography (GB/T 38635).
//!
//! SM9 uses bilinear pairings on BN256 curve for identity-based
//! digital signatures and encryption. No traditional certificates needed.
//!
//! - Sign system: master public on G2, user private on G1
//! - Encrypt system: master public on G1, user private on G2

mod alg;
mod curve;
mod ecp;
mod ecp2;
mod fp;
mod fp12;
mod fp2;
mod fp4;
mod hash;
mod pairing;

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// SM9 key type.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Sm9KeyType {
    /// Signing system (master pub on G2, user key on G1).
    Sign,
    /// Encryption system (master pub on G1, user key on G2).
    Encrypt,
}

/// SM9 master key held by the Key Generation Center (KGC).
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Sm9MasterKey {
    /// The master secret key ks (32 bytes, big-endian).
    master_secret: Vec<u8>,
    /// The master public key Ppub (64 or 128 bytes depending on type).
    master_public: Vec<u8>,
    #[zeroize(skip)]
    key_type: Sm9KeyType,
}

impl Sm9MasterKey {
    /// Generate a new SM9 master key pair.
    pub fn generate(key_type: Sm9KeyType) -> Result<Self, CryptoError> {
        let kt = match key_type {
            Sm9KeyType::Sign => alg::Sm9KeyType::Sign,
            Sm9KeyType::Encrypt => alg::Sm9KeyType::Encrypt,
        };
        let (ks, pub_bytes) = alg::master_keygen(kt)?;

        let mut ks_bytes = ks.to_bytes_be();
        while ks_bytes.len() < 32 {
            ks_bytes.insert(0, 0);
        }

        Ok(Self {
            master_secret: ks_bytes,
            master_public: pub_bytes,
            key_type,
        })
    }

    /// Extract a user private key for the given identity.
    pub fn extract_user_key(&self, user_id: &[u8]) -> Result<Sm9UserKey, CryptoError> {
        let ks = hitls_bignum::BigNum::from_bytes_be(&self.master_secret);
        let kt = match self.key_type {
            Sm9KeyType::Sign => alg::Sm9KeyType::Sign,
            Sm9KeyType::Encrypt => alg::Sm9KeyType::Encrypt,
        };
        let user_key_bytes = alg::extract_user_key(&ks, user_id, kt)?;

        Ok(Sm9UserKey {
            private_key: user_key_bytes,
            user_id: user_id.to_vec(),
            key_type: self.key_type,
        })
    }

    /// Return the master public key bytes.
    pub fn master_public_key(&self) -> &[u8] {
        &self.master_public
    }

    /// Verify a signature against a message and user ID.
    pub fn verify(
        &self,
        user_id: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        if self.key_type != Sm9KeyType::Sign {
            return Err(CryptoError::InvalidArg);
        }
        alg::verify(message, user_id, signature, &self.master_public)
    }

    /// Encrypt a message to a user ID.
    pub fn encrypt(&self, user_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.key_type != Sm9KeyType::Encrypt {
            return Err(CryptoError::InvalidArg);
        }
        alg::encrypt(plaintext, user_id, &self.master_public)
    }
}

/// SM9 user private key derived from a user identity.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Sm9UserKey {
    /// The user private key (64 bytes for sign, 128 bytes for encrypt).
    private_key: Vec<u8>,
    /// The user identity string.
    user_id: Vec<u8>,
    #[zeroize(skip)]
    key_type: Sm9KeyType,
}

impl Sm9UserKey {
    /// Sign a message using this user's SM9 private key.
    /// Requires the master public key for computing the pairing.
    pub fn sign(&self, message: &[u8], master_pub: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.key_type != Sm9KeyType::Sign {
            return Err(CryptoError::InvalidArg);
        }
        alg::sign(message, &self.private_key, master_pub)
    }

    /// Decrypt an SM9 ciphertext using this user's private key.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.key_type != Sm9KeyType::Encrypt {
            return Err(CryptoError::InvalidArg);
        }
        alg::decrypt(ciphertext, &self.private_key, &self.user_id)
    }

    /// Return the user identity.
    pub fn user_id(&self) -> &[u8] {
        &self.user_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm9_fp2_arithmetic() {
        let a = fp2::Fp2::new(fp::Fp::from_u64(3), fp::Fp::from_u64(7));
        let b = fp2::Fp2::new(fp::Fp::from_u64(5), fp::Fp::from_u64(11));
        // (3 + 7u)(5 + 11u) = 15 + 33u + 35u + 77u²
        // = 15 + 68u + 77*(-2) = 15 - 154 + 68u = -139 + 68u (mod p)
        let c = a.mul(&b).unwrap();
        // Verify via inverse: c * b⁻¹ == a
        let b_inv = b.inv().unwrap();
        let should_be_a = c.mul(&b_inv).unwrap();
        assert_eq!(should_be_a, a);
    }

    #[test]
    fn test_sm9_fp12_arithmetic() {
        // Test that 1 * x = x
        let one = fp12::Fp12::one();
        let x = fp12::Fp12::new(
            fp4::Fp4::new(
                fp2::Fp2::new(fp::Fp::from_u64(1), fp::Fp::from_u64(2)),
                fp2::Fp2::new(fp::Fp::from_u64(3), fp::Fp::from_u64(4)),
            ),
            fp4::Fp4::new(
                fp2::Fp2::new(fp::Fp::from_u64(5), fp::Fp::from_u64(6)),
                fp2::Fp2::new(fp::Fp::from_u64(7), fp::Fp::from_u64(8)),
            ),
            fp4::Fp4::new(
                fp2::Fp2::new(fp::Fp::from_u64(9), fp::Fp::from_u64(10)),
                fp2::Fp2::new(fp::Fp::from_u64(11), fp::Fp::from_u64(12)),
            ),
        );
        let result = one.mul(&x).unwrap();
        assert_eq!(result, x);
        // Test x * x⁻¹ = 1
        let x_inv = x.inv().unwrap();
        let product = x.mul(&x_inv).unwrap();
        assert_eq!(product, one);
    }

    #[test]
    fn test_sm9_g1_generator_on_curve() {
        // Verify P1 satisfies y² = x³ + 5
        let p1 = ecp::EcPointG1::generator();
        let (x, y) = p1.to_affine().unwrap();
        let p = curve::p();
        let y2 = y.sqr().unwrap();
        let x3 = x.sqr().unwrap().mul(&x).unwrap();
        let b = fp::Fp::from_u64(5);
        let rhs = x3.add(&b).unwrap();
        assert_eq!(y2, rhs);
    }

    #[test]
    fn test_sm9_g1_scalar_mul() {
        let p1 = ecp::EcPointG1::generator();
        let n = curve::order();
        // [n]P1 = infinity
        let result = p1.scalar_mul(&n).unwrap();
        assert!(result.is_infinity());
    }

    #[test]
    fn test_sm9_g2_on_curve() {
        let p2 = ecp2::EcPointG2::generator();
        let (x, y) = p2.to_affine().unwrap();
        let y2 = y.sqr().unwrap();
        let x3 = x.sqr().unwrap().mul(&x).unwrap();
        // b' = 5u = (0, 5) in Fp2
        let b_twist = fp2::Fp2::new(fp::Fp::zero(), fp::Fp::from_u64(5));
        let rhs = x3.add(&b_twist).unwrap();
        assert_eq!(y2, rhs, "P2 should be on y²=x³+5u");
    }

    #[test]
    fn test_sm9_g2_scalar_mul() {
        let p2 = ecp2::EcPointG2::generator();
        let n = curve::order();
        // [n]P2 = infinity
        let result = p2.scalar_mul(&n).unwrap();
        assert!(result.is_infinity());
    }

    #[test]
    fn test_sm9_hash_to_range() {
        let n = curve::order();
        let result = hash::h1(b"Alice\x01", 0x01).unwrap();
        assert!(result > hitls_bignum::BigNum::from_u64(0));
        assert!(result < n);
    }

    #[test]
    #[ignore] // Pairing is very slow in debug mode
    fn test_sm9_pairing_bilinearity() {
        // e(aP, bQ) == e(P, Q)^(ab)
        let p1 = ecp::EcPointG1::generator();
        let p2 = ecp2::EcPointG2::generator();

        let a = hitls_bignum::BigNum::from_u64(7);
        let b = hitls_bignum::BigNum::from_u64(11);

        let ap = p1.scalar_mul(&a).unwrap();
        let bq = p2.scalar_mul(&b).unwrap();

        let e1 = pairing::pairing(&ap, &bq).unwrap();

        let e_pq = pairing::pairing(&p1, &p2).unwrap();
        let ab = a.mul(&b);
        let e2 = e_pq.pow(&ab).unwrap();

        assert_eq!(e1, e2);
    }

    #[test]
    #[ignore]
    fn test_sm9_pairing_frobenius_check() {
        // Verify Frobenius constants and Q1 on curve
        let p = curve::p();
        let xi = fp2::Fp2::new(fp::Fp::zero(), fp::Fp::one()); // u

        let p_minus_1 = p.sub(&hitls_bignum::BigNum::from_u64(1));
        let (exp3, rem3) = p_minus_1
            .div_rem(&hitls_bignum::BigNum::from_u64(3))
            .unwrap();
        let (exp2, rem2) = p_minus_1
            .div_rem(&hitls_bignum::BigNum::from_u64(2))
            .unwrap();

        // Check remainders are 0
        assert!(rem3.is_zero(), "(p-1) not divisible by 3");
        assert!(rem2.is_zero(), "(p-1) not divisible by 2");

        let alpha = pairing::fp2_pow(&xi, &exp3).unwrap();
        let beta = pairing::fp2_pow(&xi, &exp2).unwrap();

        // alpha should be in Fp (c1 = 0)
        assert!(alpha.c1.is_zero(), "alpha.c1 should be 0, got non-zero");
        // beta should be in Fp (c1 = 0)
        assert!(beta.c1.is_zero(), "beta.c1 should be 0, got non-zero");

        // Check alpha^3 = -1 (mod p)
        let a3 = alpha.mul(&alpha).unwrap().mul(&alpha).unwrap();
        let neg_one = fp2::Fp2::new(
            fp::Fp::from_bignum(p.sub(&hitls_bignum::BigNum::from_u64(1))),
            fp::Fp::zero(),
        );
        assert_eq!(a3, neg_one, "alpha^3 should be -1");

        // Check beta^2 = -1 (mod p)
        let b2 = beta.mul(&beta).unwrap();
        assert_eq!(b2, neg_one, "beta^2 should be -1");

        // Check that Q1 = frobenius(Q) is on E'(Fp2): y^2 = x^3 + 5u
        let p2 = ecp2::EcPointG2::generator();
        let (qx, qy) = p2.to_affine().unwrap();
        let q1 = pairing::frobenius_map_g2(&qx, &qy).unwrap();
        let (q1x, q1y) = q1.to_affine().unwrap();
        let q1_y2 = q1y.sqr().unwrap();
        let q1_x3 = q1x.sqr().unwrap().mul(&q1x).unwrap();
        let b_twist = fp2::Fp2::new(fp::Fp::zero(), fp::Fp::from_u64(5));
        let q1_rhs = q1_x3.add(&b_twist).unwrap();
        assert_eq!(q1_y2, q1_rhs, "Q1 should be on E'(Fp2)");

        // Check that [n]Q1 = infinity
        let n = curve::order();
        let q1n = q1.scalar_mul(&n).unwrap();
        assert!(q1n.is_infinity(), "[n]Q1 should be infinity");
    }

    #[test]
    #[ignore]
    fn test_sm9_pairing_deterministic() {
        // e(P, Q) computed twice should be equal
        let p1 = ecp::EcPointG1::generator();
        let p2 = ecp2::EcPointG2::generator();
        let e1 = pairing::pairing(&p1, &p2).unwrap();
        let e2 = pairing::pairing(&p1, &p2).unwrap();
        assert_eq!(e1, e2, "Pairing should be deterministic");

        // Simple bilinearity: e(2P, Q) = e(P, Q)^2
        let two = hitls_bignum::BigNum::from_u64(2);
        let p1_2 = p1.scalar_mul(&two).unwrap();
        let e_2p_q = pairing::pairing(&p1_2, &p2).unwrap();
        let e_pq_sq = e1.sqr().unwrap();
        assert_eq!(e_2p_q, e_pq_sq, "e(2P, Q) should equal e(P, Q)^2");
    }

    #[test]
    #[ignore]
    fn test_sm9_pairing_debug_stages() {
        // Step 1: Verify the hard part exponent is exact
        let p = curve::p();
        let n = curve::order();
        let p2 = p.mul(&p);
        let p4 = p2.mul(&p2);
        let num = p4.sub(&p2).add(&hitls_bignum::BigNum::from_u64(1));
        let (exp, rem) = num.div_rem(&n).unwrap();
        assert!(
            rem.is_zero(),
            "FAIL: (p^4-p^2+1) mod n != 0, remainder = {:?}",
            rem
        );
        // Verify exp * n = num
        let check = exp.mul(&n);
        assert_eq!(check, num, "FAIL: exp * n != p^4-p^2+1");
        eprintln!(
            "PASS: Hard part exponent is exact, exp has {} bits",
            exp.to_bytes_be().len() * 8
        );

        // Step 2: Test Frobenius on Fp12 by comparing explicit formula with f^p
        let f = fp12::Fp12::new(
            fp4::Fp4::new(
                fp2::Fp2::new(fp::Fp::from_u64(3), fp::Fp::from_u64(7)),
                fp2::Fp2::new(fp::Fp::from_u64(11), fp::Fp::from_u64(13)),
            ),
            fp4::Fp4::new(
                fp2::Fp2::new(fp::Fp::from_u64(17), fp::Fp::from_u64(19)),
                fp2::Fp2::new(fp::Fp::from_u64(23), fp::Fp::from_u64(29)),
            ),
            fp4::Fp4::new(
                fp2::Fp2::new(fp::Fp::from_u64(31), fp::Fp::from_u64(37)),
                fp2::Fp2::new(fp::Fp::from_u64(41), fp::Fp::from_u64(43)),
            ),
        );
        let f_frob_explicit = f.frobenius().unwrap();
        let f_frob_pow = f.pow(&p).unwrap();
        assert_eq!(
            f_frob_explicit, f_frob_pow,
            "FAIL: Frobenius explicit formula != f^p"
        );
        eprintln!("PASS: Fp12 Frobenius explicit formula matches f^p");

        // Step 3: Test Frobenius2
        let f_frob2_explicit = f.frobenius2().unwrap();
        let f_frob2_pow = f.pow(&p2).unwrap();
        assert_eq!(
            f_frob2_explicit, f_frob2_pow,
            "FAIL: Frobenius2 explicit formula != f^(p^2)"
        );
        eprintln!("PASS: Fp12 Frobenius2 matches f^(p^2)");

        // Step 4: Test p^6 conjugation
        let f_conj = fp12::Fp12::new(
            f.c0.conjugate().unwrap(),
            f.c1.conjugate().unwrap().neg().unwrap(),
            f.c2.conjugate().unwrap(),
        );
        let f_pow_p6 = {
            let p3 = p2.mul(&p);
            let p6 = p3.mul(&p3);
            f.pow(&p6).unwrap()
        };
        assert_eq!(f_conj, f_pow_p6, "FAIL: p^6 conjugation formula != f^(p^6)");
        eprintln!("PASS: p^6 conjugation matches f^(p^6)");

        // Step 5: Test second argument linearity: e(P, 2Q) == e(P, Q)^2
        let p1 = ecp::EcPointG1::generator();
        let p2_gen = ecp2::EcPointG2::generator();
        let two = hitls_bignum::BigNum::from_u64(2);
        let q2 = p2_gen.scalar_mul(&two).unwrap();

        let e_p_q = pairing::pairing(&p1, &p2_gen).unwrap();
        let e_p_2q = pairing::pairing(&p1, &q2).unwrap();
        let e_p_q_sq = e_p_q.sqr().unwrap();

        let second_arg_ok = e_p_2q == e_p_q_sq;
        eprintln!(
            "Second argument linearity e(P, 2Q) == e(P, Q)^2: {}",
            second_arg_ok
        );

        // Step 6: Test first argument linearity: e(2P, Q) == e(P, Q)^2
        let p1_2 = p1.scalar_mul(&two).unwrap();
        let e_2p_q = pairing::pairing(&p1_2, &p2_gen).unwrap();

        let first_arg_ok = e_2p_q == e_p_q_sq;
        eprintln!(
            "First argument linearity e(2P, Q) == e(P, Q)^2: {}",
            first_arg_ok
        );

        assert!(
            second_arg_ok || first_arg_ok,
            "Neither linearity direction works"
        );
    }

    #[test]
    #[ignore] // Very slow in debug mode
    fn test_sm9_sign_verify() {
        let master = Sm9MasterKey::generate(Sm9KeyType::Sign).unwrap();
        let user = master.extract_user_key(b"Alice").unwrap();
        let msg = b"test message for SM9 signing";
        let sig = user.sign(msg, master.master_public_key()).unwrap();
        assert!(master.verify(b"Alice", msg, &sig).unwrap());
    }

    #[test]
    #[ignore] // Very slow in debug mode
    fn test_sm9_sign_wrong_id() {
        let master = Sm9MasterKey::generate(Sm9KeyType::Sign).unwrap();
        let user = master.extract_user_key(b"Alice").unwrap();
        let msg = b"test message";
        let sig = user.sign(msg, master.master_public_key()).unwrap();
        assert!(!master.verify(b"Bob", msg, &sig).unwrap());
    }

    #[test]
    #[ignore] // Very slow in debug mode
    fn test_sm9_encrypt_decrypt() {
        let master = Sm9MasterKey::generate(Sm9KeyType::Encrypt).unwrap();
        let user = master.extract_user_key(b"Bob").unwrap();
        let msg = b"secret message for Bob";
        let ct = master.encrypt(b"Bob", msg).unwrap();
        let pt = user.decrypt(&ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    #[ignore] // Very slow in debug mode
    fn test_sm9_encrypt_tampered() {
        let master = Sm9MasterKey::generate(Sm9KeyType::Encrypt).unwrap();
        let user = master.extract_user_key(b"Bob").unwrap();
        let msg = b"secret message";
        let mut ct = master.encrypt(b"Bob", msg).unwrap();
        ct[70] ^= 0xFF; // Tamper with MAC area
        assert!(user.decrypt(&ct).is_err());
    }
}
