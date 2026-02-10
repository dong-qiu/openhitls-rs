//! RSA (Rivest-Shamir-Adleman) public-key cryptosystem.
//!
//! Provides RSA key generation, encryption/decryption, and signing/verification.
//! Supports PKCS#1 v1.5, OAEP, and PSS padding schemes. Key sizes of 2048,
//! 3072, and 4096 bits are recommended.

mod oaep;
mod pkcs1v15;
mod pss;

use hitls_bignum::BigNum;
use hitls_types::CryptoError;
use zeroize::Zeroize;

/// Default RSA public exponent (65537).
const RSA_DEFAULT_E: u64 = 65537;

/// Minimum RSA key size in bits.
const RSA_MIN_BITS: usize = 2048;

/// Maximum RSA key size in bits.
const RSA_MAX_BITS: usize = 8192;

/// RSA padding scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPadding {
    /// PKCS#1 v1.5 padding for encryption.
    Pkcs1v15Encrypt,
    /// PKCS#1 v1.5 padding for signatures.
    Pkcs1v15Sign,
    /// OAEP padding (for encryption).
    Oaep,
    /// PSS padding (for signatures).
    Pss,
    /// No padding (raw RSA) -- use with extreme caution.
    None,
}

/// Hash algorithm identifier for RSA padding operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaHashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// An RSA public key.
#[derive(Clone)]
pub struct RsaPublicKey {
    /// The modulus n.
    n: BigNum,
    /// The public exponent e.
    e: BigNum,
    /// Key size in bits.
    bits: usize,
    /// Modulus byte length (k).
    k: usize,
}

impl std::fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaPublicKey")
            .field("bits", &self.bits)
            .finish()
    }
}

impl RsaPublicKey {
    /// Create an RSA public key from modulus and exponent (big-endian bytes).
    pub fn new(n: &[u8], e: &[u8]) -> Result<Self, CryptoError> {
        let n_bn = BigNum::from_bytes_be(n);
        let e_bn = BigNum::from_bytes_be(e);

        if n_bn.is_zero() || n_bn.is_even() {
            return Err(CryptoError::InvalidKey);
        }
        if e_bn.is_zero() || e_bn.is_even() {
            return Err(CryptoError::InvalidKey);
        }

        let bits = n_bn.bit_len();
        let k = bits.div_ceil(8);

        Ok(RsaPublicKey {
            n: n_bn,
            e: e_bn,
            bits,
            k,
        })
    }

    /// Encrypt data using this public key.
    pub fn encrypt(&self, padding: RsaPadding, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match padding {
            RsaPadding::Pkcs1v15Encrypt => {
                let em = pkcs1v15::pkcs1v15_encrypt_pad(plaintext, self.k)?;
                self.raw_encrypt(&em)
            }
            RsaPadding::Oaep => {
                let em = oaep::oaep_encrypt_pad(plaintext, self.k)?;
                self.raw_encrypt(&em)
            }
            RsaPadding::None => self.raw_encrypt(plaintext),
            _ => Err(CryptoError::InvalidArg),
        }
    }

    /// Verify a signature against a message digest.
    pub fn verify(
        &self,
        padding: RsaPadding,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        if signature.len() != self.k {
            return Err(CryptoError::RsaVerifyFail);
        }

        let em = self.raw_encrypt(signature)?;

        match padding {
            RsaPadding::Pkcs1v15Sign => pkcs1v15::pkcs1v15_verify_unpad(&em, digest, self.k),
            RsaPadding::Pss => pss::pss_verify_unpad(&em, digest, self.bits - 1),
            _ => Err(CryptoError::InvalidArg),
        }
    }

    /// Return the key size in bits.
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// Return the modulus byte length.
    pub fn modulus_len(&self) -> usize {
        self.k
    }

    /// Return the modulus as big-endian bytes.
    pub fn n_bytes(&self) -> Vec<u8> {
        self.n.to_bytes_be()
    }

    /// Return the public exponent as big-endian bytes.
    pub fn e_bytes(&self) -> Vec<u8> {
        self.e.to_bytes_be()
    }

    /// Raw RSA public key operation: c = m^e mod n (RSAEP).
    fn raw_encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let m = BigNum::from_bytes_be(data);
        if m >= self.n {
            return Err(CryptoError::InvalidArg);
        }
        let c = m.mod_exp(&self.e, &self.n)?;
        c.to_bytes_be_padded(self.k)
    }
}

/// An RSA private key with CRT optimization.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct RsaPrivateKey {
    /// The modulus n.
    n: BigNum,
    /// The private exponent d.
    d: BigNum,
    /// The public exponent e.
    e: BigNum,
    /// Prime factor p.
    p: BigNum,
    /// Prime factor q.
    q: BigNum,
    /// d mod (p-1) — CRT exponent.
    dp: BigNum,
    /// d mod (q-1) — CRT exponent.
    dq: BigNum,
    /// q^(-1) mod p — CRT coefficient.
    qinv: BigNum,
    /// Key size in bits.
    #[zeroize(skip)]
    bits: usize,
    /// Modulus byte length (k).
    #[zeroize(skip)]
    k: usize,
}

impl std::fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("bits", &self.bits)
            .finish()
    }
}

impl RsaPrivateKey {
    /// Generate a new RSA key pair with the given bit size.
    pub fn generate(bits: usize) -> Result<Self, CryptoError> {
        if !(RSA_MIN_BITS..=RSA_MAX_BITS).contains(&bits) || bits % 2 != 0 {
            return Err(CryptoError::RsaInvalidKeyBits);
        }

        let e = BigNum::from_u64(RSA_DEFAULT_E);
        let half_bits = bits / 2;

        // Generate prime p
        let p = generate_rsa_prime(half_bits, &e)?;

        // Generate prime q (must differ from p)
        let q = loop {
            let candidate = generate_rsa_prime(half_bits, &e)?;
            if candidate != p {
                break candidate;
            }
        };

        // Ensure p > q for consistent CRT
        let (p, q) = if p > q { (p, q) } else { (q, p) };

        // n = p * q
        let n = p.mul(&q);
        if n.bit_len() != bits {
            // Extremely rare: retry if product doesn't have expected bit length
            return Self::generate(bits);
        }

        // phi = (p-1) * (q-1)
        let p_minus_1 = p.sub(&BigNum::from_u64(1));
        let q_minus_1 = q.sub(&BigNum::from_u64(1));
        let phi = p_minus_1.mul(&q_minus_1);

        // d = e^(-1) mod phi
        let d = e.mod_inv(&phi)?;

        // CRT parameters
        let (_, dp) = d.div_rem(&p_minus_1)?;
        let (_, dq) = d.div_rem(&q_minus_1)?;
        let qinv = q.mod_inv(&p)?;

        let k = bits.div_ceil(8);

        Ok(RsaPrivateKey {
            n,
            d,
            e,
            p,
            q,
            dp,
            dq,
            qinv,
            bits,
            k,
        })
    }

    /// Create an RSA private key from its components (big-endian bytes).
    pub fn new(n: &[u8], d: &[u8], e: &[u8], p: &[u8], q: &[u8]) -> Result<Self, CryptoError> {
        let n_bn = BigNum::from_bytes_be(n);
        let d_bn = BigNum::from_bytes_be(d);
        let e_bn = BigNum::from_bytes_be(e);
        let p_bn = BigNum::from_bytes_be(p);
        let q_bn = BigNum::from_bytes_be(q);

        if n_bn.is_zero() || d_bn.is_zero() || e_bn.is_zero() {
            return Err(CryptoError::InvalidKey);
        }

        // Compute CRT parameters
        let p_minus_1 = p_bn.sub(&BigNum::from_u64(1));
        let q_minus_1 = q_bn.sub(&BigNum::from_u64(1));
        let (_, dp) = d_bn.div_rem(&p_minus_1)?;
        let (_, dq) = d_bn.div_rem(&q_minus_1)?;
        let qinv = q_bn.mod_inv(&p_bn)?;

        let bits = n_bn.bit_len();
        let k = bits.div_ceil(8);

        Ok(RsaPrivateKey {
            n: n_bn,
            d: d_bn,
            e: e_bn,
            p: p_bn,
            q: q_bn,
            dp,
            dq,
            qinv,
            bits,
            k,
        })
    }

    /// Decrypt ciphertext using this private key.
    pub fn decrypt(&self, padding: RsaPadding, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() != self.k {
            return Err(CryptoError::InvalidArg);
        }

        let em = self.raw_decrypt(ciphertext)?;

        match padding {
            RsaPadding::Pkcs1v15Encrypt => pkcs1v15::pkcs1v15_decrypt_unpad(&em),
            RsaPadding::Oaep => oaep::oaep_decrypt_unpad(&em),
            RsaPadding::None => Ok(em),
            _ => Err(CryptoError::InvalidArg),
        }
    }

    /// Sign a message digest using this private key.
    pub fn sign(&self, padding: RsaPadding, digest: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match padding {
            RsaPadding::Pkcs1v15Sign => {
                let em = pkcs1v15::pkcs1v15_sign_pad(digest, self.k)?;
                self.raw_decrypt(&em)
            }
            RsaPadding::Pss => {
                let em = pss::pss_sign_pad(digest, self.bits - 1)?;
                self.raw_decrypt(&em)
            }
            RsaPadding::None => self.raw_decrypt(digest),
            _ => Err(CryptoError::InvalidArg),
        }
    }

    /// Extract the corresponding public key.
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            n: self.n.clone(),
            e: self.e.clone(),
            bits: self.bits,
            k: self.k,
        }
    }

    /// Return the modulus as big-endian bytes.
    pub fn n_bytes(&self) -> Vec<u8> {
        self.n.to_bytes_be()
    }

    /// Return the public exponent as big-endian bytes.
    pub fn e_bytes(&self) -> Vec<u8> {
        self.e.to_bytes_be()
    }

    /// Return the private exponent as big-endian bytes.
    pub fn d_bytes(&self) -> Vec<u8> {
        self.d.to_bytes_be()
    }

    /// Return prime factor p as big-endian bytes.
    pub fn p_bytes(&self) -> Vec<u8> {
        self.p.to_bytes_be()
    }

    /// Return prime factor q as big-endian bytes.
    pub fn q_bytes(&self) -> Vec<u8> {
        self.q.to_bytes_be()
    }

    /// Raw RSA private key operation: m = c^d mod n (RSADP).
    /// Uses CRT optimization for ~4x speedup over direct exponentiation.
    fn raw_decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let c = BigNum::from_bytes_be(data);
        if c >= self.n {
            return Err(CryptoError::InvalidArg);
        }

        // CRT: m1 = c^dp mod p, m2 = c^dq mod q
        let m1 = c.mod_exp(&self.dp, &self.p)?;
        let m2 = c.mod_exp(&self.dq, &self.q)?;

        // h = qinv * (m1 - m2 + p) mod p
        // Add p to ensure non-negative before subtraction
        let diff = m1.add(&self.p).sub(&m2);
        let h = diff.mul(&self.qinv).mod_reduce(&self.p)?;

        // m = m2 + h * q
        let m = m2.add(&h.mul(&self.q));

        m.to_bytes_be_padded(self.k)
    }
}

/// Generate an RSA prime of the given bit size.
/// Ensures gcd(p-1, e) = 1 so that e has an inverse mod (p-1).
fn generate_rsa_prime(bits: usize, e: &BigNum) -> Result<BigNum, CryptoError> {
    let one = BigNum::from_u64(1);
    // FIPS 186-4: 5 rounds for >= 1024-bit primes
    let mr_rounds = if bits >= 1024 { 5 } else { 10 };

    for _ in 0..5000 {
        // Generate random odd number with exactly `bits` significant bits
        let mut candidate = BigNum::random(bits, true)?;
        // Set the top bit to ensure exactly `bits` length
        candidate.set_bit(bits - 1);

        // Check gcd(candidate - 1, e) == 1
        let p_minus_1 = candidate.sub(&one);
        let g = p_minus_1.gcd(e)?;
        if !g.is_one() {
            continue;
        }

        // Miller-Rabin primality test
        if candidate.is_probably_prime(mr_rounds)? {
            return Ok(candidate);
        }
    }

    Err(CryptoError::BnPrimeGenFail)
}

/// MGF1 mask generation function (RFC 8017 B.2.1).
/// Uses SHA-256 as the hash function.
pub(crate) fn mgf1_sha256(seed: &[u8], mask_len: usize) -> Vec<u8> {
    use crate::sha2::Sha256;

    let h_len = 32; // SHA-256 output size
    let iterations = mask_len.div_ceil(h_len);
    let mut t = Vec::with_capacity(iterations * h_len);

    for counter in 0..iterations {
        let mut hasher = Sha256::new();
        hasher.update(seed).unwrap();
        hasher.update(&(counter as u32).to_be_bytes()).unwrap();
        let hash = hasher.finish().unwrap();
        t.extend_from_slice(&hash);
    }

    t.truncate(mask_len);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: hex string to bytes.
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // A valid RSA-1024 key generated by OpenSSL (NOT for production use).
    // Verified: n = p * q, d * e ≡ 1 (mod (p-1)(q-1)).
    #[allow(clippy::type_complexity)]
    fn test_key_1024() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let n = hex(
            "00d531c26a4cc6443cca66325ba2746a7eaf0423112d1aa222c8a89f5bb8d12c\
             3dccf8386a53b9aa4d1cfbe5b17ddb8a329732110aa1dd06c55dccb849e5ffc8\
             b2c213bdc95d8fe28e4b75b483b95b7d4cde85ab58dd9cc2b741b79b74c0d09c\
             df85612ca1793d16e28e8d98af311ac3b242c074e551767d0659e9fbaae940c091",
        );
        let e = hex("010001");
        let d = hex(
            "0df14923a68db8dcb8e7e2173812a0fc53f9d3494647dd9ea4bcd25f2f410ec1\
             a3ebffd484513a1ffceb44644d34d45ee6a07198de69140e484a212b440d6c54\
             95e905a5294f7f30066100900603b9f68d2c23d149bb3a09393bca9b09a6d479\
             dd953b76884fb7127db6d169fd7bbdfa5fcd8047876d965d936e819232622cb9",
        );
        let p = hex(
            "00ed8bdd1da05a922e09eae43fc535ba4c0fb7315dab0b6a24136a7ddc0803c1\
             6426f829298419218307822335145a1dc864e3e165a09444fc6106f93809bb934f",
        );
        let q = hex(
            "00e5c19a4c79326ace1080b907791eb70a6a8a164473e18445193743a784f68a\
             72867b962d8c5c42a68ef865c79660a2ae63a9ae8dec8bdcd28e348a3b3544f61f",
        );
        (n, e, d, p, q)
    }

    #[test]
    fn test_rsa_raw_encrypt_decrypt() {
        let (n, e, d, p, q) = test_key_1024();
        let pub_key = RsaPublicKey::new(&n, &e).unwrap();
        let priv_key = RsaPrivateKey::new(&n, &d, &e, &p, &q).unwrap();

        // Raw RSA: encrypt then decrypt
        let msg = hex(
            "0000000000000000000000000000000000000000000000000000000000000000\
                       0000000000000000000000000000000000000000000000000000000000000000\
                       0000000000000000000000000000000000000000000000000000000000000000\
                       00000000000000000000000000000000000000000000000000000000deadbeef",
        );
        let ct = pub_key.encrypt(RsaPadding::None, &msg).unwrap();
        let pt = priv_key.decrypt(RsaPadding::None, &ct).unwrap();
        assert_eq!(msg, pt);
    }

    #[test]
    #[ignore] // Slow in debug mode (~minutes); run with: cargo test --release -- --ignored
    fn test_rsa_keygen_basic() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        assert_eq!(key.bits, 2048);
        assert_eq!(key.k, 256);

        // Verify: n = p * q
        let n_check = key.p.mul(&key.q);
        assert_eq!(key.n, n_check);

        // Verify: d * e ≡ 1 (mod phi)
        let one = BigNum::from_u64(1);
        let p_minus_1 = key.p.sub(&one);
        let q_minus_1 = key.q.sub(&one);
        let phi = p_minus_1.mul(&q_minus_1);
        let de = key.d.mul(&key.e);
        let (_, rem) = de.div_rem(&phi).unwrap();
        assert!(rem.is_one());

        // Verify round-trip: sign and verify
        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        let sig = key.sign(RsaPadding::Pkcs1v15Sign, &digest).unwrap();
        let pub_key = key.public_key();
        let valid = pub_key
            .verify(RsaPadding::Pkcs1v15Sign, &digest, &sig)
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_rsa_pkcs1v15_sign_verify() {
        let (n, e, d, p, q) = test_key_1024();
        let pub_key = RsaPublicKey::new(&n, &e).unwrap();
        let priv_key = RsaPrivateKey::new(&n, &d, &e, &p, &q).unwrap();

        // SHA-256 digest of "hello" (pre-computed)
        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

        let sig = priv_key.sign(RsaPadding::Pkcs1v15Sign, &digest).unwrap();
        assert_eq!(sig.len(), priv_key.k);

        let valid = pub_key
            .verify(RsaPadding::Pkcs1v15Sign, &digest, &sig)
            .unwrap();
        assert!(valid);

        // Tampered digest should fail
        let mut bad_digest = digest.clone();
        bad_digest[0] ^= 0x01;
        let invalid = pub_key
            .verify(RsaPadding::Pkcs1v15Sign, &bad_digest, &sig)
            .unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_rsa_pkcs1v15_encrypt_decrypt() {
        let (n, e, d, p, q) = test_key_1024();
        let pub_key = RsaPublicKey::new(&n, &e).unwrap();
        let priv_key = RsaPrivateKey::new(&n, &d, &e, &p, &q).unwrap();

        let msg = b"Hello, RSA!";
        let ct = pub_key.encrypt(RsaPadding::Pkcs1v15Encrypt, msg).unwrap();
        assert_eq!(ct.len(), pub_key.k);

        let pt = priv_key.decrypt(RsaPadding::Pkcs1v15Encrypt, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn test_rsa_oaep_encrypt_decrypt() {
        let (n, e, d, p, q) = test_key_1024();
        let pub_key = RsaPublicKey::new(&n, &e).unwrap();
        let priv_key = RsaPrivateKey::new(&n, &d, &e, &p, &q).unwrap();

        let msg = b"OAEP test message";
        let ct = pub_key.encrypt(RsaPadding::Oaep, msg).unwrap();
        assert_eq!(ct.len(), pub_key.k);

        let pt = priv_key.decrypt(RsaPadding::Oaep, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn test_rsa_pss_sign_verify() {
        let (n, e, d, p, q) = test_key_1024();
        let pub_key = RsaPublicKey::new(&n, &e).unwrap();
        let priv_key = RsaPrivateKey::new(&n, &d, &e, &p, &q).unwrap();

        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

        let sig = priv_key.sign(RsaPadding::Pss, &digest).unwrap();
        assert_eq!(sig.len(), priv_key.k);

        let valid = pub_key.verify(RsaPadding::Pss, &digest, &sig).unwrap();
        assert!(valid);

        // Tampered digest should fail
        let mut bad_digest = digest.clone();
        bad_digest[0] ^= 0x01;
        let invalid = pub_key.verify(RsaPadding::Pss, &bad_digest, &sig).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_rsa_public_key_extraction() {
        let (n, e, d, p, q) = test_key_1024();
        let priv_key = RsaPrivateKey::new(&n, &d, &e, &p, &q).unwrap();
        let pub_key = priv_key.public_key();

        assert_eq!(pub_key.bits(), priv_key.bits);
        assert_eq!(pub_key.n, priv_key.n);
        assert_eq!(pub_key.e, priv_key.e);
    }

    #[test]
    fn test_rsa_invalid_key_sizes() {
        // Too small
        assert!(RsaPrivateKey::generate(1024).is_err());
        // Odd
        assert!(RsaPrivateKey::generate(2049).is_err());
    }

    #[test]
    fn test_mgf1_sha256() {
        // RFC 8017 doesn't provide standalone MGF1 test vectors,
        // so we test basic properties: deterministic and correct length
        let seed = b"test seed";
        let mask1 = mgf1_sha256(seed, 48);
        let mask2 = mgf1_sha256(seed, 48);
        assert_eq!(mask1.len(), 48);
        assert_eq!(mask1, mask2); // deterministic

        let mask3 = mgf1_sha256(seed, 64);
        assert_eq!(mask3.len(), 64);
        assert_eq!(&mask3[..48], &mask1[..]); // prefix matches shorter mask
    }
}
