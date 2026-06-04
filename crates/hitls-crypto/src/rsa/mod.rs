//! RSA (Rivest-Shamir-Adleman) public-key cryptosystem.
//!
//! Provides RSA key generation, encryption/decryption, and signing/verification.
//! Supports PKCS#1 v1.5, OAEP, PSS, and ISO/IEC 9796-2:1997 Scheme 1 padding
//! schemes. Key sizes of 2048, 3072, and 4096 bits are recommended.

mod iso9796_2;
mod oaep;
mod pkcs1v15;
mod pss;

use hitls_bignum::{BigNum, MontgomeryCtx};
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
    /// ISO/IEC 9796-2:1997 Scheme 1 padding for signatures.
    /// Encoded form: `0x6A || H(m) || 0xBC`. Deterministic, no message
    /// recovery, no DigestInfo prefix.
    Iso9796_2,
    /// No padding (raw RSA) -- use with extreme caution.
    None,
}

/// Hash algorithm identifier for RSA padding operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaHashAlg {
    Sha1,
    Sha224,
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
            _ => Err(CryptoError::InvalidArg("")),
        }
    }

    /// OAEP-encrypt with an explicit hash function (MGF1 uses the same hash;
    /// empty label). `RsaPadding::Oaep` in [`Self::encrypt`] is the SHA-256
    /// case; this exposes SHA-1/384/512 for interop. SHA-1 requires the
    /// `sha1` feature.
    pub fn encrypt_oaep(&self, plaintext: &[u8], alg: RsaHashAlg) -> Result<Vec<u8>, CryptoError> {
        let em = oaep::oaep_encrypt_pad_alg(plaintext, self.k, alg)?;
        self.raw_encrypt(&em)
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
            RsaPadding::Iso9796_2 => iso9796_2::iso9796_2_verify(&em, digest),
            _ => Err(CryptoError::InvalidArg("")),
        }
    }

    /// Verify a PSS signature with an explicit hash algorithm (Phase T95).
    /// Use this when the PSS hash is not SHA-256 (the default
    /// `verify(RsaPadding::Pss, ...)` is SHA-256 only). `digest.len()`
    /// must equal the output size of `alg`.
    pub fn verify_pss(
        &self,
        digest: &[u8],
        signature: &[u8],
        alg: RsaHashAlg,
    ) -> Result<bool, CryptoError> {
        if signature.len() != self.k {
            return Err(CryptoError::RsaVerifyFail);
        }
        let em = self.raw_encrypt(signature)?;
        pss::pss_verify_unpad_alg(&em, digest, self.bits - 1, alg)
    }

    /// Verify a PSS signature with an explicit hash algorithm **and** salt
    /// length (RFC 8017 EMSA-PSS-VERIFY `sLen`). Use this when the salt length
    /// is not the hash output length (the [`Self::verify_pss`] default) — e.g.
    /// NIST FIPS 186 PSS vectors often use a fixed 20-byte salt regardless of
    /// the hash. `digest.len()` must equal the output size of `alg`.
    pub fn verify_pss_with_salt(
        &self,
        digest: &[u8],
        signature: &[u8],
        alg: RsaHashAlg,
        salt_len: usize,
    ) -> Result<bool, CryptoError> {
        if signature.len() != self.k {
            return Err(CryptoError::RsaVerifyFail);
        }
        let em = self.raw_encrypt(signature)?;
        pss::pss_verify_unpad_with_salt_alg(&em, digest, self.bits - 1, salt_len, alg)
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
            return Err(CryptoError::InvalidArg(""));
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
    /// Cached Montgomery context for mod p (avoids R² recomputation per CRT op).
    #[zeroize(skip)]
    mont_p: Option<MontgomeryCtx>,
    /// Cached Montgomery context for mod q.
    #[zeroize(skip)]
    mont_q: Option<MontgomeryCtx>,
    /// q^(-1) mod p in Montgomery form (avoids per-operation to_mont + mod_reduce).
    #[zeroize(skip)]
    qinv_mont: Option<BigNum>,
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

        // Pre-build Montgomery contexts for CRT (eliminates R² recomputation per decrypt)
        let mont_p = MontgomeryCtx::new(&p).ok();
        let mont_q = MontgomeryCtx::new(&q).ok();
        let qinv_mont = mont_p.as_ref().and_then(|ctx| ctx.to_mont(&qinv).ok());

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
            mont_p,
            mont_q,
            qinv_mont,
        })
    }

    /// **KAT / testing only.** Build a private key from just `(n, d)` — no CRT
    /// parameters. `sign` / `decrypt` then use the plain `m = c^d mod n` path,
    /// which is **not** side-channel-hardened (production keys go through
    /// [`Self::new`] with `p, q` and use the CRT path). This exists only to
    /// reproduce sign / decrypt KAT vectors that publish only `(n, d)`; it is
    /// gated behind the non-default `kat-nonce` feature and marked
    /// `#[deprecated]` as a danger sentinel.
    #[cfg(feature = "kat-nonce")]
    #[doc(hidden)]
    #[deprecated(
        note = "test/KAT only: builds a non-CRT (n,d) key whose plain-d private \
                path is not side-channel-hardened — never use in production"
    )]
    pub fn from_nd(n: &[u8], d: &[u8]) -> Result<Self, CryptoError> {
        let n_bn = BigNum::from_bytes_be(n);
        let d_bn = BigNum::from_bytes_be(d);
        if n_bn.is_zero() || d_bn.is_zero() {
            return Err(CryptoError::InvalidKey);
        }
        let bits = n_bn.bit_len();
        let k = bits.div_ceil(8);
        Ok(RsaPrivateKey {
            n: n_bn,
            d: d_bn,
            // No e / CRT params: a zero `p` selects the plain-d path in
            // `raw_decrypt`.
            e: BigNum::from_u64(0),
            p: BigNum::from_u64(0),
            q: BigNum::from_u64(0),
            dp: BigNum::from_u64(0),
            dq: BigNum::from_u64(0),
            qinv: BigNum::from_u64(0),
            bits,
            k,
            mont_p: None,
            mont_q: None,
            qinv_mont: None,
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

        // Pre-build Montgomery contexts for CRT
        let mont_p = MontgomeryCtx::new(&p_bn).ok();
        let mont_q = MontgomeryCtx::new(&q_bn).ok();
        let qinv_mont = mont_p.as_ref().and_then(|ctx| ctx.to_mont(&qinv).ok());

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
            mont_p,
            mont_q,
            qinv_mont,
        })
    }

    /// Decrypt ciphertext using this private key.
    pub fn decrypt(&self, padding: RsaPadding, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() != self.k {
            return Err(CryptoError::InvalidArg(""));
        }

        let em = self.raw_decrypt(ciphertext)?;

        match padding {
            RsaPadding::Pkcs1v15Encrypt => pkcs1v15::pkcs1v15_decrypt_unpad(&em),
            RsaPadding::Oaep => oaep::oaep_decrypt_unpad(&em),
            RsaPadding::None => Ok(em),
            _ => Err(CryptoError::InvalidArg("")),
        }
    }

    /// OAEP-decrypt with an explicit hash function (MGF1 uses the same hash;
    /// empty label). `RsaPadding::Oaep` in [`Self::decrypt`] is the SHA-256
    /// case; this exposes SHA-1/384/512 for interop. SHA-1 requires the
    /// `sha1` feature.
    pub fn decrypt_oaep(&self, ciphertext: &[u8], alg: RsaHashAlg) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() != self.k {
            return Err(CryptoError::InvalidArg(""));
        }
        let em = self.raw_decrypt(ciphertext)?;
        oaep::oaep_decrypt_unpad_alg(&em, alg)
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
            RsaPadding::Iso9796_2 => {
                let em = iso9796_2::iso9796_2_encode(digest, self.k)?;
                self.raw_decrypt(&em)
            }
            RsaPadding::None => self.raw_decrypt(digest),
            _ => Err(CryptoError::InvalidArg("")),
        }
    }

    /// Sign with PSS using an explicit hash algorithm (Phase T95).
    /// Use this when the PSS hash is not SHA-256 (the default
    /// `sign(RsaPadding::Pss, ...)` is SHA-256 only). `digest.len()`
    /// must equal the output size of `alg`.
    pub fn sign_pss(&self, digest: &[u8], alg: RsaHashAlg) -> Result<Vec<u8>, CryptoError> {
        let em = pss::pss_sign_pad_alg(digest, self.bits - 1, alg)?;
        self.raw_decrypt(&em)
    }

    /// **KAT / testing only.** PSS sign with a caller-provided fixed `salt`
    /// (the normal [`Self::sign_pss`] generates a random salt of length
    /// `h_len(alg)`). PSS does not require salt secrecy and salt reuse does
    /// not leak the private key (unlike an ECDSA/DSA nonce), but a fixed salt
    /// removes the scheme's randomisation, so this is gated behind the
    /// non-default `kat-nonce` feature and marked `#[deprecated]` as a danger
    /// sentinel. It exists only to reproduce fixed-salt PSS sign KAT vectors.
    #[cfg(feature = "kat-nonce")]
    #[doc(hidden)]
    #[deprecated(
        note = "test/KAT only: a fixed PSS salt removes the scheme's randomisation — \
                production code must use sign_pss (random salt)"
    )]
    pub fn sign_pss_with_salt(
        &self,
        digest: &[u8],
        alg: RsaHashAlg,
        salt: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let em = pss::pss_sign_pad_with_salt_bytes_alg(digest, self.bits - 1, salt, alg)?;
        self.raw_decrypt(&em)
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
    /// Uses CRT optimization with cached Montgomery contexts for ~4x speedup.
    fn raw_decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let c = BigNum::from_bytes_be(data);
        if c >= self.n {
            return Err(CryptoError::InvalidArg(""));
        }

        // Non-CRT key (built via the test-only `from_nd`, which leaves `p`
        // zero): plain m = c^d mod n. Gated behind `kat-nonce` so this
        // unhardened path is NOT compiled into production builds — the only
        // way to reach a zero-`p` key is `from_nd`, which is itself
        // `kat-nonce`-only, so production keys (always built via `new`, which
        // requires non-zero CRT primes) never see this branch.
        #[cfg(feature = "kat-nonce")]
        if self.p.is_zero() {
            let m = c.mod_exp(&self.d, &self.n)?;
            return m.to_bytes_be_padded(self.k);
        }

        // CRT with cached Montgomery contexts (skip R² recomputation per call)
        let (m1, m2) = match (&self.mont_p, &self.mont_q) {
            (Some(ctx_p), Some(ctx_q)) => {
                let m1 = ctx_p.mont_exp(&c, &self.dp)?;
                let m2 = ctx_q.mont_exp(&c, &self.dq)?;
                (m1, m2)
            }
            _ => {
                // Fallback: compute contexts on the fly
                let m1 = c.mod_exp(&self.dp, &self.p)?;
                let m2 = c.mod_exp(&self.dq, &self.q)?;
                (m1, m2)
            }
        };

        // h = qinv * (m1 - m2 + p) mod p
        let diff = m1.add(&self.p).sub(&m2);

        // Use Montgomery multiplication for qinv * diff mod p when cached
        let h = match (&self.mont_p, &self.qinv_mont) {
            (Some(ctx_p), Some(qinv_m)) => {
                let diff_m = ctx_p.to_mont(&diff)?;
                let h_m = ctx_p.mont_mul(&diff_m, qinv_m);
                ctx_p.from_mont(&h_m)
            }
            _ => diff.mul(&self.qinv).mod_reduce(&self.p)?,
        };

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

/// MGF1 mask generation function (RFC 8017 B.2.1) using SHA-256.
/// Kept as a thin wrapper for backward compat; new code should use
/// `mgf1_with_hash` with an explicit hash.
pub(crate) fn mgf1_sha256(seed: &[u8], mask_len: usize) -> Result<Vec<u8>, CryptoError> {
    mgf1_with_hash(seed, mask_len, RsaHashAlg::Sha256)
}

/// MGF1 mask generation function parameterised by hash algorithm
/// (Phase T95). Output length is `mask_len` bytes.
pub(crate) fn mgf1_with_hash(
    seed: &[u8],
    mask_len: usize,
    alg: RsaHashAlg,
) -> Result<Vec<u8>, CryptoError> {
    use crate::sha2::{Sha224, Sha256, Sha384, Sha512};

    // SHA-1 MGF1 is only available with the `sha1` feature (used by OAEP-SHA-1
    // for interop; PSS never uses SHA-1). h_len is harmless to compute even
    // without the feature — the per-iteration match below fails closed.
    let h_len = match alg {
        RsaHashAlg::Sha1 => 20,
        RsaHashAlg::Sha224 => 28,
        RsaHashAlg::Sha256 => 32,
        RsaHashAlg::Sha384 => 48,
        RsaHashAlg::Sha512 => 64,
    };
    let iterations = mask_len.div_ceil(h_len);
    let mut t = Vec::with_capacity(iterations * h_len);

    for counter in 0..iterations {
        let c = (counter as u32).to_be_bytes();
        match alg {
            RsaHashAlg::Sha1 => {
                #[cfg(feature = "sha1")]
                {
                    let mut hasher = crate::sha1::Sha1::new();
                    hasher.update(seed)?;
                    hasher.update(&c)?;
                    t.extend_from_slice(&hasher.finish()?);
                }
                #[cfg(not(feature = "sha1"))]
                return Err(CryptoError::InvalidArg(
                    "SHA-1 MGF1 requires the sha1 feature",
                ));
            }
            RsaHashAlg::Sha224 => {
                let mut hasher = Sha224::new();
                hasher.update(seed)?;
                hasher.update(&c)?;
                t.extend_from_slice(&hasher.finish()?);
            }
            RsaHashAlg::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(seed)?;
                hasher.update(&c)?;
                t.extend_from_slice(&hasher.finish()?);
            }
            RsaHashAlg::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(seed)?;
                hasher.update(&c)?;
                t.extend_from_slice(&hasher.finish()?);
            }
            RsaHashAlg::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(seed)?;
                hasher.update(&c)?;
                t.extend_from_slice(&hasher.finish()?);
            }
        }
    }

    t.truncate(mask_len);
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    use hitls_utils::hex::hex;

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
    fn test_rsa_iso9796_2_sign_verify() {
        let (n, e, d, p, q) = test_key_1024();
        let pub_key = RsaPublicKey::new(&n, &e).unwrap();
        let priv_key = RsaPrivateKey::new(&n, &d, &e, &p, &q).unwrap();

        // SHA-256 digest of "hello" (32 bytes); RSA-1024 modulus is 128 bytes,
        // so EM = 0x6A || hash(32) || 94 zero bytes || 0xBC fits comfortably.
        let digest = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

        let sig = priv_key.sign(RsaPadding::Iso9796_2, &digest).unwrap();
        assert_eq!(sig.len(), priv_key.k);

        let valid = pub_key
            .verify(RsaPadding::Iso9796_2, &digest, &sig)
            .unwrap();
        assert!(valid);

        // Tampered digest must fail.
        let mut bad_digest = digest.clone();
        bad_digest[0] ^= 0x01;
        let invalid = pub_key
            .verify(RsaPadding::Iso9796_2, &bad_digest, &sig)
            .unwrap();
        assert!(!invalid);

        // Tampered signature must fail.
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0x01;
        let bad_verify = pub_key
            .verify(RsaPadding::Iso9796_2, &digest, &bad_sig)
            .unwrap();
        assert!(!bad_verify);
    }

    #[test]
    fn test_rsa_iso9796_2_determinism() {
        // Scheme 1 is deterministic — signing the same digest twice must
        // produce byte-identical signatures.
        let (n, e, d, p, q) = test_key_1024();
        let priv_key = RsaPrivateKey::new(&n, &d, &e, &p, &q).unwrap();
        let digest = [0x55u8; 32];
        let sig_a = priv_key.sign(RsaPadding::Iso9796_2, &digest).unwrap();
        let sig_b = priv_key.sign(RsaPadding::Iso9796_2, &digest).unwrap();
        assert_eq!(sig_a, sig_b);
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

    /// Phase T95 — PSS sign+verify roundtrip across SHA-256 / SHA-384 /
    /// SHA-512. Pre-T95, `sign(RsaPadding::Pss, digest)` only accepted
    /// 32-byte SHA-256 digests; SHA-384 / SHA-512 returned `InvalidArg`.
    /// The new `sign_pss(digest, alg)` / `verify_pss(digest, sig, alg)`
    /// API thread the hash through M' and MGF1 properly.
    #[test]
    fn test_rsa_pss_sign_verify_all_hashes() {
        // 2048-bit RSA key — needed because PSS-SHA-512 with sLen=64
        // requires modBits-1 large enough for emLen >= hLen + sLen + 2
        // = 64 + 64 + 2 = 130 bytes; 1024-bit (128 bytes) is too small.
        let priv_key = RsaPrivateKey::generate(2048).unwrap();
        let pub_key = priv_key.public_key();

        let msg = b"phase t95 verifies pss across hash sizes";

        // SHA-256
        let mut h256 = crate::sha2::Sha256::new();
        h256.update(msg).unwrap();
        let d256 = h256.finish().unwrap().to_vec();
        let sig256 = priv_key.sign_pss(&d256, RsaHashAlg::Sha256).unwrap();
        assert!(pub_key
            .verify_pss(&d256, &sig256, RsaHashAlg::Sha256)
            .unwrap());
        // Wrong-hash digest length → InvalidArg from PSS.
        assert!(pub_key
            .verify_pss(&d256, &sig256, RsaHashAlg::Sha384)
            .is_err());

        // SHA-384
        let mut h384 = crate::sha2::Sha384::new();
        h384.update(msg).unwrap();
        let d384 = h384.finish().unwrap().to_vec();
        let sig384 = priv_key.sign_pss(&d384, RsaHashAlg::Sha384).unwrap();
        assert!(pub_key
            .verify_pss(&d384, &sig384, RsaHashAlg::Sha384)
            .unwrap());
        // Wrong digest length under SHA-384 → InvalidArg.
        assert!(pub_key
            .verify_pss(&d256, &sig384, RsaHashAlg::Sha384)
            .is_err());

        // SHA-512
        let mut h512 = crate::sha2::Sha512::new();
        h512.update(msg).unwrap();
        let d512 = h512.finish().unwrap().to_vec();
        let sig512 = priv_key.sign_pss(&d512, RsaHashAlg::Sha512).unwrap();
        assert!(pub_key
            .verify_pss(&d512, &sig512, RsaHashAlg::Sha512)
            .unwrap());

        // Tampered digest fails verification.
        let mut bad = d384.clone();
        bad[0] ^= 0x01;
        assert!(!pub_key
            .verify_pss(&bad, &sig384, RsaHashAlg::Sha384)
            .unwrap());
    }

    /// Phase I159 — PSS-SHA-224 sign+verify roundtrip. Closes the four
    /// `RSA_{SIGN,VERIFY}_PSS_FUNC_TC003` SDV rows that previously fell
    /// to `RsaHashAlg` not having a `Sha224` variant. The verify path
    /// must also reject a wrong-length digest (a SHA-256 digest fed under
    /// `Sha224` triggers the EMSA-PSS hash-length check) and a tampered
    /// digest.
    #[test]
    fn test_rsa_pss_sign_verify_sha224() {
        let priv_key = RsaPrivateKey::generate(2048).unwrap();
        let pub_key = priv_key.public_key();
        let msg = b"phase i159 verifies pss-sha224 sign+verify roundtrip";

        let mut h224 = crate::sha2::Sha224::new();
        h224.update(msg).unwrap();
        let d224 = h224.finish().unwrap().to_vec();
        assert_eq!(d224.len(), 28, "SHA-224 digest must be 28 bytes");

        let sig = priv_key.sign_pss(&d224, RsaHashAlg::Sha224).unwrap();
        assert!(pub_key
            .verify_pss(&d224, &sig, RsaHashAlg::Sha224)
            .unwrap());

        // Cross-hash digest length check: a SHA-256 digest (32 B) fed
        // under `Sha224` (expects 28 B) must be rejected by the PSS
        // encoder's hash-length precondition, not silently accepted.
        let mut h256 = crate::sha2::Sha256::new();
        h256.update(msg).unwrap();
        let d256 = h256.finish().unwrap().to_vec();
        assert!(pub_key
            .verify_pss(&d256, &sig, RsaHashAlg::Sha224)
            .is_err());

        // Tampered digest must fail verification (return Ok(false), not
        // Err — the signature is well-formed, just doesn't match).
        let mut bad = d224.clone();
        bad[0] ^= 0x01;
        assert!(!pub_key
            .verify_pss(&bad, &sig, RsaHashAlg::Sha224)
            .unwrap());
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
        let mask1 = mgf1_sha256(seed, 48).unwrap();
        let mask2 = mgf1_sha256(seed, 48).unwrap();
        assert_eq!(mask1.len(), 48);
        assert_eq!(mask1, mask2); // deterministic

        let mask3 = mgf1_sha256(seed, 64).unwrap();
        assert_eq!(mask3.len(), 64);
        assert_eq!(&mask3[..48], &mask1[..]); // prefix matches shorter mask
    }

    #[test]
    fn test_rsa_cross_padding_verify() {
        let (n, e, d, p, q) = test_key_1024();
        let priv_key = RsaPrivateKey::new(&n, &d, &e, &p, &q).unwrap();
        let pub_key = priv_key.public_key();
        let digest = crate::sha2::Sha256::digest(b"test message").unwrap();

        // Sign with PKCS1v15Sign, verify with PSS → should not verify
        let sig_pkcs = priv_key.sign(RsaPadding::Pkcs1v15Sign, &digest).unwrap();
        let result_pss = pub_key.verify(RsaPadding::Pss, &digest, &sig_pkcs).unwrap();
        assert!(!result_pss, "PKCS1v15 signature should not verify as PSS");

        // Sign with PSS, verify with PKCS1v15Sign → should not verify
        let sig_pss = priv_key.sign(RsaPadding::Pss, &digest).unwrap();
        let result_pkcs = pub_key
            .verify(RsaPadding::Pkcs1v15Sign, &digest, &sig_pss)
            .unwrap();
        assert!(!result_pkcs, "PSS signature should not verify as PKCS1v15");
    }

    #[test]
    fn test_rsa_oaep_message_too_long() {
        let (n, e, d, p, q) = test_key_1024();
        let priv_key = RsaPrivateKey::new(&n, &d, &e, &p, &q).unwrap();
        let pub_key = priv_key.public_key();

        // 1024-bit key: k=128, hLen=32, max_msg = 128-2*32-2 = 62 bytes
        let msg_ok = vec![0x42u8; 62];
        assert!(pub_key.encrypt(RsaPadding::Oaep, &msg_ok).is_ok());

        let msg_too_long = vec![0x42u8; 63];
        assert!(
            pub_key.encrypt(RsaPadding::Oaep, &msg_too_long).is_err(),
            "63-byte message should exceed OAEP capacity for 1024-bit key"
        );
    }

    #[test]
    fn test_rsa_cross_key_verify() {
        let (n, e, d, p, q) = test_key_1024();
        let priv_key_a = RsaPrivateKey::new(&n, &d, &e, &p, &q).unwrap();

        // Generate a different key (use different primes via generate is too slow;
        // instead use a second known key by modifying the existing one)
        // We'll just sign with key A and verify with key A's public → true,
        // then verify same signature with a shifted public key → false
        let digest = crate::sha2::Sha256::digest(b"cross key test").unwrap();
        let sig = priv_key_a.sign(RsaPadding::Pss, &digest).unwrap();

        // Verify with correct key
        let pub_a = priv_key_a.public_key();
        assert!(pub_a.verify(RsaPadding::Pss, &digest, &sig).unwrap());

        // Create a different public key by changing n slightly
        let mut n_modified = n.clone();
        let last = n_modified.len() - 1;
        n_modified[last] ^= 0x02; // flip a bit
        if let Ok(pub_b) = RsaPublicKey::new(&n_modified, &e) {
            if let Ok(valid) = pub_b.verify(RsaPadding::Pss, &digest, &sig) {
                assert!(!valid, "signature should not verify with different key");
            }
        }
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(3))]

            #[test]
            fn prop_rsa1024_pss_sign_verify_roundtrip(
                digest in prop::array::uniform32(any::<u8>()),
            ) {
                let (n, e, d, p, q) = test_key_1024();
                let priv_key = RsaPrivateKey::new(&n, &d, &e, &p, &q).unwrap();
                let pub_key = priv_key.public_key();
                let sig = priv_key.sign(RsaPadding::Pss, &digest).unwrap();
                prop_assert!(pub_key.verify(RsaPadding::Pss, &digest, &sig).unwrap());
            }

            #[test]
            fn prop_rsa1024_tampered_sig_rejected(
                digest in prop::array::uniform32(any::<u8>()),
                tamper_pos in any::<usize>(),
            ) {
                let (n, e, d, p, q) = test_key_1024();
                let priv_key = RsaPrivateKey::new(&n, &d, &e, &p, &q).unwrap();
                let pub_key = priv_key.public_key();
                let mut sig = priv_key.sign(RsaPadding::Pss, &digest).unwrap();
                let pos = tamper_pos % sig.len();
                sig[pos] ^= 0xFF;
                let valid = pub_key.verify(RsaPadding::Pss, &digest, &sig).unwrap_or(false);
                prop_assert!(!valid);
            }
        }
    }
}
