//! SLH-DSA hash function abstraction (FIPS 205 Section 11).
//!
//! Two modes:
//! - SHAKE: All functions use SHAKE256
//! - SHA-2: F/PRF use SHA-256 (sec_cat=1) or both SHA-256/SHA-512 (sec_cat=3,5)

use hitls_types::CryptoError;

use super::address::Adrs;

/// Hash function interface for SLH-DSA.
pub(crate) trait SlhHashFunctions {
    /// PRF(PK.seed, ADRS, SK.seed) -> n bytes
    fn prf(&self, adrs: &Adrs, sk_seed: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// F(PK.seed, ADRS, M) -> n bytes
    fn f(&self, adrs: &Adrs, msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// H(PK.seed, ADRS, M) -> n bytes
    fn h(&self, adrs: &Adrs, msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// T_l(PK.seed, ADRS, M) -> n bytes
    fn t_l(&self, adrs: &Adrs, msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// H_msg(R, PK.seed, PK.root, M) -> m bytes
    fn h_msg(&self, r: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// PRF_msg(SK.prf, opt_rand, M) -> n bytes
    fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Security parameter n
    fn n(&self) -> usize;
    /// Message digest length m
    fn m(&self) -> usize;
}

// ============ SHAKE mode ============

pub(crate) struct ShakeHasher {
    pub n: usize,
    pub m: usize,
    pub pk_seed: Vec<u8>,
    pub pk_root: Vec<u8>,
}

fn shake256_hash(inputs: &[&[u8]], out_len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut hasher = crate::sha3::Shake256::new();
    for input in inputs {
        hasher.update(input)?;
    }
    hasher.squeeze(out_len)
}

impl SlhHashFunctions for ShakeHasher {
    fn prf(&self, adrs: &Adrs, sk_seed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        shake256_hash(&[&self.pk_seed, adrs.as_bytes(), sk_seed], self.n)
    }

    fn f(&self, adrs: &Adrs, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        shake256_hash(&[&self.pk_seed, adrs.as_bytes(), msg], self.n)
    }

    fn h(&self, adrs: &Adrs, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        shake256_hash(&[&self.pk_seed, adrs.as_bytes(), msg], self.n)
    }

    fn t_l(&self, adrs: &Adrs, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        shake256_hash(&[&self.pk_seed, adrs.as_bytes(), msg], self.n)
    }

    fn h_msg(&self, r: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        shake256_hash(&[r, &self.pk_seed, &self.pk_root, msg], self.m)
    }

    fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        shake256_hash(&[sk_prf, opt_rand, msg], self.n)
    }

    fn n(&self) -> usize {
        self.n
    }
    fn m(&self) -> usize {
        self.m
    }
}

// ============ SHA-2 mode ============

pub(crate) struct Sha2Hasher {
    pub n: usize,
    pub m: usize,
    pub pk_seed: Vec<u8>,
    pub pk_root: Vec<u8>,
    pub sec_category: u8, // 1, 3, or 5
}

/// SHA-256 hash of concatenated inputs, truncated to out_len bytes.
fn sha256_hash(inputs: &[&[u8]], out_len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut h = crate::sha2::Sha256::new();
    for input in inputs {
        h.update(input)?;
    }
    let digest = h.finish()?;
    Ok(digest[..out_len].to_vec())
}

/// SHA-512 hash of concatenated inputs, truncated to out_len bytes.
fn sha512_hash(inputs: &[&[u8]], out_len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut h = crate::sha2::Sha512::new();
    for input in inputs {
        h.update(input)?;
    }
    let digest = h.finish()?;
    Ok(digest[..out_len].to_vec())
}

/// MGF1-SHA-256: mask generation function per PKCS#1 B.2.1.
fn mgf1_sha256(seed: &[u8], mask_len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut result = Vec::with_capacity(mask_len);
    let mut counter: u32 = 0;
    while result.len() < mask_len {
        let mut h = crate::sha2::Sha256::new();
        h.update(seed)?;
        h.update(&counter.to_be_bytes())?;
        let block = h.finish()?;
        let take = (mask_len - result.len()).min(32);
        result.extend_from_slice(&block[..take]);
        counter += 1;
    }
    Ok(result)
}

/// MGF1-SHA-512: mask generation function per PKCS#1 B.2.1.
fn mgf1_sha512(seed: &[u8], mask_len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut result = Vec::with_capacity(mask_len);
    let mut counter: u32 = 0;
    while result.len() < mask_len {
        let mut h = crate::sha2::Sha512::new();
        h.update(seed)?;
        h.update(&counter.to_be_bytes())?;
        let block = h.finish()?;
        let take = (mask_len - result.len()).min(64);
        result.extend_from_slice(&block[..take]);
        counter += 1;
    }
    Ok(result)
}

impl Sha2Hasher {
    /// Build the padded prefix: PK.seed || zeros-to-block-size || compressed-ADRS
    fn padded_prefix(&self, adrs: &Adrs) -> Vec<u8> {
        let block_size = if self.sec_category == 1 { 64 } else { 128 };
        let mut buf = Vec::with_capacity(block_size + 22);
        buf.extend_from_slice(&self.pk_seed);
        // Pad to block_size
        let pad_len = block_size - self.n;
        buf.extend(std::iter::repeat(0u8).take(pad_len));
        buf.extend_from_slice(adrs.as_bytes());
        buf
    }

    /// F/H for sec_category 1: SHA-256(padded_prefix || msg), truncated to n
    fn sha256_fh(&self, adrs: &Adrs, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let prefix = self.padded_prefix(adrs);
        sha256_hash(&[&prefix, msg], self.n)
    }

    /// H for sec_category 3,5: SHA-512(padded_prefix || msg), truncated to n
    fn sha512_fh(&self, adrs: &Adrs, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let prefix = self.padded_prefix(adrs);
        sha512_hash(&[&prefix, msg], self.n)
    }
}

impl SlhHashFunctions for Sha2Hasher {
    fn prf(&self, adrs: &Adrs, sk_seed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // PRF always uses SHA-256 regardless of security category
        let prefix = self.padded_prefix(adrs);
        sha256_hash(&[&prefix, sk_seed], self.n)
    }

    fn f(&self, adrs: &Adrs, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // F always uses SHA-256
        self.sha256_fh(adrs, msg)
    }

    fn h(&self, adrs: &Adrs, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.sec_category == 1 {
            self.sha256_fh(adrs, msg)
        } else {
            self.sha512_fh(adrs, msg)
        }
    }

    fn t_l(&self, adrs: &Adrs, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.sec_category == 1 {
            self.sha256_fh(adrs, msg)
        } else {
            self.sha512_fh(adrs, msg)
        }
    }

    fn h_msg(&self, r: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // H_msg = MGF1(SHA-x(R || PK.seed) || SHA-x(R || PK.seed || PK.root || msg), m)
        // First compute SHA(R || PK.seed) as seed prefix
        let mut seed_buf = Vec::new();
        if self.sec_category == 1 {
            // SHA-256
            let hash1 = sha256_hash(&[r, &self.pk_seed], 32)?;
            seed_buf.extend_from_slice(r);
            seed_buf.extend_from_slice(&self.pk_seed);
            let hash2 = sha256_hash(&[&seed_buf, &self.pk_root, msg], 32)?;
            let mut mgf_seed = hash1;
            mgf_seed.extend_from_slice(&hash2);
            mgf1_sha256(&mgf_seed, self.m)
        } else {
            // SHA-512
            let hash1 = sha512_hash(&[r, &self.pk_seed], 64)?;
            seed_buf.extend_from_slice(r);
            seed_buf.extend_from_slice(&self.pk_seed);
            let hash2 = sha512_hash(&[&seed_buf, &self.pk_root, msg], 64)?;
            let mut mgf_seed = hash1;
            mgf_seed.extend_from_slice(&hash2);
            mgf1_sha512(&mgf_seed, self.m)
        }
    }

    fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // PRF_msg = HMAC-SHA-x(SK.prf, opt_rand || msg), truncated to n
        use crate::hmac::Hmac;
        use crate::provider::Digest;
        if self.sec_category == 1 {
            let factory = || -> Box<dyn Digest> { Box::new(crate::sha2::Sha256::new()) };
            let mut hmac = Hmac::new(factory, sk_prf)?;
            hmac.update(opt_rand)?;
            hmac.update(msg)?;
            let mut out = vec![0u8; 32];
            hmac.finish(&mut out)?;
            out.truncate(self.n);
            Ok(out)
        } else {
            let factory = || -> Box<dyn Digest> { Box::new(crate::sha2::Sha512::new()) };
            let mut hmac = Hmac::new(factory, sk_prf)?;
            hmac.update(opt_rand)?;
            hmac.update(msg)?;
            let mut out = vec![0u8; 64];
            hmac.finish(&mut out)?;
            out.truncate(self.n);
            Ok(out)
        }
    }

    fn n(&self) -> usize {
        self.n
    }
    fn m(&self) -> usize {
        self.m
    }
}

/// Create the appropriate hasher for the given parameter set.
pub(crate) fn make_hasher(
    params: &super::params::SlhDsaParams,
    pk_seed: &[u8],
    pk_root: &[u8],
) -> Box<dyn SlhHashFunctions> {
    if params.is_sha2 {
        Box::new(Sha2Hasher {
            n: params.n,
            m: params.m,
            pk_seed: pk_seed.to_vec(),
            pk_root: pk_root.to_vec(),
            sec_category: params.sec_category,
        })
    } else {
        Box::new(ShakeHasher {
            n: params.n,
            m: params.m,
            pk_seed: pk_seed.to_vec(),
            pk_root: pk_root.to_vec(),
        })
    }
}
