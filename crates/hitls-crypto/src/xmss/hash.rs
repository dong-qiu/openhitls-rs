//! XMSS hash function abstraction (RFC 8391 Section 5).
//!
//! ROBUST mode: F and H use bitmask XOR before hashing.
//! Three hash backends: SHA-256, SHAKE128, SHAKE256.

use hitls_types::CryptoError;

use super::address::XmssAdrs;
use super::params::XmssHashMode;

/// Padding bytes for domain separation (RFC 8391 Section 5.1).
/// toByte(0, 32) = 0x00...00 (32 bytes) for F
/// toByte(1, 32) = 0x00...01 (32 bytes) for H
/// toByte(2, 32) = 0x00...02 (32 bytes) for H_msg
/// toByte(3, 32) = 0x00...03 (32 bytes) for PRF
fn to_byte(val: u32, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let bytes = val.to_be_bytes();
    let start = n.saturating_sub(4);
    buf[start..n].copy_from_slice(&bytes[4 - (n - start)..]);
    buf
}

/// Core hash: hash arbitrary-length input to n bytes.
fn core_hash(mode: XmssHashMode, input: &[u8], n: usize) -> Result<Vec<u8>, CryptoError> {
    match mode {
        XmssHashMode::Sha256 => {
            let mut h = crate::sha2::Sha256::new();
            h.update(input)?;
            let digest = h.finish()?;
            Ok(digest[..n].to_vec())
        }
        XmssHashMode::Shake128 => {
            let mut h = crate::sha3::Shake128::new();
            h.update(input)?;
            h.squeeze(n)
        }
        XmssHashMode::Shake256 => {
            let mut h = crate::sha3::Shake256::new();
            h.update(input)?;
            h.squeeze(n)
        }
    }
}

/// XMSS hash function context.
pub(crate) struct XmssHasher {
    pub n: usize,
    pub mode: XmssHashMode,
    pub sk_seed: Vec<u8>,
    pub pk_seed: Vec<u8>,
}

impl XmssHasher {
    /// PRF: H(toByte(3,n) || SEED || ADRS)
    pub fn prf(&self, seed: &[u8], adrs: &XmssAdrs) -> Result<Vec<u8>, CryptoError> {
        let pad = to_byte(3, self.n);
        let mut input = Vec::with_capacity(self.n + seed.len() + 32);
        input.extend_from_slice(&pad);
        input.extend_from_slice(seed);
        input.extend_from_slice(adrs.as_bytes());
        core_hash(self.mode, &input, self.n)
    }

    /// PRF_keygen: Generate a WOTS+ secret key element.
    /// PRF(SK.seed, ADRS) = H(toByte(3,n) || SK.seed || ADRS)
    pub fn prf_keygen(&self, adrs: &XmssAdrs) -> Result<Vec<u8>, CryptoError> {
        self.prf(&self.sk_seed, adrs)
    }

    /// F (ROBUST): F(KEY, M ⊕ BM)
    /// KEY = PRF(PK.seed, ADRS with km=0)
    /// BM  = PRF(PK.seed, ADRS with km=1)
    /// Result = H(toByte(0,n) || KEY || (M ⊕ BM))
    pub fn f(&self, adrs: &XmssAdrs, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let n = self.n;

        // Generate KEY
        let mut adrs_key = adrs.clone();
        adrs_key.set_key_and_mask(0);
        let key = self.prf(&self.pk_seed, &adrs_key)?;

        // Generate BM
        let mut adrs_bm = adrs.clone();
        adrs_bm.set_key_and_mask(1);
        let bm = self.prf(&self.pk_seed, &adrs_bm)?;

        // XOR message with bitmask
        let mut xored = Vec::with_capacity(n);
        for i in 0..n {
            xored.push(msg[i] ^ bm[i]);
        }

        // Hash: toByte(0,n) || KEY || xored
        let pad = to_byte(0, n);
        let mut input = Vec::with_capacity(3 * n);
        input.extend_from_slice(&pad);
        input.extend_from_slice(&key);
        input.extend_from_slice(&xored);
        core_hash(self.mode, &input, n)
    }

    /// H (ROBUST): H(KEY, left ⊕ BM0 || right ⊕ BM1)
    /// KEY = PRF(PK.seed, ADRS with km=0)
    /// BM0 = PRF(PK.seed, ADRS with km=1)
    /// BM1 = PRF(PK.seed, ADRS with km=2)
    /// Result = H(toByte(1,n) || KEY || (left ⊕ BM0) || (right ⊕ BM1))
    pub fn h(&self, adrs: &XmssAdrs, left: &[u8], right: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let n = self.n;

        let mut adrs_key = adrs.clone();
        adrs_key.set_key_and_mask(0);
        let key = self.prf(&self.pk_seed, &adrs_key)?;

        let mut adrs_bm0 = adrs.clone();
        adrs_bm0.set_key_and_mask(1);
        let bm0 = self.prf(&self.pk_seed, &adrs_bm0)?;

        let mut adrs_bm1 = adrs.clone();
        adrs_bm1.set_key_and_mask(2);
        let bm1 = self.prf(&self.pk_seed, &adrs_bm1)?;

        // XOR
        let mut xored = Vec::with_capacity(2 * n);
        for i in 0..n {
            xored.push(left[i] ^ bm0[i]);
        }
        for i in 0..n {
            xored.push(right[i] ^ bm1[i]);
        }

        let pad = to_byte(1, n);
        let mut input = Vec::with_capacity(n + n + 2 * n);
        input.extend_from_slice(&pad);
        input.extend_from_slice(&key);
        input.extend_from_slice(&xored);
        core_hash(self.mode, &input, n)
    }

    /// H_msg: Randomized message hash.
    /// H(toByte(2,n) || R || root || toByte(idx, n) || msg)
    pub fn h_msg(
        &self,
        r: &[u8],
        root: &[u8],
        idx: u64,
        msg: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let n = self.n;
        let pad = to_byte(2, n);
        let idx_bytes = {
            let mut buf = vec![0u8; n];
            let be = idx.to_be_bytes();
            let start = n.saturating_sub(8);
            let copy_len = 8.min(n);
            buf[start..start + copy_len].copy_from_slice(&be[8 - copy_len..]);
            buf
        };

        let mut input = Vec::with_capacity(4 * n + msg.len());
        input.extend_from_slice(&pad);
        input.extend_from_slice(r);
        input.extend_from_slice(root);
        input.extend_from_slice(&idx_bytes);
        input.extend_from_slice(msg);
        core_hash(self.mode, &input, n)
    }

    /// PRF_msg: Generate randomness for signing.
    /// PRF(SK.prf, idx_bytes || msg)
    pub fn prf_msg(&self, sk_prf: &[u8], idx: u64, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let n = self.n;
        let pad = to_byte(3, n);
        let idx_bytes = {
            let mut buf = vec![0u8; 32];
            let be = idx.to_be_bytes();
            buf[24..32].copy_from_slice(&be);
            buf
        };

        let mut input = Vec::with_capacity(n + 32 + sk_prf.len() + msg.len());
        input.extend_from_slice(&pad);
        input.extend_from_slice(sk_prf);
        input.extend_from_slice(&idx_bytes);
        input.extend_from_slice(msg);
        core_hash(self.mode, &input, n)
    }
}
