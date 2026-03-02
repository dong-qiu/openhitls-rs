//! XMSS hash function abstraction (RFC 8391 Section 5).
//!
//! ROBUST mode: F and H use bitmask XOR before hashing.
//! Four hash backends: SHA-256, SHA-512, SHAKE128, SHAKE256.

use hitls_types::CryptoError;

use super::address::XmssAdrs;
use super::params::XmssHashMode;

/// Padding bytes for domain separation (RFC 8391 Section 5.1).
/// toByte(0, padding_len) for F, toByte(1, padding_len) for H, etc.
fn to_byte(val: u32, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let bytes = val.to_be_bytes();
    let start = len.saturating_sub(4);
    buf[start..len].copy_from_slice(&bytes[4 - (len - start)..]);
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
        XmssHashMode::Sha512 => {
            let mut h = crate::sha2::Sha512::new();
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
    pub padding_len: usize,
    pub mode: XmssHashMode,
    pub sk_seed: Vec<u8>,
    pub pk_seed: Vec<u8>,
}

impl XmssHasher {
    /// PRF: H(toByte(3,padding_len) || SEED || ADRS)
    pub fn prf(&self, seed: &[u8], adrs: &XmssAdrs) -> Result<Vec<u8>, CryptoError> {
        let pad = to_byte(3, self.padding_len);
        let mut input = Vec::with_capacity(self.padding_len + seed.len() + 32);
        input.extend_from_slice(&pad);
        input.extend_from_slice(seed);
        input.extend_from_slice(adrs.as_bytes());
        core_hash(self.mode, &input, self.n)
    }

    /// PRF_keygen: Generate a WOTS+ secret key element.
    pub fn prf_keygen(&self, adrs: &XmssAdrs) -> Result<Vec<u8>, CryptoError> {
        self.prf(&self.sk_seed, adrs)
    }

    /// F (ROBUST): F(KEY, M XOR BM)
    pub fn f(&self, adrs: &XmssAdrs, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let n = self.n;

        let mut adrs_key = adrs.clone();
        adrs_key.set_key_and_mask(0);
        let key = self.prf(&self.pk_seed, &adrs_key)?;

        let mut adrs_bm = adrs.clone();
        adrs_bm.set_key_and_mask(1);
        let bm = self.prf(&self.pk_seed, &adrs_bm)?;

        let mut xored = Vec::with_capacity(n);
        for i in 0..n {
            xored.push(msg[i] ^ bm[i]);
        }

        let pad = to_byte(0, self.padding_len);
        let mut input = Vec::with_capacity(self.padding_len + n + n);
        input.extend_from_slice(&pad);
        input.extend_from_slice(&key);
        input.extend_from_slice(&xored);
        core_hash(self.mode, &input, n)
    }

    /// H (ROBUST): H(KEY, left XOR BM0 || right XOR BM1)
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

        let mut xored = Vec::with_capacity(2 * n);
        for i in 0..n {
            xored.push(left[i] ^ bm0[i]);
        }
        for i in 0..n {
            xored.push(right[i] ^ bm1[i]);
        }

        let pad = to_byte(1, self.padding_len);
        let mut input = Vec::with_capacity(self.padding_len + n + 2 * n);
        input.extend_from_slice(&pad);
        input.extend_from_slice(&key);
        input.extend_from_slice(&xored);
        core_hash(self.mode, &input, n)
    }

    /// H_msg: Randomized message hash.
    /// H(toByte(2,padding_len) || R || root || toByte(idx, n) || msg)
    pub fn h_msg(
        &self,
        r: &[u8],
        root: &[u8],
        idx: u64,
        msg: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let n = self.n;
        let pad = to_byte(2, self.padding_len);
        let idx_bytes = {
            let mut buf = vec![0u8; n];
            let be = idx.to_be_bytes();
            let start = n.saturating_sub(8);
            let copy_len = 8.min(n);
            buf[start..start + copy_len].copy_from_slice(&be[8 - copy_len..]);
            buf
        };

        let mut input = Vec::with_capacity(self.padding_len + 2 * n + n + msg.len());
        input.extend_from_slice(&pad);
        input.extend_from_slice(r);
        input.extend_from_slice(root);
        input.extend_from_slice(&idx_bytes);
        input.extend_from_slice(msg);
        core_hash(self.mode, &input, n)
    }

    /// PRF_msg: Generate randomness for signing.
    pub fn prf_msg(&self, sk_prf: &[u8], idx: u64, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let n = self.n;
        let pad = to_byte(3, self.padding_len);
        let idx_bytes = {
            let mut buf = vec![0u8; 32];
            let be = idx.to_be_bytes();
            buf[24..32].copy_from_slice(&be);
            buf
        };

        let mut input = Vec::with_capacity(self.padding_len + 32 + sk_prf.len() + msg.len());
        input.extend_from_slice(&pad);
        input.extend_from_slice(sk_prf);
        input.extend_from_slice(&idx_bytes);
        input.extend_from_slice(msg);
        core_hash(self.mode, &input, n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmss::address::XmssAdrs;

    #[test]
    fn test_to_byte_padding() {
        let b0 = super::to_byte(0, 32);
        assert_eq!(b0.len(), 32);
        assert!(b0.iter().all(|&x| x == 0));

        let b1 = super::to_byte(1, 32);
        assert_eq!(b1.len(), 32);
        assert!(b1[..31].iter().all(|&x| x == 0));
        assert_eq!(b1[31], 1);

        let b3 = super::to_byte(3, 32);
        assert_eq!(b3[31], 3);

        let b256 = super::to_byte(256, 32);
        assert_eq!(b256[30], 1);
        assert_eq!(b256[31], 0);

        // 4-byte padding (for n=24 / 192-bit variants)
        let b4 = super::to_byte(3, 4);
        assert_eq!(b4.len(), 4);
        assert_eq!(b4, vec![0, 0, 0, 3]);

        // 64-byte padding (for n=64 / 512-bit variants)
        let b64 = super::to_byte(2, 64);
        assert_eq!(b64.len(), 64);
        assert_eq!(b64[63], 2);
        assert!(b64[..63].iter().all(|&x| x == 0));
    }

    #[test]
    fn test_xmss_hasher_prf_different_addresses() {
        let hasher = XmssHasher {
            n: 32,
            padding_len: 32,
            mode: XmssHashMode::Sha256,
            sk_seed: vec![0x11u8; 32],
            pk_seed: vec![0x22u8; 32],
        };

        let seed = vec![0x33u8; 32];
        let mut adrs1 = XmssAdrs::new();
        adrs1.set_layer_addr(0);
        let mut adrs2 = XmssAdrs::new();
        adrs2.set_layer_addr(1);

        let out1 = hasher.prf(&seed, &adrs1).unwrap();
        let out2 = hasher.prf(&seed, &adrs2).unwrap();
        assert_ne!(
            out1, out2,
            "different addresses should produce different PRF outputs"
        );
    }

    #[test]
    fn test_xmss_hasher_f_deterministic() {
        let hasher = XmssHasher {
            n: 32,
            padding_len: 32,
            mode: XmssHashMode::Shake128,
            sk_seed: vec![0xAAu8; 32],
            pk_seed: vec![0xBBu8; 32],
        };
        let adrs = XmssAdrs::new();
        let msg = vec![0x55u8; 32];

        let f1 = hasher.f(&adrs, &msg).unwrap();
        let f2 = hasher.f(&adrs, &msg).unwrap();
        assert_eq!(f1, f2, "F should be deterministic");
        assert_eq!(f1.len(), 32);
    }

    #[test]
    fn test_xmss_hasher_h_msg_idx_sensitivity() {
        let hasher = XmssHasher {
            n: 32,
            padding_len: 32,
            mode: XmssHashMode::Sha256,
            sk_seed: vec![0xAAu8; 32],
            pk_seed: vec![0xBBu8; 32],
        };
        let r = vec![0x11u8; 32];
        let root = vec![0x22u8; 32];
        let msg = b"test message";

        let h1 = hasher.h_msg(&r, &root, 0, msg).unwrap();
        let h2 = hasher.h_msg(&r, &root, 0, msg).unwrap();
        assert_eq!(h1, h2);

        let h3 = hasher.h_msg(&r, &root, 1, msg).unwrap();
        assert_ne!(h1, h3, "different idx should produce different h_msg");
    }

    #[test]
    fn test_xmss_hasher_prf_msg_output() {
        let hasher = XmssHasher {
            n: 32,
            padding_len: 32,
            mode: XmssHashMode::Shake256,
            sk_seed: vec![0xAAu8; 32],
            pk_seed: vec![0xBBu8; 32],
        };
        let sk_prf = vec![0xCCu8; 32];

        let out = hasher.prf_msg(&sk_prf, 42, b"hello").unwrap();
        assert_eq!(out.len(), 32);

        let out2 = hasher.prf_msg(&sk_prf, 42, b"hello").unwrap();
        assert_eq!(out, out2);

        let out3 = hasher.prf_msg(&sk_prf, 43, b"hello").unwrap();
        assert_ne!(out, out3);
    }

    #[test]
    fn test_xmss_hasher_prf_determinism() {
        let hasher = XmssHasher {
            n: 32,
            padding_len: 32,
            mode: XmssHashMode::Shake256,
            sk_seed: vec![0xAAu8; 32],
            pk_seed: vec![0xBBu8; 32],
        };

        let adrs = XmssAdrs::new();
        let seed = vec![0xCCu8; 32];

        let prf1 = hasher.prf(&seed, &adrs).unwrap();
        let prf2 = hasher.prf(&seed, &adrs).unwrap();
        assert_eq!(prf1, prf2);
        assert_eq!(prf1.len(), 32);

        let pk1 = hasher.prf_keygen(&adrs).unwrap();
        let pk2 = hasher.prf_keygen(&adrs).unwrap();
        assert_eq!(pk1, pk2);
        assert_eq!(pk1.len(), 32);
    }

    #[test]
    fn test_xmss_hasher_f_h_output_lengths() {
        let hasher = XmssHasher {
            n: 32,
            padding_len: 32,
            mode: XmssHashMode::Sha256,
            sk_seed: vec![0xAAu8; 32],
            pk_seed: vec![0xBBu8; 32],
        };

        let adrs = XmssAdrs::new();
        let msg = vec![0x55u8; 32];

        let f_out = hasher.f(&adrs, &msg).unwrap();
        assert_eq!(f_out.len(), 32);

        let left = vec![0x11u8; 32];
        let right = vec![0x22u8; 32];
        let h_out = hasher.h(&adrs, &left, &right).unwrap();
        assert_eq!(h_out.len(), 32);

        let r = vec![0x33u8; 32];
        let root = vec![0x44u8; 32];
        let hm_out = hasher.h_msg(&r, &root, 0, b"test").unwrap();
        assert_eq!(hm_out.len(), 32);
    }

    #[test]
    fn test_xmss_hasher_n64_sha512() {
        let hasher = XmssHasher {
            n: 64,
            padding_len: 64,
            mode: XmssHashMode::Sha512,
            sk_seed: vec![0xAAu8; 64],
            pk_seed: vec![0xBBu8; 64],
        };
        let adrs = XmssAdrs::new();
        let out = hasher.prf_keygen(&adrs).unwrap();
        assert_eq!(out.len(), 64);

        let msg = vec![0x55u8; 64];
        let f_out = hasher.f(&adrs, &msg).unwrap();
        assert_eq!(f_out.len(), 64);
    }

    #[test]
    fn test_xmss_hasher_n24_truncated() {
        let hasher = XmssHasher {
            n: 24,
            padding_len: 4,
            mode: XmssHashMode::Sha256,
            sk_seed: vec![0xAAu8; 24],
            pk_seed: vec![0xBBu8; 24],
        };
        let adrs = XmssAdrs::new();
        let out = hasher.prf_keygen(&adrs).unwrap();
        assert_eq!(out.len(), 24);

        let msg = vec![0x55u8; 24];
        let f_out = hasher.f(&adrs, &msg).unwrap();
        assert_eq!(f_out.len(), 24);
    }
}
