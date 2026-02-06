//! HKDF (HMAC-based Extract-and-Expand Key Derivation Function).
//!
//! HKDF is defined in RFC 5869. It consists of two stages:
//! extract (produce a PRK from input keying material) and
//! expand (derive output keying material of any length).

use crate::hmac::Hmac;
use crate::provider::Digest;
use crate::sha2::Sha256;
use hitls_types::CryptoError;
use zeroize::Zeroize;

fn sha256_factory() -> Box<dyn Digest> {
    Box::new(Sha256::new())
}

/// HKDF context (default: HMAC-SHA-256).
pub struct Hkdf {
    prk: Vec<u8>,
    hash_len: usize,
}

impl Hkdf {
    /// Create a new HKDF instance by performing the extract step with SHA-256.
    /// If `salt` is empty, uses a hash-length zero-filled salt.
    pub fn new(salt: &[u8], ikm: &[u8]) -> Result<Self, CryptoError> {
        let hash_len = 32; // SHA-256
        let effective_salt = if salt.is_empty() {
            vec![0u8; hash_len]
        } else {
            salt.to_vec()
        };
        let prk = Hmac::mac(sha256_factory, &effective_salt, ikm)?;
        Ok(Self { prk, hash_len })
    }

    /// Perform the expand step to derive `okm_len` bytes.
    pub fn expand(&self, info: &[u8], okm_len: usize) -> Result<Vec<u8>, CryptoError> {
        if okm_len > 255 * self.hash_len {
            return Err(CryptoError::KdfDkLenOverflow);
        }
        let n = okm_len.div_ceil(self.hash_len);
        let mut okm = Vec::with_capacity(okm_len);
        let mut t_prev = Vec::new();

        for i in 1..=n {
            let mut hmac = Hmac::new(sha256_factory, &self.prk)?;
            if !t_prev.is_empty() {
                hmac.update(&t_prev)?;
            }
            hmac.update(info)?;
            hmac.update(&[i as u8])?;
            let mut t = vec![0u8; self.hash_len];
            hmac.finish(&mut t)?;
            let take = (okm_len - okm.len()).min(self.hash_len);
            okm.extend_from_slice(&t[..take]);
            t_prev = t;
        }
        Ok(okm)
    }

    /// One-shot: extract and expand in a single call.
    pub fn derive(
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let hkdf = Self::new(salt, ikm)?;
        hkdf.expand(info, okm_len)
    }
}

impl Drop for Hkdf {
    fn drop(&mut self) {
        self.prk.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // RFC 5869 Test Case 1
    #[test]
    fn test_hkdf_case1() {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
        let expected_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
        let expected_okm =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

        let hkdf = Hkdf::new(&salt, &ikm).unwrap();
        assert_eq!(hex(&hkdf.prk), expected_prk);
        let okm = hkdf.expand(&info, 42).unwrap();
        assert_eq!(hex(&okm), expected_okm);
    }

    // RFC 5869 Test Case 2 (longer inputs)
    #[test]
    fn test_hkdf_case2() {
        let ikm = hex_to_bytes(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
        );
        let salt = hex_to_bytes(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        );
        let info = hex_to_bytes(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );
        let expected_okm = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87";

        let okm = Hkdf::derive(&salt, &ikm, &info, 82).unwrap();
        assert_eq!(hex(&okm), expected_okm);
    }

    // RFC 5869 Test Case 3 (zero-length salt and info)
    #[test]
    fn test_hkdf_case3() {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let expected_okm =
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";

        let okm = Hkdf::derive(&[], &ikm, &[], 42).unwrap();
        assert_eq!(hex(&okm), expected_okm);
    }
}
