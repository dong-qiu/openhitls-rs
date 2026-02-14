//! PBKDF2 (Password-Based Key Derivation Function 2) implementation.
//!
//! Defined in RFC 8018 (PKCS#5 v2.1). Uses HMAC-SHA-256 as the PRF.

use crate::hmac::Hmac;
use crate::provider::Digest;
use crate::sha2::Sha256;
use hitls_types::CryptoError;
use zeroize::Zeroize;

fn sha256_factory() -> Box<dyn Digest> {
    Box::new(Sha256::new())
}

/// Derive a key from a password using PBKDF2-HMAC-SHA256.
pub fn pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dk_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    if iterations == 0 || dk_len == 0 {
        return Err(CryptoError::InvalidArg);
    }
    let hash_len = 32; // SHA-256
    let n = dk_len.div_ceil(hash_len);
    let mut dk = Vec::with_capacity(dk_len);

    for i in 1..=n {
        // U1 = HMAC(password, salt || i_be32)
        let mut hmac = Hmac::new(sha256_factory, password)?;
        hmac.update(salt)?;
        hmac.update(&(i as u32).to_be_bytes())?;
        let mut u = vec![0u8; hash_len];
        hmac.finish(&mut u)?;

        let mut t = u.clone();

        // U2..Uc
        for _ in 1..iterations {
            hmac.reset();
            hmac.update(&u)?;
            let mut u_next = vec![0u8; hash_len];
            hmac.finish(&mut u_next)?;
            u.copy_from_slice(&u_next);
            for (tj, &uj) in t.iter_mut().zip(u.iter()) {
                *tj ^= uj;
            }
        }

        let take = (dk_len - dk.len()).min(hash_len);
        dk.extend_from_slice(&t[..take]);
        t.zeroize();
        u.zeroize();
    }
    Ok(dk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // PBKDF2-HMAC-SHA256 test vectors
    // From RFC 7914 Section 11 and other known-good sources
    #[test]
    fn test_pbkdf2_sha256_c1() {
        // password="passwd", salt="salt", c=1, dkLen=64
        let dk = pbkdf2(b"passwd", b"salt", 1, 64).unwrap();
        let expected = "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783";
        assert_eq!(hex(&dk), expected);
    }

    #[test]
    fn test_pbkdf2_sha256_c80000() {
        // password="Password", salt="NaCl", c=80000, dkLen=64
        let dk = pbkdf2(b"Password", b"NaCl", 80000, 64).unwrap();
        let expected = "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d";
        assert_eq!(hex(&dk), expected);
    }

    #[test]
    fn test_pbkdf2_sha256_short() {
        // Simple test: derive 16 bytes
        let dk = pbkdf2(b"password", b"salt", 1, 16).unwrap();
        assert_eq!(dk.len(), 16);

        // Same parameters should give same result
        let dk2 = pbkdf2(b"password", b"salt", 1, 16).unwrap();
        assert_eq!(dk, dk2);
    }

    #[test]
    fn test_pbkdf2_invalid_params() {
        assert!(pbkdf2(b"password", b"salt", 0, 16).is_err());
        assert!(pbkdf2(b"password", b"salt", 1, 0).is_err());
    }

    #[test]
    fn test_pbkdf2_single_byte_output() {
        let dk = pbkdf2(b"password", b"salt", 1, 1).unwrap();
        assert_eq!(dk.len(), 1);
    }

    #[test]
    fn test_pbkdf2_deterministic() {
        let dk1 = pbkdf2(b"secret", b"pepper", 100, 32).unwrap();
        let dk2 = pbkdf2(b"secret", b"pepper", 100, 32).unwrap();
        assert_eq!(dk1, dk2);
    }
}
