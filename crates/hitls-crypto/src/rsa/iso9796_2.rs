//! ISO/IEC 9796-2:1997 Scheme 1 RSA signature padding.
//!
//! Scheme 1 is the deterministic, hash-only variant (no message recovery)
//! defined in clause 5 of ISO/IEC 9796-2:1997. The encoded message is:
//!
//! ```text
//!   EM = 0x6A || H(m) || 0xBC
//! ```
//!
//! where `H(m)` is the full hash of the message. The total length of EM is
//! `2 + hash_len` bytes; the modulus `k` must be at least that large. There
//! is no PKCS#1-style DigestInfo prefix and no random salt — verification is
//! a simple equality test on the recovered hash.
//!
//! This is the simplest of the three ISO 9796-2 schemes; Schemes 2 and 3
//! provide partial / full message recovery and are not implemented here.
//! Mirrors the C v0.3.2 backport in `crypto/rsa/src/rsa_padding.c`
//! (`CRYPT_RSA_SetIso9796_2` / `CRYPT_RSA_VerifyIso9796_2`, commit `0d96cb28`).

use hitls_types::CryptoError;
use subtle::ConstantTimeEq;

/// Build an ISO/IEC 9796-2:1997 Scheme 1 encoded message.
///
/// `digest` is the message hash (caller computes it). `em_len` is the modulus
/// length in bytes (`k`). Fails with `InvalidArg` if `em_len < digest.len() + 2`.
pub fn iso9796_2_encode(digest: &[u8], em_len: usize) -> Result<Vec<u8>, CryptoError> {
    if em_len < digest.len() + 2 {
        return Err(CryptoError::InvalidArg(
            "ISO 9796-2 modulus too small for hash",
        ));
    }
    let mut em = vec![0u8; em_len];
    em[0] = 0x6A;
    // Place the hash flush left after the header, leaving the trailer at the end.
    // Bytes between the hash and trailer are zero — Scheme 1 is silent on the
    // padding interior; in practice header + hash + trailer suffice and the
    // gap is empty, but we keep the buffer length-correct for arbitrary `k`.
    em[1..1 + digest.len()].copy_from_slice(digest);
    em[em_len - 1] = 0xBC;
    Ok(em)
}

/// Verify an ISO/IEC 9796-2:1997 Scheme 1 encoded message.
///
/// Returns `Ok(true)` only when the trailer/header are correct AND the
/// embedded hash matches `digest`. Comparison is constant-time.
pub fn iso9796_2_verify(em: &[u8], digest: &[u8]) -> Result<bool, CryptoError> {
    if em.len() < digest.len() + 2 {
        return Ok(false);
    }
    // Header and trailer are fixed.
    if em[0] != 0x6A || em[em.len() - 1] != 0xBC {
        return Ok(false);
    }
    let recovered = &em[1..1 + digest.len()];
    Ok(recovered.ct_eq(digest).unwrap_u8() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_basic_sha256() {
        // 256-byte modulus (RSA-2048), 32-byte SHA-256 hash.
        let digest = [0x42u8; 32];
        let em = iso9796_2_encode(&digest, 256).unwrap();
        assert_eq!(em.len(), 256);
        assert_eq!(em[0], 0x6A);
        assert_eq!(em[em.len() - 1], 0xBC);
        assert_eq!(&em[1..33], &digest[..]);
        // Bytes between the hash and trailer are zero.
        assert!(em[33..255].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encode_minimum_length() {
        // em_len == hash_len + 2 is the boundary case.
        let digest = [0xAAu8; 32];
        let em = iso9796_2_encode(&digest, 34).unwrap();
        assert_eq!(em, [&[0x6A][..], &digest[..], &[0xBC][..]].concat());
    }

    #[test]
    fn test_encode_too_small_modulus_rejected() {
        let digest = [0u8; 32];
        // em_len < hash_len + 2 → reject
        assert!(iso9796_2_encode(&digest, 33).is_err());
        assert!(iso9796_2_encode(&digest, 0).is_err());
    }

    #[test]
    fn test_verify_roundtrip_sha256() {
        let digest = [0xCDu8; 32];
        let em = iso9796_2_encode(&digest, 256).unwrap();
        assert!(iso9796_2_verify(&em, &digest).unwrap());
    }

    #[test]
    fn test_verify_wrong_hash_rejected() {
        let digest = [0xCDu8; 32];
        let other = [0xCEu8; 32];
        let em = iso9796_2_encode(&digest, 256).unwrap();
        assert!(!iso9796_2_verify(&em, &other).unwrap());
    }

    #[test]
    fn test_verify_bad_header_rejected() {
        let digest = [0u8; 32];
        let mut em = iso9796_2_encode(&digest, 256).unwrap();
        em[0] = 0x6B; // tweak header
        assert!(!iso9796_2_verify(&em, &digest).unwrap());
    }

    #[test]
    fn test_verify_bad_trailer_rejected() {
        let digest = [0u8; 32];
        let mut em = iso9796_2_encode(&digest, 256).unwrap();
        em[255] = 0xBD; // tweak trailer
        assert!(!iso9796_2_verify(&em, &digest).unwrap());
    }

    #[test]
    fn test_verify_short_em_rejected() {
        let digest = [0u8; 32];
        let em = vec![0x6A, 0xBC]; // too short
        assert!(!iso9796_2_verify(&em, &digest).unwrap());
    }
}
