//! RSASSA-PSS signature padding (RFC 8017 §9.1).
//!
//! Supports SHA-256, SHA-384, and SHA-512 as the hash function (Phase T95
//! generalised this from SHA-256 only). MGF1 uses the same hash. Default
//! salt length equals the hash output length.

use hitls_types::CryptoError;

use super::{mgf1_with_hash, RsaHashAlg};

/// Hash output length for the given algorithm (bytes).
pub(crate) const fn h_len(alg: RsaHashAlg) -> usize {
    match alg {
        RsaHashAlg::Sha1 => 20,
        RsaHashAlg::Sha256 => 32,
        RsaHashAlg::Sha384 => 48,
        RsaHashAlg::Sha512 => 64,
    }
}

/// Hash a buffer with the given algorithm. Returns `Vec<u8>` of `h_len(alg)`.
fn hash_with(alg: RsaHashAlg, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match alg {
        RsaHashAlg::Sha256 => {
            let mut h = crate::sha2::Sha256::new();
            h.update(data)?;
            Ok(h.finish()?.to_vec())
        }
        RsaHashAlg::Sha384 => {
            let mut h = crate::sha2::Sha384::new();
            h.update(data)?;
            Ok(h.finish()?.to_vec())
        }
        RsaHashAlg::Sha512 => {
            let mut h = crate::sha2::Sha512::new();
            h.update(data)?;
            Ok(h.finish()?.to_vec())
        }
        RsaHashAlg::Sha1 => Err(CryptoError::InvalidArg("SHA-1 not supported in PSS")),
    }
}

/// EMSA-PSS encoding (RFC 8017 §9.1.1) — SHA-256 wrapper for backward
/// compatibility with pre-T95 callers.
pub(crate) fn pss_sign_pad(digest: &[u8], em_bits: usize) -> Result<Vec<u8>, CryptoError> {
    pss_sign_pad_alg(digest, em_bits, RsaHashAlg::Sha256)
}

/// EMSA-PSS encoding with explicit salt length — SHA-256 wrapper.
pub(crate) fn pss_sign_pad_with_salt(
    digest: &[u8],
    em_bits: usize,
    salt_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    pss_sign_pad_with_salt_alg(digest, em_bits, salt_len, RsaHashAlg::Sha256)
}

/// EMSA-PSS encoding parameterised by hash algorithm (Phase T95).
///
/// `digest` is the pre-computed message hash (mHash). Its length MUST equal
/// the output size of `alg` (32 / 48 / 64 bytes for SHA-256 / 384 / 512).
/// Salt length defaults to the hash output length.
pub(crate) fn pss_sign_pad_alg(
    digest: &[u8],
    em_bits: usize,
    alg: RsaHashAlg,
) -> Result<Vec<u8>, CryptoError> {
    pss_sign_pad_with_salt_alg(digest, em_bits, h_len(alg), alg)
}

/// EMSA-PSS encoding parameterised by hash algorithm AND salt length.
pub(crate) fn pss_sign_pad_with_salt_alg(
    digest: &[u8],
    em_bits: usize,
    salt_len: usize,
    alg: RsaHashAlg,
) -> Result<Vec<u8>, CryptoError> {
    let hl = h_len(alg);
    if digest.len() != hl {
        return Err(CryptoError::InvalidArg(""));
    }

    let em_len = em_bits.div_ceil(8);

    // emLen must be >= hLen + sLen + 2
    if em_len < hl + salt_len + 2 {
        return Err(CryptoError::RsaInvalidPadding);
    }

    // Generate random salt (stack-allocated for typical sizes).
    if salt_len <= 64 {
        let mut salt = [0u8; 64];
        if salt_len > 0 {
            getrandom::fill(&mut salt[..salt_len]).map_err(|_| CryptoError::BnRandGenFail)?;
        }
        pss_encode_alg(digest, em_bits, &salt[..salt_len], alg)
    } else {
        let mut salt = vec![0u8; salt_len];
        getrandom::fill(&mut salt).map_err(|_| CryptoError::BnRandGenFail)?;
        pss_encode_alg(digest, em_bits, &salt, alg)
    }
}

/// EMSA-PSS encoding with a **caller-provided salt** (no RNG). Used only by
/// the `kat-nonce` deterministic-sign hook to reproduce fixed-salt PSS sign
/// KAT vectors; production signing uses `pss_sign_pad_with_salt_alg`, which
/// generates a random salt. Validates `digest.len()` and the
/// `emLen >= hLen + sLen + 2` bound (checked arithmetic, so a huge caller
/// `salt.len()` cannot wrap) before encoding.
#[cfg(feature = "kat-nonce")]
pub(crate) fn pss_sign_pad_with_salt_bytes_alg(
    digest: &[u8],
    em_bits: usize,
    salt: &[u8],
    alg: RsaHashAlg,
) -> Result<Vec<u8>, CryptoError> {
    let hl = h_len(alg);
    if digest.len() != hl {
        return Err(CryptoError::InvalidArg(""));
    }
    let em_len = em_bits.div_ceil(8);
    match hl.checked_add(salt.len()).and_then(|x| x.checked_add(2)) {
        Some(need) if need <= em_len => {}
        _ => return Err(CryptoError::RsaInvalidPadding),
    }
    pss_encode_alg(digest, em_bits, salt, alg)
}

/// Core PSS encoding with a provided salt (used by tests for determinism).
/// SHA-256 wrapper kept for the existing test surface.
#[cfg(test)]
fn pss_encode(digest: &[u8], em_bits: usize, salt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    pss_encode_alg(digest, em_bits, salt, RsaHashAlg::Sha256)
}

/// Core PSS encoding parameterised by hash algorithm.
fn pss_encode_alg(
    digest: &[u8],
    em_bits: usize,
    salt: &[u8],
    alg: RsaHashAlg,
) -> Result<Vec<u8>, CryptoError> {
    let hl = h_len(alg);
    let em_len = em_bits.div_ceil(8);
    let salt_len = salt.len();

    // M' = 0x00 00 00 00 00 00 00 00 || mHash || salt
    let mut m_prime = Vec::with_capacity(8 + hl + salt_len);
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(salt);

    // H = Hash(M')
    let h = hash_with(alg, &m_prime)?;

    // DB = PS || 0x01 || salt
    // PS = zero octets, length = emLen - hLen - sLen - 2
    let db_len = em_len - hl - 1;
    let ps_len = db_len - salt_len - 1;
    let mut db = Vec::with_capacity(db_len);
    db.extend(std::iter::repeat(0x00).take(ps_len));
    db.push(0x01);
    db.extend_from_slice(salt);
    debug_assert_eq!(db.len(), db_len);

    // dbMask = MGF(H, emLen - hLen - 1) — same hash as the outer PSS hash.
    let db_mask = mgf1_with_hash(&h, db_len, alg)?;

    // maskedDB = DB XOR dbMask (in-place on db)
    for (d, m) in db.iter_mut().zip(db_mask.iter()) {
        *d ^= m;
    }

    // Set the leftmost 8*emLen - emBits bits of maskedDB to zero
    let top_bits = 8 * em_len - em_bits;
    if top_bits > 0 {
        db[0] &= 0xFF >> top_bits;
    }

    // EM = maskedDB || H || 0xbc
    let mut em = Vec::with_capacity(em_len);
    em.extend_from_slice(&db);
    em.extend_from_slice(&h);
    em.push(0xbc);
    debug_assert_eq!(em.len(), em_len);

    Ok(em)
}

/// EMSA-PSS verification (RFC 8017 §9.1.2) — SHA-256 wrapper.
pub(crate) fn pss_verify_unpad(
    em: &[u8],
    digest: &[u8],
    em_bits: usize,
) -> Result<bool, CryptoError> {
    pss_verify_unpad_with_salt(em, digest, em_bits, h_len(RsaHashAlg::Sha256))
}

/// EMSA-PSS verification with explicit salt length — SHA-256 wrapper.
pub(crate) fn pss_verify_unpad_with_salt(
    em: &[u8],
    digest: &[u8],
    em_bits: usize,
    salt_len: usize,
) -> Result<bool, CryptoError> {
    pss_verify_unpad_with_salt_alg(em, digest, em_bits, salt_len, RsaHashAlg::Sha256)
}

/// EMSA-PSS verification parameterised by hash algorithm (Phase T95).
pub(crate) fn pss_verify_unpad_alg(
    em: &[u8],
    digest: &[u8],
    em_bits: usize,
    alg: RsaHashAlg,
) -> Result<bool, CryptoError> {
    pss_verify_unpad_with_salt_alg(em, digest, em_bits, h_len(alg), alg)
}

/// EMSA-PSS verification parameterised by hash algorithm AND salt length.
pub(crate) fn pss_verify_unpad_with_salt_alg(
    em: &[u8],
    digest: &[u8],
    em_bits: usize,
    salt_len: usize,
    alg: RsaHashAlg,
) -> Result<bool, CryptoError> {
    use subtle::ConstantTimeEq;

    let hl = h_len(alg);
    if digest.len() != hl {
        return Err(CryptoError::InvalidArg(""));
    }

    let em_len = em_bits.div_ceil(8);

    if em.len() < em_len {
        return Ok(false);
    }
    // Use the rightmost em_len bytes (in case em is padded with a leading zero)
    let em = &em[em.len() - em_len..];

    // emLen must be >= hLen + sLen + 2. Compute with checked arithmetic: with a
    // caller-supplied `salt_len` (e.g. via `RsaPublicKey::verify_pss_with_salt`),
    // `hl + salt_len + 2` must not wrap and let an oversized salt reach the
    // `db[..ps_len]` slice below (`ps_len = db_len - salt_len - 1`).
    match hl.checked_add(salt_len).and_then(|x| x.checked_add(2)) {
        Some(need) if need <= em_len => {}
        _ => return Ok(false),
    }

    // Check the rightmost octet is 0xbc
    if em[em_len - 1] != 0xbc {
        return Ok(false);
    }

    // Split: maskedDB || H
    let db_len = em_len - hl - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..db_len + hl];

    // Check the leftmost 8*emLen - emBits bits of maskedDB are zero
    let top_bits = 8 * em_len - em_bits;
    if top_bits > 0 && (masked_db[0] & (0xFF << (8 - top_bits))) != 0 {
        return Ok(false);
    }

    // dbMask = MGF(H, emLen - hLen - 1) — same hash as the outer PSS hash.
    let db_mask = mgf1_with_hash(h, db_len, alg)?;

    // DB = maskedDB XOR dbMask (in-place on copy)
    let mut db = masked_db.to_vec();
    for (d, m) in db.iter_mut().zip(db_mask.iter()) {
        *d ^= m;
    }

    // Set the leftmost 8*emLen - emBits bits of DB to zero
    if top_bits > 0 {
        db[0] &= 0xFF >> top_bits;
    }

    // Check DB = PS || 0x01 || salt
    // PS should be all zeros
    let ps_len = db_len - salt_len - 1;
    for &b in &db[..ps_len] {
        if b != 0x00 {
            return Ok(false);
        }
    }
    if db[ps_len] != 0x01 {
        return Ok(false);
    }

    let salt = &db[ps_len + 1..];

    // M' = 0x00 00 00 00 00 00 00 00 || mHash || salt
    let mut m_prime = Vec::with_capacity(8 + hl + salt_len);
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(salt);

    // H' = Hash(M')
    let h_prime = hash_with(alg, &m_prime)?;

    // Compare H == H' (constant-time)
    Ok(h.ct_eq(&h_prime).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256(data: &[u8]) -> Vec<u8> {
        let mut h = crate::sha2::Sha256::new();
        h.update(data).unwrap();
        h.finish().unwrap().to_vec()
    }

    fn sha384(data: &[u8]) -> Vec<u8> {
        let mut h = crate::sha2::Sha384::new();
        h.update(data).unwrap();
        h.finish().unwrap().to_vec()
    }

    fn sha512(data: &[u8]) -> Vec<u8> {
        let mut h = crate::sha2::Sha512::new();
        h.update(data).unwrap();
        h.finish().unwrap().to_vec()
    }

    #[test]
    fn test_pss_sign_pad_wrong_digest_length() {
        // PSS requires exactly 32-byte (SHA-256) digest
        let short = vec![0u8; 20];
        assert!(pss_sign_pad(&short, 1023).is_err());

        let long = vec![0u8; 64];
        assert!(pss_sign_pad(&long, 1023).is_err());
    }

    #[test]
    fn test_pss_sign_pad_em_too_small() {
        let digest = sha256(b"hello");
        // em_bits must allow em_len >= H_LEN + salt_len + 2 = 32 + 32 + 2 = 66
        // em_len = ceil(em_bits/8), so em_bits = 65*8 = 520 gives em_len=65 (too small)
        assert!(pss_sign_pad(&digest, 520).is_err());
    }

    #[test]
    fn test_pss_encode_and_verify_roundtrip() {
        let digest = sha256(b"test message");
        let salt = vec![0xAB; 32];
        let em_bits = 1023; // 128 bytes em_len

        let em = pss_encode(&digest, em_bits, &salt).unwrap();
        assert_eq!(em.len(), 128);
        assert_eq!(em[127], 0xbc);

        // Top bit must be zero (8*128 - 1023 = 1 top bit cleared)
        assert_eq!(em[0] & 0x80, 0);

        // Verify should succeed
        let ok = pss_verify_unpad(&em, &digest, em_bits).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_pss_verify_wrong_digest() {
        let digest = sha256(b"message A");
        let salt = vec![0xCD; 32];
        let em_bits = 1023;

        let em = pss_encode(&digest, em_bits, &salt).unwrap();

        let wrong_digest = sha256(b"message B");
        let ok = pss_verify_unpad(&em, &wrong_digest, em_bits).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_pss_verify_tampered_em() {
        let digest = sha256(b"data");
        let salt = vec![0x11; 32];
        let em_bits = 1023;

        let mut em = pss_encode(&digest, em_bits, &salt).unwrap();

        // Tamper with a byte in the middle
        em[60] ^= 0x01;
        let ok = pss_verify_unpad(&em, &digest, em_bits).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_pss_verify_bad_trailer() {
        let digest = sha256(b"data");
        let salt = vec![0x22; 32];
        let em_bits = 1023;

        let mut em = pss_encode(&digest, em_bits, &salt).unwrap();

        // Replace trailer byte 0xbc with something else
        let last = em.len() - 1;
        em[last] = 0xAA;
        let ok = pss_verify_unpad(&em, &digest, em_bits).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_pss_zero_salt_roundtrip() {
        let digest = sha256(b"zero salt");
        let em_bits = 1023;

        let em = pss_encode(&digest, em_bits, &[]).unwrap();
        let ok = pss_verify_unpad_with_salt(&em, &digest, em_bits, 0).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_pss_verify_wrong_digest_length() {
        let em = vec![0u8; 128];
        let short_digest = vec![0u8; 20];
        assert!(pss_verify_unpad(&em, &short_digest, 1023).is_err());
    }

    #[test]
    fn test_pss_verify_em_too_short() {
        let digest = sha256(b"x");
        // em shorter than em_len
        let em = vec![0u8; 10];
        let ok = pss_verify_unpad(&em, &digest, 1023).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_pss_verify_huge_salt_len_no_panic() {
        // A caller-supplied salt_len near usize::MAX must not wrap the
        // `hLen + salt_len + 2` length check (which would otherwise reach an
        // out-of-bounds `db[..ps_len]` slice). It must reject cleanly.
        let digest = sha256(b"x");
        let em = vec![0u8; 256];
        let ok = pss_verify_unpad_with_salt_alg(&em, &digest, 2047, usize::MAX, RsaHashAlg::Sha256)
            .unwrap();
        assert!(!ok);
    }
}
