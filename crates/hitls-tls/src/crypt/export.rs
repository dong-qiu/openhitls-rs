//! TLS Key Material Export (RFC 5705 / RFC 8446 §7.5).
//!
//! Provides helpers for `export_keying_material()` on both TLS 1.3 and TLS 1.2 connections.

use super::hkdf::{derive_secret, hkdf_expand_label};
use super::prf::prf;
use hitls_crypto::provider::Digest;
use hitls_types::TlsError;

type Factory = dyn Fn() -> Box<dyn Digest> + Send + Sync;

/// Reserved labels that MUST NOT be used with key export (RFC 5705 §4).
const RESERVED_LABELS: &[&str] = &[
    "client finished",
    "server finished",
    "master secret",
    "extended master secret",
    "key expansion",
];

/// Validate that a label is not reserved.
pub fn validate_exporter_label(label: &[u8]) -> Result<(), TlsError> {
    if let Ok(label_str) = std::str::from_utf8(label) {
        for reserved in RESERVED_LABELS {
            if label_str == *reserved {
                return Err(TlsError::HandshakeFailed(format!(
                    "reserved label for key export: {label_str}"
                )));
            }
        }
    }
    Ok(())
}

/// TLS 1.3 key material export (RFC 8446 §7.5).
///
/// ```text
/// tmp = Derive-Secret(exporter_master_secret, label, "")
/// out = HKDF-Expand-Label(tmp, "exporter", Hash(context), length)
/// ```
pub fn tls13_export_keying_material(
    factory: &Factory,
    exporter_master_secret: &[u8],
    label: &[u8],
    context: Option<&[u8]>,
    length: usize,
) -> Result<Vec<u8>, TlsError> {
    validate_exporter_label(label)?;

    // Step 1: tmp = Derive-Secret(exporter_master_secret, label, "")
    // Derive-Secret uses Hash("") as the transcript_hash
    let mut empty_hasher = factory();
    let hash_len = empty_hasher.output_size();
    let mut empty_hash = vec![0u8; hash_len];
    empty_hasher
        .finish(&mut empty_hash)
        .map_err(TlsError::CryptoError)?;

    let tmp = derive_secret(factory, exporter_master_secret, label, &empty_hash)?;

    // Step 2: out = HKDF-Expand-Label(tmp, "exporter", Hash(context), length)
    let ctx = context.unwrap_or(b"");
    let mut ctx_hasher = factory();
    ctx_hasher.update(ctx).map_err(TlsError::CryptoError)?;
    let mut ctx_hash = vec![0u8; hash_len];
    ctx_hasher
        .finish(&mut ctx_hash)
        .map_err(TlsError::CryptoError)?;

    hkdf_expand_label(factory, &tmp, b"exporter", &ctx_hash, length)
}

/// TLS 1.2 key material export (RFC 5705).
///
/// ```text
/// seed = client_random(32) || server_random(32) [|| BE16(context_len) || context]
/// PRF(master_secret, label, seed, length)
/// ```
pub fn tls12_export_keying_material(
    factory: &Factory,
    master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    label: &[u8],
    context: Option<&[u8]>,
    length: usize,
) -> Result<Vec<u8>, TlsError> {
    validate_exporter_label(label)?;

    let label_str = std::str::from_utf8(label)
        .map_err(|_| TlsError::HandshakeFailed("label must be valid UTF-8".into()))?;

    let mut seed = Vec::with_capacity(64 + context.map_or(0, |c| 2 + c.len()));
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);

    if let Some(ctx) = context {
        let ctx_len = ctx.len() as u16;
        seed.extend_from_slice(&ctx_len.to_be_bytes());
        seed.extend_from_slice(ctx);
    }

    prf(factory, master_secret, label_str, &seed, length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_crypto::sha2::{Sha256, Sha384};

    fn sha256_factory() -> Box<dyn Fn() -> Box<dyn Digest> + Send + Sync> {
        Box::new(|| Box::new(Sha256::new()))
    }

    fn sha384_factory() -> Box<dyn Fn() -> Box<dyn Digest> + Send + Sync> {
        Box::new(|| Box::new(Sha384::new()))
    }

    #[test]
    fn test_validate_exporter_label_ok() {
        assert!(validate_exporter_label(b"my custom label").is_ok());
        assert!(validate_exporter_label(b"EXPORTER-my-protocol").is_ok());
    }

    #[test]
    fn test_validate_exporter_label_reserved() {
        assert!(validate_exporter_label(b"client finished").is_err());
        assert!(validate_exporter_label(b"server finished").is_err());
        assert!(validate_exporter_label(b"master secret").is_err());
        assert!(validate_exporter_label(b"extended master secret").is_err());
        assert!(validate_exporter_label(b"key expansion").is_err());
    }

    #[test]
    fn test_tls13_export_deterministic() {
        let factory = sha256_factory();
        let ems = vec![0xAA; 32]; // fake exporter_master_secret
        let label = b"test-exporter";
        let ctx = b"context data";

        let out1 = tls13_export_keying_material(&*factory, &ems, label, Some(ctx), 32).unwrap();
        let out2 = tls13_export_keying_material(&*factory, &ems, label, Some(ctx), 32).unwrap();
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 32);
    }

    #[test]
    fn test_tls13_export_no_context_differs() {
        let factory = sha256_factory();
        let ems = vec![0xBB; 32];
        let label = b"test-exporter";

        let out_none = tls13_export_keying_material(&*factory, &ems, label, None, 32).unwrap();
        let out_empty =
            tls13_export_keying_material(&*factory, &ems, label, Some(b""), 32).unwrap();
        // None and Some(b"") should produce the same result since both hash empty data
        assert_eq!(out_none, out_empty);
    }

    #[test]
    fn test_tls13_export_different_lengths() {
        let factory = sha256_factory();
        let ems = vec![0xCC; 32];
        let label = b"test-exporter";

        let out16 = tls13_export_keying_material(&*factory, &ems, label, None, 16).unwrap();
        let out32 = tls13_export_keying_material(&*factory, &ems, label, None, 32).unwrap();
        let out64 = tls13_export_keying_material(&*factory, &ems, label, None, 64).unwrap();

        assert_eq!(out16.len(), 16);
        assert_eq!(out32.len(), 32);
        assert_eq!(out64.len(), 64);
        // Shorter output should be a prefix of longer (due to HKDF-Expand)
        // (Actually not necessarily for HKDF-Expand-Label, since length is encoded in the label)
        assert_ne!(out16, out32[..16]);
    }

    #[test]
    fn test_tls13_export_forbidden_label() {
        let factory = sha256_factory();
        let ems = vec![0xDD; 32];
        assert!(tls13_export_keying_material(&*factory, &ems, b"master secret", None, 32).is_err());
    }

    #[test]
    fn test_tls13_export_sha384() {
        let factory = sha384_factory();
        let ems = vec![0xEE; 48];
        let out =
            tls13_export_keying_material(&*factory, &ems, b"test-384", Some(b"ctx"), 48).unwrap();
        assert_eq!(out.len(), 48);
    }

    #[test]
    fn test_tls12_export_deterministic() {
        let factory = sha256_factory();
        let ms = vec![0x42; 48];
        let cr = [1u8; 32];
        let sr = [2u8; 32];

        let out1 = tls12_export_keying_material(&*factory, &ms, &cr, &sr, b"test-label", None, 32)
            .unwrap();
        let out2 = tls12_export_keying_material(&*factory, &ms, &cr, &sr, b"test-label", None, 32)
            .unwrap();
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 32);
    }

    #[test]
    fn test_tls12_export_with_context() {
        let factory = sha256_factory();
        let ms = vec![0x42; 48];
        let cr = [1u8; 32];
        let sr = [2u8; 32];

        let out_none =
            tls12_export_keying_material(&*factory, &ms, &cr, &sr, b"test-label", None, 32)
                .unwrap();
        let out_ctx = tls12_export_keying_material(
            &*factory,
            &ms,
            &cr,
            &sr,
            b"test-label",
            Some(b"my context"),
            32,
        )
        .unwrap();
        // With and without context should differ
        assert_ne!(out_none, out_ctx);
    }

    #[test]
    fn test_tls12_export_forbidden_label() {
        let factory = sha256_factory();
        let ms = vec![0x42; 48];
        let cr = [1u8; 32];
        let sr = [2u8; 32];
        assert!(tls12_export_keying_material(
            &*factory,
            &ms,
            &cr,
            &sr,
            b"client finished",
            None,
            32
        )
        .is_err());
    }
}
