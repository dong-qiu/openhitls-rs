//! HPKE (Hybrid Public Key Encryption) — RFC 9180.
//!
//! Supports all 4 modes (Base, PSK, Auth, AuthPSK), 4 KEMs, 3 KDFs, and 4 AEADs.
//!
//! KEMs: DHKEM(X25519, HKDF-SHA256), DHKEM(P-256, HKDF-SHA256),
//!       DHKEM(P-384, HKDF-SHA384), DHKEM(P-521, HKDF-SHA512)
//! KDFs: HKDF-SHA256, HKDF-SHA384, HKDF-SHA512
//! AEADs: AES-128-GCM, AES-256-GCM, ChaCha20Poly1305, Export-only

use crate::chacha20::ChaCha20Poly1305;
use crate::ecdh::EcdhKeyPair;
use crate::hkdf::Hkdf;
use crate::hmac::Hmac;
use crate::modes::gcm::{gcm_decrypt, gcm_encrypt};
use crate::provider::Digest;
use crate::sha2::{Sha256, Sha384, Sha512};
use crate::x25519::{X25519PrivateKey, X25519PublicKey};
use hitls_types::{CryptoError, EccCurveId};
use zeroize::Zeroize;

// --- Mode Constants ---

const MODE_BASE: u8 = 0x00;
const MODE_PSK: u8 = 0x01;
const MODE_AUTH: u8 = 0x02;
const MODE_AUTH_PSK: u8 = 0x03;

// --- Enums ---

/// KEM algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeKem {
    /// DHKEM(X25519, HKDF-SHA256) — KEM ID 0x0020.
    DhkemX25519HkdfSha256,
    /// DHKEM(P-256, HKDF-SHA256) — KEM ID 0x0010.
    DhkemP256HkdfSha256,
    /// DHKEM(P-384, HKDF-SHA384) — KEM ID 0x0011.
    DhkemP384HkdfSha384,
    /// DHKEM(P-521, HKDF-SHA512) — KEM ID 0x0012.
    DhkemP521HkdfSha512,
}

/// KDF algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeKdf {
    /// HKDF-SHA256 — KDF ID 0x0001.
    HkdfSha256,
    /// HKDF-SHA384 — KDF ID 0x0002.
    HkdfSha384,
    /// HKDF-SHA512 — KDF ID 0x0003.
    HkdfSha512,
}

/// AEAD algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeAead {
    /// AES-128-GCM — AEAD ID 0x0001.
    Aes128Gcm,
    /// AES-256-GCM — AEAD ID 0x0002.
    Aes256Gcm,
    /// ChaCha20Poly1305 — AEAD ID 0x0003.
    ChaCha20Poly1305,
    /// Export-only — AEAD ID 0xFFFF.
    ExportOnly,
}

/// HPKE cipher suite (KEM + KDF + AEAD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSuite {
    pub kem: HpkeKem,
    pub kdf: HpkeKdf,
    pub aead: HpkeAead,
}

// --- Parameter methods ---

impl HpkeKem {
    fn kem_id(self) -> u16 {
        match self {
            Self::DhkemP256HkdfSha256 => 0x0010,
            Self::DhkemP384HkdfSha384 => 0x0011,
            Self::DhkemP521HkdfSha512 => 0x0012,
            Self::DhkemX25519HkdfSha256 => 0x0020,
        }
    }

    /// Shared secret size (Nsecret).
    fn nsecret(self) -> usize {
        match self {
            Self::DhkemX25519HkdfSha256 | Self::DhkemP256HkdfSha256 => 32,
            Self::DhkemP384HkdfSha384 => 48,
            Self::DhkemP521HkdfSha512 => 64,
        }
    }

    /// DH output size (Ndh).
    fn ndh(self) -> usize {
        match self {
            Self::DhkemX25519HkdfSha256 => 32,
            Self::DhkemP256HkdfSha256 => 32,
            Self::DhkemP384HkdfSha384 => 48,
            Self::DhkemP521HkdfSha512 => 66,
        }
    }

    /// Public key size (Npk).
    fn npk(self) -> usize {
        match self {
            Self::DhkemX25519HkdfSha256 => 32,
            Self::DhkemP256HkdfSha256 => 65, // uncompressed
            Self::DhkemP384HkdfSha384 => 97,
            Self::DhkemP521HkdfSha512 => 133,
        }
    }

    /// Private key size (Nsk).
    fn nsk(self) -> usize {
        match self {
            Self::DhkemX25519HkdfSha256 => 32,
            Self::DhkemP256HkdfSha256 => 32,
            Self::DhkemP384HkdfSha384 => 48,
            Self::DhkemP521HkdfSha512 => 66,
        }
    }

    /// KEM hash output size (Nh for the KEM's internal HKDF).
    fn nh(self) -> usize {
        match self {
            Self::DhkemX25519HkdfSha256 | Self::DhkemP256HkdfSha256 => 32,
            Self::DhkemP384HkdfSha384 => 48,
            Self::DhkemP521HkdfSha512 => 64,
        }
    }

    fn hash_factory(self) -> fn() -> Box<dyn Digest> {
        match self {
            Self::DhkemX25519HkdfSha256 | Self::DhkemP256HkdfSha256 => sha256_factory,
            Self::DhkemP384HkdfSha384 => sha384_factory,
            Self::DhkemP521HkdfSha512 => sha512_factory,
        }
    }

    fn curve_id(self) -> Option<EccCurveId> {
        match self {
            Self::DhkemP256HkdfSha256 => Some(EccCurveId::NistP256),
            Self::DhkemP384HkdfSha384 => Some(EccCurveId::NistP384),
            Self::DhkemP521HkdfSha512 => Some(EccCurveId::NistP521),
            Self::DhkemX25519HkdfSha256 => None,
        }
    }
}

impl HpkeKdf {
    fn kdf_id(self) -> u16 {
        match self {
            Self::HkdfSha256 => 0x0001,
            Self::HkdfSha384 => 0x0002,
            Self::HkdfSha512 => 0x0003,
        }
    }

    fn nh(self) -> usize {
        match self {
            Self::HkdfSha256 => 32,
            Self::HkdfSha384 => 48,
            Self::HkdfSha512 => 64,
        }
    }

    fn hash_factory(self) -> fn() -> Box<dyn Digest> {
        match self {
            Self::HkdfSha256 => sha256_factory,
            Self::HkdfSha384 => sha384_factory,
            Self::HkdfSha512 => sha512_factory,
        }
    }
}

impl HpkeAead {
    fn aead_id(self) -> u16 {
        match self {
            Self::Aes128Gcm => 0x0001,
            Self::Aes256Gcm => 0x0002,
            Self::ChaCha20Poly1305 => 0x0003,
            Self::ExportOnly => 0xFFFF,
        }
    }

    /// Key size (Nk).
    fn nk(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
            Self::ExportOnly => 0,
        }
    }

    /// Nonce size (Nn).
    fn nn(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm | Self::ChaCha20Poly1305 => 12,
            Self::ExportOnly => 0,
        }
    }

    fn seal(self, key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => gcm_encrypt(key, nonce, aad, pt),
            Self::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(key)?;
                cipher.encrypt(nonce, aad, pt)
            }
            Self::ExportOnly => Err(CryptoError::NotSupported),
        }
    }

    fn open(self, key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => gcm_decrypt(key, nonce, aad, ct),
            Self::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(key)?;
                cipher.decrypt(nonce, aad, ct)
            }
            Self::ExportOnly => Err(CryptoError::NotSupported),
        }
    }
}

// --- Default suite (backward compat) ---

const DEFAULT_SUITE: CipherSuite = CipherSuite {
    kem: HpkeKem::DhkemX25519HkdfSha256,
    kdf: HpkeKdf::HkdfSha256,
    aead: HpkeAead::Aes128Gcm,
};

// --- Hash factories ---

fn sha256_factory() -> Box<dyn Digest> {
    Box::new(Sha256::new())
}

fn sha384_factory() -> Box<dyn Digest> {
    Box::new(Sha384::new())
}

fn sha512_factory() -> Box<dyn Digest> {
    Box::new(Sha512::new())
}

// --- Suite IDs ---

fn kem_suite_id(kem: HpkeKem) -> Vec<u8> {
    let mut id = b"KEM".to_vec();
    id.extend_from_slice(&kem.kem_id().to_be_bytes());
    id
}

fn hpke_suite_id(suite: &CipherSuite) -> Vec<u8> {
    let mut id = b"HPKE".to_vec();
    id.extend_from_slice(&suite.kem.kem_id().to_be_bytes());
    id.extend_from_slice(&suite.kdf.kdf_id().to_be_bytes());
    id.extend_from_slice(&suite.aead.aead_id().to_be_bytes());
    id
}

// --- Labeled Extract / Expand (RFC 9180 §4) ---

fn labeled_extract(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
    factory: fn() -> Box<dyn Digest>,
    nh: usize,
) -> Result<Vec<u8>, CryptoError> {
    let mut labeled_ikm = b"HPKE-v1".to_vec();
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    let effective_salt = if salt.is_empty() {
        vec![0u8; nh]
    } else {
        salt.to_vec()
    };

    Hmac::mac(factory, &effective_salt, &labeled_ikm)
}

fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
    factory: fn() -> Box<dyn Digest>,
    nh: usize,
) -> Result<Vec<u8>, CryptoError> {
    let mut labeled_info = (len as u16).to_be_bytes().to_vec();
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    Hkdf::from_prk_with_factory(prk, factory, nh).expand(&labeled_info, len)
}

// --- KEM operations ---

/// DeriveKeyPair for X25519 KEM.
fn x25519_derive_key_pair(kem: HpkeKem, ikm: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let sid = kem_suite_id(kem);
    let factory = kem.hash_factory();
    let nh = kem.nh();
    let dkp_prk = labeled_extract(&sid, &[], b"dkp_prk", ikm, factory, nh)?;
    let sk_bytes = labeled_expand(&sid, &dkp_prk, b"sk", &[], 32, factory, nh)?;
    let sk = X25519PrivateKey::new(&sk_bytes)?;
    let pk = sk.public_key();
    Ok((sk_bytes, pk.as_bytes().to_vec()))
}

/// DeriveKeyPair for ECC KEMs (P-256, P-384, P-521) — RFC 9180 §7.1.3.
fn ecc_derive_key_pair(kem: HpkeKem, ikm: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let sid = kem_suite_id(kem);
    let factory = kem.hash_factory();
    let nh = kem.nh();
    let curve_id = kem.curve_id().ok_or(CryptoError::NotSupported)?;
    let nsk = kem.nsk();

    let dkp_prk = labeled_extract(&sid, &[], b"dkp_prk", ikm, factory, nh)?;

    // Counter-based rejection sampling (RFC 9180 §7.1.3)
    let order = ecc_order(curve_id);
    for counter in 0u8..=255 {
        let mut sk_bytes =
            labeled_expand(&sid, &dkp_prk, b"candidate", &[counter], nsk, factory, nh)?;

        // Apply bitmask for P-521
        if curve_id == EccCurveId::NistP521 {
            sk_bytes[0] &= 0x01;
        }

        // Check 0 < sk < order
        if sk_bytes.iter().all(|&b| b == 0) {
            continue;
        }
        if !less_than_order(&sk_bytes, &order) {
            continue;
        }

        let kp = EcdhKeyPair::from_private_key(curve_id, &sk_bytes)?;
        let pk = kp.public_key_bytes()?;
        return Ok((sk_bytes, pk));
    }
    Err(CryptoError::BnRandGenFail)
}

fn ecc_order(curve: EccCurveId) -> Vec<u8> {
    match curve {
        EccCurveId::NistP256 => {
            hex_literal(
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            )
        }
        EccCurveId::NistP384 => {
            hex_literal(
                "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            )
        }
        EccCurveId::NistP521 => {
            hex_literal(
                "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
            )
        }
        _ => Vec::new(),
    }
}

fn hex_literal(s: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let mut chars = s.chars();
    while let (Some(h), Some(l)) = (chars.next(), chars.next()) {
        let hv = h.to_digit(16).expect("valid hex digit") as u8;
        let lv = l.to_digit(16).expect("valid hex digit") as u8;
        bytes.push((hv << 4) | lv);
    }
    bytes
}

fn less_than_order(sk: &[u8], order: &[u8]) -> bool {
    if sk.len() != order.len() {
        return sk.len() < order.len();
    }
    for (s, o) in sk.iter().zip(order.iter()) {
        match s.cmp(o) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    false // equal → not less
}

/// Derive key pair for the given KEM.
fn kem_derive_key_pair(kem: HpkeKem, ikm: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    match kem {
        HpkeKem::DhkemX25519HkdfSha256 => x25519_derive_key_pair(kem, ikm),
        _ => ecc_derive_key_pair(kem, ikm),
    }
}

/// Perform DH operation.
fn dh(kem: HpkeKem, sk: &[u8], pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match kem {
        HpkeKem::DhkemX25519HkdfSha256 => {
            let sk = X25519PrivateKey::new(sk)?;
            let pk = X25519PublicKey::new(pk)?;
            sk.diffie_hellman(&pk)
        }
        _ => {
            let curve_id = kem.curve_id().ok_or(CryptoError::NotSupported)?;
            let kp = EcdhKeyPair::from_private_key(curve_id, sk)?;
            kp.compute_shared_secret(pk)
        }
    }
}

/// Generate a random key pair for the given KEM.
fn kem_generate(kem: HpkeKem) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    match kem {
        HpkeKem::DhkemX25519HkdfSha256 => {
            let sk = X25519PrivateKey::generate()?;
            let pk = sk.public_key();
            Ok((sk.to_bytes().to_vec(), pk.as_bytes().to_vec()))
        }
        _ => {
            let curve_id = kem.curve_id().ok_or(CryptoError::NotSupported)?;
            let kp = EcdhKeyPair::generate(curve_id)?;
            let sk = kp.private_key_bytes();
            let pk = kp.public_key_bytes()?;
            Ok((sk, pk))
        }
    }
}

/// Get the public key from a private key.
fn kem_public_key(kem: HpkeKem, sk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match kem {
        HpkeKem::DhkemX25519HkdfSha256 => {
            let sk = X25519PrivateKey::new(sk)?;
            Ok(sk.public_key().as_bytes().to_vec())
        }
        _ => {
            let curve_id = kem.curve_id().ok_or(CryptoError::NotSupported)?;
            let kp = EcdhKeyPair::from_private_key(curve_id, sk)?;
            kp.public_key_bytes()
        }
    }
}

/// ExtractAndExpand(dh, kem_context) → shared_secret (RFC 9180 §4.1).
fn kem_extract_and_expand(
    kem: HpkeKem,
    dh: &[u8],
    kem_context: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let sid = kem_suite_id(kem);
    let factory = kem.hash_factory();
    let nh = kem.nh();
    let eae_prk = labeled_extract(&sid, &[], b"eae_prk", dh, factory, nh)?;
    labeled_expand(
        &sid,
        &eae_prk,
        b"shared_secret",
        kem_context,
        kem.nsecret(),
        factory,
        nh,
    )
}

/// Base mode Encap (random ephemeral key).
fn kem_encap(kem: HpkeKem, pk_r: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let (sk_e, pk_e) = kem_generate(kem)?;
    let dh_val = dh(kem, &sk_e, pk_r)?;

    let mut kem_context = Vec::with_capacity(pk_e.len() + pk_r.len());
    kem_context.extend_from_slice(&pk_e);
    kem_context.extend_from_slice(pk_r);

    let shared_secret = kem_extract_and_expand(kem, &dh_val, &kem_context)?;
    Ok((shared_secret, pk_e))
}

/// Base mode Decap.
fn kem_decap(kem: HpkeKem, enc: &[u8], sk_r: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let dh_val = dh(kem, sk_r, enc)?;
    let pk_r = kem_public_key(kem, sk_r)?;

    let mut kem_context = Vec::with_capacity(enc.len() + pk_r.len());
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(&pk_r);

    kem_extract_and_expand(kem, &dh_val, &kem_context)
}

/// Auth mode Encap: dual DH.
fn kem_auth_encap(
    kem: HpkeKem,
    pk_r: &[u8],
    sk_s: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let (sk_e, pk_e) = kem_generate(kem)?;
    let dh1 = dh(kem, &sk_e, pk_r)?;
    let dh2 = dh(kem, sk_s, pk_r)?;

    let mut dh_combined = Vec::with_capacity(dh1.len() + dh2.len());
    dh_combined.extend_from_slice(&dh1);
    dh_combined.extend_from_slice(&dh2);

    let pk_s = kem_public_key(kem, sk_s)?;
    let mut kem_context = Vec::with_capacity(pk_e.len() + pk_r.len() + pk_s.len());
    kem_context.extend_from_slice(&pk_e);
    kem_context.extend_from_slice(pk_r);
    kem_context.extend_from_slice(&pk_s);

    let shared_secret = kem_extract_and_expand(kem, &dh_combined, &kem_context)?;
    Ok((shared_secret, pk_e))
}

/// Auth mode Decap: dual DH.
fn kem_auth_decap(
    kem: HpkeKem,
    enc: &[u8],
    sk_r: &[u8],
    pk_s: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let dh1 = dh(kem, sk_r, enc)?;
    let dh2 = dh(kem, sk_r, pk_s)?;

    let mut dh_combined = Vec::with_capacity(dh1.len() + dh2.len());
    dh_combined.extend_from_slice(&dh1);
    dh_combined.extend_from_slice(&dh2);

    let pk_r = kem_public_key(kem, sk_r)?;
    let mut kem_context = Vec::with_capacity(enc.len() + pk_r.len() + pk_s.len());
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(&pk_r);
    kem_context.extend_from_slice(pk_s);

    kem_extract_and_expand(kem, &dh_combined, &kem_context)
}

/// Deterministic Encap (for testing) — uses DeriveKeyPair.
#[cfg(test)]
fn kem_encap_deterministic(
    kem: HpkeKem,
    pk_r: &[u8],
    ikm_e: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let (sk_e, pk_e) = kem_derive_key_pair(kem, ikm_e)?;
    let dh_val = dh(kem, &sk_e, pk_r)?;

    let mut kem_context = Vec::with_capacity(pk_e.len() + pk_r.len());
    kem_context.extend_from_slice(&pk_e);
    kem_context.extend_from_slice(pk_r);

    let shared_secret = kem_extract_and_expand(kem, &dh_val, &kem_context)?;
    Ok((shared_secret, pk_e))
}

// --- HPKE Key Schedule (RFC 9180 §5.1) ---

type KsOutput = (Vec<u8>, Vec<u8>, Vec<u8>);

fn key_schedule(
    suite: &CipherSuite,
    mode: u8,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<KsOutput, CryptoError> {
    let sid = hpke_suite_id(suite);
    let factory = suite.kdf.hash_factory();
    let nh = suite.kdf.nh();

    let psk_id_hash = labeled_extract(&sid, &[], b"psk_id_hash", psk_id, factory, nh)?;
    let info_hash = labeled_extract(&sid, &[], b"info_hash", info, factory, nh)?;

    let mut ks_context = Vec::with_capacity(1 + nh + nh);
    ks_context.push(mode);
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);

    let secret = labeled_extract(&sid, shared_secret, b"secret", psk, factory, nh)?;

    let nk = suite.aead.nk();
    let nn = suite.aead.nn();

    let key = if nk > 0 {
        labeled_expand(&sid, &secret, b"key", &ks_context, nk, factory, nh)?
    } else {
        Vec::new()
    };
    let base_nonce = if nn > 0 {
        labeled_expand(&sid, &secret, b"base_nonce", &ks_context, nn, factory, nh)?
    } else {
        Vec::new()
    };
    let exporter_secret = labeled_expand(&sid, &secret, b"exp", &ks_context, nh, factory, nh)?;

    Ok((key, base_nonce, exporter_secret))
}

// --- HPKE Context ---

/// HPKE encryption context.
///
/// After setup, use `seal`/`open` for AEAD encryption/decryption,
/// and `export` for secret export.
#[derive(Clone)]
pub struct HpkeCtx {
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    exporter_secret: Vec<u8>,
    seq: u64,
    suite: CipherSuite,
}

impl HpkeCtx {
    // ===== Backward-compatible API (X25519/SHA-256/AES-128-GCM) =====

    /// Set up an HPKE sender context (Base mode, default suite).
    pub fn setup_sender(
        recipient_public_key: &[u8],
        info: &[u8],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        Self::setup_sender_with_suite(DEFAULT_SUITE, recipient_public_key, info)
    }

    /// Set up an HPKE recipient context (Base mode, default suite).
    pub fn setup_recipient(
        private_key: &[u8],
        enc: &[u8],
        info: &[u8],
    ) -> Result<Self, CryptoError> {
        Self::setup_recipient_with_suite(DEFAULT_SUITE, private_key, enc, info)
    }

    /// Set up an HPKE sender context (PSK mode, default suite).
    pub fn setup_sender_psk(
        recipient_public_key: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        Self::setup_sender_psk_with_suite(DEFAULT_SUITE, recipient_public_key, info, psk, psk_id)
    }

    /// Set up an HPKE recipient context (PSK mode, default suite).
    pub fn setup_recipient_psk(
        private_key: &[u8],
        enc: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, CryptoError> {
        Self::setup_recipient_psk_with_suite(DEFAULT_SUITE, private_key, enc, info, psk, psk_id)
    }

    // ===== Suite-parameterized API =====

    /// Set up an HPKE sender context (Base mode) with a given cipher suite.
    pub fn setup_sender_with_suite(
        suite: CipherSuite,
        pk_r: &[u8],
        info: &[u8],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        let (shared_secret, enc) = kem_encap(suite.kem, pk_r)?;
        let (key, base_nonce, exporter_secret) =
            key_schedule(&suite, MODE_BASE, &shared_secret, info, &[], &[])?;
        Ok((
            Self {
                key,
                base_nonce,
                exporter_secret,
                seq: 0,
                suite,
            },
            enc,
        ))
    }

    /// Set up an HPKE recipient context (Base mode) with a given cipher suite.
    pub fn setup_recipient_with_suite(
        suite: CipherSuite,
        sk_r: &[u8],
        enc: &[u8],
        info: &[u8],
    ) -> Result<Self, CryptoError> {
        let shared_secret = kem_decap(suite.kem, enc, sk_r)?;
        let (key, base_nonce, exporter_secret) =
            key_schedule(&suite, MODE_BASE, &shared_secret, info, &[], &[])?;
        Ok(Self {
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
            suite,
        })
    }

    /// Set up an HPKE sender context (PSK mode) with a given cipher suite.
    pub fn setup_sender_psk_with_suite(
        suite: CipherSuite,
        pk_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        if psk.is_empty() || psk_id.is_empty() {
            return Err(CryptoError::InvalidArg("PSK and PSK ID must be non-empty"));
        }
        let (shared_secret, enc) = kem_encap(suite.kem, pk_r)?;
        let (key, base_nonce, exporter_secret) =
            key_schedule(&suite, MODE_PSK, &shared_secret, info, psk, psk_id)?;
        Ok((
            Self {
                key,
                base_nonce,
                exporter_secret,
                seq: 0,
                suite,
            },
            enc,
        ))
    }

    /// Set up an HPKE recipient context (PSK mode) with a given cipher suite.
    pub fn setup_recipient_psk_with_suite(
        suite: CipherSuite,
        sk_r: &[u8],
        enc: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, CryptoError> {
        if psk.is_empty() || psk_id.is_empty() {
            return Err(CryptoError::InvalidArg("PSK and PSK ID must be non-empty"));
        }
        let shared_secret = kem_decap(suite.kem, enc, sk_r)?;
        let (key, base_nonce, exporter_secret) =
            key_schedule(&suite, MODE_PSK, &shared_secret, info, psk, psk_id)?;
        Ok(Self {
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
            suite,
        })
    }

    /// Set up an HPKE sender context (Auth mode).
    pub fn setup_sender_auth(
        suite: CipherSuite,
        pk_r: &[u8],
        sk_s: &[u8],
        info: &[u8],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        let (shared_secret, enc) = kem_auth_encap(suite.kem, pk_r, sk_s)?;
        let (key, base_nonce, exporter_secret) =
            key_schedule(&suite, MODE_AUTH, &shared_secret, info, &[], &[])?;
        Ok((
            Self {
                key,
                base_nonce,
                exporter_secret,
                seq: 0,
                suite,
            },
            enc,
        ))
    }

    /// Set up an HPKE recipient context (Auth mode).
    pub fn setup_recipient_auth(
        suite: CipherSuite,
        sk_r: &[u8],
        enc: &[u8],
        pk_s: &[u8],
        info: &[u8],
    ) -> Result<Self, CryptoError> {
        let shared_secret = kem_auth_decap(suite.kem, enc, sk_r, pk_s)?;
        let (key, base_nonce, exporter_secret) =
            key_schedule(&suite, MODE_AUTH, &shared_secret, info, &[], &[])?;
        Ok(Self {
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
            suite,
        })
    }

    /// Set up an HPKE sender context (AuthPSK mode).
    pub fn setup_sender_auth_psk(
        suite: CipherSuite,
        pk_r: &[u8],
        sk_s: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        if psk.is_empty() || psk_id.is_empty() {
            return Err(CryptoError::InvalidArg("PSK and PSK ID must be non-empty"));
        }
        let (shared_secret, enc) = kem_auth_encap(suite.kem, pk_r, sk_s)?;
        let (key, base_nonce, exporter_secret) =
            key_schedule(&suite, MODE_AUTH_PSK, &shared_secret, info, psk, psk_id)?;
        Ok((
            Self {
                key,
                base_nonce,
                exporter_secret,
                seq: 0,
                suite,
            },
            enc,
        ))
    }

    /// Set up an HPKE recipient context (AuthPSK mode).
    pub fn setup_recipient_auth_psk(
        suite: CipherSuite,
        sk_r: &[u8],
        enc: &[u8],
        pk_s: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, CryptoError> {
        if psk.is_empty() || psk_id.is_empty() {
            return Err(CryptoError::InvalidArg("PSK and PSK ID must be non-empty"));
        }
        let shared_secret = kem_auth_decap(suite.kem, enc, sk_r, pk_s)?;
        let (key, base_nonce, exporter_secret) =
            key_schedule(&suite, MODE_AUTH_PSK, &shared_secret, info, psk, psk_id)?;
        Ok(Self {
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
            suite,
        })
    }

    /// Encrypt a plaintext with associated data (AEAD seal).
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.compute_nonce();
        let ct = self.suite.aead.seal(&self.key, &nonce, aad, plaintext)?;
        self.increment_seq()?;
        Ok(ct)
    }

    /// Decrypt a ciphertext with associated data (AEAD open).
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.compute_nonce();
        let pt = self.suite.aead.open(&self.key, &nonce, aad, ciphertext)?;
        self.increment_seq()?;
        Ok(pt)
    }

    /// Export a secret of `len` bytes from the HPKE context.
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, CryptoError> {
        let sid = hpke_suite_id(&self.suite);
        let factory = self.suite.kdf.hash_factory();
        let nh = self.suite.kdf.nh();
        labeled_expand(
            &sid,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            len,
            factory,
            nh,
        )
    }

    fn compute_nonce(&self) -> Vec<u8> {
        let nn = self.suite.aead.nn();
        if nn == 0 {
            return Vec::new();
        }
        let seq_bytes = self.seq.to_be_bytes();
        let mut nonce = self.base_nonce.clone();
        for i in 0..8.min(nn) {
            nonce[nn - 1 - i] ^= seq_bytes[7 - i];
        }
        nonce
    }

    fn increment_seq(&mut self) -> Result<(), CryptoError> {
        if self.seq == u64::MAX {
            return Err(CryptoError::InvalidArg("HPKE sequence overflow"));
        }
        self.seq += 1;
        Ok(())
    }
}

impl Drop for HpkeCtx {
    fn drop(&mut self) {
        self.key.zeroize();
        self.base_nonce.zeroize();
        self.exporter_secret.zeroize();
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::hex::{hex, to_hex};

    // ---- RFC 9180 Appendix A.1 ----
    // DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
    // mode = 0 (Base)

    const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    const IKM_E: &str = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234";
    const PK_EM: &str = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
    const IKM_R: &str = "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037";
    const PK_RM: &str = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d";
    const SK_RM: &str = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
    const ENC_A1: &str = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
    const SHARED_SECRET: &str = "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc";
    const KEY: &str = "4531685d41d65f03dc48f6b8302c05b0";
    const BASE_NONCE: &str = "56d890e5accaaf011cff4b7d";
    const EXPORTER_SECRET: &str =
        "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8";

    #[test]
    fn test_kem_derive_key_pair_x25519() {
        let (_, pk) = kem_derive_key_pair(HpkeKem::DhkemX25519HkdfSha256, &hex(IKM_E)).unwrap();
        assert_eq!(to_hex(&pk), PK_EM);

        let (_, pk_r) = kem_derive_key_pair(HpkeKem::DhkemX25519HkdfSha256, &hex(IKM_R)).unwrap();
        assert_eq!(to_hex(&pk_r), PK_RM);
    }

    #[test]
    fn test_kem_encap_decap_x25519() {
        let kem = HpkeKem::DhkemX25519HkdfSha256;
        let (shared_secret, enc) = kem_encap_deterministic(kem, &hex(PK_RM), &hex(IKM_E)).unwrap();
        assert_eq!(to_hex(&enc), ENC_A1);
        assert_eq!(to_hex(&shared_secret), SHARED_SECRET);

        let shared_secret_r = kem_decap(kem, &enc, &hex(SK_RM)).unwrap();
        assert_eq!(to_hex(&shared_secret_r), SHARED_SECRET);
    }

    #[test]
    fn test_key_schedule_a1() {
        let suite = DEFAULT_SUITE;
        let (key, base_nonce, exporter_secret) =
            key_schedule(&suite, MODE_BASE, &hex(SHARED_SECRET), &hex(INFO), &[], &[]).unwrap();
        assert_eq!(to_hex(&key), KEY);
        assert_eq!(to_hex(&base_nonce), BASE_NONCE);
        assert_eq!(to_hex(&exporter_secret), EXPORTER_SECRET);
    }

    #[test]
    fn test_seal_open_seq0() {
        let kem = HpkeKem::DhkemX25519HkdfSha256;
        let suite = DEFAULT_SUITE;
        let (shared_secret, enc) = kem_encap_deterministic(kem, &hex(PK_RM), &hex(IKM_E)).unwrap();
        let (key, base_nonce, exporter_secret) =
            key_schedule(&suite, MODE_BASE, &shared_secret, &hex(INFO), &[], &[]).unwrap();
        let mut ctx = HpkeCtx {
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
            suite,
        };

        let pt = hex("4265617574792069732074727574682c20747275746820626561757479");
        let aad = hex("436f756e742d30");
        let expected_ct = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a";

        let ct = ctx.seal(&aad, &pt).unwrap();
        assert_eq!(to_hex(&ct), expected_ct);

        let mut recipient =
            HpkeCtx::setup_recipient(&hex(SK_RM), &hex(ENC_A1), &hex(INFO)).unwrap();
        let decrypted = recipient.open(&aad, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_seal_open_seq1() {
        let kem = HpkeKem::DhkemX25519HkdfSha256;
        let suite = DEFAULT_SUITE;
        let (shared_secret, _) = kem_encap_deterministic(kem, &hex(PK_RM), &hex(IKM_E)).unwrap();
        let (key, base_nonce, exporter_secret) =
            key_schedule(&suite, MODE_BASE, &shared_secret, &hex(INFO), &[], &[]).unwrap();
        let mut ctx = HpkeCtx {
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
            suite,
        };

        let pt = hex("4265617574792069732074727574682c20747275746820626561757479");
        let aad0 = hex("436f756e742d30");
        let _ = ctx.seal(&aad0, &pt).unwrap();

        let aad1 = hex("436f756e742d31");
        let expected_ct1 = "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84";
        let ct1 = ctx.seal(&aad1, &pt).unwrap();
        assert_eq!(to_hex(&ct1), expected_ct1);
    }

    #[test]
    fn test_export() {
        let kem = HpkeKem::DhkemX25519HkdfSha256;
        let suite = DEFAULT_SUITE;
        let (shared_secret, _) = kem_encap_deterministic(kem, &hex(PK_RM), &hex(IKM_E)).unwrap();
        let (key, base_nonce, exporter_secret) =
            key_schedule(&suite, MODE_BASE, &shared_secret, &hex(INFO), &[], &[]).unwrap();
        let ctx = HpkeCtx {
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
            suite,
        };

        let exported = ctx.export(&[], 32).unwrap();
        assert_eq!(
            to_hex(&exported),
            "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee"
        );

        let exported = ctx.export(&hex("00"), 32).unwrap();
        assert_eq!(
            to_hex(&exported),
            "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5"
        );

        let exported = ctx.export(&hex("54657374436f6e74657874"), 32).unwrap();
        assert_eq!(
            to_hex(&exported),
            "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931"
        );
    }

    #[test]
    fn test_hpke_tampered_ciphertext_open() {
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        let (mut sender, enc) = HpkeCtx::setup_sender(pk_r.as_bytes(), b"info").unwrap();
        let mut recipient = HpkeCtx::setup_recipient(&sk_bytes, &enc, b"info").unwrap();

        let ct = sender.seal(b"aad", b"hello").unwrap();
        let mut tampered = ct.clone();
        tampered[0] ^= 0x01;
        assert!(recipient.open(b"aad", &tampered).is_err());
    }

    #[test]
    fn test_hpke_wrong_aad_open() {
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        let (mut sender, enc) = HpkeCtx::setup_sender(pk_r.as_bytes(), b"info").unwrap();
        let mut recipient = HpkeCtx::setup_recipient(&sk_bytes, &enc, b"info").unwrap();

        let ct = sender.seal(b"correct", b"payload").unwrap();
        assert!(recipient.open(b"wrong", &ct).is_err());
    }

    #[test]
    fn test_hpke_psk_mode_roundtrip() {
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        let psk = b"my-pre-shared-key";
        let psk_id = b"psk-identifier";

        let (mut sender, enc) =
            HpkeCtx::setup_sender_psk(pk_r.as_bytes(), b"info", psk, psk_id).unwrap();
        let mut recipient =
            HpkeCtx::setup_recipient_psk(&sk_bytes, &enc, b"info", psk, psk_id).unwrap();

        let ct = sender.seal(b"aad", b"psk message").unwrap();
        let pt = recipient.open(b"aad", &ct).unwrap();
        assert_eq!(pt, b"psk message");
    }

    #[test]
    fn test_hpke_psk_empty_psk_rejected() {
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        assert!(HpkeCtx::setup_sender_psk(pk_r.as_bytes(), b"info", &[], b"id").is_err());
        assert!(HpkeCtx::setup_sender_psk(pk_r.as_bytes(), b"info", b"psk", &[]).is_err());
        assert!(HpkeCtx::setup_recipient_psk(&sk_bytes, &[0u8; 32], b"info", &[], b"id").is_err());
        assert!(HpkeCtx::setup_recipient_psk(&sk_bytes, &[0u8; 32], b"info", b"psk", &[]).is_err());
    }

    #[test]
    fn test_roundtrip_random() {
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        let info = b"test info";
        let (mut sender, enc) = HpkeCtx::setup_sender(pk_r.as_bytes(), info).unwrap();
        let mut recipient = HpkeCtx::setup_recipient(&sk_bytes, &enc, info).unwrap();

        let ct = sender.seal(b"aad", b"hello, HPKE!").unwrap();
        let decrypted = recipient.open(b"aad", &ct).unwrap();
        assert_eq!(decrypted, b"hello, HPKE!");

        let ct2 = sender.seal(b"aad2", b"second message").unwrap();
        let decrypted2 = recipient.open(b"aad2", &ct2).unwrap();
        assert_eq!(decrypted2, b"second message");
    }

    // ===== New multi-suite tests =====

    #[test]
    fn test_aes256gcm_roundtrip() {
        let suite = CipherSuite {
            kem: HpkeKem::DhkemX25519HkdfSha256,
            kdf: HpkeKdf::HkdfSha256,
            aead: HpkeAead::Aes256Gcm,
        };
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        let (mut sender, enc) =
            HpkeCtx::setup_sender_with_suite(suite, pk_r.as_bytes(), b"info").unwrap();
        let mut recipient =
            HpkeCtx::setup_recipient_with_suite(suite, &sk_bytes, &enc, b"info").unwrap();

        let ct = sender.seal(b"aad", b"aes-256-gcm test").unwrap();
        let pt = recipient.open(b"aad", &ct).unwrap();
        assert_eq!(pt, b"aes-256-gcm test");
    }

    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let suite = CipherSuite {
            kem: HpkeKem::DhkemX25519HkdfSha256,
            kdf: HpkeKdf::HkdfSha256,
            aead: HpkeAead::ChaCha20Poly1305,
        };
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        let (mut sender, enc) =
            HpkeCtx::setup_sender_with_suite(suite, pk_r.as_bytes(), b"info").unwrap();
        let mut recipient =
            HpkeCtx::setup_recipient_with_suite(suite, &sk_bytes, &enc, b"info").unwrap();

        let ct = sender.seal(b"aad", b"chacha20 test").unwrap();
        let pt = recipient.open(b"aad", &ct).unwrap();
        assert_eq!(pt, b"chacha20 test");
    }

    #[test]
    fn test_export_only_seal_error() {
        let suite = CipherSuite {
            kem: HpkeKem::DhkemX25519HkdfSha256,
            kdf: HpkeKdf::HkdfSha256,
            aead: HpkeAead::ExportOnly,
        };
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        let (mut sender, enc) =
            HpkeCtx::setup_sender_with_suite(suite, pk_r.as_bytes(), b"info").unwrap();

        // seal should fail for ExportOnly
        assert!(sender.seal(b"aad", b"data").is_err());

        // export should work
        let recipient =
            HpkeCtx::setup_recipient_with_suite(suite, &sk_bytes, &enc, b"info").unwrap();
        let exported = recipient.export(b"ctx", 32).unwrap();
        assert_eq!(exported.len(), 32);
    }

    #[test]
    fn test_p256_base_mode_roundtrip() {
        let suite = CipherSuite {
            kem: HpkeKem::DhkemP256HkdfSha256,
            kdf: HpkeKdf::HkdfSha256,
            aead: HpkeAead::Aes128Gcm,
        };
        let kp = EcdhKeyPair::generate(EccCurveId::NistP256).unwrap();
        let pk_r = kp.public_key_bytes().unwrap();
        let sk_r = kp.private_key_bytes();

        let (mut sender, enc) = HpkeCtx::setup_sender_with_suite(suite, &pk_r, b"info").unwrap();
        let mut recipient =
            HpkeCtx::setup_recipient_with_suite(suite, &sk_r, &enc, b"info").unwrap();

        let ct = sender.seal(b"aad", b"P-256 test").unwrap();
        let pt = recipient.open(b"aad", &ct).unwrap();
        assert_eq!(pt, b"P-256 test");
    }

    #[test]
    fn test_p384_base_mode_roundtrip() {
        let suite = CipherSuite {
            kem: HpkeKem::DhkemP384HkdfSha384,
            kdf: HpkeKdf::HkdfSha384,
            aead: HpkeAead::Aes256Gcm,
        };
        let kp = EcdhKeyPair::generate(EccCurveId::NistP384).unwrap();
        let pk_r = kp.public_key_bytes().unwrap();
        let sk_r = kp.private_key_bytes();

        let (mut sender, enc) = HpkeCtx::setup_sender_with_suite(suite, &pk_r, b"info").unwrap();
        let mut recipient =
            HpkeCtx::setup_recipient_with_suite(suite, &sk_r, &enc, b"info").unwrap();

        let ct = sender.seal(b"aad", b"P-384 test").unwrap();
        let pt = recipient.open(b"aad", &ct).unwrap();
        assert_eq!(pt, b"P-384 test");
    }

    #[test]
    fn test_p521_base_mode_roundtrip() {
        let suite = CipherSuite {
            kem: HpkeKem::DhkemP521HkdfSha512,
            kdf: HpkeKdf::HkdfSha512,
            aead: HpkeAead::ChaCha20Poly1305,
        };
        let kp = EcdhKeyPair::generate(EccCurveId::NistP521).unwrap();
        let pk_r = kp.public_key_bytes().unwrap();
        let sk_r = kp.private_key_bytes();

        let (mut sender, enc) = HpkeCtx::setup_sender_with_suite(suite, &pk_r, b"info").unwrap();
        let mut recipient =
            HpkeCtx::setup_recipient_with_suite(suite, &sk_r, &enc, b"info").unwrap();

        let ct = sender.seal(b"aad", b"P-521 test").unwrap();
        let pt = recipient.open(b"aad", &ct).unwrap();
        assert_eq!(pt, b"P-521 test");
    }

    #[test]
    fn test_auth_mode_x25519_roundtrip() {
        let suite = DEFAULT_SUITE;

        // Generate sender and recipient keys
        let sk_s = X25519PrivateKey::generate().unwrap();
        let pk_s = sk_s.public_key();
        let sk_r = X25519PrivateKey::generate().unwrap();
        let pk_r = sk_r.public_key();

        let (mut sender, enc) =
            HpkeCtx::setup_sender_auth(suite, pk_r.as_bytes(), &sk_s.to_bytes(), b"auth info")
                .unwrap();

        let mut recipient = HpkeCtx::setup_recipient_auth(
            suite,
            &sk_r.to_bytes(),
            &enc,
            pk_s.as_bytes(),
            b"auth info",
        )
        .unwrap();

        let ct = sender.seal(b"aad", b"authenticated").unwrap();
        let pt = recipient.open(b"aad", &ct).unwrap();
        assert_eq!(pt, b"authenticated");
    }

    #[test]
    fn test_auth_wrong_sender_key() {
        let suite = DEFAULT_SUITE;

        let sk_s = X25519PrivateKey::generate().unwrap();
        let pk_s = sk_s.public_key();
        let sk_r = X25519PrivateKey::generate().unwrap();
        let pk_r = sk_r.public_key();

        let (mut sender, enc) =
            HpkeCtx::setup_sender_auth(suite, pk_r.as_bytes(), &sk_s.to_bytes(), b"info").unwrap();

        // Recipient uses wrong sender public key
        let wrong_sk = X25519PrivateKey::generate().unwrap();
        let wrong_pk = wrong_sk.public_key();

        let mut recipient = HpkeCtx::setup_recipient_auth(
            suite,
            &sk_r.to_bytes(),
            &enc,
            wrong_pk.as_bytes(),
            b"info",
        )
        .unwrap();

        let ct = sender.seal(b"aad", b"data").unwrap();
        // Should fail because wrong sender key → different shared secret
        assert!(recipient.open(b"aad", &ct).is_err());
    }

    #[test]
    fn test_auth_psk_roundtrip() {
        let suite = DEFAULT_SUITE;

        let sk_s = X25519PrivateKey::generate().unwrap();
        let pk_s = sk_s.public_key();
        let sk_r = X25519PrivateKey::generate().unwrap();
        let pk_r = sk_r.public_key();

        let psk = b"auth-psk-secret";
        let psk_id = b"auth-psk-id";

        let (mut sender, enc) = HpkeCtx::setup_sender_auth_psk(
            suite,
            pk_r.as_bytes(),
            &sk_s.to_bytes(),
            b"info",
            psk,
            psk_id,
        )
        .unwrap();

        let mut recipient = HpkeCtx::setup_recipient_auth_psk(
            suite,
            &sk_r.to_bytes(),
            &enc,
            pk_s.as_bytes(),
            b"info",
            psk,
            psk_id,
        )
        .unwrap();

        let ct = sender.seal(b"aad", b"auth+psk").unwrap();
        let pt = recipient.open(b"aad", &ct).unwrap();
        assert_eq!(pt, b"auth+psk");
    }

    #[test]
    fn test_p256_auth_mode_roundtrip() {
        let suite = CipherSuite {
            kem: HpkeKem::DhkemP256HkdfSha256,
            kdf: HpkeKdf::HkdfSha256,
            aead: HpkeAead::Aes128Gcm,
        };

        let kp_s = EcdhKeyPair::generate(EccCurveId::NistP256).unwrap();
        let pk_s = kp_s.public_key_bytes().unwrap();
        let sk_s = kp_s.private_key_bytes();

        let kp_r = EcdhKeyPair::generate(EccCurveId::NistP256).unwrap();
        let pk_r = kp_r.public_key_bytes().unwrap();
        let sk_r = kp_r.private_key_bytes();

        let (mut sender, enc) =
            HpkeCtx::setup_sender_auth(suite, &pk_r, &sk_s, b"p256 auth").unwrap();
        let mut recipient =
            HpkeCtx::setup_recipient_auth(suite, &sk_r, &enc, &pk_s, b"p256 auth").unwrap();

        let ct = sender.seal(b"aad", b"P-256 auth").unwrap();
        let pt = recipient.open(b"aad", &ct).unwrap();
        assert_eq!(pt, b"P-256 auth");
    }

    #[test]
    fn test_hkdf_sha384_labeled_expand() {
        let suite = CipherSuite {
            kem: HpkeKem::DhkemP384HkdfSha384,
            kdf: HpkeKdf::HkdfSha384,
            aead: HpkeAead::Aes256Gcm,
        };
        // Test that the labeled expand works with SHA-384
        let prk = vec![0xab; 48]; // dummy PRK of SHA-384 length
        let sid = hpke_suite_id(&suite);
        let factory = suite.kdf.hash_factory();
        let nh = suite.kdf.nh();
        let result = labeled_expand(&sid, &prk, b"test", b"info", 32, factory, nh).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hkdf_sha512_labeled_expand() {
        let suite = CipherSuite {
            kem: HpkeKem::DhkemP521HkdfSha512,
            kdf: HpkeKdf::HkdfSha512,
            aead: HpkeAead::Aes256Gcm,
        };
        let prk = vec![0xcd; 64]; // dummy PRK of SHA-512 length
        let sid = hpke_suite_id(&suite);
        let factory = suite.kdf.hash_factory();
        let nh = suite.kdf.nh();
        let result = labeled_expand(&sid, &prk, b"test", b"info", 48, factory, nh).unwrap();
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_p256_psk_roundtrip() {
        let suite = CipherSuite {
            kem: HpkeKem::DhkemP256HkdfSha256,
            kdf: HpkeKdf::HkdfSha256,
            aead: HpkeAead::Aes128Gcm,
        };
        let kp = EcdhKeyPair::generate(EccCurveId::NistP256).unwrap();
        let pk_r = kp.public_key_bytes().unwrap();
        let sk_r = kp.private_key_bytes();

        let (mut sender, enc) =
            HpkeCtx::setup_sender_psk_with_suite(suite, &pk_r, b"info", b"psk-secret", b"psk-id")
                .unwrap();
        let mut recipient = HpkeCtx::setup_recipient_psk_with_suite(
            suite,
            &sk_r,
            &enc,
            b"info",
            b"psk-secret",
            b"psk-id",
        )
        .unwrap();

        let ct = sender.seal(b"aad", b"P-256 PSK").unwrap();
        let pt = recipient.open(b"aad", &ct).unwrap();
        assert_eq!(pt, b"P-256 PSK");
    }

    #[test]
    fn test_multiple_seal_open() {
        let suite = CipherSuite {
            kem: HpkeKem::DhkemX25519HkdfSha256,
            kdf: HpkeKdf::HkdfSha256,
            aead: HpkeAead::ChaCha20Poly1305,
        };
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        let (mut sender, enc) =
            HpkeCtx::setup_sender_with_suite(suite, pk_r.as_bytes(), b"info").unwrap();
        let mut recipient =
            HpkeCtx::setup_recipient_with_suite(suite, &sk_bytes, &enc, b"info").unwrap();

        for i in 0..10 {
            let msg = format!("message {i}");
            let ct = sender.seal(b"aad", msg.as_bytes()).unwrap();
            let pt = recipient.open(b"aad", &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_export_only_export_works() {
        let suite = CipherSuite {
            kem: HpkeKem::DhkemX25519HkdfSha256,
            kdf: HpkeKdf::HkdfSha256,
            aead: HpkeAead::ExportOnly,
        };
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        let (sender, enc) =
            HpkeCtx::setup_sender_with_suite(suite, pk_r.as_bytes(), b"info").unwrap();
        let recipient =
            HpkeCtx::setup_recipient_with_suite(suite, &sk_bytes, &enc, b"info").unwrap();

        // Both sides should derive the same export secret
        let s_export = sender.export(b"ctx", 64).unwrap();
        let r_export = recipient.export(b"ctx", 64).unwrap();
        assert_eq!(s_export, r_export);
        assert_eq!(s_export.len(), 64);
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(5))]

            #[test]
            fn prop_hpke_base_mode_roundtrip(
                pt in proptest::collection::vec(any::<u8>(), 0..128),
                aad in proptest::collection::vec(any::<u8>(), 0..32),
            ) {
                let suite = DEFAULT_SUITE;
                let mut sk_bytes = [0u8; 32];
                getrandom::getrandom(&mut sk_bytes).unwrap();
                let sk = X25519PrivateKey::new(&sk_bytes).unwrap();
                let pk = sk.public_key();

                let (mut sender, enc) =
                    HpkeCtx::setup_sender_with_suite(suite, pk.as_bytes(), b"info")
                        .unwrap();
                let ct = sender.seal(&aad, &pt).unwrap();

                let mut recipient =
                    HpkeCtx::setup_recipient_with_suite(suite, &sk_bytes, &enc, b"info")
                        .unwrap();
                let decrypted = recipient.open(&aad, &ct).unwrap();
                prop_assert_eq!(pt, decrypted);
            }

            #[test]
            fn prop_hpke_psk_mode_roundtrip(
                pt in proptest::collection::vec(any::<u8>(), 0..64),
            ) {
                let suite = DEFAULT_SUITE;
                let mut sk_bytes = [0u8; 32];
                getrandom::getrandom(&mut sk_bytes).unwrap();
                let sk = X25519PrivateKey::new(&sk_bytes).unwrap();
                let pk = sk.public_key();

                let psk = b"shared secret psk";
                let psk_id = b"psk-id-001";

                let (mut sender, enc) =
                    HpkeCtx::setup_sender_psk_with_suite(
                        suite, pk.as_bytes(), b"info", psk, psk_id,
                    )
                    .unwrap();
                let ct = sender.seal(b"", &pt).unwrap();

                let mut recipient =
                    HpkeCtx::setup_recipient_psk_with_suite(
                        suite, &sk_bytes, &enc, b"info", psk, psk_id,
                    )
                    .unwrap();
                let decrypted = recipient.open(b"", &ct).unwrap();
                prop_assert_eq!(pt, decrypted);
            }
        }
    }
}
