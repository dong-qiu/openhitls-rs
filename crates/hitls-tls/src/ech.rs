//! Encrypted Client Hello (ECH) — RFC 9578.
//!
//! ECH encrypts the inner ClientHello (containing the real SNI and extensions)
//! using HPKE, and sends it inside an outer ClientHello with a placeholder SNI.
//!
//! # Wire format
//!
//! ```text
//! ECHClientHello (in encrypted_client_hello extension):
//!   type(1) || cipher_suite(4) || config_id(1) || enc_len(2) || enc || payload_len(2) || payload
//!
//! ECHConfig:
//!   version(2) || length(2) || contents
//!   contents = config_id(1) || kem_id(2) || public_key_len(2) || public_key
//!            || cipher_suites_len(2) || cipher_suites || max_name_len(1)
//!            || public_name_len(1) || public_name || extensions_len(2) || extensions
//! ```

use hitls_crypto::hpke::{CipherSuite as HpkeCipherSuite, HpkeAead, HpkeCtx, HpkeKdf, HpkeKem};
use hitls_types::TlsError;

/// ECH extension type: Outer = 0 (from client), Inner = 1 (not used in wire).
const ECH_TYPE_OUTER: u8 = 0;

/// ECH config version (RFC 9578 §4).
pub const ECH_CONFIG_VERSION: u16 = 0xFE0D;

/// An HPKE cipher suite used within ECH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchCipherSuite {
    pub kdf_id: u16,
    pub aead_id: u16,
}

/// A parsed ECHConfig (RFC 9578 §4).
#[derive(Debug, Clone)]
pub struct EchConfig {
    /// Config identifier (1 byte).
    pub config_id: u8,
    /// HPKE KEM identifier.
    pub kem_id: u16,
    /// HPKE public key for the server.
    pub public_key: Vec<u8>,
    /// Supported HPKE cipher suites.
    pub cipher_suites: Vec<EchCipherSuite>,
    /// Maximum inner client hello name length.
    pub max_name_len: u8,
    /// Public name (used in the outer ClientHello SNI).
    pub public_name: Vec<u8>,
}

/// Parsed ECHClientHello payload from the encrypted_client_hello extension.
#[derive(Debug, Clone)]
pub struct EchClientHello {
    /// ECH type: 0 = outer.
    pub ech_type: u8,
    /// Selected cipher suite.
    pub cipher_suite: EchCipherSuite,
    /// Config ID.
    pub config_id: u8,
    /// HPKE encapsulated key.
    pub enc: Vec<u8>,
    /// Encrypted inner ClientHello payload.
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// ECHConfig parsing/encoding
// ---------------------------------------------------------------------------

/// Parse an ECHConfigList (one or more ECHConfig entries).
///
/// Wire format: `ECHConfig...` (concatenated, each self-delimiting via length).
pub fn parse_ech_config_list(data: &[u8]) -> Result<Vec<EchConfig>, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed(
            "ECH: config list too short".into(),
        ));
    }
    let total_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + total_len {
        return Err(TlsError::HandshakeFailed(
            "ECH: config list truncated".into(),
        ));
    }

    let mut configs = Vec::new();
    let mut offset = 2;
    let end = 2 + total_len;

    while offset < end {
        let (config, consumed) = parse_ech_config(&data[offset..end])?;
        configs.push(config);
        offset += consumed;
    }

    Ok(configs)
}

/// Parse a single ECHConfig.
///
/// Returns (config, bytes_consumed).
fn parse_ech_config(data: &[u8]) -> Result<(EchConfig, usize), TlsError> {
    if data.len() < 4 {
        return Err(TlsError::HandshakeFailed("ECH: config too short".into()));
    }

    let version = u16::from_be_bytes([data[0], data[1]]);
    let length = u16::from_be_bytes([data[2], data[3]]) as usize;

    if version != ECH_CONFIG_VERSION {
        // Skip unknown version
        if data.len() < 4 + length {
            return Err(TlsError::HandshakeFailed("ECH: config truncated".into()));
        }
        // Return a dummy config that will be skipped
        return Err(TlsError::HandshakeFailed(format!(
            "ECH: unsupported config version 0x{version:04X}"
        )));
    }

    if data.len() < 4 + length {
        return Err(TlsError::HandshakeFailed(
            "ECH: config body truncated".into(),
        ));
    }

    let body = &data[4..4 + length];
    let mut pos = 0;

    // config_id (1)
    if pos >= body.len() {
        return Err(TlsError::HandshakeFailed("ECH: missing config_id".into()));
    }
    let config_id = body[pos];
    pos += 1;

    // kem_id (2)
    if pos + 2 > body.len() {
        return Err(TlsError::HandshakeFailed("ECH: missing kem_id".into()));
    }
    let kem_id = u16::from_be_bytes([body[pos], body[pos + 1]]);
    pos += 2;

    // public_key (2 + N)
    if pos + 2 > body.len() {
        return Err(TlsError::HandshakeFailed(
            "ECH: missing public_key len".into(),
        ));
    }
    let pk_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + pk_len > body.len() {
        return Err(TlsError::HandshakeFailed(
            "ECH: public_key truncated".into(),
        ));
    }
    let public_key = body[pos..pos + pk_len].to_vec();
    pos += pk_len;

    // cipher_suites (2 + N*4)
    if pos + 2 > body.len() {
        return Err(TlsError::HandshakeFailed(
            "ECH: missing cipher_suites len".into(),
        ));
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if cs_len % 4 != 0 || pos + cs_len > body.len() {
        return Err(TlsError::HandshakeFailed(
            "ECH: invalid cipher_suites".into(),
        ));
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 4);
    for i in (0..cs_len).step_by(4) {
        let kdf_id = u16::from_be_bytes([body[pos + i], body[pos + i + 1]]);
        let aead_id = u16::from_be_bytes([body[pos + i + 2], body[pos + i + 3]]);
        cipher_suites.push(EchCipherSuite { kdf_id, aead_id });
    }
    pos += cs_len;

    // max_name_len (1)
    if pos >= body.len() {
        return Err(TlsError::HandshakeFailed(
            "ECH: missing max_name_len".into(),
        ));
    }
    let max_name_len = body[pos];
    pos += 1;

    // public_name (1 + N)
    if pos >= body.len() {
        return Err(TlsError::HandshakeFailed(
            "ECH: missing public_name len".into(),
        ));
    }
    let name_len = body[pos] as usize;
    pos += 1;
    if pos + name_len > body.len() {
        return Err(TlsError::HandshakeFailed(
            "ECH: public_name truncated".into(),
        ));
    }
    let public_name = body[pos..pos + name_len].to_vec();
    pos += name_len;

    // extensions (2 + N) — skip for now
    if pos + 2 <= body.len() {
        let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2 + ext_len;
    }
    let _ = pos; // mark as used

    Ok((
        EchConfig {
            config_id,
            kem_id,
            public_key,
            cipher_suites,
            max_name_len,
            public_name,
        },
        4 + length,
    ))
}

/// Encode an ECHConfig into wire format.
pub fn encode_ech_config(config: &EchConfig) -> Vec<u8> {
    let cs_len = config.cipher_suites.len() * 4;
    let body_len = 1  // config_id
        + 2  // kem_id
        + 2 + config.public_key.len()  // public_key
        + 2 + cs_len  // cipher_suites
        + 1  // max_name_len
        + 1 + config.public_name.len()  // public_name
        + 2; // extensions (empty)

    let mut buf = Vec::with_capacity(4 + body_len);
    buf.extend_from_slice(&ECH_CONFIG_VERSION.to_be_bytes());
    buf.extend_from_slice(&(body_len as u16).to_be_bytes());

    buf.push(config.config_id);
    buf.extend_from_slice(&config.kem_id.to_be_bytes());
    buf.extend_from_slice(&(config.public_key.len() as u16).to_be_bytes());
    buf.extend_from_slice(&config.public_key);

    buf.extend_from_slice(&(cs_len as u16).to_be_bytes());
    for cs in &config.cipher_suites {
        buf.extend_from_slice(&cs.kdf_id.to_be_bytes());
        buf.extend_from_slice(&cs.aead_id.to_be_bytes());
    }

    buf.push(config.max_name_len);
    buf.push(config.public_name.len() as u8);
    buf.extend_from_slice(&config.public_name);

    // Empty extensions
    buf.extend_from_slice(&0u16.to_be_bytes());

    buf
}

/// Encode an ECHConfigList (length-prefixed list of configs).
pub fn encode_ech_config_list(configs: &[EchConfig]) -> Vec<u8> {
    let mut inner = Vec::new();
    for config in configs {
        inner.extend_from_slice(&encode_ech_config(config));
    }
    let mut buf = Vec::with_capacity(2 + inner.len());
    buf.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    buf.extend_from_slice(&inner);
    buf
}

// ---------------------------------------------------------------------------
// ECHClientHello encoding/parsing
// ---------------------------------------------------------------------------

/// Encode the ECHClientHello payload for the encrypted_client_hello extension.
pub fn encode_ech_client_hello(ech: &EchClientHello) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 4 + 1 + 2 + ech.enc.len() + 2 + ech.payload.len());
    buf.push(ech.ech_type);
    buf.extend_from_slice(&ech.cipher_suite.kdf_id.to_be_bytes());
    buf.extend_from_slice(&ech.cipher_suite.aead_id.to_be_bytes());
    buf.push(ech.config_id);
    buf.extend_from_slice(&(ech.enc.len() as u16).to_be_bytes());
    buf.extend_from_slice(&ech.enc);
    buf.extend_from_slice(&(ech.payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(&ech.payload);
    buf
}

/// Parse an ECHClientHello payload from the encrypted_client_hello extension.
pub fn parse_ech_client_hello(data: &[u8]) -> Result<EchClientHello, TlsError> {
    if data.len() < 10 {
        return Err(TlsError::HandshakeFailed(
            "ECH: client hello payload too short".into(),
        ));
    }
    let ech_type = data[0];
    let kdf_id = u16::from_be_bytes([data[1], data[2]]);
    let aead_id = u16::from_be_bytes([data[3], data[4]]);
    let config_id = data[5];

    let enc_len = u16::from_be_bytes([data[6], data[7]]) as usize;
    if data.len() < 8 + enc_len + 2 {
        return Err(TlsError::HandshakeFailed("ECH: enc truncated".into()));
    }
    let enc = data[8..8 + enc_len].to_vec();

    let payload_offset = 8 + enc_len;
    let payload_len = u16::from_be_bytes([data[payload_offset], data[payload_offset + 1]]) as usize;
    if data.len() < payload_offset + 2 + payload_len {
        return Err(TlsError::HandshakeFailed("ECH: payload truncated".into()));
    }
    let payload = data[payload_offset + 2..payload_offset + 2 + payload_len].to_vec();

    Ok(EchClientHello {
        ech_type,
        cipher_suite: EchCipherSuite { kdf_id, aead_id },
        config_id,
        enc,
        payload,
    })
}

// ---------------------------------------------------------------------------
// HPKE integration: encrypt / decrypt inner ClientHello
// ---------------------------------------------------------------------------

/// Map ECH KEM/KDF/AEAD IDs to HPKE types.
fn resolve_kem(kem_id: u16) -> Result<HpkeKem, TlsError> {
    match kem_id {
        0x0010 => Ok(HpkeKem::DhkemP256HkdfSha256),
        0x0011 => Ok(HpkeKem::DhkemP384HkdfSha384),
        0x0012 => Ok(HpkeKem::DhkemP521HkdfSha512),
        0x0020 => Ok(HpkeKem::DhkemX25519HkdfSha256),
        _ => Err(TlsError::HandshakeFailed(format!(
            "ECH: unsupported KEM 0x{kem_id:04X}"
        ))),
    }
}

fn resolve_kdf(kdf_id: u16) -> Result<HpkeKdf, TlsError> {
    match kdf_id {
        0x0001 => Ok(HpkeKdf::HkdfSha256),
        0x0002 => Ok(HpkeKdf::HkdfSha384),
        0x0003 => Ok(HpkeKdf::HkdfSha512),
        _ => Err(TlsError::HandshakeFailed(format!(
            "ECH: unsupported KDF 0x{kdf_id:04X}"
        ))),
    }
}

fn resolve_aead(aead_id: u16) -> Result<HpkeAead, TlsError> {
    match aead_id {
        0x0001 => Ok(HpkeAead::Aes128Gcm),
        0x0002 => Ok(HpkeAead::Aes256Gcm),
        0x0003 => Ok(HpkeAead::ChaCha20Poly1305),
        _ => Err(TlsError::HandshakeFailed(format!(
            "ECH: unsupported AEAD 0x{aead_id:04X}"
        ))),
    }
}

/// Build the HPKE info string for ECH (RFC 9578 §6.1).
///
/// `info = "tls ech" || 0x00 || ECHConfig`
fn build_ech_info(config: &EchConfig) -> Vec<u8> {
    let encoded = encode_ech_config(config);
    let mut info = Vec::with_capacity(8 + encoded.len());
    info.extend_from_slice(b"tls ech\x00");
    info.extend_from_slice(&encoded);
    info
}

/// Build a GREASE ECH client hello extension payload (Phase I92).
///
/// Per draft-ietf-tls-esni §6.2, a client that does not have an `ECHConfig`
/// SHOULD send a GREASE ECH extension that is byte-indistinguishable from
/// a real ECH offer. This anti-fingerprinting deployment pattern (used
/// by Chrome / Firefox in production) prevents network observers from
/// distinguishing ECH-capable clients from ECH-non-capable ones, raising
/// the bar for traffic correlation attacks even before any real
/// `ECHConfig` is published.
///
/// # Wire format
///
/// The returned bytes are the **payload** of the
/// `encrypted_client_hello` extension (the caller wraps them in the
/// usual `extension_type(2) || extension_length(2) || data` envelope):
///
/// ```text
/// type=0 (outer) || cipher_suite(4) || config_id(1) || enc_len(2) ||
///   enc(=randomly-generated KEM-shape ephemeral pubkey) ||
///   payload_len(2) || payload(random bytes sized to look like an
///   AEAD-sealed inner ClientHello of `inner_payload_len` plaintext)
/// ```
///
/// `enc_len` and `payload_len` are RFC-realistic so a passive observer
/// cannot trivially distinguish GREASE from a real ECH offer:
///
/// - `enc_len = 32` (X25519 / DHKEM(X25519, HKDF-SHA256) public key
///   length, the dominant deployment).
/// - `payload_len = inner_payload_len + 16` (AES-128-GCM tag overhead).
///
/// All bytes after the first 5 (type + suite + config_id) are uniformly
/// random.
///
/// # Errors
///
/// Returns `TlsError::HandshakeFailed` only if `getrandom` itself fails.
pub fn build_grease_ech_payload(inner_payload_len: u16) -> Result<Vec<u8>, TlsError> {
    // Standard "looks like the dominant deployment" suite: HKDF-SHA256 +
    // AES-128-GCM. KEM is implicit (encoded into `enc_len`); we choose
    // X25519 (32-byte enc) so the byte budget matches Cloudflare /
    // Chrome production deployments.
    let kdf_id: u16 = 0x0001;
    let aead_id: u16 = 0x0001;
    let enc_len: u16 = 32; // X25519 KEM
    let aead_tag_len: u16 = 16; // AES-128-GCM tag
    let payload_len = inner_payload_len.saturating_add(aead_tag_len);

    let total = 1 + 2 + 2 + 1 + 2 + (enc_len as usize) + 2 + (payload_len as usize);
    let mut buf = Vec::with_capacity(total);
    buf.push(ECH_TYPE_OUTER);
    buf.extend_from_slice(&kdf_id.to_be_bytes());
    buf.extend_from_slice(&aead_id.to_be_bytes());

    // config_id, enc, payload: all random.
    let mut random_tail = vec![0u8; 1 + (enc_len as usize) + (payload_len as usize)];
    getrandom::getrandom(&mut random_tail)
        .map_err(|e| TlsError::HandshakeFailed(format!("ECH GREASE random: {e}")))?;
    let (config_id_byte, rest) = random_tail.split_at(1);
    let (enc_bytes, payload_bytes) = rest.split_at(enc_len as usize);

    buf.push(config_id_byte[0]);
    buf.extend_from_slice(&enc_len.to_be_bytes());
    buf.extend_from_slice(enc_bytes);
    buf.extend_from_slice(&payload_len.to_be_bytes());
    buf.extend_from_slice(payload_bytes);
    debug_assert_eq!(buf.len(), total);
    Ok(buf)
}

/// Encrypt the inner ClientHello using HPKE (client-side).
///
/// Returns an `EchClientHello` containing the encrypted payload and HPKE `enc`.
pub fn encrypt_inner_client_hello(
    config: &EchConfig,
    inner_ch: &[u8],
    outer_aad: &[u8],
) -> Result<EchClientHello, TlsError> {
    if config.cipher_suites.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "ECH: no cipher suites in config".into(),
        ));
    }

    let cs = &config.cipher_suites[0];
    let kem = resolve_kem(config.kem_id)?;
    let kdf = resolve_kdf(cs.kdf_id)?;
    let aead = resolve_aead(cs.aead_id)?;

    let hpke_suite = HpkeCipherSuite { kem, kdf, aead };
    let info = build_ech_info(config);

    let (mut ctx, enc) = HpkeCtx::setup_sender_with_suite(hpke_suite, &config.public_key, &info)
        .map_err(|e| TlsError::HandshakeFailed(format!("ECH HPKE setup: {e}")))?;

    let ciphertext = ctx
        .seal(outer_aad, inner_ch)
        .map_err(|e| TlsError::HandshakeFailed(format!("ECH HPKE seal: {e}")))?;

    Ok(EchClientHello {
        ech_type: ECH_TYPE_OUTER,
        cipher_suite: *cs,
        config_id: config.config_id,
        enc,
        payload: ciphertext,
    })
}

/// Decrypt the inner ClientHello using HPKE (server-side).
///
/// `sk_r` is the server's HPKE private key corresponding to the config's public key.
pub fn decrypt_inner_client_hello(
    config: &EchConfig,
    ech_hello: &EchClientHello,
    sk_r: &[u8],
    outer_aad: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let kem = resolve_kem(config.kem_id)?;
    let kdf = resolve_kdf(ech_hello.cipher_suite.kdf_id)?;
    let aead = resolve_aead(ech_hello.cipher_suite.aead_id)?;

    let hpke_suite = HpkeCipherSuite { kem, kdf, aead };
    let info = build_ech_info(config);

    let mut ctx = HpkeCtx::setup_recipient_with_suite(hpke_suite, sk_r, &ech_hello.enc, &info)
        .map_err(|e| TlsError::HandshakeFailed(format!("ECH HPKE setup: {e}")))?;

    ctx.open(outer_aad, &ech_hello.payload)
        .map_err(|e| TlsError::HandshakeFailed(format!("ECH HPKE open: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> EchConfig {
        EchConfig {
            config_id: 0x42,
            kem_id: 0x0020, // X25519
            public_key: vec![0xAA; 32],
            cipher_suites: vec![EchCipherSuite {
                kdf_id: 0x0001,  // HKDF-SHA256
                aead_id: 0x0001, // AES-128-GCM
            }],
            max_name_len: 64,
            public_name: b"public.example.com".to_vec(),
        }
    }

    #[test]
    fn test_ech_config_encode_parse_roundtrip() {
        let config = test_config();
        let config_list = encode_ech_config_list(std::slice::from_ref(&config));
        let parsed = parse_ech_config_list(&config_list).unwrap();
        assert_eq!(parsed.len(), 1);
        let c = &parsed[0];
        assert_eq!(c.config_id, 0x42);
        assert_eq!(c.kem_id, 0x0020);
        assert_eq!(c.public_key, vec![0xAA; 32]);
        assert_eq!(c.cipher_suites.len(), 1);
        assert_eq!(c.cipher_suites[0].kdf_id, 0x0001);
        assert_eq!(c.cipher_suites[0].aead_id, 0x0001);
        assert_eq!(c.max_name_len, 64);
        assert_eq!(c.public_name, b"public.example.com");
    }

    #[test]
    fn test_ech_config_multiple() {
        let config1 = test_config();
        let mut config2 = test_config();
        config2.config_id = 0x43;
        config2.public_name = b"alt.example.com".to_vec();

        let config_list = encode_ech_config_list(&[config1, config2]);
        let parsed = parse_ech_config_list(&config_list).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].config_id, 0x42);
        assert_eq!(parsed[1].config_id, 0x43);
        assert_eq!(parsed[1].public_name, b"alt.example.com");
    }

    #[test]
    fn test_ech_client_hello_encode_parse_roundtrip() {
        let ech = EchClientHello {
            ech_type: ECH_TYPE_OUTER,
            cipher_suite: EchCipherSuite {
                kdf_id: 0x0001,
                aead_id: 0x0001,
            },
            config_id: 0x42,
            enc: vec![0xBB; 32],
            payload: vec![0xCC; 100],
        };
        let encoded = encode_ech_client_hello(&ech);
        let parsed = parse_ech_client_hello(&encoded).unwrap();
        assert_eq!(parsed.ech_type, ECH_TYPE_OUTER);
        assert_eq!(parsed.cipher_suite.kdf_id, 0x0001);
        assert_eq!(parsed.cipher_suite.aead_id, 0x0001);
        assert_eq!(parsed.config_id, 0x42);
        assert_eq!(parsed.enc, vec![0xBB; 32]);
        assert_eq!(parsed.payload, vec![0xCC; 100]);
    }

    #[test]
    fn test_ech_client_hello_parse_too_short() {
        assert!(parse_ech_client_hello(&[0; 5]).is_err());
    }

    #[test]
    fn test_ech_config_parse_too_short() {
        assert!(parse_ech_config_list(&[0]).is_err());
        assert!(parse_ech_config_list(&[0, 10]).is_err()); // claims 10 bytes but only 2
    }

    #[test]
    fn test_resolve_kem_kdf_aead() {
        assert_eq!(resolve_kem(0x0020).unwrap(), HpkeKem::DhkemX25519HkdfSha256);
        assert_eq!(resolve_kem(0x0010).unwrap(), HpkeKem::DhkemP256HkdfSha256);
        assert!(resolve_kem(0x9999).is_err());

        assert_eq!(resolve_kdf(0x0001).unwrap(), HpkeKdf::HkdfSha256);
        assert!(resolve_kdf(0x9999).is_err());

        assert_eq!(resolve_aead(0x0001).unwrap(), HpkeAead::Aes128Gcm);
        assert_eq!(resolve_aead(0x0003).unwrap(), HpkeAead::ChaCha20Poly1305);
        assert!(resolve_aead(0x9999).is_err());
    }

    #[test]
    fn test_ech_encrypt_decrypt_roundtrip() {
        use hitls_crypto::x25519::X25519PrivateKey;

        // Generate X25519 key pair for the server
        let sk = X25519PrivateKey::generate().unwrap();
        let pk = sk.public_key();

        let config = EchConfig {
            config_id: 0x01,
            kem_id: 0x0020, // X25519
            public_key: pk.as_bytes().to_vec(),
            cipher_suites: vec![EchCipherSuite {
                kdf_id: 0x0001,  // HKDF-SHA256
                aead_id: 0x0001, // AES-128-GCM
            }],
            max_name_len: 64,
            public_name: b"public.example.com".to_vec(),
        };

        let inner_ch = b"inner ClientHello with real SNI: secret.example.com";
        let outer_aad = b"outer ClientHello AAD";

        // Client encrypts
        let ech_hello = encrypt_inner_client_hello(&config, inner_ch, outer_aad).unwrap();
        assert_eq!(ech_hello.ech_type, ECH_TYPE_OUTER);
        assert_eq!(ech_hello.config_id, 0x01);
        assert!(!ech_hello.enc.is_empty());
        assert!(!ech_hello.payload.is_empty());

        // Server decrypts
        let decrypted =
            decrypt_inner_client_hello(&config, &ech_hello, &sk.to_bytes(), outer_aad).unwrap();
        assert_eq!(decrypted, inner_ch);
    }

    #[test]
    fn test_ech_decrypt_wrong_key_fails() {
        use hitls_crypto::x25519::X25519PrivateKey;

        let sk = X25519PrivateKey::generate().unwrap();
        let pk = sk.public_key();

        let config = EchConfig {
            config_id: 0x02,
            kem_id: 0x0020,
            public_key: pk.as_bytes().to_vec(),
            cipher_suites: vec![EchCipherSuite {
                kdf_id: 0x0001,
                aead_id: 0x0001,
            }],
            max_name_len: 64,
            public_name: b"public.example.com".to_vec(),
        };

        let ech_hello = encrypt_inner_client_hello(&config, b"secret data", b"aad").unwrap();

        // Decrypt with wrong key
        let wrong_sk = X25519PrivateKey::generate().unwrap();
        assert!(
            decrypt_inner_client_hello(&config, &ech_hello, &wrong_sk.to_bytes(), b"aad").is_err()
        );
    }

    #[test]
    fn test_ech_decrypt_wrong_aad_fails() {
        use hitls_crypto::x25519::X25519PrivateKey;

        let sk = X25519PrivateKey::generate().unwrap();
        let pk = sk.public_key();

        let config = EchConfig {
            config_id: 0x03,
            kem_id: 0x0020,
            public_key: pk.as_bytes().to_vec(),
            cipher_suites: vec![EchCipherSuite {
                kdf_id: 0x0001,
                aead_id: 0x0001,
            }],
            max_name_len: 64,
            public_name: b"test.example.com".to_vec(),
        };

        let ech_hello =
            encrypt_inner_client_hello(&config, b"inner hello", b"correct aad").unwrap();

        // Decrypt with wrong AAD
        assert!(
            decrypt_inner_client_hello(&config, &ech_hello, &sk.to_bytes(), b"wrong aad").is_err()
        );
    }

    #[test]
    fn test_ech_encrypt_no_cipher_suites_fails() {
        let config = EchConfig {
            config_id: 0x04,
            kem_id: 0x0020,
            public_key: vec![0; 32],
            cipher_suites: vec![], // empty
            max_name_len: 64,
            public_name: b"test.example.com".to_vec(),
        };

        assert!(encrypt_inner_client_hello(&config, b"data", b"aad").is_err());
    }

    #[test]
    fn test_ech_config_encode_deterministic() {
        let config = test_config();
        let encoded1 = encode_ech_config(&config);
        let encoded2 = encode_ech_config(&config);
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_ech_config_multiple_cipher_suites() {
        let config = EchConfig {
            config_id: 0x05,
            kem_id: 0x0020,
            public_key: vec![0xAA; 32],
            cipher_suites: vec![
                EchCipherSuite {
                    kdf_id: 0x0001,
                    aead_id: 0x0001,
                },
                EchCipherSuite {
                    kdf_id: 0x0001,
                    aead_id: 0x0003, // ChaCha20-Poly1305
                },
            ],
            max_name_len: 128,
            public_name: b"multi.example.com".to_vec(),
        };

        let config_list = encode_ech_config_list(&[config]);
        let parsed = parse_ech_config_list(&config_list).unwrap();
        assert_eq!(parsed[0].cipher_suites.len(), 2);
        assert_eq!(parsed[0].cipher_suites[1].aead_id, 0x0003);
    }

    #[test]
    fn test_ech_wire_format_roundtrip() {
        use hitls_crypto::x25519::X25519PrivateKey;

        let sk = X25519PrivateKey::generate().unwrap();
        let pk = sk.public_key();

        let config = EchConfig {
            config_id: 0x10,
            kem_id: 0x0020,
            public_key: pk.as_bytes().to_vec(),
            cipher_suites: vec![EchCipherSuite {
                kdf_id: 0x0001,
                aead_id: 0x0001,
            }],
            max_name_len: 64,
            public_name: b"ech.example.com".to_vec(),
        };

        // Encrypt
        let inner = b"full roundtrip test";
        let aad = b"outer ch aad";
        let ech_hello = encrypt_inner_client_hello(&config, inner, aad).unwrap();

        // Encode → parse → decode → decrypt
        let wire = encode_ech_client_hello(&ech_hello);
        let parsed = parse_ech_client_hello(&wire).unwrap();
        let decrypted = decrypt_inner_client_hello(&config, &parsed, &sk.to_bytes(), aad).unwrap();
        assert_eq!(decrypted, inner);
    }

    // ================================================================
    // Phase I92 — ECH GREASE anti-fingerprinting tests
    // ================================================================

    /// GREASE ECH payload must parse as a valid `EchClientHello` so a
    /// network observer cannot trivially distinguish it from a real
    /// offer at the wire-shape level.
    #[test]
    fn test_grease_ech_parses_as_client_hello() {
        let payload = build_grease_ech_payload(200).unwrap();
        let parsed = parse_ech_client_hello(&payload).expect("must parse as ECH client hello");
        assert_eq!(parsed.ech_type, ECH_TYPE_OUTER, "GREASE = outer type");
        assert_eq!(parsed.cipher_suite.kdf_id, 0x0001, "HKDF-SHA256");
        assert_eq!(parsed.cipher_suite.aead_id, 0x0001, "AES-128-GCM");
        assert_eq!(
            parsed.enc.len(),
            32,
            "X25519 KEM enc len = 32 (matches Cloudflare/Chrome deployment)"
        );
        assert_eq!(
            parsed.payload.len(),
            200 + 16,
            "payload = inner + AES-128-GCM tag overhead"
        );
    }

    /// Two consecutive GREASE payloads must be byte-different in the
    /// random tail (config_id, enc, payload). The static prefix is
    /// constant by design.
    #[test]
    fn test_grease_ech_random_tail_varies_between_calls() {
        let a = build_grease_ech_payload(100).unwrap();
        let b = build_grease_ech_payload(100).unwrap();
        // Same length is fine; the static prefix bytes 0..5 (type + suite)
        // are deliberately constant so an active observer cannot
        // distinguish *that* from real ECH either.
        assert_eq!(a.len(), b.len(), "same inner_len → same total len");
        assert_eq!(&a[..5], &b[..5], "static prefix invariant");
        // Random tail must vary across calls (probability of collision
        // is negligible; each call draws ~250 bytes from getrandom).
        assert_ne!(&a[5..], &b[5..], "GREASE random tail must differ");
    }

    /// Edge cases on `inner_payload_len`.
    #[test]
    fn test_grease_ech_boundary_inner_lengths() {
        // Zero inner length: payload is just the AEAD tag.
        let p0 = build_grease_ech_payload(0).unwrap();
        let parsed0 = parse_ech_client_hello(&p0).unwrap();
        assert_eq!(parsed0.payload.len(), 16);

        // Max u16 inner length: must not panic, must produce a parseable
        // payload (memory permitting).
        let pmax = build_grease_ech_payload(u16::MAX - 16).unwrap();
        let parsed_max = parse_ech_client_hello(&pmax).unwrap();
        assert_eq!(parsed_max.payload.len(), u16::MAX as usize);

        // Saturating add: u16::MAX + anything still fits in u16.
        let psat = build_grease_ech_payload(u16::MAX).unwrap();
        let parsed_sat = parse_ech_client_hello(&psat).unwrap();
        assert_eq!(parsed_sat.payload.len(), u16::MAX as usize);
    }
}
