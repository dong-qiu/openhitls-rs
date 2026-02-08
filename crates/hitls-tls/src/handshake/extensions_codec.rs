//! TLS 1.3 extension encoding/decoding for ClientHello/ServerHello.

use crate::crypt::{NamedGroup, SignatureScheme};
use crate::extensions::{Extension, ExtensionType};
use crate::handshake::codec::CertCompressionAlgorithm;
use hitls_types::TlsError;

// ---------------------------------------------------------------------------
// Build extensions for ClientHello
// ---------------------------------------------------------------------------

/// Build the `supported_versions` extension for ClientHello.
/// Contains a single entry: TLS 1.3 (0x0304).
pub fn build_supported_versions_ch() -> Extension {
    // Format: list_length(1) || version(2)
    let data = vec![0x02, 0x03, 0x04];
    Extension {
        extension_type: ExtensionType::SUPPORTED_VERSIONS,
        data,
    }
}

/// Build the `supported_groups` extension.
pub fn build_supported_groups(groups: &[NamedGroup]) -> Extension {
    let mut data = Vec::with_capacity(2 + groups.len() * 2);
    let list_len = (groups.len() * 2) as u16;
    data.extend_from_slice(&list_len.to_be_bytes());
    for g in groups {
        data.extend_from_slice(&g.0.to_be_bytes());
    }
    Extension {
        extension_type: ExtensionType::SUPPORTED_GROUPS,
        data,
    }
}

/// Build the `signature_algorithms` extension.
pub fn build_signature_algorithms(schemes: &[SignatureScheme]) -> Extension {
    let mut data = Vec::with_capacity(2 + schemes.len() * 2);
    let list_len = (schemes.len() * 2) as u16;
    data.extend_from_slice(&list_len.to_be_bytes());
    for s in schemes {
        data.extend_from_slice(&s.0.to_be_bytes());
    }
    Extension {
        extension_type: ExtensionType::SIGNATURE_ALGORITHMS,
        data,
    }
}

/// Build a `key_share` extension for ClientHello with a single key share entry.
pub fn build_key_share_ch(group: NamedGroup, public_key: &[u8]) -> Extension {
    // Format: client_shares_length(2) || group(2) || key_exchange_length(2) || key_exchange
    let entry_len = 2 + 2 + public_key.len();
    let mut data = Vec::with_capacity(2 + entry_len);
    data.extend_from_slice(&(entry_len as u16).to_be_bytes());
    data.extend_from_slice(&group.0.to_be_bytes());
    data.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    data.extend_from_slice(public_key);
    Extension {
        extension_type: ExtensionType::KEY_SHARE,
        data,
    }
}

/// Build a `server_name` (SNI) extension.
pub fn build_server_name(hostname: &str) -> Extension {
    // Format: server_name_list_length(2) || name_type(1)=0 || host_name_length(2) || hostname
    let name_bytes = hostname.as_bytes();
    let entry_len = 1 + 2 + name_bytes.len(); // name_type + length + name
    let list_len = entry_len;
    let mut data = Vec::with_capacity(2 + list_len);
    data.extend_from_slice(&(list_len as u16).to_be_bytes());
    data.push(0); // host_name type
    data.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    data.extend_from_slice(name_bytes);
    Extension {
        extension_type: ExtensionType::SERVER_NAME,
        data,
    }
}

// ---------------------------------------------------------------------------
// Build extensions for ServerHello
// ---------------------------------------------------------------------------

/// Build the `supported_versions` extension for ServerHello.
/// Contains exactly: TLS 1.3 (0x0304), no list prefix.
pub fn build_supported_versions_sh() -> Extension {
    Extension {
        extension_type: ExtensionType::SUPPORTED_VERSIONS,
        data: vec![0x03, 0x04],
    }
}

/// Build a `key_share` extension for ServerHello (single entry, no list prefix).
/// Format: group(2) || key_exchange_length(2) || key_exchange
pub fn build_key_share_sh(group: NamedGroup, public_key: &[u8]) -> Extension {
    let mut data = Vec::with_capacity(4 + public_key.len());
    data.extend_from_slice(&group.0.to_be_bytes());
    data.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    data.extend_from_slice(public_key);
    Extension {
        extension_type: ExtensionType::KEY_SHARE,
        data,
    }
}

/// Build a `key_share` extension for HelloRetryRequest (selected group only, no key data).
/// Format: group(2) — just the selected NamedGroup.
pub fn build_key_share_hrr(group: NamedGroup) -> Extension {
    Extension {
        extension_type: ExtensionType::KEY_SHARE,
        data: group.0.to_be_bytes().to_vec(),
    }
}

/// Build a `cookie` extension (RFC 8446 §4.2.2).
/// Format: cookie_length(2) || cookie
pub fn build_cookie(cookie: &[u8]) -> Extension {
    let mut data = Vec::with_capacity(2 + cookie.len());
    data.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
    data.extend_from_slice(cookie);
    Extension {
        extension_type: ExtensionType::COOKIE,
        data,
    }
}

/// Parse a `cookie` extension from data.
/// Format: cookie_length(2) || cookie
pub fn parse_cookie(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed("cookie: too short".into()));
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + len {
        return Err(TlsError::HandshakeFailed("cookie: truncated".into()));
    }
    Ok(data[2..2 + len].to_vec())
}

/// Parse the `key_share` extension from HelloRetryRequest.
/// Format: selected_group(2) — just the group ID, no key data.
pub fn parse_key_share_hrr(data: &[u8]) -> Result<NamedGroup, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed("key_share HRR: too short".into()));
    }
    Ok(NamedGroup(u16::from_be_bytes([data[0], data[1]])))
}

// ---------------------------------------------------------------------------
// PSK extensions
// ---------------------------------------------------------------------------

/// Build the `psk_key_exchange_modes` extension (RFC 8446 §4.2.9).
/// Advertises psk_dhe_ke (1) mode only.
pub fn build_psk_key_exchange_modes() -> Extension {
    // Format: list_length(1) || mode(1)
    Extension {
        extension_type: ExtensionType::PSK_KEY_EXCHANGE_MODES,
        data: vec![0x01, 0x01], // length=1, psk_dhe_ke=1
    }
}

/// Parse `psk_key_exchange_modes` extension.
/// Returns the list of PSK modes.
pub fn parse_psk_key_exchange_modes(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    if data.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "psk_key_exchange_modes: empty".into(),
        ));
    }
    let list_len = data[0] as usize;
    if data.len() < 1 + list_len {
        return Err(TlsError::HandshakeFailed(
            "psk_key_exchange_modes: truncated".into(),
        ));
    }
    Ok(data[1..1 + list_len].to_vec())
}

/// Build the `pre_shared_key` extension for ClientHello (RFC 8446 §4.2.11).
///
/// `identities`: list of (identity, obfuscated_ticket_age).
/// `binders`: list of binder values (HMAC hashes).
///
/// **This extension MUST be the last extension in the ClientHello.**
pub fn build_pre_shared_key_ch(identities: &[(Vec<u8>, u32)], binders: &[Vec<u8>]) -> Extension {
    let mut data = Vec::new();

    // Identities list
    let mut id_buf = Vec::new();
    for (identity, age) in identities {
        id_buf.extend_from_slice(&(identity.len() as u16).to_be_bytes());
        id_buf.extend_from_slice(identity);
        id_buf.extend_from_slice(&age.to_be_bytes());
    }
    data.extend_from_slice(&(id_buf.len() as u16).to_be_bytes());
    data.extend_from_slice(&id_buf);

    // Binders list
    let mut binder_buf = Vec::new();
    for binder in binders {
        binder_buf.push(binder.len() as u8);
        binder_buf.extend_from_slice(binder);
    }
    data.extend_from_slice(&(binder_buf.len() as u16).to_be_bytes());
    data.extend_from_slice(&binder_buf);

    Extension {
        extension_type: ExtensionType::PRE_SHARED_KEY,
        data,
    }
}

/// PSK identity: (ticket bytes, obfuscated ticket age).
pub type PskIdentity = (Vec<u8>, u32);

/// Parse the `pre_shared_key` extension from ClientHello.
/// Returns (identities, binders) where identities = [(identity, age)].
pub fn parse_pre_shared_key_ch(data: &[u8]) -> Result<(Vec<PskIdentity>, Vec<Vec<u8>>), TlsError> {
    let err = |msg: &str| TlsError::HandshakeFailed(format!("pre_shared_key CH: {msg}"));
    let mut pos = 0;

    // Identities
    if data.len() < 2 {
        return Err(err("too short for identities length"));
    }
    let id_list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if data.len() < pos + id_list_len {
        return Err(err("truncated identities"));
    }
    let id_end = pos + id_list_len;
    let mut identities = Vec::new();
    while pos < id_end {
        if id_end - pos < 2 {
            return Err(err("truncated identity length"));
        }
        let id_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if id_end - pos < id_len + 4 {
            return Err(err("truncated identity"));
        }
        let identity = data[pos..pos + id_len].to_vec();
        pos += id_len;
        let age = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        identities.push((identity, age));
    }

    // Binders
    if data.len() < pos + 2 {
        return Err(err("too short for binders length"));
    }
    let binder_list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if data.len() < pos + binder_list_len {
        return Err(err("truncated binders"));
    }
    let binder_end = pos + binder_list_len;
    let mut binders = Vec::new();
    while pos < binder_end {
        if binder_end - pos < 1 {
            return Err(err("truncated binder length"));
        }
        let binder_len = data[pos] as usize;
        pos += 1;
        if binder_end - pos < binder_len {
            return Err(err("truncated binder"));
        }
        binders.push(data[pos..pos + binder_len].to_vec());
        pos += binder_len;
    }

    Ok((identities, binders))
}

/// Build the `pre_shared_key` extension for ServerHello (RFC 8446 §4.2.11).
/// Contains the selected identity index (2 bytes).
pub fn build_pre_shared_key_sh(selected_identity: u16) -> Extension {
    Extension {
        extension_type: ExtensionType::PRE_SHARED_KEY,
        data: selected_identity.to_be_bytes().to_vec(),
    }
}

/// Parse the `pre_shared_key` extension from ServerHello.
/// Returns the selected identity index.
pub fn parse_pre_shared_key_sh(data: &[u8]) -> Result<u16, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed(
            "pre_shared_key SH: too short".into(),
        ));
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

// ---------------------------------------------------------------------------
// Parse extensions from ClientHello
// ---------------------------------------------------------------------------

/// Parse `supported_versions` from ClientHello.
/// Format: list_length(1) || version(2)*
pub fn parse_supported_versions_ch(data: &[u8]) -> Result<Vec<u16>, TlsError> {
    if data.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "supported_versions CH: empty".into(),
        ));
    }
    let list_len = data[0] as usize;
    if data.len() < 1 + list_len || list_len % 2 != 0 {
        return Err(TlsError::HandshakeFailed(
            "supported_versions CH: invalid length".into(),
        ));
    }
    let mut versions = Vec::with_capacity(list_len / 2);
    for i in (0..list_len).step_by(2) {
        versions.push(u16::from_be_bytes([data[1 + i], data[1 + i + 1]]));
    }
    Ok(versions)
}

/// Parse `supported_groups` from ClientHello.
/// Format: list_length(2) || group(2)*
pub fn parse_supported_groups_ch(data: &[u8]) -> Result<Vec<NamedGroup>, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed(
            "supported_groups CH: too short".into(),
        ));
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len || list_len % 2 != 0 {
        return Err(TlsError::HandshakeFailed(
            "supported_groups CH: invalid length".into(),
        ));
    }
    let mut groups = Vec::with_capacity(list_len / 2);
    for i in (0..list_len).step_by(2) {
        groups.push(NamedGroup(u16::from_be_bytes([
            data[2 + i],
            data[2 + i + 1],
        ])));
    }
    Ok(groups)
}

/// Parse `signature_algorithms` from ClientHello.
/// Format: list_length(2) || scheme(2)*
pub fn parse_signature_algorithms_ch(data: &[u8]) -> Result<Vec<SignatureScheme>, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed(
            "signature_algorithms CH: too short".into(),
        ));
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len || list_len % 2 != 0 {
        return Err(TlsError::HandshakeFailed(
            "signature_algorithms CH: invalid length".into(),
        ));
    }
    let mut schemes = Vec::with_capacity(list_len / 2);
    for i in (0..list_len).step_by(2) {
        schemes.push(SignatureScheme(u16::from_be_bytes([
            data[2 + i],
            data[2 + i + 1],
        ])));
    }
    Ok(schemes)
}

/// Parse `key_share` from ClientHello.
/// Format: client_shares_length(2) || [group(2) || key_len(2) || key_exchange]*
pub fn parse_key_share_ch(data: &[u8]) -> Result<Vec<(NamedGroup, Vec<u8>)>, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed("key_share CH: too short".into()));
    }
    let shares_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + shares_len {
        return Err(TlsError::HandshakeFailed("key_share CH: truncated".into()));
    }

    let mut entries = Vec::new();
    let mut pos = 2;
    let end = 2 + shares_len;
    while pos + 4 <= end {
        let group = NamedGroup(u16::from_be_bytes([data[pos], data[pos + 1]]));
        let key_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + key_len > end {
            return Err(TlsError::HandshakeFailed(
                "key_share CH: entry truncated".into(),
            ));
        }
        entries.push((group, data[pos..pos + key_len].to_vec()));
        pos += key_len;
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Parse extensions from ServerHello
// ---------------------------------------------------------------------------

/// Parse the `supported_versions` extension from ServerHello.
/// Returns the selected version (e.g., 0x0304 for TLS 1.3).
pub fn parse_supported_versions_sh(data: &[u8]) -> Result<u16, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed(
            "supported_versions SH too short".into(),
        ));
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

/// Parse the `key_share` extension from ServerHello.
/// Returns (NamedGroup, public_key_bytes).
pub fn parse_key_share_sh(data: &[u8]) -> Result<(NamedGroup, Vec<u8>), TlsError> {
    // Format: group(2) || key_exchange_length(2) || key_exchange
    if data.len() < 4 {
        return Err(TlsError::HandshakeFailed("key_share SH too short".into()));
    }
    let group = NamedGroup(u16::from_be_bytes([data[0], data[1]]));
    let key_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + key_len {
        return Err(TlsError::HandshakeFailed(
            "key_share SH key truncated".into(),
        ));
    }
    Ok((group, data[4..4 + key_len].to_vec()))
}

/// Parse a generic extension list (with 2-byte length prefix).
pub fn parse_extensions(data: &[u8]) -> Result<Vec<Extension>, TlsError> {
    if data.len() < 2 {
        return Ok(vec![]);
    }
    let ext_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + ext_len {
        return Err(TlsError::HandshakeFailed(
            "extensions data truncated".into(),
        ));
    }
    parse_extensions_raw(&data[2..2 + ext_len])
}

/// Parse extensions from raw bytes (no length prefix).
fn parse_extensions_raw(data: &[u8]) -> Result<Vec<Extension>, TlsError> {
    let mut exts = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let ext_type = ExtensionType(u16::from_be_bytes([data[pos], data[pos + 1]]));
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if data.len() < pos + ext_len {
            return Err(TlsError::HandshakeFailed("extension data truncated".into()));
        }
        exts.push(Extension {
            extension_type: ext_type,
            data: data[pos..pos + ext_len].to_vec(),
        });
        pos += ext_len;
    }
    Ok(exts)
}

// ---------------------------------------------------------------------------
// Early Data (0-RTT) extensions
// ---------------------------------------------------------------------------

/// Build `early_data` extension for ClientHello (empty, just indicates intent).
pub fn build_early_data_ch() -> Extension {
    Extension {
        extension_type: ExtensionType::EARLY_DATA,
        data: vec![],
    }
}

/// Build `early_data` extension for EncryptedExtensions (empty, indicates server acceptance).
pub fn build_early_data_ee() -> Extension {
    Extension {
        extension_type: ExtensionType::EARLY_DATA,
        data: vec![],
    }
}

/// Build `early_data` extension for NewSessionTicket (4-byte max_early_data_size).
pub fn build_early_data_nst(max_size: u32) -> Extension {
    Extension {
        extension_type: ExtensionType::EARLY_DATA,
        data: max_size.to_be_bytes().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Post-Handshake Auth extension
// ---------------------------------------------------------------------------

/// Build post_handshake_auth extension (empty, for ClientHello).
/// Indicates client willingness to respond to post-handshake CertificateRequest.
pub fn build_post_handshake_auth() -> Extension {
    Extension {
        extension_type: ExtensionType::POST_HANDSHAKE_AUTH,
        data: vec![],
    }
}

/// Build compress_certificate extension for ClientHello (RFC 8879).
/// Format: algorithms_len(1) || [algorithm(2)]*
pub fn build_compress_certificate(algos: &[CertCompressionAlgorithm]) -> Extension {
    let list_len = (algos.len() * 2) as u8;
    let mut data = Vec::with_capacity(1 + algos.len() * 2);
    data.push(list_len);
    for algo in algos {
        data.extend_from_slice(&algo.0.to_be_bytes());
    }
    Extension {
        extension_type: ExtensionType::COMPRESS_CERTIFICATE,
        data,
    }
}

/// Parse compress_certificate extension from ClientHello.
pub fn parse_compress_certificate(data: &[u8]) -> Result<Vec<CertCompressionAlgorithm>, TlsError> {
    if data.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "compress_certificate: empty".into(),
        ));
    }
    let list_len = data[0] as usize;
    if list_len % 2 != 0 || data.len() < 1 + list_len {
        return Err(TlsError::HandshakeFailed(
            "compress_certificate: invalid length".into(),
        ));
    }
    let mut algos = Vec::new();
    let mut pos = 1;
    while pos < 1 + list_len {
        let algo = u16::from_be_bytes([data[pos], data[pos + 1]]);
        algos.push(CertCompressionAlgorithm(algo));
        pos += 2;
    }
    Ok(algos)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_supported_versions() {
        let ext = build_supported_versions_ch();
        assert_eq!(ext.extension_type, ExtensionType::SUPPORTED_VERSIONS);
        // list_length(1)=2, version=0x0304
        assert_eq!(ext.data, vec![0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_build_parse_key_share() {
        let pub_key = vec![0x42; 32];
        let ext = build_key_share_ch(NamedGroup::X25519, &pub_key);
        assert_eq!(ext.extension_type, ExtensionType::KEY_SHARE);

        // The outer data has: client_shares_len(2) || group(2) || key_len(2) || key(32)
        assert_eq!(ext.data.len(), 2 + 2 + 2 + 32);

        // Parse back the inner entry (skip the client_shares_len prefix)
        let (group, key) = parse_key_share_sh(&ext.data[2..]).unwrap();
        assert_eq!(group, NamedGroup::X25519);
        assert_eq!(key, pub_key);
    }

    #[test]
    fn test_build_server_name() {
        let ext = build_server_name("example.com");
        assert_eq!(ext.extension_type, ExtensionType::SERVER_NAME);

        // list_len(2) || name_type(1)=0 || name_len(2) || "example.com"
        let name = b"example.com";
        let expected_len = 2 + 1 + 2 + name.len();
        assert_eq!(ext.data.len(), expected_len);

        // Check name_type = 0
        assert_eq!(ext.data[2], 0x00);
        // Check name
        let name_start = 5;
        assert_eq!(&ext.data[name_start..], name);
    }

    #[test]
    fn test_build_supported_groups() {
        let ext = build_supported_groups(&[NamedGroup::X25519, NamedGroup::SECP256R1]);
        assert_eq!(ext.extension_type, ExtensionType::SUPPORTED_GROUPS);
        // list_len(2)=4, X25519=0x001d, SECP256R1=0x0017
        assert_eq!(ext.data, vec![0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
    }

    #[test]
    fn test_build_signature_algorithms() {
        let ext = build_signature_algorithms(&[
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
        ]);
        assert_eq!(ext.extension_type, ExtensionType::SIGNATURE_ALGORITHMS);
        assert_eq!(ext.data, vec![0x00, 0x04, 0x08, 0x04, 0x04, 0x03]);
    }

    #[test]
    fn test_parse_supported_versions_sh() {
        let data = vec![0x03, 0x04];
        let version = parse_supported_versions_sh(&data).unwrap();
        assert_eq!(version, 0x0304);
    }

    #[test]
    fn test_build_supported_versions_sh() {
        let ext = build_supported_versions_sh();
        assert_eq!(ext.extension_type, ExtensionType::SUPPORTED_VERSIONS);
        // ServerHello: no list prefix, just the version
        assert_eq!(ext.data, vec![0x03, 0x04]);
    }

    #[test]
    fn test_build_parse_key_share_sh_roundtrip() {
        let pub_key = vec![0x55; 32];
        let ext = build_key_share_sh(NamedGroup::X25519, &pub_key);
        assert_eq!(ext.extension_type, ExtensionType::KEY_SHARE);
        // ServerHello key_share has no list prefix: group(2)||key_len(2)||key(32)
        assert_eq!(ext.data.len(), 4 + 32);
        let (group, key) = parse_key_share_sh(&ext.data).unwrap();
        assert_eq!(group, NamedGroup::X25519);
        assert_eq!(key, pub_key);
    }

    #[test]
    fn test_parse_key_share_ch() {
        // Build a CH key_share with two entries
        let key1 = vec![0xAA; 32];
        let key2 = vec![0xBB; 32];
        let mut data = Vec::new();
        // entry1: X25519(0x001d) + 32 bytes
        // entry2: SECP256R1(0x0017) + 32 bytes
        let entry_size = 2 + 2 + 32;
        let shares_len = (entry_size * 2) as u16;
        data.extend_from_slice(&shares_len.to_be_bytes());
        // Entry 1
        data.extend_from_slice(&0x001du16.to_be_bytes());
        data.extend_from_slice(&32u16.to_be_bytes());
        data.extend_from_slice(&key1);
        // Entry 2
        data.extend_from_slice(&0x0017u16.to_be_bytes());
        data.extend_from_slice(&32u16.to_be_bytes());
        data.extend_from_slice(&key2);

        let entries = parse_key_share_ch(&data).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, NamedGroup::X25519);
        assert_eq!(entries[0].1, key1);
        assert_eq!(entries[1].0, NamedGroup::SECP256R1);
        assert_eq!(entries[1].1, key2);
    }

    #[test]
    fn test_parse_supported_versions_ch() {
        // list_length(1)=4, versions: 0x0304, 0x0303
        let data = vec![0x04, 0x03, 0x04, 0x03, 0x03];
        let versions = parse_supported_versions_ch(&data).unwrap();
        assert_eq!(versions, vec![0x0304, 0x0303]);
    }

    #[test]
    fn test_parse_key_share_sh() {
        // group=X25519(0x001d), key_len=32, key=0x42*32
        let mut data = Vec::new();
        data.extend_from_slice(&0x001du16.to_be_bytes());
        data.extend_from_slice(&32u16.to_be_bytes());
        data.extend_from_slice(&[0x42; 32]);

        let (group, key) = parse_key_share_sh(&data).unwrap();
        assert_eq!(group, NamedGroup::X25519);
        assert_eq!(key, vec![0x42; 32]);
    }

    #[test]
    fn test_build_parse_key_share_hrr() {
        let ext = build_key_share_hrr(NamedGroup::SECP256R1);
        assert_eq!(ext.extension_type, ExtensionType::KEY_SHARE);
        // HRR key_share: just group(2), no key data
        assert_eq!(ext.data.len(), 2);
        let group = parse_key_share_hrr(&ext.data).unwrap();
        assert_eq!(group, NamedGroup::SECP256R1);
    }

    #[test]
    fn test_build_parse_cookie() {
        let cookie = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
        let ext = build_cookie(&cookie);
        assert_eq!(ext.extension_type, ExtensionType::COOKIE);
        let parsed = parse_cookie(&ext.data).unwrap();
        assert_eq!(parsed, cookie);

        // Empty cookie
        let ext2 = build_cookie(&[]);
        let parsed2 = parse_cookie(&ext2.data).unwrap();
        assert!(parsed2.is_empty());

        // Truncated data
        assert!(parse_cookie(&[0x00]).is_err());
    }

    #[test]
    fn test_build_parse_psk_key_exchange_modes() {
        let ext = build_psk_key_exchange_modes();
        assert_eq!(ext.extension_type, ExtensionType::PSK_KEY_EXCHANGE_MODES);
        let modes = parse_psk_key_exchange_modes(&ext.data).unwrap();
        assert_eq!(modes, vec![0x01]); // psk_dhe_ke
    }

    #[test]
    fn test_build_parse_pre_shared_key_ch() {
        let identities = vec![(vec![0xAA; 32], 12345u32)];
        let binders = vec![vec![0xBB; 32]];
        let ext = build_pre_shared_key_ch(&identities, &binders);
        assert_eq!(ext.extension_type, ExtensionType::PRE_SHARED_KEY);

        let (parsed_ids, parsed_binders) = parse_pre_shared_key_ch(&ext.data).unwrap();
        assert_eq!(parsed_ids.len(), 1);
        assert_eq!(parsed_ids[0].0, vec![0xAA; 32]);
        assert_eq!(parsed_ids[0].1, 12345);
        assert_eq!(parsed_binders.len(), 1);
        assert_eq!(parsed_binders[0], vec![0xBB; 32]);
    }

    #[test]
    fn test_build_parse_pre_shared_key_sh() {
        let ext = build_pre_shared_key_sh(0);
        assert_eq!(ext.extension_type, ExtensionType::PRE_SHARED_KEY);
        let idx = parse_pre_shared_key_sh(&ext.data).unwrap();
        assert_eq!(idx, 0);

        let ext2 = build_pre_shared_key_sh(3);
        let idx2 = parse_pre_shared_key_sh(&ext2.data).unwrap();
        assert_eq!(idx2, 3);
    }

    #[test]
    fn test_build_parse_compress_certificate() {
        let algos = vec![
            CertCompressionAlgorithm::ZLIB,
            CertCompressionAlgorithm::BROTLI,
        ];
        let ext = build_compress_certificate(&algos);
        assert_eq!(ext.extension_type, ExtensionType::COMPRESS_CERTIFICATE);

        let parsed = parse_compress_certificate(&ext.data).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], CertCompressionAlgorithm::ZLIB);
        assert_eq!(parsed[1], CertCompressionAlgorithm::BROTLI);
    }

    #[test]
    fn test_build_parse_compress_certificate_single() {
        let algos = vec![CertCompressionAlgorithm::ZLIB];
        let ext = build_compress_certificate(&algos);
        let parsed = parse_compress_certificate(&ext.data).unwrap();
        assert_eq!(parsed, vec![CertCompressionAlgorithm::ZLIB]);
    }
}
