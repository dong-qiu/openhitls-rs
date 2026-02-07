//! TLS 1.3 extension encoding/decoding for ClientHello/ServerHello.

use crate::crypt::{NamedGroup, SignatureScheme};
use crate::extensions::{Extension, ExtensionType};
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
}
