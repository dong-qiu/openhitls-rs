//! TLS 1.3 extension encoding/decoding for ClientHello/ServerHello.

use crate::config::MaxFragmentLength;
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
// ALPN extension (RFC 7301)
// ---------------------------------------------------------------------------

/// Build the `application_layer_protocol_negotiation` extension for ClientHello.
/// Format: protocol_name_list_length(2) || (protocol_name_length(1) || protocol_name)*
pub fn build_alpn(protocols: &[Vec<u8>]) -> Extension {
    let mut list = Vec::new();
    for proto in protocols {
        list.push(proto.len() as u8);
        list.extend_from_slice(proto);
    }
    let mut data = Vec::with_capacity(2 + list.len());
    data.extend_from_slice(&(list.len() as u16).to_be_bytes());
    data.extend_from_slice(&list);
    Extension {
        extension_type: ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        data,
    }
}

/// Parse ALPN extension from ClientHello (returns list of protocol names).
pub fn parse_alpn_ch(data: &[u8]) -> Result<Vec<Vec<u8>>, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed("ALPN CH: too short".into()));
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return Err(TlsError::HandshakeFailed("ALPN CH: truncated".into()));
    }
    let mut protos = Vec::new();
    let mut pos = 2;
    let end = 2 + list_len;
    while pos < end {
        let proto_len = data[pos] as usize;
        pos += 1;
        if pos + proto_len > end {
            return Err(TlsError::HandshakeFailed(
                "ALPN CH: protocol truncated".into(),
            ));
        }
        protos.push(data[pos..pos + proto_len].to_vec());
        pos += proto_len;
    }
    Ok(protos)
}

/// Build ALPN extension for ServerHello (single selected protocol).
pub fn build_alpn_selected(protocol: &[u8]) -> Extension {
    let mut data = Vec::with_capacity(2 + 1 + protocol.len());
    let list_len = (1 + protocol.len()) as u16;
    data.extend_from_slice(&list_len.to_be_bytes());
    data.push(protocol.len() as u8);
    data.extend_from_slice(protocol);
    Extension {
        extension_type: ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        data,
    }
}

/// Parse ALPN extension from ServerHello (returns single selected protocol).
pub fn parse_alpn_sh(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed("ALPN SH: too short".into()));
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len || list_len < 2 {
        return Err(TlsError::HandshakeFailed("ALPN SH: truncated".into()));
    }
    let proto_len = data[2] as usize;
    if 1 + proto_len != list_len {
        return Err(TlsError::HandshakeFailed(
            "ALPN SH: unexpected list size".into(),
        ));
    }
    Ok(data[3..3 + proto_len].to_vec())
}

// ---------------------------------------------------------------------------
// SNI parsing
// ---------------------------------------------------------------------------

/// Parse `server_name` extension from ClientHello.
/// Format: server_name_list_length(2) || name_type(1) || host_name_length(2) || host_name
pub fn parse_server_name(data: &[u8]) -> Result<String, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed("SNI: too short".into()));
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len || list_len < 3 {
        return Err(TlsError::HandshakeFailed("SNI: truncated".into()));
    }
    let name_type = data[2];
    if name_type != 0 {
        return Err(TlsError::HandshakeFailed(format!(
            "SNI: unsupported name type {name_type}"
        )));
    }
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + name_len {
        return Err(TlsError::HandshakeFailed("SNI: name truncated".into()));
    }
    String::from_utf8(data[5..5 + name_len].to_vec())
        .map_err(|_| TlsError::HandshakeFailed("SNI: invalid UTF-8".into()))
}

// ---------------------------------------------------------------------------
// TLS 1.2 extensions
// ---------------------------------------------------------------------------

/// Build the `ec_point_formats` extension (RFC 4492 §5.1.2).
/// Advertises uncompressed (0) point format only.
pub fn build_ec_point_formats() -> Extension {
    // Format: ec_point_formats_length(1) || uncompressed(1)
    Extension {
        extension_type: ExtensionType::EC_POINT_FORMATS,
        data: vec![0x01, 0x00], // length=1, uncompressed=0
    }
}

/// Parse `ec_point_formats` extension.
/// Returns the list of supported EC point format codes.
pub fn parse_ec_point_formats(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    if data.is_empty() {
        return Err(TlsError::HandshakeFailed("ec_point_formats: empty".into()));
    }
    let list_len = data[0] as usize;
    if data.len() < 1 + list_len {
        return Err(TlsError::HandshakeFailed(
            "ec_point_formats: truncated".into(),
        ));
    }
    Ok(data[1..1 + list_len].to_vec())
}

/// Build the `renegotiation_info` extension (RFC 5746) for initial handshake.
/// Contains an empty renegotiated_connection field.
pub fn build_renegotiation_info_initial() -> Extension {
    // Format: renegotiated_connection_length(1) = 0
    Extension {
        extension_type: ExtensionType::RENEGOTIATION_INFO,
        data: vec![0x00], // empty renegotiated_connection
    }
}

/// Parse `renegotiation_info` extension.
/// Returns the renegotiated_connection bytes.
pub fn parse_renegotiation_info(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    if data.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "renegotiation_info: empty".into(),
        ));
    }
    let len = data[0] as usize;
    if data.len() < 1 + len {
        return Err(TlsError::HandshakeFailed(
            "renegotiation_info: truncated".into(),
        ));
    }
    Ok(data[1..1 + len].to_vec())
}

// ---------------------------------------------------------------------------
// Extended Master Secret extension (RFC 7627)
// ---------------------------------------------------------------------------

/// Build the `extended_master_secret` extension (RFC 7627).
/// Empty extension — presence signals EMS support.
pub fn build_extended_master_secret() -> Extension {
    Extension {
        extension_type: ExtensionType::EXTENDED_MASTER_SECRET,
        data: vec![],
    }
}

/// Parse `extended_master_secret` extension (must be empty).
pub fn parse_extended_master_secret(data: &[u8]) -> Result<(), TlsError> {
    if !data.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "extended_master_secret: expected empty".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Encrypt-Then-MAC extension (RFC 7366)
// ---------------------------------------------------------------------------

/// Build the `encrypt_then_mac` extension (RFC 7366).
/// Empty extension — presence signals ETM support.
pub fn build_encrypt_then_mac() -> Extension {
    Extension {
        extension_type: ExtensionType::ENCRYPT_THEN_MAC,
        data: vec![],
    }
}

/// Parse `encrypt_then_mac` extension (must be empty).
pub fn parse_encrypt_then_mac(data: &[u8]) -> Result<(), TlsError> {
    if !data.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "encrypt_then_mac: expected empty".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Renegotiation info with verify_data (RFC 5746)
// ---------------------------------------------------------------------------

/// Build the `renegotiation_info` extension with verify_data for renegotiation.
/// Format: renegotiated_connection_length(1) || client_verify_data || server_verify_data
pub fn build_renegotiation_info(client_verify_data: &[u8], server_verify_data: &[u8]) -> Extension {
    let total_len = client_verify_data.len() + server_verify_data.len();
    let mut data = Vec::with_capacity(1 + total_len);
    data.push(total_len as u8);
    data.extend_from_slice(client_verify_data);
    data.extend_from_slice(server_verify_data);
    Extension {
        extension_type: ExtensionType::RENEGOTIATION_INFO,
        data,
    }
}

// ---------------------------------------------------------------------------
// Session Ticket extension (RFC 5077)
// ---------------------------------------------------------------------------

/// Build SessionTicket extension for ClientHello.
/// Empty data = "I support tickets", non-empty = ticket for resumption.
pub fn build_session_ticket_ch(ticket: &[u8]) -> Extension {
    Extension {
        extension_type: ExtensionType::SESSION_TICKET,
        data: ticket.to_vec(),
    }
}

/// Parse SessionTicket extension from ClientHello.
/// Returns the ticket bytes (empty = new session, non-empty = resumption attempt).
pub fn parse_session_ticket_ch(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    Ok(data.to_vec())
}

/// Build empty SessionTicket extension for ServerHello (signals ticket support).
pub fn build_session_ticket_sh() -> Extension {
    Extension {
        extension_type: ExtensionType::SESSION_TICKET,
        data: vec![],
    }
}

/// Parse SessionTicket extension from ServerHello (expect empty).
pub fn parse_session_ticket_sh(data: &[u8]) -> Result<(), TlsError> {
    if !data.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "session_ticket SH: expected empty".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Record Size Limit (RFC 8449)
// ---------------------------------------------------------------------------

/// Build `record_size_limit` extension (RFC 8449).
/// Wire format: 2-byte uint16 value representing the maximum record size
/// the sender is willing to receive.
pub fn build_record_size_limit(limit: u16) -> Extension {
    Extension {
        extension_type: ExtensionType::RECORD_SIZE_LIMIT,
        data: limit.to_be_bytes().to_vec(),
    }
}

/// Parse `record_size_limit` extension. Returns the uint16 value.
/// Valid range: 64..=16384 (TLS 1.2) or 64..=16385 (TLS 1.3).
pub fn parse_record_size_limit(data: &[u8]) -> Result<u16, TlsError> {
    if data.len() != 2 {
        return Err(TlsError::HandshakeFailed(
            "record_size_limit: expected 2 bytes".into(),
        ));
    }
    let limit = u16::from_be_bytes([data[0], data[1]]);
    if limit < 64 {
        return Err(TlsError::HandshakeFailed(
            "record_size_limit: value must be >= 64".into(),
        ));
    }
    Ok(limit)
}

// ---------------------------------------------------------------------------
// OCSP Stapling (RFC 6066 Section 8)
// ---------------------------------------------------------------------------

/// Build `status_request` extension for ClientHello (RFC 6066 §8).
/// Requests OCSP stapling: type=ocsp(1), empty responder_id_list, empty extensions.
pub fn build_status_request_ch() -> Extension {
    // status_type(1) = ocsp(1), responder_id_list_len(2) = 0, request_extensions_len(2) = 0
    Extension {
        extension_type: ExtensionType::STATUS_REQUEST,
        data: vec![0x01, 0x00, 0x00, 0x00, 0x00],
    }
}

/// Parse `status_request` extension from ClientHello.
/// Returns true if the client requests OCSP stapling (type == ocsp(1)).
pub fn parse_status_request_ch(data: &[u8]) -> Result<bool, TlsError> {
    if data.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "status_request: empty data".into(),
        ));
    }
    Ok(data[0] == 1) // type = ocsp
}

/// Build `status_request` extension for TLS 1.3 Certificate entry.
/// Contains the raw DER-encoded OCSP response wrapped in CertificateStatus format.
pub fn build_status_request_cert_entry(ocsp_response_der: &[u8]) -> Extension {
    // CertificateStatus: status_type(1)=ocsp(1) + OCSPResponse length(3) + OCSPResponse
    let len = ocsp_response_der.len();
    let mut data = Vec::with_capacity(4 + len);
    data.push(0x01); // status_type = ocsp
    data.push((len >> 16) as u8);
    data.push((len >> 8) as u8);
    data.push(len as u8);
    data.extend_from_slice(ocsp_response_der);
    Extension {
        extension_type: ExtensionType::STATUS_REQUEST,
        data,
    }
}

/// Parse `status_request` extension from TLS 1.3 Certificate entry.
/// Returns the raw DER-encoded OCSP response.
pub fn parse_status_request_cert_entry(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    if data.len() < 4 {
        return Err(TlsError::HandshakeFailed(
            "status_request cert entry: too short".into(),
        ));
    }
    if data[0] != 0x01 {
        return Err(TlsError::HandshakeFailed(
            "status_request cert entry: expected ocsp type".into(),
        ));
    }
    let len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);
    if data.len() < 4 + len {
        return Err(TlsError::HandshakeFailed(
            "status_request cert entry: truncated OCSP response".into(),
        ));
    }
    Ok(data[4..4 + len].to_vec())
}

// ---------------------------------------------------------------------------
// Signed Certificate Timestamp (RFC 6962)
// ---------------------------------------------------------------------------

/// Build `signed_certificate_timestamp` extension for ClientHello (empty, signals support).
pub fn build_sct_ch() -> Extension {
    Extension {
        extension_type: ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP,
        data: vec![],
    }
}

/// Build `signed_certificate_timestamp` extension for TLS 1.3 Certificate entry.
/// Contains the raw SCT list bytes (opaque SignedCertificateTimestampList).
pub fn build_sct_cert_entry(sct_list: &[u8]) -> Extension {
    Extension {
        extension_type: ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP,
        data: sct_list.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Max Fragment Length (RFC 6066 §4)
// ---------------------------------------------------------------------------

/// Build `max_fragment_length` extension (RFC 6066).
/// Wire format: 1-byte enum value (1=512, 2=1024, 3=2048, 4=4096).
pub fn build_max_fragment_length(mfl: MaxFragmentLength) -> Extension {
    Extension {
        extension_type: ExtensionType::MAX_FRAGMENT_LENGTH,
        data: vec![mfl as u8],
    }
}

/// Parse `max_fragment_length` extension. Returns the `MaxFragmentLength` value.
pub fn parse_max_fragment_length(data: &[u8]) -> Result<MaxFragmentLength, TlsError> {
    if data.len() != 1 {
        return Err(TlsError::HandshakeFailed(
            "max_fragment_length: expected 1 byte".into(),
        ));
    }
    MaxFragmentLength::from_u8(data[0]).ok_or_else(|| {
        TlsError::HandshakeFailed(format!("max_fragment_length: invalid value {}", data[0]))
    })
}

// ---------------------------------------------------------------------------
// Signature Algorithms Cert (RFC 8446 §4.2.3)
// ---------------------------------------------------------------------------

/// Build `signature_algorithms_cert` extension (RFC 8446 §4.2.3).
/// Wire format is identical to `signature_algorithms` but with type 50.
pub fn build_signature_algorithms_cert(schemes: &[SignatureScheme]) -> Extension {
    let mut data = Vec::with_capacity(2 + schemes.len() * 2);
    let list_len = (schemes.len() * 2) as u16;
    data.extend_from_slice(&list_len.to_be_bytes());
    for s in schemes {
        data.extend_from_slice(&s.0.to_be_bytes());
    }
    Extension {
        extension_type: ExtensionType::SIGNATURE_ALGORITHMS_CERT,
        data,
    }
}

/// Parse `signature_algorithms_cert` extension.
/// Reuses the same wire format as `signature_algorithms`.
pub fn parse_signature_algorithms_cert(data: &[u8]) -> Result<Vec<SignatureScheme>, TlsError> {
    parse_signature_algorithms_ch(data)
}

// ---------------------------------------------------------------------------
// Certificate Authorities (RFC 8446 §4.2.4)
// ---------------------------------------------------------------------------

/// Build `certificate_authorities` extension (RFC 8446 §4.2.4, type 47).
/// Wire format: ca_list_length(2) || [dn_length(2) || distinguished_name(DER)]*
pub fn build_certificate_authorities(ca_list: &[Vec<u8>]) -> Extension {
    let mut list = Vec::new();
    for dn in ca_list {
        list.extend_from_slice(&(dn.len() as u16).to_be_bytes());
        list.extend_from_slice(dn);
    }
    let mut data = Vec::with_capacity(2 + list.len());
    data.extend_from_slice(&(list.len() as u16).to_be_bytes());
    data.extend_from_slice(&list);
    Extension {
        extension_type: ExtensionType::CERTIFICATE_AUTHORITIES,
        data,
    }
}

/// Parse `certificate_authorities` extension (RFC 8446 §4.2.4).
/// Returns list of DER-encoded Distinguished Names.
pub fn parse_certificate_authorities(data: &[u8]) -> Result<Vec<Vec<u8>>, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed(
            "certificate_authorities: too short".into(),
        ));
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return Err(TlsError::HandshakeFailed(
            "certificate_authorities: truncated".into(),
        ));
    }
    let mut dns = Vec::new();
    let mut pos = 2;
    let end = 2 + list_len;
    while pos < end {
        if end - pos < 2 {
            return Err(TlsError::HandshakeFailed(
                "certificate_authorities: truncated DN length".into(),
            ));
        }
        let dn_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if end - pos < dn_len {
            return Err(TlsError::HandshakeFailed(
                "certificate_authorities: truncated DN".into(),
            ));
        }
        dns.push(data[pos..pos + dn_len].to_vec());
        pos += dn_len;
    }
    Ok(dns)
}

// ---------------------------------------------------------------------------
// PADDING Extension (RFC 7685, type 21)
// ---------------------------------------------------------------------------

/// Build `padding` extension (RFC 7685, type 21).
/// Wire format: N zero bytes.
pub fn build_padding(padding_len: usize) -> Extension {
    Extension {
        extension_type: ExtensionType::PADDING,
        data: vec![0u8; padding_len],
    }
}

/// Parse `padding` extension.
/// Validates all bytes are zero per RFC 7685.
pub fn parse_padding(data: &[u8]) -> Result<usize, TlsError> {
    for &b in data {
        if b != 0 {
            return Err(TlsError::HandshakeFailed("padding: non-zero byte".into()));
        }
    }
    Ok(data.len())
}

// ---------------------------------------------------------------------------
// OID Filters Extension (RFC 8446 §4.2.5, type 48)
// ---------------------------------------------------------------------------

/// Build `oid_filters` extension (RFC 8446 §4.2.5, type 48).
/// Wire format: filters_length(2) || [oid_length(1) || oid || values_length(2) || values]*
pub fn build_oid_filters(filters: &[(Vec<u8>, Vec<u8>)]) -> Extension {
    let mut list = Vec::new();
    for (oid, values) in filters {
        list.push(oid.len() as u8);
        list.extend_from_slice(oid);
        list.extend_from_slice(&(values.len() as u16).to_be_bytes());
        list.extend_from_slice(values);
    }
    let mut data = Vec::with_capacity(2 + list.len());
    data.extend_from_slice(&(list.len() as u16).to_be_bytes());
    data.extend_from_slice(&list);
    Extension {
        extension_type: ExtensionType::OID_FILTERS,
        data,
    }
}

/// Parse `oid_filters` extension.
/// Returns list of (OID DER bytes, certificate extension values) pairs.
#[allow(clippy::type_complexity)]
pub fn parse_oid_filters(data: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed("oid_filters: too short".into()));
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return Err(TlsError::HandshakeFailed("oid_filters: truncated".into()));
    }
    let mut filters = Vec::new();
    let mut pos = 2;
    let end = 2 + list_len;
    while pos < end {
        if end - pos < 1 {
            return Err(TlsError::HandshakeFailed(
                "oid_filters: truncated OID length".into(),
            ));
        }
        let oid_len = data[pos] as usize;
        pos += 1;
        if end - pos < oid_len {
            return Err(TlsError::HandshakeFailed(
                "oid_filters: truncated OID".into(),
            ));
        }
        let oid = data[pos..pos + oid_len].to_vec();
        pos += oid_len;
        if end - pos < 2 {
            return Err(TlsError::HandshakeFailed(
                "oid_filters: truncated values length".into(),
            ));
        }
        let values_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if end - pos < values_len {
            return Err(TlsError::HandshakeFailed(
                "oid_filters: truncated values".into(),
            ));
        }
        let values = data[pos..pos + values_len].to_vec();
        pos += values_len;
        filters.push((oid, values));
    }
    Ok(filters)
}

// ---------------------------------------------------------------------------
// Heartbeat Extension (RFC 6520, type 15)
// ---------------------------------------------------------------------------

/// Build `heartbeat` extension (RFC 6520, type 15).
/// Wire format: mode(1) — 1=peer_allowed_to_send, 2=peer_not_allowed_to_send.
pub fn build_heartbeat(mode: u8) -> Extension {
    Extension {
        extension_type: ExtensionType::HEARTBEAT,
        data: vec![mode],
    }
}

/// Parse `heartbeat` extension.
/// Returns the mode value (1 or 2).
pub fn parse_heartbeat(data: &[u8]) -> Result<u8, TlsError> {
    if data.len() != 1 {
        return Err(TlsError::HandshakeFailed(
            "heartbeat: expected 1 byte".into(),
        ));
    }
    let mode = data[0];
    if mode != 1 && mode != 2 {
        return Err(TlsError::HandshakeFailed(format!(
            "heartbeat: invalid mode {mode}, expected 1 or 2"
        )));
    }
    Ok(mode)
}

// ---------------------------------------------------------------------------
// Trusted CA Keys (RFC 6066 §6, type 3)
// ---------------------------------------------------------------------------

/// Identifier type for trusted CA keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrustedAuthorityType {
    /// Pre-agreed — no data follows.
    PreAgreed = 0,
    /// SHA-1 hash of the distinguished name.
    KeySha1Hash = 1,
    /// SHA-1 hash of the public key.
    X509Name = 2,
    /// SHA-1 hash of the certificate.
    CertSha1Hash = 3,
}

/// A single trusted authority entry.
#[derive(Debug, Clone)]
pub struct TrustedAuthority {
    pub identifier_type: u8,
    pub data: Vec<u8>,
}

/// Build `trusted_ca_keys` extension for ClientHello (RFC 6066 §6, type 3).
/// Wire format: trusted_authorities_len(2) || [identifier_type(1) || data]*
pub fn build_trusted_ca_keys(authorities: &[TrustedAuthority]) -> Extension {
    let mut list = Vec::new();
    for auth in authorities {
        list.push(auth.identifier_type);
        if auth.identifier_type == 0 {
            // pre-agreed: no data
        } else if auth.identifier_type == 2 {
            // x509_name: dn_length(2) + dn
            list.extend_from_slice(&(auth.data.len() as u16).to_be_bytes());
            list.extend_from_slice(&auth.data);
        } else {
            // key_sha1_hash(1) / cert_sha1_hash(3): 20-byte SHA-1 hash
            list.extend_from_slice(&auth.data);
        }
    }
    let mut data = Vec::with_capacity(2 + list.len());
    data.extend_from_slice(&(list.len() as u16).to_be_bytes());
    data.extend_from_slice(&list);
    Extension {
        extension_type: ExtensionType::TRUSTED_CA_KEYS,
        data,
    }
}

/// Parse `trusted_ca_keys` extension.
/// Returns list of TrustedAuthority entries.
pub fn parse_trusted_ca_keys(data: &[u8]) -> Result<Vec<TrustedAuthority>, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed(
            "trusted_ca_keys: too short".into(),
        ));
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return Err(TlsError::HandshakeFailed(
            "trusted_ca_keys: truncated".into(),
        ));
    }
    let mut result = Vec::new();
    let mut pos = 2;
    let end = 2 + list_len;
    while pos < end {
        let id_type = data[pos];
        pos += 1;
        let entry_data = match id_type {
            0 => Vec::new(), // pre-agreed
            1 | 3 => {
                // SHA-1 hash: 20 bytes
                if end - pos < 20 {
                    return Err(TlsError::HandshakeFailed(
                        "trusted_ca_keys: truncated hash".into(),
                    ));
                }
                let d = data[pos..pos + 20].to_vec();
                pos += 20;
                d
            }
            2 => {
                // x509_name: dn_length(2) + dn
                if end - pos < 2 {
                    return Err(TlsError::HandshakeFailed(
                        "trusted_ca_keys: truncated DN length".into(),
                    ));
                }
                let dn_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                if end - pos < dn_len {
                    return Err(TlsError::HandshakeFailed(
                        "trusted_ca_keys: truncated DN".into(),
                    ));
                }
                let d = data[pos..pos + dn_len].to_vec();
                pos += dn_len;
                d
            }
            _ => {
                return Err(TlsError::HandshakeFailed(format!(
                    "trusted_ca_keys: unknown identifier type {id_type}"
                )));
            }
        };
        result.push(TrustedAuthority {
            identifier_type: id_type,
            data: entry_data,
        });
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// USE_SRTP (RFC 5764, type 14)
// ---------------------------------------------------------------------------

/// Build `use_srtp` extension (RFC 5764, type 14).
/// Wire format: profiles_len(2) || profiles(2 each) || mki_len(1) || mki
pub fn build_use_srtp(profiles: &[u16], mki: &[u8]) -> Extension {
    let profiles_len = (profiles.len() * 2) as u16;
    let mut data = Vec::with_capacity(2 + profiles.len() * 2 + 1 + mki.len());
    data.extend_from_slice(&profiles_len.to_be_bytes());
    for &p in profiles {
        data.extend_from_slice(&p.to_be_bytes());
    }
    data.push(mki.len() as u8);
    data.extend_from_slice(mki);
    Extension {
        extension_type: ExtensionType::USE_SRTP,
        data,
    }
}

/// Parse `use_srtp` extension.
/// Returns (profiles, mki).
pub fn parse_use_srtp(data: &[u8]) -> Result<(Vec<u16>, Vec<u8>), TlsError> {
    if data.len() < 3 {
        return Err(TlsError::HandshakeFailed("use_srtp: too short".into()));
    }
    let profiles_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if profiles_len % 2 != 0 {
        return Err(TlsError::HandshakeFailed(
            "use_srtp: odd profiles length".into(),
        ));
    }
    if data.len() < 2 + profiles_len + 1 {
        return Err(TlsError::HandshakeFailed("use_srtp: truncated".into()));
    }
    let mut profiles = Vec::with_capacity(profiles_len / 2);
    for i in (2..2 + profiles_len).step_by(2) {
        profiles.push(u16::from_be_bytes([data[i], data[i + 1]]));
    }
    let mki_pos = 2 + profiles_len;
    let mki_len = data[mki_pos] as usize;
    if data.len() < mki_pos + 1 + mki_len {
        return Err(TlsError::HandshakeFailed("use_srtp: truncated MKI".into()));
    }
    let mki = data[mki_pos + 1..mki_pos + 1 + mki_len].to_vec();
    Ok((profiles, mki))
}

// ---------------------------------------------------------------------------
// STATUS_REQUEST_V2 (RFC 6961, type 17)
// ---------------------------------------------------------------------------

/// Build `status_request_v2` extension for ClientHello (RFC 6961, type 17).
/// Requests OCSP multi-stapling.
/// Wire format: list_len(2) || [status_type(1) || request_len(2) || request]*
/// For ocsp(1): request = responder_id_list_len(2)=0 || request_extensions_len(2)=0
/// For ocsp_multi(2): same structure as ocsp but allows per-cert OCSP responses.
pub fn build_status_request_v2(request_types: &[u8]) -> Extension {
    let mut list = Vec::new();
    for &status_type in request_types {
        list.push(status_type);
        // request_length(2) = 4 (empty responder + empty extensions)
        list.extend_from_slice(&4u16.to_be_bytes());
        // responder_id_list_len(2) = 0
        list.extend_from_slice(&0u16.to_be_bytes());
        // request_extensions_len(2) = 0
        list.extend_from_slice(&0u16.to_be_bytes());
    }
    let mut data = Vec::with_capacity(2 + list.len());
    data.extend_from_slice(&(list.len() as u16).to_be_bytes());
    data.extend_from_slice(&list);
    Extension {
        extension_type: ExtensionType::STATUS_REQUEST_V2,
        data,
    }
}

/// Parse `status_request_v2` extension.
/// Returns list of status types requested (1=ocsp, 2=ocsp_multi).
pub fn parse_status_request_v2(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailed(
            "status_request_v2: too short".into(),
        ));
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return Err(TlsError::HandshakeFailed(
            "status_request_v2: truncated".into(),
        ));
    }
    let mut types = Vec::new();
    let mut pos = 2;
    let end = 2 + list_len;
    while pos < end {
        if end - pos < 3 {
            return Err(TlsError::HandshakeFailed(
                "status_request_v2: truncated entry".into(),
            ));
        }
        let status_type = data[pos];
        pos += 1;
        let request_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if end - pos < request_len {
            return Err(TlsError::HandshakeFailed(
                "status_request_v2: truncated request".into(),
            ));
        }
        pos += request_len;
        types.push(status_type);
    }
    Ok(types)
}

// ---------------------------------------------------------------------------
// GREASE (RFC 8701)
// ---------------------------------------------------------------------------

/// The 16 GREASE values defined in RFC 8701.
pub const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

/// Returns true if a u16 value matches the GREASE pattern (0x?A?A where both nibbles match).
pub fn is_grease_value(v: u16) -> bool {
    (v & 0x0F0F) == 0x0A0A && (v >> 8) == (v & 0xFF)
}

/// Pick a random GREASE value from the 16 defined values.
pub fn grease_value() -> u16 {
    let mut buf = [0u8; 1];
    let _ = getrandom::getrandom(&mut buf);
    GREASE_VALUES[(buf[0] & 0x0F) as usize]
}

/// Build a GREASE extension with a random type code and empty data.
pub fn build_grease_extension() -> Extension {
    Extension {
        extension_type: ExtensionType(grease_value()),
        data: vec![],
    }
}

/// Build `supported_versions` ClientHello extension with a GREASE version prepended.
pub fn build_supported_versions_ch_grease(grease_ver: u16) -> Extension {
    // Format: list_length(1) || grease_version(2) || TLS 1.3 (0x0304)
    let data = vec![
        0x04, // list_length = 4 bytes (2 versions)
        (grease_ver >> 8) as u8,
        (grease_ver & 0xFF) as u8,
        0x03,
        0x04, // TLS 1.3
    ];
    Extension {
        extension_type: ExtensionType::SUPPORTED_VERSIONS,
        data,
    }
}

/// Build `supported_groups` extension with a GREASE group prepended.
pub fn build_supported_groups_grease(groups: &[NamedGroup], grease_group: u16) -> Extension {
    let mut data = Vec::with_capacity(2 + 2 + groups.len() * 2);
    let list_len = (2 + groups.len() * 2) as u16;
    data.extend_from_slice(&list_len.to_be_bytes());
    data.extend_from_slice(&grease_group.to_be_bytes());
    for g in groups {
        data.extend_from_slice(&g.0.to_be_bytes());
    }
    Extension {
        extension_type: ExtensionType::SUPPORTED_GROUPS,
        data,
    }
}

/// Build `signature_algorithms` extension with a GREASE scheme prepended.
pub fn build_signature_algorithms_grease(
    schemes: &[SignatureScheme],
    grease_sig: u16,
) -> Extension {
    let mut data = Vec::with_capacity(2 + 2 + schemes.len() * 2);
    let list_len = (2 + schemes.len() * 2) as u16;
    data.extend_from_slice(&list_len.to_be_bytes());
    data.extend_from_slice(&grease_sig.to_be_bytes());
    for s in schemes {
        data.extend_from_slice(&s.0.to_be_bytes());
    }
    Extension {
        extension_type: ExtensionType::SIGNATURE_ALGORITHMS,
        data,
    }
}

/// Build `key_share` ClientHello extension with a GREASE key_share entry prepended.
/// The GREASE entry uses a 1-byte dummy public key (0x00).
pub fn build_key_share_ch_grease(
    group: NamedGroup,
    public_key: &[u8],
    grease_group: u16,
) -> Extension {
    // GREASE entry: group(2) + key_len(2) + key(1) = 5 bytes
    // Real entry: group(2) + key_len(2) + key(N)
    let grease_entry_len = 2 + 2 + 1;
    let real_entry_len = 2 + 2 + public_key.len();
    let total_len = grease_entry_len + real_entry_len;
    let mut data = Vec::with_capacity(2 + total_len);
    data.extend_from_slice(&(total_len as u16).to_be_bytes());
    // GREASE entry
    data.extend_from_slice(&grease_group.to_be_bytes());
    data.extend_from_slice(&1u16.to_be_bytes()); // key_exchange_length = 1
    data.push(0x00); // dummy key
                     // Real entry
    data.extend_from_slice(&group.0.to_be_bytes());
    data.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    data.extend_from_slice(public_key);
    Extension {
        extension_type: ExtensionType::KEY_SHARE,
        data,
    }
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

    #[test]
    fn test_alpn_build_parse_ch_roundtrip() {
        let protos = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let ext = build_alpn(&protos);
        assert_eq!(
            ext.extension_type,
            ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
        );
        let parsed = parse_alpn_ch(&ext.data).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], b"h2");
        assert_eq!(parsed[1], b"http/1.1");
    }

    #[test]
    fn test_alpn_build_parse_sh_roundtrip() {
        let ext = build_alpn_selected(b"h2");
        let parsed = parse_alpn_sh(&ext.data).unwrap();
        assert_eq!(parsed, b"h2");
    }

    #[test]
    fn test_sni_parse_roundtrip() {
        let ext = build_server_name("example.com");
        let parsed = parse_server_name(&ext.data).unwrap();
        assert_eq!(parsed, "example.com");
    }

    #[test]
    fn test_sni_parse_unicode() {
        let ext = build_server_name("test.example.org");
        let parsed = parse_server_name(&ext.data).unwrap();
        assert_eq!(parsed, "test.example.org");
    }

    #[test]
    fn test_build_parse_ec_point_formats() {
        let ext = build_ec_point_formats();
        assert_eq!(ext.extension_type, ExtensionType::EC_POINT_FORMATS);
        let formats = parse_ec_point_formats(&ext.data).unwrap();
        assert_eq!(formats, vec![0x00]); // uncompressed only
    }

    #[test]
    fn test_build_parse_renegotiation_info() {
        let ext = build_renegotiation_info_initial();
        assert_eq!(ext.extension_type, ExtensionType::RENEGOTIATION_INFO);
        let info = parse_renegotiation_info(&ext.data).unwrap();
        assert!(info.is_empty()); // empty for initial handshake
    }

    #[test]
    fn test_build_parse_extended_master_secret() {
        let ext = build_extended_master_secret();
        assert_eq!(ext.extension_type, ExtensionType::EXTENDED_MASTER_SECRET);
        assert!(ext.data.is_empty());
        parse_extended_master_secret(&ext.data).unwrap();
    }

    #[test]
    fn test_extended_master_secret_non_empty_fails() {
        assert!(parse_extended_master_secret(&[0x01]).is_err());
    }

    #[test]
    fn test_build_parse_encrypt_then_mac() {
        let ext = build_encrypt_then_mac();
        assert_eq!(ext.extension_type, ExtensionType::ENCRYPT_THEN_MAC);
        assert!(ext.data.is_empty());
        parse_encrypt_then_mac(&ext.data).unwrap();
    }

    #[test]
    fn test_encrypt_then_mac_non_empty_fails() {
        assert!(parse_encrypt_then_mac(&[0x01]).is_err());
    }

    #[test]
    fn test_build_parse_renegotiation_info_with_verify_data() {
        let client_vd = vec![0xAA; 12];
        let server_vd = vec![0xBB; 12];
        let ext = build_renegotiation_info(&client_vd, &server_vd);
        assert_eq!(ext.extension_type, ExtensionType::RENEGOTIATION_INFO);
        let info = parse_renegotiation_info(&ext.data).unwrap();
        assert_eq!(info.len(), 24);
        assert_eq!(&info[..12], &client_vd[..]);
        assert_eq!(&info[12..], &server_vd[..]);
    }

    #[test]
    fn test_session_ticket_ch_empty() {
        let ext = build_session_ticket_ch(&[]);
        assert_eq!(ext.extension_type, ExtensionType::SESSION_TICKET);
        assert!(ext.data.is_empty());
        let parsed = parse_session_ticket_ch(&ext.data).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_session_ticket_ch_with_ticket() {
        let ticket = vec![0xDE; 128];
        let ext = build_session_ticket_ch(&ticket);
        assert_eq!(ext.extension_type, ExtensionType::SESSION_TICKET);
        assert_eq!(ext.data.len(), ticket.len());
        let parsed = parse_session_ticket_ch(&ext.data).unwrap();
        assert_eq!(parsed, ticket);
    }

    #[test]
    fn test_session_ticket_sh() {
        let ext = build_session_ticket_sh();
        assert_eq!(ext.extension_type, ExtensionType::SESSION_TICKET);
        assert!(ext.data.is_empty());
        parse_session_ticket_sh(&ext.data).unwrap();
    }

    #[test]
    fn test_session_ticket_sh_non_empty_fails() {
        assert!(parse_session_ticket_sh(&[0x01]).is_err());
    }

    // Record Size Limit tests

    #[test]
    fn test_build_parse_record_size_limit() {
        let ext = build_record_size_limit(4096);
        assert_eq!(ext.extension_type, ExtensionType::RECORD_SIZE_LIMIT);
        assert_eq!(ext.data.len(), 2);
        let parsed = parse_record_size_limit(&ext.data).unwrap();
        assert_eq!(parsed, 4096);
    }

    #[test]
    fn test_record_size_limit_min_64() {
        let ext = build_record_size_limit(64);
        let parsed = parse_record_size_limit(&ext.data).unwrap();
        assert_eq!(parsed, 64);
    }

    #[test]
    fn test_record_size_limit_max_16385() {
        let ext = build_record_size_limit(16385);
        let parsed = parse_record_size_limit(&ext.data).unwrap();
        assert_eq!(parsed, 16385);
    }

    #[test]
    fn test_record_size_limit_below_64_rejected() {
        let data = 63u16.to_be_bytes();
        assert!(parse_record_size_limit(&data).is_err());
    }

    #[test]
    fn test_record_size_limit_wrong_length() {
        assert!(parse_record_size_limit(&[0x10]).is_err());
        assert!(parse_record_size_limit(&[0x00, 0x40, 0x00]).is_err());
    }

    // OCSP Stapling tests

    #[test]
    fn test_build_status_request_ch() {
        let ext = build_status_request_ch();
        assert_eq!(ext.extension_type, ExtensionType::STATUS_REQUEST);
        assert_eq!(ext.data, vec![0x01, 0x00, 0x00, 0x00, 0x00]);
        let is_ocsp = parse_status_request_ch(&ext.data).unwrap();
        assert!(is_ocsp);
    }

    #[test]
    fn test_status_request_ch_non_ocsp() {
        let is_ocsp = parse_status_request_ch(&[0x02, 0x00, 0x00]).unwrap();
        assert!(!is_ocsp);
    }

    #[test]
    fn test_status_request_ch_empty_fails() {
        assert!(parse_status_request_ch(&[]).is_err());
    }

    #[test]
    fn test_build_parse_status_request_cert_entry() {
        let ocsp_der = vec![0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB];
        let ext = build_status_request_cert_entry(&ocsp_der);
        assert_eq!(ext.extension_type, ExtensionType::STATUS_REQUEST);
        let parsed = parse_status_request_cert_entry(&ext.data).unwrap();
        assert_eq!(parsed, ocsp_der);
    }

    #[test]
    fn test_status_request_cert_entry_truncated() {
        assert!(parse_status_request_cert_entry(&[0x01, 0x00, 0x00]).is_err());
    }

    // SCT tests

    #[test]
    fn test_build_sct_ch() {
        let ext = build_sct_ch();
        assert_eq!(
            ext.extension_type,
            ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP
        );
        assert!(ext.data.is_empty());
    }

    #[test]
    fn test_build_sct_cert_entry() {
        let sct_list = vec![0x00, 0x10, 0x01, 0x02, 0x03];
        let ext = build_sct_cert_entry(&sct_list);
        assert_eq!(
            ext.extension_type,
            ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP
        );
        assert_eq!(ext.data, sct_list);
    }

    #[test]
    fn test_renegotiation_info_with_verify_data() {
        let client_vd = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let server_vd = vec![
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
        ];

        let ext = build_renegotiation_info(&client_vd, &server_vd);
        assert_eq!(ext.extension_type, ExtensionType::RENEGOTIATION_INFO);

        // Parse it back
        let parsed = parse_renegotiation_info(&ext.data).unwrap();
        // Should be client_vd || server_vd
        assert_eq!(parsed.len(), 24);
        assert_eq!(&parsed[..12], &client_vd[..]);
        assert_eq!(&parsed[12..], &server_vd[..]);

        // Client-only (for ClientHello during renegotiation)
        let ext2 = build_renegotiation_info(&client_vd, &[]);
        let parsed2 = parse_renegotiation_info(&ext2.data).unwrap();
        assert_eq!(parsed2.len(), 12);
        assert_eq!(&parsed2[..], &client_vd[..]);
    }

    #[test]
    fn test_mfl_codec_roundtrip() {
        use crate::config::MaxFragmentLength;

        // Test all valid values
        for (val, expected_size) in [
            (MaxFragmentLength::Bits512, 512),
            (MaxFragmentLength::Bits1024, 1024),
            (MaxFragmentLength::Bits2048, 2048),
            (MaxFragmentLength::Bits4096, 4096),
        ] {
            let ext = build_max_fragment_length(val);
            assert_eq!(ext.extension_type, ExtensionType::MAX_FRAGMENT_LENGTH);
            assert_eq!(ext.data.len(), 1);
            let parsed = parse_max_fragment_length(&ext.data).unwrap();
            assert_eq!(parsed, val);
            assert_eq!(parsed.to_size(), expected_size);
        }

        // Invalid values rejected
        assert!(parse_max_fragment_length(&[0]).is_err());
        assert!(parse_max_fragment_length(&[5]).is_err());
        assert!(parse_max_fragment_length(&[]).is_err());
        assert!(parse_max_fragment_length(&[1, 2]).is_err());
    }

    #[test]
    fn test_certificate_authorities_codec_roundtrip() {
        // Single DN
        let dn1 = vec![0x30, 0x0A, 0x31, 0x08, 0x30, 0x06];
        let ext = build_certificate_authorities(std::slice::from_ref(&dn1));
        assert_eq!(ext.extension_type, ExtensionType::CERTIFICATE_AUTHORITIES);
        let parsed = parse_certificate_authorities(&ext.data).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], dn1);

        // Multiple DNs
        let dn2 = vec![0x30, 0x0B, 0x31, 0x09, 0x30, 0x07, 0x01];
        let ext2 = build_certificate_authorities(&[dn1.clone(), dn2.clone()]);
        let parsed2 = parse_certificate_authorities(&ext2.data).unwrap();
        assert_eq!(parsed2.len(), 2);
        assert_eq!(parsed2[0], dn1);
        assert_eq!(parsed2[1], dn2);
    }

    #[test]
    fn test_certificate_authorities_empty() {
        let ext = build_certificate_authorities(&[]);
        assert_eq!(ext.extension_type, ExtensionType::CERTIFICATE_AUTHORITIES);
        let parsed = parse_certificate_authorities(&ext.data).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_certificate_authorities_truncated_rejected() {
        // Too short for list length
        assert!(parse_certificate_authorities(&[0x00]).is_err());
        // List length says 10 bytes but only 2 available
        assert!(parse_certificate_authorities(&[0x00, 0x0A, 0x00, 0x02]).is_err());
        // DN length says 5 but only 2 bytes available
        assert!(parse_certificate_authorities(&[0x00, 0x04, 0x00, 0x05, 0xAA, 0xBB]).is_err());
    }

    #[test]
    fn test_sig_algs_cert_codec_roundtrip() {
        let schemes = vec![
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::ED25519,
        ];
        let ext = build_signature_algorithms_cert(&schemes);
        assert_eq!(ext.extension_type, ExtensionType::SIGNATURE_ALGORITHMS_CERT);
        // Same wire format as signature_algorithms: list_len(2) + 3*scheme(2)
        assert_eq!(ext.data.len(), 2 + 3 * 2);
        let parsed = parse_signature_algorithms_cert(&ext.data).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], SignatureScheme::RSA_PSS_RSAE_SHA256);
        assert_eq!(parsed[1], SignatureScheme::ECDSA_SECP256R1_SHA256);
        assert_eq!(parsed[2], SignatureScheme::ED25519);
    }

    // PADDING tests

    #[test]
    fn test_padding_codec_roundtrip() {
        for len in [0, 1, 100, 512] {
            let ext = build_padding(len);
            assert_eq!(ext.extension_type, ExtensionType::PADDING);
            assert_eq!(ext.data.len(), len);
            let parsed_len = parse_padding(&ext.data).unwrap();
            assert_eq!(parsed_len, len);
        }
    }

    #[test]
    fn test_padding_rejects_nonzero() {
        let mut data = vec![0u8; 10];
        data[5] = 0x01;
        assert!(parse_padding(&data).is_err());
    }

    // OID Filters tests

    #[test]
    fn test_oid_filters_codec_roundtrip() {
        // Single filter
        let oid1 = vec![0x55, 0x1D, 0x25]; // id-ce-extKeyUsage OID bytes
        let values1 = vec![0x30, 0x0A, 0x06, 0x08];
        let ext = build_oid_filters(&[(oid1.clone(), values1.clone())]);
        assert_eq!(ext.extension_type, ExtensionType::OID_FILTERS);
        let parsed = parse_oid_filters(&ext.data).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, oid1);
        assert_eq!(parsed[0].1, values1);

        // Multiple filters
        let oid2 = vec![0x55, 0x1D, 0x0F]; // id-ce-keyUsage
        let values2 = vec![0x03, 0x02, 0x05, 0xA0];
        let ext2 = build_oid_filters(&[
            (oid1.clone(), values1.clone()),
            (oid2.clone(), values2.clone()),
        ]);
        let parsed2 = parse_oid_filters(&ext2.data).unwrap();
        assert_eq!(parsed2.len(), 2);
        assert_eq!(parsed2[0], (oid1, values1));
        assert_eq!(parsed2[1], (oid2, values2));
    }

    #[test]
    fn test_oid_filters_empty() {
        let ext = build_oid_filters(&[]);
        assert_eq!(ext.extension_type, ExtensionType::OID_FILTERS);
        let parsed = parse_oid_filters(&ext.data).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_oid_filters_truncated_rejected() {
        // Too short for list length
        assert!(parse_oid_filters(&[0x00]).is_err());
        // List length says 10 but only 2 available
        assert!(parse_oid_filters(&[0x00, 0x0A, 0x03]).is_err());
        // OID length says 5 but only 2 bytes available
        assert!(parse_oid_filters(&[0x00, 0x04, 0x05, 0xAA, 0xBB, 0xCC]).is_err());
    }

    // Heartbeat extension tests

    #[test]
    fn test_heartbeat_codec_roundtrip() {
        // Mode 1: peer_allowed_to_send
        let ext = build_heartbeat(1);
        assert_eq!(ext.extension_type, ExtensionType::HEARTBEAT);
        assert_eq!(ext.data.len(), 1);
        let mode = parse_heartbeat(&ext.data).unwrap();
        assert_eq!(mode, 1);

        // Mode 2: peer_not_allowed_to_send
        let ext2 = build_heartbeat(2);
        let mode2 = parse_heartbeat(&ext2.data).unwrap();
        assert_eq!(mode2, 2);
    }

    #[test]
    fn test_heartbeat_invalid_mode() {
        // Mode 0 → error
        assert!(parse_heartbeat(&[0]).is_err());
        // Mode 3 → error
        assert!(parse_heartbeat(&[3]).is_err());
        // Empty → error
        assert!(parse_heartbeat(&[]).is_err());
        // Too long → error
        assert!(parse_heartbeat(&[1, 2]).is_err());
    }

    // GREASE tests

    #[test]
    fn test_grease_value_is_valid() {
        // Call multiple times to exercise randomness
        for _ in 0..20 {
            let gv = grease_value();
            assert!(
                is_grease_value(gv),
                "grease_value() returned {gv:#06X} which is not a valid GREASE value"
            );
            assert!(GREASE_VALUES.contains(&gv));
        }
    }

    #[test]
    fn test_grease_extension_build() {
        let ext = build_grease_extension();
        assert!(is_grease_value(ext.extension_type.0));
        assert!(ext.data.is_empty());
    }

    #[test]
    fn test_grease_supported_versions() {
        let gv = 0x3A3A;
        let ext = build_supported_versions_ch_grease(gv);
        assert_eq!(ext.extension_type, ExtensionType::SUPPORTED_VERSIONS);
        // Parse: list_length(1) + versions
        assert_eq!(ext.data[0], 4); // 2 versions * 2 bytes
        let ver1 = u16::from_be_bytes([ext.data[1], ext.data[2]]);
        let ver2 = u16::from_be_bytes([ext.data[3], ext.data[4]]);
        assert_eq!(ver1, 0x3A3A); // GREASE
        assert_eq!(ver2, 0x0304); // TLS 1.3
    }

    // -------------------------------------------------------
    // Testing-Phase 78 — H4: Extension codec negative/edge case tests
    // -------------------------------------------------------

    #[test]
    fn test_parse_supported_versions_ch_empty_data() {
        // Totally empty data → error
        assert!(parse_supported_versions_ch(&[]).is_err());
    }

    #[test]
    fn test_parse_supported_versions_ch_zero_list() {
        // List length 0 → empty list (codec accepts)
        let result = parse_supported_versions_ch(&[0]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_supported_versions_ch_truncated() {
        // List length says 4 bytes but only 2 bytes follow
        assert!(parse_supported_versions_ch(&[4, 0x03, 0x04]).is_err());
    }

    #[test]
    fn test_parse_supported_versions_ch_odd_length() {
        // Odd list length (3 bytes) → not a multiple of 2 → error
        assert!(parse_supported_versions_ch(&[3, 0x03, 0x04, 0x01]).is_err());
    }

    #[test]
    fn test_parse_signature_algorithms_ch_empty_data() {
        // Too short → error
        assert!(parse_signature_algorithms_ch(&[]).is_err());
        assert!(parse_signature_algorithms_ch(&[0]).is_err());
    }

    #[test]
    fn test_parse_key_share_ch_empty_list() {
        // Key share list with 0 length → empty (should succeed, 0 entries)
        let result = parse_key_share_ch(&[0, 0]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_certificate_authorities_truncated_name() {
        // Total length = 4, then name length says 10 but only 2 bytes follow
        let data = [0, 4, 0, 10, 0xAA, 0xBB];
        assert!(parse_certificate_authorities(&data).is_err());
    }

    #[test]
    fn test_parse_alpn_ch_empty_protocol_name() {
        // ALPN with a zero-length protocol name → error per RFC 7301
        // outer_len(2) = 3, then name_len=0 (invalid)
        let data = [0, 3, 0];
        assert!(parse_alpn_ch(&data).is_err());
    }

    #[test]
    fn test_parse_server_name_empty() {
        // Empty SNI data → error
        assert!(parse_server_name(&[]).is_err());
    }

    #[test]
    fn test_parse_max_fragment_length_wrong_length() {
        // MFL extension must be exactly 1 byte
        assert!(parse_max_fragment_length(&[]).is_err());
        assert!(parse_max_fragment_length(&[1, 2]).is_err());
    }

    #[test]
    fn test_parse_max_fragment_length_invalid_value() {
        // Valid values are 1-4, value 0 and 5+ are invalid
        assert!(parse_max_fragment_length(&[0]).is_err());
        assert!(parse_max_fragment_length(&[5]).is_err());
    }

    #[test]
    fn test_grease_supported_groups_includes_real_groups() {
        use crate::crypt::NamedGroup;
        let groups = [NamedGroup::SECP256R1, NamedGroup::X25519];
        let gv = 0x4A4A;
        let ext = build_supported_groups_grease(&groups, gv);
        // Should contain GREASE value + real groups
        let parsed = parse_supported_groups_ch(&ext.data).unwrap();
        assert!(parsed.len() >= 3); // 1 GREASE + 2 real
    }

    #[test]
    fn test_grease_signature_algorithms_includes_real() {
        use crate::crypt::SignatureScheme;
        let algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];
        let gv = 0x5A5A;
        let ext = build_signature_algorithms_grease(&algs, gv);
        let parsed = parse_signature_algorithms_ch(&ext.data).unwrap();
        assert!(parsed.len() >= 2); // 1 GREASE + 1 real
    }

    // -------------------------------------------------------
    // Phase 78 — Trusted CA Keys / USE_SRTP / STATUS_REQUEST_V2
    // -------------------------------------------------------

    #[test]
    fn test_trusted_ca_keys_roundtrip() {
        let authorities = vec![
            TrustedAuthority {
                identifier_type: 0, // pre-agreed
                data: vec![],
            },
            TrustedAuthority {
                identifier_type: 1, // key_sha1_hash
                data: vec![0xAA; 20],
            },
            TrustedAuthority {
                identifier_type: 2,                 // x509_name
                data: vec![0x30, 0x0C, 0x31, 0x0A], // short DN
            },
            TrustedAuthority {
                identifier_type: 3, // cert_sha1_hash
                data: vec![0xBB; 20],
            },
        ];
        let ext = build_trusted_ca_keys(&authorities);
        assert_eq!(ext.extension_type, ExtensionType::TRUSTED_CA_KEYS);
        let parsed = parse_trusted_ca_keys(&ext.data).unwrap();
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].identifier_type, 0);
        assert!(parsed[0].data.is_empty());
        assert_eq!(parsed[1].identifier_type, 1);
        assert_eq!(parsed[1].data, vec![0xAA; 20]);
        assert_eq!(parsed[2].identifier_type, 2);
        assert_eq!(parsed[2].data, vec![0x30, 0x0C, 0x31, 0x0A]);
        assert_eq!(parsed[3].identifier_type, 3);
        assert_eq!(parsed[3].data, vec![0xBB; 20]);
    }

    #[test]
    fn test_trusted_ca_keys_empty() {
        let ext = build_trusted_ca_keys(&[]);
        let parsed = parse_trusted_ca_keys(&ext.data).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_trusted_ca_keys_parse_errors() {
        // Too short
        assert!(parse_trusted_ca_keys(&[]).is_err());
        assert!(parse_trusted_ca_keys(&[0x00]).is_err());
        // Truncated list
        assert!(parse_trusted_ca_keys(&[0x00, 0x05, 0x01]).is_err());
        // Unknown identifier type
        assert!(parse_trusted_ca_keys(&[0x00, 0x01, 0xFF]).is_err());
    }

    #[test]
    fn test_use_srtp_roundtrip() {
        let profiles = vec![0x0001, 0x0007]; // SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AEAD_AES_128_GCM
        let mki = vec![0x42];
        let ext = build_use_srtp(&profiles, &mki);
        assert_eq!(ext.extension_type, ExtensionType::USE_SRTP);
        let (parsed_profiles, parsed_mki) = parse_use_srtp(&ext.data).unwrap();
        assert_eq!(parsed_profiles, profiles);
        assert_eq!(parsed_mki, mki);
    }

    #[test]
    fn test_use_srtp_empty_mki() {
        let profiles = vec![0x0001];
        let ext = build_use_srtp(&profiles, &[]);
        let (parsed_profiles, parsed_mki) = parse_use_srtp(&ext.data).unwrap();
        assert_eq!(parsed_profiles, vec![0x0001]);
        assert!(parsed_mki.is_empty());
    }

    #[test]
    fn test_use_srtp_parse_errors() {
        // Too short
        assert!(parse_use_srtp(&[]).is_err());
        assert!(parse_use_srtp(&[0x00, 0x02]).is_err());
        // Odd profiles length
        assert!(parse_use_srtp(&[0x00, 0x03, 0x00, 0x01, 0x00, 0x00]).is_err());
    }

    #[test]
    fn test_status_request_v2_roundtrip() {
        let ext = build_status_request_v2(&[1, 2]); // ocsp + ocsp_multi
        assert_eq!(ext.extension_type, ExtensionType::STATUS_REQUEST_V2);
        let parsed = parse_status_request_v2(&ext.data).unwrap();
        assert_eq!(parsed, vec![1, 2]);
    }

    #[test]
    fn test_status_request_v2_single() {
        let ext = build_status_request_v2(&[2]); // ocsp_multi only
        let parsed = parse_status_request_v2(&ext.data).unwrap();
        assert_eq!(parsed, vec![2]);
    }

    #[test]
    fn test_status_request_v2_parse_errors() {
        // Too short
        assert!(parse_status_request_v2(&[]).is_err());
        assert!(parse_status_request_v2(&[0x00]).is_err());
        // Truncated entry
        assert!(parse_status_request_v2(&[0x00, 0x03, 0x01, 0x00]).is_err());
    }

    #[test]
    fn test_grease_key_share_ch_includes_real_entry() {
        let real_group = NamedGroup::X25519;
        let fake_pk = vec![0x42u8; 32];
        let grease_group = GREASE_VALUES[0]; // 0x0A0A
        let ext = build_key_share_ch_grease(real_group, &fake_pk, grease_group);
        assert_eq!(ext.extension_type, ExtensionType::KEY_SHARE);

        // Parse the key_share entries — should contain GREASE entry + real entry
        let entries = parse_key_share_ch(&ext.data).unwrap();
        assert_eq!(entries.len(), 2);
        // First entry is GREASE (1-byte key)
        assert_eq!(entries[0].0 .0, grease_group);
        assert_eq!(entries[0].1.len(), 1);
        // Second entry is the real key share
        assert_eq!(entries[1].0, real_group);
        assert_eq!(entries[1].1, fake_pk);
    }

    #[test]
    fn test_parse_extensions_truncated_length() {
        // Total length says 8 but only 4 bytes of extension data follow
        let data = [
            0x00, 0x08, // extensions total length = 8
            0x00, 0x0A, // extension type 10
            0x00,
            0x02, // ext data length = 2
                  // missing 2 bytes of extension data
        ];
        assert!(parse_extensions(&data).is_err());
    }

    #[test]
    fn test_parse_extensions_empty_returns_empty() {
        // Less than 2 bytes → Ok(empty)
        assert!(parse_extensions(&[]).unwrap().is_empty());
        assert!(parse_extensions(&[0x00]).unwrap().is_empty());
        // Zero-length extensions list
        assert!(parse_extensions(&[0x00, 0x00]).unwrap().is_empty());
    }

    #[test]
    fn test_parse_pre_shared_key_ch_truncated_identity() {
        // identities_length = 10 but data too short
        let data = [
            0x00, 0x0A, // identities list length = 10
            0x00, 0x03, // identity length = 3
            0x41, 0x42,
            0x43, // identity bytes "ABC"
                  // missing obfuscated_ticket_age (4 bytes) + rest
        ];
        let result = parse_pre_shared_key_ch(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_alpn_sh_list_length_mismatch() {
        // list_len claims 10, but actual data after header is only 3 bytes
        let data = [
            0x00, 0x0A, // list_length = 10
            0x02, // proto_len = 2
            0x68, 0x32, // "h2"
        ];
        // list_len(10) != 1 + proto_len(2) = 3 → unexpected list size
        let result = parse_alpn_sh(&data);
        assert!(result.is_err());
    }

    // ===================================================================
    // Early Data extension codec tests (Testing-Phase 91)
    // ===================================================================

    #[test]
    fn test_build_early_data_ch_empty() {
        let ext = build_early_data_ch();
        assert_eq!(ext.extension_type, ExtensionType::EARLY_DATA);
        assert!(ext.data.is_empty(), "ClientHello early_data must be empty");
    }

    #[test]
    fn test_build_early_data_ee_empty() {
        let ext = build_early_data_ee();
        assert_eq!(ext.extension_type, ExtensionType::EARLY_DATA);
        assert!(
            ext.data.is_empty(),
            "EncryptedExtensions early_data must be empty"
        );
    }

    #[test]
    fn test_build_early_data_nst_max_size() {
        let ext = build_early_data_nst(16384);
        assert_eq!(ext.extension_type, ExtensionType::EARLY_DATA);
        assert_eq!(ext.data.len(), 4, "NST early_data must be 4 bytes");
        let val = u32::from_be_bytes(ext.data[..4].try_into().unwrap());
        assert_eq!(val, 16384);

        // Zero max size
        let ext0 = build_early_data_nst(0);
        let val0 = u32::from_be_bytes(ext0.data[..4].try_into().unwrap());
        assert_eq!(val0, 0);

        // Max u32
        let ext_max = build_early_data_nst(u32::MAX);
        let val_max = u32::from_be_bytes(ext_max.data[..4].try_into().unwrap());
        assert_eq!(val_max, u32::MAX);
    }
}
