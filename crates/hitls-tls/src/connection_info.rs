//! Connection information snapshot.
//!
//! After a TLS handshake completes, callers can query negotiated parameters
//! via the [`ConnectionInfo`] struct returned by `connection_info()`.

use crate::crypt::NamedGroup;
use crate::CipherSuite;

/// Snapshot of negotiated connection parameters after handshake.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// The negotiated cipher suite.
    pub cipher_suite: CipherSuite,
    /// Peer certificates (DER-encoded, leaf first).
    pub peer_certificates: Vec<Vec<u8>>,
    /// Negotiated ALPN protocol (if any).
    pub alpn_protocol: Option<Vec<u8>>,
    /// Server name (SNI) used in this connection.
    pub server_name: Option<String>,
    /// Negotiated key exchange group (if applicable).
    pub negotiated_group: Option<NamedGroup>,
    /// Whether this connection was resumed from a previous session.
    pub session_resumed: bool,
    /// Peer's Finished verify_data.
    pub peer_verify_data: Vec<u8>,
    /// Local Finished verify_data.
    pub local_verify_data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypt::NamedGroup;

    #[test]
    fn test_connection_info_construction_all_fields() {
        let info = ConnectionInfo {
            cipher_suite: CipherSuite(0x1301),
            peer_certificates: vec![vec![0x30, 0x82], vec![0x30, 0x83]],
            alpn_protocol: Some(b"h2".to_vec()),
            server_name: Some("example.com".to_string()),
            negotiated_group: Some(NamedGroup::SECP256R1),
            session_resumed: true,
            peer_verify_data: vec![0xAA; 12],
            local_verify_data: vec![0xBB; 12],
        };

        assert_eq!(info.cipher_suite.0, 0x1301);
        assert_eq!(info.peer_certificates.len(), 2);
        assert_eq!(info.alpn_protocol.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(info.server_name.as_deref(), Some("example.com"));
        assert_eq!(info.negotiated_group, Some(NamedGroup::SECP256R1));
        assert!(info.session_resumed);
        assert_eq!(info.peer_verify_data.len(), 12);
        assert_eq!(info.local_verify_data.len(), 12);
    }

    #[test]
    fn test_connection_info_optional_fields_none() {
        let info = ConnectionInfo {
            cipher_suite: CipherSuite(0xC02F),
            peer_certificates: vec![],
            alpn_protocol: None,
            server_name: None,
            negotiated_group: None,
            session_resumed: false,
            peer_verify_data: vec![],
            local_verify_data: vec![],
        };

        assert_eq!(info.cipher_suite.0, 0xC02F);
        assert!(info.peer_certificates.is_empty());
        assert!(info.alpn_protocol.is_none());
        assert!(info.server_name.is_none());
        assert!(info.negotiated_group.is_none());
        assert!(!info.session_resumed);
        assert!(info.peer_verify_data.is_empty());
        assert!(info.local_verify_data.is_empty());
    }

    #[test]
    fn test_connection_info_debug_format() {
        let info = ConnectionInfo {
            cipher_suite: CipherSuite(0x1301),
            peer_certificates: vec![],
            alpn_protocol: None,
            server_name: Some("test.local".to_string()),
            negotiated_group: None,
            session_resumed: false,
            peer_verify_data: vec![],
            local_verify_data: vec![],
        };
        let debug = format!("{info:?}");
        assert!(debug.contains("ConnectionInfo"));
        assert!(debug.contains("test.local"));
        assert!(debug.contains("CipherSuite"));
    }

    #[test]
    fn test_connection_info_clone_independence() {
        let info = ConnectionInfo {
            cipher_suite: CipherSuite(0x1302),
            peer_certificates: vec![vec![0x01, 0x02, 0x03]],
            alpn_protocol: Some(b"h2".to_vec()),
            server_name: Some("clone.test".to_string()),
            negotiated_group: Some(NamedGroup::X25519),
            session_resumed: true,
            peer_verify_data: vec![0xCC; 12],
            local_verify_data: vec![0xDD; 12],
        };

        let cloned = info.clone();
        assert_eq!(cloned.cipher_suite, info.cipher_suite);
        assert_eq!(cloned.peer_certificates, info.peer_certificates);
        assert_eq!(cloned.alpn_protocol, info.alpn_protocol);
        assert_eq!(cloned.server_name, info.server_name);
        assert_eq!(cloned.negotiated_group, info.negotiated_group);
        assert_eq!(cloned.session_resumed, info.session_resumed);
        assert_eq!(cloned.peer_verify_data, info.peer_verify_data);
        assert_eq!(cloned.local_verify_data, info.local_verify_data);
    }

    #[test]
    fn test_connection_info_large_peer_certs() {
        let info = ConnectionInfo {
            cipher_suite: CipherSuite(0x1303),
            peer_certificates: vec![vec![0x30; 1024], vec![0x31; 2048], vec![0x32; 512]],
            alpn_protocol: None,
            server_name: None,
            negotiated_group: None,
            session_resumed: false,
            peer_verify_data: vec![],
            local_verify_data: vec![],
        };

        assert_eq!(info.peer_certificates.len(), 3);
        assert_eq!(info.peer_certificates[0].len(), 1024);
        assert_eq!(info.peer_certificates[1].len(), 2048);
        assert_eq!(info.peer_certificates[2].len(), 512);
    }
}
