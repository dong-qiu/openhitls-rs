//! TLS alert protocol.

/// Alert severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

/// Alert description codes (RFC 8446 Section 6, plus legacy/reserved codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    /// Deprecated in TLS 1.2 (RFC 5246); replaced by BadRecordMac.
    DecryptionFailed = 21,
    RecordOverflow = 22,
    /// Deprecated: TLS record compression removed (CRIME attack).
    DecompressionFailure = 30,
    HandshakeFailure = 40,
    /// Reserved (SSLv3 legacy, not used in TLS 1.0+).
    NoCertificateReserved = 41,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    /// Reserved (export cipher suites removed).
    ExportRestrictionReserved = 60,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    NoRenegotiation = 100,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    /// Certificate could not be obtained (RFC 4366, deprecated).
    CertificateUnobtainable = 111,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    /// Deprecated (RFC 7366).
    BadCertificateHashValue = 114,
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}

/// A TLS alert.
#[derive(Debug, Clone, Copy)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl AlertLevel {
    /// Convert from u8 to AlertLevel.
    pub fn from_u8(v: u8) -> Result<Self, u8> {
        match v {
            1 => Ok(AlertLevel::Warning),
            2 => Ok(AlertLevel::Fatal),
            _ => Err(v),
        }
    }
}

/// Map an internal `TlsError` to the wire alert description that should
/// be sent to the peer before closing (Phase T89).
///
/// Most TLS 1.3 paths just need a sensible default — the only invariant
/// we guarantee is that the peer receives **something** in the
/// `unexpected_message` / `decrypt_error` / `handshake_failure` /
/// `decode_error` / `internal_error` family rather than a bare TCP
/// close. The mapping uses the error variant first; for `HandshakeFailed`
/// and `RecordError` we additionally substring-match the human-readable
/// reason because most of our handshake errors are typed as
/// `HandshakeFailed(String)` with a free-form message.
///
/// Substring matches are case-sensitive and conservative: when in doubt
/// we fall through to `handshake_failure` (40) for handshake-stage
/// errors and `internal_error` (80) for everything else. Keep the
/// substrings in sync with the error site producing them — see the
/// covering tests in `tests/interop/tests/protocol_attacks.rs`.
pub fn tls_error_to_alert(err: &hitls_types::TlsError) -> AlertDescription {
    use hitls_types::TlsError;
    match err {
        TlsError::HandshakeFailed(msg) => {
            let m = msg.as_str();
            if m.contains("verify_data mismatch")
                || m.contains("MAC verification")
                || m.contains("decrypt")
                || m.contains("AEAD")
                || m.contains("tag mismatch")
                || m.contains("BadRecordMac")
            {
                AlertDescription::DecryptError
            } else if m.contains("missing extension")
                || m.contains("missing_extension")
                || m.contains("missing required extension")
                // RFC 8446 §9.2: a TLS 1.3 ClientHello missing
                // key_share / supported_versions / signature_algorithms
                // (etc.) MUST be aborted with missing_extension.
                || m.contains("missing key_share")
                || m.contains("missing supported_versions")
                || m.contains("missing signature_algorithms")
                || m.contains("missing supported_groups")
                || m.contains("missing pre_shared_key")
                || m.contains("missing psk_key_exchange_modes")
            {
                AlertDescription::MissingExtension
            } else if m.contains("unexpected_message")
                || m.contains("unexpected ChangeCipherSpec")
                || m.contains("unexpected post-handshake")
                || m.contains("unexpected content type")
            {
                AlertDescription::UnexpectedMessage
            } else if m.contains("unsupported_extension") {
                // RFC 8446 §6.2 — an extension appearing in a message it is
                // not permitted in (e.g. an extension the client never
                // offered echoed in ServerHello / EncryptedExtensions).
                AlertDescription::UnsupportedExtension
            } else if m.contains("illegal_parameter")
                || m.contains("illegal parameter")
                || m.contains("invalid key_share")
                || m.contains("empty key_share")
                || m.contains("invalid extension")
            {
                AlertDescription::IllegalParameter
            } else if m.contains("bad_certificate") {
                // Phase T117 — RFC 5246 §7.2.2 `bad_certificate` (42):
                // "A certificate was corrupt, contained signatures
                // that did not verify correctly, etc." Cert-content
                // problems detected at codec time (DER-shape check
                // on each entry) belong here. Routed BEFORE the
                // decode_error branch because some of our error
                // strings necessarily include parser-style words
                // like "malformed DER length" or "length mismatch"
                // that would otherwise grab the decode_error mapping.
                AlertDescription::BadCertificate
            } else if m.contains("decode")
                || m.contains("malformed")
                || m.contains("parse")
                || m.contains("truncated")
                || m.contains("incomplete")
                // Phase T100 — RFC 8446 §6.2 `decode_error`: "A message
                // could not be decoded because some field was out of the
                // specified range or the length of the message was
                // incorrect." Cover the common parser substrings used
                // throughout the handshake codec — pre-T100 these all
                // fell through to handshake_failure, breaking
                // tlsfuzzer's per-conversation alert pinning on
                // `test-tls13-signature-algorithms.py` and similar.
                || m.contains("too short")
                || m.contains("invalid length")
            {
                AlertDescription::DecodeError
            } else if m.contains("unsupported version")
                || m.contains("ProtocolVersion")
                || m.contains("protocol version")
            {
                AlertDescription::ProtocolVersion
            } else {
                // `no shared` / `no common` / `no acceptable` and any
                // unmatched handshake-stage error all fall through to
                // generic `handshake_failure` (40).
                AlertDescription::HandshakeFailure
            }
        }
        TlsError::RecordError(msg) => {
            let m = msg.as_str();
            // RFC 8446 §6.2.1 `record_overflow`: routed FIRST so error
            // messages like "decrypted plaintext exceeds maximum length"
            // (which legitimately contain the substring `decrypt`) are
            // not misclassified as `bad_record_mac` by the AEAD branch
            // below. Phase I108: tlsfuzzer test-tls13-record-layer-limits
            // pins this discrimination.
            if m.contains("overflow") || m.contains("too large") || m.contains("exceed") {
                AlertDescription::RecordOverflow
            } else if m.contains("decrypt")
                || m.contains("AEAD")
                || m.contains("tag")
                || m.contains("MAC")
                || m.contains("bad record")
                || m.contains("BadRecordMac")
            {
                AlertDescription::BadRecordMac
            } else if m.contains("decode") || m.contains("incomplete") || m.contains("malformed") {
                AlertDescription::DecodeError
            } else if m.contains("unexpected content type")
                // Phase T126 — RFC 8446 §5.1 / §5.2: an unknown record
                // content type, or a TLS 1.3 inner plaintext with no
                // non-zero type octet (a "zero content type" record),
                // MUST terminate the connection with `unexpected_message`
                // — previously these hit the `internal_error`
                // fall-through below.
                || m.contains("unknown content type")
                || m.contains("unknown inner content type")
                || m.contains("inner plaintext has no content type")
                // RFC 8446 §5.1 — a zero-length Handshake / Alert fragment
                // (forbidden) is also `unexpected_message`.
                || m.contains("unexpected_message")
            {
                AlertDescription::UnexpectedMessage
            } else {
                AlertDescription::InternalError
            }
        }
        TlsError::UnsupportedVersion => AlertDescription::ProtocolVersion,
        TlsError::NoSharedCipherSuite => AlertDescription::HandshakeFailure,
        TlsError::CertVerifyFailed(_) => AlertDescription::BadCertificate,
        TlsError::AlertReceived(_) | TlsError::ConnectionClosed | TlsError::SessionExpired => {
            // Symmetric paths — peer already knows; nothing useful to say.
            AlertDescription::CloseNotify
        }
        TlsError::IoError(_) | TlsError::CryptoError(_) => AlertDescription::InternalError,
    }
}

impl AlertDescription {
    /// Convert from u8 to AlertDescription.
    pub fn from_u8(v: u8) -> Result<Self, u8> {
        match v {
            0 => Ok(AlertDescription::CloseNotify),
            10 => Ok(AlertDescription::UnexpectedMessage),
            20 => Ok(AlertDescription::BadRecordMac),
            21 => Ok(AlertDescription::DecryptionFailed),
            22 => Ok(AlertDescription::RecordOverflow),
            30 => Ok(AlertDescription::DecompressionFailure),
            40 => Ok(AlertDescription::HandshakeFailure),
            41 => Ok(AlertDescription::NoCertificateReserved),
            42 => Ok(AlertDescription::BadCertificate),
            43 => Ok(AlertDescription::UnsupportedCertificate),
            44 => Ok(AlertDescription::CertificateRevoked),
            45 => Ok(AlertDescription::CertificateExpired),
            46 => Ok(AlertDescription::CertificateUnknown),
            47 => Ok(AlertDescription::IllegalParameter),
            48 => Ok(AlertDescription::UnknownCa),
            49 => Ok(AlertDescription::AccessDenied),
            50 => Ok(AlertDescription::DecodeError),
            51 => Ok(AlertDescription::DecryptError),
            60 => Ok(AlertDescription::ExportRestrictionReserved),
            70 => Ok(AlertDescription::ProtocolVersion),
            71 => Ok(AlertDescription::InsufficientSecurity),
            80 => Ok(AlertDescription::InternalError),
            86 => Ok(AlertDescription::InappropriateFallback),
            90 => Ok(AlertDescription::UserCanceled),
            100 => Ok(AlertDescription::NoRenegotiation),
            109 => Ok(AlertDescription::MissingExtension),
            110 => Ok(AlertDescription::UnsupportedExtension),
            111 => Ok(AlertDescription::CertificateUnobtainable),
            112 => Ok(AlertDescription::UnrecognizedName),
            113 => Ok(AlertDescription::BadCertificateStatusResponse),
            114 => Ok(AlertDescription::BadCertificateHashValue),
            115 => Ok(AlertDescription::UnknownPskIdentity),
            116 => Ok(AlertDescription::CertificateRequired),
            120 => Ok(AlertDescription::NoApplicationProtocol),
            _ => Err(v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_supported_version_maps_to_protocol_version() {
        // RFC 8446 §4.2.1 — a ClientHello offering no supported version draws
        // protocol_version (70), not handshake_failure (40). The server raises
        // this exact message; `tls_error_to_alert` routes it via the
        // "protocol version" substring.
        let err = hitls_types::TlsError::HandshakeFailed(
            "client does not support TLS 1.3 — no acceptable protocol version".into(),
        );
        assert_eq!(tls_error_to_alert(&err), AlertDescription::ProtocolVersion);
    }

    #[test]
    fn test_alert_level_values() {
        assert_eq!(AlertLevel::Warning as u8, 1);
        assert_eq!(AlertLevel::Fatal as u8, 2);
    }

    #[test]
    fn test_alert_description_values() {
        assert_eq!(AlertDescription::CloseNotify as u8, 0);
        assert_eq!(AlertDescription::UnexpectedMessage as u8, 10);
        assert_eq!(AlertDescription::BadRecordMac as u8, 20);
        assert_eq!(AlertDescription::DecryptionFailed as u8, 21);
        assert_eq!(AlertDescription::RecordOverflow as u8, 22);
        assert_eq!(AlertDescription::DecompressionFailure as u8, 30);
        assert_eq!(AlertDescription::HandshakeFailure as u8, 40);
        assert_eq!(AlertDescription::NoCertificateReserved as u8, 41);
        assert_eq!(AlertDescription::BadCertificate as u8, 42);
        assert_eq!(AlertDescription::UnknownCa as u8, 48);
        assert_eq!(AlertDescription::DecodeError as u8, 50);
        assert_eq!(AlertDescription::ExportRestrictionReserved as u8, 60);
        assert_eq!(AlertDescription::ProtocolVersion as u8, 70);
        assert_eq!(AlertDescription::InternalError as u8, 80);
        assert_eq!(AlertDescription::CertificateUnobtainable as u8, 111);
        assert_eq!(AlertDescription::UnrecognizedName as u8, 112);
        assert_eq!(AlertDescription::BadCertificateHashValue as u8, 114);
        assert_eq!(AlertDescription::NoApplicationProtocol as u8, 120);
    }

    #[test]
    fn test_alert_description_all_34_variants() {
        let all = [
            AlertDescription::CloseNotify,
            AlertDescription::UnexpectedMessage,
            AlertDescription::BadRecordMac,
            AlertDescription::DecryptionFailed,
            AlertDescription::RecordOverflow,
            AlertDescription::DecompressionFailure,
            AlertDescription::HandshakeFailure,
            AlertDescription::NoCertificateReserved,
            AlertDescription::BadCertificate,
            AlertDescription::UnsupportedCertificate,
            AlertDescription::CertificateRevoked,
            AlertDescription::CertificateExpired,
            AlertDescription::CertificateUnknown,
            AlertDescription::IllegalParameter,
            AlertDescription::UnknownCa,
            AlertDescription::AccessDenied,
            AlertDescription::DecodeError,
            AlertDescription::DecryptError,
            AlertDescription::ExportRestrictionReserved,
            AlertDescription::ProtocolVersion,
            AlertDescription::InsufficientSecurity,
            AlertDescription::InternalError,
            AlertDescription::InappropriateFallback,
            AlertDescription::UserCanceled,
            AlertDescription::NoRenegotiation,
            AlertDescription::MissingExtension,
            AlertDescription::UnsupportedExtension,
            AlertDescription::CertificateUnobtainable,
            AlertDescription::UnrecognizedName,
            AlertDescription::BadCertificateStatusResponse,
            AlertDescription::BadCertificateHashValue,
            AlertDescription::UnknownPskIdentity,
            AlertDescription::CertificateRequired,
            AlertDescription::NoApplicationProtocol,
        ];
        assert_eq!(all.len(), 34);
        // Each variant is distinct
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn test_alert_creation() {
        let alert = Alert {
            level: AlertLevel::Fatal,
            description: AlertDescription::HandshakeFailure,
        };
        assert_eq!(alert.level, AlertLevel::Fatal);
        assert_eq!(alert.description, AlertDescription::HandshakeFailure);
    }

    #[test]
    fn test_alert_debug_display() {
        let alert = Alert {
            level: AlertLevel::Warning,
            description: AlertDescription::CloseNotify,
        };
        let dbg = format!("{:?}", alert);
        assert!(dbg.contains("Warning"));
        assert!(dbg.contains("CloseNotify"));
    }

    #[test]
    fn test_alert_level_from_u8() {
        assert_eq!(AlertLevel::from_u8(1).unwrap(), AlertLevel::Warning);
        assert_eq!(AlertLevel::from_u8(2).unwrap(), AlertLevel::Fatal);
        assert_eq!(AlertLevel::from_u8(0).unwrap_err(), 0);
        assert_eq!(AlertLevel::from_u8(3).unwrap_err(), 3);
        assert_eq!(AlertLevel::from_u8(255).unwrap_err(), 255);
    }

    #[test]
    fn test_alert_description_from_u8_roundtrip() {
        let codes: &[u8] = &[
            0, 10, 20, 21, 22, 30, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 60, 70, 71, 80,
            86, 90, 100, 109, 110, 111, 112, 113, 114, 115, 116, 120,
        ];
        for &code in codes {
            let desc = AlertDescription::from_u8(code).unwrap();
            assert_eq!(desc as u8, code);
        }
    }

    #[test]
    fn test_alert_description_unknown() {
        assert!(AlertDescription::from_u8(1).is_err());
        assert!(AlertDescription::from_u8(5).is_err());
        assert!(AlertDescription::from_u8(99).is_err());
        assert!(AlertDescription::from_u8(255).is_err());
    }

    #[test]
    fn test_legacy_alert_codes() {
        // Verify legacy/deprecated alert codes map correctly
        assert_eq!(
            AlertDescription::from_u8(21).unwrap(),
            AlertDescription::DecryptionFailed
        );
        assert_eq!(
            AlertDescription::from_u8(30).unwrap(),
            AlertDescription::DecompressionFailure
        );
        assert_eq!(
            AlertDescription::from_u8(41).unwrap(),
            AlertDescription::NoCertificateReserved
        );
        assert_eq!(
            AlertDescription::from_u8(60).unwrap(),
            AlertDescription::ExportRestrictionReserved
        );
        assert_eq!(
            AlertDescription::from_u8(111).unwrap(),
            AlertDescription::CertificateUnobtainable
        );
        assert_eq!(
            AlertDescription::from_u8(114).unwrap(),
            AlertDescription::BadCertificateHashValue
        );
    }

    #[test]
    fn test_no_renegotiation_alert() {
        assert_eq!(AlertDescription::NoRenegotiation as u8, 100);
        let desc = AlertDescription::from_u8(100).unwrap();
        assert_eq!(desc, AlertDescription::NoRenegotiation);
    }

    #[test]
    fn test_alert_level_from_u8_all_invalid() {
        // All values except 1 (Warning) and 2 (Fatal) must return Err
        for v in 0..=255u8 {
            if v == 1 || v == 2 {
                assert!(AlertLevel::from_u8(v).is_ok());
            } else {
                assert_eq!(AlertLevel::from_u8(v).unwrap_err(), v);
            }
        }
    }

    #[test]
    fn test_alert_description_undefined_gaps() {
        // Specific gaps in the code space should return Err
        let undefined: &[u8] = &[
            1, 2, 3, 5, 9, 11, 15, 19, 23, 25, 31, 35, 39, 52, 55, 61, 65, 72, 75, 81, 85, 87, 91,
            95, 99, 101, 105, 108, 117, 119, 121, 130, 200, 254, 255,
        ];
        for &code in undefined {
            assert!(
                AlertDescription::from_u8(code).is_err(),
                "code {} should be undefined",
                code,
            );
        }
    }

    #[test]
    fn test_alert_clone_and_copy() {
        let a = Alert {
            level: AlertLevel::Fatal,
            description: AlertDescription::HandshakeFailure,
        };
        let b = a; // Copy
        let c: Alert = {
            // Explicit copy (not clone, to avoid clippy::clone_on_copy)
            Alert {
                level: a.level,
                description: a.description,
            }
        };
        assert_eq!(a.level, b.level);
        assert_eq!(a.description, b.description);
        assert_eq!(a.level, c.level);
        assert_eq!(a.description, c.description);
    }

    #[test]
    fn test_alert_to_bytes_roundtrip() {
        // Serialize alert to 2-byte wire format and parse back
        let alert = Alert {
            level: AlertLevel::Fatal,
            description: AlertDescription::DecodeError,
        };
        let bytes = [alert.level as u8, alert.description as u8];
        assert_eq!(bytes, [2, 50]);
        let level = AlertLevel::from_u8(bytes[0]).unwrap();
        let desc = AlertDescription::from_u8(bytes[1]).unwrap();
        assert_eq!(level, AlertLevel::Fatal);
        assert_eq!(desc, AlertDescription::DecodeError);
    }

    #[test]
    fn test_alert_description_tls13_specific_codes() {
        // TLS 1.3 specific alert codes (RFC 8446)
        assert_eq!(AlertDescription::MissingExtension as u8, 109);
        assert_eq!(AlertDescription::CertificateRequired as u8, 116);
        assert_eq!(AlertDescription::NoApplicationProtocol as u8, 120);

        assert_eq!(
            AlertDescription::from_u8(109).unwrap(),
            AlertDescription::MissingExtension,
        );
        assert_eq!(
            AlertDescription::from_u8(116).unwrap(),
            AlertDescription::CertificateRequired,
        );
        assert_eq!(
            AlertDescription::from_u8(120).unwrap(),
            AlertDescription::NoApplicationProtocol,
        );
    }
}
