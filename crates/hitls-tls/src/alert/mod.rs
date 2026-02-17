//! TLS alert protocol.

/// Alert severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

/// Alert description codes (RFC 8446 Section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
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
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    NoRenegotiation = 100,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
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

impl AlertDescription {
    /// Convert from u8 to AlertDescription.
    pub fn from_u8(v: u8) -> Result<Self, u8> {
        match v {
            0 => Ok(AlertDescription::CloseNotify),
            10 => Ok(AlertDescription::UnexpectedMessage),
            20 => Ok(AlertDescription::BadRecordMac),
            22 => Ok(AlertDescription::RecordOverflow),
            40 => Ok(AlertDescription::HandshakeFailure),
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
            70 => Ok(AlertDescription::ProtocolVersion),
            71 => Ok(AlertDescription::InsufficientSecurity),
            80 => Ok(AlertDescription::InternalError),
            86 => Ok(AlertDescription::InappropriateFallback),
            90 => Ok(AlertDescription::UserCanceled),
            100 => Ok(AlertDescription::NoRenegotiation),
            109 => Ok(AlertDescription::MissingExtension),
            110 => Ok(AlertDescription::UnsupportedExtension),
            112 => Ok(AlertDescription::UnrecognizedName),
            113 => Ok(AlertDescription::BadCertificateStatusResponse),
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
    fn test_alert_level_values() {
        assert_eq!(AlertLevel::Warning as u8, 1);
        assert_eq!(AlertLevel::Fatal as u8, 2);
    }

    #[test]
    fn test_alert_description_values() {
        assert_eq!(AlertDescription::CloseNotify as u8, 0);
        assert_eq!(AlertDescription::UnexpectedMessage as u8, 10);
        assert_eq!(AlertDescription::BadRecordMac as u8, 20);
        assert_eq!(AlertDescription::RecordOverflow as u8, 22);
        assert_eq!(AlertDescription::HandshakeFailure as u8, 40);
        assert_eq!(AlertDescription::BadCertificate as u8, 42);
        assert_eq!(AlertDescription::UnknownCa as u8, 48);
        assert_eq!(AlertDescription::DecodeError as u8, 50);
        assert_eq!(AlertDescription::ProtocolVersion as u8, 70);
        assert_eq!(AlertDescription::InternalError as u8, 80);
        assert_eq!(AlertDescription::UnrecognizedName as u8, 112);
        assert_eq!(AlertDescription::NoApplicationProtocol as u8, 120);
    }

    #[test]
    fn test_alert_description_all_28_variants() {
        let all = [
            AlertDescription::CloseNotify,
            AlertDescription::UnexpectedMessage,
            AlertDescription::BadRecordMac,
            AlertDescription::RecordOverflow,
            AlertDescription::HandshakeFailure,
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
            AlertDescription::ProtocolVersion,
            AlertDescription::InsufficientSecurity,
            AlertDescription::InternalError,
            AlertDescription::InappropriateFallback,
            AlertDescription::UserCanceled,
            AlertDescription::NoRenegotiation,
            AlertDescription::MissingExtension,
            AlertDescription::UnsupportedExtension,
            AlertDescription::UnrecognizedName,
            AlertDescription::BadCertificateStatusResponse,
            AlertDescription::UnknownPskIdentity,
            AlertDescription::CertificateRequired,
            AlertDescription::NoApplicationProtocol,
        ];
        assert_eq!(all.len(), 28);
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
            0, 10, 20, 22, 40, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 70, 71, 80, 86, 90, 100,
            109, 110, 112, 113, 115, 116, 120,
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
    fn test_no_renegotiation_alert() {
        assert_eq!(AlertDescription::NoRenegotiation as u8, 100);
        let desc = AlertDescription::from_u8(100).unwrap();
        assert_eq!(desc, AlertDescription::NoRenegotiation);
    }
}
