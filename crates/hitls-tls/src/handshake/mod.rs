//! TLS handshake protocol state machine.

pub mod client;
pub mod client12;
#[cfg(feature = "dtlcp")]
pub mod client_dtlcp;
#[cfg(feature = "dtls12")]
pub mod client_dtls12;
#[cfg(feature = "tlcp")]
pub mod client_tlcp;
pub mod codec;
pub mod codec12;
#[cfg(feature = "dtls12")]
pub mod codec_dtls;
#[cfg(feature = "tlcp")]
pub mod codec_tlcp;
pub mod extensions_codec;
#[cfg(feature = "dtls12")]
pub mod fragment;
pub mod key_exchange;
#[cfg(feature = "dtls12")]
pub mod retransmit;
pub mod server;
pub mod server12;
#[cfg(feature = "dtlcp")]
pub mod server_dtlcp;
#[cfg(feature = "dtls12")]
pub mod server_dtls12;
#[cfg(feature = "tlcp")]
pub mod server_tlcp;
pub mod signing;
pub mod verify;

/// Handshake message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    CertificateStatus = 22,
    KeyUpdate = 24,
    CompressedCertificate = 25,
    MessageHash = 254,
}

/// Handshake state for the TLS state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state before handshake.
    Idle,
    /// Client: waiting for ServerHello.
    WaitServerHello,
    /// Client: waiting for EncryptedExtensions.
    WaitEncryptedExtensions,
    /// Client: waiting for Certificate/CertificateRequest.
    WaitCertCertReq,
    /// Client: waiting for CertificateVerify.
    WaitCertVerify,
    /// Client: waiting for Finished.
    WaitFinished,
    /// Server: waiting for ClientHello.
    WaitClientHello,
    /// Server: waiting for retried ClientHello after HRR.
    WaitClientHelloRetry,
    /// Server: waiting for client Finished.
    WaitClientFinished,
    /// Handshake complete.
    Connected,
    /// Connection closed.
    Closed,
    /// Error state.
    Error,
}

/// A parsed handshake message.
#[derive(Debug, Clone)]
pub struct HandshakeMessage {
    pub msg_type: HandshakeType,
    pub body: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_type_discriminant_values() {
        // RFC 8446 §4 / RFC 5246 §7.4 — wire values are security-critical
        assert_eq!(HandshakeType::HelloRequest as u8, 0);
        assert_eq!(HandshakeType::ClientHello as u8, 1);
        assert_eq!(HandshakeType::ServerHello as u8, 2);
        assert_eq!(HandshakeType::HelloVerifyRequest as u8, 3);
        assert_eq!(HandshakeType::NewSessionTicket as u8, 4);
        assert_eq!(HandshakeType::EndOfEarlyData as u8, 5);
        assert_eq!(HandshakeType::EncryptedExtensions as u8, 8);
        assert_eq!(HandshakeType::Certificate as u8, 11);
        assert_eq!(HandshakeType::ServerKeyExchange as u8, 12);
        assert_eq!(HandshakeType::CertificateRequest as u8, 13);
        assert_eq!(HandshakeType::ServerHelloDone as u8, 14);
        assert_eq!(HandshakeType::CertificateVerify as u8, 15);
        assert_eq!(HandshakeType::ClientKeyExchange as u8, 16);
        assert_eq!(HandshakeType::Finished as u8, 20);
        assert_eq!(HandshakeType::CertificateStatus as u8, 22);
        assert_eq!(HandshakeType::KeyUpdate as u8, 24);
        assert_eq!(HandshakeType::CompressedCertificate as u8, 25);
        assert_eq!(HandshakeType::MessageHash as u8, 254);
    }

    #[test]
    fn test_handshake_type_all_variants_distinct() {
        let types: Vec<u8> = vec![
            HandshakeType::HelloRequest as u8,
            HandshakeType::ClientHello as u8,
            HandshakeType::ServerHello as u8,
            HandshakeType::HelloVerifyRequest as u8,
            HandshakeType::NewSessionTicket as u8,
            HandshakeType::EndOfEarlyData as u8,
            HandshakeType::EncryptedExtensions as u8,
            HandshakeType::Certificate as u8,
            HandshakeType::ServerKeyExchange as u8,
            HandshakeType::CertificateRequest as u8,
            HandshakeType::ServerHelloDone as u8,
            HandshakeType::CertificateVerify as u8,
            HandshakeType::ClientKeyExchange as u8,
            HandshakeType::Finished as u8,
            HandshakeType::CertificateStatus as u8,
            HandshakeType::KeyUpdate as u8,
            HandshakeType::CompressedCertificate as u8,
            HandshakeType::MessageHash as u8,
        ];
        for i in 0..types.len() {
            for j in (i + 1)..types.len() {
                assert_ne!(types[i], types[j], "types[{i}] == types[{j}]");
            }
        }
    }

    #[test]
    fn test_handshake_state_all_variants() {
        let states = [
            HandshakeState::Idle,
            HandshakeState::WaitServerHello,
            HandshakeState::WaitEncryptedExtensions,
            HandshakeState::WaitCertCertReq,
            HandshakeState::WaitCertVerify,
            HandshakeState::WaitFinished,
            HandshakeState::WaitClientHello,
            HandshakeState::WaitClientHelloRetry,
            HandshakeState::WaitClientFinished,
            HandshakeState::Connected,
            HandshakeState::Closed,
            HandshakeState::Error,
        ];
        // All 12 variants are distinct
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(states[i], states[j]);
            }
        }
        assert_eq!(states.len(), 12);
    }

    #[test]
    fn test_handshake_type_debug_and_clone() {
        let t = HandshakeType::ClientHello;
        let t2 = t;
        assert_eq!(t, t2);
        assert_eq!(format!("{t:?}"), "ClientHello");

        let t3 = HandshakeType::Finished;
        assert_eq!(format!("{t3:?}"), "Finished");
    }

    #[test]
    fn test_handshake_message_construction_and_clone() {
        let msg = HandshakeMessage {
            msg_type: HandshakeType::ClientHello,
            body: vec![0x01, 0x02, 0x03, 0x04],
        };

        assert_eq!(msg.msg_type, HandshakeType::ClientHello);
        assert_eq!(msg.body, vec![0x01, 0x02, 0x03, 0x04]);

        let cloned = msg.clone();
        assert_eq!(cloned.msg_type, msg.msg_type);
        assert_eq!(cloned.body, msg.body);

        let debug = format!("{msg:?}");
        assert!(debug.contains("HandshakeMessage"));
        assert!(debug.contains("ClientHello"));
    }
}
