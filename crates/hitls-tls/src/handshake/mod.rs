//! TLS handshake protocol state machine.

pub mod client;
pub mod client12;
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
