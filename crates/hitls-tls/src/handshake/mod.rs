//! TLS handshake protocol state machine.

/// Handshake message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
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
