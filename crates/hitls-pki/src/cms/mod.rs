//! CMS (Cryptographic Message Syntax) / PKCS#7.

use hitls_types::PkiError;

/// CMS content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmsContentType {
    Data,
    SignedData,
    EnvelopedData,
    DigestedData,
    EncryptedData,
    AuthenticatedData,
}

/// A CMS message.
#[derive(Debug)]
pub struct CmsMessage {
    pub content_type: CmsContentType,
    pub raw: Vec<u8>,
}

impl CmsMessage {
    /// Parse a CMS message from DER-encoded bytes.
    pub fn from_der(_data: &[u8]) -> Result<Self, PkiError> {
        todo!("CMS DER parsing")
    }

    /// Parse a CMS message from PEM.
    pub fn from_pem(_pem: &str) -> Result<Self, PkiError> {
        todo!("CMS PEM parsing")
    }
}
