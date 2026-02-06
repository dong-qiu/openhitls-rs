//! PKCS#12 (PFX) container format.

use hitls_types::PkiError;

/// A parsed PKCS#12 container.
#[derive(Debug)]
pub struct Pkcs12 {
    /// Private key (DER-encoded).
    pub private_key: Option<Vec<u8>>,
    /// Certificate chain.
    pub certificates: Vec<Vec<u8>>,
}

impl Pkcs12 {
    /// Parse a PKCS#12 file from DER-encoded bytes with a password.
    pub fn from_der(_data: &[u8], _password: &str) -> Result<Self, PkiError> {
        todo!("PKCS#12 parsing")
    }

    /// Create a PKCS#12 container.
    pub fn new(
        _private_key: Option<&[u8]>,
        _certificates: &[&[u8]],
        _password: &str,
    ) -> Result<Vec<u8>, PkiError> {
        todo!("PKCS#12 creation")
    }
}
