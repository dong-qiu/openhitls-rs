//! SPAKE2+ password-authenticated key exchange (RFC 9382).

use hitls_types::CryptoError;

/// SPAKE2+ protocol role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spake2Role {
    Prover,
    Verifier,
}

/// SPAKE2+ protocol context.
pub struct Spake2Plus {
    role: Spake2Role,
}

impl Spake2Plus {
    /// Create a new SPAKE2+ context.
    pub fn new(role: Spake2Role) -> Self {
        Self { role }
    }

    /// Generate the SPAKE2+ share (pA or pB).
    pub fn generate_share(&mut self, _password: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("SPAKE2+ share generation")
    }

    /// Process the peer's share and compute the shared secret.
    pub fn process_share(&mut self, _peer_share: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("SPAKE2+ share processing")
    }

    /// Get the confirmation value for key confirmation.
    pub fn get_confirmation(&self) -> Result<Vec<u8>, CryptoError> {
        todo!("SPAKE2+ confirmation")
    }

    /// Verify the peer's confirmation value.
    pub fn verify_confirmation(&self, _confirmation: &[u8]) -> Result<bool, CryptoError> {
        todo!("SPAKE2+ confirmation verification")
    }
}
