//! Privacy Pass token issuance and redemption.

use hitls_types::CryptoError;

/// Privacy Pass token type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// Publicly verifiable token (type 0x0002).
    PubliclyVerifiable,
    /// Privately verifiable token (type 0x0001).
    PrivatelyVerifiable,
}

/// Privacy Pass token request.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub token_type: TokenType,
    pub blinded_element: Vec<u8>,
}

/// Privacy Pass token.
#[derive(Debug, Clone)]
pub struct Token {
    pub token_type: TokenType,
    pub nonce: Vec<u8>,
    pub authenticator: Vec<u8>,
}

/// Issue a Privacy Pass token.
pub fn issue_token(_request: &TokenRequest) -> Result<Token, CryptoError> {
    todo!("Privacy Pass token issuance")
}

/// Verify a Privacy Pass token.
pub fn verify_token(_token: &Token) -> Result<bool, CryptoError> {
    todo!("Privacy Pass token verification")
}
