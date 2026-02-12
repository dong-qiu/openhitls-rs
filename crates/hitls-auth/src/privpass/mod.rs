//! Privacy Pass token issuance and redemption (RFC 9578 Type 2).
//!
//! Implements publicly verifiable tokens using RSA blind signatures.
//!
//! ## Protocol Flow
//!
//! ```text
//! Client -> Issuer:  TokenRequest { blinded_element = H(token_input) * r^e mod n }
//! Issuer -> Client:  TokenResponse { blind_sig = blinded_element^d mod n }
//! Client:            sig = blind_sig * r^(-1) mod n
//! Verifier:          sig^e mod n == H(token_input)  (standard RSA verify)
//! ```
//!
//! Where `token_input = 0x0002 || nonce(32) || challenge_digest(32) || token_key_id(32)`.

use hitls_bignum::BigNum;
use hitls_crypto::sha2::Sha256;
use hitls_types::CryptoError;

/// Privacy Pass token type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// Publicly verifiable token (type 0x0002).
    PubliclyVerifiable,
    /// Privately verifiable token (type 0x0001).
    PrivatelyVerifiable,
}

impl TokenType {
    /// Return the two-byte wire encoding of this token type.
    pub fn to_wire(&self) -> [u8; 2] {
        match self {
            TokenType::PubliclyVerifiable => [0x00, 0x02],
            TokenType::PrivatelyVerifiable => [0x00, 0x01],
        }
    }

    /// Parse a token type from its two-byte wire encoding.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 2 {
            return Err(CryptoError::InvalidArg);
        }
        match (bytes[0], bytes[1]) {
            (0x00, 0x02) => Ok(TokenType::PubliclyVerifiable),
            (0x00, 0x01) => Ok(TokenType::PrivatelyVerifiable),
            _ => Err(CryptoError::InvalidArg),
        }
    }
}

/// Privacy Pass token request (sent from Client to Issuer).
#[derive(Debug, Clone)]
pub struct TokenRequest {
    /// The token type being requested.
    pub token_type: TokenType,
    /// The blinded element: `H(token_input) * r^e mod n`, serialized as big-endian bytes.
    pub blinded_element: Vec<u8>,
}

/// Privacy Pass token response (sent from Issuer to Client).
#[derive(Debug, Clone)]
pub struct TokenResponse {
    /// The blind signature: `blinded_element^d mod n`, serialized as big-endian bytes.
    pub blind_sig: Vec<u8>,
}

/// Privacy Pass token (final artifact held by Client, presented to Verifier).
#[derive(Debug, Clone)]
pub struct Token {
    /// The token type.
    pub token_type: TokenType,
    /// The 32-byte random nonce.
    pub nonce: Vec<u8>,
    /// The RSA signature (authenticator): `blind_sig * r^(-1) mod n`.
    pub authenticator: Vec<u8>,
}

/// Client-side blinding state, kept between `create_token_request` and `finalize_token`.
///
/// Contains the nonce, the blinding factor inverse, and the original `token_input`
/// so that the client can unblind the issuer's response and construct the final token.
pub struct BlindState {
    /// The 32-byte random nonce used in `token_input`.
    nonce: [u8; 32],
    /// The modular inverse of the blinding factor: `r^(-1) mod n`.
    blind_inv: BigNum,
    /// The full `token_input` bytes: `0x0002 || nonce || challenge_digest || token_key_id`.
    token_input: Vec<u8>,
}

/// Privacy Pass Issuer (holds the RSA private key, signs blinded requests).
pub struct Issuer {
    /// RSA modulus.
    n: BigNum,
    /// RSA private exponent.
    d: BigNum,
    /// RSA public exponent.
    e: BigNum,
    /// SHA-256 hash of `n_bytes || e_bytes`, identifying this issuer's key.
    token_key_id: [u8; 32],
}

impl Issuer {
    /// Create a new Issuer from RSA key components (big-endian bytes).
    ///
    /// `n` is the RSA modulus, `d` is the private exponent, `e` is the public exponent.
    pub fn new(n: &[u8], d: &[u8], e: &[u8]) -> Result<Self, CryptoError> {
        let n_bn = BigNum::from_bytes_be(n);
        let d_bn = BigNum::from_bytes_be(d);
        let e_bn = BigNum::from_bytes_be(e);

        if n_bn.is_zero() || n_bn.is_even() {
            return Err(CryptoError::InvalidKey);
        }
        if d_bn.is_zero() {
            return Err(CryptoError::InvalidKey);
        }
        if e_bn.is_zero() || e_bn.is_even() {
            return Err(CryptoError::InvalidKey);
        }

        let token_key_id = compute_token_key_id(n, e)?;

        Ok(Issuer {
            n: n_bn,
            d: d_bn,
            e: e_bn,
            token_key_id,
        })
    }

    /// Issue a blind signature on a token request.
    ///
    /// Computes `blind_sig = blinded_element^d mod n` and returns it in a `TokenResponse`.
    pub fn issue(&self, request: &TokenRequest) -> Result<TokenResponse, CryptoError> {
        if request.token_type != TokenType::PubliclyVerifiable {
            return Err(CryptoError::InvalidArg);
        }

        let blinded = BigNum::from_bytes_be(&request.blinded_element);

        // Validate: blinded_element must be in [1, n-1]
        if blinded.is_zero() || blinded >= self.n {
            return Err(CryptoError::InvalidArg);
        }

        // blind_sig = blinded_element^d mod n
        let blind_sig = blinded.mod_exp(&self.d, &self.n)?;

        let n_len = self.n.bit_len().div_ceil(8);
        Ok(TokenResponse {
            blind_sig: blind_sig.to_bytes_be_padded(n_len)?,
        })
    }

    /// Return the token key ID (SHA-256 of n || e).
    pub fn token_key_id(&self) -> &[u8; 32] {
        &self.token_key_id
    }
}

/// Privacy Pass Client (holds the RSA public key, creates blinded requests and unblinds responses).
pub struct Client {
    /// RSA modulus.
    n: BigNum,
    /// RSA public exponent.
    e: BigNum,
    /// SHA-256 hash of `n_bytes || e_bytes`.
    token_key_id: [u8; 32],
}

impl Client {
    /// Create a new Client from RSA public key components (big-endian bytes).
    ///
    /// `n` is the RSA modulus, `e` is the public exponent.
    pub fn new(n: &[u8], e: &[u8]) -> Result<Self, CryptoError> {
        let n_bn = BigNum::from_bytes_be(n);
        let e_bn = BigNum::from_bytes_be(e);

        if n_bn.is_zero() || n_bn.is_even() {
            return Err(CryptoError::InvalidKey);
        }
        if e_bn.is_zero() || e_bn.is_even() {
            return Err(CryptoError::InvalidKey);
        }

        let token_key_id = compute_token_key_id(n, e)?;

        Ok(Client {
            n: n_bn,
            e: e_bn,
            token_key_id,
        })
    }

    /// Create a blinded token request for the given challenge.
    ///
    /// Returns a `TokenRequest` to send to the issuer and a `BlindState` to keep locally
    /// for unblinding the response.
    ///
    /// Steps:
    /// 1. Generate a random 32-byte nonce.
    /// 2. Compute `challenge_digest = SHA-256(challenge)`.
    /// 3. Build `token_input = 0x0002 || nonce || challenge_digest || token_key_id`.
    /// 4. Compute `msg_hash = SHA-256(token_input)`.
    /// 5. Generate a random blinding factor `r` coprime to `n`.
    /// 6. Compute `blinded = msg_hash * r^e mod n`.
    /// 7. Store `r^(-1) mod n` in `BlindState`.
    pub fn create_token_request(
        &self,
        challenge: &[u8],
    ) -> Result<(TokenRequest, BlindState), CryptoError> {
        // Step 1: Generate random nonce
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| CryptoError::BnRandGenFail)?;

        // Step 2: Compute challenge_digest = SHA-256(challenge)
        let challenge_digest = Sha256::digest(challenge)?;

        // Step 3: Build token_input = 0x0002 || nonce || challenge_digest || token_key_id
        let mut token_input = Vec::with_capacity(2 + 32 + 32 + 32);
        token_input.extend_from_slice(&[0x00, 0x02]); // PubliclyVerifiable type
        token_input.extend_from_slice(&nonce);
        token_input.extend_from_slice(&challenge_digest);
        token_input.extend_from_slice(&self.token_key_id);

        // Step 4: Compute msg_hash = SHA-256(token_input) and convert to BigNum
        let msg_hash = Sha256::digest(&token_input)?;
        let m = BigNum::from_bytes_be(&msg_hash);

        // Step 5: Generate random blinding factor r coprime to n
        let (r, r_inv) = generate_blind_factor(&self.n)?;

        // Step 6: Compute blinded = m * r^e mod n
        let r_e = r.mod_exp(&self.e, &self.n)?;
        let blinded = m.mul(&r_e).mod_reduce(&self.n)?;

        let n_len = self.n.bit_len().div_ceil(8);

        // Step 7: Build request and blind state
        let request = TokenRequest {
            token_type: TokenType::PubliclyVerifiable,
            blinded_element: blinded.to_bytes_be_padded(n_len)?,
        };

        let state = BlindState {
            nonce,
            blind_inv: r_inv,
            token_input,
        };

        Ok((request, state))
    }

    /// Finalize a token by unblinding the issuer's response.
    ///
    /// Computes `sig = blind_sig * r_inv mod n` and returns the final `Token`.
    pub fn finalize_token(
        &self,
        response: &TokenResponse,
        state: BlindState,
    ) -> Result<Token, CryptoError> {
        let blind_sig = BigNum::from_bytes_be(&response.blind_sig);

        // Validate: blind_sig must be in [1, n-1]
        if blind_sig.is_zero() || blind_sig >= self.n {
            return Err(CryptoError::InvalidArg);
        }

        // Unblind: sig = blind_sig * r_inv mod n
        let sig = blind_sig.mul(&state.blind_inv).mod_reduce(&self.n)?;

        let n_len = self.n.bit_len().div_ceil(8);

        Ok(Token {
            token_type: TokenType::PubliclyVerifiable,
            nonce: state.nonce.to_vec(),
            authenticator: sig.to_bytes_be_padded(n_len)?,
        })
    }
}

/// Verify a Privacy Pass token.
///
/// The verifier must know the challenge that was originally used to create the token,
/// plus the issuer's RSA public key (`n`, `e`).
///
/// Verification steps:
/// 1. Recompute `token_key_id = SHA-256(n || e)`.
/// 2. Recompute `challenge_digest = SHA-256(challenge)`.
/// 3. Rebuild `token_input = 0x0002 || nonce || challenge_digest || token_key_id`.
/// 4. Compute `expected = SHA-256(token_input)`.
/// 5. Compute `recovered = sig^e mod n`.
/// 6. Compare `recovered == expected`.
pub fn verify_token(
    token: &Token,
    n: &[u8],
    e: &[u8],
    challenge: &[u8],
) -> Result<bool, CryptoError> {
    if token.token_type != TokenType::PubliclyVerifiable {
        return Err(CryptoError::InvalidArg);
    }

    if token.nonce.len() != 32 {
        return Err(CryptoError::InvalidArg);
    }

    let n_bn = BigNum::from_bytes_be(n);
    let e_bn = BigNum::from_bytes_be(e);

    if n_bn.is_zero() || n_bn.is_even() {
        return Err(CryptoError::InvalidKey);
    }
    if e_bn.is_zero() || e_bn.is_even() {
        return Err(CryptoError::InvalidKey);
    }

    // Step 1: Recompute token_key_id
    let token_key_id = compute_token_key_id(n, e)?;

    // Step 2: Recompute challenge_digest
    let challenge_digest = Sha256::digest(challenge)?;

    // Step 3: Rebuild token_input
    let mut token_input = Vec::with_capacity(2 + 32 + 32 + 32);
    token_input.extend_from_slice(&[0x00, 0x02]);
    token_input.extend_from_slice(&token.nonce);
    token_input.extend_from_slice(&challenge_digest);
    token_input.extend_from_slice(&token_key_id);

    // Step 4: Compute expected hash
    let expected = Sha256::digest(&token_input)?;
    let expected_bn = BigNum::from_bytes_be(&expected);

    // Step 5: Compute recovered = sig^e mod n
    let sig = BigNum::from_bytes_be(&token.authenticator);
    if sig.is_zero() || sig >= n_bn {
        return Ok(false);
    }
    let recovered = sig.mod_exp(&e_bn, &n_bn)?;

    // Step 6: Compare (constant-time via subtle)
    let expected_bytes = expected_bn.to_bytes_be();
    let recovered_bytes = recovered.to_bytes_be();

    // Pad both to the same length for constant-time comparison
    let max_len = expected_bytes.len().max(recovered_bytes.len());
    let mut expected_padded = vec![0u8; max_len];
    let mut recovered_padded = vec![0u8; max_len];
    expected_padded[max_len - expected_bytes.len()..].copy_from_slice(&expected_bytes);
    recovered_padded[max_len - recovered_bytes.len()..].copy_from_slice(&recovered_bytes);

    use subtle::ConstantTimeEq;
    let eq: bool = expected_padded.ct_eq(&recovered_padded).into();
    Ok(eq)
}

/// Compute `token_key_id = SHA-256(n_bytes || e_bytes)`.
fn compute_token_key_id(n: &[u8], e: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut hasher = Sha256::new();
    hasher.update(n)?;
    hasher.update(e)?;
    hasher.finish()
}

/// Generate a random blinding factor `r` in [2, n-1] that is coprime to `n`.
///
/// Returns `(r, r_inv)` where `r_inv = r^(-1) mod n`.
fn generate_blind_factor(n: &BigNum) -> Result<(BigNum, BigNum), CryptoError> {
    let one = BigNum::from_u64(1);

    for _ in 0..1000 {
        // Generate random r in [1, n-1]
        let r = BigNum::random_range(n)?;
        if r.is_zero() || r.is_one() {
            continue;
        }

        // Check gcd(r, n) == 1
        let g = r.gcd(n)?;
        if !g.is_one() {
            continue;
        }

        // Compute r_inv = r^(-1) mod n
        let r_inv = r.mod_inv(n)?;

        // Verify: r * r_inv mod n == 1
        let check = r.mul(&r_inv).mod_reduce(n)?;
        if check != one {
            continue;
        }

        return Ok((r, r_inv));
    }

    Err(CryptoError::BnRandGenFail)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: hex string to bytes.
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // A valid RSA-1024 key for testing (same as hitls-crypto RSA test key).
    // NOT for production use -- 1024-bit RSA is insecure.
    fn test_key_1024() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let n = hex(
            "00d531c26a4cc6443cca66325ba2746a7eaf0423112d1aa222c8a89f5bb8d12c\
             3dccf8386a53b9aa4d1cfbe5b17ddb8a329732110aa1dd06c55dccb849e5ffc8\
             b2c213bdc95d8fe28e4b75b483b95b7d4cde85ab58dd9cc2b741b79b74c0d09c\
             df85612ca1793d16e28e8d98af311ac3b242c074e551767d0659e9fbaae940c091",
        );
        let e = hex("010001");
        let d = hex(
            "0df14923a68db8dcb8e7e2173812a0fc53f9d3494647dd9ea4bcd25f2f410ec1\
             a3ebffd484513a1ffceb44644d34d45ee6a07198de69140e484a212b440d6c54\
             95e905a5294f7f30066100900603b9f68d2c23d149bb3a09393bca9b09a6d479\
             dd953b76884fb7127db6d169fd7bbdfa5fcd8047876d965d936e819232622cb9",
        );
        (n, e, d)
    }

    #[test]
    fn test_privpass_issue_verify_roundtrip() {
        let (n, e, d) = test_key_1024();

        let issuer = Issuer::new(&n, &d, &e).unwrap();
        let client = Client::new(&n, &e).unwrap();

        let challenge = b"example.com challenge nonce xyz";

        // Client creates blinded token request
        let (request, state) = client.create_token_request(challenge).unwrap();
        assert_eq!(request.token_type, TokenType::PubliclyVerifiable);
        assert!(!request.blinded_element.is_empty());

        // Issuer signs the blinded request
        let response = issuer.issue(&request).unwrap();
        assert!(!response.blind_sig.is_empty());

        // Client unblinds the response to get the final token
        let token = client.finalize_token(&response, state).unwrap();
        assert_eq!(token.token_type, TokenType::PubliclyVerifiable);
        assert_eq!(token.nonce.len(), 32);
        assert!(!token.authenticator.is_empty());

        // Verifier checks the token
        let valid = verify_token(&token, &n, &e, challenge).unwrap();
        assert!(valid, "Token should verify successfully");
    }

    #[test]
    fn test_privpass_invalid_token() {
        let (n, e, d) = test_key_1024();

        let issuer = Issuer::new(&n, &d, &e).unwrap();
        let client = Client::new(&n, &e).unwrap();

        let challenge = b"test challenge";

        let (request, state) = client.create_token_request(challenge).unwrap();
        let response = issuer.issue(&request).unwrap();
        let mut token = client.finalize_token(&response, state).unwrap();

        // Tamper with the authenticator
        if let Some(byte) = token.authenticator.last_mut() {
            *byte ^= 0x01;
        }

        let valid = verify_token(&token, &n, &e, challenge).unwrap();
        assert!(!valid, "Tampered token should NOT verify");
    }

    #[test]
    fn test_privpass_wrong_key() {
        let (n, e, d) = test_key_1024();

        let issuer = Issuer::new(&n, &d, &e).unwrap();
        let client = Client::new(&n, &e).unwrap();

        let challenge = b"test challenge for wrong key";

        let (request, state) = client.create_token_request(challenge).unwrap();
        let response = issuer.issue(&request).unwrap();
        let token = client.finalize_token(&response, state).unwrap();

        // Verify with a different (wrong) public exponent
        // Use e=3 instead of e=65537
        let wrong_e = vec![0x03];
        let result = verify_token(&token, &n, &wrong_e, challenge).unwrap();
        assert!(!result, "Token verified with wrong key should fail");
    }

    #[test]
    fn test_privpass_token_type_encoding() {
        // Test wire format values
        assert_eq!(TokenType::PubliclyVerifiable.to_wire(), [0x00, 0x02],);
        assert_eq!(TokenType::PrivatelyVerifiable.to_wire(), [0x00, 0x01],);

        // Round-trip
        let pv = TokenType::from_wire(&[0x00, 0x02]).unwrap();
        assert_eq!(pv, TokenType::PubliclyVerifiable);

        let priv_v = TokenType::from_wire(&[0x00, 0x01]).unwrap();
        assert_eq!(priv_v, TokenType::PrivatelyVerifiable);

        // Invalid wire encoding
        assert!(TokenType::from_wire(&[0x00, 0x03]).is_err());
        assert!(TokenType::from_wire(&[0x00]).is_err());
    }
}
