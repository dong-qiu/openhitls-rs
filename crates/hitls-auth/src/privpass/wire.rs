//! RFC 9577 / RFC 9578 Privacy Pass wire serialization.
//!
//! Byte-exact `serialize` / `deserialize` for the Privacy Pass token-protocol
//! structures, matching the openHiTLS C `HITLS_AUTH_PrivPassSerialization` /
//! `HITLS_AUTH_PrivPassDeserialization` wire format:
//!
//! - [`TokenChallengeRequest`] — `uint16 token_type` (RFC 9577 §2.1, a bare
//!   2-byte type advertising which token type the origin will accept).
//! - [`TokenChallenge`] — RFC 9577 §2.1:
//!   `token_type(2) ‖ u16-len issuer_name ‖ u8-len redemption_context(0|32)
//!   ‖ u16-len origin_info`.
//! - [`TokenRequest`] — RFC 9578 §5.2:
//!   `token_type(2) ‖ truncated_token_key_id(1) ‖ blinded_msg`.
//! - [`TokenResponse`] — RFC 9578 §5.3: the raw `blind_sig` bytes.
//! - [`Token`] — RFC 9578 §5.4:
//!   `token_type(2) ‖ nonce(32) ‖ challenge_digest(32) ‖ token_key_id(32)
//!   ‖ authenticator`.
//!
//! These are the wire-level structures (independent of the issuance-flow types
//! in the parent module, which carry only the fields the RSA-BSSA flow needs).
//! `deserialize` is strict: it rejects trailing bytes, truncated buffers, and
//! out-of-range length prefixes, so malformed inputs do not silently parse.

use hitls_types::CryptoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

const NONCE_LEN: usize = 32;
const DIGEST_LEN: usize = 32;
const KEY_ID_LEN: usize = 32;

/// A cursor over a byte buffer with strict bounds-checked reads.
struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, off: 0 }
    }

    fn u16(&mut self) -> Result<u16, CryptoError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u8(&mut self) -> Result<u8, CryptoError> {
        Ok(self.bytes(1)?[0])
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], CryptoError> {
        let end = self.off.checked_add(n).ok_or(CryptoError::InvalidArg(""))?;
        if end > self.buf.len() {
            return Err(CryptoError::InvalidArg(""));
        }
        let out = &self.buf[self.off..end];
        self.off = end;
        Ok(out)
    }

    /// All remaining (unconsumed) bytes.
    fn rest(&mut self) -> &'a [u8] {
        // Invariant: every read advances `off` by a bounds-checked amount, so
        // `off <= buf.len()` always holds and this slice never panics.
        debug_assert!(self.off <= self.buf.len());
        let out = &self.buf[self.off..];
        self.off = self.buf.len();
        out
    }

    /// Require that the whole buffer was consumed (no trailing bytes).
    fn finish(&self) -> Result<(), CryptoError> {
        if self.off == self.buf.len() {
            Ok(())
        } else {
            Err(CryptoError::InvalidArg(""))
        }
    }
}

/// RFC 9577 §2.1 TokenChallengeRequest — a bare `uint16 token_type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenChallengeRequest {
    /// The advertised token type.
    pub token_type: u16,
}

impl TokenChallengeRequest {
    /// Serialize to the 2-byte wire form.
    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.token_type.to_be_bytes().to_vec())
    }

    /// Parse from the 2-byte wire form (rejects any other length).
    pub fn deserialize(buf: &[u8]) -> Result<Self, CryptoError> {
        let mut r = Reader::new(buf);
        let token_type = r.u16()?;
        r.finish()?;
        Ok(Self { token_type })
    }
}

/// RFC 9577 §2.1 TokenChallenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenChallenge {
    /// The token type.
    pub token_type: u16,
    /// Issuer name (`<1..2^16-1>` on the wire; not length-restricted here).
    pub issuer_name: Vec<u8>,
    /// Redemption context — exactly 0 or 32 bytes per RFC 9577.
    pub redemption_context: Vec<u8>,
    /// Origin info (`<0..2^16-1>`).
    pub origin_info: Vec<u8>,
}

impl TokenChallenge {
    /// Serialize to the RFC 9577 §2.1 wire form.
    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
        // RFC 9577 §2.1: issuer_name is `opaque issuer_name<1..2^16-1>` (≥ 1).
        if self.issuer_name.is_empty()
            || self.issuer_name.len() > u16::MAX as usize
            || self.origin_info.len() > u16::MAX as usize
        {
            return Err(CryptoError::InvalidArg(""));
        }
        if !self.redemption_context.is_empty() && self.redemption_context.len() != KEY_ID_LEN {
            return Err(CryptoError::InvalidArg(""));
        }
        let mut out = Vec::new();
        out.extend_from_slice(&self.token_type.to_be_bytes());
        out.extend_from_slice(&(self.issuer_name.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.issuer_name);
        out.push(self.redemption_context.len() as u8);
        out.extend_from_slice(&self.redemption_context);
        out.extend_from_slice(&(self.origin_info.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.origin_info);
        Ok(out)
    }

    /// Parse from the RFC 9577 §2.1 wire form. Rejects a `redemption_context`
    /// length other than 0 or 32, and any trailing bytes.
    pub fn deserialize(buf: &[u8]) -> Result<Self, CryptoError> {
        let mut r = Reader::new(buf);
        let token_type = r.u16()?;
        let issuer_len = r.u16()? as usize;
        // RFC 9577 §2.1: issuer_name is `<1..2^16-1>` — reject a zero length.
        if issuer_len == 0 {
            return Err(CryptoError::InvalidArg(""));
        }
        let issuer_name = r.bytes(issuer_len)?.to_vec();
        let redemption_len = r.u8()? as usize;
        if redemption_len != 0 && redemption_len != KEY_ID_LEN {
            return Err(CryptoError::InvalidArg(""));
        }
        let redemption_context = r.bytes(redemption_len)?.to_vec();
        let origin_len = r.u16()? as usize;
        let origin_info = r.bytes(origin_len)?.to_vec();
        r.finish()?;
        Ok(Self {
            token_type,
            issuer_name,
            redemption_context,
            origin_info,
        })
    }
}

/// RFC 9578 §5.2 TokenRequest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRequest {
    /// The token type.
    pub token_type: u16,
    /// Truncated token key id (low byte of `SHA256(token_key)`).
    pub truncated_token_key_id: u8,
    /// The blinded message `blinded_msg` (length `Nk`).
    pub blinded_msg: Vec<u8>,
}

impl TokenRequest {
    /// Serialize to the RFC 9578 §5.2 wire form.
    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::with_capacity(3 + self.blinded_msg.len());
        out.extend_from_slice(&self.token_type.to_be_bytes());
        out.push(self.truncated_token_key_id);
        out.extend_from_slice(&self.blinded_msg);
        Ok(out)
    }

    /// Parse from the wire form. Per RFC 9578 §5.2 `blinded_msg` is
    /// `opaque blinded_msg[Nk]` — exactly `nk` bytes — so the total buffer must
    /// be `3 + nk` bytes (`nk` is the issuer key's modulus size, e.g. 256 for
    /// RSA-2048).
    pub fn deserialize(buf: &[u8], nk: usize) -> Result<Self, CryptoError> {
        if buf.len() != 3 + nk {
            return Err(CryptoError::InvalidArg(""));
        }
        let mut r = Reader::new(buf);
        let token_type = r.u16()?;
        let truncated_token_key_id = r.u8()?;
        let blinded_msg = r.rest().to_vec();
        Ok(Self {
            token_type,
            truncated_token_key_id,
            blinded_msg,
        })
    }
}

/// RFC 9578 §5.3 TokenResponse — the raw `blind_sig` bytes.
///
/// `blind_sig` is a cryptographic intermediate (unblinds to the token), so the
/// struct derives `Zeroize` + `ZeroizeOnDrop` and does **not** derive
/// `PartialEq`/`Eq` (a derived `==` would compare it in variable time).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct TokenResponse {
    /// The blind signature.
    pub blind_sig: Vec<u8>,
}

impl TokenResponse {
    /// Serialize to the wire form (the `blind_sig` bytes verbatim).
    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.blind_sig.clone())
    }

    /// Parse from the wire form. Per RFC 9578 §5.3 the response is
    /// `blind_sig[Nk]` — exactly `nk` bytes.
    pub fn deserialize(buf: &[u8], nk: usize) -> Result<Self, CryptoError> {
        if buf.len() != nk {
            return Err(CryptoError::InvalidArg(""));
        }
        Ok(Self {
            blind_sig: buf.to_vec(),
        })
    }
}

/// RFC 9578 §5.4 Token.
///
/// `authenticator` is the redemption credential (the unblinded RSA signature),
/// so the struct derives `Zeroize` + `ZeroizeOnDrop` and does **not** derive
/// `PartialEq`/`Eq` (a derived `==` would compare the credential in variable
/// time — callers needing to compare tokens must use a constant-time path).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Token {
    /// The token type.
    pub token_type: u16,
    /// 32-byte nonce.
    pub nonce: [u8; NONCE_LEN],
    /// 32-byte challenge digest `SHA256(TokenChallenge)`.
    pub challenge_digest: [u8; DIGEST_LEN],
    /// 32-byte token key id.
    pub token_key_id: [u8; KEY_ID_LEN],
    /// The authenticator (length `Nk`).
    pub authenticator: Vec<u8>,
}

impl Token {
    /// Serialize to the RFC 9578 §5.4 wire form.
    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out =
            Vec::with_capacity(2 + NONCE_LEN + DIGEST_LEN + KEY_ID_LEN + self.authenticator.len());
        out.extend_from_slice(&self.token_type.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.challenge_digest);
        out.extend_from_slice(&self.token_key_id);
        out.extend_from_slice(&self.authenticator);
        Ok(out)
    }

    /// Parse from the wire form. Per RFC 9578 §5.4 the `authenticator` is
    /// `[Nk]` bytes, so the total buffer must be `2 + 32 + 32 + 32 + nk` bytes.
    pub fn deserialize(buf: &[u8], nk: usize) -> Result<Self, CryptoError> {
        if buf.len() != 2 + NONCE_LEN + DIGEST_LEN + KEY_ID_LEN + nk {
            return Err(CryptoError::InvalidArg(""));
        }
        let mut r = Reader::new(buf);
        let token_type = r.u16()?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(r.bytes(NONCE_LEN)?);
        let mut challenge_digest = [0u8; DIGEST_LEN];
        challenge_digest.copy_from_slice(r.bytes(DIGEST_LEN)?);
        let mut token_key_id = [0u8; KEY_ID_LEN];
        token_key_id.copy_from_slice(r.bytes(KEY_ID_LEN)?);
        let authenticator = r.rest().to_vec();
        Ok(Self {
            token_type,
            nonce,
            challenge_digest,
            token_key_id,
            authenticator,
        })
    }
}
