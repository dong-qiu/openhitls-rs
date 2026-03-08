//! Security level policy for TLS configuration.
//!
//! Implements the default security callback that enforces minimum algorithm
//! strength, forward secrecy, and version restrictions based on security levels.

use crate::CipherSuite;

/// Security operation types passed as the `op` parameter to [`SecurityCallback`](super::SecurityCallback).
pub mod security_op {
    /// Cipher suite check.
    pub const CIPHER_SUITE: u32 = 0;
    /// Named group / curve check.
    pub const NAMED_GROUP: u32 = 1;
    /// Signature algorithm check.
    pub const SIGNATURE_ALG: u32 = 2;
    /// Protocol version check.
    pub const VERSION: u32 = 3;
}

/// Minimum security bits for each security level (1–5).
///
/// | Level | Min bits | Meaning |
/// |-------|----------|---------|
/// | 0     | 0        | No restrictions |
/// | 1     | 80       | Reject export ciphers, SSL 3.0, anonymous auth |
/// | 2     | 112      | Reject < 112-bit symmetric/hash |
/// | 3     | 128      | Reject non-forward-secret key exchange |
/// | 4     | 192      | Reject SHA-1 MAC |
/// | 5     | 256      | Reject < 256-bit |
const LEVEL_MIN_BITS: [u32; 5] = [80, 112, 128, 192, 256];

/// Returns the minimum security bits required for the given security level.
pub fn security_level_bits(level: u32) -> u32 {
    if level == 0 {
        return 0;
    }
    let idx = (level as usize).min(LEVEL_MIN_BITS.len()) - 1;
    LEVEL_MIN_BITS[idx]
}

/// Returns the approximate security strength (in bits) for a cipher suite.
fn cipher_suite_strength_bits(suite_id: u16) -> u32 {
    let suite = CipherSuite(suite_id);
    // TLS 1.3 suites
    if let Ok(params) = crate::crypt::CipherSuiteParams::from_suite(suite) {
        return (params.key_len as u32) * 8;
    }
    // TLS 1.2 suites
    if let Ok(params) = crate::crypt::Tls12CipherSuiteParams::from_suite(suite) {
        return (params.key_len as u32) * 8;
    }
    0
}

/// Returns true if the cipher suite uses forward-secret key exchange (DHE/ECDHE).
fn cipher_suite_is_forward_secret(suite_id: u16) -> bool {
    let suite = CipherSuite(suite_id);
    if let Ok(params) = crate::crypt::Tls12CipherSuiteParams::from_suite(suite) {
        return matches!(
            params.kx_alg,
            crate::crypt::KeyExchangeAlg::Ecdhe
                | crate::crypt::KeyExchangeAlg::Dhe
                | crate::crypt::KeyExchangeAlg::DhePsk
                | crate::crypt::KeyExchangeAlg::EcdhePsk
        );
    }
    // All TLS 1.3 suites are forward-secret by design
    crate::crypt::CipherSuiteParams::from_suite(suite).is_ok()
}

/// Returns true if the cipher suite uses anonymous authentication.
fn cipher_suite_is_anon(suite_id: u16) -> bool {
    let suite = CipherSuite(suite_id);
    if let Ok(params) = crate::crypt::Tls12CipherSuiteParams::from_suite(suite) {
        return params.auth_alg == crate::crypt::AuthAlg::Anon;
    }
    false
}

/// Returns true if the cipher suite uses SHA-1 for MAC.
fn cipher_suite_uses_sha1_mac(suite_id: u16) -> bool {
    let suite = CipherSuite(suite_id);
    if let Ok(params) = crate::crypt::Tls12CipherSuiteParams::from_suite(suite) {
        // SHA-1 MAC: mac_key_len=20, mac_len=20
        return params.mac_key_len == 20 && params.mac_len == 20;
    }
    false
}

/// Default security callback implementing the standard security level policy.
///
/// Enforcement rules by level:
/// - **Level 0**: No restrictions.
/// - **Level ≥ 1**: Reject anonymous auth, reject versions < TLS 1.2 / DTLS 1.2.
/// - **Level ≥ 2**: Reject ciphers with strength < 112 bits.
/// - **Level ≥ 3**: Reject non-forward-secret key exchange (static RSA, plain PSK).
/// - **Level ≥ 4**: Reject SHA-1 MAC.
/// - **Level ≥ 5**: Reject ciphers with strength < 256 bits.
pub fn default_security_callback(op: u32, level: u32, id: u16) -> bool {
    if level == 0 {
        return true;
    }

    match op {
        security_op::CIPHER_SUITE => {
            // Reject anonymous cipher suites at level ≥ 1
            if cipher_suite_is_anon(id) {
                return false;
            }
            // Check strength bits
            let bits = cipher_suite_strength_bits(id);
            let min_bits = security_level_bits(level);
            if bits < min_bits {
                return false;
            }
            // Level ≥ 3: require forward secrecy
            if level >= 3 && !cipher_suite_is_forward_secret(id) {
                return false;
            }
            // Level ≥ 4: reject SHA-1 MAC
            if level >= 4 && cipher_suite_uses_sha1_mac(id) {
                return false;
            }
            true
        }
        security_op::VERSION => {
            // Level ≥ 1: reject TLS < 1.2
            let version = id;
            match version {
                // TLS versions (higher value = newer)
                0x0300 => false, // SSL 3.0: always reject at level ≥ 1
                0x0301 => false, // TLS 1.0: reject at level ≥ 1
                0x0302 => false, // TLS 1.1: reject at level ≥ 1
                0x0303 => true,  // TLS 1.2: allow
                0x0304 => true,  // TLS 1.3: allow
                // DTLS versions (lower value = newer, inverted)
                0xFEFF => false, // DTLS 1.0: reject at level ≥ 1
                0xFEFD => true,  // DTLS 1.2: allow
                // TLCP
                0x0101 => level < 4, // TLCP 1.1: reject at level ≥ 4
                _ => true,
            }
        }
        security_op::NAMED_GROUP | security_op::SIGNATURE_ALG => {
            // Groups and signature algorithms are allowed at all levels
            // (their strength is implicitly checked via cipher suite selection)
            true
        }
        _ => true,
    }
}
