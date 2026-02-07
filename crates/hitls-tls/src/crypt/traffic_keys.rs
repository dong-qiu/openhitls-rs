//! TLS 1.3 traffic key derivation.
//!
//! Derives concrete AEAD key + IV from a traffic secret.

use super::hkdf::hkdf_expand_label;
use super::CipherSuiteParams;
use hitls_types::TlsError;
use zeroize::Zeroize;

/// Concrete traffic keys (AEAD key + IV) derived from a traffic secret.
pub struct TrafficKeys {
    /// AEAD encryption key.
    pub key: Vec<u8>,
    /// AEAD nonce/IV.
    pub iv: Vec<u8>,
}

impl Drop for TrafficKeys {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl TrafficKeys {
    /// Derive traffic keys from a traffic secret.
    ///
    /// ```text
    /// key = HKDF-Expand-Label(secret, "key", "", key_length)
    /// iv  = HKDF-Expand-Label(secret, "iv", "", iv_length)
    /// ```
    pub fn derive(params: &CipherSuiteParams, traffic_secret: &[u8]) -> Result<Self, TlsError> {
        let factory = params.hash_factory();
        let key = hkdf_expand_label(&*factory, traffic_secret, b"key", b"", params.key_len)?;
        let iv = hkdf_expand_label(&*factory, traffic_secret, b"iv", b"", params.iv_len)?;
        Ok(TrafficKeys { key, iv })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CipherSuite;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_traffic_key_derivation() {
        // RFC 8448 Section 3: server handshake traffic key derivation
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();

        let server_hs_secret =
            hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");

        let tk = TrafficKeys::derive(&params, &server_hs_secret).unwrap();
        assert_eq!(tk.key.len(), 16);
        assert_eq!(tk.iv.len(), 12);

        // RFC 8448 expected values
        let expected_key = hex("3fce516009c21727d0f2e4e86ee403bc");
        let expected_iv = hex("5d313eb2671276ee13000b30");
        assert_eq!(to_hex(&tk.key), to_hex(&expected_key));
        assert_eq!(to_hex(&tk.iv), to_hex(&expected_iv));
    }
}
