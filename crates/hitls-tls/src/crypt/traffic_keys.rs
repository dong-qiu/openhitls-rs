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
        let alg = params.hash_alg_id();
        let key = hkdf_expand_label(alg, traffic_secret, b"key", b"", params.key_len)?;
        let iv = hkdf_expand_label(alg, traffic_secret, b"iv", b"", params.iv_len)?;
        Ok(TrafficKeys { key, iv })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CipherSuite;
    use hitls_utils::hex::{hex, to_hex};

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

    #[test]
    fn test_traffic_key_derivation_client_hs() {
        // RFC 8448 Section 3: client handshake traffic key derivation
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();

        let client_hs_secret =
            hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");

        let tk = TrafficKeys::derive(&params, &client_hs_secret).unwrap();
        assert_eq!(tk.key.len(), 16);
        assert_eq!(tk.iv.len(), 12);

        // RFC 8448 expected values
        let expected_key = hex("dbfaa693d1762c5b666af5d950258d01");
        let expected_iv = hex("5bd3c71b836e0b76bb73265f");
        assert_eq!(to_hex(&tk.key), to_hex(&expected_key));
        assert_eq!(to_hex(&tk.iv), to_hex(&expected_iv));
    }

    #[test]
    fn test_traffic_key_derivation_sha384() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_256_GCM_SHA384).unwrap();

        let secret = vec![0xAA; 48]; // 48-byte secret for SHA-384
        let tk = TrafficKeys::derive(&params, &secret).unwrap();

        // AES-256-GCM: key=32, iv=12
        assert_eq!(tk.key.len(), 32);
        assert_eq!(tk.iv.len(), 12);
    }

    #[test]
    fn test_traffic_key_derivation_chacha20() {
        let params =
            CipherSuiteParams::from_suite(CipherSuite::TLS_CHACHA20_POLY1305_SHA256).unwrap();

        let secret = vec![0xBB; 32];
        let tk = TrafficKeys::derive(&params, &secret).unwrap();

        // ChaCha20-Poly1305: key=32, iv=12
        assert_eq!(tk.key.len(), 32);
        assert_eq!(tk.iv.len(), 12);
    }

    #[test]
    fn test_traffic_key_deterministic() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let secret = vec![0xCC; 32];

        let tk1 = TrafficKeys::derive(&params, &secret).unwrap();
        let tk2 = TrafficKeys::derive(&params, &secret).unwrap();
        assert_eq!(tk1.key, tk2.key);
        assert_eq!(tk1.iv, tk2.iv);
    }

    #[test]
    fn test_traffic_key_different_secrets() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();

        let tk1 = TrafficKeys::derive(&params, &[0xAA; 32]).unwrap();
        let tk2 = TrafficKeys::derive(&params, &[0xBB; 32]).unwrap();

        assert_ne!(tk1.key, tk2.key);
        assert_ne!(tk1.iv, tk2.iv);
    }

    #[test]
    fn test_traffic_key_different_suites_different_lengths() {
        let params128 = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let params256 = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_256_GCM_SHA384).unwrap();

        let secret128 = vec![0xAA; 32];
        let secret256 = vec![0xAA; 48];

        let tk128 = TrafficKeys::derive(&params128, &secret128).unwrap();
        let tk256 = TrafficKeys::derive(&params256, &secret256).unwrap();

        assert_eq!(tk128.key.len(), 16);
        assert_eq!(tk256.key.len(), 32);
        // Both have 12-byte IVs
        assert_eq!(tk128.iv.len(), 12);
        assert_eq!(tk256.iv.len(), 12);
    }

    #[test]
    fn test_traffic_keys_rfc8448_server_app() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let server_app_secret =
            hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");
        let tk = TrafficKeys::derive(&params, &server_app_secret).unwrap();
        assert_eq!(
            to_hex(&tk.key),
            to_hex(&hex("9f02283b6c9c07efc26bb9f2ac92e356"))
        );
        assert_eq!(to_hex(&tk.iv), to_hex(&hex("cf782b88dd83549aadf1e984")));
    }

    #[test]
    fn test_traffic_keys_rfc8448_client_app() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let client_app_secret =
            hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
        let tk = TrafficKeys::derive(&params, &client_app_secret).unwrap();
        // RFC 8448 §3: client application write key/iv
        assert_eq!(
            to_hex(&tk.key),
            to_hex(&hex("17422dda596ed5d9acd890e3c63f5051"))
        );
        assert_eq!(to_hex(&tk.iv), to_hex(&hex("5b78923dee08579033e523d9")));
    }

    #[test]
    fn test_traffic_keys_ccm8() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_CCM_8_SHA256).unwrap();
        let secret = vec![0xCC; 32];
        let tk = TrafficKeys::derive(&params, &secret).unwrap();
        assert_eq!(tk.key.len(), 16); // AES-128
        assert_eq!(tk.iv.len(), 12);

        // Deterministic
        let tk2 = TrafficKeys::derive(&params, &secret).unwrap();
        assert_eq!(tk.key, tk2.key);
        assert_eq!(tk.iv, tk2.iv);
    }

    #[test]
    fn test_traffic_keys_after_key_update() {
        use crate::crypt::hkdf::hkdf_expand_label;
        use crate::crypt::HashAlgId;

        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let original_secret = vec![0xDD; 32];

        // Derive keys from original secret
        let tk_original = TrafficKeys::derive(&params, &original_secret).unwrap();

        // Simulate KeyUpdate: update_traffic_secret
        let updated_secret =
            hkdf_expand_label(HashAlgId::Sha256, &original_secret, b"traffic upd", b"", 32)
                .unwrap();

        // Derive keys from updated secret
        let tk_updated = TrafficKeys::derive(&params, &updated_secret).unwrap();

        // Keys must differ after key update
        assert_ne!(tk_original.key, tk_updated.key);
        assert_ne!(tk_original.iv, tk_updated.iv);
    }

    #[cfg(feature = "sm_tls13")]
    #[test]
    fn test_traffic_keys_sm4_gcm_sm3() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_SM4_GCM_SM3).unwrap();
        let secret = vec![0xEE; 32];
        let tk = TrafficKeys::derive(&params, &secret).unwrap();
        assert_eq!(tk.key.len(), 16); // SM4: 128-bit key
        assert_eq!(tk.iv.len(), 12);

        // Deterministic
        let tk2 = TrafficKeys::derive(&params, &secret).unwrap();
        assert_eq!(tk.key, tk2.key);
        assert_eq!(tk.iv, tk2.iv);

        // Differs from AES-128-GCM-SHA256 keys (different hash algorithm)
        let params_aes =
            CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let tk_aes = TrafficKeys::derive(&params_aes, &secret).unwrap();
        assert_ne!(tk.key, tk_aes.key);
        assert_ne!(tk.iv, tk_aes.iv);
    }
}
