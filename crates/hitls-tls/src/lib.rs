#![forbid(unsafe_code)]
#![doc = "TLS protocol implementation for openHiTLS."]

#[macro_use]
mod macros;

pub mod alert;
pub mod cert_verify;
pub mod config;
pub mod connection;
pub mod connection12;
#[cfg(feature = "async")]
pub mod connection12_async;
#[cfg(feature = "async")]
pub mod connection_async;
#[cfg(feature = "dtlcp")]
pub mod connection_dtlcp;
#[cfg(feature = "dtls12")]
pub mod connection_dtls12;
#[cfg(all(feature = "async", feature = "dtls12"))]
pub mod connection_dtls12_async;
pub mod connection_info;
#[cfg(feature = "tlcp")]
pub mod connection_tlcp;
pub mod crypt;
pub mod extensions;
pub mod handshake;
pub mod record;
pub mod session;

use hitls_types::TlsError;

/// TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    Tls12,
    Tls13,
    Dtls12,
    Tlcp,
    Dtlcp,
}

/// TLS cipher suite identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CipherSuite(pub u16);

impl CipherSuite {
    // TLS 1.3 cipher suites
    pub const TLS_AES_128_GCM_SHA256: Self = Self(0x1301);
    pub const TLS_AES_256_GCM_SHA384: Self = Self(0x1302);
    pub const TLS_CHACHA20_POLY1305_SHA256: Self = Self(0x1303);
    pub const TLS_AES_128_CCM_SHA256: Self = Self(0x1304);

    pub const TLS_AES_128_CCM_8_SHA256: Self = Self(0x1305);

    // TLS 1.3 SM4 cipher suites (RFC 8998)
    #[cfg(feature = "sm_tls13")]
    pub const TLS_SM4_GCM_SM3: Self = Self(0x00C6);
    #[cfg(feature = "sm_tls13")]
    pub const TLS_SM4_CCM_SM3: Self = Self(0x00C7);

    // TLS 1.2 ECDHE-GCM cipher suites
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0xC02F);
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0xC030);
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Self = Self(0xC02B);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: Self = Self(0xC02C);

    // TLS 1.2 ECDHE-CBC cipher suites
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: Self = Self(0xC013);
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: Self = Self(0xC014);
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: Self = Self(0xC009);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: Self = Self(0xC00A);
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: Self = Self(0xC027);
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: Self = Self(0xC028);
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: Self = Self(0xC023);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: Self = Self(0xC024);

    // TLS 1.2 ECDHE-CCM cipher suites (RFC 7251)
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CCM: Self = Self(0xC0AC);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CCM: Self = Self(0xC0AD);

    // TLS 1.2 ECDHE_ECDSA CCM_8 cipher suites (RFC 7251, 8-byte tag)
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: Self = Self(0xC0AE);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8: Self = Self(0xC0AF);

    // TLS 1.2 ECDHE-ChaCha20-Poly1305 cipher suites
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xCCA8);
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xCCA9);

    // TLS 1.2 RSA-CCM cipher suites (RFC 6655)
    pub const TLS_RSA_WITH_AES_128_CCM: Self = Self(0xC09C);
    pub const TLS_RSA_WITH_AES_256_CCM: Self = Self(0xC09D);

    // TLS 1.2 RSA-CCM_8 cipher suites (RFC 6655, 8-byte tag)
    pub const TLS_RSA_WITH_AES_128_CCM_8: Self = Self(0xC0A0);
    pub const TLS_RSA_WITH_AES_256_CCM_8: Self = Self(0xC0A1);

    // TLS 1.2 DHE_RSA CCM_8 cipher suites (RFC 6655, 8-byte tag)
    pub const TLS_DHE_RSA_WITH_AES_128_CCM_8: Self = Self(0xC0A2);
    pub const TLS_DHE_RSA_WITH_AES_256_CCM_8: Self = Self(0xC0A3);

    // TLS 1.2 DHE_DSS cipher suites (RFC 5246)
    pub const TLS_DHE_DSS_WITH_AES_128_CBC_SHA: Self = Self(0x0032);
    pub const TLS_DHE_DSS_WITH_AES_256_CBC_SHA: Self = Self(0x0038);
    pub const TLS_DHE_DSS_WITH_AES_128_CBC_SHA256: Self = Self(0x0040);
    pub const TLS_DHE_DSS_WITH_AES_256_CBC_SHA256: Self = Self(0x006A);
    pub const TLS_DHE_DSS_WITH_AES_128_GCM_SHA256: Self = Self(0x00A2);
    pub const TLS_DHE_DSS_WITH_AES_256_GCM_SHA384: Self = Self(0x00A3);

    // TLS 1.2 DH_ANON cipher suites (RFC 5246)
    pub const TLS_DH_ANON_WITH_AES_128_CBC_SHA: Self = Self(0x0034);
    pub const TLS_DH_ANON_WITH_AES_256_CBC_SHA: Self = Self(0x003A);
    pub const TLS_DH_ANON_WITH_AES_128_CBC_SHA256: Self = Self(0x006C);
    pub const TLS_DH_ANON_WITH_AES_256_CBC_SHA256: Self = Self(0x006D);
    pub const TLS_DH_ANON_WITH_AES_128_GCM_SHA256: Self = Self(0x00A6);
    pub const TLS_DH_ANON_WITH_AES_256_GCM_SHA384: Self = Self(0x00A7);

    // TLS 1.2 ECDH_ANON cipher suites (RFC 4492)
    pub const TLS_ECDH_ANON_WITH_AES_128_CBC_SHA: Self = Self(0xC018);
    pub const TLS_ECDH_ANON_WITH_AES_256_CBC_SHA: Self = Self(0xC019);

    // TLS 1.2 RSA static key exchange cipher suites
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0x009C);
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0x009D);
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: Self = Self(0x002F);
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: Self = Self(0x0035);
    pub const TLS_RSA_WITH_AES_128_CBC_SHA256: Self = Self(0x003C);
    pub const TLS_RSA_WITH_AES_256_CBC_SHA256: Self = Self(0x003D);

    // TLS 1.2 DHE_RSA-CCM cipher suites (RFC 6655)
    pub const TLS_DHE_RSA_WITH_AES_128_CCM: Self = Self(0xC09E);
    pub const TLS_DHE_RSA_WITH_AES_256_CCM: Self = Self(0xC09F);

    // TLS 1.2 DHE_RSA key exchange cipher suites
    pub const TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0x009E);
    pub const TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0x009F);
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: Self = Self(0x0033);
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: Self = Self(0x0039);
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: Self = Self(0x0067);
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: Self = Self(0x006B);
    pub const TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xCCAA);

    // TLS 1.2 PSK cipher suites (RFC 4279, RFC 5487)
    pub const TLS_PSK_WITH_AES_128_GCM_SHA256: Self = Self(0x00A8);
    pub const TLS_PSK_WITH_AES_256_GCM_SHA384: Self = Self(0x00A9);
    pub const TLS_PSK_WITH_AES_128_CBC_SHA: Self = Self(0x008C);
    pub const TLS_PSK_WITH_AES_256_CBC_SHA: Self = Self(0x008D);
    pub const TLS_PSK_WITH_AES_128_CBC_SHA256: Self = Self(0x00AE);
    pub const TLS_PSK_WITH_AES_256_CBC_SHA384: Self = Self(0x00AF);
    pub const TLS_PSK_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xCCAB);
    pub const TLS_PSK_WITH_AES_256_CCM: Self = Self(0xC0A5);

    // TLS 1.2 PSK CCM/CCM_8 cipher suites (RFC 6655)
    pub const TLS_PSK_WITH_AES_128_CCM: Self = Self(0xC0A4);
    pub const TLS_PSK_WITH_AES_128_CCM_8: Self = Self(0xC0A8);
    pub const TLS_PSK_WITH_AES_256_CCM_8: Self = Self(0xC0A9);

    // TLS 1.2 DHE_PSK cipher suites (RFC 4279, RFC 5487)
    pub const TLS_DHE_PSK_WITH_AES_128_GCM_SHA256: Self = Self(0x00AA);
    pub const TLS_DHE_PSK_WITH_AES_256_GCM_SHA384: Self = Self(0x00AB);
    pub const TLS_DHE_PSK_WITH_AES_128_CBC_SHA: Self = Self(0x0090);
    pub const TLS_DHE_PSK_WITH_AES_256_CBC_SHA: Self = Self(0x0091);
    pub const TLS_DHE_PSK_WITH_AES_128_CBC_SHA256: Self = Self(0x00B2);
    pub const TLS_DHE_PSK_WITH_AES_256_CBC_SHA384: Self = Self(0x00B3);
    pub const TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xCCAD);
    pub const TLS_DHE_PSK_WITH_AES_128_CCM: Self = Self(0xC0A6);
    pub const TLS_DHE_PSK_WITH_AES_256_CCM: Self = Self(0xC0A7);

    // TLS 1.2 DHE_PSK CCM_8 cipher suites (RFC 6655, 8-byte tag)
    pub const TLS_DHE_PSK_WITH_AES_128_CCM_8: Self = Self(0xC0AA);
    pub const TLS_DHE_PSK_WITH_AES_256_CCM_8: Self = Self(0xC0AB);

    // TLS 1.2 RSA_PSK cipher suites (RFC 4279, RFC 5487)
    pub const TLS_RSA_PSK_WITH_AES_128_GCM_SHA256: Self = Self(0x00AC);
    pub const TLS_RSA_PSK_WITH_AES_256_GCM_SHA384: Self = Self(0x00AD);
    pub const TLS_RSA_PSK_WITH_AES_128_CBC_SHA: Self = Self(0x0094);
    pub const TLS_RSA_PSK_WITH_AES_256_CBC_SHA: Self = Self(0x0095);
    pub const TLS_RSA_PSK_WITH_AES_128_CBC_SHA256: Self = Self(0x00B6);
    pub const TLS_RSA_PSK_WITH_AES_256_CBC_SHA384: Self = Self(0x00B7);
    pub const TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xCCAE);

    // TLS 1.2 ECDHE_PSK cipher suites (RFC 5489)
    pub const TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA: Self = Self(0xC035);
    pub const TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA: Self = Self(0xC036);
    pub const TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256: Self = Self(0xC037);
    pub const TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384: Self = Self(0xC038);
    pub const TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xCCAC);
    pub const TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256: Self = Self(0xD001);
    pub const TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384: Self = Self(0xD002);
    pub const TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256: Self = Self(0xD005);

    // TLS 1.2 ECDHE_PSK CCM_8 cipher suites (draft-ietf-tls-ecdhe-psk-aead, 8-byte tag)
    pub const TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256: Self = Self(0xD003);

    // TLCP cipher suites (GM/T 0024)
    pub const ECDHE_SM4_CBC_SM3: Self = Self(0xE011);
    pub const ECC_SM4_CBC_SM3: Self = Self(0xE013);
    pub const ECDHE_SM4_GCM_SM3: Self = Self(0xE051);
    pub const ECC_SM4_GCM_SM3: Self = Self(0xE053);

    // Signaling cipher suite values
    /// TLS Fallback SCSV (RFC 7507) — signals intentional version downgrade.
    pub const TLS_FALLBACK_SCSV: Self = Self(0x5600);
}

/// The role of a TLS endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRole {
    Client,
    Server,
}

/// A synchronous TLS connection.
pub trait TlsConnection {
    /// Perform the TLS handshake.
    fn handshake(&mut self) -> Result<(), TlsError>;
    /// Read decrypted data into `buf`.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError>;
    /// Write data to be encrypted and sent.
    fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError>;
    /// Shut down the TLS connection gracefully.
    fn shutdown(&mut self) -> Result<(), TlsError>;
    /// Get the negotiated TLS version.
    fn version(&self) -> Option<TlsVersion>;
    /// Get the negotiated cipher suite.
    fn cipher_suite(&self) -> Option<CipherSuite>;
}

/// An asynchronous TLS connection (requires `async` feature + tokio).
#[cfg(feature = "async")]
#[allow(async_fn_in_trait)]
pub trait AsyncTlsConnection {
    /// Perform the TLS handshake asynchronously.
    async fn handshake(&mut self) -> Result<(), TlsError>;
    /// Read decrypted data into `buf` asynchronously.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError>;
    /// Write data to be encrypted and sent asynchronously.
    async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError>;
    /// Shut down the TLS connection gracefully.
    async fn shutdown(&mut self) -> Result<(), TlsError>;
    /// Get the negotiated TLS version.
    fn version(&self) -> Option<TlsVersion>;
    /// Get the negotiated cipher suite.
    fn cipher_suite(&self) -> Option<CipherSuite>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_debug_and_clone() {
        let v = TlsVersion::Tls13;
        let v2 = v;
        assert_eq!(v, v2);
        assert_eq!(format!("{v:?}"), "Tls13");
    }

    #[test]
    fn test_tls_version_all_variants_distinct() {
        let versions = [
            TlsVersion::Tls12,
            TlsVersion::Tls13,
            TlsVersion::Dtls12,
            TlsVersion::Tlcp,
            TlsVersion::Dtlcp,
        ];
        for i in 0..versions.len() {
            for j in (i + 1)..versions.len() {
                assert_ne!(versions[i], versions[j]);
            }
        }
    }

    #[test]
    fn test_cipher_suite_tls13_constants() {
        assert_eq!(CipherSuite::TLS_AES_128_GCM_SHA256.0, 0x1301);
        assert_eq!(CipherSuite::TLS_AES_256_GCM_SHA384.0, 0x1302);
        assert_eq!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.0, 0x1303);
        assert_eq!(CipherSuite::TLS_AES_128_CCM_SHA256.0, 0x1304);
        assert_eq!(CipherSuite::TLS_AES_128_CCM_8_SHA256.0, 0x1305);
    }

    #[test]
    fn test_cipher_suite_hash_and_eq() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CipherSuite::TLS_AES_128_GCM_SHA256);
        set.insert(CipherSuite::TLS_AES_256_GCM_SHA384);
        set.insert(CipherSuite::TLS_AES_128_GCM_SHA256); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_cipher_suite_fallback_scsv() {
        assert_eq!(CipherSuite::TLS_FALLBACK_SCSV.0, 0x5600);
        assert_ne!(
            CipherSuite::TLS_FALLBACK_SCSV,
            CipherSuite::TLS_AES_128_GCM_SHA256
        );
    }

    #[test]
    fn test_cipher_suite_tls12_ecdhe_constants() {
        // ECDHE-GCM suites (RFC 5289)
        assert_eq!(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.0, 0xC02F);
        assert_eq!(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.0, 0xC030);
        assert_eq!(
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.0,
            0xC02B
        );
        assert_eq!(
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.0,
            0xC02C
        );
        // ECDHE-CBC suites
        assert_eq!(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.0, 0xC013);
        assert_eq!(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.0, 0xC009);
        // ECDHE-ChaCha20 suites
        assert_eq!(
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.0,
            0xCCA8
        );
        assert_eq!(
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.0,
            0xCCA9
        );
    }

    #[test]
    fn test_cipher_suite_tls12_rsa_and_dhe_constants() {
        // RSA static suites
        assert_eq!(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256.0, 0x009C);
        assert_eq!(CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384.0, 0x009D);
        assert_eq!(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA.0, 0x002F);
        assert_eq!(CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA.0, 0x0035);
        // DHE_RSA suites
        assert_eq!(CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256.0, 0x009E);
        assert_eq!(CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384.0, 0x009F);
        assert_eq!(
            CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256.0,
            0xCCAA
        );
    }

    #[test]
    fn test_cipher_suite_tls12_psk_constants() {
        // PSK suites (RFC 4279/5487)
        assert_eq!(CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256.0, 0x00A8);
        assert_eq!(CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384.0, 0x00A9);
        assert_eq!(CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA.0, 0x008C);
        assert_eq!(CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256.0, 0x00AE);
        assert_eq!(CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256.0, 0xCCAB);
        // DHE_PSK suites
        assert_eq!(CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256.0, 0x00AA);
        assert_eq!(CipherSuite::TLS_DHE_PSK_WITH_AES_128_CCM.0, 0xC0A6);
        // RSA_PSK suites
        assert_eq!(CipherSuite::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256.0, 0x00AC);
        // ECDHE_PSK suites
        assert_eq!(CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA.0, 0xC035);
        assert_eq!(CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256.0, 0xD001);
    }

    #[test]
    fn test_cipher_suite_tlcp_constants() {
        // TLCP cipher suites (GM/T 0024)
        assert_eq!(CipherSuite::ECDHE_SM4_CBC_SM3.0, 0xE011);
        assert_eq!(CipherSuite::ECC_SM4_CBC_SM3.0, 0xE013);
        assert_eq!(CipherSuite::ECDHE_SM4_GCM_SM3.0, 0xE051);
        assert_eq!(CipherSuite::ECC_SM4_GCM_SM3.0, 0xE053);
        // All TLCP suites are distinct
        let suites = [
            CipherSuite::ECDHE_SM4_CBC_SM3,
            CipherSuite::ECC_SM4_CBC_SM3,
            CipherSuite::ECDHE_SM4_GCM_SM3,
            CipherSuite::ECC_SM4_GCM_SM3,
        ];
        for i in 0..suites.len() {
            for j in (i + 1)..suites.len() {
                assert_ne!(suites[i], suites[j]);
            }
        }
    }

    #[test]
    fn test_tls_role_enum() {
        let client = TlsRole::Client;
        let server = TlsRole::Server;
        assert_ne!(client, server);
        assert_eq!(client, TlsRole::Client);
        assert_eq!(server, TlsRole::Server);

        // Debug
        assert_eq!(format!("{client:?}"), "Client");
        assert_eq!(format!("{server:?}"), "Server");

        // Copy
        let c2 = client;
        assert_eq!(c2, client);
    }

    #[test]
    fn test_cipher_suite_debug_format() {
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let debug = format!("{suite:?}");
        assert!(debug.contains("CipherSuite"));
        assert!(debug.contains("4865")); // 0x1301 = 4865
    }

    #[test]
    fn test_tls_version_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TlsVersion::Tls12);
        set.insert(TlsVersion::Tls13);
        set.insert(TlsVersion::Dtls12);
        set.insert(TlsVersion::Tlcp);
        set.insert(TlsVersion::Dtlcp);
        set.insert(TlsVersion::Tls12); // duplicate
        assert_eq!(set.len(), 5);
    }
}
