//! TLS 1.2 key derivation using PRF (RFC 5246 §6.3, §8.1).
//!
//! Derives the master secret from the pre-master secret, then expands
//! the master secret into a key block containing per-direction keys and IVs.

use super::prf::prf;
use super::Tls12CipherSuiteParams;
use hitls_crypto::provider::Digest;
use hitls_types::TlsError;
use zeroize::Zeroize;

type Factory = dyn Fn() -> Box<dyn Digest> + Send + Sync;

/// TLS 1.2 key block: MAC keys (CBC only), symmetric keys, and IVs.
///
/// For GCM/ChaCha20 suites, MAC keys are empty (AEAD handles auth).
/// For CBC suites, MAC keys are extracted first per RFC 5246 §6.3.
pub struct Tls12KeyBlock {
    pub client_write_mac_key: Vec<u8>,
    pub server_write_mac_key: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

impl Drop for Tls12KeyBlock {
    fn drop(&mut self) {
        self.client_write_mac_key.zeroize();
        self.server_write_mac_key.zeroize();
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
        self.client_write_iv.zeroize();
        self.server_write_iv.zeroize();
    }
}

/// Derive the 48-byte master secret from the pre-master secret.
///
/// RFC 5246 §8.1:
/// ```text
/// master_secret = PRF(pre_master_secret, "master secret",
///                     ClientHello.random + ServerHello.random)[0..47]
/// ```
pub fn derive_master_secret(
    factory: &Factory,
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<Vec<u8>, TlsError> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    prf(factory, pre_master_secret, "master secret", &seed, 48)
}

/// Derive the 48-byte master secret using the Extended Master Secret extension (RFC 7627).
///
/// ```text
/// master_secret = PRF(pre_master_secret, "extended master secret",
///                     session_hash)[0..47]
/// ```
///
/// `session_hash` is the hash of all handshake messages up to and including
/// the ClientKeyExchange message.
pub fn derive_extended_master_secret(
    factory: &Factory,
    pre_master_secret: &[u8],
    session_hash: &[u8],
) -> Result<Vec<u8>, TlsError> {
    prf(
        factory,
        pre_master_secret,
        "extended master secret",
        session_hash,
        48,
    )
}

/// Derive the key block from the master secret.
///
/// RFC 5246 §6.3:
/// ```text
/// key_block = PRF(master_secret, "key expansion",
///                 ServerHello.random + ClientHello.random)
/// ```
///
/// For GCM cipher suites the key block is partitioned as:
/// ```text
/// client_write_key[key_len] || server_write_key[key_len] ||
/// client_write_iv[fixed_iv_len] || server_write_iv[fixed_iv_len]
/// ```
pub fn derive_key_block(
    factory: &Factory,
    master_secret: &[u8],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    params: &Tls12CipherSuiteParams,
) -> Result<Tls12KeyBlock, TlsError> {
    // Note: key expansion seed is server_random + client_random (reversed from master_secret)
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    let total_len = params.key_block_len();
    let key_block = prf(factory, master_secret, "key expansion", &seed, total_len)?;

    // RFC 5246 §6.3: MAC keys → enc keys → IVs
    let mut offset = 0;
    let client_write_mac_key = key_block[offset..offset + params.mac_key_len].to_vec();
    offset += params.mac_key_len;
    let server_write_mac_key = key_block[offset..offset + params.mac_key_len].to_vec();
    offset += params.mac_key_len;
    let client_write_key = key_block[offset..offset + params.key_len].to_vec();
    offset += params.key_len;
    let server_write_key = key_block[offset..offset + params.key_len].to_vec();
    offset += params.key_len;
    let client_write_iv = key_block[offset..offset + params.fixed_iv_len].to_vec();
    offset += params.fixed_iv_len;
    let server_write_iv = key_block[offset..offset + params.fixed_iv_len].to_vec();

    Ok(Tls12KeyBlock {
        client_write_mac_key,
        server_write_mac_key,
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    })
}

/// Compute the Finished message verify_data (12 bytes).
///
/// RFC 5246 §7.4.9:
/// ```text
/// verify_data = PRF(master_secret, finished_label,
///                   Hash(handshake_messages))[0..11]
/// ```
///
/// `label` is `"client finished"` or `"server finished"`.
pub fn compute_verify_data(
    factory: &Factory,
    master_secret: &[u8],
    label: &str,
    handshake_hash: &[u8],
) -> Result<Vec<u8>, TlsError> {
    prf(factory, master_secret, label, handshake_hash, 12)
}

/// TLCP key block: MAC keys, symmetric keys, and IVs for both directions.
///
/// For CBC cipher suites: mac_key(32) + enc_key(16) + iv(16) per direction.
/// For GCM cipher suites: enc_key(16) + fixed_iv(4) per direction (no MAC keys).
#[cfg(feature = "tlcp")]
pub struct TlcpKeyBlock {
    pub client_write_mac_key: Vec<u8>,
    pub server_write_mac_key: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

#[cfg(feature = "tlcp")]
impl Drop for TlcpKeyBlock {
    fn drop(&mut self) {
        self.client_write_mac_key.zeroize();
        self.server_write_mac_key.zeroize();
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
        self.client_write_iv.zeroize();
        self.server_write_iv.zeroize();
    }
}

/// Derive the TLCP key block from the master secret.
///
/// Key block layout (RFC 5246 §6.3, same for TLCP):
/// ```text
/// client_write_MAC_key[mac_key_len] || server_write_MAC_key[mac_key_len] ||
/// client_write_key[enc_key_len] || server_write_key[enc_key_len] ||
/// client_write_IV[iv_len] || server_write_IV[iv_len]
/// ```
#[cfg(feature = "tlcp")]
pub fn derive_tlcp_key_block(
    factory: &Factory,
    master_secret: &[u8],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    params: &crate::crypt::TlcpCipherSuiteParams,
) -> Result<TlcpKeyBlock, TlsError> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    let total_len = params.key_block_len();
    let key_block = prf(factory, master_secret, "key expansion", &seed, total_len)?;

    let mut offset = 0;
    let client_write_mac_key = key_block[offset..offset + params.mac_key_len].to_vec();
    offset += params.mac_key_len;
    let server_write_mac_key = key_block[offset..offset + params.mac_key_len].to_vec();
    offset += params.mac_key_len;
    let client_write_key = key_block[offset..offset + params.enc_key_len].to_vec();
    offset += params.enc_key_len;
    let server_write_key = key_block[offset..offset + params.enc_key_len].to_vec();
    offset += params.enc_key_len;
    let client_write_iv = key_block[offset..offset + params.iv_len].to_vec();
    offset += params.iv_len;
    let server_write_iv = key_block[offset..offset + params.iv_len].to_vec();

    Ok(TlcpKeyBlock {
        client_write_mac_key,
        server_write_mac_key,
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_crypto::sha2::{Sha256, Sha384};

    fn sha256_factory() -> Box<dyn Fn() -> Box<dyn Digest> + Send + Sync> {
        Box::new(|| Box::new(Sha256::new()))
    }

    fn sha384_factory() -> Box<dyn Fn() -> Box<dyn Digest> + Send + Sync> {
        Box::new(|| Box::new(Sha384::new()))
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn test_derive_master_secret_deterministic() {
        let factory = sha256_factory();
        let pms = hex("0303aabbccdd");
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let ms1 = derive_master_secret(&*factory, &pms, &client_random, &server_random).unwrap();
        let ms2 = derive_master_secret(&*factory, &pms, &client_random, &server_random).unwrap();
        assert_eq!(ms1, ms2);
        assert_eq!(ms1.len(), 48);
        eprintln!("master_secret: {}", to_hex(&ms1));
    }

    #[test]
    fn test_derive_master_secret_different_inputs() {
        let factory = sha256_factory();
        let pms = hex("0303aabbccdd");
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];
        let other_random = [0x03u8; 32];

        let ms1 = derive_master_secret(&*factory, &pms, &client_random, &server_random).unwrap();
        let ms2 = derive_master_secret(&*factory, &pms, &client_random, &other_random).unwrap();
        assert_ne!(ms1, ms2);
    }

    #[test]
    fn test_derive_key_block_aes128_gcm() {
        let factory = sha256_factory();
        let master_secret = [0xABu8; 48];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let params = Tls12CipherSuiteParams::from_suite(
            crate::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        )
        .unwrap();

        let kb = derive_key_block(
            &*factory,
            &master_secret,
            &server_random,
            &client_random,
            &params,
        )
        .unwrap();

        assert_eq!(kb.client_write_key.len(), 16);
        assert_eq!(kb.server_write_key.len(), 16);
        assert_eq!(kb.client_write_iv.len(), 4);
        assert_eq!(kb.server_write_iv.len(), 4);
        // Keys should be different
        assert_ne!(kb.client_write_key, kb.server_write_key);
    }

    #[test]
    fn test_derive_key_block_aes256_gcm() {
        let factory = sha384_factory();
        let master_secret = [0xCDu8; 48];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let params = Tls12CipherSuiteParams::from_suite(
            crate::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        )
        .unwrap();

        let kb = derive_key_block(
            &*factory,
            &master_secret,
            &server_random,
            &client_random,
            &params,
        )
        .unwrap();

        assert_eq!(kb.client_write_key.len(), 32);
        assert_eq!(kb.server_write_key.len(), 32);
        assert_eq!(kb.client_write_iv.len(), 4);
        assert_eq!(kb.server_write_iv.len(), 4);
    }

    #[test]
    fn test_compute_verify_data_client() {
        let factory = sha256_factory();
        let master_secret = [0xABu8; 48];
        let handshake_hash = [0xCDu8; 32];

        let vd = compute_verify_data(
            &*factory,
            &master_secret,
            "client finished",
            &handshake_hash,
        )
        .unwrap();
        assert_eq!(vd.len(), 12);

        // Deterministic
        let vd2 = compute_verify_data(
            &*factory,
            &master_secret,
            "client finished",
            &handshake_hash,
        )
        .unwrap();
        assert_eq!(vd, vd2);

        // Server label produces different result
        let vd_server = compute_verify_data(
            &*factory,
            &master_secret,
            "server finished",
            &handshake_hash,
        )
        .unwrap();
        assert_ne!(vd, vd_server);
        assert_eq!(vd_server.len(), 12);
    }

    #[test]
    fn test_derive_extended_master_secret() {
        let factory = sha256_factory();
        let pms = hex("0303aabbccdd");
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];
        let session_hash = hex("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

        // EMS should produce 48-byte master secret
        let ems = derive_extended_master_secret(&*factory, &pms, &session_hash).unwrap();
        assert_eq!(ems.len(), 48);

        // EMS should differ from standard master secret derivation
        let standard =
            derive_master_secret(&*factory, &pms, &client_random, &server_random).unwrap();
        assert_ne!(ems, standard);

        // EMS should be deterministic
        let ems2 = derive_extended_master_secret(&*factory, &pms, &session_hash).unwrap();
        assert_eq!(ems, ems2);

        // Different session_hash → different EMS
        let other_hash = hex("1111111111111111111111111111111111111111111111111111111111111111");
        let ems3 = derive_extended_master_secret(&*factory, &pms, &other_hash).unwrap();
        assert_ne!(ems, ems3);
    }

    #[test]
    fn test_key_block_len() {
        let params128 = Tls12CipherSuiteParams::from_suite(
            crate::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        )
        .unwrap();
        // 2*16 + 2*4 = 40
        assert_eq!(params128.key_block_len(), 40);

        let params256 = Tls12CipherSuiteParams::from_suite(
            crate::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        )
        .unwrap();
        // 2*32 + 2*4 = 72
        assert_eq!(params256.key_block_len(), 72);
    }

    #[cfg(feature = "tlcp")]
    #[test]
    fn test_derive_tlcp_key_block_cbc() {
        use hitls_crypto::sm3::Sm3;

        fn sm3_factory() -> Box<dyn Fn() -> Box<dyn Digest> + Send + Sync> {
            Box::new(|| Box::new(Sm3::new()))
        }

        let factory = sm3_factory();
        let master_secret = [0xABu8; 48];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let params =
            crate::crypt::TlcpCipherSuiteParams::from_suite(crate::CipherSuite::ECDHE_SM4_CBC_SM3)
                .unwrap();

        let kb = derive_tlcp_key_block(
            &*factory,
            &master_secret,
            &server_random,
            &client_random,
            &params,
        )
        .unwrap();

        assert_eq!(kb.client_write_mac_key.len(), 32);
        assert_eq!(kb.server_write_mac_key.len(), 32);
        assert_eq!(kb.client_write_key.len(), 16);
        assert_eq!(kb.server_write_key.len(), 16);
        assert_eq!(kb.client_write_iv.len(), 16);
        assert_eq!(kb.server_write_iv.len(), 16);
        // All different
        assert_ne!(kb.client_write_mac_key, kb.server_write_mac_key);
        assert_ne!(kb.client_write_key, kb.server_write_key);
    }

    #[cfg(feature = "tlcp")]
    #[test]
    fn test_derive_tlcp_key_block_gcm() {
        use hitls_crypto::sm3::Sm3;

        fn sm3_factory() -> Box<dyn Fn() -> Box<dyn Digest> + Send + Sync> {
            Box::new(|| Box::new(Sm3::new()))
        }

        let factory = sm3_factory();
        let master_secret = [0xCDu8; 48];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let params =
            crate::crypt::TlcpCipherSuiteParams::from_suite(crate::CipherSuite::ECDHE_SM4_GCM_SM3)
                .unwrap();

        let kb = derive_tlcp_key_block(
            &*factory,
            &master_secret,
            &server_random,
            &client_random,
            &params,
        )
        .unwrap();

        // GCM: no MAC keys
        assert!(kb.client_write_mac_key.is_empty());
        assert!(kb.server_write_mac_key.is_empty());
        assert_eq!(kb.client_write_key.len(), 16);
        assert_eq!(kb.server_write_key.len(), 16);
        assert_eq!(kb.client_write_iv.len(), 4);
        assert_eq!(kb.server_write_iv.len(), 4);
    }
}
