//! TLS 1.3 Key Schedule (RFC 8446 Section 7.1).
//!
//! Implements the full secret derivation chain:
//! Early Secret → Handshake Secret → Master Secret → Traffic Secrets.

use super::hkdf::{derive_secret, hkdf_expand_label, hkdf_extract, hmac_hash};
use super::{CipherSuiteParams, HashFactory};
use hitls_types::TlsError;
use zeroize::Zeroize;

/// Current stage of the TLS 1.3 key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyScheduleStage {
    Initial,
    EarlySecret,
    HandshakeSecret,
    MasterSecret,
}

/// TLS 1.3 Key Schedule state.
///
/// Tracks the current secret and stage. All secret material is zeroized on drop.
pub struct KeySchedule {
    params: CipherSuiteParams,
    hash_factory: HashFactory,
    stage: KeyScheduleStage,
    current_secret: Vec<u8>,
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        self.current_secret.zeroize();
    }
}

impl KeySchedule {
    /// Create a new KeySchedule for the given cipher suite.
    pub fn new(params: CipherSuiteParams) -> Self {
        let hash_factory = params.hash_factory();
        Self {
            params,
            hash_factory,
            stage: KeyScheduleStage::Initial,
            current_secret: Vec::new(),
        }
    }

    /// Return the current stage.
    pub fn stage(&self) -> KeyScheduleStage {
        self.stage
    }

    /// Hash length for this cipher suite.
    pub fn hash_len(&self) -> usize {
        self.params.hash_len
    }

    /// Compute Hash("") for the "derived" label context.
    fn empty_hash(&self) -> Result<Vec<u8>, TlsError> {
        let mut hasher = (self.hash_factory)();
        let mut out = vec![0u8; self.params.hash_len];
        hasher.finish(&mut out).map_err(TlsError::CryptoError)?;
        Ok(out)
    }

    /// Derive Early Secret from PSK (or None for zero-PSK).
    ///
    /// Transitions: Initial → EarlySecret.
    pub fn derive_early_secret(&mut self, psk: Option<&[u8]>) -> Result<(), TlsError> {
        if self.stage != KeyScheduleStage::Initial {
            return Err(TlsError::HandshakeFailed(
                "derive_early_secret: wrong stage".into(),
            ));
        }
        let zero_psk = vec![0u8; self.params.hash_len];
        let ikm = psk.unwrap_or(&zero_psk);
        self.current_secret = hkdf_extract(&*self.hash_factory, &[], ikm)?;
        self.stage = KeyScheduleStage::EarlySecret;
        Ok(())
    }

    /// Derive Handshake Secret from DHE shared secret.
    ///
    /// Transitions: EarlySecret → HandshakeSecret.
    ///
    /// Internally: `Derive-Secret(ES, "derived", "") → salt → HKDF-Extract(salt, DHE)`
    pub fn derive_handshake_secret(&mut self, dhe_shared_secret: &[u8]) -> Result<(), TlsError> {
        if self.stage != KeyScheduleStage::EarlySecret {
            return Err(TlsError::HandshakeFailed(
                "derive_handshake_secret: wrong stage".into(),
            ));
        }
        let empty_hash = self.empty_hash()?;
        let mut salt = derive_secret(
            &*self.hash_factory,
            &self.current_secret,
            b"derived",
            &empty_hash,
        )?;
        self.current_secret.zeroize();
        self.current_secret = hkdf_extract(&*self.hash_factory, &salt, dhe_shared_secret)?;
        salt.zeroize();
        self.stage = KeyScheduleStage::HandshakeSecret;
        Ok(())
    }

    /// Derive handshake traffic secrets from the Handshake Secret.
    ///
    /// `transcript_hash` = Hash(ClientHello...ServerHello).
    ///
    /// Returns `(client_hs_traffic_secret, server_hs_traffic_secret)`.
    pub fn derive_handshake_traffic_secrets(
        &self,
        transcript_hash: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        if self.stage != KeyScheduleStage::HandshakeSecret {
            return Err(TlsError::HandshakeFailed(
                "derive_handshake_traffic_secrets: wrong stage".into(),
            ));
        }
        let client = derive_secret(
            &*self.hash_factory,
            &self.current_secret,
            b"c hs traffic",
            transcript_hash,
        )?;
        let server = derive_secret(
            &*self.hash_factory,
            &self.current_secret,
            b"s hs traffic",
            transcript_hash,
        )?;
        Ok((client, server))
    }

    /// Derive Master Secret.
    ///
    /// Transitions: HandshakeSecret → MasterSecret.
    ///
    /// Internally: `Derive-Secret(HS, "derived", "") → salt → HKDF-Extract(salt, 0)`
    pub fn derive_master_secret(&mut self) -> Result<(), TlsError> {
        if self.stage != KeyScheduleStage::HandshakeSecret {
            return Err(TlsError::HandshakeFailed(
                "derive_master_secret: wrong stage".into(),
            ));
        }
        let empty_hash = self.empty_hash()?;
        let mut salt = derive_secret(
            &*self.hash_factory,
            &self.current_secret,
            b"derived",
            &empty_hash,
        )?;
        let zero_ikm = vec![0u8; self.params.hash_len];
        self.current_secret.zeroize();
        self.current_secret = hkdf_extract(&*self.hash_factory, &salt, &zero_ikm)?;
        salt.zeroize();
        self.stage = KeyScheduleStage::MasterSecret;
        Ok(())
    }

    /// Derive application traffic secrets from the Master Secret.
    ///
    /// `transcript_hash` = Hash(ClientHello...server Finished).
    ///
    /// Returns `(client_app_traffic_secret, server_app_traffic_secret)`.
    pub fn derive_app_traffic_secrets(
        &self,
        transcript_hash: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        if self.stage != KeyScheduleStage::MasterSecret {
            return Err(TlsError::HandshakeFailed(
                "derive_app_traffic_secrets: wrong stage".into(),
            ));
        }
        let client = derive_secret(
            &*self.hash_factory,
            &self.current_secret,
            b"c ap traffic",
            transcript_hash,
        )?;
        let server = derive_secret(
            &*self.hash_factory,
            &self.current_secret,
            b"s ap traffic",
            transcript_hash,
        )?;
        Ok((client, server))
    }

    /// Derive the exporter master secret.
    ///
    /// `transcript_hash` = Hash(ClientHello...server Finished).
    pub fn derive_exporter_master_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        if self.stage != KeyScheduleStage::MasterSecret {
            return Err(TlsError::HandshakeFailed(
                "derive_exporter_master_secret: wrong stage".into(),
            ));
        }
        derive_secret(
            &*self.hash_factory,
            &self.current_secret,
            b"exp master",
            transcript_hash,
        )
    }

    /// Derive the resumption master secret.
    ///
    /// `transcript_hash` = Hash(ClientHello...client Finished).
    pub fn derive_resumption_master_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        if self.stage != KeyScheduleStage::MasterSecret {
            return Err(TlsError::HandshakeFailed(
                "derive_resumption_master_secret: wrong stage".into(),
            ));
        }
        derive_secret(
            &*self.hash_factory,
            &self.current_secret,
            b"res master",
            transcript_hash,
        )
    }

    /// Derive a finished key from a base key (traffic secret).
    ///
    /// `finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length)`
    pub fn derive_finished_key(&self, base_key: &[u8]) -> Result<Vec<u8>, TlsError> {
        hkdf_expand_label(
            &*self.hash_factory,
            base_key,
            b"finished",
            b"",
            self.params.hash_len,
        )
    }

    /// Compute the Finished verify_data.
    ///
    /// `verify_data = HMAC(finished_key, transcript_hash)`
    pub fn compute_finished_verify_data(
        &self,
        finished_key: &[u8],
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        hmac_hash(&*self.hash_factory, finished_key, transcript_hash)
    }

    /// Derive the client early traffic secret (for 0-RTT data).
    ///
    /// `transcript_hash` = Hash(ClientHello).
    ///
    /// `client_early_traffic_secret = Derive-Secret(ES, "c e traffic", CH_hash)`
    pub fn derive_early_traffic_secret(&self, transcript_hash: &[u8]) -> Result<Vec<u8>, TlsError> {
        if self.stage != KeyScheduleStage::EarlySecret {
            return Err(TlsError::HandshakeFailed(
                "derive_early_traffic_secret: wrong stage".into(),
            ));
        }
        derive_secret(
            &*self.hash_factory,
            &self.current_secret,
            b"c e traffic",
            transcript_hash,
        )
    }

    /// Derive the early exporter master secret (RFC 8446 §7.1).
    ///
    /// `transcript_hash` = Hash(ClientHello).
    ///
    /// `early_exporter_master_secret = Derive-Secret(ES, "e exp master", CH_hash)`
    pub fn derive_early_exporter_master_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        if self.stage != KeyScheduleStage::EarlySecret {
            return Err(TlsError::HandshakeFailed(
                "derive_early_exporter_master_secret: wrong stage".into(),
            ));
        }
        derive_secret(
            &*self.hash_factory,
            &self.current_secret,
            b"e exp master",
            transcript_hash,
        )
    }

    /// Derive binder key from the Early Secret (for PSK binder verification).
    ///
    /// For resumption PSK: label = "res binder".
    /// For external PSK: label = "ext binder".
    pub fn derive_binder_key(&self, external: bool) -> Result<Vec<u8>, TlsError> {
        if self.stage != KeyScheduleStage::EarlySecret {
            return Err(TlsError::HandshakeFailed(
                "derive_binder_key: wrong stage".into(),
            ));
        }
        let label: &[u8] = if external {
            b"ext binder"
        } else {
            b"res binder"
        };
        let empty_hash = self.empty_hash()?;
        derive_secret(
            &*self.hash_factory,
            &self.current_secret,
            label,
            &empty_hash,
        )
    }

    /// Derive resumption PSK from the resumption master secret and a ticket nonce.
    ///
    /// `resumption_psk = HKDF-Expand-Label(rms, "resumption", nonce, Hash.length)`
    ///
    /// This can be called at any stage since it doesn't use the current secret.
    pub fn derive_resumption_psk(&self, rms: &[u8], nonce: &[u8]) -> Result<Vec<u8>, TlsError> {
        hkdf_expand_label(
            &*self.hash_factory,
            rms,
            b"resumption",
            nonce,
            self.params.hash_len,
        )
    }

    /// Update traffic secret for post-handshake key update.
    ///
    /// `new_secret = HKDF-Expand-Label(current_secret, "traffic upd", "", Hash.length)`
    pub fn update_traffic_secret(&self, current_secret: &[u8]) -> Result<Vec<u8>, TlsError> {
        hkdf_expand_label(
            &*self.hash_factory,
            current_secret,
            b"traffic upd",
            b"",
            self.params.hash_len,
        )
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

    // RFC 8448 Section 3: Simple 1-RTT Handshake (TLS_AES_128_GCM_SHA256)
    // All hex values from the RFC example trace.

    #[test]
    fn test_full_key_schedule_sha256() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks = KeySchedule::new(params);

        // Step 1: Early Secret (no PSK → zero IKM)
        ks.derive_early_secret(None).unwrap();
        assert_eq!(ks.stage(), KeyScheduleStage::EarlySecret);
        let expected_early =
            hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        assert_eq!(to_hex(&ks.current_secret), to_hex(&expected_early));

        // Step 2: Handshake Secret (from DHE shared secret)
        // DHE shared secret from RFC 8448 Section 3
        let dhe_shared = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        ks.derive_handshake_secret(&dhe_shared).unwrap();
        assert_eq!(ks.stage(), KeyScheduleStage::HandshakeSecret);

        // Verify handshake secret matches RFC 8448
        let expected_hs = hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
        assert_eq!(to_hex(&ks.current_secret), to_hex(&expected_hs));

        // Step 3: Handshake traffic secrets
        // Transcript hash at CH..SH from RFC 8448
        let transcript_ch_sh =
            hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let (client_hs, server_hs) = ks
            .derive_handshake_traffic_secrets(&transcript_ch_sh)
            .unwrap();

        let expected_client_hs =
            hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
        let expected_server_hs =
            hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
        assert_eq!(to_hex(&client_hs), to_hex(&expected_client_hs));
        assert_eq!(to_hex(&server_hs), to_hex(&expected_server_hs));

        // Step 4: Master Secret
        ks.derive_master_secret().unwrap();
        assert_eq!(ks.stage(), KeyScheduleStage::MasterSecret);
        // Verify master secret matches RFC 8448
        let expected_ms = hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
        assert_eq!(to_hex(&ks.current_secret), to_hex(&expected_ms));

        // Step 5: Application traffic secrets
        // Transcript hash at CH..SF from RFC 8448
        let transcript_ch_sf =
            hex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
        let (client_app, server_app) = ks.derive_app_traffic_secrets(&transcript_ch_sf).unwrap();

        let expected_client_app =
            hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
        let expected_server_app =
            hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");
        assert_eq!(to_hex(&client_app), to_hex(&expected_client_app));
        assert_eq!(to_hex(&server_app), to_hex(&expected_server_app));
    }

    #[test]
    fn test_finished_key_and_verify_data() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let ks = KeySchedule::new(params);

        // Server finished key derived from server_hs_traffic_secret
        let server_hs_secret =
            hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
        let finished_key = ks.derive_finished_key(&server_hs_secret).unwrap();
        assert_eq!(finished_key.len(), 32);

        // The finished key should be deterministic
        let finished_key2 = ks.derive_finished_key(&server_hs_secret).unwrap();
        assert_eq!(finished_key, finished_key2);
    }

    #[test]
    fn test_key_schedule_stage_enforcement() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks = KeySchedule::new(params);

        // Cannot derive handshake secret before early secret
        assert!(ks.derive_handshake_secret(b"test").is_err());

        // Cannot derive master secret before handshake secret
        assert!(ks.derive_master_secret().is_err());

        // Cannot derive traffic secrets from wrong stage
        assert!(ks.derive_handshake_traffic_secrets(&[0u8; 32]).is_err());
        assert!(ks.derive_app_traffic_secrets(&[0u8; 32]).is_err());

        // Proper sequence works
        ks.derive_early_secret(None).unwrap();
        ks.derive_handshake_secret(b"shared_secret").unwrap();
        ks.derive_master_secret().unwrap();
        assert_eq!(ks.stage(), KeyScheduleStage::MasterSecret);
    }

    #[test]
    fn test_traffic_secret_update() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let ks = KeySchedule::new(params);

        let secret = hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
        let updated = ks.update_traffic_secret(&secret).unwrap();
        assert_eq!(updated.len(), 32);
        // Updated secret should differ from original
        assert_ne!(to_hex(&updated), to_hex(&secret));
    }

    #[test]
    fn test_key_schedule_sha384() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_256_GCM_SHA384).unwrap();
        let mut ks = KeySchedule::new(params);
        assert_eq!(ks.hash_len(), 48);

        ks.derive_early_secret(None).unwrap();
        assert_eq!(ks.current_secret.len(), 48);

        ks.derive_handshake_secret(&[0u8; 48]).unwrap();
        assert_eq!(ks.current_secret.len(), 48);

        let (client_hs, server_hs) = ks.derive_handshake_traffic_secrets(&[0u8; 48]).unwrap();
        assert_eq!(client_hs.len(), 48);
        assert_eq!(server_hs.len(), 48);

        ks.derive_master_secret().unwrap();
        assert_eq!(ks.current_secret.len(), 48);
    }

    #[test]
    fn test_early_secret_with_psk() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks_no_psk = KeySchedule::new(params.clone());
        ks_no_psk.derive_early_secret(None).unwrap();
        let no_psk_secret = ks_no_psk.current_secret.clone();

        let mut ks_psk = KeySchedule::new(params);
        let psk = vec![0xDE; 32];
        ks_psk.derive_early_secret(Some(&psk)).unwrap();

        // PSK vs zero-PSK should produce different early secrets
        assert_ne!(ks_psk.current_secret, no_psk_secret);
        assert_eq!(ks_psk.current_secret.len(), 32);
    }

    #[test]
    fn test_early_traffic_secret() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks = KeySchedule::new(params);
        ks.derive_early_secret(Some(&[0xAA; 32])).unwrap();

        let ch_hash = [0xBB; 32];
        let early_traffic = ks.derive_early_traffic_secret(&ch_hash).unwrap();
        assert_eq!(early_traffic.len(), 32);

        // Deterministic
        let early_traffic2 = ks.derive_early_traffic_secret(&ch_hash).unwrap();
        assert_eq!(early_traffic, early_traffic2);

        // Different CH hash → different secret
        let early_traffic3 = ks.derive_early_traffic_secret(&[0xCC; 32]).unwrap();
        assert_ne!(early_traffic, early_traffic3);
    }

    #[test]
    fn test_early_traffic_secret_wrong_stage() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks = KeySchedule::new(params);

        // Initial stage → should fail
        assert!(ks.derive_early_traffic_secret(&[0u8; 32]).is_err());

        // After handshake secret → should fail
        ks.derive_early_secret(None).unwrap();
        ks.derive_handshake_secret(&[0u8; 32]).unwrap();
        assert!(ks.derive_early_traffic_secret(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_binder_key_resumption_vs_external() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks = KeySchedule::new(params);
        ks.derive_early_secret(Some(&[0xAA; 32])).unwrap();

        let res_binder = ks.derive_binder_key(false).unwrap(); // resumption
        let ext_binder = ks.derive_binder_key(true).unwrap(); // external

        assert_eq!(res_binder.len(), 32);
        assert_eq!(ext_binder.len(), 32);
        // Different labels → different keys
        assert_ne!(res_binder, ext_binder);
    }

    #[test]
    fn test_binder_key_wrong_stage() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks = KeySchedule::new(params);
        ks.derive_early_secret(None).unwrap();
        ks.derive_handshake_secret(&[0u8; 32]).unwrap();

        // HandshakeSecret stage → should fail
        assert!(ks.derive_binder_key(false).is_err());
    }

    #[test]
    fn test_exporter_master_secret() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks = KeySchedule::new(params);
        ks.derive_early_secret(None).unwrap();
        ks.derive_handshake_secret(&[0xAA; 32]).unwrap();
        ks.derive_master_secret().unwrap();

        let transcript = [0xBB; 32];
        let exp = ks.derive_exporter_master_secret(&transcript).unwrap();
        assert_eq!(exp.len(), 32);

        // Deterministic
        let exp2 = ks.derive_exporter_master_secret(&transcript).unwrap();
        assert_eq!(exp, exp2);
    }

    #[test]
    fn test_exporter_master_secret_wrong_stage() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks = KeySchedule::new(params);
        ks.derive_early_secret(None).unwrap();

        // EarlySecret stage → should fail
        assert!(ks.derive_exporter_master_secret(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_resumption_master_secret() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks = KeySchedule::new(params);
        ks.derive_early_secret(None).unwrap();
        ks.derive_handshake_secret(&[0xAA; 32]).unwrap();
        ks.derive_master_secret().unwrap();

        let transcript_cf = [0xCC; 32];
        let rms = ks.derive_resumption_master_secret(&transcript_cf).unwrap();
        assert_eq!(rms.len(), 32);

        // Different transcript → different secret
        let rms2 = ks.derive_resumption_master_secret(&[0xDD; 32]).unwrap();
        assert_ne!(rms, rms2);
    }

    #[test]
    fn test_resumption_psk_derivation() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let ks = KeySchedule::new(params);

        let rms = vec![0xAA; 32];
        let nonce1 = vec![0x01];
        let nonce2 = vec![0x02];

        let psk1 = ks.derive_resumption_psk(&rms, &nonce1).unwrap();
        let psk2 = ks.derive_resumption_psk(&rms, &nonce2).unwrap();

        assert_eq!(psk1.len(), 32);
        assert_eq!(psk2.len(), 32);
        // Different nonces → different PSKs
        assert_ne!(psk1, psk2);
    }

    #[test]
    fn test_compute_finished_verify_data() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks = KeySchedule::new(params);
        ks.derive_early_secret(None).unwrap();
        ks.derive_handshake_secret(&[0xAA; 32]).unwrap();

        let (client_hs, _server_hs) = ks.derive_handshake_traffic_secrets(&[0xBB; 32]).unwrap();

        let finished_key = ks.derive_finished_key(&client_hs).unwrap();
        let verify_data = ks
            .compute_finished_verify_data(&finished_key, &[0xCC; 32])
            .unwrap();
        assert_eq!(verify_data.len(), 32);

        // Deterministic
        let verify_data2 = ks
            .compute_finished_verify_data(&finished_key, &[0xCC; 32])
            .unwrap();
        assert_eq!(verify_data, verify_data2);

        // Different transcript → different verify_data
        let verify_data3 = ks
            .compute_finished_verify_data(&finished_key, &[0xDD; 32])
            .unwrap();
        assert_ne!(verify_data, verify_data3);
    }

    #[test]
    fn test_double_derive_early_secret_fails() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks = KeySchedule::new(params);
        ks.derive_early_secret(None).unwrap();

        // Second derive_early_secret should fail (already in EarlySecret stage)
        assert!(ks.derive_early_secret(None).is_err());
    }

    #[test]
    fn test_early_exporter_master_secret() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks = KeySchedule::new(params);
        ks.derive_early_secret(Some(&[0xAA; 32])).unwrap();

        let ch_hash = [0xBB; 32];
        let eems = ks.derive_early_exporter_master_secret(&ch_hash).unwrap();
        assert_eq!(eems.len(), 32);

        // Deterministic
        let eems2 = ks.derive_early_exporter_master_secret(&ch_hash).unwrap();
        assert_eq!(eems, eems2);

        // Different transcript → different secret
        let eems3 = ks.derive_early_exporter_master_secret(&[0xCC; 32]).unwrap();
        assert_ne!(eems, eems3);

        // Different from early traffic secret (different label)
        let ets = ks.derive_early_traffic_secret(&ch_hash).unwrap();
        assert_ne!(eems, ets);
    }

    #[test]
    fn test_early_exporter_master_secret_wrong_stage() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let mut ks = KeySchedule::new(params);

        // Initial stage → should fail
        assert!(ks.derive_early_exporter_master_secret(&[0u8; 32]).is_err());

        // After handshake secret → should fail
        ks.derive_early_secret(None).unwrap();
        ks.derive_handshake_secret(&[0u8; 32]).unwrap();
        assert!(ks.derive_early_exporter_master_secret(&[0u8; 32]).is_err());

        // After master secret → should fail
        ks.derive_master_secret().unwrap();
        assert!(ks.derive_early_exporter_master_secret(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_traffic_secret_update_chain() {
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        let ks = KeySchedule::new(params);

        let secret0 = hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
        let secret1 = ks.update_traffic_secret(&secret0).unwrap();
        let secret2 = ks.update_traffic_secret(&secret1).unwrap();

        // Each update produces a different secret
        assert_ne!(secret0, secret1);
        assert_ne!(secret1, secret2);
        assert_ne!(secret0, secret2);

        // All are 32 bytes
        assert_eq!(secret1.len(), 32);
        assert_eq!(secret2.len(), 32);
    }
}
