//! HPKE (Hybrid Public Key Encryption) — RFC 9180.
//!
//! Implements DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM.
//! Supports Base mode (mode=0x00) and PSK mode (mode=0x01).

use crate::hkdf::Hkdf;
use crate::hmac::Hmac;
use crate::modes::gcm::{gcm_decrypt, gcm_encrypt};
use crate::provider::Digest;
use crate::sha2::Sha256;
use crate::x25519::{X25519PrivateKey, X25519PublicKey};
use hitls_types::CryptoError;
use zeroize::Zeroize;

// --- Constants ---

/// HPKE Mode: Base (0x00).
const MODE_BASE: u8 = 0x00;
/// HPKE Mode: PSK (0x01).
const MODE_PSK: u8 = 0x01;

/// KEM identifier: DHKEM(X25519, HKDF-SHA256).
const KEM_X25519_HKDF_SHA256: u16 = 0x0020;
/// KDF identifier: HKDF-SHA256.
const KDF_HKDF_SHA256: u16 = 0x0001;
/// AEAD identifier: AES-128-GCM.
const AEAD_AES_128_GCM: u16 = 0x0001;

/// AES-128-GCM key size (Nk).
const NK: usize = 16;
/// AES-128-GCM nonce size (Nn).
const NN: usize = 12;
/// SHA-256 output size (Nh) and KEM shared secret size (Nsecret).
const NH: usize = 32;

fn sha256_factory() -> Box<dyn Digest> {
    Box::new(Sha256::new())
}

// --- Suite IDs ---

/// KEM suite_id = "KEM" || I2OSP(kem_id, 2).
fn kem_suite_id() -> Vec<u8> {
    let mut id = b"KEM".to_vec();
    id.extend_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
    id
}

/// HPKE suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2).
fn hpke_suite_id() -> Vec<u8> {
    let mut id = b"HPKE".to_vec();
    id.extend_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
    id.extend_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
    id.extend_from_slice(&AEAD_AES_128_GCM.to_be_bytes());
    id
}

// --- Labeled Extract / Expand (RFC 9180 §4) ---

/// LabeledExtract(salt, label, ikm) = HMAC-SHA-256(salt, "HPKE-v1" || suite_id || label || ikm).
fn labeled_extract(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut labeled_ikm = b"HPKE-v1".to_vec();
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    let effective_salt = if salt.is_empty() {
        vec![0u8; NH]
    } else {
        salt.to_vec()
    };

    Hmac::mac(sha256_factory, &effective_salt, &labeled_ikm)
}

/// LabeledExpand(prk, label, info, L) = HKDF-Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L).
fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let mut labeled_info = (len as u16).to_be_bytes().to_vec();
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    Hkdf::from_prk(prk).expand(&labeled_info, len)
}

// --- DHKEM(X25519, HKDF-SHA256) (RFC 9180 §4.1) ---

/// DeriveKeyPair(ikm): deterministic key derivation from IKM.
fn kem_derive_key_pair(ikm: &[u8]) -> Result<(X25519PrivateKey, X25519PublicKey), CryptoError> {
    let sid = kem_suite_id();
    let dkp_prk = labeled_extract(&sid, &[], b"dkp_prk", ikm)?;
    let sk_bytes = labeled_expand(&sid, &dkp_prk, b"sk", &[], 32)?;
    let sk = X25519PrivateKey::new(&sk_bytes)?;
    let pk = sk.public_key();
    Ok((sk, pk))
}

/// ExtractAndExpand(dh, kem_context) → shared_secret (RFC 9180 §4.1).
fn kem_extract_and_expand(dh: &[u8], kem_context: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sid = kem_suite_id();
    let eae_prk = labeled_extract(&sid, &[], b"eae_prk", dh)?;
    labeled_expand(&sid, &eae_prk, b"shared_secret", kem_context, NH)
}

/// Encap with deterministic ephemeral key (for testing with known IKM).
fn kem_encap_deterministic(
    pk_r: &X25519PublicKey,
    ikm_e: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let (sk_e, pk_e) = kem_derive_key_pair(ikm_e)?;
    let dh = sk_e.diffie_hellman(pk_r)?;
    let enc = pk_e.as_bytes().to_vec();

    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(pk_r.as_bytes());

    let shared_secret = kem_extract_and_expand(&dh, &kem_context)?;
    Ok((shared_secret, enc))
}

/// Encap with random ephemeral key (production use).
fn kem_encap(pk_r: &X25519PublicKey) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let sk_e = X25519PrivateKey::generate()?;
    let pk_e = sk_e.public_key();
    let dh = sk_e.diffie_hellman(pk_r)?;
    let enc = pk_e.as_bytes().to_vec();

    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(pk_r.as_bytes());

    let shared_secret = kem_extract_and_expand(&dh, &kem_context)?;
    Ok((shared_secret, enc))
}

/// Decap: recover shared_secret from enc and recipient's private key.
fn kem_decap(enc: &[u8], sk_r: &X25519PrivateKey) -> Result<Vec<u8>, CryptoError> {
    let pk_e = X25519PublicKey::new(enc)?;
    let dh = sk_r.diffie_hellman(&pk_e)?;

    let pk_r = sk_r.public_key();
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(pk_r.as_bytes());

    kem_extract_and_expand(&dh, &kem_context)
}

// --- HPKE Key Schedule (RFC 9180 §5.1) ---

/// Key schedule output: (key, base_nonce, exporter_secret).
type KsOutput = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Derive (key, base_nonce, exporter_secret) from the key schedule.
fn key_schedule(
    mode: u8,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<KsOutput, CryptoError> {
    let sid = hpke_suite_id();

    let psk_id_hash = labeled_extract(&sid, &[], b"psk_id_hash", psk_id)?;
    let info_hash = labeled_extract(&sid, &[], b"info_hash", info)?;

    let mut ks_context = Vec::with_capacity(1 + NH + NH);
    ks_context.push(mode);
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);

    let secret = labeled_extract(&sid, shared_secret, b"secret", psk)?;

    let key = labeled_expand(&sid, &secret, b"key", &ks_context, NK)?;
    let base_nonce = labeled_expand(&sid, &secret, b"base_nonce", &ks_context, NN)?;
    let exporter_secret = labeled_expand(&sid, &secret, b"exp", &ks_context, NH)?;

    Ok((key, base_nonce, exporter_secret))
}

// --- HPKE Context ---

/// HPKE encryption context.
///
/// After setup, use `seal`/`open` for AEAD encryption/decryption,
/// and `export` for secret export.
#[derive(Clone)]
pub struct HpkeCtx {
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    exporter_secret: Vec<u8>,
    seq: u64,
}

impl HpkeCtx {
    /// Set up an HPKE sender context (Base mode).
    ///
    /// Returns `(context, enc)` where `enc` is the encapsulated key to send to the recipient.
    pub fn setup_sender(
        recipient_public_key: &[u8],
        info: &[u8],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        let pk_r = X25519PublicKey::new(recipient_public_key)?;
        let (shared_secret, enc) = kem_encap(&pk_r)?;
        let (key, base_nonce, exporter_secret) =
            key_schedule(MODE_BASE, &shared_secret, info, &[], &[])?;
        Ok((
            Self {
                key,
                base_nonce,
                exporter_secret,
                seq: 0,
            },
            enc,
        ))
    }

    /// Set up an HPKE recipient context (Base mode).
    pub fn setup_recipient(
        private_key: &[u8],
        enc: &[u8],
        info: &[u8],
    ) -> Result<Self, CryptoError> {
        let sk_r = X25519PrivateKey::new(private_key)?;
        let shared_secret = kem_decap(enc, &sk_r)?;
        let (key, base_nonce, exporter_secret) =
            key_schedule(MODE_BASE, &shared_secret, info, &[], &[])?;
        Ok(Self {
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
        })
    }

    /// Set up an HPKE sender context (PSK mode).
    pub fn setup_sender_psk(
        recipient_public_key: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        if psk.is_empty() || psk_id.is_empty() {
            return Err(CryptoError::InvalidArg);
        }
        let pk_r = X25519PublicKey::new(recipient_public_key)?;
        let (shared_secret, enc) = kem_encap(&pk_r)?;
        let (key, base_nonce, exporter_secret) =
            key_schedule(MODE_PSK, &shared_secret, info, psk, psk_id)?;
        Ok((
            Self {
                key,
                base_nonce,
                exporter_secret,
                seq: 0,
            },
            enc,
        ))
    }

    /// Set up an HPKE recipient context (PSK mode).
    pub fn setup_recipient_psk(
        private_key: &[u8],
        enc: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, CryptoError> {
        if psk.is_empty() || psk_id.is_empty() {
            return Err(CryptoError::InvalidArg);
        }
        let sk_r = X25519PrivateKey::new(private_key)?;
        let shared_secret = kem_decap(enc, &sk_r)?;
        let (key, base_nonce, exporter_secret) =
            key_schedule(MODE_PSK, &shared_secret, info, psk, psk_id)?;
        Ok(Self {
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
        })
    }

    /// Encrypt a plaintext with associated data (AEAD seal).
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.compute_nonce();
        let ct = gcm_encrypt(&self.key, &nonce, aad, plaintext)?;
        self.increment_seq()?;
        Ok(ct)
    }

    /// Decrypt a ciphertext with associated data (AEAD open).
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.compute_nonce();
        let pt = gcm_decrypt(&self.key, &nonce, aad, ciphertext)?;
        self.increment_seq()?;
        Ok(pt)
    }

    /// Export a secret of `len` bytes from the HPKE context.
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, CryptoError> {
        let sid = hpke_suite_id();
        labeled_expand(&sid, &self.exporter_secret, b"sec", exporter_context, len)
    }

    /// Compute nonce = base_nonce XOR I2OSP(seq, Nn).
    fn compute_nonce(&self) -> Vec<u8> {
        let seq_bytes = self.seq.to_be_bytes(); // 8 bytes
        let mut nonce = self.base_nonce.clone();
        // XOR the 8-byte seq into the last 8 bytes of the 12-byte nonce
        for i in 0..8 {
            nonce[NN - 8 + i] ^= seq_bytes[i];
        }
        nonce
    }

    /// Increment the sequence number.
    fn increment_seq(&mut self) -> Result<(), CryptoError> {
        if self.seq == u64::MAX {
            return Err(CryptoError::InvalidArg);
        }
        self.seq += 1;
        Ok(())
    }
}

impl Drop for HpkeCtx {
    fn drop(&mut self) {
        self.key.zeroize();
        self.base_nonce.zeroize();
        self.exporter_secret.zeroize();
    }
}

// --- Deterministic setup (for testing) ---

/// Set up a sender context with a deterministic ephemeral key (for testing only).
#[cfg(test)]
fn setup_sender_deterministic(
    pk_r: &[u8],
    info: &[u8],
    ikm_e: &[u8],
) -> Result<(HpkeCtx, Vec<u8>), CryptoError> {
    let pk_r = X25519PublicKey::new(pk_r)?;
    let (shared_secret, enc) = kem_encap_deterministic(&pk_r, ikm_e)?;
    let (key, base_nonce, exporter_secret) =
        key_schedule(MODE_BASE, &shared_secret, info, &[], &[])?;
    Ok((
        HpkeCtx {
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
        },
        enc,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ---- RFC 9180 Appendix A.1 ----
    // DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
    // mode = 0 (Base)

    const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    const IKM_E: &str = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234";
    const PK_EM: &str = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
    const SK_EM: &str = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";
    const IKM_R: &str = "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037";
    const PK_RM: &str = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d";
    const SK_RM: &str = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
    const ENC: &str = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
    const SHARED_SECRET: &str = "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc";
    const KEY_SCHEDULE_CONTEXT: &str = "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449";
    const SECRET: &str = "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397";
    const KEY: &str = "4531685d41d65f03dc48f6b8302c05b0";
    const BASE_NONCE: &str = "56d890e5accaaf011cff4b7d";
    const EXPORTER_SECRET: &str =
        "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8";

    #[test]
    fn test_kem_derive_key_pair() {
        let (sk, pk) = kem_derive_key_pair(&hex(IKM_E)).unwrap();
        assert_eq!(to_hex(pk.as_bytes()), PK_EM);

        let (sk_r, pk_r) = kem_derive_key_pair(&hex(IKM_R)).unwrap();
        assert_eq!(to_hex(pk_r.as_bytes()), PK_RM);
    }

    #[test]
    fn test_kem_encap_decap() {
        let pk_r = X25519PublicKey::new(&hex(PK_RM)).unwrap();
        let (shared_secret, enc) = kem_encap_deterministic(&pk_r, &hex(IKM_E)).unwrap();
        assert_eq!(to_hex(&enc), ENC);
        assert_eq!(to_hex(&shared_secret), SHARED_SECRET);

        // Decap with recipient's private key
        let sk_r = X25519PrivateKey::new(&hex(SK_RM)).unwrap();
        let shared_secret_r = kem_decap(&enc, &sk_r).unwrap();
        assert_eq!(to_hex(&shared_secret_r), SHARED_SECRET);
    }

    #[test]
    fn test_key_schedule() {
        let (key, base_nonce, exporter_secret) =
            key_schedule(MODE_BASE, &hex(SHARED_SECRET), &hex(INFO), &[], &[]).unwrap();
        assert_eq!(to_hex(&key), KEY);
        assert_eq!(to_hex(&base_nonce), BASE_NONCE);
        assert_eq!(to_hex(&exporter_secret), EXPORTER_SECRET);
    }

    #[test]
    fn test_seal_open_seq0() {
        let (mut ctx, enc) =
            setup_sender_deterministic(&hex(PK_RM), &hex(INFO), &hex(IKM_E)).unwrap();

        let pt = hex("4265617574792069732074727574682c20747275746820626561757479");
        let aad = hex("436f756e742d30");
        let expected_ct = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a";

        let ct = ctx.seal(&aad, &pt).unwrap();
        assert_eq!(to_hex(&ct), expected_ct);

        // Decrypt with recipient
        let mut recipient = HpkeCtx::setup_recipient(&hex(SK_RM), &hex(ENC), &hex(INFO)).unwrap();
        let decrypted = recipient.open(&aad, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_seal_open_seq1() {
        let (mut ctx, _) =
            setup_sender_deterministic(&hex(PK_RM), &hex(INFO), &hex(IKM_E)).unwrap();

        // Seal seq 0 first (to advance the counter)
        let pt = hex("4265617574792069732074727574682c20747275746820626561757479");
        let aad0 = hex("436f756e742d30");
        let _ = ctx.seal(&aad0, &pt).unwrap();

        // Seal seq 1
        let aad1 = hex("436f756e742d31");
        let expected_ct1 = "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84";
        let ct1 = ctx.seal(&aad1, &pt).unwrap();
        assert_eq!(to_hex(&ct1), expected_ct1);
    }

    #[test]
    fn test_export() {
        let (ctx, _) = setup_sender_deterministic(&hex(PK_RM), &hex(INFO), &hex(IKM_E)).unwrap();

        // Export with empty context
        let exported = ctx.export(&[], 32).unwrap();
        assert_eq!(
            to_hex(&exported),
            "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee"
        );

        // Export with context = 0x00
        let exported = ctx.export(&hex("00"), 32).unwrap();
        assert_eq!(
            to_hex(&exported),
            "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5"
        );

        // Export with "TestContext"
        let exported = ctx.export(&hex("54657374436f6e74657874"), 32).unwrap();
        assert_eq!(
            to_hex(&exported),
            "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931"
        );
    }

    #[test]
    fn test_hpke_tampered_ciphertext_open() {
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        let (mut sender, enc) = HpkeCtx::setup_sender(pk_r.as_bytes(), b"info").unwrap();
        let mut recipient = HpkeCtx::setup_recipient(&sk_bytes, &enc, b"info").unwrap();

        let ct = sender.seal(b"aad", b"hello").unwrap();
        // Flip a bit in the ciphertext
        let mut tampered = ct.clone();
        tampered[0] ^= 0x01;
        assert!(recipient.open(b"aad", &tampered).is_err());
    }

    #[test]
    fn test_hpke_wrong_aad_open() {
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        let (mut sender, enc) = HpkeCtx::setup_sender(pk_r.as_bytes(), b"info").unwrap();
        let mut recipient = HpkeCtx::setup_recipient(&sk_bytes, &enc, b"info").unwrap();

        let ct = sender.seal(b"correct", b"payload").unwrap();
        // Open with wrong AAD
        assert!(recipient.open(b"wrong", &ct).is_err());
    }

    #[test]
    fn test_hpke_psk_mode_roundtrip() {
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        let psk = b"my-pre-shared-key";
        let psk_id = b"psk-identifier";

        let (mut sender, enc) =
            HpkeCtx::setup_sender_psk(pk_r.as_bytes(), b"info", psk, psk_id).unwrap();
        let mut recipient =
            HpkeCtx::setup_recipient_psk(&sk_bytes, &enc, b"info", psk, psk_id).unwrap();

        let ct = sender.seal(b"aad", b"psk message").unwrap();
        let pt = recipient.open(b"aad", &ct).unwrap();
        assert_eq!(pt, b"psk message");
    }

    #[test]
    fn test_hpke_psk_empty_psk_rejected() {
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        // Empty PSK → error
        assert!(HpkeCtx::setup_sender_psk(pk_r.as_bytes(), b"info", &[], b"id").is_err());
        // Empty PSK ID → error
        assert!(HpkeCtx::setup_sender_psk(pk_r.as_bytes(), b"info", b"psk", &[]).is_err());

        // Same for recipient side
        assert!(HpkeCtx::setup_recipient_psk(&sk_bytes, &[0u8; 32], b"info", &[], b"id").is_err());
        assert!(HpkeCtx::setup_recipient_psk(&sk_bytes, &[0u8; 32], b"info", b"psk", &[]).is_err());
    }

    #[test]
    fn test_roundtrip_random() {
        // Generate random key pair from raw bytes
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        let sk_r = X25519PrivateKey::new(&sk_bytes).unwrap();
        let pk_r = sk_r.public_key();

        let info = b"test info";
        let (mut sender, enc) = HpkeCtx::setup_sender(pk_r.as_bytes(), info).unwrap();
        let mut recipient = HpkeCtx::setup_recipient(&sk_bytes, &enc, info).unwrap();

        let aad = b"associated data";
        let pt = b"hello, HPKE!";

        let ct = sender.seal(aad, pt).unwrap();
        let decrypted = recipient.open(aad, &ct).unwrap();
        assert_eq!(decrypted, pt);

        // Second message
        let ct2 = sender.seal(b"aad2", b"second message").unwrap();
        let decrypted2 = recipient.open(b"aad2", &ct2).unwrap();
        assert_eq!(decrypted2, b"second message");
    }
}
