//! Hybrid KEM combining a classical DH key exchange with ML-KEM.
//!
//! Supports 12 parameter combinations: 3 X25519 + 9 ECDH (P-256/P-384/P-521)
//! variants crossed with ML-KEM-512/768/1024. The shared secret is
//! SHA-256(ss_classical || ss_pq).
//!
//! Byte ordering follows the C reference (`CRYPT_HybridGetKeyPtr`):
//! - X25519 variants: `[ML-KEM data || X25519 data]`
//! - ECDH variants:   `[ECDH data || ML-KEM data]`

use crate::ecdh::EcdhKeyPair;
use crate::mlkem::MlKemKeyPair;
use crate::sha2::Sha256;
use crate::x25519::{X25519PrivateKey, X25519PublicKey, X25519_KEY_SIZE};
use hitls_types::{CryptoError, EccCurveId, HybridKemParamId};
use zeroize::Zeroize;

/// Classic (non-PQ) key exchange type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassicType {
    X25519,
    EcdhP256,
    EcdhP384,
    EcdhP521,
}

/// Resolved parameters for a hybrid KEM variant.
#[derive(Debug, Clone, Copy)]
struct HybridKemParams {
    classic_type: ClassicType,
    mlkem_param: u32,
    /// Classic public key length in bytes.
    classic_pk_len: usize,
    /// ML-KEM ciphertext length in bytes.
    mlkem_ct_len: usize,
}

/// Return the resolved parameters for a `HybridKemParamId`.
fn get_params(param_id: HybridKemParamId) -> HybridKemParams {
    use ClassicType::*;
    use HybridKemParamId::*;

    let (classic_type, mlkem_param) = match param_id {
        X25519MlKem512 => (X25519, 512),
        X25519MlKem768 => (X25519, 768),
        X25519MlKem1024 => (X25519, 1024),
        EcdhNistP256MlKem512 => (EcdhP256, 512),
        EcdhNistP256MlKem768 => (EcdhP256, 768),
        EcdhNistP256MlKem1024 => (EcdhP256, 1024),
        EcdhNistP384MlKem512 => (EcdhP384, 512),
        EcdhNistP384MlKem768 => (EcdhP384, 768),
        EcdhNistP384MlKem1024 => (EcdhP384, 1024),
        EcdhNistP521MlKem512 => (EcdhP521, 512),
        EcdhNistP521MlKem768 => (EcdhP521, 768),
        EcdhNistP521MlKem1024 => (EcdhP521, 1024),
    };

    let classic_pk_len = match classic_type {
        X25519 => 32,
        EcdhP256 => 65,
        EcdhP384 => 97,
        EcdhP521 => 133,
    };

    let mlkem_ct_len = match mlkem_param {
        512 => 768,
        768 => 1088,
        1024 => 1568,
        _ => unreachable!(),
    };

    HybridKemParams {
        classic_type,
        mlkem_param,
        classic_pk_len,
        mlkem_ct_len,
    }
}

/// Return the ML-KEM encapsulation key length for a given parameter set.
fn mlkem_ek_len(mlkem_param: u32) -> usize {
    match mlkem_param {
        512 => 800,
        768 => 1184,
        1024 => 1568,
        _ => unreachable!(),
    }
}

/// Map a `ClassicType` to its `EccCurveId`.
fn classic_curve_id(ct: ClassicType) -> EccCurveId {
    match ct {
        ClassicType::EcdhP256 => EccCurveId::NistP256,
        ClassicType::EcdhP384 => EccCurveId::NistP384,
        ClassicType::EcdhP521 => EccCurveId::NistP521,
        ClassicType::X25519 => unreachable!("X25519 is not an ECC curve"),
    }
}

/// Internal representation of the classic DH key material.
enum ClassicDh {
    /// X25519 key pair with inline fixed-size arrays.
    X25519 {
        sk_bytes: [u8; 32],
        pk_bytes: [u8; 32],
    },
    /// X25519 public key only (for encapsulate-only use).
    X25519PubOnly { pk_bytes: [u8; 32] },
    /// ECDH key pair (P-256/P-384/P-521).
    Ecdh(Box<EcdhKeyPair>),
    /// ECDH public key only (for encapsulate-only use).
    EcdhPubOnly {
        curve_id: EccCurveId,
        pk_bytes: Vec<u8>,
    },
}

impl Drop for ClassicDh {
    fn drop(&mut self) {
        if let ClassicDh::X25519 { sk_bytes, .. } = self {
            sk_bytes.zeroize();
        }
        // EcdhKeyPair already zeroizes in its own Drop
    }
}

impl ClassicDh {
    /// Return the public key bytes for this classic DH key.
    fn pk_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        match self {
            ClassicDh::X25519 { pk_bytes, .. } | ClassicDh::X25519PubOnly { pk_bytes } => {
                Ok(pk_bytes.to_vec())
            }
            ClassicDh::Ecdh(kp) => kp.public_key_bytes(),
            ClassicDh::EcdhPubOnly { pk_bytes, .. } => Ok(pk_bytes.clone()),
        }
    }

    /// Perform encapsulation-side DH: generate ephemeral keypair, compute
    /// shared secret against the stored public key.
    /// Returns `(ephemeral_public_key, shared_secret)`.
    fn encaps_dh(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        match self {
            ClassicDh::X25519 { pk_bytes, .. } | ClassicDh::X25519PubOnly { pk_bytes } => {
                let sk_e = X25519PrivateKey::generate()?;
                let pk_e = sk_e.public_key();
                let pk_r = X25519PublicKey::new(pk_bytes)?;
                let ss = sk_e.diffie_hellman(&pk_r)?;
                Ok((pk_e.as_bytes().to_vec(), ss))
            }
            ClassicDh::Ecdh(kp) => {
                let peer_pk = kp.public_key_bytes()?;
                let ephemeral = EcdhKeyPair::generate(kp.curve_id())?;
                let ss = ephemeral.compute_shared_secret(&peer_pk)?;
                let ct = ephemeral.public_key_bytes()?;
                Ok((ct, ss))
            }
            ClassicDh::EcdhPubOnly { curve_id, pk_bytes } => {
                let ephemeral = EcdhKeyPair::generate(*curve_id)?;
                let ss = ephemeral.compute_shared_secret(pk_bytes)?;
                let ct = ephemeral.public_key_bytes()?;
                Ok((ct, ss))
            }
        }
    }

    /// Perform decapsulation-side DH: compute shared secret using our
    /// private key and the peer's ephemeral public key from the ciphertext.
    fn decaps_dh(&self, peer_ephemeral_pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            ClassicDh::X25519 { sk_bytes, .. } => {
                let sk = X25519PrivateKey::new(sk_bytes)?;
                let pk_e = X25519PublicKey::new(peer_ephemeral_pk)?;
                sk.diffie_hellman(&pk_e)
            }
            ClassicDh::Ecdh(kp) => kp.compute_shared_secret(peer_ephemeral_pk),
            ClassicDh::X25519PubOnly { .. } | ClassicDh::EcdhPubOnly { .. } => {
                Err(CryptoError::InvalidArg)
            }
        }
    }
}

/// A hybrid KEM key pair combining a classical DH exchange with ML-KEM.
///
/// Supports all 12 `HybridKemParamId` variants.
pub struct HybridKemKeyPair {
    param_id: HybridKemParamId,
    params: HybridKemParams,
    classic: ClassicDh,
    mlkem: MlKemKeyPair,
}

impl HybridKemKeyPair {
    /// Generate a new hybrid KEM key pair for the given parameter set.
    pub fn generate(param_id: HybridKemParamId) -> Result<Self, CryptoError> {
        let params = get_params(param_id);

        let classic = match params.classic_type {
            ClassicType::X25519 => {
                let mut sk_bytes = [0u8; X25519_KEY_SIZE];
                getrandom::getrandom(&mut sk_bytes).map_err(|_| CryptoError::BnRandGenFail)?;
                let sk = X25519PrivateKey::new(&sk_bytes)?;
                let pk = sk.public_key();
                ClassicDh::X25519 {
                    sk_bytes,
                    pk_bytes: *pk.as_bytes(),
                }
            }
            _ => {
                let curve_id = classic_curve_id(params.classic_type);
                ClassicDh::Ecdh(Box::new(EcdhKeyPair::generate(curve_id)?))
            }
        };

        let mlkem = MlKemKeyPair::generate(params.mlkem_param)?;
        Ok(Self {
            param_id,
            params,
            classic,
            mlkem,
        })
    }

    /// Construct a hybrid KEM key pair from a combined public key (encapsulate-only).
    ///
    /// The resulting key pair can only `encapsulate()`; calling `decapsulate()`
    /// will return an error.
    pub fn from_public_key(
        param_id: HybridKemParamId,
        combined_pk: &[u8],
    ) -> Result<Self, CryptoError> {
        let params = get_params(param_id);
        let ek_len = mlkem_ek_len(params.mlkem_param);
        let expected_len = params.classic_pk_len + ek_len;
        if combined_pk.len() != expected_len {
            return Err(CryptoError::InvalidArg);
        }

        let (classic_pk, mlkem_ek) = split_combined(
            combined_pk,
            params.classic_type,
            params.classic_pk_len,
            ek_len,
        );

        let classic = match params.classic_type {
            ClassicType::X25519 => {
                let mut pk_bytes = [0u8; 32];
                pk_bytes.copy_from_slice(classic_pk);
                ClassicDh::X25519PubOnly { pk_bytes }
            }
            _ => {
                let curve_id = classic_curve_id(params.classic_type);
                ClassicDh::EcdhPubOnly {
                    curve_id,
                    pk_bytes: classic_pk.to_vec(),
                }
            }
        };

        let mlkem = MlKemKeyPair::from_encapsulation_key(params.mlkem_param, mlkem_ek)?;
        Ok(Self {
            param_id,
            params,
            classic,
            mlkem,
        })
    }

    /// Return the `HybridKemParamId` for this key pair.
    pub fn param_id(&self) -> HybridKemParamId {
        self.param_id
    }

    /// Return the combined public key bytes.
    ///
    /// Byte ordering:
    /// - X25519 variants: `[ML-KEM ek || X25519 pk]`
    /// - ECDH variants:   `[ECDH pk || ML-KEM ek]`
    pub fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
        let classic_pk = self.classic.pk_bytes()?;
        let mlkem_ek = self.mlkem.encapsulation_key();
        let mut pk = Vec::with_capacity(classic_pk.len() + mlkem_ek.len());

        if self.params.classic_type == ClassicType::X25519 {
            pk.extend_from_slice(mlkem_ek);
            pk.extend_from_slice(&classic_pk);
        } else {
            pk.extend_from_slice(&classic_pk);
            pk.extend_from_slice(mlkem_ek);
        }
        Ok(pk)
    }

    /// Encapsulate: produce a shared secret and hybrid ciphertext.
    ///
    /// Returns `(shared_secret, ciphertext)` where `shared_secret` is 32 bytes.
    ///
    /// Ciphertext ordering:
    /// - X25519 variants: `[ML-KEM ct || X25519 ephemeral pk]`
    /// - ECDH variants:   `[ECDH ephemeral pk || ML-KEM ct]`
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let (classic_ct, ss_c) = self.classic.encaps_dh()?;
        let (ss_pq, ct_pq) = self.mlkem.encapsulate()?;

        let mut ct = Vec::with_capacity(classic_ct.len() + ct_pq.len());
        if self.params.classic_type == ClassicType::X25519 {
            ct.extend_from_slice(&ct_pq);
            ct.extend_from_slice(&classic_ct);
        } else {
            ct.extend_from_slice(&classic_ct);
            ct.extend_from_slice(&ct_pq);
        }

        let ss = combine_secrets(&ss_c, &ss_pq)?;
        Ok((ss, ct))
    }

    /// Decapsulate: recover the shared secret from a hybrid ciphertext.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let expected_ct_len = self.params.classic_pk_len + self.params.mlkem_ct_len;
        if ciphertext.len() != expected_ct_len {
            return Err(CryptoError::InvalidArg);
        }

        let (classic_ct, ct_pq) = if self.params.classic_type == ClassicType::X25519 {
            let (pq, cl) = ciphertext.split_at(self.params.mlkem_ct_len);
            (cl, pq)
        } else {
            ciphertext.split_at(self.params.classic_pk_len)
        };

        let ss_c = self.classic.decaps_dh(classic_ct)?;
        let ss_pq = self.mlkem.decapsulate(ct_pq)?;
        combine_secrets(&ss_c, &ss_pq)
    }
}

/// Split a combined buffer into (classic_part, mlkem_part) respecting
/// the byte ordering convention.
fn split_combined(
    buf: &[u8],
    classic_type: ClassicType,
    classic_len: usize,
    mlkem_len: usize,
) -> (&[u8], &[u8]) {
    debug_assert_eq!(buf.len(), classic_len + mlkem_len);
    if classic_type == ClassicType::X25519 {
        // [ML-KEM || X25519]
        let (mlkem, classic) = buf.split_at(mlkem_len);
        (classic, mlkem)
    } else {
        // [ECDH || ML-KEM]
        buf.split_at(classic_len)
    }
}

/// Combine two shared secrets: SHA-256(ss_classical || ss_pq).
fn combine_secrets(ss_classical: &[u8], ss_pq: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut hasher = Sha256::new();
    hasher.update(ss_classical)?;
    hasher.update(ss_pq)?;
    let hash = hasher.finish()?;
    Ok(hash.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All 12 hybrid KEM parameter IDs.
    const ALL_PARAM_IDS: [HybridKemParamId; 12] = [
        HybridKemParamId::X25519MlKem512,
        HybridKemParamId::X25519MlKem768,
        HybridKemParamId::X25519MlKem1024,
        HybridKemParamId::EcdhNistP256MlKem512,
        HybridKemParamId::EcdhNistP256MlKem768,
        HybridKemParamId::EcdhNistP256MlKem1024,
        HybridKemParamId::EcdhNistP384MlKem512,
        HybridKemParamId::EcdhNistP384MlKem768,
        HybridKemParamId::EcdhNistP384MlKem1024,
        HybridKemParamId::EcdhNistP521MlKem512,
        HybridKemParamId::EcdhNistP521MlKem768,
        HybridKemParamId::EcdhNistP521MlKem1024,
    ];

    /// Expected combined public key length for each variant.
    fn expected_pk_len(param_id: HybridKemParamId) -> usize {
        let p = get_params(param_id);
        p.classic_pk_len + mlkem_ek_len(p.mlkem_param)
    }

    /// Expected ciphertext length for each variant.
    fn expected_ct_len(param_id: HybridKemParamId) -> usize {
        let p = get_params(param_id);
        p.classic_pk_len + p.mlkem_ct_len
    }

    #[test]
    fn test_roundtrip_all_variants() {
        for &param_id in &ALL_PARAM_IDS {
            let kp = HybridKemKeyPair::generate(param_id).unwrap();
            assert_eq!(kp.param_id(), param_id);

            let (ss_enc, ct) = kp.encapsulate().unwrap();
            let ss_dec = kp.decapsulate(&ct).unwrap();
            assert_eq!(ss_enc, ss_dec, "roundtrip failed for {param_id:?}");
            assert_eq!(ss_enc.len(), 32, "shared secret should be 32 bytes");
        }
    }

    #[test]
    fn test_public_key_lengths() {
        for &param_id in &ALL_PARAM_IDS {
            let kp = HybridKemKeyPair::generate(param_id).unwrap();
            let pk = kp.public_key().unwrap();
            assert_eq!(
                pk.len(),
                expected_pk_len(param_id),
                "pk length mismatch for {param_id:?}"
            );
        }
    }

    #[test]
    fn test_ciphertext_lengths() {
        for &param_id in &ALL_PARAM_IDS {
            let kp = HybridKemKeyPair::generate(param_id).unwrap();
            let (_, ct) = kp.encapsulate().unwrap();
            assert_eq!(
                ct.len(),
                expected_ct_len(param_id),
                "ct length mismatch for {param_id:?}"
            );
        }
    }

    #[test]
    fn test_tampered_ciphertext() {
        for &param_id in &ALL_PARAM_IDS {
            let kp = HybridKemKeyPair::generate(param_id).unwrap();
            let (ss_enc, mut ct) = kp.encapsulate().unwrap();
            // Tamper in the middle of the ciphertext
            let mid = ct.len() / 2;
            ct[mid] ^= 0xff;
            let ss_dec = kp.decapsulate(&ct).unwrap();
            assert_ne!(
                ss_enc, ss_dec,
                "tampered ct should produce different ss for {param_id:?}"
            );
        }
    }

    #[test]
    fn test_invalid_ciphertext_length() {
        for &param_id in &ALL_PARAM_IDS {
            let kp = HybridKemKeyPair::generate(param_id).unwrap();
            assert!(kp.decapsulate(&[0u8; 10]).is_err());
            assert!(kp.decapsulate(&[]).is_err());
        }
    }

    #[test]
    fn test_cross_key_decapsulation() {
        for &param_id in &ALL_PARAM_IDS {
            let kp1 = HybridKemKeyPair::generate(param_id).unwrap();
            let kp2 = HybridKemKeyPair::generate(param_id).unwrap();
            let (ss1, ct) = kp1.encapsulate().unwrap();
            let ss2 = kp2.decapsulate(&ct).unwrap();
            assert_ne!(
                ss1, ss2,
                "cross-key decapsulation should differ for {param_id:?}"
            );
        }
    }

    #[test]
    fn test_cross_variant_decapsulation_fails() {
        // Different variants have different ciphertext sizes, so decapsulation
        // with the wrong variant should fail due to length mismatch.
        let kp_768 = HybridKemKeyPair::generate(HybridKemParamId::X25519MlKem768).unwrap();
        let kp_512 = HybridKemKeyPair::generate(HybridKemParamId::X25519MlKem512).unwrap();
        let (_, ct_768) = kp_768.encapsulate().unwrap();
        assert!(
            kp_512.decapsulate(&ct_768).is_err(),
            "cross-variant decapsulation should fail"
        );
    }

    #[test]
    fn test_multiple_encapsulations_differ() {
        let kp = HybridKemKeyPair::generate(HybridKemParamId::X25519MlKem768).unwrap();
        let (ss1, ct1) = kp.encapsulate().unwrap();
        let (ss2, ct2) = kp.encapsulate().unwrap();
        assert_ne!(ct1, ct2, "ciphertexts should differ");
        assert_ne!(ss1, ss2, "shared secrets should differ");
    }

    #[test]
    fn test_from_public_key_roundtrip() {
        for &param_id in &ALL_PARAM_IDS {
            let kp = HybridKemKeyPair::generate(param_id).unwrap();
            let pk = kp.public_key().unwrap();

            // Reconstruct from combined public key (encapsulate-only)
            let kp_pub = HybridKemKeyPair::from_public_key(param_id, &pk).unwrap();
            assert_eq!(kp_pub.param_id(), param_id);

            // Encapsulate with the pub-only key pair
            let (ss_enc, ct) = kp_pub.encapsulate().unwrap();
            assert_eq!(ss_enc.len(), 32);

            // Decapsulate with the original full key pair
            let ss_dec = kp.decapsulate(&ct).unwrap();
            assert_eq!(
                ss_enc, ss_dec,
                "from_public_key roundtrip failed for {param_id:?}"
            );
        }
    }

    #[test]
    fn test_from_public_key_decapsulate_fails() {
        let kp = HybridKemKeyPair::generate(HybridKemParamId::X25519MlKem768).unwrap();
        let pk = kp.public_key().unwrap();
        let kp_pub =
            HybridKemKeyPair::from_public_key(HybridKemParamId::X25519MlKem768, &pk).unwrap();
        let (_, ct) = kp.encapsulate().unwrap();
        assert!(
            kp_pub.decapsulate(&ct).is_err(),
            "pub-only key pair should not be able to decapsulate"
        );
    }

    #[test]
    fn test_from_public_key_invalid_length() {
        assert!(
            HybridKemKeyPair::from_public_key(HybridKemParamId::X25519MlKem768, &[0u8; 10])
                .is_err()
        );
    }

    #[test]
    fn test_from_public_key_public_key_matches() {
        for &param_id in &ALL_PARAM_IDS {
            let kp = HybridKemKeyPair::generate(param_id).unwrap();
            let pk = kp.public_key().unwrap();
            let kp_pub = HybridKemKeyPair::from_public_key(param_id, &pk).unwrap();
            let pk2 = kp_pub.public_key().unwrap();
            assert_eq!(
                pk, pk2,
                "public key should survive round-trip for {param_id:?}"
            );
        }
    }
}
