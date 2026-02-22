//! Signature verification helpers and the `SigningKey` abstraction.

use hitls_types::{CryptoError, EccCurveId, PkiError};
use hitls_utils::asn1::{Decoder, Encoder};
use hitls_utils::oid::{known, Oid};

use super::SubjectPublicKeyInfo;
use crate::oid_mapping;

// ---------------------------------------------------------------------------
// Hash algorithm dispatch
// ---------------------------------------------------------------------------

pub(crate) enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

pub(crate) fn compute_hash(data: &[u8], alg: &HashAlg) -> Result<Vec<u8>, CryptoError> {
    match alg {
        HashAlg::Sha1 => {
            let mut h = hitls_crypto::sha1::Sha1::new();
            h.update(data)?;
            Ok(h.finish()?.to_vec())
        }
        HashAlg::Sha256 => {
            let mut h = hitls_crypto::sha2::Sha256::new();
            h.update(data)?;
            Ok(h.finish()?.to_vec())
        }
        HashAlg::Sha384 => {
            let mut h = hitls_crypto::sha2::Sha384::new();
            h.update(data)?;
            Ok(h.finish()?.to_vec())
        }
        HashAlg::Sha512 => {
            let mut h = hitls_crypto::sha2::Sha512::new();
            h.update(data)?;
            Ok(h.finish()?.to_vec())
        }
    }
}

// ---------------------------------------------------------------------------
// Signature verification functions
// ---------------------------------------------------------------------------

pub(crate) fn verify_rsa(
    tbs: &[u8],
    signature: &[u8],
    spki: &SubjectPublicKeyInfo,
    hash_alg: HashAlg,
) -> Result<bool, PkiError> {
    // RSA SPKI public_key is DER: SEQUENCE { modulus INTEGER, exponent INTEGER }
    let mut key_dec = Decoder::new(&spki.public_key);
    let mut seq = key_dec
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let n = seq
        .read_integer()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let e = seq
        .read_integer()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

    let rsa_pub = hitls_crypto::rsa::RsaPublicKey::new(n, e).map_err(PkiError::from)?;
    let digest = compute_hash(tbs, &hash_alg).map_err(PkiError::from)?;
    rsa_pub
        .verify(
            hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign,
            &digest,
            signature,
        )
        .map_err(PkiError::from)
}

pub(crate) fn oid_to_curve_id(oid: &Oid) -> Result<EccCurveId, PkiError> {
    oid_mapping::oid_to_curve_id(oid)
        .ok_or_else(|| PkiError::InvalidCert(format!("unsupported EC curve: {}", oid)))
}

pub(crate) fn verify_ecdsa(
    tbs: &[u8],
    signature: &[u8],
    spki: &SubjectPublicKeyInfo,
    hash_alg: HashAlg,
) -> Result<bool, PkiError> {
    let curve_oid_bytes = spki
        .algorithm_params
        .as_ref()
        .ok_or_else(|| PkiError::InvalidCert("missing EC curve OID in algorithm params".into()))?;
    let curve_oid =
        Oid::from_der_value(curve_oid_bytes).map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let curve_id = oid_to_curve_id(&curve_oid)?;

    let verifier = hitls_crypto::ecdsa::EcdsaKeyPair::from_public_key(curve_id, &spki.public_key)
        .map_err(PkiError::from)?;

    let digest = compute_hash(tbs, &hash_alg).map_err(PkiError::from)?;
    verifier.verify(&digest, signature).map_err(PkiError::from)
}

pub(crate) fn verify_ed25519(
    tbs: &[u8],
    signature: &[u8],
    spki: &SubjectPublicKeyInfo,
) -> Result<bool, PkiError> {
    let verifier = hitls_crypto::ed25519::Ed25519KeyPair::from_public_key(&spki.public_key)
        .map_err(PkiError::from)?;
    // Ed25519 takes the raw message (not pre-hashed)
    verifier.verify(tbs, signature).map_err(PkiError::from)
}

pub(crate) fn verify_ed448(
    tbs: &[u8],
    signature: &[u8],
    spki: &SubjectPublicKeyInfo,
) -> Result<bool, PkiError> {
    let verifier = hitls_crypto::ed448::Ed448KeyPair::from_public_key(&spki.public_key)
        .map_err(PkiError::from)?;
    // Ed448 takes the raw message (not pre-hashed)
    verifier.verify(tbs, signature).map_err(PkiError::from)
}

pub(crate) fn verify_sm2(
    tbs: &[u8],
    signature: &[u8],
    spki: &SubjectPublicKeyInfo,
) -> Result<bool, PkiError> {
    let verifier =
        hitls_crypto::sm2::Sm2KeyPair::from_public_key(&spki.public_key).map_err(PkiError::from)?;
    // SM2 with SM3 — use empty user ID for X.509 certificate verification
    // (matches C implementation which uses zero-length userId by default)
    verifier
        .verify_with_id(b"", tbs, signature)
        .map_err(PkiError::from)
}

pub(crate) fn verify_rsa_pss(
    tbs: &[u8],
    signature: &[u8],
    spki: &SubjectPublicKeyInfo,
) -> Result<bool, PkiError> {
    // RSA-PSS SPKI uses the same RSA key format
    let mut key_dec = Decoder::new(&spki.public_key);
    let mut seq = key_dec
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let n = seq
        .read_integer()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let e = seq
        .read_integer()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

    let rsa_pub = hitls_crypto::rsa::RsaPublicKey::new(n, e).map_err(PkiError::from)?;
    // Default to SHA-256 for PSS hash; compute digest then verify with PSS padding
    let digest = compute_hash(tbs, &HashAlg::Sha256).map_err(PkiError::from)?;
    rsa_pub
        .verify(hitls_crypto::rsa::RsaPadding::Pss, &digest, signature)
        .map_err(PkiError::from)
}

// ---------------------------------------------------------------------------
// SigningKey — unified signing dispatch
// ---------------------------------------------------------------------------

/// NULL parameter bytes for AlgorithmIdentifier (DER: 0x05 0x00).
pub(super) const ALG_PARAMS_NULL: &[u8] = &[0x05, 0x00];

/// A private key that can sign data. Supports RSA, ECDSA, Ed25519, and SM2.
pub enum SigningKey {
    /// RSA private key (signs with SHA-256 + PKCS#1 v1.5).
    Rsa(hitls_crypto::rsa::RsaPrivateKey),
    /// ECDSA private key (signs with SHA-256/384 depending on curve).
    Ecdsa {
        curve_id: EccCurveId,
        key_pair: hitls_crypto::ecdsa::EcdsaKeyPair,
    },
    /// Ed25519 private key (signs raw message).
    Ed25519(hitls_crypto::ed25519::Ed25519KeyPair),
    /// SM2 private key (signs with SM2-SM3).
    Sm2(hitls_crypto::sm2::Sm2KeyPair),
}

impl SigningKey {
    /// Create a SigningKey from PKCS#8 DER bytes.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, PkiError> {
        use crate::pkcs8::{parse_pkcs8_der, Pkcs8PrivateKey};
        let key = parse_pkcs8_der(der).map_err(PkiError::from)?;
        match key {
            Pkcs8PrivateKey::Rsa(rsa) => Ok(SigningKey::Rsa(rsa)),
            Pkcs8PrivateKey::Ec { curve_id, key_pair } => {
                Ok(SigningKey::Ecdsa { curve_id, key_pair })
            }
            Pkcs8PrivateKey::Ed25519(ed) => Ok(SigningKey::Ed25519(ed)),
            _ => Err(PkiError::InvalidCert(
                "unsupported key type for signing".into(),
            )),
        }
    }

    /// Create a SigningKey from PKCS#8 PEM string.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, PkiError> {
        let blocks =
            hitls_utils::pem::parse(pem).map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let key_block = blocks
            .iter()
            .find(|b| b.label == "PRIVATE KEY")
            .ok_or_else(|| PkiError::InvalidCert("no PRIVATE KEY block found".into()))?;
        Self::from_pkcs8_der(&key_block.data)
    }

    /// Sign the given data (hash + sign for RSA/ECDSA, raw sign for Ed25519).
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, PkiError> {
        match self {
            SigningKey::Rsa(rsa) => {
                let digest = compute_hash(data, &HashAlg::Sha256).map_err(PkiError::from)?;
                rsa.sign(hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign, &digest)
                    .map_err(PkiError::from)
            }
            SigningKey::Ecdsa { curve_id, key_pair } => {
                let hash_alg = match curve_id {
                    EccCurveId::NistP384 | EccCurveId::BrainpoolP384r1 => HashAlg::Sha384,
                    EccCurveId::NistP521 | EccCurveId::BrainpoolP512r1 => HashAlg::Sha512,
                    _ => HashAlg::Sha256,
                };
                let digest = compute_hash(data, &hash_alg).map_err(PkiError::from)?;
                key_pair.sign(&digest).map_err(PkiError::from)
            }
            SigningKey::Ed25519(ed) => {
                let sig = ed.sign(data).map_err(PkiError::from)?;
                Ok(sig.to_vec())
            }
            SigningKey::Sm2(sm2) => sm2.sign(data).map_err(PkiError::from),
        }
    }

    /// Get the signature algorithm OID bytes for this key type.
    pub fn algorithm_oid(&self) -> Vec<u8> {
        match self {
            SigningKey::Rsa(_) => known::sha256_with_rsa_encryption().to_der_value(),
            SigningKey::Ecdsa { curve_id, .. } => match curve_id {
                EccCurveId::NistP384 | EccCurveId::BrainpoolP384r1 => {
                    known::ecdsa_with_sha384().to_der_value()
                }
                EccCurveId::NistP521 | EccCurveId::BrainpoolP512r1 => {
                    known::ecdsa_with_sha512().to_der_value()
                }
                _ => known::ecdsa_with_sha256().to_der_value(),
            },
            SigningKey::Ed25519(_) => known::ed25519().to_der_value(),
            SigningKey::Sm2(_) => known::sm2_with_sm3().to_der_value(),
        }
    }

    /// Get the signature algorithm parameters as full DER TLV.
    /// Returns Some(NULL TLV) for RSA, None (absent) for ECDSA/Ed25519/SM2.
    pub fn algorithm_params(&self) -> Option<Vec<u8>> {
        match self {
            SigningKey::Rsa(_) => Some(ALG_PARAMS_NULL.to_vec()),
            SigningKey::Ecdsa { .. } | SigningKey::Ed25519(_) | SigningKey::Sm2(_) => None,
        }
    }

    /// Extract the SubjectPublicKeyInfo for this key.
    pub fn public_key_info(&self) -> Result<SubjectPublicKeyInfo, PkiError> {
        match self {
            SigningKey::Rsa(rsa) => {
                let pub_key = rsa.public_key();
                // Encode public key as SEQUENCE { modulus INTEGER, exponent INTEGER }
                let mut inner = Encoder::new();
                inner.write_integer(&pub_key.n_bytes());
                inner.write_integer(&pub_key.e_bytes());
                let mut seq = Encoder::new();
                seq.write_sequence(&inner.finish());
                // RSA SPKI algorithm_params: None here means NULL will be added
                // by encode_subject_public_key_info (since it doesn't match OID pattern)
                Ok(SubjectPublicKeyInfo {
                    algorithm_oid: known::rsa_encryption().to_der_value(),
                    algorithm_params: None,
                    public_key: seq.finish(),
                })
            }
            SigningKey::Ecdsa { curve_id, key_pair } => {
                let pub_bytes = key_pair.public_key_bytes().map_err(PkiError::from)?;
                let curve_oid = curve_id_to_oid(*curve_id)?;
                // algorithm_params stores raw OID value bytes (without tag+length)
                // because parse_algorithm_identifier stores tlv.value
                Ok(SubjectPublicKeyInfo {
                    algorithm_oid: known::ec_public_key().to_der_value(),
                    algorithm_params: Some(curve_oid.to_der_value()),
                    public_key: pub_bytes,
                })
            }
            SigningKey::Ed25519(ed) => Ok(SubjectPublicKeyInfo {
                algorithm_oid: known::ed25519().to_der_value(),
                algorithm_params: None,
                public_key: ed.public_key().to_vec(),
            }),
            SigningKey::Sm2(sm2) => {
                let pub_bytes = sm2.public_key_bytes().map_err(PkiError::from)?;
                Ok(SubjectPublicKeyInfo {
                    algorithm_oid: known::ec_public_key().to_der_value(),
                    algorithm_params: Some(known::sm2_curve().to_der_value()),
                    public_key: pub_bytes,
                })
            }
        }
    }
}

/// Map an EccCurveId to its OID.
fn curve_id_to_oid(curve_id: EccCurveId) -> Result<Oid, PkiError> {
    match curve_id {
        EccCurveId::NistP224 => Ok(known::secp224r1()),
        EccCurveId::NistP256 => Ok(known::prime256v1()),
        EccCurveId::NistP384 => Ok(known::secp384r1()),
        EccCurveId::NistP521 => Ok(known::secp521r1()),
        EccCurveId::BrainpoolP256r1 => Ok(known::brainpool_p256r1()),
        EccCurveId::BrainpoolP384r1 => Ok(known::brainpool_p384r1()),
        EccCurveId::BrainpoolP512r1 => Ok(known::brainpool_p512r1()),
        _ => Err(PkiError::InvalidCert(format!(
            "unsupported curve: {:?}",
            curve_id
        ))),
    }
}
