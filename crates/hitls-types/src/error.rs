/// Cryptographic operation errors.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    // General errors
    #[error("null or empty input")]
    NullInput,
    #[error("memory allocation failed")]
    MemAllocFail,
    #[error("invalid algorithm id")]
    InvalidAlgId,
    #[error("invalid argument")]
    InvalidArg,
    #[error("operation not supported")]
    NotSupported,
    #[error("invalid key")]
    InvalidKey,
    #[error("key pairwise consistency check failed")]
    PairwiseCheckFail,

    // Buffer errors
    #[error("buffer length not enough: need {need}, got {got}")]
    BufferTooSmall { need: usize, got: usize },
    #[error("input data too long")]
    InputOverflow,

    // BigNum errors
    #[error("big number: insufficient space")]
    BnSpaceNotEnough,
    #[error("big number: division by zero")]
    BnDivisionByZero,
    #[error("big number: no modular inverse")]
    BnNoInverse,
    #[error("big number: prime generation failed")]
    BnPrimeGenFail,
    #[error("big number: random generation failed")]
    BnRandGenFail,

    // RSA errors
    #[error("rsa: invalid key bits")]
    RsaInvalidKeyBits,
    #[error("rsa: verification failed")]
    RsaVerifyFail,
    #[error("rsa: invalid padding")]
    RsaInvalidPadding,
    #[error("rsa: missing key info")]
    RsaNoKeyInfo,

    // ECC errors
    #[error("ecc: point at infinity")]
    EccPointAtInfinity,
    #[error("ecc: point not on curve")]
    EccPointNotOnCurve,
    #[error("ecc: invalid private key")]
    EccInvalidPrivateKey,
    #[error("ecc: invalid public key")]
    EccInvalidPublicKey,

    // ECDSA errors
    #[error("ecdsa: verification failed")]
    EcdsaVerifyFail,

    // DSA errors
    #[error("dsa: verification failed")]
    DsaVerifyFail,

    // SM2 errors
    #[error("sm2: verification failed")]
    Sm2VerifyFail,
    #[error("sm2: decryption failed")]
    Sm2DecryptFail,

    // SM9 errors
    #[error("sm9: verification failed")]
    Sm9VerifyFail,

    // Curve25519 errors
    #[error("curve25519: verification failed")]
    Curve25519VerifyFail,

    // Symmetric cipher errors
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("invalid iv length")]
    InvalidIvLength,
    #[error("invalid tag length")]
    InvalidTagLength,
    #[error("aead: tag verification failed")]
    AeadTagVerifyFail,
    #[error("invalid padding")]
    InvalidPadding,

    // DRBG errors
    #[error("drbg: invalid state")]
    DrbgInvalidState,
    #[error("drbg: failed to obtain entropy")]
    DrbgEntropyFail,

    // Entropy health test errors
    #[error("entropy: repetition count test failed")]
    EntropyRctFailure,
    #[error("entropy: adaptive proportion test failed")]
    EntropyAptFailure,

    // KDF errors
    #[error("kdf: derived key length overflow")]
    KdfDkLenOverflow,

    // Encoding/Decoding errors
    #[error("decode: asn1 buffer failed")]
    DecodeAsn1Fail,
    #[error("decode: unknown oid")]
    DecodeUnknownOid,
    #[error("encode: unsupported format")]
    EncodeUnsupportedFormat,

    // ML-KEM errors
    #[error("ml-kem: key not set")]
    MlKemKeyNotSet,
    #[error("ml-kem: invalid key length")]
    MlKemInvalidKeyLen,

    // ML-DSA errors
    #[error("ml-dsa: verification failed")]
    MlDsaVerifyFail,
    #[error("ml-dsa: invalid signature data")]
    MlDsaInvalidSigData,

    // SLH-DSA errors
    #[error("slh-dsa: hypertree verification failed")]
    SlhDsaHypertreeVerifyFail,

    // XMSS errors
    #[error("xmss: key expired")]
    XmssKeyExpired,
    #[error("xmss: merkle tree root mismatch")]
    XmssMerkleRootMismatch,

    // McEliece errors
    #[error("mceliece: keygen failed")]
    McElieceKeygenFail,
    #[error("mceliece: decode failed")]
    McElieceDecodeFail,

    // FIPS/CMVP errors
    #[error("cmvp: {0}")]
    Cmvp(#[from] CmvpError),
}

/// FIPS/CMVP self-test and compliance errors.
#[derive(Debug, thiserror::Error)]
pub enum CmvpError {
    #[error("integrity check failed")]
    IntegrityError,
    #[error("KAT self-test failed: {0}")]
    KatFailure(String),
    #[error("randomness test failed")]
    RandomnessError,
    #[error("pairwise consistency test failed: {0}")]
    PairwiseTestError(String),
    #[error("FIPS module not in operational state")]
    InvalidState,
    #[error("parameter check failed: {0}")]
    ParamCheckError(String),
}

/// TLS protocol errors.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("alert received: {0}")]
    AlertReceived(String),
    #[error("record layer error: {0}")]
    RecordError(String),
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("no shared cipher suite")]
    NoSharedCipherSuite,
    #[error("certificate verification failed: {0}")]
    CertVerifyFailed(String),
    #[error("session expired")]
    SessionExpired,
    #[error("connection closed")]
    ConnectionClosed,
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    CryptoError(#[from] CryptoError),
}

/// PKI certificate errors.
#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("invalid certificate: {0}")]
    InvalidCert(String),
    #[error("certificate expired")]
    CertExpired,
    #[error("certificate not yet valid")]
    CertNotYetValid,
    #[error("certificate chain verification failed: {0}")]
    ChainVerifyFailed(String),
    #[error("unsupported certificate extension: {0}")]
    UnsupportedExtension(String),
    #[error("invalid CRL: {0}")]
    InvalidCrl(String),
    #[error("certificate revoked")]
    CertRevoked,
    #[error("pkcs12 error: {0}")]
    Pkcs12Error(String),
    #[error("cms error: {0}")]
    CmsError(String),
    #[error("asn1 parse error: {0}")]
    Asn1Error(String),
    #[error("issuer certificate not found")]
    IssuerNotFound,
    #[error("basic constraints violation: {0}")]
    BasicConstraintsViolation(String),
    #[error("key usage violation: {0}")]
    KeyUsageViolation(String),
    #[error("max chain depth exceeded: {0}")]
    MaxDepthExceeded(u32),
    #[error("crypto error: {0}")]
    CryptoError(#[from] CryptoError),
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CryptoError
    // -----------------------------------------------------------------------

    #[test]
    fn test_crypto_error_display_simple_variants() {
        assert_eq!(CryptoError::NullInput.to_string(), "null or empty input");
        assert_eq!(
            CryptoError::MemAllocFail.to_string(),
            "memory allocation failed"
        );
        assert_eq!(
            CryptoError::InvalidAlgId.to_string(),
            "invalid algorithm id"
        );
        assert_eq!(CryptoError::InvalidArg.to_string(), "invalid argument");
        assert_eq!(
            CryptoError::NotSupported.to_string(),
            "operation not supported"
        );
        assert_eq!(CryptoError::InvalidKey.to_string(), "invalid key");
        assert_eq!(
            CryptoError::PairwiseCheckFail.to_string(),
            "key pairwise consistency check failed"
        );
    }

    #[test]
    fn test_crypto_error_structured_variants() {
        let e = CryptoError::BufferTooSmall { need: 64, got: 32 };
        assert_eq!(e.to_string(), "buffer length not enough: need 64, got 32");

        let e = CryptoError::InvalidKeyLength {
            expected: 32,
            got: 16,
        };
        assert_eq!(e.to_string(), "invalid key length: expected 32, got 16");
    }

    #[test]
    fn test_crypto_error_domain_variants() {
        // RSA
        assert_eq!(
            CryptoError::RsaInvalidKeyBits.to_string(),
            "rsa: invalid key bits"
        );
        assert_eq!(
            CryptoError::RsaVerifyFail.to_string(),
            "rsa: verification failed"
        );
        assert_eq!(
            CryptoError::RsaInvalidPadding.to_string(),
            "rsa: invalid padding"
        );
        assert_eq!(
            CryptoError::RsaNoKeyInfo.to_string(),
            "rsa: missing key info"
        );

        // ECC
        assert_eq!(
            CryptoError::EccPointAtInfinity.to_string(),
            "ecc: point at infinity"
        );
        assert_eq!(
            CryptoError::EccPointNotOnCurve.to_string(),
            "ecc: point not on curve"
        );
        assert_eq!(
            CryptoError::EccInvalidPrivateKey.to_string(),
            "ecc: invalid private key"
        );

        // DRBG
        assert_eq!(
            CryptoError::DrbgInvalidState.to_string(),
            "drbg: invalid state"
        );
        assert_eq!(
            CryptoError::DrbgEntropyFail.to_string(),
            "drbg: failed to obtain entropy"
        );

        // Entropy health
        assert_eq!(
            CryptoError::EntropyRctFailure.to_string(),
            "entropy: repetition count test failed"
        );
        assert_eq!(
            CryptoError::EntropyAptFailure.to_string(),
            "entropy: adaptive proportion test failed"
        );
    }

    #[test]
    fn test_crypto_error_debug_impl() {
        let e = CryptoError::NullInput;
        let dbg = format!("{:?}", e);
        assert!(dbg.contains("NullInput"));

        let e = CryptoError::BufferTooSmall { need: 10, got: 5 };
        let dbg = format!("{:?}", e);
        assert!(dbg.contains("BufferTooSmall"));
        assert!(dbg.contains("10"));
        assert!(dbg.contains("5"));
    }

    #[test]
    fn test_crypto_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CryptoError>();
    }

    // -----------------------------------------------------------------------
    // CmvpError
    // -----------------------------------------------------------------------

    #[test]
    fn test_cmvp_error_display() {
        assert_eq!(
            CmvpError::IntegrityError.to_string(),
            "integrity check failed"
        );
        assert_eq!(
            CmvpError::KatFailure("AES".into()).to_string(),
            "KAT self-test failed: AES"
        );
        assert_eq!(
            CmvpError::RandomnessError.to_string(),
            "randomness test failed"
        );
        assert_eq!(
            CmvpError::PairwiseTestError("RSA".into()).to_string(),
            "pairwise consistency test failed: RSA"
        );
        assert_eq!(
            CmvpError::InvalidState.to_string(),
            "FIPS module not in operational state"
        );
        assert_eq!(
            CmvpError::ParamCheckError("bad len".into()).to_string(),
            "parameter check failed: bad len"
        );
    }

    #[test]
    fn test_cmvp_to_crypto_error_conversion() {
        let cmvp = CmvpError::IntegrityError;
        let crypto: CryptoError = cmvp.into();
        let display = crypto.to_string();
        assert!(display.contains("integrity check failed"), "got: {display}");
    }

    // -----------------------------------------------------------------------
    // TlsError
    // -----------------------------------------------------------------------

    #[test]
    fn test_tls_error_display() {
        assert_eq!(
            TlsError::HandshakeFailed("bad cert".into()).to_string(),
            "handshake failed: bad cert"
        );
        assert_eq!(
            TlsError::AlertReceived("fatal".into()).to_string(),
            "alert received: fatal"
        );
        assert_eq!(
            TlsError::RecordError("overflow".into()).to_string(),
            "record layer error: overflow"
        );
        assert_eq!(
            TlsError::UnsupportedVersion.to_string(),
            "unsupported protocol version"
        );
        assert_eq!(
            TlsError::NoSharedCipherSuite.to_string(),
            "no shared cipher suite"
        );
        assert_eq!(TlsError::SessionExpired.to_string(), "session expired");
        assert_eq!(TlsError::ConnectionClosed.to_string(), "connection closed");
    }

    #[test]
    fn test_tls_error_from_crypto_error() {
        let crypto = CryptoError::InvalidKey;
        let tls: TlsError = crypto.into();
        let display = tls.to_string();
        assert!(display.contains("invalid key"), "got: {display}");
    }

    #[test]
    fn test_tls_error_from_io_error() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let tls: TlsError = io.into();
        let display = tls.to_string();
        assert!(display.contains("refused"), "got: {display}");
    }

    // -----------------------------------------------------------------------
    // PkiError
    // -----------------------------------------------------------------------

    #[test]
    fn test_pki_error_display() {
        assert_eq!(
            PkiError::InvalidCert("bad ASN.1".into()).to_string(),
            "invalid certificate: bad ASN.1"
        );
        assert_eq!(PkiError::CertExpired.to_string(), "certificate expired");
        assert_eq!(
            PkiError::CertNotYetValid.to_string(),
            "certificate not yet valid"
        );
        assert_eq!(PkiError::CertRevoked.to_string(), "certificate revoked");
        assert_eq!(
            PkiError::IssuerNotFound.to_string(),
            "issuer certificate not found"
        );
        assert_eq!(
            PkiError::MaxDepthExceeded(10).to_string(),
            "max chain depth exceeded: 10"
        );
    }

    #[test]
    fn test_pki_error_from_crypto_error() {
        let crypto = CryptoError::EcdsaVerifyFail;
        let pki: PkiError = crypto.into();
        let display = pki.to_string();
        assert!(
            display.contains("ecdsa: verification failed"),
            "got: {display}"
        );
    }

    #[test]
    fn test_pki_error_chain_variants() {
        let e = PkiError::ChainVerifyFailed("depth check".into());
        assert_eq!(
            e.to_string(),
            "certificate chain verification failed: depth check"
        );

        let e = PkiError::BasicConstraintsViolation("not CA".into());
        assert_eq!(e.to_string(), "basic constraints violation: not CA");

        let e = PkiError::KeyUsageViolation("no digital sig".into());
        assert_eq!(e.to_string(), "key usage violation: no digital sig");
    }

    #[test]
    fn test_pki_error_encoding_variants() {
        assert_eq!(
            PkiError::Pkcs12Error("bad mac".into()).to_string(),
            "pkcs12 error: bad mac"
        );
        assert_eq!(
            PkiError::CmsError("unsupported".into()).to_string(),
            "cms error: unsupported"
        );
        assert_eq!(
            PkiError::Asn1Error("unexpected tag".into()).to_string(),
            "asn1 parse error: unexpected tag"
        );
    }
}
