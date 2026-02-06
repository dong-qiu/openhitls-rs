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
    #[error("crypto error: {0}")]
    CryptoError(#[from] CryptoError),
}
