/// Hash algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgId {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
    Sm3,
}

/// MAC algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MacAlgId {
    HmacMd5,
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    HmacSha3_224,
    HmacSha3_256,
    HmacSha3_384,
    HmacSha3_512,
    HmacSm3,
    CmacAes128,
    CmacAes192,
    CmacAes256,
    CmacSm4,
    CbcMacSm4,
    GmacAes128,
    GmacAes192,
    GmacAes256,
    SipHash64,
    SipHash128,
}

/// Symmetric cipher algorithm identifiers (algorithm + mode combination).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherAlgId {
    // AES-CBC
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    // AES-CTR
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    // AES-ECB
    Aes128Ecb,
    Aes192Ecb,
    Aes256Ecb,
    // AES-XTS
    Aes128Xts,
    Aes256Xts,
    // AES-CCM
    Aes128Ccm,
    Aes192Ccm,
    Aes256Ccm,
    // AES-GCM
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    // AES key wrap
    Aes128WrapNoPad,
    Aes192WrapNoPad,
    Aes256WrapNoPad,
    Aes128WrapPad,
    Aes192WrapPad,
    Aes256WrapPad,
    // AES-CFB
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    // AES-OFB
    Aes128Ofb,
    Aes192Ofb,
    Aes256Ofb,
    // ChaCha20-Poly1305
    Chacha20Poly1305,
    // SM4 modes
    Sm4Xts,
    Sm4Cbc,
    Sm4Ecb,
    Sm4Ctr,
    Sm4Hctr,
    Sm4Gcm,
    Sm4Cfb,
    Sm4Ofb,
    Sm4Ccm,
}

/// Asymmetric (public key) algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PkeyAlgId {
    Rsa,
    Dsa,
    Dh,
    Ecdsa,
    Ecdh,
    Ed25519,
    X25519,
    Sm2,
    Sm9,
    Paillier,
    ElGamal,
    MlKem,
    MlDsa,
    SlhDsa,
    Xmss,
    FrodoKem,
    McEliece,
    HybridKem,
}

/// Elliptic curve parameter identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EccCurveId {
    NistP192,
    NistP224,
    NistP256,
    NistP384,
    NistP521,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
    Sm2Prime256,
}

/// DH named group parameter identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhParamId {
    Rfc2409_768,
    Rfc2409_1024,
    Rfc3526_1536,
    Rfc3526_2048,
    Rfc3526_3072,
    Rfc3526_4096,
    Rfc3526_6144,
    Rfc3526_8192,
    Rfc7919_2048,
    Rfc7919_3072,
    Rfc7919_4096,
    Rfc7919_6144,
    Rfc7919_8192,
}

/// ML-KEM parameter set identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlKemParamId {
    MlKem512,
    MlKem768,
    MlKem1024,
}

/// ML-DSA parameter set identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlDsaParamId {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

/// SLH-DSA parameter set identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlhDsaParamId {
    Sha2128s,
    Shake128s,
    Sha2128f,
    Shake128f,
    Sha2192s,
    Shake192s,
    Sha2192f,
    Shake192f,
    Sha2256s,
    Shake256s,
    Sha2256f,
    Shake256f,
}

/// FrodoKEM parameter set identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrodoKemParamId {
    FrodoKem640Shake,
    FrodoKem976Shake,
    FrodoKem1344Shake,
    FrodoKem640Aes,
    FrodoKem976Aes,
    FrodoKem1344Aes,
    EFrodoKem640Shake,
    EFrodoKem976Shake,
    EFrodoKem1344Shake,
    EFrodoKem640Aes,
    EFrodoKem976Aes,
    EFrodoKem1344Aes,
}

/// Classic McEliece parameter set identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McElieceParamId {
    McEliece6688128,
    McEliece6688128F,
    McEliece6688128Pc,
    McEliece6688128Pcf,
    McEliece6960119,
    McEliece6960119F,
    McEliece6960119Pc,
    McEliece6960119Pcf,
    McEliece8192128,
    McEliece8192128F,
    McEliece8192128Pc,
    McEliece8192128Pcf,
}

/// Hybrid KEM combination identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HybridKemParamId {
    X25519MlKem512,
    X25519MlKem768,
    X25519MlKem1024,
    EcdhNistP256MlKem512,
    EcdhNistP256MlKem768,
    EcdhNistP256MlKem1024,
    EcdhNistP384MlKem512,
    EcdhNistP384MlKem768,
    EcdhNistP384MlKem1024,
    EcdhNistP521MlKem512,
    EcdhNistP521MlKem768,
    EcdhNistP521MlKem1024,
}

/// DRBG (random number generator) algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RandAlgId {
    // Hash-DRBG
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sm3,
    // HMAC-DRBG
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    // CTR-DRBG
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    Aes128CtrDf,
    Aes192CtrDf,
    Aes256CtrDf,
    Sm4CtrDf,
}

/// KDF algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KdfAlgId {
    Scrypt,
    Pbkdf2,
    KdfTls12,
    Hkdf,
}

/// Elliptic curve point encoding formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointFormat {
    Compressed,
    Uncompressed,
    Hybrid,
}

impl Default for PointFormat {
    fn default() -> Self {
        Self::Uncompressed
    }
}
