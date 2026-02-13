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
    Ed448,
    X25519,
    X448,
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

/// SLH-DSA parameter set identifiers (FIPS 205).
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

/// XMSS parameter set identifiers (RFC 8391, single-tree).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XmssParamId {
    /// XMSS-SHA2_10_256: SHA-256, h=10, n=32 (1024 signatures)
    Sha2_10_256,
    /// XMSS-SHA2_16_256: SHA-256, h=16, n=32 (65536 signatures)
    Sha2_16_256,
    /// XMSS-SHA2_20_256: SHA-256, h=20, n=32 (1048576 signatures)
    Sha2_20_256,
    /// XMSS-SHAKE_10_256: SHAKE128, h=10, n=32
    Shake128_10_256,
    /// XMSS-SHAKE_16_256: SHAKE128, h=16, n=32
    Shake128_16_256,
    /// XMSS-SHAKE_20_256: SHAKE128, h=20, n=32
    Shake128_20_256,
    /// XMSS-SHAKE256_10_256: SHAKE256, h=10, n=32
    Shake256_10_256,
    /// XMSS-SHAKE256_16_256: SHAKE256, h=16, n=32
    Shake256_16_256,
    /// XMSS-SHAKE256_20_256: SHAKE256, h=20, n=32
    Shake256_20_256,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PointFormat {
    Compressed,
    #[default]
    Uncompressed,
    Hybrid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_hash_alg_id_variant_count_and_uniqueness() {
        let all = [
            HashAlgId::Md5,
            HashAlgId::Sha1,
            HashAlgId::Sha224,
            HashAlgId::Sha256,
            HashAlgId::Sha384,
            HashAlgId::Sha512,
            HashAlgId::Sha3_224,
            HashAlgId::Sha3_256,
            HashAlgId::Sha3_384,
            HashAlgId::Sha3_512,
            HashAlgId::Shake128,
            HashAlgId::Shake256,
            HashAlgId::Sm3,
        ];
        assert_eq!(all.len(), 13);
        let set: HashSet<HashAlgId> = all.iter().copied().collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn test_hash_alg_id_clone_copy_eq_debug() {
        let a = HashAlgId::Sha256;
        let b = a; // Copy
        let c = Clone::clone(&a); // Clone (use Clone::clone to avoid clippy clone_on_copy)
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, HashAlgId::Sha384);
        assert_eq!(format!("{:?}", a), "Sha256");
    }

    #[test]
    fn test_cipher_alg_id_all_distinct() {
        let all = [
            CipherAlgId::Aes128Cbc,
            CipherAlgId::Aes192Cbc,
            CipherAlgId::Aes256Cbc,
            CipherAlgId::Aes128Ctr,
            CipherAlgId::Aes192Ctr,
            CipherAlgId::Aes256Ctr,
            CipherAlgId::Aes128Ecb,
            CipherAlgId::Aes192Ecb,
            CipherAlgId::Aes256Ecb,
            CipherAlgId::Aes128Xts,
            CipherAlgId::Aes256Xts,
            CipherAlgId::Aes128Ccm,
            CipherAlgId::Aes192Ccm,
            CipherAlgId::Aes256Ccm,
            CipherAlgId::Aes128Gcm,
            CipherAlgId::Aes192Gcm,
            CipherAlgId::Aes256Gcm,
            CipherAlgId::Aes128WrapNoPad,
            CipherAlgId::Aes192WrapNoPad,
            CipherAlgId::Aes256WrapNoPad,
            CipherAlgId::Aes128WrapPad,
            CipherAlgId::Aes192WrapPad,
            CipherAlgId::Aes256WrapPad,
            CipherAlgId::Aes128Cfb,
            CipherAlgId::Aes192Cfb,
            CipherAlgId::Aes256Cfb,
            CipherAlgId::Aes128Ofb,
            CipherAlgId::Aes192Ofb,
            CipherAlgId::Aes256Ofb,
            CipherAlgId::Chacha20Poly1305,
            CipherAlgId::Sm4Xts,
            CipherAlgId::Sm4Cbc,
            CipherAlgId::Sm4Ecb,
            CipherAlgId::Sm4Ctr,
            CipherAlgId::Sm4Hctr,
            CipherAlgId::Sm4Gcm,
            CipherAlgId::Sm4Cfb,
            CipherAlgId::Sm4Ofb,
            CipherAlgId::Sm4Ccm,
        ];
        let set: HashSet<CipherAlgId> = all.iter().copied().collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn test_pkey_alg_id_all_distinct() {
        let all = [
            PkeyAlgId::Rsa,
            PkeyAlgId::Dsa,
            PkeyAlgId::Dh,
            PkeyAlgId::Ecdsa,
            PkeyAlgId::Ecdh,
            PkeyAlgId::Ed25519,
            PkeyAlgId::Ed448,
            PkeyAlgId::X25519,
            PkeyAlgId::X448,
            PkeyAlgId::Sm2,
            PkeyAlgId::Sm9,
            PkeyAlgId::Paillier,
            PkeyAlgId::ElGamal,
            PkeyAlgId::MlKem,
            PkeyAlgId::MlDsa,
            PkeyAlgId::SlhDsa,
            PkeyAlgId::Xmss,
            PkeyAlgId::FrodoKem,
            PkeyAlgId::McEliece,
            PkeyAlgId::HybridKem,
        ];
        assert_eq!(all.len(), 20);
        let set: HashSet<PkeyAlgId> = all.iter().copied().collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn test_ecc_curve_id_all_distinct() {
        let all = [
            EccCurveId::NistP192,
            EccCurveId::NistP224,
            EccCurveId::NistP256,
            EccCurveId::NistP384,
            EccCurveId::NistP521,
            EccCurveId::BrainpoolP256r1,
            EccCurveId::BrainpoolP384r1,
            EccCurveId::BrainpoolP512r1,
            EccCurveId::Sm2Prime256,
        ];
        assert_eq!(all.len(), 9);
        let set: HashSet<EccCurveId> = all.iter().copied().collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn test_dh_param_id_count() {
        let all = [
            DhParamId::Rfc2409_768,
            DhParamId::Rfc2409_1024,
            DhParamId::Rfc3526_1536,
            DhParamId::Rfc3526_2048,
            DhParamId::Rfc3526_3072,
            DhParamId::Rfc3526_4096,
            DhParamId::Rfc3526_6144,
            DhParamId::Rfc3526_8192,
            DhParamId::Rfc7919_2048,
            DhParamId::Rfc7919_3072,
            DhParamId::Rfc7919_4096,
            DhParamId::Rfc7919_6144,
            DhParamId::Rfc7919_8192,
        ];
        assert_eq!(all.len(), 13);
        let set: HashSet<DhParamId> = all.iter().copied().collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn test_pq_param_ids() {
        let mlkem = [
            MlKemParamId::MlKem512,
            MlKemParamId::MlKem768,
            MlKemParamId::MlKem1024,
        ];
        assert_eq!(mlkem.len(), 3);
        let mldsa = [
            MlDsaParamId::MlDsa44,
            MlDsaParamId::MlDsa65,
            MlDsaParamId::MlDsa87,
        ];
        assert_eq!(mldsa.len(), 3);

        let slh: HashSet<_> = [
            SlhDsaParamId::Sha2128s,
            SlhDsaParamId::Shake128s,
            SlhDsaParamId::Sha2128f,
            SlhDsaParamId::Shake128f,
            SlhDsaParamId::Sha2192s,
            SlhDsaParamId::Shake192s,
            SlhDsaParamId::Sha2192f,
            SlhDsaParamId::Shake192f,
            SlhDsaParamId::Sha2256s,
            SlhDsaParamId::Shake256s,
            SlhDsaParamId::Sha2256f,
            SlhDsaParamId::Shake256f,
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(slh.len(), 12);
    }

    #[test]
    fn test_mac_alg_id_all_distinct() {
        let all = [
            MacAlgId::HmacMd5,
            MacAlgId::HmacSha1,
            MacAlgId::HmacSha224,
            MacAlgId::HmacSha256,
            MacAlgId::HmacSha384,
            MacAlgId::HmacSha512,
            MacAlgId::HmacSha3_224,
            MacAlgId::HmacSha3_256,
            MacAlgId::HmacSha3_384,
            MacAlgId::HmacSha3_512,
            MacAlgId::HmacSm3,
            MacAlgId::CmacAes128,
            MacAlgId::CmacAes192,
            MacAlgId::CmacAes256,
            MacAlgId::CmacSm4,
            MacAlgId::CbcMacSm4,
            MacAlgId::GmacAes128,
            MacAlgId::GmacAes192,
            MacAlgId::GmacAes256,
            MacAlgId::SipHash64,
            MacAlgId::SipHash128,
        ];
        assert_eq!(all.len(), 21);
        let set: HashSet<MacAlgId> = all.iter().copied().collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn test_rand_alg_id_all_distinct() {
        let all = [
            RandAlgId::Sha1,
            RandAlgId::Sha224,
            RandAlgId::Sha256,
            RandAlgId::Sha384,
            RandAlgId::Sha512,
            RandAlgId::Sm3,
            RandAlgId::HmacSha1,
            RandAlgId::HmacSha224,
            RandAlgId::HmacSha256,
            RandAlgId::HmacSha384,
            RandAlgId::HmacSha512,
            RandAlgId::Aes128Ctr,
            RandAlgId::Aes192Ctr,
            RandAlgId::Aes256Ctr,
            RandAlgId::Aes128CtrDf,
            RandAlgId::Aes192CtrDf,
            RandAlgId::Aes256CtrDf,
            RandAlgId::Sm4CtrDf,
        ];
        assert_eq!(all.len(), 18);
        let set: HashSet<RandAlgId> = all.iter().copied().collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn test_kdf_alg_id_all_distinct() {
        let all = [
            KdfAlgId::Scrypt,
            KdfAlgId::Pbkdf2,
            KdfAlgId::KdfTls12,
            KdfAlgId::Hkdf,
        ];
        assert_eq!(all.len(), 4);
        let set: HashSet<KdfAlgId> = all.iter().copied().collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn test_point_format_default_is_uncompressed() {
        assert_eq!(PointFormat::default(), PointFormat::Uncompressed);
        assert_ne!(PointFormat::Compressed, PointFormat::Uncompressed);
        assert_ne!(PointFormat::Compressed, PointFormat::Hybrid);
    }

    #[test]
    fn test_enums_as_hashmap_keys() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        map.insert(HashAlgId::Sha256, "SHA-256");
        map.insert(HashAlgId::Sha384, "SHA-384");
        assert_eq!(map[&HashAlgId::Sha256], "SHA-256");
        assert_eq!(map.get(&HashAlgId::Sm3), None);
    }
}
