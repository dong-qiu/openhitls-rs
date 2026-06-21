//! PBKDF2 (Password-Based Key Derivation Function 2) implementation.
//!
//! Defined in RFC 8018 (PKCS#5 v2.1). Uses HMAC as the PRF.
//! Default: HMAC-SHA-256. Use `pbkdf2_with_hmac` for other hash functions.

use crate::hmac::Hmac;
use crate::provider::Digest;
use crate::sha2::Sha256;
use hitls_types::CryptoError;
use zeroize::Zeroize;

fn sha256_factory() -> Box<dyn Digest> {
    Box::new(Sha256::new())
}

/// Derive a key from a password using PBKDF2 with a custom HMAC hash function.
pub fn pbkdf2_with_hmac(
    factory: fn() -> Box<dyn Digest>,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dk_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    if iterations == 0 || dk_len == 0 {
        return Err(CryptoError::InvalidArg("iterations and dk_len must be > 0"));
    }
    let hash_len = factory().output_size();
    let n = dk_len.div_ceil(hash_len);
    let mut dk = Vec::with_capacity(dk_len);

    for i in 1..=n {
        // U1 = HMAC(password, salt || i_be32)
        let mut hmac = Hmac::new(factory, password)?;
        hmac.update(salt)?;
        hmac.update(&(i as u32).to_be_bytes())?;
        let mut u = [0u8; 64]; // Max SHA-512 output
        hmac.finish(&mut u[..hash_len])?;

        let mut t = [0u8; 64];
        t[..hash_len].copy_from_slice(&u[..hash_len]);

        // U2..Uc — reuse single stack buffer for all iterations
        for _ in 1..iterations {
            hmac.reset()?;
            hmac.update(&u[..hash_len])?;
            hmac.finish(&mut u[..hash_len])?;
            for j in 0..hash_len {
                t[j] ^= u[j];
            }
        }

        let take = (dk_len - dk.len()).min(hash_len);
        dk.extend_from_slice(&t[..take]);
        t.zeroize();
        u.zeroize();
    }
    Ok(dk)
}

/// Derive a key from a password using PBKDF2-HMAC-SHA256.
pub fn pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dk_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    pbkdf2_with_hmac(sha256_factory, password, salt, iterations, dk_len)
}

/// PRF (the inner HMAC hash) selector for RFC 8018 PBKDF2.
///
/// RFC 8018 §5.2 makes the PRF an `AlgorithmIdentifier` defaulting to
/// `hmacWithSHA1`; PBES2-encrypted PKCS#8/PKCS#12 in the wild uses any of
/// these (OpenSSL's legacy default is HMAC-SHA1, its modern default
/// HMAC-SHA256). `pbkdf2_prf` lets the codec layer drive the right hash by
/// enum without reaching into this crate's digest types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pbkdf2Prf {
    /// HMAC-SHA-1 (RFC 8018 default).
    HmacSha1,
    /// HMAC-SHA-224.
    HmacSha224,
    /// HMAC-SHA-256.
    HmacSha256,
    /// HMAC-SHA-384.
    HmacSha384,
    /// HMAC-SHA-512.
    HmacSha512,
    /// HMAC-SM3 (GM/T).
    #[cfg(feature = "sm3")]
    HmacSm3,
}

/// PBKDF2 with an explicit PRF (inner HMAC hash) selector.
pub fn pbkdf2_prf(
    prf: Pbkdf2Prf,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dk_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    fn f_sha1() -> Box<dyn Digest> {
        Box::new(crate::sha1::Sha1::new())
    }
    fn f_sha224() -> Box<dyn Digest> {
        Box::new(crate::sha2::Sha224::new())
    }
    fn f_sha384() -> Box<dyn Digest> {
        Box::new(crate::sha2::Sha384::new())
    }
    fn f_sha512() -> Box<dyn Digest> {
        Box::new(crate::sha2::Sha512::new())
    }
    #[cfg(feature = "sm3")]
    fn f_sm3() -> Box<dyn Digest> {
        Box::new(crate::sm3::Sm3::new())
    }
    let factory: fn() -> Box<dyn Digest> = match prf {
        Pbkdf2Prf::HmacSha1 => f_sha1,
        Pbkdf2Prf::HmacSha224 => f_sha224,
        Pbkdf2Prf::HmacSha256 => sha256_factory,
        Pbkdf2Prf::HmacSha384 => f_sha384,
        Pbkdf2Prf::HmacSha512 => f_sha512,
        #[cfg(feature = "sm3")]
        Pbkdf2Prf::HmacSm3 => f_sm3,
    };
    pbkdf2_with_hmac(factory, password, salt, iterations, dk_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::hex::to_hex;

    // PBKDF2-HMAC-SHA256 test vectors
    // From RFC 7914 Section 11 and other known-good sources
    #[test]
    fn test_pbkdf2_sha256_c1() {
        // password="passwd", salt="salt", c=1, dkLen=64
        let dk = pbkdf2(b"passwd", b"salt", 1, 64).unwrap();
        let expected = "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783";
        assert_eq!(to_hex(&dk), expected);
    }

    #[test]
    fn test_pbkdf2_sha256_c80000() {
        // password="Password", salt="NaCl", c=80000, dkLen=64
        let dk = pbkdf2(b"Password", b"NaCl", 80000, 64).unwrap();
        let expected = "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d";
        assert_eq!(to_hex(&dk), expected);
    }

    #[test]
    fn test_pbkdf2_sha256_short() {
        // Simple test: derive 16 bytes
        let dk = pbkdf2(b"password", b"salt", 1, 16).unwrap();
        assert_eq!(dk.len(), 16);

        // Same parameters should give same result
        let dk2 = pbkdf2(b"password", b"salt", 1, 16).unwrap();
        assert_eq!(dk, dk2);
    }

    #[test]
    fn test_pbkdf2_invalid_params() {
        assert!(pbkdf2(b"password", b"salt", 0, 16).is_err());
        assert!(pbkdf2(b"password", b"salt", 1, 0).is_err());
    }

    #[test]
    fn test_pbkdf2_single_byte_output() {
        let dk = pbkdf2(b"password", b"salt", 1, 1).unwrap();
        assert_eq!(dk.len(), 1);
    }

    #[test]
    fn test_pbkdf2_deterministic() {
        let dk1 = pbkdf2(b"secret", b"pepper", 100, 32).unwrap();
        let dk2 = pbkdf2(b"secret", b"pepper", 100, 32).unwrap();
        assert_eq!(dk1, dk2);
    }

    // Test pbkdf2_with_hmac using SHA-1 (RFC 6070 test vectors)
    #[cfg(feature = "sha1")]
    #[test]
    fn test_pbkdf2_with_sha1_rfc6070_vector1() {
        use crate::sha1::Sha1;
        fn sha1_factory() -> Box<dyn Digest> {
            Box::new(Sha1::new())
        }
        // RFC 6070 Test Vector 1: "password", "salt", c=1, dkLen=20
        let dk = pbkdf2_with_hmac(sha1_factory, b"password", b"salt", 1, 20).unwrap();
        assert_eq!(to_hex(&dk), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    }

    // RFC 6070 Test Vector 2: "password", "salt", c=2, dkLen=20
    #[cfg(feature = "sha1")]
    #[test]
    fn test_pbkdf2_with_sha1_rfc6070_vector2() {
        use crate::sha1::Sha1;
        fn sha1_factory() -> Box<dyn Digest> {
            Box::new(Sha1::new())
        }
        let dk = pbkdf2_with_hmac(sha1_factory, b"password", b"salt", 2, 20).unwrap();
        assert_eq!(to_hex(&dk), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    }

    // RFC 6070 Test Vector 3: "password", "salt", c=4096, dkLen=20
    #[cfg(feature = "sha1")]
    #[test]
    fn test_pbkdf2_with_sha1_rfc6070_vector3() {
        use crate::sha1::Sha1;
        fn sha1_factory() -> Box<dyn Digest> {
            Box::new(Sha1::new())
        }
        let dk = pbkdf2_with_hmac(sha1_factory, b"password", b"salt", 4096, 20).unwrap();
        assert_eq!(to_hex(&dk), "4b007901b765489abead49d926f721d065a429c1");
    }

    // RFC 6070 Test Vector 4: "password", "salt", c=16777216, dkLen=20
    // This test takes minutes to run due to 16M iterations.
    #[cfg(feature = "sha1")]
    #[test]
    #[ignore]
    fn test_pbkdf2_with_sha1_rfc6070_vector4() {
        use crate::sha1::Sha1;
        fn sha1_factory() -> Box<dyn Digest> {
            Box::new(Sha1::new())
        }
        let dk = pbkdf2_with_hmac(sha1_factory, b"password", b"salt", 16_777_216, 20).unwrap();
        assert_eq!(to_hex(&dk), "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984");
    }

    // RFC 6070 Test Vector 5: long password and salt, c=4096, dkLen=25
    #[cfg(feature = "sha1")]
    #[test]
    fn test_pbkdf2_with_sha1_rfc6070_vector5() {
        use crate::sha1::Sha1;
        fn sha1_factory() -> Box<dyn Digest> {
            Box::new(Sha1::new())
        }
        let dk = pbkdf2_with_hmac(
            sha1_factory,
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            25,
        )
        .unwrap();
        assert_eq!(
            to_hex(&dk),
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
        );
    }

    // Test with SHA-384
    #[test]
    fn test_pbkdf2_with_sha384() {
        use crate::sha2::Sha384;
        fn sha384_factory() -> Box<dyn Digest> {
            Box::new(Sha384::new())
        }
        let dk = pbkdf2_with_hmac(sha384_factory, b"password", b"salt", 1, 48).unwrap();
        assert_eq!(dk.len(), 48);
        // Deterministic
        let dk2 = pbkdf2_with_hmac(sha384_factory, b"password", b"salt", 1, 48).unwrap();
        assert_eq!(dk, dk2);
    }

    // Test with SHA-512
    #[test]
    fn test_pbkdf2_with_sha512() {
        use crate::sha2::Sha512;
        fn sha512_factory() -> Box<dyn Digest> {
            Box::new(Sha512::new())
        }
        let dk = pbkdf2_with_hmac(sha512_factory, b"password", b"salt", 1, 64).unwrap();
        assert_eq!(dk.len(), 64);
        // Deterministic
        let dk2 = pbkdf2_with_hmac(sha512_factory, b"password", b"salt", 1, 64).unwrap();
        assert_eq!(dk, dk2);
    }

    // Test with SM3
    #[cfg(feature = "sm3")]
    #[test]
    fn test_pbkdf2_with_sm3() {
        use crate::sm3::Sm3;
        fn sm3_factory() -> Box<dyn Digest> {
            Box::new(Sm3::new())
        }
        let dk = pbkdf2_with_hmac(sm3_factory, b"password", b"salt", 1, 32).unwrap();
        assert_eq!(dk.len(), 32);
        // Deterministic
        let dk2 = pbkdf2_with_hmac(sm3_factory, b"password", b"salt", 1, 32).unwrap();
        assert_eq!(dk, dk2);
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(10))]

            #[test]
            fn prop_pbkdf2_deterministic(
                password in prop::collection::vec(any::<u8>(), 1..32),
                salt in prop::collection::vec(any::<u8>(), 1..16),
                dk_len in 1usize..=64,
            ) {
                let dk1 = pbkdf2(&password, &salt, 1, dk_len).unwrap();
                let dk2 = pbkdf2(&password, &salt, 1, dk_len).unwrap();
                prop_assert_eq!(&dk1, &dk2);
                prop_assert_eq!(dk1.len(), dk_len);
            }
        }
    }
}
