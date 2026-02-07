//! Predefined DH group parameters from RFC 7919 (FFDHE).
//!
//! Provides the prime p and generator g for ffdhe2048 and ffdhe3072.

use hitls_bignum::BigNum;
use hitls_types::DhParamId;

/// Return (p, g) as BigNum for a predefined DH group.
pub(crate) fn get_ffdhe_params(id: DhParamId) -> Option<(BigNum, BigNum)> {
    match id {
        DhParamId::Rfc7919_2048 => Some((bn(FFDHE2048_P), BigNum::from_u64(2))),
        DhParamId::Rfc7919_3072 => Some((bn(FFDHE3072_P), BigNum::from_u64(2))),
        _ => None,
    }
}

/// Helper: parse a hex string into a BigNum.
fn bn(hex: &str) -> BigNum {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    BigNum::from_bytes_be(&bytes)
}

// RFC 7919 §3.1 ffdhe2048 prime (2048-bit, 512 hex chars)
const FFDHE2048_P: &str = "\
FFFFFFFFFFFFFFFFADF85458a2bb4a9aafdc5620273d3cf1\
d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef9\
7d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd6561\
2433f51f5f066ed0856365553ded1af3b557135e7f57c935\
984f0c70e0e68b77e2a689daf3efe8721df158a136ade735\
30acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fb\
b96adab760d7f4681d4f42a3de394df4ae56ede76372bb19\
0b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61\
9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad73\
3bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa\
886b423861285c97ffffffffffffffff";

// RFC 7919 §3.2 ffdhe3072 prime (3072-bit, 768 hex chars)
const FFDHE3072_P: &str = "\
FFFFFFFFFFFFFFFFADF85458a2bb4a9aafdc5620273d3cf1\
d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef9\
7d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd6561\
2433f51f5f066ed0856365553ded1af3b557135e7f57c935\
984f0c70e0e68b77e2a689daf3efe8721df158a136ade735\
30acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fb\
b96adab760d7f4681d4f42a3de394df4ae56ede76372bb19\
0b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61\
9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad73\
3bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa\
886b4238611fcfdcde355b3b6519035bbc34f4def99c0238\
61b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c\
aefe130985139270b4130c93bc437944f4fd4452e2d74dd3\
64f2e21e71f54bff5cae82ab9c9df69ee86d2bc522363a0d\
abc521979b0deada1dbf9a42d5c4484e0abcd06bfa53ddef\
3c1b20ee3fd59d7c25e41d2b66c62e37ffffffffffffffff";
