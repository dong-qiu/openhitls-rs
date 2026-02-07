//! Elliptic curve parameter definitions for Weierstrass curves.
//!
//! Provides hard-coded parameters for NIST P-256 (secp256r1) and P-384 (secp384r1).

use hitls_bignum::BigNum;
use hitls_types::{CryptoError, EccCurveId};

/// Parameters for a short Weierstrass curve: y² = x³ + ax + b (mod p).
#[derive(Clone)]
pub(crate) struct CurveParams {
    /// Prime field modulus.
    pub p: BigNum,
    /// Curve coefficient a.
    pub a: BigNum,
    /// Curve coefficient b.
    pub b: BigNum,
    /// Base point G x-coordinate.
    pub gx: BigNum,
    /// Base point G y-coordinate.
    pub gy: BigNum,
    /// Order of the base point G.
    pub n: BigNum,
    /// Cofactor (1 for P-256 and P-384).
    pub h: u32,
    /// Field element byte length (32 for P-256, 48 for P-384).
    pub field_size: usize,
}

/// Helper: parse a hex string into a BigNum.
fn bn(hex: &str) -> BigNum {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    BigNum::from_bytes_be(&bytes)
}

/// Return curve parameters for the given curve ID.
pub(crate) fn get_curve_params(curve_id: EccCurveId) -> Result<CurveParams, CryptoError> {
    match curve_id {
        EccCurveId::NistP256 => Ok(p256_params()),
        EccCurveId::NistP384 => Ok(p384_params()),
        EccCurveId::Sm2Prime256 => Ok(sm2p256v1_params()),
        _ => Err(CryptoError::InvalidArg),
    }
}

/// NIST P-256 (secp256r1) parameters.
fn p256_params() -> CurveParams {
    CurveParams {
        p: bn("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
        a: bn("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
        b: bn("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
        gx: bn("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
        gy: bn("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
        n: bn("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
        h: 1,
        field_size: 32,
    }
}

/// SM2P256V1 (GB/T 32918.5-2017) parameters.
fn sm2p256v1_params() -> CurveParams {
    CurveParams {
        p: bn("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
        a: bn("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"),
        b: bn("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
        gx: bn("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
        gy: bn("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
        n: bn("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
        h: 1,
        field_size: 32,
    }
}

/// NIST P-384 (secp384r1) parameters.
fn p384_params() -> CurveParams {
    CurveParams {
        p: bn("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"),
        a: bn("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"),
        b: bn("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"),
        gx: bn("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"),
        gy: bn("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"),
        n: bn("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
        h: 1,
        field_size: 48,
    }
}
