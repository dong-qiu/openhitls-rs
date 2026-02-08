//! BN256 curve parameters for SM9.
//!
//! Curve E(Fp): y² = x³ + 5 (a=0, b=5)
//! Twist E'(Fp²): y² = x³ + 5u (sextic twist)
//! Tower: Fp2=Fp[u]/(u²+2), Fp4=Fp2[v]/(v²-u), Fp12=Fp4[w]/(w³-v)

use hitls_bignum::BigNum;

/// BN256 prime: p
pub fn p() -> BigNum {
    BigNum::from_bytes_be(&hex(
        "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D",
    ))
}

/// Subgroup order: n
pub fn order() -> BigNum {
    BigNum::from_bytes_be(&hex(
        "B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25",
    ))
}

/// Curve coefficient b = 5
pub fn b_coeff() -> BigNum {
    BigNum::from_u64(5)
}

/// Generator P1 on E(Fp) — x coordinate
pub fn p1_x() -> BigNum {
    BigNum::from_bytes_be(&hex(
        "93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD",
    ))
}

/// Generator P1 on E(Fp) — y coordinate
pub fn p1_y() -> BigNum {
    BigNum::from_bytes_be(&hex(
        "21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616",
    ))
}

/// Generator P2 on E'(Fp²) — x0 coordinate (constant term)
pub fn p2_x0() -> BigNum {
    // SM9 serializes Fp2 as (c1, c0), so the second 32 bytes is c0
    BigNum::from_bytes_be(&hex(
        "3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B",
    ))
}

/// Generator P2 on E'(Fp²) — x1 coordinate (coefficient of u)
pub fn p2_x1() -> BigNum {
    // First 32 bytes in the serialized form is c1
    BigNum::from_bytes_be(&hex(
        "85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141",
    ))
}

/// Generator P2 on E'(Fp²) — y0 coordinate (constant term)
pub fn p2_y0() -> BigNum {
    BigNum::from_bytes_be(&hex(
        "A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7",
    ))
}

/// Generator P2 on E'(Fp²) — y1 coordinate (coefficient of u)
pub fn p2_y1() -> BigNum {
    BigNum::from_bytes_be(&hex(
        "17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96",
    ))
}

/// Miller loop parameter: 6t + 2 = 0x2400000000215D93E
pub fn miller_param() -> BigNum {
    BigNum::from_bytes_be(&hex("02400000000215D93E"))
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
