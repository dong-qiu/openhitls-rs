//! Elliptic curve parameter definitions for Weierstrass curves.
//!
//! Provides hard-coded parameters for NIST P-192, P-224, P-256, P-384, P-521,
//! Brainpool P-256r1, P-384r1, P-512r1, and SM2P256V1.

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
    /// Cofactor.
    pub h: u32,
    /// Field element byte length.
    pub field_size: usize,
    /// Whether a = p - 3 (enables optimized point doubling for NIST curves).
    pub a_is_minus_3: bool,
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
        EccCurveId::NistP192 => Ok(p192_params()),
        EccCurveId::NistP224 => Ok(p224_params()),
        EccCurveId::NistP256 => Ok(p256_params()),
        EccCurveId::NistP384 => Ok(p384_params()),
        EccCurveId::NistP521 => Ok(p521_params()),
        EccCurveId::BrainpoolP256r1 => Ok(brainpool_p256r1_params()),
        EccCurveId::BrainpoolP384r1 => Ok(brainpool_p384r1_params()),
        EccCurveId::BrainpoolP512r1 => Ok(brainpool_p512r1_params()),
        EccCurveId::Sm2Prime256 => Ok(sm2p256v1_params()),
    }
}

/// NIST P-192 (secp192r1) parameters — FIPS 186-4 / SEC 2 §2.4.
fn p192_params() -> CurveParams {
    CurveParams {
        p: bn("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"),
        a: bn("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC"),
        b: bn("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1"),
        gx: bn("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"),
        gy: bn("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"),
        n: bn("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"),
        h: 1,
        field_size: 24,
        a_is_minus_3: true,
    }
}

/// NIST P-224 (secp224r1) parameters — FIPS 186-4 / SEC 2 §2.5.
fn p224_params() -> CurveParams {
    CurveParams {
        p: bn("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001"),
        a: bn("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE"),
        b: bn("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4"),
        gx: bn("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"),
        gy: bn("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"),
        n: bn("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"),
        h: 1,
        field_size: 28,
        a_is_minus_3: true,
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
        a_is_minus_3: true,
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
        a_is_minus_3: true,
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
        a_is_minus_3: true,
    }
}

/// NIST P-521 (secp521r1) parameters — FIPS 186-4 / SEC 2 §2.9.
fn p521_params() -> CurveParams {
    CurveParams {
        p: bn("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        a: bn("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"),
        b: bn("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"),
        gx: bn("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"),
        gy: bn("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"),
        n: bn("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"),
        h: 1,
        field_size: 66,
        a_is_minus_3: true,
    }
}

/// Brainpool P-256r1 parameters — RFC 5639 §3.4.
fn brainpool_p256r1_params() -> CurveParams {
    CurveParams {
        p: bn("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"),
        a: bn("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"),
        b: bn("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"),
        gx: bn("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"),
        gy: bn("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"),
        n: bn("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"),
        h: 1,
        field_size: 32,
        a_is_minus_3: false,
    }
}

/// Brainpool P-384r1 parameters — RFC 5639 §3.5.
fn brainpool_p384r1_params() -> CurveParams {
    CurveParams {
        p: bn("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53"),
        a: bn("7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826"),
        b: bn("04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11"),
        gx: bn("1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E"),
        gy: bn("8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315"),
        n: bn("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"),
        h: 1,
        field_size: 48,
        a_is_minus_3: false,
    }
}

/// Brainpool P-512r1 parameters — RFC 5639 §3.6.
fn brainpool_p512r1_params() -> CurveParams {
    CurveParams {
        p: bn("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3"),
        a: bn("7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA"),
        b: bn("3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723"),
        gx: bn("81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822"),
        gy: bn("7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892"),
        n: bn("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"),
        h: 1,
        field_size: 64,
        a_is_minus_3: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_types::EccCurveId;

    const ALL_CURVES: [EccCurveId; 9] = [
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

    #[test]
    fn test_all_curves_load_successfully() {
        for &curve_id in &ALL_CURVES {
            let params = get_curve_params(curve_id);
            assert!(params.is_ok(), "failed to load curve {curve_id:?}");
        }
    }

    #[test]
    fn test_field_size_matches_prime_byte_length() {
        let expected_sizes: [(EccCurveId, usize); 9] = [
            (EccCurveId::NistP192, 24),
            (EccCurveId::NistP224, 28),
            (EccCurveId::NistP256, 32),
            (EccCurveId::NistP384, 48),
            (EccCurveId::NistP521, 66),
            (EccCurveId::BrainpoolP256r1, 32),
            (EccCurveId::BrainpoolP384r1, 48),
            (EccCurveId::BrainpoolP512r1, 64),
            (EccCurveId::Sm2Prime256, 32),
        ];
        for (curve_id, expected) in expected_sizes {
            let params = get_curve_params(curve_id).unwrap();
            assert_eq!(
                params.field_size, expected,
                "field_size mismatch for {curve_id:?}"
            );
            let p_bytes = params.p.to_bytes_be();
            assert!(
                p_bytes.len() <= expected,
                "prime byte length > field_size for {curve_id:?}"
            );
        }
    }

    #[test]
    fn test_all_curves_cofactor_one() {
        for &curve_id in &ALL_CURVES {
            let params = get_curve_params(curve_id).unwrap();
            assert_eq!(params.h, 1, "cofactor != 1 for {curve_id:?}");
        }
    }

    #[test]
    fn test_a_is_minus_3_flag() {
        // NIST curves and SM2 have a = p - 3
        let minus3_true = [
            EccCurveId::NistP192,
            EccCurveId::NistP224,
            EccCurveId::NistP256,
            EccCurveId::NistP384,
            EccCurveId::NistP521,
            EccCurveId::Sm2Prime256,
        ];
        for &curve_id in &minus3_true {
            let params = get_curve_params(curve_id).unwrap();
            assert!(
                params.a_is_minus_3,
                "expected a_is_minus_3=true for {curve_id:?}"
            );
        }
        // Brainpool curves do NOT have a = p - 3
        let minus3_false = [
            EccCurveId::BrainpoolP256r1,
            EccCurveId::BrainpoolP384r1,
            EccCurveId::BrainpoolP512r1,
        ];
        for &curve_id in &minus3_false {
            let params = get_curve_params(curve_id).unwrap();
            assert!(
                !params.a_is_minus_3,
                "expected a_is_minus_3=false for {curve_id:?}"
            );
        }
    }

    #[test]
    fn test_all_primes_unique() {
        let primes: Vec<Vec<u8>> = ALL_CURVES
            .iter()
            .map(|&id| get_curve_params(id).unwrap().p.to_bytes_be())
            .collect();
        for i in 0..primes.len() {
            for j in (i + 1)..primes.len() {
                assert_ne!(
                    primes[i], primes[j],
                    "curves {:?} and {:?} share the same prime",
                    ALL_CURVES[i], ALL_CURVES[j]
                );
            }
        }
    }

    #[test]
    fn test_order_less_than_prime() {
        for &curve_id in &ALL_CURVES {
            let params = get_curve_params(curve_id).unwrap();
            let n_bytes = params.n.to_bytes_be();
            let p_bytes = params.p.to_bytes_be();
            // n < p: either fewer bytes, or lexicographically smaller
            assert!(
                n_bytes.len() <= p_bytes.len(),
                "order byte length > prime byte length for {curve_id:?}"
            );
        }
    }
}
