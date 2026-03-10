//! GF(2^13) arithmetic for Classic McEliece.
//!
//! Irreducible polynomial: x^13 + x^4 + x^3 + x + 1 = 0x201B
//! Generator: 3.
//! Uses LOG/EXP tables computed on first use via OnceLock.

use std::sync::OnceLock;

use super::params::{Q, Q_1};

pub(crate) type GfElement = u16;

const GF_POLY: u32 = 0x201B;

struct GfTables {
    log_table: [u16; Q],
    exp_table: [u16; Q],
}

static GF_TABLES: OnceLock<GfTables> = OnceLock::new();

fn init_tables() -> GfTables {
    let mut log_table = [0u16; Q];
    let mut exp_table = [0u16; Q];

    // Build exp table using generator 3
    // Multiply by 3 (= x+1) in GF(2^13) with reduction poly 0x201B
    let mut a: u32 = 1;
    for i in 0..(Q - 1) {
        exp_table[i] = a as u16;
        log_table[a as usize] = i as u16;
        // Multiply by generator 3: a * 3 = a * (x + 1) = (a << 1) ^ a
        let next = (a << 1) ^ a;
        a = if next & (1 << 13) != 0 {
            next ^ GF_POLY
        } else {
            next
        };
    }
    // log[0] is undefined, set to 0 as sentinel
    log_table[0] = 0;
    exp_table[Q - 1] = exp_table[0]; // wrap around

    GfTables {
        log_table,
        exp_table,
    }
}

fn tables() -> &'static GfTables {
    GF_TABLES.get_or_init(init_tables)
}

/// GF(2^13) addition (XOR).
#[inline]
pub(crate) fn gf_add(a: GfElement, b: GfElement) -> GfElement {
    a ^ b
}

/// GF(2^13) multiplication using log/exp tables.
#[inline]
pub(crate) fn gf_mul(a: GfElement, b: GfElement) -> GfElement {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    let s = u32::from(t.log_table[a as usize]) + u32::from(t.log_table[b as usize]);
    let s = if s >= u32::from(Q_1) {
        s - u32::from(Q_1)
    } else {
        s
    };
    t.exp_table[s as usize]
}

/// GF(2^13) inverse.
#[inline]
pub(crate) fn gf_inv(a: GfElement) -> GfElement {
    if a == 0 {
        return 0; // 0 has no inverse
    }
    let t = tables();
    let l = u32::from(t.log_table[a as usize]);
    t.exp_table[(u32::from(Q_1) - l) as usize]
}

/// GF(2^13) division.
#[inline]
pub(crate) fn gf_div(a: GfElement, b: GfElement) -> GfElement {
    gf_mul(a, gf_inv(b))
}

/// GF(2^13) exponentiation.
pub(crate) fn gf_pow(base: GfElement, exp: i32) -> GfElement {
    // Check exp == 0 first: x^0 = 1 for all x, including x = 0.
    // This is required for correct Goppa code syndrome computation
    // when support contains the zero element.
    if exp == 0 {
        return 1;
    }
    if base == 0 {
        return 0;
    }
    let t = tables();
    let l = u64::from(t.log_table[base as usize]);
    let mut e = i64::from(exp) % i64::from(Q_1);
    if e < 0 {
        e += i64::from(Q_1);
    }
    let s = (l * e as u64) % u64::from(Q_1);
    t.exp_table[s as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_basics() {
        // Verify table initialization
        let t = tables();
        assert_eq!(t.exp_table[0], 1); // 3^0 = 1
        assert_eq!(t.exp_table[1], 3); // 3^1 = 3

        // a * a^(-1) = 1
        for a in 1..100u16 {
            let inv = gf_inv(a);
            assert_eq!(gf_mul(a, inv), 1, "inv failed for {}", a);
        }

        // a + a = 0
        for a in 0..100u16 {
            assert_eq!(gf_add(a, a), 0);
        }

        // a * 1 = a
        for a in 0..100u16 {
            assert_eq!(gf_mul(a, 1), a);
        }
    }

    #[test]
    fn test_gf_mul_commutativity() {
        for a in 1..50u16 {
            for b in 1..50u16 {
                assert_eq!(gf_mul(a, b), gf_mul(b, a), "a={}, b={}", a, b);
            }
        }
    }

    #[test]
    fn test_gf_pow_matches_repeated_mul() {
        let base: GfElement = 7;
        let mut acc: GfElement = 1;
        for exp in 0..20 {
            assert_eq!(gf_pow(base, exp), acc, "base=7, exp={}", exp);
            acc = gf_mul(acc, base);
        }
    }

    #[test]
    fn test_gf_div_inverse_relationship() {
        // div(a, b) == mul(a, inv(b))
        for a in 1..50u16 {
            for b in 1..50u16 {
                assert_eq!(gf_div(a, b), gf_mul(a, gf_inv(b)), "a={}, b={}", a, b);
            }
        }
    }

    #[test]
    fn test_gf_inv_zero_returns_zero() {
        assert_eq!(gf_inv(0), 0);
        assert_eq!(gf_mul(0, gf_inv(0)), 0);
        assert_eq!(gf_div(0, 5), 0);
        assert_eq!(gf_pow(0, 5), 0);
    }

    #[test]
    fn test_gf_pow_negative_exponent() {
        // pow(a, -1) == inv(a)
        for a in 1..50u16 {
            assert_eq!(gf_pow(a, -1), gf_inv(a), "a={}", a);
        }
        // pow(a, 0) == 1
        for a in 1..50u16 {
            assert_eq!(gf_pow(a, 0), 1, "a={}", a);
        }
        // pow(0, k) == 0
        assert_eq!(gf_pow(0, -1), 0);
    }
}
