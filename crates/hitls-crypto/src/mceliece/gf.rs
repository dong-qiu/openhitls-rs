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
    #[allow(clippy::needless_range_loop)]
    for i in 0..(Q - 1) {
        exp_table[i] = a as u16;
        log_table[a as usize] = i as u16;
        // Multiply by generator 3: a * 3 = a * (x + 1) = (a << 1) ^ a
        let next = (a << 1) ^ a;
        a = if next & (1 << 13) != 0 { next ^ GF_POLY } else { next };
    }
    // log[0] is undefined, set to 0 as sentinel
    log_table[0] = 0;
    exp_table[Q - 1] = exp_table[0]; // wrap around

    GfTables { log_table, exp_table }
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
    let s = t.log_table[a as usize] as u32 + t.log_table[b as usize] as u32;
    let s = if s >= Q_1 as u32 { s - Q_1 as u32 } else { s };
    t.exp_table[s as usize]
}

/// GF(2^13) inverse.
#[inline]
pub(crate) fn gf_inv(a: GfElement) -> GfElement {
    if a == 0 {
        return 0; // 0 has no inverse
    }
    let t = tables();
    let l = t.log_table[a as usize] as u32;
    t.exp_table[(Q_1 as u32 - l) as usize]
}

/// GF(2^13) division.
#[inline]
pub(crate) fn gf_div(a: GfElement, b: GfElement) -> GfElement {
    gf_mul(a, gf_inv(b))
}

/// GF(2^13) exponentiation.
pub(crate) fn gf_pow(base: GfElement, exp: i32) -> GfElement {
    if base == 0 {
        return 0;
    }
    if exp == 0 {
        return 1;
    }
    let t = tables();
    let l = t.log_table[base as usize] as u64;
    let mut e = exp as i64 % Q_1 as i64;
    if e < 0 {
        e += Q_1 as i64;
    }
    let s = (l * e as u64) % Q_1 as u64;
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
}
