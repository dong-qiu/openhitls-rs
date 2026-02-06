//! Big number type and basic operations.

use zeroize::Zeroize;

/// Limb type for big number representation (64-bit on 64-bit platforms).
pub type Limb = u64;
/// Double-width type for multiplication intermediates.
pub type DoubleLimb = u128;

/// Bits per limb.
pub const LIMB_BITS: usize = 64;

/// A heap-allocated big number that is zeroized on drop.
///
/// Internally represented as a little-endian array of `u64` limbs.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct BigNum {
    /// Little-endian limbs (limbs[0] is the least significant).
    limbs: Vec<Limb>,
    /// True if the number is negative.
    negative: bool,
}

impl BigNum {
    /// Create a zero-valued BigNum.
    pub fn zero() -> Self {
        Self {
            limbs: vec![0],
            negative: false,
        }
    }

    /// Create a BigNum from a `u64` value.
    pub fn from_u64(value: u64) -> Self {
        Self {
            limbs: vec![value],
            negative: false,
        }
    }

    /// Create a BigNum from big-endian bytes.
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }

        let num_limbs = bytes.len().div_ceil(8);
        let mut limbs = vec![0u64; num_limbs];

        for (i, &byte) in bytes.iter().rev().enumerate() {
            let limb_idx = i / 8;
            let bit_pos = (i % 8) * 8;
            limbs[limb_idx] |= (byte as u64) << bit_pos;
        }

        let mut bn = Self {
            limbs,
            negative: false,
        };
        bn.normalize();
        bn
    }

    /// Export to big-endian bytes.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let bits = self.bit_len();
        if bits == 0 {
            return vec![0];
        }

        let num_bytes = bits.div_ceil(8);
        let mut bytes = vec![0u8; num_bytes];

        for i in 0..num_bytes {
            let limb_idx = i / 8;
            let bit_pos = (i % 8) * 8;
            if limb_idx < self.limbs.len() {
                bytes[num_bytes - 1 - i] = (self.limbs[limb_idx] >> bit_pos) as u8;
            }
        }

        bytes
    }

    /// Return the number of significant bits.
    pub fn bit_len(&self) -> usize {
        for i in (0..self.limbs.len()).rev() {
            if self.limbs[i] != 0 {
                return i * LIMB_BITS + (LIMB_BITS - self.limbs[i].leading_zeros() as usize);
            }
        }
        0
    }

    /// Return the number of limbs.
    pub fn num_limbs(&self) -> usize {
        self.limbs.len()
    }

    /// Return true if this number is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    /// Return true if this number is negative.
    pub fn is_negative(&self) -> bool {
        self.negative && !self.is_zero()
    }

    /// Return the limbs as a slice.
    pub fn limbs(&self) -> &[Limb] {
        &self.limbs
    }

    /// Access mutable limbs.
    pub fn limbs_mut(&mut self) -> &mut Vec<Limb> {
        &mut self.limbs
    }

    /// Set the sign.
    pub fn set_negative(&mut self, neg: bool) {
        self.negative = neg;
    }

    /// Create a BigNum from a vector of little-endian limbs.
    pub fn from_limbs(limbs: Vec<Limb>) -> Self {
        let mut bn = Self {
            limbs: if limbs.is_empty() { vec![0] } else { limbs },
            negative: false,
        };
        bn.normalize();
        bn
    }

    /// Return true if this number equals 1.
    pub fn is_one(&self) -> bool {
        !self.negative && self.limbs.len() == 1 && self.limbs[0] == 1
    }

    /// Return true if this number is even.
    pub fn is_even(&self) -> bool {
        self.limbs[0] & 1 == 0
    }

    /// Return true if this number is odd.
    pub fn is_odd(&self) -> bool {
        self.limbs[0] & 1 == 1
    }

    /// Get bit at position `idx` (0-indexed from LSB).
    pub fn get_bit(&self, idx: usize) -> u64 {
        let limb_idx = idx / LIMB_BITS;
        let bit_idx = idx % LIMB_BITS;
        if limb_idx >= self.limbs.len() {
            0
        } else {
            (self.limbs[limb_idx] >> bit_idx) & 1
        }
    }

    /// Set bit at position `idx` (0-indexed from LSB).
    pub fn set_bit(&mut self, idx: usize) {
        let limb_idx = idx / LIMB_BITS;
        let bit_idx = idx % LIMB_BITS;
        if limb_idx >= self.limbs.len() {
            self.limbs.resize(limb_idx + 1, 0);
        }
        self.limbs[limb_idx] |= 1u64 << bit_idx;
    }

    /// Remove leading zero limbs.
    pub(crate) fn normalize(&mut self) {
        while self.limbs.len() > 1 && *self.limbs.last().unwrap() == 0 {
            self.limbs.pop();
        }
        if self.is_zero() {
            self.negative = false;
        }
    }
}

impl std::fmt::Debug for BigNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sign = if self.negative { "-" } else { "" };
        let hex = self
            .to_bytes_be()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        write!(f, "BigNum({sign}0x{hex})")
    }
}

impl PartialEq for BigNum {
    fn eq(&self, other: &Self) -> bool {
        self.negative == other.negative && self.limbs == other.limbs
    }
}

impl Eq for BigNum {}

impl PartialOrd for BigNum {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigNum {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let self_neg = self.is_negative();
        let other_neg = other.is_negative();
        match (self_neg, other_neg) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => {
                // Both non-negative: compare absolute values
                let a_bits = self.bit_len();
                let b_bits = other.bit_len();
                if a_bits != b_bits {
                    return a_bits.cmp(&b_bits);
                }
                for i in (0..self.limbs.len().max(other.limbs.len())).rev() {
                    let a = if i < self.limbs.len() {
                        self.limbs[i]
                    } else {
                        0
                    };
                    let b = if i < other.limbs.len() {
                        other.limbs[i]
                    } else {
                        0
                    };
                    if a != b {
                        return a.cmp(&b);
                    }
                }
                Ordering::Equal
            }
            (true, true) => {
                // Both negative: larger absolute value is smaller
                let a_bits = self.bit_len();
                let b_bits = other.bit_len();
                if a_bits != b_bits {
                    return b_bits.cmp(&a_bits);
                }
                for i in (0..self.limbs.len().max(other.limbs.len())).rev() {
                    let a = if i < self.limbs.len() {
                        self.limbs[i]
                    } else {
                        0
                    };
                    let b = if i < other.limbs.len() {
                        other.limbs[i]
                    } else {
                        0
                    };
                    if a != b {
                        return b.cmp(&a);
                    }
                }
                Ordering::Equal
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero() {
        let z = BigNum::zero();
        assert!(z.is_zero());
        assert_eq!(z.bit_len(), 0);
    }

    #[test]
    fn test_from_u64() {
        let n = BigNum::from_u64(0xFF);
        assert_eq!(n.bit_len(), 8);
        assert!(!n.is_zero());
    }

    #[test]
    fn test_bytes_roundtrip() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let n = BigNum::from_bytes_be(&bytes);
        let out = n.to_bytes_be();
        assert_eq!(bytes, out);
    }
}
