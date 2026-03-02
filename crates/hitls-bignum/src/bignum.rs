//! Big number type and basic operations.

use hitls_types::CryptoError;
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

    /// Export to big-endian bytes, left-padded with zeros to exactly `len` bytes.
    /// Returns error if the number requires more than `len` bytes.
    pub fn to_bytes_be_padded(&self, len: usize) -> Result<Vec<u8>, CryptoError> {
        let raw = self.to_bytes_be();
        if raw.len() > len {
            return Err(CryptoError::BufferTooSmall {
                need: raw.len(),
                got: len,
            });
        }
        let mut out = vec![0u8; len];
        out[len - raw.len()..].copy_from_slice(&raw);
        Ok(out)
    }

    /// Create a BigNum from a hexadecimal string (optional "0x" or "0X" prefix).
    pub fn from_hex_str(s: &str) -> Result<Self, CryptoError> {
        let s = s.trim();
        let s = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        if s.is_empty() {
            return Ok(Self::zero());
        }
        // Validate hex characters
        if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CryptoError::InvalidArg("invalid hex character"));
        }
        // Decode hex to bytes
        let byte_len = s.len().div_ceil(2);
        let mut bytes = vec![0u8; byte_len];
        let padded = if s.len() % 2 == 1 {
            format!("0{s}")
        } else {
            s.to_string()
        };
        for (i, chunk) in padded.as_bytes().chunks(2).enumerate() {
            let hi = Self::hex_nibble(chunk[0]);
            let lo = Self::hex_nibble(chunk[1]);
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self::from_bytes_be(&bytes))
    }

    fn hex_nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }

    /// Convert to a hexadecimal string (lowercase, no prefix).
    pub fn to_hex_str(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }
        let bytes = self.to_bytes_be();
        let mut s = String::with_capacity(bytes.len() * 2);
        for (i, &b) in bytes.iter().enumerate() {
            if i == 0 {
                // Skip leading zero in first byte
                if b >> 4 != 0 {
                    s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
                }
                s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
            } else {
                s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
                s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
            }
        }
        s
    }

    /// Create a BigNum from a decimal string.
    pub fn from_dec_str(s: &str) -> Result<Self, CryptoError> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self::zero());
        }
        let (neg, s) = if let Some(rest) = s.strip_prefix('-') {
            (true, rest)
        } else {
            (false, s)
        };
        if !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CryptoError::InvalidArg("invalid decimal character"));
        }
        let ten = Self::from_u64(10);
        let mut acc = Self::zero();
        for &b in s.as_bytes() {
            let digit = Self::from_u64((b - b'0') as u64);
            acc = acc.mul(&ten).add(&digit);
        }
        if neg && !acc.is_zero() {
            acc.set_negative(true);
        }
        Ok(acc)
    }

    /// Convert to a decimal string.
    pub fn to_dec_str(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }
        let ten = Self::from_u64(10);
        let mut digits = Vec::new();
        let mut val = self.clone();
        val.set_negative(false);
        while !val.is_zero() {
            // div_rem cannot fail with divisor=10
            let (q, r) = val.div_rem(&ten).unwrap();
            let d = if r.is_zero() { 0u8 } else { r.limbs()[0] as u8 };
            digits.push(b'0' + d);
            val = q;
        }
        if self.is_negative() {
            digits.push(b'-');
        }
        digits.reverse();
        String::from_utf8(digits).unwrap()
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
    fn test_bit_operations() {
        let n = BigNum::from_u64(0b1010_1100); // 172
        assert_eq!(n.get_bit(0), 0);
        assert_eq!(n.get_bit(2), 1);
        assert_eq!(n.get_bit(3), 1);
        assert_eq!(n.get_bit(5), 1);
        assert_eq!(n.get_bit(7), 1);
        // Out-of-range returns 0
        assert_eq!(n.get_bit(100), 0);
        assert_eq!(n.get_bit(1000), 0);

        // set_bit extends limbs if needed
        let mut m = BigNum::zero();
        m.set_bit(0);
        assert_eq!(m, BigNum::from_u64(1));
        m.set_bit(7);
        assert_eq!(m, BigNum::from_u64(129)); // 2^7 + 1 = 129
                                              // Set a bit beyond current limbs
        m.set_bit(128);
        assert_eq!(m.get_bit(128), 1);
        assert_eq!(m.get_bit(0), 1);
    }

    #[test]
    fn test_is_predicates() {
        assert!(BigNum::from_u64(1).is_one());
        assert!(!BigNum::from_u64(0).is_one());
        assert!(!BigNum::from_u64(2).is_one());

        assert!(BigNum::from_u64(0).is_even());
        assert!(BigNum::from_u64(2).is_even());
        assert!(BigNum::from_u64(100).is_even());
        assert!(!BigNum::from_u64(1).is_even());
        assert!(!BigNum::from_u64(99).is_even());

        assert!(BigNum::from_u64(1).is_odd());
        assert!(BigNum::from_u64(3).is_odd());
        assert!(!BigNum::from_u64(0).is_odd());
        assert!(!BigNum::from_u64(4).is_odd());
    }

    #[test]
    fn test_negative_and_ordering() {
        let mut neg5 = BigNum::from_u64(5);
        neg5.set_negative(true);
        let mut neg3 = BigNum::from_u64(3);
        neg3.set_negative(true);
        let pos5 = BigNum::from_u64(5);
        let zero = BigNum::zero();

        // -5 < -3 < 0 < 5
        assert!(neg5 < neg3);
        assert!(neg3 < zero);
        assert!(zero < pos5);
        assert!(neg5 < pos5);

        // is_negative flag
        assert!(neg5.is_negative());
        assert!(!pos5.is_negative());
        assert!(!zero.is_negative());
    }

    #[test]
    fn test_from_bytes_be_edge_cases() {
        // Empty bytes → zero
        let z = BigNum::from_bytes_be(&[]);
        assert!(z.is_zero());

        // Single byte
        let one = BigNum::from_bytes_be(&[1]);
        assert_eq!(one, BigNum::from_u64(1));

        // Leading zero bytes are preserved in input but normalized
        let n = BigNum::from_bytes_be(&[0x00, 0x00, 0xFF]);
        assert_eq!(n, BigNum::from_u64(0xFF));
        assert_eq!(n.to_bytes_be(), vec![0xFF]); // leading zeros stripped

        // Large value (>64 bits)
        let big_bytes = vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let big = BigNum::from_bytes_be(&big_bytes);
        assert_eq!(big.to_bytes_be(), big_bytes);
        assert!(big.bit_len() > 64);
    }

    #[test]
    fn test_from_limbs_and_normalize() {
        // Trailing zero limbs get normalized away
        let n = BigNum::from_limbs(vec![42, 0, 0, 0]);
        assert_eq!(n.num_limbs(), 1);
        assert_eq!(n, BigNum::from_u64(42));

        // Empty limbs → zero
        let z = BigNum::from_limbs(vec![]);
        assert!(z.is_zero());
        assert_eq!(z.num_limbs(), 1);

        // Multi-limb preserved when significant
        let m = BigNum::from_limbs(vec![1, 1]);
        assert_eq!(m.num_limbs(), 2);
        assert!(!m.is_zero());
    }

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

    #[test]
    fn test_to_bytes_be_padded() {
        let n = BigNum::from_u64(0xFF);
        // Pad to 4 bytes
        let padded = n.to_bytes_be_padded(4).unwrap();
        assert_eq!(padded, vec![0x00, 0x00, 0x00, 0xFF]);
        // Exact size
        let exact = n.to_bytes_be_padded(1).unwrap();
        assert_eq!(exact, vec![0xFF]);
        // Too small should error
        let big = BigNum::from_bytes_be(&[0x01, 0x02, 0x03]);
        assert!(big.to_bytes_be_padded(2).is_err());
    }

    #[test]
    fn test_from_hex_str() {
        assert_eq!(BigNum::from_hex_str("0").unwrap(), BigNum::zero());
        assert_eq!(BigNum::from_hex_str("ff").unwrap(), BigNum::from_u64(0xff));
        assert_eq!(
            BigNum::from_hex_str("0xFF").unwrap(),
            BigNum::from_u64(0xff)
        );
        assert_eq!(
            BigNum::from_hex_str("0X1a2B").unwrap(),
            BigNum::from_u64(0x1a2b)
        );
        // Odd-length hex string
        assert_eq!(
            BigNum::from_hex_str("abc").unwrap(),
            BigNum::from_u64(0xabc)
        );
        // Invalid
        assert!(BigNum::from_hex_str("xyz").is_err());
    }

    #[test]
    fn test_to_hex_str() {
        assert_eq!(BigNum::zero().to_hex_str(), "0");
        assert_eq!(BigNum::from_u64(0xff).to_hex_str(), "ff");
        assert_eq!(BigNum::from_u64(0x1a2b).to_hex_str(), "1a2b");
        assert_eq!(BigNum::from_u64(1).to_hex_str(), "1");
    }

    #[test]
    fn test_hex_str_roundtrip() {
        for val in [0u64, 1, 255, 65535, 0xdeadbeef, u64::MAX] {
            let n = BigNum::from_u64(val);
            let hex = n.to_hex_str();
            let back = BigNum::from_hex_str(&hex).unwrap();
            assert_eq!(n, back, "hex roundtrip failed for {val}");
        }
    }

    #[test]
    fn test_from_dec_str() {
        assert_eq!(BigNum::from_dec_str("0").unwrap(), BigNum::zero());
        assert_eq!(BigNum::from_dec_str("255").unwrap(), BigNum::from_u64(255));
        assert_eq!(
            BigNum::from_dec_str("12345678901234567890").unwrap(),
            BigNum::from_bytes_be(&[0xab, 0x54, 0xa9, 0x8c, 0xeb, 0x1f, 0x0a, 0xd2])
        );
        // Negative
        let neg = BigNum::from_dec_str("-42").unwrap();
        assert!(neg.is_negative());
        // Invalid
        assert!(BigNum::from_dec_str("12x3").is_err());
    }

    #[test]
    fn test_to_dec_str() {
        assert_eq!(BigNum::zero().to_dec_str(), "0");
        assert_eq!(BigNum::from_u64(255).to_dec_str(), "255");
        assert_eq!(BigNum::from_u64(1000000).to_dec_str(), "1000000");
        let mut neg = BigNum::from_u64(42);
        neg.set_negative(true);
        assert_eq!(neg.to_dec_str(), "-42");
    }

    #[test]
    fn test_dec_str_roundtrip() {
        for val in [0u64, 1, 255, 65535, 999999999, u64::MAX] {
            let n = BigNum::from_u64(val);
            let dec = n.to_dec_str();
            let back = BigNum::from_dec_str(&dec).unwrap();
            assert_eq!(n, back, "dec roundtrip failed for {val}");
        }
    }
}
