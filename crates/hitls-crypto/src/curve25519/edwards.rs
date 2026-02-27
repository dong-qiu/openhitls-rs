//! Edwards curve point operations for Ed25519.
//!
//! Uses extended coordinates (X, Y, Z, T) where T = XY/Z on the twisted
//! Edwards curve: -x² + y² = 1 + d·x²·y² with d = -121665/121666.

use std::sync::OnceLock;

use hitls_types::CryptoError;

use super::field::Fe25519;

/// d = -121665/121666 mod p (the Edwards curve parameter).
pub(crate) const D: Fe25519 = Fe25519([
    0x00034DCA135978A3,
    0x0001A8283B156EBD,
    0x0005E7A26001C029,
    0x000739C663A03CBB,
    0x00052036CEE2B6FF,
]);

/// 2*d mod p.
pub(crate) const D2: Fe25519 = Fe25519([
    0x00069B9426B2F159,
    0x00035050762ADD7A,
    0x0003CF44C0038052,
    0x0006738CC7407977,
    0x0002406D9DC56DFF,
]);

/// sqrt(-1) mod p = 2^((p-1)/4) mod p.
pub(crate) const SQRT_M1: Fe25519 = Fe25519([
    0x00061B274A0EA0B0,
    0x0000D5A5FC8F189D,
    0x0007EF5E9CBD0C60,
    0x00078595A6804C9E,
    0x0002B8324804FC1D,
]);

/// Base point Y coordinate: y = 4/5 mod p.
const BASE_Y: Fe25519 = Fe25519([
    0x0006666666666658,
    0x0004CCCCCCCCCCCC,
    0x0001999999999999,
    0x0003333333333333,
    0x0006666666666666,
]);

/// Base point X coordinate (positive, derived from y = 4/5).
const BASE_X: Fe25519 = Fe25519([
    0x00062D608F25D51A,
    0x000412A4B4F6592A,
    0x00075B7171A4B31D,
    0x0001FF60527118FE,
    0x000216936D3CD6E5,
]);

/// A point on the twisted Edwards curve in extended coordinates.
/// Represents the affine point (X/Z, Y/Z) with T = XY/Z.
#[derive(Clone)]
pub(crate) struct GeExtended {
    pub x: Fe25519,
    pub y: Fe25519,
    pub z: Fe25519,
    pub t: Fe25519,
}

impl GeExtended {
    /// The identity point (neutral element): (0, 1, 1, 0).
    pub fn identity() -> Self {
        GeExtended {
            x: Fe25519::zero(),
            y: Fe25519::one(),
            z: Fe25519::one(),
            t: Fe25519::zero(),
        }
    }

    /// The base point B for Ed25519.
    pub fn basepoint() -> Self {
        GeExtended {
            x: BASE_X,
            y: BASE_Y,
            z: Fe25519::one(),
            t: BASE_X.mul(&BASE_Y),
        }
    }

    /// Encode a point to 32 bytes: the y-coordinate with the sign of x in the top bit.
    pub fn to_bytes(&self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);

        let mut out = y.to_bytes();
        out[31] ^= x.is_negative() << 7;
        out
    }

    /// Decode a point from 32 bytes.
    ///
    /// Recovers the x-coordinate from y using the curve equation.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        // Extract the sign bit and clear it
        let x_sign = bytes[31] >> 7;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;

        let y = Fe25519::from_bytes(&y_bytes);

        // Compute x from the curve equation: -x² + y² = 1 + d·x²·y²
        // => x² = (y² - 1) / (d·y² + 1)
        let y2 = y.square();
        let u = y2.sub(&Fe25519::one()); // u = y² - 1
        let v = y2.mul(&D).add(&Fe25519::one()); // v = d·y² + 1

        // x = u·v³ · (u·v⁷)^((p-5)/8)
        let v3 = v.square().mul(&v); // v³
        let v7 = v3.square().mul(&v); // v⁷
        let uv7 = u.mul(&v7);
        let uv3 = u.mul(&v3);

        let mut x = uv3.mul(&uv7.pow25523()); // u·v³ · (u·v⁷)^((p-5)/8)

        // Check: v·x² == u
        let vx2 = x.square().mul(&v);
        if vx2 == u {
            // x is correct
        } else if vx2 == u.neg() {
            // x = x * sqrt(-1)
            x = x.mul(&SQRT_M1);
        } else {
            return Err(CryptoError::EccPointNotOnCurve);
        }

        // Adjust sign
        if x.is_negative() != x_sign {
            x = x.neg();
        }

        // x == 0 and x_sign == 1 is invalid
        if x.is_zero() && x_sign == 1 {
            return Err(CryptoError::EccPointNotOnCurve);
        }

        let t = x.mul(&y);
        Ok(GeExtended {
            x,
            y,
            z: Fe25519::one(),
            t,
        })
    }
}

/// Extended point addition: R = A + B.
///
/// Uses the unified addition formula from Hisil et al. 2008.
pub(crate) fn point_add(a: &GeExtended, b: &GeExtended) -> GeExtended {
    let a_val = a.y.sub(&a.x); // Y1 - X1
    let b_val = b.y.sub(&b.x); // Y2 - X2
    let aa = a_val.mul(&b_val); // A = (Y1-X1)·(Y2-X2)

    let a_val = a.y.add(&a.x); // Y1 + X1
    let b_val = b.y.add(&b.x); // Y2 + X2
    let bb = a_val.mul(&b_val); // B = (Y1+X1)·(Y2+X2)

    let cc = a.t.mul(&D2).mul(&b.t); // C = T1·2d·T2
    let dd = a.z.add(&a.z).mul(&b.z); // D = 2·Z1·Z2

    let e = bb.sub(&aa); // E = B - A
    let f = dd.sub(&cc); // F = D - C
    let g = dd.add(&cc); // G = D + C
    let h = bb.add(&aa); // H = B + A

    GeExtended {
        x: e.mul(&f), // X3 = E·F
        y: g.mul(&h), // Y3 = G·H
        z: f.mul(&g), // Z3 = F·G
        t: e.mul(&h), // T3 = E·H
    }
}

/// Extended point doubling: R = 2A.
///
/// Uses the "dbl-2008-hwcd" formula for twisted Edwards curve with a = -1.
pub(crate) fn point_double(a: &GeExtended) -> GeExtended {
    let aa = a.x.square(); // A = X1²
    let bb = a.y.square(); // B = Y1²
    let cc = a.z.square().add(&a.z.square()); // C = 2·Z1²
    let d_val = aa.neg(); // D = a·A = -A (since a = -1)
    let xy = a.x.add(&a.y);
    let e = xy.square().sub(&aa).sub(&bb); // E = (X1+Y1)² - A - B
    let g = d_val.add(&bb); // G = D + B = B - A
    let f = g.sub(&cc); // F = G - C
    let h = d_val.sub(&bb); // H = D - B = -A - B

    GeExtended {
        x: e.mul(&f), // X3 = E·F
        y: g.mul(&h), // Y3 = G·H
        z: f.mul(&g), // Z3 = F·G
        t: e.mul(&h), // T3 = E·H
    }
}

/// A point in Niels form for fast mixed addition with extended coordinates.
///
/// Stores precomputed values (Y+X, Y-X, 2d·T) from an affine point,
/// eliminating 2 multiplications per addition compared to full extended add.
#[derive(Clone)]
struct NielsPoint {
    ypx: Fe25519, // Y + X
    ymx: Fe25519, // Y - X
    td: Fe25519,  // 2d · T (= 2d · X·Y for affine points where Z=1)
}

impl NielsPoint {
    /// The identity element in Niels form.
    fn identity() -> Self {
        // Identity: (X=0, Y=1, Z=1, T=0) → ypx = 1, ymx = 1, td = 0
        NielsPoint {
            ypx: Fe25519::one(),
            ymx: Fe25519::one(),
            td: Fe25519::zero(),
        }
    }

    /// Convert an extended point to Niels form.
    fn from_extended(p: &GeExtended) -> Self {
        // For affine points (Z=1): ypx = Y+X, ymx = Y-X, td = 2d·X·Y
        // For projective: we need to normalize first, but our table points are affine.
        let z_inv = p.z.invert();
        let x = p.x.mul(&z_inv);
        let y = p.y.mul(&z_inv);
        let t = x.mul(&y);
        NielsPoint {
            ypx: y.add(&x),
            ymx: y.sub(&x),
            td: t.mul(&D2),
        }
    }

    /// Constant-time conditional assignment: self = src if mask is all-1s.
    fn ct_assign(&mut self, src: &NielsPoint, mask: u64) {
        for j in 0..5 {
            self.ypx.0[j] ^= mask & (self.ypx.0[j] ^ src.ypx.0[j]);
            self.ymx.0[j] ^= mask & (self.ymx.0[j] ^ src.ymx.0[j]);
            self.td.0[j] ^= mask & (self.td.0[j] ^ src.td.0[j]);
        }
    }
}

/// Extended + Niels mixed addition: R = A + B (where B is in Niels form).
///
/// Cost: 7M + 6A (vs 9M + 6A for full extended addition).
fn point_add_niels(a: &GeExtended, b: &NielsPoint) -> GeExtended {
    let aa = a.y.sub(&a.x).mul(&b.ymx); // A = (Y1-X1)·(Y2-X2)
    let bb = a.y.add(&a.x).mul(&b.ypx); // B = (Y1+X1)·(Y2+X2)
    let cc = a.t.mul(&b.td); // C = T1·(2d·T2)
    let dd = a.z.add(&a.z); // D = 2·Z1 (Z2=1 for Niels)

    let e = bb.sub(&aa); // E = B - A
    let f = dd.sub(&cc); // F = D - C
    let g = dd.add(&cc); // G = D + C
    let h = bb.add(&aa); // H = B + A

    GeExtended {
        x: e.mul(&f), // X3 = E·F
        y: g.mul(&h), // Y3 = G·H
        z: f.mul(&g), // Z3 = F·G
        t: e.mul(&h), // T3 = E·H
    }
}

/// Constant-time table lookup: select table[index] for index in 0..16.
fn ct_select_niels(table: &[NielsPoint; 16], index: u8) -> NielsPoint {
    let mut result = NielsPoint::identity();
    for i in 1..16u8 {
        // mask = all-1s if i == index, all-0s otherwise
        let mask = (((i ^ index) as i64).wrapping_sub(1) >> 63) as u64;
        result.ct_assign(&table[i as usize], mask);
    }
    result
}

/// Precomputed base point table for the comb method.
///
/// 64 groups × 16 entries. Group i stores [0·Bi, 1·Bi, ..., 15·Bi]
/// where Bi = 2^(4i) · B. Each entry is in Niels form for fast mixed addition.
///
/// Total computation: sum over 64 groups of table[i][window_i] = scalar·B,
/// requiring only 63 additions and 0 doublings.
fn base_table() -> &'static [[NielsPoint; 16]; 64] {
    static TABLE: OnceLock<Box<[[NielsPoint; 16]; 64]>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = Vec::with_capacity(64);

        // Bi = 2^(4i) · B. Start with B, then double 4 times for each group.
        let mut bi = GeExtended::basepoint();

        for _group in 0..64 {
            // Compute [0·Bi, 1·Bi, 2·Bi, ..., 15·Bi]
            let mut group = Vec::with_capacity(16);
            group.push(NielsPoint::identity()); // 0·Bi

            let mut accum = bi.clone();
            group.push(NielsPoint::from_extended(&accum)); // 1·Bi

            for _j in 2..16 {
                accum = point_add(&accum, &bi);
                group.push(NielsPoint::from_extended(&accum));
            }

            let group_arr: [NielsPoint; 16] = group.try_into().unwrap_or_else(|_| unreachable!());
            table.push(group_arr);

            // Advance Bi: Bi+1 = 2^4 · Bi = 16 · Bi
            bi = point_double(&bi);
            bi = point_double(&bi);
            bi = point_double(&bi);
            bi = point_double(&bi);
        }

        let table_arr: [[NielsPoint; 16]; 64] =
            table.try_into().unwrap_or_else(|_| unreachable!());
        Box::new(table_arr)
    })
}

/// Scalar multiplication: R = scalar * point using double-and-add (MSB to LSB).
///
/// The scalar is a 256-bit little-endian byte array.
pub(crate) fn scalar_mul(scalar: &[u8; 32], point: &GeExtended) -> GeExtended {
    let mut result = GeExtended::identity();

    // Iterate from the most significant bit to the least significant bit
    for i in (0..256).rev() {
        result = point_double(&result);
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if (scalar[byte_idx] >> bit_idx) & 1 == 1 {
            result = point_add(&result, point);
        }
    }

    result
}

/// Scalar multiplication with the base point: R = scalar * B.
///
/// Uses a precomputed comb table (64 groups × 16 Niels points) for
/// fast constant-time base point multiplication: 63 mixed additions,
/// 0 doublings.
pub(crate) fn scalar_mul_base(scalar: &[u8; 32]) -> GeExtended {
    let table = base_table();

    // Decompose scalar into 64 4-bit windows.
    // Window i covers bits [4i..4i+3] of the little-endian scalar.
    let mut result = GeExtended::identity();

    for (group_idx, group_table) in table.iter().enumerate() {
        let bit_offset = group_idx * 4;
        let byte_idx = bit_offset / 8;
        let bit_idx = bit_offset % 8;

        // Extract 4-bit window, handling the byte boundary
        let window = if bit_idx <= 4 {
            (scalar[byte_idx] >> bit_idx) & 0x0F
        } else {
            // Window spans two bytes
            let lo = scalar[byte_idx] >> bit_idx;
            let hi = scalar.get(byte_idx + 1).copied().unwrap_or(0) << (8 - bit_idx);
            (lo | hi) & 0x0F
        };

        let niels = ct_select_niels(group_table, window);
        result = point_add_niels(&result, &niels);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity() {
        let id = GeExtended::identity();
        let encoded = id.to_bytes();
        // Identity point encodes as y=1, x=0 → [1, 0, 0, ..., 0]
        assert_eq!(encoded[0], 1);
        for &b in &encoded[1..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn test_basepoint_encode_decode_roundtrip() {
        let bp = GeExtended::basepoint();
        let encoded = bp.to_bytes();
        let decoded = GeExtended::from_bytes(&encoded).unwrap();
        assert_eq!(bp.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn test_double_equals_add() {
        let bp = GeExtended::basepoint();
        let doubled = point_double(&bp);
        let added = point_add(&bp, &bp);
        assert_eq!(doubled.to_bytes(), added.to_bytes());
    }

    #[test]
    fn test_scalar_mul_one() {
        let bp = GeExtended::basepoint();
        let mut scalar = [0u8; 32];
        scalar[0] = 1; // scalar = 1
        let result = scalar_mul(&scalar, &bp);
        assert_eq!(result.to_bytes(), bp.to_bytes());
    }

    #[test]
    fn test_add_identity_neutral() {
        let bp = GeExtended::basepoint();
        let id = GeExtended::identity();
        // P + O = P
        let result = point_add(&bp, &id);
        assert_eq!(result.to_bytes(), bp.to_bytes());
        // O + P = P
        let result2 = point_add(&id, &bp);
        assert_eq!(result2.to_bytes(), bp.to_bytes());
    }

    #[test]
    fn test_scalar_mul_zero_is_identity() {
        let bp = GeExtended::basepoint();
        let scalar = [0u8; 32];
        let result = scalar_mul(&scalar, &bp);
        let id = GeExtended::identity();
        assert_eq!(result.to_bytes(), id.to_bytes());
    }

    #[test]
    fn test_scalar_mul_three_equals_repeated_add() {
        let bp = GeExtended::basepoint();
        // 3 * B via scalar_mul
        let mut scalar = [0u8; 32];
        scalar[0] = 3;
        let result_scalar = scalar_mul(&scalar, &bp);
        // B + B + B via repeated addition
        let two_b = point_add(&bp, &bp);
        let three_b = point_add(&two_b, &bp);
        assert_eq!(result_scalar.to_bytes(), three_b.to_bytes());
    }

    #[test]
    fn test_from_bytes_invalid_point() {
        // y=1 with x_sign=1: x must be 0 (since u=y²-1=0), but x_sign=1
        // means requesting negative x while x=0 → error
        let mut y1_signed = [0u8; 32];
        y1_signed[0] = 1; // y = 1 (little-endian)
        y1_signed[31] = 0x80; // set x_sign = 1
        assert!(GeExtended::from_bytes(&y1_signed).is_err());

        // Also verify that y=1 without sign bit IS valid (the identity point)
        let mut y1_unsigned = [0u8; 32];
        y1_unsigned[0] = 1;
        assert!(GeExtended::from_bytes(&y1_unsigned).is_ok());
    }

    #[test]
    fn test_point_add_commutative() {
        let bp = GeExtended::basepoint();
        let two_b = point_double(&bp);
        // B + 2B should equal 2B + B
        let r1 = point_add(&bp, &two_b);
        let r2 = point_add(&two_b, &bp);
        assert_eq!(r1.to_bytes(), r2.to_bytes());
    }

    #[test]
    fn test_scalar_mul_two() {
        let bp = GeExtended::basepoint();
        let mut scalar = [0u8; 32];
        scalar[0] = 2;
        let result = scalar_mul(&scalar, &bp);
        let doubled = point_double(&bp);
        assert_eq!(result.to_bytes(), doubled.to_bytes());
    }

    // --- Precomputed base table tests ---

    #[test]
    fn test_scalar_mul_base_one() {
        let mut scalar = [0u8; 32];
        scalar[0] = 1;
        let result = scalar_mul_base(&scalar);
        let bp = GeExtended::basepoint();
        assert_eq!(result.to_bytes(), bp.to_bytes());
    }

    #[test]
    fn test_scalar_mul_base_zero_is_identity() {
        let scalar = [0u8; 32];
        let result = scalar_mul_base(&scalar);
        let id = GeExtended::identity();
        assert_eq!(result.to_bytes(), id.to_bytes());
    }

    #[test]
    fn test_scalar_mul_base_matches_generic() {
        let bp = GeExtended::basepoint();
        // Test several scalar values
        for k in [2u8, 3, 7, 15, 16, 17, 100, 255] {
            let mut scalar = [0u8; 32];
            scalar[0] = k;
            let fast = scalar_mul_base(&scalar);
            let generic = scalar_mul(&scalar, &bp);
            assert_eq!(
                fast.to_bytes(),
                generic.to_bytes(),
                "mismatch for scalar = {k}"
            );
        }
    }

    #[test]
    fn test_scalar_mul_base_large_scalar() {
        // Test with a larger scalar spanning multiple bytes
        let bp = GeExtended::basepoint();
        let mut scalar = [0u8; 32];
        scalar[0] = 0xAB;
        scalar[1] = 0xCD;
        scalar[2] = 0xEF;
        scalar[15] = 0x42;
        scalar[31] = 0x07; // keep below L to avoid wrapping issues
        let fast = scalar_mul_base(&scalar);
        let generic = scalar_mul(&scalar, &bp);
        assert_eq!(fast.to_bytes(), generic.to_bytes());
    }

    #[test]
    fn test_scalar_mul_base_order_is_identity() {
        // Ed25519 group order L (little-endian)
        let l: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let result = scalar_mul_base(&l);
        let id = GeExtended::identity();
        assert_eq!(result.to_bytes(), id.to_bytes());
    }

    #[test]
    fn test_niels_point_add_matches_full_add() {
        let bp = GeExtended::basepoint();
        let bp_niels = NielsPoint::from_extended(&bp);
        let two_b = point_double(&bp);

        // 2B + B via full addition
        let three_b_full = point_add(&two_b, &bp);
        // 2B + B via Niels mixed addition
        let three_b_niels = point_add_niels(&two_b, &bp_niels);
        assert_eq!(three_b_full.to_bytes(), three_b_niels.to_bytes());
    }

    #[test]
    fn test_ct_select_niels_selects_correct_entry() {
        // Build a small table where each entry is i*B
        let bp = GeExtended::basepoint();
        let mut table = [
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
            NielsPoint::identity(),
        ];
        let mut accum = GeExtended::identity();
        for entry in &mut table {
            *entry = NielsPoint::from_extended(&accum);
            accum = point_add(&accum, &bp);
        }

        // Verify ct_select picks the right one
        for i in 0..16u8 {
            let selected = ct_select_niels(&table, i);
            // Verify by adding identity to the selected point
            let result = point_add_niels(&GeExtended::identity(), &selected);
            let expected = point_add_niels(&GeExtended::identity(), &table[i as usize]);
            assert_eq!(
                result.to_bytes(),
                expected.to_bytes(),
                "ct_select mismatch at index {i}"
            );
        }
    }
}
