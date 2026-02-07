//! Edwards curve point operations for Ed25519.
//!
//! Uses extended coordinates (X, Y, Z, T) where T = XY/Z on the twisted
//! Edwards curve: -x² + y² = 1 + d·x²·y² with d = -121665/121666.

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
pub(crate) fn scalar_mul_base(scalar: &[u8; 32]) -> GeExtended {
    let base = GeExtended::basepoint();
    scalar_mul(scalar, &base)
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
    fn test_scalar_mul_two() {
        let bp = GeExtended::basepoint();
        let mut scalar = [0u8; 32];
        scalar[0] = 2;
        let result = scalar_mul(&scalar, &bp);
        let doubled = point_double(&bp);
        assert_eq!(result.to_bytes(), doubled.to_bytes());
    }
}
