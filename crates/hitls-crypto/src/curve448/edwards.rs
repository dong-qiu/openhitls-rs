//! Edwards curve point operations for Ed448 (Goldilocks).
//!
//! Uses extended coordinates (X, Y, Z, T) where T = XY/Z on the
//! Edwards curve: x² + y² = 1 + d·x²·y² with **a = 1** (NOT a = −1 like Ed25519).
//!
//! d = −39081 mod p.

use hitls_types::CryptoError;

use super::field::Fe448;

/// d = −39081 mod p = p − 39081.
/// p = 2^448 − 2^224 − 1. So d = 2^448 − 2^224 − 39082.
/// Computed as Fe448::zero().sub(&Fe448::from_small(39081)).
fn d_const() -> Fe448 {
    let mut bytes = [0u8; 56];
    bytes[0] = 39081u16 as u8; // 0x98B9 & 0xFF = 0xB9
    bytes[1] = (39081u16 >> 8) as u8; // 0x98
    let pos = Fe448::from_bytes(&bytes);
    Fe448::zero().sub(&pos) // -39081 mod p
}

/// 2*d mod p.
fn d2_const() -> Fe448 {
    let d = d_const();
    d.add(&d)
}

/// Base point Y coordinate for Ed448 (from RFC 8032 §5.2.5).
/// y = 298819210078481492676017930443930673437544040154080242095928241
///     372331506189835876003536878655418784733982303233503462500531545
///     062832660
/// Little-endian encoding (56 bytes).
fn base_y() -> Fe448 {
    let bytes: [u8; 56] = [
        0x14, 0xFA, 0x30, 0xF2, 0x5B, 0x79, 0x08, 0x98, 0xAD, 0xC8, 0xD7, 0x4E, 0x2C, 0x13, 0xBD,
        0xFD, 0xC4, 0x39, 0x7C, 0xE6, 0x1C, 0xFF, 0xD3, 0x3A, 0xD7, 0xC2, 0xA0, 0x05, 0x1E, 0x9C,
        0x78, 0x87, 0x40, 0x98, 0xA3, 0x6C, 0x73, 0x73, 0xEA, 0x4B, 0x62, 0xC7, 0xC9, 0x56, 0x37,
        0x20, 0x76, 0x88, 0x24, 0xBC, 0xB6, 0x6E, 0x71, 0x46, 0x3F, 0x69,
    ];
    Fe448::from_bytes(&bytes)
}

/// Base point X coordinate for Ed448 (from RFC 8032 §5.2.5).
/// Computed as the positive (even) square root of (y²−1)/(d·y²−1).
/// Little-endian encoding (56 bytes).
fn base_x() -> Fe448 {
    let bytes: [u8; 56] = [
        0x5E, 0xC0, 0x0C, 0xC7, 0x2B, 0xA8, 0x26, 0x26, 0x8E, 0x93, 0x00, 0x8B, 0xE1, 0x80, 0x3B,
        0x43, 0x11, 0x65, 0xB6, 0x2A, 0xF7, 0x1A, 0xAE, 0x12, 0x64, 0xA4, 0xD3, 0xA3, 0x24, 0xE3,
        0x6D, 0xEA, 0x67, 0x17, 0x0F, 0x47, 0x70, 0x65, 0x14, 0x9E, 0xDA, 0x36, 0xBF, 0x22, 0xA6,
        0x15, 0x1D, 0x22, 0xED, 0x0D, 0xED, 0x6B, 0xC6, 0x70, 0x19, 0x4F,
    ];
    Fe448::from_bytes(&bytes)
}

/// Group order L for Ed448.
/// L = 2^446 − 13818066809895115352007386748515426880336692474882178609894547503885
/// In hex (big-endian):
/// 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
/// 7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3
pub(crate) const L_BYTES_LE: [u8; 57] = [
    0xF3, 0x44, 0x58, 0xAB, 0x92, 0xC2, 0x78, 0x23, // bytes 0-7
    0x55, 0x8F, 0xC5, 0x8D, 0x72, 0xC2, 0x6C, 0x21, // bytes 8-15
    0x90, 0x36, 0xD6, 0xAE, 0x49, 0xDB, 0x4E, 0xC4, // bytes 16-23
    0xE9, 0x23, 0xCA, 0x7C, 0xFF, 0xFF, 0xFF, 0xFF, // bytes 24-31
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // bytes 32-39
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // bytes 40-47
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F, // bytes 48-55
    0x00, // byte 56
];

/// A point on the Edwards curve in extended coordinates.
/// Represents the affine point (X/Z, Y/Z) with T = XY/Z.
#[derive(Clone)]
pub(crate) struct GeExtended448 {
    pub x: Fe448,
    pub y: Fe448,
    pub z: Fe448,
    pub t: Fe448,
}

impl GeExtended448 {
    /// The identity point (neutral element): (0, 1, 1, 0).
    pub fn identity() -> Self {
        GeExtended448 {
            x: Fe448::zero(),
            y: Fe448::one(),
            z: Fe448::one(),
            t: Fe448::zero(),
        }
    }

    /// The base point B for Ed448 (RFC 8032 §5.2.5).
    pub fn basepoint() -> Self {
        let x = base_x();
        let y = base_y();
        GeExtended448 {
            t: x.mul(&y),
            x,
            y,
            z: Fe448::one(),
        }
    }

    /// Encode a point to 57 bytes: y (56 bytes LE) with sign of x in top bit of byte[56].
    pub fn to_bytes(&self) -> [u8; 57] {
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);

        let mut out = [0u8; 57];
        let y_bytes = y.to_bytes();
        out[..56].copy_from_slice(&y_bytes);
        out[56] = x.is_negative() << 7;
        out
    }

    /// Decode a point from 57 bytes.
    ///
    /// Recovers the x-coordinate from y using the curve equation.
    /// Curve: x² + y² = 1 + d·x²·y²
    /// => x² = (y² − 1) / (d·y² − 1)
    pub fn from_bytes(bytes: &[u8; 57]) -> Result<Self, CryptoError> {
        // Extract the sign bit from byte[56]
        let x_sign = bytes[56] >> 7;

        let mut y_bytes = [0u8; 56];
        y_bytes.copy_from_slice(&bytes[..56]);

        let y = Fe448::from_bytes(&y_bytes);
        let d = d_const();

        // x² = (y² − 1) / (d·y² − 1)
        let y2 = y.square();
        let u = y2.sub(&Fe448::one()); // u = y² − 1
        let v = y2.mul(&d).sub(&Fe448::one()); // v = d·y² − 1

        // x = sqrt(u/v) = sqrt(u) * sqrt(v^(-1))
        // Since p ≡ 3 (mod 4), we can use: x = (u/v)^((p+1)/4)
        // = u * v^(-1) raised to (p+1)/4
        // Or better: u * (u*v)^((p-3)/4) * v ... but simplest is u * v^(-1) then sqrt.
        //
        // Actually: u/v has a square root iff (u/v)^((p-1)/2) = 1.
        // sqrt(u/v) = (u*v^3)^((p-3)/4) * u * v ... no, let's just do:
        //
        // Since p ≡ 3 (mod 4):
        //   sqrt(w) = w^((p+1)/4)
        // So: x = (u * v^(-1))^((p+1)/4)
        //       = (u * v^(p-2))^((p+1)/4)
        // But this requires two exponentiations. Better:
        //   x = u^((p+1)/4) * v^(-(p+1)/4)
        //     = u^((p+1)/4) * v^((p - (p+1)/4)) ... this gets messy.
        //
        // Standard approach for Ed448 decompression (RFC 8032 §5.2.5):
        //   u/v method:
        //   1. Compute w = u * v^3 * (u * v^7)^((p-3)/4)
        //      But (p-3)/4 = (2^448 - 2^224 - 4)/4 = 2^446 - 2^222 - 1
        //      This is complex. Simpler:
        //
        //   Since p ≡ 3 (mod 4):
        //     sqrt(a) = a^((p+1)/4)
        //
        //   x = sqrt(u * v^(-1)) = sqrt(u * v^(p-2))
        //   Or: compute v_inv, then sqrt(u * v_inv).
        let v_inv = v.invert();
        let uv_inv = u.mul(&v_inv);

        let x = uv_inv.sqrt();

        // Verify: x² * v == u
        let check = x.square().mul(&v);
        if check != u {
            return Err(CryptoError::EccPointNotOnCurve);
        }

        // Adjust sign
        let mut x_final = x;
        if x_final.is_negative() != x_sign {
            x_final = x_final.neg();
        }

        // x == 0 and x_sign == 1 is invalid
        if x_final.is_zero() && x_sign == 1 {
            return Err(CryptoError::EccPointNotOnCurve);
        }

        let t = x_final.mul(&y);
        Ok(GeExtended448 {
            x: x_final,
            y,
            z: Fe448::one(),
            t,
        })
    }
}

/// Extended point addition: R = A + B.
///
/// Generic addition formula for Edwards curves with **a = 1**.
///
/// IMPORTANT: The HWCD `(Y−X)(Y'−X')` trick only works for a=−1.
/// For a=1, we compute X1·X2 and Y1·Y2 separately so that
/// H = Y1Y2 − X1X2 (not Y1Y2 + X1X2 as in Ed25519).
pub(crate) fn point_add(a: &GeExtended448, b: &GeExtended448) -> GeExtended448 {
    let d = d_const();

    let p1 = a.x.mul(&b.x); // X1·X2
    let p2 = a.y.mul(&b.y); // Y1·Y2
    let cc = d.mul(&a.t).mul(&b.t); // C = d·T1·T2
    let dd = a.z.mul(&b.z); // D = Z1·Z2

    // E = (X1+Y1)·(X2+Y2) − X1X2 − Y1Y2 = X1Y2 + X2Y1
    let e = a.x.add(&a.y).mul(&b.x.add(&b.y)).sub(&p1).sub(&p2);
    let f = dd.sub(&cc); // F = D − C
    let g = dd.add(&cc); // G = D + C
    let h = p2.sub(&p1); // H = Y1Y2 − X1X2 (a=1: H = B − a·A = B − A)

    GeExtended448 {
        x: e.mul(&f), // X3 = E·F
        y: g.mul(&h), // Y3 = G·H
        z: f.mul(&g), // Z3 = F·G
        t: e.mul(&h), // T3 = E·H
    }
}

/// Extended point doubling: R = 2A.
///
/// Uses the doubling formula for Edwards curves with **a = 1**.
/// CRITICAL: D = A (since a = 1), NOT D = −A (which is Ed25519's a = −1).
pub(crate) fn point_double(a: &GeExtended448) -> GeExtended448 {
    let aa = a.x.square(); // A = X1²
    let bb = a.y.square(); // B = Y1²
    let z2 = a.z.square();
    let cc = z2.add(&z2); // C = 2·Z1²
    let d_val = aa; // D = a·A = A (since a = 1)
    let xy = a.x.add(&a.y);
    let e = xy.square().sub(&aa).sub(&bb); // E = (X1+Y1)² − A − B
    let g = d_val.add(&bb); // G = D + B = A + B
    let f = g.sub(&cc); // F = G − C
    let h = d_val.sub(&bb); // H = D − B = A − B

    GeExtended448 {
        x: e.mul(&f), // X3 = E·F
        y: g.mul(&h), // Y3 = G·H
        z: f.mul(&g), // Z3 = F·G
        t: e.mul(&h), // T3 = E·H
    }
}

/// Scalar multiplication: R = scalar * point using double-and-add (MSB to LSB).
///
/// The scalar is a 57-byte little-endian byte array (446 effective bits).
pub(crate) fn scalar_mul(scalar: &[u8], point: &GeExtended448) -> GeExtended448 {
    let mut result = GeExtended448::identity();
    let num_bits = scalar.len() * 8;

    // Iterate from the most significant bit to the least significant bit
    for i in (0..num_bits).rev() {
        result = point_double(&result);
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if byte_idx < scalar.len() && (scalar[byte_idx] >> bit_idx) & 1 == 1 {
            result = point_add(&result, point);
        }
    }

    result
}

/// Scalar multiplication with the base point: R = scalar * B.
pub(crate) fn scalar_mul_base(scalar: &[u8]) -> GeExtended448 {
    let base = GeExtended448::basepoint();
    scalar_mul(scalar, &base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity() {
        let id = GeExtended448::identity();
        let encoded = id.to_bytes();
        // Identity point encodes as y=1, x=0 → [1, 0, ..., 0, 0] (57 bytes)
        assert_eq!(encoded[0], 1);
        for &b in &encoded[1..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn test_basepoint_encode_decode_roundtrip() {
        let bp = GeExtended448::basepoint();
        let encoded = bp.to_bytes();
        let decoded = GeExtended448::from_bytes(&encoded).unwrap();
        assert_eq!(bp.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn test_double_equals_add() {
        let bp = GeExtended448::basepoint();
        let doubled = point_double(&bp);
        let added = point_add(&bp, &bp);
        assert_eq!(doubled.to_bytes(), added.to_bytes());
    }

    #[test]
    fn test_scalar_mul_one() {
        let bp = GeExtended448::basepoint();
        let scalar = [1u8]; // scalar = 1
        let result = scalar_mul(&scalar, &bp);
        assert_eq!(result.to_bytes(), bp.to_bytes());
    }

    #[test]
    fn test_scalar_mul_two() {
        let bp = GeExtended448::basepoint();
        let scalar = [2u8]; // scalar = 2
        let result = scalar_mul(&scalar, &bp);
        let doubled = point_double(&bp);
        assert_eq!(result.to_bytes(), doubled.to_bytes());
    }

    #[test]
    fn test_order() {
        // L * B should equal the identity
        let result = scalar_mul_base(&L_BYTES_LE);
        let id = GeExtended448::identity();
        assert_eq!(result.to_bytes(), id.to_bytes());
    }
}
