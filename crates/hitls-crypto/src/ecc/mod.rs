//! Elliptic Curve Cryptography (ECC) core primitives.
//!
//! Provides fundamental elliptic curve types including points, groups (curves),
//! and scalar arithmetic. This module underpins higher-level protocols such as
//! ECDSA, ECDH, and SM2. Supported curves include NIST P-256, P-384, P-521,
//! brainpool curves, and SM2.

use hitls_types::CryptoError;

/// An elliptic curve group (i.e., the curve and its parameters).
#[derive(Debug, Clone)]
pub struct EcGroup {
    /// Identifier for the named curve.
    curve_id: u32,
}

impl EcGroup {
    /// Create an `EcGroup` for a named curve by its identifier.
    pub fn new(curve_id: u32) -> Result<Self, CryptoError> {
        todo!("EcGroup construction not yet implemented")
    }

    /// Return the size of the field in bytes.
    pub fn field_size(&self) -> usize {
        todo!("EcGroup field_size not yet implemented")
    }

    /// Return the order of the generator point in bytes.
    pub fn order_size(&self) -> usize {
        todo!("EcGroup order_size not yet implemented")
    }
}

/// A point on an elliptic curve.
#[derive(Debug, Clone)]
pub struct EcPoint {
    /// The affine x-coordinate.
    x: Vec<u8>,
    /// The affine y-coordinate.
    y: Vec<u8>,
}

impl EcPoint {
    /// Create a new point from affine coordinates.
    pub fn new(x: &[u8], y: &[u8]) -> Result<Self, CryptoError> {
        todo!("EcPoint construction not yet implemented")
    }

    /// Create the point at infinity (identity element).
    pub fn infinity() -> Self {
        todo!("EcPoint infinity not yet implemented")
    }

    /// Check whether this point lies on the given curve.
    pub fn is_on_curve(&self, group: &EcGroup) -> Result<bool, CryptoError> {
        todo!("EcPoint on-curve check not yet implemented")
    }

    /// Encode the point in uncompressed form (0x04 || x || y).
    pub fn to_uncompressed(&self, group: &EcGroup) -> Result<Vec<u8>, CryptoError> {
        todo!("EcPoint encoding not yet implemented")
    }

    /// Decode a point from its uncompressed representation.
    pub fn from_uncompressed(group: &EcGroup, data: &[u8]) -> Result<Self, CryptoError> {
        todo!("EcPoint decoding not yet implemented")
    }
}
