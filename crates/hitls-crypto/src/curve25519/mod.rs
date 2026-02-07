//! Curve25519 primitives shared between Ed25519 and X25519.
//!
//! Provides field arithmetic over GF(2^255 - 19) and Edwards curve point
//! operations for the twisted Edwards curve used by Ed25519.

pub(crate) mod edwards;
pub(crate) mod field;
