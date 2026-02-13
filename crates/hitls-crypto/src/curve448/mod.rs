//! Curve448 (Goldilocks) primitives shared between Ed448 and X448.
//!
//! Provides field arithmetic over GF(2^448 − 2^224 − 1) and Edwards curve point
//! operations for the untwisted Edwards curve used by Ed448 (a = 1).

pub(crate) mod edwards;
pub(crate) mod field;
