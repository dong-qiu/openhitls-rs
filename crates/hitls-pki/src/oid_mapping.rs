//! Shared OID-to-algorithm mapping helpers for the PKI crate.

use hitls_types::EccCurveId;
use hitls_utils::oid::{known, Oid};

/// Map an ECC curve OID to its `EccCurveId`.
///
/// Returns `None` for unrecognized OIDs — callers wrap in their own error type.
pub(crate) fn oid_to_curve_id(oid: &Oid) -> Option<EccCurveId> {
    if *oid == known::secp224r1() {
        Some(EccCurveId::NistP224)
    } else if *oid == known::prime256v1() {
        Some(EccCurveId::NistP256)
    } else if *oid == known::secp384r1() {
        Some(EccCurveId::NistP384)
    } else if *oid == known::secp521r1() {
        Some(EccCurveId::NistP521)
    } else if *oid == known::brainpool_p256r1() {
        Some(EccCurveId::BrainpoolP256r1)
    } else if *oid == known::brainpool_p384r1() {
        Some(EccCurveId::BrainpoolP384r1)
    } else if *oid == known::brainpool_p512r1() {
        Some(EccCurveId::BrainpoolP512r1)
    } else {
        None
    }
}
