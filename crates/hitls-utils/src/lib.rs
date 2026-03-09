#![forbid(unsafe_code)]
#![doc = "Utility functions for openHiTLS: ASN.1, Base64, PEM, OID."]
#![warn(missing_docs)]

/// Hex encoding and decoding utilities.
pub mod hex;

#[cfg(feature = "asn1")]
/// ASN.1 DER/BER encoding and decoding.
pub mod asn1;

#[cfg(feature = "base64")]
/// Base64 encoding and decoding.
pub mod base64;

#[cfg(feature = "pem")]
/// PEM encoding and decoding.
pub mod pem;

#[cfg(feature = "oid")]
/// OID (Object Identifier) management.
pub mod oid;
