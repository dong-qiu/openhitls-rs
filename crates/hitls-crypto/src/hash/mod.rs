//! Unified hash module.
//!
//! This module re-exports all supported hash algorithm implementations and
//! provides a common entry point for digest computation. Individual hash
//! algorithms (MD5, SHA-1, SHA-2, SHA-3, SM3) live in their own feature-gated
//! sub-crates and are re-exported here for convenience.

pub use crate::provider::{Digest, HashAlgorithm};

#[cfg(feature = "md5")]
pub use crate::md5::Md5;

#[cfg(feature = "sha1")]
pub use crate::sha1::Sha1;

#[cfg(feature = "sha2")]
pub use crate::sha2::{Sha224, Sha256, Sha384, Sha512};

#[cfg(feature = "sha3")]
pub use crate::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};

#[cfg(feature = "sm3")]
pub use crate::sm3::Sm3;
