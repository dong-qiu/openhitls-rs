//! Deterministic Random Bit Generators (NIST SP 800-90A).
//!
//! Provides four DRBG variants:
//! - HMAC-DRBG (Section 10.1.2) — using HMAC-SHA-256
//! - CTR-DRBG (Section 10.2) — using AES-256
//! - SM4-CTR-DRBG (Section 10.2) — using SM4
//! - Hash-DRBG (Section 10.1.1) — using SHA-256/384/512

mod hmac_drbg;
pub use hmac_drbg::HmacDrbg;

pub mod ctr_drbg;
pub use ctr_drbg::CtrDrbg;

#[cfg(feature = "sm4")]
pub mod sm4_ctr_drbg;
#[cfg(feature = "sm4")]
pub use sm4_ctr_drbg::Sm4CtrDrbg;

pub mod hash_drbg;
pub use hash_drbg::HashDrbg;
