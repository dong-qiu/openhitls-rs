//! Deterministic Random Bit Generators (NIST SP 800-90A).
//!
//! Provides three DRBG variants:
//! - HMAC-DRBG (Section 10.1.2) — using HMAC-SHA-256
//! - CTR-DRBG (Section 10.2) — using AES-256
//! - Hash-DRBG (Section 10.1.1) — using SHA-256/384/512

mod hmac_drbg;
pub use hmac_drbg::HmacDrbg;

pub mod ctr_drbg;
pub use ctr_drbg::CtrDrbg;

pub mod hash_drbg;
pub use hash_drbg::HashDrbg;
