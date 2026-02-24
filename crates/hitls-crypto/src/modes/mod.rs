//! Block cipher modes of operation.
//!
//! This module provides implementations of standard block cipher modes
//! including CBC, CTR, ECB, GCM, CCM, HCTR, XTS, CFB, OFB, and key wrap.
//! Each mode operates on top of a block cipher (e.g., AES, SM4) through
//! the [`BlockCipher`](crate::provider::BlockCipher) trait.

pub mod cbc;
pub mod ccm;
pub mod cfb;
pub mod ctr;
pub mod ecb;
pub mod gcm;
#[cfg(target_arch = "aarch64")]
mod ghash_arm;
#[cfg(target_arch = "x86_64")]
mod ghash_x86;
pub mod hctr;
pub mod ofb;
pub mod wrap;
pub mod xts;
