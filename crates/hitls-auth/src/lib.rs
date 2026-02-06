#![forbid(unsafe_code)]
#![doc = "Authentication protocols for openHiTLS."]
// Allow dead code during the stub/scaffolding phase.
#![allow(dead_code)]

#[cfg(feature = "otp")]
pub mod otp;

#[cfg(feature = "spake2plus")]
pub mod spake2plus;

#[cfg(feature = "privpass")]
pub mod privpass;
