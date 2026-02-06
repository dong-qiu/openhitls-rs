#![forbid(unsafe_code)]
#![doc = "Authentication protocols for openHiTLS."]

#[cfg(feature = "otp")]
pub mod otp;

#[cfg(feature = "spake2plus")]
pub mod spake2plus;

#[cfg(feature = "privpass")]
pub mod privpass;
