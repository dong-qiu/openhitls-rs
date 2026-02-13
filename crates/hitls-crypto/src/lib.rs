#![doc = "Cryptographic algorithm library for openHiTLS."]
// Allow dead code and unused variables during the stub/scaffolding phase.
// These will be removed as algorithms are implemented.
#![allow(dead_code, unused_variables, clippy::new_without_default)]

// Core traits
pub mod provider;

// Hash algorithms
#[cfg(feature = "md5")]
pub mod md5;
#[cfg(feature = "sha1")]
pub mod sha1;
#[cfg(feature = "sha2")]
pub mod sha2;
#[cfg(feature = "sha3")]
pub mod sha3;
#[cfg(feature = "sm3")]
pub mod sm3;

pub mod hash;

// Symmetric ciphers
#[cfg(feature = "aes")]
pub mod aes;
#[cfg(feature = "chacha20")]
pub mod chacha20;
#[cfg(feature = "sm4")]
pub mod sm4;

// Modes of operation
#[cfg(feature = "modes")]
pub mod modes;

pub mod cipher {
    //! Unified symmetric cipher interface.
    pub use super::provider::{Aead, BlockCipher};
}

// MAC algorithms
#[cfg(feature = "cmac")]
pub mod cmac;
#[cfg(feature = "gmac")]
pub mod gmac;
#[cfg(feature = "hmac")]
pub mod hmac;
#[cfg(feature = "siphash")]
pub mod siphash;

pub mod mac {
    //! Unified MAC interface.
    pub use super::provider::Mac;
}

// Asymmetric algorithms
#[cfg(any(feature = "ed25519", feature = "x25519"))]
pub(crate) mod curve25519;
#[cfg(feature = "dh")]
pub mod dh;
#[cfg(feature = "dsa")]
pub mod dsa;
#[cfg(feature = "ecc")]
pub mod ecc;
#[cfg(feature = "ecdh")]
pub mod ecdh;
#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(feature = "ed25519")]
pub mod ed25519;
#[cfg(feature = "elgamal")]
pub mod elgamal;
#[cfg(feature = "paillier")]
pub mod paillier;
#[cfg(feature = "rsa")]
pub mod rsa;
#[cfg(feature = "sm2")]
pub mod sm2;
#[cfg(feature = "sm9")]
pub mod sm9;
#[cfg(feature = "x25519")]
pub mod x25519;

// Post-quantum algorithms
#[cfg(feature = "frodokem")]
pub mod frodokem;
#[cfg(feature = "hybridkem")]
pub mod hybridkem;
#[cfg(feature = "mceliece")]
pub mod mceliece;
#[cfg(feature = "mldsa")]
pub mod mldsa;
#[cfg(feature = "mlkem")]
pub mod mlkem;
#[cfg(feature = "slh-dsa")]
pub mod slh_dsa;
#[cfg(feature = "xmss")]
pub mod xmss;

// KDF and DRBG
#[cfg(feature = "drbg")]
pub mod drbg;
#[cfg(feature = "hkdf")]
pub mod hkdf;
#[cfg(feature = "pbkdf2")]
pub mod pbkdf2;
#[cfg(feature = "scrypt")]
pub mod scrypt;

// HPKE
#[cfg(feature = "hpke")]
pub mod hpke;

pub mod kdf {
    //! Unified KDF interface.
    pub use super::provider::Kdf;
}

// FIPS/CMVP compliance
#[cfg(feature = "fips")]
pub mod fips;
