//! TLS cryptographic operations wrapper.
//!
//! Bridges the TLS protocol with the underlying `hitls-crypto` primitives.

/// TLS named group identifiers (for key exchange).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedGroup(pub u16);

impl NamedGroup {
    // Elliptic curves
    pub const SECP256R1: Self = Self(0x0017);
    pub const SECP384R1: Self = Self(0x0018);
    pub const SECP521R1: Self = Self(0x0019);
    pub const X25519: Self = Self(0x001D);
    pub const X448: Self = Self(0x001E);
    // Finite field DH
    pub const FFDHE2048: Self = Self(0x0100);
    pub const FFDHE3072: Self = Self(0x0101);
    pub const FFDHE4096: Self = Self(0x0102);
    // Post-quantum (draft)
    pub const X25519_MLKEM768: Self = Self(0x6399);
}

/// TLS signature scheme identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureScheme(pub u16);

impl SignatureScheme {
    pub const RSA_PKCS1_SHA256: Self = Self(0x0401);
    pub const RSA_PKCS1_SHA384: Self = Self(0x0501);
    pub const RSA_PKCS1_SHA512: Self = Self(0x0601);
    pub const ECDSA_SECP256R1_SHA256: Self = Self(0x0403);
    pub const ECDSA_SECP384R1_SHA384: Self = Self(0x0503);
    pub const ECDSA_SECP521R1_SHA512: Self = Self(0x0603);
    pub const RSA_PSS_RSAE_SHA256: Self = Self(0x0804);
    pub const RSA_PSS_RSAE_SHA384: Self = Self(0x0805);
    pub const RSA_PSS_RSAE_SHA512: Self = Self(0x0806);
    pub const ED25519: Self = Self(0x0807);
    pub const SM2_SM3: Self = Self(0x0708);
}
