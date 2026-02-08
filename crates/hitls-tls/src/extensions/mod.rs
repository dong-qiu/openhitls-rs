//! TLS extensions (ALPN, SNI, supported_versions, etc.).

/// TLS extension type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionType(pub u16);

impl ExtensionType {
    pub const SERVER_NAME: Self = Self(0);
    pub const MAX_FRAGMENT_LENGTH: Self = Self(1);
    pub const STATUS_REQUEST: Self = Self(5);
    pub const SUPPORTED_GROUPS: Self = Self(10);
    pub const SIGNATURE_ALGORITHMS: Self = Self(13);
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: Self = Self(16);
    pub const SIGNED_CERTIFICATE_TIMESTAMP: Self = Self(18);
    pub const PRE_SHARED_KEY: Self = Self(41);
    pub const EARLY_DATA: Self = Self(42);
    pub const SUPPORTED_VERSIONS: Self = Self(43);
    pub const COOKIE: Self = Self(44);
    pub const PSK_KEY_EXCHANGE_MODES: Self = Self(45);
    pub const CERTIFICATE_AUTHORITIES: Self = Self(47);
    pub const POST_HANDSHAKE_AUTH: Self = Self(49);
    pub const SIGNATURE_ALGORITHMS_CERT: Self = Self(50);
    pub const COMPRESS_CERTIFICATE: Self = Self(27);
    pub const KEY_SHARE: Self = Self(51);
}

/// A raw TLS extension.
#[derive(Debug, Clone)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub data: Vec<u8>,
}
