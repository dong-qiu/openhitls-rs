//! TLS extensions (ALPN, SNI, supported_versions, etc.).

use std::sync::Arc;

/// TLS extension type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionType(pub u16);

impl ExtensionType {
    pub const SERVER_NAME: Self = Self(0);
    pub const MAX_FRAGMENT_LENGTH: Self = Self(1);
    pub const TRUSTED_CA_KEYS: Self = Self(3);
    pub const STATUS_REQUEST: Self = Self(5);
    pub const SUPPORTED_GROUPS: Self = Self(10);
    pub const SIGNATURE_ALGORITHMS: Self = Self(13);
    pub const USE_SRTP: Self = Self(14);
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: Self = Self(16);
    pub const STATUS_REQUEST_V2: Self = Self(17);
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
    pub const EC_POINT_FORMATS: Self = Self(11);
    pub const PADDING: Self = Self(21);
    pub const ENCRYPT_THEN_MAC: Self = Self(22);
    pub const EXTENDED_MASTER_SECRET: Self = Self(23);
    pub const SESSION_TICKET: Self = Self(35);
    pub const RECORD_SIZE_LIMIT: Self = Self(28);
    pub const OID_FILTERS: Self = Self(48);
    pub const HEARTBEAT: Self = Self(15);
    pub const RENEGOTIATION_INFO: Self = Self(0xFF01);
}

/// A raw TLS extension.
#[derive(Debug, Clone)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub data: Vec<u8>,
}

/// Context flags indicating where a custom extension is sent/received.
///
/// A custom extension is active in all message types whose bits are set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionContext(pub u32);

impl ExtensionContext {
    pub const CLIENT_HELLO: Self = Self(0x0001);
    pub const SERVER_HELLO: Self = Self(0x0002);
    pub const ENCRYPTED_EXTENSIONS: Self = Self(0x0010);
    pub const CERTIFICATE: Self = Self(0x0020);
    pub const CERTIFICATE_REQUEST: Self = Self(0x0040);
    pub const NEW_SESSION_TICKET: Self = Self(0x0080);

    /// Returns true if `other` context is included in this context.
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Callback to build custom extension data.
///
/// Called when constructing the relevant handshake message.
/// Return `Some(data)` to include the extension, or `None` to skip it.
pub type CustomExtAddCallback = Arc<dyn Fn(ExtensionContext) -> Option<Vec<u8>> + Send + Sync>;

/// Callback to parse received custom extension data.
///
/// Called when a matching extension_type is found in a received message.
/// Return `Ok(())` on success, or `Err(alert_code)` to abort with an alert.
pub type CustomExtParseCallback =
    Arc<dyn Fn(ExtensionContext, &[u8]) -> Result<(), u8> + Send + Sync>;

/// Registration for a single custom TLS extension.
pub struct CustomExtension {
    /// Extension type code (must not collide with standard extensions).
    pub extension_type: u16,
    /// Bitmask of message contexts where this extension is active.
    pub context: ExtensionContext,
    /// Callback to generate extension data for outgoing messages.
    pub add_cb: CustomExtAddCallback,
    /// Callback to parse extension data from incoming messages.
    pub parse_cb: CustomExtParseCallback,
}

impl std::fmt::Debug for CustomExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomExtension")
            .field("extension_type", &self.extension_type)
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

impl Clone for CustomExtension {
    fn clone(&self) -> Self {
        Self {
            extension_type: self.extension_type,
            context: self.context,
            add_cb: self.add_cb.clone(),
            parse_cb: self.parse_cb.clone(),
        }
    }
}

/// Build custom extensions for the given message context.
///
/// Returns a list of `Extension` values to append to the message.
pub fn build_custom_extensions(
    custom_exts: &[CustomExtension],
    ctx: ExtensionContext,
) -> Vec<Extension> {
    let mut result = Vec::new();
    for ext in custom_exts {
        if ext.context.contains(ctx) {
            if let Some(data) = (ext.add_cb)(ctx) {
                result.push(Extension {
                    extension_type: ExtensionType(ext.extension_type),
                    data,
                });
            }
        }
    }
    result
}

/// Parse custom extensions from received extensions list.
///
/// For each extension in `received` that matches a registered custom extension
/// in the given context, calls the parse callback.
///
/// Returns `Ok(())` on success, or `Err(TlsError)` with the alert code on failure.
pub fn parse_custom_extensions(
    custom_exts: &[CustomExtension],
    ctx: ExtensionContext,
    received: &[Extension],
) -> Result<(), hitls_types::TlsError> {
    for ext in received {
        for custom in custom_exts {
            if custom.extension_type == ext.extension_type.0 && custom.context.contains(ctx) {
                (custom.parse_cb)(ctx, &ext.data).map_err(|alert| {
                    hitls_types::TlsError::AlertReceived(format!(
                        "custom extension 0x{:04X} parse failed (alert {})",
                        custom.extension_type, alert
                    ))
                })?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_extension_context_contains() {
        let ctx = ExtensionContext(0x0003); // CH | SH
        assert!(ctx.contains(ExtensionContext::CLIENT_HELLO));
        assert!(ctx.contains(ExtensionContext::SERVER_HELLO));
        assert!(!ctx.contains(ExtensionContext::ENCRYPTED_EXTENSIONS));
    }

    #[test]
    fn test_build_custom_extensions_add() {
        let ext = CustomExtension {
            extension_type: 0xFF00,
            context: ExtensionContext::CLIENT_HELLO,
            add_cb: Arc::new(|_ctx| Some(vec![0x01, 0x02])),
            parse_cb: Arc::new(|_ctx, _data| Ok(())),
        };
        let result = build_custom_extensions(&[ext], ExtensionContext::CLIENT_HELLO);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].extension_type, ExtensionType(0xFF00));
        assert_eq!(result[0].data, vec![0x01, 0x02]);
    }

    #[test]
    fn test_build_custom_extensions_skip_wrong_context() {
        let ext = CustomExtension {
            extension_type: 0xFF00,
            context: ExtensionContext::CLIENT_HELLO,
            add_cb: Arc::new(|_ctx| Some(vec![0x01])),
            parse_cb: Arc::new(|_ctx, _data| Ok(())),
        };
        let result = build_custom_extensions(&[ext], ExtensionContext::SERVER_HELLO);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_custom_extensions_skip_none() {
        let ext = CustomExtension {
            extension_type: 0xFF00,
            context: ExtensionContext::CLIENT_HELLO,
            add_cb: Arc::new(|_ctx| None),
            parse_cb: Arc::new(|_ctx, _data| Ok(())),
        };
        let result = build_custom_extensions(&[ext], ExtensionContext::CLIENT_HELLO);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_multiple_custom_extensions() {
        let ext1 = CustomExtension {
            extension_type: 0xFF00,
            context: ExtensionContext(0x0003), // CH | SH
            add_cb: Arc::new(|_ctx| Some(vec![0x01])),
            parse_cb: Arc::new(|_ctx, _data| Ok(())),
        };
        let ext2 = CustomExtension {
            extension_type: 0xFF01,
            context: ExtensionContext::CLIENT_HELLO,
            add_cb: Arc::new(|_ctx| Some(vec![0x02])),
            parse_cb: Arc::new(|_ctx, _data| Ok(())),
        };
        let result = build_custom_extensions(&[ext1, ext2], ExtensionContext::CLIENT_HELLO);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_custom_extensions_ok() {
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = call_count.clone();
        let ext = CustomExtension {
            extension_type: 0xFF00,
            context: ExtensionContext::SERVER_HELLO,
            add_cb: Arc::new(|_ctx| None),
            parse_cb: Arc::new(move |_ctx, data| {
                assert_eq!(data, &[0xAB, 0xCD]);
                cc.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        };
        let received = vec![Extension {
            extension_type: ExtensionType(0xFF00),
            data: vec![0xAB, 0xCD],
        }];
        parse_custom_extensions(&[ext], ExtensionContext::SERVER_HELLO, &received).unwrap();
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_parse_custom_extensions_alert() {
        let ext = CustomExtension {
            extension_type: 0xFF00,
            context: ExtensionContext::SERVER_HELLO,
            add_cb: Arc::new(|_ctx| None),
            parse_cb: Arc::new(|_ctx, _data| Err(47)), // illegal_parameter
        };
        let received = vec![Extension {
            extension_type: ExtensionType(0xFF00),
            data: vec![],
        }];
        let err =
            parse_custom_extensions(&[ext], ExtensionContext::SERVER_HELLO, &received).unwrap_err();
        match err {
            hitls_types::TlsError::AlertReceived(msg) => {
                assert!(msg.contains("alert 47"));
            }
            _ => panic!("expected AlertReceived"),
        }
    }

    #[test]
    fn test_parse_ignores_unregistered_extensions() {
        let received = vec![Extension {
            extension_type: ExtensionType(0xFF99),
            data: vec![0x01],
        }];
        // No custom extensions registered → should succeed
        parse_custom_extensions(&[], ExtensionContext::CLIENT_HELLO, &received).unwrap();
    }

    #[test]
    fn test_custom_extension_clone() {
        let ext = CustomExtension {
            extension_type: 0xFF00,
            context: ExtensionContext::CLIENT_HELLO,
            add_cb: Arc::new(|_ctx| Some(vec![0x01])),
            parse_cb: Arc::new(|_ctx, _data| Ok(())),
        };
        let cloned = ext.clone();
        assert_eq!(cloned.extension_type, 0xFF00);
    }
}
