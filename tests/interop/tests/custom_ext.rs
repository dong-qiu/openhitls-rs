//! TLS custom (vendor-defined) extension negotiation tests — T185 (#58).
//!
//! Migrated from `openhitls/testcode/sdv/testcase/tls/custom/`
//! `test_suite_sdv_custom_extensions.{c,data}` (11 base TCs: 7 API + 4 FUNCTION).
//!
//! The issue claims "33 TCs"; the actual C source has 11 base TCs. The `.data`
//! file lists one entry per TC (some TCs use macro-generated row expansions
//! that inflate the apparent count). We migrate the 11 base TCs.
//!
//! ## Coverage map (C TC → Rust test)
//!
//! | C TC | Rust test | Notes |
//! |------|-----------|-------|
//! | `SDV_TLS_PACK_CUSTOM_EXTENSIONS_API_TC001` | `api_pack_single_no_callback_returns_empty` | No add_cb → not packed |
//! | `SDV_TLS_PARSE_CUSTOM_EXTENSIONS_API_TC001` | `api_parse_single_no_callback_returns_ok` | No parse_cb → silent skip |
//! | `SDV_TLS_PACK_CUSTOM_EXTENSIONS_MULTIPLE_API_TC001` | `api_pack_multiple_no_callbacks_returns_empty` | Two exts, neither has add_cb |
//! | `SDV_TLS_PACK_CUSTOM_EXTENSIONS_EMPTY_API_TC001` | `api_pack_no_extensions_returns_empty` | No exts registered |
//! | `SDV_TLS_PACK_CUSTOM_EXTENSIONS_CALLBACK_API_TC001` | `api_pack_with_callback_emits_extension` | add_cb returns `Some(vec![0xAA])` → ext present |
//! | `SDV_TLS_PARSE_CUSTOM_EXTENSIONS_CALLBACK_API_TC001` | `api_parse_with_callback_invokes_cb` | parse_cb runs on matching ext |
//! | `SDV_HITLS_ADD_CUSTOM_EXTENSION_API_TC001` | `api_add_custom_extension_*` (3 tests) | Add / duplicate-pin (gap) / context-filter |
//! | `SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC001` | `function_basic_handshake_round_trip` | Simplified: only CH/SH/EE contexts wired in Rust today; CERT/CERT_REQ/NST contexts not supported (see `TODO(#58-context-gap)`) |
//! | `SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC002` | `function_alert_on_parse_failure` | parse_cb returns `Err` → handshake aborts |
//! | `SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC003` | `function_empty_extension_capability` | `Some(vec![])` → empty data on the wire |
//! | `SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC004` | `function_pass_extension_capability` | `None` → not sent (PASS semantics) |
//!
//! ## Rust API mapping
//!
//! C's `HITLS_CFG_AddCustomExtension` takes `(extType, context, addCb, freeCb,
//! addArg, parseCb, parseArg)`. Rust folds this into `CustomExtension`:
//! - `extension_type: u16` — wire-level type code
//! - `context: ExtensionContext` — bitmask of message contexts
//! - `add_cb: Arc<Fn(ExtensionContext) -> Option<Vec<u8>>>` — `None` = PASS,
//!   `Some(data)` = PACK
//! - `parse_cb: Arc<Fn(ExtensionContext, &[u8]) -> Result<(), u8>>` —
//!   `Err(alert_code)` aborts with that alert
//!
//! C's `freeCb` is absorbed by Rust's `Vec<u8>` `Drop`. C's `addArg` /
//! `parseArg` are folded into the closure capture.
//!
//! ## Documented gaps (RFC 8446 §4.2 + C behaviour)
//!
//! - `TODO(#58-dup-check)`: Rust `TlsConfig::custom_extension` accepts
//!   duplicate `extension_type` registrations without rejecting; C returns
//!   `HITLS_CONFIG_DUP_CUSTOM_EXT`. Pinned by
//!   `api_add_custom_extension_duplicate_not_rejected`.
//! - `TODO(#58-context-gap)`: Rust today wires custom extensions only at
//!   ClientHello / ServerHello / EncryptedExtensions; CERTIFICATE /
//!   CERTIFICATE_REQUEST / NEW_SESSION_TICKET contexts are accepted by the
//!   config API but never invoked during handshake. C wires all six.

use hitls_integration_tests::make_ed25519_server_identity;
use hitls_tls::config::TlsConfig;
use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
use hitls_tls::extensions::{
    build_custom_extensions, parse_custom_extensions, CustomExtAddCallback, CustomExtParseCallback,
    CustomExtension, Extension, ExtensionContext, ExtensionType,
};
use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const CUSTOM_EXT_TYPE_1: u16 = 0xFA00;
const CUSTOM_EXT_TYPE_2: u16 = 0xFA01;
const ALERT_ILLEGAL_PARAMETER: u8 = 47;

// ---------------------------------------------------------------------------
// API-level tests (Group 1: PACK / PARSE / MULTIPLE / EMPTY / CALLBACK / ADD)
// ---------------------------------------------------------------------------

fn noop_add() -> CustomExtAddCallback {
    Arc::new(|_| None)
}

fn noop_parse() -> CustomExtParseCallback {
    Arc::new(|_, _| Ok(()))
}

#[test]
fn api_pack_single_no_callback_returns_empty() {
    // C `SDV_TLS_PACK_CUSTOM_EXTENSIONS_API_TC001`: one ext registered, add_cb
    // returns None → nothing on the wire.
    let ext = CustomExtension {
        extension_type: CUSTOM_EXT_TYPE_1,
        context: ExtensionContext::CLIENT_HELLO,
        add_cb: noop_add(),
        parse_cb: noop_parse(),
    };
    let result = build_custom_extensions(&[ext], ExtensionContext::CLIENT_HELLO);
    assert!(result.is_empty(), "no-callback ext must not pack");
}

#[test]
fn api_parse_single_no_callback_returns_ok() {
    // C `SDV_TLS_PARSE_CUSTOM_EXTENSIONS_API_TC001`: an incoming ext matches a
    // registered type but the registered parse_cb is a no-op → Ok(()).
    let ext = CustomExtension {
        extension_type: CUSTOM_EXT_TYPE_1,
        context: ExtensionContext::CLIENT_HELLO,
        add_cb: noop_add(),
        parse_cb: noop_parse(),
    };
    let received = [Extension {
        extension_type: ExtensionType(CUSTOM_EXT_TYPE_1),
        data: vec![0xAA],
    }];
    let result = parse_custom_extensions(&[ext], ExtensionContext::CLIENT_HELLO, &received);
    assert!(result.is_ok());
}

#[test]
fn api_pack_multiple_no_callbacks_returns_empty() {
    // C `SDV_TLS_PACK_CUSTOM_EXTENSIONS_MULTIPLE_API_TC001`: two exts both with
    // no add_cb → empty result.
    let exts = vec![
        CustomExtension {
            extension_type: CUSTOM_EXT_TYPE_1,
            context: ExtensionContext::CLIENT_HELLO,
            add_cb: noop_add(),
            parse_cb: noop_parse(),
        },
        CustomExtension {
            extension_type: CUSTOM_EXT_TYPE_2,
            context: ExtensionContext::CLIENT_HELLO,
            add_cb: noop_add(),
            parse_cb: noop_parse(),
        },
    ];
    let result = build_custom_extensions(&exts, ExtensionContext::CLIENT_HELLO);
    assert!(result.is_empty());
}

#[test]
fn api_pack_no_extensions_returns_empty() {
    // C `SDV_TLS_PACK_CUSTOM_EXTENSIONS_EMPTY_API_TC001`: no registrations →
    // build returns empty.
    let result = build_custom_extensions(&[], ExtensionContext::CLIENT_HELLO);
    assert!(result.is_empty());
}

#[test]
fn api_pack_with_callback_emits_extension() {
    // C `SDV_TLS_PACK_CUSTOM_EXTENSIONS_CALLBACK_API_TC001`: add_cb returns
    // `Some(vec![0xAA])` → one extension on the wire with that data.
    let ext = CustomExtension {
        extension_type: CUSTOM_EXT_TYPE_1,
        context: ExtensionContext::CLIENT_HELLO,
        add_cb: Arc::new(|_| Some(vec![0xAA])),
        parse_cb: noop_parse(),
    };
    let result = build_custom_extensions(&[ext], ExtensionContext::CLIENT_HELLO);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].extension_type.0, CUSTOM_EXT_TYPE_1);
    assert_eq!(result[0].data, vec![0xAA]);
}

#[test]
fn api_parse_with_callback_invokes_cb() {
    // C `SDV_TLS_PARSE_CUSTOM_EXTENSIONS_CALLBACK_API_TC001`: parse_cb fires on
    // a matching incoming extension.
    let counter = Arc::new(AtomicU32::new(0));
    let c = counter.clone();
    let ext = CustomExtension {
        extension_type: CUSTOM_EXT_TYPE_1,
        context: ExtensionContext::CLIENT_HELLO,
        add_cb: noop_add(),
        parse_cb: Arc::new(move |_, data| {
            assert_eq!(data, &[0xAA]);
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    };
    let received = [Extension {
        extension_type: ExtensionType(CUSTOM_EXT_TYPE_1),
        data: vec![0xAA],
    }];
    let result = parse_custom_extensions(&[ext], ExtensionContext::CLIENT_HELLO, &received);
    assert!(result.is_ok());
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[test]
fn api_add_custom_extension_via_builder() {
    // C `SDV_HITLS_ADD_CUSTOM_EXTENSION_API_TC001` (normal case): config
    // stores the registration.
    let ext = CustomExtension {
        extension_type: CUSTOM_EXT_TYPE_1,
        context: ExtensionContext::CLIENT_HELLO,
        add_cb: noop_add(),
        parse_cb: noop_parse(),
    };
    let cfg = TlsConfig::builder()
        .role(TlsRole::Client)
        .custom_extension(ext)
        .build();
    assert_eq!(cfg.custom_extensions.len(), 1);
    assert_eq!(cfg.custom_extensions[0].extension_type, CUSTOM_EXT_TYPE_1);
}

#[test]
fn api_add_custom_extension_duplicate_not_rejected() {
    // C `SDV_HITLS_ADD_CUSTOM_EXTENSION_API_TC001` (duplicate case): C returns
    // `HITLS_CONFIG_DUP_CUSTOM_EXT`. Rust currently pushes the second copy
    // without complaint — pin the gap.
    // TODO(#58-dup-check): reject duplicate `extension_type` registrations.
    let make_ext = || CustomExtension {
        extension_type: CUSTOM_EXT_TYPE_1,
        context: ExtensionContext::CLIENT_HELLO,
        add_cb: noop_add(),
        parse_cb: noop_parse(),
    };
    let cfg = TlsConfig::builder()
        .role(TlsRole::Client)
        .custom_extension(make_ext())
        .custom_extension(make_ext())
        .build();
    assert_eq!(
        cfg.custom_extensions.len(),
        2,
        "Rust does not enforce dup check; gap pinned"
    );
}

#[test]
fn api_context_filter_skips_wrong_context() {
    // The ext is registered for CLIENT_HELLO; building for SERVER_HELLO must
    // skip it even though add_cb would otherwise produce data.
    let ext = CustomExtension {
        extension_type: CUSTOM_EXT_TYPE_1,
        context: ExtensionContext::CLIENT_HELLO,
        add_cb: Arc::new(|_| Some(vec![0xAA])),
        parse_cb: noop_parse(),
    };
    let result = build_custom_extensions(&[ext], ExtensionContext::SERVER_HELLO);
    assert!(result.is_empty(), "wrong context must be skipped");
}

// ---------------------------------------------------------------------------
// Function-level handshake interop tests (Group 2: TC001-TC004 analogues)
// ---------------------------------------------------------------------------

/// Trace of the contexts each callback was invoked in. Wrapped in `Arc<Mutex<>>`
/// so the same trace can be inspected from both the test thread and the
/// server thread.
#[derive(Default, Clone)]
struct CallbackTrace {
    added: Arc<Mutex<Vec<u32>>>,
    parsed: Arc<Mutex<Vec<u32>>>,
}

impl CallbackTrace {
    fn new() -> Self {
        Self::default()
    }
    fn record_add(&self, ctx: ExtensionContext) {
        self.added.lock().unwrap().push(ctx.0);
    }
    fn record_parse(&self, ctx: ExtensionContext) {
        self.parsed.lock().unwrap().push(ctx.0);
    }
    fn added(&self) -> Vec<u32> {
        self.added.lock().unwrap().clone()
    }
    fn parsed(&self) -> Vec<u32> {
        self.parsed.lock().unwrap().clone()
    }
}

/// Build a `CustomExtension` whose `add_cb` records the invocation and emits
/// `data_to_send`, and whose `parse_cb` records the invocation and returns
/// `Ok(())`.
fn echo_ext(
    ext_type: u16,
    context: ExtensionContext,
    trace: CallbackTrace,
    data_to_send: Option<Vec<u8>>,
) -> CustomExtension {
    let add_trace = trace.clone();
    let parse_trace = trace;
    CustomExtension {
        extension_type: ext_type,
        context,
        add_cb: Arc::new(move |ctx| {
            add_trace.record_add(ctx);
            data_to_send.clone()
        }),
        parse_cb: Arc::new(move |ctx, _| {
            parse_trace.record_parse(ctx);
            Ok(())
        }),
    }
}

fn run_tls13_handshake(
    client_ext: CustomExtension,
    server_ext: CustomExtension,
) -> Result<(), String> {
    let (cert_chain, server_key) = make_ed25519_server_identity();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .custom_extension(server_ext)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        let handshake_ok = conn.handshake().is_ok();
        let send_result = if handshake_ok {
            Ok(())
        } else {
            Err("server: handshake".to_string())
        };
        let _ = tx.send(send_result);
        if handshake_ok {
            let mut buf = [0u8; 32];
            if let Ok(n) = conn.read(&mut buf) {
                let _ = conn.write(&buf[..n]);
            }
        }
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .custom_extension(client_ext)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    let client_result = conn.handshake();

    if client_result.is_ok() {
        let _ = conn.write(b"ping");
        let mut buf = [0u8; 32];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
    }

    // Server may legitimately hang waiting for client Finished if the client
    // bailed mid-handshake (e.g. the alert-on-parse-failure scenario). A
    // timed-out recv is treated as "server didn't observe success" — the
    // client-side error is the authoritative outcome for the test.
    let server_result = rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap_or(Err("server: timeout (client likely sent alert)".to_string()));
    // Do not join the server thread; it may be blocked. The test harness
    // will reap the thread when the process exits.
    drop(server_handle);

    match (client_result, server_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), _) => Err(format!("client: {e:?}")),
        (Ok(()), Err(e)) => Err(e),
    }
}

#[test]
fn function_basic_handshake_round_trip() {
    // C `SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC001` (simplified): full TLS 1.3
    // handshake with one custom extension registered on both sides for all
    // currently-wired contexts (CH | SH | EE). The C TC also expects
    // CERTIFICATE / CERTIFICATE_REQUEST / NEW_SESSION_TICKET to fire — Rust
    // doesn't wire those today (see `TODO(#58-context-gap)` in module doc),
    // so we restrict the asserted contexts to the supported subset.
    let client_trace = CallbackTrace::new();
    let server_trace = CallbackTrace::new();

    let ctx = ExtensionContext(
        ExtensionContext::CLIENT_HELLO.0
            | ExtensionContext::SERVER_HELLO.0
            | ExtensionContext::ENCRYPTED_EXTENSIONS.0,
    );
    let client_ext = echo_ext(
        CUSTOM_EXT_TYPE_2,
        ctx,
        client_trace.clone(),
        Some(vec![0xAA]),
    );
    let server_ext = echo_ext(
        CUSTOM_EXT_TYPE_2,
        ctx,
        server_trace.clone(),
        Some(vec![0xAA]),
    );

    run_tls13_handshake(client_ext, server_ext).expect("handshake");

    // Client adds at CH, parses at SH and EE
    assert!(
        client_trace
            .added()
            .contains(&ExtensionContext::CLIENT_HELLO.0),
        "client must have added at CH"
    );
    let client_parsed = client_trace.parsed();
    assert!(
        client_parsed.contains(&ExtensionContext::SERVER_HELLO.0)
            || client_parsed.contains(&ExtensionContext::ENCRYPTED_EXTENSIONS.0),
        "client must have parsed at SH or EE; got {client_parsed:?}"
    );

    // Server parses at CH, adds at SH and EE
    assert!(
        server_trace
            .parsed()
            .contains(&ExtensionContext::CLIENT_HELLO.0),
        "server must have parsed at CH"
    );
    let server_added = server_trace.added();
    assert!(
        server_added.contains(&ExtensionContext::SERVER_HELLO.0)
            || server_added.contains(&ExtensionContext::ENCRYPTED_EXTENSIONS.0),
        "server must have added at SH or EE; got {server_added:?}"
    );
}

#[test]
fn function_alert_on_parse_failure() {
    // C `SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC002`: client's parse_cb returns
    // an alert when it sees the server's echoed extension → handshake fails.
    let client_trace = CallbackTrace::new();
    let trace_for_parse = client_trace.clone();
    // Server echoes the custom extension in EncryptedExtensions per RFC 8446
    // §4.2 (most server custom extensions live in EE, not ServerHello).
    let echo_ctx = ExtensionContext(
        ExtensionContext::CLIENT_HELLO.0 | ExtensionContext::ENCRYPTED_EXTENSIONS.0,
    );
    let client_ext = CustomExtension {
        extension_type: CUSTOM_EXT_TYPE_2,
        context: echo_ctx,
        add_cb: {
            let t = client_trace.clone();
            Arc::new(move |ctx| {
                t.record_add(ctx);
                Some(vec![0xAA])
            })
        },
        // parse_cb at EE (server's echo) rejects with an alert
        parse_cb: Arc::new(move |ctx, _| {
            trace_for_parse.record_parse(ctx);
            Err(ALERT_ILLEGAL_PARAMETER)
        }),
    };

    let server_trace = CallbackTrace::new();
    let server_ext = echo_ext(CUSTOM_EXT_TYPE_2, echo_ctx, server_trace, Some(vec![0xAA]));

    let result = run_tls13_handshake(client_ext, server_ext);
    assert!(
        result.is_err(),
        "handshake must fail when client parse_cb returns Err alert"
    );
}

#[test]
fn function_empty_extension_capability() {
    // C `SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC003`: client sends an empty
    // extension body (`Some(vec![])`), server parses it (data slice is empty)
    // and the handshake completes.
    let client_trace = CallbackTrace::new();
    let server_trace = CallbackTrace::new();

    let ctx = ExtensionContext(ExtensionContext::CLIENT_HELLO.0 | ExtensionContext::SERVER_HELLO.0);
    let client_ext = echo_ext(CUSTOM_EXT_TYPE_2, ctx, client_trace.clone(), Some(vec![]));
    let parse_seen_empty = Arc::new(AtomicU32::new(0));
    let parse_seen_empty_c = parse_seen_empty.clone();
    let server_ext = CustomExtension {
        extension_type: CUSTOM_EXT_TYPE_2,
        context: ctx,
        add_cb: {
            let t = server_trace.clone();
            Arc::new(move |ctx| {
                t.record_add(ctx);
                None
            })
        },
        parse_cb: Arc::new(move |_, data| {
            if data.is_empty() {
                parse_seen_empty_c.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }),
    };

    run_tls13_handshake(client_ext, server_ext).expect("empty-ext handshake");
    assert!(
        parse_seen_empty.load(Ordering::SeqCst) >= 1,
        "server parse_cb must see empty data slice at least once"
    );
    assert!(
        client_trace
            .added()
            .contains(&ExtensionContext::CLIENT_HELLO.0),
        "client add_cb fired at CH"
    );
}

#[test]
fn function_pass_extension_capability() {
    // C `SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC004`: client add_cb returns
    // `None` (PASS) — extension is NOT sent. Server's parse_cb must not fire.
    let client_trace = CallbackTrace::new();
    let server_trace = CallbackTrace::new();

    let ctx = ExtensionContext(ExtensionContext::CLIENT_HELLO.0 | ExtensionContext::SERVER_HELLO.0);
    let client_ext = echo_ext(CUSTOM_EXT_TYPE_2, ctx, client_trace.clone(), None);
    let server_ext = echo_ext(CUSTOM_EXT_TYPE_2, ctx, server_trace.clone(), None);

    run_tls13_handshake(client_ext, server_ext).expect("pass-ext handshake");
    assert!(
        client_trace
            .added()
            .contains(&ExtensionContext::CLIENT_HELLO.0),
        "client add_cb must have been called (even when returning None)"
    );
    // Server parsing did NOT fire because client didn't send the ext.
    assert!(
        !server_trace
            .parsed()
            .contains(&ExtensionContext::CLIENT_HELLO.0),
        "server parse_cb must not see CH ext (client returned PASS); got {:?}",
        server_trace.parsed()
    );
}
