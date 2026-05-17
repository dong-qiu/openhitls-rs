# Plan — `s-server` DTLS mode (server-side tlsfuzzer plan, task ⑤)

Status: **planning / scoping only — not yet implemented.**
Written: 2026-05-17, after tasks ①–④ of the server-side tlsfuzzer
plan landed (DEV_LOG phases T126–T128, I96–I102).

---

## TL;DR

Task ⑤ was listed as "`s-server` DTLS mode" — add a DTLS listener to
the CLI so the tlsfuzzer harness can exercise the DTLS server path.

**Investigation surfaced a premise problem: tlsfuzzer has no DTLS
scripts.** The pinned tlsfuzzer (`bf7f579dc0e65498cfb21b60e9b152f6bd84a3bf`)
ships 168 scripts; **0** are DTLS (`ls scripts/ | grep -ci dtls` → 0).
tlsfuzzer is a TLS-over-TCP conformance fuzzer — DTLS/UDP is outside
its design. So a `s-server --dtls` listener would add **no tlsfuzzer
coverage at all**.

`s-server --dtls` is still a legitimate CLI feature (openssl
`s_client -dtls` interop, manual UDP testing), but it does **not**
serve the goal the 5-task plan was built around (tlsfuzzer
server-side validation). It should be treated as a separate
CLI-feature item, re-scoped or deprioritised — not as "task ⑤ of the
tlsfuzzer plan".

## Recommendation

1. **Close the tlsfuzzer server-side plan at ①–④.** Those four tasks
   delivered real, measurable tlsfuzzer coverage + 5 conformance-bug
   fixes (I96/I97/I99/I101 + T126). ⑤ cannot extend tlsfuzzer
   coverage, so the plan is effectively complete.
2. **DTLS is already regression-covered** without a CLI listener:
   `tests/interop/tests/dtls12.rs` and `dtls_resilience.rs` drive the
   full DTLS 1.2 handshake (incl. HelloVerifyRequest cookie exchange,
   anti-replay, retransmission) in-memory via
   `dtls12_handshake_in_memory`. The protocol logic is exercised on
   every CI run.
3. **If a DTLS CLI listener is still wanted** — for openssl-interop
   differential testing, parallel to the existing TLS interop — the
   implementation plan below stands. But frame it as a CLI-feature
   phase (openssl-DTLS-interop), not a tlsfuzzer phase, and weigh it
   against other work since the marginal coverage is modest (the
   handshake is already tested in-memory; the listener mainly adds
   *cross-implementation* confidence).

---

## Background — what ⑤ was meant to be

`s-server` (`crates/hitls-cli/src/s_server.rs`) is a TLS-over-TCP
server: it binds a `TcpListener`, and per accepted `TcpStream`
constructs a `TlsServerConnection<TcpStream>` (TLS 1.3) or
`Tls12ServerConnection` (TLS 1.2) — both wrap a `Read + Write` stream
and expose a blocking `.handshake()`. Phase I100 added `--tls auto`
(peek the ClientHello, dispatch per connection).

⑤ would add `--dtls` so the same server speaks DTLS 1.2 over UDP.

## Why it is not a flag

`hitls-tls` has full DTLS 1.2/1.3 support, but the DTLS connection
type is **not socket-shaped**. `Dtls12ServerConnection`
(`connection_dtls12.rs`) does not wrap a stream and has no
`.handshake()`; it exposes datagram-level
`seal_app_data` / `open_app_data`, and the handshake is driven
**flight-by-flight** by the caller using `Dtls12ServerHandshake`
(`handshake/server_dtls12.rs`). The only end-to-end driver today is
`dtls12_handshake_in_memory` — an in-memory test helper that passes
`Vec<u8>` datagrams between two connections, not a socket loop.

So `--dtls` requires a hand-rolled UDP server loop in the CLI.

## DTLS 1.2 server API (the building blocks)

`Dtls12ServerHandshake::new(config, enable_cookie)` then, per the
reference flow in `connection_dtls12.rs::do_full_handshake`:

| Step | Call |
|------|------|
| recv ClientHello | `process_client_hello(&hs_msg)` → `Ok(Err(DtlsHelloVerifyResult))` (cookie mode → send HVR) **or** `Ok(Ok(DtlsServerHelloResult))` |
| recv ClientHello2 (post-cookie) | `process_client_hello_with_cookie(&hs_msg)` → `DtlsServerHelloResult` |
| — | `DtlsServerHelloResult::Full(flight)` (fresh) or `::Abbreviated(abbr)` (resumption) |
| send server flight | `flight.{server_hello,certificate,server_key_exchange,server_hello_done}` |
| recv ClientKeyExchange | `process_client_key_exchange(&fragment)` → `DtlsDerivedKeys` |
| recv ChangeCipherSpec | `process_change_cipher_spec()` |
| recv Finished (encrypted) | `process_finished(&decrypted_plain)` → `DtlsServerFinishedResult` |
| send server CCS + Finished | from the finished result |

Record framing helpers live in `record/dtls.rs` (`parse_dtls_record`)
and `connection_dtls12.rs` (`wrap_handshake_record`,
`wrap_encrypted_handshake_record`, `wrap_ccs_record` — **currently
private**; the CLI would need them `pub(crate)`/exported or a thin
public wrapper). `DtlsRecordEncryptor12` / `DtlsRecordDecryptor12`
handle epoch-1 record protection.

## Implementation plan (if pursued)

**Phase D1 — `s-server --dtls` DTLS 1.2 listener.**
- `main.rs`: add `--dtls` to the `s-server` subcommand (mutually
  exclusive with `--tls auto`; pin DTLS 1.2 for the first cut).
- `s_server.rs`: when `--dtls`, bind a `UdpSocket` instead of
  `TcpListener`. Single-client model first (one handshake at a time,
  keyed by the first peer `SocketAddr` from `recv_from`) — the CLI is
  a test server, not a production multiplexer.
- Drive the server flights: a `dtls_serve_one(socket, peer, config)`
  that mirrors `do_full_handshake`'s server side over
  `recv_from` / `send_to`, with a read timeout + bounded retransmit
  (DTLS flights can be lost; resend the last flight on timeout).
- Enable cookie exchange (`enable_cookie = true`) — exercises the
  HelloVerifyRequest path and is the RFC-recommended default.
- Echo loop via `seal_app_data` / `open_app_data` once `Connected`.
- Export the `wrap_*` record helpers from `hitls-tls` (or add a
  small `Dtls12ServerConnection` convenience method) so the CLI
  doesn't re-implement record framing.
- Verify against `openssl s_client -dtls1_2 -connect …`.

**Phase D2 (optional) — openssl DTLS interop test.**
- A `tests/interop/` test that runs `s-server --dtls` against
  `openssl s_client -dtls1_2`, parallel to the existing TLS interop
  tests. This is the actual *new* coverage a listener buys.

**Phase D3 (optional) — DTLS 1.3.** `connection_dtls13.rs` exists;
a `--dtls --tls 1.3` variant could follow once D1 is solid.

## Effort estimate

D1 is ~1 focused phase (the server flight sequence is fully specced
by `do_full_handshake`; the new work is the UDP loop + timeout/
retransmit + exporting the record helpers). D2/D3 are independent
follow-ons. None of it adds tlsfuzzer coverage.
