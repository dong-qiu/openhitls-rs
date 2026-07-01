# TLS-Anvil Conformance Analysis Report

> 中文版见 [`tls-anvil-analysis-report.zh-CN.md`](./tls-anvil-analysis-report.zh-CN.md)（this document is the source of truth）.

**Status: closed-out summary (consolidated 2026-06-30).** Pulls the multi-run
TLS-Anvil analysis — previously scattered across `DEV_LOG.md` / `PROMPT_LOG.md`
phases I185–I196 and the `tls-anvil-run-native` working note — into one
auditable record: what was run, how the failure surface collapsed run-over-run,
every fix, and the confirmed non-issues.

TLS-Anvil is a complementary layer to the curated [tlsfuzzer](./tls-test-coverage-contract.md)
suite: tlsfuzzer probes targeted protocol mutations, while TLS-Anvil is a broad
RFC-conformance harness (built on TLS-Attacker, ~437 TLS 1.2/1.3 tests) that
scores every category against the spec.

---

## 1. How it is run (and why natively)

| Item | Value |
|---|---|
| Harness | TLS-Anvil (TLS-Attacker), ~437 TLS 1.2/1.3 conformance tests |
| Execution | **Native** — extracted JAR + arm64 Temurin 21 JDK (NOT the emulated-amd64 Docker image) |
| Server under test | `hitls s-server --tls auto -p 4470`, **RSA-2048** cert |
| Run command | `java -jar TLS-Anvil.jar -outputFolder <dir> -parallelTests 2 -parallelHandshakes 1 -strength 1 -connectionTimeout 4000 -disableTcpDump -identifier 127.0.0.1:4470 server -connect 127.0.0.1:4470` |
| Wall-clock | ≈ 3.3 h / 437 tests (strength-1); ≈ 11 h / 18,897 pairwise cases (strength-2) |
| Output | `<dir>/report.json` (per-category score) + `<dir>/results/<id>/_testRun.json` (per-test; `FailureInducingCombinations` names the culprit param) |

**Why native, not Docker.** The first attempt used TLS-Anvil's emulated-amd64
Docker image. On the arm64 Mac it ran under qemu and produced **~66 % spurious
failures** — mass `TransportHandler` connection noise from emulation + cross-VM
networking — directly contradicting the clean native tlsfuzzer (6213/0),
testssl.sh, and sslyze results. The JAR is platform-independent bytecode (only
the *image* is amd64), so it is extracted and run under a native arm64 JDK for
real signal. Notes: pass `-disableTcpDump` (pcap ioctl fails near the container);
RSA cert is required (Anvil's sigalg tests assume RSA signing, an EC-only cert
skews results); macOS has no `timeout` — use `nc -z` for port checks.

Scoring vocabulary (per category): **STRICTLY_SUCCEEDED** (conforms strictly),
**PARTIALLY** (conforms but with a tolerated deviation), **FULLY_FAILED**.

---

## 2. Server-mode: run-over-run failure-surface collapse

Six runs. Each fix de-noised the next run, exposing the genuine residual under
the noise.

| # | Run | Outcome | Phase(s) produced |
|---|-----|---------|-------------------|
| 0 | Docker (emulated amd64) | **Discarded** — ~66 % spurious qemu/network noise, contradicted by native tlsfuzzer/testssl/sslyze | — (switched to native) |
| 1 | Native baseline | Surfaced two real bugs under the noise | **I185**, **I186** |
| 2 | Native, after I185/I186 | STRICTLY 113→154, PARTIALLY 81→45; RecordLayer 64→80, Interop 59→77, Handshake 64→79, DeprecatedFeature→100. **100 % of the 754 residual failing cases carried a small `RECORD_LENGTH` (1/50/111); 0 were pure-logic** → isolated the single biggest finding | **I187** (~734 cases) |
| 3 | Native, after I187 | STRICTLY 154→**202**, PARTIALLY 45→**5**; RecordLayer→97, Interop→95, Handshake→94. Residual de-noised into 4 clean strictness groups | **I188** (A), **I189** (B), **I190** (C), **I191** (D) |
| 4 | Native confirmation, after I188–I191 | STRICTLY 113→**213**, PARTIALLY 81→**0**, FULLY 5→**3**; 4 categories at 100, rest 98–99.7. Of the 3 FULLY: 1 real bug, 2 non-issues | **I192** (the 1 real bug) |
| 5 | Deep, strength-2 `-ignoreCache` | 18,897 pairwise cases, ≈ 11 h → **PARTIALLY 0, FULLY 2** (the same two non-issues); `invalidEllipticCurve` confirmed STRICTLY. **Zero new issues** — fixes are robust under combinatorial coverage, not overfit to strength-1 | — (validation only) |

**Bottom line:** strength-1 (≈ 3 h) is sufficient for routine re-checks; reserve
strength-2 for deep audits.

---

## 3. Server-mode fixes (I185–I192)

The three **primary findings** (I185–I187) were the high-blast-radius bugs; the
four **strictness groups** (I188–I191) were the de-noised residual; **I192** was
the lone real bug among the final 3 FULLY.

| Phase | Finding | RFC | Fix |
|---|---|---|---|
| **I185** | TLS 1.2 downgrade-protection sentinel missing from `ServerHello.random` | RFC 8446 §4.1.3 | Emit the `DOWNGRD\x01` / `\x00` sentinel in the last 8 bytes of `ServerHello.random` when negotiating below the highest supported version |
| **I186** | `seal_record` *rejected* (not split) plaintext larger than a negotiated smaller fragment | RFC 6066 `max_fragment_length` / RFC 8449 `record_size_limit` | Split outgoing plaintext across records at the negotiated `max_fragment_size` instead of erroring |
| **I187** | `--tls auto` misrouted a **record-fragmented** ClientHello to the TLS 1.2 handler → `handshake_failure` (**the single biggest finding, ~734 cases**) | RFC 8446 §5.1 | Version-route on the *reassembled* CH, not the first fragment |
| **I188** | TLS 1.3 server completed the handshake instead of aborting on a malformed/under-specified ClientHello (A-group): `legacy_version` ≤ 0x0300; `legacy_compression_methods` ≠ `[0x00]`; `key_share` present but `supported_groups` omitted | §4.1.2, §9.2 | → `protocol_version` / `illegal_parameter` / `missing_extension` respectively |
| **I189** | No inbound record-fragment-length enforcement (B-group) | RFC 6066 §4 / RFC 8449 / §5.2 | Reject a *decrypted* plaintext exceeding the negotiated MFL with `record_overflow` (proven to be the plaintext-length path, not `bad_record_mac`) |
| **I190** | Extension parsers silently dropped off-by-one trailing bytes (C-group; largest blast radius — 1.2/1.3/TLCP/DTLS share the parser) | §6.2 | Strict exact-length consumption in `parse_extensions_from` / `parse_extensions_list` → `decode_error` |
| **I191** | Zero-length Handshake/Alert fragments were not rejected → reassembly loop blocked instead of aborting (D-group) | §5.1 | `pt.is_empty() && ct ∈ {Handshake, Alert}` → `unexpected_message`; zero-length ApplicationData still passes through |
| **I192** | Non-ECC cipher (`DHE_RSA`) + `supported_groups` holding only an unusable curve drew `handshake_failure` instead of falling back to DHE (the 1 real bug among the final 3 FULLY) | RFC 8422 §4 / RFC 7919 §4 | The I105 `kx_group_satisfiable` DHE gate contradicted `negotiate_ffdhe_group`'s FFDHE2048 fallback; fixed via the RFC 7919 §4 codepoint **range** (`0x0100..=0x01ff`) |

### Confirmed non-issues (do not re-investigate)

Two of the final 3 FULLY are **not bugs**:

- **`tls12 closeNotify`** — our TLS 1.2 server sends a correct **warning-level (1)**
  `close_notify`, verified via `openssl s_client -trace` across all ciphers. The
  harness's "level 2" verdict is non-reproducible against a real client — a
  harness artifact.
- **`ecdsaNoSignatureAlgorithmsExtension`** — N/A under an RSA server cert; it
  would need an ECDSA cert to be meaningful (and an EC-only cert skews the rest
  of Anvil's RSA-signing sigalg tests, hence the RSA-2048 default).

---

## 4. Adjacent finding (specialized testing, not Anvil) — I193

While auditing "what other specialized tests exist", an **ECDSA-cert** run
immediately surfaced a real bug, recorded here because it belongs to the same
conformance-hardening push:

| Phase | Finding | RFC | Fix |
|---|---|---|---|
| **I193** | TLS 1.2 cipher selection filtered candidates by version + key-exchange-group satisfiability but **never** by whether the suite's **authentication** algorithm matched the server's key — a server holding only an EC cert would pick an RSA-auth suite (`ECDHE_RSA` / `DHE_RSA`), present its EC cert, and the client rejected the mismatch (`wrong certificate type`). This is also why Anvil is always run with an RSA cert. | RFC 5246 §7.4.2 | Add an `auth_satisfiable(auth, key)` gate to suite selection |

---

## 5. Client-mode (≈ 223 tests) — I194–I196

TLS-Anvil also drives **client** conformance: `client -port <p> -triggerScript <cmd>`,
where the trigger launches `hitls s-client 127.0.0.1:<p> --insecure --quiet`
backgrounded. This is the **largest previously-untested surface** (server-mode
runs never exercise client message-handling), and it found three real client
bugs:

| Phase | Finding | RFC | Fix |
|---|---|---|---|
| **I194** | The post-HRR ClientHello re-randomized `client_random` and emitted an empty `legacy_session_id` — both MUST be identical to the original CH | RFC 8446 §4.1.2 | Store the initial `client_random` + `legacy_session_id` and reuse them verbatim in the retry CH |
| **I195** | Client failed to abort on several malformed server messages: `legacy_session_id_echo` mismatch / non-zero `legacy_compression_method` / disallowed extensions in ServerHello / CH/SH-only extensions in EncryptedExtensions | §4.1.3, §4.2 | `illegal_parameter` (SH session_id/compression + extension allowlist), `unsupported_extension`; EE denylist |
| **I196** | Client did not verify the post-HRR ServerHello `cipher_suite` matched the HRR's — a server/MITM could switch suites after the HRR undetected | §4.1.4 | One-shot check: when `hrr_done`, SH suite ≠ stored HRR suite → `illegal_parameter` |

**Caveat — CertificateVerify-family tests are confounded.** Running the trigger
s-client with `--insecure` makes the client skip verification because it was told
to; the resulting CertificateVerify "failures" are **test artifacts, not bugs**
(verification is correct when `verify_peer=true`). Do not re-characterize these.

---

## 6. DTLS-mode does NOT work (TLS-Attacker limitation, not our bug)

`java -jar JAR -dtls ... server -connect <host:port>` against `hitls s-server
--dtls` fails at feature extraction:
`FeatureExtractionFailedException: unable to determine SUPPORTED_CIPHERSUITES`.

This is a **TLS-Attacker DTLS-scanner maturity limitation, not a defect in our
server**: our DTLS server completes 5/5 sequential `openssl s_client -dtls1_2`
handshakes (ECDHE-RSA-AES128-GCM) and stays robust under the scanner's malformed
probes (logs "too short" / "cookie mismatch" then continues). **Do not
re-attempt DTLS via TLS-Anvil** — use openssl / dtlsfuzzer for DTLS instead.

---

## 7. Final status

- **Server-mode line: fully closed (2026-06-26).** 8 fixes (I185–I192). Final
  strength-1: STRICTLY 213, PARTIALLY 0, FULLY 3 (1 fixed → 2 confirmed
  non-issues). Strength-2 deep run: 0 new issues.
- **Client-mode line: 3 real bugs fixed (I194–I196).** CertVerify artifacts
  understood.
- **DTLS-mode: not runnable via Anvil** (TLS-Attacker limitation); covered by
  openssl + dtlsfuzzer instead.
- **Adjacent: I193** (cipher auth-type gate) from specialized ECDSA-cert testing.

For routine regression, a strength-1 native run (~3 h) suffices; reserve
strength-2 (~11 h) for deep audits. Per-phase implementation detail lives in
`DEV_LOG.md` (I185–I196); the operational how-to-run note is the
`tls-anvil-run-native` memory.
