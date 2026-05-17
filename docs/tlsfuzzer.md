# Testing openhitls-rs with tlsfuzzer

[tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer) is a TLS protocol-level
test harness driven by [tlslite-ng](https://github.com/tlsfuzzer/tlslite-ng).
It is the same suite that has historically caught real bugs in OpenSSL,
NSS, GnuTLS, and BoringSSL. This document captures everything you need
to point it at `hitls s-server` and read the result.

The CI hook lives at `.github/workflows/tlsfuzzer.yml`
(workflow_dispatch + weekly schedule). What follows is the equivalent
local setup, written so a new contributor can reproduce a CI failure
without re-deriving the gotchas.

## TL;DR

```bash
# 1. Build the server.
cargo build --release -p hitls-cli

# 2. Generate a server certificate (RSA 2048, PKCS#8 — see "gotchas").
mkdir -p /tmp/hitls-tlsfuzzer && cd /tmp/hitls-tlsfuzzer
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout key-rsa.pem -out cert-rsa.pem \
    -subj "/CN=localhost" -days 1
openssl pkcs8 -topk8 -nocrypt -in key-rsa.pem -out key-rsa-pkcs8.pem

# 3. Install tlsfuzzer + tlslite-ng from git (NOT from PyPI).
python3 -m venv /tmp/tlsfuzzer-venv
/tmp/tlsfuzzer-venv/bin/pip install \
    ecdsa \
    "git+https://github.com/tlsfuzzer/tlslite-ng"
git clone --depth 1 \
    https://github.com/tlsfuzzer/tlsfuzzer /tmp/tlsfuzzer

# 4. Start the server.
./target/release/hitls s-server -p 4444 \
    --cert /tmp/hitls-tlsfuzzer/cert-rsa.pem \
    --key  /tmp/hitls-tlsfuzzer/key-rsa-pkcs8.pem -q &

# 5. Run a script.
cd /tmp/tlsfuzzer
PYTHONPATH=. /tmp/tlsfuzzer-venv/bin/python \
    scripts/test-tls13-ccs.py -p 4444 -h localhost
```

A clean run prints `PASS: N` and `FAIL: 0`.

## Gotchas (read these before you debug)

These are the things that wasted the most time the first time around.

### tlsfuzzer is not on PyPI

`pip install tlsfuzzer` silently installs an unrelated stub. You must
clone the GitHub repo and run scripts in-tree with `PYTHONPATH=.`.

### tlslite-ng on PyPI lags HEAD

The PyPI release (`tlslite-ng==0.8.2` at time of writing) is missing
recent `SignatureScheme` constants (e.g. `mldsa87`) that tlsfuzzer's
HEAD references. Importing certain scripts will raise
`AttributeError: type object 'SignatureScheme' has no attribute 'mldsa87'`
and abort the whole run. Install from git:

```bash
pip install "git+https://github.com/tlsfuzzer/tlslite-ng"
```

### `hitls s-server` only accepts PKCS#8 PEM keys

Plain `openssl genrsa` / `openssl ecparam -genkey` output is in legacy
PKCS#1 / SEC1 form and `s-server` will refuse it. Pipe through
`openssl pkcs8 -topk8 -nocrypt`.

### Use an RSA 2048 cert, not ECDSA P-256

`s-server` happily serves either. tlsfuzzer's default
`signature_algorithms` extension prefers `rsa_pss_rsae_sha256`, so
many scripts (including the `*` wildcard sanity ones) abort with
`no common signature scheme` against an ECDSA-only cert. RSA cuts
that whole class of false negatives.

### `s-server` advertises four common groups

To avoid `no common named group` HRRs against tlsfuzzer scripts that
offer P-256 only, the CLI defaults to:

```
X25519, secp256r1, secp384r1, secp521r1
```

(See `crates/hitls-cli/src/s_server.rs`.)

### Argument style is `--cert`, not `-cert`

`s-server` uses long-only flags. The OpenSSL-style `-cert`,
`-accept`, `-key` will fail with `unexpected argument`.

```
hitls s-server -p 4444 --cert ... --key ...
```

## Recommended scripts

The scripts under `tlsfuzzer/scripts/` cover hundreds of edge cases.
A reasonable starter set, in increasing order of strictness:

| Script | What it covers |
|---|---|
| `test-tls13-conversation.py` | Sanity — basic TLS 1.3 handshake over multiple variants. Should be 3/3 PASS. |
| `test-tls13-ccs.py` | RFC 8446 §5 / §D.4 ChangeCipherSpec compatibility rules. Pinned by Phase T88 — must be 5/5 PASS. |
| `test-tls13-multiple-ccs-messages.py` | Multiple CCS records during the handshake. |
| `test-tls13-version-negotiation.py` | `supported_versions` + legacy-version handling. |
| `test-tls13-keyshare-omitted.py` | HRR triggered by missing key share. |
| `test-tls13-finished.py` | Finished MAC mutations — many of these are deep mutation tests; expect partial PASS until covered. |

Avoid the broader `test-tls13-*` mutation scripts in CI gating
unless the failures have been triaged — they are a research tool,
not a regression suite.

## Reading the output

Each script prints a per-test trace followed by:

```
====================
version: 6
====================
TOTAL: 5
SKIP:  0
PASS:  5
XFAIL: 0
FAIL:  0
XPASS: 0
====================
```

- `TOTAL` = number of conversations (sub-tests) the script defined.
- `PASS` / `FAIL` = the only signal you need for a pass/fail decision.
- `XFAIL` = expected-to-fail (use the `-x` flag to mark known
  divergences as expected).
- `XPASS` = something previously XFAIL'd is now passing — should be
  removed from the expected-failure list.
- A `FAILED:` block lists the individual conversation names that
  failed. Run a single one with the conversation name as a positional
  arg, e.g.:

  ```bash
  PYTHONPATH=. python scripts/test-tls13-ccs.py \
      -p 4444 -h localhost "two byte long CCS"
  ```

When a conversation fails the trace shows the message it expected
versus what `s-server` actually sent (typically an `Alert` of the
wrong description, or a `TLSBadRecordMAC` if a key transition is
mistimed).

## XFAIL bookkeeping

Some failures are real, scheduled gaps (e.g. RFC 8446 §9.2's
`missing_extension` requirement for omitted `key_share`) and others
are tlsfuzzer encoding OpenSSL-flavoured choices that we deliberately
don't share (e.g. the 263 "fallback from TLS 1.3-draft<N>" cases).
Either way, leaving them in the FAIL column means CI signal is
indistinguishable from noise the moment the file lands.

We track them as **XFAIL**:

- one file per script under `tests/tlsfuzzer/xfail/<script-stem>.txt`,
  one conversation name per line, optional `<name> :: <reason>`;
- `tests/tlsfuzzer/run.sh <script>` reads the file, attaches the
  appropriate `-x ... -X ...` flags, then execs the script;
- tlsfuzzer's own exit code becomes the gating signal (`exit 1` on
  `FAIL > 0` or `XPASS > 0`), so CI fails on a NEW regression OR on
  a previously-XFAIL'd case suddenly passing.

For scripts that need a fixed extra flag every run (e.g. TLS 1.2
scripts need `-C 49199` so they negotiate our ECDHE-AES-128-GCM
cipher instead of their default RSA-static-key-exchange + AES-CBC),
drop a sibling file at `tests/tlsfuzzer/args/<script-stem>.txt`,
one arg per line. The runner appends those before the XFAIL chain.

Workflow:

```bash
# Run a single script through the runner:
TLSFUZZER_DIR=/tmp/tlsfuzzer \
TLSFUZZER_PY=/tmp/tlsfuzzer-venv/bin/python \
  ./tests/tlsfuzzer/run.sh test-tls13-ccs.py -p 4444 -h localhost
```

To regenerate an XFAIL list (e.g. after upstream tlsfuzzer adds new
conversations or after fixing a class of bugs and wanting to
re-baseline), pipe FAILED through sed and overwrite the file:

```bash
PYTHONPATH=. python scripts/test-tls13-finished.py -h $H -p $P -n 9999 \
  2>&1 | sed -n '/FAILED:/,/^=/p' | grep "^\s\+'" \
  | sed "s/^[[:space:]]*'\(.*\)'/\1/" \
  > tests/tlsfuzzer/xfail/test-tls13-finished.txt
# then prepend the file's existing rationale comment block by hand
```

When you fix a conformance gap, **delete the corresponding XFAIL
entries**. CI's next run reports them as XPASS and fails — this is
the desired signal that the XFAIL list is now stale.

## CI hookup

Since Phase T124 the harness runs in **two tiers**:

**Tier 1 — `tlsfuzzer-core` job in `.github/workflows/ci.yml`.** A tiny,
deterministic, 0-XFAIL subset (6 scripts: `conversation`, `ccs`,
`multiple-ccs-messages`, `nociphers`, `record-padding`,
`count-tickets`) runs on **every PR and push** and is wired into the
`ci-gate` aggregate — so it is part of the required `CI Gate` status
check. These scripts are basic handshake / record-layer / CCS
correctness; a failure is a real regression, so it *should* block a
merge. No branch-protection change was needed: requiring `CI Gate`
already requires every job in its `needs:` list.

**Tier 2 — the full curated suite in `.github/workflows/tlsfuzzer.yml`.**
All 51 curated script-runs run on `workflow_dispatch`, on a weekly
schedule (Mon 06:00 UTC, sampled), and on a monthly schedule (1st
07:00 UTC, full `-n 9999` sweep). This tier is **not** a required PR
check — it exercises edge-case mutations that legitimately probe spec
ambiguities, and surfacing those should not gate merges. Per-script
logs are uploaded as the `tlsfuzzer-logs` artifact for triage.

Either way each script is invoked through `tests/tlsfuzzer/run.sh`, so
the exit code reflects only NEW regressions and NEW XPASSes;
pre-existing XFAILs are filed via the per-script files and produce no
noise.

To run Tier 2 manually: GitHub Actions → tlsfuzzer → "Run workflow".

### Sampled vs. full sweep

tlsfuzzer scripts sub-sample their conversation pool by default (see
`-n`). The weekly run keeps that sampling (≈2 min wall-clock); the
monthly run exports `SWEEP_N=9999`, which `run.sh` turns into `-n 9999`
so *every* conversation is exercised. Run a full sweep locally with:

```bash
SWEEP_N=9999 TLSFUZZER_DIR=/tmp/tlsfuzzer \
TLSFUZZER_PY=/tmp/tlsfuzzer-venv/bin/python \
  ./tests/tlsfuzzer/run.sh test-tls13-finished.py -p 4444 -h localhost
```

### Pinned upstream — how to bump

`TLSFUZZER_REF` / `TLSLITE_NG_REF` are pinned to specific upstream
commits in **both** workflow files (not `master`). An unpinned
`master` silently shifts the conversation set under our per-script
XFAIL files, making CI signal indistinguishable from upstream drift.

To upgrade tlsfuzzer/tlslite-ng, treat it as a deliberate phase:
bump the two SHAs in `ci.yml` *and* `tlsfuzzer.yml`, re-run the full
sweep, re-baseline any XFAIL lists that drifted, and land it all in
one reviewed PR.

## Phase reference

- T88 — fixed two TLS 1.3 CCS conformance gaps surfaced by
  `test-tls13-ccs.py` and added the in-tree pinning tests in
  `tests/interop/tests/protocol_attacks.rs`. The same change set
  fixed the server-side write-key timing (RFC 8446 §A.1: switch
  to `server_application_traffic_secret_0` immediately after
  sending Finished, not after receiving client Finished) so that
  alerts emitted between the two Finished messages decrypt under
  the key the peer is actually using.

- T89 — generalised the alert-before-close behaviour to the entire
  TLS 1.3 read/handshake path. Introduced a centralised
  `tls_error_to_alert(err) -> AlertDescription` mapping in
  `crates/hitls-tls/src/alert/mod.rs` and a `try_alert! /
  return_alert_err! / send_fatal_alert_for_error_body!` macro family
  in `crates/hitls-tls/src/macros.rs` that wraps every error path in
  the TLS 1.3 client/server handshake and read trait bodies with a
  best-effort fatal alert send. Effect on the curated tlsfuzzer
  suite: `test-tls13-finished.py` 3/42 PASS → 642/714 PASS;
  `test-tls13-ccs.py` 5/5 PASS sustained. Built the XFAIL
  bookkeeping infrastructure described above and curated XFAIL
  lists for the 4 scripts whose remaining failures are pre-existing
  spec gaps or upstream-test idiosyncrasies (341 XFAILs total). CI
  workflow now uses `run.sh` and gates on real exit codes instead
  of `continue-on-error`.

- T90 — extended the same alert-on-error discipline to the TLS 1.2
  server (handshake-trait wrapper + post-handshake `read()` loop in
  `connection12/server.rs`), and curated 9 TLS 1.2 tlsfuzzer scripts
  driven against a second `s-server --tls 1.2` instance on a
  separate port. Added per-script "extra args" plumbing
  (`tests/tlsfuzzer/args/<script-stem>.txt`) so each TLS 1.2 script
  picks up `-C 49199` automatically — needed because tlsfuzzer's
  default cipher (`TLS_RSA_WITH_AES_128_CBC_SHA`) collides with our
  modern ECDHE-only TLS 1.2 defaults. Tlsfuzzer baseline added by
  this phase: 501/517 PASS / 16 XFAIL / 0 FAIL across 9 scripts.
  Notable per-script results:
    - `test-fuzzed-ciphertext.py`: **2/338 → 338/338 PASS** (the
      AEAD-MAC-failure class that T89 fixed for 1.3, now also fixed
      for 1.2 once the mapper learned the `"bad record MAC"` /
      `"MAC"` / `"BadRecordMac"` substrings).
    - `test-connection-abort.py`: 150/150 PASS.
    - `test-invalid-content-type.py`, `test-conversation.py`: clean.

- T91 — closed 66 of the 72 `test-tls13-finished.py` XFAILs by
  fixing two real bugs: (1) `decode_finished` was silently
  truncating Finished bodies longer than `Hash.length` (RFC 8446
  §4.4.4 says exactly `Hash.length` — strict `!=` now), allowing
  padded Finished messages to verify and leaving stale bytes in
  the read buffer; (2) `get_body` rejected zero-body handshake
  messages with `if msg_data.len() <= 4`, folding "header-only"
  into "too short" and emitting `handshake_failure` instead of
  the `decode_error` tlsfuzzer (and RFC 8446) expects. Three
  callers of `get_body` (TLS 1.3 server / client + TLS 1.2 server)
  relaxed to `< 4`. Effect: `test-tls13-finished.py` 642/72 →
  **708/6**; remaining 6 are huge-padding cases needing
  cross-record handshake reassembly, deferred.

- T92 — broadened the curated TLS 1.3 set from 6 to **17 scripts**
  by probing 28 candidates and triaging into clean (3) /
  partial-XFAIL (8) / mass-fail (17, deferred). Added: HRR, record
  padding, record-layer limits, length fuzzing, `nociphers`,
  unknown-groups, connection-abort, RSA signatures, EdDSA,
  KeyUpdate-from-server, finished-plaintext. CI workflow's
  `scripts=()` array updated; `-n 9999` dropped from the loop so
  per-script defaults apply (typically 40-1000 sample) — wall-clock
  cut from ~12 min to ~80 s for all 26 scripts. The deferred 17
  mass-fail scripts (signature-algorithms, rsapss-signatures,
  keyupdate, symetric-ciphers, etc.) need real protocol fixes,
  not bulk XFAILs; queued for future targeted T- or I- phases.
  Combined post-T92 baseline: **1790 PASS / 244 XFAIL / 0 FAIL**
  (CI sampling) across 26 scripts; **11789 PASS / 320 XFAIL / 0
  FAIL** with `-n 9999` full sweep across 12109 conversations.

- T93 — added **cert-matrix** coverage. Pre-T93 the entire suite
  ran against a single RSA 2048 server cert; ECDSA-key-exchange
  and Ed25519 sign/verify paths were never actually exercised
  (test conversations like `ed25519 only` were XFAIL'd
  defensively because RSA-cert can't satisfy them). T93 generates
  ECDSA P-256 and Ed25519 server certs in CI, brings up two more
  `s-server` instances on ports 4446 / 4447, and runs cert-
  specific scripts against each. Per-cert XFAIL dirs
  (`tests/tlsfuzzer/xfail-ecdsa/`, `tests/tlsfuzzer/xfail-ed25519/`)
  use `run.sh`'s pre-existing `XFAIL_DIR` env-var hook — same
  script can have different XFAIL contents per cert without code
  changes. Notable: `test-tls13-eddsa.py` `'ed25519 only'`
  flips RSA-cert XFAIL → Ed25519-cert PASS, validating the
  Ed25519 sign-side end-to-end. Cert-matrix sub-aggregate: 19
  PASS / 6 XFAIL / 0 FAIL across 4 runs. Combined post-T93
  baseline: **1808 PASS / 251 XFAIL / 0 FAIL** across 30 scripts.

- T94 — added **NewSessionTicket emission count** coverage
  (`test-tls13-count-tickets.py`, 3/3 PASS clean) and
  **0-RTT-garbage edge cases** (`test-tls13-0rtt-garbage.py`,
  4/11 PASS / 7 XFAIL — the XFAIL'd cases all involve actual
  early-data sending; our `s-server` doesn't have a
  `--max-early-data-size` CLI flag yet so 0-RTT-accepting paths
  can't be exercised). Combined post-T94 baseline: **1815 PASS
  / 258 XFAIL / 0 FAIL** across 32 scripts.

  **Deferred from T94's original scope**, with concrete blockers:
    - **PSK / session resumption** (test-tls13-psk_*, session-
      resumption.py) — needs `--ticket-key` / `--psk-identity` /
      `--psk-key` CLI flags on `s-server`. Underlying TLS 1.3
      PSK code exists since I17/I21.
    - **0-RTT acceptance** — needs `--max-early-data-size <N>`
      CLI flag + server read-loop alert-on-stray-early-data.
    - **mTLS** (test-tls13-certificate-request, certificate-verify,
      post-handshake-auth) — needs `--require-client-cert` +
      `--ca-cert <path>` CLI flags. `verify_client_cert` config
      field exists.
    - **DTLS** scripts — no DTLS mode in `s-server`; would need
      `--dtls 1.{2,3}` CLI flag + UDP socket switch.
    - **Client-side hostile-server harness** — tlsfuzzer is
      server-driven by design; either build a small custom
      harness or switch to tls-attacker (Java) which supports
      both directions.

- T95 — closed two real production bugs surfaced by the post-T94
  XFAIL audit:
  - **P0**: `rsa::pss` was hardcoded to SHA-256, returning
    `internal_error` for `rsa_pss_rsae_sha384` / `rsa_pss_rsae_sha512`.
    Generalised PSS to thread `RsaHashAlg` through M' and MGF1
    (`mgf1_with_hash` + `sign_pss(digest, alg)` /
    `verify_pss(digest, sig, alg)` API; legacy SHA-256 paths
    preserved for backward compat). Default `signature_algorithms`
    extended to advertise PSS-SHA-384/512 + ECDSA-SECP384R1-SHA384.
    Closed `test-tls13-rsa-signatures.py` (6/8 → **8/8 PASS**).
  - **P1**: CVE-2020-25648 multi-CCS hardening missing.
    `read_record_body_tls13!` now tracks `ccs_seen_in_handshake`
    per connection and rejects same-round duplicate CCS with
    `unexpected_message`. Reset-on-handshake-msg preserves the
    legitimate HRR-then-SH double-CCS flow. Closed
    `test-tls13-multiple-ccs-messages.py` (4/7 → **7/7 PASS**).
  - +1 unit test (`test_rsa_pss_sign_verify_all_hashes`) and +1
    wire-level integration test
    (`test_tls13_server_rejects_second_ccs_during_handshake`).
  - Combined post-T95 baseline: **1819 PASS / 254 XFAIL / 0 FAIL**
    (+4/-4 vs T94; the math is +5/-5 closed but
    version-negotiation's random sampling shifts ~1 between runs).

- T96–T119 — incrementally grew the curated suite to 46 scripts and
  closed conformance gaps across mTLS (T98–T102, T108, T117–T118),
  alert mapping (T99–T100), cross-record reassembly (T101, T104),
  record-layer rules (T103), AES-CCM negotiation (T105), 0-RTT
  tolerance (T106, T109), PSS-OID certs (T107), and external PSK
  (T119). See the per-phase DEV_LOG entries for detail.

- T124 — split the harness into two tiers (see "CI hookup" above):
  a 6-script `tlsfuzzer-core` gate in `ci.yml` that runs on every
  PR/push and is part of the required `CI Gate`, plus the full
  46-script suite kept in the weekly/monthly `tlsfuzzer.yml`. Pinned
  `TLSFUZZER_REF` / `TLSLITE_NG_REF` from `master` to specific upstream
  commits so XFAIL lists stop drifting against upstream HEAD. Added a
  monthly full `-n 9999` sweep (`run.sh` honours the `SWEEP_N` env var)
  so conversations the weekly sampled run skips still get exercised.
  No Rust source changed — workflow + `run.sh` + docs only.

- I96 / T123 — extended the cert matrix to ECDSA P-384 + P-521.
  Probing the P-521 server cert surfaced that `hitls-tls` rejected
  P-521 CertificateVerify signing outright (`unsupported ECDSA curve
  for signing`); **I96** added P-521 to the TLS 1.3 + 1.2 signature
  dispatch, then **T123** added P-384 / P-521 `s-server` instances
  (ports 4452 / 4453) each running `test-tls13-ecdsa-support.py` with
  a per-cert XFAIL dir (`xfail-ecdsa-p384/`, `xfail-ecdsa-p521/`).
  Both gate at 5 PASS / 5 XFAIL (the XFAILs are conversations a single
  ECDSA cert structurally cannot satisfy). Suite size 46 → 48.

- T122 — `s-server` gained a `--key-update` flag: a request whose
  path contains `/keyupdate` triggers a server-initiated
  post-handshake KeyUpdate (`update_requested`); a plain `GET /` is
  echoed untouched. `test-tls13-keyupdate-from-server.py` moved off
  the shared RSA listener onto a dedicated `--key-update` instance
  (port 4454) and its last XFAIL closed — 2/1 → 3/0. Server-initiated
  post-handshake client auth (PHA) is a separate, later phase: the
  `request_client_auth()` post-handshake transcript needs a `hitls-tls`
  fix first (RFC 8446 §4.4.1). Suite size unchanged at 48 (the
  KeyUpdate script was relocated, not added).

- I97 / T125 — post-handshake client authentication (PHA). **I97**
  fixed a real RFC 8446 §4.4.1 bug: the post-handshake
  CertificateVerify was hashed over `CertificateRequest ‖ Certificate`
  alone instead of continuing the main-handshake transcript — a
  *symmetric* bug, so our client and server agreed with each other but
  not with a conformant peer. **T125** then committed the
  `--post-handshake-auth` `s-server` flag (a `/secret`-path request
  triggers a post-handshake CertificateRequest) and wired
  `test-tls13-post-handshake-auth.py` into CI on a dedicated instance
  (port 4455): 4 PASS / 2 XFAIL. The 2 XFAILs — `malformed signature
  in PHA` (server should send a fatal `decrypt_error` alert, not close
  abruptly) and `with KeyUpdate` (interleaved KeyUpdate not tolerated
  in the post-handshake read loop) — are robustness gaps queued for a
  follow-up. Suite size 48 → 49.

- I98 — closed the 2 T125 PHA XFAILs: `request_client_auth` now sends
  a fatal alert on failure (RFC 8446 §6.2 — a malformed post-handshake
  CertificateVerify yields `decrypt_error`, not a bare close) and
  transparently consumes a KeyUpdate interleaved into the
  post-handshake exchange (RFC 8446 §4.6.3).
  `test-tls13-post-handshake-auth.py` is now **6/6** with no XFAILs.

- T120 — server-side `psk_ke` (RFC 8446 §4.2.9 mode 0 — PSK
  resumption without (EC)DHE). The server negotiates `psk_ke` when the
  client offers it without `psk_dhe_ke`: no `key_share` in the
  ServerHello, Handshake Secret extracted over a Hash.length zero
  string. Closes the `session resumption - PSK_ONLY` XFAIL in
  `test-tls13-session-resumption.py` (4/3 → 5/2 — the 2 residual
  XFAILs are the TLS-1.2 cross-version gap awaiting `--tls auto`).

- T126 — mass-fail-script triage, batch 1. `tls_error_to_alert` now
  maps a TLS 1.3 zero-content-type record (RFC 8446 §5.1/§5.2) to
  `unexpected_message` instead of `internal_error`;
  `test-tls13-zero-content-type.py` joins CI at 6/8 (2 app-data-phase
  XFAILs). `test-tls13-legacy-version.py` triaged won't-fix (the
  server is RFC 8446 §4.2.1-correct — it ignores `legacy_version`
  when `supported_versions` is present); `non-support` /
  `unencrypted-alert` deferred to batch 2. Suite size 49 → 50.

- I99 — mass-fail batch-2 probing (`dhe-shared-secret-padding` /
  `ecdhe-curves`) surfaced a real bug: the TLS 1.3 `KeyExchange`
  advertised secp384r1/secp521r1 but `generate` only implemented
  X25519/X448/SECP256R1 — a client offering only secp384r1 hit
  `unsupported named group`. Wired P-384/P-521 ECDH into
  `handshake/key_exchange.rs` (the curves were already in
  `hitls-crypto::ecdh`). `dhe-shared-secret-padding` 559/5 → 703/3,
  `ecdhe-curves` 4/33 → 6/33.

- T127 — mass-fail triage batch-2 CI wiring.
  `test-tls13-dhe-shared-secret-padding.py` joins the curated suite
  (513 PASS / 3 XFAIL — `ffdhe2048`/`ffdhe3072` pending the FFDHE
  phase, `x448` not in the default `supported_groups`). Completes the
  mass-fail-triage effort: all ~10 T92-deferred scripts probed; 2 real
  bugs fixed (T126, I99), 2 scripts added to CI, the rest triaged +
  deferred. Suite size 50 → 51.
