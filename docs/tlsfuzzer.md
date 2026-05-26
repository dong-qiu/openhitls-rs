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
All 58 curated script-runs run on `workflow_dispatch`, on a weekly
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

## Uncurated-corpus scan backlog (T133)

A systematic sweep (T133) ran all 99 server-testable uncurated
scripts against a fresh release `s-server` (TLS 1.3 `:4444`, TLS 1.2
fallback `:4445`). Buckets below are the working backlog for the
remaining tlsfuzzer effort. Re-run the sweep with
`/tmp/tlsfuzzer_scan.sh`-style harness after any conformance fix.

**Curated in T133 (clean-PASS, 0 XFAIL)** — `tls13-ffdhe-sanity`
(7/7), `tls13-pkcs-signature` (8/8), `cve-2004-0079` (4/4, 1.2),
`no-mlkem-in-old-tls` (12/12, 1.2).

**Small-XFAIL candidates — triaged (T134).** Curated 3 with
per-entry XFAIL lists (each failure classified, none hiding a real
bug): `test-signature-algorithms` (275/1 — SHA-1-only sig_algs
refused, won't fix), `test-x25519` (20/4 — 2 ECDHE→DHE cross-kx
fallback per the I105 gap + 2 malformed-keyshare strictness),
`test-point-extension` (7/2 — malformed/absent `ec_point_formats`
leniency). The other 3 candidates are NOT XFAIL material:
- `test-invalid-cipher-suites` — sanity fails on both ports without
  a forced cipher; belongs to the cipher-args-plumbing bucket below,
  not small-XFAIL.
- `test-bleichenbacher-workaround` — sanity needs static-RSA key
  exchange (kRSA), which we intentionally do not offer (Bleichenbacher
  /ROBOT-safe). N/A — cannot be curated (sanity can't be XFAIL'd).
- `test-sig-algs` (13/5) — **contains a real gap, do NOT XFAIL**: the
  3 `rsa_pss_pss_*-only` fails are a legitimate cert-type mismatch
  (our RSA-rsae cert can't satisfy `rsa_pss_pss_*`; the PSS-OID server
  on :4449 can), BUT `rsa_pss_rsae_sha384 only` → `internal_error`
  and `rsa_pss_rsae_sha512 only` → `handshake_failure` indicate the
  **TLS 1.2** server cannot sign CertificateVerify/SKE under
  `rsa_pss_rsae_sha384/512` — the TLS-1.2 analogue of the TLS 1.3
  RSA-PSS-SHA-384/512 fix. **I-phase candidate** (TLS 1.2 RSA-PSS-rsae
  SHA-384/512 signing).

**Non-deterministic — do NOT curate (server is NOT at fault)**:
`test-ecdhe-padded-shared-secret` (varies 2/1 ↔ 77/0 ↔ 238/0 run to
run) and `test-tls13-large-number-of-extensions` (22/22 standalone,
occasional 20/2). A dedicated load probe (T133: 600 sequential
openssl handshakes against a fresh `s-server`) **disproved** the
earlier "server degrades / leaks fds" hypothesis: server fd count
stayed flat at 8 across all 600 connections, client TIME_WAIT stayed
at 2, no accept errors, and `ecdhe-padded` returned the *same* 2/1
both before and after the load — load made zero difference. The
variance is **test-side non-determinism** (the script randomly
samples padding-length conversations; one intermittently fails), not
a server resource problem. Curating these would only add flaky CI
signal. The intermittent 1-conversation failure in `ecdhe-padded` is
worth a separate script-level look (which padding case; value- or
timing-dependent) but is not a robustness/leak issue. `ecdhe-padded`
was also T128-excluded for TLS 1.0/1.1/SSLv2-compat fails.

**Curve family — triaged (I124).** The heavy "fail" counts were
dominated by a **real bug**: a malformed peer key_share for a
*supported* group drew `internal_error` instead of `illegal_parameter`
(RFC 8446 §4.2.8.2). I124 fixed it (`build_server_flight` maps the
`compute_shared_secret` / `encapsulate` peer-input error to
`illegal_parameter`), flipping 77 conversations:
- `test-tls13-crfg-curves` 8/10 → **18/0** — curated, clean.
- `test-tls13-ecdhe-curves` 7/26 → **33/0** — curated, clean.
- `test-tls13-ffdhe-groups` 7/55 → **48/14** — curated; the 14 XFAILs
  are a *separate* FFDHE key-share framing-validation gap (truncated /
  wrong-group / duplicated accepted → ServerHello instead of
  `illegal_parameter`; would fail later at Finished). Follow-up:
  validate FFDHE key-share length/group/duplicate at parse time.

Still genuine feature gaps (not curated):
- `test-tls13-obsolete-curves` (8/163) — triaged (I126 sweep): the 163
  failures are *not* a clean feature gap but a policy/conformance call —
  109 expect `illegal_parameter`/rejection where we (per RFC 8446 §4.2.7
  "ignore unrecognized") proceed with a supported group + send
  ServerHello/HRR, and 54 want `illegal_parameter` where we send
  `handshake_failure`. Reconciling these risks diverging from the RFC's
  ignore-unrecognized rule; deferred pending a careful per-case RFC read.
- `test-tls13-certificate-compression` — **CURATED (I128), 28/1**. RFC
  8879 is implemented in the library; I126 wired it into the CLI
  (`s-server --cert-compression`, advertises zlib) + hardened
  `parse_compress_certificate`; I128's close_notify §6.1 fix below
  flipped the remaining 10 conversations. Runs against a dedicated
  `--cert-compression` listener (`HITLS_PORT_CERTCOMP`); the single XFAIL
  ("sending extension in TLS-1.2") is a TLS-1.2 ClientHello rejected by
  this TLS-1.3-only listener (cert compression is TLS-1.3-only).
- `test-extensions` (215/77, 1.2), `test-export-ciphers-rejected`
  (76/78, 1.2), `test-alpn-negotiation` (3/16, 1.2),
  `test-invalid-server-name-extension` (3/13, 1.2),
  `test-dhe-rsa-key-exchange-signatures` (4/8, 1.2),
  `test-ecdsa-sig-flexibility` (3/8, 1.2).

**Read-path conformance — I-phase candidate**:
`test-tls13-unencrypted-alert` (2/2 fail) — server replies
`unexpected_message` to a peer abort-alert instead of closing
silently (RFC 8446 §6.2). Fix unblocks curation.

**close_notify reply — FIXED (I128).** On receiving the peer's
`close_notify` the server set `state = Closed` (read path), and
`shutdown()` (`tls13_client_shutdown_trait_body!`, macros.rs)
early-returned on `state == Closed` **without sending its own
`close_notify`** — dropping the TCP abruptly instead of replying (RFC
8446 §6.1: each party MUST send `close_notify` before closing its write
side). Most curated scripts tolerate abrupt close (`ExpectAlert` with
`next_sibling = ExpectClose()`), so this was invisible until the strict
`ExpectAlert` → `add_child(ExpectClose())` form in
`test-tls13-certificate-compression` (10 conversations) caught it. Fix:
the shutdown macro now bails early only when closed *without* a clean
peer close_notify (`state == Closed && !received_close_notify`, the RFC
§6.2 fatal-alert path — close immediately, no reply); a clean peer
close_notify is answered with our own (gated on `sent_close_notify` for
idempotency). One macro covers TLS 1.3 + 1.2, client + server, sync +
async. Full curated-suite regression: 0 FAIL / 0 XPASS (the change only
flipped the 10 cert-compression conversations XFAIL→PASS).

**Cipher-args plumbing — triaged (T135).** The four headline
candidates turned out to be mostly NOT a simple args fix:
- `test-extended-master-secret-extension` — **curated** with `-d`
  (ECDHE). 9/9; the 9 XFAILs are unsupported features (TLS 1.1,
  renegotiation, TLS 1.2 session resumption) + 1 malformed-ext
  strictness. The 9 PASS give regression coverage on our EMS
  three-state policy.
- `test-chacha20` — **FIXED in I122** (RFC 7905). The TLS 1.2 record
  layer framed ChaCha20-Poly1305 like AES-GCM (4-byte salt + 8-byte
  explicit nonce) instead of RFC 7905's 12-byte write_iv + implicit
  `seq⊕iv` nonce, so the handshake interoperated with itself but not
  with tlslite-ng (`bad_record_mac` on the first encrypted record).
  I122 fixed it: **0/52 → ~51/52** interop. **Not curated into CI** —
  the 2 residual conversations were investigated (run in isolation
  they fail deterministically; in the full suite they look "flaky")
  and are **not read-path bugs**:
  - `1/n-1 record splitting` — the server returns `ApplicationData`
    where the script expects `close_notify`. Our `s-server` is an
    **echo server**: it echoes the client's HTTP request back as
    application data, which *races* the connection-close sequence on
    the wire — so the conversation deterministically fails in
    isolation and intermittently fails in the suite. This is the same
    "echo-server vs abort" expectation mismatch already documented
    won't-fix for `test-tls13-connection-abort` / `test-tls13-non-
    support` — not a record-reassembly or read-path timing bug (the
    `fill_buf` read loop correctly reassembles split records).
  - `Chacha20 in TLS1.1` — we reject the TLS 1.1 ClientHello with
    `protocol_version` (correct: we are TLS 1.2-only); the script
    expects `handshake_failure` (its "ChaCha20 not allowed in TLS 1.1"
    semantics assume a 1.1-capable server). Deterministic won't-fix
    (TLS 1.1), not flaky.

  Net: the apparent flakiness is the echo-server's app-data echo
  racing the close, plus a deterministic TLS-1.1 alert-code
  divergence — neither warrants a code change, and xfail can't cover
  an echo-race conversation that intermittently passes (XPASS). The
  earlier "read-path timing" framing (T133/I122) was incorrect.
- `test-aesccm` — **N/A**: `default_tls12_suites()` offers no TLS 1.2
  AES-CCM suite (CCM is TLS 1.3-only here). Needs new TLS 1.2 CCM
  cipher suites (a feature), not args.
- `test-downgrade-protection` — **N/A / won't-fix**: sanity fails even
  with `-d`, and its substantive conversations check the TLS 1.3
  downgrade sentinel for `(3,1)`/`(3,2)` — we are TLS 1.2-only and
  reject those with `protocol_version`, which is correct.

Remaining un-probed cipher-args candidates: `test-dhe-rsa-key-exchange`,
`test-record-size-limit`, `test-fuzzed-{finished,MAC,padding,plaintext}`.

**Not applicable** — client-side tests, renegotiation/resumption,
SSLv2, PSK-server-only, and brainpool-curve scripts that need a
dedicated server config or are out of scope for the current
server build.

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

- I100 — `s-server --tls auto`: a single listener that peeks each
  pending ClientHello (`TcpStream::peek`) for the `supported_versions`
  extension and dispatches the connection to the TLS 1.3 or TLS 1.2
  handler — so one port serves both versions.

- I101 / T128 — TLS 1.2 curated-suite breadth. Probing the TLS 1.2
  corpus measured 453/889 connections failing on "no common signature
  scheme": **I101** fixed two TLS 1.2 server-conformance gaps — the
  `signature_algorithms`-absent `{sha1,*}` default (RFC 5246
  §7.4.1.4.1) and the `ec_point_formats` ServerHello echo (RFC 8422
  §5.1.2) — unblocking the TLS 1.2 sanity handshake. **T128** then
  curated 5 newly-passing TLS 1.2 scripts (`aes-gcm-nonces`,
  `encrypt-then-mac`, `version-numbers`, `zero-length-data`,
  `ecdhe-rsa-key-exchange`) into `scripts_12`, full-set verified
  (`-n 9999`). Suite size 51 → 56.

- I102 — TLS 1.3 FFDHE (RFC 7919) key exchange. The TLS 1.3
  `KeyExchange` had no finite-field-DHE variant, so a client offering
  only an `ffdhe*` group hit `unsupported named group`. Wired all 5
  RFC 7919 groups (ffdhe2048…8192) into `KeyExchange` (the
  `hitls-crypto::dh` primitive already existed); the `s-server`
  default `supported_groups` gained the FFDHE groups + X448. Two
  curated scripts went fully clean and lost their XFAIL files:
  `test-tls13-dhe-shared-secret-padding.py` 513/3 → **2203/0** (full
  `-n 9999` set) and `test-tls13-psk_dhe_ke.py` 3/1 → **4/4**. Suite
  size unchanged at 56 (no scripts added — two existing ones became
  0-XFAIL).

- I103 / I104 — post-④ TLS 1.2 conformance-fix batch. Probing the
  curated TLS 1.2 set surfaced five small server-conformance gaps;
  **I103** hardened ClientKeyExchange handling (invalid ECDHE point →
  `illegal_parameter`; reject padding-extended CKE), **I104** fixed
  the ClientHello `legacy_version` floor, zero-length-ApplicationData
  pass-through, and the no-`supported_groups` ECDHE default-curve
  fallback. Four curated scripts went 0-XFAIL
  (`test-ecdhe-rsa-key-exchange-with-bad-messages`,
  `test-version-numbers`, `test-zero-length-data`,
  `test-ecdhe-rsa-key-exchange`); their XFAIL files were removed.

- T129 — TLS 1.2 DHE / FFDHE curation (closing phase). Added 6
  DHE_RSA cipher suites to the `s-server` TLS 1.2 default list (last,
  lowest preference) so the `test-ffdhe-*` scripts — which hard-code
  `TLS_DHE_RSA_*` — can negotiate. Curated `test-ffdhe-expected-params`
  (3/3) and `test-ffdhe-negotiation` (38/41 — 3 XFAILs for the TLS 1.2
  cipher/group co-negotiation gap). Suite size 56 → 58.
