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

## CI hookup

`.github/workflows/tlsfuzzer.yml` runs the recommended scripts above
on `workflow_dispatch` and on a weekly schedule (Mon 06:00 UTC). It
is **not** part of the required PR check set — see the comment at
the top of that file for the rationale. Each script is run with
`continue-on-error`, so a single regression doesn't mask the rest,
and the per-script logs are uploaded as the `tlsfuzzer-logs`
artifact for triage.

To run it manually: GitHub Actions → tlsfuzzer → "Run workflow".

## Phase reference

- T88 — fixed two TLS 1.3 CCS conformance gaps surfaced by
  `test-tls13-ccs.py` and added the in-tree pinning tests in
  `tests/interop/tests/protocol_attacks.rs`. The same change set
  fixed the server-side write-key timing (RFC 8446 §A.1: switch
  to `server_application_traffic_secret_0` immediately after
  sending Finished, not after receiving client Finished) so that
  alerts emitted between the two Finished messages decrypt under
  the key the peer is actually using.
