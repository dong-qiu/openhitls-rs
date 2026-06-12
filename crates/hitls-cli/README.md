# `hitls-cli` — openHiTLS command-line tool

This crate provides the `hitls` binary, a command-line tool for cryptographic
operations modelled on `openssl` and the openHiTLS C `apps/` family.

The list of implemented subcommands is in `src/main.rs::Commands`. This README
documents subcommands that the C reference ships but the Rust port has
intentionally **not** ported, together with the rationale.

## Non-ported subcommands

`#47` (CLI: port 5 missing subcommands) explicitly allows per-subcommand
decisions of either *implement & test* or *document non-port rationale here*.

The table below carries that decision for each C subcommand the issue lists.

| C subcommand | Status | Rationale |
|--------------|--------|-----------|
| `genrsa` | ✅ ported | T189 / PR #269 — see `genrsa.rs` |
| `pkey` (a.k.a. C `key` tests) | ✅ ported (stub → real) | T190 / PR #270 — see `pkey.rs` |
| `sm` | ⏸️ deferred (not ported) | **See dedicated section below** |
| `conf` (utility helpers) | 🟡 partial port | T192 / PR #272 — see `conf_util.rs` + section below |
| `rsa` | TBD | T193 / #47-E |
| `keymgmt` | TBD | T194 / #47-F |

### `sm` — non-port rationale (T191 / #47-C)

The openHiTLS C `sm` subcommand implements an **operator-mode** workflow gated
behind the compile-time `HITLS_APP_SM_MODE` feature. It is not a crypto
primitive but a self-contained access-control subsystem.

#### What the C `sm` subcommand does

1. **Root check** — refuses to run unless `getuid() == 0`
   (`HITLS_APP_ROOT_CHECK_FAIL`).
2. **User database file** — maintains a binary file
   `openhitls_user` in a `WORK_PATH` directory with the layout:

   ```text
   UserParam ::= SEQUENCE OF u32+ {
       version           u32,
       deriveMacId       u32,    -- e.g. CRYPT_MAC_HMAC_SM3
       integrityMacId    u32,
       iter              u32,    -- PBKDF2 iteration count
       salt              [u8; 64],
       saltLen           u32,
       dKey              [u8; 32],
       dKeyLen           u32,
       -- (followed by HMAC tag over the above for integrity)
   }
   ```
3. **Password retrieval** — prompts via `BSL_UI_ReadPwdUtil` (terminal
   echo-off), then derives a key via `HMAC-SM3-PBKDF2(password, salt, iter)`
   and compares with stored `dKey`.
4. **Integrity check** — recomputes the HMAC tag over UserParam fields and
   fails with `HITLS_APP_INTEGRITY_VERIFY_FAIL` if the file has been tampered
   with (the C `TC003` test corrupts the salt directly with `lseek`/`write`
   to exercise this path).
5. **Wrong-password counter** — on a second login attempt with a wrong
   password, returns `HITLS_APP_PASSWD_FAIL` and locks the account.

#### Why the Rust port defers it

This subsystem requires several pieces that the Rust workspace does **not**
currently expose, and that are out of scope for "CLI subcommand test
migration":

- **`UserDb` file format & codec** — the binary layout above must be
  encoded/decoded byte-exact to interoperate with C-side files. There is no
  Rust counterpart and no public spec; the format is internal to C `apps/`.
- **Terminal password prompt** — the C side uses `BSL_UI_ReadPwdUtil` which
  is a custom terminal utility. The Rust workspace has no `rpassword`-style
  facility and no plan to add one as a hitls-cli dependency.
- **HMAC-SM3-PBKDF2 with the C-side constants** — Rust has the primitive
  but the iteration count / salt length / dKey length defaults are baked
  into the C `app_sm.c` source, not specified anywhere migratable.
- **Unix `getuid()` enforcement** — Rust supports it but the wider design
  question "should `hitls` ever refuse to run for non-root users?" is a
  product decision rather than a porting task.

Together, porting `sm` would constitute a 500-line+ subsystem with binary
file-format compatibility, terminal UX, and access-control policy — a
distinct feature, not a test migration.

#### Migrated C TC tally

The C source has **4 TCs** in `test_suite_ut_app_sm.c`
(`UT_HITLS_APP_SM_TC001..TC003` + `TC005`). All four are guarded by
`#ifndef HITLS_APP_SM_MODE -> SKIP_TEST()`, i.e. they only run when the C
build is compiled with the SM mode enabled. The Rust port migrates **0/4**
with the rationale above; the C tests are tracked as scope-cuts in
`docs/c-test-na-list.md`.

#### Follow-up

A future GitHub issue may revisit this if a Rust GM-compliance operator
mode is genuinely needed. For now the decision is documented and frozen.

`TODO(#47-sm-defer)` — pinned in `sm_defer.rs` so the deferral surfaces
as part of `cargo test -p hitls-cli`.

### `conf` — partial port rationale (T192 / #47-D)

The openHiTLS C `apps/src/app_conf.c` is **not a stand-alone subcommand**.
It is a header of three utility helpers used internally by `req` / `x509`:

| C helper | Status | Rust home |
|----------|--------|-----------|
| `HITLS_APP_SplitString` | ✅ ported | `conf_util.rs::split_string` |
| `HITLS_APP_CFG_ProcDnName` | ✅ covered by req.rs | `req.rs::parse_subject` (+ its own unit tests) |
| `HITLS_APP_CONF_ProcExt` | ⏸️ deferred (non-port) | OpenSSL `.cnf` parser — see below |

C TC tally (`test_suite_ut_app_conf.{c,data}`):

- `SplitString_Api_TC001` (3 negative API cases) — migrated as
  `ut_split_api_tc001_*`
- `SplitString_Func_TC001` (8 `.data` rows: simple CSV, empty matrix,
  whitespace trimming, inner-space preservation) — migrated as
  `ut_split_func_tc001_*`
- `SplitString_Error_TC001` (empty-disallowed + capacity overflow) —
  migrated as `ut_split_error_tc001_*`
- `conf_subj_TC001/TC002` — DN parsing is already covered by
  `req.rs::parse_subject` + its own `test_parse_subject_*` unit tests;
  we add `dn_parser_negative_cases_pin_req_module` in `conf_util.rs`
  to pin the cross-coverage relationship.
- `conf_X509Ext_TC001/TC002` — NOT migrated; see below.

#### Why `HITLS_APP_CONF_ProcExt` is deferred

`ProcExt` consumes an OpenSSL `openssl.cnf` style configuration file
(INI-like syntax with `[section]` headers + `key = value` directives,
variable expansion via `${env::VAR}` and `$key`, and stanza-internal
list expansion) and dispatches each extension directive to a callback
that translates it into an `HITLS_X509_Ext` structure. The Rust
workspace has no OpenSSL `.cnf` parser, and porting one entails:

- An INI-style tokenizer covering OpenSSL's specific quoting + line
  continuation rules.
- Variable resolution (`$key` within the same section, `${env::VAR}`
  for environment lookups, `${section::key}` for cross-section
  reference) — features the OpenSSL `.cnf` parser supports verbatim.
- Per-extension parsers: `subjectAltName = DNS:foo.example,IP:1.2.3.4`,
  `basicConstraints = CA:true,pathlen:0`, `keyUsage = critical,
  digitalSignature, keyEncipherment`, etc. The C side wires these into
  ASN.1 structures via the X509Ext_TC001 callback.

This is a distinct subsystem in the same spirit as `sm` — porting it
would be a feature of its own, not a unit-test migration. The C
`X509Ext_TC001/TC002` TCs are tracked as scope cuts in `docs/c-test-na-list.md`.

`TODO(#47-conf-cnf)` — revisit if an OpenSSL `.cnf` parser is needed
for `req -extfile` / `x509 -extfile` workflows. Pinned in
`conf_util.rs` module doc.
