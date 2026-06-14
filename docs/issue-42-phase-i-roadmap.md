# Phase I — Roadmap for the 49 audit-pinned Phase B anchors

**Status**: Planning — emitted by Phase B T236 closeout as the
deferred-work roadmap.
**Tracking issue**: [#42](https://github.com/dong-qiu/openhitls-rs/issues/42)
**Predecessor**: Phase B (T112 + T233-T236) — audit-pin closure of
49 deeper `#43-#61` TODO anchors.

This document captures the substantive crypto-implementation and
codec-hardening work that Phase B deliberately deferred. Each Phase B
anchor (43 audit pins across `migrated_phase_b_audit_pins.rs`) is
mapped here to a concrete "what-to-close" pointer so a future Phase I
implementor can pick up the work without re-doing the audit.

## 1. Phase I work estimate

Total: ~5-7 days across 4-6 sub-PRs, organised by crypto/codec family
rather than per-anchor.

| Phase I sub-task | TODO families closed | Est. days | Primary crate |
|------------------|----------------------|----------:|---------------|
| I-1: RSA-PSS PKCS#8 codec | `#47-pkey-rsa-pss` (3) | 1.5 | hitls-pki + hitls-cli |
| I-2: SM2 PKCS#8 codec | `#47-pkey-sm2` (3) | 1.0 | hitls-pki + hitls-cli |
| I-3: Brainpool + NIST P-224 curves | `#47-pkey-brainpool` (1) + `#47-pkey-p224` (1) | 2.0 | hitls-crypto + hitls-pki |
| I-4: PBES2 encrypted PKCS#8 | `#47-pkey-encrypted-pkcs8` (2) + `#47-genrsa-encryption` (2) | 1.0 | hitls-pki + hitls-cli |
| I-5: RSA codec extract refactor | `#47-rsa-codec-extract` (2) | 0.5 | hitls-pki |
| I-6: TLS builder + custom-ext + SNI hardening | `#46-*` (4) + `#58-*` (4) + `#61-*` (4) | 1.0 | hitls-tls |

`#47-conf-cnf` (1) + `#47-sm-defer` (3) + `#47-keymgmt-defer` (3) are
**design decisions deferred to product-roadmap review** — they will
be re-scoped only if a use case surfaces (OpenSSL `.cnf` parser parity
or GM-compliance operator-mode driver).

## 2. Per-anchor "what-to-close" pointers

### 2.1 `#44-strict-version` (3 sites, T112)

- **Anchor location**: `crates/hitls-pki/tests/migrated_csr_negative_parse.rs`
- **RFC reference**: RFC 2986 §4.1 — `CertificationRequestInfo.version`
  MUST be 0 (v1)
- **Current behaviour**: parser stores corrupted version verbatim
- **What to close**: tighten `Csr::parse` to return
  `Err(PkiError::InvalidCsr)` when `version != 0`; update the existing
  `expect("parser stores the corrupted version verbatim ...")` test
  assertion to `expect_err(PkiError::InvalidCsr)`
- **Phase B pin**: T112 `t112_csr_rfc2986_version_codepoint_pin`

### 2.2 `#45-strict-version` (3 sites, T112)

- **Anchor location**: `crates/hitls-pki/tests/migrated_crl_rfc5280_verify.rs`
- **RFC reference**: RFC 5280 §5.1.2.1 — CRL `version` MUST be 1 (v2)
  when extensions present
- **Current behaviour**: parser tolerates invalid version
- **What to close**: tighten `Crl::parse` to return
  `Err(PkiError::InvalidCrl)` when `extensions.is_some() &&
  version != 1`; flip the `expect("Rust parser tolerates ...")`
  assertion accordingly
- **Phase B pin**: T112 `t112_crl_rfc5280_version_codepoint_pin`

### 2.3 `#45-aki-match` (2 sites, T112)

- **Anchor location**: `crates/hitls-pki/tests/migrated_crl_rfc5280_verify.rs`
- **RFC reference**: RFC 5280 §5.2.1 + §4.2.1.1 — AuthorityKeyIdentifier
  ↔ SubjectKeyIdentifier match required for unambiguous chain
- **Current behaviour**: CRL matched to issuer by DN only
- **What to close**: extend `crl_matches_issuer(crl, ca)` to also
  compare `crl.aki()` with `ca.ski()` (both Option, use as-strong-as-
  possible signal — both present → must match; both absent → fall
  through to DN)
- **Phase B pin**: T112 `t112_crl_aki_match_anchor_preserved_in_source`

### 2.4 `#47-pkey-rsa-pss` (3 sites, T233 → I-1)

- **Anchor location**: `crates/hitls-cli/src/pkey.rs` (module doc + 2
  `"not implemented"` returns)
- **RFC reference**: RFC 8017 §C.1 — `id-RSASSA-PSS` OID
  `1.2.840.113549.1.1.10`
- **Current behaviour**: `Pkcs8PrivateKey::RsaPss(_)` arms return
  `"RSA-PSS PKCS#8 re-encoding not implemented"`
- **What to close**: add `encode_rsa_pss_pkcs8_der` +
  `encode_rsa_pss_spki_der` helpers in `hitls-pki::pkcs8`; wire the
  `RsaPss` arms in `pkey.rs` `encode_priv` + `encode_pubout` to call
  them; cover with PEM round-trip integration test
- **Phase B pin**: T233 `t233_rsa_pss_pkcs8_anchor_preserved_in_source`
  + `t233_rsa_pss_oid_codepoint_pin`

### 2.5 `#47-pkey-sm2` (3 sites, T233 → I-2)

- **Anchor location**: `crates/hitls-cli/src/pkey.rs`
- **RFC reference**: GM/T 0006 / RFC 8998 — sm2 curve OID
  `1.2.156.10197.1.301`
- **Current behaviour**: `Pkcs8PrivateKey::Sm2(_)` arms return
  `"SM2 PKCS#8 re-encoding not implemented"`
- **What to close**: extend the existing EC PKCS#8 codec to dispatch
  on `oid_to_curve_id(sm2_oid) = Some(CurveId::Sm2)`; reuse the I89
  `Pkcs8PrivateKey::Sm2` variant; wire `encode_priv` + `encode_pubout`
- **Phase B pin**: T233 `t233_sm2_pkcs8_anchor_preserved_in_source`
  + `t233_sm2_pkcs8_oid_codepoint_pin`

### 2.6 `#47-pkey-brainpool` (1 site, T233 → I-3)

- **Anchor location**: `crates/hitls-cli/src/pkey.rs` module doc
- **RFC reference**: RFC 5639 §A.1 — `brainpoolP256r1` OID
  `1.3.36.3.3.2.8.1.1.7` (also P-384/P-512)
- **Current behaviour**: Brainpool curves are not implemented in
  hitls-crypto
- **What to close**: this is the biggest single Phase I task — implement
  Brainpool curve arithmetic in `hitls-crypto::ec` (P-256/P-384/P-512
  variants per RFC 5639); add OID dispatch in `hitls-pki::pkcs8`;
  wire into `pkey.rs` EC arm
- **Phase B pin**: T233 `t233_brainpool_anchor_preserved_in_source`
  + `t233_brainpool_p256_oid_codepoint_pin`

### 2.7 `#47-pkey-p224` (1 site, T233 → I-3)

- **Anchor location**: `crates/hitls-cli/src/pkey.rs` module doc
- **RFC reference**: RFC 5480 / SEC 2 — secp224r1 OID `1.3.132.0.33`
- **Current behaviour**: NIST P-224 is not implemented
- **What to close**: implement P-224 curve arithmetic in
  `hitls-crypto::ec::p224`; add OID dispatch; wire into `pkey.rs`
- **Phase B pin**: T233 `t233_p224_anchor_preserved_in_source`
  + `t233_nist_p224_oid_codepoint_pin`

### 2.8 `#47-pkey-encrypted-pkcs8` (2 sites, T233 → I-4)

- **Anchor location**: `crates/hitls-cli/src/pkey.rs`
- **RFC reference**: RFC 8018 §A.4 PBES2 OID `1.2.840.113549.1.5.13`
  + RFC 8018 §A.2 PBKDF2 OID `1.2.840.113549.1.5.12`
- **Current behaviour**: `-passin <pass>` / `-passout <pass>` flags
  not wired
- **What to close**: implement PBES2 (PBKDF2 + AES-CBC) encoding /
  decoding in `hitls-pki::pkcs8`; add `-passin` / `-passout`
  command-line flag handling to `pkey.rs` + `genrsa.rs`
- **Phase B pin**: T233 `t233_encrypted_pkcs8_anchor_preserved_in_source`
  + `t233_pbes2_pbkdf2_oid_codepoint_pin`

### 2.9 `#47-genrsa-encryption` (2 sites, T234 → I-4)

- **Anchor location**: `crates/hitls-cli/src/genrsa.rs`
- **RFC reference**: RFC 7468 §10 — PEM label `RSA PRIVATE KEY` vs
  `ENCRYPTED PRIVATE KEY`
- **Current behaviour**: `-cipher` flag accepted but no encryption
  applied (writes unencrypted PEM)
- **What to close**: shares PBES2 work with `#47-pkey-encrypted-pkcs8`
  (I-4); switch PEM label to `ENCRYPTED PRIVATE KEY` when `-cipher`
  given; emit PBES2 ciphertext body
- **Phase B pin**: T234 `t234_genrsa_encryption_anchor_preserved_in_source`
  + `t234_genrsa_pem_label_constant_pin`

### 2.10 `#47-rsa-codec-extract` (2 sites, T234 → I-5)

- **Anchor location**: `crates/hitls-cli/src/rsa_cmd.rs`
- **Current behaviour**: RSA PKCS#1 CRT-form encoder duplicated
  inside `rsa_cmd` rather than extracted to `hitls-pki`
- **What to close**: extract the `rsa_pkcs1_encode_*` helpers from
  `rsa_cmd.rs` into `hitls-pki::rsa`; call back from `rsa_cmd.rs`;
  remove the duplicate
- **Phase B pin**: T234 `t234_rsa_codec_extract_anchor_preserved_in_source`
  + `t234_rsa_pkcs1_oid_codepoint_pin`

### 2.11 `#47-conf-cnf` (1 site, T234 → Phase I product review)

- **Anchor location**: `crates/hitls-cli/src/conf_util.rs`
- **What to close**: this is a **product-roadmap decision**, not a
  pure implementation task. If OpenSSL `.cnf` config-file
  compatibility is required for interop, implement a `[section]`
  grammar parser; otherwise document the omission in the CLI README
- **Phase B pin**: T234 `t234_conf_cnf_anchor_preserved_in_source`

### 2.12 `#47-sm-defer` (3 sites, T234 → Phase I product review)

- **Anchor location**: `crates/hitls-cli/src/sm_defer.rs`
- **What to close**: depends on a Rust GM-compliance operator-mode
  decision; if pursued, build the `sm` subcommand wrapping the
  hitls-tls TLCP plumbing; otherwise keep the stub
- **Phase B pin**: T234 `t234_sm_defer_anchor_preserved_in_source`

### 2.13 `#47-keymgmt-defer` (3 sites, T234 → Phase I product review)

- **Anchor location**: `crates/hitls-cli/src/keymgmt_defer.rs`
- **What to close**: linked to `#47-sm-defer` via the GM-compliance
  roadmap; both must land together
- **Phase B pin**: T234 `t234_keymgmt_defer_anchor_preserved_in_source`

### 2.14 `#46-version-bounds` + `#46-groups-empty` + `#46-sigalg-empty` + `#46-plan` (4 sites, T235 → I-6)

- **Anchor location**: `crates/hitls-tls/tests/migrated_interface_tlcp_audit.rs`
- **What to close**: harden `TlsConfig::builder()` to reject
  `min_version > max_version`, empty `supported_groups`, empty
  `signature_algorithms`; emit `Err(TlsError::InvalidConfig)`
- **Phase B pin**: T235 `t235_tlcp_builder_46_anchors_preserved_in_source`
  + `t235_tlcp_builder_version_bound_field_names_pin`

### 2.15 `#58-dup-check` (2 sites, T235 → I-6)

- **Anchor location**: `tests/interop/tests/custom_ext.rs`
- **What to close**: `TlsConfig::custom_extension(ext_type, ...)`
  should track registered `ext_type` values in a `HashSet` and
  return `Err(TlsError::DuplicateExtension(u16))` on duplicate
- **Phase B pin**: T235 `t235_custom_extension_dup_check_anchor_preserved`

### 2.16 `#58-context-gap` (2 sites, T235 → I-6)

- **Anchor location**: `tests/interop/tests/custom_ext.rs`
- **RFC reference**: RFC 8446 §4.2 + §A.3 — custom extensions can be
  wired into 6 contexts: CH, SH, EE, CR, Cert, NewSessionTicket
- **Current behaviour**: Rust wires only at CH/SH boundary
- **What to close**: extend `TlsConfig::custom_extension` to take a
  `Context: u32` bitmask; thread the bitmask through the handshake
  state machine; emit/parse in each enabled context
- **Phase B pin**: T235 `t235_custom_extension_context_gap_anchor_preserved`
  + `t235_custom_extension_context_constants_pin`

### 2.17 `#61-codec-gap` (3 sites, T235 → I-6)

- **Anchor location**: `tests/interop/tests/sni_boundary.rs`
- **RFC reference**: RFC 6066 §3 — `server_name` extension codepoint
  0; `host_name` NameType 0
- **What to close**: tighten the SNI decoder to (1) reject empty
  hostname; (2) reject multi-entry HostName list; (3) reject IP
  literals (deferred to `#61-design` for product review)
- **Phase B pin**: T235 `t235_sni_codec_gap_anchor_preserved`
  + `t235_sni_extension_codepoint_pin`

### 2.18 `#61-design` (1 site, T235 → Phase I product review)

- **Anchor location**: `tests/interop/tests/sni_boundary.rs`
- **What to close**: design decision — RFC 6066 §3 says SNI is for
  DNS names, not IP literals, but interop reality is fuzzy. Phase I
  must decide: strict (reject IP literals) or lenient (current).
- **Phase B pin**: T235 `t235_sni_design_anchor_preserved`

## 3. Phase I acceptance criteria

- [ ] 6 sub-PRs implementing I-1 through I-6 above
- [ ] All Phase B anchors flipped from `TODO(...)` to either (a)
      removed because closed, or (b) replaced with
      `H-RESOLVED(...) by Phase I` annotation per the T223/T228
      layered closeout methodology
- [ ] Phase B `migrated_phase_b_audit_pins.rs` test file remains
      passing — each Phase B pin's anchor-preservation assertion must
      either be updated (if anchor removed) or continue passing (if
      annotation layered)
- [ ] `docs/issue-42-phase-i-roadmap.md` (this doc) flips §1 status
      to ✅ Complete when all 6 sub-PRs land
- [ ] DEV_LOG **Phase I** entries; PROMPT_LOG entries
