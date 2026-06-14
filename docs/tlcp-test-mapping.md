# TLCP test mapping — Phase E audit-pin coverage

**Emitted by**: Phase E T245 closeout (see
`docs/issue-42-phase-e-plan.md`).

**Purpose**: cross-reference the C SDV `interface_tlcp` 718-row
inventory against the Rust audit-pin coverage shipped by Phase E
(T115 + T242-T245) and the existing TLCP integration test files.

This document complements `docs/issue-42-phase-e-plan.md` §2
classification table by showing **where each class is pinned in
the Rust test tree**.

## 1. 3-class breakdown recap

| Class | Share | Row count | Disposition |
|-------|------:|----------:|-------------|
| Behaviour-class | ~40 % | ~287 rows | Audit-pin via T242 + T243 |
| API-form class | ~50 % | ~359 rows | Audit-pin via T244 |
| Exempt | ~10 % | ~72 rows | Documented as non-portable in `issue-42-phase-e-plan.md` §2 |

## 2. Behaviour-class → Rust pin map

### 2.1 GM cert verify (T242 — 10 pins)

| C SDV facet | Rust pin | Source coverage |
|-------------|----------|-----------------|
| SM2 curve OID dispatch | `t242_sm2_curve_oid_identity_pin` | `hitls_pki::pkcs8::oid_to_curve_id` (Sm2 variant) |
| SM3 hash OID dispatch | `t242_sm3_hash_oid_identity_pin` | `crypt::transcript::TranscriptHash::new(HashAlgId::Sm3)` |
| SM2-with-SM3 sig OID dispatch | `t242_sm2_with_sm3_sig_oid_identity_pin` | `crypt::sm2` verify path |
| TLCP cipher GCM variants | `t242_tlcp_cipher_suite_gcm_codepoint_pin` | `crypt::CipherSuite::TLCP_ECC_SM4_GCM_SM3` etc. |
| TLCP version codepoint | `t242_tlcp_version_codepoint_pin` | `TlsVersion::Tlcp` |
| TLCP source files present | `t242_tlcp_handshake_source_files_present` | `connection_tlcp.rs` + `handshake/{client,server}_tlcp.rs` etc. |
| Client SM3 transcript hash | `t242_tlcp_client_uses_sm3_transcript_hash_pin` | `handshake/client_tlcp.rs` `HashAlgId::Sm3` |
| Server SM3 transcript hash | `t242_tlcp_server_uses_sm3_transcript_hash_pin` | `handshake/server_tlcp.rs` `HashAlgId::Sm3` |
| Dual-cert architecture | `t242_tlcp_dual_cert_architecture_source_pin` | TLCP source multi-file scan |
| Plan-doc cross-coverage | `t242_audit_phase_e_behaviour_class_plan_docs_in_sync` | this plan doc |

### 2.2 Handshake variants ECDHE/ECC × GCM/CBC (T243 — 10 pins)

| C SDV facet | Rust pin | Source coverage |
|-------------|----------|-----------------|
| SM4 block cipher OID | `t243_sm4_block_cipher_oid_identity_pin` | GM/T 0002 OID |
| `tlcp.rs` test floor | `t243_tlcp_integration_tests_target_floor_pin` | `tests/interop/tests/tlcp.rs` ≥11 tests |
| SM4 in record layer | `t243_tlcp_record_encryption_uses_sm4_pin` | `record/encryption_tlcp.rs` |
| TLCP handshake codec source | `t243_tlcp_handshake_codec_source_file_present` | `handshake/codec_tlcp.rs` |
| ECDHE key-exchange path | `t243_tlcp_ecdhe_key_exchange_source_pin` | `handshake/client_tlcp.rs` |
| ECC key-exchange path | `t243_tlcp_ecc_key_exchange_source_pin` | TLCP source multi-file scan |
| CertificateVerify wire format | `t243_tlcp_cert_verify_handling_source_pin` | TLCP handshake multi-file scan |
| ChangeCipherSpec ordering | `t243_tlcp_change_cipher_spec_source_pin` | TLCP source multi-file scan |
| Finished message MAC | `t243_tlcp_finished_message_source_pin` | TLCP handshake multi-file scan |
| Plan-doc cross-coverage | `t243_audit_phase_e_behaviour_remaining_plan_docs_in_sync` | this plan doc |

## 3. API-form class → Rust pin map (T244 — 10 pins)

| C SDV `HITLS_CFG_Set*` family | Rust `TlsConfigBuilder` pin |
|-------------------------------|----------------------------|
| `HITLS_CFG_SetCipherSuites` | `t244_tls_config_builder_cipher_suites_setter_pin` (`fn cipher_suites`) |
| `HITLS_CFG_SetGroups` | `t244_tls_config_builder_supported_groups_setter_pin` (`fn supported_groups` / `fn groups`) |
| `HITLS_CFG_SetSignatureAlgorithms` | `t244_tls_config_builder_signature_algorithms_setter_pin` (`fn signature_algorithms`) |
| `HITLS_CFG_SetServerCertificate` family | `t244_tls_config_builder_server_cert_setters_pin` (multi-anchor scan) |
| `HITLS_CFG_SetVerifyPeer` | covered by `t244_tls_config_builder_core_setters_pin` (`fn verify_peer`) |
| `HITLS_CFG_SetMin/MaxVersion` | covered by `t244_tls_config_builder_core_setters_pin` (`fn min_version` / `fn max_version`) |
| `HITLS_CFG_SetRole` | covered by `t244_tls_config_builder_core_setters_pin` (`fn role`) |
| Builder finalisation | `t244_tls_config_builder_core_setters_pin` (`fn build`) |
| TLCP-specific dual-cert setter | covered by `t242_tlcp_dual_cert_architecture_source_pin` (cross-phase) |
| TLCP-specific knobs (T199 anchors) | `t244_tlcp_specific_config_knobs_cross_pin_t199` |

## 4. Exempt class

The ~72 exempt rows are C SDV cases that test the C memory-model
specifically (`HITLS_X509_CTX_GET_OPS` get/put cycles, C-style
opaque-context lifecycle, etc.). The Rust port uses Rust ownership
semantics instead, so these rows have no Rust analogue. See
`docs/issue-42-phase-e-plan.md` §2 "Exempt" class for the
disposition rationale.

## 5. Cross-phase coverage matrix

| Coverage facet | Phase | Test file |
|----------------|-------|-----------|
| TLCP integration handshakes | Pre-Phase E | `tests/interop/tests/tlcp.rs` (11 tests) |
| TLCP consistency mutations | Phase F (T209-T210) | `tests/interop/tests/tlcp_consistency.rs` (22 tests) |
| `TlsConfig` builder edge cases | Phase B-4 (T235) | `tests/migrated_interface_tlcp_audit.rs` (T199 + 4 `#46-*` anchors) |
| TLCP behaviour + API audit | Phase E (T115 + T242-T245) | `tests/migrated_phase_e_audit_pins.rs` (43 tests) |
| TLCP cross-facet floor | Phase F follow-up (T246) | `tests/migrated_phase_f_audit_pins.rs` (TLCP-specific subset) |

## 6. Provenance + plan-doc anchors

- Phase E plan doc: `docs/issue-42-phase-e-plan.md`
- 5-sub-PR series: T115 + T242-T245
- Audit-pin file: `crates/hitls-tls/tests/migrated_phase_e_audit_pins.rs`
- Methodology lineage: see Phase E plan §8 (5 codified patterns)
- Complete C→Rust test migration parity milestone: see Phase E plan §9

This doc is the canonical TLCP test-mapping artefact and is referenced
by the Phase E plan doc + the Phase E T245 closeout pin
`t245_tlcp_test_mapping_doc_emitted`.
