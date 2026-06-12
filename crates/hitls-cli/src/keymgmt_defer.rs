//! `keymgmt` subcommand — **NOT PORTED** (decision documented in
//! `crates/hitls-cli/README.md` per #47 / T194). Closes the #47 6-PR
//! series.
//!
//! Same non-port pattern as `sm_defer.rs` (T191): keymgmt is the
//! second GM-compliance operator-mode CLI subcommand in the openHiTLS
//! C source, gated behind the same compile-time `HITLS_APP_SM_MODE`
//! feature. All 19 `UT_HITLS_APP_KEYMGMT_TC*` cases are
//! `#ifndef HITLS_APP_SM_MODE -> SKIP_TEST()`.
//!
//! The keymgmt subsystem manages a UUID-indexed key database with:
//!
//! - Create (`create`) keys for SM4 / SM4-XTS / SM2 / MAC algorithms
//! - Find (`find`) by UUID
//! - Derive (`derive`) sub-keys via PBKDF2
//! - Delete (`delete`) one or many UUIDs
//! - Erase all keys (`erase`)
//! - Compute MAC via stored key (`mac`)
//! - SM2 sign/verify via stored key
//! - Status / version / self-test endpoints
//!
//! Together with `sm` (the operator authentication layer from T191),
//! this is a ~2K-LOC GM-mode access-control subsystem — a feature in
//! its own right, not a test migration.
//!
//! `TODO(#47-keymgmt-defer)` — revisit when a Rust GM-compliance
//! operator mode is genuinely needed. Co-deferred with T191
//! `TODO(#47-sm-defer)`; both must land together because keymgmt
//! depends on `sm`'s user database for authorization.

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    fn read_crate_readme() -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md");
        fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("crate README missing at {path:?}: {e}"))
    }

    #[test]
    fn keymgmt_defer_readme_exists_and_explains_non_port() {
        let readme = read_crate_readme();
        assert!(
            readme.contains("`keymgmt` — non-port rationale"),
            "README must carry the keymgmt non-port rationale section heading"
        );
        assert!(
            readme.contains("HITLS_APP_SM_MODE"),
            "README must reference the C compile-time feature flag (shared with `sm`)"
        );
        assert!(
            readme.contains("TODO(#47-keymgmt-defer)"),
            "README must pin the follow-up TODO marker"
        );
    }

    #[test]
    fn keymgmt_defer_readme_lists_19_c_tcs() {
        // The C source has 19 TCs (TC001..TC019). All are
        // `#ifndef HITLS_APP_SM_MODE -> SKIP_TEST()` gated. README
        // must state "0/19" so the scope decision is unambiguous.
        let readme = read_crate_readme();
        assert!(
            readme.contains("0/19") || readme.contains("0 / 19"),
            "README must explicitly state 0-of-19 C TCs migrated"
        );
    }

    #[test]
    fn keymgmt_defer_readme_lists_subsystem_components() {
        // Pin that the rationale enumerates each subsystem capability
        // so a future contributor sees the full picture.
        let readme = read_crate_readme();
        for needle in &[
            "UUID-indexed", // key database
            "create",       // primary CLI ops
            "find",
            "derive",
            "delete",
            "erase",
        ] {
            assert!(
                readme.contains(needle),
                "README must mention `{needle}` as part of the deferred keymgmt subsystem"
            );
        }
    }

    #[test]
    fn keymgmt_defer_codeferred_with_sm() {
        // Cross-reference assertion: keymgmt depends on sm's user DB
        // for authorization, so the two TODOs must be co-mentioned.
        let readme = read_crate_readme();
        assert!(
            readme.contains("Co-deferred") || readme.contains("co-deferred"),
            "README must note keymgmt is co-deferred with sm (shared HITLS_APP_SM_MODE)"
        );
    }
}
