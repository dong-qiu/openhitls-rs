//! `sm` subcommand — **NOT PORTED** (decision documented in
//! `crates/hitls-cli/README.md` per #47 / T191).
//!
//! The openHiTLS C `apps/src/app_sm.c` implements a GM-compliance operator
//! mode behind the compile-time `HITLS_APP_SM_MODE` feature. It is not a
//! crypto primitive but a self-contained access-control subsystem
//! (user-database file with HMAC-SM3-PBKDF2 derived key, root-only execution
//! check, terminal password prompt, wrong-password counter). Porting it
//! would require a 500-line+ subsystem with binary file-format compatibility,
//! terminal UX, and access-control policy — out of scope for "CLI subcommand
//! test migration".
//!
//! `#47` acceptance criteria explicitly allows this kind of deferral:
//!
//! > Decide per-subcommand: implement & test, or document non-port rationale
//! > in `crates/hitls-cli/README.md`
//!
//! The README in this crate carries the full rationale. The tests below
//! pin that the decision is on the record: the README exists, mentions
//! `sm`, and lists the deferral with the `TODO(#47-sm-defer)` marker.
//!
//! `TODO(#47-sm-defer)` — revisit if a Rust GM-compliance operator mode is
//! ever needed.

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    fn read_crate_readme() -> String {
        // CARGO_MANIFEST_DIR points at this crate's root at test time.
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md");
        fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("crate README missing at {path:?}: {e}"))
    }

    #[test]
    fn sm_defer_readme_exists_and_explains_non_port() {
        let readme = read_crate_readme();
        assert!(
            readme.contains("`sm` — non-port rationale"),
            "README must carry the sm non-port rationale section heading"
        );
        assert!(
            readme.contains("HITLS_APP_SM_MODE"),
            "README must reference the C compile-time feature flag"
        );
        assert!(
            readme.contains("TODO(#47-sm-defer)"),
            "README must pin the follow-up TODO marker"
        );
    }

    #[test]
    fn sm_defer_readme_lists_4_c_tcs() {
        let readme = read_crate_readme();
        // The C source has 4 TCs (TC001/TC002/TC003/TC005). The README must
        // state "0/4" migrated so the scope decision is unambiguous.
        assert!(
            readme.contains("0/4") || readme.contains("0 / 4"),
            "README must explicitly state 0-of-4 C TCs migrated"
        );
    }

    #[test]
    fn sm_defer_readme_lists_subsystem_components() {
        // Pin that the rationale enumerates each Rust-workspace gap so a
        // future contributor sees the full picture.
        let readme = read_crate_readme();
        for needle in &[
            "UserDb",             // file format
            "PBKDF2",             // KDF
            "getuid",             // root check
            "BSL_UI_ReadPwdUtil", // terminal password prompt
        ] {
            assert!(
                readme.contains(needle),
                "README must mention `{needle}` as part of the deferred subsystem"
            );
        }
    }
}
