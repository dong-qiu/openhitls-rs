// Phase J-3 — SPAKE2+ (RFC 9383) round-trip migration.
//
// Source: openHiTLS C SDV auth/pake/test_suite_sdv_pake.data
//         (SDV_CRYPT_EAL_SPAKE2PLUS_TC001, RFC 9383 test vectors).
//
// NOT byte-exact. The C `.data` carries 14 RFC 9383 vectors across cipher
// suites P-256/P-384/P-521 × SHA-256/512 × HMAC/CMAC-AES, each pinning the
// ephemeral scalars `x` / `y` (via a stubbed RNG) so `shareP` / `shareV` /
// `kShared` / `confirmP` / `confirmV` are reproducible. The Rust
// `hitls_auth::spake2plus` implementation supports **only** the
// P-256 + SHA-256 + HMAC-SHA-256 suite (group/hash/MAC are hardcoded) and
// `generate_share` draws the ephemeral scalar internally via the DRBG with no
// injection hook. So the C share/confirm bytes are NOT reproducible by the Rust
// port. See `docs/c-test-na-list.md` "Structural gaps" → SPAKE2+ for the
// byte-exact unblock path (multi-suite support + `kat-nonce`-gated scalar
// injection + RFC 9383 KDF/confirm verification).
//
// What IS migrated (this file, T257; SM9/T158 round-trip methodology): the
// P-256-SHA256-HMAC vector's registration triple `(w0, w1, L)`. We drive the
// Rust prover + verifier through a full SPAKE2+ exchange with these values; the
// round-trip succeeding (mutual confirmation + equal shared key) proves the
// RFC 9383 vector's `(w0, w1, L)` registration record is self-consistent under
// the Rust math (in particular `L = w1·G` holds — otherwise confirmation would
// fail), and that the vector's password-derived values are usable by the port.

#![cfg(feature = "spake2plus")]

use hitls_auth::spake2plus::{Spake2Plus, Spake2Role};
use hitls_utils::hex::hex;

/// Registration triple from the C SDV `SPAKE2PLUS_TC001`
/// `SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256` (RFC 9383) vector:
/// `(w0, w1, L)` where `L = w1·G` (uncompressed P-256 point, 65 bytes).
fn p256_vector() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let w0 = hex("bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3");
    let w1 = hex("7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba");
    let l = hex(
        "04eb7c9db3d9a9eb1f8adab81b5794c1f13ae3e225efbe91ea487425854c7fc0\
         0f00bfedcbd09b2400142d40a14f2064ef31dfaa903b91d1faea7093d835966efd",
    );
    (w0, w1, l)
}

/// Full SPAKE2+ exchange driven by the RFC 9383 P-256 vector's `(w0, w1, L)`:
/// both parties confirm each other and derive the same shared key.
#[test]
fn tc_spake2plus_rfc9383_p256_vector_roundtrip() {
    let (w0, w1, l) = p256_vector();

    let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
    let mut verifier = Spake2Plus::new(Spake2Role::Verifier).unwrap();
    prover.setup(&w0, &w1).unwrap();
    verifier.setup(&w0, &l).unwrap();

    let share_p = prover.generate_share().unwrap();
    let share_v = verifier.generate_share().unwrap();
    // RFC 9383 P-256 shares are uncompressed points (0x04 || x || y = 65 bytes).
    assert_eq!(share_p.len(), 65);
    assert_eq!(share_p[0], 0x04);
    assert_eq!(share_v.len(), 65);

    let ke_p = prover.process_share(&share_v).unwrap();
    let ke_v = verifier.process_share(&share_p).unwrap();

    let conf_p = prover.get_confirmation().unwrap();
    let conf_v = verifier.get_confirmation().unwrap();

    // Mutual key confirmation succeeds → (w0, w1, L) is a consistent triple.
    assert!(verifier.verify_confirmation(&conf_p).unwrap());
    assert!(prover.verify_confirmation(&conf_v).unwrap());
    // Both sides derive the identical shared secret.
    assert_eq!(ke_p, ke_v);
}

/// If the verifier registers an `L` that does not match the prover's `w1`
/// (here: the prover uses a tampered `w1`), key confirmation MUST fail.
#[test]
fn tc_spake2plus_rfc9383_p256_vector_mismatched_w1_rejected() {
    let (w0, w1, l) = p256_vector();
    let mut bad_w1 = w1.clone();
    bad_w1[0] ^= 0x01;

    let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
    let mut verifier = Spake2Plus::new(Spake2Role::Verifier).unwrap();
    prover.setup(&w0, &bad_w1).unwrap();
    verifier.setup(&w0, &l).unwrap();

    let share_p = prover.generate_share().unwrap();
    let share_v = verifier.generate_share().unwrap();
    let _ = prover.process_share(&share_v).unwrap();
    let _ = verifier.process_share(&share_p).unwrap();

    let conf_p = prover.get_confirmation().unwrap();
    let conf_v = verifier.get_confirmation().unwrap();
    assert!(!verifier.verify_confirmation(&conf_p).unwrap());
    assert!(!prover.verify_confirmation(&conf_v).unwrap());
}

/// A wrong `w0` (shared password element) on the verifier side must also break
/// confirmation, even with the correct `L`.
#[test]
fn tc_spake2plus_rfc9383_p256_vector_wrong_w0_rejected() {
    let (w0, w1, l) = p256_vector();
    let mut bad_w0 = w0.clone();
    bad_w0[0] ^= 0x01;

    let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
    let mut verifier = Spake2Plus::new(Spake2Role::Verifier).unwrap();
    prover.setup(&w0, &w1).unwrap();
    verifier.setup(&bad_w0, &l).unwrap();

    let share_p = prover.generate_share().unwrap();
    let share_v = verifier.generate_share().unwrap();
    let _ = prover.process_share(&share_v).unwrap();
    let _ = verifier.process_share(&share_p).unwrap();

    let conf_p = prover.get_confirmation().unwrap();
    assert!(!verifier.verify_confirmation(&conf_p).unwrap());
}
