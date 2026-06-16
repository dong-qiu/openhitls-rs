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

/// Byte-exact prover-side migration of the RFC 9383 P-256 vector (T281, WP-A).
///
/// Injects the vector's ephemeral scalar `x` via the `kat-nonce`-gated
/// `generate_share_with_scalar`, drives the prover with the vector's `shareV`,
/// and asserts ALL outputs byte-exact against the independent C SDV vector:
/// `shareP`, `K_shared`, `confirmP`, and that the vector's `confirmV` verifies.
/// This is true RFC 9383 ground-truth verification — only possible after the
/// I161 key-schedule conformance fix (RFC 9383 §3.4 HKDF schedule).
#[cfg(feature = "kat-nonce")]
#[test]
fn tc_spake2plus_rfc9383_p256_vector_byte_exact() {
    let (w0, w1, _l) = p256_vector();
    // Vector fields x / shareP / shareV / kShared / confirmP / confirmV
    // (SPAKE2PLUS_TC001, P256-SHA256-HKDF-SHA256-HMAC-SHA256).
    let x = hex("d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539");
    let share_p_expected = hex(
        "04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0\
         c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727",
    );
    let share_v = hex(
        "04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810f\
         b5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048",
    );
    let k_shared = hex("0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7");
    let confirm_p = hex("926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527");
    let confirm_v = hex("9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68");

    let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
    // RFC 9383 identities from the vector (Context = suite string, idProver =
    // "client", idVerifier = "server").
    prover.set_identities(
        b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors",
        b"client",
        b"server",
    );
    prover.setup(&w0, &w1).unwrap();

    #[allow(deprecated)]
    let share_p = prover.generate_share_with_scalar(&x).unwrap();
    assert_eq!(share_p, share_p_expected, "shareP = x·G + w0·M byte-exact");

    let ke = prover.process_share(&share_v).unwrap();
    assert_eq!(
        ke, k_shared,
        "K_shared (RFC 9383 §3.4 HKDF 'SharedKey') byte-exact"
    );

    let cp = prover.get_confirmation().unwrap();
    assert_eq!(
        cp, confirm_p,
        "confirmP = HMAC(K_confirmP, shareV) byte-exact"
    );

    assert!(
        prover.verify_confirmation(&confirm_v).unwrap(),
        "the vector's confirmV = HMAC(K_confirmV, shareP) must verify"
    );
}

/// Byte-exact prover-side migration of the RFC 9383
/// `SPAKE2+-P256-SHA512-HKDF-SHA512-HMAC-SHA512` vector (A-2, multi-suite).
///
/// Same methodology as the SHA-256 case, but driven through
/// `Spake2Plus::with_suite(.., Spake2Suite::P256Sha512)` so the §3.4 key
/// schedule runs Hash = SHA-512, HKDF-SHA512, MAC = HMAC-SHA512 (each derived
/// key 64 bytes). The curve stays P-256 (M/N points + scalar math identical),
/// so only the hash family changes vs the SHA-256 vector. Asserts `shareP`,
/// 64-byte `K_shared`, `confirmP` byte-exact, and that the vector's `confirmV`
/// verifies — independent C ground-truth, cannot false-pass.
#[cfg(feature = "kat-nonce")]
#[test]
fn tc_spake2plus_rfc9383_p256_sha512_vector_byte_exact() {
    use hitls_auth::spake2plus::Spake2Suite;
    // SPAKE2PLUS_TC001, suite "SPAKE2+-P256-SHA512-HKDF-SHA512-HMAC-SHA512".
    let w0 = hex("1cc5207d6e34b8f7828206fb64b86aa9c712bc952abf251bb9f5856b24d8c8cc");
    let w1 = hex("4279649e62532b01dc27d2ed39100ba350518fb969672061a01edce752d0e672");
    let x = hex("b586ab83f175c1a2b56b6a1b6a283523f88a9befcf11e22efb48e2ee1fe69a23");
    let share_p_expected = hex(
        "04a7928c4b47f6b8657a5b8ebcb6f1bd266192e152fb9745a4180c94657a2f323\
         b4d50d536c0325cdb0ec42c9bd8db8d7af3ff6dc85edb4b5365375c62e09def4a",
    );
    let share_v = hex(
        "04498c29e37dbd53ebf8db76679901d90c6be3af57f46ac3025b32420839f0489\
         c6c3b6bf5ddc8ecbc3d7c83d0891ad814a00ad23eba13197c9d96a5b10275e35d",
    );
    let k_shared = hex(
        "11887659d9e002f34fa6cc270d33570f001b2a3fc0522b643c07327d09a4a9f47\
         aab85813d13c585b53adf5ac9de5707114848f3dc31a4045f69a2cc1972b098",
    );
    let confirm_p = hex(
        "6b2469b56cf8ac3f94a8d0b533380ea6b3d0f46b3e12ee82550d49e129c241272\
         8c9437a64ee5f80c8cdc5e8a30faa0a6deb8a5251346ba81bb6fc955b2304fc",
    );
    let confirm_v = hex(
        "154174fc278a935e290b3352ba877e179fa9281c0a76928faea703c72d383b267\
         511a5cf084cb07147efece94e3cfd91944e7baab856858fbebc087167b0f409",
    );

    let mut prover = Spake2Plus::with_suite(Spake2Role::Prover, Spake2Suite::P256Sha512).unwrap();
    prover.set_identities(
        b"SPAKE2+-P256-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors",
        b"client",
        b"server",
    );
    prover.setup(&w0, &w1).unwrap();

    #[allow(deprecated)]
    let share_p = prover.generate_share_with_scalar(&x).unwrap();
    assert_eq!(share_p, share_p_expected, "shareP = x·G + w0·M byte-exact");

    let ke = prover.process_share(&share_v).unwrap();
    assert_eq!(ke.len(), 64, "SHA-512 K_shared is 64 bytes");
    assert_eq!(
        ke, k_shared,
        "K_shared (RFC 9383 §3.4 HKDF-SHA512 'SharedKey') byte-exact"
    );

    let cp = prover.get_confirmation().unwrap();
    assert_eq!(
        cp, confirm_p,
        "confirmP = HMAC-SHA512(K_confirmP, shareV) byte-exact"
    );

    assert!(
        prover.verify_confirmation(&confirm_v).unwrap(),
        "the vector's confirmV = HMAC-SHA512(K_confirmV, shareP) must verify"
    );
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
