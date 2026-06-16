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

/// Shared byte-exact prover-side driver for the multi-curve A-2 vectors
/// (P-384 / P-521). Asserts `shareP`, `K_shared`, `confirmP` byte-exact and the
/// vector's `confirmV` verifies — all against the independent C SDV vector.
#[cfg(feature = "kat-nonce")]
#[allow(clippy::too_many_arguments)]
fn check_prover_byte_exact(
    suite: hitls_auth::spake2plus::Spake2Suite,
    context: &[u8],
    w0: &str,
    w1: &str,
    x: &str,
    share_p_expected: &str,
    share_v: &str,
    k_shared: &str,
    confirm_p: &str,
    confirm_v: &str,
) {
    let hlen = k_shared.len() / 2;
    let mut prover = Spake2Plus::with_suite(Spake2Role::Prover, suite).unwrap();
    prover.set_identities(context, b"client", b"server");
    prover.setup(&hex(w0), &hex(w1)).unwrap();

    #[allow(deprecated)]
    let share_p = prover.generate_share_with_scalar(&hex(x)).unwrap();
    assert_eq!(
        share_p,
        hex(share_p_expected),
        "shareP = x·G + w0·M byte-exact"
    );

    let ke = prover.process_share(&hex(share_v)).unwrap();
    assert_eq!(ke.len(), hlen, "K_shared length matches the suite hash");
    assert_eq!(ke, hex(k_shared), "K_shared (HKDF 'SharedKey') byte-exact");

    let cp = prover.get_confirmation().unwrap();
    assert_eq!(
        cp,
        hex(confirm_p),
        "confirmP = MAC(K_confirmP, shareV) byte-exact"
    );

    assert!(
        prover.verify_confirmation(&hex(confirm_v)).unwrap(),
        "the vector's confirmV = MAC(K_confirmV, shareP) must verify"
    );
}

/// Byte-exact migration of the RFC 9383 P-384-SHA-256 vector (A-2 multi-curve).
#[cfg(feature = "kat-nonce")]
#[test]
fn tc_spake2plus_rfc9383_p384_sha256_vector_byte_exact() {
    check_prover_byte_exact(
        hitls_auth::spake2plus::Spake2Suite::P384Sha256,
        b"SPAKE2+-P384-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors",
        "097a61cbb1cee72bb654be96d80f46e0e3531151003903b572fc193f233772c23c22228884a0d5447d0ab49a656ce1d2",
        "18772816140e6c3c3938a693c600b2191118a34c7956e1f1cd5b0d519b56ea5858060966cfaf27679c9182129949e74f",
        "2f1bdbeda162ff2beba0293d3cd3ae95f663c53663378c7e18ee8f56a4a48b00d31ce0ef43606548da485058f12e8e73",
        "049fb0404ca7ce71fb85d3aaa8fd05fa054affac996135bc245149be09571e43e2bf76e00d6d52ac452b8224f6b9da31420a4f5e214b377546daad4d61da5ca0cfdea59a5a92ebdb6b42da5d14663b8d1f9eb97050139ab89788e0ada27b048fcf",
        "0493b1c1f6a30eac4ac4a15711e44640bae3576787627ee25411042981e94b2e9604b9374f66bb247bc431759212ef3fa0a20c087863b89efb32219e1337ce94be2175f8cb9fd50cf0b84772717fd063c52b69de1229a01ab840b55993287f32ed",
        "99758e838ae1a856589689fb55b6befe4e2382e6ebbeca1a6232a68f9dc04c1a",
        "7ae825e242a5a1f86ad7db172c2c12fcb458b6a2b1ddfc96b2b7cfd2eed5f7ab",
        "1581062167d6a3d14493447cd170d408f6fdc58e31225438db86214167426a7a",
    );
}

/// Byte-exact migration of the RFC 9383 P-384-SHA-512 vector (A-2 multi-curve).
#[cfg(feature = "kat-nonce")]
#[test]
fn tc_spake2plus_rfc9383_p384_sha512_vector_byte_exact() {
    check_prover_byte_exact(
        hitls_auth::spake2plus::Spake2Suite::P384Sha512,
        b"SPAKE2+-P384-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors",
        "b8d44a0982b88abe19b724d4bdafba8c90dc93130e0bf4f8062810992326da126fd01db53e40250ca33a3ff302044cb0",
        "2373e2071c3bb2a6d53ece57830d56f8080189816803c22375d6a4a514f9d161b64d0f05b97735b98b348f9b33cc2e30",
        "5a835d52714f30d2ef539268b89df9558628400063dfa0e41eb979066f4caf409bbf7aab3ddddea13f1b070a1827d3d4",
        "042f382eef464a2c9aecfdf4b81d25c4de2de113ba67405ce336c762c69217ae7e27bda875144140d7536c4cc08b9b4dace5f872a6a2ed57f34042688ad3c5d446c187dc0caf9cea812df3a4dd6fdbc64b9d7d7d7ff4bf6965abb06eeb108d55ee",
        "04d72e11eee332305062454c0a058b8103a3304785d445510cd8d101e9cb44cfb159cb7b72123abaf719ab1c42e0558c84c14b0886e8b446e4c880bff2f4b291fafafc748cb4115824e66732bdeba7fae176388e228ab9d7546255994ca3fb5a52",
        "31e0075a823b9269af5769d71ef3b2f5001cbfe044584fe8551124a217dad078415630bf3eda16b5a38341d418a6d72b3960f818a0926f0de88784b59d6a694b",
        "7f806ae56ea3e49a8b16ffee528086489418913641f529d50ff92aa456ad4648e522f9540b403bff6bd94ee1adc95c7d1b2666f7ba6f9c10748bc7bfb4181d27",
        "8daa262decb79cceda4421f4f8dacf22ec027c08e036f071beea563c8e00813a29807963ff9d7d6bbff48dd5bdcdd9ca9fd7ffc272b162258d981913f7253dcb",
    );
}

/// Byte-exact migration of the RFC 9383 P-521-SHA-512 vector (A-2 multi-curve).
#[cfg(feature = "kat-nonce")]
#[test]
fn tc_spake2plus_rfc9383_p521_sha512_vector_byte_exact() {
    check_prover_byte_exact(
        hitls_auth::spake2plus::Spake2Suite::P521Sha512,
        b"SPAKE2+-P521-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors",
        "009c79bcd7656716314fca5a6e2c5cda7ef86131399438e012a043051e863f60b5aeb3c101731e1505e721580f48535a9b0456b231b9266ae6fff49ee90d25f72f5f",
        "01632c15f51fcd916cd79e19075f8a69b72b0099922ad62ff8d540b469569f0aa027047aed2b3f242ea0ac4288b4e4db6a4e5946d8ad32b42192c5aa66d9ef8e1b33",
        "00b69e3bb15df82c9fa0057461334e2c66ab92fc9b8d3662eec81216ef5ddc4a43f19e90dedaa2d72502f69673a115984ffcf88e03a9364b07102114c5602cd93c69",
        "0400a14431edf6852ff5fe868f8683e16e9e0a45d9e27f9a96442285ac6b161fc0bf267362a5ffb06f9cbd14b7a37e492146d77cae4c77812df00a91dbae09e27e1fac00ae019317ef9768548325bca35ce258e6206fe03c6338b2eb889d09d9f11400a36cf6328a7e1f81c6c7a2af7ff1d9b5210768318f27e57b75b39b9fbfc7b37a60ab",
        "0401aa5af0f3027f63b7170572db5ff06dd1f3d6ea8ea771b26b434fbbc6c9de7d80975131c9c2e94d30c0ed2d62449c4c1b7e95037a85ed7598e415a259126365e89500d0f2156b551b70416d719944736990f346f6f9ba4fbaf2f63e09873690bcf730582e0a7b03ffede50f5787b631d5021a94287f0a29a081b62b9f5a3bf393b001b3",
        "d1c170e4e55efacb9db8abad286293ebd1dcf24f13973427b9632bbc323e42e447afca2aa7f74f2af3fb5f51684ec543db854b7002cde6799c330b032ba8820a",
        "f0f5c903dfa42fe367659656a26058cd984b76a8e91ae4d0fa4c13db149008e2ae57713fb230a627761174fefd263b9c10e9a4b6a3746cde59c5943040c17133",
        "a8f7ab43f3a800171d3a3fb26d742e1ed236c2d5804ecd328f220a7d245cd2e3bfb6c0526983bff9229c94f70fe64ba9bb5a4d0dc10afcda64a4c96d4c3d81ad",
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
