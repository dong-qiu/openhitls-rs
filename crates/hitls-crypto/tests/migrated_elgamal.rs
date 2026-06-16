// ElGamal — migration of the openHiTLS C SDV `crypto/elgamal` test suite.
//
// Source: openHiTLS C SDV crypto/elgamal/test_suite_sdv_eal_elgamal.c (+ .data)
//         (SDV_CRYPTO_ELGAMAL_*_API_TC001 / *_FUNC_TC001).
//
// NOT an xtask byte-exact KAT migration. The C `crypto/elgamal` suite is an
// **API-test** suite — its rows exercise EAL ctx mechanics (NewCtx / SetPara /
// Gen / Get/Set Pub/Prv / Encrypt / Decrypt / DupCtx parameter validation) and
// ElGamal encryption is **randomized** (fresh ephemeral `k` per call), so the
// C `Encrypt` output is not a reproducible KAT. There is also no standard
// ElGamal ciphertext wire format, and the Rust port uses its own framing
// (`4-byte c1_len || c1 || c2`) which is not the C encoding.
//
// What IS migrated (SM9 / T158 round-trip methodology): the C ENC/DEC vector's
// real 1024-bit key material `(p, g, x, y)` drives:
//   1. a **byte-exact** public-key derivation KAT (`y = g^x mod p`) — proves the
//      Rust 1024-bit modular exponentiation matches the C reference, and that
//      the C key params load into the Rust port;
//   2. a round-trip (`encrypt` → `decrypt`) under the C key params;
//   3. negative parameter checks pinned against the real key.
// This closes the "zero C-test-derived coverage" gap for `hitls_crypto::elgamal`.

#![cfg(feature = "elgamal")]

use hitls_bignum::BigNum;
use hitls_crypto::elgamal::ElGamalKeyPair;
use hitls_utils::hex::hex;

/// The single 1024-bit ElGamal keypair from the C SDV `ELGAMAL_ENC_API_TC001`
/// (`q, p, g, y, in`) + `ELGAMAL_DEC_API_TC001` (`p, g, x, in`) rows — the two
/// rows share `p` / `g`, so `(p, g, x)` is the private key and `y` its public
/// key. `x` is a 160-bit exponent in the `q`-order subgroup.
fn c_vector() -> (BigNum, BigNum, BigNum, Vec<u8>) {
    let p = BigNum::from_bytes_be(&hex(
        "e5256a788f875183ec56a332d38db31de883cded25ae635a656823b5c801b44a\
         104f4e1d604153adaaa5d6d107feb3a8e721a32f3e6780645c85de2d4f4f85568\
         767efc9b8363193497c052a5b832464b81a209d393eb6d3a464cba0b7607dc79b\
         3611dcd1544e4ed329cc913f68234b1d5f209ae7081c0d44662ee1f86c458f",
    ));
    let g = BigNum::from_bytes_be(&hex(
        "5a0c1ebde9c0787f3d426e2036455fcd25bc32b1e666b2ba90dad169af7043c1\
         8b266d530d0f607ea46c182dd7c88d919158343441e001b10e36c8ffa03cb80d\
         adcf7e84393561d2f4f2d067222d5a33157b81f4f4a46c9526375920cac73c23\
         e100e8b43eb8a4bc83047ae45b079bca6dbf69b4b0c1e6bffdfd232b99c5d61a",
    ));
    let x = BigNum::from_bytes_be(&hex("013d5955a5e91b8fed1b56b6bdcd467939de9bfc"));
    let y = hex(
        "b7866990d044b1bccbbcf84c29f145ee17d4f4608c79a55e249e9e108b91e363\
         81944fa3c0c3f51876f63bce7bb30ffde9ca02265e916dd3fb2e060b0dfeaaa6\
         7d5a359159b948c3df1141f0e0a22380a3633c1ffbcb1c228ffe4ef0bab52293\
         bfdff4b64e3f362d63b11a4d2507f6e9e98de71aff09fdb64e3737c046044138",
    );
    (p, g, x, y)
}

/// Byte-exact: the C vector's public key `y = g^x mod p`, recomputed by the Rust
/// port from `(p, g, x)`, must equal the C `y` bit-for-bit. This is a real
/// 1024-bit modexp KAT against an independent C reference value.
#[test]
fn tc_elgamal_public_key_y_eq_g_pow_x_mod_p() {
    let (p, g, x, y) = c_vector();
    let kp = ElGamalKeyPair::from_private_key(&p, &g, &x).unwrap();
    assert_eq!(
        kp.public_key_bytes(),
        y,
        "y = g^x mod p must match the C SDV vector byte-exact"
    );
}

/// Round-trip under the C key params: encrypt the C ENC plaintext (a value < p)
/// then decrypt and recover it. Encryption is randomized, so this pins the
/// `encrypt`/`decrypt` inverse relationship on the real 1024-bit key rather than
/// a fixed ciphertext.
#[test]
fn tc_elgamal_c_key_encrypt_decrypt_roundtrip() {
    let (p, g, x, _y) = c_vector();
    let kp = ElGamalKeyPair::from_private_key(&p, &g, &x).unwrap();
    // The C ENC `in` plaintext (128 bytes, < p).
    let msg = hex(
        "de318d9540168f7cbd4e87358c2f5b2a9c541328ad51cb3157f8b9ade4b61e08\
         0184d2779ebfb79d70ec0a075aa70b0ceb34e418ba063c53b6724cfc5675c2ce\
         e91cddd79ad3bc1360f78a3894c3f92c0523e3fa694e2bd749344676a118be58\
         37e676ca882b5b14e274b44f925f4160e119e9d6774261c3676bb36ee47a547f",
    );
    let ct = kp.encrypt(&msg).unwrap();
    let pt = kp.decrypt(&ct).unwrap();
    assert_eq!(
        BigNum::from_bytes_be(&pt).to_bytes_be(),
        BigNum::from_bytes_be(&msg).to_bytes_be(),
        "decrypt(encrypt(m)) must recover m under the C key params"
    );
}

/// Negative parameter pins against the real C key: `m == 0` and `m >= p` are
/// rejected by `encrypt` (RFC/lib contract, pinned on the 1024-bit key).
#[test]
fn tc_elgamal_c_key_rejects_invalid_messages() {
    let (p, g, x, _y) = c_vector();
    let kp = ElGamalKeyPair::from_private_key(&p, &g, &x).unwrap();
    // m = 0.
    assert!(kp.encrypt(&[0u8]).is_err(), "m = 0 must be rejected");
    // m = p (not < p).
    assert!(
        kp.encrypt(&p.to_bytes_be()).is_err(),
        "m = p must be rejected"
    );
}
