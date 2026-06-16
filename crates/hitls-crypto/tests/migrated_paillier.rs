// Paillier — migration of the openHiTLS C SDV `crypto/paillier` test suite.
//
// Source: openHiTLS C SDV crypto/paillier/test_suite_sdv_eal_paillier.c (+ .data)
//         (SDV_CRYPTO_PAILLIER_*_API_TC001/TC002 / *_FUNC_TC001 / ADD_API_TC001).
//
// NOT an xtask byte-exact KAT migration. Like `crypto/elgamal`, the C
// `crypto/paillier` suite is an **API-test** suite (NewCtx / SetPara / Gen /
// Get/Set Pub/Prv / Encrypt / Decrypt / DupCtx / homomorphic Add parameter
// validation), and Paillier encryption is **randomized** (fresh `r` per call)
// so the C `Encrypt` output is not a reproducible KAT.
//
// What IS migrated (SM9 / T158 round-trip methodology): the C
// `SET_PUB_API_TC002` vector's real 1024-bit key material `(p, q, n)` drives:
//   1. a **byte-exact** public-modulus KAT (`n = p * q`) — proves the Rust
//      1024-bit multiplication matches the C reference and the C primes load;
//   2. an `encrypt` -> `decrypt` round-trip under the C primes;
//   3. the **additive-homomorphic** property (Paillier's defining feature):
//      `decrypt(add(E(m1), E(m2))) == (m1 + m2) mod n`, under the C primes.
// This closes the "zero C-test-derived coverage" gap for `hitls_crypto::paillier`.

#![cfg(feature = "paillier")]

use hitls_bignum::BigNum;
use hitls_crypto::paillier::PaillierKeyPair;
use hitls_utils::hex::hex;

/// The 1024-bit Paillier key from the C SDV `PAILLIER_SET_PUB_API_TC002`
/// (`p, q, n, n2, bits`) row: two 512-bit primes `p`, `q` and the modulus
/// `n = p * q`.
fn c_vector() -> (BigNum, BigNum, Vec<u8>) {
    let p = BigNum::from_bytes_be(&hex(
        "ff03b1a74827c746db83d2eaff00067622f545b62584321256e62b01509f1096\
         2f9c5c8fd0b7f5184a9ce8e81f439df47dda14563dd55a221799d2aa57ed2713\
         271678a5a0b8b40a84ad13d5b6e6599e6467c670109cf1f45ccfed8f75ea3b81\
         4548ab294626fe4d14ff764dd8b091f11a0943a2dd2b983b0df02f4c4d00b413",
    ));
    let q = BigNum::from_bytes_be(&hex(
        "dacaabc1dc57faa9fd6a4274c4d588765a1d3311c22e57d8101431b07eb3ddcb\
         05d77d9a742ac2322fe6a063bd1e05acb13b0fe91c70115c2b1eee1155e07252\
         7011a5f849de7072a1ce8e6b71db525fbcda7a89aaed46d27aca5eaeaf35a262\
         70a4a833c5cda681ffd49baa0f610bad100cdf47cc86e5034e2a0b2179e04ec7",
    ));
    let n = hex(
        "d9f3094b36634c05a02ae1a5569035107a48029e39b3c6a1853817f063e18e76\
         1c0c538e55ff2c7e53d603bb35cabb3b8d07f82aa0afdeaf7441fcf6746c5bca\
         aa2cde398ad73edb9c340c3ffca559132581eaf8f65c13d02f3445a932a3e1fa\
         db5912f7553edec5047e4d0ed06ee87effc549e194d38e06b73a971c961688ba\
         2d4aa4f450d2523372f317d41d06f9f0360e962ce953a69f36c53c370799fcfb\
         a195e8f691ebe862f84ae4bbd7747bc14499bd0efffcdc7154325908355c2ffc\
         5b3948b8102b33aa2420381470e4ee858380ff0eea58288516c263f6d51dbbd0\
         e477d1393a0a3ee60e1fde4330856665bf522006608a6104c138c0f39e09c4c5",
    );
    (p, q, n)
}

/// Byte-exact: the public modulus `n = p * q` recomputed by the Rust port from
/// the C primes must equal the C `n` bit-for-bit (1024-bit multiply KAT).
#[test]
fn tc_paillier_public_modulus_n_eq_p_times_q() {
    let (p, q, n) = c_vector();
    let kp = PaillierKeyPair::from_primes(&p, &q).unwrap();
    assert_eq!(
        kp.public_key(),
        n,
        "n = p * q must match the C SDV vector byte-exact"
    );
}

/// Round-trip under the C primes: encrypt a message `m < n`, then decrypt and
/// recover it. Encryption is randomized, so this pins the encrypt/decrypt
/// inverse on the real 1024-bit key.
#[test]
fn tc_paillier_c_key_encrypt_decrypt_roundtrip() {
    let (p, q, _n) = c_vector();
    let kp = PaillierKeyPair::from_primes(&p, &q).unwrap();
    // An arbitrary 256-bit message, well below the 1024-bit modulus n.
    let msg = hex("0123456789abcdeffedcba98765432100f1e2d3c4b5a69788796a5b4c3d2e1f0");
    let ct = kp.encrypt(&msg).unwrap();
    let pt = kp.decrypt(&ct).unwrap();
    assert_eq!(
        BigNum::from_bytes_be(&pt).to_bytes_be(),
        BigNum::from_bytes_be(&msg).to_bytes_be(),
        "decrypt(encrypt(m)) must recover m under the C primes"
    );
}

/// Additive homomorphism (Paillier's defining property), pinned under the C
/// primes: `decrypt(E(m1) * E(m2) mod n^2) == (m1 + m2) mod n`.
#[test]
fn tc_paillier_c_key_additive_homomorphism() {
    let (p, q, _n) = c_vector();
    let kp = PaillierKeyPair::from_primes(&p, &q).unwrap();
    let m1 = hex("00cafebabe0011223344");
    let m2 = hex("00beeff00d5566778899");
    let c1 = kp.encrypt(&m1).unwrap();
    let c2 = kp.encrypt(&m2).unwrap();
    let c_sum = kp.add_ciphertexts(&c1, &c2).unwrap();
    let pt = kp.decrypt(&c_sum).unwrap();

    let expected = BigNum::from_bytes_be(&m1).add(&BigNum::from_bytes_be(&m2));
    assert_eq!(
        BigNum::from_bytes_be(&pt).to_bytes_be(),
        expected.to_bytes_be(),
        "decrypt(E(m1)*E(m2)) must equal m1 + m2 under the C primes"
    );
}
