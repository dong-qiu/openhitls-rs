// Phase J-2 — Privacy Pass (RFC 9578 Type 2) round-trip migration.
//
// Source: openHiTLS C SDV auth/privpass_token/test_suite_sdv_privpass_token.data
//         (SDV_AUTH_PRIVPASS_TOKEN_VECTOR_TEST_TC001).
//
// NOT byte-exact. The C VECTOR_TEST publishes RFC 9474 RSABSSA vectors
// (token_request / token_response / token) produced with EMSA-PSS encoding and
// a stubbed RNG injecting fixed `nonce` / `salt` / `blind`. The Rust
// `hitls_auth::privpass` implementation is a *simplified* blind-RSA that blinds
// `SHA-256(token_input)` directly — it has no EMSA-PSS step, no salt, no
// TokenChallenge wire codec, and draws the nonce / blind internally via
// `getrandom`. Consequently the C `request` / `response` / `token` bytes are
// NOT reproducible by the Rust port. See `docs/c-test-na-list.md` "Structural
// gaps" → Privacy Pass for the byte-exact unblock path (a future Implementation
// phase adding RFC 9474 EMSA-PSS + deterministic nonce/salt/blind hooks +
// RFC 9577 TokenChallenge serialization).
//
// What IS migratable (this file, T256): the *key material* of the C vector.
// We drive the Rust Issuer/Client/verify pipeline end-to-end with the actual
// RSA-2048 keypair the C VECTOR_TEST_TC001 row publishes (extracted from its
// PKCS#8 `ski` field) and its `challenge` bytes, proving the C vector's key is
// usable by the Rust port (create → issue → finalize → verify round-trips, and
// tamper / wrong-key paths reject). This mirrors the SM9 (T158) round-trip
// migration methodology for C SDV families that carry no Rust-reproducible KAT.

#![cfg(feature = "privpass")]

use hitls_auth::privpass::{verify_token, Client, Issuer};
use hitls_utils::hex::hex;

/// RSA-2048 keypair from the C SDV `VECTOR_TEST_TC001` `ski` PKCS#8 key
/// (`e = 65537`). Returns `(n, e, d)` big-endian.
fn vector_key() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let n = hex(
        "cb1aed6b6a95f5b1ce013a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c\
         12993af12b111908d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a224\
         d6b02f09e5c374d0cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af7\
         2d7b5e794fc98a3139276879757ce453b526ef9bf6ceb99979b8423b90f4461a\
         22af37aab0cf5733f7597abe44d31c732db68a181c6cbbe607d8c0e52e0655fd\
         9996dc584eca0be87afbcd78a337d17b1dba9e828bbd81e291317144e7ff89f5\
         5619709b096cbb9ea474cead264c2073fe49740c01f00e109106066983d21e5f\
         83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b7e225a5f",
    );
    let e = hex("010001");
    let d = hex(
        "2f309b7738b58cf779f0c915f822dfc9f490dbeadf1e7adfac578ffd5703c6bb\
         a2da9d5a49725889b7ba112f8c6ff30551d9473e000bc35c50e167ab7fa73a0c\
         2b21965c4b59257c1ac06cbdcf28e863f6718ea8c29043c1c6da84629490fd04\
         91bf52d172c959c1921b96949c725747b8a7c7871995fa0b9eb1107ba854c6c3\
         2a6f4747c5d1c304c7467d55b080aa233a3a52ffdf26114cbb541ffa6b696b7a\
         096f8dcff69ca08ab58efb0fb753aa5185c73001696bbce8c099e3f435dcbbfe\
         05e7dbaad23db2a659c23add521407f150b1af2d9054c4164229d6840b7a32a4\
         f8481493ae8959cf0aea8def0c3c9f75b9a34c75718b7072c8dbab17cefeca49",
    );
    (n, e, d)
}

/// The `challenge` field of `VECTOR_TEST_TC001` (RFC 9577 TokenChallenge wire
/// bytes). The Rust API treats the challenge as opaque input that it SHA-256s,
/// so the exact bytes drive a consistent round-trip on both create + verify.
fn vector_challenge() -> Vec<u8> {
    hex(
        "0002000e6973737565722e6578616d706c65208e7acc900e393381e8810b7c9e\
         4a68b5163f1f880ab6688a6ffe780923609e88000e6f726967696e2e6578616d\
         706c65",
    )
}

/// End-to-end pipeline with the C vector's real RSA-2048 key + challenge:
/// create_token_request → issue → finalize_token → verify_token == true.
#[test]
fn tc_privpass_vector_key_roundtrip_verifies() {
    let (n, e, d) = vector_key();
    let challenge = vector_challenge();

    let issuer = Issuer::new(&n, &d, &e).unwrap();
    let client = Client::new(&n, &e).unwrap();

    let (request, state) = client.create_token_request(&challenge).unwrap();
    let response = issuer.issue(&request).unwrap();
    let token = client.finalize_token(&response, &state).unwrap();

    assert_eq!(token.nonce.len(), 32);
    // The unblinded authenticator is an RSA-2048 signature → 256 bytes.
    assert_eq!(token.authenticator.len(), 256);
    assert!(verify_token(&token, &n, &e, &challenge).unwrap());
}

/// The issuer's token_key_id is SHA-256(n || e); both roles derive the same
/// blinded element size (RSA-2048 = 256 bytes) from the vector key.
#[test]
fn tc_privpass_vector_key_blinded_element_size() {
    let (n, e, d) = vector_key();
    let challenge = vector_challenge();
    let _issuer = Issuer::new(&n, &d, &e).unwrap();
    let client = Client::new(&n, &e).unwrap();
    let (request, _state) = client.create_token_request(&challenge).unwrap();
    assert_eq!(request.blinded_element.len(), 256);
}

/// Tampering the authenticator must make verification fail (C vector key).
#[test]
fn tc_privpass_vector_key_tampered_token_rejected() {
    let (n, e, d) = vector_key();
    let challenge = vector_challenge();

    let issuer = Issuer::new(&n, &d, &e).unwrap();
    let client = Client::new(&n, &e).unwrap();

    let (request, state) = client.create_token_request(&challenge).unwrap();
    let response = issuer.issue(&request).unwrap();
    let mut token = client.finalize_token(&response, &state).unwrap();

    if let Some(byte) = token.authenticator.last_mut() {
        *byte ^= 0x01;
    }
    assert!(!verify_token(&token, &n, &e, &challenge).unwrap());
}

/// Verifying a valid token against a *different* challenge must fail.
#[test]
fn tc_privpass_vector_key_wrong_challenge_rejected() {
    let (n, e, d) = vector_key();
    let challenge = vector_challenge();

    let issuer = Issuer::new(&n, &d, &e).unwrap();
    let client = Client::new(&n, &e).unwrap();

    let (request, state) = client.create_token_request(&challenge).unwrap();
    let response = issuer.issue(&request).unwrap();
    let token = client.finalize_token(&response, &state).unwrap();

    let mut wrong = challenge.clone();
    if let Some(byte) = wrong.last_mut() {
        *byte ^= 0xff;
    }
    assert!(!verify_token(&token, &n, &e, &wrong).unwrap());
}

/// Verifying with a wrong public exponent must fail (C vector key).
#[test]
fn tc_privpass_vector_key_wrong_pubkey_rejected() {
    let (n, e, d) = vector_key();
    let challenge = vector_challenge();

    let issuer = Issuer::new(&n, &d, &e).unwrap();
    let client = Client::new(&n, &e).unwrap();

    let (request, state) = client.create_token_request(&challenge).unwrap();
    let response = issuer.issue(&request).unwrap();
    let token = client.finalize_token(&response, &state).unwrap();

    let wrong_e = hex("03");
    assert!(!verify_token(&token, &n, &wrong_e, &challenge).unwrap());
}
