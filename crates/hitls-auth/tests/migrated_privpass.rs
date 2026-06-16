// Phase J-2 — Privacy Pass (RFC 9578 Type 2) round-trip migration.
//
// Source: openHiTLS C SDV auth/privpass_token/test_suite_sdv_privpass_token.data
//         (SDV_AUTH_PRIVPASS_TOKEN_VECTOR_TEST_TC001).
//
// This file has two layers:
//   * T256 (J-2) round-trip pins: drive the Rust Issuer/Client/verify pipeline
//     end-to-end with the C vector's actual RSA-2048 keypair (extracted from its
//     PKCS#8 `ski` field) + challenge, proving the key material is usable and
//     that tamper / wrong-key paths reject (SM9/T158 round-trip methodology).
//   * T282 (WP-B) byte-exact pin: after the I162 conformance rewrite of
//     `hitls_auth::privpass` to RFC 9474 RSABSSA-SHA384-PSS (sLen=48) — the C
//     VECTOR_TEST's `request` / `response` / `token` are now reproduced
//     byte-exact via the `kat-nonce` randomness-injection hook (see below).
//
// The C VECTOR_TEST publishes RFC 9474 RSABSSA-SHA384-PSS vectors produced with
// EMSA-PSS encoding (salt length 48) and a stubbed RNG injecting fixed
// `nonce` / `salt` / `blind`.

#![cfg(feature = "privpass")]

#[cfg(feature = "kat-nonce")]
use hitls_auth::privpass::verify_token_with_key_id;
use hitls_auth::privpass::{verify_token, Client, Issuer};
use hitls_utils::hex::hex;

/// Byte-exact migration of the C SDV `VECTOR_TEST_TC001` (T282, WP-B).
///
/// Drives the RFC 9474 RSABSSA-SHA384-PSS (sLen=48) + RFC 9578 flow with the
/// vector's injected `nonce` / `salt` / blinding factor `r` and the correct
/// `token_key_id = SHA256(issuer SPKI)`, and asserts the `blinded_msg`,
/// `blind_sig` (response), and token `authenticator` byte-exact against the
/// independent C vector — true RFC 9474/9578 ground-truth verification, only
/// possible after the I162 EMSA-PSS-SHA384 RSABSSA conformance rewrite.
#[cfg(feature = "kat-nonce")]
#[test]
fn tc_privpass_rfc9474_vector_byte_exact() {
    let (n, e, d) = vector_key();
    let challenge = vector_challenge();
    // token_key_id = SHA-256(DER SPKI), nonce, and blinding factor r from the
    // C VECTOR_TEST_TC001 row.
    let token_key_id: [u8; 32] =
        hex("ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708")
            .try_into()
            .unwrap();
    let nonce: [u8; 32] = hex("aa72019d1f951df197021ce63876fe8b0a02dc1c31a12b0a2dd1508d07827f05")
        .try_into()
        .unwrap();
    // RSABSSA-SHA384-PSS uses a 48-byte salt (the C vector's `salt` field).
    let salt =
        hex("3d980852fa570c064204feb8d107098db976ef8c2137e8641d234bbd88a986fdb306a7af220cfadede08f51e1ef61766");
    let blind = hex(
        "425421de54c7381864ce36473abfb988c454fe6c27de863de702a6a2adca153f\
         a2de47bd8fcd62734caa8ce1f920b77d980ab58c32d16dde54873f28ca968e8c\
         125b8363514be68972f553655bcc7f80a284cc327e47e804a47333c5b3cdf773\
         312cc7ad9fda748aed0baa7e19c5a2d1dafda718f086d7fc0a4bc02d488e0f208\
         12daee335af7177b7a8369bd617066aed7a58f659f295c36b418827f679725b81\
         ca14ea16fb82df21ad76da1ac38dcf24bf6252f8510e2308608ac9197f6cb54f\
         dcb19db17837302a2b87d659c5605f35f3709a130f0c3d50e172f0cae36cbc946\
         7f9914895a215a9e32443bcafff795273ccf8965a7eaa8c0b2184763e3e5c",
    );
    let expected_blinded_msg = hex(
        "6a95be84b63cfed0993bb579194a72a95057e1548ac463a9a5b33b011f2b2011\
         d59487f01862f1d8e4d5ea42e73a660fbc3d010b944a54da3a4e0942f8894c088\
         4589b438cb902e9a34278970f33c16f351f7dae58d273c3ab66ef368da36f785e\
         89e24d1d983d5c34311cd21f290f9e89e8646ab0d0a48988fcd46230de5e7603c\
         d12cc95c7ec5002e5e26737aa7eb69c626476e6c8d46510ee404a3d7daf3a23b7\
         c66735d363ca13676925c6ed0117f60d165ce1f8ba616d041b6384baf6da3e2f7\
         57cb18e879a4f8595c2dc895ddf1f4279c75768d108b5c47f95f94e81e2d8b9c8\
         b74476924ab3b7c45243fc99ac5466e8a3680ad37fa15c96010b274094",
    );
    let expected_response = hex(
        "675d84b751d9e593330ec4b6d7ab69c9a61517e98971f4b736150508174b4335\
         761464f237be2d72bbae4b94dffc6143413f6351f1aa4efde6c32d4d6d9392a00\
         8290d56d1222f9b77a1336213e01934f7d972f3bf9ea5a5786c321352f103b366\
         7e605379a55f0fb925fbb09b8a9f85e7dd4b388a3b49d06fd70ba28f6a780e3bc\
         8f6421554fd6c38b63ef19f84ccfcf14709dd0b4d72213c1f060893854eba0ea1\
         a147e275da320db5e9849882d5f9179efa8a2d8d3b803f9d1445ef5c1f660be08\
         883ce9b29a0a992fc035d2938cbb61c440044438dbb8b3ce7158a8f9827d23048\
         2f622d291406ab236b32b122627ae0fd36bd0d6b7607b8044ace404d44",
    );
    let expected_authenticator = hex(
        "bc6a21b533d07294b5e900faf5537dd3eb33cee4e08c9670d1e5358fd184b0e0\
         0c637174f5206b14c7bb0e724ebf6b56271e5aa2ed94c051c4a433d302b23bc52\
         460810d489fb050f9de5c868c6c1b06e3849fd087629f704cc724bc0d0984d5c3\
         39686fcdd75f9a9cdd25f37f855f6f4c584d84f716864f546b696d620c5bd41a8\
         11498de84ff9740ba3003ba2422d26b91eb745c084758974642a4207820154324\
         6ddb58030ea8e722376aa82484dca9610a8fb7e018e396165462e17a03e40ea7e\
         128c090a911ecc708066cb201833010c1ebd4e910fc8e27a1be467f78671836a5\
         08257123a45e4e0ae2180a434bd1037713466347a8ebe46439d3da1970",
    );

    let client = Client::with_token_key_id(&n, &e, token_key_id).unwrap();
    #[allow(deprecated)]
    let (request, state) = client
        .create_token_request_with_randomness(&challenge, nonce, &salt, &blind)
        .unwrap();
    assert_eq!(
        request.blinded_element, expected_blinded_msg,
        "RFC 9474 blinded_msg byte-exact"
    );

    let issuer = Issuer::new(&n, &d, &e).unwrap();
    let response = issuer.issue(&request).unwrap();
    assert_eq!(
        response.blind_sig, expected_response,
        "RFC 9474 BlindSign blind_sig byte-exact"
    );

    let token = client.finalize_token(&response, &state).unwrap();
    assert_eq!(
        token.authenticator, expected_authenticator,
        "RFC 9474 Finalize token authenticator byte-exact"
    );

    assert!(
        verify_token_with_key_id(&token, &n, &e, &challenge, &token_key_id).unwrap(),
        "the finalized token must verify under RSASSA-PSS-SHA384 (sLen=48)"
    );
}

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
