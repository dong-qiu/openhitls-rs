#![no_main]
use hitls_crypto::hpke::{CipherSuite, HpkeAead, HpkeCtx, HpkeKdf, HpkeKem};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [suite_sel(1B), mode_sel(1B), rest...]
    if data.len() < 2 {
        return;
    }

    let suite_sel = data[0];
    let mode_sel = data[1];
    let rest = &data[2..];

    let suite = match suite_sel % 2 {
        0 => CipherSuite {
            kem: HpkeKem::DhkemX25519HkdfSha256,
            kdf: HpkeKdf::HkdfSha256,
            aead: HpkeAead::Aes128Gcm,
        },
        _ => CipherSuite {
            kem: HpkeKem::DhkemX25519HkdfSha256,
            kdf: HpkeKdf::HkdfSha256,
            aead: HpkeAead::ChaCha20Poly1305,
        },
    };

    match mode_sel % 2 {
        0 => {
            // Mode 0: keygen → setup_sender → seal → setup_recipient → open → assert_eq
            let sk_r = match hitls_crypto::x25519::X25519PrivateKey::generate() {
                Ok(k) => k,
                Err(_) => return,
            };
            let pk_r = sk_r.public_key();
            let pk_bytes = pk_r.as_bytes();

            let (mut sender, enc) =
                match HpkeCtx::setup_sender_with_suite(suite, pk_bytes, b"fuzz info") {
                    Ok(r) => r,
                    Err(_) => return,
                };

            let pt = if rest.is_empty() { &[0u8][..] } else { rest };
            let ct = match sender.seal(b"aad", pt) {
                Ok(c) => c,
                Err(_) => return,
            };

            let sk_bytes = sk_r.to_bytes();
            let mut recipient =
                match HpkeCtx::setup_recipient_with_suite(suite, &sk_bytes, &enc, b"fuzz info") {
                    Ok(r) => r,
                    Err(_) => return,
                };

            let decrypted = match recipient.open(b"aad", &ct) {
                Ok(p) => p,
                Err(_) => return,
            };
            assert_eq!(pt, &decrypted[..], "HPKE seal/open roundtrip must match");
        }
        _ => {
            // Mode 1: setup_sender with fuzzed pk — must not panic
            let _ = HpkeCtx::setup_sender_with_suite(suite, rest, b"fuzz info");
        }
    }
});
