#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static RSA_KEY: OnceLock<hitls_crypto::rsa::RsaPrivateKey> = OnceLock::new();

fn get_rsa_key() -> &'static hitls_crypto::rsa::RsaPrivateKey {
    RSA_KEY.get_or_init(|| {
        hitls_crypto::rsa::RsaPrivateKey::generate(2048).expect("RSA keygen must succeed")
    })
}

fuzz_target!(|data: &[u8]| {
    // Input: [padding_sel(1B), digest(32B), tamper...]
    // Minimum: 1 + 32 = 33 bytes
    if data.len() < 33 {
        return;
    }

    let padding_sel = data[0];
    let digest = &data[1..33];
    let tamper = &data[33..];

    let padding = match padding_sel % 2 {
        0 => hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign,
        _ => hitls_crypto::rsa::RsaPadding::Pss,
    };

    let sk = get_rsa_key();
    let pk = sk.public_key();

    // Sign the digest
    let sig = match sk.sign(padding, digest) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Verify must succeed
    let valid = pk.verify(padding, digest, &sig).unwrap_or(false);
    assert!(valid, "RSA sign/verify roundtrip must succeed");

    // Tamper and verify must fail
    if !tamper.is_empty() && tamper[0] != 0 {
        let mut tampered_digest = digest.to_vec();
        tampered_digest[0] ^= tamper[0];
        let invalid = pk.verify(padding, &tampered_digest, &sig).unwrap_or(false);
        assert!(!invalid, "RSA tampered verification must fail");

        // Also try fuzzed signature
        let mut tampered_sig = sig.clone();
        let tlen = tampered_sig.len();
        for (i, &b) in tamper.iter().enumerate() {
            tampered_sig[i % tlen] ^= b;
        }
        let _ = pk.verify(padding, digest, &tampered_sig);
    }
});
