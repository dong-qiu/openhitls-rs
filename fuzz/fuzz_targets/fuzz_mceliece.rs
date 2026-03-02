#![no_main]
use hitls_types::algorithm::McElieceParamId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // McEliece keygen is very slow; use smallest available params (6688128)
    // and only run roundtrip + tamper test.

    let kp = match hitls_crypto::mceliece::McElieceKeyPair::generate(
        McElieceParamId::McEliece6688128,
    ) {
        Ok(k) => k,
        Err(_) => return,
    };

    // Encapsulate → decapsulate roundtrip
    let (ct, ss) = match kp.encapsulate() {
        Ok(r) => r,
        Err(_) => return,
    };
    let ss2 = match kp.decapsulate(&ct) {
        Ok(s) => s,
        Err(_) => return,
    };
    assert_eq!(ss, ss2, "McEliece roundtrip must recover shared secret");

    // Tamper ciphertext with fuzz data — decapsulate must not panic
    if !data.is_empty() {
        let mut tampered = ct.clone();
        let tlen = tampered.len();
        for (i, &b) in data.iter().enumerate() {
            tampered[i % tlen] ^= b;
        }
        let _ = kp.decapsulate(&tampered);
    }
});
