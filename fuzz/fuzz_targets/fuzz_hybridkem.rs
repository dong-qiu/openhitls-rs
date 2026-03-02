#![no_main]
use hitls_types::HybridKemParamId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [param_sel(1B), mode_sel(1B), rest...]
    if data.len() < 2 {
        return;
    }

    let param_sel = data[0];
    let mode_sel = data[1];
    let rest = &data[2..];

    let param = match param_sel % 3 {
        0 => HybridKemParamId::X25519MlKem768,
        1 => HybridKemParamId::EcdhNistP256MlKem768,
        _ => HybridKemParamId::EcdhNistP384MlKem768,
    };

    match mode_sel % 2 {
        0 => {
            // Mode 0: generate → encapsulate → decapsulate → roundtrip assert
            let kp = match hitls_crypto::hybridkem::HybridKemKeyPair::generate(param) {
                Ok(k) => k,
                Err(_) => return,
            };
            let (ss, ct) = match kp.encapsulate() {
                Ok(r) => r,
                Err(_) => return,
            };
            let ss2 = match kp.decapsulate(&ct) {
                Ok(s) => s,
                Err(_) => return,
            };
            assert_eq!(ss, ss2, "HybridKEM roundtrip must match");
        }
        _ => {
            // Mode 1: generate → decapsulate fuzzed ct — must not panic
            let kp = match hitls_crypto::hybridkem::HybridKemKeyPair::generate(param) {
                Ok(k) => k,
                Err(_) => return,
            };
            let _ = kp.decapsulate(rest);
        }
    }
});
