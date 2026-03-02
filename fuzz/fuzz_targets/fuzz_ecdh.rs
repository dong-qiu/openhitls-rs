#![no_main]
use hitls_types::EccCurveId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [curve_sel(1B)]
    if data.is_empty() {
        return;
    }

    let curve = match data[0] % 3 {
        0 => EccCurveId::NistP256,
        1 => EccCurveId::NistP384,
        _ => EccCurveId::NistP521,
    };

    // Generate two key pairs
    let kp_a = match hitls_crypto::ecdh::EcdhKeyPair::generate(curve) {
        Ok(k) => k,
        Err(_) => return,
    };
    let kp_b = match hitls_crypto::ecdh::EcdhKeyPair::generate(curve) {
        Ok(k) => k,
        Err(_) => return,
    };

    let pub_a = match kp_a.public_key_bytes() {
        Ok(p) => p,
        Err(_) => return,
    };
    let pub_b = match kp_b.public_key_bytes() {
        Ok(p) => p,
        Err(_) => return,
    };

    // ECDH commutativity: dh(a, pub_b) == dh(b, pub_a)
    let ss_ab = match kp_a.compute_shared_secret(&pub_b) {
        Ok(s) => s,
        Err(_) => return,
    };
    let ss_ba = match kp_b.compute_shared_secret(&pub_a) {
        Ok(s) => s,
        Err(_) => return,
    };

    assert_eq!(ss_ab, ss_ba, "ECDH shared secret must be commutative");
});
