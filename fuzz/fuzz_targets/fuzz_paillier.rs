#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    use hitls_crypto::paillier::PaillierKeyPair;
    use hitls_bignum::BigNum;

    // Use small fixed primes for speed
    let p = BigNum::from_bytes_be(&[
        0xf5, 0x2a, 0xdd, 0x6c, 0x04, 0x53, 0x6f, 0xdb,
        0x66, 0x9f, 0x8c, 0x95, 0x53, 0x93, 0xe5, 0x47,
    ]);
    let q = BigNum::from_bytes_be(&[
        0xe2, 0x04, 0x67, 0x7d, 0x6c, 0xf7, 0x07, 0x69,
        0x8f, 0xd2, 0x35, 0xbc, 0x67, 0x82, 0x41, 0x3b,
    ]);
    if let Ok(kp) = PaillierKeyPair::from_primes(&p, &q) {
        // Fuzz encrypt
        let _ = kp.encrypt(data);

        // Fuzz decrypt with raw data
        let _ = kp.decrypt(data);

        // Fuzz homomorphic add with two halves
        if data.len() >= 8 {
            let (a, b) = data.split_at(data.len() / 2);
            let _ = kp.add_ciphertexts(a, b);
        }
    }
});
