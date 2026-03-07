#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    use hitls_crypto::elgamal::ElGamalKeyPair;
    use hitls_bignum::BigNum;

    // Use small fixed params for speed (512-bit safe prime would be slow to generate)
    // Instead, test encrypt/decrypt error paths with fuzzed plaintext
    let p = BigNum::from_bytes_be(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34,
        0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
        0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
    ]);
    let g = BigNum::from_u64(2);
    if let Ok(kp) = ElGamalKeyPair::from_params(&p, &g) {
        // Fuzz encrypt path — may fail on large plaintext
        let _ = kp.encrypt(data);

        // Fuzz decrypt path with raw fuzzed data
        let _ = kp.decrypt(data);
    }
});
