#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz CBC record decryption with various malformed inputs.
    // Fixed enc_key and mac_key — the fuzzer exercises parsing/validation paths.
    let enc_key = vec![0x42u8; 16]; // AES-128
    let mac_key = vec![0xABu8; 32]; // HMAC-SHA256

    // Need at least some data to form a record fragment
    if data.len() < 2 {
        return;
    }

    let record = hitls_tls::record::Record {
        content_type: hitls_tls::record::ContentType::ApplicationData,
        version: 0x0303,
        fragment: data.to_vec(),
    };

    // Test CBC MAC-then-encrypt decryption
    let mut dec_cbc =
        hitls_tls::record::encryption12_cbc::RecordDecryptor12Cbc::new(enc_key.clone(), mac_key.clone(), 32);
    let _ = dec_cbc.decrypt_record(&record);

    // Test EtM decryption with same data
    let mut dec_etm =
        hitls_tls::record::encryption12_cbc::RecordDecryptor12EtM::new(enc_key, mac_key, 32);
    let _ = dec_etm.decrypt_record(&record);
});
