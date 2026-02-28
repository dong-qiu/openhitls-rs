#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [hash_sel(1B), mode_sel(1B), key_len(1B), rest...]
    if data.len() < 3 {
        return;
    }

    let hash_sel = data[0];
    let mode_sel = data[1];
    let key_len = (data[2] as usize).min(data.len() - 3);
    let rest = &data[3..];
    if rest.len() < key_len {
        return;
    }
    let key = &rest[..key_len];
    let msg = &rest[key_len..];

    let factory: fn() -> Box<dyn hitls_crypto::provider::Digest> = match hash_sel % 2 {
        0 => || Box::new(hitls_crypto::sha2::Sha256::new()),
        _ => || Box::new(hitls_crypto::sha2::Sha512::new()),
    };

    let digest_len = match hash_sel % 2 {
        0 => 32usize,
        _ => 64,
    };

    match mode_sel % 2 {
        0 => {
            // Mode 0: one-shot mac → incremental mac → must match
            let mac_result = match hitls_crypto::hmac::Hmac::mac(factory, key, msg) {
                Ok(m) => m,
                Err(_) => return,
            };

            // Incremental
            let mut hmac = match hitls_crypto::hmac::Hmac::new(factory, key) {
                Ok(h) => h,
                Err(_) => return,
            };
            if hmac.update(msg).is_err() {
                return;
            }
            let mut out = vec![0u8; digest_len];
            if hmac.finish(&mut out).is_err() {
                return;
            }
            assert_eq!(mac_result, out, "HMAC one-shot and incremental must match");
        }
        _ => {
            // Mode 1: chunked update → must produce same result as one-shot
            let mac_result = match hitls_crypto::hmac::Hmac::mac(factory, key, msg) {
                Ok(m) => m,
                Err(_) => return,
            };

            let mut hmac = match hitls_crypto::hmac::Hmac::new(factory, key) {
                Ok(h) => h,
                Err(_) => return,
            };
            // Update in variable-size chunks
            let chunk_size = if data[0] == 0 { 1 } else { data[0] as usize % 64 + 1 };
            for chunk in msg.chunks(chunk_size) {
                if hmac.update(chunk).is_err() {
                    return;
                }
            }
            let mut out = vec![0u8; digest_len];
            if hmac.finish(&mut out).is_err() {
                return;
            }
            assert_eq!(mac_result, out, "HMAC chunked and one-shot must match");
        }
    }
});
