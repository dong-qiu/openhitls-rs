#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [key_sel(1B), split_point(1B), rest...]
    if data.len() < 3 {
        return;
    }

    let key_sel = data[0];
    let split_byte = data[1];
    let rest = &data[2..];

    // Select key size: 16 (AES-128) or 32 (AES-256)
    let key_len = if key_sel % 2 == 0 { 16 } else { 32 };

    if rest.len() < key_len {
        return;
    }
    let key = &rest[..key_len];
    let message = &rest[key_len..];

    // One-shot: update(all) → finish
    let mut cmac1 = match hitls_crypto::cmac::Cmac::new(key) {
        Ok(c) => c,
        Err(_) => return,
    };
    if cmac1.update(message).is_err() {
        return;
    }
    let mut out1 = [0u8; 16];
    if cmac1.finish(&mut out1).is_err() {
        return;
    }

    // Incremental: update(chunks) → finish
    let mut cmac2 = match hitls_crypto::cmac::Cmac::new(key) {
        Ok(c) => c,
        Err(_) => return,
    };
    if !message.is_empty() {
        let split = (split_byte as usize) % message.len().max(1);
        let (a, b) = message.split_at(split);
        if cmac2.update(a).is_err() {
            return;
        }
        if cmac2.update(b).is_err() {
            return;
        }
    }
    let mut out2 = [0u8; 16];
    if cmac2.finish(&mut out2).is_err() {
        return;
    }

    assert_eq!(out1, out2, "CMAC one-shot and incremental must match");
});
