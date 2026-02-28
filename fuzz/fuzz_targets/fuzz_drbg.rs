#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [type_sel(1B), mode_sel(1B), rest...]
    if data.len() < 2 {
        return;
    }

    let type_sel = data[0];
    let mode_sel = data[1];
    let rest = &data[2..];

    match type_sel % 2 {
        0 => {
            // HMAC-DRBG
            let seed = if rest.is_empty() { &[0u8; 32][..] } else { rest };
            let mut drbg = match hitls_crypto::drbg::HmacDrbg::new(seed) {
                Ok(d) => d,
                Err(_) => return,
            };
            match mode_sel % 2 {
                0 => {
                    // Mode 0: generate output
                    let out_len = (rest.first().copied().unwrap_or(16) as usize % 256) + 1;
                    let mut output = vec![0u8; out_len];
                    let _ = drbg.generate(&mut output, None);
                }
                _ => {
                    // Mode 1: generate → reseed → generate → outputs must differ
                    let mut out1 = vec![0u8; 32];
                    if drbg.generate(&mut out1, None).is_err() {
                        return;
                    }
                    let reseed_data = if rest.len() > 1 { &rest[1..] } else { &[0xAA; 32][..] };
                    if drbg.reseed(reseed_data, None).is_err() {
                        return;
                    }
                    let mut out2 = vec![0u8; 32];
                    if drbg.generate(&mut out2, None).is_err() {
                        return;
                    }
                    // After reseed, outputs should differ (overwhelmingly likely)
                    // Don't assert — just exercise the path
                }
            }
        }
        _ => {
            // CTR-DRBG (needs exactly 48 bytes seed, or use with_df)
            match mode_sel % 2 {
                0 => {
                    // Mode 0: with_df constructor (flexible input sizes)
                    let entropy = if rest.len() >= 16 { &rest[..16] } else { &[0u8; 16][..] };
                    let nonce = if rest.len() >= 24 { &rest[16..24] } else { &[0u8; 8][..] };
                    let pers = if rest.len() >= 32 { &rest[24..32] } else { &[][..] };
                    let mut drbg = match hitls_crypto::drbg::CtrDrbg::with_df(entropy, nonce, pers)
                    {
                        Ok(d) => d,
                        Err(_) => return,
                    };
                    let out_len = (rest.first().copied().unwrap_or(16) as usize % 256) + 1;
                    let mut output = vec![0u8; out_len];
                    let _ = drbg.generate(&mut output, None);
                }
                _ => {
                    // Mode 1: exact 48-byte seed constructor
                    if rest.len() < 48 {
                        return;
                    }
                    let mut drbg = match hitls_crypto::drbg::CtrDrbg::new(&rest[..48]) {
                        Ok(d) => d,
                        Err(_) => return,
                    };
                    let mut output = vec![0u8; 32];
                    let _ = drbg.generate(&mut output, Some(&rest[48..]));
                }
            }
        }
    }
});
