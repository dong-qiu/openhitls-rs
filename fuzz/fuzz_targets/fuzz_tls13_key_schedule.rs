#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }
    use hitls_tls::crypt::hkdf::{hkdf_expand_label, derive_secret, hkdf_extract};
    use hitls_tls::crypt::HashAlgId;

    // Split fuzzed data into secret, label, context
    let alg = if data[0] & 1 == 0 {
        HashAlgId::Sha256
    } else {
        HashAlgId::Sha384
    };
    let label_len = (data[1] as usize).min(data.len() / 3).min(64);
    let ctx_len = (data[2] as usize).min(data.len() / 3).min(64);
    let secret_start = 3;
    let secret_end = secret_start + data.len().saturating_sub(3 + label_len + ctx_len);
    if secret_end <= secret_start || secret_end > data.len() {
        return;
    }
    let secret = &data[secret_start..secret_end];
    let label_start = secret_end;
    let label_end = (label_start + label_len).min(data.len());
    let label = &data[label_start..label_end];
    let ctx_start = label_end;
    let ctx_end = (ctx_start + ctx_len).min(data.len());
    let context = &data[ctx_start..ctx_end];

    let hash_len = match alg {
        HashAlgId::Sha256 => 32,
        HashAlgId::Sha384 => 48,
        _ => return,
    };

    // Exercise hkdf_extract (salt, ikm)
    let _ = hkdf_extract(alg, label, secret);

    // Exercise hkdf_expand_label with bounded length
    let out_len = ((data[0] as usize) % hash_len).max(1);
    let _ = hkdf_expand_label(alg, secret, label, context, out_len);

    // Exercise derive_secret
    if context.len() == hash_len {
        let _ = derive_secret(alg, secret, label, context);
    }
});
