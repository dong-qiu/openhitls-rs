//! Cryptographic algorithm benchmarks.
//!
//! Run with: cargo bench -p hitls-crypto --all-features

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

// ---------------------------------------------------------------------------
// AES benchmarks
// ---------------------------------------------------------------------------

fn bench_aes(c: &mut Criterion) {
    use hitls_crypto::aes::AesKey;

    let mut group = c.benchmark_group("aes");

    for key_len in [16, 32] {
        let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
        let cipher = AesKey::new(&key).unwrap();
        let label = format!("aes-{}", key_len * 8);

        let mut block = [0u8; 16];
        group.bench_function(format!("{label}/encrypt_block"), |b| {
            b.iter(|| cipher.encrypt_block(&mut block).unwrap());
        });

        let mut block = [0u8; 16];
        group.bench_function(format!("{label}/decrypt_block"), |b| {
            b.iter(|| cipher.decrypt_block(&mut block).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// AES-GCM benchmarks
// ---------------------------------------------------------------------------

fn bench_aes_gcm(c: &mut Criterion) {
    use hitls_crypto::modes::gcm::{gcm_decrypt, gcm_encrypt};

    let mut group = c.benchmark_group("aes-256-gcm");

    for size in [1024usize, 16384, 1048576] {
        group.throughput(Throughput::Bytes(size as u64));

        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let aad = b"benchmark";
        let plaintext = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, _| {
            b.iter(|| gcm_encrypt(&key, &nonce, aad, &plaintext).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("decrypt", size), &size, |b, _| {
            // Pre-encrypt to get valid ciphertext + tag
            let ct_with_tag = gcm_encrypt(&key, &nonce, aad, &plaintext).unwrap();

            b.iter(|| gcm_decrypt(&key, &nonce, aad, &ct_with_tag).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// SHA-2 benchmarks
// ---------------------------------------------------------------------------

fn bench_sha2(c: &mut Criterion) {
    use hitls_crypto::sha2::{Sha256, Sha512};

    let mut group = c.benchmark_group("sha");

    for size in [1024usize, 16384, 1048576] {
        group.throughput(Throughput::Bytes(size as u64));
        let data = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("sha256", size), &size, |b, _| {
            b.iter(|| {
                let mut h = Sha256::new();
                h.update(&data).unwrap();
                h.finish().unwrap()
            });
        });

        group.bench_with_input(BenchmarkId::new("sha512", size), &size, |b, _| {
            b.iter(|| {
                let mut h = Sha512::new();
                h.update(&data).unwrap();
                h.finish().unwrap()
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// HMAC benchmarks
// ---------------------------------------------------------------------------

fn bench_hmac(c: &mut Criterion) {
    use hitls_crypto::hmac::Hmac;
    use hitls_crypto::sha2::Sha256;

    let mut group = c.benchmark_group("hmac-sha256");

    for size in [1024usize, 16384, 1048576] {
        group.throughput(Throughput::Bytes(size as u64));
        let key = [0x42u8; 32];
        let data = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("compute", size), &size, |b, _| {
            b.iter(|| {
                let factory: fn() -> Box<dyn hitls_crypto::provider::Digest> =
                    || Box::new(Sha256::new());
                let mut mac = Hmac::new(factory, &key).unwrap();
                mac.update(&data).unwrap();
                let mut out = [0u8; 32];
                mac.finish(&mut out).unwrap();
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// ECDSA benchmarks
// ---------------------------------------------------------------------------

fn bench_ecdsa(c: &mut Criterion) {
    use hitls_crypto::ecdsa::EcdsaKeyPair;
    use hitls_types::EccCurveId;

    let mut group = c.benchmark_group("ecdsa-p256");

    let kp = EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();
    // ECDSA sign() takes a digest, so pre-hash the message
    let digest = {
        use hitls_crypto::sha2::Sha256;
        let mut h = Sha256::new();
        h.update(b"benchmark message for ECDSA signing").unwrap();
        h.finish().unwrap()
    };

    group.bench_function("sign", |b| {
        b.iter(|| kp.sign(&digest).unwrap());
    });

    let sig = kp.sign(&digest).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| kp.verify(&digest, &sig).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Ed25519 benchmarks
// ---------------------------------------------------------------------------

fn bench_ed25519(c: &mut Criterion) {
    use hitls_crypto::ed25519::Ed25519KeyPair;

    let mut group = c.benchmark_group("ed25519");

    let seed = [0x42u8; 32];
    let kp = Ed25519KeyPair::from_seed(&seed).unwrap();
    let msg = b"benchmark message for Ed25519 signing";

    group.bench_function("sign", |b| {
        b.iter(|| kp.sign(msg).unwrap());
    });

    let sig = kp.sign(msg).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| kp.verify(msg, &sig).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// X25519 benchmarks
// ---------------------------------------------------------------------------

fn bench_x25519(c: &mut Criterion) {
    use hitls_crypto::x25519::X25519PrivateKey;

    let mut group = c.benchmark_group("x25519");

    let sk1_bytes = [0x42u8; 32];
    let sk2_bytes = [0x43u8; 32];
    let sk1 = X25519PrivateKey::new(&sk1_bytes).unwrap();
    let sk2 = X25519PrivateKey::new(&sk2_bytes).unwrap();
    let pk2 = sk2.public_key();

    group.bench_function("diffie_hellman", |b| {
        b.iter(|| sk1.diffie_hellman(&pk2).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// BigNum benchmarks (moved from root benches/)
// ---------------------------------------------------------------------------

fn bench_bignum(c: &mut Criterion) {
    use hitls_bignum::BigNum;

    let mut group = c.benchmark_group("bignum");

    for size in [256, 512, 1024, 2048, 4096] {
        let bytes = vec![0xFFu8; size / 8];
        let a = BigNum::from_bytes_be(&bytes);
        let b = BigNum::from_bytes_be(&bytes);

        group.bench_with_input(BenchmarkId::new("mul", size), &size, |bench, _| {
            bench.iter(|| a.mul(&b));
        });

        group.bench_with_input(BenchmarkId::new("add", size), &size, |bench, _| {
            bench.iter(|| a.add(&b));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_aes,
    bench_aes_gcm,
    bench_sha2,
    bench_hmac,
    bench_ecdsa,
    bench_ed25519,
    bench_x25519,
    bench_bignum,
);
criterion_main!(benches);
