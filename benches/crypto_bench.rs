//! Cryptographic algorithm benchmarks.
//!
//! Run with: cargo bench

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_bignum(c: &mut Criterion) {
    use hitls_bignum::BigNum;

    let mut group = c.benchmark_group("bignum");

    for size in [256, 512, 1024, 2048, 4096] {
        let bytes = vec![0xFFu8; size / 8];
        let a = BigNum::from_bytes_be(&bytes);
        let b = BigNum::from_bytes_be(&bytes);

        group.bench_with_input(
            BenchmarkId::new("mul", size),
            &size,
            |bench, _| {
                bench.iter(|| a.mul(&b));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("add", size),
            &size,
            |bench, _| {
                bench.iter(|| a.add(&b));
            },
        );
    }

    group.finish();
}

fn bench_sm2(c: &mut Criterion) {
    use hitls_crypto::sm2::{Sm2, Sm2Params};

    let params = Sm2Params::default();
    let sm2 = Sm2::generate_key(&params).unwrap();
    let msg = b"benchmark test message for SM2 operations";

    let mut group = c.benchmark_group("sm2");

    group.bench_function("sign", |b| {
        b.iter(|| sm2.sign(msg).unwrap());
    });

    let sig = sm2.sign(msg).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| sm2.verify(msg, &sig).unwrap());
    });

    let plaintext = b"SM2 encryption benchmark plaintext data";
    group.bench_function("encrypt", |b| {
        b.iter(|| sm2.encrypt(plaintext).unwrap());
    });

    let ciphertext = sm2.encrypt(plaintext).unwrap();
    group.bench_function("decrypt", |b| {
        b.iter(|| sm2.decrypt(&ciphertext).unwrap());
    });

    group.finish();
}

criterion_group!(benches, bench_bignum, bench_sm2);
criterion_main!(benches);
