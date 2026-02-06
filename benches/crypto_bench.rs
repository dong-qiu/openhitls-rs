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

criterion_group!(benches, bench_bignum);
criterion_main!(benches);
