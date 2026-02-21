//! Cryptographic algorithm benchmarks.
//!
//! Run with: cargo bench -p hitls-crypto --all-features

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

// ---------------------------------------------------------------------------
// AES block benchmarks
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

    let mut group = c.benchmark_group("aes-gcm");

    for (key_len, label) in [(16, "aes-128-gcm"), (32, "aes-256-gcm")] {
        for size in [1024usize, 8192, 16384] {
            group.throughput(Throughput::Bytes(size as u64));

            let key = vec![0x42u8; key_len];
            let nonce = [0u8; 12];
            let aad = b"benchmark";
            let plaintext = vec![0u8; size];

            group.bench_with_input(
                BenchmarkId::new(format!("{label}/encrypt"), size),
                &size,
                |b, _| {
                    b.iter(|| gcm_encrypt(&key, &nonce, aad, &plaintext).unwrap());
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("{label}/decrypt"), size),
                &size,
                |b, _| {
                    let ct_with_tag = gcm_encrypt(&key, &nonce, aad, &plaintext).unwrap();
                    b.iter(|| gcm_decrypt(&key, &nonce, aad, &ct_with_tag).unwrap());
                },
            );
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// AES-CBC benchmarks
// ---------------------------------------------------------------------------

fn bench_aes_cbc(c: &mut Criterion) {
    use hitls_crypto::modes::cbc::{cbc_decrypt, cbc_encrypt};

    let mut group = c.benchmark_group("aes-cbc");

    for (key_len, label) in [(16, "aes-128-cbc"), (32, "aes-256-cbc")] {
        for size in [1024usize, 8192, 16384] {
            group.throughput(Throughput::Bytes(size as u64));

            let key = vec![0x42u8; key_len];
            let iv = [0u8; 16];
            let plaintext = vec![0u8; size];

            group.bench_with_input(
                BenchmarkId::new(format!("{label}/encrypt"), size),
                &size,
                |b, _| {
                    b.iter(|| cbc_encrypt(&key, &iv, &plaintext).unwrap());
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("{label}/decrypt"), size),
                &size,
                |b, _| {
                    let ct = cbc_encrypt(&key, &iv, &plaintext).unwrap();
                    b.iter(|| cbc_decrypt(&key, &iv, &ct).unwrap());
                },
            );
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// AES-CTR benchmarks
// ---------------------------------------------------------------------------

fn bench_aes_ctr(c: &mut Criterion) {
    use hitls_crypto::modes::ctr::ctr_crypt;

    let mut group = c.benchmark_group("aes-ctr");

    for (key_len, label) in [(16, "aes-128-ctr"), (32, "aes-256-ctr")] {
        for size in [1024usize, 8192, 16384] {
            group.throughput(Throughput::Bytes(size as u64));

            let key = vec![0x42u8; key_len];
            let nonce = [0u8; 16];

            group.bench_with_input(
                BenchmarkId::new(format!("{label}/crypt"), size),
                &size,
                |b, _| {
                    let mut data = vec![0u8; size];
                    b.iter(|| ctr_crypt(&key, &nonce, &mut data).unwrap());
                },
            );
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 benchmarks
// ---------------------------------------------------------------------------

fn bench_chacha20(c: &mut Criterion) {
    use hitls_crypto::chacha20::ChaCha20Poly1305;

    let mut group = c.benchmark_group("chacha20-poly1305");

    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let aad = b"benchmark";
    let cipher = ChaCha20Poly1305::new(&key).unwrap();

    for size in [1024usize, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, _| {
            b.iter(|| cipher.encrypt(&nonce, aad, &plaintext).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("decrypt", size), &size, |b, _| {
            let ct = cipher.encrypt(&nonce, aad, &plaintext).unwrap();
            b.iter(|| cipher.decrypt(&nonce, aad, &ct).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// SHA-2 benchmarks
// ---------------------------------------------------------------------------

fn bench_sha2(c: &mut Criterion) {
    use hitls_crypto::sha2::{Sha256, Sha384, Sha512};

    let mut group = c.benchmark_group("sha");

    for size in [1024usize, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));
        let data = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("sha256", size), &size, |b, _| {
            b.iter(|| {
                let mut h = Sha256::new();
                h.update(&data).unwrap();
                h.finish().unwrap()
            });
        });

        group.bench_with_input(BenchmarkId::new("sha384", size), &size, |b, _| {
            b.iter(|| {
                let mut h = Sha384::new();
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
// SM3 benchmarks
// ---------------------------------------------------------------------------

fn bench_sm3(c: &mut Criterion) {
    use hitls_crypto::sm3::Sm3;

    let mut group = c.benchmark_group("sm3");

    for size in [1024usize, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));
        let data = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("hash", size), &size, |b, _| {
            b.iter(|| {
                let mut h = Sm3::new();
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
    use hitls_crypto::sha2::{Sha256, Sha512};
    use hitls_crypto::sm3::Sm3;

    // HMAC-SHA256
    {
        let mut group = c.benchmark_group("hmac-sha256");
        for size in [1024usize, 8192, 16384] {
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

    // HMAC-SHA512
    {
        let mut group = c.benchmark_group("hmac-sha512");
        for size in [1024usize, 8192, 16384] {
            group.throughput(Throughput::Bytes(size as u64));
            let key = [0x42u8; 64];
            let data = vec![0u8; size];

            group.bench_with_input(BenchmarkId::new("compute", size), &size, |b, _| {
                b.iter(|| {
                    let factory: fn() -> Box<dyn hitls_crypto::provider::Digest> =
                        || Box::new(Sha512::new());
                    let mut mac = Hmac::new(factory, &key).unwrap();
                    mac.update(&data).unwrap();
                    let mut out = [0u8; 64];
                    mac.finish(&mut out).unwrap();
                });
            });
        }
        group.finish();
    }

    // HMAC-SM3
    {
        let mut group = c.benchmark_group("hmac-sm3");
        for size in [1024usize, 8192, 16384] {
            group.throughput(Throughput::Bytes(size as u64));
            let key = [0x42u8; 32];
            let data = vec![0u8; size];

            group.bench_with_input(BenchmarkId::new("compute", size), &size, |b, _| {
                b.iter(|| {
                    let factory: fn() -> Box<dyn hitls_crypto::provider::Digest> =
                        || Box::new(Sm3::new());
                    let mut mac = Hmac::new(factory, &key).unwrap();
                    mac.update(&data).unwrap();
                    let mut out = [0u8; 32];
                    mac.finish(&mut out).unwrap();
                });
            });
        }
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// SM4 block benchmarks
// ---------------------------------------------------------------------------

fn bench_sm4(c: &mut Criterion) {
    use hitls_crypto::sm4::Sm4Key;

    let mut group = c.benchmark_group("sm4");

    let key = [0x42u8; 16];
    let cipher = Sm4Key::new(&key).unwrap();

    let mut block = [0u8; 16];
    group.bench_function("encrypt_block", |b| {
        b.iter(|| cipher.encrypt_block(&mut block).unwrap());
    });

    let mut block = [0u8; 16];
    group.bench_function("decrypt_block", |b| {
        b.iter(|| cipher.decrypt_block(&mut block).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// SM4-CBC benchmarks
// ---------------------------------------------------------------------------

fn bench_sm4_cbc(c: &mut Criterion) {
    use hitls_crypto::modes::cbc::{sm4_cbc_decrypt, sm4_cbc_encrypt};

    let mut group = c.benchmark_group("sm4-cbc");

    for size in [1024usize, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));

        let key = [0x42u8; 16];
        let iv = [0u8; 16];
        let plaintext = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, _| {
            b.iter(|| sm4_cbc_encrypt(&key, &iv, &plaintext).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("decrypt", size), &size, |b, _| {
            let ct = sm4_cbc_encrypt(&key, &iv, &plaintext).unwrap();
            b.iter(|| sm4_cbc_decrypt(&key, &iv, &ct).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// SM4-GCM benchmarks
// ---------------------------------------------------------------------------

fn bench_sm4_gcm(c: &mut Criterion) {
    use hitls_crypto::modes::gcm::{sm4_gcm_decrypt, sm4_gcm_encrypt};

    let mut group = c.benchmark_group("sm4-gcm");

    for size in [1024usize, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));

        let key = [0x42u8; 16];
        let nonce = [0u8; 12];
        let aad = b"benchmark";
        let plaintext = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, _| {
            b.iter(|| sm4_gcm_encrypt(&key, &nonce, aad, &plaintext).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("decrypt", size), &size, |b, _| {
            let ct = sm4_gcm_encrypt(&key, &nonce, aad, &plaintext).unwrap();
            b.iter(|| sm4_gcm_decrypt(&key, &nonce, aad, &ct).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// DH benchmarks
// ---------------------------------------------------------------------------

fn bench_dh(c: &mut Criterion) {
    use hitls_crypto::dh::{DhKeyPair, DhParams};
    use hitls_types::DhParamId;

    let mut group = c.benchmark_group("dh");
    group.sample_size(20);

    for (id, label) in [
        (DhParamId::Rfc7919_2048, "ffdhe2048"),
        (DhParamId::Rfc7919_3072, "ffdhe3072"),
        (DhParamId::Rfc7919_4096, "ffdhe4096"),
    ] {
        let params = DhParams::from_group(id).unwrap();
        let kp1 = DhKeyPair::generate(&params).unwrap();
        let kp2 = DhKeyPair::generate(&params).unwrap();
        let pk2 = kp2.public_key_bytes(&params).unwrap();

        group.bench_function(format!("{label}/keygen"), |b| {
            b.iter(|| DhKeyPair::generate(&params).unwrap());
        });

        group.bench_function(format!("{label}/key_derive"), |b| {
            b.iter(|| kp1.compute_shared_secret(&params, &pk2).unwrap());
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
// ECDH benchmarks
// ---------------------------------------------------------------------------

fn bench_ecdh(c: &mut Criterion) {
    use hitls_crypto::ecdh::EcdhKeyPair;
    use hitls_types::EccCurveId;

    let mut group = c.benchmark_group("ecdh");

    let kp1 = EcdhKeyPair::generate(EccCurveId::NistP256).unwrap();
    let kp2 = EcdhKeyPair::generate(EccCurveId::NistP256).unwrap();
    let pk2 = kp2.public_key_bytes().unwrap();

    group.bench_function("p256/key_derive", |b| {
        b.iter(|| kp1.compute_shared_secret(&pk2).unwrap());
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
// SM2 benchmarks
// ---------------------------------------------------------------------------

fn bench_sm2(c: &mut Criterion) {
    use hitls_crypto::sm2::Sm2KeyPair;

    let mut group = c.benchmark_group("sm2");

    let kp = Sm2KeyPair::generate().unwrap();
    let msg = b"benchmark message for SM2 signing";

    group.bench_function("sign", |b| {
        b.iter(|| kp.sign(msg).unwrap());
    });

    let sig = kp.sign(msg).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| kp.verify(msg, &sig).unwrap());
    });

    group.bench_function("encrypt", |b| {
        b.iter(|| kp.encrypt(msg).unwrap());
    });

    let ct = kp.encrypt(msg).unwrap();
    group.bench_function("decrypt", |b| {
        b.iter(|| kp.decrypt(&ct).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// RSA benchmarks
// ---------------------------------------------------------------------------

fn bench_rsa(c: &mut Criterion) {
    use hitls_crypto::rsa::{RsaPadding, RsaPrivateKey};

    let mut group = c.benchmark_group("rsa-2048");

    let sk = RsaPrivateKey::generate(2048).unwrap();
    let pk = sk.public_key();
    let digest = [0x42u8; 32]; // pre-hashed message

    group.bench_function("sign_pss", |b| {
        b.iter(|| sk.sign(RsaPadding::Pss, &digest).unwrap());
    });

    let sig = sk.sign(RsaPadding::Pss, &digest).unwrap();
    group.bench_function("verify_pss", |b| {
        b.iter(|| pk.verify(RsaPadding::Pss, &digest, &sig).unwrap());
    });

    group.bench_function("encrypt_oaep", |b| {
        b.iter(|| pk.encrypt(RsaPadding::Oaep, &digest).unwrap());
    });

    let ct = pk.encrypt(RsaPadding::Oaep, &digest).unwrap();
    group.bench_function("decrypt_oaep", |b| {
        b.iter(|| sk.decrypt(RsaPadding::Oaep, &ct).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ML-KEM benchmarks
// ---------------------------------------------------------------------------

fn bench_mlkem(c: &mut Criterion) {
    use hitls_crypto::mlkem::MlKemKeyPair;

    let mut group = c.benchmark_group("mlkem");

    for param in [512u32, 768, 1024] {
        let kp = MlKemKeyPair::generate(param).unwrap();

        group.bench_function(format!("mlkem-{param}/keygen"), |b| {
            b.iter(|| MlKemKeyPair::generate(param).unwrap());
        });

        group.bench_function(format!("mlkem-{param}/encaps"), |b| {
            b.iter(|| kp.encapsulate().unwrap());
        });

        let (_, ct) = kp.encapsulate().unwrap();
        group.bench_function(format!("mlkem-{param}/decaps"), |b| {
            b.iter(|| kp.decapsulate(&ct).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// ML-DSA benchmarks
// ---------------------------------------------------------------------------

fn bench_mldsa(c: &mut Criterion) {
    use hitls_crypto::mldsa::MlDsaKeyPair;

    let mut group = c.benchmark_group("mldsa");

    for param in [44u32, 65, 87] {
        let kp = MlDsaKeyPair::generate(param).unwrap();
        let msg = b"benchmark message for ML-DSA signing";

        group.bench_function(format!("mldsa-{param}/keygen"), |b| {
            b.iter(|| MlDsaKeyPair::generate(param).unwrap());
        });

        group.bench_function(format!("mldsa-{param}/sign"), |b| {
            b.iter(|| kp.sign(msg).unwrap());
        });

        let sig = kp.sign(msg).unwrap();
        group.bench_function(format!("mldsa-{param}/verify"), |b| {
            b.iter(|| kp.verify(msg, &sig).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// BigNum benchmarks
// ---------------------------------------------------------------------------

fn bench_bignum(c: &mut Criterion) {
    use hitls_bignum::BigNum;

    let mut group = c.benchmark_group("bignum");

    for size in [256, 512, 1024, 2048, 4096] {
        let bytes = vec![0xFFu8; size / 8];
        let a = BigNum::from_bytes_be(&bytes);
        let b_num = BigNum::from_bytes_be(&bytes);

        group.bench_with_input(BenchmarkId::new("mul", size), &size, |bench, _| {
            bench.iter(|| a.mul(&b_num));
        });

        group.bench_with_input(BenchmarkId::new("add", size), &size, |bench, _| {
            bench.iter(|| a.add(&b_num));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_aes,
    bench_aes_gcm,
    bench_aes_cbc,
    bench_aes_ctr,
    bench_chacha20,
    bench_sha2,
    bench_sm3,
    bench_hmac,
    bench_sm4,
    bench_sm4_cbc,
    bench_sm4_gcm,
    bench_ecdsa,
    bench_ecdh,
    bench_ed25519,
    bench_x25519,
    bench_sm2,
    bench_rsa,
    bench_mlkem,
    bench_mldsa,
    bench_dh,
    bench_bignum,
);
criterion_main!(benches);
