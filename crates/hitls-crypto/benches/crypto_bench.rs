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

    for (curve, label) in [
        (EccCurveId::NistP256, "p256"),
        (EccCurveId::NistP384, "p384"),
        (EccCurveId::NistP521, "p521"),
    ] {
        let kp1 = EcdhKeyPair::generate(curve).unwrap();
        let kp2 = EcdhKeyPair::generate(curve).unwrap();
        let pk2 = kp2.public_key_bytes().unwrap();

        group.bench_function(format!("{label}/key_derive"), |b| {
            b.iter(|| kp1.compute_shared_secret(&pk2).unwrap());
        });
    }

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

    // Modular exponentiation benchmarks
    group.sample_size(20);
    for size in [1024, 2048, 4096] {
        let base_bytes = vec![0x42u8; size / 8];
        let base = BigNum::from_bytes_be(&base_bytes);
        let exp_bytes = vec![0xFFu8; size / 8];
        let exp = BigNum::from_bytes_be(&exp_bytes);
        // Use a prime-like modulus (odd number with top bit set)
        let mut mod_bytes = vec![0xFFu8; size / 8];
        mod_bytes[size / 8 - 1] = 0xFD; // ensure odd
        let modulus = BigNum::from_bytes_be(&mod_bytes);

        group.bench_with_input(BenchmarkId::new("mod_exp", size), &size, |bench, _| {
            bench.iter(|| base.mod_exp(&exp, &modulus).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// SHA-3 + SHAKE benchmarks
// ---------------------------------------------------------------------------

fn bench_sha3(c: &mut Criterion) {
    use hitls_crypto::sha3::{Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};

    // SHA-3 fixed-output hashes
    {
        let mut group = c.benchmark_group("sha3");
        for size in [1024usize, 8192, 16384] {
            group.throughput(Throughput::Bytes(size as u64));
            let data = vec![0u8; size];

            group.bench_with_input(BenchmarkId::new("sha3-256", size), &size, |b, _| {
                b.iter(|| {
                    let mut h = Sha3_256::new();
                    h.update(&data).unwrap();
                    h.finish().unwrap()
                });
            });

            group.bench_with_input(BenchmarkId::new("sha3-384", size), &size, |b, _| {
                b.iter(|| {
                    let mut h = Sha3_384::new();
                    h.update(&data).unwrap();
                    h.finish().unwrap()
                });
            });

            group.bench_with_input(BenchmarkId::new("sha3-512", size), &size, |b, _| {
                b.iter(|| {
                    let mut h = Sha3_512::new();
                    h.update(&data).unwrap();
                    h.finish().unwrap()
                });
            });
        }
        group.finish();
    }

    // SHAKE XOFs
    {
        let mut group = c.benchmark_group("shake");
        for size in [1024usize, 8192, 16384] {
            group.throughput(Throughput::Bytes(size as u64));
            let data = vec![0u8; size];

            group.bench_with_input(BenchmarkId::new("shake128", size), &size, |b, _| {
                let mut out = vec![0u8; size];
                b.iter(|| {
                    let mut h = Shake128::new();
                    h.update(&data).unwrap();
                    h.squeeze_into(&mut out);
                });
            });

            group.bench_with_input(BenchmarkId::new("shake256", size), &size, |b, _| {
                let mut out = vec![0u8; size];
                b.iter(|| {
                    let mut h = Shake256::new();
                    h.update(&data).unwrap();
                    h.squeeze_into(&mut out);
                });
            });
        }
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// SLH-DSA benchmarks
// ---------------------------------------------------------------------------

fn bench_slh_dsa(c: &mut Criterion) {
    use hitls_crypto::slh_dsa::SlhDsaKeyPair;
    use hitls_types::SlhDsaParamId;

    let mut group = c.benchmark_group("slh-dsa");
    group.sample_size(10);

    let msg = b"benchmark message for SLH-DSA signing";

    for (param_id, label) in [
        (SlhDsaParamId::Sha2128f, "sha2-128f"),
        (SlhDsaParamId::Shake128f, "shake-128f"),
        (SlhDsaParamId::Sha2192f, "sha2-192f"),
        (SlhDsaParamId::Sha2256f, "sha2-256f"),
    ] {
        group.bench_function(format!("{label}/keygen"), |b| {
            b.iter(|| SlhDsaKeyPair::generate(param_id).unwrap());
        });

        let kp = SlhDsaKeyPair::generate(param_id).unwrap();

        group.bench_function(format!("{label}/sign"), |b| {
            b.iter(|| kp.sign(msg).unwrap());
        });

        let sig = kp.sign(msg).unwrap();
        group.bench_function(format!("{label}/verify"), |b| {
            b.iter(|| kp.verify(msg, &sig).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// SM9 benchmarks
// ---------------------------------------------------------------------------

fn bench_sm9(c: &mut Criterion) {
    use hitls_crypto::sm9::{Sm9KeyType, Sm9MasterKey};

    let mut group = c.benchmark_group("sm9");
    group.sample_size(20);

    let user_id = b"alice@example.com";
    let msg = b"benchmark message for SM9 signing";

    // Sign
    let master_sign = Sm9MasterKey::generate(Sm9KeyType::Sign).unwrap();
    let user_sign = master_sign.extract_user_key(user_id).unwrap();
    let master_pub = master_sign.master_public_key().to_vec();

    group.bench_function("sign", |b| {
        b.iter(|| user_sign.sign(msg, &master_pub).unwrap());
    });

    let sig = user_sign.sign(msg, &master_pub).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| master_sign.verify(user_id, msg, &sig).unwrap());
    });

    // Encrypt
    let master_enc = Sm9MasterKey::generate(Sm9KeyType::Encrypt).unwrap();
    let user_enc = master_enc.extract_user_key(user_id).unwrap();

    group.bench_function("encrypt", |b| {
        b.iter(|| master_enc.encrypt(user_id, msg).unwrap());
    });

    let ct = master_enc.encrypt(user_id, msg).unwrap();
    group.bench_function("decrypt", |b| {
        b.iter(|| user_enc.decrypt(&ct).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Ed448 benchmarks
// ---------------------------------------------------------------------------

fn bench_ed448(c: &mut Criterion) {
    use hitls_crypto::ed448::Ed448KeyPair;

    let mut group = c.benchmark_group("ed448");

    let seed = [0x42u8; 57];
    let kp = Ed448KeyPair::from_seed(&seed).unwrap();
    let msg = b"benchmark message for Ed448 signing";

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
// X448 benchmarks
// ---------------------------------------------------------------------------

fn bench_x448(c: &mut Criterion) {
    use hitls_crypto::x448::X448PrivateKey;

    let mut group = c.benchmark_group("x448");

    let sk1_bytes = [0x42u8; 56];
    let sk2_bytes = [0x43u8; 56];
    let sk1 = X448PrivateKey::new(&sk1_bytes).unwrap();
    let sk2 = X448PrivateKey::new(&sk2_bytes).unwrap();
    let pk2 = sk2.public_key();

    group.bench_function("diffie_hellman", |b| {
        b.iter(|| sk1.diffie_hellman(&pk2).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ECDSA P-384 / P-521 benchmarks
// ---------------------------------------------------------------------------

fn bench_ecdsa_curves(c: &mut Criterion) {
    use hitls_crypto::ecdsa::EcdsaKeyPair;
    use hitls_types::EccCurveId;

    // P-384
    {
        let mut group = c.benchmark_group("ecdsa-p384");
        let kp = EcdsaKeyPair::generate(EccCurveId::NistP384).unwrap();
        let digest = [0x42u8; 48];

        group.bench_function("sign", |b| {
            b.iter(|| kp.sign(&digest).unwrap());
        });

        let sig = kp.sign(&digest).unwrap();
        group.bench_function("verify", |b| {
            b.iter(|| kp.verify(&digest, &sig).unwrap());
        });

        group.finish();
    }

    // P-521
    {
        let mut group = c.benchmark_group("ecdsa-p521");
        let kp = EcdsaKeyPair::generate(EccCurveId::NistP521).unwrap();
        let digest = [0x42u8; 64];

        group.bench_function("sign", |b| {
            b.iter(|| kp.sign(&digest).unwrap());
        });

        let sig = kp.sign(&digest).unwrap();
        group.bench_function("verify", |b| {
            b.iter(|| kp.verify(&digest, &sig).unwrap());
        });

        group.finish();
    }
}

// ---------------------------------------------------------------------------
// AES-CCM benchmarks
// ---------------------------------------------------------------------------

fn bench_aes_ccm(c: &mut Criterion) {
    use hitls_crypto::modes::ccm::{ccm_decrypt, ccm_encrypt};

    let mut group = c.benchmark_group("aes-ccm");

    for size in [1024usize, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));

        let key = [0x42u8; 16];
        let nonce = [0u8; 12];
        let aad = b"benchmark";
        let plaintext = vec![0u8; size];

        group.bench_with_input(
            BenchmarkId::new("aes-128-ccm/encrypt", size),
            &size,
            |b, _| {
                b.iter(|| ccm_encrypt(&key, &nonce, aad, &plaintext, 16).unwrap());
            },
        );

        group.bench_with_input(
            BenchmarkId::new("aes-128-ccm/decrypt", size),
            &size,
            |b, _| {
                let ct = ccm_encrypt(&key, &nonce, aad, &plaintext, 16).unwrap();
                b.iter(|| ccm_decrypt(&key, &nonce, aad, &ct, 16).unwrap());
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// CMAC benchmarks
// ---------------------------------------------------------------------------

fn bench_cmac(c: &mut Criterion) {
    use hitls_crypto::cmac::Cmac;

    let mut group = c.benchmark_group("cmac");

    for (key_len, label) in [(16, "aes-128"), (32, "aes-256")] {
        for size in [1024usize, 8192, 16384] {
            group.throughput(Throughput::Bytes(size as u64));

            let key = vec![0x42u8; key_len];
            let data = vec![0u8; size];

            group.bench_with_input(
                BenchmarkId::new(format!("{label}/compute"), size),
                &size,
                |b, _| {
                    b.iter(|| {
                        let mut mac = Cmac::new(&key).unwrap();
                        mac.update(&data).unwrap();
                        let mut tag = [0u8; 16];
                        mac.finish(&mut tag).unwrap();
                    });
                },
            );
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// HMAC-SHA384 benchmarks
// ---------------------------------------------------------------------------

fn bench_hmac_sha384(c: &mut Criterion) {
    use hitls_crypto::hmac::Hmac;
    use hitls_crypto::sha2::Sha384;

    let mut group = c.benchmark_group("hmac-sha384");

    for size in [1024usize, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));
        let key = [0x42u8; 48];
        let data = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("compute", size), &size, |b, _| {
            b.iter(|| {
                let factory: fn() -> Box<dyn hitls_crypto::provider::Digest> =
                    || Box::new(Sha384::new());
                let mut mac = Hmac::new(factory, &key).unwrap();
                mac.update(&data).unwrap();
                let mut out = [0u8; 48];
                mac.finish(&mut out).unwrap();
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// KDF benchmarks (HKDF, PBKDF2, DRBG)
// ---------------------------------------------------------------------------

fn bench_kdf(c: &mut Criterion) {
    use hitls_crypto::drbg::{CtrDrbg, HmacDrbg};
    use hitls_crypto::hkdf::Hkdf;
    use hitls_crypto::pbkdf2::pbkdf2;

    // HKDF
    {
        let mut group = c.benchmark_group("hkdf");
        let salt = [0x42u8; 32];
        let ikm = [0x42u8; 32];
        let info = b"benchmark";

        group.bench_function("extract+expand/32B", |b| {
            b.iter(|| Hkdf::derive(&salt, &ikm, info, 32).unwrap());
        });

        group.bench_function("extract+expand/64B", |b| {
            b.iter(|| Hkdf::derive(&salt, &ikm, info, 64).unwrap());
        });

        group.finish();
    }

    // PBKDF2
    {
        let mut group = c.benchmark_group("pbkdf2");
        group.sample_size(10);
        let password = b"benchmark-password";
        let salt = b"benchmark-salt";

        group.bench_function("1000_iters", |b| {
            b.iter(|| pbkdf2(password, salt, 1000, 32).unwrap());
        });

        group.bench_function("10000_iters", |b| {
            b.iter(|| pbkdf2(password, salt, 10000, 32).unwrap());
        });

        group.finish();
    }

    // DRBG
    {
        let mut group = c.benchmark_group("drbg");

        group.bench_function("ctr-drbg/generate_32B", |b| {
            let mut drbg = CtrDrbg::new(&[0x42u8; 48]).unwrap();
            let mut out = [0u8; 32];
            b.iter(|| drbg.generate(&mut out, None).unwrap());
        });

        group.bench_function("hmac-drbg/generate_32B", |b| {
            let mut drbg = HmacDrbg::new(&[0x42u8; 48]).unwrap();
            let mut out = [0u8; 32];
            b.iter(|| drbg.generate(&mut out, None).unwrap());
        });

        group.finish();
    }
}

// ---------------------------------------------------------------------------
// HybridKEM benchmarks
// ---------------------------------------------------------------------------

fn bench_hybridkem(c: &mut Criterion) {
    use hitls_crypto::hybridkem::HybridKemKeyPair;
    use hitls_types::HybridKemParamId;

    let mut group = c.benchmark_group("hybridkem");

    for (param_id, label) in [
        (HybridKemParamId::X25519MlKem768, "x25519-mlkem768"),
        (HybridKemParamId::EcdhNistP256MlKem768, "p256-mlkem768"),
        (HybridKemParamId::EcdhNistP384MlKem768, "p384-mlkem768"),
    ] {
        let kp = HybridKemKeyPair::generate(param_id).unwrap();

        group.bench_function(format!("{label}/keygen"), |b| {
            b.iter(|| HybridKemKeyPair::generate(param_id).unwrap());
        });

        group.bench_function(format!("{label}/encaps"), |b| {
            b.iter(|| kp.encapsulate().unwrap());
        });

        let (_, ct) = kp.encapsulate().unwrap();
        group.bench_function(format!("{label}/decaps"), |b| {
            b.iter(|| kp.decapsulate(&ct).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// AES-XTS benchmarks
// ---------------------------------------------------------------------------

fn bench_aes_xts(c: &mut Criterion) {
    use hitls_crypto::modes::xts::{xts_decrypt, xts_encrypt};

    let mut group = c.benchmark_group("aes-xts");

    for (key_len, label) in [(16, "aes-128-xts"), (32, "aes-256-xts")] {
        for size in [1024usize, 8192, 16384] {
            group.throughput(Throughput::Bytes(size as u64));

            let key1 = vec![0x42u8; key_len];
            let key2 = vec![0x43u8; key_len];
            let tweak = [0u8; 16];
            let plaintext = vec![0u8; size];

            group.bench_with_input(
                BenchmarkId::new(format!("{label}/encrypt"), size),
                &size,
                |b, _| {
                    b.iter(|| xts_encrypt(&key1, &key2, &tweak, &plaintext).unwrap());
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("{label}/decrypt"), size),
                &size,
                |b, _| {
                    let ct = xts_encrypt(&key1, &key2, &tweak, &plaintext).unwrap();
                    b.iter(|| xts_decrypt(&key1, &key2, &tweak, &ct).unwrap());
                },
            );
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// AES-CFB benchmarks
// ---------------------------------------------------------------------------

fn bench_aes_cfb(c: &mut Criterion) {
    use hitls_crypto::modes::cfb::{cfb_decrypt, cfb_encrypt};

    let mut group = c.benchmark_group("aes-cfb");

    for (key_len, label) in [(16, "aes-128-cfb"), (32, "aes-256-cfb")] {
        for size in [1024usize, 8192, 16384] {
            group.throughput(Throughput::Bytes(size as u64));

            let key = vec![0x42u8; key_len];
            let iv = [0u8; 16];
            let plaintext = vec![0u8; size];

            group.bench_with_input(
                BenchmarkId::new(format!("{label}/encrypt"), size),
                &size,
                |b, _| {
                    b.iter(|| cfb_encrypt(&key, &iv, &plaintext).unwrap());
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("{label}/decrypt"), size),
                &size,
                |b, _| {
                    let ct = cfb_encrypt(&key, &iv, &plaintext).unwrap();
                    b.iter(|| cfb_decrypt(&key, &iv, &ct).unwrap());
                },
            );
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// AES-OFB benchmarks
// ---------------------------------------------------------------------------

fn bench_aes_ofb(c: &mut Criterion) {
    use hitls_crypto::modes::ofb::ofb_crypt;

    let mut group = c.benchmark_group("aes-ofb");

    for (key_len, label) in [(16, "aes-128-ofb"), (32, "aes-256-ofb")] {
        for size in [1024usize, 8192, 16384] {
            group.throughput(Throughput::Bytes(size as u64));

            let key = vec![0x42u8; key_len];
            let iv = [0u8; 16];

            group.bench_with_input(
                BenchmarkId::new(format!("{label}/crypt"), size),
                &size,
                |b, _| {
                    let mut data = vec![0u8; size];
                    b.iter(|| ofb_crypt(&key, &iv, &mut data).unwrap());
                },
            );
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// AES-ECB benchmarks
// ---------------------------------------------------------------------------

fn bench_aes_ecb(c: &mut Criterion) {
    use hitls_crypto::modes::ecb::{ecb_decrypt, ecb_encrypt};

    let mut group = c.benchmark_group("aes-ecb");

    for (key_len, label) in [(16, "aes-128-ecb"), (32, "aes-256-ecb")] {
        for size in [1024usize, 8192, 16384] {
            group.throughput(Throughput::Bytes(size as u64));

            let key = vec![0x42u8; key_len];
            let plaintext = vec![0u8; size];

            group.bench_with_input(
                BenchmarkId::new(format!("{label}/encrypt"), size),
                &size,
                |b, _| {
                    b.iter(|| ecb_encrypt(&key, &plaintext).unwrap());
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("{label}/decrypt"), size),
                &size,
                |b, _| {
                    let ct = ecb_encrypt(&key, &plaintext).unwrap();
                    b.iter(|| ecb_decrypt(&key, &ct).unwrap());
                },
            );
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// AES Key Wrap benchmarks
// ---------------------------------------------------------------------------

fn bench_aes_wrap(c: &mut Criterion) {
    use hitls_crypto::modes::wrap::{key_unwrap, key_wrap};

    let mut group = c.benchmark_group("aes-wrap");

    for (kek_len, label) in [(16, "aes-128"), (32, "aes-256")] {
        let kek = vec![0x42u8; kek_len];
        // Wrap a 256-bit key (32 bytes, multiple of 8)
        let plaintext_key = [0x55u8; 32];

        group.bench_function(format!("{label}/wrap"), |b| {
            b.iter(|| key_wrap(&kek, &plaintext_key).unwrap());
        });

        let wrapped = key_wrap(&kek, &plaintext_key).unwrap();
        group.bench_function(format!("{label}/unwrap"), |b| {
            b.iter(|| key_unwrap(&kek, &wrapped).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// AES-HCTR benchmarks
// ---------------------------------------------------------------------------

fn bench_aes_hctr(c: &mut Criterion) {
    use hitls_crypto::modes::hctr::{hctr_decrypt, hctr_encrypt};

    let mut group = c.benchmark_group("aes-hctr");

    for size in [1024usize, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));

        let key = [0x42u8; 16];
        let hash_key = [0x43u8; 16];
        let tweak = [0u8; 16];
        let plaintext = vec![0u8; size];

        group.bench_with_input(
            BenchmarkId::new("aes-128-hctr/encrypt", size),
            &size,
            |b, _| {
                b.iter(|| hctr_encrypt(&key, &hash_key, &tweak, &plaintext).unwrap());
            },
        );

        group.bench_with_input(
            BenchmarkId::new("aes-128-hctr/decrypt", size),
            &size,
            |b, _| {
                let ct = hctr_encrypt(&key, &hash_key, &tweak, &plaintext).unwrap();
                b.iter(|| hctr_decrypt(&key, &hash_key, &tweak, &ct).unwrap());
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// SM4-CCM benchmarks
// ---------------------------------------------------------------------------

fn bench_sm4_ccm(c: &mut Criterion) {
    use hitls_crypto::modes::ccm::{sm4_ccm_decrypt, sm4_ccm_encrypt};

    let mut group = c.benchmark_group("sm4-ccm");

    for size in [1024usize, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));

        let key = [0x42u8; 16];
        let nonce = [0u8; 12];
        let aad = b"benchmark";
        let plaintext = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, _| {
            b.iter(|| sm4_ccm_encrypt(&key, &nonce, aad, &plaintext, 16).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("decrypt", size), &size, |b, _| {
            let ct = sm4_ccm_encrypt(&key, &nonce, aad, &plaintext, 16).unwrap();
            b.iter(|| sm4_ccm_decrypt(&key, &nonce, aad, &ct, 16).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// scrypt benchmarks
// ---------------------------------------------------------------------------

fn bench_scrypt(c: &mut Criterion) {
    use hitls_crypto::scrypt::scrypt;

    let mut group = c.benchmark_group("scrypt");
    group.sample_size(10);

    let password = b"benchmark-password";
    let salt = b"benchmark-salt";

    group.bench_function("n1024_r8_p1", |b| {
        b.iter(|| scrypt(password, salt, 1024, 8, 1, 32).unwrap());
    });

    group.bench_function("n16384_r8_p1", |b| {
        b.iter(|| scrypt(password, salt, 16384, 8, 1, 32).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// DSA benchmarks
// ---------------------------------------------------------------------------

fn bench_dsa(c: &mut Criterion) {
    use hitls_crypto::dsa::{DsaKeyPair, DsaParams};

    let mut group = c.benchmark_group("dsa");
    group.sample_size(20);

    // Use small but non-trivial params: p=23, q=11, g=4
    // (realistic 2048-bit params require prime generation which is too slow for setup)
    let params = DsaParams::new(&[23], &[11], &[4]).unwrap();
    let kp = DsaKeyPair::generate(params).unwrap();
    let digest = [0x42u8; 2]; // digest shorter than q

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
// FrodoKEM benchmarks
// ---------------------------------------------------------------------------

fn bench_frodokem(c: &mut Criterion) {
    use hitls_crypto::frodokem::FrodoKemKeyPair;
    use hitls_types::FrodoKemParamId;

    let mut group = c.benchmark_group("frodokem");
    group.sample_size(10);

    for (param_id, label) in [
        (FrodoKemParamId::FrodoKem640Shake, "frodokem-640-shake"),
        (FrodoKemParamId::FrodoKem976Shake, "frodokem-976-shake"),
    ] {
        group.bench_function(format!("{label}/keygen"), |b| {
            b.iter(|| FrodoKemKeyPair::generate(param_id).unwrap());
        });

        let kp = FrodoKemKeyPair::generate(param_id).unwrap();

        group.bench_function(format!("{label}/encaps"), |b| {
            b.iter(|| kp.encapsulate().unwrap());
        });

        let (ct, _) = kp.encapsulate().unwrap();
        group.bench_function(format!("{label}/decaps"), |b| {
            b.iter(|| kp.decapsulate(&ct).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// HPKE benchmarks
// ---------------------------------------------------------------------------

fn bench_hpke(c: &mut Criterion) {
    use hitls_crypto::hpke::HpkeCtx;
    use hitls_crypto::x25519::X25519PrivateKey;

    let mut group = c.benchmark_group("hpke");

    let sk_bytes = [0x42u8; 32];
    let sk = X25519PrivateKey::new(&sk_bytes).unwrap();
    let pk = sk.public_key();
    let pk_bytes = pk.as_bytes();
    let info = b"benchmark";
    let aad = b"benchmark-aad";
    let msg = b"benchmark message for HPKE seal/open operations";

    group.bench_function("setup+seal", |b| {
        b.iter(|| {
            let (mut ctx, _enc) = HpkeCtx::setup_sender(pk_bytes, info).unwrap();
            ctx.seal(aad, msg).unwrap()
        });
    });

    // Pre-setup for open benchmark
    let (mut sender_ctx, enc) = HpkeCtx::setup_sender(pk_bytes, info).unwrap();
    let ct = sender_ctx.seal(aad, msg).unwrap();

    group.bench_function("setup+open", |b| {
        b.iter(|| {
            let mut ctx = HpkeCtx::setup_recipient(&sk_bytes, &enc, info).unwrap();
            ctx.open(aad, &ct).unwrap()
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// SHA-1 benchmarks
// ---------------------------------------------------------------------------

fn bench_sha1(c: &mut Criterion) {
    use hitls_crypto::sha1::Sha1;

    let mut group = c.benchmark_group("sha1");

    for size in [1024usize, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));
        let data = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("hash", size), &size, |b, _| {
            b.iter(|| {
                let mut h = Sha1::new();
                h.update(&data).unwrap();
                h.finish().unwrap()
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// MD5 benchmarks
// ---------------------------------------------------------------------------

fn bench_md5(c: &mut Criterion) {
    use hitls_crypto::md5::Md5;

    let mut group = c.benchmark_group("md5");

    for size in [1024usize, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));
        let data = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("hash", size), &size, |b, _| {
            b.iter(|| {
                let mut h = Md5::new();
                h.update(&data).unwrap();
                h.finish().unwrap()
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// GMAC benchmarks
// ---------------------------------------------------------------------------

fn bench_gmac(c: &mut Criterion) {
    use hitls_crypto::gmac::Gmac;

    let mut group = c.benchmark_group("gmac");

    for size in [1024usize, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));

        let key = [0x42u8; 16];
        let iv = [0u8; 12];
        let data = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("aes-128/compute", size), &size, |b, _| {
            b.iter(|| {
                let mut mac = Gmac::new(&key, &iv).unwrap();
                mac.update(&data).unwrap();
                let mut tag = [0u8; 16];
                mac.finish(&mut tag).unwrap();
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// SipHash benchmarks
// ---------------------------------------------------------------------------

fn bench_siphash(c: &mut Criterion) {
    use hitls_crypto::siphash::SipHash;

    let mut group = c.benchmark_group("siphash");

    for size in [64usize, 1024, 8192] {
        group.throughput(Throughput::Bytes(size as u64));
        let key = [0x42u8; 16];
        let data = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("hash", size), &size, |b, _| {
            b.iter(|| SipHash::hash(&key, &data).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// CBC-MAC-SM4 benchmarks
// ---------------------------------------------------------------------------

fn bench_cbc_mac_sm4(c: &mut Criterion) {
    use hitls_crypto::cbc_mac::CbcMacSm4;

    let mut group = c.benchmark_group("cbc-mac-sm4");

    for size in [1024usize, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));

        let key = [0x42u8; 16];
        let data = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("compute", size), &size, |b, _| {
            b.iter(|| {
                let mut mac = CbcMacSm4::new(&key).unwrap();
                mac.update(&data).unwrap();
                let mut tag = [0u8; 16];
                mac.finish(&mut tag).unwrap();
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// XMSS benchmarks
// ---------------------------------------------------------------------------

fn bench_xmss(c: &mut Criterion) {
    use hitls_crypto::xmss::XmssKeyPair;
    use hitls_types::XmssParamId;

    let mut group = c.benchmark_group("xmss");
    group.sample_size(10);

    // Only h=10 (1024 signatures) — keygen is expensive even at this size
    let param_id = XmssParamId::Sha2_10_256;
    let msg = b"benchmark message for XMSS signing";

    let mut kp = XmssKeyPair::generate(param_id).unwrap();
    let sig = kp.sign(msg).unwrap();

    // Verify-only benchmark (sign is stateful and consumes OTS keys)
    group.bench_function("sha2-10-256/verify", |b| {
        b.iter(|| kp.verify(msg, &sig).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// McEliece benchmarks
// ---------------------------------------------------------------------------

fn bench_mceliece(c: &mut Criterion) {
    use hitls_crypto::mceliece::McElieceKeyPair;
    use hitls_types::McElieceParamId;

    let mut group = c.benchmark_group("mceliece");
    group.sample_size(10);

    // Use smallest param set; keygen is too slow to benchmark
    let param_id = McElieceParamId::McEliece6688128;
    let kp = McElieceKeyPair::generate(param_id).unwrap();

    group.bench_function("6688128/encaps", |b| {
        b.iter(|| kp.encapsulate().unwrap());
    });

    let (ct, _) = kp.encapsulate().unwrap();
    group.bench_function("6688128/decaps", |b| {
        b.iter(|| kp.decapsulate(&ct).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ElGamal benchmarks
// ---------------------------------------------------------------------------

fn bench_elgamal(c: &mut Criterion) {
    use hitls_bignum::BigNum;
    use hitls_crypto::elgamal::ElGamalKeyPair;

    let mut group = c.benchmark_group("elgamal");
    group.sample_size(10);

    // Use pre-defined small safe prime p=23, g=5
    let p = BigNum::from_u64(23);
    let g = BigNum::from_u64(5);
    let kp = ElGamalKeyPair::from_params(&p, &g).unwrap();
    let msg = &[2u8]; // plaintext must be < p

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
// Paillier benchmarks
// ---------------------------------------------------------------------------

fn bench_paillier(c: &mut Criterion) {
    use hitls_crypto::paillier::PaillierKeyPair;

    let mut group = c.benchmark_group("paillier");
    group.sample_size(10);

    // 512-bit key for reasonable benchmark time
    let kp = PaillierKeyPair::generate(512).unwrap();
    let msg = [0x42u8; 32];

    group.bench_function("512/encrypt", |b| {
        b.iter(|| kp.encrypt(&msg).unwrap());
    });

    let ct = kp.encrypt(&msg).unwrap();
    group.bench_function("512/decrypt", |b| {
        b.iter(|| kp.decrypt(&ct).unwrap());
    });

    let ct2 = kp.encrypt(&[0x01]).unwrap();
    group.bench_function("512/add_ciphertexts", |b| {
        b.iter(|| kp.add_ciphertexts(&ct, &ct2).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Hash-DRBG + SM4-CTR-DRBG benchmarks
// ---------------------------------------------------------------------------

fn bench_drbg_extra(c: &mut Criterion) {
    use hitls_crypto::drbg::hash_drbg::{HashDrbg, HashDrbgType};
    use hitls_crypto::drbg::sm4_ctr_drbg::Sm4CtrDrbg;

    let mut group = c.benchmark_group("drbg-extra");

    group.bench_function("hash-drbg-sha256/generate_32B", |b| {
        let mut drbg = HashDrbg::new(HashDrbgType::Sha256, &[0x42u8; 55]).unwrap();
        let mut out = [0u8; 32];
        b.iter(|| drbg.generate(&mut out, None).unwrap());
    });

    group.bench_function("sm4-ctr-drbg/generate_32B", |b| {
        let mut drbg = Sm4CtrDrbg::new(&[0x42u8; 32]).unwrap();
        let mut out = [0u8; 32];
        b.iter(|| drbg.generate(&mut out, None).unwrap());
    });

    group.finish();
}

criterion_group!(
    benches,
    // Symmetric ciphers & modes
    bench_aes,
    bench_aes_gcm,
    bench_aes_cbc,
    bench_aes_ctr,
    bench_aes_ccm,
    bench_aes_xts,
    bench_aes_cfb,
    bench_aes_ofb,
    bench_aes_ecb,
    bench_aes_wrap,
    bench_aes_hctr,
    bench_chacha20,
    bench_sm4,
    bench_sm4_cbc,
    bench_sm4_gcm,
    bench_sm4_ccm,
    // Hash functions
    bench_sha1,
    bench_sha2,
    bench_sha3,
    bench_sm3,
    bench_md5,
    // MACs
    bench_hmac,
    bench_hmac_sha384,
    bench_cmac,
    bench_gmac,
    bench_siphash,
    bench_cbc_mac_sm4,
    // Asymmetric / signatures
    bench_ecdsa,
    bench_ecdsa_curves,
    bench_ecdh,
    bench_ed25519,
    bench_ed448,
    bench_x25519,
    bench_x448,
    bench_sm2,
    bench_sm9,
    bench_rsa,
    bench_dsa,
    bench_dh,
    bench_elgamal,
    bench_paillier,
    bench_hpke,
    // PQC
    bench_mlkem,
    bench_mldsa,
    bench_slh_dsa,
    bench_hybridkem,
    bench_frodokem,
    bench_mceliece,
    bench_xmss,
    // KDFs & DRBGs
    bench_kdf,
    bench_scrypt,
    bench_drbg_extra,
    // BigNum
    bench_bignum,
);
criterion_main!(benches);
