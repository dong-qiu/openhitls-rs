//! Throughput benchmark for cryptographic algorithms.

use std::time::{Duration, Instant};

pub fn run(algorithm: &str, seconds: u64) -> Result<(), Box<dyn std::error::Error>> {
    let duration = Duration::from_secs(seconds);

    match algorithm {
        "aes-128-gcm" => bench_aes_gcm(16, duration),
        "aes-256-gcm" => bench_aes_gcm(32, duration),
        "chacha20-poly1305" => bench_chacha20(duration),
        "sha256" => bench_hash("SHA-256", duration, |data| {
            hitls_crypto::sha2::Sha256::digest(data).map(|_| ())
        }),
        "sha384" => bench_hash("SHA-384", duration, |data| {
            hitls_crypto::sha2::Sha384::digest(data).map(|_| ())
        }),
        "sha512" => bench_hash("SHA-512", duration, |data| {
            hitls_crypto::sha2::Sha512::digest(data).map(|_| ())
        }),
        "sm3" => bench_hash("SM3", duration, |data| {
            hitls_crypto::sm3::Sm3::digest(data).map(|_| ())
        }),
        "all" => {
            bench_aes_gcm(16, duration)?;
            bench_aes_gcm(32, duration)?;
            bench_chacha20(duration)?;
            bench_hash("SHA-256", duration, |data| {
                hitls_crypto::sha2::Sha256::digest(data).map(|_| ())
            })?;
            bench_hash("SHA-384", duration, |data| {
                hitls_crypto::sha2::Sha384::digest(data).map(|_| ())
            })?;
            bench_hash("SM3", duration, |data| {
                hitls_crypto::sm3::Sm3::digest(data).map(|_| ())
            })?;
            Ok(())
        }
        _ => Err(format!(
            "unknown algorithm: {algorithm}\n\
             Valid: aes-128-gcm, aes-256-gcm, chacha20-poly1305, sha256, sha384, sha512, sm3, all"
        )
        .into()),
    }
}

fn bench_aes_gcm(key_len: usize, duration: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let name = if key_len == 16 {
        "AES-128-GCM"
    } else {
        "AES-256-GCM"
    };
    let key = vec![0x42u8; key_len];
    let nonce = [0x01u8; 12];
    let aad = b"benchmark";
    let block = vec![0u8; 8192];

    let start = Instant::now();
    let mut total_bytes: u64 = 0;
    let mut ops: u64 = 0;

    while start.elapsed() < duration {
        let _ = hitls_crypto::modes::gcm::gcm_encrypt(&key, &nonce, aad, &block)
            .map_err(|e| format!("{e}"))?;
        total_bytes += block.len() as u64;
        ops += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let mb_per_sec = total_bytes as f64 / (1024.0 * 1024.0) / elapsed;
    println!("{name:24} {mb_per_sec:10.2} MB/s  ({ops} ops in {elapsed:.2}s)");
    Ok(())
}

fn bench_chacha20(duration: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let aad = b"benchmark";
    let block = vec![0u8; 8192];

    let cipher = hitls_crypto::chacha20::ChaCha20Poly1305::new(&key).map_err(|e| format!("{e}"))?;

    let start = Instant::now();
    let mut total_bytes: u64 = 0;
    let mut ops: u64 = 0;

    while start.elapsed() < duration {
        let _ = cipher
            .encrypt(&nonce, aad, &block)
            .map_err(|e| format!("{e}"))?;
        total_bytes += block.len() as u64;
        ops += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let mb_per_sec = total_bytes as f64 / (1024.0 * 1024.0) / elapsed;
    let name = "ChaCha20-Poly1305";
    println!("{name:24} {mb_per_sec:10.2} MB/s  ({ops} ops in {elapsed:.2}s)");
    Ok(())
}

fn bench_hash<F>(
    name: &str,
    duration: Duration,
    hash_fn: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: Fn(&[u8]) -> Result<(), hitls_types::CryptoError>,
{
    let block = vec![0u8; 8192];

    let start = Instant::now();
    let mut total_bytes: u64 = 0;
    let mut ops: u64 = 0;

    while start.elapsed() < duration {
        hash_fn(&block).map_err(|e| format!("{e}"))?;
        total_bytes += block.len() as u64;
        ops += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let mb_per_sec = total_bytes as f64 / (1024.0 * 1024.0) / elapsed;
    println!("{name:24} {mb_per_sec:10.2} MB/s  ({ops} ops in {elapsed:.2}s)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_speed_sha256() {
        run("sha256", 1).unwrap();
    }

    #[test]
    fn test_cli_speed_invalid_algorithm() {
        assert!(run("invalid", 1).is_err());
    }
}
