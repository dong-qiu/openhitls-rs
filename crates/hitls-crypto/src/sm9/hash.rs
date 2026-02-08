//! SM9 hash functions H1, H2 and KDF.
//!
//! H1 and H2 hash arbitrary data to an integer in [1, n-1].
//! KDF derives keys using SM3 in counter mode.

use hitls_bignum::BigNum;
use hitls_types::CryptoError;

use super::curve;

/// H1(ID || hid, n): hash identity to range [1, n-1].
/// hid = 0x01 for signing.
pub(crate) fn h1(id: &[u8], hid: u8) -> Result<BigNum, CryptoError> {
    hash_to_range(id, hid)
}

/// H2(M || w, n): hash message and pairing value to range [1, n-1].
pub(crate) fn h2(data: &[u8]) -> Result<BigNum, CryptoError> {
    hash_to_range(data, 0x02)
}

/// Hash to range [1, n-1] using SM3.
/// Algorithm: ct=1, compute Ha = SM3(0x01||data||ct) iteratively,
/// interpret Ha₁||Ha₂ as 256+32=288-bit integer, return (Ha mod (n-1)) + 1.
fn hash_to_range(data: &[u8], hash_id: u8) -> Result<BigNum, CryptoError> {
    use crate::sm3::Sm3;

    let n = curve::order();
    let n_minus_1 = n.sub(&BigNum::from_u64(1));

    // We need ceil(log2(n)/32)*32 = 256 bits → but the spec says
    // hlen = 8*ceil(5*log2(n)/32) = 8*ceil(5*256/32) = 8*40 = 320 bits = 40 bytes
    // So we compute two SM3 hashes (32+32=64 bytes), take first 40 bytes.
    let hlen = 40;
    let mut hash_buf = Vec::with_capacity(64);

    let mut ct: u32 = 1;
    while hash_buf.len() < hlen {
        let mut h = Sm3::new();
        h.update(&[hash_id])?;
        h.update(data)?;
        h.update(&ct.to_be_bytes())?;
        let digest = h.finish()?;
        hash_buf.extend_from_slice(&digest);
        ct += 1;
    }
    hash_buf.truncate(hlen);

    // Interpret as big-endian integer
    let ha = BigNum::from_bytes_be(&hash_buf);

    // result = (ha mod (n-1)) + 1
    let r = ha.mod_reduce(&n_minus_1)?;
    Ok(r.add(&BigNum::from_u64(1)))
}

/// KDF(Z, klen): Key derivation function using SM3 in counter mode.
/// Returns `klen` bytes derived from input `z`.
pub(crate) fn kdf(z: &[u8], klen: usize) -> Result<Vec<u8>, CryptoError> {
    use crate::sm3::Sm3;

    let mut result = Vec::with_capacity(klen);
    let mut ct: u32 = 1;

    while result.len() < klen {
        let mut h = Sm3::new();
        h.update(z)?;
        h.update(&ct.to_be_bytes())?;
        let digest = h.finish()?;
        result.extend_from_slice(&digest);
        ct += 1;
    }
    result.truncate(klen);

    // Check that the key is not all zeros
    if result.iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidArg);
    }

    Ok(result)
}
