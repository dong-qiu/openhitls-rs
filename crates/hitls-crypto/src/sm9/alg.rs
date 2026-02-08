//! SM9 signature and encryption algorithms.

use hitls_bignum::BigNum;
use hitls_types::CryptoError;

use super::curve;
use super::ecp::EcPointG1;
use super::ecp2::EcPointG2;
use super::fp12::Fp12;
use super::hash;
use super::pairing;

/// Key type for SM9 master key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sm9KeyType {
    Sign,
    Encrypt,
}

/// Generate a master key pair.
/// For signing: Ppub = [ks]P2 (master pub on G2, user key on G1)
/// For encryption: Ppub = [ke]P1 (master pub on G1, user key on G2)
pub(crate) fn master_keygen(key_type: Sm9KeyType) -> Result<(BigNum, Vec<u8>), CryptoError> {
    let n = curve::order();
    let n_minus_1 = n.sub(&BigNum::from_u64(1));

    // Generate random master secret in [1, n-1]
    let ks = random_in_range(&n_minus_1)?;

    let pub_key = match key_type {
        Sm9KeyType::Sign => {
            let p2 = EcPointG2::generator();
            let ppub = p2.scalar_mul(&ks)?;
            ppub.to_bytes()?
        }
        Sm9KeyType::Encrypt => {
            let p1 = EcPointG1::generator();
            let ppub = p1.scalar_mul(&ks)?;
            ppub.to_bytes()?
        }
    };

    Ok((ks, pub_key))
}

/// Extract user private key from master secret and user ID.
/// For signing: dA = [ks/(H1(ID||0x01) + ks)]P1
/// For encryption: dB = [ke/(H1(ID||0x03) + ke)]P2
pub(crate) fn extract_user_key(
    ks: &BigNum,
    user_id: &[u8],
    key_type: Sm9KeyType,
) -> Result<Vec<u8>, CryptoError> {
    let n = curve::order();

    let hid = match key_type {
        Sm9KeyType::Sign => 0x01u8,
        Sm9KeyType::Encrypt => 0x03u8,
    };

    // t1 = H1(ID || hid) + ks mod n
    let mut input = Vec::with_capacity(user_id.len() + 1);
    input.extend_from_slice(user_id);
    input.push(hid);
    let h1_val = hash::h1(&input, 0x01)?;
    let t1 = h1_val.mod_add(ks, &n)?;

    if t1.is_zero() {
        return Err(CryptoError::InvalidArg); // Reject this ID
    }

    // t2 = ks · t1⁻¹ mod n
    let t1_inv = t1.mod_inv(&n)?;
    let t2 = ks.mod_mul(&t1_inv, &n)?;

    match key_type {
        Sm9KeyType::Sign => {
            let p1 = EcPointG1::generator();
            let d = p1.scalar_mul(&t2)?;
            d.to_bytes()
        }
        Sm9KeyType::Encrypt => {
            let p2 = EcPointG2::generator();
            let d = p2.scalar_mul(&t2)?;
            d.to_bytes()
        }
    }
}

/// SM9 signature: sign a message.
/// Returns signature bytes: h(32) || S(64).
pub(crate) fn sign(
    message: &[u8],
    user_key: &[u8], // dA: 64 bytes (point on G1)
    ppub: &[u8],     // Master public key: 128 bytes (point on G2)
) -> Result<Vec<u8>, CryptoError> {
    let n = curve::order();
    let da = EcPointG1::from_bytes(user_key)?;
    let ppub_pt = EcPointG2::from_bytes(ppub)?;

    // g = e(P1, Ppub) ∈ Fp12
    let p1 = EcPointG1::generator();
    let g = pairing::pairing(&p1, &ppub_pt)?;

    loop {
        // r ← random in [1, n-1]
        let n_minus_1 = n.sub(&BigNum::from_u64(1));
        let r = random_in_range(&n_minus_1)?;

        // w = g^r
        let w = g.pow(&r)?;
        let w_bytes = fp12_to_bytes(&w);

        // h = H2(M || w)
        let mut h2_input = Vec::with_capacity(message.len() + w_bytes.len());
        h2_input.extend_from_slice(message);
        h2_input.extend_from_slice(&w_bytes);
        let h = hash::h2(&h2_input)?;

        // l = (r - h) mod n
        let h_mod = h.mod_reduce(&n)?;
        let l = r.mod_add(&n.sub(&h_mod), &n)?;
        if l.is_zero() {
            continue; // Retry
        }

        // S = [l]dA
        let s_pt = da.scalar_mul(&l)?;
        let s_bytes = s_pt.to_bytes()?;

        // Signature: h(32) || S(64)
        let mut sig = Vec::with_capacity(96);
        let h_bytes = bignum_to_32bytes(&h);
        sig.extend_from_slice(&h_bytes);
        sig.extend_from_slice(&s_bytes);

        return Ok(sig);
    }
}

/// SM9 signature verification.
/// Returns true if signature is valid.
pub(crate) fn verify(
    message: &[u8],
    user_id: &[u8],
    signature: &[u8], // h(32) || S(64)
    ppub: &[u8],      // Master public key: 128 bytes
) -> Result<bool, CryptoError> {
    if signature.len() != 96 {
        return Ok(false);
    }

    let n = curve::order();
    let h = BigNum::from_bytes_be(&signature[..32]);
    let s_pt = EcPointG1::from_bytes(&signature[32..96])?;
    let ppub_pt = EcPointG2::from_bytes(ppub)?;

    // Check h in [1, n-1]
    if h.is_zero() || h >= n {
        return Ok(false);
    }

    // t = g^h where g = e(P1, Ppub)
    let p1 = EcPointG1::generator();
    let g = pairing::pairing(&p1, &ppub_pt)?;
    let t = g.pow(&h)?;

    // h1 = H1(ID || 0x01)
    let mut h1_input = Vec::with_capacity(user_id.len() + 1);
    h1_input.extend_from_slice(user_id);
    h1_input.push(0x01);
    let h1_val = hash::h1(&h1_input, 0x01)?;

    // P2_mul = [h1]P2 + Ppub
    let p2 = EcPointG2::generator();
    let h1_p2 = p2.scalar_mul(&h1_val)?;
    let p2_sum = h1_p2.add(&ppub_pt)?;

    // u = e(S, [h1]P2 + Ppub)
    let u = pairing::pairing(&s_pt, &p2_sum)?;

    // w' = u · t
    let w_prime = u.mul(&t)?;
    let w_bytes = fp12_to_bytes(&w_prime);

    // h2 = H2(M || w')
    let mut h2_input = Vec::with_capacity(message.len() + w_bytes.len());
    h2_input.extend_from_slice(message);
    h2_input.extend_from_slice(&w_bytes);
    let h2_val = hash::h2(&h2_input)?;

    // Verify h == h2
    Ok(h == h2_val)
}

/// SM9 encryption.
/// Returns ciphertext: C1(64) || C3(32) || C2(variable).
pub(crate) fn encrypt(
    message: &[u8],
    user_id: &[u8],
    ppub: &[u8], // Master public key for encryption: 64 bytes (point on G1)
) -> Result<Vec<u8>, CryptoError> {
    let n = curve::order();
    let ppub_pt = EcPointG1::from_bytes(ppub)?;

    // h1 = H1(ID || 0x03)
    let mut h1_input = Vec::with_capacity(user_id.len() + 1);
    h1_input.extend_from_slice(user_id);
    h1_input.push(0x03);
    let h1_val = hash::h1(&h1_input, 0x01)?;

    // QB = [h1]P1 + Ppub
    let p1 = EcPointG1::generator();
    let h1_p1 = p1.scalar_mul(&h1_val)?;
    let qb = h1_p1.add(&ppub_pt)?;

    // g = e(Ppub, P2)
    let p2 = EcPointG2::generator();
    let g = pairing::pairing(&ppub_pt, &p2)?;

    loop {
        // r ← random in [1, n-1]
        let n_minus_1 = n.sub(&BigNum::from_u64(1));
        let r = random_in_range(&n_minus_1)?;

        // C1 = [r]QB
        let c1 = qb.scalar_mul(&r)?;
        let c1_bytes = c1.to_bytes()?;

        // w = g^r
        let w = g.pow(&r)?;
        let w_bytes = fp12_to_bytes(&w);

        // K = KDF(C1 || w || ID_B, klen + 32)
        let klen = message.len();
        let k_total = klen + 32; // K1 for encryption + K2 for MAC
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(&c1_bytes);
        kdf_input.extend_from_slice(&w_bytes);
        kdf_input.extend_from_slice(user_id);

        let k = match hash::kdf(&kdf_input, k_total) {
            Ok(k) => k,
            Err(_) => continue, // KDF returned all zeros, retry
        };

        let k1 = &k[..klen];
        let k2 = &k[klen..];

        // C2 = M XOR K1
        let c2: Vec<u8> = message.iter().zip(k1.iter()).map(|(m, k)| m ^ k).collect();

        // C3 = SM3(M || K2)  — MAC
        let c3 = {
            use crate::sm3::Sm3;
            let mut h = Sm3::new();
            h.update(message)?;
            h.update(k2)?;
            h.finish()?
        };

        // Output: C1(64) || C3(32) || C2(var)
        let mut ct = Vec::with_capacity(64 + 32 + c2.len());
        ct.extend_from_slice(&c1_bytes);
        ct.extend_from_slice(&c3);
        ct.extend_from_slice(&c2);

        return Ok(ct);
    }
}

/// SM9 decryption.
pub(crate) fn decrypt(
    ciphertext: &[u8],
    user_key: &[u8], // dB: 128 bytes (point on G2)
    user_id: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < 96 {
        return Err(CryptoError::InvalidArg);
    }

    let c1_bytes = &ciphertext[..64];
    let c3 = &ciphertext[64..96];
    let c2 = &ciphertext[96..];
    let klen = c2.len();

    let c1 = EcPointG1::from_bytes(c1_bytes)?;
    let db = EcPointG2::from_bytes(user_key)?;

    // w' = e(C1, dB)
    let w_prime = pairing::pairing(&c1, &db)?;
    let w_bytes = fp12_to_bytes(&w_prime);

    // K = KDF(C1 || w' || ID, klen + 32)
    let mut kdf_input = Vec::new();
    kdf_input.extend_from_slice(c1_bytes);
    kdf_input.extend_from_slice(&w_bytes);
    kdf_input.extend_from_slice(user_id);

    let k = hash::kdf(&kdf_input, klen + 32)?;
    let k1 = &k[..klen];
    let k2 = &k[klen..];

    // M' = C2 XOR K1
    let m_prime: Vec<u8> = c2.iter().zip(k1.iter()).map(|(c, k)| c ^ k).collect();

    // Verify: C3 == SM3(M' || K2)
    let c3_check = {
        use crate::sm3::Sm3;
        let mut h = Sm3::new();
        h.update(&m_prime)?;
        h.update(k2)?;
        h.finish()?
    };

    if c3 != c3_check.as_slice() {
        return Err(CryptoError::Sm9VerifyFail);
    }

    Ok(m_prime)
}

// Helper functions

/// Generate random BigNum in [1, max].
fn random_in_range(max: &BigNum) -> Result<BigNum, CryptoError> {
    let bytes_len = max.to_bytes_be().len();
    loop {
        let mut buf = vec![0u8; bytes_len];
        getrandom::getrandom(&mut buf).map_err(|_| CryptoError::BnRandGenFail)?;
        let val = BigNum::from_bytes_be(&buf);
        if !val.is_zero() && val <= *max {
            return Ok(val);
        }
    }
}

/// Convert Fp12 element to bytes for hashing.
fn fp12_to_bytes(f: &Fp12) -> Vec<u8> {
    // Serialize all 12 Fp elements (32 bytes each = 384 bytes total)
    let mut out = Vec::with_capacity(384);
    // c0 = Fp4(Fp2(c00, c01), Fp2(c10, c11))
    out.extend_from_slice(&f.c0.c0.c0.to_bytes_be());
    out.extend_from_slice(&f.c0.c0.c1.to_bytes_be());
    out.extend_from_slice(&f.c0.c1.c0.to_bytes_be());
    out.extend_from_slice(&f.c0.c1.c1.to_bytes_be());
    out.extend_from_slice(&f.c1.c0.c0.to_bytes_be());
    out.extend_from_slice(&f.c1.c0.c1.to_bytes_be());
    out.extend_from_slice(&f.c1.c1.c0.to_bytes_be());
    out.extend_from_slice(&f.c1.c1.c1.to_bytes_be());
    out.extend_from_slice(&f.c2.c0.c0.to_bytes_be());
    out.extend_from_slice(&f.c2.c0.c1.to_bytes_be());
    out.extend_from_slice(&f.c2.c1.c0.to_bytes_be());
    out.extend_from_slice(&f.c2.c1.c1.to_bytes_be());
    out
}

/// Convert BigNum to exactly 32 bytes (big-endian, zero-padded).
fn bignum_to_32bytes(n: &BigNum) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = n.to_bytes_be();
    let start = if bytes.len() > 32 {
        0
    } else {
        32 - bytes.len()
    };
    let copy_len = core::cmp::min(bytes.len(), 32);
    out[start..start + copy_len].copy_from_slice(&bytes[bytes.len() - copy_len..]);
    out
}
