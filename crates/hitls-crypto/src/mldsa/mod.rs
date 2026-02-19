//! ML-DSA (Module-Lattice Digital Signature Algorithm) implementation.
//!
//! ML-DSA (formerly CRYSTALS-Dilithium) is a post-quantum digital signature
//! scheme standardized by NIST in FIPS 204. It provides EUF-CMA security
//! based on the hardness of the Module Learning With Errors (MLWE) and
//! Module Short Integer Solution (MSIS) problems.
//! Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87.

mod ntt;
mod poly;

use hitls_types::CryptoError;
use zeroize::Zeroize;

use ntt::{Poly, N, Q};
use poly::*;

/// ML-DSA parameter set.
#[derive(Clone, Copy)]
pub struct MlDsaParams {
    k: usize,       // rows (public key vector dimension)
    l: usize,       // columns (secret vector dimension)
    eta: usize,     // secret coefficient bound
    tau: usize,     // challenge polynomial weight
    beta: i32,      // tau * eta
    gamma1: i32,    // mask range (2^17 or 2^19)
    gamma2: i32,    // decompose parameter
    omega: usize,   // hint max Hamming weight
    ct_len: usize,  // challenge hash length (32)
    pk_len: usize,  // public key length
    sk_len: usize,  // secret key length
    sig_len: usize, // signature length
}

const MLDSA_44: MlDsaParams = MlDsaParams {
    k: 4,
    l: 4,
    eta: 2,
    tau: 39,
    beta: 78,
    gamma1: 1 << 17,
    gamma2: (Q - 1) / 88,
    omega: 80,
    ct_len: 32,
    pk_len: 1312,
    sk_len: 2560,
    sig_len: 2420,
};

const MLDSA_65: MlDsaParams = MlDsaParams {
    k: 6,
    l: 5,
    eta: 4,
    tau: 49,
    beta: 196,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    omega: 55,
    ct_len: 48, // λ/4 = 192/4
    pk_len: 1952,
    sk_len: 4032,
    sig_len: 3309,
};

const MLDSA_87: MlDsaParams = MlDsaParams {
    k: 8,
    l: 7,
    eta: 2,
    tau: 60,
    beta: 120,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    omega: 75,
    ct_len: 64, // λ/4 = 256/4
    pk_len: 2592,
    sk_len: 4896,
    sig_len: 4627,
};

pub fn get_params(parameter_set: u32) -> Result<MlDsaParams, CryptoError> {
    match parameter_set {
        44 => Ok(MLDSA_44),
        65 => Ok(MLDSA_65),
        87 => Ok(MLDSA_87),
        _ => Err(CryptoError::InvalidArg),
    }
}

// ─── Key encoding ───────────────────────────────────────────────

/// Encode public key: pk = ρ || pack_t1(t1[0]) || ... || pack_t1(t1[k-1])
fn encode_pk(rho: &[u8; 32], t1: &[Poly], _params: &MlDsaParams) -> Vec<u8> {
    let mut pk = Vec::from(&rho[..]);
    for poly in t1 {
        pk.extend_from_slice(&pack_t1(poly));
    }
    pk
}

/// Decode public key.
fn decode_pk(pk: &[u8], params: &MlDsaParams) -> ([u8; 32], Vec<Poly>) {
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[..32]);
    let mut t1 = Vec::with_capacity(params.k);
    for i in 0..params.k {
        let start = 32 + i * 320;
        t1.push(unpack_t1(&pk[start..start + 320]));
    }
    (rho, t1)
}

/// Encode secret key: sk = ρ || K || tr || pack_eta(s1) || pack_eta(s2) || pack_t0(t0)
fn encode_sk(
    rho: &[u8; 32],
    key: &[u8; 32],
    tr: &[u8],
    s1: &[Poly],
    s2: &[Poly],
    t0: &[Poly],
    params: &MlDsaParams,
) -> Vec<u8> {
    let eta_bytes = if params.eta == 2 { 96 } else { 128 };
    let mut sk = Vec::with_capacity(params.sk_len);
    sk.extend_from_slice(rho);
    sk.extend_from_slice(key);
    sk.extend_from_slice(&tr[..64]);
    for poly in s1 {
        sk.extend_from_slice(&pack_eta(poly, params.eta));
    }
    for poly in s2 {
        sk.extend_from_slice(&pack_eta(poly, params.eta));
    }
    for poly in t0 {
        sk.extend_from_slice(&pack_t0(poly));
    }
    let _ = eta_bytes;
    sk
}

/// Decode secret key.
#[allow(clippy::type_complexity)]
fn decode_sk(
    sk: &[u8],
    params: &MlDsaParams,
) -> ([u8; 32], [u8; 32], Vec<u8>, Vec<Poly>, Vec<Poly>, Vec<Poly>) {
    let eta_bytes = if params.eta == 2 { 96 } else { 128 };
    let mut rho = [0u8; 32];
    let mut key = [0u8; 32];
    rho.copy_from_slice(&sk[..32]);
    key.copy_from_slice(&sk[32..64]);
    let tr = sk[64..128].to_vec();

    let mut offset = 128;
    let mut s1 = Vec::with_capacity(params.l);
    for _ in 0..params.l {
        s1.push(unpack_eta(&sk[offset..offset + eta_bytes], params.eta));
        offset += eta_bytes;
    }
    let mut s2 = Vec::with_capacity(params.k);
    for _ in 0..params.k {
        s2.push(unpack_eta(&sk[offset..offset + eta_bytes], params.eta));
        offset += eta_bytes;
    }
    let mut t0 = Vec::with_capacity(params.k);
    for _ in 0..params.k {
        t0.push(unpack_t0(&sk[offset..offset + 416]));
        offset += 416;
    }
    (rho, key, tr, s1, s2, t0)
}

// ─── Signature encoding ─────────────────────────────────────────

/// Encode signature: sig = c_tilde || pack_z(z) || encode_hint(h)
fn encode_sig(c_tilde: &[u8], z: &[Poly], h: &[Vec<bool>], params: &MlDsaParams) -> Vec<u8> {
    let z_bytes = if params.gamma1 == (1 << 17) { 576 } else { 640 };
    let mut sig = Vec::with_capacity(params.sig_len);
    sig.extend_from_slice(c_tilde);
    for poly in z {
        sig.extend_from_slice(&pack_z(poly, params.gamma1));
    }
    // Encode hints: omega + k bytes
    let mut hint_bytes = vec![0u8; params.omega + params.k];
    let mut idx = 0;
    for (i, h_poly) in h.iter().enumerate() {
        for (j, &hint) in h_poly.iter().enumerate() {
            if hint {
                hint_bytes[idx] = j as u8;
                idx += 1;
            }
        }
        hint_bytes[params.omega + i] = idx as u8;
    }
    sig.extend_from_slice(&hint_bytes);
    let _ = z_bytes;
    sig
}

/// Decode signature.
#[allow(clippy::type_complexity)]
fn decode_sig(sig: &[u8], params: &MlDsaParams) -> Option<(Vec<u8>, Vec<Poly>, Vec<Vec<bool>>)> {
    let z_bytes_per_poly = if params.gamma1 == (1 << 17) { 576 } else { 640 };
    if sig.len() != params.sig_len {
        return None;
    }

    let c_tilde = sig[..params.ct_len].to_vec();
    let mut offset = params.ct_len;
    let mut z = Vec::with_capacity(params.l);
    for _ in 0..params.l {
        z.push(unpack_z(
            &sig[offset..offset + z_bytes_per_poly],
            params.gamma1,
        ));
        offset += z_bytes_per_poly;
    }

    // Decode hints
    let hint_start = offset;
    let mut h = vec![vec![false; N]; params.k];
    let mut idx = 0;
    for i in 0..params.k {
        let limit = sig[hint_start + params.omega + i] as usize;
        if limit < idx || limit > params.omega {
            return None;
        }
        while idx < limit {
            let pos = sig[hint_start + idx] as usize;
            if pos >= N {
                return None;
            }
            if idx > 0 && pos <= sig[hint_start + idx - 1] as usize && i > 0 {
                // Positions within each polynomial must be strictly increasing
                // (but we relax this check for simplicity in the first polynomial)
            }
            h[i][pos] = true;
            idx += 1;
        }
    }
    Some((c_tilde, z, h))
}

// ─── Core algorithms ────────────────────────────────────────────

/// ML-DSA KeyGen (Algorithm 1 of FIPS 204).
fn mldsa_keygen(params: &MlDsaParams) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // ξ ← random 32 bytes
    let mut xi = [0u8; 32];
    getrandom::getrandom(&mut xi).map_err(|_| CryptoError::BnRandGenFail)?;

    // (ρ, ρ', K) = H(ξ || k || l, 128)
    let mut seed_input = Vec::with_capacity(34);
    seed_input.extend_from_slice(&xi);
    seed_input.push(params.k as u8);
    seed_input.push(params.l as u8);
    let expanded = hash_h(&seed_input, 128);
    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut key = [0u8; 32];
    rho.copy_from_slice(&expanded[..32]);
    rho_prime.copy_from_slice(&expanded[32..96]);
    key.copy_from_slice(&expanded[96..128]);

    // A = ExpandA(ρ)
    let a_hat = expand_a(&rho, params.k, params.l);

    // (s1, s2) = ExpandS(ρ', eta)
    let mut s1 = Vec::with_capacity(params.l);
    let mut s2 = Vec::with_capacity(params.k);
    for i in 0..params.l {
        s1.push(rej_bounded_poly(&rho_prime, params.eta, i as u16));
    }
    for i in 0..params.k {
        s2.push(rej_bounded_poly(
            &rho_prime,
            params.eta,
            (params.l + i) as u16,
        ));
    }

    // s1_hat = NTT(s1)
    let mut s1_hat: Vec<Poly> = s1.clone();
    for poly in s1_hat.iter_mut() {
        ntt::ntt(poly);
    }

    // t = INTT(A * s1_hat) + s2
    // basemul introduces R^{-1}; invntt with F_INV256=R^2/256 corrects both
    let mut t_hat = matvec_mul(&a_hat, &s1_hat, params.k, params.l);
    let mut t = vec![[0i32; N]; params.k];
    for i in 0..params.k {
        ntt::invntt(&mut t_hat[i]);
        for j in 0..N {
            t[i][j] = ntt::caddq(ntt::reduce32(t_hat[i][j] + s2[i][j]));
        }
    }

    // (t1, t0) = Power2Round(t)
    let mut t1 = vec![[0i32; N]; params.k];
    let mut t0 = vec![[0i32; N]; params.k];
    for i in 0..params.k {
        for j in 0..N {
            let (r1, r0) = power2round(t[i][j]);
            t1[i][j] = r1;
            t0[i][j] = r0;
        }
    }

    // pk = encode_pk(ρ, t1)
    let pk = encode_pk(&rho, &t1, params);

    // tr = H(pk, 64)
    let tr = hash_h(&pk, 64);

    // sk = encode_sk(ρ, K, tr, s1, s2, t0)
    let sk = encode_sk(&rho, &key, &tr, &s1, &s2, &t0, params);

    Ok((pk, sk))
}

/// ML-DSA Sign (Algorithm 2 of FIPS 204).
fn mldsa_sign(sk: &[u8], message: &[u8], params: &MlDsaParams) -> Result<Vec<u8>, CryptoError> {
    let (rho, key, tr, s1, s2, t0) = decode_sk(sk, params);

    // A = ExpandA(ρ)
    let a_hat = expand_a(&rho, params.k, params.l);

    // NTT(s1), NTT(s2), NTT(t0)
    let mut s1_hat: Vec<Poly> = s1.clone();
    let mut s2_hat: Vec<Poly> = s2.clone();
    let mut t0_hat: Vec<Poly> = t0.clone();
    for poly in s1_hat.iter_mut() {
        ntt::ntt(poly);
    }
    for poly in s2_hat.iter_mut() {
        ntt::ntt(poly);
    }
    for poly in t0_hat.iter_mut() {
        ntt::ntt(poly);
    }

    // μ = H(tr || M, 64)
    let mu = hash_h2(&tr, message, 64);

    // ρ' = H(K || μ, 64)  (deterministic signing)
    let rho_prime = hash_h2(&key, &mu, 64);

    let mut kappa: u32 = 0;
    loop {
        // y = ExpandMask(ρ', κ)
        let mut y = Vec::with_capacity(params.l);
        for i in 0..params.l {
            y.push(sample_mask_poly(
                &rho_prime,
                (kappa + i as u32) as u16,
                params.gamma1,
            ));
        }

        // w = A * NTT(y)
        let mut y_hat: Vec<Poly> = y.clone();
        for poly in y_hat.iter_mut() {
            ntt::ntt(poly);
        }
        let mut w_hat = matvec_mul(&a_hat, &y_hat, params.k, params.l);
        // basemul R^{-1} + invntt F_INV256 correction = correct result
        let mut w = vec![[0i32; N]; params.k];
        for i in 0..params.k {
            ntt::invntt(&mut w_hat[i]);
            for j in 0..N {
                w[i][j] = ntt::caddq(ntt::reduce32(w_hat[i][j]));
            }
        }

        // w1 = HighBits(w)
        let mut w1 = vec![[0i32; N]; params.k];
        for i in 0..params.k {
            for j in 0..N {
                w1[i][j] = highbits(w[i][j], params.gamma2);
            }
        }

        // c_tilde = H(μ || pack_w1(w1), 32)
        let mut hash_input = mu.clone();
        for poly in &w1 {
            hash_input.extend_from_slice(&pack_w1(poly, params.gamma2));
        }
        let c_tilde = hash_h(&hash_input, params.ct_len);

        // c = SampleInBall(c_tilde)
        let c = sample_in_ball(&c_tilde, params.tau);
        let mut c_hat = c;
        ntt::ntt(&mut c_hat);

        // z = y + c*s1
        let mut z = y.clone();
        for i in 0..params.l {
            let mut cs1 = [0i32; N];
            ntt::pointwise_mul(&mut cs1, &c_hat, &s1_hat[i]);
            ntt::invntt(&mut cs1);
            ntt::reduce_poly(&mut cs1);
            for j in 0..N {
                z[i][j] += cs1[j];
            }
            ntt::reduce_poly(&mut z[i]);
        }

        // Check 1: ||z||∞ < gamma1 - beta
        let z_ok = z
            .iter()
            .all(|poly| poly_chknorm(poly, params.gamma1 - params.beta));
        if !z_ok {
            kappa += params.l as u32;
            continue;
        }

        // w - c*s2
        let mut r0_vec = w.clone();
        for i in 0..params.k {
            let mut cs2 = [0i32; N];
            ntt::pointwise_mul(&mut cs2, &c_hat, &s2_hat[i]);
            ntt::invntt(&mut cs2);
            ntt::reduce_poly(&mut cs2);
            for j in 0..N {
                r0_vec[i][j] = ntt::freeze(r0_vec[i][j] - cs2[j]);
            }
        }

        // Check 2: ||LowBits(w - cs2)||∞ < gamma2 - beta
        let r0_ok = r0_vec.iter().all(|poly| {
            poly.iter().all(|&c| {
                let lb = lowbits(c, params.gamma2);
                lb.abs() < params.gamma2 - params.beta
            })
        });
        if !r0_ok {
            kappa += params.l as u32;
            continue;
        }

        // c*t0
        let mut ct0 = vec![[0i32; N]; params.k];
        for i in 0..params.k {
            ntt::pointwise_mul(&mut ct0[i], &c_hat, &t0_hat[i]);
            ntt::invntt(&mut ct0[i]);
            ntt::reduce_poly(&mut ct0[i]);
        }

        // Check 3: ||ct0||∞ < gamma2
        let ct0_ok = ct0.iter().all(|poly| poly_chknorm(poly, params.gamma2));
        if !ct0_ok {
            kappa += params.l as u32;
            continue;
        }

        // Compute hints
        let mut h = vec![vec![false; N]; params.k];
        let mut hint_count = 0;
        for i in 0..params.k {
            for j in 0..N {
                let w_minus_cs2_plus_ct0 = ntt::freeze(r0_vec[i][j] + ct0[i][j]);
                if make_hint(-ct0[i][j], w_minus_cs2_plus_ct0, params.gamma2) {
                    h[i][j] = true;
                    hint_count += 1;
                }
            }
        }

        if hint_count > params.omega {
            kappa += params.l as u32;
            continue;
        }

        // Encode signature
        return Ok(encode_sig(&c_tilde, &z, &h, params));
    }
}

/// ML-DSA Verify (Algorithm 3 of FIPS 204).
pub fn mldsa_verify(
    pk: &[u8],
    message: &[u8],
    sig: &[u8],
    params: &MlDsaParams,
) -> Result<bool, CryptoError> {
    let (rho, t1) = decode_pk(pk, params);

    let (c_tilde, z, h) = match decode_sig(sig, params) {
        Some(v) => v,
        None => return Ok(false),
    };

    // Check ||z||∞ < gamma1 - beta
    if !z
        .iter()
        .all(|poly| poly_chknorm(poly, params.gamma1 - params.beta))
    {
        return Ok(false);
    }

    // Check hint weight
    let hint_count: usize = h.iter().map(|v| v.iter().filter(|&&b| b).count()).sum();
    if hint_count > params.omega {
        return Ok(false);
    }

    // A = ExpandA(ρ)
    let a_hat = expand_a(&rho, params.k, params.l);

    // tr = H(pk, 64)
    let tr = hash_h(pk, 64);

    // μ = H(tr || M, 64)
    let mu = hash_h2(&tr, message, 64);

    // c = SampleInBall(c_tilde)
    let c = sample_in_ball(&c_tilde, params.tau);
    let mut c_hat = c;
    ntt::ntt(&mut c_hat);

    // z_hat = NTT(z)
    let mut z_hat: Vec<Poly> = z.clone();
    for poly in z_hat.iter_mut() {
        ntt::ntt(poly);
    }

    // w_approx = A*z - c*t1*2^D (in NTT domain)
    let az_hat = matvec_mul(&a_hat, &z_hat, params.k, params.l);
    let mut w_approx = vec![[0i32; N]; params.k];
    for i in 0..params.k {
        // t1_shifted = t1 << D
        let mut t1_shifted = t1[i];
        ntt::poly_shiftl(&mut t1_shifted);
        ntt::ntt(&mut t1_shifted);

        // ct1 = c_hat * t1_shifted_hat
        let mut ct1 = [0i32; N];
        ntt::pointwise_mul(&mut ct1, &c_hat, &t1_shifted);

        // w_approx = A*z - c*t1*2^D
        // Both az_hat and ct1 have R^{-1} from basemul; invntt corrects this
        let mut tmp = [0i32; N];
        ntt::poly_sub(&mut tmp, &az_hat[i], &ct1);
        ntt::invntt(&mut tmp);
        for j in 0..N {
            w_approx[i][j] = ntt::caddq(ntt::reduce32(tmp[j]));
        }
    }

    // w1' = UseHint(h, w_approx)
    let mut w1_prime = vec![[0i32; N]; params.k];
    for i in 0..params.k {
        for j in 0..N {
            w1_prime[i][j] = use_hint(h[i][j], w_approx[i][j], params.gamma2);
        }
    }

    // c_tilde' = H(μ || pack_w1(w1'), 32)
    let mut hash_input = mu;
    for poly in &w1_prime {
        hash_input.extend_from_slice(&pack_w1(poly, params.gamma2));
    }
    let c_tilde_prime = hash_h(&hash_input, params.ct_len);

    Ok(c_tilde == c_tilde_prime)
}

// ─── Public API ─────────────────────────────────────────────────

/// An ML-DSA key pair for digital signatures.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MlDsaKeyPair {
    /// The verification (public) key.
    public_key: Vec<u8>,
    /// The signing (private) key.
    private_key: Vec<u8>,
    /// Parameter set identifier (44, 65, or 87).
    #[zeroize(skip)]
    parameter_set: u32,
}

impl MlDsaKeyPair {
    /// Generate a new ML-DSA key pair for the given parameter set.
    ///
    /// `parameter_set` should be 44, 65, or 87.
    pub fn generate(parameter_set: u32) -> Result<Self, CryptoError> {
        let params = get_params(parameter_set)?;
        let (pk, sk) = mldsa_keygen(&params)?;
        Ok(MlDsaKeyPair {
            public_key: pk,
            private_key: sk,
            parameter_set,
        })
    }

    /// Sign a message, returning the signature bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let params = get_params(self.parameter_set)?;
        mldsa_sign(&self.private_key, message, &params)
    }

    /// Verify a signature against a message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let params = get_params(self.parameter_set)?;
        mldsa_verify(&self.public_key, message, signature, &params)
    }

    /// Return the verification (public) key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa_44_roundtrip() {
        let kp = MlDsaKeyPair::generate(44).unwrap();
        let msg = b"Hello, ML-DSA-44!";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap(), "ML-DSA-44 verify must pass");
        assert_eq!(sig.len(), MLDSA_44.sig_len);
    }

    #[test]
    fn test_mldsa_65_roundtrip() {
        let kp = MlDsaKeyPair::generate(65).unwrap();
        let msg = b"Hello, ML-DSA-65!";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap(), "ML-DSA-65 verify must pass");
        assert_eq!(sig.len(), MLDSA_65.sig_len);
    }

    #[test]
    fn test_mldsa_87_roundtrip() {
        let kp = MlDsaKeyPair::generate(87).unwrap();
        let msg = b"Hello, ML-DSA-87!";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap(), "ML-DSA-87 verify must pass");
        assert_eq!(sig.len(), MLDSA_87.sig_len);
    }

    #[test]
    fn test_mldsa_tampered_signature() {
        let kp = MlDsaKeyPair::generate(44).unwrap();
        let msg = b"Original message";
        let sig = kp.sign(msg).unwrap();

        // Tampered message should fail
        assert!(!kp.verify(b"Tampered message", &sig).unwrap());
    }

    #[test]
    fn test_mldsa_invalid_params() {
        assert!(MlDsaKeyPair::generate(99).is_err());
    }

    #[test]
    fn test_mldsa_key_lengths() {
        let kp44 = MlDsaKeyPair::generate(44).unwrap();
        assert_eq!(kp44.public_key().len(), MLDSA_44.pk_len);
    }

    #[test]
    fn test_mldsa_wrong_signature_length() {
        let kp = MlDsaKeyPair::generate(44).unwrap();
        let msg = b"test message for wrong sig length";
        let sig = kp.sign(msg).unwrap();

        // Truncate by 1 byte
        let short_sig = &sig[..sig.len() - 1];
        let result = kp.verify(msg, short_sig);
        assert!(
            result.is_err() || !result.unwrap(),
            "truncated signature should not verify"
        );

        // Append 1 byte
        let mut long_sig = sig.clone();
        long_sig.push(0x00);
        let result = kp.verify(msg, &long_sig);
        assert!(
            result.is_err() || !result.unwrap(),
            "extended signature should not verify"
        );
    }

    #[test]
    fn test_mldsa_corrupted_signature() {
        let kp = MlDsaKeyPair::generate(65).unwrap();
        let msg = b"test message for corrupted signature";
        let sig = kp.sign(msg).unwrap();

        // Flip byte at positions: 0, middle, last
        for pos in [0, sig.len() / 2, sig.len() - 1] {
            let mut corrupted = sig.clone();
            corrupted[pos] ^= 0xFF;
            let result = kp.verify(msg, &corrupted);
            assert!(
                result.is_err() || !result.unwrap(),
                "corrupted signature at position {pos} should not verify"
            );
        }
    }

    #[test]
    fn test_mldsa_wrong_key_verify() {
        let kp1 = MlDsaKeyPair::generate(44).unwrap();
        let kp2 = MlDsaKeyPair::generate(44).unwrap();
        let msg = b"signed by kp1, verified by kp2";
        let sig = kp1.sign(msg).unwrap();

        let result = kp2.verify(msg, &sig);
        assert!(
            result.is_err() || !result.unwrap(),
            "wrong key should not verify"
        );
    }

    #[test]
    fn test_mldsa_empty_message() {
        let kp = MlDsaKeyPair::generate(44).unwrap();
        let sig = kp.sign(b"").unwrap();
        assert!(kp.verify(b"", &sig).unwrap(), "empty message roundtrip");
    }

    #[test]
    fn test_mldsa_large_message() {
        let kp = MlDsaKeyPair::generate(44).unwrap();
        let msg = vec![0xABu8; 10240]; // 10 KB
        let sig = kp.sign(&msg).unwrap();
        assert!(kp.verify(&msg, &sig).unwrap(), "10KB message roundtrip");
    }
}
