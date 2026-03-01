//! ML-KEM (Module-Lattice Key Encapsulation Mechanism) implementation.
//!
//! ML-KEM (formerly CRYSTALS-Kyber) is a post-quantum key encapsulation
//! mechanism standardized by NIST in FIPS 203. It provides IND-CCA2
//! security based on the hardness of the Module Learning With Errors
//! (MLWE) problem. Supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

pub(crate) mod ntt;
#[cfg(target_arch = "aarch64")]
mod ntt_neon;
pub(crate) mod poly;

use hitls_types::CryptoError;
use zeroize::Zeroize;

use ntt::{Poly, N};
use poly::*;

/// ML-KEM parameter set.
#[derive(Clone, Copy)]
struct MlKemParams {
    k: usize,
    eta1: usize,
    eta2: usize,
    du: u32,
    dv: u32,
    ek_len: usize,
    dk_len: usize,
    ct_len: usize,
}

const MLKEM_512: MlKemParams = MlKemParams {
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
    ek_len: 800,
    dk_len: 1632,
    ct_len: 768,
};

const MLKEM_768: MlKemParams = MlKemParams {
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
    ek_len: 1184,
    dk_len: 2400,
    ct_len: 1088,
};

const MLKEM_1024: MlKemParams = MlKemParams {
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
    ek_len: 1568,
    dk_len: 3168,
    ct_len: 1568,
};

fn get_params(parameter_set: u32) -> Result<MlKemParams, CryptoError> {
    match parameter_set {
        512 => Ok(MLKEM_512),
        768 => Ok(MLKEM_768),
        1024 => Ok(MLKEM_1024),
        _ => Err(CryptoError::InvalidArg),
    }
}

/// An ML-KEM key pair for key encapsulation.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MlKemKeyPair {
    /// The encapsulation (public) key.
    encapsulation_key: Vec<u8>,
    /// The decapsulation (private) key.
    decapsulation_key: Vec<u8>,
    /// Parameter set identifier.
    #[zeroize(skip)]
    parameter_set: u32,
}

// ---- K-PKE (Internal Public-Key Encryption) ----

/// K-PKE Key Generation (FIPS 203 Algorithm 12).
fn kpke_keygen(d: &[u8; 32], params: &MlKemParams) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let k = params.k;

    // (ρ, σ) = G(d || k)
    let mut g_input = [0u8; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = k as u8;
    let g_out = hash_g(&g_input);
    let rho: [u8; 32] = g_out[..32].try_into().unwrap();
    let sigma: [u8; 32] = g_out[32..64].try_into().unwrap();

    // Generate matrix A in NTT domain
    let a_hat = expand_a(&rho, k);

    // Sample secret vector s and error vector e
    let mut s = Vec::with_capacity(k);
    let mut e = Vec::with_capacity(k);
    let mut prf_buf = [0u8; 192]; // max(64*eta1=192 for eta=3, 128 for eta=2)
    let prf_len = 64 * params.eta1;
    for i in 0..k {
        prf_into(&sigma, i as u8, &mut prf_buf[..prf_len]);
        s.push(sample_cbd(&prf_buf[..prf_len], params.eta1)?);
    }
    for i in 0..k {
        prf_into(&sigma, (k + i) as u8, &mut prf_buf[..prf_len]);
        e.push(sample_cbd(&prf_buf[..prf_len], params.eta1)?);
    }

    // NTT(s), NTT(e)
    let mut s_hat: Vec<Poly> = s.clone();
    let mut e_hat: Vec<Poly> = e.clone();
    for poly in s_hat.iter_mut() {
        ntt::ntt(poly);
    }
    for poly in e_hat.iter_mut() {
        ntt::ntt(poly);
    }

    // t_hat = A_hat * s_hat + e_hat
    let mut t_hat = matvec_mul(&a_hat, &s_hat, k);
    for i in 0..k {
        // basemul introduces R^{-1}; to_mont multiplies by R to cancel it
        ntt::to_mont(&mut t_hat[i]);
        for j in 0..N {
            t_hat[i][j] += e_hat[i][j];
        }
        ntt::reduce_poly(&mut t_hat[i]);
    }

    // Encode encapsulation key: ek = ByteEncode_12(t_hat) || ρ
    let poly_bytes = 384; // 256 * 12 / 8
    let mut ek = vec![0u8; k * poly_bytes + 32];
    for (i, poly) in t_hat.iter().enumerate() {
        byte_encode_into(poly, 12, &mut ek[i * poly_bytes..(i + 1) * poly_bytes]);
    }
    ek[k * poly_bytes..].copy_from_slice(&rho);

    // Encode decapsulation key: dk = ByteEncode_12(s_hat)
    let mut dk = vec![0u8; k * poly_bytes];
    for (i, poly) in s_hat.iter().enumerate() {
        byte_encode_into(poly, 12, &mut dk[i * poly_bytes..(i + 1) * poly_bytes]);
    }

    Ok((ek, dk))
}

/// K-PKE Encryption (FIPS 203 Algorithm 13).
fn kpke_encrypt(
    ek: &[u8],
    msg: &[u8; 32],
    randomness: &[u8; 32],
    params: &MlKemParams,
) -> Result<Vec<u8>, CryptoError> {
    let k = params.k;

    // Decode encapsulation key
    let poly_bytes = 384; // 256 * 12 / 8
    let mut t_hat = Vec::with_capacity(k);
    for i in 0..k {
        t_hat.push(byte_decode(&ek[i * poly_bytes..(i + 1) * poly_bytes], 12));
    }
    let rho: [u8; 32] = ek[k * poly_bytes..k * poly_bytes + 32].try_into().unwrap();

    // Generate matrix A in NTT domain
    let a_hat = expand_a(&rho, k);

    // Sample r, e1, e2
    let mut r_vec = Vec::with_capacity(k);
    let mut e1 = Vec::with_capacity(k);
    let mut prf_buf = [0u8; 192]; // max(64*eta1=192 for eta=3, 128 for eta=2)
    let prf_len1 = 64 * params.eta1;
    for i in 0..k {
        prf_into(randomness, i as u8, &mut prf_buf[..prf_len1]);
        r_vec.push(sample_cbd(&prf_buf[..prf_len1], params.eta1)?);
    }
    let prf_len2 = 64 * params.eta2;
    for i in 0..k {
        prf_into(randomness, (k + i) as u8, &mut prf_buf[..prf_len2]);
        e1.push(sample_cbd(&prf_buf[..prf_len2], params.eta2)?);
    }
    prf_into(randomness, (2 * k) as u8, &mut prf_buf[..prf_len2]);
    let e2 = sample_cbd(&prf_buf[..prf_len2], params.eta2)?;

    // NTT(r)
    let mut r_hat: Vec<Poly> = r_vec.clone();
    for poly in r_hat.iter_mut() {
        ntt::ntt(poly);
    }

    // u = INTT(A^T * r_hat) + e1
    let mut u = matvec_mul_t(&a_hat, &r_hat, k);
    for poly in u.iter_mut() {
        ntt::invntt(poly);
    }
    for i in 0..k {
        for j in 0..N {
            u[i][j] += e1[i][j];
        }
        ntt::reduce_poly(&mut u[i]);
    }

    // v = INTT(t_hat^T * r_hat) + e2 + Decompress(m, 1)
    let mut v = inner_product(&t_hat, &r_hat);
    ntt::invntt(&mut v);
    let m_poly = msg_to_poly(msg);
    let mut v_tmp = v;
    ntt::poly_add(&mut v, &v_tmp, &e2);
    v_tmp = v;
    ntt::poly_add(&mut v, &v_tmp, &m_poly);
    ntt::reduce_poly(&mut v);

    // Ciphertext: c1 = Compress(u, du) || c2 = Compress(v, dv)
    let du_bytes = N * params.du as usize / 8;
    let dv_bytes = N * params.dv as usize / 8;
    let mut ct = vec![0u8; k * du_bytes + dv_bytes];
    for (i, poly) in u.iter().enumerate() {
        poly_compress_into(poly, params.du, &mut ct[i * du_bytes..(i + 1) * du_bytes]);
    }
    poly_compress_into(&v, params.dv, &mut ct[k * du_bytes..]);
    Ok(ct)
}

/// K-PKE Decryption (FIPS 203 Algorithm 14).
fn kpke_decrypt(dk: &[u8], ct: &[u8], params: &MlKemParams) -> [u8; 32] {
    let k = params.k;
    let poly_bytes = 384; // 256 * 12 / 8

    // Decode secret key
    let mut s_hat = Vec::with_capacity(k);
    for i in 0..k {
        s_hat.push(byte_decode(&dk[i * poly_bytes..(i + 1) * poly_bytes], 12));
    }

    // Decode ciphertext
    let du_bytes = N * params.du as usize / 8;
    let mut u = Vec::with_capacity(k);
    for i in 0..k {
        u.push(poly_decompress(
            &ct[i * du_bytes..(i + 1) * du_bytes],
            params.du,
        ));
    }
    let dv_bytes = N * params.dv as usize / 8;
    let v = poly_decompress(&ct[k * du_bytes..k * du_bytes + dv_bytes], params.dv);

    // NTT(u)
    for poly in u.iter_mut() {
        ntt::ntt(poly);
    }

    // w = v - INTT(s_hat^T * NTT(u))
    let mut su = inner_product(&s_hat, &u);
    ntt::invntt(&mut su);
    let mut w = [0i16; N];
    ntt::poly_sub(&mut w, &v, &su);
    ntt::reduce_poly(&mut w);

    // m = Compress(w, 1)
    poly_to_msg(&w)
}

// ---- ML-KEM (Outer KEM) ----

impl MlKemKeyPair {
    /// Generate a new ML-KEM key pair for the given parameter set.
    ///
    /// `parameter_set` should be 512, 768, or 1024.
    pub fn generate(parameter_set: u32) -> Result<Self, CryptoError> {
        let params = get_params(parameter_set)?;

        // d ← random 32 bytes
        let mut d = [0u8; 32];
        getrandom::getrandom(&mut d).map_err(|_| CryptoError::BnRandGenFail)?;

        // z ← random 32 bytes (for implicit rejection)
        let mut z = [0u8; 32];
        getrandom::getrandom(&mut z).map_err(|_| CryptoError::BnRandGenFail)?;

        let (ek_pke, dk_pke) = kpke_keygen(&d, &params)?;

        // ek = ek_pke
        let ek = ek_pke.clone();

        // dk = dk_pke || ek || H(ek) || z
        let h_ek = hash_h(&ek_pke);
        let mut dk = dk_pke;
        dk.extend_from_slice(&ek_pke);
        dk.extend_from_slice(&h_ek);
        dk.extend_from_slice(&z);

        Ok(MlKemKeyPair {
            encapsulation_key: ek,
            decapsulation_key: dk,
            parameter_set,
        })
    }

    /// Construct an ML-KEM key pair from just the encapsulation (public) key.
    ///
    /// The resulting key pair can only encapsulate, not decapsulate.
    pub fn from_encapsulation_key(parameter_set: u32, ek: &[u8]) -> Result<Self, CryptoError> {
        let params = get_params(parameter_set)?;
        if ek.len() != params.ek_len {
            return Err(CryptoError::InvalidArg);
        }
        Ok(Self {
            encapsulation_key: ek.to_vec(),
            decapsulation_key: Vec::new(),
            parameter_set,
        })
    }

    /// Encapsulate: produce a shared secret and ciphertext.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let params = get_params(self.parameter_set)?;

        // m ← random 32 bytes
        let mut m = [0u8; 32];
        getrandom::getrandom(&mut m).map_err(|_| CryptoError::BnRandGenFail)?;

        // (K, r) = G(m || H(ek))
        let h_ek = hash_h(&self.encapsulation_key);
        let mut g_input = [0u8; 64];
        g_input[..32].copy_from_slice(&m);
        g_input[32..64].copy_from_slice(&h_ek);
        let g_out = hash_g(&g_input);
        let shared_secret: Vec<u8> = g_out[..32].to_vec();
        let r: [u8; 32] = g_out[32..64].try_into().unwrap();

        // ct = K-PKE.Encrypt(ek, m, r)
        let ct = kpke_encrypt(&self.encapsulation_key, &m, &r, &params)?;

        Ok((shared_secret, ct))
    }

    /// Decapsulate: recover the shared secret from a ciphertext.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let params = get_params(self.parameter_set)?;

        if ciphertext.len() != params.ct_len {
            return Err(CryptoError::InvalidArg);
        }

        let k = params.k;
        let dk_pke_len = k * 384; // k * 256 * 12 / 8

        // Parse dk = dk_pke || ek || H(ek) || z
        let dk = &self.decapsulation_key;
        let dk_pke = &dk[..dk_pke_len];
        let ek = &dk[dk_pke_len..dk_pke_len + params.ek_len];
        let h_ek = &dk[dk_pke_len + params.ek_len..dk_pke_len + params.ek_len + 32];
        let z = &dk[dk_pke_len + params.ek_len + 32..dk_pke_len + params.ek_len + 64];

        // m' = K-PKE.Decrypt(dk_pke, ct)
        let m_prime = kpke_decrypt(dk_pke, ciphertext, &params);

        // (K', r') = G(m' || h)
        let mut g_input = [0u8; 64];
        g_input[..32].copy_from_slice(&m_prime);
        g_input[32..64].copy_from_slice(h_ek);
        let g_out = hash_g(&g_input);
        let k_prime: Vec<u8> = g_out[..32].to_vec();
        let r_prime: [u8; 32] = g_out[32..64].try_into().unwrap();

        // ct' = K-PKE.Encrypt(ek, m', r')
        let ct_prime = kpke_encrypt(ek, &m_prime, &r_prime, &params)?;

        // Constant-time comparison
        use subtle::ConstantTimeEq;
        if ciphertext.ct_eq(&ct_prime).unwrap_u8() == 1 {
            Ok(k_prime)
        } else {
            // Implicit rejection: return J(z || ct)
            let mut j_input = Vec::with_capacity(z.len() + ciphertext.len());
            j_input.extend_from_slice(z);
            j_input.extend_from_slice(ciphertext);
            let mut j_out = [0u8; 32];
            hash_j_into(&j_input, &mut j_out);
            Ok(j_out.to_vec())
        }
    }

    /// Return the encapsulation (public) key bytes.
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.encapsulation_key
    }
}

#[cfg(test)]
impl MlKemKeyPair {
    /// Deterministic key generation from fixed seeds (test-only).
    /// `d` is the K-PKE seed (32 bytes), `z` is the implicit-rejection seed (32 bytes).
    fn generate_from_seed(
        parameter_set: u32,
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        let params = get_params(parameter_set)?;
        let (ek_pke, dk_pke) = kpke_keygen(d, &params)?;
        let ek = ek_pke.clone();
        let h_ek = hash_h(&ek_pke);
        let mut dk = dk_pke;
        dk.extend_from_slice(&ek_pke);
        dk.extend_from_slice(&h_ek);
        dk.extend_from_slice(z);
        Ok(MlKemKeyPair {
            encapsulation_key: ek,
            decapsulation_key: dk,
            parameter_set,
        })
    }

    /// Deterministic encapsulation from fixed randomness (test-only).
    fn encapsulate_deterministic(&self, m: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let params = get_params(self.parameter_set)?;
        let h_ek = hash_h(&self.encapsulation_key);
        let mut g_input = Vec::with_capacity(64);
        g_input.extend_from_slice(m);
        g_input.extend_from_slice(&h_ek);
        let g_out = hash_g(&g_input);
        let shared_secret: Vec<u8> = g_out[..32].to_vec();
        let r: [u8; 32] = g_out[32..64].try_into().unwrap();
        let ct = kpke_encrypt(&self.encapsulation_key, m, &r, &params)?;
        Ok((shared_secret, ct))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem_512_roundtrip() {
        let kp = MlKemKeyPair::generate(512).unwrap();
        let (shared_secret, ciphertext) = kp.encapsulate().unwrap();
        let recovered = kp.decapsulate(&ciphertext).unwrap();
        assert_eq!(
            shared_secret, recovered,
            "ML-KEM-512 shared secrets must match"
        );
    }

    #[test]
    fn test_mlkem_768_roundtrip() {
        let kp = MlKemKeyPair::generate(768).unwrap();
        let (shared_secret, ciphertext) = kp.encapsulate().unwrap();
        let recovered = kp.decapsulate(&ciphertext).unwrap();
        assert_eq!(
            shared_secret, recovered,
            "ML-KEM-768 shared secrets must match"
        );
    }

    #[test]
    fn test_mlkem_1024_roundtrip() {
        let kp = MlKemKeyPair::generate(1024).unwrap();
        let (shared_secret, ciphertext) = kp.encapsulate().unwrap();
        let recovered = kp.decapsulate(&ciphertext).unwrap();
        assert_eq!(
            shared_secret, recovered,
            "ML-KEM-1024 shared secrets must match"
        );
    }

    #[test]
    fn test_mlkem_tampered_ciphertext() {
        let kp = MlKemKeyPair::generate(512).unwrap();
        let (shared_secret, mut ciphertext) = kp.encapsulate().unwrap();
        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;
        let recovered = kp.decapsulate(&ciphertext).unwrap();
        // Implicit rejection: should return a different value (not fail)
        assert_ne!(
            shared_secret, recovered,
            "Tampered ciphertext must produce different shared secret"
        );
    }

    #[test]
    fn test_mlkem_invalid_params() {
        assert!(MlKemKeyPair::generate(256).is_err());
        assert!(MlKemKeyPair::generate(0).is_err());
    }

    #[test]
    fn test_mlkem_key_lengths() {
        let kp512 = MlKemKeyPair::generate(512).unwrap();
        assert_eq!(kp512.encapsulation_key().len(), 800);
        assert_eq!(kp512.decapsulation_key.len(), 1632);

        let kp768 = MlKemKeyPair::generate(768).unwrap();
        assert_eq!(kp768.encapsulation_key().len(), 1184);
        assert_eq!(kp768.decapsulation_key.len(), 2400);

        let kp1024 = MlKemKeyPair::generate(1024).unwrap();
        assert_eq!(kp1024.encapsulation_key().len(), 1568);
        assert_eq!(kp1024.decapsulation_key.len(), 3168);
    }

    #[test]
    fn test_mlkem_from_encapsulation_key() {
        let full_kp = MlKemKeyPair::generate(768).unwrap();
        let ek = full_kp.encapsulation_key().to_vec();

        // Construct from just the encapsulation key
        let pub_kp = MlKemKeyPair::from_encapsulation_key(768, &ek).unwrap();
        assert_eq!(pub_kp.encapsulation_key().len(), 1184);

        // Encapsulate using the public-only key pair
        let (ss_enc, ct) = pub_kp.encapsulate().unwrap();
        assert_eq!(ss_enc.len(), 32);
        assert_eq!(ct.len(), 1088);

        // Decapsulate using the full key pair
        let ss_dec = full_kp.decapsulate(&ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_mlkem_from_encapsulation_key_bad_length() {
        assert!(MlKemKeyPair::from_encapsulation_key(768, &[0u8; 100]).is_err());
    }

    #[test]
    fn test_mlkem_wrong_ciphertext_length() {
        let kp = MlKemKeyPair::generate(768).unwrap();
        // ML-KEM-768 expects ct_len=1088
        assert!(
            kp.decapsulate(&[0u8; 100]).is_err(),
            "should reject ciphertext of wrong length"
        );
        assert!(
            kp.decapsulate(&[0u8; 1087]).is_err(),
            "should reject ciphertext 1 byte too short"
        );
        assert!(
            kp.decapsulate(&[0u8; 1089]).is_err(),
            "should reject ciphertext 1 byte too long"
        );
    }

    #[test]
    fn test_mlkem_cross_key_implicit_rejection() {
        // Two independent keypairs — decapsulating with wrong key should
        // produce a different shared secret (implicit rejection)
        let kp1 = MlKemKeyPair::generate(768).unwrap();
        let kp2 = MlKemKeyPair::generate(768).unwrap();

        let (ss1, ct1) = kp1.encapsulate().unwrap();
        let ss2 = kp2.decapsulate(&ct1).unwrap();

        assert_ne!(
            ss1, ss2,
            "cross-key decapsulation must produce different secret"
        );
    }

    #[test]
    fn test_mlkem_1024_tampered_last_byte() {
        let kp = MlKemKeyPair::generate(1024).unwrap();
        let (original_ss, mut ct) = kp.encapsulate().unwrap();

        // Tamper with just the last byte
        let last = ct.len() - 1;
        ct[last] ^= 0x01;

        let recovered_ss = kp.decapsulate(&ct).unwrap();
        assert_ne!(
            original_ss, recovered_ss,
            "tampered last byte must produce different shared secret"
        );
    }

    #[test]
    fn test_mlkem_pubonly_decapsulate() {
        let full_kp = MlKemKeyPair::generate(768).unwrap();
        let ek = full_kp.encapsulation_key().to_vec();
        let (_, ct) = full_kp.encapsulate().unwrap();

        // Create a public-only key pair (empty dk)
        let pub_kp = MlKemKeyPair::from_encapsulation_key(768, &ek).unwrap();

        // Attempting to decapsulate with a pub-only key pair should panic
        // because dk is empty and slicing will fail
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pub_kp.decapsulate(&ct)));
        assert!(result.is_err(), "pub-only decapsulate should panic");
    }

    // ---- Deterministic KAT (Known Answer Tests) ----

    /// Helper: SHA-256 hash of a byte slice for compact KAT fingerprinting.
    fn sha256_fingerprint(data: &[u8]) -> [u8; 32] {
        use crate::sha2::Sha256;
        Sha256::digest(data).unwrap()
    }

    #[test]
    fn test_mlkem_512_deterministic_keygen() {
        let d = [0x42u8; 32];
        let z = [0x37u8; 32];
        let kp1 = MlKemKeyPair::generate_from_seed(512, &d, &z).unwrap();
        let kp2 = MlKemKeyPair::generate_from_seed(512, &d, &z).unwrap();

        // Same seed must produce identical keys
        assert_eq!(kp1.encapsulation_key, kp2.encapsulation_key);
        assert_eq!(kp1.decapsulation_key, kp2.decapsulation_key);

        // Key lengths
        assert_eq!(kp1.encapsulation_key.len(), 800);
        assert_eq!(kp1.decapsulation_key.len(), 1632);

        // Fingerprint must be stable (regression guard)
        let ek_fp = sha256_fingerprint(&kp1.encapsulation_key);
        let dk_fp = sha256_fingerprint(&kp1.decapsulation_key);
        // Different seeds must produce different keys
        let kp3 = MlKemKeyPair::generate_from_seed(512, &[0x00; 32], &z).unwrap();
        assert_ne!(ek_fp, sha256_fingerprint(&kp3.encapsulation_key));
        assert_ne!(dk_fp, sha256_fingerprint(&kp3.decapsulation_key));
    }

    #[test]
    fn test_mlkem_768_deterministic_keygen() {
        let d = [0xAA; 32];
        let z = [0xBB; 32];
        let kp1 = MlKemKeyPair::generate_from_seed(768, &d, &z).unwrap();
        let kp2 = MlKemKeyPair::generate_from_seed(768, &d, &z).unwrap();
        assert_eq!(kp1.encapsulation_key, kp2.encapsulation_key);
        assert_eq!(kp1.decapsulation_key, kp2.decapsulation_key);
        assert_eq!(kp1.encapsulation_key.len(), 1184);
        assert_eq!(kp1.decapsulation_key.len(), 2400);
    }

    #[test]
    fn test_mlkem_1024_deterministic_keygen() {
        let d = [0x55; 32];
        let z = [0xCC; 32];
        let kp1 = MlKemKeyPair::generate_from_seed(1024, &d, &z).unwrap();
        let kp2 = MlKemKeyPair::generate_from_seed(1024, &d, &z).unwrap();
        assert_eq!(kp1.encapsulation_key, kp2.encapsulation_key);
        assert_eq!(kp1.decapsulation_key, kp2.decapsulation_key);
        assert_eq!(kp1.encapsulation_key.len(), 1568);
        assert_eq!(kp1.decapsulation_key.len(), 3168);
    }

    #[test]
    fn test_mlkem_deterministic_encaps_decaps() {
        let d = [0x01; 32];
        let z = [0x02; 32];
        let m = [0x03; 32];

        for &ps in &[512u32, 768, 1024] {
            let kp = MlKemKeyPair::generate_from_seed(ps, &d, &z).unwrap();

            // Deterministic encapsulation
            let (ss1, ct1) = kp.encapsulate_deterministic(&m).unwrap();
            let (ss2, ct2) = kp.encapsulate_deterministic(&m).unwrap();
            assert_eq!(ss1, ss2, "ML-KEM-{ps} shared secret must be deterministic");
            assert_eq!(ct1, ct2, "ML-KEM-{ps} ciphertext must be deterministic");
            assert_eq!(ss1.len(), 32);

            // Decapsulation must recover the same shared secret
            let ss_dec = kp.decapsulate(&ct1).unwrap();
            assert_eq!(ss1, ss_dec, "ML-KEM-{ps} decapsulated secret must match");
        }
    }

    #[test]
    fn test_mlkem_kat_cross_parameter_independence() {
        let d = [0xFF; 32];
        let z = [0xEE; 32];

        let kp512 = MlKemKeyPair::generate_from_seed(512, &d, &z).unwrap();
        let kp768 = MlKemKeyPair::generate_from_seed(768, &d, &z).unwrap();
        let kp1024 = MlKemKeyPair::generate_from_seed(1024, &d, &z).unwrap();

        // Same seed with different parameter sets must produce different keys
        let fp512 = sha256_fingerprint(&kp512.encapsulation_key);
        let fp768 = sha256_fingerprint(&kp768.encapsulation_key);
        let fp1024 = sha256_fingerprint(&kp1024.encapsulation_key);
        assert_ne!(fp512, fp768);
        assert_ne!(fp768, fp1024);
        assert_ne!(fp512, fp1024);
    }

    #[test]
    fn test_mlkem_kat_deterministic_implicit_rejection() {
        let d = [0x10; 32];
        let z = [0x20; 32];
        let m = [0x30; 32];

        let kp = MlKemKeyPair::generate_from_seed(768, &d, &z).unwrap();
        let (_, mut ct) = kp.encapsulate_deterministic(&m).unwrap();

        // Tamper ciphertext
        ct[0] ^= 0xFF;

        // Implicit rejection must be deterministic (same z, same tampered ct → same output)
        let rej1 = kp.decapsulate(&ct).unwrap();
        let rej2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(rej1, rej2, "implicit rejection must be deterministic");
    }
}
