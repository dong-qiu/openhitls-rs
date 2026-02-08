//! FrodoKEM (Learning With Errors Key Encapsulation Mechanism).
//!
//! FrodoKEM is a conservative, post-quantum KEM based on the plain LWE problem.
//! It offers strong security margins at the cost of larger key/ciphertext sizes.
//!
//! Supports 12 parameter sets:
//! - FrodoKEM-{640,976,1344} × {SHAKE,AES} (with salt, IND-CCA2)
//! - eFrodoKEM-{640,976,1344} × {SHAKE,AES} (no salt, ephemeral)

mod matrix;
mod params;
mod pke;
mod util;

use hitls_types::{CryptoError, FrodoKemParamId};
use zeroize::Zeroize;

use params::get_params;

/// A FrodoKEM key pair for key encapsulation.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct FrodoKemKeyPair {
    /// Public key: seed_a(16) || pack(B)
    encapsulation_key: Vec<u8>,
    /// Secret key: s || pk || S^T_packed || pk_hash
    decapsulation_key: Vec<u8>,
    #[zeroize(skip)]
    param_id: FrodoKemParamId,
}

impl FrodoKemKeyPair {
    /// Generate a new FrodoKEM key pair for the given parameter set.
    pub fn generate(param_id: FrodoKemParamId) -> Result<Self, CryptoError> {
        let p = get_params(param_id);
        let n = p.n;
        let n_bar = p.n_bar;

        // Generate random bytes: s(ss_len) || seed_se(seed_se_len) || z(16)
        let rnd_len = p.ss_len + p.seed_se_len + 16;
        let mut rnd = vec![0u8; rnd_len];
        getrandom::getrandom(&mut rnd).map_err(|_| CryptoError::BnRandGenFail)?;

        let s = &rnd[..p.ss_len];
        let seed_se = &rnd[p.ss_len..p.ss_len + p.seed_se_len];
        let z = &rnd[p.ss_len + p.seed_se_len..];

        // seed_a = SHAKE(z, 16)
        let seed_a = util::shake_hash(z, &[], 16, p)?;

        // PKE keygen
        let (b_packed, s_t) = pke::pke_keygen(&seed_a, seed_se, p)?;

        // Build public key: seed_a || pack(B)
        let mut pk = Vec::with_capacity(p.pk_size);
        pk.extend_from_slice(&seed_a);
        pk.extend_from_slice(&b_packed);

        // Hash of public key
        let pk_hash = util::shake_hash(&pk, &[], p.pk_hash_len, p)?;

        // Store S^T as raw u16 bytes (little-endian, 2 bytes each)
        let mut s_t_bytes = vec![0u8; n_bar * n * 2];
        for (i, &val) in s_t.iter().enumerate() {
            s_t_bytes[2 * i] = val as u8;
            s_t_bytes[2 * i + 1] = (val >> 8) as u8;
        }

        // Build secret key: s || pk || S^T_bytes || pk_hash
        let mut sk = Vec::with_capacity(p.sk_size);
        sk.extend_from_slice(s);
        sk.extend_from_slice(&pk);
        sk.extend_from_slice(&s_t_bytes);
        sk.extend_from_slice(&pk_hash);

        let mut rnd_copy = rnd;
        rnd_copy.zeroize();

        Ok(Self {
            encapsulation_key: pk,
            decapsulation_key: sk,
            param_id,
        })
    }

    /// Encapsulate: produce a ciphertext and shared secret.
    /// Returns (ciphertext, shared_secret).
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let p = get_params(self.param_id);

        // Extract pk and pk_hash from sk
        let pk = &self.encapsulation_key;
        let pk_hash = &self.decapsulation_key[self.decapsulation_key.len() - p.pk_hash_len..];

        // Generate random mu
        let mut mu = vec![0u8; p.mu_len];
        getrandom::getrandom(&mut mu).map_err(|_| CryptoError::BnRandGenFail)?;

        // Generate salt (if applicable)
        let mut salt = vec![0u8; p.salt_len];
        if p.salt_len > 0 {
            getrandom::getrandom(&mut salt).map_err(|_| CryptoError::BnRandGenFail)?;
        }

        // seed_se || k = SHAKE(pk_hash || mu || salt, seed_se_len + ss_len)
        let mut hash_input = Vec::with_capacity(p.pk_hash_len + p.mu_len + p.salt_len);
        hash_input.extend_from_slice(pk_hash);
        hash_input.extend_from_slice(&mu);
        hash_input.extend_from_slice(&salt);
        let seed_k = util::shake_hash(&hash_input, &[], p.seed_se_len + p.ss_len, p)?;

        let seed_se = &seed_k[..p.seed_se_len];
        let k = &seed_k[p.seed_se_len..];

        // Extract seed_a and b_packed from pk
        let seed_a = &pk[..p.seed_a_len];
        let b_packed = &pk[p.seed_a_len..];

        // PKE encrypt
        let (c1_packed, c2_packed) = pke::pke_encrypt(seed_a, b_packed, seed_se, &mu, p)?;

        // Build ciphertext: c1 || c2 || salt
        let mut ct = Vec::with_capacity(p.ct_size);
        ct.extend_from_slice(&c1_packed);
        ct.extend_from_slice(&c2_packed);
        ct.extend_from_slice(&salt);

        // Shared secret = SHAKE(ct || k, ss_len)
        let ss = util::shake_hash3(&ct, k, &[], p.ss_len, p)?;

        mu.zeroize();

        Ok((ct, ss))
    }

    /// Decapsulate: recover the shared secret from a ciphertext.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let p = get_params(self.param_id);
        let n = p.n;
        let n_bar = p.n_bar;

        if ciphertext.len() != p.ct_size {
            return Err(CryptoError::InvalidArg);
        }

        // Parse secret key: s || pk || S^T_bytes || pk_hash
        let s = &self.decapsulation_key[..p.ss_len];
        let pk = &self.decapsulation_key[p.ss_len..p.ss_len + p.pk_size];
        let s_t_bytes_start = p.ss_len + p.pk_size;
        let s_t_bytes_len = n_bar * n * 2;
        let s_t_bytes = &self.decapsulation_key[s_t_bytes_start..s_t_bytes_start + s_t_bytes_len];
        let pk_hash = &self.decapsulation_key[self.decapsulation_key.len() - p.pk_hash_len..];

        // Parse ciphertext: c1 || c2 || salt
        let c1_len = p.packed_len(n_bar * n);
        let c2_len = p.packed_len(n_bar * n_bar);
        let c1_packed = &ciphertext[..c1_len];
        let c2_packed = &ciphertext[c1_len..c1_len + c2_len];
        let salt = &ciphertext[c1_len + c2_len..];

        // Unpack S^T from raw u16 bytes
        let mut s_t = vec![0u16; n_bar * n];
        for i in 0..s_t.len() {
            s_t[i] = u16::from_le_bytes([s_t_bytes[2 * i], s_t_bytes[2 * i + 1]]);
        }

        // PKE decrypt: recover mu'
        let mu_prime = pke::pke_decrypt(&s_t, c1_packed, c2_packed, p);

        // Re-derive: seed_se' || k' = SHAKE(pk_hash || mu' || salt, seed_se_len + ss_len)
        let mut hash_input = Vec::with_capacity(p.pk_hash_len + p.mu_len + salt.len());
        hash_input.extend_from_slice(pk_hash);
        hash_input.extend_from_slice(&mu_prime);
        hash_input.extend_from_slice(salt);
        let seed_k_prime = util::shake_hash(&hash_input, &[], p.seed_se_len + p.ss_len, p)?;

        let seed_se_prime = &seed_k_prime[..p.seed_se_len];
        let k_prime = &seed_k_prime[p.seed_se_len..];

        // Re-encrypt
        let seed_a = &pk[..p.seed_a_len];
        let b_packed_pk = &pk[p.seed_a_len..];
        let (c1_prime, c2_prime) =
            pke::pke_encrypt(seed_a, b_packed_pk, seed_se_prime, &mu_prime, p)?;

        // Build re-encrypted ciphertext for comparison
        let mut ct_prime = Vec::with_capacity(c1_prime.len() + c2_prime.len() + salt.len());
        ct_prime.extend_from_slice(&c1_prime);
        ct_prime.extend_from_slice(&c2_prime);
        ct_prime.extend_from_slice(salt);

        // Constant-time comparison
        let selector = util::ct_verify(ciphertext, &ct_prime);

        // If match: ss = SHAKE(ct || k', ss_len)
        // If no match: ss = SHAKE(ct || s, ss_len) (implicit rejection)
        let k_or_s = util::ct_select(k_prime, s, selector);
        let ss = util::shake_hash3(ciphertext, &k_or_s, &[], p.ss_len, p)?;

        Ok(ss)
    }

    /// Return the encapsulation (public) key bytes.
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.encapsulation_key
    }

    /// Return the parameter set identifier.
    pub fn param_id(&self) -> FrodoKemParamId {
        self.param_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frodokem_640_shake_roundtrip() {
        let kp = FrodoKemKeyPair::generate(FrodoKemParamId::FrodoKem640Shake).unwrap();
        let (ct, ss1) = kp.encapsulate().unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_frodokem_640_aes_roundtrip() {
        let kp = FrodoKemKeyPair::generate(FrodoKemParamId::FrodoKem640Aes).unwrap();
        let (ct, ss1) = kp.encapsulate().unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_efrodokem_640_shake_roundtrip() {
        let kp = FrodoKemKeyPair::generate(FrodoKemParamId::EFrodoKem640Shake).unwrap();
        let (ct, ss1) = kp.encapsulate().unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    #[ignore] // ~5s in debug mode
    fn test_frodokem_976_shake_roundtrip() {
        let kp = FrodoKemKeyPair::generate(FrodoKemParamId::FrodoKem976Shake).unwrap();
        let (ct, ss1) = kp.encapsulate().unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    #[ignore] // ~15s in debug mode
    fn test_frodokem_1344_shake_roundtrip() {
        let kp = FrodoKemKeyPair::generate(FrodoKemParamId::FrodoKem1344Shake).unwrap();
        let (ct, ss1) = kp.encapsulate().unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_frodokem_tampered_ciphertext() {
        let kp = FrodoKemKeyPair::generate(FrodoKemParamId::FrodoKem640Shake).unwrap();
        let (mut ct, ss1) = kp.encapsulate().unwrap();
        // Tamper with ciphertext
        ct[100] ^= 0xFF;
        let ss2 = kp.decapsulate(&ct).unwrap();
        // Implicit rejection: should produce different shared secret
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_frodokem_cross_key_decaps() {
        let kp1 = FrodoKemKeyPair::generate(FrodoKemParamId::FrodoKem640Shake).unwrap();
        let kp2 = FrodoKemKeyPair::generate(FrodoKemParamId::FrodoKem640Shake).unwrap();
        let (ct, ss1) = kp1.encapsulate().unwrap();
        let ss2 = kp2.decapsulate(&ct).unwrap();
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_frodokem_key_sizes() {
        use params::get_params;

        let test_cases = [
            FrodoKemParamId::FrodoKem640Shake,
            FrodoKemParamId::FrodoKem640Aes,
            FrodoKemParamId::EFrodoKem640Shake,
            FrodoKemParamId::EFrodoKem640Aes,
        ];

        for param_id in test_cases {
            let p = get_params(param_id);
            let kp = FrodoKemKeyPair::generate(param_id).unwrap();
            assert_eq!(kp.encapsulation_key().len(), p.pk_size, "{:?} pk", param_id);
            assert_eq!(kp.decapsulation_key.len(), p.sk_size, "{:?} sk", param_id);
            let (ct, ss) = kp.encapsulate().unwrap();
            assert_eq!(ct.len(), p.ct_size, "{:?} ct", param_id);
            assert_eq!(ss.len(), p.ss_len, "{:?} ss", param_id);
        }
    }
}
