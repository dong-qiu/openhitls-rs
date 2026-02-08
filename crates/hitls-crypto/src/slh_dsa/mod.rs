//! SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) — FIPS 205.
//!
//! SLH-DSA (formerly SPHINCS+) is a post-quantum, hash-based digital
//! signature scheme. It is stateless (no signature index tracking needed)
//! and relies only on the security of the underlying hash function.
//!
//! Supports all 12 parameter sets: SHA2/SHAKE × {128,192,256} × {s,f}.

mod address;
mod fors;
mod hash;
mod hypertree;
mod params;
mod wots;

use hitls_types::{CryptoError, SlhDsaParamId};
use zeroize::Zeroize;

use address::Adrs;
use hash::make_hasher;
use params::get_params;

/// SLH-DSA key pair for digital signatures.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SlhDsaKeyPair {
    /// Public key: PK.seed || PK.root (2*n bytes)
    public_key: Vec<u8>,
    /// Private key: SK.seed || SK.prf || PK.seed || PK.root (4*n bytes)
    private_key: Vec<u8>,
    #[zeroize(skip)]
    param_id: SlhDsaParamId,
}

/// Extract tree index and leaf index from message digest.
fn get_tree_and_leaf_idx(digest: &[u8], k: usize, a: usize, h: usize, d: usize) -> (u64, u32) {
    let md_idx = (k * a).div_ceil(8); // ceil(k*a / 8) bytes used for FORS indices
    let hp = h / d;
    let tree_bits = h - hp;
    let leaf_bits = hp;
    let tree_idx_len = tree_bits.div_ceil(8);
    let leaf_idx_len = leaf_bits.div_ceil(8);

    let tree_idx = to_int_mod(&digest[md_idx..md_idx + tree_idx_len], tree_bits);
    let leaf_idx = to_int_mod(
        &digest[md_idx + tree_idx_len..md_idx + tree_idx_len + leaf_idx_len],
        leaf_bits,
    ) as u32;

    (tree_idx, leaf_idx)
}

/// Convert byte array to integer mod 2^m.
fn to_int_mod(b: &[u8], m: usize) -> u64 {
    let mut ret: u64 = 0;
    for &byte in b {
        ret = (ret << 8) | (byte as u64);
    }
    if m < 64 {
        ret & ((1u64 << m) - 1)
    } else {
        ret
    }
}

impl SlhDsaKeyPair {
    /// Generate a new SLH-DSA key pair.
    pub fn generate(param_id: SlhDsaParamId) -> Result<Self, CryptoError> {
        let p = get_params(param_id);
        let n = p.n;

        // Generate random seeds
        let mut sk_seed = vec![0u8; n];
        let mut sk_prf = vec![0u8; n];
        let mut pk_seed = vec![0u8; n];
        getrandom::getrandom(&mut sk_seed).map_err(|_| CryptoError::BnRandGenFail)?;
        getrandom::getrandom(&mut sk_prf).map_err(|_| CryptoError::BnRandGenFail)?;
        getrandom::getrandom(&mut pk_seed).map_err(|_| CryptoError::BnRandGenFail)?;

        // Compute public root: top layer (d-1) tree root
        let placeholder_root = vec![0u8; n]; // temporary for hasher creation
        let hasher = make_hasher(p, &pk_seed, &placeholder_root);

        let compressed = p.is_sha2;
        let mut adrs = Adrs::new(compressed);
        adrs.set_layer_addr((p.d - 1) as u32);

        let pk_root = hypertree::xmss_compute_root(&*hasher, &sk_seed, &mut adrs, p)?;

        // Build key material
        let mut private_key = Vec::with_capacity(4 * n);
        private_key.extend_from_slice(&sk_seed);
        private_key.extend_from_slice(&sk_prf);
        private_key.extend_from_slice(&pk_seed);
        private_key.extend_from_slice(&pk_root);

        let mut public_key = Vec::with_capacity(2 * n);
        public_key.extend_from_slice(&pk_seed);
        public_key.extend_from_slice(&pk_root);

        // Zeroize temporary secrets
        sk_seed.zeroize();
        sk_prf.zeroize();

        Ok(Self {
            public_key,
            private_key,
            param_id,
        })
    }

    /// Sign a message. Returns signature bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let p = get_params(self.param_id);
        let n = p.n;

        let sk_seed = &self.private_key[..n];
        let sk_prf = &self.private_key[n..2 * n];
        let pk_seed = &self.private_key[2 * n..3 * n];
        let pk_root = &self.private_key[3 * n..4 * n];

        let hasher = make_hasher(p, pk_seed, pk_root);
        let compressed = p.is_sha2;

        // Step 1: Generate randomizer R
        let mut opt_rand = vec![0u8; n];
        getrandom::getrandom(&mut opt_rand).map_err(|_| CryptoError::BnRandGenFail)?;
        let r = hasher.prf_msg(sk_prf, &opt_rand, message)?;

        // Step 2: Compute message digest
        let digest = hasher.h_msg(&r, message)?;

        // Step 3: Extract FORS indices + tree/leaf indices
        let md_len = (p.k * p.a).div_ceil(8);
        let fors_md = &digest[..md_len];
        let (tree_idx, leaf_idx) = get_tree_and_leaf_idx(&digest, p.k, p.a, p.h, p.d);

        // Step 4: FORS signature
        let mut adrs = Adrs::new(compressed);
        adrs.set_tree_addr(tree_idx);
        adrs.set_type(address::AdrsType::ForsTree);
        adrs.set_key_pair_addr(leaf_idx);
        let fors_sig = fors::fors_sign(&*hasher, sk_seed, fors_md, &mut adrs, p)?;

        // Step 5: Recover FORS public key
        let fors_pk = fors::fors_pk_from_sig(&*hasher, &fors_sig, fors_md, &mut adrs, p)?;

        // Step 6: Hypertree signature
        let mut ht_adrs = Adrs::new(compressed);
        let ht_sig = hypertree::hypertree_sign(
            &*hasher,
            sk_seed,
            &fors_pk,
            tree_idx,
            leaf_idx,
            &mut ht_adrs,
            p,
        )?;

        // Assemble: R || FORS_SIG || HT_SIG
        let mut sig = Vec::with_capacity(p.sig_bytes);
        sig.extend_from_slice(&r);
        sig.extend_from_slice(&fors_sig);
        sig.extend_from_slice(&ht_sig);

        Ok(sig)
    }

    /// Verify a signature against a message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let p = get_params(self.param_id);
        let n = p.n;

        if signature.len() != p.sig_bytes {
            return Ok(false);
        }

        let pk_seed = &self.public_key[..n];
        let pk_root = &self.public_key[n..2 * n];

        let hasher = make_hasher(p, pk_seed, pk_root);
        let compressed = p.is_sha2;

        // Extract R from signature
        let r = &signature[..n];
        let fors_sig_len = p.k * (1 + p.a) * n;
        let fors_sig = &signature[n..n + fors_sig_len];
        let ht_sig = &signature[n + fors_sig_len..];

        // Compute message digest
        let digest = hasher.h_msg(r, message)?;

        let md_len = (p.k * p.a).div_ceil(8);
        let fors_md = &digest[..md_len];
        let (tree_idx, leaf_idx) = get_tree_and_leaf_idx(&digest, p.k, p.a, p.h, p.d);

        // Recover FORS public key from signature
        let mut adrs = Adrs::new(compressed);
        adrs.set_tree_addr(tree_idx);
        adrs.set_type(address::AdrsType::ForsTree);
        adrs.set_key_pair_addr(leaf_idx);
        let fors_pk = fors::fors_pk_from_sig(&*hasher, fors_sig, fors_md, &mut adrs, p)?;

        // Verify hypertree signature
        let mut ht_adrs = Adrs::new(compressed);
        hypertree::hypertree_verify(
            &*hasher,
            &fors_pk,
            ht_sig,
            tree_idx,
            leaf_idx,
            pk_root,
            &mut ht_adrs,
            p,
        )
    }

    /// Return the public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Return the parameter set identifier.
    pub fn param_id(&self) -> SlhDsaParamId {
        self.param_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slhdsa_shake_128f_roundtrip() {
        let kp = SlhDsaKeyPair::generate(SlhDsaParamId::Shake128f).unwrap();
        let msg = b"test message for SLH-DSA SHAKE-128f";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_slhdsa_sha2_128f_roundtrip() {
        let kp = SlhDsaKeyPair::generate(SlhDsaParamId::Sha2128f).unwrap();
        let msg = b"test message for SLH-DSA SHA2-128f";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    #[ignore] // slow: 128s has hp=9 (512 leaves per tree)
    fn test_slhdsa_shake_128s_roundtrip() {
        let kp = SlhDsaKeyPair::generate(SlhDsaParamId::Shake128s).unwrap();
        let msg = b"test message for SLH-DSA SHAKE-128s";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    #[ignore] // slow
    fn test_slhdsa_sha2_128s_roundtrip() {
        let kp = SlhDsaKeyPair::generate(SlhDsaParamId::Sha2128s).unwrap();
        let msg = b"test message for SLH-DSA SHA2-128s";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_slhdsa_tampered_signature() {
        let kp = SlhDsaKeyPair::generate(SlhDsaParamId::Shake128f).unwrap();
        let msg = b"tamper test";
        let mut sig = kp.sign(msg).unwrap();
        // Flip a byte in the FORS signature part
        let n = 16;
        sig[n + 10] ^= 0xff;
        assert!(!kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_slhdsa_tampered_message() {
        let kp = SlhDsaKeyPair::generate(SlhDsaParamId::Shake128f).unwrap();
        let msg = b"original message";
        let sig = kp.sign(msg).unwrap();
        assert!(!kp.verify(b"modified message", &sig).unwrap());
    }

    #[test]
    fn test_slhdsa_cross_key_verify() {
        let kp1 = SlhDsaKeyPair::generate(SlhDsaParamId::Shake128f).unwrap();
        let kp2 = SlhDsaKeyPair::generate(SlhDsaParamId::Shake128f).unwrap();
        let msg = b"cross key test";
        let sig = kp1.sign(msg).unwrap();
        assert!(!kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_slhdsa_invalid_signature_length() {
        let kp = SlhDsaKeyPair::generate(SlhDsaParamId::Shake128f).unwrap();
        let msg = b"length test";
        // Too short
        assert!(!kp.verify(msg, &[0u8; 100]).unwrap());
    }

    #[test]
    fn test_slhdsa_different_messages() {
        let kp = SlhDsaKeyPair::generate(SlhDsaParamId::Shake128f).unwrap();
        let sig1 = kp.sign(b"message 1").unwrap();
        let sig2 = kp.sign(b"message 2").unwrap();
        // Different messages should produce different signatures (with overwhelming probability)
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_slhdsa_key_lengths() {
        // Verify key and signature sizes for a few parameter sets
        let test_cases = [
            (SlhDsaParamId::Shake128f, 16, 17088),
            (SlhDsaParamId::Sha2128f, 16, 17088),
        ];
        for (param_id, n, sig_bytes) in &test_cases {
            let p = get_params(*param_id);
            assert_eq!(p.n, *n);
            assert_eq!(p.sig_bytes, *sig_bytes);

            let kp = SlhDsaKeyPair::generate(*param_id).unwrap();
            assert_eq!(kp.public_key().len(), 2 * n);
            assert_eq!(kp.private_key.len(), 4 * n);

            let sig = kp.sign(b"key length test").unwrap();
            assert_eq!(sig.len(), *sig_bytes);
        }
    }

    #[test]
    fn test_slhdsa_empty_message() {
        let kp = SlhDsaKeyPair::generate(SlhDsaParamId::Shake128f).unwrap();
        let sig = kp.sign(b"").unwrap();
        assert!(kp.verify(b"", &sig).unwrap());
    }

    #[test]
    fn test_slhdsa_large_message() {
        let kp = SlhDsaKeyPair::generate(SlhDsaParamId::Shake128f).unwrap();
        let msg = vec![0xab; 10000];
        let sig = kp.sign(&msg).unwrap();
        assert!(kp.verify(&msg, &sig).unwrap());
    }
}
