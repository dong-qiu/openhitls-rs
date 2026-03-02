//! XMSS (eXtended Merkle Signature Scheme) — RFC 8391.
//!
//! XMSS is a stateful, hash-based digital signature scheme. Each key pair
//! can produce a fixed number of signatures (2^h). The signer must track
//! state to avoid one-time key reuse.
//!
//! Supports 21 single-tree parameter sets:
//! SHA-256, SHA-512, SHAKE128, SHAKE256 × h=10,16,20 × n=24,32,64.
//!
//! XMSS-MT: 56 multi-tree parameter sets with d layers.

mod address;
mod hash;
mod params;
mod tree;
mod wots;

use hitls_types::{CryptoError, XmssMtParamId, XmssParamId};
use zeroize::Zeroize;

use address::XmssAdrs;
use hash::XmssHasher;
use params::{get_mt_params, get_params, hash_mode, mt_hash_mode};

/// XMSS key pair for digital signatures.
///
/// This is a **stateful** signature scheme — `sign()` takes `&mut self`
/// and advances the leaf index. The caller must persist the updated key.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct XmssKeyPair {
    /// Public key: OID(4) || root(n) || PK.seed(n)
    public_key: Vec<u8>,
    /// Private key: SK.seed(n) || SK.prf(n) || PK.seed(n) || PK.root(n)
    private_key: Vec<u8>,
    #[zeroize(skip)]
    param_id: XmssParamId,
    #[zeroize(skip)]
    leaf_idx: u64,
    #[zeroize(skip)]
    max_signatures: u64,
}

impl XmssKeyPair {
    /// Generate a new XMSS key pair.
    ///
    /// Warning: This is expensive for large h (h=16 builds 65536 leaves, h=20 builds 1M leaves).
    pub fn generate(param_id: XmssParamId) -> Result<Self, CryptoError> {
        let p = get_params(param_id);
        let n = p.n;
        let mode = hash_mode(param_id);

        // Generate random seeds
        let mut sk_seed = vec![0u8; n];
        let mut sk_prf = vec![0u8; n];
        let mut pk_seed = vec![0u8; n];
        getrandom::getrandom(&mut sk_seed).map_err(|_| CryptoError::BnRandGenFail)?;
        getrandom::getrandom(&mut sk_prf).map_err(|_| CryptoError::BnRandGenFail)?;
        getrandom::getrandom(&mut pk_seed).map_err(|_| CryptoError::BnRandGenFail)?;

        let hasher = XmssHasher {
            n,
            padding_len: p.padding_len,
            mode,
            sk_seed: sk_seed.clone(),
            pk_seed: pk_seed.clone(),
        };

        // Compute tree root
        let mut adrs = XmssAdrs::new();
        let root = tree::compute_root(&hasher, &mut adrs, &p)?;

        // Build public key: OID(4) || root(n) || PK.seed(n)
        let oid_val = params::oid(param_id);
        let mut public_key = Vec::with_capacity(4 + 2 * n);
        public_key.extend_from_slice(&oid_val.to_be_bytes());
        public_key.extend_from_slice(&root);
        public_key.extend_from_slice(&pk_seed);

        // Build private key: SK.seed || SK.prf || PK.seed || PK.root
        let mut private_key = Vec::with_capacity(4 * n);
        private_key.extend_from_slice(&sk_seed);
        private_key.extend_from_slice(&sk_prf);
        private_key.extend_from_slice(&pk_seed);
        private_key.extend_from_slice(&root);

        sk_seed.zeroize();
        sk_prf.zeroize();

        Ok(Self {
            public_key,
            private_key,
            param_id,
            leaf_idx: 0,
            max_signatures: 1u64 << p.h,
        })
    }

    /// Sign a message. Advances the internal leaf index.
    ///
    /// Returns signature: idx(4) || R(n) || WOTS_sig(wots_len*n) || auth(h*n).
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.leaf_idx >= self.max_signatures {
            return Err(CryptoError::InvalidArg("XMSS signatures exhausted"));
        }

        let p = get_params(self.param_id);
        let n = p.n;
        let mode = hash_mode(self.param_id);

        let sk_seed = &self.private_key[..n];
        let sk_prf = &self.private_key[n..2 * n];
        let pk_seed = &self.private_key[2 * n..3 * n];
        let pk_root = &self.private_key[3 * n..4 * n];

        let hasher = XmssHasher {
            n,
            padding_len: p.padding_len,
            mode,
            sk_seed: sk_seed.to_vec(),
            pk_seed: pk_seed.to_vec(),
        };

        let idx = self.leaf_idx as u32;

        // Generate randomness R
        let r = hasher.prf_msg(sk_prf, self.leaf_idx, message)?;

        // Compute message digest
        let msg_hash = hasher.h_msg(&r, pk_root, self.leaf_idx, message)?;

        // XMSS sign: WOTS+ sig + auth path
        let mut adrs = XmssAdrs::new();
        let (tree_sig, _root) = tree::xmss_sign(&hasher, &msg_hash, idx, &mut adrs, &p)?;

        // Assemble: idx(4) || R(n) || tree_sig
        let mut sig = Vec::with_capacity(p.sig_bytes);
        sig.extend_from_slice(&idx.to_be_bytes());
        sig.extend_from_slice(&r);
        sig.extend_from_slice(&tree_sig);

        // Advance state
        self.leaf_idx += 1;

        Ok(sig)
    }

    /// Verify a signature against a message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let p = get_params(self.param_id);
        let n = p.n;
        let mode = hash_mode(self.param_id);

        if signature.len() != p.sig_bytes {
            return Ok(false);
        }

        let pk_seed = &self.public_key[4 + n..4 + 2 * n]; // After OID + root
        let pk_root = &self.public_key[4..4 + n]; // After OID

        let hasher = XmssHasher {
            n,
            padding_len: p.padding_len,
            mode,
            sk_seed: vec![0u8; n], // Not needed for verification
            pk_seed: pk_seed.to_vec(),
        };

        // Parse signature
        let idx = u32::from_be_bytes([signature[0], signature[1], signature[2], signature[3]]);
        let r = &signature[4..4 + n];
        let tree_sig = &signature[4 + n..];

        // Compute message digest
        let msg_hash = hasher.h_msg(r, pk_root, idx as u64, message)?;

        // Verify: recover root from signature
        let mut adrs = XmssAdrs::new();
        let computed_root =
            tree::xmss_root_from_sig(&hasher, &msg_hash, tree_sig, idx, &mut adrs, &p)?;

        Ok(subtle::ConstantTimeEq::ct_eq(computed_root.as_slice(), pk_root).into())
    }

    /// Return the number of remaining signatures.
    pub fn remaining_signatures(&self) -> u64 {
        self.max_signatures - self.leaf_idx
    }

    /// Return the public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Return the parameter set identifier.
    pub fn param_id(&self) -> XmssParamId {
        self.param_id
    }
}

/// XMSS-MT multi-tree key pair for digital signatures (RFC 8391 Section 4.2).
///
/// Multi-tree variant of XMSS with d layers of XMSS trees, enabling
/// larger signing capacities (up to 2^60 signatures).
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct XmssMtKeyPair {
    /// Public key: OID(4) || root(n) || PK.seed(n)
    public_key: Vec<u8>,
    /// Private key: SK.seed(n) || SK.prf(n) || PK.seed(n) || PK.root(n)
    private_key: Vec<u8>,
    #[zeroize(skip)]
    param_id: XmssMtParamId,
    #[zeroize(skip)]
    leaf_idx: u64,
    #[zeroize(skip)]
    max_signatures: u64,
}

impl XmssMtKeyPair {
    /// Generate a new XMSS-MT key pair.
    ///
    /// Builds the top-layer (layer d-1) tree of height hp to compute root.
    pub fn generate(param_id: XmssMtParamId) -> Result<Self, CryptoError> {
        let mt = get_mt_params(param_id);
        let n = mt.n;
        let mode = mt_hash_mode(param_id);

        let mut sk_seed = vec![0u8; n];
        let mut sk_prf = vec![0u8; n];
        let mut pk_seed = vec![0u8; n];
        getrandom::getrandom(&mut sk_seed).map_err(|_| CryptoError::BnRandGenFail)?;
        getrandom::getrandom(&mut sk_prf).map_err(|_| CryptoError::BnRandGenFail)?;
        getrandom::getrandom(&mut pk_seed).map_err(|_| CryptoError::BnRandGenFail)?;

        let hasher = XmssHasher {
            n,
            padding_len: mt.padding_len,
            mode,
            sk_seed: sk_seed.clone(),
            pk_seed: pk_seed.clone(),
        };

        // Build top-layer tree (layer d-1) to get root
        let lp = tree::layer_params(&mt);
        let mut adrs = XmssAdrs::new();
        adrs.set_layer_addr((mt.d - 1) as u32);
        adrs.set_tree_addr(0);
        let root = tree::compute_root(&hasher, &mut adrs, &lp)?;

        // Build public key: OID(4) || root(n) || PK.seed(n)
        let oid_val = params::mt_oid(param_id);
        let mut public_key = Vec::with_capacity(4 + 2 * n);
        public_key.extend_from_slice(&oid_val.to_be_bytes());
        public_key.extend_from_slice(&root);
        public_key.extend_from_slice(&pk_seed);

        // Build private key: SK.seed || SK.prf || PK.seed || PK.root
        let mut private_key = Vec::with_capacity(4 * n);
        private_key.extend_from_slice(&sk_seed);
        private_key.extend_from_slice(&sk_prf);
        private_key.extend_from_slice(&pk_seed);
        private_key.extend_from_slice(&root);

        sk_seed.zeroize();
        sk_prf.zeroize();

        Ok(Self {
            public_key,
            private_key,
            param_id,
            leaf_idx: 0,
            max_signatures: 1u64 << mt.total_h,
        })
    }

    /// Sign a message. Advances the internal leaf index.
    ///
    /// Returns signature: idx(idx_bytes) || R(n) || hypertree_sig.
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.leaf_idx >= self.max_signatures {
            return Err(CryptoError::InvalidArg("XMSS-MT signatures exhausted"));
        }

        let mt = get_mt_params(self.param_id);
        let n = mt.n;
        let mode = mt_hash_mode(self.param_id);
        let idx_bytes = mt.total_h.div_ceil(8);

        let sk_seed = &self.private_key[..n];
        let sk_prf = &self.private_key[n..2 * n];
        let pk_seed = &self.private_key[2 * n..3 * n];
        let pk_root = &self.private_key[3 * n..4 * n];

        let hasher = XmssHasher {
            n,
            padding_len: mt.padding_len,
            mode,
            sk_seed: sk_seed.to_vec(),
            pk_seed: pk_seed.to_vec(),
        };

        // Generate randomness R
        let r = hasher.prf_msg(sk_prf, self.leaf_idx, message)?;

        // Compute message digest
        let msg_hash = hasher.h_msg(&r, pk_root, self.leaf_idx, message)?;

        // Hypertree sign
        let (ht_sig, _root) = tree::hypertree_sign(&hasher, &msg_hash, self.leaf_idx, &mt)?;

        // Assemble: idx(idx_bytes) || R(n) || ht_sig
        let mut sig = Vec::with_capacity(mt.sig_bytes);
        // Encode idx as idx_bytes big-endian
        let idx_be = self.leaf_idx.to_be_bytes();
        sig.extend_from_slice(&idx_be[8 - idx_bytes..]);
        sig.extend_from_slice(&r);
        sig.extend_from_slice(&ht_sig);

        self.leaf_idx += 1;

        Ok(sig)
    }

    /// Verify a signature against a message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let mt = get_mt_params(self.param_id);
        let n = mt.n;
        let mode = mt_hash_mode(self.param_id);
        let idx_bytes = mt.total_h.div_ceil(8);

        if signature.len() != mt.sig_bytes {
            return Ok(false);
        }

        let pk_seed = &self.public_key[4 + n..4 + 2 * n];
        let pk_root = &self.public_key[4..4 + n];

        let hasher = XmssHasher {
            n,
            padding_len: mt.padding_len,
            mode,
            sk_seed: vec![0u8; n],
            pk_seed: pk_seed.to_vec(),
        };

        // Parse variable-length idx
        let mut idx_buf = [0u8; 8];
        idx_buf[8 - idx_bytes..].copy_from_slice(&signature[..idx_bytes]);
        let global_idx = u64::from_be_bytes(idx_buf);

        let r = &signature[idx_bytes..idx_bytes + n];
        let ht_sig = &signature[idx_bytes + n..];

        // Compute message digest
        let msg_hash = hasher.h_msg(r, pk_root, global_idx, message)?;

        // Hypertree verify
        let computed_root = tree::hypertree_verify(&hasher, &msg_hash, ht_sig, global_idx, &mt)?;

        Ok(subtle::ConstantTimeEq::ct_eq(computed_root.as_slice(), pk_root).into())
    }

    /// Return the number of remaining signatures.
    pub fn remaining_signatures(&self) -> u64 {
        self.max_signatures - self.leaf_idx
    }

    /// Return the public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Return the parameter set identifier.
    pub fn param_id(&self) -> XmssMtParamId {
        self.param_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xmss_sha2_10_256_roundtrip() {
        let mut kp = XmssKeyPair::generate(XmssParamId::Sha2_10_256).unwrap();
        let msg = b"test message for XMSS SHA2-10-256";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_xmss_shake256_10_256_roundtrip() {
        let mut kp = XmssKeyPair::generate(XmssParamId::Shake256_10_256).unwrap();
        let msg = b"test message for XMSS SHAKE256-10-256";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_xmss_shake128_10_256_roundtrip() {
        let mut kp = XmssKeyPair::generate(XmssParamId::Shake128_10_256).unwrap();
        let msg = b"test message for XMSS SHAKE128-10-256";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_xmss_stateful_signing() {
        let mut kp = XmssKeyPair::generate(XmssParamId::Sha2_10_256).unwrap();
        let msgs = [b"msg1".as_ref(), b"msg2", b"msg3"];
        let mut sigs = Vec::new();
        for msg in &msgs {
            sigs.push(kp.sign(msg).unwrap());
        }
        // All signatures should verify
        for (msg, sig) in msgs.iter().zip(&sigs) {
            assert!(kp.verify(msg, sig).unwrap());
        }
        assert_eq!(kp.remaining_signatures(), (1u64 << 10) - 3);
    }

    #[test]
    fn test_xmss_remaining_signatures() {
        let mut kp = XmssKeyPair::generate(XmssParamId::Sha2_10_256).unwrap();
        assert_eq!(kp.remaining_signatures(), 1024);
        kp.sign(b"one").unwrap();
        assert_eq!(kp.remaining_signatures(), 1023);
        kp.sign(b"two").unwrap();
        assert_eq!(kp.remaining_signatures(), 1022);
    }

    #[test]
    fn test_xmss_tampered_signature() {
        let mut kp = XmssKeyPair::generate(XmssParamId::Sha2_10_256).unwrap();
        let msg = b"tamper test";
        let mut sig = kp.sign(msg).unwrap();
        // Flip byte in WOTS+ sig portion
        sig[40] ^= 0xff;
        assert!(!kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_xmss_tampered_message() {
        let mut kp = XmssKeyPair::generate(XmssParamId::Sha2_10_256).unwrap();
        let sig = kp.sign(b"original").unwrap();
        assert!(!kp.verify(b"modified", &sig).unwrap());
    }

    #[test]
    fn test_xmss_cross_key_verify() {
        let mut kp1 = XmssKeyPair::generate(XmssParamId::Sha2_10_256).unwrap();
        let kp2 = XmssKeyPair::generate(XmssParamId::Sha2_10_256).unwrap();
        let msg = b"cross key test";
        let sig = kp1.sign(msg).unwrap();
        assert!(!kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_xmss_key_lengths() {
        let kp = XmssKeyPair::generate(XmssParamId::Sha2_10_256).unwrap();
        let p = get_params(XmssParamId::Sha2_10_256);
        // Public key: OID(4) + root(32) + seed(32) = 68
        assert_eq!(kp.public_key().len(), 4 + 2 * 32);
        // Private key: SK.seed(32) + SK.prf(32) + PK.seed(32) + PK.root(32) = 128
        assert_eq!(kp.private_key.len(), 4 * 32);
        assert_eq!(p.sig_bytes, 2500);
    }

    #[test]
    #[ignore] // h=16 builds 65536 leaves — ~61s even with opt-level=2
    fn test_xmss_sha2_16_256_roundtrip() {
        let mut kp = XmssKeyPair::generate(XmssParamId::Sha2_16_256).unwrap();
        let msg = b"test message for XMSS SHA2-16-256";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    // Extended single-tree tests (n=64 and n=24)

    #[test]
    fn test_xmss_sha2_10_512_roundtrip() {
        let mut kp = XmssKeyPair::generate(XmssParamId::Sha2_10_512).unwrap();
        let p = get_params(XmssParamId::Sha2_10_512);
        assert_eq!(p.n, 64);
        assert_eq!(p.wots_len, 131);
        let msg = b"test message for XMSS SHA2-10-512 (n=64)";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), p.sig_bytes);
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_xmss_sha2_10_192_roundtrip() {
        let mut kp = XmssKeyPair::generate(XmssParamId::Sha2_10_192).unwrap();
        let p = get_params(XmssParamId::Sha2_10_192);
        assert_eq!(p.n, 24);
        assert_eq!(p.wots_len, 51);
        assert_eq!(p.padding_len, 4);
        let msg = b"test message for XMSS SHA2-10-192 (n=24)";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), p.sig_bytes);
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_xmss_shake256_10_512_roundtrip() {
        let mut kp = XmssKeyPair::generate(XmssParamId::Shake256_10_512).unwrap();
        let p = get_params(XmssParamId::Shake256_10_512);
        assert_eq!(p.n, 64);
        let msg = b"test message for XMSS SHAKE256-10-512 (n=64)";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), p.sig_bytes);
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_xmss_shake256_10_192_roundtrip() {
        let mut kp = XmssKeyPair::generate(XmssParamId::Shake256_10_192).unwrap();
        let p = get_params(XmssParamId::Shake256_10_192);
        assert_eq!(p.n, 24);
        assert_eq!(p.padding_len, 4);
        let msg = b"test message for XMSS SHAKE256-10-192 (n=24)";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), p.sig_bytes);
        assert!(kp.verify(msg, &sig).unwrap());
    }

    // XMSS-MT tests

    #[test]
    fn test_xmss_mt_sha2_20_2_256_roundtrip() {
        let mut kp = XmssMtKeyPair::generate(XmssMtParamId::Sha2_20_2_256).unwrap();
        let mt = get_mt_params(XmssMtParamId::Sha2_20_2_256);
        assert_eq!(mt.total_h, 20);
        assert_eq!(mt.d, 2);
        assert_eq!(mt.hp, 10);
        let msg = b"test XMSS-MT SHA2-20/2-256";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), mt.sig_bytes);
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_xmss_mt_sha2_20_4_256_roundtrip() {
        let mut kp = XmssMtKeyPair::generate(XmssMtParamId::Sha2_20_4_256).unwrap();
        let mt = get_mt_params(XmssMtParamId::Sha2_20_4_256);
        assert_eq!(mt.hp, 5);
        assert_eq!(mt.d, 4);
        let msg = b"test XMSS-MT SHA2-20/4-256";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), mt.sig_bytes);
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_xmss_mt_sha2_20_4_512_roundtrip() {
        let mut kp = XmssMtKeyPair::generate(XmssMtParamId::Sha2_20_4_512).unwrap();
        let mt = get_mt_params(XmssMtParamId::Sha2_20_4_512);
        assert_eq!(mt.n, 64);
        assert_eq!(mt.hp, 5);
        let msg = b"test XMSS-MT SHA2-20/4-512 (n=64)";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), mt.sig_bytes);
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_xmss_mt_tampered_signature() {
        let mut kp = XmssMtKeyPair::generate(XmssMtParamId::Sha2_20_4_256).unwrap();
        let msg = b"tamper test MT";
        let mut sig = kp.sign(msg).unwrap();
        // Flip a byte in the hypertree signature portion
        let flip_pos = sig.len() / 2;
        sig[flip_pos] ^= 0xff;
        assert!(!kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_xmss_mt_wrong_message() {
        let mut kp = XmssMtKeyPair::generate(XmssMtParamId::Sha2_20_4_256).unwrap();
        let sig = kp.sign(b"original MT").unwrap();
        assert!(!kp.verify(b"modified MT", &sig).unwrap());
    }

    #[test]
    fn test_xmss_mt_remaining_signatures() {
        let mut kp = XmssMtKeyPair::generate(XmssMtParamId::Sha2_20_4_256).unwrap();
        let mt = get_mt_params(XmssMtParamId::Sha2_20_4_256);
        assert_eq!(kp.remaining_signatures(), 1u64 << mt.total_h);
        kp.sign(b"one").unwrap();
        assert_eq!(kp.remaining_signatures(), (1u64 << mt.total_h) - 1);
    }

    #[test]
    fn test_xmss_mt_cross_key_verify() {
        let mut kp1 = XmssMtKeyPair::generate(XmssMtParamId::Sha2_20_4_256).unwrap();
        let kp2 = XmssMtKeyPair::generate(XmssMtParamId::Sha2_20_4_256).unwrap();
        let msg = b"cross key MT test";
        let sig = kp1.sign(msg).unwrap();
        assert!(!kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_xmss_mt_key_lengths() {
        let kp = XmssMtKeyPair::generate(XmssMtParamId::Sha2_20_2_256).unwrap();
        let mt = get_mt_params(XmssMtParamId::Sha2_20_2_256);
        // PK: OID(4) + root(n) + seed(n)
        assert_eq!(kp.public_key().len(), 4 + 2 * mt.n);
        // SK: SK.seed(n) + SK.prf(n) + PK.seed(n) + PK.root(n)
        assert_eq!(kp.private_key.len(), 4 * mt.n);
    }
}
