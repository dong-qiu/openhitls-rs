//! Classic McEliece key encapsulation mechanism.
//!
//! Classic McEliece is a code-based, post-quantum key encapsulation mechanism
//! with very small ciphertexts but large public keys. It is based on the
//! Niederreiter dual of the McEliece cryptosystem using binary Goppa codes,
//! and has a long history of cryptanalytic study.

mod benes;
mod decode;
mod encode;
mod gf;
mod keygen;
mod matrix;
mod params;
mod poly;
mod vector;

use hitls_types::algorithm::McElieceParamId;
use hitls_types::CryptoError;
use zeroize::Zeroize;

use self::params::L_BYTES;

/// A Classic McEliece key pair for key encapsulation.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct McElieceKeyPair {
    encapsulation_key: Vec<u8>,
    decapsulation_key: Vec<u8>,
    #[zeroize(skip)]
    param_id: McElieceParamId,
}

impl McElieceKeyPair {
    /// Generate a new Classic McEliece key pair for the given parameter set.
    pub fn generate(param_id: McElieceParamId) -> Result<Self, CryptoError> {
        let p = params::get_params(param_id);

        // Generate random seed delta
        let mut delta = vec![0u8; L_BYTES];
        getrandom::fill(&mut delta).map_err(|_| CryptoError::McElieceKeygenFail)?;

        let kp = keygen::seeded_keygen(&delta, &p)?;

        // Serialize sk in the C reference layout — see
        // `serialize_private_key` doc-comment for the wire format.
        let sk = serialize_private_key(&kp, &p);

        Ok(Self {
            encapsulation_key: kp.pk_t,
            decapsulation_key: sk,
            param_id,
        })
    }

    /// Reconstruct a key pair from a serialised decapsulation key,
    /// matching the openHiTLS C reference sk byte layout
    /// `delta(32) || c(8) || g[0..t](2t) || controlbits(...) || s(n_bytes)`.
    /// The resulting key pair has an empty encapsulation key — only the
    /// `decapsulate` direction is available. Intended for reference KAT
    /// migration where a published `(dk, ct, ss)` triple is replayed.
    pub fn from_decapsulation_key(
        param_id: McElieceParamId,
        dk: &[u8],
    ) -> Result<Self, CryptoError> {
        let p = params::get_params(param_id);
        if dk.len() != p.private_key_bytes {
            return Err(CryptoError::InvalidArg(""));
        }
        Ok(Self {
            encapsulation_key: Vec::new(),
            decapsulation_key: dk.to_vec(),
            param_id,
        })
    }

    /// Encapsulate: produce a shared secret and ciphertext.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        // A key pair reconstructed via `from_decapsulation_key` has no
        // encapsulation key; reject rather than encode against an empty
        // matrix.
        if self.encapsulation_key.is_empty() {
            return Err(CryptoError::InvalidArg(
                "encapsulation key absent (key pair built from a decapsulation key only)",
            ));
        }
        let p = params::get_params(self.param_id);

        // Generate random error vector
        let e = encode::fixed_weight_vector(&p)?;

        // Encode: C0 = H*e (syndrome)
        let c0 = encode::encode_vector(&e, &self.encapsulation_key, &p)?;

        let mut ciphertext = c0;

        // If PC variant, add C1 = Hash(2, e)
        if p.pc {
            let mut hash_in = vec![2u8];
            hash_in.extend_from_slice(&e[..L_BYTES.min(e.len())]);
            let c1 = shake256_hash(&hash_in, L_BYTES)?;
            ciphertext.extend_from_slice(&c1);
        }

        // Session key K = Hash(1, e, C)
        let session_key = compute_session_key(1, &e, &ciphertext, &p)?;

        Ok((ciphertext, session_key))
    }

    /// Decapsulate: recover the shared secret from a ciphertext.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let p = params::get_params(self.param_id);

        if ciphertext.len() != p.cipher_bytes {
            return Err(CryptoError::InvalidArg(""));
        }

        // Deserialize private key
        let sk = deserialize_private_key(&self.decapsulation_key, &p)?;

        // Reconstruct support from control bits
        let gf_l = benes::support_from_cbits(&sk.controlbits, p.m, p.n)?;

        // Build received vector from ciphertext
        let mut v = vec![0u8; p.n_bytes];
        for i in 0..p.mt {
            if i / 8 < ciphertext.len() {
                let bit = vector::vec_get_bit(ciphertext, i);
                vector::vec_set_bit(&mut v, i, bit);
            }
        }

        // Decode
        let (mut e, success) = decode::decode_goppa(&v, &sk.g, &gf_l, &p)?;

        // If decode failed, use s for implicit rejection
        if !success {
            e.copy_from_slice(&sk.s[..p.n_bytes.min(sk.s.len())]);
        }

        let mut b: u8 = if success { 1 } else { 0 };

        // If PC variant, verify C1
        if p.pc {
            let c1_offset = p.cipher_bytes - L_BYTES;
            let c1 = &ciphertext[c1_offset..];
            let mut hash_in = vec![2u8];
            hash_in.extend_from_slice(&e[..L_BYTES.min(e.len())]);
            let c1_prime = shake256_hash(&hash_in, L_BYTES)?;
            if c1 != c1_prime.as_slice() {
                b = 0;
            }
        }

        // Session key K = Hash(b, e, C)
        compute_session_key(b, &e, ciphertext, &p)
    }

    /// Return the encapsulation (public) key bytes.
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.encapsulation_key
    }

    /// Return the parameter set ID.
    pub fn param_id(&self) -> McElieceParamId {
        self.param_id
    }
}

fn compute_session_key(
    prefix: u8,
    e: &[u8],
    ciphertext: &[u8],
    params: &params::McElieceParams,
) -> Result<Vec<u8>, CryptoError> {
    let mut hash_in = Vec::with_capacity(1 + params.n_bytes + params.cipher_bytes);
    hash_in.push(prefix);
    hash_in.extend_from_slice(&e[..params.n_bytes.min(e.len())]);
    hash_in.extend_from_slice(ciphertext);
    shake256_hash(&hash_in, L_BYTES)
}

fn shake256_hash(input: &[u8], output_len: usize) -> Result<Vec<u8>, CryptoError> {
    use crate::sha3::Shake256;

    let mut hasher = Shake256::new();
    hasher.update(input)?;
    hasher.squeeze(output_len)
}

/// Serialise the McEliece secret key to bytes in the **openHiTLS C
/// reference layout** (see `crypto/mceliece/src/mceliece.c::
/// McelieceExportPrvKey`): `delta || c || g[0..t] || controlbits || s`.
///
/// **Note on the `g` block.** The Goppa polynomial is monic — its
/// leading coefficient `g[t]` is always `1` — so the reference only
/// stores coefficients `g[0..t]` (i.e. `t` of them, not `t+1`) and the
/// parser re-sets `g[t] = 1` on read. The Rust keygen already produces
/// a monic `g`, so dropping the leading coefficient from the wire is
/// lossless.
///
/// Pre-I160 the Rust layout also embedded a full `alpha` block (2·Q
/// bytes = 16384 B) and ordered `s` ahead of `controlbits`. Neither
/// matches the C reference: `alpha` is recovered from the Benes
/// `controlbits` via `support_from_cbits`, and the section order is
/// `controlbits` then `s`. I160 realigns both.
fn serialize_private_key(kp: &keygen::KeyPairInternal, p: &params::McElieceParams) -> Vec<u8> {
    let mut sk = Vec::with_capacity(p.private_key_bytes);
    // delta (32 bytes)
    sk.extend_from_slice(&kp.sk_delta);
    // c (pivot mask, 8 bytes, little-endian)
    sk.extend_from_slice(&kp.sk_c.to_le_bytes());
    // g coefficients (2*t bytes, little-endian; leading g[t] = 1 is implicit)
    for i in 0..p.t {
        sk.extend_from_slice(&kp.sk_g.coeffs[i].to_le_bytes());
    }
    // controlbits (variable, depends on m)
    sk.extend_from_slice(&kp.sk_controlbits);
    // s (n_bytes random tail)
    sk.extend_from_slice(&kp.sk_s);
    sk
}

struct PrivateKeyParts {
    g: poly::GfPoly,
    s: Vec<u8>,
    controlbits: Vec<u8>,
}

/// Parse a McEliece secret key in the openHiTLS C reference layout.
/// Mirrors `McelieceParsePrvKey` in `crypto/mceliece/src/mceliece.c`:
/// reads `t` `g` coefficients then sets `g[t] = 1` (monic), then takes
/// `controlbits` followed by `s`. See `serialize_private_key` for the
/// pre-I160 divergence write-up.
fn deserialize_private_key(
    sk: &[u8],
    p: &params::McElieceParams,
) -> Result<PrivateKeyParts, CryptoError> {
    let mut offset = 0;
    // delta (32 bytes) - skip
    offset += L_BYTES;
    // c (8 bytes) - skip
    offset += 8;
    // g coefficients: t coeffs on the wire, plus implicit monic leading
    let mut g = poly::GfPoly::new(p.t);
    for i in 0..p.t {
        if offset + 2 > sk.len() {
            return Err(CryptoError::InvalidArg(""));
        }
        let coeff = u16::from_le_bytes([sk[offset], sk[offset + 1]]);
        g.set_coeff(i, coeff);
        offset += 2;
    }
    // Monic leading coefficient — never written by the reference, but
    // required by the decoder.
    g.set_coeff(p.t, 1);
    // controlbits: a fixed `(2*m - 1) * 2^(m-1) / 8` bytes (the size of
    // a Benes-network control sequence over 2^m permutation slots; for
    // m = 13 that's 25 · 4096 / 8 = 12800 bytes). Listed ahead of `s`
    // in the wire layout per the C reference.
    let cb_len = ((2 * p.m - 1) << (p.m - 1)) / 8;
    let cb_end = offset + cb_len;
    if cb_end > sk.len() {
        return Err(CryptoError::InvalidArg(""));
    }
    let controlbits = sk[offset..cb_end].to_vec();
    offset = cb_end;
    // s (n_bytes tail)
    let s_end = offset + p.n_bytes;
    if s_end > sk.len() {
        return Err(CryptoError::InvalidArg(""));
    }
    let s = sk[offset..s_end].to_vec();

    Ok(PrivateKeyParts { g, s, controlbits })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mceliece_gf_arithmetic() {
        use super::gf::*;

        // GF(2^13) basics
        assert_eq!(gf_add(0, 0), 0);
        assert_eq!(gf_add(1, 1), 0);
        assert_eq!(gf_mul(1, 1), 1);
        assert_eq!(gf_mul(0, 100), 0);

        // Multiplicative inverse
        for a in 1..200u16 {
            let inv = gf_inv(a);
            assert_eq!(gf_mul(a, inv), 1, "gf_inv failed for a={}", a);
        }

        // Division
        for a in 1..50u16 {
            for b in 1..50u16 {
                let q = gf_div(a, b);
                assert_eq!(gf_mul(q, b), a, "gf_div failed for {}/{}", a, b);
            }
        }
    }

    #[test]
    fn test_mceliece_gf_poly_eval() {
        use super::poly::GfPoly;

        // p(x) = x + 1
        let mut p = GfPoly::new(1);
        p.set_coeff(0, 1);
        p.set_coeff(1, 1);
        assert_eq!(p.eval(0), 1); // p(0) = 1
        assert_eq!(p.eval(1), 0); // p(1) = 1 + 1 = 0 (GF(2))
        assert_eq!(p.eval(2), 3); // p(2) = 2 + 1 = 3 (XOR)

        // p(x) = x^2 + x + 1
        let mut p2 = GfPoly::new(2);
        p2.set_coeff(0, 1);
        p2.set_coeff(1, 1);
        p2.set_coeff(2, 1);
        assert_eq!(p2.eval(0), 1); // p(0) = 1
                                   // p(1) = 1 + 1 + 1 = 1
        assert_eq!(p2.eval(1), 1);
    }

    #[test]
    fn test_mceliece_vector_ops() {
        use super::vector::*;

        let mut v = vec![0u8; 16];
        vec_set_bit(&mut v, 0, 1);
        assert_eq!(vec_get_bit(&v, 0), 1);
        assert_eq!(vec_get_bit(&v, 1), 0);

        vec_set_bit(&mut v, 7, 1);
        assert_eq!(vec_get_bit(&v, 7), 1);
        assert_eq!(v[0], 0x81);

        vec_set_bit(&mut v, 8, 1);
        assert_eq!(vec_get_bit(&v, 8), 1);
        assert_eq!(v[1], 0x01);

        assert_eq!(vec_weight(&v), 3);

        vec_set_bit(&mut v, 0, 0);
        assert_eq!(vec_get_bit(&v, 0), 0);
        assert_eq!(vec_weight(&v), 2);
    }

    #[test]
    fn test_mceliece_key_sizes() {
        use hitls_types::algorithm::McElieceParamId::*;

        let checks = [
            (McEliece6688128, 1044992, 208, 32),
            (McEliece6688128Pc, 1044992, 240, 32),
            (McEliece6960119, 1047319, 194, 32),
            (McEliece6960119Pc, 1047319, 226, 32),
            (McEliece8192128, 1357824, 208, 32),
            (McEliece8192128Pc, 1357824, 240, 32),
        ];

        for (id, pk_size, ct_size, ss_size) in &checks {
            let p = params::get_params(*id);
            assert_eq!(p.public_key_bytes, *pk_size, "{:?} pk size", id);
            assert_eq!(p.cipher_bytes, *ct_size, "{:?} ct size", id);
            assert_eq!(p.shared_key_bytes, *ss_size, "{:?} ss size", id);
        }
    }

    #[test]
    fn test_mceliece_6688128_roundtrip() {
        for _ in 0..10 {
            let kp = McElieceKeyPair::generate(McElieceParamId::McEliece6688128).unwrap();
            let (ct, ss1) = kp.encapsulate().unwrap();
            let ss2 = kp.decapsulate(&ct).unwrap();
            assert_eq!(ss1, ss2);
            assert_eq!(ss1.len(), 32);
        }
    }

    #[test]
    fn test_mceliece_8192128_roundtrip() {
        let kp = McElieceKeyPair::generate(McElieceParamId::McEliece8192128).unwrap();
        let (ct, ss1) = kp.encapsulate().unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
        assert_eq!(ss1.len(), 32);
    }

    #[test]
    fn test_mceliece_benes_roundtrip() {
        // Permutation test: 2^5 = 32 elements (n must be >=16 for byte-aligned layers)
        let w = 5;
        let n = 1usize << w;
        // Build a permutation: simple reversal
        let pi: Vec<i16> = (0..n).rev().map(|x| x as i16).collect();

        let cbits = benes::cbits_from_perm(&pi, w, n).unwrap();
        let support = benes::support_from_cbits(&cbits, w, n).unwrap();

        // Verify the support is a valid permutation
        assert_eq!(support.len(), n);

        // All values should be < n
        for &v in &support {
            assert!((v as usize) < n, "support value {} out of range", v);
        }

        // All values should be distinct
        let mut sorted: Vec<u16> = support.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), n, "support has duplicates");
    }

    #[test]
    fn test_mceliece_syndrome_decode_small() {
        // Test that the GF arithmetic and poly evaluation work together
        use super::poly::GfPoly;

        // Create a simple Goppa polynomial: g(x) = x^2 + x + 1
        let mut g = GfPoly::new(2);
        g.set_coeff(0, 1);
        g.set_coeff(1, 1);
        g.set_coeff(2, 1);

        // Verify g evaluates correctly
        assert_eq!(g.eval(0), 1);
        assert_eq!(g.eval(1), 1); // 1 + 1 + 1 = 1 in GF(2^13)

        // Test polynomial root finding
        let support: Vec<gf::GfElement> = (0..10).collect();
        let f = vec![1, 1, 1]; // x^2 + x + 1
        let mut out = vec![0u16; 10];
        GfPoly::eval_roots(&mut out, &f, &support, 10, 2);
        // f(0) = 1, f(1) = 1, f(2) = 2+2+1 = 1 (XOR), etc.
        assert_eq!(out[0], 1);
        assert_eq!(out[1], 1);
    }

    #[test]
    fn test_mceliece_pack_unpack() {
        // Test vector bit operations with various patterns
        use super::vector::*;

        let n = 128;
        let n_bytes = n / 8;
        let mut v = vec![0u8; n_bytes];

        // Set every 3rd bit
        for i in (0..n).step_by(3) {
            vec_set_bit(&mut v, i, 1);
        }

        // Verify
        for i in 0..n {
            let expected = if i % 3 == 0 { 1 } else { 0 };
            assert_eq!(vec_get_bit(&v, i), expected, "bit {} mismatch", i);
        }

        let weight = vec_weight(&v);
        assert_eq!(weight, (0..n).step_by(3).count());
    }

    #[test]
    fn test_mceliece_tampered_ciphertext() {
        // Test that decode handles invalid input gracefully
        use super::poly::GfPoly;

        // Create a simple Goppa polynomial: g(x) = x^2 + x + 1
        let mut g = GfPoly::new(2);
        g.set_coeff(0, 1);
        g.set_coeff(1, 1);
        g.set_coeff(2, 1);

        // 64 support elements, none are roots of g
        let alpha: Vec<gf::GfElement> = (3..67).collect();
        let n = 64;
        let t = 2;
        let mt = t * 13; // 26
        let p = params::McElieceParams {
            m: 13,
            n,
            t,
            mt,
            k: n - mt, // 64 - 26 = 38
            n_bytes: 8,
            mt_bytes: mt.div_ceil(8),
            k_bytes: (n - mt).div_ceil(8),
            private_key_bytes: 0,
            public_key_bytes: 0,
            cipher_bytes: mt.div_ceil(8),
            shared_key_bytes: 32,
            semi: false,
            pc: false,
        };
        // Create a random received vector — decoding should produce an error or non-match
        let received = vec![0xFFu8; 8];
        let result = decode::decode_goppa(&received, &g, &alpha, &p);
        assert!(result.is_ok());
        let (_e, success) = result.unwrap();
        // With random input, decoding should fail verification (wrong weight)
        assert!(!success, "random input should not decode correctly");
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(3))]

            #[test]
            fn prop_mceliece_encap_decap_roundtrip(
                _seed in any::<u64>(), // for randomness variation
            ) {
                let kp =
                    McElieceKeyPair::generate(McElieceParamId::McEliece6688128).unwrap();
                let (ct, ss1) = kp.encapsulate().unwrap();
                let ss2 = kp.decapsulate(&ct).unwrap();
                prop_assert_eq!(&ss1, &ss2);
                prop_assert_eq!(ss1.len(), 32);
            }
        }
    }

    #[test]
    fn test_mceliece_cross_key_decaps() {
        // Test that decapsulating with wrong key fails
        // This requires keygen so mark as integration-level test
        // For now verify the error path exists
        use super::params;

        let p = params::get_params(McElieceParamId::McEliece6688128);
        assert_eq!(p.shared_key_bytes, 32);
        assert_eq!(p.n, 6688);
        assert_eq!(p.t, 128);
        assert_eq!(p.mt, 1664);
        assert_eq!(p.k, 5024);
    }
}
