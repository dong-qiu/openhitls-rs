//! XMSS WOTS+ (RFC 8391 Section 3).
//!
//! W=16, n=32, len_1=64, len_2=3, wots_len=67.

use hitls_types::CryptoError;

use super::address::{XmssAdrs, XmssAdrsType};
use super::hash::XmssHasher;
use super::params::XmssParams;

/// Convert byte array to base-W representation (W=16, b=4 bits).
fn base_w(x: &[u8], out_len: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(out_len);
    let mut bit: u32 = 0;
    let mut o: u64 = 0;
    let mut xi: usize = 0;

    for _ in 0..out_len {
        while bit < 4 && xi < x.len() {
            o = (o << 8) | (x[xi] as u64);
            bit += 8;
            xi += 1;
        }
        bit -= 4;
        out.push((o >> bit) as u32);
        o &= (1u64 << bit) - 1;
    }
    out
}

/// Convert message to base-W with checksum.
fn msg_to_base_w(msg: &[u8], n: usize) -> Vec<u32> {
    let w: u32 = 16;
    let len_1 = 2 * n;
    let len_2 = 3;

    let mut values = base_w(msg, len_1);

    // Checksum
    let mut csum: u32 = 0;
    for &v in &values {
        csum += (w - 1) - v;
    }
    csum <<= 4;

    let csum_bytes = [(csum >> 8) as u8, (csum & 0xff) as u8];
    let csum_vals = base_w(&csum_bytes, len_2);
    values.extend_from_slice(&csum_vals);

    values
}

/// WOTS+ chain function (ROBUST mode via hasher.f).
fn chain(
    h: &XmssHasher,
    x: &[u8],
    start: u32,
    steps: u32,
    adrs: &mut XmssAdrs,
) -> Result<Vec<u8>, CryptoError> {
    let mut tmp = x.to_vec();
    for i in start..start + steps {
        adrs.set_hash_addr(i);
        tmp = h.f(adrs, &tmp)?;
    }
    Ok(tmp)
}

/// L-tree: compress wots_len * n bytes to n bytes using pairwise hashing.
pub(crate) fn l_tree(
    h: &XmssHasher,
    pk_parts: &[u8],
    adrs: &mut XmssAdrs,
    p: &XmssParams,
) -> Result<Vec<u8>, CryptoError> {
    let n = p.n;
    let mut nodes: Vec<Vec<u8>> = pk_parts.chunks(n).map(|c| c.to_vec()).collect();

    let mut height: u32 = 0;
    while nodes.len() > 1 {
        adrs.set_tree_height(height);
        let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < nodes.len() {
            adrs.set_tree_index((i / 2) as u32);
            let parent = h.h(adrs, &nodes[i], &nodes[i + 1])?;
            next.push(parent);
            i += 2;
        }
        // Odd node: carry forward
        if i < nodes.len() {
            next.push(nodes[i].clone());
        }
        nodes = next;
        height += 1;
    }

    Ok(nodes.into_iter().next().unwrap_or_default())
}

/// Generate WOTS+ public key for a given OTS address.
pub(crate) fn wots_pk_gen(
    h: &XmssHasher,
    ots_addr: u32,
    adrs: &mut XmssAdrs,
    p: &XmssParams,
) -> Result<Vec<u8>, CryptoError> {
    let n = p.n;
    let w = 15u32; // W-1

    let mut pk_parts = Vec::with_capacity(p.wots_len * n);
    let mut ots_adrs = adrs.clone();
    ots_adrs.set_type(XmssAdrsType::Ots);
    ots_adrs.set_ots_addr(ots_addr);

    for i in 0..p.wots_len {
        // Generate secret key element via PRF
        ots_adrs.set_chain_addr(i as u32);
        ots_adrs.set_hash_addr(0);
        ots_adrs.set_key_and_mask(0);
        let sk_i = h.prf_keygen(&ots_adrs)?;

        // Chain to public key element
        ots_adrs.set_chain_addr(i as u32);
        let pk_i = chain(h, &sk_i, 0, w, &mut ots_adrs)?;
        pk_parts.extend_from_slice(&pk_i);
    }

    // Compress via L-tree
    let mut ltree_adrs = adrs.clone();
    ltree_adrs.set_type(XmssAdrsType::LTree);
    ltree_adrs.set_ltree_addr(ots_addr);
    l_tree(h, &pk_parts, &mut ltree_adrs, p)
}

/// WOTS+ sign: generate signature for n-byte message digest.
pub(crate) fn wots_sign(
    h: &XmssHasher,
    msg: &[u8],
    ots_addr: u32,
    adrs: &mut XmssAdrs,
    p: &XmssParams,
) -> Result<Vec<u8>, CryptoError> {
    let n = p.n;
    let msgw = msg_to_base_w(msg, n);

    let mut sig = Vec::with_capacity(p.wots_len * n);
    let mut ots_adrs = adrs.clone();
    ots_adrs.set_type(XmssAdrsType::Ots);
    ots_adrs.set_ots_addr(ots_addr);

    for (i, &mw) in msgw.iter().enumerate().take(p.wots_len) {
        ots_adrs.set_chain_addr(i as u32);
        ots_adrs.set_hash_addr(0);
        ots_adrs.set_key_and_mask(0);
        let sk_i = h.prf_keygen(&ots_adrs)?;

        ots_adrs.set_chain_addr(i as u32);
        let sig_i = chain(h, &sk_i, 0, mw, &mut ots_adrs)?;
        sig.extend_from_slice(&sig_i);
    }

    Ok(sig)
}

/// WOTS+ pk_from_sig: recover public key from signature.
pub(crate) fn wots_pk_from_sig(
    h: &XmssHasher,
    sig: &[u8],
    msg: &[u8],
    ots_addr: u32,
    adrs: &mut XmssAdrs,
    p: &XmssParams,
) -> Result<Vec<u8>, CryptoError> {
    let n = p.n;
    let w = 15u32; // W-1
    let msgw = msg_to_base_w(msg, n);

    let mut pk_parts = Vec::with_capacity(p.wots_len * n);
    let mut ots_adrs = adrs.clone();
    ots_adrs.set_type(XmssAdrsType::Ots);
    ots_adrs.set_ots_addr(ots_addr);

    for i in 0..p.wots_len {
        let sig_i = &sig[i * n..(i + 1) * n];
        ots_adrs.set_chain_addr(i as u32);
        let remaining = w - msgw[i];
        let pk_i = chain(h, sig_i, msgw[i], remaining, &mut ots_adrs)?;
        pk_parts.extend_from_slice(&pk_i);
    }

    // Compress via L-tree
    let mut ltree_adrs = adrs.clone();
    ltree_adrs.set_type(XmssAdrsType::LTree);
    ltree_adrs.set_ltree_addr(ots_addr);
    l_tree(h, &pk_parts, &mut ltree_adrs, p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmss::hash::XmssHasher;
    use crate::xmss::params::{get_params, XmssHashMode};
    use hitls_types::XmssParamId;

    #[test]
    fn test_xmss_base_w_extraction() {
        // W=16, so each nibble is one base-W digit
        assert_eq!(base_w(&[0x12, 0x34], 4), vec![1, 2, 3, 4]);
        assert_eq!(base_w(&[0xFF], 2), vec![15, 15]);
        assert_eq!(base_w(&[0x00], 2), vec![0, 0]);
        assert_eq!(base_w(&[0xAB], 2), vec![0x0A, 0x0B]);

        // Multi-byte extraction
        assert_eq!(base_w(&[0xDE, 0xAD], 4), vec![0x0D, 0x0E, 0x0A, 0x0D]);

        // Single digit
        assert_eq!(base_w(&[0x70], 1), vec![7]);
    }

    #[test]
    fn test_msg_to_base_w_length() {
        // For n=32: len_1 = 64, len_2 = 3, total wots_len = 67
        let msg = vec![0x55u8; 32];
        let vals = msg_to_base_w(&msg, 32);
        assert_eq!(vals.len(), 67);
    }

    #[test]
    fn test_msg_to_base_w_all_values_in_range() {
        // All base-W values must be in [0, W-1] = [0, 15]
        let msg = vec![0xFFu8; 32];
        let vals = msg_to_base_w(&msg, 32);
        for &v in &vals {
            assert!(v <= 15, "base-W value {} exceeds W-1=15", v);
        }
        // Also test with zeros
        let msg_zero = vec![0x00u8; 32];
        let vals_zero = msg_to_base_w(&msg_zero, 32);
        for &v in &vals_zero {
            assert!(v <= 15, "base-W value {} exceeds W-1=15", v);
        }
    }

    #[test]
    fn test_chain_zero_steps_identity() {
        let hasher = XmssHasher {
            n: 32,
            padding_len: 32,
            mode: XmssHashMode::Shake256,
            sk_seed: vec![0xAAu8; 32],
            pk_seed: vec![0xBBu8; 32],
        };
        let input = vec![0x42u8; 32];
        let mut adrs = XmssAdrs::new();
        adrs.set_type(XmssAdrsType::Ots);
        let result = chain(&hasher, &input, 0, 0, &mut adrs).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn test_l_tree_single_chunk_passthrough() {
        // With a single n-byte chunk, l_tree returns it unchanged (loop body not entered)
        let hasher = XmssHasher {
            n: 32,
            padding_len: 32,
            mode: XmssHashMode::Shake256,
            sk_seed: vec![0xAAu8; 32],
            pk_seed: vec![0xBBu8; 32],
        };
        let p = get_params(XmssParamId::Shake256_10_256);
        let single = vec![0x77u8; 32];
        let mut adrs = XmssAdrs::new();
        adrs.set_type(XmssAdrsType::LTree);
        let result = l_tree(&hasher, &single, &mut adrs, &p).unwrap();
        assert_eq!(result, single);
    }

    #[test]
    fn test_wots_sign_pk_from_sig_roundtrip() {
        let hasher = XmssHasher {
            n: 32,
            padding_len: 32,
            mode: XmssHashMode::Shake256,
            sk_seed: vec![0xAAu8; 32],
            pk_seed: vec![0xBBu8; 32],
        };
        let p = get_params(XmssParamId::Shake256_10_256);
        let msg = vec![0x42u8; 32];
        let ots_addr = 0;

        // Generate WOTS+ public key
        let mut adrs1 = XmssAdrs::new();
        let pk = wots_pk_gen(&hasher, ots_addr, &mut adrs1, &p).unwrap();
        assert_eq!(pk.len(), p.n);

        // Sign message
        let mut adrs2 = XmssAdrs::new();
        let sig = wots_sign(&hasher, &msg, ots_addr, &mut adrs2, &p).unwrap();
        assert_eq!(sig.len(), p.wots_len * p.n);

        // Recover public key from signature
        let mut adrs3 = XmssAdrs::new();
        let recovered = wots_pk_from_sig(&hasher, &sig, &msg, ots_addr, &mut adrs3, &p).unwrap();
        assert_eq!(pk, recovered);
    }
}
