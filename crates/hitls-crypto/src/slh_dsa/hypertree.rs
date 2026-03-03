//! SLH-DSA hypertree implementation (FIPS 205 Section 7).
//!
//! The hypertree is a multi-layer structure of d XMSS trees.
//! Each layer signs the root of the layer below it.

use hitls_types::CryptoError;

use super::address::{Adrs, AdrsType};
use super::hash::SlhHashFunctions;
use super::params::SlhDsaParams;
use super::wots;

/// Compute an XMSS tree node recursively and optionally collect the authentication path.
///
/// - `idx`: node index at current height (0-based)
/// - `height`: current height (0 = leaf)
/// - `auth_path`: if Some, collect siblings of the path to `leaf_idx`
/// - `leaf_idx`: leaf whose auth path we collect
#[allow(clippy::too_many_arguments)]
fn xmss_node(
    h: &dyn SlhHashFunctions,
    sk_seed: &[u8],
    idx: u32,
    height: u32,
    adrs: &mut Adrs,
    p: &SlhDsaParams,
    auth_path: Option<&mut Vec<u8>>,
    leaf_idx: u32,
) -> Result<Vec<u8>, CryptoError> {
    let n = h.n();
    let hp = p.hp as u32;

    if height == 0 {
        // Leaf node: WOTS+ public key
        let mut wots_adrs = adrs.clone();
        wots_adrs.set_type(AdrsType::WotsHash);
        wots_adrs.set_key_pair_addr(idx);
        let pk = wots::wots_pk_gen(h, sk_seed, &mut wots_adrs, p)?;

        // Check if this is a sibling on the auth path
        if let Some(ap) = auth_path {
            let sibling = (leaf_idx >> height) ^ 1;
            if idx == sibling {
                ap.extend_from_slice(&pk);
            }
        }

        return Ok(pk);
    }

    // Internal node: hash left || right children
    // We need to pass auth_path through both children
    let left = xmss_node(h, sk_seed, 2 * idx, height - 1, adrs, p, None, leaf_idx)?;

    // For auth path, we check the right child too
    let right = xmss_node(h, sk_seed, 2 * idx + 1, height - 1, adrs, p, None, leaf_idx)?;

    // SLH-DSA uses treeHeight = height (not height - 1 like XMSS)
    let mut tree_adrs = adrs.clone();
    tree_adrs.set_type(AdrsType::Tree);
    tree_adrs.set_tree_height(height);
    tree_adrs.set_tree_index(idx);

    let mut combined = left;
    combined.extend_from_slice(&right);
    let node = h.h(&tree_adrs, &combined)?;

    // Check if this is a sibling on the auth path (but not the root)
    if height < hp {
        if let Some(ap) = auth_path {
            let sibling = (leaf_idx >> height) ^ 1;
            if idx == sibling {
                ap.extend_from_slice(&node);
            }
        }
    }

    Ok(node)
}

/// Compute the full XMSS tree root and collect authentication path for `leaf_idx`.
///
/// Returns (root, auth_path) where auth_path has hp * n bytes.
pub(crate) fn xmss_compute_root_with_auth(
    h: &dyn SlhHashFunctions,
    sk_seed: &[u8],
    leaf_idx: u32,
    adrs: &mut Adrs,
    p: &SlhDsaParams,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Compute all leaves bottom-up into a flat buffer to avoid Vec<Vec<u8>>.
    let n = h.n();
    let hp = p.hp;
    let num_leaves = 1u32 << hp;

    // Flat buffer: nodes[i*n..(i+1)*n] = node i
    let mut nodes = vec![0u8; num_leaves as usize * n];
    for i in 0..num_leaves {
        let mut wots_adrs = adrs.clone();
        wots_adrs.set_type(AdrsType::WotsHash);
        wots_adrs.set_key_pair_addr(i);
        let pk = wots::wots_pk_gen(h, sk_seed, &mut wots_adrs, p)?;
        nodes[i as usize * n..(i as usize + 1) * n].copy_from_slice(&pk);
    }

    // Build tree bottom-up in-place, collecting auth path
    let mut auth_path = Vec::with_capacity(hp * n);
    let mut current_idx = leaf_idx;
    let mut current_count = num_leaves as usize;
    let mut combined = vec![0u8; 2 * n];

    for height in 0..hp as u32 {
        let sibling_idx = (current_idx ^ 1) as usize;
        auth_path.extend_from_slice(&nodes[sibling_idx * n..(sibling_idx + 1) * n]);

        let next_count = current_count / 2;
        for j in 0..next_count {
            let mut tree_adrs = adrs.clone();
            tree_adrs.set_type(AdrsType::Tree);
            tree_adrs.set_tree_height(height + 1);
            tree_adrs.set_tree_index(j as u32);

            combined[..n].copy_from_slice(&nodes[2 * j * n..(2 * j + 1) * n]);
            combined[n..2 * n].copy_from_slice(&nodes[(2 * j + 1) * n..(2 * j + 2) * n]);
            let parent = h.h(&tree_adrs, &combined)?;
            nodes[j * n..(j + 1) * n].copy_from_slice(&parent);
        }
        current_count = next_count;
        current_idx >>= 1;
    }

    Ok((nodes[..n].to_vec(), auth_path))
}

/// Compute just the XMSS tree root (no auth path needed).
pub(crate) fn xmss_compute_root(
    h: &dyn SlhHashFunctions,
    sk_seed: &[u8],
    adrs: &mut Adrs,
    p: &SlhDsaParams,
) -> Result<Vec<u8>, CryptoError> {
    let n = h.n();
    let hp = p.hp;
    let num_leaves = 1u32 << hp;

    // Flat buffer: nodes[i*n..(i+1)*n] = node i
    let mut nodes = vec![0u8; num_leaves as usize * n];
    for i in 0..num_leaves {
        let mut wots_adrs = adrs.clone();
        wots_adrs.set_type(AdrsType::WotsHash);
        wots_adrs.set_key_pair_addr(i);
        let pk = wots::wots_pk_gen(h, sk_seed, &mut wots_adrs, p)?;
        nodes[i as usize * n..(i as usize + 1) * n].copy_from_slice(&pk);
    }

    let mut current_count = num_leaves as usize;
    let mut combined = vec![0u8; 2 * n];

    for height in 0..hp as u32 {
        let next_count = current_count / 2;
        for j in 0..next_count {
            let mut tree_adrs = adrs.clone();
            tree_adrs.set_type(AdrsType::Tree);
            tree_adrs.set_tree_height(height + 1);
            tree_adrs.set_tree_index(j as u32);

            combined[..n].copy_from_slice(&nodes[2 * j * n..(2 * j + 1) * n]);
            combined[n..2 * n].copy_from_slice(&nodes[(2 * j + 1) * n..(2 * j + 2) * n]);
            let parent = h.h(&tree_adrs, &combined)?;
            nodes[j * n..(j + 1) * n].copy_from_slice(&parent);
        }
        current_count = next_count;
    }

    Ok(nodes[..n].to_vec())
}

/// Verify a tree path: given a leaf node and auth path, recompute the root.
fn xmss_root_from_sig(
    h: &dyn SlhHashFunctions,
    msg: &[u8],
    sig: &[u8],
    leaf_idx: u32,
    adrs: &mut Adrs,
    p: &SlhDsaParams,
) -> Result<Vec<u8>, CryptoError> {
    let n = h.n();
    let hp = p.hp;
    let wots_sig_len = p.wots_len * n;

    // Recover WOTS+ public key (leaf node)
    let wots_sig = &sig[..wots_sig_len];
    let mut wots_adrs = adrs.clone();
    wots_adrs.set_type(AdrsType::WotsHash);
    wots_adrs.set_key_pair_addr(leaf_idx);
    let mut node = wots::wots_pk_from_sig(h, wots_sig, msg, &mut wots_adrs, p)?;

    // Climb tree using auth path with pre-allocated combined buffer
    let auth = &sig[wots_sig_len..];
    let mut idx = leaf_idx;
    let mut combined = vec![0u8; 2 * n];

    for k in 0..hp {
        let mut tree_adrs = adrs.clone();
        tree_adrs.set_type(AdrsType::Tree);
        tree_adrs.set_tree_height((k + 1) as u32);
        tree_adrs.set_tree_index(idx >> 1);

        let sibling = &auth[k * n..(k + 1) * n];

        if (idx & 1) == 1 {
            combined[..n].copy_from_slice(sibling);
            combined[n..2 * n].copy_from_slice(&node);
        } else {
            combined[..n].copy_from_slice(&node);
            combined[n..2 * n].copy_from_slice(sibling);
        }
        node = h.h(&tree_adrs, &combined)?;
        idx >>= 1;
    }

    Ok(node)
}

/// Sign with the hypertree: d layers of XMSS tree signatures.
///
/// Returns signature of size d * (wots_len + hp) * n bytes.
pub(crate) fn hypertree_sign(
    h: &dyn SlhHashFunctions,
    sk_seed: &[u8],
    msg: &[u8],
    tree_idx: u64,
    leaf_idx: u32,
    adrs: &mut Adrs,
    p: &SlhDsaParams,
) -> Result<Vec<u8>, CryptoError> {
    let n = h.n();
    let d = p.d;
    let hp = p.hp;
    let layer_sig_len = (p.wots_len + hp) * n;

    let mut sig = Vec::with_capacity(d * layer_sig_len);
    let mut current_msg = msg.to_vec();
    let mut current_tree_idx = tree_idx;
    let mut current_leaf_idx = leaf_idx;

    for layer in 0..d {
        adrs.set_layer_addr(layer as u32);
        adrs.set_tree_addr(current_tree_idx);

        // WOTS+ signature
        let mut wots_adrs = adrs.clone();
        wots_adrs.set_type(AdrsType::WotsHash);
        wots_adrs.set_key_pair_addr(current_leaf_idx);
        let wots_sig = wots::wots_sign(h, &current_msg, sk_seed, &mut wots_adrs, p)?;
        sig.extend_from_slice(&wots_sig);

        // Compute tree root and auth path
        let (root, auth) = xmss_compute_root_with_auth(h, sk_seed, current_leaf_idx, adrs, p)?;
        sig.extend_from_slice(&auth);

        // Next layer: root becomes message, extract indices from tree_idx
        current_msg = root;
        if layer + 1 < d {
            current_leaf_idx = (current_tree_idx & ((1u64 << hp) - 1)) as u32;
            current_tree_idx >>= hp;
        }
    }

    Ok(sig)
}

/// Verify a hypertree signature. Returns true if valid.
#[allow(clippy::too_many_arguments)]
pub(crate) fn hypertree_verify(
    h: &dyn SlhHashFunctions,
    msg: &[u8],
    sig: &[u8],
    tree_idx: u64,
    leaf_idx: u32,
    pk_root: &[u8],
    adrs: &mut Adrs,
    p: &SlhDsaParams,
) -> Result<bool, CryptoError> {
    let n = h.n();
    let d = p.d;
    let hp = p.hp;
    let layer_sig_len = (p.wots_len + hp) * n;

    let mut node = msg.to_vec();
    let mut current_tree_idx = tree_idx;
    let mut current_leaf_idx = leaf_idx;

    for layer in 0..d {
        adrs.set_layer_addr(layer as u32);
        adrs.set_tree_addr(current_tree_idx);

        let layer_sig = &sig[layer * layer_sig_len..(layer + 1) * layer_sig_len];
        node = xmss_root_from_sig(h, &node, layer_sig, current_leaf_idx, adrs, p)?;

        if layer + 1 < d {
            current_leaf_idx = (current_tree_idx & ((1u64 << hp) - 1)) as u32;
            current_tree_idx >>= hp;
        }
    }

    // Compare computed root with expected root
    Ok(subtle::ConstantTimeEq::ct_eq(node.as_slice(), pk_root).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::address::Adrs;
    use crate::slh_dsa::hash::make_hasher;
    use crate::slh_dsa::params::get_params;
    use hitls_types::SlhDsaParamId;

    #[test]
    fn test_xmss_root_consistency() {
        let p = get_params(SlhDsaParamId::Shake128f);
        let pk_seed = vec![0xAAu8; p.n];
        let pk_root = vec![0xBBu8; p.n];
        let sk_seed = vec![0xCCu8; p.n];
        let h = make_hasher(p, &pk_seed, &pk_root);

        let mut adrs1 = Adrs::new(false);
        adrs1.set_layer_addr(0);
        adrs1.set_tree_addr(0);
        let root1 = xmss_compute_root(&*h, &sk_seed, &mut adrs1, p).unwrap();

        let mut adrs2 = Adrs::new(false);
        adrs2.set_layer_addr(0);
        adrs2.set_tree_addr(0);
        let (root2, auth_path) =
            xmss_compute_root_with_auth(&*h, &sk_seed, 0, &mut adrs2, p).unwrap();

        assert_eq!(root1, root2);
        // Auth path: hp * n bytes = 3 * 16 = 48 bytes
        assert_eq!(auth_path.len(), p.hp * p.n);
    }

    #[test]
    fn test_xmss_root_different_seeds_differ() {
        let p = get_params(SlhDsaParamId::Shake128f);
        let pk_seed = vec![0xAAu8; p.n];
        let pk_root = vec![0xBBu8; p.n];
        let h = make_hasher(p, &pk_seed, &pk_root);

        let sk_seed_a = vec![0x11u8; p.n];
        let sk_seed_b = vec![0x22u8; p.n];

        let mut adrs1 = Adrs::new(false);
        adrs1.set_layer_addr(0);
        adrs1.set_tree_addr(0);
        let root_a = xmss_compute_root(&*h, &sk_seed_a, &mut adrs1, p).unwrap();

        let mut adrs2 = Adrs::new(false);
        adrs2.set_layer_addr(0);
        adrs2.set_tree_addr(0);
        let root_b = xmss_compute_root(&*h, &sk_seed_b, &mut adrs2, p).unwrap();

        assert_ne!(root_a, root_b);
    }

    #[test]
    fn test_xmss_auth_path_different_leaves_same_root() {
        let p = get_params(SlhDsaParamId::Shake128f);
        let pk_seed = vec![0xAAu8; p.n];
        let pk_root = vec![0xBBu8; p.n];
        let sk_seed = vec![0xCCu8; p.n];
        let h = make_hasher(p, &pk_seed, &pk_root);

        let mut adrs0 = Adrs::new(false);
        adrs0.set_layer_addr(0);
        adrs0.set_tree_addr(0);
        let (root0, auth0) = xmss_compute_root_with_auth(&*h, &sk_seed, 0, &mut adrs0, p).unwrap();

        let mut adrs1 = Adrs::new(false);
        adrs1.set_layer_addr(0);
        adrs1.set_tree_addr(0);
        let (root1, auth1) = xmss_compute_root_with_auth(&*h, &sk_seed, 1, &mut adrs1, p).unwrap();

        // Same tree → same root
        assert_eq!(root0, root1);
        // Different leaf → different auth path
        assert_ne!(auth0, auth1);
    }

    #[test]
    fn test_xmss_root_from_sig_recovers_root() {
        let p = get_params(SlhDsaParamId::Shake128f);
        let pk_seed = vec![0xAAu8; p.n];
        let pk_root = vec![0xBBu8; p.n];
        let sk_seed = vec![0xCCu8; p.n];
        let h = make_hasher(p, &pk_seed, &pk_root);

        let leaf_idx = 2u32;
        let msg = vec![0x42u8; p.n];

        // Compute root and auth path
        let mut adrs = Adrs::new(false);
        adrs.set_layer_addr(0);
        adrs.set_tree_addr(0);
        let (root, auth) =
            xmss_compute_root_with_auth(&*h, &sk_seed, leaf_idx, &mut adrs, p).unwrap();

        // WOTS+ sign the message
        let mut sign_adrs = Adrs::new(false);
        sign_adrs.set_layer_addr(0);
        sign_adrs.set_tree_addr(0);
        sign_adrs.set_type(AdrsType::WotsHash);
        sign_adrs.set_key_pair_addr(leaf_idx);
        let wots_sig = wots::wots_sign(&*h, &msg, &sk_seed, &mut sign_adrs, p).unwrap();

        // Construct full sig = wots_sig || auth_path
        let mut full_sig = wots_sig;
        full_sig.extend_from_slice(&auth);

        // Recover root from sig
        let mut verify_adrs = Adrs::new(false);
        verify_adrs.set_layer_addr(0);
        verify_adrs.set_tree_addr(0);
        let recovered =
            xmss_root_from_sig(&*h, &msg, &full_sig, leaf_idx, &mut verify_adrs, p).unwrap();

        assert_eq!(recovered, root);
    }

    #[test]
    fn test_hypertree_sign_verify_roundtrip() {
        let p = get_params(SlhDsaParamId::Shake128f);
        let pk_seed = vec![0xAAu8; p.n];
        let pk_root_dummy = vec![0xBBu8; p.n];
        let sk_seed = vec![0xCCu8; p.n];
        let h = make_hasher(p, &pk_seed, &pk_root_dummy);

        let msg = vec![0x42u8; p.n];
        let tree_idx = 0u64;
        let leaf_idx = 3u32;

        // Compute the actual pk_root (top-layer XMSS root)
        let mut root_adrs = Adrs::new(false);
        root_adrs.set_layer_addr((p.d - 1) as u32);
        root_adrs.set_tree_addr(0);
        let pk_root = xmss_compute_root(&*h, &sk_seed, &mut root_adrs, p).unwrap();

        let h_real = make_hasher(p, &pk_seed, &pk_root);

        let mut sign_adrs = Adrs::new(false);
        let sig = hypertree_sign(
            &*h_real,
            &sk_seed,
            &msg,
            tree_idx,
            leaf_idx,
            &mut sign_adrs,
            p,
        )
        .unwrap();

        let expected_sig_len = p.d * (p.wots_len + p.hp) * p.n;
        assert_eq!(sig.len(), expected_sig_len);

        let mut verify_adrs = Adrs::new(false);
        let valid = hypertree_verify(
            &*h_real,
            &msg,
            &sig,
            tree_idx,
            leaf_idx,
            &pk_root,
            &mut verify_adrs,
            p,
        )
        .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_hypertree_verify_wrong_message_fails() {
        let p = get_params(SlhDsaParamId::Shake128f);
        let pk_seed = vec![0xAAu8; p.n];
        let pk_root_dummy = vec![0xBBu8; p.n];
        let sk_seed = vec![0xCCu8; p.n];
        let h = make_hasher(p, &pk_seed, &pk_root_dummy);

        let msg1 = vec![0x42u8; p.n];
        let msg2 = vec![0x99u8; p.n];
        let tree_idx = 0u64;
        let leaf_idx = 0u32;

        // Compute pk_root for top layer
        let mut root_adrs = Adrs::new(false);
        root_adrs.set_layer_addr((p.d - 1) as u32);
        root_adrs.set_tree_addr(0);
        let pk_root = xmss_compute_root(&*h, &sk_seed, &mut root_adrs, p).unwrap();

        let h_real = make_hasher(p, &pk_seed, &pk_root);

        // Sign msg1
        let mut sign_adrs = Adrs::new(false);
        let sig = hypertree_sign(
            &*h_real,
            &sk_seed,
            &msg1,
            tree_idx,
            leaf_idx,
            &mut sign_adrs,
            p,
        )
        .unwrap();

        // Verify with msg2 — should fail
        let mut verify_adrs = Adrs::new(false);
        let valid = hypertree_verify(
            &*h_real,
            &msg2,
            &sig,
            tree_idx,
            leaf_idx,
            &pk_root,
            &mut verify_adrs,
            p,
        )
        .unwrap();
        assert!(!valid);
    }
}
