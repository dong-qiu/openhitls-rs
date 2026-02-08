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
    // We need a different approach: compute all leaves, then build tree bottom-up
    // to correctly collect auth path nodes.
    let n = h.n();
    let hp = p.hp;
    let num_leaves = 1u32 << hp;

    // Compute all leaf nodes (WOTS+ public keys)
    let mut nodes: Vec<Vec<u8>> = Vec::with_capacity(num_leaves as usize);
    for i in 0..num_leaves {
        let mut wots_adrs = adrs.clone();
        wots_adrs.set_type(AdrsType::WotsHash);
        wots_adrs.set_key_pair_addr(i);
        let pk = wots::wots_pk_gen(h, sk_seed, &mut wots_adrs, p)?;
        nodes.push(pk);
    }

    // Build tree bottom-up, collecting auth path
    let mut auth_path = Vec::with_capacity(hp * n);
    let mut current_idx = leaf_idx;

    for height in 0..hp as u32 {
        // Sibling of current_idx at this height
        let sibling_idx = current_idx ^ 1;
        auth_path.extend_from_slice(&nodes[sibling_idx as usize]);

        // Build next level
        let num_nodes = nodes.len() / 2;
        let mut next_level = Vec::with_capacity(num_nodes);
        for j in 0..num_nodes {
            let mut tree_adrs = adrs.clone();
            tree_adrs.set_type(AdrsType::Tree);
            tree_adrs.set_tree_height(height + 1);
            tree_adrs.set_tree_index(j as u32);

            let mut combined = nodes[2 * j].clone();
            combined.extend_from_slice(&nodes[2 * j + 1]);
            let parent = h.h(&tree_adrs, &combined)?;
            next_level.push(parent);
        }
        nodes = next_level;
        current_idx >>= 1;
    }

    Ok((nodes[0].clone(), auth_path))
}

/// Compute just the XMSS tree root (no auth path needed).
pub(crate) fn xmss_compute_root(
    h: &dyn SlhHashFunctions,
    sk_seed: &[u8],
    adrs: &mut Adrs,
    p: &SlhDsaParams,
) -> Result<Vec<u8>, CryptoError> {
    let hp = p.hp;
    let num_leaves = 1u32 << hp;

    let mut nodes: Vec<Vec<u8>> = Vec::with_capacity(num_leaves as usize);
    for i in 0..num_leaves {
        let mut wots_adrs = adrs.clone();
        wots_adrs.set_type(AdrsType::WotsHash);
        wots_adrs.set_key_pair_addr(i);
        let pk = wots::wots_pk_gen(h, sk_seed, &mut wots_adrs, p)?;
        nodes.push(pk);
    }

    for height in 0..hp as u32 {
        let num_nodes = nodes.len() / 2;
        let mut next_level = Vec::with_capacity(num_nodes);
        for j in 0..num_nodes {
            let mut tree_adrs = adrs.clone();
            tree_adrs.set_type(AdrsType::Tree);
            tree_adrs.set_tree_height(height + 1);
            tree_adrs.set_tree_index(j as u32);

            let mut combined = nodes[2 * j].clone();
            combined.extend_from_slice(&nodes[2 * j + 1]);
            let parent = h.h(&tree_adrs, &combined)?;
            next_level.push(parent);
        }
        nodes = next_level;
    }

    Ok(nodes[0].clone())
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

    // Climb tree using auth path
    let auth = &sig[wots_sig_len..];
    let mut idx = leaf_idx;

    for k in 0..hp {
        let mut tree_adrs = adrs.clone();
        tree_adrs.set_type(AdrsType::Tree);
        tree_adrs.set_tree_height((k + 1) as u32);

        let sibling = &auth[k * n..(k + 1) * n];

        if (idx & 1) == 1 {
            // Right child
            tree_adrs.set_tree_index(idx >> 1);
            let mut combined = sibling.to_vec();
            combined.extend_from_slice(&node);
            node = h.h(&tree_adrs, &combined)?;
        } else {
            // Left child
            tree_adrs.set_tree_index(idx >> 1);
            let mut combined = node;
            combined.extend_from_slice(sibling);
            node = h.h(&tree_adrs, &combined)?;
        }
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
