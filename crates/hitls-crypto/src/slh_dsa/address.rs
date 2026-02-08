//! SLH-DSA address scheme (FIPS 205 Section 4.2).
//!
//! Two modes: uncompressed (32 bytes, SHAKE) and compressed (22 bytes, SHA-2).
//! Layout (uncompressed):
//!   [0:4]   layer address
//!   [4:16]  tree address (8 bytes at offset 8)
//!   [16:20] type
//!   [20:24] field1: keyPairAddr (WOTS/FORS) or padding (TREE)
//!   [24:28] field2: chainAddr (WOTS) / treeHeight (TREE/FORS)
//!   [28:32] field3: hashAddr (WOTS) / treeIndex (TREE/FORS)
//!
//! Layout (compressed, 22 bytes):
//!   [0]     layer address
//!   [1:9]   tree address (8 bytes)
//!   [9]     type
//!   [10:14] field1
//!   [14:18] field2
//!   [18:22] field3

#[derive(Clone, Copy)]
#[repr(u32)]
pub(crate) enum AdrsType {
    WotsHash = 0,
    WotsPk = 1,
    Tree = 2,
    ForsTree = 3,
    ForsRoots = 4,
    WotsPrf = 5,
    ForsPrf = 6,
}

#[derive(Clone)]
pub(crate) struct Adrs {
    bytes: [u8; 32],
    compressed: bool,
}

impl Adrs {
    pub fn new(compressed: bool) -> Self {
        Self {
            bytes: [0u8; 32],
            compressed,
        }
    }

    pub fn set_layer_addr(&mut self, layer: u32) {
        if self.compressed {
            self.bytes[0] = layer as u8;
        } else {
            self.bytes[0..4].copy_from_slice(&layer.to_be_bytes());
        }
    }

    pub fn set_tree_addr(&mut self, tree: u64) {
        if self.compressed {
            self.bytes[1..9].copy_from_slice(&tree.to_be_bytes());
        } else {
            // Write 8-byte tree address starting at offset 4 within treeAddr[12]
            self.bytes[8..16].copy_from_slice(&tree.to_be_bytes());
        }
    }

    pub fn set_type(&mut self, addr_type: AdrsType) {
        if self.compressed {
            self.bytes[9] = addr_type as u8;
            self.bytes[10..22].fill(0);
        } else {
            self.bytes[16..20].copy_from_slice(&(addr_type as u32).to_be_bytes());
            self.bytes[20..32].fill(0);
        }
    }

    pub fn set_key_pair_addr(&mut self, key_pair: u32) {
        let off = if self.compressed { 10 } else { 20 };
        self.bytes[off..off + 4].copy_from_slice(&key_pair.to_be_bytes());
    }

    pub fn set_chain_addr(&mut self, chain: u32) {
        let off = if self.compressed { 14 } else { 24 };
        self.bytes[off..off + 4].copy_from_slice(&chain.to_be_bytes());
    }

    pub fn set_tree_height(&mut self, height: u32) {
        // Same offset as chain_addr (field2)
        let off = if self.compressed { 14 } else { 24 };
        self.bytes[off..off + 4].copy_from_slice(&height.to_be_bytes());
    }

    pub fn set_hash_addr(&mut self, hash: u32) {
        let off = if self.compressed { 18 } else { 28 };
        self.bytes[off..off + 4].copy_from_slice(&hash.to_be_bytes());
    }

    pub fn set_tree_index(&mut self, index: u32) {
        // Same offset as hash_addr (field3)
        let off = if self.compressed { 18 } else { 28 };
        self.bytes[off..off + 4].copy_from_slice(&index.to_be_bytes());
    }

    pub fn get_tree_index(&self) -> u32 {
        let off = if self.compressed { 18 } else { 28 };
        u32::from_be_bytes([
            self.bytes[off],
            self.bytes[off + 1],
            self.bytes[off + 2],
            self.bytes[off + 3],
        ])
    }

    pub fn copy_key_pair_addr(&mut self, other: &Adrs) {
        let off = if self.compressed { 10 } else { 20 };
        self.bytes[off..off + 4].copy_from_slice(&other.bytes[off..off + 4]);
    }

    pub fn as_bytes(&self) -> &[u8] {
        if self.compressed {
            &self.bytes[..22]
        } else {
            &self.bytes[..32]
        }
    }
}
