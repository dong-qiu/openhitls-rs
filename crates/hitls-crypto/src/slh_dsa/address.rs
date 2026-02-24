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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adrs_new_all_zeros() {
        let uncomp = Adrs::new(false);
        assert_eq!(uncomp.as_bytes().len(), 32);
        assert!(uncomp.as_bytes().iter().all(|&b| b == 0));

        let comp = Adrs::new(true);
        assert_eq!(comp.as_bytes().len(), 22);
        assert!(comp.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_all_adrs_types() {
        let types = [
            (AdrsType::WotsHash, 0u32),
            (AdrsType::WotsPk, 1),
            (AdrsType::Tree, 2),
            (AdrsType::ForsTree, 3),
            (AdrsType::ForsRoots, 4),
            (AdrsType::WotsPrf, 5),
            (AdrsType::ForsPrf, 6),
        ];
        for (ty, expected_val) in &types {
            // Uncompressed: type at [16:20]
            let mut a = Adrs::new(false);
            a.set_type(*ty);
            assert_eq!(
                &a.as_bytes()[16..20],
                &expected_val.to_be_bytes(),
                "uncompressed type mismatch for {expected_val}"
            );

            // Compressed: type at [9]
            let mut c = Adrs::new(true);
            c.set_type(*ty);
            assert_eq!(c.as_bytes()[9], *expected_val as u8);
        }
    }

    #[test]
    fn test_adrs_clone_independence() {
        let mut orig = Adrs::new(false);
        orig.set_layer_addr(10);
        orig.set_tree_addr(200);
        orig.set_type(AdrsType::WotsHash);
        orig.set_key_pair_addr(5);

        let mut cloned = orig.clone();
        cloned.set_layer_addr(99);
        cloned.set_key_pair_addr(77);

        // Original unchanged
        assert_eq!(&orig.as_bytes()[0..4], &10u32.to_be_bytes());
        assert_eq!(&orig.as_bytes()[20..24], &5u32.to_be_bytes());
        // Clone modified
        assert_eq!(&cloned.as_bytes()[0..4], &99u32.to_be_bytes());
        assert_eq!(&cloned.as_bytes()[20..24], &77u32.to_be_bytes());
    }

    #[test]
    fn test_field_overlap_height_chain() {
        // set_tree_height and set_chain_addr write to the same offset (field2)
        let mut a1 = Adrs::new(false);
        a1.set_tree_height(42);
        let mut a2 = Adrs::new(false);
        a2.set_chain_addr(42);
        assert_eq!(&a1.as_bytes()[24..28], &a2.as_bytes()[24..28]);

        // Compressed mode
        let mut c1 = Adrs::new(true);
        c1.set_tree_height(42);
        let mut c2 = Adrs::new(true);
        c2.set_chain_addr(42);
        assert_eq!(&c1.as_bytes()[14..18], &c2.as_bytes()[14..18]);
    }

    #[test]
    fn test_hash_addr_tree_index_same_offset() {
        // set_hash_addr and set_tree_index write to the same offset (field3)
        let mut a1 = Adrs::new(false);
        a1.set_hash_addr(123);
        let mut a2 = Adrs::new(false);
        a2.set_tree_index(123);
        assert_eq!(&a1.as_bytes()[28..32], &a2.as_bytes()[28..32]);
        assert_eq!(a1.get_tree_index(), 123);
        assert_eq!(a2.get_tree_index(), 123);

        // Compressed
        let mut c1 = Adrs::new(true);
        c1.set_hash_addr(456);
        let mut c2 = Adrs::new(true);
        c2.set_tree_index(456);
        assert_eq!(&c1.as_bytes()[18..22], &c2.as_bytes()[18..22]);
    }

    #[test]
    fn test_adrs_uncompressed_set_get() {
        let mut adrs = Adrs::new(false);
        adrs.set_layer_addr(5);
        adrs.set_tree_addr(0x123456);
        adrs.set_type(AdrsType::WotsHash);
        adrs.set_key_pair_addr(7);
        adrs.set_chain_addr(3);
        adrs.set_tree_index(42);

        assert_eq!(adrs.as_bytes().len(), 32);
        assert_eq!(adrs.get_tree_index(), 42);

        let b = adrs.as_bytes();
        // Layer at [0:4] big-endian
        assert_eq!(&b[0..4], &5u32.to_be_bytes());
        // Tree address at [8:16] big-endian
        assert_eq!(&b[8..16], &0x123456u64.to_be_bytes());
        // Type at [16:20] = WotsHash = 0
        assert_eq!(&b[16..20], &0u32.to_be_bytes());
        // Keypair at [20:24]
        assert_eq!(&b[20..24], &7u32.to_be_bytes());
        // Chain at [24:28]
        assert_eq!(&b[24..28], &3u32.to_be_bytes());
        // TreeIndex at [28:32]
        assert_eq!(&b[28..32], &42u32.to_be_bytes());
    }

    #[test]
    fn test_adrs_compressed_set_get() {
        let mut adrs = Adrs::new(true);
        adrs.set_layer_addr(5);
        adrs.set_tree_addr(0x123456);
        adrs.set_type(AdrsType::WotsHash);
        adrs.set_key_pair_addr(7);
        adrs.set_chain_addr(3);
        adrs.set_tree_index(42);

        assert_eq!(adrs.as_bytes().len(), 22);
        assert_eq!(adrs.get_tree_index(), 42);

        let b = adrs.as_bytes();
        // Layer at [0]
        assert_eq!(b[0], 5);
        // Tree at [1:9]
        assert_eq!(&b[1..9], &0x123456u64.to_be_bytes());
        // Type at [9] = WotsHash = 0
        assert_eq!(b[9], 0);
        // Keypair at [10:14]
        assert_eq!(&b[10..14], &7u32.to_be_bytes());
        // Chain at [14:18]
        assert_eq!(&b[14..18], &3u32.to_be_bytes());
        // TreeIndex at [18:22]
        assert_eq!(&b[18..22], &42u32.to_be_bytes());
    }

    #[test]
    fn test_adrs_set_type_clears_trailing() {
        // Uncompressed mode
        let mut adrs = Adrs::new(false);
        adrs.set_type(AdrsType::WotsHash);
        adrs.set_key_pair_addr(99);
        adrs.set_chain_addr(55);
        adrs.set_hash_addr(77);

        // Verify fields are set
        let b = adrs.as_bytes();
        assert_eq!(&b[20..24], &99u32.to_be_bytes());
        assert_eq!(&b[24..28], &55u32.to_be_bytes());
        assert_eq!(&b[28..32], &77u32.to_be_bytes());

        // set_type should zero fields 1-3 (bytes [20:32])
        adrs.set_type(AdrsType::Tree);
        let b = adrs.as_bytes();
        assert_eq!(&b[20..32], &[0u8; 12]);

        // Compressed mode
        let mut adrs_c = Adrs::new(true);
        adrs_c.set_type(AdrsType::WotsHash);
        adrs_c.set_key_pair_addr(99);
        adrs_c.set_chain_addr(55);
        adrs_c.set_hash_addr(77);

        adrs_c.set_type(AdrsType::Tree);
        let b = adrs_c.as_bytes();
        assert_eq!(&b[10..22], &[0u8; 12]);
    }

    #[test]
    fn test_adrs_copy_key_pair_addr() {
        // Uncompressed
        let mut src = Adrs::new(false);
        src.set_type(AdrsType::WotsHash);
        src.set_key_pair_addr(99);

        let mut dst = Adrs::new(false);
        dst.set_type(AdrsType::WotsHash);
        dst.copy_key_pair_addr(&src);
        assert_eq!(&dst.as_bytes()[20..24], &99u32.to_be_bytes());

        // Compressed
        let mut src_c = Adrs::new(true);
        src_c.set_type(AdrsType::WotsHash);
        src_c.set_key_pair_addr(99);

        let mut dst_c = Adrs::new(true);
        dst_c.set_type(AdrsType::WotsHash);
        dst_c.copy_key_pair_addr(&src_c);
        assert_eq!(&dst_c.as_bytes()[10..14], &99u32.to_be_bytes());
    }
}
