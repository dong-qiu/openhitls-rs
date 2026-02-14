//! GMAC (Galois Message Authentication Code) implementation.
//!
//! GMAC is the authentication-only variant of GCM mode. It provides
//! message authentication using the GHASH universal hash function over
//! GF(2^128) combined with AES encryption.
//!
//! Reuses the GHASH infrastructure from the GCM module.

use crate::aes::{AesKey, AES_BLOCK_SIZE};
use crate::modes::gcm::{Gf128, GhashTable};
use hitls_types::CryptoError;

/// GMAC context.
pub struct Gmac {
    cipher: AesKey,
    table: GhashTable,
    ghash_state: Gf128,
    /// Encrypted J0 for final tag XOR.
    ek0: [u8; AES_BLOCK_SIZE],
    aad_len: u64,
    finalized: bool,
}

impl Gmac {
    /// Create a new GMAC instance with the given AES key and IV.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, CryptoError> {
        let cipher = AesKey::new(key)?;

        // H = E_K(0^128)
        let mut h_block = [0u8; AES_BLOCK_SIZE];
        cipher.encrypt_block(&mut h_block)?;
        let table = GhashTable::new(&h_block);

        // Compute J0
        let mut j0 = [0u8; AES_BLOCK_SIZE];
        if iv.len() == 12 {
            j0[..12].copy_from_slice(iv);
            j0[15] = 1;
        } else {
            let mut state = Gf128::default();
            table.ghash_data(&mut state, iv);
            let mut len_block = [0u8; 16];
            len_block[8..16].copy_from_slice(&((iv.len() as u64 * 8).to_be_bytes()));
            table.ghash_block(&mut state, &len_block);
            j0 = state.to_bytes();
        }

        // EK0 = E_K(J0)
        let mut ek0 = j0;
        cipher.encrypt_block(&mut ek0)?;

        Ok(Gmac {
            cipher,
            table,
            ghash_state: Gf128::default(),
            ek0,
            aad_len: 0,
            finalized: false,
        })
    }

    /// Feed authenticated data into the GMAC computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.finalized {
            return Err(CryptoError::InvalidArg);
        }
        self.table.ghash_data(&mut self.ghash_state, data);
        self.aad_len += data.len() as u64;
        Ok(())
    }

    /// Finalize the GMAC computation and write the 16-byte tag to `out`.
    pub fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 16 {
            return Err(CryptoError::InvalidArg);
        }

        // Length block: [len(AAD) in bits || 0 (no ciphertext)]
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(self.aad_len * 8).to_be_bytes());
        // len_block[8..16] = 0 (no ciphertext for GMAC)
        self.table.ghash_block(&mut self.ghash_state, &len_block);

        // Tag = GHASH ^ EK0
        let tag_bytes = self.ghash_state.to_bytes();
        for (i, (&t, &e)) in tag_bytes.iter().zip(self.ek0.iter()).enumerate() {
            out[i] = t ^ e;
        }

        self.finalized = true;
        Ok(())
    }

    /// Reset the GMAC state for a new computation with a new IV.
    pub fn reset(&mut self, iv: &[u8]) -> Result<(), CryptoError> {
        // Recompute J0 and EK0
        let mut j0 = [0u8; AES_BLOCK_SIZE];
        if iv.len() == 12 {
            j0[..12].copy_from_slice(iv);
            j0[15] = 1;
        } else {
            let mut state = Gf128::default();
            self.table.ghash_data(&mut state, iv);
            let mut len_block = [0u8; 16];
            len_block[8..16].copy_from_slice(&((iv.len() as u64 * 8).to_be_bytes()));
            self.table.ghash_block(&mut state, &len_block);
            j0 = state.to_bytes();
        }

        self.ek0 = j0;
        self.cipher.encrypt_block(&mut self.ek0)?;
        self.ghash_state = Gf128::default();
        self.aad_len = 0;
        self.finalized = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modes::gcm;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn test_gmac_vs_gcm_auth_only() {
        // GMAC should produce the same tag as GCM with empty plaintext
        let key = hex_to_bytes("00000000000000000000000000000000");
        let nonce = hex_to_bytes("000000000000000000000000");
        let aad = b"authenticated data for testing";

        // GCM with empty plaintext
        let gcm_result = gcm::gcm_encrypt(&key, &nonce, aad, &[]).unwrap();
        let gcm_tag = &gcm_result[..]; // should be just the 16-byte tag

        // GMAC
        let mut gmac = Gmac::new(&key, &nonce).unwrap();
        gmac.update(aad).unwrap();
        let mut gmac_tag = [0u8; 16];
        gmac.finish(&mut gmac_tag).unwrap();

        assert_eq!(hex(&gmac_tag), hex(gcm_tag));
    }

    #[test]
    fn test_gmac_empty_aad() {
        // GMAC with no AAD should match GCM with empty plaintext and empty AAD
        let key = hex_to_bytes("00000000000000000000000000000000");
        let nonce = hex_to_bytes("000000000000000000000000");

        let gcm_result = gcm::gcm_encrypt(&key, &nonce, &[], &[]).unwrap();

        let mut gmac = Gmac::new(&key, &nonce).unwrap();
        let mut tag = [0u8; 16];
        gmac.finish(&mut tag).unwrap();

        assert_eq!(hex(&tag), hex(&gcm_result));
    }

    #[test]
    fn test_gmac_reset() {
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let nonce1 = hex_to_bytes("cafebabefacedbaddecaf888");
        let aad = b"test data";

        let mut gmac = Gmac::new(&key, &nonce1).unwrap();
        gmac.update(aad).unwrap();
        let mut tag1 = [0u8; 16];
        gmac.finish(&mut tag1).unwrap();

        // Reset with same IV
        gmac.reset(&nonce1).unwrap();
        gmac.update(aad).unwrap();
        let mut tag2 = [0u8; 16];
        gmac.finish(&mut tag2).unwrap();

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_gmac_update_after_finalize() {
        let key = hex_to_bytes("00000000000000000000000000000000");
        let nonce = hex_to_bytes("000000000000000000000000");
        let mut gmac = Gmac::new(&key, &nonce).unwrap();
        gmac.update(b"data").unwrap();
        let mut tag = [0u8; 16];
        gmac.finish(&mut tag).unwrap();

        // update after finish should fail (finalized flag)
        assert!(gmac.update(b"more data").is_err());
    }

    #[test]
    fn test_gmac_finish_output_too_small() {
        let key = hex_to_bytes("00000000000000000000000000000000");
        let nonce = hex_to_bytes("000000000000000000000000");
        let mut gmac = Gmac::new(&key, &nonce).unwrap();
        let mut small_buf = [0u8; 8];
        assert!(gmac.finish(&mut small_buf).is_err());
    }
}
