//! Hash-DRBG (Hash-based Deterministic Random Bit Generator).
//!
//! Implements NIST SP 800-90A Section 10.1.1 using SHA-256, SHA-384, or SHA-512
//! as the underlying hash function.

use crate::provider::Digest;
use crate::sha2::{Sha256, Sha384, Sha512};
use hitls_types::CryptoError;
use zeroize::Zeroize;

/// Maximum number of generate requests before reseed is required.
const RESEED_INTERVAL: u64 = 1 << 48;

/// Hash algorithm selection for Hash-DRBG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashDrbgType {
    /// SHA-256 (seedLen=55, output=32).
    Sha256,
    /// SHA-384 (seedLen=111, output=48).
    Sha384,
    /// SHA-512 (seedLen=111, output=64).
    Sha512,
}

impl HashDrbgType {
    /// Seed length in bytes (SP 800-90A Table 2).
    fn seed_len(self) -> usize {
        match self {
            Self::Sha256 => 55,
            Self::Sha384 | Self::Sha512 => 111,
        }
    }

    /// Hash output size in bytes.
    fn output_size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Create a new hash context.
    fn new_hash(self) -> Box<dyn Digest> {
        match self {
            Self::Sha256 => Box::new(Sha256::new()),
            Self::Sha384 => Box::new(Sha384::new()),
            Self::Sha512 => Box::new(Sha512::new()),
        }
    }
}

/// Hash-DRBG context (NIST SP 800-90A Section 10.1.1).
pub struct HashDrbg {
    /// State value V (seedLen bytes).
    v: Vec<u8>,
    /// Constant C (seedLen bytes).
    c: Vec<u8>,
    /// Seed length in bytes.
    seed_len: usize,
    /// Hash algorithm type.
    hash_type: HashDrbgType,
    /// Number of generate requests since last (re)seed.
    reseed_counter: u64,
}

impl Drop for HashDrbg {
    fn drop(&mut self) {
        self.v.zeroize();
        self.c.zeroize();
    }
}

/// Compute Hash(data) using the given hash type.
fn hash(hash_type: HashDrbgType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut h = hash_type.new_hash();
    let out_size = hash_type.output_size();
    let mut out = vec![0u8; out_size];
    h.update(data)?;
    h.finish(&mut out)?;
    Ok(out)
}

/// Hash_df: Hash derivation function (SP 800-90A §10.3.1).
///
/// Derives `output_len` bytes from input using counter-mode hashing.
fn hash_df(
    hash_type: HashDrbgType,
    input: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hash_size = hash_type.output_size();
    let mut temp = Vec::with_capacity(output_len + hash_size);
    let mut counter: u8 = 1;

    // number_of_bits_to_return = output_len * 8
    let bits = (output_len as u32) * 8;

    while temp.len() < output_len {
        // Hash(counter || no_of_bits_to_return || input_string)
        let mut msg = Vec::with_capacity(1 + 4 + input.len());
        msg.push(counter);
        msg.extend_from_slice(&bits.to_be_bytes());
        msg.extend_from_slice(input);

        let digest = hash(hash_type, &msg)?;
        temp.extend_from_slice(&digest);
        counter = counter.wrapping_add(1);
    }

    temp.truncate(output_len);
    Ok(temp)
}

/// Big-endian modular addition: v = (v + addend) mod 2^(8*len).
/// Operates on byte arrays of the same length as `v`.
fn v_add(v: &mut [u8], addend: &[u8]) {
    let len = v.len();
    let alen = addend.len();
    let mut carry: u16 = 0;
    for i in (0..len).rev() {
        let a = if i >= len - alen {
            addend[i - (len - alen)] as u16
        } else {
            0
        };
        let sum = v[i] as u16 + a + carry;
        v[i] = sum as u8;
        carry = sum >> 8;
    }
}

/// Big-endian modular addition of a u64: v = (v + val) mod 2^(8*len).
fn v_add_u64(v: &mut [u8], val: u64) {
    let bytes = val.to_be_bytes();
    let len = v.len();
    let mut carry: u16 = 0;
    for i in (0..len).rev() {
        let offset = i as isize - (len as isize - 8);
        let a = if offset >= 0 {
            bytes[offset as usize] as u16
        } else {
            0
        };
        let sum = v[i] as u16 + a + carry;
        v[i] = sum as u8;
        carry = sum >> 8;
    }
}

impl HashDrbg {
    /// Instantiate a new Hash-DRBG (SP 800-90A §10.1.1.2).
    ///
    /// `seed_material` should contain entropy_input || nonce || personalization_string.
    pub fn new(hash_type: HashDrbgType, seed_material: &[u8]) -> Result<Self, CryptoError> {
        let seed_len = hash_type.seed_len();

        // V = Hash_df(seed_material, seedlen)
        let v = hash_df(hash_type, seed_material, seed_len)?;

        // C = Hash_df(0x00 || V, seedlen)
        let mut c_input = Vec::with_capacity(1 + seed_len);
        c_input.push(0x00);
        c_input.extend_from_slice(&v);
        let c = hash_df(hash_type, &c_input, seed_len)?;

        Ok(HashDrbg {
            v,
            c,
            seed_len,
            hash_type,
            reseed_counter: 1,
        })
    }

    /// Instantiate from the system entropy source (getrandom).
    pub fn from_system_entropy(hash_type: HashDrbgType) -> Result<Self, CryptoError> {
        let seed_len = hash_type.seed_len();
        let mut entropy = vec![0u8; seed_len];
        getrandom::getrandom(&mut entropy).map_err(|_| CryptoError::BnRandGenFail)?;
        let result = Self::new(hash_type, &entropy);
        entropy.zeroize();
        result
    }

    /// Hashgen: Generate pseudorandom bytes using the hash function (SP 800-90A §10.1.1.4).
    fn hashgen(&self, output_len: usize) -> Result<Vec<u8>, CryptoError> {
        let hash_size = self.hash_type.output_size();
        let mut data = self.v.clone();
        let mut result = Vec::with_capacity(output_len + hash_size);

        while result.len() < output_len {
            let digest = hash(self.hash_type, &data)?;
            result.extend_from_slice(&digest);

            // data = (data + 1) mod 2^seedlen
            v_add_u64(&mut data, 1);
        }

        data.zeroize();
        result.truncate(output_len);
        Ok(result)
    }

    /// Generate pseudorandom bytes (SP 800-90A §10.1.1.4).
    pub fn generate(
        &mut self,
        output: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        if self.reseed_counter > RESEED_INTERVAL {
            return Err(CryptoError::DrbgInvalidState);
        }

        // Step 2: If additional_input is provided
        if let Some(data) = additional_input {
            if !data.is_empty() {
                // w = Hash(0x02 || V || additional_input)
                let mut msg = Vec::with_capacity(1 + self.seed_len + data.len());
                msg.push(0x02);
                msg.extend_from_slice(&self.v);
                msg.extend_from_slice(data);
                let w = hash(self.hash_type, &msg)?;

                // V = (V + w) mod 2^seedlen
                v_add(&mut self.v, &w);
            }
        }

        // Step 3: Generate output using Hashgen
        let generated = self.hashgen(output.len())?;
        output.copy_from_slice(&generated);

        // Step 4: H = Hash(0x03 || V)
        let mut h_input = Vec::with_capacity(1 + self.seed_len);
        h_input.push(0x03);
        h_input.extend_from_slice(&self.v);
        let h = hash(self.hash_type, &h_input)?;

        // Step 5: V = (V + H + C + reseed_counter) mod 2^seedlen
        v_add(&mut self.v, &h);
        v_add(&mut self.v, &self.c);
        v_add_u64(&mut self.v, self.reseed_counter);

        self.reseed_counter += 1;

        Ok(())
    }

    /// Generate `len` pseudorandom bytes (convenience method).
    pub fn generate_bytes(&mut self, len: usize) -> Result<Vec<u8>, CryptoError> {
        let mut output = vec![0u8; len];
        self.generate(&mut output, None)?;
        Ok(output)
    }

    /// Reseed the DRBG with fresh entropy (SP 800-90A §10.1.1.3).
    pub fn reseed(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        // seed_material = 0x01 || V || entropy_input || additional_input
        let adin_len = additional_input.map_or(0, |d| d.len());
        let mut seed_material = Vec::with_capacity(1 + self.seed_len + entropy.len() + adin_len);
        seed_material.push(0x01);
        seed_material.extend_from_slice(&self.v);
        seed_material.extend_from_slice(entropy);
        if let Some(data) = additional_input {
            seed_material.extend_from_slice(data);
        }

        // V = Hash_df(seed_material, seedlen)
        self.v = hash_df(self.hash_type, &seed_material, self.seed_len)?;

        // C = Hash_df(0x00 || V, seedlen)
        let mut c_input = Vec::with_capacity(1 + self.seed_len);
        c_input.push(0x00);
        c_input.extend_from_slice(&self.v);
        self.c = hash_df(self.hash_type, &c_input, self.seed_len)?;

        seed_material.zeroize();
        self.reseed_counter = 1;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_drbg_sha256_instantiate() {
        let seed = b"test seed material with sufficient entropy for Hash-DRBG SHA-256";
        let drbg = HashDrbg::new(HashDrbgType::Sha256, seed).unwrap();
        assert_eq!(drbg.reseed_counter, 1);
        assert_eq!(drbg.v.len(), 55);
        assert_eq!(drbg.c.len(), 55);
    }

    #[test]
    fn test_hash_drbg_sha256_generate() {
        let seed = b"test seed material with sufficient entropy for Hash-DRBG SHA-256";
        let mut drbg = HashDrbg::new(HashDrbgType::Sha256, seed).unwrap();

        let output1 = drbg.generate_bytes(32).unwrap();
        let output2 = drbg.generate_bytes(32).unwrap();

        assert_eq!(output1.len(), 32);
        assert_eq!(output2.len(), 32);
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_hash_drbg_sha256_deterministic() {
        let seed = b"deterministic test seed for Hash-DRBG";

        let mut drbg1 = HashDrbg::new(HashDrbgType::Sha256, seed).unwrap();
        let out1 = drbg1.generate_bytes(64).unwrap();

        let mut drbg2 = HashDrbg::new(HashDrbgType::Sha256, seed).unwrap();
        let out2 = drbg2.generate_bytes(64).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_hash_drbg_sha256_reseed() {
        let seed = b"initial seed for Hash-DRBG reseed test";
        let mut drbg = HashDrbg::new(HashDrbgType::Sha256, seed).unwrap();

        let _ = drbg.generate_bytes(32).unwrap();
        assert_eq!(drbg.reseed_counter, 2);

        drbg.reseed(b"new entropy for reseed", None).unwrap();
        assert_eq!(drbg.reseed_counter, 1);
    }

    #[test]
    fn test_hash_drbg_sha256_additional_input() {
        let seed = b"seed for additional input test with Hash-DRBG";
        let mut drbg = HashDrbg::new(HashDrbgType::Sha256, seed).unwrap();

        let mut output = vec![0u8; 64];
        drbg.generate(&mut output, Some(b"additional input data"))
            .unwrap();

        assert_eq!(output.len(), 64);
        assert!(output.iter().any(|&b| b != 0));

        // Verify additional input changes output
        let mut drbg2 = HashDrbg::new(HashDrbgType::Sha256, seed).unwrap();
        let mut output2 = vec![0u8; 64];
        drbg2
            .generate(&mut output2, Some(b"different additional input"))
            .unwrap();
        assert_ne!(output, output2);
    }

    #[test]
    fn test_hash_drbg_sha512_generate() {
        let seed = b"test seed material with sufficient entropy for Hash-DRBG SHA-512";
        let mut drbg = HashDrbg::new(HashDrbgType::Sha512, seed).unwrap();

        assert_eq!(drbg.v.len(), 111);
        assert_eq!(drbg.c.len(), 111);

        let output = drbg.generate_bytes(64).unwrap();
        assert_eq!(output.len(), 64);
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hash_drbg_sha384_generate() {
        let seed = b"test seed material with sufficient entropy for Hash-DRBG SHA-384";
        let mut drbg = HashDrbg::new(HashDrbgType::Sha384, seed).unwrap();

        assert_eq!(drbg.v.len(), 111);

        let output = drbg.generate_bytes(48).unwrap();
        assert_eq!(output.len(), 48);
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hash_drbg_large_output() {
        let seed = b"seed for large output test with Hash-DRBG";
        let mut drbg = HashDrbg::new(HashDrbgType::Sha256, seed).unwrap();

        // Request more than one hash block
        let output = drbg.generate_bytes(200).unwrap();
        assert_eq!(output.len(), 200);
    }

    #[test]
    fn test_hash_df() {
        // Basic hash_df test
        let input = b"test input for hash derivation function";
        let output = hash_df(HashDrbgType::Sha256, input, 55).unwrap();
        assert_eq!(output.len(), 55);

        // Deterministic
        let output2 = hash_df(HashDrbgType::Sha256, input, 55).unwrap();
        assert_eq!(output, output2);

        // Different input → different output
        let output3 = hash_df(HashDrbgType::Sha256, b"different", 55).unwrap();
        assert_ne!(output, output3);
    }

    #[test]
    fn test_v_add() {
        // Simple addition
        let mut v = vec![0x00, 0x00, 0x00, 0x01];
        v_add(&mut v, &[0x00, 0x00, 0x00, 0x02]);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x03]);

        // Addition with carry
        let mut v = vec![0x00, 0x00, 0x00, 0xFF];
        v_add(&mut v, &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(v, vec![0x00, 0x00, 0x01, 0x00]);

        // Full overflow
        let mut v = vec![0xFF, 0xFF, 0xFF, 0xFF];
        v_add(&mut v, &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(v, vec![0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_v_add_u64() {
        let mut v = vec![0x00; 16];
        v_add_u64(&mut v, 256);
        assert_eq!(v[14], 0x01);
        assert_eq!(v[15], 0x00);
    }
}
