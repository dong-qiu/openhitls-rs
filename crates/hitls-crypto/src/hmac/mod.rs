//! HMAC (Hash-based Message Authentication Code) implementation.
//!
//! HMAC provides message authentication using a cryptographic hash function
//! combined with a secret key, as defined in RFC 2104.
//!
//! HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
//!
//! where K' is the key padded/hashed to block size, ipad = 0x36, opad = 0x5c.

use crate::provider::Digest;
use hitls_types::CryptoError;
use zeroize::Zeroize;

/// HMAC context using a boxed Digest for the underlying hash.
pub struct Hmac {
    /// Inner hash context (initialized with ipad-xored key).
    inner: Box<dyn Digest>,
    /// Outer hash context (initialized with opad-xored key).
    outer: Box<dyn Digest>,
    /// Factory to create fresh digest instances (for reset).
    factory: Box<dyn Fn() -> Box<dyn Digest>>,
    /// Processed key block (for reset).
    key_block: Vec<u8>,
}

impl Hmac {
    /// Create a new HMAC instance with the given key and hash factory.
    ///
    /// The `hash_factory` closure creates fresh Digest instances.
    pub fn new(
        hash_factory: impl Fn() -> Box<dyn Digest> + 'static,
        key: &[u8],
    ) -> Result<Self, CryptoError> {
        let sample = hash_factory();
        let block_size = sample.block_size();
        let output_size = sample.output_size();
        drop(sample);

        // Step 1: If key > block_size, hash it; otherwise pad with zeros
        let mut key_block = vec![0u8; block_size];
        if key.len() > block_size {
            let mut hasher = hash_factory();
            hasher.update(key)?;
            let mut hashed_key = vec![0u8; output_size];
            hasher.finish(&mut hashed_key)?;
            key_block[..output_size].copy_from_slice(&hashed_key);
            hashed_key.zeroize();
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        // Step 2: Create inner and outer hash contexts
        let mut inner = hash_factory();
        let mut outer = hash_factory();

        // inner key = key_block XOR ipad
        let mut ipad_key = vec![0u8; block_size];
        for (i, byte) in ipad_key.iter_mut().enumerate() {
            *byte = key_block[i] ^ 0x36;
        }
        inner.update(&ipad_key)?;
        ipad_key.zeroize();

        // outer key = key_block XOR opad
        let mut opad_key = vec![0u8; block_size];
        for (i, byte) in opad_key.iter_mut().enumerate() {
            *byte = key_block[i] ^ 0x5c;
        }
        outer.update(&opad_key)?;
        opad_key.zeroize();

        Ok(Self {
            inner,
            outer,
            factory: Box::new(hash_factory),
            key_block,
        })
    }

    /// Feed data into the HMAC computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.inner.update(data)
    }

    /// Finalize the HMAC computation and write the result to `out`.
    pub fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let output_size = self.inner.output_size();
        let mut inner_hash = vec![0u8; output_size];
        self.inner.finish(&mut inner_hash)?;

        self.outer.update(&inner_hash)?;
        inner_hash.zeroize();

        self.outer.finish(out)
    }

    /// Reset the HMAC state for reuse with the same key.
    pub fn reset(&mut self) {
        let block_size = self.inner.block_size();

        self.inner = (self.factory)();
        self.outer = (self.factory)();

        let mut ipad_key = vec![0u8; block_size];
        for (i, byte) in ipad_key.iter_mut().enumerate() {
            *byte = self.key_block[i] ^ 0x36;
        }
        // Ignore errors in reset — update on fresh context should not fail
        let _ = self.inner.update(&ipad_key);
        ipad_key.zeroize();

        let mut opad_key = vec![0u8; block_size];
        for (i, byte) in opad_key.iter_mut().enumerate() {
            *byte = self.key_block[i] ^ 0x5c;
        }
        let _ = self.outer.update(&opad_key);
        opad_key.zeroize();
    }

    /// One-shot HMAC computation.
    pub fn mac(
        hash_factory: impl Fn() -> Box<dyn Digest> + 'static,
        key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut ctx = Self::new(hash_factory, key)?;
        ctx.update(data)?;
        let output_size = ctx.inner.output_size();
        let mut out = vec![0u8; output_size];
        ctx.finish(&mut out)?;
        Ok(out)
    }
}

impl Drop for Hmac {
    fn drop(&mut self) {
        self.key_block.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::Sha256;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn sha256_factory() -> Box<dyn Digest> {
        Box::new(Sha256::new())
    }

    // RFC 4231 Test Case 1
    #[test]
    fn test_hmac_sha256_case1() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

        let result = Hmac::mac(sha256_factory, &key, data).unwrap();
        assert_eq!(hex(&result), expected);
    }

    // RFC 4231 Test Case 2
    #[test]
    fn test_hmac_sha256_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

        let result = Hmac::mac(sha256_factory, key, data).unwrap();
        assert_eq!(hex(&result), expected);
    }

    // RFC 4231 Test Case 3
    #[test]
    fn test_hmac_sha256_case3() {
        let key = [0xaa; 20];
        let data = [0xdd; 50];
        let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

        let result = Hmac::mac(sha256_factory, &key, &data).unwrap();
        assert_eq!(hex(&result), expected);
    }

    // RFC 4231 Test Case 4
    #[test]
    fn test_hmac_sha256_case4() {
        let key: Vec<u8> = (0x01..=0x19).collect();
        let data = [0xcd; 50];
        let expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";

        let result = Hmac::mac(sha256_factory, &key, &data).unwrap();
        assert_eq!(hex(&result), expected);
    }

    // RFC 4231 Test Case 6 (key longer than block size)
    #[test]
    fn test_hmac_sha256_case6() {
        let key = [0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";

        let result = Hmac::mac(sha256_factory, &key, data).unwrap();
        assert_eq!(hex(&result), expected);
    }

    // RFC 4231 Test Case 7 (key and data longer than block size)
    #[test]
    fn test_hmac_sha256_case7() {
        let key = [0xaa; 131];
        let data =
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";

        let result = Hmac::mac(sha256_factory, &key, data).unwrap();
        assert_eq!(hex(&result), expected);
    }

    // Test reset functionality
    #[test]
    fn test_hmac_reset() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

        let mut ctx = Hmac::new(sha256_factory, key).unwrap();
        ctx.update(data).unwrap();
        let mut out1 = vec![0u8; 32];
        ctx.finish(&mut out1).unwrap();
        assert_eq!(hex(&out1), expected);

        // Reset and compute again
        ctx.reset();
        ctx.update(data).unwrap();
        let mut out2 = vec![0u8; 32];
        ctx.finish(&mut out2).unwrap();
        assert_eq!(hex(&out2), expected);
    }
}
