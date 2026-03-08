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

/// Maximum block size of any supported hash (SHA-512 = 128 bytes).
const MAX_BLOCK_SIZE: usize = 128;

/// Maximum output size of any supported hash (SHA-512 = 64 bytes).
const MAX_OUTPUT_SIZE: usize = 64;

/// HMAC context using a boxed Digest for the underlying hash.
///
/// # Examples
///
/// One-shot HMAC-SHA-256 computation:
///
/// ```
/// use hitls_crypto::hmac::Hmac;
/// use hitls_crypto::sha2::Sha256;
/// use hitls_crypto::provider::Digest;
///
/// let mac = Hmac::mac(
///     || Box::new(Sha256::new()) as Box<dyn Digest>,
///     b"secret key",
///     b"message",
/// ).unwrap();
/// assert_eq!(mac.len(), 32);
/// ```
///
/// Incremental HMAC computation:
///
/// ```
/// use hitls_crypto::hmac::Hmac;
/// use hitls_crypto::sha2::Sha256;
/// use hitls_crypto::provider::Digest;
///
/// let mut ctx = Hmac::new(
///     || Box::new(Sha256::new()) as Box<dyn Digest>,
///     b"secret key",
/// ).unwrap();
/// ctx.update(b"message").unwrap();
/// let mut out = vec![0u8; 32];
/// ctx.finish(&mut out).unwrap();
/// assert_eq!(out.len(), 32);
/// ```
pub struct Hmac {
    /// Inner hash context (initialized with ipad-xored key).
    inner: Box<dyn Digest>,
    /// Outer hash context (initialized with opad-xored key).
    outer: Box<dyn Digest>,
    /// Processed key block (for reset), stored as fixed-size stack array.
    key_block: [u8; MAX_BLOCK_SIZE],
    /// Actual block size of the hash.
    block_size: usize,
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
        let mut key_block = [0u8; MAX_BLOCK_SIZE];
        if key.len() > block_size {
            let mut hasher = hash_factory();
            hasher.update(key)?;
            let mut hashed_key = [0u8; MAX_OUTPUT_SIZE];
            hasher.finish(&mut hashed_key[..output_size])?;
            key_block[..output_size].copy_from_slice(&hashed_key[..output_size]);
            hashed_key.zeroize();
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        // Step 2: Create inner and outer hash contexts
        let mut inner = hash_factory();
        let mut outer = hash_factory();

        // inner key = key_block XOR ipad (stack array, no heap)
        let mut ipad_key = [0u8; MAX_BLOCK_SIZE];
        for (dst, &src) in ipad_key[..block_size]
            .iter_mut()
            .zip(&key_block[..block_size])
        {
            *dst = src ^ 0x36;
        }
        inner.update(&ipad_key[..block_size])?;
        ipad_key.zeroize();

        // outer key = key_block XOR opad (stack array, no heap)
        let mut opad_key = [0u8; MAX_BLOCK_SIZE];
        for (dst, &src) in opad_key[..block_size]
            .iter_mut()
            .zip(&key_block[..block_size])
        {
            *dst = src ^ 0x5c;
        }
        outer.update(&opad_key[..block_size])?;
        opad_key.zeroize();

        Ok(Self {
            inner,
            outer,
            key_block,
            block_size,
        })
    }

    /// Feed data into the HMAC computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.inner.update(data)
    }

    /// Finalize the HMAC computation and write the result to `out`.
    pub fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let output_size = self.inner.output_size();
        let mut inner_hash = [0u8; MAX_OUTPUT_SIZE];
        self.inner.finish(&mut inner_hash[..output_size])?;

        self.outer.update(&inner_hash[..output_size])?;
        inner_hash.zeroize();

        self.outer.finish(out)
    }

    /// Reset the HMAC state for reuse with the same key.
    /// Uses `Digest::reset()` to avoid `Box<dyn Digest>` re-allocation.
    pub fn reset(&mut self) -> Result<(), CryptoError> {
        let bs = self.block_size;

        self.inner.reset();
        self.outer.reset();

        // Re-feed ipad/opad keys using stack arrays (zero heap allocation)
        let mut ipad_key = [0u8; MAX_BLOCK_SIZE];
        for (dst, &src) in ipad_key[..bs].iter_mut().zip(&self.key_block[..bs]) {
            *dst = src ^ 0x36;
        }
        self.inner.update(&ipad_key[..bs])?;
        ipad_key.zeroize();

        let mut opad_key = [0u8; MAX_BLOCK_SIZE];
        for (dst, &src) in opad_key[..bs].iter_mut().zip(&self.key_block[..bs]) {
            *dst = src ^ 0x5c;
        }
        self.outer.update(&opad_key[..bs])?;
        opad_key.zeroize();

        Ok(())
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
        // block_size is not secret, no need to zeroize
    }
}

#[cfg(all(test, feature = "sha2"))]
mod tests {
    use super::*;
    use crate::sha2::Sha256;
    use hitls_utils::hex::to_hex;

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
        assert_eq!(to_hex(&result), expected);
    }

    // RFC 4231 Test Case 2
    #[test]
    fn test_hmac_sha256_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

        let result = Hmac::mac(sha256_factory, key, data).unwrap();
        assert_eq!(to_hex(&result), expected);
    }

    // RFC 4231 Test Case 3
    #[test]
    fn test_hmac_sha256_case3() {
        let key = [0xaa; 20];
        let data = [0xdd; 50];
        let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

        let result = Hmac::mac(sha256_factory, &key, &data).unwrap();
        assert_eq!(to_hex(&result), expected);
    }

    // RFC 4231 Test Case 4
    #[test]
    fn test_hmac_sha256_case4() {
        let key: Vec<u8> = (0x01..=0x19).collect();
        let data = [0xcd; 50];
        let expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";

        let result = Hmac::mac(sha256_factory, &key, &data).unwrap();
        assert_eq!(to_hex(&result), expected);
    }

    // RFC 4231 Test Case 6 (key longer than block size)
    #[test]
    fn test_hmac_sha256_case6() {
        let key = [0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";

        let result = Hmac::mac(sha256_factory, &key, data).unwrap();
        assert_eq!(to_hex(&result), expected);
    }

    // RFC 4231 Test Case 7 (key and data longer than block size)
    #[test]
    fn test_hmac_sha256_case7() {
        let key = [0xaa; 131];
        let data =
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";

        let result = Hmac::mac(sha256_factory, &key, data).unwrap();
        assert_eq!(to_hex(&result), expected);
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
        assert_eq!(to_hex(&out1), expected);

        // Reset and compute again
        ctx.reset().unwrap();
        ctx.update(data).unwrap();
        let mut out2 = vec![0u8; 32];
        ctx.finish(&mut out2).unwrap();
        assert_eq!(to_hex(&out2), expected);
    }

    #[cfg(feature = "sha1")]
    fn sha1_factory() -> Box<dyn Digest> {
        Box::new(crate::sha1::Sha1::new())
    }

    fn sha384_factory() -> Box<dyn Digest> {
        Box::new(crate::sha2::Sha384::new())
    }

    fn sha512_factory() -> Box<dyn Digest> {
        Box::new(crate::sha2::Sha512::new())
    }

    // RFC 2202 Case 1: HMAC-SHA1
    #[cfg(feature = "sha1")]
    #[test]
    fn test_hmac_sha1_rfc2202_case1() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected = "b617318655057264e28bc0b6fb378c8ef146be00";

        let result = Hmac::mac(sha1_factory, &key, data).unwrap();
        assert_eq!(to_hex(&result), expected);
    }

    // RFC 2202 Case 2: HMAC-SHA1
    #[cfg(feature = "sha1")]
    #[test]
    fn test_hmac_sha1_rfc2202_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79";

        let result = Hmac::mac(sha1_factory, key, data).unwrap();
        assert_eq!(to_hex(&result), expected);
    }

    // RFC 4231 Case 1: HMAC-SHA384
    #[test]
    fn test_hmac_sha384_rfc4231_case1() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected = "afd03944d84895626b0825f4ab46907f\
                        15f9dadbe4101ec682aa034c7cebc59c\
                        faea9ea9076ede7f4af152e8b2fa9cb6";

        let result = Hmac::mac(sha384_factory, &key, data).unwrap();
        assert_eq!(to_hex(&result), expected);
    }

    // RFC 4231 Case 1: HMAC-SHA512
    #[test]
    fn test_hmac_sha512_rfc4231_case1() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected = "87aa7cdea5ef619d4ff0b4241a1d6cb0\
                        2379f4e2ce4ec2787ad0b30545e17cde\
                        daa833b7d6b8a702038b274eaea3f4e4\
                        be9d914eeb61f1702e696c203a126854";

        let result = Hmac::mac(sha512_factory, &key, data).unwrap();
        assert_eq!(to_hex(&result), expected);
    }

    // HMAC-SHA256 with empty message
    #[test]
    fn test_hmac_empty_message() {
        let key = [0x0b; 20];
        let result1 = Hmac::mac(sha256_factory, &key, b"").unwrap();
        let result2 = Hmac::mac(sha256_factory, &key, b"").unwrap();
        // Output should be non-empty and deterministic
        assert_eq!(result1.len(), 32);
        assert_eq!(result1, result2);
    }

    mod proptests {
        use super::super::Hmac;
        use super::{sha256_factory, sha384_factory, sha512_factory};
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn prop_hmac_sha256_determinism(
                key in proptest::collection::vec(any::<u8>(), 1..64),
                data in proptest::collection::vec(any::<u8>(), 0..256),
            ) {
                let r1 = Hmac::mac(sha256_factory, &key, &data).unwrap();
                let r2 = Hmac::mac(sha256_factory, &key, &data).unwrap();
                prop_assert_eq!(r1, r2);
            }

            /// HMAC-SHA-384 determinism.
            #[test]
            fn prop_hmac_sha384_determinism(
                key in proptest::collection::vec(any::<u8>(), 1..64),
                data in proptest::collection::vec(any::<u8>(), 0..256),
            ) {
                let r1 = Hmac::mac(sha384_factory, &key, &data).unwrap();
                let r2 = Hmac::mac(sha384_factory, &key, &data).unwrap();
                prop_assert_eq!(r1, r2);
            }

            /// HMAC-SHA-512 determinism.
            #[test]
            fn prop_hmac_sha512_determinism(
                key in proptest::collection::vec(any::<u8>(), 1..64),
                data in proptest::collection::vec(any::<u8>(), 0..256),
            ) {
                let r1 = Hmac::mac(sha512_factory, &key, &data).unwrap();
                let r2 = Hmac::mac(sha512_factory, &key, &data).unwrap();
                prop_assert_eq!(r1, r2);
            }
        }
    }
}
