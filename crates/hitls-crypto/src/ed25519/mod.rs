//! Ed25519 digital signature algorithm.
//!
//! Ed25519 is an EdDSA signature scheme using SHA-512 and Curve25519,
//! as defined in RFC 8032. It provides high-speed signing and verification
//! with 128-bit security.

use hitls_bignum::BigNum;
use hitls_types::CryptoError;
use zeroize::Zeroize;

use crate::curve25519::edwards::{
    point_add, points_equal_ct, scalar_mul, scalar_mul_base, GeExtended,
};
use crate::sha2::Sha512;

/// Ed25519 key size in bytes.
pub const ED25519_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// The group order L = 2^252 + 27742317777372353535851937790883648493.
/// In little-endian hex bytes.
const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// An Ed25519 key pair for signing and verification.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Ed25519KeyPair {
    /// The 32-byte private seed.
    private_key: [u8; ED25519_KEY_SIZE],
    /// The 32-byte public key.
    public_key: [u8; ED25519_KEY_SIZE],
}

impl Ed25519KeyPair {
    /// Generate a new random Ed25519 key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| CryptoError::BnRandGenFail)?;
        Self::from_seed(&seed)
    }

    /// Return a reference to the 32-byte private seed.
    pub fn seed(&self) -> &[u8; 32] {
        &self.private_key
    }

    /// Create an Ed25519 key pair from a 32-byte private seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        if seed.len() != 32 {
            return Err(CryptoError::InvalidArg("seed must be 32 bytes"));
        }

        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(seed);

        // Derive public key: hash seed, clamp, scalar_mul_base
        let h = sha512(&private_key)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        clamp(&mut a);

        let public_point = scalar_mul_base(&a);
        let public_key = public_point.to_bytes();

        Ok(Ed25519KeyPair {
            private_key,
            public_key,
        })
    }

    /// Create an Ed25519 verifier from a 32-byte public key (verify-only).
    pub fn from_public_key(public_key: &[u8]) -> Result<Self, CryptoError> {
        if public_key.len() != 32 {
            return Err(CryptoError::InvalidArg("public key must be 32 bytes"));
        }

        // Validate the public key can be decoded as a point
        let mut pk = [0u8; 32];
        pk.copy_from_slice(public_key);
        GeExtended::from_bytes(&pk)?;

        Ok(Ed25519KeyPair {
            private_key: [0u8; 32],
            public_key: pk,
        })
    }

    /// Sign a message, returning the 64-byte signature.
    ///
    /// Implements RFC 8032 §5.1.6.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; ED25519_SIGNATURE_SIZE], CryptoError> {
        if self.private_key == [0u8; 32] {
            return Err(CryptoError::EccInvalidPrivateKey);
        }

        // Step 1: h = SHA-512(seed); a = clamp(h[0..32]); prefix = h[32..64]
        let h = sha512(&self.private_key)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        clamp(&mut a);
        let prefix = &h[32..64];

        // Step 2: r = SHA-512(prefix || message) mod L
        let mut hasher = Sha512::new();
        hasher
            .update(prefix)
            .map_err(|_| CryptoError::InvalidArg(""))?;
        hasher
            .update(message)
            .map_err(|_| CryptoError::InvalidArg(""))?;
        let r_hash = hasher.finish().map_err(|_| CryptoError::InvalidArg(""))?;
        let r_scalar = reduce_scalar_wide(&r_hash)?;

        // Step 3: R = r * B
        let r_point = scalar_mul_base(&r_scalar);
        let r_bytes = r_point.to_bytes();

        // Step 4: k = SHA-512(R || public_key || message) mod L
        let mut hasher = Sha512::new();
        hasher
            .update(&r_bytes)
            .map_err(|_| CryptoError::InvalidArg(""))?;
        hasher
            .update(&self.public_key)
            .map_err(|_| CryptoError::InvalidArg(""))?;
        hasher
            .update(message)
            .map_err(|_| CryptoError::InvalidArg(""))?;
        let k_hash = hasher.finish().map_err(|_| CryptoError::InvalidArg(""))?;
        let k_scalar = reduce_scalar_wide(&k_hash)?;

        // Step 5: S = (r + k * a) mod L
        let s_scalar = scalar_muladd(&k_scalar, &a, &r_scalar)?;

        // Step 6: signature = R || S
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(&s_scalar);
        Ok(sig)
    }

    /// Verify a signature against a message.
    ///
    /// Implements RFC 8032 §5.1.7.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        if signature.len() != 64 {
            return Ok(false);
        }

        // Parse signature: R = sig[0..32], S = sig[32..64]
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&signature[..32]);
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&signature[32..]);

        // Check S < L
        if !scalar_is_canonical(&s_bytes) {
            return Ok(false);
        }

        // Decode R
        let Ok(r_point) = GeExtended::from_bytes(&r_bytes) else {
            return Ok(false);
        };

        // Decode public key A
        let Ok(a_point) = GeExtended::from_bytes(&self.public_key) else {
            return Ok(false);
        };

        // k = SHA-512(R || A || message) mod L
        let mut hasher = Sha512::new();
        hasher
            .update(&r_bytes)
            .map_err(|_| CryptoError::InvalidArg(""))?;
        hasher
            .update(&self.public_key)
            .map_err(|_| CryptoError::InvalidArg(""))?;
        hasher
            .update(message)
            .map_err(|_| CryptoError::InvalidArg(""))?;
        let k_hash = hasher.finish().map_err(|_| CryptoError::InvalidArg(""))?;
        let k_scalar = reduce_scalar_wide(&k_hash)?;

        // Verify: S*B == R + k*A
        let sb = scalar_mul_base(&s_bytes);
        let ka = scalar_mul(&k_scalar, &a_point);
        let rka = point_add(&r_point, &ka);

        Ok(points_equal_ct(&sb, &rka).into())
    }

    /// Return the 32-byte public key.
    pub fn public_key(&self) -> &[u8; ED25519_KEY_SIZE] {
        &self.public_key
    }
}

/// SHA-512 helper.
fn sha512(data: &[u8]) -> Result<[u8; 64], CryptoError> {
    let mut hasher = Sha512::new();
    hasher.update(data)?;
    hasher.finish()
}

/// Clamp a 32-byte scalar for Ed25519.
fn clamp(a: &mut [u8; 32]) {
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
}

/// Reduce a 64-byte (512-bit) hash to a 32-byte scalar mod L using BigNum.
fn reduce_scalar_wide(hash: &[u8; 64]) -> Result<[u8; 32], CryptoError> {
    // Convert from little-endian to BigNum (big-endian)
    let mut be_bytes = [0u8; 64];
    for i in 0..64 {
        be_bytes[63 - i] = hash[i];
    }
    let val = BigNum::from_bytes_be(&be_bytes);

    // L in big-endian
    let mut l_be = [0u8; 32];
    for i in 0..32 {
        l_be[31 - i] = L_BYTES[i];
    }
    let l = BigNum::from_bytes_be(&l_be);

    // val mod L
    let result = val.mod_reduce(&l)?;
    let result_be = result.to_bytes_be();

    // Convert back to little-endian 32 bytes
    let mut out = [0u8; 32];
    let len = result_be.len().min(32);
    for i in 0..len {
        out[i] = result_be[result_be.len() - 1 - i];
    }
    Ok(out)
}

/// Compute (a * b + c) mod L using BigNum. All inputs are 32-byte little-endian scalars.
fn scalar_muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    // Convert to big-endian
    let to_be = |le: &[u8; 32]| -> [u8; 32] {
        let mut be = [0u8; 32];
        for i in 0..32 {
            be[31 - i] = le[i];
        }
        be
    };

    let a_bn = BigNum::from_bytes_be(&to_be(a));
    let b_bn = BigNum::from_bytes_be(&to_be(b));
    let c_bn = BigNum::from_bytes_be(&to_be(c));

    let mut l_be = [0u8; 32];
    for i in 0..32 {
        l_be[31 - i] = L_BYTES[i];
    }
    let l = BigNum::from_bytes_be(&l_be);

    // (a * b + c) mod L
    let ab = a_bn.mul(&b_bn);
    let abc = ab.add(&c_bn);
    let result = abc.mod_reduce(&l)?;
    let result_be = result.to_bytes_be();

    // Convert back to LE 32 bytes
    let mut out = [0u8; 32];
    let len = result_be.len().min(32);
    for i in 0..len {
        out[i] = result_be[result_be.len() - 1 - i];
    }
    Ok(out)
}

/// Check if a scalar is canonical (< L).
fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    // Compare in little-endian: check s < L byte-by-byte from MSB
    for i in (0..32).rev() {
        if s[i] < L_BYTES[i] {
            return true;
        }
        if s[i] > L_BYTES[i] {
            return false;
        }
    }
    // s == L is not canonical
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    use hitls_utils::hex::hex;

    /// RFC 8032 §7.1 Test Vector 1: empty message.
    #[test]
    fn test_ed25519_rfc8032_test1() {
        let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_pub = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_sig = hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );

        let key = Ed25519KeyPair::from_seed(&seed).unwrap();
        assert_eq!(key.public_key().as_slice(), &expected_pub);

        let sig = key.sign(b"").unwrap();
        assert_eq!(sig.as_slice(), &expected_sig);

        let valid = key.verify(b"", &sig).unwrap();
        assert!(valid);
    }

    /// RFC 8032 §7.1 Test Vector 2: single byte 0x72.
    #[test]
    fn test_ed25519_rfc8032_test2() {
        let seed = hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let expected_pub = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let expected_sig = hex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );

        let key = Ed25519KeyPair::from_seed(&seed).unwrap();
        assert_eq!(key.public_key().as_slice(), &expected_pub);

        let sig = key.sign(&[0x72]).unwrap();
        assert_eq!(sig.as_slice(), &expected_sig);

        let valid = key.verify(&[0x72], &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        let key = Ed25519KeyPair::generate().unwrap();
        let msg = b"Hello, Ed25519!";
        let sig = key.sign(msg).unwrap();
        assert!(key.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_ed25519_tamper_detection() {
        let key = Ed25519KeyPair::generate().unwrap();
        let msg = b"original message";
        let sig = key.sign(msg).unwrap();
        assert!(!key.verify(b"tampered message", &sig).unwrap());
    }

    #[test]
    fn test_ed25519_verify_with_public_key_only() {
        let key = Ed25519KeyPair::generate().unwrap();
        let msg = b"verify with pubkey only";
        let sig = key.sign(msg).unwrap();

        let verifier = Ed25519KeyPair::from_public_key(key.public_key()).unwrap();
        assert!(verifier.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_ed25519_invalid_signature_rejected() {
        let key = Ed25519KeyPair::generate().unwrap();
        let msg = b"test message";
        let mut sig = key.sign(msg).unwrap();
        sig[0] ^= 0x01; // tamper with R
        assert!(!key.verify(msg, &sig).unwrap());
    }

    // RFC 8032 §7.1 Test Vector 3 (2-byte message)
    #[test]
    fn test_ed25519_rfc8032_test3() {
        let seed = hex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        let expected_pub = hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        let message = hex("af82");
        let expected_sig = hex(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        );

        let key = Ed25519KeyPair::from_seed(&seed).unwrap();
        assert_eq!(key.public_key(), &expected_pub[..]);

        let sig = key.sign(&message).unwrap();
        assert_eq!(sig.as_slice(), &expected_sig[..]);
        assert!(key.verify(&message, &sig).unwrap());
    }

    /// RFC 8032 §7.1 Test Vector 4: 1023-byte message.
    #[test]
    fn test_ed25519_rfc8032_test4() {
        let seed = hex("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
        let expected_pub = hex("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");
        // Verified against RFC 8032 text: 1023 bytes, signature matches
        let message = hex(
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98\
             fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8\
             79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d\
             658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc\
             1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe\
             ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e\
             06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef\
             efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7\
             aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1\
             85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2\
             d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24\
             554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270\
             88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc\
             2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07\
             07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba\
             b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a\
             ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e\
             c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb75\
             1fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c4\
             2f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8c\
             a61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff\
             7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d\
             78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649d\
             e6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e48\
             8acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32\
             ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6\
             aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb\
             93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50\
             d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef13\
             69546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db\
             2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0\
             618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
        );
        let expected_sig = hex(
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350\
             aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
        );

        let key = Ed25519KeyPair::from_seed(&seed).unwrap();
        assert_eq!(key.public_key(), &expected_pub[..]);

        let sig = key.sign(&message).unwrap();
        assert_eq!(sig.as_slice(), &expected_sig[..]);
        assert!(key.verify(&message, &sig).unwrap());
    }

    /// RFC 8032 §7.1 Test Vector 5: SHA(abc) message.
    #[test]
    fn test_ed25519_rfc8032_test5() {
        let seed = hex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
        let expected_pub = hex("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
        let message = hex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        );
        let expected_sig = hex(
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589\
             09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        );

        let key = Ed25519KeyPair::from_seed(&seed).unwrap();
        assert_eq!(key.public_key(), &expected_pub[..]);

        let sig = key.sign(&message).unwrap();
        assert_eq!(sig.as_slice(), &expected_sig[..]);
        assert!(key.verify(&message, &sig).unwrap());
    }

    #[test]
    fn test_ed25519_wrong_seed_length() {
        assert!(Ed25519KeyPair::from_seed(&[0u8; 31]).is_err());
        assert!(Ed25519KeyPair::from_seed(&[0u8; 33]).is_err());
    }

    #[test]
    fn test_ed25519_wrong_pubkey_length() {
        assert!(Ed25519KeyPair::from_public_key(&[0u8; 31]).is_err());
        assert!(Ed25519KeyPair::from_public_key(&[0u8; 33]).is_err());
    }

    mod proptests {
        use super::super::Ed25519KeyPair;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn prop_ed25519_sign_verify(
                seed in prop::array::uniform32(any::<u8>()),
                msg in proptest::collection::vec(any::<u8>(), 0..256),
            ) {
                let key = Ed25519KeyPair::from_seed(&seed).unwrap();
                let sig = key.sign(&msg).unwrap();
                prop_assert!(key.verify(&msg, &sig).unwrap());
            }
        }
    }
}
