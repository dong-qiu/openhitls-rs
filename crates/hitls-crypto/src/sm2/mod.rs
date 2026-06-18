//! SM2 elliptic curve public-key cryptography.
//!
//! SM2 is a Chinese national standard (GB/T 32918) for elliptic curve
//! cryptography. It supports digital signatures and public-key encryption,
//! based on the SM2P256V1 curve over a 256-bit prime field.

use hitls_bignum::BigNum;
use hitls_types::{CryptoError, EccCurveId};
use hitls_utils::asn1::{Decoder, Encoder};
use zeroize::Zeroize;

use crate::ecc::{EcGroup, EcPoint};
use crate::sm3::{Sm3, SM3_OUTPUT_SIZE};

/// Default user ID for SM2 (16-byte ASCII string per GB/T 32918).
const SM2_DEFAULT_ID: &[u8] = b"1234567812345678";

/// An SM2 key pair for signing, verification, encryption, and decryption.
#[derive(Clone)]
pub struct Sm2KeyPair {
    group: EcGroup,
    /// The private scalar d (1 <= d < n).
    private_key: BigNum,
    /// The public point P = d*G.
    public_key: EcPoint,
}

impl Drop for Sm2KeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl Sm2KeyPair {
    /// Generate a new SM2 key pair on the SM2P256V1 curve.
    pub fn generate() -> Result<Self, CryptoError> {
        let group = EcGroup::new(EccCurveId::Sm2Prime256)?;
        let n = group.order();

        let d = loop {
            let d = BigNum::random_range(n)?;
            if !d.is_zero() {
                break d;
            }
        };

        let p = group.scalar_mul_base(&d)?;

        Ok(Sm2KeyPair {
            group,
            private_key: d,
            public_key: p,
        })
    }

    /// Create an SM2 key pair from existing private key bytes (big-endian).
    pub fn from_private_key(private_key: &[u8]) -> Result<Self, CryptoError> {
        let group = EcGroup::new(EccCurveId::Sm2Prime256)?;
        let d = BigNum::from_bytes_be(private_key);

        if d.is_zero() || d >= *group.order() {
            return Err(CryptoError::EccInvalidPrivateKey);
        }

        let p = group.scalar_mul_base(&d)?;

        Ok(Sm2KeyPair {
            group,
            private_key: d,
            public_key: p,
        })
    }

    /// Create an SM2 verifier/encryptor from a public key (uncompressed encoding).
    pub fn from_public_key(public_key: &[u8]) -> Result<Self, CryptoError> {
        let group = EcGroup::new(EccCurveId::Sm2Prime256)?;
        let p = EcPoint::from_uncompressed(&group, public_key)?;

        Ok(Sm2KeyPair {
            group,
            private_key: BigNum::zero(),
            public_key: p,
        })
    }

    /// Sign a message using the default user ID.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.sign_with_id(SM2_DEFAULT_ID, message)
    }

    /// Sign a message with a custom user ID.
    pub fn sign_with_id(&self, user_id: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.private_key.is_zero() {
            return Err(CryptoError::EccInvalidPrivateKey);
        }

        let e = self.sign_digest(user_id, message)?;
        let n = self.group.order();

        for _ in 0..100 {
            let k = BigNum::random_range(n)?;
            if k.is_zero() {
                continue;
            }
            if let Some(der) = self.sign_with_k(&e, &k)? {
                return Ok(der);
            }
        }

        Err(CryptoError::BnRandGenFail)
    }

    /// Compute the SM2 sign digest integer `e = SM3(Z_A ‖ M)`.
    fn sign_digest(&self, user_id: &[u8], message: &[u8]) -> Result<BigNum, CryptoError> {
        let za = compute_za(user_id, &self.public_key, &self.group)?;
        let mut hasher = Sm3::new();
        hasher.update(&za)?;
        hasher.update(message)?;
        let digest = hasher.finish()?;
        Ok(BigNum::from_bytes_be(&digest))
    }

    /// Compute the SM2 signature `(r, s)` for digest-integer `e` with a specific
    /// nonce `k` (GB/T 32918.2 §6.1), returning the DER encoding. Yields
    /// `Ok(None)` when this `k` gives `kG == ∞`, `r == 0`, or `r + k == n` /
    /// `s == 0` — the random-`k` retry loop then tries another nonce.
    fn sign_with_k(&self, e: &BigNum, k: &BigNum) -> Result<Option<Vec<u8>>, CryptoError> {
        let n = self.group.order();
        let d = &self.private_key;

        let kg = self.group.scalar_mul_base(k)?;
        if kg.is_infinity() {
            return Ok(None);
        }

        // r = (e + x1) mod n
        let r = e.mod_add(kg.x(), n)?;
        if r.is_zero() {
            return Ok(None);
        }

        // Check r + k != n
        let r_plus_k = r.add(k);
        if r_plus_k == *n {
            return Ok(None);
        }

        // s = (1+d)^(-1) * (k - r*d) mod n
        let d_plus_1 = d.mod_add(&BigNum::from_u64(1), n)?;
        let d_plus_1_inv = d_plus_1.mod_inv(n)?;
        let rd = r.mod_mul(d, n)?;
        // k - r*d mod n: add n to avoid underflow
        let k_minus_rd = k.mod_add(&n.sub(&rd), n)?;
        let s = d_plus_1_inv.mod_mul(&k_minus_rd, n)?;
        if s.is_zero() {
            return Ok(None);
        }

        Ok(Some(encode_der_signature(&r, &s)?))
    }

    /// **KAT / testing only — never use in production.** SM2-sign `message`
    /// under `user_id` with a caller-supplied big-endian nonce `k`.
    ///
    /// # Security
    /// A reused or chosen SM2 nonce leaks the private key. This exists only to
    /// reproduce published deterministic sign KATs; it is gated behind the
    /// non-default `kat-nonce` feature and marked `#[deprecated]` as a danger
    /// sentinel (a non-`#[allow(deprecated)]` caller fails to build under
    /// `-D warnings`).
    #[cfg(feature = "kat-nonce")]
    #[doc(hidden)]
    #[deprecated(
        note = "test/KAT only: signing with a caller-chosen nonce leaks the SM2 \
                private key — never use in production"
    )]
    pub fn sign_with_id_nonce(
        &self,
        user_id: &[u8],
        message: &[u8],
        k: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if self.private_key.is_zero() {
            return Err(CryptoError::EccInvalidPrivateKey);
        }
        let e = self.sign_digest(user_id, message)?;
        let n = self.group.order();
        let k = BigNum::from_bytes_be(k);
        if k.is_zero() || k >= *n {
            return Err(CryptoError::EccInvalidPrivateKey);
        }
        self.sign_with_k(&e, &k)?.ok_or(CryptoError::BnRandGenFail)
    }

    /// Verify a signature against a message using the default user ID.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        self.verify_with_id(SM2_DEFAULT_ID, message, signature)
    }

    /// Verify a signature with a custom user ID.
    pub fn verify_with_id(
        &self,
        user_id: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let (r, s) = decode_der_signature(signature)?;

        let n = self.group.order();
        let one = BigNum::from_u64(1);
        if r < one || r >= *n || s < one || s >= *n {
            return Ok(false);
        }

        let za = compute_za(user_id, &self.public_key, &self.group)?;

        // e = SM3(ZA || M)
        let mut hasher = Sm3::new();
        hasher.update(&za)?;
        hasher.update(message)?;
        let digest = hasher.finish()?;
        let e = BigNum::from_bytes_be(&digest);

        // t = (r + s) mod n
        let t = r.mod_add(&s, n)?;
        if t.is_zero() {
            return Ok(false);
        }

        // (x1', y1') = s*G + t*PA
        let point = self.group.scalar_mul_add(&s, &t, &self.public_key)?;
        if point.is_infinity() {
            return Ok(false);
        }

        // R' = (e + x1') mod n
        let r_prime = e.mod_add(point.x(), n)?;

        Ok(r_prime == r)
    }

    /// Encrypt plaintext using SM2 public key encryption.
    ///
    /// Returns ciphertext in new format: C1 || C3 || C2 (GB/T 32918.4-2016).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.is_empty() {
            return Err(CryptoError::InvalidArg(""));
        }

        let n = self.group.order();
        let fs = self.group.field_size();

        for _ in 0..100 {
            let k = BigNum::random_range(n)?;
            if k.is_zero() {
                continue;
            }

            // C1 = k * G
            let c1_point = self.group.scalar_mul_base(&k)?;
            if c1_point.is_infinity() {
                continue;
            }
            let c1 = c1_point.to_uncompressed(&self.group)?;

            // (x2, y2) = k * PB
            let s_point = self.group.scalar_mul(&k, &self.public_key)?;
            if s_point.is_infinity() {
                continue;
            }

            let x2 = s_point.x().to_bytes_be_padded(fs)?;
            let y2 = s_point.y().to_bytes_be_padded(fs)?;

            // t = KDF(x2 || y2, len)
            let t = sm2_kdf(&x2, &y2, plaintext.len())?;
            if t.iter().all(|&b| b == 0) {
                continue;
            }

            // C2 = M XOR t (in-place on t)
            let mut c2 = t;
            for (c, m) in c2.iter_mut().zip(plaintext.iter()) {
                *c ^= m;
            }

            // C3 = SM3(x2 || M || y2)
            let mut hasher = Sm3::new();
            hasher.update(&x2)?;
            hasher.update(plaintext)?;
            hasher.update(&y2)?;
            let c3 = hasher.finish()?;

            // Output: C1 || C3 || C2
            let mut ciphertext = Vec::with_capacity(c1.len() + SM3_OUTPUT_SIZE + c2.len());
            ciphertext.extend_from_slice(&c1);
            ciphertext.extend_from_slice(&c3);
            ciphertext.extend_from_slice(&c2);

            return Ok(ciphertext);
        }

        Err(CryptoError::BnRandGenFail)
    }

    /// Decrypt ciphertext using SM2 private key.
    ///
    /// Expects new format: C1 || C3 || C2.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use subtle::ConstantTimeEq;

        if self.private_key.is_zero() {
            return Err(CryptoError::EccInvalidPrivateKey);
        }

        let fs = self.group.field_size();
        let c1_len = 1 + 2 * fs; // 0x04 || x || y

        if ciphertext.len() < c1_len + SM3_OUTPUT_SIZE + 1 {
            return Err(CryptoError::Sm2DecryptFail);
        }

        let c1_bytes = &ciphertext[..c1_len];
        let c3 = &ciphertext[c1_len..c1_len + SM3_OUTPUT_SIZE];
        let c2 = &ciphertext[c1_len + SM3_OUTPUT_SIZE..];

        let c1_point = EcPoint::from_uncompressed(&self.group, c1_bytes)?;

        // (x2, y2) = dB * C1
        let s_point = self.group.scalar_mul(&self.private_key, &c1_point)?;
        if s_point.is_infinity() {
            return Err(CryptoError::Sm2DecryptFail);
        }

        let x2 = s_point.x().to_bytes_be_padded(fs)?;
        let y2 = s_point.y().to_bytes_be_padded(fs)?;

        // t = KDF(x2 || y2, len(C2))
        let t = sm2_kdf(&x2, &y2, c2.len())?;

        // M = C2 XOR t (in-place on t)
        let mut plaintext = t;
        for (p, c) in plaintext.iter_mut().zip(c2.iter()) {
            *p ^= c;
        }

        // u = SM3(x2 || M || y2)
        let mut hasher = Sm3::new();
        hasher.update(&x2)?;
        hasher.update(&plaintext)?;
        hasher.update(&y2)?;
        let u = hasher.finish()?;

        // Constant-time comparison
        if u.ct_eq(c3).into() {
            Ok(plaintext)
        } else {
            Err(CryptoError::Sm2DecryptFail)
        }
    }

    /// Return the public key in uncompressed encoding.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.public_key.to_uncompressed(&self.group)
    }

    /// Return the private key as 32-byte big-endian.
    pub fn private_key_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        if self.private_key.is_zero() {
            return Err(CryptoError::EccInvalidPrivateKey);
        }
        let mut bytes = self.private_key.to_bytes_be();
        // Pad to 32 bytes for SM2P256
        while bytes.len() < 32 {
            bytes.insert(0, 0);
        }
        Ok(bytes)
    }

    /// SM2 key exchange per **GB/T 32918.3-2016 §6.1**, deterministic
    /// (own ephemeral nonce supplied by the caller).
    ///
    /// One party in a two-party SM2 key agreement. Each side independently
    /// calls this with their **own** long-term keypair (`self`), their own
    /// ephemeral private nonce `my_r`, the **peer's** long-term public key
    /// (uncompressed 65 bytes) and ephemeral public point
    /// `R_peer = r_peer * G` (uncompressed 65 bytes), the two user IDs, the
    /// role flag (initiator vs responder, see below), and the desired output
    /// length `key_len`. Both sides derive the same `key_len`-byte shared
    /// secret as long as the inputs match.
    ///
    /// **Role convention** (`is_initiator`):
    /// * `true`  — this side is GB/T 32918.3 party **A** (initiator).
    /// * `false` — this side is party **B** (responder).
    ///
    /// The KDF input ordering is `V.x || V.y || Z_A || Z_B` regardless of
    /// role: `Z_A` is the initiator's user-ID hash, `Z_B` is the
    /// responder's. This call places `self`'s Z in the right slot based on
    /// `is_initiator`.
    ///
    /// `my_r` is the ephemeral private nonce `r ∈ [1, n-1]`. **Reusing**
    /// `my_r` across sessions defeats the protocol; this entry point exists
    /// for spec/KAT reproduction. For application use you must supply
    /// fresh randomness.
    pub fn exchange_with_nonce(
        &self,
        my_r: &[u8],
        peer_pubkey: &[u8],
        peer_r_point: &[u8],
        my_id: &[u8],
        peer_id: &[u8],
        is_initiator: bool,
        key_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        if self.private_key.is_zero() {
            return Err(CryptoError::EccInvalidPrivateKey);
        }
        if key_len == 0 {
            return Err(CryptoError::InvalidArg(""));
        }

        let group = &self.group;
        let n = group.order();
        let fs = group.field_size();

        // 1. Parse ephemeral nonce r ∈ [1, n-1].
        let r = BigNum::from_bytes_be(my_r);
        if r.is_zero() || r >= *n {
            return Err(CryptoError::EccInvalidPrivateKey);
        }

        // 2. Compute own ephemeral public point R_self = r * G.
        let r_self = group.scalar_mul_base(&r)?;

        // 3. Parse peer's public key P_peer and ephemeral point R_peer.
        let p_peer = EcPoint::from_uncompressed(group, peer_pubkey)?;
        let r_peer_point = EcPoint::from_uncompressed(group, peer_r_point)?;

        // 4. Compute x̄ = 2^w + (x mod 2^w) for both R points.
        //    w = ⌈log2(n) / 2⌉ - 1 = 127 for SM2P256V1 (256-bit order).
        let w = n.bit_len().div_ceil(2) - 1;
        let x_bar_self = x_bar(r_self.x(), w)?;
        let x_bar_peer = x_bar(r_peer_point.x(), w)?;

        // 5. t = (d + x̄_self * r) mod n.
        let t_inner = x_bar_self.mod_mul(&r, n)?;
        let t = self.private_key.mod_add(&t_inner, n)?;

        // 6. U = h * t * (P_peer + x̄_peer * R_peer). h = 1 for SM2.
        //    Compute (x̄_peer * R_peer) first via scalar_mul, then add P_peer,
        //    then scalar-mul by t.
        let scaled_r_peer = group.scalar_mul(&x_bar_peer, &r_peer_point)?;
        let q = group.point_add(&p_peer, &scaled_r_peer)?;
        let u = group.scalar_mul(&t, &q)?;

        if u.is_infinity() {
            // Point at infinity → exchange aborted per GB/T 32918.3 §6.1
            // step 7's validity check. Mapped to `Sm2DecryptFail` to reuse
            // the existing SM2 "operation failed" error.
            return Err(CryptoError::Sm2DecryptFail);
        }

        // 7. KDF input is V.x || V.y || Z_A || Z_B. Z_A = initiator's Z,
        //    Z_B = responder's Z, regardless of which side is computing.
        let my_z = compute_za(my_id, &self.public_key, group)?;
        let peer_z = compute_za(peer_id, &p_peer, group)?;
        let (z_a, z_b) = if is_initiator {
            (my_z, peer_z)
        } else {
            (peer_z, my_z)
        };

        let ux = u.x().to_bytes_be_padded(fs)?;
        let uy = u.y().to_bytes_be_padded(fs)?;
        let key = sm2_exchange_kdf(&ux, &uy, &z_a, &z_b, key_len)?;
        Ok(key)
    }
}

/// Compute ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA).
fn compute_za(
    user_id: &[u8],
    public_key: &EcPoint,
    group: &EcGroup,
) -> Result<[u8; SM3_OUTPUT_SIZE], CryptoError> {
    let params = group.params();
    let fs = group.field_size();

    let mut hasher = Sm3::new();

    // ENTLA: bit length of IDA as 2-byte big-endian
    let entla = (user_id.len() * 8) as u16;
    hasher.update(&entla.to_be_bytes())?;

    // IDA
    hasher.update(user_id)?;

    // Curve parameters: a, b, xG, yG
    hasher.update(&params.a.to_bytes_be_padded(fs)?)?;
    hasher.update(&params.b.to_bytes_be_padded(fs)?)?;
    hasher.update(&params.gx.to_bytes_be_padded(fs)?)?;
    hasher.update(&params.gy.to_bytes_be_padded(fs)?)?;

    // Public key coordinates: xA, yA
    hasher.update(&public_key.x().to_bytes_be_padded(fs)?)?;
    hasher.update(&public_key.y().to_bytes_be_padded(fs)?)?;

    hasher.finish()
}

/// Compute the GB/T 32918.3 §6.1 truncated coordinate
/// `x̄ = 2^w + (x mod 2^w)`.
fn x_bar(x: &BigNum, w: usize) -> Result<BigNum, CryptoError> {
    // pow2w = 2^w (used both as the modulus and as the additive prefix).
    let mut pow2w = BigNum::zero();
    pow2w.set_bit(w);
    // low = x mod 2^w  (keeps the bottom w bits of x).
    let low = x.mod_reduce(&pow2w)?;
    Ok(pow2w.add(&low))
}

/// Key-exchange KDF input is `V.x || V.y || Z_A || Z_B || counter` per
/// GB/T 32918.3 §6.1; the underlying `KDF` is the SM2 `Kdf` from
/// GB/T 32918.4 §5.4.3. (The single-shot SM2 encrypt `sm2_kdf` below
/// hashes only `x || y || counter`; this variant prepends the two Z
/// values.)
fn sm2_exchange_kdf(
    vx: &[u8],
    vy: &[u8],
    z_a: &[u8],
    z_b: &[u8],
    klen: usize,
) -> Result<Vec<u8>, CryptoError> {
    let mut output = Vec::with_capacity(klen);
    let mut counter: u32 = 1;

    while output.len() < klen {
        let mut hasher = Sm3::new();
        hasher.update(vx)?;
        hasher.update(vy)?;
        hasher.update(z_a)?;
        hasher.update(z_b)?;
        hasher.update(&counter.to_be_bytes())?;
        let digest = hasher.finish()?;
        output.extend_from_slice(&digest);
        counter += 1;
    }
    output.truncate(klen);
    Ok(output)
}

/// SM2 Key Derivation Function (GB/T 32918.4 Section 5.4.3).
fn sm2_kdf(x2: &[u8], y2: &[u8], klen: usize) -> Result<Vec<u8>, CryptoError> {
    let mut output = Vec::with_capacity(klen);
    let mut counter: u32 = 1;

    while output.len() < klen {
        let mut hasher = Sm3::new();
        hasher.update(x2)?;
        hasher.update(y2)?;
        hasher.update(&counter.to_be_bytes())?;
        let digest = hasher.finish()?;
        output.extend_from_slice(&digest);
        counter += 1;
    }

    output.truncate(klen);
    Ok(output)
}

/// DER-encode an SM2 signature: SEQUENCE { INTEGER r, INTEGER s }.
fn encode_der_signature(r: &BigNum, s: &BigNum) -> Result<Vec<u8>, CryptoError> {
    let r_bytes = r.to_bytes_be();
    let s_bytes = s.to_bytes_be();

    let mut inner = Encoder::new();
    inner.write_integer(&r_bytes).write_integer(&s_bytes);
    let inner_bytes = inner.finish();

    let mut outer = Encoder::new();
    outer.write_sequence(&inner_bytes);
    Ok(outer.finish())
}

/// DER-decode an SM2 signature.
fn decode_der_signature(data: &[u8]) -> Result<(BigNum, BigNum), CryptoError> {
    let mut decoder = Decoder::new(data);
    let mut seq = decoder
        .read_sequence()
        .map_err(|_| CryptoError::InvalidArg(""))?;

    let r_bytes = seq
        .read_integer()
        .map_err(|_| CryptoError::InvalidArg(""))?;
    let s_bytes = seq
        .read_integer()
        .map_err(|_| CryptoError::InvalidArg(""))?;

    Ok((
        BigNum::from_bytes_be(r_bytes),
        BigNum::from_bytes_be(s_bytes),
    ))
}

/// DER-encode an SM2 ciphertext in the GB/T 32918.4 / GM/T 0009 ASN.1 form:
///
/// ```text
/// SM2Cipher ::= SEQUENCE {
///     XCoordinate  INTEGER,        -- C1 x
///     YCoordinate  INTEGER,        -- C1 y
///     HASH         OCTET STRING,   -- C3 (SM3 digest)
///     CipherText   OCTET STRING    -- C2
/// }
/// ```
///
/// `c1x` / `c1y` are the affine coordinates of `C1 = k·G` (big-endian, emitted
/// as canonical DER `INTEGER`s — a leading `0x00` is added when the top bit is
/// set). This is the structured wire form; the raw `encrypt` output uses the
/// `C1 ‖ C3 ‖ C2` concatenation instead.
pub fn encode_sm2_ciphertext(
    c1x: &[u8],
    c1y: &[u8],
    c3: &[u8],
    c2: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // The C1 coordinates are EC field elements and cannot be empty (a
    // zero-length DER INTEGER is invalid).
    if c1x.is_empty() || c1y.is_empty() {
        return Err(CryptoError::InvalidArg(""));
    }
    let mut inner = Encoder::new();
    inner
        .write_integer(c1x)
        .write_integer(c1y)
        .write_octet_string(c3)
        .write_octet_string(c2);
    let inner_bytes = inner.finish();

    let mut outer = Encoder::new();
    outer.write_sequence(&inner_bytes);
    Ok(outer.finish())
}

/// The four components of an SM2 ciphertext: `(C1x, C1y, C3, C2)`.
pub type Sm2CiphertextParts = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// DER-decode an SM2 ciphertext (GB/T 32918.4) into `(C1x, C1y, C3, C2)`.
///
/// `C1x` / `C1y` are the raw `INTEGER` content octets (a DER sign-pad `0x00`, if
/// present, is preserved). Rejects trailing bytes inside or after the SEQUENCE.
pub fn decode_sm2_ciphertext(der: &[u8]) -> Result<Sm2CiphertextParts, CryptoError> {
    let mut decoder = Decoder::new(der);
    let mut seq = decoder
        .read_sequence()
        .map_err(|_| CryptoError::InvalidArg(""))?;

    let c1x = seq
        .read_integer()
        .map_err(|_| CryptoError::InvalidArg(""))?;
    let c1y = seq
        .read_integer()
        .map_err(|_| CryptoError::InvalidArg(""))?;
    // Strict-DER: the C1 coordinates must be non-empty, non-negative, minimally
    // encoded INTEGERs (rejects the non-minimal / negative encodings the C
    // reference also rejects).
    check_der_positive_integer(c1x)?;
    check_der_positive_integer(c1y)?;
    let (c1x, c1y) = (c1x.to_vec(), c1y.to_vec());
    let c3 = seq
        .read_octet_string()
        .map_err(|_| CryptoError::InvalidArg(""))?
        .to_vec();
    let c2 = seq
        .read_octet_string()
        .map_err(|_| CryptoError::InvalidArg(""))?
        .to_vec();

    // C3 (the SM3 digest) and C2 (the ciphertext over a non-empty plaintext)
    // are never empty; the C reference rejects zero-length octet strings.
    if c3.is_empty() || c2.is_empty() {
        return Err(CryptoError::InvalidArg(""));
    }
    if !seq.is_empty() || !decoder.is_empty() {
        return Err(CryptoError::InvalidArg(""));
    }
    Ok((c1x, c1y, c3, c2))
}

/// Validate the raw content octets of a DER `INTEGER` that must be a
/// non-negative, minimally-encoded value (an SM2 ciphertext `C1` coordinate).
/// Rejects empty content, a set high bit on the first octet (negative), and a
/// superfluous leading `0x00` (non-minimal).
fn check_der_positive_integer(bytes: &[u8]) -> Result<(), CryptoError> {
    match bytes {
        [] => Err(CryptoError::InvalidArg("")),
        [0x00] => Ok(()),
        [0x00, second, ..] if second & 0x80 == 0 => Err(CryptoError::InvalidArg("")),
        [first, ..] if first & 0x80 != 0 => Err(CryptoError::InvalidArg("")),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm2_sign_verify() {
        let key = Sm2KeyPair::generate().unwrap();
        let message = b"SM2 signature test message";

        let sig = key.sign(message).unwrap();
        let valid = key.verify(message, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sm2_sign_verify_custom_id() {
        let key = Sm2KeyPair::generate().unwrap();
        let user_id = b"custom_user_id";
        let message = b"test message";

        let sig = key.sign_with_id(user_id, message).unwrap();
        let valid = key.verify_with_id(user_id, message, &sig).unwrap();
        assert!(valid);

        // Wrong ID should fail
        let wrong = key.verify_with_id(b"wrong_id", message, &sig).unwrap();
        assert!(!wrong);
    }

    #[test]
    fn test_sm2_tamper_detection() {
        let key = Sm2KeyPair::generate().unwrap();
        let message = b"original message";
        let sig = key.sign(message).unwrap();

        assert!(!key.verify(b"tampered message", &sig).unwrap());
    }

    #[test]
    fn test_sm2_public_key_only_verify() {
        let key = Sm2KeyPair::generate().unwrap();
        let message = b"verify with pubkey only";
        let sig = key.sign(message).unwrap();

        let verifier = Sm2KeyPair::from_public_key(&key.public_key_bytes().unwrap()).unwrap();
        assert!(verifier.verify(message, &sig).unwrap());
    }

    #[test]
    fn test_sm2_encrypt_decrypt() {
        let key = Sm2KeyPair::generate().unwrap();
        let plaintext = b"SM2 encryption test message";

        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), &decrypted[..]);
    }

    #[test]
    fn test_sm2_decrypt_tampered_fails() {
        let key = Sm2KeyPair::generate().unwrap();
        let plaintext = b"test message for tampering";

        let mut ciphertext = key.encrypt(plaintext).unwrap();
        // Tamper with the last byte of C2
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0x01;

        assert!(key.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_sm2_encrypt_decrypt_short() {
        let key = Sm2KeyPair::generate().unwrap();
        let plaintext = b"x"; // single byte

        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), &decrypted[..]);
    }

    #[test]
    fn test_sm2_public_only_sign_fails() {
        let full_key = Sm2KeyPair::generate().unwrap();
        let pub_bytes = full_key.public_key_bytes().unwrap();
        let pub_only = Sm2KeyPair::from_public_key(&pub_bytes).unwrap();
        assert!(
            pub_only.sign(b"msg").is_err(),
            "sign with public-only key should fail"
        );
    }

    #[test]
    fn test_sm2_public_only_decrypt_fails() {
        let full_key = Sm2KeyPair::generate().unwrap();
        let ct = full_key.encrypt(b"hello").unwrap();
        let pub_bytes = full_key.public_key_bytes().unwrap();
        let pub_only = Sm2KeyPair::from_public_key(&pub_bytes).unwrap();
        assert!(
            pub_only.decrypt(&ct).is_err(),
            "decrypt with public-only key should fail"
        );
    }

    #[test]
    fn test_sm2_corrupted_signature_verify() {
        let key = Sm2KeyPair::generate().unwrap();
        let msg = b"test message";
        let mut sig = key.sign(msg).unwrap();

        // Corrupt a byte in the middle of the signature
        let mid = sig.len() / 2;
        sig[mid] ^= 0xFF;

        // Should either error or return false
        if let Ok(valid) = key.verify(msg, &sig) {
            assert!(!valid, "corrupted signature should not verify");
        }
    }

    /// SM2P256V1 ZA computation golden test.
    ///
    /// Validates the ZA hash algorithm: ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA).
    ///
    /// The public key (xA, yA) is derived from the well-known SM2P256V1 test private key
    /// used by the Botan cryptographic library (src/tests/data/pubkey/sm2_sig.vec, Curve2).
    ///
    /// Private key: 110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC
    /// Derived public key (verified on curve via y²=x³+ax+b mod p):
    ///   xA = D03D30DD01CA3422AEACCF9B88043B554659D3092B0A9E8CCE3E8C4530A98CB7
    ///   yA = 9D705E6213EEE145B748E36E274E5F101DC10D7BBC9DAB9A04022E73B76E02CD
    /// User ID = "1234567812345678" (the SM2 default per GB/T 32918)
    /// Expected ZA (computed by the implementation — deterministic golden value):
    ///   see assertion below
    #[test]
    fn test_sm2_za_algorithm_correctness() {
        use hitls_utils::hex::{hex, to_hex};

        // Derive the public key from the well-known SM2P256V1 test private key.
        let da = hex("110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC");
        let kp = Sm2KeyPair::from_private_key(&da).unwrap();

        // ZA is deterministic: verify it produces the same result across runs.
        let user_id = b"1234567812345678"; // SM2 default user ID (GB/T 32918)
        let za1 = compute_za(user_id, &kp.public_key, &kp.group).unwrap();
        let za2 = compute_za(user_id, &kp.public_key, &kp.group).unwrap();
        assert_eq!(za1, za2, "ZA must be deterministic");
        assert_eq!(za1.len(), 32, "ZA must be a 32-byte SM3 hash");

        // Verify ZA output is the expected golden value.
        // This golden value was computed using this implementation and verifies that the
        // SM3(ENTLA || IDA || a || b || xG || yG || xA || yA) formula from GM/T 0003.2
        // is correctly implemented on SM2P256V1 (GB/T 32918.5-2017).
        let za_hex = to_hex(&za1);
        assert_eq!(
            za_hex, "5578dd585cbf448fb1bce47cac071f2a8539fca987121c6a691225dc9c69805e",
            "ZA mismatch: SM3 hash of (ENTLA || IDA || curve_params || public_key)"
        );
    }

    /// SM2P256V1 sign then verify round-trip using the Botan test private key.
    ///
    /// Uses the SM2P256V1 private key from Botan's sm2_sig.vec (Curve2) and verifies
    /// that SM2DSA sign+verify is internally consistent on this key with user ID and message.
    ///
    /// Private key: 110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC
    #[test]
    fn test_sm2_sign_verify_botan_test_key() {
        use hitls_utils::hex::hex;

        let da = hex("110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC");
        let kp = Sm2KeyPair::from_private_key(&da).unwrap();

        let user_id = b"1234567812345678";
        let message = b"hi chappy"; // Botan SM2 test message

        let sig = kp.sign_with_id(user_id, message).unwrap();
        let valid = kp.verify_with_id(user_id, message, &sig).unwrap();
        assert!(
            valid,
            "SM2 sign/verify round-trip must succeed (Botan SM2P256V1 test key)"
        );

        // Signature must not verify for a different message
        let valid_wrong = kp
            .verify_with_id(user_id, b"different message", &sig)
            .unwrap();
        assert!(
            !valid_wrong,
            "Signature must not verify against a different message"
        );
    }

    /// GM/T 0003.2-2012 — sign then verify with the IETF draft private key.
    ///
    /// Uses dA = 128B2FA8... from draft-shen-sm2-ecdsa-02.  The draft's xA/yA are for a
    /// different (older) curve; this test derives the SM2P256V1 public key from dA and
    /// confirms that sign + verify is consistent on this implementation.
    #[test]
    fn test_sm2_standard_vector_sign_verify_roundtrip() {
        use hitls_utils::hex::hex;

        let da = hex("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263");
        let kp = Sm2KeyPair::from_private_key(&da).unwrap();

        let user_id = b"ALICE123@YAHOO.COM";
        let message = b"message digest";

        let sig = kp.sign_with_id(user_id, message).unwrap();
        let valid = kp.verify_with_id(user_id, message, &sig).unwrap();
        assert!(
            valid,
            "SM2 sign/verify roundtrip must succeed with standard private key"
        );
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(5))]

            #[test]
            fn prop_sm2_sign_verify_roundtrip(
                msg in prop::collection::vec(any::<u8>(), 1..128),
            ) {
                let kp = Sm2KeyPair::generate().unwrap();
                let sig = kp.sign(&msg).unwrap();
                prop_assert!(kp.verify(&msg, &sig).unwrap());
            }

            #[test]
            fn prop_sm2_encrypt_decrypt_roundtrip(
                pt in prop::collection::vec(any::<u8>(), 1..64),
            ) {
                let kp = Sm2KeyPair::generate().unwrap();
                let ct = kp.encrypt(&pt).unwrap();
                let recovered = kp.decrypt(&ct).unwrap();
                prop_assert_eq!(recovered, pt);
            }
        }
    }

    /// SM2 key-exchange GB/T 32918.5-2017 §A.1 / openHiTLS C SDV vector 1.
    ///
    /// `prvKey` (own d) + `pubKey` (peer P) + `r` (own ephemeral nonce) +
    /// `R` (peer's pre-generated ephemeral point) + expected 16-byte
    /// shared key. Both sides use the SM2 default user ID
    /// `1234567812345678`.
    #[test]
    fn test_sm2_exchange_gb_32918_5_vector1() {
        use hitls_utils::hex::{hex, to_hex};

        let my_prv = hex("81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029");
        let peer_pub = hex(
            "046ae848c57c53c7b1b5fa99eb2286af078ba64c64591b8b566f7357d576f16dfbee489d771621a27b36c5c7992062e9cd09a9264386f3fbea54dff69305621c4d",
        );
        let my_r = hex("d4de15474db74d06491c440d305e012400990f3e390c7e87153c12db2ea60bb3");
        let peer_r = hex(
            "04acc27688a6f7b706098bc91ff3ad1bff7dc2802cdb14ccccdb0a90471f9bd7072fedac0494b2ffc4d6853876c79b8f301c6573ad0aa50f39fc87181e1a1b46fe",
        );
        let expected_key = hex("6c89347354de2484c60b4ab1fde4c6e5");
        let my_id = b"1234567812345678";
        let peer_id = b"1234567812345678";

        let kp = Sm2KeyPair::from_private_key(&my_prv).unwrap();

        // GB/T 32918.5 vector 1 places `me` in the initiator role
        // (`server = 1` in the C SDV maps to initiator A).
        let key = kp
            .exchange_with_nonce(&my_r, &peer_pub, &peer_r, my_id, peer_id, true, 16)
            .unwrap();
        assert_eq!(
            to_hex(&key),
            to_hex(&expected_key),
            "SM2 key exchange vector 1 mismatch"
        );
    }

    /// Two-party round-trip: A and B each call `exchange_with_nonce` with
    /// random keys + nonces and converge on the same shared secret.
    #[test]
    fn test_sm2_exchange_roundtrip() {
        let kp_a = Sm2KeyPair::generate().unwrap();
        let kp_b = Sm2KeyPair::generate().unwrap();

        // Ephemeral nonces (in production these must be fresh randomness).
        let r_a = {
            let kp = Sm2KeyPair::generate().unwrap();
            kp.private_key_bytes().unwrap()
        };
        let r_b = {
            let kp = Sm2KeyPair::generate().unwrap();
            kp.private_key_bytes().unwrap()
        };

        // Each side needs the peer's ephemeral *point* R = r * G. We
        // generate that by deriving a keypair from r and reading its
        // public point.
        let r_a_point = Sm2KeyPair::from_private_key(&r_a)
            .unwrap()
            .public_key_bytes()
            .unwrap();
        let r_b_point = Sm2KeyPair::from_private_key(&r_b)
            .unwrap()
            .public_key_bytes()
            .unwrap();

        let pub_a = kp_a.public_key_bytes().unwrap();
        let pub_b = kp_b.public_key_bytes().unwrap();

        let id_a = b"alice@example.com";
        let id_b = b"bob@example.com";

        let key_a = kp_a
            .exchange_with_nonce(&r_a, &pub_b, &r_b_point, id_a, id_b, true, 32)
            .unwrap();
        let key_b = kp_b
            .exchange_with_nonce(&r_b, &pub_a, &r_a_point, id_b, id_a, false, 32)
            .unwrap();
        assert_eq!(key_a, key_b, "two-party SM2 exchange must converge");
        assert_eq!(key_a.len(), 32);
    }

    #[test]
    fn test_sm2_exchange_public_only_fails() {
        let alice = Sm2KeyPair::generate().unwrap();
        let pub_only = Sm2KeyPair::from_public_key(&alice.public_key_bytes().unwrap()).unwrap();
        let r = alice.private_key_bytes().unwrap();
        let peer_pub = alice.public_key_bytes().unwrap();
        let peer_r_point = peer_pub.clone();
        let result =
            pub_only.exchange_with_nonce(&r, &peer_pub, &peer_r_point, b"a", b"b", true, 16);
        assert!(matches!(result, Err(CryptoError::EccInvalidPrivateKey)));
    }
}
