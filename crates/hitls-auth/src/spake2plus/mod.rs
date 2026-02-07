//! SPAKE2+ password-authenticated key exchange (RFC 9382).
//!
//! Implements SPAKE2+ over P-256 with HMAC-SHA-256 for key confirmation.

use hitls_bignum::BigNum;
use hitls_crypto::ecc::{EcGroup, EcPoint};
use hitls_crypto::hmac::Hmac;
use hitls_crypto::provider::Digest;
use hitls_crypto::sha2::Sha256;
use hitls_types::{CryptoError, EccCurveId};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// SPAKE2+ protocol role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spake2Role {
    Prover,
    Verifier,
}

/// SPAKE2+ protocol state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Init,
    Setup,
    ShareGenerated,
    KeyDerived,
}

/// SPAKE2+ protocol context over P-256 (RFC 9382).
pub struct Spake2Plus {
    role: Spake2Role,
    state: State,
    group: EcGroup,
    // Password-derived values
    w0: Option<BigNum>,
    w1: Option<BigNum>,       // Prover stores w1
    l_point: Option<EcPoint>, // Verifier stores L = w1*G
    // Ephemeral scalar
    x_scalar: Option<BigNum>,
    // My share and peer share
    my_share: Option<Vec<u8>>,
    peer_share: Option<Vec<u8>>,
    // Derived keys
    ke: Option<Vec<u8>>,
    kc_a: Option<Vec<u8>>,
    kc_b: Option<Vec<u8>>,
}

impl Drop for Spake2Plus {
    fn drop(&mut self) {
        if let Some(ref mut w) = self.w0 {
            w.zeroize();
        }
        if let Some(ref mut w) = self.w1 {
            w.zeroize();
        }
        if let Some(ref mut x) = self.x_scalar {
            x.zeroize();
        }
        if let Some(ref mut k) = self.ke {
            k.zeroize();
        }
        if let Some(ref mut k) = self.kc_a {
            k.zeroize();
        }
        if let Some(ref mut k) = self.kc_b {
            k.zeroize();
        }
    }
}

fn sha256_factory() -> Box<dyn Digest> {
    Box::new(Sha256::new())
}

/// Hash data with SHA-256.
fn sha256(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut h = Sha256::new();
    h.update(data)?;
    Ok(h.finish()?.to_vec())
}

/// HMAC-SHA-256(key, data).
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Hmac::mac(sha256_factory, key, data)
}

/// Decompress a point from compressed form (02/03 || x).
/// For P-256, p ≡ 3 mod 4, so y = rhs^((p+1)/4) mod p.
fn decompress_point(group: &EcGroup, compressed: &[u8]) -> Result<EcPoint, CryptoError> {
    if compressed.len() != 33 || (compressed[0] != 0x02 && compressed[0] != 0x03) {
        return Err(CryptoError::EccInvalidPublicKey);
    }
    let sign = compressed[0]; // 02 = even y, 03 = odd y
    let x = BigNum::from_bytes_be(&compressed[1..]);

    // P-256 curve parameters for decompression
    let field_p = BigNum::from_bytes_be(&hex(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    ));
    let a = BigNum::from_bytes_be(&hex(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
    ));
    let b = BigNum::from_bytes_be(&hex(
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
    ));

    // rhs = x³ + ax + b mod p
    let x_sq = x.mod_mul(&x, &field_p)?;
    let x_cu = x_sq.mod_mul(&x, &field_p)?;
    let ax = a.mod_mul(&x, &field_p)?;
    let rhs = x_cu.mod_add(&ax, &field_p)?.mod_add(&b, &field_p)?;

    // y = rhs^((p+1)/4) mod p (since p ≡ 3 mod 4)
    let exp = field_p.add(&BigNum::from_u64(1)).shr(2usize);
    let mut y = rhs.mod_exp(&exp, &field_p)?;

    // Check parity
    let y_bytes = y.to_bytes_be();
    let y_is_odd = if y_bytes.is_empty() {
        false
    } else {
        y_bytes[y_bytes.len() - 1] & 1 == 1
    };
    let want_odd = sign == 0x03;
    if y_is_odd != want_odd {
        y = field_p.sub(&y);
    }

    let point = EcPoint::new(x, y);
    if !point.is_on_curve(group)? {
        return Err(CryptoError::EccPointNotOnCurve);
    }
    Ok(point)
}

// RFC 9382 Section 4: M and N compressed points for P-256.
// M = 02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f
// N = 03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49
fn m_point(group: &EcGroup) -> Result<EcPoint, CryptoError> {
    let compressed = hex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f");
    decompress_point(group, &compressed)
}

fn n_point(group: &EcGroup) -> Result<EcPoint, CryptoError> {
    let compressed = hex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49");
    decompress_point(group, &compressed)
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Encode length-prefixed data for the transcript TT.
fn encode_len_data(out: &mut Vec<u8>, data: &[u8]) {
    // 8-byte LE length prefix + data (RFC 9382 Section 3.4)
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(data);
}

impl Spake2Plus {
    /// Create a new SPAKE2+ context.
    pub fn new(role: Spake2Role) -> Result<Self, CryptoError> {
        let group = EcGroup::new(EccCurveId::NistP256)?;
        Ok(Self {
            role,
            state: State::Init,
            group,
            w0: None,
            w1: None,
            l_point: None,
            x_scalar: None,
            my_share: None,
            peer_share: None,
            ke: None,
            kc_a: None,
            kc_b: None,
        })
    }

    /// Set up from raw w0, w1 (prover) or w0, L (verifier) bytes.
    pub fn setup(&mut self, w0_bytes: &[u8], w1_or_l: &[u8]) -> Result<(), CryptoError> {
        let n = self.group.order();
        let w0_raw = BigNum::from_bytes_be(w0_bytes);
        let w0 = w0_raw.mod_reduce(n)?;

        match self.role {
            Spake2Role::Prover => {
                let w1_raw = BigNum::from_bytes_be(w1_or_l);
                let w1 = w1_raw.mod_reduce(n)?;
                self.w0 = Some(w0);
                self.w1 = Some(w1);
            }
            Spake2Role::Verifier => {
                // w1_or_l is the serialized L point
                let l = EcPoint::from_uncompressed(&self.group, w1_or_l)?;
                self.w0 = Some(w0);
                self.l_point = Some(l);
            }
        }
        self.state = State::Setup;
        Ok(())
    }

    /// Set up from a password using PBKDF2-HMAC-SHA-256.
    ///
    /// Derives w0 and w1 from password+salt, then:
    /// - Prover stores (w0, w1)
    /// - Verifier stores (w0, L = w1*G)
    pub fn setup_from_password(
        &mut self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<(), CryptoError> {
        let n = self.group.order();

        // Derive 2*32 = 64 bytes of key material
        let dk = hitls_crypto::pbkdf2::pbkdf2(password, salt, iterations, 64)?;
        let w0_raw = BigNum::from_bytes_be(&dk[..32]);
        let w1_raw = BigNum::from_bytes_be(&dk[32..64]);

        let w0 = w0_raw.mod_reduce(n)?;
        let w1 = w1_raw.mod_reduce(n)?;

        match self.role {
            Spake2Role::Prover => {
                self.w0 = Some(w0);
                self.w1 = Some(w1);
            }
            Spake2Role::Verifier => {
                let l = self.group.scalar_mul_base(&w1)?;
                self.w0 = Some(w0);
                self.l_point = Some(l);
            }
        }
        self.state = State::Setup;
        Ok(())
    }

    /// Generate the SPAKE2+ share (pA or pB).
    ///
    /// - Prover: pA = x*G + w0*M
    /// - Verifier: pB = y*G + w0*N
    pub fn generate_share(&mut self) -> Result<Vec<u8>, CryptoError> {
        if self.state != State::Setup {
            return Err(CryptoError::DrbgInvalidState);
        }

        let w0 = self.w0.as_ref().ok_or(CryptoError::NullInput)?;
        let n = self.group.order().clone();

        // Generate random scalar x (or y) in [1, n-1]
        let x = random_scalar(&n)?;

        // Compute share: x*G + w0*M (prover) or x*G + w0*N (verifier)
        let blinding_point = match self.role {
            Spake2Role::Prover => m_point(&self.group)?,
            Spake2Role::Verifier => n_point(&self.group)?,
        };
        let share = self.group.scalar_mul_add(&x, w0, &blinding_point)?;
        let share_bytes = share.to_uncompressed(&self.group)?;

        self.x_scalar = Some(x);
        self.my_share = Some(share_bytes.clone());
        self.state = State::ShareGenerated;
        Ok(share_bytes)
    }

    /// Process the peer's share and derive the shared key Ke.
    ///
    /// Returns the encryption key Ke.
    pub fn process_share(&mut self, peer_share: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.state != State::ShareGenerated {
            return Err(CryptoError::DrbgInvalidState);
        }

        let w0 = self.w0.as_ref().ok_or(CryptoError::NullInput)?;
        let x = self.x_scalar.as_ref().ok_or(CryptoError::NullInput)?;

        // Decode peer's share point
        let peer_point = EcPoint::from_uncompressed(&self.group, peer_share)?;

        // Unblind: subtract w0 * M_or_N from peer share
        let unbind_point = match self.role {
            Spake2Role::Prover => {
                // Peer is verifier, used N blinding
                n_point(&self.group)?
            }
            Spake2Role::Verifier => {
                // Peer is prover, used M blinding
                m_point(&self.group)?
            }
        };
        let w0_times_unbind = self.group.scalar_mul(w0, &unbind_point)?;
        let neg_w0_unbind = self.group.point_negate(&w0_times_unbind)?;
        let q = self.group.point_add(&peer_point, &neg_w0_unbind)?;

        if q.is_infinity() {
            return Err(CryptoError::EccPointAtInfinity);
        }

        // Compute Z and V
        let (z, v) = match self.role {
            Spake2Role::Prover => {
                let w1 = self.w1.as_ref().ok_or(CryptoError::NullInput)?;
                // Z = x * Q, V = w1 * Q
                let z = self.group.scalar_mul(x, &q)?;
                let v = self.group.scalar_mul(w1, &q)?;
                (z, v)
            }
            Spake2Role::Verifier => {
                let l = self.l_point.as_ref().ok_or(CryptoError::NullInput)?;
                // Z = y * Q, V = y * L
                let z = self.group.scalar_mul(x, &q)?;
                let v = self.group.scalar_mul(x, l)?;
                (z, v)
            }
        };

        self.peer_share = Some(peer_share.to_vec());

        // Build transcript TT (RFC 9382 Section 3.4)
        let (pa_bytes, pb_bytes) = match self.role {
            Spake2Role::Prover => (
                self.my_share
                    .as_ref()
                    .ok_or(CryptoError::NullInput)?
                    .as_slice(),
                peer_share,
            ),
            Spake2Role::Verifier => (
                peer_share,
                self.my_share
                    .as_ref()
                    .ok_or(CryptoError::NullInput)?
                    .as_slice(),
            ),
        };

        let z_bytes = z.to_uncompressed(&self.group)?;
        let v_bytes = v.to_uncompressed(&self.group)?;
        let w0_bytes = w0.to_bytes_be_padded(32)?;

        let mut tt = Vec::new();
        // Context: empty for default
        encode_len_data(&mut tt, b"");
        // idProver: empty
        encode_len_data(&mut tt, b"");
        // idVerifier: empty
        encode_len_data(&mut tt, b"");
        // M
        let m_bytes = m_point(&self.group)?.to_uncompressed(&self.group)?;
        encode_len_data(&mut tt, &m_bytes);
        // N
        let n_bytes = n_point(&self.group)?.to_uncompressed(&self.group)?;
        encode_len_data(&mut tt, &n_bytes);
        // pA
        encode_len_data(&mut tt, pa_bytes);
        // pB
        encode_len_data(&mut tt, pb_bytes);
        // Z
        encode_len_data(&mut tt, &z_bytes);
        // V
        encode_len_data(&mut tt, &v_bytes);
        // w0
        encode_len_data(&mut tt, &w0_bytes);

        // Hash the transcript
        let hash_tt = sha256(&tt)?;

        // Split: Ke || Ka (each 16 bytes for SHA-256, or 32/2 = 16)
        let ke = hash_tt[..16].to_vec();
        let ka = &hash_tt[16..];

        // Derive confirmation keys using HMAC
        let kc_a = hmac_sha256(ka, b"ConfirmProver")?;
        let kc_b = hmac_sha256(ka, b"ConfirmVerifier")?;

        self.ke = Some(ke.clone());
        self.kc_a = Some(kc_a);
        self.kc_b = Some(kc_b);
        self.state = State::KeyDerived;

        Ok(ke)
    }

    /// Get the confirmation value for key confirmation.
    ///
    /// - Prover sends: HMAC(KcA, pB)
    /// - Verifier sends: HMAC(KcB, pA)
    pub fn get_confirmation(&self) -> Result<Vec<u8>, CryptoError> {
        if self.state != State::KeyDerived {
            return Err(CryptoError::DrbgInvalidState);
        }

        let peer_share = self.peer_share.as_ref().ok_or(CryptoError::NullInput)?;

        match self.role {
            Spake2Role::Prover => {
                let kc_a = self.kc_a.as_ref().ok_or(CryptoError::NullInput)?;
                hmac_sha256(kc_a, peer_share)
            }
            Spake2Role::Verifier => {
                let kc_b = self.kc_b.as_ref().ok_or(CryptoError::NullInput)?;
                hmac_sha256(kc_b, peer_share)
            }
        }
    }

    /// Verify the peer's confirmation value.
    pub fn verify_confirmation(&self, confirmation: &[u8]) -> Result<bool, CryptoError> {
        if self.state != State::KeyDerived {
            return Err(CryptoError::DrbgInvalidState);
        }

        // Compute expected confirmation from the peer
        let expected = match self.role {
            Spake2Role::Prover => {
                // Peer is verifier, sent HMAC(KcB, pA) where pA = my_share
                let kc_b = self.kc_b.as_ref().ok_or(CryptoError::NullInput)?;
                let my_share = self.my_share.as_ref().ok_or(CryptoError::NullInput)?;
                hmac_sha256(kc_b, my_share)?
            }
            Spake2Role::Verifier => {
                // Peer is prover, sent HMAC(KcA, pB) where pB = my_share
                let kc_a = self.kc_a.as_ref().ok_or(CryptoError::NullInput)?;
                let my_share = self.my_share.as_ref().ok_or(CryptoError::NullInput)?;
                hmac_sha256(kc_a, my_share)?
            }
        };

        // Constant-time comparison
        Ok(confirmation.ct_eq(&expected).into())
    }

    /// Return the peer's share (only available after `process_share`).
    pub fn peer_share(&self) -> Option<&[u8]> {
        self.peer_share.as_deref()
    }
}

/// Generate a random scalar in [1, n-1].
fn random_scalar(n: &BigNum) -> Result<BigNum, CryptoError> {
    let n_bytes = n.to_bytes_be();
    let byte_len = n_bytes.len();
    let mut buf = vec![0u8; byte_len];
    loop {
        getrandom::getrandom(&mut buf).map_err(|_| CryptoError::BnRandGenFail)?;
        let k = BigNum::from_bytes_be(&buf);
        if k > BigNum::zero() && k < *n {
            buf.zeroize();
            return Ok(k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_m_n_on_curve() {
        let group = EcGroup::new(EccCurveId::NistP256).unwrap();
        let m = m_point(&group).unwrap();
        let n = n_point(&group).unwrap();
        assert!(m.is_on_curve(&group).unwrap());
        assert!(n.is_on_curve(&group).unwrap());
        assert_ne!(m, n);
    }

    #[test]
    fn test_full_exchange_password() {
        let password = b"test_password_123";
        let salt = b"salt_for_spake2plus";
        let iterations = 1000;

        let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
        let mut verifier = Spake2Plus::new(Spake2Role::Verifier).unwrap();

        prover
            .setup_from_password(password, salt, iterations)
            .unwrap();
        verifier
            .setup_from_password(password, salt, iterations)
            .unwrap();

        let pa = prover.generate_share().unwrap();
        let pb = verifier.generate_share().unwrap();

        let ke_prover = prover.process_share(&pb).unwrap();
        let ke_verifier = verifier.process_share(&pa).unwrap();

        assert_eq!(ke_prover, ke_verifier, "Shared keys must match");

        // Key confirmation
        let conf_a = prover.get_confirmation().unwrap();
        let conf_b = verifier.get_confirmation().unwrap();

        assert!(verifier.verify_confirmation(&conf_a).unwrap());
        assert!(prover.verify_confirmation(&conf_b).unwrap());
    }

    #[test]
    fn test_wrong_password_fails() {
        let salt = b"salt";
        let iterations = 1000;

        let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
        let mut verifier = Spake2Plus::new(Spake2Role::Verifier).unwrap();

        prover
            .setup_from_password(b"correct_password", salt, iterations)
            .unwrap();
        verifier
            .setup_from_password(b"wrong_password", salt, iterations)
            .unwrap();

        let pa = prover.generate_share().unwrap();
        let pb = verifier.generate_share().unwrap();

        let ke_prover = prover.process_share(&pb).unwrap();
        let ke_verifier = verifier.process_share(&pa).unwrap();

        // Keys should NOT match with different passwords
        assert_ne!(ke_prover, ke_verifier);
    }

    #[test]
    fn test_confirmation_mismatch_wrong_password() {
        let salt = b"salt";
        let iterations = 1000;

        let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
        let mut verifier = Spake2Plus::new(Spake2Role::Verifier).unwrap();

        prover
            .setup_from_password(b"password1", salt, iterations)
            .unwrap();
        verifier
            .setup_from_password(b"password2", salt, iterations)
            .unwrap();

        let pa = prover.generate_share().unwrap();
        let pb = verifier.generate_share().unwrap();

        let _ke_prover = prover.process_share(&pb).unwrap();
        let _ke_verifier = verifier.process_share(&pa).unwrap();

        let conf_a = prover.get_confirmation().unwrap();
        let conf_b = verifier.get_confirmation().unwrap();

        // Confirmations should fail with wrong passwords
        assert!(!verifier.verify_confirmation(&conf_a).unwrap());
        assert!(!prover.verify_confirmation(&conf_b).unwrap());
    }

    #[test]
    fn test_setup_with_raw_w0_w1() {
        let group = EcGroup::new(EccCurveId::NistP256).unwrap();

        // Generate w0, w1 from a password manually
        let dk = hitls_crypto::pbkdf2::pbkdf2(b"test", b"salt", 1000, 64).unwrap();
        let n = group.order();
        let w0 = BigNum::from_bytes_be(&dk[..32]).mod_reduce(n).unwrap();
        let w1 = BigNum::from_bytes_be(&dk[32..64]).mod_reduce(n).unwrap();
        let l = group.scalar_mul_base(&w1).unwrap();
        let l_bytes = l.to_uncompressed(&group).unwrap();

        let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
        let mut verifier = Spake2Plus::new(Spake2Role::Verifier).unwrap();

        let w0_bytes = w0.to_bytes_be_padded(32).unwrap();
        let w1_bytes = w1.to_bytes_be_padded(32).unwrap();

        prover.setup(&w0_bytes, &w1_bytes).unwrap();
        verifier.setup(&w0_bytes, &l_bytes).unwrap();

        let pa = prover.generate_share().unwrap();
        let pb = verifier.generate_share().unwrap();

        let ke_p = prover.process_share(&pb).unwrap();
        let ke_v = verifier.process_share(&pa).unwrap();

        assert_eq!(ke_p, ke_v);
    }

    #[test]
    fn test_share_format() {
        let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
        prover.setup_from_password(b"pw", b"salt", 1000).unwrap();
        let share = prover.generate_share().unwrap();

        // P-256 uncompressed point: 0x04 || x(32) || y(32) = 65 bytes
        assert_eq!(share.len(), 65);
        assert_eq!(share[0], 0x04);

        // The share should be a valid point on P-256
        let group = EcGroup::new(EccCurveId::NistP256).unwrap();
        let p = EcPoint::from_uncompressed(&group, &share).unwrap();
        assert!(p.is_on_curve(&group).unwrap());
    }

    #[test]
    fn test_state_machine_enforcement() {
        let mut ctx = Spake2Plus::new(Spake2Role::Prover).unwrap();

        // Should fail: not set up
        assert!(ctx.generate_share().is_err());

        ctx.setup_from_password(b"pw", b"salt", 1000).unwrap();
        let share = ctx.generate_share().unwrap();

        // Should fail: can't process share before generating one (verifier side)
        let mut ctx2 = Spake2Plus::new(Spake2Role::Verifier).unwrap();
        assert!(ctx2.process_share(&share).is_err());

        // Should fail: can't get confirmation before key derived
        assert!(ctx.get_confirmation().is_err());
    }

    #[test]
    fn test_key_determinism_with_known_scalars() {
        // Run the exchange twice with the same password → shared key differs
        // (because random ephemeral scalars differ each time)
        let mut p1 = Spake2Plus::new(Spake2Role::Prover).unwrap();
        let mut v1 = Spake2Plus::new(Spake2Role::Verifier).unwrap();
        p1.setup_from_password(b"pw", b"salt", 100).unwrap();
        v1.setup_from_password(b"pw", b"salt", 100).unwrap();
        let pa1 = p1.generate_share().unwrap();
        let pb1 = v1.generate_share().unwrap();
        let ke1 = p1.process_share(&pb1).unwrap();
        let _ke1v = v1.process_share(&pa1).unwrap();

        let mut p2 = Spake2Plus::new(Spake2Role::Prover).unwrap();
        let mut v2 = Spake2Plus::new(Spake2Role::Verifier).unwrap();
        p2.setup_from_password(b"pw", b"salt", 100).unwrap();
        v2.setup_from_password(b"pw", b"salt", 100).unwrap();
        let pa2 = p2.generate_share().unwrap();
        let pb2 = v2.generate_share().unwrap();
        let ke2 = p2.process_share(&pb2).unwrap();
        let _ke2v = v2.process_share(&pa2).unwrap();

        // Keys differ due to random ephemeral scalars
        assert_ne!(ke1, ke2);
    }

    #[test]
    fn test_key_length() {
        let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
        let mut verifier = Spake2Plus::new(Spake2Role::Verifier).unwrap();

        prover.setup_from_password(b"pw", b"s", 100).unwrap();
        verifier.setup_from_password(b"pw", b"s", 100).unwrap();

        let pa = prover.generate_share().unwrap();
        let pb = verifier.generate_share().unwrap();

        let ke = prover.process_share(&pb).unwrap();
        let _ = verifier.process_share(&pa).unwrap();

        // Ke is 16 bytes (half of SHA-256 output)
        assert_eq!(ke.len(), 16);

        // Confirmations are 32 bytes (HMAC-SHA-256 output)
        let conf = prover.get_confirmation().unwrap();
        assert_eq!(conf.len(), 32);
    }
}
