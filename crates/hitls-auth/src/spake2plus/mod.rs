//! SPAKE2+ password-authenticated key exchange (RFC 9383).
//!
//! Supports the RFC 9383 ciphersuites over NIST P-256 / P-384 / P-521 with
//! SHA-256 / SHA-512 + HKDF + HMAC for the key schedule and confirmation
//! (`Spake2Suite`). Defaults to P256-SHA256.

use hitls_bignum::BigNum;
use hitls_crypto::ecc::{EcGroup, EcPoint};
use hitls_crypto::hkdf::Hkdf;
use hitls_crypto::hmac::Hmac;
use hitls_crypto::provider::Digest;
use hitls_crypto::sha2::{Sha256, Sha512};
use hitls_types::{CryptoError, EccCurveId};
use hitls_utils::hex::hex;
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
    // RFC 9383 protocol identities (default empty). These feed the transcript
    // TT (Context || idProver || idVerifier) and so the derived keys.
    context: Vec<u8>,
    id_prover: Vec<u8>,
    id_verifier: Vec<u8>,
    // RFC 9383 ciphersuite (hash / KDF / MAC family). Default P256-SHA256.
    suite: Spake2Suite,
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

fn sha512_factory() -> Box<dyn Digest> {
    Box::new(Sha512::new())
}

/// Hash data with SHA-256.
fn sha256(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut h = Sha256::new();
    h.update(data)?;
    Ok(h.finish()?.to_vec())
}

/// RFC 9383 ciphersuite — binds the elliptic curve **and** the
/// `Hash = KDF-hash = HMAC-hash` family (RFC 9383 Table 1). Each variant maps
/// to one openHiTLS C SDV `SPAKE2PLUS_TC001` vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spake2Suite {
    /// SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256.
    P256Sha256,
    /// SPAKE2+-P256-SHA512-HKDF-SHA512-HMAC-SHA512.
    P256Sha512,
    /// SPAKE2+-P384-SHA256-HKDF-SHA256-HMAC-SHA256.
    P384Sha256,
    /// SPAKE2+-P384-SHA512-HKDF-SHA512-HMAC-SHA512.
    P384Sha512,
    /// SPAKE2+-P521-SHA512-HKDF-SHA512-HMAC-SHA512.
    P521Sha512,
}

impl Spake2Suite {
    /// The elliptic curve this ciphersuite runs over.
    fn curve(self) -> EccCurveId {
        match self {
            Spake2Suite::P256Sha256 | Spake2Suite::P256Sha512 => EccCurveId::NistP256,
            Spake2Suite::P384Sha256 | Spake2Suite::P384Sha512 => EccCurveId::NistP384,
            Spake2Suite::P521Sha512 => EccCurveId::NistP521,
        }
    }

    /// Hash output length in bytes (also the derived-key length: RFC 9383 §3.4
    /// recommends each key = the digest output length).
    fn hlen(self) -> usize {
        match self {
            Spake2Suite::P256Sha256 | Spake2Suite::P384Sha256 => 32,
            Spake2Suite::P256Sha512 | Spake2Suite::P384Sha512 | Spake2Suite::P521Sha512 => 64,
        }
    }

    fn factory(self) -> fn() -> Box<dyn Digest> {
        if self.hlen() == 32 {
            sha256_factory
        } else {
            sha512_factory
        }
    }

    /// `K_main = Hash(TT)`.
    fn hash(self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.hlen() == 32 {
            sha256(data)
        } else {
            let mut h = Sha512::new();
            h.update(data)?;
            Ok(h.finish()?.to_vec())
        }
    }

    /// The key-confirmation MAC over the peer's share.
    fn mac(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Hmac::mac(self.factory(), key, data)
    }

    /// RFC 9383 §4 constant point M for this curve (SEC1 compressed).
    fn m_compressed(self) -> &'static str {
        match self {
            Spake2Suite::P256Sha256 | Spake2Suite::P256Sha512 => {
                "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
            }
            Spake2Suite::P384Sha256 | Spake2Suite::P384Sha512 => {
                "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d\
                 3dc36f15314739074d2eb8613fceec2853"
            }
            Spake2Suite::P521Sha512 => {
                "02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85\
                 608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b569799\
                 62d7aa"
            }
        }
    }

    /// RFC 9383 §4 constant point N for this curve (SEC1 compressed).
    fn n_compressed(self) -> &'static str {
        match self {
            Spake2Suite::P256Sha256 | Spake2Suite::P256Sha512 => {
                "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
            }
            Spake2Suite::P384Sha256 | Spake2Suite::P384Sha512 => {
                "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c54\
                 3bb252c5490214cf9aa3f0baab4b665c10"
            }
            Spake2Suite::P521Sha512 => {
                "0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e49\
                 4b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d955\
                 75cd25"
            }
        }
    }
}

/// RFC 9383 §4 constant point M for the suite's curve, decompressed onto `group`.
fn m_point(group: &EcGroup, suite: Spake2Suite) -> Result<EcPoint, CryptoError> {
    EcPoint::from_compressed(group, &hex(suite.m_compressed()))
}

/// RFC 9383 §4 constant point N for the suite's curve, decompressed onto `group`.
fn n_point(group: &EcGroup, suite: Spake2Suite) -> Result<EcPoint, CryptoError> {
    EcPoint::from_compressed(group, &hex(suite.n_compressed()))
}

/// Encode length-prefixed data for the transcript TT.
fn encode_len_data(out: &mut Vec<u8>, data: &[u8]) {
    // 8-byte LE length prefix + data (RFC 9382 Section 3.4)
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(data);
}

impl Spake2Plus {
    /// Create a new SPAKE2+ context (default ciphersuite P256-SHA256).
    pub fn new(role: Spake2Role) -> Result<Self, CryptoError> {
        Self::with_suite(role, Spake2Suite::P256Sha256)
    }

    /// Create a new SPAKE2+ context with an explicit RFC 9383 ciphersuite.
    pub fn with_suite(role: Spake2Role, suite: Spake2Suite) -> Result<Self, CryptoError> {
        let group = EcGroup::new(suite.curve())?;
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
            context: Vec::new(),
            id_prover: Vec::new(),
            id_verifier: Vec::new(),
            suite,
        })
    }

    /// Set the RFC 9383 protocol identities (`Context`, `idProver`,
    /// `idVerifier`) used in the transcript `TT`. Default is all-empty. Must be
    /// called before `process_share` for the values to take effect. Both peers
    /// must agree on these out-of-band.
    pub fn set_identities(&mut self, context: &[u8], id_prover: &[u8], id_verifier: &[u8]) {
        self.context = context.to_vec();
        self.id_prover = id_prover.to_vec();
        self.id_verifier = id_verifier.to_vec();
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

        // Derive 2 field-element halves of key material (one each for w0, w1),
        // then reduce mod n. Width tracks the curve (32 / 48 / 66 bytes).
        let fs = self.group.field_size();
        let dk = hitls_crypto::pbkdf2::pbkdf2(password, salt, iterations, 2 * fs)?;
        let w0_raw = BigNum::from_bytes_be(&dk[..fs]);
        let w1_raw = BigNum::from_bytes_be(&dk[fs..2 * fs]);

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
            Spake2Role::Prover => m_point(&self.group, self.suite)?,
            Spake2Role::Verifier => n_point(&self.group, self.suite)?,
        };
        let share = self.group.scalar_mul_add(&x, w0, &blinding_point)?;
        let share_bytes = share.to_uncompressed(&self.group)?;

        self.x_scalar = Some(x);
        self.my_share = Some(share_bytes.clone());
        self.state = State::ShareGenerated;
        Ok(share_bytes)
    }

    /// Test-only: generate the share with a caller-supplied ephemeral scalar
    /// `x` (big-endian), instead of a random one — for byte-exact reproduction
    /// of RFC 9383 test vectors (`shareP = x·G + w0·M`).
    ///
    /// Gated behind the non-default `kat-nonce` feature. A caller-chosen
    /// ephemeral scalar **leaks the password** in a real exchange, so this must
    /// never be used in production.
    #[cfg(feature = "kat-nonce")]
    #[doc(hidden)]
    #[deprecated(note = "test-only: a caller-chosen ephemeral scalar leaks the password")]
    pub fn generate_share_with_scalar(&mut self, x_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.state != State::Setup {
            return Err(CryptoError::DrbgInvalidState);
        }
        let w0 = self.w0.as_ref().ok_or(CryptoError::NullInput)?;
        let n = self.group.order().clone();
        let x = BigNum::from_bytes_be(x_bytes).mod_reduce(&n)?;

        let blinding_point = match self.role {
            Spake2Role::Prover => m_point(&self.group, self.suite)?,
            Spake2Role::Verifier => n_point(&self.group, self.suite)?,
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
                n_point(&self.group, self.suite)?
            }
            Spake2Role::Verifier => {
                // Peer is prover, used M blinding
                m_point(&self.group, self.suite)?
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
        let w0_bytes = w0.to_bytes_be_padded(self.group.field_size())?;

        let mut tt = Vec::new();
        // Context / idProver / idVerifier (RFC 9383 §3.3; default empty).
        encode_len_data(&mut tt, &self.context);
        encode_len_data(&mut tt, &self.id_prover);
        encode_len_data(&mut tt, &self.id_verifier);
        // M
        let m_bytes = m_point(&self.group, self.suite)?.to_uncompressed(&self.group)?;
        encode_len_data(&mut tt, &m_bytes);
        // N
        let n_bytes = n_point(&self.group, self.suite)?.to_uncompressed(&self.group)?;
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

        // RFC 9383 §3.4 key schedule (ciphersuite-parameterised over the hash):
        //   K_main = Hash(TT)
        //   K_confirmP || K_confirmV = HKDF(nil, K_main, "ConfirmationKeys")
        //   K_shared                 = HKDF(nil, K_main, "SharedKey")
        // Each derived key is `hlen` bytes (= the digest output length).
        let hlen = self.suite.hlen();
        let k_main = self.suite.hash(&tt)?;
        let hkdf = Hkdf::new_with_factory(&[], &k_main, self.suite.factory(), hlen)?;
        let confirm_keys = hkdf.expand(b"ConfirmationKeys", 2 * hlen)?;
        let kc_a = confirm_keys[..hlen].to_vec(); // K_confirmP
        let kc_b = confirm_keys[hlen..].to_vec(); // K_confirmV
        let ke = hkdf.expand(b"SharedKey", hlen)?; // K_shared

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
                self.suite.mac(kc_a, peer_share)
            }
            Spake2Role::Verifier => {
                let kc_b = self.kc_b.as_ref().ok_or(CryptoError::NullInput)?;
                self.suite.mac(kc_b, peer_share)
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
                self.suite.mac(kc_b, my_share)?
            }
            Spake2Role::Verifier => {
                // Peer is prover, sent HMAC(KcA, pB) where pB = my_share
                let kc_a = self.kc_a.as_ref().ok_or(CryptoError::NullInput)?;
                let my_share = self.my_share.as_ref().ok_or(CryptoError::NullInput)?;
                self.suite.mac(kc_a, my_share)?
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
        getrandom::fill(&mut buf).map_err(|_| CryptoError::BnRandGenFail)?;
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
        // Every supported suite's M/N must decompress onto its curve.
        for suite in [
            Spake2Suite::P256Sha256,
            Spake2Suite::P384Sha256,
            Spake2Suite::P521Sha512,
        ] {
            let group = EcGroup::new(suite.curve()).unwrap();
            let m = m_point(&group, suite).unwrap();
            let n = n_point(&group, suite).unwrap();
            assert!(m.is_on_curve(&group).unwrap());
            assert!(n.is_on_curve(&group).unwrap());
            assert_ne!(m, n);
        }
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
        assert!(
            matches!(ctx.generate_share(), Err(CryptoError::DrbgInvalidState)),
            "generate_share before setup should return DrbgInvalidState"
        );

        ctx.setup_from_password(b"pw", b"salt", 1000).unwrap();
        let share = ctx.generate_share().unwrap();

        // Should fail: can't process share before generating one (verifier side)
        let mut ctx2 = Spake2Plus::new(Spake2Role::Verifier).unwrap();
        assert!(
            matches!(
                ctx2.process_share(&share),
                Err(CryptoError::DrbgInvalidState)
            ),
            "process_share before generate_share should return DrbgInvalidState"
        );

        // Should fail: can't get confirmation before key derived
        assert!(
            matches!(ctx.get_confirmation(), Err(CryptoError::DrbgInvalidState)),
            "get_confirmation before key derivation should return DrbgInvalidState"
        );
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

        // RFC 9383 §3.4: K_shared = KDF(nil, K_main, "SharedKey") is 32 bytes
        // for the SHA-256 ciphersuite.
        assert_eq!(ke.len(), 32);

        // Confirmations are 32 bytes (HMAC-SHA-256 output)
        let conf = prover.get_confirmation().unwrap();
        assert_eq!(conf.len(), 32);
    }

    #[test]
    fn test_spake2_setup_before_generate() {
        let mut ctx = Spake2Plus::new(Spake2Role::Prover).unwrap();
        // generate_share before setup should fail
        assert!(
            matches!(ctx.generate_share(), Err(CryptoError::DrbgInvalidState)),
            "generate_share before setup should return DrbgInvalidState"
        );
    }

    #[test]
    fn test_spake2_empty_password() {
        let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
        let mut verifier = Spake2Plus::new(Spake2Role::Verifier).unwrap();

        // Empty password is valid
        prover.setup_from_password(b"", b"salt", 1000).unwrap();
        verifier.setup_from_password(b"", b"salt", 1000).unwrap();

        let pa = prover.generate_share().unwrap();
        let pb = verifier.generate_share().unwrap();

        let ke_p = prover.process_share(&pb).unwrap();
        let ke_v = verifier.process_share(&pa).unwrap();
        assert_eq!(ke_p, ke_v);
    }

    #[test]
    fn test_spake2_process_invalid_share() {
        let mut ctx = Spake2Plus::new(Spake2Role::Prover).unwrap();
        ctx.setup_from_password(b"password", b"salt", 1000).unwrap();
        let _share = ctx.generate_share().unwrap();

        // Invalid point encoding (10 random bytes, not a valid P-256 point)
        assert!(
            matches!(
                ctx.process_share(&[0xFF; 10]),
                Err(CryptoError::EccInvalidPublicKey)
            ),
            "process_share with invalid point should return EccInvalidPublicKey"
        );
    }

    // ================================================================
    // Phase T85 — D28 coverage: SPAKE2+ negative paths and state-machine
    // boundaries. Each test pins a functional contract that, if regressed,
    // would let an attacker bypass key confirmation or coerce the protocol
    // into a partial state.
    // ================================================================

    /// Helper: drive a complete prover ↔ verifier exchange to `KeyDerived`.
    fn drive_to_key_derived(password: &[u8]) -> (Spake2Plus, Spake2Plus) {
        let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
        let mut verifier = Spake2Plus::new(Spake2Role::Verifier).unwrap();
        prover.setup_from_password(password, b"salt", 100).unwrap();
        verifier
            .setup_from_password(password, b"salt", 100)
            .unwrap();
        let pa = prover.generate_share().unwrap();
        let pb = verifier.generate_share().unwrap();
        let _ = prover.process_share(&pb).unwrap();
        let _ = verifier.process_share(&pa).unwrap();
        (prover, verifier)
    }

    /// Confirmation verification must reject any single-bit flip in the
    /// confirmation tag. This pins the functional contract on the existing
    /// `subtle::ConstantTimeEq` path in `verify_confirmation`.
    #[test]
    fn test_spake2_verify_confirmation_rejects_tampered() {
        let (prover, verifier) = drive_to_key_derived(b"password");
        let mut conf_a = prover.get_confirmation().unwrap();
        // Sanity: untampered confirmation accepts.
        assert!(verifier.verify_confirmation(&conf_a).unwrap());
        // Flip first byte → must reject.
        conf_a[0] ^= 0x80;
        assert!(!verifier.verify_confirmation(&conf_a).unwrap());
        // Restore + flip last byte → also reject.
        conf_a[0] ^= 0x80;
        let last = conf_a.len() - 1;
        conf_a[last] ^= 0x01;
        assert!(!verifier.verify_confirmation(&conf_a).unwrap());
    }

    /// Length-mismatched confirmation must reject. `subtle::ConstantTimeEq`
    /// only constant-time-compares equal-length slices, so the pre-check
    /// must reject mismatches without panicking.
    #[test]
    fn test_spake2_verify_confirmation_length_mismatch_rejected() {
        let (_prover, verifier) = drive_to_key_derived(b"password");
        // Empty, short, oversized — all must return Ok(false), not panic.
        assert!(!verifier.verify_confirmation(&[]).unwrap());
        assert!(!verifier.verify_confirmation(&[0xAA; 16]).unwrap());
        assert!(!verifier.verify_confirmation(&[0xAA; 64]).unwrap());
    }

    /// State-machine: `get_confirmation` before key derivation must reject.
    /// Without the state guard a caller could read a stale/unset key.
    #[test]
    fn test_spake2_get_confirmation_before_key_derived_rejected() {
        let mut ctx = Spake2Plus::new(Spake2Role::Prover).unwrap();
        ctx.setup_from_password(b"pw", b"salt", 100).unwrap();
        // Idle — must reject.
        assert!(matches!(
            ctx.get_confirmation(),
            Err(CryptoError::DrbgInvalidState)
        ));
        // ShareGenerated — still must reject (peer share not yet processed).
        let _ = ctx.generate_share().unwrap();
        assert!(matches!(
            ctx.get_confirmation(),
            Err(CryptoError::DrbgInvalidState)
        ));
    }

    /// State-machine: `verify_confirmation` before key derivation must reject.
    /// Otherwise an attacker could feed a tag during share-generation and
    /// observe whether the (unset) ke happens to match.
    #[test]
    fn test_spake2_verify_confirmation_before_key_derived_rejected() {
        let mut ctx = Spake2Plus::new(Spake2Role::Verifier).unwrap();
        ctx.setup_from_password(b"pw", b"salt", 100).unwrap();
        assert!(matches!(
            ctx.verify_confirmation(&[0u8; 32]),
            Err(CryptoError::DrbgInvalidState)
        ));
        let _ = ctx.generate_share().unwrap();
        assert!(matches!(
            ctx.verify_confirmation(&[0u8; 32]),
            Err(CryptoError::DrbgInvalidState)
        ));
    }

    /// `peer_share()` accessor lifecycle: `None` before `process_share`,
    /// `Some` after, and stays `Some` through `KeyDerived`.
    #[test]
    fn test_spake2_peer_share_accessor_lifecycle() {
        let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
        prover.setup_from_password(b"pw", b"salt", 100).unwrap();
        assert!(prover.peer_share().is_none(), "Idle: no peer share");
        let _ = prover.generate_share().unwrap();
        assert!(
            prover.peer_share().is_none(),
            "ShareGenerated: still no peer share"
        );

        let mut verifier = Spake2Plus::new(Spake2Role::Verifier).unwrap();
        verifier.setup_from_password(b"pw", b"salt", 100).unwrap();
        let pb = verifier.generate_share().unwrap();
        let _ = prover.process_share(&pb).unwrap();
        assert!(
            prover.peer_share().is_some(),
            "KeyDerived: peer share recorded"
        );
        assert_eq!(
            prover.peer_share().unwrap(),
            pb.as_slice(),
            "peer share must match what was passed in"
        );
    }

    /// State-machine: calling `generate_share` twice must reject. A second
    /// generation would replace `x_scalar` mid-protocol and let the peer's
    /// already-sent share become useless without explicit error.
    #[test]
    fn test_spake2_double_generate_share_rejected() {
        let mut ctx = Spake2Plus::new(Spake2Role::Prover).unwrap();
        ctx.setup_from_password(b"pw", b"salt", 100).unwrap();
        let _ = ctx.generate_share().unwrap();
        assert!(matches!(
            ctx.generate_share(),
            Err(CryptoError::DrbgInvalidState)
        ));
    }

    /// Setup followed by an unrelated method must reject — `generate_share`
    /// requires `setup` first, but `process_share` requires `setup` *and*
    /// `generate_share`. Calling `process_share` straight after `setup`
    /// (skipping share generation) must error rather than panic.
    #[test]
    fn test_spake2_process_share_before_generate_rejected() {
        let mut ctx = Spake2Plus::new(Spake2Role::Prover).unwrap();
        ctx.setup_from_password(b"pw", b"salt", 100).unwrap();
        // Build a syntactically valid peer share via a separate verifier so
        // we exercise the *state* check, not the share-decode path.
        let mut peer = Spake2Plus::new(Spake2Role::Verifier).unwrap();
        peer.setup_from_password(b"pw", b"salt", 100).unwrap();
        let pb = peer.generate_share().unwrap();
        assert!(matches!(
            ctx.process_share(&pb),
            Err(CryptoError::DrbgInvalidState)
        ));
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(3))]

            #[test]
            fn prop_spake2plus_same_password_succeeds(
                password in prop::collection::vec(any::<u8>(), 8..32),
            ) {
                let mut prover = Spake2Plus::new(Spake2Role::Prover).unwrap();
                let mut verifier = Spake2Plus::new(Spake2Role::Verifier).unwrap();

                prover.setup_from_password(&password, b"salt", 100).unwrap();
                verifier.setup_from_password(&password, b"salt", 100).unwrap();

                let pa = prover.generate_share().unwrap();
                let pb = verifier.generate_share().unwrap();

                let ke_p = prover.process_share(&pb).unwrap();
                let ke_v = verifier.process_share(&pa).unwrap();
                prop_assert_eq!(ke_p, ke_v);

                let conf_p = prover.get_confirmation().unwrap();
                let conf_v = verifier.get_confirmation().unwrap();
                prop_assert!(verifier.verify_confirmation(&conf_p).unwrap());
                prop_assert!(prover.verify_confirmation(&conf_v).unwrap());
            }
        }
    }
}
