//! SM9 key exchange (GB/T 38635 §4.4 / GM/T 0044.3-2016).
//!
//! Two-party identity-based key agreement built on the same encryption
//! master key (`Ppub_enc` on G1, user keys `dA / dB` on G2). Both parties
//! agree on a shared symmetric key of caller-chosen length `klen`.
//!
//! The protocol has three round-trip phases:
//!   * Init    — each party draws a private nonce `rX` and publishes
//!     `RX = [rX] · Q_peer` on G1.
//!   * Confirm — each party computes the three pairing values
//!     `g1, g2, g3 ∈ F_{p^12}` from their own nonce + peer `R`,
//!     derives `SK = KDF(g1 || H(g2 || g3 || IDA || IDB || RA || RB))`
//!     and a side-tag `SA` / `SB`.
//!   * Verify  — each party checks the peer's side-tag.
//!
//! The pairing identity `e(Ppub_enc, P2) = e(P1, P2)^ks` and
//! `e(QX, dX) = e(P1, P2)^ks` make `g1_A = g1_B`, `g2_A = g2_B`,
//! `g3_A = g3_B`, so both sides reach the same `SK` and the same inner
//! hash, hence `SA / SB` cross-verify.
//!
//! The `compute_share_key` helper mirrors openHiTLS C's
//! `CRYPT_SM9_ComputeShareKey` EAL wrapper: it runs both sides locally
//! with deterministic nonces seeded from the two user IDs, returning
//! the shared `SK` from the "self" perspective. This is the shape the
//! C SDV `SDV_CRYPTO_SM9_KEYEX_API_TC001` round-trip test consumes.

use hitls_bignum::BigNum;
use hitls_types::CryptoError;

use super::curve;
use super::ecp::EcPointG1;
use super::ecp2::EcPointG2;
use super::fp12::Fp12;
use super::hash;
use super::pairing;
use crate::sm3::Sm3;

/// HID byte for the encryption sub-system (see `extract_user_key`).
const HID_ENC: u8 = 0x03;
/// SM3 digest size.
const SM3_BYTES: usize = 32;
/// Serialised G1 point length used for the `R` exchange.
const RX_BYTES: usize = 64;
/// Serialised Fp12 element length.
const FP12_BYTES: usize = 384;

/// Initiator (`A`) tag prefix for the side-confirmation hash.
const TAG_SA: u8 = 0x82;
/// Responder (`B`) tag prefix for the side-confirmation hash.
const TAG_SB: u8 = 0x83;

/// Compute `RX = [rX] · Q_peer` and serialise it.
///
/// `Q_peer = H1(ID_peer || HID_enc) · P1 + Ppub_enc` is the peer's
/// identity-bound point on G1. `r` is the caller-supplied 32-byte
/// scalar (the random nonce) reduced mod `n`.
fn init_compute_r(
    peer_id: &[u8],
    r_bytes: &[u8; 32],
    master_pub_enc: &[u8],
) -> Result<(BigNum, [u8; RX_BYTES]), CryptoError> {
    let n = curve::order();
    let r = BigNum::from_bytes_be(r_bytes).mod_reduce(&n)?;
    if r.is_zero() {
        return Err(CryptoError::BnRandGenFail);
    }

    let ppub = EcPointG1::from_bytes(master_pub_enc)?;

    // Q_peer = H1(ID_peer || HID_enc) · P1 + Ppub
    let mut h1_input = Vec::with_capacity(peer_id.len() + 1);
    h1_input.extend_from_slice(peer_id);
    h1_input.push(HID_ENC);
    let h1_val = hash::h1(&h1_input, 0x01)?;

    let p1 = EcPointG1::generator();
    let h1_p1 = p1.scalar_mul(&h1_val)?;
    let q_peer = h1_p1.add(&ppub)?;

    // R = [r] · Q_peer
    let r_pt = q_peer.scalar_mul(&r)?;
    let r_vec = r_pt.to_bytes()?;
    let mut r_arr = [0u8; RX_BYTES];
    r_arr.copy_from_slice(&r_vec);

    Ok((r, r_arr))
}

/// Initiator's first message: returns the reduced `rA` and `RA = [rA] · QB`.
pub(crate) fn key_exchange_init_a(
    peer_id_b: &[u8],
    r_a_bytes: &[u8; 32],
    master_pub_enc: &[u8],
) -> Result<(BigNum, [u8; RX_BYTES]), CryptoError> {
    init_compute_r(peer_id_b, r_a_bytes, master_pub_enc)
}

/// Responder's first message: returns the reduced `rB` and `RB = [rB] · QA`.
pub(crate) fn key_exchange_init_b(
    peer_id_a: &[u8],
    r_b_bytes: &[u8; 32],
    master_pub_enc: &[u8],
) -> Result<(BigNum, [u8; RX_BYTES]), CryptoError> {
    init_compute_r(peer_id_a, r_b_bytes, master_pub_enc)
}

/// Shared sub-routine that computes the inner hash, `SK`, and side-tag.
///
/// Both A and B feed the same `(g1, g2, g3)` tuple in the SAME slot
/// (g2 in g2-slot, g3 in g3-slot, etc.) — caller is responsible for
/// computing the pairings appropriate to its role.
fn confirm_finalise(
    g1: &Fp12,
    g2: &Fp12,
    g3: &Fp12,
    id_a: &[u8],
    id_b: &[u8],
    ra: &[u8; RX_BYTES],
    rb: &[u8; RX_BYTES],
    klen: usize,
    self_tag: u8,
) -> Result<(Vec<u8>, [u8; SM3_BYTES]), CryptoError> {
    let g1_bytes = fp12_to_bytes(g1);
    let g2_bytes = fp12_to_bytes(g2);
    let g3_bytes = fp12_to_bytes(g3);

    // inner_hash = SM3(g2 || g3 || IDA || IDB || RA || RB)
    let inner_hash = {
        let mut h = Sm3::new();
        h.update(&g2_bytes)?;
        h.update(&g3_bytes)?;
        h.update(id_a)?;
        h.update(id_b)?;
        h.update(ra)?;
        h.update(rb)?;
        h.finish()?
    };

    // Z = g1 || inner_hash; SK = KDF(Z, klen)
    let mut z = Vec::with_capacity(FP12_BYTES + SM3_BYTES);
    z.extend_from_slice(&g1_bytes);
    z.extend_from_slice(&inner_hash);
    let sk = hash::kdf(&z, klen)?;

    // S_self = SM3(tag || g1 || inner_hash)
    let s_self = {
        let mut h = Sm3::new();
        h.update(&[self_tag])?;
        h.update(&g1_bytes)?;
        h.update(&inner_hash)?;
        h.finish()?
    };

    Ok((sk, s_self))
}

/// Initiator's `Confirm`: returns `(SK_A, S_A)`.
///
/// `r_a` must be the same (mod-n-reduced) scalar produced by
/// `key_exchange_init_a`; `r_b_bytes_g1` is the peer's RB serialisation.
/// `user_key_a` is the initiator's encryption user private key
/// (`dA`, 128 bytes on G2).
pub(crate) fn key_exchange_confirm_a(
    id_a: &[u8],
    id_b: &[u8],
    r_a: &BigNum,
    ra_bytes: &[u8; RX_BYTES],
    rb_bytes: &[u8; RX_BYTES],
    user_key_a: &[u8],
    master_pub_enc: &[u8],
    klen: usize,
) -> Result<(Vec<u8>, [u8; SM3_BYTES]), CryptoError> {
    let ppub = EcPointG1::from_bytes(master_pub_enc)?;
    let p2 = EcPointG2::generator();
    let da = EcPointG2::from_bytes(user_key_a)?;
    let rb_pt = EcPointG1::from_bytes(rb_bytes)?;

    // g1 = e(Ppub, P2)^rA
    let g_base = pairing::pairing(&ppub, &p2)?;
    let g1 = g_base.pow(r_a)?;

    // g2 = e(RB, dA)
    let g2 = pairing::pairing(&rb_pt, &da)?;

    // g3 = g2^rA
    let g3 = g2.pow(r_a)?;

    confirm_finalise(&g1, &g2, &g3, id_a, id_b, ra_bytes, rb_bytes, klen, TAG_SA)
}

/// Responder's `Confirm`: returns `(SK_B, S_B)`.
///
/// `user_key_b` is the responder's encryption user private key
/// (`dB`, 128 bytes on G2). The argument order of `id_a/id_b/ra/rb`
/// matches the initiator (the inner hash uses IDA, IDB, RA, RB in that
/// fixed order regardless of which side is computing it).
pub(crate) fn key_exchange_confirm_b(
    id_a: &[u8],
    id_b: &[u8],
    r_b: &BigNum,
    ra_bytes: &[u8; RX_BYTES],
    rb_bytes: &[u8; RX_BYTES],
    user_key_b: &[u8],
    master_pub_enc: &[u8],
    klen: usize,
) -> Result<(Vec<u8>, [u8; SM3_BYTES]), CryptoError> {
    let ppub = EcPointG1::from_bytes(master_pub_enc)?;
    let p2 = EcPointG2::generator();
    let db = EcPointG2::from_bytes(user_key_b)?;
    let ra_pt = EcPointG1::from_bytes(ra_bytes)?;

    // g1 = e(RA, dB)
    let g1 = pairing::pairing(&ra_pt, &db)?;

    // g2 = e(Ppub, P2)^rB
    let g_base = pairing::pairing(&ppub, &p2)?;
    let g2 = g_base.pow(r_b)?;

    // g3 = g1^rB
    let g3 = g1.pow(r_b)?;

    confirm_finalise(&g1, &g2, &g3, id_a, id_b, ra_bytes, rb_bytes, klen, TAG_SB)
}

/// Verify a peer side-tag using already-computed inner state.
///
/// `g1 || inner_hash` is the same `Z` the local `Confirm` step built;
/// `expected_tag` is `TAG_SA` when A is verifying B's `SB` and vice
/// versa. Returns `true` iff the recomputed `S = SM3(tag || Z)` matches
/// `peer_s`.
fn verify_side_tag(
    g1_bytes: &[u8],
    inner_hash: &[u8],
    peer_tag: u8,
    peer_s: &[u8; SM3_BYTES],
) -> Result<bool, CryptoError> {
    let expected = {
        let mut h = Sm3::new();
        h.update(&[peer_tag])?;
        h.update(g1_bytes)?;
        h.update(inner_hash)?;
        h.finish()?
    };
    use subtle::ConstantTimeEq;
    Ok(bool::from(expected.as_slice().ct_eq(peer_s)))
}

/// One-shot wrapper that runs both halves of the exchange locally with
/// deterministic nonces seeded from the two user IDs, returning the
/// shared key from the "self" perspective. Mirrors openHiTLS C's
/// `CRYPT_SM9_ComputeShareKey` (used by `SDV_CRYPTO_SM9_KEYEX_API_TC001`).
///
/// The initiator is whichever side has the lexicographically smaller
/// user ID — that side's deterministic nonce is `rA = SM3(id_init ||
/// id_resp || 'A')` and the responder's is `rB = SM3(id_init || id_resp
/// || 'B')`. Both nonces are reduced mod `n` inside `init`.
///
/// Production callers wanting non-test key agreement should drive the
/// `key_exchange_init_a/b` + `key_exchange_confirm_a/b` primitives
/// directly with cryptographically random nonces and a real network
/// exchange of `RA / RB`.
pub(crate) fn compute_share_key(
    self_user_id: &[u8],
    self_user_key: &[u8],
    peer_user_id: &[u8],
    peer_user_key: &[u8],
    master_pub_enc: &[u8],
    klen: usize,
) -> Result<Vec<u8>, CryptoError> {
    if klen == 0 {
        return Err(CryptoError::InvalidArg(""));
    }

    // Decide initiator role by lex-comparing user IDs (matches the C
    // EAL wrapper). `self_is_initiator == true` ⇔ self_id < peer_id.
    let self_is_initiator = match self_user_id.cmp(peer_user_id) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => {
            // Self and peer cannot be the same identity (shared key with
            // yourself is undefined).
            return Err(CryptoError::InvalidArg(""));
        }
    };

    let (id_a, id_b, dek_a, dek_b) = if self_is_initiator {
        (self_user_id, peer_user_id, self_user_key, peer_user_key)
    } else {
        (peer_user_id, self_user_id, peer_user_key, self_user_key)
    };

    let rand_a = derive_nonce(id_a, id_b, b'A')?;
    let rand_b = derive_nonce(id_a, id_b, b'B')?;

    let (r_a, ra_bytes) = key_exchange_init_a(id_b, &rand_a, master_pub_enc)?;
    let (r_b, rb_bytes) = key_exchange_init_b(id_a, &rand_b, master_pub_enc)?;

    let (sk, _s_self) = if self_is_initiator {
        key_exchange_confirm_a(
            id_a,
            id_b,
            &r_a,
            &ra_bytes,
            &rb_bytes,
            dek_a,
            master_pub_enc,
            klen,
        )?
    } else {
        key_exchange_confirm_b(
            id_a,
            id_b,
            &r_b,
            &ra_bytes,
            &rb_bytes,
            dek_b,
            master_pub_enc,
            klen,
        )?
    };

    Ok(sk)
}

/// `SM3(id_a || id_b || tag)` truncated to 32 bytes — exactly matches
/// the C EAL wrapper's deterministic seed scheme. `tag` is `b'A'` for
/// the initiator nonce and `b'B'` for the responder nonce.
fn derive_nonce(id_init: &[u8], id_resp: &[u8], tag: u8) -> Result<[u8; 32], CryptoError> {
    let mut h = Sm3::new();
    h.update(id_init)?;
    h.update(id_resp)?;
    h.update(&[tag])?;
    h.finish()
}

/// Serialise Fp12 (12 Fp coordinates, 32 BE bytes each = 384 bytes).
/// Kept local to this module to avoid leaking a private helper from
/// `alg.rs`; the layout matches the C `SM9_Fp12_WriteBytes`.
fn fp12_to_bytes(f: &Fp12) -> Vec<u8> {
    let mut out = Vec::with_capacity(FP12_BYTES);
    out.extend_from_slice(&f.c0.c0.c0.to_bytes_be());
    out.extend_from_slice(&f.c0.c0.c1.to_bytes_be());
    out.extend_from_slice(&f.c0.c1.c0.to_bytes_be());
    out.extend_from_slice(&f.c0.c1.c1.to_bytes_be());
    out.extend_from_slice(&f.c1.c0.c0.to_bytes_be());
    out.extend_from_slice(&f.c1.c0.c1.to_bytes_be());
    out.extend_from_slice(&f.c1.c1.c0.to_bytes_be());
    out.extend_from_slice(&f.c1.c1.c1.to_bytes_be());
    out.extend_from_slice(&f.c2.c0.c0.to_bytes_be());
    out.extend_from_slice(&f.c2.c0.c1.to_bytes_be());
    out.extend_from_slice(&f.c2.c1.c0.to_bytes_be());
    out.extend_from_slice(&f.c2.c1.c1.to_bytes_be());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm9::{Sm9KeyType, Sm9MasterKey};

    /// Public-API round trip. Mirrors `SDV_CRYPTO_SM9_KEYEX_API_TC001`:
    /// both sides hit `compute_share_key` and must agree, and `klen`
    /// shorter / longer than the SM3 block boundary must still succeed.
    #[test]
    fn test_sm9_key_exchange_roundtrip_default_klen() {
        let master = Sm9MasterKey::generate(Sm9KeyType::Encrypt).unwrap();
        let alice = master.extract_user_key(b"Alice").unwrap();
        let bob = master.extract_user_key(b"Bob").unwrap();

        let sk_a = compute_share_key(
            alice.user_id(),
            &alice.private_key,
            bob.user_id(),
            &bob.private_key,
            master.master_public_key(),
            32,
        )
        .unwrap();
        let sk_b = compute_share_key(
            bob.user_id(),
            &bob.private_key,
            alice.user_id(),
            &alice.private_key,
            master.master_public_key(),
            32,
        )
        .unwrap();

        assert_eq!(sk_a.len(), 32);
        assert_eq!(sk_a, sk_b);
    }

    #[test]
    fn test_sm9_key_exchange_long_klen_crosses_sm3_boundary() {
        let master = Sm9MasterKey::generate(Sm9KeyType::Encrypt).unwrap();
        let alice = master.extract_user_key(b"Alice").unwrap();
        let bob = master.extract_user_key(b"Bob").unwrap();

        // 63 bytes: forces both a full 32-byte SM3 block and a partial
        // tail (rcnt=1, rbit=31) — matches the SDV's `SK_Long` case.
        let sk_a = compute_share_key(
            alice.user_id(),
            &alice.private_key,
            bob.user_id(),
            &bob.private_key,
            master.master_public_key(),
            63,
        )
        .unwrap();
        let sk_b = compute_share_key(
            bob.user_id(),
            &bob.private_key,
            alice.user_id(),
            &alice.private_key,
            master.master_public_key(),
            63,
        )
        .unwrap();

        assert_eq!(sk_a.len(), 63);
        assert_eq!(sk_a, sk_b);
    }

    #[test]
    fn test_sm9_key_exchange_short_klen() {
        let master = Sm9MasterKey::generate(Sm9KeyType::Encrypt).unwrap();
        let alice = master.extract_user_key(b"Alice").unwrap();
        let bob = master.extract_user_key(b"Bob").unwrap();

        // 15 bytes: no full SM3 block, only the partial tail (rcnt=0,
        // rbit=15) — matches the SDV's `SK_Short` case.
        let sk_a = compute_share_key(
            alice.user_id(),
            &alice.private_key,
            bob.user_id(),
            &bob.private_key,
            master.master_public_key(),
            15,
        )
        .unwrap();
        let sk_b = compute_share_key(
            bob.user_id(),
            &bob.private_key,
            alice.user_id(),
            &alice.private_key,
            master.master_public_key(),
            15,
        )
        .unwrap();

        assert_eq!(sk_a.len(), 15);
        assert_eq!(sk_a, sk_b);
    }

    #[test]
    fn test_sm9_key_exchange_self_rejected() {
        let master = Sm9MasterKey::generate(Sm9KeyType::Encrypt).unwrap();
        let alice = master.extract_user_key(b"Alice").unwrap();

        let err = compute_share_key(
            alice.user_id(),
            &alice.private_key,
            alice.user_id(),
            &alice.private_key,
            master.master_public_key(),
            32,
        );
        assert!(err.is_err(), "exchanging with yourself must be refused");
    }

    #[test]
    fn test_sm9_key_exchange_zero_klen_rejected() {
        let master = Sm9MasterKey::generate(Sm9KeyType::Encrypt).unwrap();
        let alice = master.extract_user_key(b"Alice").unwrap();
        let bob = master.extract_user_key(b"Bob").unwrap();

        let err = compute_share_key(
            alice.user_id(),
            &alice.private_key,
            bob.user_id(),
            &bob.private_key,
            master.master_public_key(),
            0,
        );
        assert!(err.is_err(), "klen=0 must be refused");
    }

    /// Drive the 3-phase primitives directly: A and B run Init + Confirm
    /// + cross-verify side tags. Exercises `key_exchange_confirm_a/b`
    ///   and `verify_side_tag` outside the one-shot wrapper.
    #[test]
    fn test_sm9_key_exchange_three_phase_with_side_tags() {
        let master = Sm9MasterKey::generate(Sm9KeyType::Encrypt).unwrap();
        let alice = master.extract_user_key(b"Alice").unwrap();
        let bob = master.extract_user_key(b"Bob").unwrap();
        let mpk = master.master_public_key();

        let r_a_bytes: [u8; 32] = [
            0x5F, 0xE1, 0x3F, 0x9D, 0x05, 0xC1, 0x4D, 0xA7, 0x9C, 0x6E, 0xF6, 0x57, 0x21, 0x6F,
            0x06, 0xC4, 0xC2, 0x9C, 0x0B, 0x42, 0x9C, 0x18, 0x09, 0xB8, 0x12, 0x14, 0xFE, 0xBD,
            0xC7, 0xE1, 0x4E, 0xB1,
        ];
        let r_b_bytes: [u8; 32] = [
            0x33, 0xFE, 0x21, 0x94, 0x05, 0xAC, 0x97, 0x96, 0x91, 0x52, 0x29, 0x66, 0xE5, 0x6B,
            0x05, 0xB2, 0x86, 0x83, 0x3E, 0xB9, 0xAC, 0x6E, 0xD2, 0x5D, 0xA4, 0xF6, 0x4C, 0xF1,
            0x9E, 0x05, 0xC6, 0x21,
        ];

        let (r_a, ra_bytes) = key_exchange_init_a(bob.user_id(), &r_a_bytes, mpk).unwrap();
        let (r_b, rb_bytes) = key_exchange_init_b(alice.user_id(), &r_b_bytes, mpk).unwrap();

        let klen = 32;
        let (sk_a, s_a) = key_exchange_confirm_a(
            alice.user_id(),
            bob.user_id(),
            &r_a,
            &ra_bytes,
            &rb_bytes,
            &alice.private_key,
            mpk,
            klen,
        )
        .unwrap();
        let (sk_b, s_b) = key_exchange_confirm_b(
            alice.user_id(),
            bob.user_id(),
            &r_b,
            &ra_bytes,
            &rb_bytes,
            &bob.private_key,
            mpk,
            klen,
        )
        .unwrap();

        assert_eq!(sk_a, sk_b, "SK_A must equal SK_B");

        // Re-derive the (g1 || inner_hash) bytes from A's perspective
        // to drive `verify_side_tag` — replicate just enough of A's
        // Confirm to feed the verifier (the verifier itself is the
        // smallest surface; the alternative is exposing the inner hash
        // up the call chain, which would leak more API than needed).
        let ppub = EcPointG1::from_bytes(mpk).unwrap();
        let p2 = EcPointG2::generator();
        let g_base = pairing::pairing(&ppub, &p2).unwrap();
        let g1_a = g_base.pow(&r_a).unwrap();
        let rb_pt = EcPointG1::from_bytes(&rb_bytes).unwrap();
        let da = EcPointG2::from_bytes(&alice.private_key).unwrap();
        let g2_a = pairing::pairing(&rb_pt, &da).unwrap();
        let g3_a = g2_a.pow(&r_a).unwrap();
        let g1_a_bytes = fp12_to_bytes(&g1_a);
        let inner_hash_a = {
            let mut h = Sm3::new();
            h.update(&fp12_to_bytes(&g2_a)).unwrap();
            h.update(&fp12_to_bytes(&g3_a)).unwrap();
            h.update(alice.user_id()).unwrap();
            h.update(bob.user_id()).unwrap();
            h.update(&ra_bytes).unwrap();
            h.update(&rb_bytes).unwrap();
            h.finish().unwrap()
        };
        assert!(verify_side_tag(&g1_a_bytes, &inner_hash_a, TAG_SB, &s_b).unwrap());
        assert!(verify_side_tag(&g1_a_bytes, &inner_hash_a, TAG_SA, &s_a).unwrap());

        // Tamper-detection: a corrupted peer side-tag must be rejected.
        let mut bad_s_b = s_b;
        bad_s_b[0] ^= 0xFF;
        assert!(!verify_side_tag(&g1_a_bytes, &inner_hash_a, TAG_SB, &bad_s_b).unwrap());
    }
}
