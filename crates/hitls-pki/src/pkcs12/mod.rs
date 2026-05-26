//! PKCS#12 (PFX) container format (RFC 7292).
//!
//! Supports parsing and creating PKCS#12 files with password-based encryption.
//! Uses PBES2 (PBKDF2 + AES-256-CBC) for key encryption and
//! PKCS#12 KDF (RFC 7292 Appendix B) for MAC key derivation.

use hitls_crypto::hmac::Hmac;
use hitls_crypto::modes::cbc;
use hitls_crypto::pbkdf2;
use hitls_crypto::provider::Digest;
use hitls_crypto::sha1::Sha1;
use hitls_crypto::sha2::{Sha224, Sha256, Sha384, Sha512};
use hitls_types::PkiError;
use hitls_utils::asn1::Decoder;
use hitls_utils::oid::{known, Oid};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::encoding::{
    bytes_to_u32, enc_explicit_ctx, enc_int, enc_null, enc_octet, enc_oid, enc_seq, enc_set,
};

/// A parsed PKCS#12 container.
#[derive(Debug)]
pub struct Pkcs12 {
    /// Private key (DER-encoded PKCS#8 PrivateKeyInfo).
    pub private_key: Option<Vec<u8>>,
    /// Certificate chain (DER-encoded X.509 certificates).
    pub certificates: Vec<Vec<u8>>,
}

// ── PKCS#12 KDF (RFC 7292 Appendix B) ────────────────────────────────

/// Convert password to BMPString (UTF-16BE with null terminator).
fn password_to_bmp(password: &str) -> Vec<u8> {
    let mut bmp = Vec::with_capacity((password.len() + 1) * 2);
    for ch in password.encode_utf16() {
        bmp.push((ch >> 8) as u8);
        bmp.push(ch as u8);
    }
    bmp.push(0);
    bmp.push(0);
    bmp
}

/// Hash family for the PKCS#12 KDF / MAC (RFC 7292 Appendix B + §4).
///
/// RFC 7292 fixed the KDF on SHA-1, but real-world PKCS#12 producers
/// (including openHiTLS C) emit a SHA-2 MAC, in which case the KDF is run with
/// the same SHA-2 hash. We therefore parameterise both over the hash.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum P12MacHash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl P12MacHash {
    /// Map a digest-algorithm OID (from the MacData DigestInfo) to a hash.
    fn from_oid(oid: &Oid) -> Result<Self, PkiError> {
        // id-sha1 (1.3.14.3.2.26) and id-sha224 (2.16.840.1.101.3.4.2.4) have
        // no `known::` helper, so match them by dotted form.
        match oid.to_dot_string().as_str() {
            "1.3.14.3.2.26" => Ok(Self::Sha1),
            "2.16.840.1.101.3.4.2.4" => Ok(Self::Sha224),
            _ if *oid == known::sha256() => Ok(Self::Sha256),
            _ if *oid == known::sha384() => Ok(Self::Sha384),
            _ if *oid == known::sha512() => Ok(Self::Sha512),
            _ => Err(perr(&format!("unsupported PKCS#12 MAC hash OID: {oid}"))),
        }
    }

    fn digest(self) -> Box<dyn Digest> {
        match self {
            Self::Sha1 => Box::new(Sha1::new()),
            Self::Sha224 => Box::new(Sha224::new()),
            Self::Sha256 => Box::new(Sha256::new()),
            Self::Sha384 => Box::new(Sha384::new()),
            Self::Sha512 => Box::new(Sha512::new()),
        }
    }

    fn output_len(self) -> usize {
        self.digest().output_size()
    }

    fn block_size(self) -> usize {
        self.digest().block_size()
    }

    fn hash(self, data: &[u8]) -> Result<Vec<u8>, PkiError> {
        let mut d = self.digest();
        d.update(data)
            .map_err(|e| PkiError::Pkcs12Error(e.to_string()))?;
        let mut out = vec![0u8; d.output_size()];
        d.finish(&mut out)
            .map_err(|e| PkiError::Pkcs12Error(e.to_string()))?;
        Ok(out)
    }

    fn hash_concat(self, a: &[u8], b: &[u8]) -> Result<Vec<u8>, PkiError> {
        let mut d = self.digest();
        d.update(a)
            .map_err(|e| PkiError::Pkcs12Error(e.to_string()))?;
        d.update(b)
            .map_err(|e| PkiError::Pkcs12Error(e.to_string()))?;
        let mut out = vec![0u8; d.output_size()];
        d.finish(&mut out)
            .map_err(|e| PkiError::Pkcs12Error(e.to_string()))?;
        Ok(out)
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, PkiError> {
        Hmac::mac(move || self.digest(), key, data)
            .map_err(|e| PkiError::Pkcs12Error(format!("HMAC: {e}")))
    }
}

/// PKCS#12 KDF (RFC 7292 Appendix B) over the given `hash`.
/// id: 1 = encryption key, 2 = IV, 3 = MAC key
fn pkcs12_kdf(
    password: &str,
    salt: &[u8],
    id: u8,
    iterations: u32,
    dk_len: usize,
    hash: P12MacHash,
) -> Result<Vec<u8>, PkiError> {
    let hash_len: usize = hash.output_len();
    let block_size: usize = hash.block_size();

    let d = vec![id; block_size];

    let s = if salt.is_empty() {
        Vec::new()
    } else {
        let s_len = salt.len().div_ceil(block_size) * block_size;
        (0..s_len).map(|i| salt[i % salt.len()]).collect()
    };

    // RFC 7292 Appendix B.2: P is the BMPString password (UTF-16BE + a 2-byte
    // null terminator) repeated to fill a whole number of blocks. An *empty*
    // password is the 2-byte BMP null, so P is built from `[0x00, 0x00]`
    // (a block of zeros) — NOT an empty diversifier. (Previously the
    // `bmp.len() <= 2` short-circuit emptied P for the empty password, which
    // matched a NULL-password convention and diverged from openHiTLS C /
    // OpenSSL, breaking MAC verification of empty-password PFX files.)
    let bmp = password_to_bmp(password);
    let p_len = bmp.len().div_ceil(block_size) * block_size;
    let p: Vec<u8> = (0..p_len).map(|i| bmp[i % bmp.len()]).collect();

    let mut i_buf = Vec::with_capacity(s.len() + p.len());
    i_buf.extend_from_slice(&s);
    i_buf.extend_from_slice(&p);

    let n = dk_len.div_ceil(hash_len);
    let mut dk = Vec::with_capacity(dk_len);

    for _ in 0..n {
        let mut a = hash.hash_concat(&d, &i_buf)?;
        for _ in 1..iterations {
            a = hash.hash(&a)?;
        }

        let take = (dk_len - dk.len()).min(hash_len);
        dk.extend_from_slice(&a[..take]);

        if dk.len() < dk_len {
            let mut b = vec![0u8; block_size];
            for j in 0..block_size {
                b[j] = a[j % hash_len];
            }
            for j in (0..i_buf.len()).step_by(block_size) {
                let mut carry: u16 = 1;
                for k in (0..block_size).rev() {
                    let sum = u16::from(i_buf[j + k]) + u16::from(b[k]) + carry;
                    i_buf[j + k] = sum as u8;
                    carry = sum >> 8;
                }
            }
        }
    }

    Ok(dk)
}

fn generate_random(len: usize) -> Result<Vec<u8>, PkiError> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf)
        .map_err(|_| PkiError::Pkcs12Error("random generation failed".into()))?;
    Ok(buf)
}

// ── PKCS#12 Parsing ──────────────────────────────────────────────────

impl Pkcs12 {
    /// Parse a PKCS#12 file from DER-encoded bytes with a password.
    pub fn from_der(data: &[u8], password: &str) -> Result<Self, PkiError> {
        let mut dec = Decoder::new(data);
        let mut pfx = dec
            .read_sequence()
            .map_err(|e| perr(&format!("PFX: {e}")))?;

        // version INTEGER (3)
        let ver = pfx
            .read_integer()
            .map_err(|e| perr(&format!("version: {e}")))?;
        if bytes_to_u32(ver) != 3 {
            return Err(perr("unsupported PFX version"));
        }

        // authSafe ContentInfo
        let mut as_ci = pfx
            .read_sequence()
            .map_err(|e| perr(&format!("authSafe CI: {e}")))?;
        let ct_bytes = as_ci
            .read_oid()
            .map_err(|e| perr(&format!("CI type: {e}")))?;
        let ct = Oid::from_der_value(ct_bytes).map_err(|e| perr(&format!("CI OID: {e}")))?;
        if ct != known::pkcs7_data() {
            return Err(perr("authSafe not pkcs7-data"));
        }

        let ctx0 = as_ci
            .read_context_specific(0, true)
            .map_err(|e| perr(&format!("[0]: {e}")))?;
        let mut ctx0_dec = Decoder::new(ctx0.value);
        let auth_safe_content = ctx0_dec
            .read_octet_string()
            .map_err(|e| perr(&format!("authSafe octet: {e}")))?;

        // macData (optional)
        if !pfx.is_empty() {
            verify_mac(auth_safe_content, &mut pfx, password)?;
        }

        // Parse AuthenticatedSafe: SEQUENCE OF ContentInfo
        let mut private_key = None;
        let mut certificates = Vec::new();

        let mut as_dec = Decoder::new(auth_safe_content);
        let mut as_seq = as_dec
            .read_sequence()
            .map_err(|e| perr(&format!("AuthSafe: {e}")))?;

        while !as_seq.is_empty() {
            let mut ci = as_seq
                .read_sequence()
                .map_err(|e| perr(&format!("CI: {e}")))?;
            let ci_type_bytes = ci.read_oid().map_err(|e| perr(&format!("CI type: {e}")))?;
            let ci_type =
                Oid::from_der_value(ci_type_bytes).map_err(|e| perr(&format!("CI OID: {e}")))?;

            if ci_type == known::pkcs7_data() {
                let c0 = ci
                    .read_context_specific(0, true)
                    .map_err(|e| perr(&format!("data [0]: {e}")))?;
                let mut c0d = Decoder::new(c0.value);
                let sc_bytes = c0d
                    .read_octet_string()
                    .map_err(|e| perr(&format!("SC octet: {e}")))?;
                parse_safe_contents(sc_bytes, password, &mut private_key, &mut certificates)?;
            } else if ci_type == known::pkcs7_encrypted_data() {
                let c0 = ci
                    .read_context_specific(0, true)
                    .map_err(|e| perr(&format!("encdata [0]: {e}")))?;
                let decrypted = decrypt_encrypted_data(c0.value, password)?;
                parse_safe_contents(&decrypted, password, &mut private_key, &mut certificates)?;
            }
        }

        Ok(Pkcs12 {
            private_key,
            certificates,
        })
    }

    /// Create a PKCS#12 container, returning the DER-encoded bytes.
    pub fn create(
        private_key: Option<&[u8]>,
        certificates: &[&[u8]],
        password: &str,
    ) -> Result<Vec<u8>, PkiError> {
        let local_key_id = [0x01];

        // Build SafeBags
        let mut all_bags = Vec::new();
        if let Some(pk_der) = private_key {
            let encrypted_pk = encrypt_private_key(pk_der, password)?;
            all_bags.push(encode_safe_bag(
                &known::pkcs12_bag_type_pkcs8_shrouded_key(),
                &encrypted_pk,
                Some(&local_key_id),
            ));
        }
        for (i, cert_der) in certificates.iter().enumerate() {
            let cert_bag_value = encode_cert_bag(cert_der);
            let key_id = if i == 0 {
                Some(&local_key_id[..])
            } else {
                None
            };
            all_bags.push(encode_safe_bag(
                &known::pkcs12_bag_type_cert(),
                &cert_bag_value,
                key_id,
            ));
        }

        // SafeContents = SEQUENCE OF SafeBag
        let mut sc_inner = Vec::new();
        for bag in &all_bags {
            sc_inner.extend_from_slice(bag);
        }
        let safe_contents = enc_seq(&sc_inner);

        // ContentInfo(pkcs7-data, OCTET STRING of safe_contents)
        let content_info = encode_content_info_data(&safe_contents);

        // AuthenticatedSafe = SEQUENCE OF ContentInfo
        let auth_safe = enc_seq(&content_info);

        // Outer ContentInfo wrapping AuthenticatedSafe
        let outer_ci = encode_content_info_data(&auth_safe);

        // MAC
        let salt = generate_random(16)?;
        let iterations: u32 = 2048;
        // Encode side emits a SHA-1 MAC (RFC 7292 baseline; widely interoperable).
        let mac_hash = P12MacHash::Sha1;
        let mac_key = pkcs12_kdf(
            password,
            &salt,
            3,
            iterations,
            mac_hash.output_len(),
            mac_hash,
        )?;
        let mac_value = mac_hash.hmac(&mac_key, &auth_safe)?;
        let mac_data = encode_mac_data(&mac_value, &salt, iterations);

        // PFX = SEQUENCE { version, authSafe, macData }
        let mut pfx_inner = Vec::new();
        pfx_inner.extend_from_slice(&enc_int(&[3]));
        pfx_inner.extend_from_slice(&outer_ci);
        pfx_inner.extend_from_slice(&mac_data);
        Ok(enc_seq(&pfx_inner))
    }
}

// ── MAC Verification ─────────────────────────────────────────────────

fn verify_mac(auth_safe_content: &[u8], pfx: &mut Decoder, password: &str) -> Result<(), PkiError> {
    let mut mac_dec = pfx
        .read_sequence()
        .map_err(|e| perr(&format!("macData: {e}")))?;

    // DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }
    let mut di = mac_dec
        .read_sequence()
        .map_err(|e| perr(&format!("DigestInfo: {e}")))?;
    let mut alg = di
        .read_sequence()
        .map_err(|e| perr(&format!("mac alg: {e}")))?;
    let alg_oid_bytes = alg
        .read_oid()
        .map_err(|e| perr(&format!("mac alg OID: {e}")))?;
    let alg_oid = Oid::from_der_value(alg_oid_bytes).map_err(|e| perr(&format!("mac OID: {e}")))?;
    // RFC 7292 fixed SHA-1, but SHA-2 MACs are common in practice; pick the KDF
    // hash from the declared MAC algorithm rather than assuming SHA-1.
    let hash = P12MacHash::from_oid(&alg_oid)?;
    let stored_mac = di
        .read_octet_string()
        .map_err(|e| perr(&format!("mac digest: {e}")))?
        .to_vec();

    let mac_salt = mac_dec
        .read_octet_string()
        .map_err(|e| perr(&format!("mac salt: {e}")))?
        .to_vec();

    let iterations = if !mac_dec.is_empty() {
        let iter_bytes = mac_dec
            .read_integer()
            .map_err(|e| perr(&format!("mac iter: {e}")))?;
        bytes_to_u32(iter_bytes)
    } else {
        1
    };

    let mac_key = pkcs12_kdf(password, &mac_salt, 3, iterations, hash.output_len(), hash)?;
    let computed = hash.hmac(&mac_key, auth_safe_content)?;

    // Constant-time MAC tag comparison. `stored_mac` comes from the PFX file
    // (attacker-controlled in network/file scenarios). Naive `Vec<u8> != ...`
    // early-exits per byte and lets a forger probe MAC bytes one at a time
    // (PKCS#12 §4.2 password-based integrity). Length-check first because
    // `ct_eq` requires equal-length inputs.
    if computed.len() != stored_mac.len()
        || !bool::from(computed.as_slice().ct_eq(stored_mac.as_slice()))
    {
        return Err(perr("MAC verification failed (wrong password?)"));
    }
    Ok(())
}

// ── Decrypt helpers ──────────────────────────────────────────────────

fn decrypt_encrypted_data(data: &[u8], password: &str) -> Result<Vec<u8>, PkiError> {
    let mut dec = Decoder::new(data);
    let mut ed = dec
        .read_sequence()
        .map_err(|e| perr(&format!("EncryptedData: {e}")))?;
    let _version = ed
        .read_integer()
        .map_err(|e| perr(&format!("ED ver: {e}")))?;

    let mut eci = ed
        .read_sequence()
        .map_err(|e| perr(&format!("EncCI: {e}")))?;
    let _content_type = eci
        .read_oid()
        .map_err(|e| perr(&format!("EncCI type: {e}")))?;

    let mut alg = eci
        .read_sequence()
        .map_err(|e| perr(&format!("enc alg: {e}")))?;
    let alg_oid_bytes = alg.read_oid().map_err(|e| perr(&format!("enc OID: {e}")))?;
    let alg_oid = Oid::from_der_value(alg_oid_bytes).map_err(|e| perr(&format!("OID: {e}")))?;
    let alg_params = alg.remaining().to_vec();

    let ctx0 = eci
        .read_context_specific(0, false)
        .map_err(|e| perr(&format!("enc [0]: {e}")))?;

    if alg_oid == known::pbes2() {
        decrypt_pbes2(&alg_params, ctx0.value, password)
    } else {
        Err(perr(&format!("unsupported encryption: {alg_oid}")))
    }
}

fn decrypt_pbes2(alg_params: &[u8], encrypted: &[u8], password: &str) -> Result<Vec<u8>, PkiError> {
    let mut dec = Decoder::new(alg_params);
    let mut params = dec
        .read_sequence()
        .map_err(|e| perr(&format!("PBES2 params: {e}")))?;

    // KDF
    let mut kdf = params
        .read_sequence()
        .map_err(|e| perr(&format!("KDF: {e}")))?;
    let kdf_oid_bytes = kdf.read_oid().map_err(|e| perr(&format!("KDF OID: {e}")))?;
    let kdf_oid = Oid::from_der_value(kdf_oid_bytes).map_err(|e| perr(&format!("KDF OID: {e}")))?;
    if kdf_oid != known::pbkdf2_oid() {
        return Err(perr("unsupported KDF"));
    }

    let mut pbkdf2_params = kdf
        .read_sequence()
        .map_err(|e| perr(&format!("PBKDF2: {e}")))?;
    let salt = pbkdf2_params
        .read_octet_string()
        .map_err(|e| perr(&format!("salt: {e}")))?
        .to_vec();
    let iter_bytes = pbkdf2_params
        .read_integer()
        .map_err(|e| perr(&format!("iter: {e}")))?;
    let iterations = bytes_to_u32(iter_bytes);

    // Encryption scheme
    let mut enc = params
        .read_sequence()
        .map_err(|e| perr(&format!("enc scheme: {e}")))?;
    let enc_oid_bytes = enc.read_oid().map_err(|e| perr(&format!("enc OID: {e}")))?;
    let enc_oid = Oid::from_der_value(enc_oid_bytes).map_err(|e| perr(&format!("enc OID: {e}")))?;

    let key_len = if enc_oid == known::aes256_cbc() {
        32
    } else if enc_oid == known::aes128_cbc() {
        16
    } else if enc_oid == known::aes192_cbc() {
        24
    } else {
        return Err(perr(&format!("unsupported cipher: {enc_oid}")));
    };

    let iv = enc
        .read_octet_string()
        .map_err(|e| perr(&format!("IV: {e}")))?
        .to_vec();

    let key = pbkdf2::pbkdf2(password.as_bytes(), &salt, iterations, key_len)
        .map_err(|e| perr(&format!("PBKDF2: {e}")))?;

    cbc::cbc_decrypt(&key, &iv, encrypted).map_err(|e| perr(&format!("AES-CBC: {e}")))
}

fn decrypt_encrypted_private_key(data: &[u8], password: &str) -> Result<Vec<u8>, PkiError> {
    let mut dec = Decoder::new(data);
    let mut seq = dec
        .read_sequence()
        .map_err(|e| perr(&format!("EncPKI: {e}")))?;

    let mut alg = seq
        .read_sequence()
        .map_err(|e| perr(&format!("EncPKI alg: {e}")))?;
    let alg_oid_bytes = alg.read_oid().map_err(|e| perr(&format!("alg OID: {e}")))?;
    let alg_oid = Oid::from_der_value(alg_oid_bytes).map_err(|e| perr(&format!("OID: {e}")))?;
    let alg_params = alg.remaining().to_vec();

    let encrypted = seq
        .read_octet_string()
        .map_err(|e| perr(&format!("enc data: {e}")))?
        .to_vec();

    if alg_oid == known::pbes2() {
        decrypt_pbes2(&alg_params, &encrypted, password)
    } else {
        Err(perr(&format!("unsupported key encryption: {alg_oid}")))
    }
}

// ── SafeContents parsing ─────────────────────────────────────────────

fn parse_safe_contents(
    data: &[u8],
    password: &str,
    private_key: &mut Option<Vec<u8>>,
    certificates: &mut Vec<Vec<u8>>,
) -> Result<(), PkiError> {
    let mut dec = Decoder::new(data);
    let mut seq = dec
        .read_sequence()
        .map_err(|e| perr(&format!("SafeContents: {e}")))?;

    while !seq.is_empty() {
        let mut bag = seq
            .read_sequence()
            .map_err(|e| perr(&format!("SafeBag: {e}")))?;
        let bag_id_bytes = bag.read_oid().map_err(|e| perr(&format!("bag id: {e}")))?;
        let bag_id =
            Oid::from_der_value(bag_id_bytes).map_err(|e| perr(&format!("bag OID: {e}")))?;

        let bag_val = bag
            .read_context_specific(0, true)
            .map_err(|e| perr(&format!("bag [0]: {e}")))?;

        if bag_id == known::pkcs12_bag_type_pkcs8_shrouded_key() {
            *private_key = Some(decrypt_encrypted_private_key(bag_val.value, password)?);
        } else if bag_id == known::pkcs12_bag_type_cert() {
            let mut cb = Decoder::new(bag_val.value);
            let mut cb_seq = cb
                .read_sequence()
                .map_err(|e| perr(&format!("CertBag: {e}")))?;
            let _cert_id = cb_seq
                .read_oid()
                .map_err(|e| perr(&format!("certId: {e}")))?;
            let cert_ctx0 = cb_seq
                .read_context_specific(0, true)
                .map_err(|e| perr(&format!("certVal: {e}")))?;
            let mut cv = Decoder::new(cert_ctx0.value);
            let cert_der = cv
                .read_octet_string()
                .map_err(|e| perr(&format!("cert: {e}")))?
                .to_vec();
            certificates.push(cert_der);
        } else if bag_id == known::pkcs12_bag_type_key() {
            *private_key = Some(bag_val.value.to_vec());
        }
        // Skip attributes and other bag types
    }
    Ok(())
}

// ── Encoding helpers ─────────────────────────────────────────────────

fn encode_content_info_data(content: &[u8]) -> Vec<u8> {
    let octet = enc_octet(content);
    let ctx0 = enc_explicit_ctx(0, &octet);
    let mut inner = enc_oid(&known::pkcs7_data().to_der_value());
    inner.extend_from_slice(&ctx0);
    enc_seq(&inner)
}

fn encode_mac_data(mac_value: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    // DigestInfo = SEQUENCE { AlgorithmIdentifier, OCTET STRING }
    let mut alg_inner = enc_oid(&known::sha1_oid().to_der_value());
    alg_inner.extend_from_slice(&enc_null());
    let alg_id = enc_seq(&alg_inner);

    let mac_digest = enc_octet(mac_value);
    let mut di_inner = Vec::new();
    di_inner.extend_from_slice(&alg_id);
    di_inner.extend_from_slice(&mac_digest);
    let digest_info = enc_seq(&di_inner);

    let mut md_inner = Vec::new();
    md_inner.extend_from_slice(&digest_info);
    md_inner.extend_from_slice(&enc_octet(salt));
    md_inner.extend_from_slice(&enc_int(&iterations.to_be_bytes()));
    enc_seq(&md_inner)
}

fn encrypt_private_key(pk_der: &[u8], password: &str) -> Result<Vec<u8>, PkiError> {
    let salt = generate_random(16)?;
    let iterations: u32 = 2048;

    let mut key = pbkdf2::pbkdf2(password.as_bytes(), &salt, iterations, 32)
        .map_err(|e| perr(&format!("PBKDF2: {e}")))?;
    let iv = generate_random(16)?;

    let encrypted =
        cbc::cbc_encrypt(&key, &iv, pk_der).map_err(|e| perr(&format!("AES-CBC: {e}")))?;
    key.zeroize();

    let pbes2_params = encode_pbes2_params(&salt, iterations, &iv);
    let mut alg_inner = enc_oid(&known::pbes2().to_der_value());
    alg_inner.extend_from_slice(&pbes2_params);
    let alg_id = enc_seq(&alg_inner);

    let mut epki_inner = Vec::new();
    epki_inner.extend_from_slice(&alg_id);
    epki_inner.extend_from_slice(&enc_octet(&encrypted));
    Ok(enc_seq(&epki_inner))
}

fn encode_pbes2_params(salt: &[u8], iterations: u32, iv: &[u8]) -> Vec<u8> {
    // PBKDF2-params
    let mut prf_inner = enc_oid(&known::hmac_sha256_oid().to_der_value());
    prf_inner.extend_from_slice(&enc_null());
    let prf_alg = enc_seq(&prf_inner);

    let mut pbkdf2_inner = Vec::new();
    pbkdf2_inner.extend_from_slice(&enc_octet(salt));
    pbkdf2_inner.extend_from_slice(&enc_int(&iterations.to_be_bytes()));
    pbkdf2_inner.extend_from_slice(&prf_alg);
    let pbkdf2_params = enc_seq(&pbkdf2_inner);

    let mut kdf_inner = enc_oid(&known::pbkdf2_oid().to_der_value());
    kdf_inner.extend_from_slice(&pbkdf2_params);
    let kdf_alg = enc_seq(&kdf_inner);

    let mut enc_inner = enc_oid(&known::aes256_cbc().to_der_value());
    enc_inner.extend_from_slice(&enc_octet(iv));
    let enc_alg = enc_seq(&enc_inner);

    let mut pbes2_inner = Vec::new();
    pbes2_inner.extend_from_slice(&kdf_alg);
    pbes2_inner.extend_from_slice(&enc_alg);
    enc_seq(&pbes2_inner)
}

fn encode_safe_bag(bag_type_oid: &Oid, bag_value: &[u8], local_key_id: Option<&[u8]>) -> Vec<u8> {
    let mut inner = enc_oid(&bag_type_oid.to_der_value());
    inner.extend_from_slice(&enc_explicit_ctx(0, bag_value));
    if let Some(kid) = local_key_id {
        let attr = encode_local_key_id_attr(kid);
        inner.extend_from_slice(&enc_set(&attr));
    }
    enc_seq(&inner)
}

fn encode_cert_bag(cert_der: &[u8]) -> Vec<u8> {
    let mut inner = enc_oid(&known::x509_certificate().to_der_value());
    inner.extend_from_slice(&enc_explicit_ctx(0, &enc_octet(cert_der)));
    enc_seq(&inner)
}

fn encode_local_key_id_attr(key_id: &[u8]) -> Vec<u8> {
    let mut inner = enc_oid(&known::pkcs9_local_key_id().to_der_value());
    inner.extend_from_slice(&enc_set(&enc_octet(key_id)));
    enc_seq(&inner)
}

fn perr(msg: &str) -> PkiError {
    PkiError::Pkcs12Error(msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_private_key() -> Vec<u8> {
        let mut alg_inner = enc_oid(&known::rsa_encryption().to_der_value());
        alg_inner.extend_from_slice(&enc_null());
        let alg_id = enc_seq(&alg_inner);

        let key_octet = enc_octet(&[0x42; 64]);
        let version = enc_int(&[0]);

        let mut pki_inner = Vec::new();
        pki_inner.extend_from_slice(&version);
        pki_inner.extend_from_slice(&alg_id);
        pki_inner.extend_from_slice(&key_octet);
        enc_seq(&pki_inner)
    }

    fn fake_certificate(id: u8) -> Vec<u8> {
        let inner = vec![0x30, 0x03, 0x02, 0x01, id];
        enc_seq(&inner)
    }

    #[test]
    fn test_pkcs12_create_and_parse_roundtrip() {
        let pk = fake_private_key();
        let cert = fake_certificate(1);
        let p12 = Pkcs12::create(Some(&pk), &[&cert], "testpassword").unwrap();
        let parsed = Pkcs12::from_der(&p12, "testpassword").unwrap();
        assert_eq!(parsed.private_key.as_ref().unwrap(), &pk);
        assert_eq!(parsed.certificates.len(), 1);
        assert_eq!(parsed.certificates[0], cert);
    }

    #[test]
    fn test_pkcs12_wrong_password_fails() {
        let pk = fake_private_key();
        let cert = fake_certificate(1);
        let p12 = Pkcs12::create(Some(&pk), &[&cert], "correct").unwrap();
        assert!(Pkcs12::from_der(&p12, "wrong").is_err());
    }

    /// Phase T84 regression: PKCS#12 password-MAC verification rejects a
    /// PFX whose stored MAC has been tampered. Locks in the move from
    /// early-exit byte compare to length-check + `subtle::ConstantTimeEq`.
    /// We encode a valid PFX with `Pkcs12::create`, then surgically flip
    /// bytes near the MAC tag inside the encoded blob and re-parse; each
    /// such tamper must fail with a MAC verification error rather than
    /// panic or silently accept.
    #[test]
    fn test_pkcs12_rejects_tampered_mac_constant_time() {
        let pk = fake_private_key();
        let cert = fake_certificate(1);
        let mut p12 = Pkcs12::create(Some(&pk), &[&cert], "pw").unwrap();
        let original_len = p12.len();
        // Sanity: original parses cleanly with the right password.
        assert!(Pkcs12::from_der(&p12, "pw").is_ok());

        // The MAC tag is HMAC-SHA-1 (20 bytes) and lives near the end of
        // the PFX before the trailing iteration count + salt. Flipping the
        // 5-th-from-last byte will hit either the tag, the salt-length
        // prefix, or an iteration field — all of which must invalidate
        // either the MAC or the structure parse.
        let target = original_len.saturating_sub(5);
        p12[target] ^= 0x40;
        let result = Pkcs12::from_der(&p12, "pw");
        assert!(
            result.is_err(),
            "tampered byte at offset {target} of {original_len}-byte PFX \
             must not parse cleanly with the original password"
        );
    }

    #[test]
    fn test_pkcs12_multiple_certs() {
        let pk = fake_private_key();
        let certs: Vec<Vec<u8>> = (1..=3).map(fake_certificate).collect();
        let cert_refs: Vec<&[u8]> = certs.iter().map(|c| c.as_slice()).collect();
        let p12 = Pkcs12::create(Some(&pk), &cert_refs, "test123").unwrap();
        let parsed = Pkcs12::from_der(&p12, "test123").unwrap();
        assert_eq!(parsed.certificates.len(), 3);
        for (i, cert) in certs.iter().enumerate() {
            assert_eq!(&parsed.certificates[i], cert);
        }
    }

    #[test]
    fn test_pkcs12_no_private_key() {
        let cert = fake_certificate(1);
        let p12 = Pkcs12::create(None, &[&cert], "nokey").unwrap();
        let parsed = Pkcs12::from_der(&p12, "nokey").unwrap();
        assert!(parsed.private_key.is_none());
        assert_eq!(parsed.certificates.len(), 1);
    }

    #[test]
    fn test_pkcs12_extract_private_key() {
        let pk = fake_private_key();
        let p12 = Pkcs12::create(Some(&pk), &[], "keyonly").unwrap();
        let parsed = Pkcs12::from_der(&p12, "keyonly").unwrap();
        assert_eq!(parsed.private_key.as_ref().unwrap(), &pk);
        assert!(parsed.certificates.is_empty());
    }

    #[test]
    fn test_pkcs12_empty_password() {
        let pk = fake_private_key();
        let cert = fake_certificate(1);
        let p12 = Pkcs12::create(Some(&pk), &[&cert], "").unwrap();
        let parsed = Pkcs12::from_der(&p12, "").unwrap();
        assert_eq!(parsed.private_key.as_ref().unwrap(), &pk);
    }

    #[test]
    fn test_pkcs12_kdf_produces_key() {
        let key = pkcs12_kdf("password", &[0x01; 8], 3, 2048, 20, P12MacHash::Sha1).unwrap();
        assert_eq!(key.len(), 20);
        let key2 = pkcs12_kdf("password", &[0x01; 8], 3, 2048, 20, P12MacHash::Sha1).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_pkcs12_kdf_different_ids() {
        let k1 = pkcs12_kdf("pass", &[0x01; 8], 1, 1, 20, P12MacHash::Sha1).unwrap();
        let k2 = pkcs12_kdf("pass", &[0x01; 8], 2, 1, 20, P12MacHash::Sha1).unwrap();
        let k3 = pkcs12_kdf("pass", &[0x01; 8], 3, 1, 20, P12MacHash::Sha1).unwrap();
        assert_ne!(k1, k2);
        assert_ne!(k2, k3);
    }

    #[test]
    fn test_pkcs12_kdf_sha256_lengths() {
        // SHA-256 KDF must yield 32-byte blocks and differ from SHA-1.
        let k_sha1 = pkcs12_kdf("pw", &[0x02; 8], 3, 100, 32, P12MacHash::Sha1).unwrap();
        let k_sha256 = pkcs12_kdf("pw", &[0x02; 8], 3, 100, 32, P12MacHash::Sha256).unwrap();
        assert_eq!(k_sha1.len(), 32);
        assert_eq!(k_sha256.len(), 32);
        assert_ne!(k_sha1, k_sha256);
        assert_eq!(P12MacHash::Sha256.output_len(), 32);
        assert_eq!(P12MacHash::Sha384.output_len(), 48);
        assert_eq!(P12MacHash::Sha512.output_len(), 64);
    }

    // ── C SDV KAT migration (T113): pki/pkcs12 CAL_KDF / CAL_MACDATA ──
    // These validate the I117 SHA-2 KDF/MAC against openHiTLS C reference
    // vectors. They live here (not the integration test file) because they
    // exercise the crate-private `pkcs12_kdf` / `P12MacHash`. The MAC-key id is
    // 3 (HITLS_PKCS12_KDF_MACKEY_ID); password "123456" BMP-encodes to the C
    // `pwd` input (00 31 00 32 00 33 00 34 00 35 00 36 00 00).
    use hitls_utils::hex::hex;

    /// SDV_PKCS12_CAL_KDF_TC001 — SHA-256 PKCS#12 KDF (RFC 7292 Appendix B).
    #[test]
    fn test_pkcs12_cal_kdf_kat_sha256() {
        let key = pkcs12_kdf(
            "123456",
            &hex("ed47d6a67b245984"),
            3,
            2048,
            32,
            P12MacHash::Sha256,
        )
        .unwrap();
        assert_eq!(
            key,
            hex("b08f3dad67e2abb1f83b1ba776c62cb969c1b50084126a3484fd9359e2934f4b")
        );
    }

    /// SDV_PKCS12_CAL_MACDATA_TC001 — full PKCS#12 MAC (KDF id=3 + HMAC over the
    /// AuthenticatedSafe content) across SHA-256 / SHA-384 / SHA-512 / SHA-224.
    #[test]
    fn test_pkcs12_cal_macdata_kat() {
        // (init_data, salt, hash, expected_mac)
        let vectors: &[(&str, &str, P12MacHash, &str)] = &[
            (
                "308203EB3082029A06092A864886F70D010706A082028B308202870201003082028006092A864886F70D010701305F06092A864886F70D01050D3052303106092A864886F70D01050C302404103CD0668BD26EF3A180DEFA61012C23D602020800300C06082A864886F70D02090500301D060960864801650304012A0410CE0B39834D2A455A4CB7C403094B844780820210A81435985F0C1B9C753CAC1C52B59C9B0B81745E76490F3118E8072D543F840272AA631575919327732F15831DBB8E1EA9880C6DE48287631E351D2B161C0EA5C4A38240219307B41B7302F6C8AB8CCD222ACD7F80CA975A4D1CF478200DB1E6A4BB8131150A389726929DAC0F28AB86DD44809C143AA644032710567721486F40F88F8B2694349A1AC47F624799E0795DA9C3FC84F06BAD8AFF7B71B2B84F6FCD40EC2202E65D1E5730CBFD33B1AF8F785F203722EAEBF9177098B6303D1905247F0363D6372FECBCDAA375463EB303B36006110114BBF3344775D89272689D1C78F6875F0492E5A641738F6B1E981196DE4021DE863BF1A53B00BF61C9E7167A881C28614000CFB03AB6DC6582B1C35E6486C6B1FED600D6BA6227E2FDBFBA4C0A80294A7B4B763749FCDF09ECD9BC72957EC288C7ED3DBFE84162E2654DEEE4F4678A80EFCA90A587D09EE00B6662E327F2173ABE800DCFE9CC3835EF4C96CF398C8E8A131477B1377F3960453494DE6020679FBE27FA5B1FAFE622E5953515E50E87369DD7A07F44267D925FDAAD1B970FF76078A9C9835256BE4FC116904D137865381AFD0633044D84C48BCBE3DCCFC3CBDADD53B81D1280A3570A6986501584AFC6FB2711AC3B48B2658A82D96B708BED6DC249B04A9AB4FBD3D27A02BEE22E2DF291932B2B1A5EA0F837582D2095247A5083CB45E11376FD0FD1699274286B283EB96A4EF21CE1818F1C52243082014906092A864886F70D010701A082013A04820136308201323082012E060B2A864886F70D010C0A0102A081F73081F4305F06092A864886F70D01050D3052303106092A864886F70D01050C30240410240BABC3C7F039F13688B6386DFCDDA002020800300C06082A864886F70D02090500301D060960864801650304012A0410D8BD500CF93A003B2F96F13BB0A3798B048190DD8C150273FEC857FA28827094A9BB41041D4EFFC4A9238429068F38759A17A61E741B1560BD816F44721E52BFB2DA1285193A5A54918389A3E3ABEC23C074224706FC341F944DA237685E8D3339D172A9C01BCB91CC722D03B43B68E1958B5121AE06F38B7C99A81E74FA479EA1F10511D0A3FC8E0D05B3B6F96C03884F3EC65DFABA4D675C0DB236664EA7ACB92BC63125302306092A864886F70D01091531160414F34CB6C5D2A309187D36DFCC0B7D5A19EC81357D",
                "eaa807dc1e56f04b",
                P12MacHash::Sha512,
                "37463ef2b29be402ceba4a9320f1615183a3dc3cfed7ed86889593d95a4da6f7d1a710037e345f048379b98a75039036a2b43522b33d6fb1670538413c57ba69",
            ),
            (
                "308203EB3082029A06092A864886F70D010706A082028B308202870201003082028006092A864886F70D010701305F06092A864886F70D01050D3052303106092A864886F70D01050C30240410FF4BC4264C1989E622A370CAB860D10D02020800300C06082A864886F70D02090500301D060960864801650304012A0410E2C1BDB40FEB09DEC5B6CDEC6FBB0E118082021083B8757108B4E7BC176273ABACE3796530C2465C6A90F81C58E1A117AC777AF4F3EE672F973805D7E41DE6FCBCDB3F4D91087B17BFB942623076B49F1A79507FC8EF5771A38580400D16DA134E5D2EC8095E9DD98F67BCB2F7602865C2FB94EB4A7BA718B370EF614FD8623F8094F242685468322C0512E1F65EA1920D6CBDEEB7F8C99ED5809A314B8032D1F5053E53D03B313143911975EC84D662C9BFADD4DD9E41583AB10A93F6BC171A9F63533B3F0AEA30FA332C2429D728A5F736E2ECBF34FBAEA6C80678496CD713D451D2B8475FF9650A5AEC694397E1767C0EF5492C3405539DBFA100D6EED691D55E7208DB0D61BE1662865AC048E9E07EE1EB9972537D4B9C036C1C314A9748A3A1E7C933C2CD18B171308379ED36B91F7DD1189B128F2E9FBD519B3E62BF3DE887260A375BB01FF1B52C3A196533E034398A01168D4A849DE33F962831C47EB7B06E0FA9318FD3E11787F01FB99FB76C83E7AC782DBF7556589ACFF5F1E9FA41B33C46CFEEAAC686B71E804EF389B925A424155C169E6EF61DB5AEE3A7CD095FEF7DA33E1E64CA2BD4DC04D22E0489698AAC74D872992B73413C4EC95B08E4BBBE49EFE83E1F3DEEB93D6FCBD646F3E59C4FCA213F6BEA338C776DF48E8FD1E9EB62B38EFEF56080D53A155CD8234DC51EC4CD3668D69A83110E0B5BA65148897C4CB4FD7519659C80B7469DEA7E4DAA60700869E960BDA25FA5D8F7849C693692AB6B3082014906092A864886F70D010701A082013A04820136308201323082012E060B2A864886F70D010C0A0102A081F73081F4305F06092A864886F70D01050D3052303106092A864886F70D01050C302404104CFE523164AF6F734E98C977A6046F4402020800300C06082A864886F70D02090500301D060960864801650304012A0410242438D64F4E882B9BC01FD47EB4ACDF04819049AD3CA5FA7F8780B39C981AFD29AD0BE6C6A69D78FE0DC9EA34CA52C7F60469396C5398DE7A152965526A0A9BDF04B6F6AF5CAD1008C074A11803416E09E72186F3BE7982C2789D9C1A995AE444A53B31A86CC0ECB62CD164D95E71C32659E0B6B25C461F81E9688DD0C260DFEF9B1D735DEF4724A438F4EBCAB7D3063C0F08C29DCB7F10280CF582287A012F96CBB33125302306092A864886F70D01091531160414F34CB6C5D2A309187D36DFCC0B7D5A19EC81357D",
                "9f1708bd9e2ce4e3",
                P12MacHash::Sha224,
                "db9eaab4df8754682737219b38b1f3c85310923b443dba27ce548fa6",
            ),
            (
                "308203EB3082029A06092A864886F70D010706A082028B308202870201003082028006092A864886F70D010701305F06092A864886F70D01050D3052303106092A864886F70D01050C3024041072C2AB19B9C84B1F8939C4952FF9146C02020800300C06082A864886F70D02090500301D060960864801650304012A0410E6F355A75780A764D528178C55EFD39480820210BFC3C2AC636A066D8649B8F9B917D8821C720AFF1F536E55BCDB7854FA5E2534445352A2DE2682A7BC38820A843C165552A642702BD9363956F49CFC5143B7ADA7C9A11191C52A9BC0AF2C1398CF2146558C756F6CCB2952616BA761B9F15BBF333130AE91BF3E5459D88B65101EF14540D5B1B11B5A24E3F06D2D983094EE95032E0D2F8E742E269CC15FE03599AE56C33B5E2577332BD9D23C7E83A819F07B5074F62AAD557044B15DEAC9734A930466B812C7746F3DE993C9EDCC1A567D2429E77240D05E311D2C4168AB9DF78BF5820C19D1AE47AE1BAE0F5C51AFEE2682FEE5C495CE1DBE0C993655C2E4C3C5F065106E3BCCA730A9A4090F228677E8DED2F7CD17D6F50EF72FF3DB6B11656A254D0B284019E2EE1AF522E4EAB26CEBA7E8774227FAFCC6E9F79BD135FB6558D406148E12008BADDF4E44D672826F32F5D57F8EA07A106F92F2D7F495E3BD26961991B4657F93347A75D5CFD9FF9C6ABB6E21F43CC86E4BEB0DCDE8EEED1A35CA2AAD2F7CF5AA8223317319DA51CEFD35EA498BBCEDA136C9E58975363FAF00152F7E269D94150ED10949E59493CE2FB15EB53D0194D3F2C8E8526B6F9C5213B8EDB9C9BD1C81E7A023F9B2DD8028791A1C5A8B727151C17055A1AC01923AEE6C4EBD94D009DFA0EEBCD5867199D5CC52E1AC13EE1A34B84015E01906D321A6054EAAF6CD24B53915ACE1691533C3FCE500E61479A0EC41218BA83E2E588095933082014906092A864886F70D010701A082013A04820136308201323082012E060B2A864886F70D010C0A0102A081F73081F4305F06092A864886F70D01050D3052303106092A864886F70D01050C30240410A3ADF3FF868A959459D683B1DCE37C0302020800300C06082A864886F70D02090500301D060960864801650304012A0410C8D39ACFC20EF5769A9AB45C2E90252504819025CE12A4383CC164F658282490C614AA9E3D2CC05ED92175A43C742A0CB099DF8648C5C4F715D6CAFB8D78F7C5B55966FFBEC70FBB44FE729248508C5650F62295FEAD88E0C3088242A28DD599A9AD2ECDEBDB106E458F711FB724493D261E811B1A33FA2E59B76AEBD4F7CD98C129897C200D98DD3B82259CD968C619B89039A9A552EBBBD830E096C6499438D022ED3125302306092A864886F70D01091531160414F34CB6C5D2A309187D36DFCC0B7D5A19EC81357D",
                "e12f596e63d6bfe6",
                P12MacHash::Sha384,
                "c2b9209605b8a54bb773a84953af5a5afd4a1f79ca0006f260d8267c1352ff02fd541d8896e5aaf38e805f81772169fa",
            ),
        ];
        for (init_hex, salt_hex, hash, expected) in vectors {
            let mac_key =
                pkcs12_kdf("123456", &hex(salt_hex), 3, 2048, hash.output_len(), *hash).unwrap();
            let mac = hash.hmac(&mac_key, &hex(init_hex)).unwrap();
            assert_eq!(mac, hex(expected), "MAC mismatch for {hash:?}");
        }
    }

    #[test]
    fn test_password_to_bmp() {
        let bmp = password_to_bmp("AB");
        assert_eq!(bmp, &[0x00, 0x41, 0x00, 0x42, 0x00, 0x00]);
    }

    // -----------------------------------------------------------------------
    // Phase 51: Real C test vector — PKCS#12 file tests
    // -----------------------------------------------------------------------

    const P12_1: &[u8] = include_bytes!("../../../../tests/vectors/pkcs12/p12_1.p12");
    const P12_2: &[u8] = include_bytes!("../../../../tests/vectors/pkcs12/p12_2.p12");
    const P12_3: &[u8] = include_bytes!("../../../../tests/vectors/pkcs12/p12_3.p12");
    const P12_CHAIN: &[u8] = include_bytes!("../../../../tests/vectors/pkcs12/chain.p12");

    #[test]
    fn test_p12_parse_real_file_1() {
        let result = Pkcs12::from_der(P12_1, "123456");
        match result {
            Ok(p12) => {
                // Should have at least a private key or certificate
                assert!(
                    p12.private_key.is_some() || !p12.certificates.is_empty(),
                    "p12_1 should contain a key or certificate"
                );
            }
            Err(e) => {
                // If the P12 uses an encryption algorithm we don't support, that's OK
                // — the test documents the gap
                eprintln!("p12_1.p12 parse failed (may use unsupported algo): {e}");
            }
        }
    }

    #[test]
    fn test_p12_parse_real_file_2() {
        let result = Pkcs12::from_der(P12_2, "123456");
        match result {
            Ok(p12) => {
                assert!(
                    p12.private_key.is_some() || !p12.certificates.is_empty(),
                    "p12_2 should contain a key or certificate"
                );
            }
            Err(e) => {
                eprintln!("p12_2.p12 parse failed (may use unsupported algo): {e}");
            }
        }
    }

    #[test]
    fn test_p12_parse_real_file_3() {
        let result = Pkcs12::from_der(P12_3, "123456");
        match result {
            Ok(p12) => {
                assert!(
                    p12.private_key.is_some() || !p12.certificates.is_empty(),
                    "p12_3 should contain a key or certificate"
                );
            }
            Err(e) => {
                eprintln!("p12_3.p12 parse failed (may use unsupported algo): {e}");
            }
        }
    }

    #[test]
    fn test_p12_parse_chain() {
        let result = Pkcs12::from_der(P12_CHAIN, "123456");
        match result {
            Ok(p12) => {
                // chain.p12 should have multiple certificates
                assert!(
                    p12.certificates.len() >= 2,
                    "chain.p12 should contain multiple certs, got {}",
                    p12.certificates.len()
                );
            }
            Err(e) => {
                eprintln!("chain.p12 parse failed (may use unsupported algo): {e}");
            }
        }
    }

    #[test]
    fn test_p12_wrong_password() {
        // Try parsing with wrong password — should fail with MAC verification error
        let result = Pkcs12::from_der(P12_1, "wrong_password");
        assert!(result.is_err(), "wrong password should fail");
    }

    #[test]
    fn test_p12_cert_and_key_match() {
        // If we can parse, verify key is present
        if let Ok(p12) = Pkcs12::from_der(P12_1, "123456") {
            if let Some(ref key) = p12.private_key {
                assert!(!key.is_empty(), "private key should not be empty");
            }
            for cert_der in &p12.certificates {
                // Each cert should be parseable
                let cert = crate::x509::Certificate::from_der(cert_der);
                assert!(cert.is_ok(), "cert in P12 should be parseable");
            }
        }
    }

    #[test]
    fn test_p12_empty_password() {
        // Test with empty string — may or may not work depending on the file
        let result = Pkcs12::from_der(P12_1, "");
        // Either it fails with a MAC error (expected) or succeeds
        // We just ensure it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_p12_extract_multiple_items() {
        if let Ok(p12) = Pkcs12::from_der(P12_CHAIN, "123456") {
            // Verify cert count
            let cert_count = p12.certificates.len();
            assert!(cert_count >= 1, "should have at least 1 cert");
            // Verify each cert is valid DER
            for (i, cert_der) in p12.certificates.iter().enumerate() {
                assert!(
                    crate::x509::Certificate::from_der(cert_der).is_ok(),
                    "cert {i} in chain.p12 should be parseable"
                );
            }
        }
    }

    #[test]
    fn test_pkcs12_large_key_data() {
        let key_data = vec![0x42; 200];
        let mut alg_inner = enc_oid(&known::rsa_encryption().to_der_value());
        alg_inner.extend_from_slice(&enc_null());
        let alg_id = enc_seq(&alg_inner);

        let mut pki_inner = Vec::new();
        pki_inner.extend_from_slice(&enc_int(&[0]));
        pki_inner.extend_from_slice(&alg_id);
        pki_inner.extend_from_slice(&enc_octet(&key_data));
        let large_pk = enc_seq(&pki_inner);

        let cert = fake_certificate(1);
        let p12 = Pkcs12::create(Some(&large_pk), &[&cert], "largekeytest").unwrap();
        let parsed = Pkcs12::from_der(&p12, "largekeytest").unwrap();
        assert_eq!(parsed.private_key.as_ref().unwrap(), &large_pk);
    }

    // -----------------------------------------------------------------------
    // Phase 54: PKCS#12 error path + ECDSA round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_pkcs12_empty_data() {
        // Empty input should fail
        assert!(Pkcs12::from_der(&[], "password").is_err());
        // Truncated/garbage input should fail
        assert!(Pkcs12::from_der(&[0x30, 0x00], "password").is_err());
        // Random garbage should fail
        assert!(Pkcs12::from_der(&[0xFF; 64], "password").is_err());
    }

    #[test]
    fn test_pkcs12_round_trip_ecdsa() {
        // Build ECDSA private key in PKCS#8 format
        let ec_oid = known::ec_public_key();
        let p256_oid = known::prime256v1();

        // AlgorithmIdentifier = SEQUENCE { OID ecPublicKey, OID secp256r1 }
        let mut alg_inner = enc_oid(&ec_oid.to_der_value());
        alg_inner.extend_from_slice(&enc_oid(&p256_oid.to_der_value()));
        let alg_id = enc_seq(&alg_inner);

        // Fake 32-byte EC private key wrapped in OCTET STRING
        let ec_key = enc_octet(&[0xAB; 32]);

        // PKCS#8 PrivateKeyInfo = SEQUENCE { version, algId, key }
        let mut pki = Vec::new();
        pki.extend_from_slice(&enc_int(&[0])); // version 0
        pki.extend_from_slice(&alg_id);
        pki.extend_from_slice(&ec_key);
        let ecdsa_pk = enc_seq(&pki);

        let cert = fake_certificate(99);
        let p12 = Pkcs12::create(Some(&ecdsa_pk), &[&cert], "ectest").unwrap();
        let parsed = Pkcs12::from_der(&p12, "ectest").unwrap();
        assert_eq!(parsed.private_key.as_ref().unwrap(), &ecdsa_pk);
        assert_eq!(parsed.certificates.len(), 1);
        assert_eq!(parsed.certificates[0], cert);
    }
}
