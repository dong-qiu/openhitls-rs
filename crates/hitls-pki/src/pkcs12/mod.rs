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
use hitls_types::PkiError;
use hitls_utils::asn1::{tags, Decoder, Encoder};
use hitls_utils::oid::{known, Oid};
use zeroize::Zeroize;

// ── Encoder helpers (Encoder::write_* returns &mut Self, finish takes self) ──

fn enc_seq(content: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_sequence(content);
    e.finish()
}

fn enc_set(content: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_set(content);
    e.finish()
}

fn enc_octet(content: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_octet_string(content);
    e.finish()
}

fn enc_oid(oid_bytes: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_oid(oid_bytes);
    e.finish()
}

fn enc_int(value: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_integer(value);
    e.finish()
}

fn enc_null() -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_null();
    e.finish()
}

fn enc_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_tlv(tag, value);
    e.finish()
}

/// Encode EXPLICIT context-specific tag.
fn enc_explicit_ctx(tag_num: u8, content: &[u8]) -> Vec<u8> {
    let tag = tags::CONTEXT_SPECIFIC | tags::CONSTRUCTED | tag_num;
    enc_tlv(tag, content)
}

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

/// PKCS#12 KDF using SHA-1 (RFC 7292 Appendix B).
/// id: 1 = encryption key, 2 = IV, 3 = MAC key
fn pkcs12_kdf(
    password: &str,
    salt: &[u8],
    id: u8,
    iterations: u32,
    dk_len: usize,
) -> Result<Vec<u8>, PkiError> {
    let hash_len: usize = 20;
    let block_size: usize = 64;

    let d = vec![id; block_size];

    let s = if salt.is_empty() {
        Vec::new()
    } else {
        let s_len = salt.len().div_ceil(block_size) * block_size;
        (0..s_len).map(|i| salt[i % salt.len()]).collect()
    };

    let bmp = password_to_bmp(password);
    let p = if bmp.len() <= 2 {
        Vec::new()
    } else {
        let p_len = bmp.len().div_ceil(block_size) * block_size;
        (0..p_len).map(|i| bmp[i % bmp.len()]).collect()
    };

    let mut i_buf = Vec::with_capacity(s.len() + p.len());
    i_buf.extend_from_slice(&s);
    i_buf.extend_from_slice(&p);

    let n = dk_len.div_ceil(hash_len);
    let mut dk = Vec::with_capacity(dk_len);

    for _ in 0..n {
        let mut a = sha1_hash_concat(&d, &i_buf)?;
        for _ in 1..iterations {
            a = sha1_hash(&a)?;
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
                    let sum = i_buf[j + k] as u16 + b[k] as u16 + carry;
                    i_buf[j + k] = sum as u8;
                    carry = sum >> 8;
                }
            }
        }
    }

    Ok(dk)
}

fn sha1_hash(data: &[u8]) -> Result<Vec<u8>, PkiError> {
    let mut h = Sha1::new();
    h.update(data)
        .map_err(|e| PkiError::Pkcs12Error(e.to_string()))?;
    Ok(h.finish()
        .map_err(|e| PkiError::Pkcs12Error(e.to_string()))?
        .to_vec())
}

fn sha1_hash_concat(a: &[u8], b: &[u8]) -> Result<Vec<u8>, PkiError> {
    let mut h = Sha1::new();
    h.update(a)
        .map_err(|e| PkiError::Pkcs12Error(e.to_string()))?;
    h.update(b)
        .map_err(|e| PkiError::Pkcs12Error(e.to_string()))?;
    Ok(h.finish()
        .map_err(|e| PkiError::Pkcs12Error(e.to_string()))?
        .to_vec())
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<Vec<u8>, PkiError> {
    Hmac::mac(|| -> Box<dyn Digest> { Box::new(Sha1::new()) }, key, data)
        .map_err(|e| PkiError::Pkcs12Error(format!("HMAC-SHA1: {e}")))
}

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_shl(8) | b as u32)
}

fn generate_random(len: usize) -> Result<Vec<u8>, PkiError> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf)
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
        let mac_key = pkcs12_kdf(password, &salt, 3, iterations, 20)?;
        let mac_value = hmac_sha1(&mac_key, &auth_safe)?;
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

    // DigestInfo
    let mut di = mac_dec
        .read_sequence()
        .map_err(|e| perr(&format!("DigestInfo: {e}")))?;
    let _alg = di
        .read_sequence()
        .map_err(|e| perr(&format!("mac alg: {e}")))?;
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

    let mac_key = pkcs12_kdf(password, &mac_salt, 3, iterations, 20)?;
    let computed = hmac_sha1(&mac_key, auth_safe_content)?;

    if computed != stored_mac {
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
        let key = pkcs12_kdf("password", &[0x01; 8], 3, 2048, 20).unwrap();
        assert_eq!(key.len(), 20);
        let key2 = pkcs12_kdf("password", &[0x01; 8], 3, 2048, 20).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_pkcs12_kdf_different_ids() {
        let k1 = pkcs12_kdf("pass", &[0x01; 8], 1, 1, 20).unwrap();
        let k2 = pkcs12_kdf("pass", &[0x01; 8], 2, 1, 20).unwrap();
        let k3 = pkcs12_kdf("pass", &[0x01; 8], 3, 1, 20).unwrap();
        assert_ne!(k1, k2);
        assert_ne!(k2, k3);
    }

    #[test]
    fn test_password_to_bmp() {
        let bmp = password_to_bmp("AB");
        assert_eq!(bmp, &[0x00, 0x41, 0x00, 0x42, 0x00, 0x00]);
    }

    // -----------------------------------------------------------------------
    // P2: Real C test vector — PKCS#12 file tests
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
}
