//! Public key utility: sign, verify, encrypt, decrypt, derive.

use std::fs;

pub fn run(
    op: &str,
    input: &str,
    output: Option<&str>,
    inkey: &str,
    peerkey: Option<&str>,
    sigfile: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_pem = fs::read_to_string(inkey)?;
    let input_data = fs::read(input)?;

    let result = match op {
        "sign" => do_sign(&key_pem, &input_data)?,
        "verify" => {
            let sig_path = sigfile.ok_or("--sigfile required for verify")?;
            let sig_data = fs::read(sig_path)?;
            return do_verify(&key_pem, &input_data, &sig_data);
        }
        "encrypt" => do_encrypt(&key_pem, &input_data)?,
        "decrypt" => do_decrypt(&key_pem, &input_data)?,
        "derive" => {
            let peer_path = peerkey.ok_or("--peerkey required for derive")?;
            let peer_pem = fs::read_to_string(peer_path)?;
            do_derive(&key_pem, &peer_pem)?
        }
        _ => {
            return Err(
                format!("unknown operation: {op} (use sign/verify/encrypt/decrypt/derive)").into(),
            )
        }
    };

    if let Some(out_path) = output {
        fs::write(out_path, &result)?;
        eprintln!("Output written to {out_path} ({} bytes)", result.len());
    } else {
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
        println!("{hex}");
    }

    Ok(())
}

fn do_sign(key_pem: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = parse_pkcs8_key(key_pem)?;
    match key {
        hitls_pki::pkcs8::Pkcs8PrivateKey::Rsa(priv_key) => {
            let digest = hitls_crypto::sha2::Sha256::digest(data)?;
            let sig = priv_key.sign(hitls_crypto::rsa::RsaPadding::Pss, &digest)?;
            Ok(sig)
        }
        hitls_pki::pkcs8::Pkcs8PrivateKey::Ec { key_pair, .. } => {
            let digest = hitls_crypto::sha2::Sha256::digest(data)?;
            let sig = key_pair.sign(&digest)?;
            Ok(sig)
        }
        hitls_pki::pkcs8::Pkcs8PrivateKey::Ed25519(kp) => {
            let sig = kp.sign(data)?;
            Ok(sig.to_vec())
        }
        hitls_pki::pkcs8::Pkcs8PrivateKey::Ed448(kp) => {
            let sig = kp.sign(data)?;
            Ok(sig.to_vec())
        }
        _ => Err("sign not supported for this key type (X25519/X448/DSA)".into()),
    }
}

fn do_verify(key_pem: &str, data: &[u8], sig: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let key = parse_pkcs8_key(key_pem)?;
    let valid = match key {
        hitls_pki::pkcs8::Pkcs8PrivateKey::Rsa(priv_key) => {
            let digest = hitls_crypto::sha2::Sha256::digest(data)?;
            let pub_key = priv_key.public_key();
            pub_key.verify(hitls_crypto::rsa::RsaPadding::Pss, &digest, sig)?
        }
        hitls_pki::pkcs8::Pkcs8PrivateKey::Ec { key_pair, .. } => {
            let digest = hitls_crypto::sha2::Sha256::digest(data)?;
            key_pair.verify(&digest, sig)?
        }
        hitls_pki::pkcs8::Pkcs8PrivateKey::Ed25519(kp) => kp.verify(data, sig)?,
        hitls_pki::pkcs8::Pkcs8PrivateKey::Ed448(kp) => kp.verify(data, sig)?,
        _ => return Err("verify not supported for this key type (X25519/X448/DSA)".into()),
    };
    if valid {
        println!("Signature Verified Successfully");
        Ok(())
    } else {
        Err("Verification Failure".into())
    }
}

fn do_encrypt(key_pem: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = parse_pkcs8_key(key_pem)?;
    match key {
        hitls_pki::pkcs8::Pkcs8PrivateKey::Rsa(priv_key) => {
            let pub_key = priv_key.public_key();
            let ct = pub_key.encrypt(hitls_crypto::rsa::RsaPadding::Oaep, data)?;
            Ok(ct)
        }
        _ => Err("encrypt only supported for RSA keys".into()),
    }
}

fn do_decrypt(key_pem: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = parse_pkcs8_key(key_pem)?;
    match key {
        hitls_pki::pkcs8::Pkcs8PrivateKey::Rsa(priv_key) => {
            let pt = priv_key.decrypt(hitls_crypto::rsa::RsaPadding::Oaep, data)?;
            Ok(pt)
        }
        _ => Err("decrypt only supported for RSA keys".into()),
    }
}

fn do_derive(key_pem: &str, peer_pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = parse_pkcs8_key(key_pem)?;
    let peer = hitls_pki::pkcs8::parse_spki_pem(peer_pem)
        .map_err(|e| format!("peer key parse failed: {e}"))?;

    match (key, peer) {
        (
            hitls_pki::pkcs8::Pkcs8PrivateKey::X25519(priv_key),
            hitls_pki::pkcs8::SpkiPublicKey::X25519(pub_bytes),
        ) => {
            let peer_pub = hitls_crypto::x25519::X25519PublicKey::new(&pub_bytes)
                .map_err(|e| format!("X25519 peer key: {e}"))?;
            let shared = priv_key
                .diffie_hellman(&peer_pub)
                .map_err(|e| format!("X25519 DH: {e}"))?;
            Ok(shared)
        }
        (
            hitls_pki::pkcs8::Pkcs8PrivateKey::X448(priv_key),
            hitls_pki::pkcs8::SpkiPublicKey::X448(pub_bytes),
        ) => {
            let peer_pub = hitls_crypto::x448::X448PublicKey::new(&pub_bytes)
                .map_err(|e| format!("X448 peer key: {e}"))?;
            let shared = priv_key
                .diffie_hellman(&peer_pub)
                .map_err(|e| format!("X448 DH: {e}"))?;
            Ok(shared)
        }
        (
            hitls_pki::pkcs8::Pkcs8PrivateKey::Ec { curve_id, .. },
            hitls_pki::pkcs8::SpkiPublicKey::Ec {
                curve_id: peer_curve,
                public_key,
            },
        ) => {
            if curve_id != peer_curve {
                return Err(format!(
                    "curve mismatch: private key is {curve_id:?}, peer is {peer_curve:?}"
                )
                .into());
            }
            // Re-parse private key bytes as ECDH key pair
            let pkcs8_key = parse_pkcs8_key(key_pem)?;
            let ecdh_kp = match pkcs8_key {
                hitls_pki::pkcs8::Pkcs8PrivateKey::Ec { key_pair, .. } => {
                    hitls_crypto::ecdh::EcdhKeyPair::from_private_key(
                        curve_id,
                        &key_pair.private_key_bytes(),
                    )
                    .map_err(|e| format!("ECDH key: {e}"))?
                }
                _ => unreachable!(),
            };
            let shared = ecdh_kp
                .compute_shared_secret(&public_key)
                .map_err(|e| format!("ECDH: {e}"))?;
            Ok(shared)
        }
        _ => Err(
            "derive: key type mismatch (both keys must be same type: X25519, X448, or EC)".into(),
        ),
    }
}

fn parse_pkcs8_key(
    pem_str: &str,
) -> Result<hitls_pki::pkcs8::Pkcs8PrivateKey, Box<dyn std::error::Error>> {
    hitls_pki::pkcs8::parse_pkcs8_pem(pem_str)
        .map_err(|e| format!("PKCS#8 parse failed: {e}").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkeyutl_derive_x25519() {
        // Alice
        let alice_priv = hitls_crypto::x25519::X25519PrivateKey::new(&[0x77u8; 32]).unwrap();
        let alice_pub = alice_priv.public_key();
        let alice_key_der = hitls_pki::pkcs8::encode_x25519_pkcs8_der(&[0x77u8; 32]);
        let alice_key_pem = hitls_utils::pem::encode("PRIVATE KEY", &alice_key_der);

        // Bob
        let bob_priv = hitls_crypto::x25519::X25519PrivateKey::new(&[0x88u8; 32]).unwrap();
        let bob_pub = bob_priv.public_key();
        let bob_key_der = hitls_pki::pkcs8::encode_x25519_pkcs8_der(&[0x88u8; 32]);
        let bob_key_pem = hitls_utils::pem::encode("PRIVATE KEY", &bob_key_der);

        // Encode public keys as SPKI PEM
        let alice_pub_der = hitls_pki::pkcs8::encode_x25519_spki_der(alice_pub.as_bytes());
        let alice_pub_pem = hitls_pki::pkcs8::encode_spki_pem(&alice_pub_der);
        let bob_pub_der = hitls_pki::pkcs8::encode_x25519_spki_der(bob_pub.as_bytes());
        let bob_pub_pem = hitls_pki::pkcs8::encode_spki_pem(&bob_pub_der);

        // Alice derives shared secret with Bob's public key
        let shared_alice = do_derive(&alice_key_pem, &bob_pub_pem).unwrap();
        // Bob derives shared secret with Alice's public key
        let shared_bob = do_derive(&bob_key_pem, &alice_pub_pem).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 32);
    }

    #[test]
    fn test_pkeyutl_derive_ecdh_p256() {
        // Alice
        let alice_kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let alice_priv_bytes = alice_kp.private_key_bytes();
        let alice_pub_bytes = alice_kp.public_key_bytes().unwrap();
        let alice_key_der = hitls_pki::pkcs8::encode_ec_pkcs8_der(
            hitls_types::EccCurveId::NistP256,
            &alice_priv_bytes,
        );
        let alice_key_pem = hitls_utils::pem::encode("PRIVATE KEY", &alice_key_der);

        // Bob
        let bob_kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let bob_priv_bytes = bob_kp.private_key_bytes();
        let bob_pub_bytes = bob_kp.public_key_bytes().unwrap();
        let bob_key_der = hitls_pki::pkcs8::encode_ec_pkcs8_der(
            hitls_types::EccCurveId::NistP256,
            &bob_priv_bytes,
        );
        let bob_key_pem = hitls_utils::pem::encode("PRIVATE KEY", &bob_key_der);

        // Encode public keys as SPKI PEM
        let alice_pub_der = hitls_pki::pkcs8::encode_ec_spki_der(
            hitls_types::EccCurveId::NistP256,
            &alice_pub_bytes,
        );
        let alice_pub_pem = hitls_pki::pkcs8::encode_spki_pem(&alice_pub_der);
        let bob_pub_der =
            hitls_pki::pkcs8::encode_ec_spki_der(hitls_types::EccCurveId::NistP256, &bob_pub_bytes);
        let bob_pub_pem = hitls_pki::pkcs8::encode_spki_pem(&bob_pub_der);

        // Alice derives with Bob's pub
        let shared_alice = do_derive(&alice_key_pem, &bob_pub_pem).unwrap();
        // Bob derives with Alice's pub
        let shared_bob = do_derive(&bob_key_pem, &alice_pub_pem).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 32); // P-256 shared secret is 32 bytes
    }

    #[test]
    fn test_pkeyutl_derive_type_mismatch() {
        // X25519 private key
        let key_der = hitls_pki::pkcs8::encode_x25519_pkcs8_der(&[0x77u8; 32]);
        let key_pem = hitls_utils::pem::encode("PRIVATE KEY", &key_der);

        // EC P-256 peer public key
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let pub_bytes = kp.public_key_bytes().unwrap();
        let peer_der =
            hitls_pki::pkcs8::encode_ec_spki_der(hitls_types::EccCurveId::NistP256, &pub_bytes);
        let peer_pem = hitls_pki::pkcs8::encode_spki_pem(&peer_der);

        let result = do_derive(&key_pem, &peer_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkeyutl_derive_x448() {
        // Alice
        let alice_priv = hitls_crypto::x448::X448PrivateKey::new(&[0x55u8; 56]).unwrap();
        let alice_pub = alice_priv.public_key();
        let alice_key_der = hitls_pki::pkcs8::encode_x448_pkcs8_der(&[0x55u8; 56]);
        let alice_key_pem = hitls_utils::pem::encode("PRIVATE KEY", &alice_key_der);

        // Bob
        let bob_priv = hitls_crypto::x448::X448PrivateKey::new(&[0x66u8; 56]).unwrap();
        let bob_pub = bob_priv.public_key();
        let bob_key_der = hitls_pki::pkcs8::encode_x448_pkcs8_der(&[0x66u8; 56]);
        let bob_key_pem = hitls_utils::pem::encode("PRIVATE KEY", &bob_key_der);

        // Encode public keys as SPKI PEM
        let alice_pub_der = hitls_pki::pkcs8::encode_x448_spki_der(alice_pub.as_bytes());
        let alice_pub_pem = hitls_pki::pkcs8::encode_spki_pem(&alice_pub_der);
        let bob_pub_der = hitls_pki::pkcs8::encode_x448_spki_der(bob_pub.as_bytes());
        let bob_pub_pem = hitls_pki::pkcs8::encode_spki_pem(&bob_pub_der);

        let shared_alice = do_derive(&alice_key_pem, &bob_pub_pem).unwrap();
        let shared_bob = do_derive(&bob_key_pem, &alice_pub_pem).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 56);
    }

    #[test]
    fn test_pkeyutl_sign_verify_ecdsa() {
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let priv_bytes = kp.private_key_bytes();
        let key_der =
            hitls_pki::pkcs8::encode_ec_pkcs8_der(hitls_types::EccCurveId::NistP256, &priv_bytes);
        let key_pem = hitls_utils::pem::encode("PRIVATE KEY", &key_der);

        let data = b"ECDSA sign/verify test message";
        let sig = do_sign(&key_pem, data).unwrap();
        assert!(!sig.is_empty());

        // Verify should succeed
        do_verify(&key_pem, data, &sig).unwrap();
    }

    #[test]
    fn test_pkeyutl_sign_verify_ed448() {
        let seed = [0x55u8; 57];
        let key_der = hitls_pki::pkcs8::encode_ed448_pkcs8_der(&seed);
        let key_pem = hitls_utils::pem::encode("PRIVATE KEY", &key_der);

        let data = b"Ed448 sign/verify test message";
        let sig = do_sign(&key_pem, data).unwrap();
        assert_eq!(sig.len(), 114); // Ed448 signature size

        // Verify should succeed
        do_verify(&key_pem, data, &sig).unwrap();
    }

    #[test]
    fn test_pkeyutl_verify_rsa_pss() {
        // Use RSA PEM key from test data
        let key_pem = "\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvU/3U/Xy0GV9p
alx4PRscBL/vllV808hJ6RKS8dDDqQYghIkqhSAMZTWltzM6J9zPzbaHGp99mrhC
yuUpWCt74SLYhpc1b2a4Oro8VWIihRpPQ1EGgjWZ8tShKDLtmhh+ewYMwHawX5RE
3KynwTfS1ajHLRvxTaftn5ZdVfIVpoiIiBpZ73QFABhZxI6dxvu6TDbcDTjqTExj
HjmsyEvUa2PyL+JSglg/MZNBONYSFIaezkpcdFa6FMx6XW4iVz561IMBdVBEc6II
7qWoQJa+lPsKEFQ8P+iG2uvZQSIboddLdOl9IEGZ4EHcMJTzxh17GaCA7BE/Mlsc
7BYph9wTAgMBAAECggEAVHY2ZGpfLlXAyIQ0Grp5OlSxcAZwlWti4/QzffWfN/rP
mE+w0nqCV2ZUY0ovk/cLIVJ8+XXiWnx0Ar1Ci1nNzOZGxp+D7XqGtf6YpCMP3QhZ
BdEskeGdV9YLB73ZVuwym4/BeNgo9Ut+HnReeowSy+8g2R7KhML/wHHuWnViY3nj
hRnd2tit+y8MQcz8fOcgTT6Uuk6XeEutDMN7FoiLIyNX+mKWtsJbeLFWpHVm9ZM/
R7wa4T/NeFVhfJbJ9YTrZDeLX2dm+F6ynYTJXZvl5KX/pDtQDMkCjadtDOVoc3S1
LYEXAq6F7rcw+S8T0sDrZxGOUw8xAWUmUlL2oSKpOQKBgQDIrom9u3bdJrzglRDP
QuA/dx4IFuZOUaVYPG3NgG/XGtx1yKF2p+XqSWI1wb4fe59S6oJj9KhUKpEZYFoW
c9zgVtl9NsU1gtXfSAuy0pAwTOTdFDzO+b9IIg6zGrh0UT83Ett/zoU2OZWej7xk
ZxCLTZ7lXav+OwquIMMsjFW3KQKBgQDfqFNOwGrWrPyLQGBS9uz4IAOysY0Nydd3
9et7ivzgVAj2p3pb8OuCuMhHmCMd7ocIrijCtF5ppNQ9UhkNhq6crlA9L5jRVLd4
GJTjYnnnA2qNGklu51Q/5XHPMTndXmbrE+jq1VLmx7pGd/XEy83gDXNsB4sLsYgH
OLZd+bRM2wKBgE0H0g9mGeYhrHZ4QY+NGA7EZl6si5KcfF82Mt+i4UssIFuFu5SU
NgiMSopf596l0S4+nfZIPySvgiq/dVUQ/EOQksMhdulnYzjlqrflYztnCKJj1kOM
UgQaLpJJO2xKk31MW7zfRPrfd7L5cVMIzKzsCoX4QsC/YQYdxU0gQPahAoGAenii
/bmyB1H8jIg49tVOF+T4AW7mTYmcWo0oYKNQK8r4iZBWGWiInjFvQn0VpbtK6D7u
BQhdtr3Slq2RGG4KybNOLuMUbHRWbwYO6aCwHgcp3pBpa7hy0vZiZtGO3SBnfQyO
+6DK36K45wOjahsr5ieXb62Fv2Z8lW/BtR4aVAcCgYEAicMLTwUle3fprqZy/Bwr
yoGhy+CaKyBWDwF2/JBMFzze9LiOqHkjW4zps4RBaHvRv84AALX0c68HUEuXZUWj
zwS7ekmeex/ZRkHXaFTKnywwOraGSJAlcwAwlMNLCrkZn9wm79fcuaRoBCCYpCZL
5U2HZPvTIa7Iry46elKZq3g=
-----END PRIVATE KEY-----";

        let data = b"RSA PSS sign/verify test";
        let sig = do_sign(key_pem, data).unwrap();
        assert!(!sig.is_empty());

        // Verify should succeed
        do_verify(key_pem, data, &sig).unwrap();
    }

    #[test]
    fn test_pkeyutl_sign_unsupported_x25519() {
        let key_der = hitls_pki::pkcs8::encode_x25519_pkcs8_der(&[0x77u8; 32]);
        let key_pem = hitls_utils::pem::encode("PRIVATE KEY", &key_der);

        let result = do_sign(&key_pem, b"test");
        assert!(result.is_err());
    }
}
