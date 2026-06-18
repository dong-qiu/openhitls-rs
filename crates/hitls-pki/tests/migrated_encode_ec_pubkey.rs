// crypto/encode — EC PKCS#8 byte-exact re-encode with SEC1 [1] publicKey (A2).
//
// Follow-up to Phase 3b (T292), which migrated the EC private key as decode-only
// because `encode_ec_pkcs8_der` omits the SEC1 OPTIONAL `[1] publicKey` that the
// C `SDV_BSL_ASN1_ENCODE_PRIKEY_BUFF` vector carries. I-phase A2 added
// `encode_ec_pkcs8_der_with_public_key`, which includes that field, so the C EC
// key now round-trips byte-exact: parse_pkcs8_der -> re-encode (with the public
// point derived from the parsed key pair) == the inline `asn1`.

#![cfg(all(feature = "x509", feature = "pkcs8"))]

use hitls_pki::pkcs8::{encode_ec_pkcs8_der_with_public_key, parse_pkcs8_der, Pkcs8PrivateKey};
use hitls_utils::hex::hex;

// C SDV ENCODE_PRIKEY_BUFF (CRYPT_PRIKEY_PKCS8_UNENCRYPT) P-384 EC private key,
// whose SEC1 ECPrivateKey includes the `[1] publicKey` field.
const EC_P384_PKCS8: &str = "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b020101043011f1ad7fd68d2bdc0fe972b521d6416b1c2d0d6ea82875b1ae97b05be297d9e7990db33f08882fdee4a285c1d87472c8a16403620004aebf47bd84a597cb41f09e1f28e13813993476c2840084dab242737516d1231b5db3cd30df7159e04abe5a6bed2f36016c2fdabb9a6f28ea558ccdd4b8e8aaca9e8aca0f55c04dad4f0f1028e4d4b0185e55c37cb25fcdfada182f0355b4aaad";

#[test]
fn tc_ec_pkcs8_reencode_with_public_key_byte_exact() {
    let der = hex(EC_P384_PKCS8);
    let key = parse_pkcs8_der(&der).expect("parse EC PKCS#8");
    match key {
        Pkcs8PrivateKey::Ec { curve_id, key_pair } => {
            let re = encode_ec_pkcs8_der_with_public_key(
                curve_id,
                &key_pair.private_key_bytes(),
                &key_pair.public_key_bytes().expect("derive EC public key"),
            );
            assert_eq!(
                re, der,
                "EC PKCS#8 re-encode (with SEC1 [1] publicKey) must be byte-exact"
            );
        }
        _ => panic!("expected an EC private key"),
    }
}
