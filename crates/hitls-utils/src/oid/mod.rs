//! OID (Object Identifier) management.

use hitls_types::*;

/// A parsed OID represented as a sequence of arc values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Oid {
    arcs: Vec<u32>,
}

impl Oid {
    /// Create an OID from a slice of arc values.
    pub fn new(arcs: &[u32]) -> Self {
        Self {
            arcs: arcs.to_vec(),
        }
    }

    /// Return the arc values.
    pub fn arcs(&self) -> &[u32] {
        &self.arcs
    }

    /// Encode this OID to DER bytes (just the value, no tag/length).
    pub fn to_der_value(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        if self.arcs.len() >= 2 {
            buf.push((self.arcs[0] * 40 + self.arcs[1]) as u8);
            for &arc in &self.arcs[2..] {
                encode_arc(&mut buf, arc);
            }
        }
        buf
    }

    /// Parse an OID from DER value bytes.
    pub fn from_der_value(data: &[u8]) -> Result<Self, CryptoError> {
        if data.is_empty() {
            return Err(CryptoError::DecodeAsn1Fail);
        }
        let mut arcs = Vec::new();
        let first = data[0] as u32;
        arcs.push(first / 40);
        arcs.push(first % 40);

        let mut i = 1;
        while i < data.len() {
            let (arc, consumed) = decode_arc(&data[i..])?;
            arcs.push(arc);
            i += consumed;
        }

        Ok(Self { arcs })
    }

    /// Return the dotted-string representation (e.g., "1.2.840.113549.1.1.1").
    pub fn to_dot_string(&self) -> String {
        self.arcs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(".")
    }
}

impl std::fmt::Display for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_dot_string())
    }
}

fn encode_arc(buf: &mut Vec<u8>, mut value: u32) {
    if value < 0x80 {
        buf.push(value as u8);
        return;
    }
    let mut bytes = Vec::new();
    while value > 0 {
        bytes.push((value & 0x7F) as u8);
        value >>= 7;
    }
    bytes.reverse();
    for (i, b) in bytes.iter().enumerate() {
        if i < bytes.len() - 1 {
            buf.push(b | 0x80);
        } else {
            buf.push(*b);
        }
    }
}

fn decode_arc(data: &[u8]) -> Result<(u32, usize), CryptoError> {
    let mut value: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        value = value.checked_shl(7).ok_or(CryptoError::DecodeAsn1Fail)? | (byte & 0x7F) as u32;
        if (byte & 0x80) == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(CryptoError::DecodeAsn1Fail)
}

// Well-known OIDs
pub mod known {
    use super::Oid;

    // RSA
    pub fn rsa_encryption() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 1, 1])
    }
    pub fn sha256_with_rsa_encryption() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 1, 11])
    }
    pub fn sha384_with_rsa_encryption() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 1, 12])
    }
    pub fn sha512_with_rsa_encryption() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 1, 13])
    }
    pub fn rsassa_pss() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 1, 10])
    }

    // EC
    pub fn ec_public_key() -> Oid {
        Oid::new(&[1, 2, 840, 10045, 2, 1])
    }
    pub fn ecdsa_with_sha256() -> Oid {
        Oid::new(&[1, 2, 840, 10045, 4, 3, 2])
    }
    pub fn ecdsa_with_sha384() -> Oid {
        Oid::new(&[1, 2, 840, 10045, 4, 3, 3])
    }

    // Named curves
    pub fn secp224r1() -> Oid {
        Oid::new(&[1, 3, 132, 0, 33])
    }
    pub fn prime256v1() -> Oid {
        Oid::new(&[1, 2, 840, 10045, 3, 1, 7])
    }
    pub fn secp384r1() -> Oid {
        Oid::new(&[1, 3, 132, 0, 34])
    }
    pub fn secp521r1() -> Oid {
        Oid::new(&[1, 3, 132, 0, 35])
    }
    pub fn brainpool_p256r1() -> Oid {
        Oid::new(&[1, 3, 36, 3, 3, 2, 8, 1, 1, 7])
    }
    pub fn brainpool_p384r1() -> Oid {
        Oid::new(&[1, 3, 36, 3, 3, 2, 8, 1, 1, 11])
    }
    pub fn brainpool_p512r1() -> Oid {
        Oid::new(&[1, 3, 36, 3, 3, 2, 8, 1, 1, 13])
    }

    // Hash algorithms
    pub fn sha256() -> Oid {
        Oid::new(&[2, 16, 840, 1, 101, 3, 4, 2, 1])
    }
    pub fn sha384() -> Oid {
        Oid::new(&[2, 16, 840, 1, 101, 3, 4, 2, 2])
    }
    pub fn sha512() -> Oid {
        Oid::new(&[2, 16, 840, 1, 101, 3, 4, 2, 3])
    }

    // SM2/SM3
    pub fn sm2_sign() -> Oid {
        Oid::new(&[1, 2, 156, 10197, 1, 301, 1])
    }
    pub fn sm2_curve() -> Oid {
        Oid::new(&[1, 2, 156, 10197, 1, 301])
    }
    pub fn sm2_with_sm3() -> Oid {
        Oid::new(&[1, 2, 156, 10197, 1, 501])
    }
    pub fn sm3() -> Oid {
        Oid::new(&[1, 2, 156, 10197, 1, 401])
    }

    // Ed25519/X25519
    pub fn ed25519() -> Oid {
        Oid::new(&[1, 3, 101, 112])
    }
    pub fn x25519() -> Oid {
        Oid::new(&[1, 3, 101, 110])
    }

    // Ed448/X448
    pub fn ed448() -> Oid {
        Oid::new(&[1, 3, 101, 113])
    }
    pub fn x448() -> Oid {
        Oid::new(&[1, 3, 101, 111])
    }

    // AES
    pub fn aes128_cbc() -> Oid {
        Oid::new(&[2, 16, 840, 1, 101, 3, 4, 1, 2])
    }
    pub fn aes256_cbc() -> Oid {
        Oid::new(&[2, 16, 840, 1, 101, 3, 4, 1, 42])
    }

    // PKCS#7/CMS
    pub fn pkcs7_data() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 7, 1])
    }
    pub fn pkcs7_signed_data() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 7, 2])
    }
    pub fn pkcs7_enveloped_data() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 7, 3])
    }

    // DSA
    pub fn dsa() -> Oid {
        Oid::new(&[1, 2, 840, 10040, 4, 1])
    }

    // Additional signature OIDs
    pub fn sha1_with_rsa_encryption() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 1, 5])
    }
    pub fn ecdsa_with_sha512() -> Oid {
        Oid::new(&[1, 2, 840, 10045, 4, 3, 4])
    }

    // X.509 Extension OIDs (RFC 5280)
    pub fn basic_constraints() -> Oid {
        Oid::new(&[2, 5, 29, 19])
    }
    pub fn key_usage() -> Oid {
        Oid::new(&[2, 5, 29, 15])
    }
    pub fn ext_key_usage() -> Oid {
        Oid::new(&[2, 5, 29, 37])
    }
    pub fn subject_alt_name() -> Oid {
        Oid::new(&[2, 5, 29, 17])
    }
    pub fn subject_key_identifier() -> Oid {
        Oid::new(&[2, 5, 29, 14])
    }
    pub fn authority_key_identifier() -> Oid {
        Oid::new(&[2, 5, 29, 35])
    }
    pub fn crl_distribution_points() -> Oid {
        Oid::new(&[2, 5, 29, 31])
    }

    // CRL Extension OIDs (RFC 5280 §5.2)
    pub fn crl_number() -> Oid {
        Oid::new(&[2, 5, 29, 20])
    }
    pub fn crl_reason() -> Oid {
        Oid::new(&[2, 5, 29, 21])
    }
    pub fn invalidity_date() -> Oid {
        Oid::new(&[2, 5, 29, 24])
    }
    pub fn delta_crl_indicator() -> Oid {
        Oid::new(&[2, 5, 29, 27])
    }
    pub fn issuing_distribution_point() -> Oid {
        Oid::new(&[2, 5, 29, 28])
    }

    // PKIX Authority Information Access (RFC 5280 §4.2.2.1)
    pub fn authority_info_access() -> Oid {
        Oid::new(&[1, 3, 6, 1, 5, 5, 7, 1, 1])
    }
    pub fn ocsp() -> Oid {
        Oid::new(&[1, 3, 6, 1, 5, 5, 7, 48, 1])
    }
    pub fn ocsp_basic() -> Oid {
        Oid::new(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1])
    }
    pub fn ca_issuers() -> Oid {
        Oid::new(&[1, 3, 6, 1, 5, 5, 7, 48, 2])
    }

    // DN Attribute Type OIDs (X.520)
    pub fn common_name() -> Oid {
        Oid::new(&[2, 5, 4, 3])
    }
    pub fn country_name() -> Oid {
        Oid::new(&[2, 5, 4, 6])
    }
    pub fn organization_name() -> Oid {
        Oid::new(&[2, 5, 4, 10])
    }
    pub fn organizational_unit_name() -> Oid {
        Oid::new(&[2, 5, 4, 11])
    }
    pub fn state_or_province_name() -> Oid {
        Oid::new(&[2, 5, 4, 8])
    }
    pub fn locality_name() -> Oid {
        Oid::new(&[2, 5, 4, 7])
    }
    pub fn serial_number_attr() -> Oid {
        Oid::new(&[2, 5, 4, 5])
    }
    pub fn email_address() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 9, 1])
    }

    // PKCS#12 bag types (1.2.840.113549.1.12.10.1.*)
    pub fn pkcs12_bag_type_key() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 12, 10, 1, 1])
    }
    pub fn pkcs12_bag_type_pkcs8_shrouded_key() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 12, 10, 1, 2])
    }
    pub fn pkcs12_bag_type_cert() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 12, 10, 1, 3])
    }
    pub fn pkcs12_bag_type_crl() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 12, 10, 1, 4])
    }
    pub fn x509_certificate() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 9, 22, 1])
    }

    // PKCS#5 / PBES2
    pub fn pbes2() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 5, 13])
    }
    pub fn pbkdf2_oid() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 5, 12])
    }
    pub fn hmac_sha256_oid() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 2, 9])
    }
    pub fn hmac_sha1_oid() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 2, 7])
    }

    // PKCS#7 additional
    pub fn pkcs7_digested_data() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 7, 5])
    }
    pub fn pkcs7_encrypted_data() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 7, 6])
    }

    // CMS / PKCS#9 attributes
    pub fn pkcs9_content_type() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 9, 3])
    }
    pub fn pkcs9_message_digest() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 9, 4])
    }
    pub fn pkcs9_signing_time() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 9, 5])
    }
    pub fn pkcs9_friendly_name() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 9, 20])
    }
    pub fn pkcs9_local_key_id() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 9, 21])
    }

    // SHA-1
    pub fn sha1_oid() -> Oid {
        Oid::new(&[1, 3, 14, 3, 2, 26])
    }

    // AES-192-CBC
    pub fn aes192_cbc() -> Oid {
        Oid::new(&[2, 16, 840, 1, 101, 3, 4, 1, 22])
    }

    // AES-GCM
    pub fn aes128_gcm() -> Oid {
        Oid::new(&[2, 16, 840, 1, 101, 3, 4, 1, 6])
    }
    pub fn aes256_gcm() -> Oid {
        Oid::new(&[2, 16, 840, 1, 101, 3, 4, 1, 46])
    }

    // AES Key Wrap
    pub fn aes128_wrap() -> Oid {
        Oid::new(&[2, 16, 840, 1, 101, 3, 4, 1, 5])
    }
    pub fn aes256_wrap() -> Oid {
        Oid::new(&[2, 16, 840, 1, 101, 3, 4, 1, 45])
    }

    // RSA OAEP
    pub fn rsaes_oaep() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 1, 7])
    }

    // PKCS#9 extensionRequest (1.2.840.113549.1.9.14)
    pub fn extension_request() -> Oid {
        Oid::new(&[1, 2, 840, 113549, 1, 9, 14])
    }

    /// Map a well-known DN attribute OID to its short name.
    pub fn oid_to_dn_short_name(oid: &super::Oid) -> Option<&'static str> {
        let arcs = oid.arcs();
        match arcs {
            [2, 5, 4, 3] => Some("CN"),
            [2, 5, 4, 6] => Some("C"),
            [2, 5, 4, 10] => Some("O"),
            [2, 5, 4, 11] => Some("OU"),
            [2, 5, 4, 8] => Some("ST"),
            [2, 5, 4, 7] => Some("L"),
            [2, 5, 4, 5] => Some("serialNumber"),
            [1, 2, 840, 113549, 1, 9, 1] => Some("emailAddress"),
            _ => None,
        }
    }

    /// Map a DN short name to its well-known OID.
    pub fn dn_short_name_to_oid(name: &str) -> Option<super::Oid> {
        match name {
            "CN" => Some(common_name()),
            "C" => Some(country_name()),
            "O" => Some(organization_name()),
            "OU" => Some(organizational_unit_name()),
            "ST" => Some(state_or_province_name()),
            "L" => Some(locality_name()),
            "serialNumber" => Some(serial_number_attr()),
            "emailAddress" => Some(email_address()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_roundtrip() {
        let oid = Oid::new(&[1, 2, 840, 113549, 1, 1, 1]);
        let der = oid.to_der_value();
        let parsed = Oid::from_der_value(&der).unwrap();
        assert_eq!(oid, parsed);
    }

    #[test]
    fn test_dot_string() {
        let oid = Oid::new(&[1, 2, 840, 113549, 1, 1, 1]);
        assert_eq!(oid.to_dot_string(), "1.2.840.113549.1.1.1");
    }

    #[test]
    fn test_rsa_encryption_oid_der() {
        // The well-known DER encoding of rsaEncryption OID
        let oid = known::rsa_encryption();
        let der = oid.to_der_value();
        assert_eq!(der, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]);
    }

    #[test]
    fn test_pkcs12_bag_oid_roundtrip() {
        let oids = [
            known::pkcs12_bag_type_key(),
            known::pkcs12_bag_type_pkcs8_shrouded_key(),
            known::pkcs12_bag_type_cert(),
            known::pkcs12_bag_type_crl(),
        ];
        for oid in &oids {
            let der = oid.to_der_value();
            let parsed = Oid::from_der_value(&der).unwrap();
            assert_eq!(oid, &parsed);
        }
    }

    #[test]
    fn test_pbes2_pbkdf2_oid_roundtrip() {
        let oids = [
            known::pbes2(),
            known::pbkdf2_oid(),
            known::hmac_sha256_oid(),
        ];
        for oid in &oids {
            let der = oid.to_der_value();
            let parsed = Oid::from_der_value(&der).unwrap();
            assert_eq!(oid, &parsed);
        }
    }

    #[test]
    fn test_pkcs9_oid_roundtrip() {
        let oids = [
            known::pkcs9_content_type(),
            known::pkcs9_message_digest(),
            known::pkcs9_signing_time(),
            known::pkcs9_friendly_name(),
            known::pkcs9_local_key_id(),
        ];
        for oid in &oids {
            let der = oid.to_der_value();
            let parsed = Oid::from_der_value(&der).unwrap();
            assert_eq!(oid, &parsed);
        }
    }

    #[test]
    fn test_sha1_oid_roundtrip() {
        let oid = known::sha1_oid();
        assert_eq!(oid.to_dot_string(), "1.3.14.3.2.26");
        let der = oid.to_der_value();
        let parsed = Oid::from_der_value(&der).unwrap();
        assert_eq!(oid, parsed);
    }

    #[test]
    fn test_dn_short_name_roundtrip() {
        let names = [
            "CN",
            "C",
            "O",
            "OU",
            "ST",
            "L",
            "serialNumber",
            "emailAddress",
        ];
        for name in &names {
            let oid = known::dn_short_name_to_oid(name).expect(name);
            let back = known::oid_to_dn_short_name(&oid).expect(name);
            assert_eq!(*name, back);
        }
        assert!(known::dn_short_name_to_oid("UNKNOWN").is_none());
    }
}
