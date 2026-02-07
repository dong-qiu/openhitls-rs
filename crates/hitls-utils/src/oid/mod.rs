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
    pub fn prime256v1() -> Oid {
        Oid::new(&[1, 2, 840, 10045, 3, 1, 7])
    }
    pub fn secp384r1() -> Oid {
        Oid::new(&[1, 3, 132, 0, 34])
    }
    pub fn secp521r1() -> Oid {
        Oid::new(&[1, 3, 132, 0, 35])
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
}
