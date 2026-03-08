/// Decode a hex string into bytes.
///
/// # Panics
/// Panics if the string length is odd or contains non-hex characters.
pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit pair"))
        .collect()
}

/// Encode bytes as a lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_hex_roundtrip(
            data in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let encoded = to_hex(&data);
            let decoded = hex(&encoded);
            prop_assert_eq!(decoded, data);
        }
    }
}
