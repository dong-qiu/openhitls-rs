//! HMAC-based library integrity check for FIPS 140-3.
//!
//! Computes HMAC-SHA256 of a library file and compares against a reference
//! value to detect tampering or corruption.

use hitls_types::CmvpError;

/// Compute HMAC-SHA256 over data with the given key.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CmvpError> {
    use crate::hmac::Hmac;
    use crate::sha2::Sha256;

    Hmac::mac(
        || Box::new(Sha256::new()) as Box<dyn crate::provider::Digest>,
        key,
        data,
    )
    .map_err(|_| CmvpError::IntegrityError)
}

/// Check the integrity of a library file using HMAC-SHA256.
///
/// Reads the file at `lib_path`, computes `HMAC-SHA256(key, file_contents)`,
/// and compares the result against `expected_hmac` in constant time.
pub(crate) fn check_integrity(
    lib_path: &str,
    key: &[u8],
    expected_hmac: &[u8],
) -> Result<(), CmvpError> {
    use subtle::ConstantTimeEq;

    // Read the library file
    let file_data = std::fs::read(lib_path).map_err(|_| CmvpError::IntegrityError)?;

    // Compute HMAC-SHA256
    let computed = hmac_sha256(key, &file_data)?;

    // Constant-time comparison
    if expected_hmac.len() != 32 {
        return Err(CmvpError::IntegrityError);
    }
    let equal: bool = computed.ct_eq(expected_hmac).into();
    if !equal {
        return Err(CmvpError::IntegrityError);
    }

    Ok(())
}

/// Compute the HMAC-SHA256 of a file for generating reference values.
///
/// This is a utility for generating the expected HMAC during build/release.
pub fn compute_file_hmac(lib_path: &str, key: &[u8]) -> Result<Vec<u8>, CmvpError> {
    let file_data = std::fs::read(lib_path).map_err(|_| CmvpError::IntegrityError)?;
    hmac_sha256(key, &file_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_integrity_check_pass() {
        let dir = std::env::temp_dir();
        let path = dir.join("fips_integrity_test.bin");
        let path_str = path.to_str().unwrap();

        let data = b"test library content for integrity check";
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(data).unwrap();
        }

        let key = b"integrity-key-for-test";
        let expected = compute_file_hmac(path_str, key).unwrap();
        assert_eq!(expected.len(), 32);

        check_integrity(path_str, key, &expected).unwrap();

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_integrity_check_fail_wrong_hmac() {
        let dir = std::env::temp_dir();
        let path = dir.join("fips_integrity_test_fail.bin");
        let path_str = path.to_str().unwrap();

        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"test library content").unwrap();
        }

        let wrong_hmac = [0xABu8; 32];
        let result = check_integrity(path_str, b"integrity-key", &wrong_hmac);
        assert!(result.is_err());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_integrity_check_fail_missing_file() {
        let result = check_integrity("/nonexistent/file.so", b"key", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_integrity_check_fail_wrong_hmac_len() {
        let dir = std::env::temp_dir();
        let path = dir.join("fips_integrity_test_len.bin");
        let path_str = path.to_str().unwrap();

        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"data").unwrap();
        }

        let result = check_integrity(path_str, b"key", &[0u8; 16]);
        assert!(result.is_err());

        std::fs::remove_file(&path).ok();
    }
}
