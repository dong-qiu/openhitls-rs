//! List supported algorithms, cipher suites, curves, and hash functions.

pub fn run(filter: &str) -> Result<(), Box<dyn std::error::Error>> {
    match filter {
        "ciphers" => print_ciphers(),
        "hashes" => print_hashes(),
        "curves" => print_curves(),
        "kex" => print_kex(),
        "all" => {
            print_hashes();
            println!();
            print_ciphers();
            println!();
            print_curves();
            println!();
            print_kex();
            println!();
            print_tls13_suites();
            println!();
            print_tls12_suites();
        }
        _ => {
            eprintln!("Unknown filter: {filter}");
            eprintln!("Valid filters: all, ciphers, hashes, curves, kex");
            return Err("invalid filter".into());
        }
    }
    Ok(())
}

fn print_hashes() {
    println!("Hash algorithms:");
    for name in [
        "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512",
        "SHAKE128", "SHAKE256", "SM3", "MD5",
    ] {
        println!("  {name}");
    }
}

fn print_ciphers() {
    println!("Symmetric ciphers:");
    for name in [
        "AES-128-ECB",
        "AES-256-ECB",
        "AES-128-CBC",
        "AES-256-CBC",
        "AES-128-CTR",
        "AES-256-CTR",
        "AES-128-GCM",
        "AES-256-GCM",
        "AES-128-CCM",
        "AES-256-CCM",
        "AES-128-XTS",
        "AES-256-XTS",
        "ChaCha20-Poly1305",
        "SM4-ECB",
        "SM4-CBC",
        "SM4-CTR",
        "SM4-GCM",
        "SM4-CCM",
    ] {
        println!("  {name}");
    }
}

fn print_curves() {
    println!("Elliptic curves:");
    for name in [
        "P-224 (secp224r1)",
        "P-256 (secp256r1 / prime256v1)",
        "P-384 (secp384r1)",
        "P-521 (secp521r1)",
        "Brainpool-P256r1",
        "Brainpool-P384r1",
        "Brainpool-P512r1",
        "Curve25519 (X25519 / Ed25519)",
        "SM2",
    ] {
        println!("  {name}");
    }
}

fn print_kex() {
    println!("Key exchange groups:");
    for name in [
        "X25519 (0x001D)",
        "secp256r1 (0x0017)",
        "secp384r1 (0x0018)",
        "secp521r1 (0x0019)",
        "ffdhe2048 (0x0100)",
        "ffdhe3072 (0x0101)",
        "ffdhe4096 (0x0102)",
        "X25519MLKEM768 (0x6399)",
    ] {
        println!("  {name}");
    }
}

fn print_tls13_suites() {
    println!("TLS 1.3 cipher suites:");
    for name in [
        "TLS_AES_128_GCM_SHA256 (0x1301)",
        "TLS_AES_256_GCM_SHA384 (0x1302)",
        "TLS_CHACHA20_POLY1305_SHA256 (0x1303)",
        "TLS_AES_128_CCM_SHA256 (0x1304)",
        "TLS_AES_128_CCM_8_SHA256 (0x1305)",
    ] {
        println!("  {name}");
    }
}

fn print_tls12_suites() {
    println!("TLS 1.2 cipher suites (selection):");
    for name in [
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02C)",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8)",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9)",
        "TLS_RSA_WITH_AES_128_CCM (0xC09C)",
        "TLS_RSA_WITH_AES_256_CCM (0xC09D)",
        "TLS_DHE_RSA_WITH_AES_128_CCM (0xC09E)",
        "TLS_DHE_RSA_WITH_AES_256_CCM (0xC09F)",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CCM (0xC0AC)",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CCM (0xC0AD)",
        "TLS_RSA_WITH_AES_128_CCM_8 (0xC0A0)",
        "TLS_RSA_WITH_AES_256_CCM_8 (0xC0A1)",
        "TLS_PSK_WITH_AES_256_CCM (0xC0A5)",
        "TLS_DHE_PSK_WITH_AES_128_CCM (0xC0A6)",
        "TLS_DHE_PSK_WITH_AES_256_CCM (0xC0A7)",
        "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 (0xD005)",
        "TLS_PSK_WITH_AES_128_CBC_SHA256 (0x00AE)",
        "TLS_PSK_WITH_AES_256_CBC_SHA384 (0x00AF)",
        "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 (0x00B2)",
        "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 (0x00B3)",
        "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 (0x00B6)",
        "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 (0x00B7)",
        "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 (0xD001)",
        "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 (0xD002)",
    ] {
        println!("  {name}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_list_all() {
        // Should not error
        run("all").unwrap();
    }

    #[test]
    fn test_cli_list_invalid_filter() {
        assert!(run("invalid").is_err());
    }
}
