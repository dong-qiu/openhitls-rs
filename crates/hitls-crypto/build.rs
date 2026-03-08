// Build script for hitls-crypto: detect rustc version for conditional features.

fn main() {
    // Declare custom cfg to avoid unexpected_cfgs warnings.
    // Use single-colon syntax for MSRV 1.75 compatibility.
    println!("cargo:rustc-check-cfg=cfg(has_sha512_arm_intrinsics)");
    println!("cargo:rustc-check-cfg=cfg(has_sha3_keccak_intrinsics)");
    println!("cargo:rustc-check-cfg=cfg(has_vaes_intrinsics)");

    // Detect Rust version to gate features that require newer intrinsics.
    // SHA-512 ARM intrinsics (vsha512*) and SHA-3 Keccak intrinsics
    // (veor3q, vbcaxq, vrax1q) were stabilized in Rust 1.79.
    let version = rustc_minor_version();
    if version >= 79 {
        println!("cargo:rustc-cfg=has_sha512_arm_intrinsics");
        println!("cargo:rustc-cfg=has_sha3_keccak_intrinsics");
    }

    // VAES (256-bit AES) and VPCLMULQDQ (256-bit carry-less multiply)
    // intrinsics were stabilized in Rust 1.78.
    if version >= 78 {
        println!("cargo:rustc-cfg=has_vaes_intrinsics");
    }
}

fn rustc_minor_version() -> u32 {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = std::process::Command::new(rustc)
        .arg("--version")
        .output()
        .expect("failed to run rustc --version");
    let version = String::from_utf8(output.stdout).expect("non-utf8 rustc output");
    // Parse "rustc 1.XX.Y ..." → extract XX
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() >= 2 {
        parts[1].parse().unwrap_or(0)
    } else {
        0
    }
}
