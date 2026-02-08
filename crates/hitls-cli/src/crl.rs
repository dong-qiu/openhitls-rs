//! CRL display command (stub implementation).

use std::fs;

pub fn run(input: &str, text: bool) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input)?;
    println!("CRL file: {input} ({} bytes)", data.len());

    if text {
        // Parse as PEM if possible
        if let Ok(pem_str) = std::str::from_utf8(&data) {
            if let Ok(blocks) = hitls_utils::pem::parse(pem_str) {
                for block in &blocks {
                    println!(
                        "  PEM block: {} ({} bytes DER)",
                        block.label,
                        block.data.len()
                    );
                }
                return Ok(());
            }
        }
        println!("  (DER format, {} bytes)", data.len());
    }

    eprintln!("Note: Full CRL parsing is not yet implemented");
    Ok(())
}
