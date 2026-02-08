//! Key display/conversion command (partial implementation).

use std::fs;

pub fn run(input: &str, pubout: bool, text: bool) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read_to_string(input)?;
    let blocks = hitls_utils::pem::parse(&data)?;

    if blocks.is_empty() {
        return Err(format!("no PEM blocks found in {input}").into());
    }

    for block in &blocks {
        println!("--- {} ({} bytes) ---", block.label, block.data.len());
        if text {
            // Hex dump of key data
            for (i, chunk) in block.data.chunks(16).enumerate() {
                print!("    {:04x}: ", i * 16);
                for b in chunk {
                    print!("{b:02x}");
                }
                println!();
            }
        }
        if pubout {
            // Re-encode as PEM
            let pem = hitls_utils::pem::encode(&block.label, &block.data);
            print!("{pem}");
        }
    }

    Ok(())
}
