//! Prime number generation and testing command.

use hitls_bignum::BigNum;

pub fn run(args: &PrimeArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.generate {
        let bits = args.bits.unwrap_or(256);
        if bits < 2 {
            return Err("bits must be >= 2".into());
        }
        let p = BigNum::gen_prime(bits, args.safe)?;
        if args.hex {
            println!("{}", p.to_hex_str());
        } else {
            println!("{}", p.to_dec_str());
        }
    } else {
        // Check mode: read number from args
        let number = args
            .number
            .as_deref()
            .ok_or("no number provided for primality check")?;

        let n = if args.hex {
            BigNum::from_hex_str(number)?
        } else {
            BigNum::from_dec_str(number)?
        };

        let checks = args.checks.unwrap_or(20);
        let is_prime = n.is_probably_prime(checks)?;

        if is_prime {
            println!("{number} is probably prime");
        } else {
            println!("{number} is composite");
            std::process::exit(1);
        }
    }
    Ok(())
}

pub struct PrimeArgs {
    pub generate: bool,
    pub bits: Option<usize>,
    pub safe: bool,
    pub hex: bool,
    pub checks: Option<usize>,
    pub number: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prime_check_known_prime() {
        let args = PrimeArgs {
            generate: false,
            bits: None,
            safe: false,
            hex: false,
            checks: Some(20),
            number: Some("997".to_string()),
        };
        assert!(run(&args).is_ok());
    }

    #[test]
    fn test_prime_check_hex() {
        // 0x101 = 257, which is prime
        let args = PrimeArgs {
            generate: false,
            bits: None,
            safe: false,
            hex: true,
            checks: Some(20),
            number: Some("101".to_string()),
        };
        assert!(run(&args).is_ok());
    }

    #[test]
    fn test_prime_generate_roundtrip() {
        let args = PrimeArgs {
            generate: true,
            bits: Some(64),
            safe: false,
            hex: false,
            checks: None,
            number: None,
        };
        assert!(run(&args).is_ok());
    }

    #[test]
    fn test_prime_generate_hex() {
        let args = PrimeArgs {
            generate: true,
            bits: Some(64),
            safe: false,
            hex: true,
            checks: None,
            number: None,
        };
        assert!(run(&args).is_ok());
    }

    #[test]
    fn test_prime_missing_number() {
        let args = PrimeArgs {
            generate: false,
            bits: None,
            safe: false,
            hex: false,
            checks: None,
            number: None,
        };
        assert!(run(&args).is_err());
    }

    #[test]
    fn test_prime_generate_invalid_bits() {
        let args = PrimeArgs {
            generate: true,
            bits: Some(1),
            safe: false,
            hex: false,
            checks: None,
            number: None,
        };
        assert!(run(&args).is_err());
    }
}
