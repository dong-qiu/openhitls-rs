//! Prime number generation and testing command.

use hitls_bignum::BigNum;

pub fn run(args: &PrimeArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.generate {
        if args.number.is_some() {
            return Err("cannot combine -generate with a number argument".into());
        }
        let bits = args.bits.ok_or("missing -bits for -generate")?;
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
        if args.bits.is_some() {
            return Err("-bits requires -generate".into());
        }
        let number = args
            .number
            .as_deref()
            .ok_or("no number provided for primality check")?;

        let n = if args.hex {
            BigNum::from_hex_str(number).map_err(|_| "invalid hex number")?
        } else {
            BigNum::from_dec_str(number).map_err(|_| "invalid decimal number")?
        };

        let checks = args.checks.unwrap_or(20);
        let is_prime = n.is_probably_prime(checks)?;

        if is_prime {
            println!("{number} is probably prime");
        } else {
            println!("{number} is composite");
            return Err("composite".into());
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

    fn check_args(number: &str, hex: bool, checks: Option<usize>) -> PrimeArgs {
        PrimeArgs {
            generate: false,
            bits: None,
            safe: false,
            hex,
            checks,
            number: Some(number.to_string()),
        }
    }

    fn gen_args(bits: Option<usize>, safe: bool, hex: bool) -> PrimeArgs {
        PrimeArgs {
            generate: true,
            bits,
            safe,
            hex,
            checks: None,
            number: None,
        }
    }

    #[test]
    fn test_prime_check_known_prime() {
        assert!(run(&check_args("997", false, Some(20))).is_ok());
    }

    #[test]
    fn test_prime_check_hex() {
        assert!(run(&check_args("101", true, Some(20))).is_ok());
    }

    #[test]
    fn test_prime_generate_roundtrip() {
        assert!(run(&gen_args(Some(64), false, false)).is_ok());
    }

    #[test]
    fn test_prime_generate_hex() {
        assert!(run(&gen_args(Some(64), false, true)).is_ok());
    }

    // ---- C SDV migrated tests ----

    // C TC002: -generate -bits 16 -safe → SUCCESS
    #[test]
    fn test_prime_generate_safe_16bit() {
        assert!(run(&gen_args(Some(16), true, false)).is_ok());
    }

    // C TC003 (extended): check more decimal/hex primes incl. hex composite
    #[test]
    fn test_prime_check_extended_known_primes() {
        for n in ["17", "97", "257"] {
            assert!(
                run(&check_args(n, false, Some(20))).is_ok(),
                "{n} should pass"
            );
        }
        // 0x101 = 257 (prime)
        assert!(run(&check_args("101", true, Some(20))).is_ok());
        // 0xFF = 255 (composite) → Err("composite")
        let err = run(&check_args("FF", true, Some(20))).unwrap_err();
        assert_eq!(err.to_string(), "composite");
    }

    // C TC004: -checks parameter accepted at 10/100/50
    #[test]
    fn test_prime_check_custom_checks() {
        for k in [10, 50, 100] {
            assert!(run(&check_args("17", false, Some(k))).is_ok(), "checks={k}");
        }
    }

    // C TC005 (subset of 9 invalid-arg cases): -bits without -generate / -generate without -bits / both gen+number
    #[test]
    fn test_prime_invalid_bits_without_generate() {
        let args = PrimeArgs {
            generate: false,
            bits: Some(256),
            safe: false,
            hex: false,
            checks: None,
            number: Some("17".to_string()),
        };
        let err = run(&args).unwrap_err();
        assert_eq!(err.to_string(), "-bits requires -generate");
    }

    #[test]
    fn test_prime_generate_missing_bits() {
        let err = run(&gen_args(None, false, false)).unwrap_err();
        assert_eq!(err.to_string(), "missing -bits for -generate");
    }

    #[test]
    fn test_prime_generate_with_number_rejected() {
        let args = PrimeArgs {
            generate: true,
            bits: Some(64),
            safe: false,
            hex: false,
            checks: None,
            number: Some("123".to_string()),
        };
        let err = run(&args).unwrap_err();
        assert_eq!(
            err.to_string(),
            "cannot combine -generate with a number argument"
        );
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
        let err = run(&args).unwrap_err();
        assert_eq!(err.to_string(), "no number provided for primality check");
    }

    #[test]
    fn test_prime_generate_invalid_bits() {
        let err = run(&gen_args(Some(1), false, false)).unwrap_err();
        assert_eq!(err.to_string(), "bits must be >= 2");
    }

    // C TC012: composite check returns failure
    #[test]
    fn test_prime_check_composite_returns_err() {
        let err = run(&check_args("15", false, Some(20))).unwrap_err();
        assert_eq!(err.to_string(), "composite");
    }

    // C TC013: invalid hex string → INVALID_ARG
    #[test]
    fn test_prime_check_invalid_hex() {
        let err = run(&check_args("ZZZ", true, Some(20))).unwrap_err();
        assert_eq!(err.to_string(), "invalid hex number");
    }

    // C TC014: invalid decimal string → INVALID_ARG
    #[test]
    fn test_prime_check_invalid_decimal() {
        let err = run(&check_args("not_a_number", false, Some(20))).unwrap_err();
        assert_eq!(err.to_string(), "invalid decimal number");
    }

    // C TC015: edge bit lengths 16 and 512
    #[test]
    fn test_prime_generate_edge_bit_lengths() {
        assert!(run(&gen_args(Some(16), false, false)).is_ok(), "16-bit");
        assert!(run(&gen_args(Some(512), false, false)).is_ok(), "512-bit");
    }
}
