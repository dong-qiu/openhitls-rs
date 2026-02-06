//! Montgomery multiplication context for modular exponentiation.

use crate::bignum::BigNum;

/// Montgomery multiplication context.
///
/// Precomputes values needed for efficient modular multiplication
/// using the Montgomery form.
pub struct MontgomeryCtx {
    /// The modulus N.
    pub modulus: BigNum,
    /// R = 2^(k * LIMB_BITS) where k = number of limbs in modulus.
    pub r_bits: usize,
    /// N' such that N * N' ≡ -1 (mod 2^LIMB_BITS).
    pub n_prime: u64,
}

impl MontgomeryCtx {
    /// Create a new Montgomery context for the given odd modulus.
    ///
    /// # Panics
    /// Panics if modulus is even or zero.
    pub fn new(modulus: &BigNum) -> Self {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        assert!(modulus.limbs()[0] & 1 == 1, "modulus must be odd");

        let r_bits = modulus.num_limbs() * 64;
        let n_prime = compute_n_prime(modulus.limbs()[0]);

        MontgomeryCtx {
            modulus: modulus.clone(),
            r_bits,
            n_prime,
        }
    }
}

/// Compute N' such that N * N' ≡ -1 (mod 2^64).
///
/// Uses the Newton's method approach for computing modular inverse.
fn compute_n_prime(n0: u64) -> u64 {
    // We want x such that n0 * x ≡ -1 (mod 2^64)
    // Start with x = 1, then iterate: x = x * (2 - n0 * x)
    let mut x: u64 = 1;
    for _ in 0..63 {
        x = x.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(x)));
    }
    // We want -x mod 2^64
    x.wrapping_neg()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_n_prime() {
        // For an odd number n, n * n_prime ≡ -1 (mod 2^64)
        let n: u64 = 0xFFFF_FFFF_FFFF_FFEF; // A large odd number
        let np = compute_n_prime(n);
        assert_eq!(n.wrapping_mul(np), u64::MAX); // -1 mod 2^64
    }

    #[test]
    fn test_montgomery_ctx_creation() {
        let modulus = BigNum::from_u64(0xFFFFFFFFFFFFFFC5); // Odd number
        let ctx = MontgomeryCtx::new(&modulus);
        assert_eq!(ctx.r_bits, 64);
        // Verify n_prime property
        let check = modulus.limbs()[0].wrapping_mul(ctx.n_prime);
        assert_eq!(check, u64::MAX);
    }
}
