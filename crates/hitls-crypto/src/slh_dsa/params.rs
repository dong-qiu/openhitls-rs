//! SLH-DSA parameter sets (FIPS 205 Table 2).

use hitls_types::SlhDsaParamId;

/// SLH-DSA parameter set.
pub(crate) struct SlhDsaParams {
    pub n: usize,         // Security parameter (hash output length in bytes)
    pub h: usize,         // Total tree height
    pub d: usize,         // Number of hypertree layers
    pub hp: usize,        // Per-layer tree height (h/d)
    pub a: usize,         // FORS tree height
    pub k: usize,         // Number of FORS trees
    pub m: usize,         // Message digest length in bytes
    pub wots_len: usize,  // WOTS+ chain count = 2*n + 3
    pub sig_bytes: usize, // Total signature size
    pub is_sha2: bool,    // true = SHA-2 mode (compressed ADRS), false = SHAKE mode
    pub sec_category: u8, // Security category: 1 (128-bit), 3 (192-bit), 5 (256-bit)
}

// FIPS 205 Table 2 parameter sets, ordered by SlhDsaParamId enum order:
// Sha2128s, Shake128s, Sha2128f, Shake128f,
// Sha2192s, Shake192s, Sha2192f, Shake192f,
// Sha2256s, Shake256s, Sha2256f, Shake256f
static PARAMS: [SlhDsaParams; 12] = [
    // SHA2-128S
    SlhDsaParams {
        n: 16,
        h: 63,
        d: 7,
        hp: 9,
        a: 12,
        k: 14,
        m: 30,
        wots_len: 35,
        sig_bytes: 7856,
        is_sha2: true,
        sec_category: 1,
    },
    // SHAKE-128S
    SlhDsaParams {
        n: 16,
        h: 63,
        d: 7,
        hp: 9,
        a: 12,
        k: 14,
        m: 30,
        wots_len: 35,
        sig_bytes: 7856,
        is_sha2: false,
        sec_category: 1,
    },
    // SHA2-128F
    SlhDsaParams {
        n: 16,
        h: 66,
        d: 22,
        hp: 3,
        a: 6,
        k: 33,
        m: 34,
        wots_len: 35,
        sig_bytes: 17088,
        is_sha2: true,
        sec_category: 1,
    },
    // SHAKE-128F
    SlhDsaParams {
        n: 16,
        h: 66,
        d: 22,
        hp: 3,
        a: 6,
        k: 33,
        m: 34,
        wots_len: 35,
        sig_bytes: 17088,
        is_sha2: false,
        sec_category: 1,
    },
    // SHA2-192S
    SlhDsaParams {
        n: 24,
        h: 63,
        d: 7,
        hp: 9,
        a: 14,
        k: 17,
        m: 39,
        wots_len: 51,
        sig_bytes: 16224,
        is_sha2: true,
        sec_category: 3,
    },
    // SHAKE-192S
    SlhDsaParams {
        n: 24,
        h: 63,
        d: 7,
        hp: 9,
        a: 14,
        k: 17,
        m: 39,
        wots_len: 51,
        sig_bytes: 16224,
        is_sha2: false,
        sec_category: 3,
    },
    // SHA2-192F
    SlhDsaParams {
        n: 24,
        h: 66,
        d: 22,
        hp: 3,
        a: 8,
        k: 33,
        m: 42,
        wots_len: 51,
        sig_bytes: 35664,
        is_sha2: true,
        sec_category: 3,
    },
    // SHAKE-192F
    SlhDsaParams {
        n: 24,
        h: 66,
        d: 22,
        hp: 3,
        a: 8,
        k: 33,
        m: 42,
        wots_len: 51,
        sig_bytes: 35664,
        is_sha2: false,
        sec_category: 3,
    },
    // SHA2-256S
    SlhDsaParams {
        n: 32,
        h: 64,
        d: 8,
        hp: 8,
        a: 14,
        k: 22,
        m: 47,
        wots_len: 67,
        sig_bytes: 29792,
        is_sha2: true,
        sec_category: 5,
    },
    // SHAKE-256S
    SlhDsaParams {
        n: 32,
        h: 64,
        d: 8,
        hp: 8,
        a: 14,
        k: 22,
        m: 47,
        wots_len: 67,
        sig_bytes: 29792,
        is_sha2: false,
        sec_category: 5,
    },
    // SHA2-256F
    SlhDsaParams {
        n: 32,
        h: 68,
        d: 17,
        hp: 4,
        a: 9,
        k: 35,
        m: 49,
        wots_len: 67,
        sig_bytes: 49856,
        is_sha2: true,
        sec_category: 5,
    },
    // SHAKE-256F
    SlhDsaParams {
        n: 32,
        h: 68,
        d: 17,
        hp: 4,
        a: 9,
        k: 35,
        m: 49,
        wots_len: 67,
        sig_bytes: 49856,
        is_sha2: false,
        sec_category: 5,
    },
];

pub(crate) fn get_params(param_id: SlhDsaParamId) -> &'static SlhDsaParams {
    let idx = match param_id {
        SlhDsaParamId::Sha2128s => 0,
        SlhDsaParamId::Shake128s => 1,
        SlhDsaParamId::Sha2128f => 2,
        SlhDsaParamId::Shake128f => 3,
        SlhDsaParamId::Sha2192s => 4,
        SlhDsaParamId::Shake192s => 5,
        SlhDsaParamId::Sha2192f => 6,
        SlhDsaParamId::Shake192f => 7,
        SlhDsaParamId::Sha2256s => 8,
        SlhDsaParamId::Shake256s => 9,
        SlhDsaParamId::Sha2256f => 10,
        SlhDsaParamId::Shake256f => 11,
    };
    &PARAMS[idx]
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_types::SlhDsaParamId;

    #[test]
    fn test_params_fips205_table2_values() {
        // Shake128f
        let p = get_params(SlhDsaParamId::Shake128f);
        assert_eq!(p.n, 16);
        assert_eq!(p.h, 66);
        assert_eq!(p.d, 22);
        assert_eq!(p.hp, 3);
        assert_eq!(p.a, 6);
        assert_eq!(p.k, 33);
        assert_eq!(p.m, 34);
        assert_eq!(p.wots_len, 35);
        assert_eq!(p.sig_bytes, 17088);
        assert!(!p.is_sha2);
        assert_eq!(p.sec_category, 1);

        // Sha2256s
        let p = get_params(SlhDsaParamId::Sha2256s);
        assert_eq!(p.n, 32);
        assert_eq!(p.h, 64);
        assert_eq!(p.d, 8);
        assert_eq!(p.hp, 8);
        assert_eq!(p.a, 14);
        assert_eq!(p.k, 22);
        assert_eq!(p.m, 47);
        assert_eq!(p.wots_len, 67);
        assert_eq!(p.sig_bytes, 29792);
        assert!(p.is_sha2);
        assert_eq!(p.sec_category, 5);
    }

    #[test]
    fn test_params_structural_invariants() {
        let all_ids = [
            SlhDsaParamId::Sha2128s,
            SlhDsaParamId::Shake128s,
            SlhDsaParamId::Sha2128f,
            SlhDsaParamId::Shake128f,
            SlhDsaParamId::Sha2192s,
            SlhDsaParamId::Shake192s,
            SlhDsaParamId::Sha2192f,
            SlhDsaParamId::Shake192f,
            SlhDsaParamId::Sha2256s,
            SlhDsaParamId::Shake256s,
            SlhDsaParamId::Sha2256f,
            SlhDsaParamId::Shake256f,
        ];

        for (i, id) in all_ids.iter().enumerate() {
            let p = get_params(*id);

            // h == d * hp
            assert_eq!(p.h, p.d * p.hp, "h != d*hp for param set {}", i);

            // wots_len == 2*n + 3
            assert_eq!(
                p.wots_len,
                2 * p.n + 3,
                "wots_len != 2n+3 for param set {}",
                i
            );

            // sig_bytes == (d*(wots_len+hp) + k*(a+1) + 1) * n
            let expected_sig = (p.d * (p.wots_len + p.hp) + p.k * (p.a + 1) + 1) * p.n;
            assert_eq!(
                p.sig_bytes, expected_sig,
                "sig_bytes mismatch for param set {}",
                i
            );
        }
    }
}
