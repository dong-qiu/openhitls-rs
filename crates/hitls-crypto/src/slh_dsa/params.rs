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

    const ALL_IDS: [SlhDsaParamId; 12] = [
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

    #[test]
    fn test_sha2_shake_pairs_identical_except_mode() {
        // Params come in SHA2/SHAKE pairs: indices 0/1, 2/3, 4/5, 6/7, 8/9, 10/11
        for chunk in ALL_IDS.chunks(2) {
            let sha2 = get_params(chunk[0]);
            let shake = get_params(chunk[1]);
            assert_eq!(sha2.n, shake.n);
            assert_eq!(sha2.h, shake.h);
            assert_eq!(sha2.d, shake.d);
            assert_eq!(sha2.hp, shake.hp);
            assert_eq!(sha2.a, shake.a);
            assert_eq!(sha2.k, shake.k);
            assert_eq!(sha2.m, shake.m);
            assert_eq!(sha2.wots_len, shake.wots_len);
            assert_eq!(sha2.sig_bytes, shake.sig_bytes);
            assert_eq!(sha2.sec_category, shake.sec_category);
            assert!(sha2.is_sha2);
            assert!(!shake.is_sha2);
        }
    }

    #[test]
    fn test_security_category_mapping() {
        for id in &ALL_IDS {
            let p = get_params(*id);
            match p.n {
                16 => assert_eq!(p.sec_category, 1, "n=16 should be cat 1"),
                24 => assert_eq!(p.sec_category, 3, "n=24 should be cat 3"),
                32 => assert_eq!(p.sec_category, 5, "n=32 should be cat 5"),
                _ => panic!("unexpected n={}", p.n),
            }
        }
    }

    #[test]
    fn test_s_vs_f_signature_size() {
        // "s" (small) variants have smaller signatures than "f" (fast) variants
        let pairs = [
            (SlhDsaParamId::Sha2128s, SlhDsaParamId::Sha2128f),
            (SlhDsaParamId::Sha2192s, SlhDsaParamId::Sha2192f),
            (SlhDsaParamId::Sha2256s, SlhDsaParamId::Sha2256f),
            (SlhDsaParamId::Shake128s, SlhDsaParamId::Shake128f),
            (SlhDsaParamId::Shake192s, SlhDsaParamId::Shake192f),
            (SlhDsaParamId::Shake256s, SlhDsaParamId::Shake256f),
        ];
        for (s_id, f_id) in &pairs {
            let s = get_params(*s_id);
            let f = get_params(*f_id);
            assert!(
                s.sig_bytes < f.sig_bytes,
                "s variant ({}) should have smaller sig than f variant ({})",
                s.sig_bytes,
                f.sig_bytes
            );
            // f variant has more layers (higher d) for faster signing
            assert!(s.d < f.d, "s.d ({}) should be < f.d ({})", s.d, f.d);
        }
    }

    #[test]
    fn test_all_twelve_params_accessible() {
        assert_eq!(ALL_IDS.len(), 12);
        for id in &ALL_IDS {
            let p = get_params(*id);
            assert!(p.n > 0);
            assert!(p.h > 0);
            assert!(p.d > 0);
            assert!(p.sig_bytes > 0);
        }
    }

    #[test]
    fn test_m_greater_than_n() {
        for id in &ALL_IDS {
            let p = get_params(*id);
            assert!(
                p.m > p.n,
                "m ({}) should be > n ({}) for message digest security",
                p.m,
                p.n
            );
        }
    }

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
