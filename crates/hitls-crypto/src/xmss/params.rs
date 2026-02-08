//! XMSS parameter sets (RFC 8391, single-tree only).
//!
//! All parameter sets use n=32, W=16, wots_len=67.

use hitls_types::XmssParamId;

/// XMSS parameter set.
pub(crate) struct XmssParams {
    pub n: usize,         // Hash output length (bytes), always 32
    pub h: usize,         // Tree height (10, 16, or 20)
    pub wots_len: usize,  // WOTS+ chain count (len_1 + len_2 = 64 + 3 = 67)
    pub sig_bytes: usize, // Total signature size = 4 + n + (wots_len + h) * n
}

/// Compute OID for the parameter set (RFC 8391 Section 5.3).
pub(crate) fn oid(param_id: XmssParamId) -> u32 {
    match param_id {
        XmssParamId::Sha2_10_256 => 0x00000001,
        XmssParamId::Sha2_16_256 => 0x00000002,
        XmssParamId::Sha2_20_256 => 0x00000003,
        XmssParamId::Shake128_10_256 => 0x00000007,
        XmssParamId::Shake128_16_256 => 0x00000008,
        XmssParamId::Shake128_20_256 => 0x00000009,
        XmssParamId::Shake256_10_256 => 0x0000000a,
        XmssParamId::Shake256_16_256 => 0x0000000b,
        XmssParamId::Shake256_20_256 => 0x0000000c,
    }
}

static PARAMS: [XmssParams; 9] = [
    // SHA2_10_256
    XmssParams {
        n: 32,
        h: 10,
        wots_len: 67,
        sig_bytes: 2500,
    },
    // SHA2_16_256
    XmssParams {
        n: 32,
        h: 16,
        wots_len: 67,
        sig_bytes: 2692,
    },
    // SHA2_20_256
    XmssParams {
        n: 32,
        h: 20,
        wots_len: 67,
        sig_bytes: 2820,
    },
    // SHAKE128_10_256
    XmssParams {
        n: 32,
        h: 10,
        wots_len: 67,
        sig_bytes: 2500,
    },
    // SHAKE128_16_256
    XmssParams {
        n: 32,
        h: 16,
        wots_len: 67,
        sig_bytes: 2692,
    },
    // SHAKE128_20_256
    XmssParams {
        n: 32,
        h: 20,
        wots_len: 67,
        sig_bytes: 2820,
    },
    // SHAKE256_10_256
    XmssParams {
        n: 32,
        h: 10,
        wots_len: 67,
        sig_bytes: 2500,
    },
    // SHAKE256_16_256
    XmssParams {
        n: 32,
        h: 16,
        wots_len: 67,
        sig_bytes: 2692,
    },
    // SHAKE256_20_256
    XmssParams {
        n: 32,
        h: 20,
        wots_len: 67,
        sig_bytes: 2820,
    },
];

pub(crate) fn get_params(param_id: XmssParamId) -> &'static XmssParams {
    let idx = match param_id {
        XmssParamId::Sha2_10_256 => 0,
        XmssParamId::Sha2_16_256 => 1,
        XmssParamId::Sha2_20_256 => 2,
        XmssParamId::Shake128_10_256 => 3,
        XmssParamId::Shake128_16_256 => 4,
        XmssParamId::Shake128_20_256 => 5,
        XmssParamId::Shake256_10_256 => 6,
        XmssParamId::Shake256_16_256 => 7,
        XmssParamId::Shake256_20_256 => 8,
    };
    &PARAMS[idx]
}

/// Hash mode for XMSS.
#[derive(Clone, Copy)]
pub(crate) enum XmssHashMode {
    Sha256,
    Shake128,
    Shake256,
}

pub(crate) fn hash_mode(param_id: XmssParamId) -> XmssHashMode {
    match param_id {
        XmssParamId::Sha2_10_256 | XmssParamId::Sha2_16_256 | XmssParamId::Sha2_20_256 => {
            XmssHashMode::Sha256
        }
        XmssParamId::Shake128_10_256
        | XmssParamId::Shake128_16_256
        | XmssParamId::Shake128_20_256 => XmssHashMode::Shake128,
        XmssParamId::Shake256_10_256
        | XmssParamId::Shake256_16_256
        | XmssParamId::Shake256_20_256 => XmssHashMode::Shake256,
    }
}
