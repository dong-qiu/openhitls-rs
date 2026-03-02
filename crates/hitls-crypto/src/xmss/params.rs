//! XMSS parameter sets (RFC 8391).
//!
//! Supports 21 single-tree parameter sets:
//! - 9 × n=32 (SHA-256, SHAKE128, SHAKE256 × h=10,16,20)
//! - 3 × n=64 SHA-512 (h=10,16,20)
//! - 3 × n=64 SHAKE256 (h=10,16,20)
//! - 3 × n=24 SHA-256 truncated (h=10,16,20)
//! - 3 × n=24 SHAKE256 (h=10,16,20)

use hitls_types::{XmssMtParamId, XmssParamId};

/// XMSS parameter set.
pub(crate) struct XmssParams {
    pub n: usize,           // Hash output length (bytes): 24, 32, or 64
    pub h: usize,           // Tree height (10, 16, or 20)
    pub wots_len: usize,    // WOTS+ chain count: n=24→51, n=32→67, n=64→131
    pub sig_bytes: usize,   // Total signature size = 4 + n + (wots_len + h) * n
    pub padding_len: usize, // Domain separation padding length
}

/// Compute OID for the parameter set (RFC 8391 Section 5.3).
pub(crate) fn oid(param_id: XmssParamId) -> u32 {
    match param_id {
        XmssParamId::Sha2_10_256 => 0x00000001,
        XmssParamId::Sha2_16_256 => 0x00000002,
        XmssParamId::Sha2_20_256 => 0x00000003,
        XmssParamId::Sha2_10_512 => 0x00000004,
        XmssParamId::Sha2_16_512 => 0x00000005,
        XmssParamId::Sha2_20_512 => 0x00000006,
        XmssParamId::Shake128_10_256 => 0x00000007,
        XmssParamId::Shake128_16_256 => 0x00000008,
        XmssParamId::Shake128_20_256 => 0x00000009,
        XmssParamId::Shake256_10_256 => 0x0000000a,
        XmssParamId::Shake256_16_256 => 0x0000000b,
        XmssParamId::Shake256_20_256 => 0x0000000c,
        XmssParamId::Shake256_10_512 => 0x0000000d,
        XmssParamId::Shake256_16_512 => 0x0000000e,
        XmssParamId::Shake256_20_512 => 0x0000000f,
        XmssParamId::Sha2_10_192 => 0x00000010,
        XmssParamId::Sha2_16_192 => 0x00000011,
        XmssParamId::Sha2_20_192 => 0x00000012,
        XmssParamId::Shake256_10_192 => 0x00000016,
        XmssParamId::Shake256_16_192 => 0x00000017,
        XmssParamId::Shake256_20_192 => 0x00000018,
    }
}

// n=32 params: wots_len=67, sig_bytes = 4 + 32 + (67+h)*32
fn xmss_params_n32(h: usize) -> XmssParams {
    XmssParams {
        n: 32,
        h,
        wots_len: 67,
        sig_bytes: 4 + 32 + (67 + h) * 32,
        padding_len: 32,
    }
}

// n=64 params: wots_len=131, sig_bytes = 4 + 64 + (131+h)*64
fn xmss_params_n64(h: usize) -> XmssParams {
    XmssParams {
        n: 64,
        h,
        wots_len: 131,
        sig_bytes: 4 + 64 + (131 + h) * 64,
        padding_len: 64,
    }
}

// n=24 params: wots_len=51, sig_bytes = 4 + 24 + (51+h)*24, padding_len=4
fn xmss_params_n24(h: usize) -> XmssParams {
    XmssParams {
        n: 24,
        h,
        wots_len: 51,
        sig_bytes: 4 + 24 + (51 + h) * 24,
        padding_len: 4,
    }
}

pub(crate) fn get_params(param_id: XmssParamId) -> XmssParams {
    match param_id {
        // n=32 SHA-256
        XmssParamId::Sha2_10_256 => xmss_params_n32(10),
        XmssParamId::Sha2_16_256 => xmss_params_n32(16),
        XmssParamId::Sha2_20_256 => xmss_params_n32(20),
        // n=32 SHAKE128
        XmssParamId::Shake128_10_256 => xmss_params_n32(10),
        XmssParamId::Shake128_16_256 => xmss_params_n32(16),
        XmssParamId::Shake128_20_256 => xmss_params_n32(20),
        // n=32 SHAKE256
        XmssParamId::Shake256_10_256 => xmss_params_n32(10),
        XmssParamId::Shake256_16_256 => xmss_params_n32(16),
        XmssParamId::Shake256_20_256 => xmss_params_n32(20),
        // n=64 SHA-512
        XmssParamId::Sha2_10_512 => xmss_params_n64(10),
        XmssParamId::Sha2_16_512 => xmss_params_n64(16),
        XmssParamId::Sha2_20_512 => xmss_params_n64(20),
        // n=64 SHAKE256
        XmssParamId::Shake256_10_512 => xmss_params_n64(10),
        XmssParamId::Shake256_16_512 => xmss_params_n64(16),
        XmssParamId::Shake256_20_512 => xmss_params_n64(20),
        // n=24 SHA-256 (truncated)
        XmssParamId::Sha2_10_192 => xmss_params_n24(10),
        XmssParamId::Sha2_16_192 => xmss_params_n24(16),
        XmssParamId::Sha2_20_192 => xmss_params_n24(20),
        // n=24 SHAKE256
        XmssParamId::Shake256_10_192 => xmss_params_n24(10),
        XmssParamId::Shake256_16_192 => xmss_params_n24(16),
        XmssParamId::Shake256_20_192 => xmss_params_n24(20),
    }
}

/// Hash mode for XMSS.
#[derive(Clone, Copy)]
pub(crate) enum XmssHashMode {
    Sha256,
    Sha512,
    Shake128,
    Shake256,
}

pub(crate) fn hash_mode(param_id: XmssParamId) -> XmssHashMode {
    match param_id {
        XmssParamId::Sha2_10_256 | XmssParamId::Sha2_16_256 | XmssParamId::Sha2_20_256 => {
            XmssHashMode::Sha256
        }
        XmssParamId::Sha2_10_192 | XmssParamId::Sha2_16_192 | XmssParamId::Sha2_20_192 => {
            XmssHashMode::Sha256
        }
        XmssParamId::Sha2_10_512 | XmssParamId::Sha2_16_512 | XmssParamId::Sha2_20_512 => {
            XmssHashMode::Sha512
        }
        XmssParamId::Shake128_10_256
        | XmssParamId::Shake128_16_256
        | XmssParamId::Shake128_20_256 => XmssHashMode::Shake128,
        XmssParamId::Shake256_10_256
        | XmssParamId::Shake256_16_256
        | XmssParamId::Shake256_20_256 => XmssHashMode::Shake256,
        XmssParamId::Shake256_10_512
        | XmssParamId::Shake256_16_512
        | XmssParamId::Shake256_20_512 => XmssHashMode::Shake256,
        XmssParamId::Shake256_10_192
        | XmssParamId::Shake256_16_192
        | XmssParamId::Shake256_20_192 => XmssHashMode::Shake256,
    }
}

/// XMSS-MT parameter set.
pub(crate) struct XmssMtParams {
    pub n: usize,         // Hash output: 24, 32, or 64
    pub total_h: usize,   // Total tree height: 20, 40, or 60
    pub d: usize,         // Number of layers: 2, 3, 4, 6, 8, or 12
    pub hp: usize,        // Per-layer height: total_h / d
    pub wots_len: usize,  // 51, 67, or 131
    pub sig_bytes: usize, // idx_bytes + n + d * (wots_len + hp) * n
    pub padding_len: usize,
}

/// Compute OID for XMSS-MT parameter set (RFC 8391 Section 5.4).
pub(crate) fn mt_oid(param_id: XmssMtParamId) -> u32 {
    match param_id {
        // SHA2-256 (n=32)
        XmssMtParamId::Sha2_20_2_256 => 0x00000001,
        XmssMtParamId::Sha2_20_4_256 => 0x00000002,
        XmssMtParamId::Sha2_40_2_256 => 0x00000003,
        XmssMtParamId::Sha2_40_4_256 => 0x00000004,
        XmssMtParamId::Sha2_40_8_256 => 0x00000005,
        XmssMtParamId::Sha2_60_3_256 => 0x00000006,
        XmssMtParamId::Sha2_60_6_256 => 0x00000007,
        XmssMtParamId::Sha2_60_12_256 => 0x00000008,
        // SHA2-512 (n=64)
        XmssMtParamId::Sha2_20_2_512 => 0x00000009,
        XmssMtParamId::Sha2_20_4_512 => 0x0000000a,
        XmssMtParamId::Sha2_40_2_512 => 0x0000000b,
        XmssMtParamId::Sha2_40_4_512 => 0x0000000c,
        XmssMtParamId::Sha2_40_8_512 => 0x0000000d,
        XmssMtParamId::Sha2_60_3_512 => 0x0000000e,
        XmssMtParamId::Sha2_60_6_512 => 0x0000000f,
        XmssMtParamId::Sha2_60_12_512 => 0x00000010,
        // SHAKE128-256 (n=32)
        XmssMtParamId::Shake128_20_2_256 => 0x00000011,
        XmssMtParamId::Shake128_20_4_256 => 0x00000012,
        XmssMtParamId::Shake128_40_2_256 => 0x00000013,
        XmssMtParamId::Shake128_40_4_256 => 0x00000014,
        XmssMtParamId::Shake128_40_8_256 => 0x00000015,
        XmssMtParamId::Shake128_60_3_256 => 0x00000016,
        XmssMtParamId::Shake128_60_6_256 => 0x00000017,
        XmssMtParamId::Shake128_60_12_256 => 0x00000018,
        // SHAKE256-512 (n=64)
        XmssMtParamId::Shake256_20_2_512 => 0x00000019,
        XmssMtParamId::Shake256_20_4_512 => 0x0000001a,
        XmssMtParamId::Shake256_40_2_512 => 0x0000001b,
        XmssMtParamId::Shake256_40_4_512 => 0x0000001c,
        XmssMtParamId::Shake256_40_8_512 => 0x0000001d,
        XmssMtParamId::Shake256_60_3_512 => 0x0000001e,
        XmssMtParamId::Shake256_60_6_512 => 0x0000001f,
        XmssMtParamId::Shake256_60_12_512 => 0x00000020,
        // SHA2-192 (n=24)
        XmssMtParamId::Sha2_20_2_192 => 0x00000021,
        XmssMtParamId::Sha2_20_4_192 => 0x00000022,
        XmssMtParamId::Sha2_40_2_192 => 0x00000023,
        XmssMtParamId::Sha2_40_4_192 => 0x00000024,
        XmssMtParamId::Sha2_40_8_192 => 0x00000025,
        XmssMtParamId::Sha2_60_3_192 => 0x00000026,
        XmssMtParamId::Sha2_60_6_192 => 0x00000027,
        XmssMtParamId::Sha2_60_12_192 => 0x00000028,
        // SHAKE256-256 (n=32)
        XmssMtParamId::Shake256_20_2_256 => 0x00000029,
        XmssMtParamId::Shake256_20_4_256 => 0x0000002a,
        XmssMtParamId::Shake256_40_2_256 => 0x0000002b,
        XmssMtParamId::Shake256_40_4_256 => 0x0000002c,
        XmssMtParamId::Shake256_40_8_256 => 0x0000002d,
        XmssMtParamId::Shake256_60_3_256 => 0x0000002e,
        XmssMtParamId::Shake256_60_6_256 => 0x0000002f,
        XmssMtParamId::Shake256_60_12_256 => 0x00000030,
        // SHAKE256-192 (n=24)
        XmssMtParamId::Shake256_20_2_192 => 0x00000031,
        XmssMtParamId::Shake256_20_4_192 => 0x00000032,
        XmssMtParamId::Shake256_40_2_192 => 0x00000033,
        XmssMtParamId::Shake256_40_4_192 => 0x00000034,
        XmssMtParamId::Shake256_40_8_192 => 0x00000035,
        XmssMtParamId::Shake256_60_3_192 => 0x00000036,
        XmssMtParamId::Shake256_60_6_192 => 0x00000037,
        XmssMtParamId::Shake256_60_12_192 => 0x00000038,
    }
}

fn mt_params_n32(total_h: usize, d: usize) -> XmssMtParams {
    let hp = total_h / d;
    let idx_bytes = total_h.div_ceil(8);
    XmssMtParams {
        n: 32,
        total_h,
        d,
        hp,
        wots_len: 67,
        sig_bytes: idx_bytes + 32 + d * (67 + hp) * 32,
        padding_len: 32,
    }
}

fn mt_params_n64(total_h: usize, d: usize) -> XmssMtParams {
    let hp = total_h / d;
    let idx_bytes = total_h.div_ceil(8);
    XmssMtParams {
        n: 64,
        total_h,
        d,
        hp,
        wots_len: 131,
        sig_bytes: idx_bytes + 64 + d * (131 + hp) * 64,
        padding_len: 64,
    }
}

fn mt_params_n24(total_h: usize, d: usize) -> XmssMtParams {
    let hp = total_h / d;
    let idx_bytes = total_h.div_ceil(8);
    XmssMtParams {
        n: 24,
        total_h,
        d,
        hp,
        wots_len: 51,
        sig_bytes: idx_bytes + 24 + d * (51 + hp) * 24,
        padding_len: 4,
    }
}

pub(crate) fn get_mt_params(param_id: XmssMtParamId) -> XmssMtParams {
    match param_id {
        // SHA2-256 (n=32)
        XmssMtParamId::Sha2_20_2_256 => mt_params_n32(20, 2),
        XmssMtParamId::Sha2_20_4_256 => mt_params_n32(20, 4),
        XmssMtParamId::Sha2_40_2_256 => mt_params_n32(40, 2),
        XmssMtParamId::Sha2_40_4_256 => mt_params_n32(40, 4),
        XmssMtParamId::Sha2_40_8_256 => mt_params_n32(40, 8),
        XmssMtParamId::Sha2_60_3_256 => mt_params_n32(60, 3),
        XmssMtParamId::Sha2_60_6_256 => mt_params_n32(60, 6),
        XmssMtParamId::Sha2_60_12_256 => mt_params_n32(60, 12),
        // SHA2-512 (n=64)
        XmssMtParamId::Sha2_20_2_512 => mt_params_n64(20, 2),
        XmssMtParamId::Sha2_20_4_512 => mt_params_n64(20, 4),
        XmssMtParamId::Sha2_40_2_512 => mt_params_n64(40, 2),
        XmssMtParamId::Sha2_40_4_512 => mt_params_n64(40, 4),
        XmssMtParamId::Sha2_40_8_512 => mt_params_n64(40, 8),
        XmssMtParamId::Sha2_60_3_512 => mt_params_n64(60, 3),
        XmssMtParamId::Sha2_60_6_512 => mt_params_n64(60, 6),
        XmssMtParamId::Sha2_60_12_512 => mt_params_n64(60, 12),
        // SHAKE128-256 (n=32)
        XmssMtParamId::Shake128_20_2_256 => mt_params_n32(20, 2),
        XmssMtParamId::Shake128_20_4_256 => mt_params_n32(20, 4),
        XmssMtParamId::Shake128_40_2_256 => mt_params_n32(40, 2),
        XmssMtParamId::Shake128_40_4_256 => mt_params_n32(40, 4),
        XmssMtParamId::Shake128_40_8_256 => mt_params_n32(40, 8),
        XmssMtParamId::Shake128_60_3_256 => mt_params_n32(60, 3),
        XmssMtParamId::Shake128_60_6_256 => mt_params_n32(60, 6),
        XmssMtParamId::Shake128_60_12_256 => mt_params_n32(60, 12),
        // SHAKE256-512 (n=64)
        XmssMtParamId::Shake256_20_2_512 => mt_params_n64(20, 2),
        XmssMtParamId::Shake256_20_4_512 => mt_params_n64(20, 4),
        XmssMtParamId::Shake256_40_2_512 => mt_params_n64(40, 2),
        XmssMtParamId::Shake256_40_4_512 => mt_params_n64(40, 4),
        XmssMtParamId::Shake256_40_8_512 => mt_params_n64(40, 8),
        XmssMtParamId::Shake256_60_3_512 => mt_params_n64(60, 3),
        XmssMtParamId::Shake256_60_6_512 => mt_params_n64(60, 6),
        XmssMtParamId::Shake256_60_12_512 => mt_params_n64(60, 12),
        // SHA2-192 (n=24)
        XmssMtParamId::Sha2_20_2_192 => mt_params_n24(20, 2),
        XmssMtParamId::Sha2_20_4_192 => mt_params_n24(20, 4),
        XmssMtParamId::Sha2_40_2_192 => mt_params_n24(40, 2),
        XmssMtParamId::Sha2_40_4_192 => mt_params_n24(40, 4),
        XmssMtParamId::Sha2_40_8_192 => mt_params_n24(40, 8),
        XmssMtParamId::Sha2_60_3_192 => mt_params_n24(60, 3),
        XmssMtParamId::Sha2_60_6_192 => mt_params_n24(60, 6),
        XmssMtParamId::Sha2_60_12_192 => mt_params_n24(60, 12),
        // SHAKE256-256 (n=32)
        XmssMtParamId::Shake256_20_2_256 => mt_params_n32(20, 2),
        XmssMtParamId::Shake256_20_4_256 => mt_params_n32(20, 4),
        XmssMtParamId::Shake256_40_2_256 => mt_params_n32(40, 2),
        XmssMtParamId::Shake256_40_4_256 => mt_params_n32(40, 4),
        XmssMtParamId::Shake256_40_8_256 => mt_params_n32(40, 8),
        XmssMtParamId::Shake256_60_3_256 => mt_params_n32(60, 3),
        XmssMtParamId::Shake256_60_6_256 => mt_params_n32(60, 6),
        XmssMtParamId::Shake256_60_12_256 => mt_params_n32(60, 12),
        // SHAKE256-192 (n=24)
        XmssMtParamId::Shake256_20_2_192 => mt_params_n24(20, 2),
        XmssMtParamId::Shake256_20_4_192 => mt_params_n24(20, 4),
        XmssMtParamId::Shake256_40_2_192 => mt_params_n24(40, 2),
        XmssMtParamId::Shake256_40_4_192 => mt_params_n24(40, 4),
        XmssMtParamId::Shake256_40_8_192 => mt_params_n24(40, 8),
        XmssMtParamId::Shake256_60_3_192 => mt_params_n24(60, 3),
        XmssMtParamId::Shake256_60_6_192 => mt_params_n24(60, 6),
        XmssMtParamId::Shake256_60_12_192 => mt_params_n24(60, 12),
    }
}

pub(crate) fn mt_hash_mode(param_id: XmssMtParamId) -> XmssHashMode {
    match param_id {
        XmssMtParamId::Sha2_20_2_256
        | XmssMtParamId::Sha2_20_4_256
        | XmssMtParamId::Sha2_40_2_256
        | XmssMtParamId::Sha2_40_4_256
        | XmssMtParamId::Sha2_40_8_256
        | XmssMtParamId::Sha2_60_3_256
        | XmssMtParamId::Sha2_60_6_256
        | XmssMtParamId::Sha2_60_12_256 => XmssHashMode::Sha256,

        XmssMtParamId::Sha2_20_2_512
        | XmssMtParamId::Sha2_20_4_512
        | XmssMtParamId::Sha2_40_2_512
        | XmssMtParamId::Sha2_40_4_512
        | XmssMtParamId::Sha2_40_8_512
        | XmssMtParamId::Sha2_60_3_512
        | XmssMtParamId::Sha2_60_6_512
        | XmssMtParamId::Sha2_60_12_512 => XmssHashMode::Sha512,

        XmssMtParamId::Sha2_20_2_192
        | XmssMtParamId::Sha2_20_4_192
        | XmssMtParamId::Sha2_40_2_192
        | XmssMtParamId::Sha2_40_4_192
        | XmssMtParamId::Sha2_40_8_192
        | XmssMtParamId::Sha2_60_3_192
        | XmssMtParamId::Sha2_60_6_192
        | XmssMtParamId::Sha2_60_12_192 => XmssHashMode::Sha256,

        XmssMtParamId::Shake128_20_2_256
        | XmssMtParamId::Shake128_20_4_256
        | XmssMtParamId::Shake128_40_2_256
        | XmssMtParamId::Shake128_40_4_256
        | XmssMtParamId::Shake128_40_8_256
        | XmssMtParamId::Shake128_60_3_256
        | XmssMtParamId::Shake128_60_6_256
        | XmssMtParamId::Shake128_60_12_256 => XmssHashMode::Shake128,

        XmssMtParamId::Shake256_20_2_512
        | XmssMtParamId::Shake256_20_4_512
        | XmssMtParamId::Shake256_40_2_512
        | XmssMtParamId::Shake256_40_4_512
        | XmssMtParamId::Shake256_40_8_512
        | XmssMtParamId::Shake256_60_3_512
        | XmssMtParamId::Shake256_60_6_512
        | XmssMtParamId::Shake256_60_12_512 => XmssHashMode::Shake256,

        XmssMtParamId::Shake256_20_2_256
        | XmssMtParamId::Shake256_20_4_256
        | XmssMtParamId::Shake256_40_2_256
        | XmssMtParamId::Shake256_40_4_256
        | XmssMtParamId::Shake256_40_8_256
        | XmssMtParamId::Shake256_60_3_256
        | XmssMtParamId::Shake256_60_6_256
        | XmssMtParamId::Shake256_60_12_256 => XmssHashMode::Shake256,

        XmssMtParamId::Shake256_20_2_192
        | XmssMtParamId::Shake256_20_4_192
        | XmssMtParamId::Shake256_40_2_192
        | XmssMtParamId::Shake256_40_4_192
        | XmssMtParamId::Shake256_40_8_192
        | XmssMtParamId::Shake256_60_3_192
        | XmssMtParamId::Shake256_60_6_192
        | XmssMtParamId::Shake256_60_12_192 => XmssHashMode::Shake256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_types::XmssParamId;

    const ALL_IDS: [XmssParamId; 9] = [
        XmssParamId::Sha2_10_256,
        XmssParamId::Sha2_16_256,
        XmssParamId::Sha2_20_256,
        XmssParamId::Shake128_10_256,
        XmssParamId::Shake128_16_256,
        XmssParamId::Shake128_20_256,
        XmssParamId::Shake256_10_256,
        XmssParamId::Shake256_16_256,
        XmssParamId::Shake256_20_256,
    ];

    #[test]
    fn test_xmss_params_sig_bytes_and_oid() {
        for id in &ALL_IDS {
            let p = get_params(*id);
            // All sets: n=32, wots_len=67
            assert_eq!(p.n, 32);
            assert_eq!(p.wots_len, 67);
            // sig_bytes = 4 + n + (wots_len + h) * n
            let expected = 4 + p.n + (p.wots_len + p.h) * p.n;
            assert_eq!(p.sig_bytes, expected, "sig_bytes mismatch for h={}", p.h);
        }

        // Check specific OID values from RFC 8391
        assert_eq!(oid(XmssParamId::Sha2_10_256), 0x00000001);
        assert_eq!(oid(XmssParamId::Sha2_16_256), 0x00000002);
        assert_eq!(oid(XmssParamId::Sha2_20_256), 0x00000003);
        assert_eq!(oid(XmssParamId::Shake128_10_256), 0x00000007);
        assert_eq!(oid(XmssParamId::Shake256_10_256), 0x0000000a);
    }

    #[test]
    fn test_xmss_all_heights_valid() {
        for id in &ALL_IDS {
            let p = get_params(*id);
            assert!(
                p.h == 10 || p.h == 16 || p.h == 20,
                "unexpected h={} for XMSS",
                p.h
            );
        }
    }

    #[test]
    fn test_xmss_oid_uniqueness() {
        let oids: Vec<u32> = ALL_IDS.iter().map(|id| oid(*id)).collect();
        for i in 0..oids.len() {
            for j in (i + 1)..oids.len() {
                assert_ne!(oids[i], oids[j], "duplicate OID at indices {} and {}", i, j);
            }
        }
    }

    #[test]
    fn test_xmss_hash_mode_consistency() {
        // SHA-2 variants → Sha256 mode
        for id in [
            XmssParamId::Sha2_10_256,
            XmssParamId::Sha2_16_256,
            XmssParamId::Sha2_20_256,
        ] {
            assert!(matches!(hash_mode(id), XmssHashMode::Sha256));
        }
        // SHAKE128 variants → Shake128 mode
        for id in [
            XmssParamId::Shake128_10_256,
            XmssParamId::Shake128_16_256,
            XmssParamId::Shake128_20_256,
        ] {
            assert!(matches!(hash_mode(id), XmssHashMode::Shake128));
        }
        // SHAKE256 variants → Shake256 mode
        for id in [
            XmssParamId::Shake256_10_256,
            XmssParamId::Shake256_16_256,
            XmssParamId::Shake256_20_256,
        ] {
            assert!(matches!(hash_mode(id), XmssHashMode::Shake256));
        }
    }

    #[test]
    fn test_xmss_same_height_same_sig_size() {
        // Same h → same sig_bytes regardless of hash mode
        let h10 = [
            XmssParamId::Sha2_10_256,
            XmssParamId::Shake128_10_256,
            XmssParamId::Shake256_10_256,
        ];
        let h16 = [
            XmssParamId::Sha2_16_256,
            XmssParamId::Shake128_16_256,
            XmssParamId::Shake256_16_256,
        ];
        let h20 = [
            XmssParamId::Sha2_20_256,
            XmssParamId::Shake128_20_256,
            XmssParamId::Shake256_20_256,
        ];
        for group in [&h10[..], &h16[..], &h20[..]] {
            let first = get_params(group[0]).sig_bytes;
            for id in &group[1..] {
                assert_eq!(get_params(*id).sig_bytes, first);
            }
        }
    }

    #[test]
    fn test_xmss_sig_bytes_monotonic_with_height() {
        let s10 = get_params(XmssParamId::Sha2_10_256).sig_bytes;
        let s16 = get_params(XmssParamId::Sha2_16_256).sig_bytes;
        let s20 = get_params(XmssParamId::Sha2_20_256).sig_bytes;
        assert!(
            s10 < s16,
            "h=10 sig ({}) should be < h=16 sig ({})",
            s10,
            s16
        );
        assert!(
            s16 < s20,
            "h=16 sig ({}) should be < h=20 sig ({})",
            s16,
            s20
        );
    }

    #[test]
    fn test_xmss_extended_sig_bytes_formula() {
        // Verify formula for all 21 single-tree params
        let all_ids = [
            XmssParamId::Sha2_10_256,
            XmssParamId::Sha2_16_256,
            XmssParamId::Sha2_20_256,
            XmssParamId::Shake128_10_256,
            XmssParamId::Shake128_16_256,
            XmssParamId::Shake128_20_256,
            XmssParamId::Shake256_10_256,
            XmssParamId::Shake256_16_256,
            XmssParamId::Shake256_20_256,
            XmssParamId::Sha2_10_512,
            XmssParamId::Sha2_16_512,
            XmssParamId::Sha2_20_512,
            XmssParamId::Shake256_10_512,
            XmssParamId::Shake256_16_512,
            XmssParamId::Shake256_20_512,
            XmssParamId::Sha2_10_192,
            XmssParamId::Sha2_16_192,
            XmssParamId::Sha2_20_192,
            XmssParamId::Shake256_10_192,
            XmssParamId::Shake256_16_192,
            XmssParamId::Shake256_20_192,
        ];
        for id in &all_ids {
            let p = get_params(*id);
            let expected = 4 + p.n + (p.wots_len + p.h) * p.n;
            assert_eq!(
                p.sig_bytes, expected,
                "sig_bytes mismatch for n={}, h={}",
                p.n, p.h
            );
        }
    }

    #[test]
    fn test_xmss_mt_sig_bytes_formula() {
        // Verify formula for all 56 MT params
        let all_mt = [
            XmssMtParamId::Sha2_20_2_256,
            XmssMtParamId::Sha2_20_4_256,
            XmssMtParamId::Sha2_40_2_256,
            XmssMtParamId::Sha2_40_4_256,
            XmssMtParamId::Sha2_40_8_256,
            XmssMtParamId::Sha2_60_3_256,
            XmssMtParamId::Sha2_60_6_256,
            XmssMtParamId::Sha2_60_12_256,
            XmssMtParamId::Sha2_20_2_512,
            XmssMtParamId::Sha2_20_4_512,
            XmssMtParamId::Sha2_40_2_512,
            XmssMtParamId::Sha2_40_4_512,
            XmssMtParamId::Sha2_40_8_512,
            XmssMtParamId::Sha2_60_3_512,
            XmssMtParamId::Sha2_60_6_512,
            XmssMtParamId::Sha2_60_12_512,
            XmssMtParamId::Shake128_20_2_256,
            XmssMtParamId::Shake128_20_4_256,
            XmssMtParamId::Shake128_40_2_256,
            XmssMtParamId::Shake128_40_4_256,
            XmssMtParamId::Shake128_40_8_256,
            XmssMtParamId::Shake128_60_3_256,
            XmssMtParamId::Shake128_60_6_256,
            XmssMtParamId::Shake128_60_12_256,
            XmssMtParamId::Shake256_20_2_512,
            XmssMtParamId::Shake256_20_4_512,
            XmssMtParamId::Shake256_40_2_512,
            XmssMtParamId::Shake256_40_4_512,
            XmssMtParamId::Shake256_40_8_512,
            XmssMtParamId::Shake256_60_3_512,
            XmssMtParamId::Shake256_60_6_512,
            XmssMtParamId::Shake256_60_12_512,
            XmssMtParamId::Sha2_20_2_192,
            XmssMtParamId::Sha2_20_4_192,
            XmssMtParamId::Sha2_40_2_192,
            XmssMtParamId::Sha2_40_4_192,
            XmssMtParamId::Sha2_40_8_192,
            XmssMtParamId::Sha2_60_3_192,
            XmssMtParamId::Sha2_60_6_192,
            XmssMtParamId::Sha2_60_12_192,
            XmssMtParamId::Shake256_20_2_256,
            XmssMtParamId::Shake256_20_4_256,
            XmssMtParamId::Shake256_40_2_256,
            XmssMtParamId::Shake256_40_4_256,
            XmssMtParamId::Shake256_40_8_256,
            XmssMtParamId::Shake256_60_3_256,
            XmssMtParamId::Shake256_60_6_256,
            XmssMtParamId::Shake256_60_12_256,
            XmssMtParamId::Shake256_20_2_192,
            XmssMtParamId::Shake256_20_4_192,
            XmssMtParamId::Shake256_40_2_192,
            XmssMtParamId::Shake256_40_4_192,
            XmssMtParamId::Shake256_40_8_192,
            XmssMtParamId::Shake256_60_3_192,
            XmssMtParamId::Shake256_60_6_192,
            XmssMtParamId::Shake256_60_12_192,
        ];
        for id in &all_mt {
            let p = get_mt_params(*id);
            let idx_bytes = p.total_h.div_ceil(8);
            let expected = idx_bytes + p.n + p.d * (p.wots_len + p.hp) * p.n;
            assert_eq!(
                p.sig_bytes, expected,
                "MT sig_bytes mismatch for n={}, h={}, d={}",
                p.n, p.total_h, p.d
            );
            assert_eq!(p.hp, p.total_h / p.d);
        }
    }

    #[test]
    fn test_xmss_mt_oid_uniqueness() {
        let all_mt = [
            XmssMtParamId::Sha2_20_2_256,
            XmssMtParamId::Sha2_20_4_256,
            XmssMtParamId::Sha2_40_2_256,
            XmssMtParamId::Sha2_40_4_256,
            XmssMtParamId::Sha2_40_8_256,
            XmssMtParamId::Sha2_60_3_256,
            XmssMtParamId::Sha2_60_6_256,
            XmssMtParamId::Sha2_60_12_256,
            XmssMtParamId::Sha2_20_2_512,
            XmssMtParamId::Sha2_20_4_512,
            XmssMtParamId::Sha2_40_2_512,
            XmssMtParamId::Sha2_40_4_512,
            XmssMtParamId::Sha2_40_8_512,
            XmssMtParamId::Sha2_60_3_512,
            XmssMtParamId::Sha2_60_6_512,
            XmssMtParamId::Sha2_60_12_512,
            XmssMtParamId::Shake128_20_2_256,
            XmssMtParamId::Shake128_20_4_256,
            XmssMtParamId::Shake128_40_2_256,
            XmssMtParamId::Shake128_40_4_256,
            XmssMtParamId::Shake128_40_8_256,
            XmssMtParamId::Shake128_60_3_256,
            XmssMtParamId::Shake128_60_6_256,
            XmssMtParamId::Shake128_60_12_256,
            XmssMtParamId::Shake256_20_2_512,
            XmssMtParamId::Shake256_20_4_512,
            XmssMtParamId::Shake256_40_2_512,
            XmssMtParamId::Shake256_40_4_512,
            XmssMtParamId::Shake256_40_8_512,
            XmssMtParamId::Shake256_60_3_512,
            XmssMtParamId::Shake256_60_6_512,
            XmssMtParamId::Shake256_60_12_512,
            XmssMtParamId::Sha2_20_2_192,
            XmssMtParamId::Sha2_20_4_192,
            XmssMtParamId::Sha2_40_2_192,
            XmssMtParamId::Sha2_40_4_192,
            XmssMtParamId::Sha2_40_8_192,
            XmssMtParamId::Sha2_60_3_192,
            XmssMtParamId::Sha2_60_6_192,
            XmssMtParamId::Sha2_60_12_192,
            XmssMtParamId::Shake256_20_2_256,
            XmssMtParamId::Shake256_20_4_256,
            XmssMtParamId::Shake256_40_2_256,
            XmssMtParamId::Shake256_40_4_256,
            XmssMtParamId::Shake256_40_8_256,
            XmssMtParamId::Shake256_60_3_256,
            XmssMtParamId::Shake256_60_6_256,
            XmssMtParamId::Shake256_60_12_256,
            XmssMtParamId::Shake256_20_2_192,
            XmssMtParamId::Shake256_20_4_192,
            XmssMtParamId::Shake256_40_2_192,
            XmssMtParamId::Shake256_40_4_192,
            XmssMtParamId::Shake256_40_8_192,
            XmssMtParamId::Shake256_60_3_192,
            XmssMtParamId::Shake256_60_6_192,
            XmssMtParamId::Shake256_60_12_192,
        ];
        let oids: Vec<u32> = all_mt.iter().map(|id| mt_oid(*id)).collect();
        for i in 0..oids.len() {
            for j in (i + 1)..oids.len() {
                assert_ne!(
                    oids[i], oids[j],
                    "duplicate MT OID at indices {} and {}",
                    i, j
                );
            }
        }
    }
}
