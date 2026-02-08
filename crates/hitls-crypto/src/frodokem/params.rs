//! FrodoKEM parameter sets.
//!
//! 12 parameter sets: FrodoKEM-{640,976,1344} × {SHAKE,AES} + eFrodoKEM variants.

use hitls_types::FrodoKemParamId;

/// CDF sampling tables for discrete noise distribution.
static CDF_640: [u16; 13] = [
    4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767,
];
static CDF_976: [u16; 11] = [
    5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767,
];
static CDF_1344: [u16; 7] = [9142, 23462, 30338, 32361, 32725, 32765, 32767];

/// PRG mode for matrix A generation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrgMode {
    Shake,
    Aes,
}

/// FrodoKEM parameter set.
pub(crate) struct FrodoParams {
    pub n: usize,
    pub n_bar: usize,
    pub logq: u8,
    pub extracted_bits: u8,
    pub pk_size: usize,
    pub sk_size: usize,
    pub ct_size: usize,
    pub ss_len: usize,
    pub seed_a_len: usize,
    pub seed_se_len: usize,
    pub mu_len: usize,
    pub pk_hash_len: usize,
    pub salt_len: usize,
    pub cdf_table: &'static [u16],
    pub prg: PrgMode,
}

impl FrodoParams {
    /// q = 2^logq
    pub fn q_mask(&self) -> u16 {
        ((1u32 << self.logq) - 1) as u16
    }

    /// Packed byte length for an n1×n2 matrix with logq bits per element.
    pub fn packed_len(&self, count: usize) -> usize {
        (count * self.logq as usize).div_ceil(8)
    }
}

pub(crate) fn get_params(param_id: FrodoKemParamId) -> &'static FrodoParams {
    match param_id {
        FrodoKemParamId::FrodoKem640Shake => &PARAMS[0],
        FrodoKemParamId::FrodoKem976Shake => &PARAMS[1],
        FrodoKemParamId::FrodoKem1344Shake => &PARAMS[2],
        FrodoKemParamId::FrodoKem640Aes => &PARAMS[3],
        FrodoKemParamId::FrodoKem976Aes => &PARAMS[4],
        FrodoKemParamId::FrodoKem1344Aes => &PARAMS[5],
        FrodoKemParamId::EFrodoKem640Shake => &PARAMS[6],
        FrodoKemParamId::EFrodoKem976Shake => &PARAMS[7],
        FrodoKemParamId::EFrodoKem1344Shake => &PARAMS[8],
        FrodoKemParamId::EFrodoKem640Aes => &PARAMS[9],
        FrodoKemParamId::EFrodoKem976Aes => &PARAMS[10],
        FrodoKemParamId::EFrodoKem1344Aes => &PARAMS[11],
    }
}

static PARAMS: [FrodoParams; 12] = [
    // FrodoKEM-640-SHAKE
    FrodoParams {
        n: 640,
        n_bar: 8,
        logq: 15,
        extracted_bits: 2,
        pk_size: 9616,
        sk_size: 19888,
        ct_size: 9752,
        ss_len: 16,
        seed_a_len: 16,
        seed_se_len: 32,
        mu_len: 16,
        pk_hash_len: 16,
        salt_len: 32,
        cdf_table: &CDF_640,
        prg: PrgMode::Shake,
    },
    // FrodoKEM-976-SHAKE
    FrodoParams {
        n: 976,
        n_bar: 8,
        logq: 16,
        extracted_bits: 3,
        pk_size: 15632,
        sk_size: 31296,
        ct_size: 15792,
        ss_len: 24,
        seed_a_len: 16,
        seed_se_len: 48,
        mu_len: 24,
        pk_hash_len: 24,
        salt_len: 48,
        cdf_table: &CDF_976,
        prg: PrgMode::Shake,
    },
    // FrodoKEM-1344-SHAKE
    FrodoParams {
        n: 1344,
        n_bar: 8,
        logq: 16,
        extracted_bits: 4,
        pk_size: 21520,
        sk_size: 43088,
        ct_size: 21696,
        ss_len: 32,
        seed_a_len: 16,
        seed_se_len: 64,
        mu_len: 32,
        pk_hash_len: 32,
        salt_len: 64,
        cdf_table: &CDF_1344,
        prg: PrgMode::Shake,
    },
    // FrodoKEM-640-AES
    FrodoParams {
        n: 640,
        n_bar: 8,
        logq: 15,
        extracted_bits: 2,
        pk_size: 9616,
        sk_size: 19888,
        ct_size: 9752,
        ss_len: 16,
        seed_a_len: 16,
        seed_se_len: 32,
        mu_len: 16,
        pk_hash_len: 16,
        salt_len: 32,
        cdf_table: &CDF_640,
        prg: PrgMode::Aes,
    },
    // FrodoKEM-976-AES
    FrodoParams {
        n: 976,
        n_bar: 8,
        logq: 16,
        extracted_bits: 3,
        pk_size: 15632,
        sk_size: 31296,
        ct_size: 15792,
        ss_len: 24,
        seed_a_len: 16,
        seed_se_len: 48,
        mu_len: 24,
        pk_hash_len: 24,
        salt_len: 48,
        cdf_table: &CDF_976,
        prg: PrgMode::Aes,
    },
    // FrodoKEM-1344-AES
    FrodoParams {
        n: 1344,
        n_bar: 8,
        logq: 16,
        extracted_bits: 4,
        pk_size: 21520,
        sk_size: 43088,
        ct_size: 21696,
        ss_len: 32,
        seed_a_len: 16,
        seed_se_len: 64,
        mu_len: 32,
        pk_hash_len: 32,
        salt_len: 64,
        cdf_table: &CDF_1344,
        prg: PrgMode::Aes,
    },
    // eFrodoKEM-640-SHAKE
    FrodoParams {
        n: 640,
        n_bar: 8,
        logq: 15,
        extracted_bits: 2,
        pk_size: 9616,
        sk_size: 19888,
        ct_size: 9720,
        ss_len: 16,
        seed_a_len: 16,
        seed_se_len: 16,
        mu_len: 16,
        pk_hash_len: 16,
        salt_len: 0,
        cdf_table: &CDF_640,
        prg: PrgMode::Shake,
    },
    // eFrodoKEM-976-SHAKE
    FrodoParams {
        n: 976,
        n_bar: 8,
        logq: 16,
        extracted_bits: 3,
        pk_size: 15632,
        sk_size: 31296,
        ct_size: 15744,
        ss_len: 24,
        seed_a_len: 16,
        seed_se_len: 24,
        mu_len: 24,
        pk_hash_len: 24,
        salt_len: 0,
        cdf_table: &CDF_976,
        prg: PrgMode::Shake,
    },
    // eFrodoKEM-1344-SHAKE
    FrodoParams {
        n: 1344,
        n_bar: 8,
        logq: 16,
        extracted_bits: 4,
        pk_size: 21520,
        sk_size: 43088,
        ct_size: 21632,
        ss_len: 32,
        seed_a_len: 16,
        seed_se_len: 32,
        mu_len: 32,
        pk_hash_len: 32,
        salt_len: 0,
        cdf_table: &CDF_1344,
        prg: PrgMode::Shake,
    },
    // eFrodoKEM-640-AES
    FrodoParams {
        n: 640,
        n_bar: 8,
        logq: 15,
        extracted_bits: 2,
        pk_size: 9616,
        sk_size: 19888,
        ct_size: 9720,
        ss_len: 16,
        seed_a_len: 16,
        seed_se_len: 16,
        mu_len: 16,
        pk_hash_len: 16,
        salt_len: 0,
        cdf_table: &CDF_640,
        prg: PrgMode::Aes,
    },
    // eFrodoKEM-976-AES
    FrodoParams {
        n: 976,
        n_bar: 8,
        logq: 16,
        extracted_bits: 3,
        pk_size: 15632,
        sk_size: 31296,
        ct_size: 15744,
        ss_len: 24,
        seed_a_len: 16,
        seed_se_len: 24,
        mu_len: 24,
        pk_hash_len: 24,
        salt_len: 0,
        cdf_table: &CDF_976,
        prg: PrgMode::Aes,
    },
    // eFrodoKEM-1344-AES
    FrodoParams {
        n: 1344,
        n_bar: 8,
        logq: 16,
        extracted_bits: 4,
        pk_size: 21520,
        sk_size: 43088,
        ct_size: 21632,
        ss_len: 32,
        seed_a_len: 16,
        seed_se_len: 32,
        mu_len: 32,
        pk_hash_len: 32,
        salt_len: 0,
        cdf_table: &CDF_1344,
        prg: PrgMode::Aes,
    },
];
