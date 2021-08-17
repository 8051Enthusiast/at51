//! Provides some statistical information on the "8051ness" of regions of a file
use crate::instr::{InsType, Instructeam};
use lazy_static::lazy_static;
use std::vec::Vec;

pub fn count_instructions(buf: &[u8], blocksize: usize) -> Vec<[usize; 256]> {
    let total_len = buf.len() / blocksize + (buf.len() % blocksize != 0) as usize;
    let mut countvec: Vec<[usize; 256]> = vec![[0; 256]; total_len];
    let instr_iter = crate::instr::Instructeam::new(buf);
    for instr in instr_iter {
        countvec[instr.pos / blocksize][instr.bytes[0] as usize] += 1;
    }
    countvec
}

/// Square-Chi test of a block, used for the statistical analysis of the blocks
/// of a file for 8051ness
pub fn square_chi(freq: &[usize], block_n: usize, pop: &[f64]) -> f64 {
    let mut square_x = 0.0f64;
    for (p, q) in freq.iter().zip(pop.iter()) {
        let rel_p = (*p as f64) / (block_n as f64);
        // I'm not sure if I should ignore the factor at the beginning, it is certainly
        // more consistent against different blocksizes when leaving it out and we
        // don't care about statistical significance anyway
        square_x += /*(block_n as f64) **/ (rel_p - q).powi(2) / q;
    }
    square_x
}

/// Kullback-Leibler divergence of a block, ranges from 0 to 1
pub fn kullback_leibler(freq: &[usize], block_n: usize, pop: &[f64]) -> f64 {
    let mut kld = 0.0f64;
    for (p, q) in freq.iter().zip(pop.iter()) {
        // if freq[i] = 0, we multiply by 0 and the log becomes 0 too (in this case)
        if *p > 0 {
            let rel_p = (*p as f64) / (block_n as f64);
            kld += rel_p * (rel_p / q).log(256.0);
        }
    }
    kld
}

/// Runs a statistical goodness-of-fit test blockwise on the opcodes (not operands!).
/// Typically, <300 means that it is 8051 code.
/// Note that the individual opcodes are grouped into groups of similar probability so that
/// smaller blocks work better.
pub fn stat_blocks(
    buf: &[u8],
    blocksize: usize,
    blockfun: fn(&[usize], usize, &[f64]) -> f64,
    freqinfo: Option<&FreqInfo>,
) -> Vec<(f64, usize)> {
    // the maximum instruction size is 3, make sure we have at least one instruction in each block
    // (not that blocksizes this small would make sense anyway)
    if blocksize < 3 {
        panic!("Blocksize needs to be at least 3");
    }
    let actual_freqinfo = freqinfo.unwrap_or_default();
    let mut ret = Vec::new();
    let mut freq = vec![0; actual_freqinfo.relative_freqency.len()];
    let mut prev_block = 0;
    let mut block_n = 0;
    // only care about opcodes
    for instr in crate::instr::Instructeam::new(buf) {
        // if new block begins
        if instr.pos / blocksize > prev_block {
            ret.push((
                blockfun(&freq, block_n, &actual_freqinfo.relative_freqency),
                block_n,
            ));
            prev_block = instr.pos / blocksize;
            block_n = 0;
            for x in &mut freq {
                *x = 0;
            }
        }
        block_n += 1;
        freq[actual_freqinfo.group_map[instr.bytes[0] as usize] as usize] += 1;
    }
    ret.push((
        blockfun(&freq, block_n, &actual_freqinfo.relative_freqency),
        block_n,
    ));
    ret
}

/// Counts the percentage of instructions whose jump address does not align with the instruction
/// stream
/// buf: firmware
/// blocksize: size of blocks where percentage is calculated
/// abs: whether to include absolute jumps and block jumps (ajmp/acall)
/// count_outside: whether to include jumps outside of the buffer
pub fn instr_align_count(
    buf: &[u8],
    blocksize: usize,
    abs: bool,
    count_outside: bool,
) -> Vec<(f64, usize)> {
    if blocksize < 3 {
        panic!("Blocksize needs to be at least 3");
    }
    let mut is_instr_start = Vec::new();
    // record which bytes are the start of an instruction,
    // assuming a continuous instruction stream
    for instr in Instructeam::new(buf) {
        for i in 0..instr.bytes.len() {
            is_instr_start.push(i == 0 && !matches!(*instr.itype, InsType::Resrv))
        }
    }
    // there might be a byte near the end whose instruction is
    // longer than the file end, so we add that here
    is_instr_start.resize(buf.len(), false);
    let mut ret = Vec::new();
    let mut prev_block = 0;
    let mut block_jumps = 0usize;
    let mut block_aligns = 0usize;
    for instr in Instructeam::new(buf) {
        if instr.pos / blocksize > prev_block {
            // begin new block
            ret.push((1.0 - block_aligns as f64 / block_jumps as f64, block_jumps));
            block_aligns = 0;
            block_jumps = 0;
            prev_block = instr.pos / blocksize;
        }
        if let Some(target) = instr.get_jump_target() {
            let is_abs = matches!(
                instr.itype,
                InsType::Ljmp | InsType::Lcall | InsType::Ajmp | InsType::Acall
            );
            // count number of valid aligned jumps
            if (abs || !is_abs) && (count_outside || target < is_instr_start.len()) {
                block_jumps += 1;
            }
            // count number of all valid jumps
            if let Some(true) = is_instr_start.get(target) {
                if abs || !is_abs {
                    block_aligns += 1;
                }
            }
        }
    }
    // push last remaining block
    ret.push((1.0 - block_aligns as f64 / block_jumps as f64, block_jumps));
    ret
}

/// Contains information about the distribution of opcodes, collected into buckets of similar
/// frequency
pub struct FreqInfo {
    group_map: [u8; 256],
    relative_freqency: Vec<f64>,
}

impl FreqInfo {
    /// Derives frequency information from a buffer with given bucket sizes
    /// # Arguments
    /// * `buckets`: sizes of the buckets where opcodes of similar frequencies get put, in
    /// ascending order of frequency
    /// * `buf`: corpus containing pure 8051 machine code
    pub fn new(buckets: &[usize], buf: &[u8]) -> Result<FreqInfo, &'static str> {
        let bucketsum: usize = buckets.iter().sum();
        if bucketsum != 256 {
            return Err("Bucket sizes must add up to exactly 256");
        };
        let count = count_instructions(buf, buf.len());
        // number of all opcodes
        let total_count: usize = count[0].iter().sum();
        // pairs of position and frequency
        let mut freq_map: Vec<(usize, &usize)> = count[0].iter().enumerate().collect();
        // sort by frequency
        freq_map.sort_by_key(|x| x.1);
        let mut buck_asc = Vec::new();
        for (i, x) in buckets.iter().enumerate() {
            for _ in 0..*x {
                buck_asc.push(i as u8);
            }
        }
        let mut group_map = [0u8; 256];
        for (i, gm) in group_map.iter_mut().enumerate() {
            match freq_map.iter().position(|x| x.0 == i) {
                Some(pos) => *gm = buck_asc[pos],
                None => panic!("Oops"),
            }
        }
        let mut sums = vec![0.0f64; buckets.len()];
        for (i, m) in freq_map {
            sums[usize::from(group_map[i])] += (*m as f64) / (total_count as f64);
        }
        Ok(FreqInfo {
            group_map,
            relative_freqency: sums,
        })
    }
}

impl Default for &FreqInfo {
    fn default() -> &'static FreqInfo {
        lazy_static! {
            static ref FREQ: FreqInfo = FreqInfo {
                group_map: [
                    13, 6, 14, 6, 7, 14, 2, 1, 6, 4, 4, 1, 2, 2, 1, 3, 2, 2, 14, 5, 12, 7, 0, 1, 4,
                    2, 1, 2, 2, 2, 0, 2, 8, 3, 13, 5, 14, 11, 0, 1, 3, 2, 3, 1, 2, 4, 5, 6, 8, 2,
                    3, 9, 13, 9, 0, 0, 3, 5, 3, 5, 5, 3, 7, 4, 10, 2, 1, 12, 4, 4, 0, 0, 3, 3, 1,
                    3, 2, 3, 3, 3, 8, 1, 2, 12, 11, 3, 0, 0, 1, 1, 1, 1, 2, 0, 2, 0, 12, 3, 6, 4,
                    8, 5, 3, 3, 6, 5, 2, 0, 3, 2, 7, 3, 13, 0, 3, 4, 14, 15, 2, 0, 10, 7, 7, 7, 8,
                    9, 7, 9, 13, 1, 3, 2, 3, 13, 4, 2, 4, 5, 8, 6, 10, 9, 11, 9, 15, 0, 5, 12, 11,
                    7, 0, 0, 3, 1, 1, 1, 3, 3, 5, 6, 0, 1, 6, 15, 12, 0, 2, 2, 5, 5, 7, 6, 8, 7,
                    11, 9, 1, 0, 1, 2, 10, 6, 0, 1, 3, 2, 2, 2, 3, 2, 3, 3, 14, 4, 11, 12, 9, 6, 2,
                    0, 7, 1, 4, 1, 4, 3, 10, 4, 14, 0, 11, 6, 0, 1, 0, 0, 5, 3, 1, 1, 0, 0, 1, 1,
                    15, 0, 1, 0, 15, 15, 10, 1, 6, 6, 5, 6, 7, 10, 11, 13, 15, 0, 2, 1, 4, 15, 5,
                    0, 8, 7, 7, 7, 10, 12, 13, 14,
                ],
                relative_freqency: vec![
                    0.001_133_263_378_803_777_4,
                    0.005_624_344_176_285_417,
                    0.012_507_869_884_575_034,
                    0.021_112_277_019_937_044,
                    0.016_243_441_762_854_145,
                    0.022_581_322_140_608_61,
                    0.033_452_256_033_578_175,
                    0.048_898_216_159_496_33,
                    0.031_143_756_558_237_15,
                    0.034_291_710_388_247_63,
                    0.040_839_454_354_669_465,
                    0.054_270_724_029_380_9,
                    0.069_464_847_848_898_21,
                    0.107_366_211_962_224_57,
                    0.145_015_739_769_150_05,
                    0.356_054_564_533_053_56,
                ]
            };
        }
        &FREQ
    }
}
