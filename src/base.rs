//! Module for finding the base address of a misaligned 8051 firmware
use crate::instr::{InsType, Instructeam};
use rustfft::algorithm::Radix4;
use rustfft::num_complex::Complex;
use rustfft::FFT;

/// Finds the base address of a misaligned 8051 firmware image.
///
/// This works by counting how many times an address is the target
/// of an lcall/ljmp (acall/ajmp too if acall is enabled) and cross-
/// correlating that with the addresses that are after ret instructions
/// This cross-correlation is equivalent to counting, for each possible
/// base address of the firmware, how many jump destinations are after
/// a ret instruction. For the right base address, this should be the
/// highest since often, new functions start after a return and jumps
/// go there.
///
/// In the naive way, calculating this would take 2^32 multiplies and
/// additions, since for each of the 2^16 base offsets, one would need
/// to multiply each value in the return array with the corresponding
/// value in the target address array, but luckily cross-correlation
/// can be done by cleverly using a FFT, so this is actually quite fast
///
/// For acall/ajmp, the target address is marked as if in the current block
/// and in the next block, since the block depends on the instruction's
/// address and cross-correlation couldn't be used, so this tradeoff is done
/// for speed.
///
/// # Arguments
///
/// * `buf` - Contents of the firmware file
/// * `acall` - whether to include acall/ajmp in the calculation (this
/// can introduce a lot of noise)
///
pub fn find_base(buf: &[u8], acall: bool) -> Vec<f64> {
    let mut rets = vec![0 as u16; 65536];
    let mut ljmps = vec![0 as u16; 65536];
    let mut ajmps = if acall {
        vec![0; 65536]
    } else {
        vec![0 as u16; 0]
    };
    // we pretend that the whole image is instructions that come right after another
    // While that is generally wrong for the whole image, this normally converges
    // to the proper instruction alignment after a few bytes (if it is actually
    // code)
    // this reduces noise that could be introduced by regarding immediate values
    // or similar opcode arguments as jump/call instructions
    for ins in Instructeam::new(buf) {
        match ins.itype {
            InsType::LJMP | InsType::LCALL => {
                // mark the target addresses in the target address array
                let target = ins.get_jump_target().unwrap();
                ljmps[target] += 1;
            }
            InsType::AJMP | InsType::ACALL => {
                if acall {
                    // find the target address of the ajmp/acall instruction
                    let target = ins.get_jump_target().unwrap();
                    ajmps[target] += 1;
                    // for different base addresses, the relative target address of two different ajmps can
                    // vary by 2048, so we just note both possibilities in the array
                    ajmps[(target + 2048) % 65536] += 1;
                }
            }
            InsType::RET => {
                // mark the address after the ret instruction
                rets[(ins.pos + 1) % 65536] += 1;
            }
            _ => {}
        }
    }
    let mut mean: Vec<f64> = cross_correlate(&rets, &ljmps)
        .iter()
        .map(|x| f64::from(x.re.round()))
        .collect();
    if acall {
        // for acalls, we only care about the first 2048 bytes (the size of a block)
        // and repeat that accross the whole address space, since it is periodic in
        // with that period (since it corresponds to moving the code block by 2048 bytes)
        mean = cross_correlate(&rets, &ajmps)
            .iter()
            .take(2048)
            .cycle()
            .take(65536)
            .zip(mean.iter())
            .map(|(x, y)| (f64::from(x.re.round()) + y) / 2.0)
            .collect();
    }
    mean
}

// finds `num` maximal indexes
pub fn maxidx(arr: &[f64], num: usize) -> Vec<(usize, f64)> {
    let mut maxidx = vec![(0, std::f64::NEG_INFINITY); num + 1];
    for candidate in arr.iter().enumerate().map(|(a, b)| (a, *b)) {
        if maxidx.len() > num {
            maxidx[num] = candidate;
        } else {
            maxidx.push(candidate);
        }
        maxidx.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Less));
    }
    if maxidx.len() > num {
        maxidx.pop();
    }
    maxidx
}

// a helper function for a circular cross-correlation of size 2¹⁶
// (the size of the code space of a conventional 8051 core)
// converts integers to floats, which can result in a bit of imprecision,
// but this hasn't been an issue yet since we're only searching for a
// maximum anyway and not a specific value (and the maximum is often
// 10x as big as the next lower value)
fn cross_correlate(a: &[u16], b: &[u16]) -> Vec<Complex<f32>> {
    let fft = Radix4::new(65536, false);
    let ifft = Radix4::new(65536, true);
    let u16_to_complex = |scl: &u16| Complex::new(f32::from(*scl), 0.0);
    let mut fa: Vec<Complex<f32>> = a.iter().map(u16_to_complex).collect();
    let mut fb: Vec<Complex<f32>> = b.iter().map(u16_to_complex).collect();
    let mut out = vec![Complex::new(0.0, 0.0); 65536];
    fft.process(&mut fa, &mut out);
    fft.process(&mut fb, &mut fa);
    fb = fa
        .iter()
        .zip(out.iter())
        .map(|(a, b)| b.conj() * a / 65536.0)
        .collect();
    ifft.process(&mut fb, &mut out);
    out
}
