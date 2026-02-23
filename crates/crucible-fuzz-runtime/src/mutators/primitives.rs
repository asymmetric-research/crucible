use libafl_bolts::rands::Rand;
use std::num::NonZeroUsize;

/// Helper: call rng.below() with a usize, handling the NonZeroUsize requirement.
/// Returns 0 if n == 0.
#[inline]
pub fn rand_below<R: Rand>(rng: &mut R, n: usize) -> usize {
    match NonZeroUsize::new(n) {
        Some(nz) => rng.below(nz),
        None => 0,
    }
}

/// Generate a random u64 in [lo, hi) using LibAFL's Rand trait.
pub fn gen_range_u64<R: Rand>(rng: &mut R, lo: u64, hi: u64) -> u64 {
    if hi <= lo {
        return lo;
    }
    let range = hi - lo;
    lo + (rng.next() % range)
}

/// Generate a random usize in [lo, hi) using LibAFL's Rand trait.
pub fn gen_range_usize<R: Rand>(rng: &mut R, lo: usize, hi: usize) -> usize {
    if hi <= lo {
        return lo;
    }
    lo + rand_below(rng, hi - lo)
}

/// Pick a random interesting u64 value in [lo, hi) without heap allocation.
/// Returns None if no interesting values fall in range.
#[inline]
fn pick_interesting_u64<R: Rand>(lo: u64, hi: u64, rng: &mut R) -> Option<u64> {
    const STATIC_CANDIDATES: [u64; 11] = [
        0, 1, 2, u64::MAX, u64::MAX / 2,
        1 << 8, 1 << 16, 1 << 32,
        (1u64 << 8) - 1, (1u64 << 16) - 1, (1u64 << 32) - 1,
    ];
    // Dynamic candidates depend on lo/hi
    let dynamic: [u64; 3] = [lo, hi.saturating_sub(1), 1u64 << 63];

    // Count in-range candidates (stack only)
    let mut count = 0u32;
    for &v in &STATIC_CANDIDATES {
        if v >= lo && v < hi {
            count += 1;
        }
    }
    for &v in &dynamic {
        if v >= lo && v < hi {
            count += 1;
        }
    }
    if count == 0 {
        return None;
    }

    // Pick random index, walk again to find it
    let target = rand_below(rng, count as usize) as u32;
    let mut seen = 0u32;
    for &v in STATIC_CANDIDATES.iter().chain(&dynamic) {
        if v >= lo && v < hi {
            if seen == target {
                return Some(v);
            }
            seen += 1;
        }
    }
    None
}

/// Mutate a u64 value within [lo, hi).
/// - 40% interesting values
/// - 30% arithmetic (+/-1, +/-small)
/// - 30% random in range
pub fn mutate_u64<R: Rand>(val: &mut u64, lo: u64, hi: u64, rng: &mut R) {
    if hi <= lo {
        return;
    }
    let choice = rand_below(rng, 100);
    if choice < 40 {
        // Interesting value (zero-alloc)
        if let Some(v) = pick_interesting_u64(lo, hi, rng) {
            *val = v;
        } else {
            *val = gen_range_u64(rng, lo, hi);
        }
    } else if choice < 70 {
        // Arithmetic mutation
        let delta_choices: &[i64] = &[-1, 1, -2, 2, -4, 4, -8, 8, -16, 16, -32, 32];
        let idx = rand_below(rng, delta_choices.len());
        let delta = delta_choices[idx];
        let new_val = (*val as i128 + delta as i128).clamp(lo as i128, (hi as i128) - 1) as u64;
        *val = new_val;
    } else {
        // Random in range
        *val = gen_range_u64(rng, lo, hi);
    }
}

/// Mutate a usize value within [lo, hi).
pub fn mutate_usize<R: Rand>(val: &mut usize, lo: usize, hi: usize, rng: &mut R) {
    let mut v64 = *val as u64;
    mutate_u64(&mut v64, lo as u64, hi as u64, rng);
    *val = v64 as usize;
}

/// Mutate a bool value (flip with some probability).
pub fn mutate_bool<R: Rand>(val: &mut bool, rng: &mut R) {
    // 50% chance to flip
    if rand_below(rng, 2) == 0 {
        *val = !*val;
    }
}

/// Pick a random interesting i64 value in [lo, hi) without heap allocation.
#[inline]
fn pick_interesting_i64<R: Rand>(lo: i64, hi: i64, rng: &mut R) -> Option<i64> {
    let candidates: [i64; 7] = [lo, hi - 1, 0, 1, -1, lo / 2, (hi - 1) / 2];
    let mut count = 0u32;
    for &v in &candidates {
        if v >= lo && v < hi {
            count += 1;
        }
    }
    if count == 0 {
        return None;
    }
    let target = rand_below(rng, count as usize) as u32;
    let mut seen = 0u32;
    for &v in &candidates {
        if v >= lo && v < hi {
            if seen == target {
                return Some(v);
            }
            seen += 1;
        }
    }
    None
}

/// Mutate an i64 value within [lo, hi).
pub fn mutate_i64<R: Rand>(val: &mut i64, lo: i64, hi: i64, rng: &mut R) {
    if hi <= lo {
        return;
    }
    // Compute range as u64 to avoid signed overflow (e.g., lo=i64::MIN, hi=0)
    let range = (hi as u64).wrapping_sub(lo as u64);
    let choice = rand_below(rng, 100);
    if choice < 40 {
        // Boundary values (zero-alloc)
        if let Some(v) = pick_interesting_i64(lo, hi, rng) {
            *val = v;
        } else {
            *val = lo.wrapping_add((rng.next() % range) as i64);
        }
    } else if choice < 70 {
        let delta_choices: &[i64] = &[-1, 1, -2, 2, -4, 4, -8, 8];
        let idx = rand_below(rng, delta_choices.len());
        let delta = delta_choices[idx];
        *val = (*val as i128 + delta as i128).clamp(lo as i128, (hi as i128) - 1) as i64;
    } else {
        *val = lo.wrapping_add((rng.next() % range) as i64);
    }
}
