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
        0,
        1,
        2,
        u64::MAX,
        u64::MAX / 2,
        1 << 8,
        1 << 16,
        1 << 32,
        (1u64 << 8) - 1,
        (1u64 << 16) - 1,
        (1u64 << 32) - 1,
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

/// Generate a u64 in [lo, hi) with 25% boundary bias.
/// Reuses `pick_interesting_u64` for boundary values.
pub fn gen_u64<R: Rand>(rng: &mut R, lo: u64, hi: u64) -> u64 {
    if hi <= lo {
        return lo;
    }
    if rand_below(rng, 4) == 0 {
        if let Some(v) = pick_interesting_u64(lo, hi, rng) {
            return v;
        }
    }
    gen_range_u64(rng, lo, hi)
}

/// Generate a usize in [lo, hi) with 25% boundary bias.
pub fn gen_usize<R: Rand>(rng: &mut R, lo: usize, hi: usize) -> usize {
    gen_u64(rng, lo as u64, hi as u64) as usize
}

/// Generate an i64 in [lo, hi) with 25% boundary bias.
pub fn gen_i64<R: Rand>(rng: &mut R, lo: i64, hi: i64) -> i64 {
    if hi <= lo {
        return lo;
    }
    if rand_below(rng, 4) == 0 {
        if let Some(v) = pick_interesting_i64(lo, hi, rng) {
            return v;
        }
    }
    let range = (hi as u64).wrapping_sub(lo as u64);
    lo.wrapping_add((rng.next() % range) as i64)
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

/// Generate a random u128 in [lo, hi) using LibAFL's Rand trait.
pub fn gen_range_u128<R: Rand>(rng: &mut R, lo: u128, hi: u128) -> u128 {
    if hi <= lo {
        return lo;
    }
    let range = hi - lo;
    let raw = ((rng.next() as u128) << 64) | (rng.next() as u128);
    lo + (raw % range)
}

/// Pick a random interesting u128 value in [lo, hi) without heap allocation.
#[inline]
fn pick_interesting_u128<R: Rand>(lo: u128, hi: u128, rng: &mut R) -> Option<u128> {
    const STATIC_CANDIDATES: [u128; 15] = [
        0,
        1,
        2,
        u128::MAX,
        u128::MAX / 2,
        1 << 8,
        1 << 16,
        1 << 32,
        1 << 64,
        (1u128 << 8) - 1,
        (1u128 << 16) - 1,
        (1u128 << 32) - 1,
        (1u128 << 64) - 1,
        u64::MAX as u128,
        (u64::MAX as u128) + 1,
    ];
    let dynamic: [u128; 2] = [lo, hi.saturating_sub(1)];

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

/// Generate a u128 in [lo, hi) with 25% boundary bias.
pub fn gen_u128<R: Rand>(rng: &mut R, lo: u128, hi: u128) -> u128 {
    if hi <= lo {
        return lo;
    }
    if rand_below(rng, 4) == 0 {
        if let Some(v) = pick_interesting_u128(lo, hi, rng) {
            return v;
        }
    }
    gen_range_u128(rng, lo, hi)
}

/// Generate an i128 in [lo, hi) with 25% boundary bias.
pub fn gen_i128<R: Rand>(rng: &mut R, lo: i128, hi: i128) -> i128 {
    if hi <= lo {
        return lo;
    }
    if rand_below(rng, 4) == 0 {
        let candidates: [i128; 7] = [lo, hi - 1, 0, 1, -1, lo / 2, (hi - 1) / 2];
        let mut count = 0u32;
        for &v in &candidates {
            if v >= lo && v < hi {
                count += 1;
            }
        }
        if count > 0 {
            let target = rand_below(rng, count as usize) as u32;
            let mut seen = 0u32;
            for &v in &candidates {
                if v >= lo && v < hi {
                    if seen == target {
                        return v;
                    }
                    seen += 1;
                }
            }
        }
    }
    let range = (hi as u128).wrapping_sub(lo as u128);
    let raw = ((rng.next() as u128) << 64) | (rng.next() as u128);
    lo.wrapping_add((raw % range) as i128)
}

/// Mutate a u128 value within [lo, hi).
/// - 40% interesting values
/// - 30% arithmetic (+/-1, +/-small)
/// - 30% random in range
pub fn mutate_u128<R: Rand>(val: &mut u128, lo: u128, hi: u128, rng: &mut R) {
    if hi <= lo {
        return;
    }
    let choice = rand_below(rng, 100);
    if choice < 40 {
        if let Some(v) = pick_interesting_u128(lo, hi, rng) {
            *val = v;
        } else {
            *val = gen_range_u128(rng, lo, hi);
        }
    } else if choice < 70 {
        // Arithmetic mutation — stay in u128 space to avoid i128 wrapping
        // when val or lo/hi are in the upper half of u128 (> i128::MAX).
        let delta_abs_choices: &[u128] = &[1, 2, 4, 8, 16, 32];
        let idx = rand_below(rng, delta_abs_choices.len());
        let delta_abs = delta_abs_choices[idx];
        let max_val = hi - 1;
        if rand_below(rng, 2) == 0 {
            // Subtract
            *val = val.saturating_sub(delta_abs).max(lo);
        } else {
            // Add
            *val = val.saturating_add(delta_abs).min(max_val);
        }
        // Clamp into [lo, hi) in case val started outside the range
        *val = (*val).max(lo).min(max_val);
    } else {
        *val = gen_range_u128(rng, lo, hi);
    }
}

/// Mutate an i128 value within [lo, hi).
pub fn mutate_i128<R: Rand>(val: &mut i128, lo: i128, hi: i128, rng: &mut R) {
    if hi <= lo {
        return;
    }
    let range = (hi as u128).wrapping_sub(lo as u128);
    let choice = rand_below(rng, 100);
    if choice < 40 {
        let candidates: [i128; 7] = [lo, hi - 1, 0, 1, -1, lo / 2, (hi - 1) / 2];
        let mut count = 0u32;
        for &v in &candidates {
            if v >= lo && v < hi {
                count += 1;
            }
        }
        if count > 0 {
            let target = rand_below(rng, count as usize) as u32;
            let mut seen = 0u32;
            for &v in &candidates {
                if v >= lo && v < hi {
                    if seen == target {
                        *val = v;
                        return;
                    }
                    seen += 1;
                }
            }
        }
        let raw = ((rng.next() as u128) << 64) | (rng.next() as u128);
        *val = lo.wrapping_add((raw % range) as i128);
    } else if choice < 70 {
        let delta_choices: &[i64] = &[-1, 1, -2, 2, -4, 4, -8, 8];
        let idx = rand_below(rng, delta_choices.len());
        let delta = delta_choices[idx] as i128;
        *val = val.saturating_add(delta).max(lo).min(hi - 1);
    } else {
        let raw = ((rng.next() as u128) << 64) | (rng.next() as u128);
        *val = lo.wrapping_add((raw % range) as i128);
    }
}
