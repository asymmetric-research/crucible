/// AFL-style hitcount bucketing.
///
/// Converts edge hitcount to 13 buckets (50% more granular than AFL's 9)
/// to reduce coverage plateaus in stateful fuzzing where action sequences
/// hit the same edges at different depths.
#[inline]
pub fn to_bucket(count: u8) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4..=5 => 4,
        6..=7 => 5,
        8..=11 => 6,
        12..=15 => 7,
        16..=23 => 8,
        24..=31 => 9,
        32..=63 => 10,
        64..=127 => 11,
        _ => 12,
    }
}

/// xxhash-style bit mixing for edge IDs.
///
/// Ensures uniform distribution even for clustered inputs like BPF program counters.
/// Used to hash edge IDs and branch PCs before indexing into bitmap.
#[inline]
pub fn mix_hash(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    h
}
