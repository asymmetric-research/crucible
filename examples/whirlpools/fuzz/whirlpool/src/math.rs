// ============================================================================
// Ported from programs/whirlpool/src/math/tick_math.rs
// Pure computation: sqrt_price_from_tick_index for tight bound invariant
// ============================================================================

/// Multiply two u128 values and shift right by 96 bits (u256 precision).
pub fn harness_mul_shift_96(a: u128, b: u128) -> u128 {
    let a_lo = a & 0xFFFF_FFFF_FFFF_FFFF;
    let a_hi = a >> 64;
    let b_lo = b & 0xFFFF_FFFF_FFFF_FFFF;
    let b_hi = b >> 64;

    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;

    let (mid, mid_overflow) = lh.overflowing_add(hl);
    let mid_lo = mid & 0xFFFF_FFFF_FFFF_FFFF;
    let (w0, w0_carry) = ll.overflowing_add(mid_lo << 64);
    let w1 = hh + (mid >> 64) + (mid_overflow as u128) + (w0_carry as u128);

    (w1 << 32) | (w0 >> 96)
}

pub fn harness_get_sqrt_price_positive_tick(tick: i32) -> u128 {
    let mut ratio: u128 = if tick & 1 != 0 {
        79232123823359799118286999567
    } else {
        79228162514264337593543950336
    };
    if tick & 2 != 0 { ratio = harness_mul_shift_96(ratio, 79236085330515764027303304731); }
    if tick & 4 != 0 { ratio = harness_mul_shift_96(ratio, 79244008939048815603706035061); }
    if tick & 8 != 0 { ratio = harness_mul_shift_96(ratio, 79259858533276714757314932305); }
    if tick & 16 != 0 { ratio = harness_mul_shift_96(ratio, 79291567232598584799939703904); }
    if tick & 32 != 0 { ratio = harness_mul_shift_96(ratio, 79355022692464371645785046466); }
    if tick & 64 != 0 { ratio = harness_mul_shift_96(ratio, 79482085999252804386437311141); }
    if tick & 128 != 0 { ratio = harness_mul_shift_96(ratio, 79736823300114093921829183326); }
    if tick & 256 != 0 { ratio = harness_mul_shift_96(ratio, 80248749790819932309965073892); }
    if tick & 512 != 0 { ratio = harness_mul_shift_96(ratio, 81282483887344747381513967011); }
    if tick & 1024 != 0 { ratio = harness_mul_shift_96(ratio, 83390072131320151908154831281); }
    if tick & 2048 != 0 { ratio = harness_mul_shift_96(ratio, 87770609709833776024991924138); }
    if tick & 4096 != 0 { ratio = harness_mul_shift_96(ratio, 97234110755111693312479820773); }
    if tick & 8192 != 0 { ratio = harness_mul_shift_96(ratio, 119332217159966728226237229890); }
    if tick & 16384 != 0 { ratio = harness_mul_shift_96(ratio, 179736315981702064433883588727); }
    if tick & 32768 != 0 { ratio = harness_mul_shift_96(ratio, 407748233172238350107850275304); }
    if tick & 65536 != 0 { ratio = harness_mul_shift_96(ratio, 2098478828474011932436660412517); }
    if tick & 131072 != 0 { ratio = harness_mul_shift_96(ratio, 55581415166113811149459800483533); }
    if tick & 262144 != 0 { ratio = harness_mul_shift_96(ratio, 38992368544603139932233054999993551); }
    ratio >> 32
}

pub fn harness_get_sqrt_price_negative_tick(tick: i32) -> u128 {
    let abs_tick = tick.abs();
    let mut ratio: u128 = if abs_tick & 1 != 0 { 18445821805675392311 } else { 18446744073709551616 };
    if abs_tick & 2 != 0 { ratio = (ratio * 18444899583751176498) >> 64 }
    if abs_tick & 4 != 0 { ratio = (ratio * 18443055278223354162) >> 64 }
    if abs_tick & 8 != 0 { ratio = (ratio * 18439367220385604838) >> 64 }
    if abs_tick & 16 != 0 { ratio = (ratio * 18431993317065449817) >> 64 }
    if abs_tick & 32 != 0 { ratio = (ratio * 18417254355718160513) >> 64 }
    if abs_tick & 64 != 0 { ratio = (ratio * 18387811781193591352) >> 64 }
    if abs_tick & 128 != 0 { ratio = (ratio * 18329067761203520168) >> 64 }
    if abs_tick & 256 != 0 { ratio = (ratio * 18212142134806087854) >> 64 }
    if abs_tick & 512 != 0 { ratio = (ratio * 17980523815641551639) >> 64 }
    if abs_tick & 1024 != 0 { ratio = (ratio * 17526086738831147013) >> 64 }
    if abs_tick & 2048 != 0 { ratio = (ratio * 16651378430235024244) >> 64 }
    if abs_tick & 4096 != 0 { ratio = (ratio * 15030750278693429944) >> 64 }
    if abs_tick & 8192 != 0 { ratio = (ratio * 12247334978882834399) >> 64 }
    if abs_tick & 16384 != 0 { ratio = (ratio * 8131365268884726200) >> 64 }
    if abs_tick & 32768 != 0 { ratio = (ratio * 3584323654723342297) >> 64 }
    if abs_tick & 65536 != 0 { ratio = (ratio * 696457651847595233) >> 64 }
    if abs_tick & 131072 != 0 { ratio = (ratio * 26294789957452057) >> 64 }
    if abs_tick & 262144 != 0 { ratio = (ratio * 37481735321082) >> 64 }
    ratio
}

/// Port of sqrt_price_from_tick_index from the Whirlpool program.
/// Returns Q64.64 sqrt_price for a given tick index.
pub fn harness_sqrt_price_from_tick(tick: i32) -> u128 {
    if tick >= 0 {
        harness_get_sqrt_price_positive_tick(tick)
    } else {
        harness_get_sqrt_price_negative_tick(tick)
    }
}
