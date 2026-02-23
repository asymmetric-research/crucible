use crate::action::FuzzAction;
use crate::input::FuzzInput;
use crate::mutators::primitives::{
    gen_range_u64, gen_range_usize, mutate_bool, mutate_i64, mutate_u64, mutate_usize, rand_below,
};
use crate::test_helpers::{TestAction, SmallIntTestAction};
use libafl_bolts::rands::{Rand, RomuDuoJrRand};
use std::collections::HashSet;
use std::time::Instant;

fn make_rng(seed: u64) -> RomuDuoJrRand {
    RomuDuoJrRand::with_seed(seed)
}

/// Build a representative 8-action input for benchmarking.
fn build_8_action_input(rng: &mut RomuDuoJrRand) -> FuzzInput<TestAction> {
    let actions: Vec<TestAction> = (0..8).map(|_| TestAction::random(rng)).collect();
    FuzzInput::new(actions)
}

// ============================================================================
// Timing benchmarks (run with `cargo test -- --nocapture` to see output)
// ============================================================================

#[test]
fn bench_from_bytes() {
    let mut rng = make_rng(1);
    let input = build_8_action_input(&mut rng);
    let bytes = input.to_bytes();
    let n = 1_000_000;

    let start = Instant::now();
    for _ in 0..n {
        let _ = FuzzInput::<TestAction>::from_bytes(&bytes);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "bench_from_bytes: {:.1} ns/iter ({} iters in {:?})",
        elapsed.as_nanos() as f64 / n as f64,
        n,
        elapsed
    );
}

#[test]
fn bench_to_bytes() {
    let mut rng = make_rng(2);
    let input = build_8_action_input(&mut rng);
    let n = 1_000_000;

    let start = Instant::now();
    for _ in 0..n {
        let _ = input.to_bytes();
    }
    let elapsed = start.elapsed();
    eprintln!(
        "bench_to_bytes: {:.1} ns/iter ({} iters in {:?})",
        elapsed.as_nanos() as f64 / n as f64,
        n,
        elapsed
    );
}

#[test]
fn bench_param_mutator_cycle() {
    let mut rng = make_rng(3);
    let input = build_8_action_input(&mut rng);
    let bytes = input.to_bytes();
    let n = 1_000_000;

    let start = Instant::now();
    for _ in 0..n {
        let mut decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
        if !decoded.actions.is_empty() {
            let idx = rand_below(&mut rng, decoded.actions.len());
            decoded.actions[idx].mutate(&mut rng);
        }
        let _ = decoded.to_bytes();
    }
    let elapsed = start.elapsed();
    eprintln!(
        "bench_param_mutator_cycle: {:.1} ns/iter ({} iters in {:?})",
        elapsed.as_nanos() as f64 / n as f64,
        n,
        elapsed
    );
}

#[test]
fn bench_sequence_mutator_cycle() {
    let mut rng = make_rng(4);
    let input = build_8_action_input(&mut rng);
    let bytes = input.to_bytes();
    let n = 1_000_000;

    let start = Instant::now();
    for _ in 0..n {
        let mut decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
        // Simulate a simple sequence mutation (swap)
        if decoded.actions.len() >= 2 {
            let i = rand_below(&mut rng, decoded.actions.len());
            let j = rand_below(&mut rng, decoded.actions.len());
            decoded.actions.swap(i, j);
        }
        let _ = decoded.to_bytes();
    }
    let elapsed = start.elapsed();
    eprintln!(
        "bench_sequence_mutator_cycle: {:.1} ns/iter ({} iters in {:?})",
        elapsed.as_nanos() as f64 / n as f64,
        n,
        elapsed
    );
}

#[test]
fn bench_interesting_u64_alloc() {
    // Benchmark the current interesting_u64_values with Vec allocation
    // We call mutate_u64 which internally calls interesting_u64_values ~40% of the time
    let mut rng = make_rng(5);
    let n = 10_000_000;
    let mut val = 50u64;

    let start = Instant::now();
    for _ in 0..n {
        mutate_u64(&mut val, 1, 100_000_000, &mut rng);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "bench_interesting_u64 (mutate_u64): {:.1} ns/iter ({} iters in {:?})",
        elapsed.as_nanos() as f64 / n as f64,
        n,
        elapsed
    );
}

#[test]
fn bench_mutate_u64_current() {
    let mut rng = make_rng(6);
    let n = 10_000_000;
    let mut val = 500_000u64;

    let start = Instant::now();
    for _ in 0..n {
        mutate_u64(&mut val, 0, u64::MAX, &mut rng);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "bench_mutate_u64_current: {:.1} ns/iter ({} iters in {:?})",
        elapsed.as_nanos() as f64 / n as f64,
        n,
        elapsed
    );
}

#[test]
fn bench_full_pipeline_8_stacked() {
    let mut rng = make_rng(7);
    let input = build_8_action_input(&mut rng);
    let initial_bytes = input.to_bytes();
    let n = 100_000;

    let start = Instant::now();
    for _ in 0..n {
        let mut bytes = initial_bytes.clone();
        // 8 stacked mutations (worst case from StdMOptMutator)
        for _ in 0..8 {
            let mut decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
            if !decoded.actions.is_empty() {
                let idx = rand_below(&mut rng, decoded.actions.len());
                decoded.actions[idx].mutate(&mut rng);
            }
            bytes = decoded.to_bytes();
        }
        // Final harness decode
        let _ = FuzzInput::<TestAction>::from_bytes(&bytes);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "bench_full_pipeline_8_stacked: {:.1} ns/iter ({} iters in {:?})",
        elapsed.as_nanos() as f64 / n as f64,
        n,
        elapsed
    );
}

#[test]
fn bench_full_pipeline_2_stacked() {
    let mut rng = make_rng(8);
    let input = build_8_action_input(&mut rng);
    let initial_bytes = input.to_bytes();
    let n = 100_000;

    let start = Instant::now();
    for _ in 0..n {
        let mut bytes = initial_bytes.clone();
        // 2 stacked mutations (best case)
        for _ in 0..2 {
            let mut decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
            if !decoded.actions.is_empty() {
                let idx = rand_below(&mut rng, decoded.actions.len());
                decoded.actions[idx].mutate(&mut rng);
            }
            bytes = decoded.to_bytes();
        }
        let _ = FuzzInput::<TestAction>::from_bytes(&bytes);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "bench_full_pipeline_2_stacked: {:.1} ns/iter ({} iters in {:?})",
        elapsed.as_nanos() as f64 / n as f64,
        n,
        elapsed
    );
}

// ============================================================================
// Correctness tests
// ============================================================================

#[test]
fn test_param_mutator_preserves_variant_types() {
    let mut rng = make_rng(100);
    let input = build_8_action_input(&mut rng);
    let original_variants: Vec<usize> = input.actions.iter().map(|a| a.variant_index()).collect();

    let bytes = input.to_bytes();
    // Apply param mutation 100 times, verify variant indices are unchanged
    for _ in 0..100 {
        let mut decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
        assert_eq!(decoded.actions.len(), original_variants.len());
        if !decoded.actions.is_empty() {
            let idx = rand_below(&mut rng, decoded.actions.len());
            decoded.actions[idx].mutate(&mut rng);
        }
        let mutated_variants: Vec<usize> =
            decoded.actions.iter().map(|a| a.variant_index()).collect();
        assert_eq!(
            original_variants, mutated_variants,
            "Param mutation changed variant types!"
        );
    }
}

#[test]
fn test_sequence_mutator_valid_roundtrip() {
    // We can't easily construct a full LibAFL state here, so we test
    // the decode/encode roundtrip after manual sequence operations
    let mut rng = make_rng(200);
    for _ in 0..100 {
        let count = 1 + (rng.next() as usize % 8);
        let mut actions: Vec<TestAction> =
            (0..count).map(|_| TestAction::random(&mut rng)).collect();

        // Apply random sequence operation
        let op = rand_below(&mut rng, 4);
        match op {
            0 if actions.len() >= 2 => {
                let i = rand_below(&mut rng, actions.len());
                let j = rand_below(&mut rng, actions.len());
                actions.swap(i, j);
            }
            1 if actions.len() > 1 => {
                let idx = rand_below(&mut rng, actions.len());
                actions.remove(idx);
            }
            2 => {
                let new_action = TestAction::random(&mut rng);
                let pos = rand_below(&mut rng, actions.len() + 1);
                actions.insert(pos, new_action);
            }
            _ => {}
        }

        // Verify roundtrip
        let input = FuzzInput::new(actions.clone());
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
        assert_eq!(actions.len(), decoded.actions.len());
        for (a, b) in actions.iter().zip(decoded.actions.iter()) {
            assert_eq!(a, b);
        }
    }
}

#[test]
fn test_mutate_u64_stays_in_range() {
    let mut rng = make_rng(300);
    let lo = 10u64;
    let hi = 1000u64;
    let mut val = 500u64;

    for _ in 0..10_000 {
        mutate_u64(&mut val, lo, hi, &mut rng);
        assert!(
            val >= lo && val < hi,
            "mutate_u64 out of range: val={}, range=[{}, {})",
            val,
            lo,
            hi
        );
    }
}

#[test]
fn test_mutate_bool_flips() {
    let mut rng = make_rng(400);
    let mut val = false;
    let mut flip_count = 0;
    let n = 10_000;

    for _ in 0..n {
        let old = val;
        mutate_bool(&mut val, &mut rng);
        if val != old {
            flip_count += 1;
        }
    }

    let flip_rate = flip_count as f64 / n as f64;
    assert!(
        flip_rate > 0.4 && flip_rate < 0.6,
        "Expected ~50% flip rate, got {:.1}%",
        flip_rate * 100.0
    );
}

// ============================================================================
// Substantive mutator functionality tests
// ============================================================================

#[test]
fn test_mutate_u64_hits_interesting_values() {
    // Verify that mutate_u64 actually produces boundary/interesting values
    // over many iterations (not just random noise)
    let mut rng = make_rng(700);
    let mut seen = HashSet::new();
    let mut val = 50u64;

    // With range [0, 1000), interesting values include: 0, 1, 2, 999
    for _ in 0..10_000 {
        mutate_u64(&mut val, 0, 1000, &mut rng);
        seen.insert(val);
    }

    assert!(seen.contains(&0), "mutate_u64 never produced boundary value 0");
    assert!(seen.contains(&1), "mutate_u64 never produced boundary value 1");
    assert!(seen.contains(&2), "mutate_u64 never produced boundary value 2");
    assert!(seen.contains(&999), "mutate_u64 never produced boundary value hi-1=999");
    assert!(seen.contains(&255), "mutate_u64 never produced interesting value (1<<8)-1=255");
    // Should produce many distinct values (not stuck on one)
    assert!(
        seen.len() > 50,
        "mutate_u64 produced too few distinct values: {}",
        seen.len()
    );
}

#[test]
fn test_mutate_u64_arithmetic_delta_works() {
    // Verify arithmetic mutations produce values near the current value
    let mut rng = make_rng(701);
    let mut deltas_seen = HashSet::new();
    let base = 500u64;

    for _ in 0..50_000 {
        let mut val = base;
        mutate_u64(&mut val, 0, 1000, &mut rng);
        let delta = val as i64 - base as i64;
        if delta.abs() <= 32 && delta != 0 {
            deltas_seen.insert(delta);
        }
    }

    // Arithmetic branch uses deltas: ±1, ±2, ±4, ±8, ±16, ±32
    // We should see at least ±1 and ±2
    assert!(
        deltas_seen.contains(&1) && deltas_seen.contains(&-1),
        "Arithmetic mutation never produced ±1 delta. Seen: {:?}",
        deltas_seen
    );
    assert!(
        deltas_seen.contains(&2) && deltas_seen.contains(&-2),
        "Arithmetic mutation never produced ±2 delta. Seen: {:?}",
        deltas_seen
    );
}

#[test]
fn test_mutate_u64_narrow_range() {
    // Range [5, 7): only values 5 and 6 are valid
    let mut rng = make_rng(702);
    let mut val = 5u64;

    for _ in 0..1000 {
        mutate_u64(&mut val, 5, 7, &mut rng);
        assert!(val >= 5 && val < 7, "Out of narrow range: {}", val);
    }
}

#[test]
fn test_mutate_u64_single_value_range() {
    // Range [42, 43): only value 42 is valid
    let mut rng = make_rng(703);
    let mut val = 42u64;

    for _ in 0..100 {
        mutate_u64(&mut val, 42, 43, &mut rng);
        assert_eq!(val, 42, "Single-value range should always produce 42");
    }
}

#[test]
fn test_mutate_usize_stays_in_range() {
    let mut rng = make_rng(710);
    let mut val = 1usize;

    for _ in 0..10_000 {
        mutate_usize(&mut val, 0, 3, &mut rng);
        assert!(
            val < 3,
            "mutate_usize out of range: val={}, expected [0, 3)",
            val
        );
    }
}

#[test]
fn test_mutate_usize_covers_range() {
    let mut rng = make_rng(711);
    let mut val = 1usize;
    let mut seen = HashSet::new();

    for _ in 0..1000 {
        mutate_usize(&mut val, 0, 5, &mut rng);
        seen.insert(val);
    }

    // Should visit all 5 values in [0, 5) eventually
    for expected in 0..5 {
        assert!(
            seen.contains(&expected),
            "mutate_usize never produced value {} in [0, 5). Seen: {:?}",
            expected,
            seen
        );
    }
}

#[test]
fn test_mutate_i64_stays_in_range() {
    let mut rng = make_rng(720);
    let mut val = 0i64;

    for _ in 0..10_000 {
        mutate_i64(&mut val, -100, 100, &mut rng);
        assert!(
            val >= -100 && val < 100,
            "mutate_i64 out of range: val={}, expected [-100, 100)",
            val
        );
    }
}

#[test]
fn test_mutate_i64_hits_boundaries() {
    let mut rng = make_rng(721);
    let mut val = 0i64;
    let mut seen = HashSet::new();

    for _ in 0..10_000 {
        mutate_i64(&mut val, -50, 50, &mut rng);
        seen.insert(val);
    }

    assert!(
        seen.contains(&-50),
        "mutate_i64 never hit lo boundary (-50)"
    );
    assert!(
        seen.contains(&49),
        "mutate_i64 never hit hi-1 boundary (49)"
    );
    assert!(seen.contains(&0), "mutate_i64 never hit 0");
    assert!(seen.contains(&-1), "mutate_i64 never hit -1");
    assert!(seen.contains(&1), "mutate_i64 never hit 1");
}

#[test]
fn test_mutate_i64_negative_only_range() {
    let mut rng = make_rng(722);
    let mut val = -10i64;

    for _ in 0..5_000 {
        mutate_i64(&mut val, -100, -1, &mut rng);
        assert!(
            val >= -100 && val < -1,
            "mutate_i64 out of negative range: val={}, expected [-100, -1)",
            val
        );
    }
}

#[test]
fn test_gen_range_u64_distribution() {
    // Verify gen_range_u64 produces values spread across the range
    let mut rng = make_rng(730);
    let mut buckets = [0u32; 10];
    let n = 100_000;

    for _ in 0..n {
        let val = gen_range_u64(&mut rng, 0, 1000);
        let bucket = (val / 100) as usize;
        if bucket < 10 {
            buckets[bucket] += 1;
        }
    }

    // Each bucket should have roughly 10% ± margin
    let expected = n as f64 / 10.0;
    for (i, &count) in buckets.iter().enumerate() {
        let ratio = count as f64 / expected;
        assert!(
            ratio > 0.5 && ratio < 1.5,
            "gen_range_u64 bucket {} has {}/{} (ratio {}), expected ~uniform",
            i,
            count,
            n / 10,
            ratio
        );
    }
}

#[test]
fn test_gen_range_usize_boundaries() {
    let mut rng = make_rng(731);
    let mut seen_lo = false;
    let mut seen_hi_minus1 = false;

    for _ in 0..10_000 {
        let val = gen_range_usize(&mut rng, 5, 10);
        assert!(val >= 5 && val < 10);
        if val == 5 {
            seen_lo = true;
        }
        if val == 9 {
            seen_hi_minus1 = true;
        }
    }
    assert!(seen_lo, "gen_range_usize never produced lo=5");
    assert!(seen_hi_minus1, "gen_range_usize never produced hi-1=9");
}

#[test]
fn test_param_mutation_actually_changes_values() {
    // Verify that after N param mutations, the input is different from original
    let mut rng = make_rng(800);
    let input = build_8_action_input(&mut rng);
    let original_bytes = input.to_bytes();
    let mut changed_count = 0;

    for _ in 0..100 {
        let mut decoded = FuzzInput::<TestAction>::from_bytes(&original_bytes);
        if !decoded.actions.is_empty() {
            let idx = rand_below(&mut rng, decoded.actions.len());
            decoded.actions[idx].mutate(&mut rng);
        }
        let new_bytes = decoded.to_bytes();
        if new_bytes != original_bytes {
            changed_count += 1;
        }
    }

    // With 8 actions, most mutations should change something
    // (NoFields variants can't change, but we have mixed variants)
    assert!(
        changed_count > 60,
        "Only {}/100 param mutations changed the input",
        changed_count
    );
}


#[test]
fn test_field_byte_count_consistency() {
    // Verify field_byte_count matches actual serialized field size for each variant
    let mut rng = make_rng(820);

    for variant_idx in 0..6 {
        let action = TestAction::random_variant(variant_idx, &mut rng);
        let mut buf = Vec::new();
        action.serialize_fields(&mut buf);
        let expected_bytes = TestAction::field_byte_count(variant_idx);
        assert_eq!(
            buf.len(),
            expected_bytes,
            "field_byte_count({}) = {} but serialize_fields produced {} bytes",
            variant_idx,
            expected_bytes,
            buf.len()
        );
    }
}


#[test]
fn test_rand_below_zero_returns_zero() {
    let mut rng = make_rng(900);
    assert_eq!(rand_below(&mut rng, 0), 0);
}

#[test]
fn test_rand_below_distribution() {
    // Verify rand_below(n) produces all values in [0, n) with reasonable uniformity
    let mut rng = make_rng(901);
    let n = 7;
    let mut counts = vec![0u32; n];
    let iters = 70_000;

    for _ in 0..iters {
        let val = rand_below(&mut rng, n);
        assert!(val < n);
        counts[val] += 1;
    }

    let expected = iters as f64 / n as f64;
    for (i, &c) in counts.iter().enumerate() {
        let ratio = c as f64 / expected;
        assert!(
            ratio > 0.7 && ratio < 1.3,
            "rand_below({}) bucket {} has count {} (ratio {:.2}), expected ~{}",
            n,
            i,
            c,
            ratio,
            expected as u32
        );
    }
}

#[test]
fn test_fuzz_action_random_variant_coverage() {
    // Verify random() generates all 6 variant types
    let mut rng = make_rng(910);
    let mut variant_counts = [0u32; 6];

    for _ in 0..12_000 {
        let action = TestAction::random(&mut rng);
        variant_counts[action.variant_index()] += 1;
    }

    for (i, &count) in variant_counts.iter().enumerate() {
        assert!(
            count > 500,
            "Variant {} generated only {} times (expected ~2000)",
            i,
            count
        );
    }
}

#[test]
fn test_mutate_no_fields_is_noop() {
    let mut rng = make_rng(920);
    let mut action = TestAction::NoFields;
    action.mutate(&mut rng);
    assert_eq!(action, TestAction::NoFields);
}

#[test]
fn test_multi_field_mutation_mutates_multiple_fields() {
    // FourFields has 4 fields. With num_mutations = 1 + rand_below(min(4,3)),
    // we get 1-3 mutations per call. Over many calls, we should see all fields change.
    let mut rng = make_rng(930);
    let original = TestAction::FourFields {
        a: 500_000,
        b: 5,
        c: 1000,
        d: false,
    };
    let mut a_changed = false;
    let mut b_changed = false;
    let mut c_changed = false;
    let mut d_changed = false;

    for _ in 0..1000 {
        let mut action = original.clone();
        action.mutate(&mut rng);
        if let TestAction::FourFields { a, b, c, d } = action {
            if a != 500_000 {
                a_changed = true;
            }
            if b != 5 {
                b_changed = true;
            }
            if c != 1000 {
                c_changed = true;
            }
            if d != false {
                d_changed = true;
            }
        }
    }

    assert!(a_changed, "Field 'a' was never mutated in 1000 iterations");
    assert!(b_changed, "Field 'b' was never mutated in 1000 iterations");
    assert!(c_changed, "Field 'c' was never mutated in 1000 iterations");
    assert!(d_changed, "Field 'd' was never mutated in 1000 iterations");
}

// ============================================================================
// Vec field tests
// ============================================================================

#[test]
fn test_vec_field_roundtrip_empty() {
    let action = TestAction::VecField { items: vec![] };
    let input = FuzzInput::new(vec![action.clone()]);
    let bytes = input.to_bytes();
    let decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
    assert_eq!(decoded.actions.len(), 1);
    assert_eq!(decoded.actions[0], action);
}

#[test]
fn test_vec_field_roundtrip_partial() {
    let action = TestAction::VecField { items: vec![10, 500] };
    let input = FuzzInput::new(vec![action.clone()]);
    let bytes = input.to_bytes();
    let decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
    assert_eq!(decoded.actions[0], action);
}

#[test]
fn test_vec_field_roundtrip_full() {
    let action = TestAction::VecField { items: vec![1, 2, 3, 4] };
    let input = FuzzInput::new(vec![action.clone()]);
    let bytes = input.to_bytes();
    let decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
    assert_eq!(decoded.actions[0], action);
}

#[test]
fn test_vec_field_fixed_byte_size() {
    // All Vec variants should serialize to exactly 40 bytes regardless of length
    let mut rng = make_rng(1100);
    for _ in 0..100 {
        let action = TestAction::random_variant(5, &mut rng);
        let mut buf = Vec::new();
        action.serialize_fields(&mut buf);
        assert_eq!(buf.len(), 40, "VecField should always serialize to 40 bytes, got {}", buf.len());
    }
}

#[test]
fn test_vec_field_mutation_changes_values() {
    let mut rng = make_rng(1101);
    let mut changed = 0;
    for _ in 0..100 {
        let mut action = TestAction::VecField { items: vec![500, 500, 500] };
        action.mutate(&mut rng);
        if let TestAction::VecField { items } = &action {
            if items != &[500, 500, 500] {
                changed += 1;
            }
        }
    }
    assert!(changed > 50, "Only {}/100 Vec mutations changed values", changed);
}

#[test]
fn test_vec_field_elements_stay_in_range() {
    let mut rng = make_rng(1102);
    let mut action = TestAction::VecField { items: vec![500, 200] };
    for _ in 0..5000 {
        action.mutate(&mut rng);
        if let TestAction::VecField { items } = &action {
            assert!(items.len() <= 4, "Vec exceeded max_len: {}", items.len());
            for &v in items {
                assert!(v < 1000, "Vec element out of range: {}", v);
            }
        }
    }
}

// ============================================================================
// Small integer type tests (Fix 1: u8/u16/u32/i8/i16/i32 support)
// ============================================================================
// These test the exact serialization patterns that were broken before Fix 1.
// Before the fix, u8.to_le_bytes() produced 1 byte (not 8), and
// u64::from_le_bytes(...) returned u64 assigned to u8 (type mismatch).

#[test]
fn test_small_int_u8_roundtrip_boundary_values() {
    // u8 boundary values must survive serialize → deserialize
    for val in [0u8, 1, 127, 128, 254, 255] {
        let action = SmallIntTestAction::UnsignedSmall { a: val, b: 0, c: 0 };
        let input = FuzzInput::new(vec![action.clone()]);
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
        assert_eq!(decoded.actions.len(), 1);
        assert_eq!(decoded.actions[0], action,
            "u8 value {} did not roundtrip correctly", val);
    }
}

#[test]
fn test_small_int_u16_roundtrip_boundary_values() {
    for val in [0u16, 1, 255, 256, 32767, 32768, 65534, 65535] {
        let action = SmallIntTestAction::UnsignedSmall { a: 0, b: val, c: 0 };
        let input = FuzzInput::new(vec![action.clone()]);
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
        assert_eq!(decoded.actions[0], action,
            "u16 value {} did not roundtrip correctly", val);
    }
}

#[test]
fn test_small_int_u32_roundtrip_boundary_values() {
    for val in [0u32, 1, 255, 65535, u32::MAX / 2, u32::MAX - 1, u32::MAX] {
        let action = SmallIntTestAction::UnsignedSmall { a: 0, b: 0, c: val };
        let input = FuzzInput::new(vec![action.clone()]);
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
        assert_eq!(decoded.actions[0], action,
            "u32 value {} did not roundtrip correctly", val);
    }
}

#[test]
fn test_small_int_i8_roundtrip_boundary_values() {
    for val in [i8::MIN, -1, 0, 1, i8::MAX] {
        let action = SmallIntTestAction::SignedSmall { x: val, y: 0, z: 0 };
        let input = FuzzInput::new(vec![action.clone()]);
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
        assert_eq!(decoded.actions[0], action,
            "i8 value {} did not roundtrip correctly", val);
    }
}

#[test]
fn test_small_int_i16_roundtrip_boundary_values() {
    for val in [i16::MIN, -1, 0, 1, i16::MAX] {
        let action = SmallIntTestAction::SignedSmall { x: 0, y: val, z: 0 };
        let input = FuzzInput::new(vec![action.clone()]);
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
        assert_eq!(decoded.actions[0], action,
            "i16 value {} did not roundtrip correctly", val);
    }
}

#[test]
fn test_small_int_i32_roundtrip_boundary_values() {
    for val in [i32::MIN, -1, 0, 1, i32::MAX] {
        let action = SmallIntTestAction::SignedSmall { x: 0, y: 0, z: val };
        let input = FuzzInput::new(vec![action.clone()]);
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
        assert_eq!(decoded.actions[0], action,
            "i32 value {} did not roundtrip correctly", val);
    }
}

#[test]
fn test_small_int_serializes_to_8_bytes_per_field() {
    // This is the core of the bug: u8.to_le_bytes() produces 1 byte, not 8.
    // With the fix, each field must serialize to exactly 8 bytes.
    let action = SmallIntTestAction::UnsignedSmall { a: 42, b: 1000, c: 100_000 };
    let mut buf = Vec::new();
    action.serialize_fields(&mut buf);
    assert_eq!(buf.len(), 24, "3 fields * 8 bytes = 24, got {}", buf.len());

    // Verify byte layout: each value should be u64 LE
    assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 42);
    assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 1000);
    assert_eq!(u64::from_le_bytes(buf[16..24].try_into().unwrap()), 100_000);
}

#[test]
fn test_small_int_signed_serializes_to_8_bytes_per_field() {
    let action = SmallIntTestAction::SignedSmall { x: -1, y: -1000, z: -100_000 };
    let mut buf = Vec::new();
    action.serialize_fields(&mut buf);
    assert_eq!(buf.len(), 24, "3 signed fields * 8 bytes = 24, got {}", buf.len());

    // Signed values cast through u64: -1i8 as u64 = 0xFFFFFFFFFFFFFFFF
    let raw_x = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let raw_y = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let raw_z = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    // Casting back should recover the original values
    assert_eq!(raw_x as i8, -1);
    assert_eq!(raw_y as i16, -1000);
    assert_eq!(raw_z as i32, -100_000);
}

#[test]
fn test_small_int_u8_truncation_on_deserialize() {
    // If serialized bytes contain a value > 255, deserialization should truncate
    // to u8 (matching Rust's `as u8` semantics). This verifies the cast path.
    let mut bytes = vec![0u8; 4 + 2 + 24]; // header + variant + 3 fields
    bytes[0..4].copy_from_slice(&1u32.to_le_bytes()); // count = 1
    bytes[4..6].copy_from_slice(&0u16.to_le_bytes()); // variant = 0 (UnsignedSmall)
    // Field a: store 256 (should become 0 as u8)
    bytes[6..14].copy_from_slice(&256u64.to_le_bytes());
    // Field b: store 65537 (should become 1 as u16)
    bytes[14..22].copy_from_slice(&65537u64.to_le_bytes());
    // Field c: store u32::MAX as u64
    bytes[22..30].copy_from_slice(&(u32::MAX as u64).to_le_bytes());

    let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
    assert_eq!(decoded.actions.len(), 1);
    if let SmallIntTestAction::UnsignedSmall { a, b, c } = decoded.actions[0] {
        assert_eq!(a, 0u8, "256 as u8 should be 0");
        assert_eq!(b, 1u16, "65537 as u16 should be 1");
        assert_eq!(c, u32::MAX, "u32::MAX as u32 should be u32::MAX");
    } else {
        panic!("wrong variant");
    }
}

#[test]
fn test_small_int_vec_u16_roundtrip() {
    // Vec<u16> with various lengths
    for items in [
        vec![],
        vec![0u16],
        vec![u16::MAX, 0, 1234],
        vec![100, 200, 300],  // max_len = 3
    ] {
        let action = SmallIntTestAction::VecU16 { items: items.clone() };
        let input = FuzzInput::new(vec![action.clone()]);
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
        assert_eq!(decoded.actions[0], action,
            "Vec<u16> {:?} did not roundtrip correctly", items);
    }
}

#[test]
fn test_small_int_vec_u16_fixed_byte_size() {
    // All Vec variants should serialize to exactly SMALL_VEC_BYTE_SIZE bytes
    let mut rng = make_rng(2000);
    for _ in 0..100 {
        let action = SmallIntTestAction::random_variant(2, &mut rng); // VecU16
        let mut buf = Vec::new();
        action.serialize_fields(&mut buf);
        assert_eq!(buf.len(), 32, "VecU16 should always serialize to 32 bytes, got {}", buf.len());
    }
}

#[test]
fn test_small_int_vec_u16_element_truncation() {
    // If serialized bytes contain a value > 65535, deserialization truncates to u16
    let mut bytes = vec![0u8; 4 + 2 + 32]; // header + variant + vec fields
    bytes[0..4].copy_from_slice(&1u32.to_le_bytes()); // count = 1
    bytes[4..6].copy_from_slice(&2u16.to_le_bytes()); // variant = 2 (VecU16)
    // len = 2
    bytes[6..14].copy_from_slice(&2u64.to_le_bytes());
    // Element 0: 70000 → should become 4464 as u16 (70000 % 65536)
    bytes[14..22].copy_from_slice(&70000u64.to_le_bytes());
    // Element 1: 65535 → u16::MAX
    bytes[22..30].copy_from_slice(&65535u64.to_le_bytes());
    // Element 2 (padding): 0
    bytes[30..38].copy_from_slice(&0u64.to_le_bytes());

    let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
    if let SmallIntTestAction::VecU16 { items } = &decoded.actions[0] {
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], 70000u64 as u16, "70000 as u16 truncation");
        assert_eq!(items[1], 65535u16);
    } else {
        panic!("wrong variant");
    }
}

#[test]
fn test_small_int_option_u8_roundtrip() {
    // Both Some and None must roundtrip
    for val in [None, Some(0u8), Some(1), Some(127), Some(255)] {
        let action = SmallIntTestAction::OptionU8 { val };
        let input = FuzzInput::new(vec![action.clone()]);
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
        assert_eq!(decoded.actions[0], action,
            "Option<u8> {:?} did not roundtrip correctly", val);
    }
}

#[test]
fn test_small_int_option_u8_none_sentinel() {
    // None is serialized as u64::MAX. When deserialized, u64::MAX should become None,
    // not Some(255) (which is u64::MAX as u8).
    let action = SmallIntTestAction::OptionU8 { val: None };
    let input = FuzzInput::new(vec![action]);
    let bytes = input.to_bytes();
    let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
    assert_eq!(decoded.actions[0], SmallIntTestAction::OptionU8 { val: None });

    // Also verify: Some(255) != None in serialized form
    let action_some = SmallIntTestAction::OptionU8 { val: Some(255) };
    let input_some = FuzzInput::new(vec![action_some]);
    let bytes_some = input_some.to_bytes();
    // Some(255) is serialized as u64 value 255, not u64::MAX
    let field_val = u64::from_le_bytes(bytes_some[6..14].try_into().unwrap());
    assert_eq!(field_val, 255, "Some(255) should serialize as 255, not u64::MAX");
    assert_ne!(field_val, u64::MAX);
}

#[test]
fn test_small_int_mixed_variant_roundtrip() {
    // Test the Mixed variant which combines u8 + i16 + Option<u32>
    let cases = [
        SmallIntTestAction::Mixed { small: 0, signed: 0, opt: None },
        SmallIntTestAction::Mixed { small: 255, signed: -1, opt: Some(0) },
        SmallIntTestAction::Mixed { small: 42, signed: i16::MIN, opt: Some(u32::MAX) },
        SmallIntTestAction::Mixed { small: 1, signed: i16::MAX, opt: None },
    ];
    for action in &cases {
        let input = FuzzInput::new(vec![action.clone()]);
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
        assert_eq!(&decoded.actions[0], action,
            "Mixed variant {:?} did not roundtrip correctly", action);
    }
}

#[test]
fn test_small_int_random_roundtrip_1000() {
    // Fuzz test: 1000 random SmallIntTestAction sequences must roundtrip
    let mut rng = make_rng(2001);
    for _ in 0..1000 {
        let count = 1 + (rng.next() as usize % 6);
        let actions: Vec<SmallIntTestAction> =
            (0..count).map(|_| SmallIntTestAction::random(&mut rng)).collect();
        let input = FuzzInput::new(actions.clone());
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
        assert_eq!(actions.len(), decoded.actions.len(),
            "Action count mismatch after roundtrip");
        for (a, b) in actions.iter().zip(decoded.actions.iter()) {
            assert_eq!(a, b, "Action mismatch after roundtrip");
        }
    }
}

#[test]
fn test_small_int_mutation_preserves_variant_types() {
    // Mutating a SmallIntTestAction should never change its variant
    let mut rng = make_rng(2002);
    for _ in 0..500 {
        let original_variant = rand_below(&mut rng, 5);
        let mut action = SmallIntTestAction::random_variant(original_variant, &mut rng);
        for _ in 0..10 {
            action.mutate(&mut rng);
            assert_eq!(action.variant_index(), original_variant,
                "Mutation changed variant from {} to {}", original_variant, action.variant_index());
        }
    }
}

#[test]
fn test_small_int_mutation_roundtrip_stability() {
    // After mutation, the result must still roundtrip correctly
    let mut rng = make_rng(2003);
    for _ in 0..500 {
        let mut action = SmallIntTestAction::random(&mut rng);
        action.mutate(&mut rng);
        let input = FuzzInput::new(vec![action.clone()]);
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
        assert_eq!(decoded.actions.len(), 1);
        assert_eq!(decoded.actions[0], action,
            "Mutated action did not roundtrip: {:?}", action);
    }
}

#[test]
fn test_small_int_mutation_actually_changes_values() {
    // Verify mutations produce different values (not no-ops)
    let mut rng = make_rng(2004);
    let mut changed = 0;
    for _ in 0..200 {
        let original = SmallIntTestAction::UnsignedSmall { a: 100, b: 30000, c: 1_000_000 };
        let mut action = original.clone();
        action.mutate(&mut rng);
        if action != original {
            changed += 1;
        }
    }
    assert!(changed > 150, "Only {}/200 mutations changed the UnsignedSmall value", changed);
}

#[test]
fn test_small_int_field_byte_count_matches_serialized_size() {
    // Verify field_byte_count matches actual serialized size for every variant
    let mut rng = make_rng(2005);
    for variant_idx in 0..5 {
        let action = SmallIntTestAction::random_variant(variant_idx, &mut rng);
        let mut buf = Vec::new();
        action.serialize_fields(&mut buf);
        let expected = SmallIntTestAction::field_byte_count(variant_idx);
        assert_eq!(buf.len(), expected,
            "field_byte_count({}) = {} but serialize_fields produced {} bytes",
            variant_idx, expected, buf.len());
    }
}

#[test]
fn test_small_int_multi_action_sequence_roundtrip() {
    // Mix of all SmallIntTestAction variants in a single sequence
    let actions = vec![
        SmallIntTestAction::UnsignedSmall { a: 255, b: 65535, c: u32::MAX },
        SmallIntTestAction::SignedSmall { x: i8::MIN, y: i16::MIN, z: i32::MIN },
        SmallIntTestAction::VecU16 { items: vec![1, 2, 3] },
        SmallIntTestAction::OptionU8 { val: None },
        SmallIntTestAction::OptionU8 { val: Some(42) },
        SmallIntTestAction::Mixed { small: 0, signed: -32768, opt: Some(0) },
    ];
    let input = FuzzInput::new(actions.clone());
    let bytes = input.to_bytes();
    let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(&bytes);
    assert_eq!(decoded.actions.len(), actions.len());
    for (i, (a, b)) in actions.iter().zip(decoded.actions.iter()).enumerate() {
        assert_eq!(a, b, "Action {} mismatch in multi-action sequence", i);
    }
}

// ============================================================================
// mutate_i64 overflow regression tests (signed range arithmetic)
// ============================================================================

#[test]
fn test_mutate_i64_full_range_no_overflow() {
    // Regression: mutate_i64(val, i64::MIN, i64::MAX, rng) panicked with
    // "attempt to subtract with overflow" because hi - lo overflows i64.
    // This is the exact range the macro generates for bare i64 fields.
    let mut rng = make_rng(800);
    let mut val = 0i64;

    for _ in 0..10_000 {
        mutate_i64(&mut val, i64::MIN, i64::MAX, &mut rng);
        assert!(
            val >= i64::MIN && val < i64::MAX,
            "mutate_i64 full range out of bounds: val={}",
            val
        );
    }
}

#[test]
fn test_mutate_i64_min_to_zero_no_overflow() {
    // hi - lo = 0 - i64::MIN overflows i64
    let mut rng = make_rng(801);
    let mut val = -1i64;

    for _ in 0..10_000 {
        mutate_i64(&mut val, i64::MIN, 0, &mut rng);
        assert!(
            val >= i64::MIN && val < 0,
            "mutate_i64 [MIN, 0) out of bounds: val={}",
            val
        );
    }
}

#[test]
fn test_mutate_i64_min_to_one_no_overflow() {
    // hi - lo = 1 - i64::MIN overflows i64
    let mut rng = make_rng(802);
    let mut val = 0i64;

    for _ in 0..10_000 {
        mutate_i64(&mut val, i64::MIN, 1, &mut rng);
        assert!(
            val >= i64::MIN && val < 1,
            "mutate_i64 [MIN, 1) out of bounds: val={}",
            val
        );
    }
}

#[test]
fn test_mutate_i64_extreme_val_delta_no_overflow() {
    // Regression: (*val + delta) overflowed before clamp when val near i64::MAX.
    // The arithmetic branch adds deltas like +1, +8 etc.
    let mut rng = make_rng(803);
    let mut val = i64::MAX - 1;

    for _ in 0..10_000 {
        mutate_i64(&mut val, i64::MIN, i64::MAX, &mut rng);
        assert!(
            val >= i64::MIN && val < i64::MAX,
            "mutate_i64 extreme delta out of bounds: val={}",
            val
        );
    }

    // Also test near i64::MIN
    val = i64::MIN + 1;
    for _ in 0..10_000 {
        mutate_i64(&mut val, i64::MIN, i64::MAX, &mut rng);
        assert!(
            val >= i64::MIN && val < i64::MAX,
            "mutate_i64 extreme delta (min) out of bounds: val={}",
            val
        );
    }
}

#[test]
fn test_mutate_i64_as_i8_range_no_overflow() {
    // Matches macro codegen: cast i8 to i64, mutate with i8 bounds, cast back
    let mut rng = make_rng(810);
    let mut val = 0i64;

    for _ in 0..10_000 {
        mutate_i64(&mut val, i8::MIN as i64, i8::MAX as i64 + 1, &mut rng);
        assert!(
            val >= i8::MIN as i64 && val <= i8::MAX as i64,
            "mutate_i64 as i8 out of bounds: val={}",
            val
        );
    }
}

#[test]
fn test_mutate_i64_as_i16_range_no_overflow() {
    let mut rng = make_rng(811);
    let mut val = 0i64;

    for _ in 0..10_000 {
        mutate_i64(&mut val, i16::MIN as i64, i16::MAX as i64 + 1, &mut rng);
        assert!(
            val >= i16::MIN as i64 && val <= i16::MAX as i64,
            "mutate_i64 as i16 out of bounds: val={}",
            val
        );
    }
}

#[test]
fn test_mutate_i64_as_i32_range_no_overflow() {
    let mut rng = make_rng(812);
    let mut val = 0i64;

    for _ in 0..10_000 {
        mutate_i64(&mut val, i32::MIN as i64, i32::MAX as i64 + 1, &mut rng);
        assert!(
            val >= i32::MIN as i64 && val <= i32::MAX as i64,
            "mutate_i64 as i32 out of bounds: val={}",
            val
        );
    }
}

#[test]
fn test_mutate_u64_as_u8_range() {
    // Matches macro codegen: cast u8 to u64, mutate with u8 bounds, cast back
    let mut rng = make_rng(820);
    let mut val = 0u64;

    for _ in 0..10_000 {
        mutate_u64(&mut val, 0, u8::MAX as u64 + 1, &mut rng);
        assert!(
            val <= u8::MAX as u64,
            "mutate_u64 as u8 out of bounds: val={}",
            val
        );
    }
}

#[test]
fn test_mutate_u64_as_u16_range() {
    let mut rng = make_rng(821);
    let mut val = 0u64;

    for _ in 0..10_000 {
        mutate_u64(&mut val, 0, u16::MAX as u64 + 1, &mut rng);
        assert!(
            val <= u16::MAX as u64,
            "mutate_u64 as u16 out of bounds: val={}",
            val
        );
    }
}

#[test]
fn test_mutate_u64_as_u32_range() {
    let mut rng = make_rng(822);
    let mut val = 0u64;

    for _ in 0..10_000 {
        mutate_u64(&mut val, 0, u32::MAX as u64 + 1, &mut rng);
        assert!(
            val <= u32::MAX as u64,
            "mutate_u64 as u32 out of bounds: val={}",
            val
        );
    }
}

#[test]
fn test_mutate_u64_full_range() {
    let mut rng = make_rng(823);
    let mut val = 0u64;

    for _ in 0..10_000 {
        mutate_u64(&mut val, 0, u64::MAX, &mut rng);
        assert!(val < u64::MAX, "mutate_u64 full range out of bounds: val={}", val);
    }
}

// ============================================================================
// Sequence mutator off-by-one tests (Fix 2)
// ============================================================================

#[test]
fn test_sequence_max_actions_2_allows_growth_from_1() {
    // Before Fix 2: `len >= max_actions - 1` with max_actions=2 meant `1 >= 1`
    // was true → only shrinking mutations for a 1-action input → could never grow.
    // After Fix 2: `len >= max_actions` → `1 >= 2` is false → growth mutations allowed.
    use libafl::inputs::BytesInput;
    use libafl::mutators::Mutator;
    use libafl::state::{NopState, HasRand};

    let mut state = NopState::<BytesInput>::new();
    let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(2);

    // Run mutations starting from 1 action until we see growth to 2
    let mut saw_growth = false;
    for _ in 0..200 {
        let action = TestAction::random(state.rand_mut());
        let fuzz_input = FuzzInput::new(vec![action]);
        let mut bytes_input = BytesInput::new(fuzz_input.to_bytes());

        let _ = mutator.mutate(&mut state, &mut bytes_input);
        let decoded = FuzzInput::<TestAction>::from_bytes(bytes_input.as_ref());
        if decoded.actions.len() == 2 {
            saw_growth = true;
            break;
        }
    }
    assert!(saw_growth, "With max_actions=2 and 1 action, growth should be possible");
}

#[test]
fn test_sequence_at_max_actions_no_growth() {
    // When len == max_actions, growth mutations (dup/insert/repeat) should be excluded
    use libafl::inputs::BytesInput;
    use libafl::mutators::Mutator;
    use libafl::state::{NopState, HasRand};

    let max_actions = 3;
    let mut state = NopState::<BytesInput>::new();
    let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(max_actions);

    // Run 500 mutations starting from exactly max_actions. None should exceed it.
    for _ in 0..500 {
        let actions: Vec<TestAction> = (0..max_actions).map(|_| TestAction::random(state.rand_mut())).collect();
        let fuzz_input = FuzzInput::new(actions);
        let mut bytes_input = BytesInput::new(fuzz_input.to_bytes());

        let _ = mutator.mutate(&mut state, &mut bytes_input);
        let decoded = FuzzInput::<TestAction>::from_bytes(bytes_input.as_ref());
        assert!(decoded.actions.len() <= max_actions,
            "Mutation grew beyond max_actions: {} > {}", decoded.actions.len(), max_actions);
    }
}

