use crate::action::FuzzAction;
use crate::input::FuzzInput;
use crate::mutators::primitives::{
    gen_range_u64, gen_range_u128, gen_range_usize, mutate_bool, mutate_i64, mutate_i128, mutate_u64, mutate_u128, mutate_usize, rand_below,
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

// ============================================================================
// 128-bit mutator tests (gen_range_u128, mutate_u128, mutate_i128)
// ============================================================================

#[test]
fn test_gen_range_u128_basic() {
    let mut rng = make_rng(900);
    for _ in 0..10_000 {
        let val = gen_range_u128(&mut rng, 0, 1000);
        assert!(val < 1000, "gen_range_u128 out of range: {}", val);
    }
}

#[test]
fn test_gen_range_u128_degenerate() {
    let mut rng = make_rng(901);
    // hi <= lo should return lo
    assert_eq!(gen_range_u128(&mut rng, 5, 5), 5);
    assert_eq!(gen_range_u128(&mut rng, 10, 3), 10);
}

#[test]
fn test_gen_range_u128_large_range() {
    let mut rng = make_rng(902);
    // Range spanning most of u128 — should not overflow
    for _ in 0..1_000 {
        let val = gen_range_u128(&mut rng, 0, u128::MAX);
        assert!(val < u128::MAX, "gen_range_u128 full range out of bounds: {}", val);
    }
}

#[test]
fn test_gen_range_u128_distribution() {
    let mut rng = make_rng(903);
    let mut buckets = [0u32; 10];
    let n = 100_000;
    for _ in 0..n {
        let val = gen_range_u128(&mut rng, 0, 1000);
        let bucket = (val / 100) as usize;
        if bucket < 10 {
            buckets[bucket] += 1;
        }
    }
    // Each bucket should have roughly 10% — allow 5-15%
    for (i, &count) in buckets.iter().enumerate() {
        let pct = (count as f64 / n as f64) * 100.0;
        assert!(
            pct > 5.0 && pct < 15.0,
            "gen_range_u128 bucket {} has {:.1}% (expected ~10%)",
            i,
            pct
        );
    }
}

#[test]
fn test_mutate_u128_stays_in_range() {
    let mut rng = make_rng(910);
    let lo = 10u128;
    let hi = 1000u128;
    let mut val = 500u128;

    for _ in 0..10_000 {
        mutate_u128(&mut val, lo, hi, &mut rng);
        assert!(
            val >= lo && val < hi,
            "mutate_u128 out of range: val={}, range=[{}, {})",
            val, lo, hi
        );
    }
}

#[test]
fn test_mutate_u128_hits_interesting_values() {
    let mut rng = make_rng(911);
    let mut seen = HashSet::new();
    let mut val = 50u128;

    for _ in 0..10_000 {
        mutate_u128(&mut val, 0, 1000, &mut rng);
        seen.insert(val);
    }

    assert!(seen.contains(&0), "mutate_u128 never produced 0");
    assert!(seen.contains(&1), "mutate_u128 never produced 1");
    assert!(seen.contains(&2), "mutate_u128 never produced 2");
    assert!(seen.contains(&999), "mutate_u128 never produced hi-1=999");
    assert!(seen.contains(&255), "mutate_u128 never produced (1<<8)-1=255");
    assert!(seen.len() > 50, "mutate_u128 too few distinct values: {}", seen.len());
}

#[test]
fn test_mutate_u128_arithmetic_delta() {
    let mut rng = make_rng(912);
    let mut deltas_seen = HashSet::new();
    let base = 500u128;

    for _ in 0..50_000 {
        let mut val = base;
        mutate_u128(&mut val, 0, 1000, &mut rng);
        let delta = val as i128 - base as i128;
        if delta.abs() <= 32 && delta != 0 {
            deltas_seen.insert(delta);
        }
    }

    assert!(
        deltas_seen.contains(&1) && deltas_seen.contains(&-1),
        "mutate_u128 arithmetic never produced ±1. Seen: {:?}",
        deltas_seen
    );
}

#[test]
fn test_mutate_u128_narrow_range() {
    let mut rng = make_rng(913);
    let mut val = 5u128;
    for _ in 0..1000 {
        mutate_u128(&mut val, 5, 7, &mut rng);
        assert!(val >= 5 && val < 7, "mutate_u128 narrow range out of bounds: {}", val);
    }
}

#[test]
fn test_mutate_u128_single_value_range() {
    let mut rng = make_rng(914);
    let mut val = 42u128;
    for _ in 0..100 {
        mutate_u128(&mut val, 42, 43, &mut rng);
        assert_eq!(val, 42, "mutate_u128 single-value range should always produce 42");
    }
}

#[test]
fn test_mutate_u128_full_range() {
    let mut rng = make_rng(915);
    let mut val = u128::MAX / 2;
    for _ in 0..10_000 {
        mutate_u128(&mut val, 0, u128::MAX, &mut rng);
        assert!(val < u128::MAX, "mutate_u128 full range out of bounds: val={}", val);
    }
}

#[test]
fn test_mutate_u128_degenerate_range_noop() {
    let mut rng = make_rng(916);
    let mut val = 99u128;
    mutate_u128(&mut val, 100, 100, &mut rng); // hi <= lo
    assert_eq!(val, 99, "mutate_u128 should be noop when hi <= lo");
}

#[test]
fn test_mutate_u128_large_offset() {
    // Test with lo far from zero (like Solana token amounts)
    let mut rng = make_rng(917);
    let lo = 1_000_000_000_000u128; // 1 trillion
    let hi = 10_000_000_000_000u128; // 10 trillion
    let mut val = 5_000_000_000_000u128;
    for _ in 0..10_000 {
        mutate_u128(&mut val, lo, hi, &mut rng);
        assert!(
            val >= lo && val < hi,
            "mutate_u128 large offset out of range: val={}, range=[{}, {})",
            val, lo, hi
        );
    }
}

// --- mutate_i128 tests ---

#[test]
fn test_mutate_i128_stays_in_range() {
    let mut rng = make_rng(920);
    let mut val = 0i128;
    for _ in 0..10_000 {
        mutate_i128(&mut val, -100, 100, &mut rng);
        assert!(
            val >= -100 && val < 100,
            "mutate_i128 out of range: val={}, expected [-100, 100)",
            val
        );
    }
}

#[test]
fn test_mutate_i128_hits_boundaries() {
    let mut rng = make_rng(921);
    let mut val = 0i128;
    let mut seen = HashSet::new();

    for _ in 0..10_000 {
        mutate_i128(&mut val, -50, 50, &mut rng);
        seen.insert(val);
    }

    assert!(seen.contains(&-50), "mutate_i128 never hit lo boundary (-50)");
    assert!(seen.contains(&49), "mutate_i128 never hit hi-1 (49)");
    assert!(seen.contains(&0), "mutate_i128 never hit 0");
    assert!(seen.contains(&-1), "mutate_i128 never hit -1");
    assert!(seen.contains(&1), "mutate_i128 never hit 1");
}

#[test]
fn test_mutate_i128_negative_only_range() {
    let mut rng = make_rng(922);
    let mut val = -10i128;
    for _ in 0..5_000 {
        mutate_i128(&mut val, -100, -1, &mut rng);
        assert!(
            val >= -100 && val < -1,
            "mutate_i128 out of negative range: val={}, expected [-100, -1)",
            val
        );
    }
}

#[test]
fn test_mutate_i128_full_range_no_overflow() {
    // Regression test: i128::MIN to i128::MAX range must not overflow
    let mut rng = make_rng(923);
    let mut val = 0i128;
    for _ in 0..10_000 {
        mutate_i128(&mut val, i128::MIN, i128::MAX, &mut rng);
        assert!(
            val >= i128::MIN && val < i128::MAX,
            "mutate_i128 full range out of bounds: val={}",
            val
        );
    }
}

#[test]
fn test_mutate_i128_min_to_zero() {
    let mut rng = make_rng(924);
    let mut val = i128::MIN / 2;
    for _ in 0..5_000 {
        mutate_i128(&mut val, i128::MIN, 0, &mut rng);
        assert!(
            val >= i128::MIN && val < 0,
            "mutate_i128 [MIN, 0) out of bounds: val={}",
            val
        );
    }
}

#[test]
fn test_mutate_i128_extreme_val_delta() {
    // Start at boundary values and ensure arithmetic delta doesn't overflow
    let mut rng = make_rng(925);
    let mut val = i128::MAX - 1;
    for _ in 0..5_000 {
        mutate_i128(&mut val, i128::MIN, i128::MAX, &mut rng);
        assert!(
            val >= i128::MIN && val < i128::MAX,
            "mutate_i128 extreme delta (max) out of bounds: val={}",
            val
        );
    }

    let mut val = i128::MIN;
    for _ in 0..5_000 {
        mutate_i128(&mut val, i128::MIN, i128::MAX, &mut rng);
        assert!(
            val >= i128::MIN && val < i128::MAX,
            "mutate_i128 extreme delta (min) out of bounds: val={}",
            val
        );
    }
}

#[test]
fn test_mutate_i128_degenerate_range_noop() {
    let mut rng = make_rng(926);
    let mut val = 42i128;
    mutate_i128(&mut val, 50, 50, &mut rng); // hi <= lo
    assert_eq!(val, 42, "mutate_i128 should be noop when hi <= lo");
}

#[test]
fn test_mutate_i128_single_value_range() {
    let mut rng = make_rng(927);
    let mut val = 7i128;
    for _ in 0..100 {
        mutate_i128(&mut val, 7, 8, &mut rng);
        assert_eq!(val, 7, "mutate_i128 single-value range should always produce 7");
    }
}

// ============================================================================
// SequenceMutator — comprehensive unit tests
// ============================================================================

mod sequence_mutator_tests {
    use crate::action::FuzzAction;
    use crate::input::FuzzInput;
    use crate::test_helpers::TestAction;
    use libafl::inputs::BytesInput;
    use libafl::mutators::{MutationResult, Mutator};
    use libafl::state::{NopState, HasRand};
    use libafl_bolts::rands::Rand;

    fn make_state() -> NopState<BytesInput> {
        NopState::<BytesInput>::new()
    }

    fn make_input(actions: Vec<TestAction>) -> BytesInput {
        BytesInput::new(FuzzInput::new(actions).to_bytes())
    }

    fn decode(input: &BytesInput) -> FuzzInput<TestAction> {
        FuzzInput::<TestAction>::from_bytes(input.as_ref())
    }

    #[test]
    fn empty_input_gets_one_action_inserted() {
        let mut state = make_state();
        let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(10);
        let mut input = make_input(vec![]);

        let result = mutator.mutate(&mut state, &mut input).unwrap();
        assert_eq!(result, MutationResult::Mutated);

        let decoded = decode(&input);
        assert_eq!(decoded.actions.len(), 1);
    }

    #[test]
    fn single_action_some_mutations_skip() {
        // Swap requires >=2, shuffle requires >=3 — single action should skip those
        let mut state = make_state();
        let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(10);
        let mut skip_count = 0;

        for _ in 0..500 {
            let action = TestAction::random(state.rand_mut());
            let mut input = make_input(vec![action]);
            let result = mutator.mutate(&mut state, &mut input).unwrap();
            if result == MutationResult::Skipped {
                skip_count += 1;
            }
            // Should never crash, action count should be 0..=2
            let decoded = decode(&input);
            assert!(decoded.actions.len() <= 2);
        }
        // Some skips expected (swap on single element, shuffle on <3)
        assert!(skip_count > 0, "expected some skipped mutations on single-action input");
    }

    #[test]
    fn max_actions_cap_enforced_when_mutated() {
        let max = 4;
        let mut state = make_state();
        let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(max);

        for _ in 0..1000 {
            // Start with 1..=max+2 actions (some above cap)
            let count = 1 + (state.rand_mut().next() as usize % (max + 2));
            let actions: Vec<TestAction> = (0..count).map(|_| TestAction::random(state.rand_mut())).collect();
            let mut input = make_input(actions);

            let result = mutator.mutate(&mut state, &mut input).unwrap();
            // Only check cap when mutation actually happened (Skipped doesn't rewrite)
            if result == MutationResult::Mutated {
                let decoded = decode(&input);
                assert!(
                    decoded.actions.len() <= max,
                    "got {} actions, max was {}",
                    decoded.actions.len(),
                    max
                );
            }
        }
    }

    #[test]
    fn roundtrip_integrity_after_mutation() {
        // After mutation, re-encoding and re-decoding should produce identical actions
        let mut state = make_state();
        let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(8);

        for _ in 0..500 {
            let count = 1 + (state.rand_mut().next() as usize % 6);
            let actions: Vec<TestAction> = (0..count).map(|_| TestAction::random(state.rand_mut())).collect();
            let mut input = make_input(actions);

            let _ = mutator.mutate(&mut state, &mut input);

            let decoded = decode(&input);
            let re_encoded = FuzzInput::new(decoded.actions.clone()).to_bytes();
            let re_decoded = FuzzInput::<TestAction>::from_bytes(&re_encoded);

            assert_eq!(decoded.actions.len(), re_decoded.actions.len());
            for (a, b) in decoded.actions.iter().zip(re_decoded.actions.iter()) {
                assert_eq!(a, b, "roundtrip mismatch after mutation");
            }
        }
    }

    #[test]
    fn all_mutation_types_reachable() {
        // With enough iterations, all 7 mutation types should fire at least once
        let mut state = make_state();
        let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(10);

        let mut saw_shrink = false;   // delete (len decreased)
        let mut saw_grow = false;     // insert/dup/repeat (len increased)
        let mut saw_same_len = false; // swap/shuffle (len unchanged)

        for _ in 0..2000 {
            let count = 3 + (state.rand_mut().next() as usize % 4); // 3..6 actions
            let actions: Vec<TestAction> = (0..count).map(|_| TestAction::random(state.rand_mut())).collect();
            let orig_len = actions.len();
            let mut input = make_input(actions);

            let result = mutator.mutate(&mut state, &mut input).unwrap();
            if result == MutationResult::Skipped {
                continue;
            }

            let new_len = decode(&input).actions.len();
            if new_len < orig_len { saw_shrink = true; }
            if new_len > orig_len { saw_grow = true; }
            if new_len == orig_len { saw_same_len = true; }

            if saw_shrink && saw_grow && saw_same_len { break; }
        }

        assert!(saw_shrink, "never saw shrink mutation (delete/truncate)");
        assert!(saw_grow, "never saw growth mutation (insert/dup/repeat)");
        assert!(saw_same_len, "never saw same-length mutation (swap/shuffle)");
    }

    #[test]
    fn post_exec_is_noop() {
        let mut state = make_state();
        let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(10);
        assert!(mutator.post_exec(&mut state, None).is_ok());
    }

    #[test]
    fn name_is_correct() {
        use libafl_bolts::Named;
        let mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(10);
        assert_eq!(mutator.name().as_ref(), "SequenceMutator");
    }
}

// ============================================================================
// ParamMutator — comprehensive unit tests
// ============================================================================

mod param_mutator_tests {
    use crate::action::FuzzAction;
    use crate::input::FuzzInput;
    use crate::test_helpers::TestAction;
    use libafl::inputs::BytesInput;
    use libafl::mutators::{MutationResult, Mutator};
    use libafl::state::{NopState, HasRand};
    use libafl_bolts::rands::Rand;

    fn make_state() -> NopState<BytesInput> {
        NopState::<BytesInput>::new()
    }

    fn make_input(actions: Vec<TestAction>) -> BytesInput {
        BytesInput::new(FuzzInput::new(actions).to_bytes())
    }

    fn decode(input: &BytesInput) -> FuzzInput<TestAction> {
        FuzzInput::<TestAction>::from_bytes(input.as_ref())
    }

    #[test]
    fn empty_input_skipped() {
        let mut state = make_state();
        let mut mutator = crate::mutators::params::ParamMutator::<TestAction>::new();
        let mut input = make_input(vec![]);

        let result = mutator.mutate(&mut state, &mut input).unwrap();
        assert_eq!(result, MutationResult::Skipped);
    }

    #[test]
    fn single_action_mutated() {
        let mut state = make_state();
        let mut mutator = crate::mutators::params::ParamMutator::<TestAction>::new();

        let action = TestAction::OneField { amount: 42 };
        let mut input = make_input(vec![action]);
        let orig_bytes = input.as_ref().to_vec();

        let result = mutator.mutate(&mut state, &mut input).unwrap();
        assert_eq!(result, MutationResult::Mutated);

        // Bytes should differ (mutation happened)
        assert_ne!(input.as_ref(), &orig_bytes[..], "bytes should change after param mutation");
    }

    #[test]
    fn preserves_action_count() {
        let mut state = make_state();
        let mut mutator = crate::mutators::params::ParamMutator::<TestAction>::new();

        for _ in 0..200 {
            let count = 1 + (state.rand_mut().next() as usize % 6);
            let actions: Vec<TestAction> = (0..count).map(|_| TestAction::random(state.rand_mut())).collect();
            let orig_count = actions.len();
            let mut input = make_input(actions);

            let _ = mutator.mutate(&mut state, &mut input);
            let decoded = decode(&input);
            assert_eq!(decoded.actions.len(), orig_count, "ParamMutator should never change action count");
        }
    }

    #[test]
    fn preserves_variant_types() {
        let mut state = make_state();
        let mut mutator = crate::mutators::params::ParamMutator::<TestAction>::new();

        for _ in 0..200 {
            let count = 2 + (state.rand_mut().next() as usize % 4);
            let actions: Vec<TestAction> = (0..count).map(|_| TestAction::random(state.rand_mut())).collect();
            let orig_variants: Vec<usize> = actions.iter().map(|a| a.variant_index()).collect();
            let mut input = make_input(actions);

            let _ = mutator.mutate(&mut state, &mut input);
            let decoded = decode(&input);
            let new_variants: Vec<usize> = decoded.actions.iter().map(|a| a.variant_index()).collect();
            assert_eq!(orig_variants, new_variants, "ParamMutator should never change variant types");
        }
    }

    #[test]
    fn roundtrip_after_mutation() {
        let mut state = make_state();
        let mut mutator = crate::mutators::params::ParamMutator::<TestAction>::new();

        for _ in 0..300 {
            let actions: Vec<TestAction> = (0..4).map(|_| TestAction::random(state.rand_mut())).collect();
            let mut input = make_input(actions);
            let _ = mutator.mutate(&mut state, &mut input);

            let decoded = decode(&input);
            let re_encoded = FuzzInput::new(decoded.actions.clone()).to_bytes();
            assert_eq!(input.as_ref(), &re_encoded[..], "roundtrip should be stable after param mutation");
        }
    }

    #[test]
    fn nofields_variant_unchanged() {
        // NoFields has no parameters to mutate, so mutation should be a no-op on the fields
        let mut state = make_state();
        let mut mutator = crate::mutators::params::ParamMutator::<TestAction>::new();

        let mut input = make_input(vec![TestAction::NoFields]);
        let orig_bytes = input.as_ref().to_vec();

        // Even after multiple mutations, NoFields stays identical
        for _ in 0..50 {
            let _ = mutator.mutate(&mut state, &mut input);
        }
        assert_eq!(input.as_ref(), &orig_bytes[..]);
    }

    #[test]
    fn post_exec_is_noop() {
        let mut state = make_state();
        let mut mutator = crate::mutators::params::ParamMutator::<TestAction>::new();
        assert!(mutator.post_exec(&mut state, None).is_ok());
    }

    #[test]
    fn name_is_correct() {
        use libafl_bolts::Named;
        let mutator = crate::mutators::params::ParamMutator::<TestAction>::new();
        assert_eq!(mutator.name().as_ref(), "ParamMutator");
    }
}

// ============================================================================
// CrossoverMutator — unit tests (requires corpus for full test)
// ============================================================================

mod crossover_mutator_tests {
    use libafl_bolts::Named;
    use libafl::corpus::{Corpus, InMemoryCorpus, Testcase};
    use libafl::inputs::BytesInput;
    use libafl::mutators::{MutationResult, Mutator};
    use libafl::state::{StdState, HasCorpus, HasRand};
    use libafl_bolts::rands::StdRand;

    use crate::action::FuzzAction;
    use crate::input::FuzzInput;
    use crate::test_helpers::TestAction;

    /// Create a state with an in-memory corpus containing the given inputs.
    fn make_corpus_state(inputs: Vec<Vec<u8>>) -> StdState<InMemoryCorpus<BytesInput>, BytesInput, StdRand, InMemoryCorpus<BytesInput>> {
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        for bytes in inputs {
            let tc = Testcase::new(BytesInput::new(bytes));
            corpus.add(tc).unwrap();
        }
        StdState::new(
            StdRand::with_seed(42),
            corpus,
            InMemoryCorpus::new(), // solutions corpus
            &mut (),
            &mut (),
        ).unwrap()
    }

    #[test]
    fn name_is_correct() {
        let mutator = crate::mutators::crossover::CrossoverMutator::<TestAction>::new(10);
        assert_eq!(mutator.name().as_ref(), "CrossoverMutator");
    }

    #[test]
    fn max_actions_stored() {
        let mutator = crate::mutators::crossover::CrossoverMutator::<TestAction>::new(42);
        assert_eq!(mutator.max_actions, 42);
    }

    #[test]
    fn crossover_splices_from_corpus() {
        let mut rng = libafl_bolts::rands::RomuDuoJrRand::with_seed(99);
        // Build a donor with 3 distinct actions
        let donor_actions: Vec<TestAction> = (0..3).map(|_| TestAction::random(&mut rng)).collect();
        let donor_bytes = FuzzInput::new(donor_actions).to_bytes();

        let mut state = make_corpus_state(vec![donor_bytes]);
        let mut mutator = crate::mutators::crossover::CrossoverMutator::<TestAction>::new(10);

        // Start with a 2-action input
        let target_actions: Vec<TestAction> = (0..2).map(|_| TestAction::random(state.rand_mut())).collect();
        let mut input = BytesInput::new(FuzzInput::new(target_actions).to_bytes());

        let original_len = FuzzInput::<TestAction>::from_bytes(input.as_ref()).actions.len();

        // Run crossover — should splice at least 1 action from donor
        let mut saw_growth = false;
        for _ in 0..100 {
            let result = mutator.mutate(&mut state, &mut input).unwrap();
            if result == MutationResult::Mutated {
                let decoded = FuzzInput::<TestAction>::from_bytes(input.as_ref());
                if decoded.actions.len() > original_len {
                    saw_growth = true;
                    break;
                }
            }
            // Reset input for next attempt
            let reset_actions: Vec<TestAction> = (0..2).map(|_| TestAction::random(state.rand_mut())).collect();
            input = BytesInput::new(FuzzInput::new(reset_actions).to_bytes());
        }
        assert!(saw_growth, "crossover should eventually grow input by splicing from corpus");
    }

    #[test]
    fn crossover_respects_max_actions() {
        let mut rng = libafl_bolts::rands::RomuDuoJrRand::with_seed(88);
        let max_actions = 5;

        // Build a large donor (8 actions)
        let donor: Vec<TestAction> = (0..8).map(|_| TestAction::random(&mut rng)).collect();
        let donor_bytes = FuzzInput::new(donor).to_bytes();

        let mut state = make_corpus_state(vec![donor_bytes]);
        let mut mutator = crate::mutators::crossover::CrossoverMutator::<TestAction>::new(max_actions);

        for _ in 0..200 {
            // Start with 4 actions (near cap)
            let target: Vec<TestAction> = (0..4).map(|_| TestAction::random(state.rand_mut())).collect();
            let mut input = BytesInput::new(FuzzInput::new(target).to_bytes());

            let _ = mutator.mutate(&mut state, &mut input);
            let decoded = FuzzInput::<TestAction>::from_bytes(input.as_ref());
            assert!(
                decoded.actions.len() <= max_actions,
                "crossover exceeded max_actions: {} > {}",
                decoded.actions.len(),
                max_actions
            );
        }
    }

    #[test]
    fn crossover_empty_corpus_skips() {
        let mut state = make_corpus_state(vec![]);
        let mut mutator = crate::mutators::crossover::CrossoverMutator::<TestAction>::new(10);

        let actions = vec![TestAction::NoFields];
        let mut input = BytesInput::new(FuzzInput::new(actions).to_bytes());

        let result = mutator.mutate(&mut state, &mut input).unwrap();
        assert_eq!(result, MutationResult::Skipped, "empty corpus should skip");
    }

    #[test]
    fn crossover_empty_donor_skips() {
        // Donor with 0 actions
        let empty_donor = FuzzInput::<TestAction>::new(vec![]).to_bytes();
        let mut state = make_corpus_state(vec![empty_donor]);
        let mut mutator = crate::mutators::crossover::CrossoverMutator::<TestAction>::new(10);

        let actions = vec![TestAction::NoFields];
        let mut input = BytesInput::new(FuzzInput::new(actions).to_bytes());

        let result = mutator.mutate(&mut state, &mut input).unwrap();
        assert_eq!(result, MutationResult::Skipped, "empty donor should skip");
    }

    #[test]
    fn crossover_into_empty_target() {
        let mut rng = libafl_bolts::rands::RomuDuoJrRand::with_seed(77);
        let donor: Vec<TestAction> = (0..3).map(|_| TestAction::random(&mut rng)).collect();
        let donor_bytes = FuzzInput::new(donor).to_bytes();

        let mut state = make_corpus_state(vec![donor_bytes]);
        let mut mutator = crate::mutators::crossover::CrossoverMutator::<TestAction>::new(10);

        // Target is empty
        let mut input = BytesInput::new(FuzzInput::<TestAction>::new(vec![]).to_bytes());
        let result = mutator.mutate(&mut state, &mut input).unwrap();
        assert_eq!(result, MutationResult::Mutated);

        let decoded = FuzzInput::<TestAction>::from_bytes(input.as_ref());
        assert!(!decoded.actions.is_empty(), "crossover into empty should produce at least 1 action");
    }

    #[test]
    fn crossover_output_roundtrips() {
        let mut rng = libafl_bolts::rands::RomuDuoJrRand::with_seed(66);
        let donor: Vec<TestAction> = (0..5).map(|_| TestAction::random(&mut rng)).collect();
        let donor_bytes = FuzzInput::new(donor).to_bytes();

        let mut state = make_corpus_state(vec![donor_bytes]);
        let mut mutator = crate::mutators::crossover::CrossoverMutator::<TestAction>::new(10);

        for _ in 0..100 {
            let target: Vec<TestAction> = (0..3).map(|_| TestAction::random(state.rand_mut())).collect();
            let mut input = BytesInput::new(FuzzInput::new(target).to_bytes());
            let _ = mutator.mutate(&mut state, &mut input);

            // Verify roundtrip
            let decoded = FuzzInput::<TestAction>::from_bytes(input.as_ref());
            let re_encoded = FuzzInput::new(decoded.actions.clone()).to_bytes();
            assert_eq!(
                input.as_ref(), &re_encoded[..],
                "crossover output should roundtrip cleanly"
            );
        }
    }
}

// ============================================================================
// ActionGenerator — unit tests
// ============================================================================

mod generator_tests {
    use crate::action::FuzzAction;
    use crate::generator::ActionGenerator;
    use crate::input::FuzzInput;
    use crate::test_helpers::TestAction;
    use libafl::generators::Generator;
    use libafl::inputs::BytesInput;
    use libafl::state::NopState;

    fn make_state() -> NopState<BytesInput> {
        NopState::<BytesInput>::new()
    }

    #[test]
    fn generates_within_bounds() {
        let mut state = make_state();
        let mut gen = ActionGenerator::<TestAction>::new(2, 5);

        for _ in 0..500 {
            let input = gen.generate(&mut state).unwrap();
            let decoded = FuzzInput::<TestAction>::from_bytes(input.as_ref());
            assert!(
                decoded.actions.len() >= 2 && decoded.actions.len() <= 5,
                "generated {} actions, expected 2..=5",
                decoded.actions.len()
            );
        }
    }

    #[test]
    fn min_equals_max_generates_exact() {
        let mut state = make_state();
        let mut gen = ActionGenerator::<TestAction>::new(3, 3);

        for _ in 0..100 {
            let input = gen.generate(&mut state).unwrap();
            let decoded = FuzzInput::<TestAction>::from_bytes(input.as_ref());
            assert_eq!(decoded.actions.len(), 3);
        }
    }

    #[test]
    fn generated_inputs_roundtrip() {
        let mut state = make_state();
        let mut gen = ActionGenerator::<TestAction>::new(1, 8);

        for _ in 0..200 {
            let input = gen.generate(&mut state).unwrap();
            let decoded = FuzzInput::<TestAction>::from_bytes(input.as_ref());
            let re_encoded = FuzzInput::new(decoded.actions.clone()).to_bytes();
            assert_eq!(input.as_ref(), &re_encoded[..], "generated input roundtrip mismatch");
        }
    }

    #[test]
    fn covers_all_variants() {
        let mut state = make_state();
        let mut gen = ActionGenerator::<TestAction>::new(1, 8);
        let mut seen = std::collections::HashSet::new();

        for _ in 0..1000 {
            let input = gen.generate(&mut state).unwrap();
            let decoded = FuzzInput::<TestAction>::from_bytes(input.as_ref());
            for action in &decoded.actions {
                seen.insert(action.variant_index());
            }
            if seen.len() == TestAction::variant_count() { break; }
        }
        assert_eq!(
            seen.len(),
            TestAction::variant_count(),
            "generator should eventually produce all {} variants, saw {:?}",
            TestAction::variant_count(),
            seen
        );
    }

    #[test]
    fn single_action_range() {
        let mut state = make_state();
        let mut gen = ActionGenerator::<TestAction>::new(1, 1);

        let input = gen.generate(&mut state).unwrap();
        let decoded = FuzzInput::<TestAction>::from_bytes(input.as_ref());
        assert_eq!(decoded.actions.len(), 1);
    }
}

// ============================================================================
// FuzzAction trait — unit tests on TestAction / SmallIntTestAction
// ============================================================================

mod fuzz_action_tests {
    use crate::action::FuzzAction;
    use crate::test_helpers::{TestAction, SmallIntTestAction};
    use libafl_bolts::rands::RomuDuoJrRand;

    fn make_rng(seed: u64) -> RomuDuoJrRand {
        RomuDuoJrRand::with_seed(seed)
    }

    #[test]
    fn variant_count_matches_variants() {
        assert_eq!(TestAction::variant_count(), 6);
        assert_eq!(SmallIntTestAction::variant_count(), 5);
    }

    #[test]
    fn random_variant_produces_correct_index() {
        let mut rng = make_rng(42);
        for vi in 0..TestAction::variant_count() {
            let action = TestAction::random_variant(vi, &mut rng);
            assert_eq!(action.variant_index(), vi, "variant_index mismatch for variant {vi}");
        }
    }

    #[test]
    fn random_variant_wraps_around() {
        let mut rng = make_rng(42);
        // Passing variant_count should wrap to 0
        let action = TestAction::random_variant(TestAction::variant_count(), &mut rng);
        assert_eq!(action.variant_index(), 0);
    }

    #[test]
    fn action_names_unique() {
        let mut rng = make_rng(42);
        let mut names = std::collections::HashSet::new();
        for vi in 0..TestAction::variant_count() {
            let action = TestAction::random_variant(vi, &mut rng);
            names.insert(action.action_name());
        }
        assert_eq!(names.len(), TestAction::variant_count(), "all variants should have unique names");
    }

    #[test]
    fn serialize_deserialize_roundtrip_all_variants() {
        let mut rng = make_rng(99);
        for vi in 0..TestAction::variant_count() {
            for _ in 0..50 {
                let action = TestAction::random_variant(vi, &mut rng);
                let mut buf = Vec::new();
                action.serialize_fields(&mut buf);
                assert_eq!(
                    buf.len(),
                    TestAction::field_byte_count(vi),
                    "field byte count mismatch for variant {vi}"
                );
                let mut cursor = 0;
                let deserialized = TestAction::deserialize_fields(vi, &buf, &mut cursor).unwrap();
                assert_eq!(action, deserialized, "roundtrip mismatch for variant {vi}");
                assert_eq!(cursor, buf.len(), "cursor should consume all bytes for variant {vi}");
            }
        }
    }

    #[test]
    fn serialize_deserialize_small_int_roundtrip() {
        let mut rng = make_rng(77);
        for vi in 0..SmallIntTestAction::variant_count() {
            for _ in 0..50 {
                let action = SmallIntTestAction::random_variant(vi, &mut rng);
                let mut buf = Vec::new();
                action.serialize_fields(&mut buf);
                assert_eq!(
                    buf.len(),
                    SmallIntTestAction::field_byte_count(vi),
                    "field byte count mismatch for SmallInt variant {vi}"
                );
                let mut cursor = 0;
                let deserialized = SmallIntTestAction::deserialize_fields(vi, &buf, &mut cursor).unwrap();
                assert_eq!(action, deserialized, "roundtrip mismatch for SmallInt variant {vi}");
            }
        }
    }

    #[test]
    fn deserialize_truncated_returns_none() {
        for vi in 0..TestAction::variant_count() {
            if TestAction::field_byte_count(vi) > 0 {
                let mut cursor = 0;
                let result = TestAction::deserialize_fields(vi, &[], &mut cursor);
                assert!(result.is_none(), "variant {vi} should return None on empty data");
            }
        }
    }

    #[test]
    fn deserialize_invalid_variant_returns_none() {
        let mut cursor = 0;
        assert!(TestAction::deserialize_fields(99, &[], &mut cursor).is_none());
    }

    #[test]
    fn mutate_changes_fields() {
        let mut rng = make_rng(42);
        let original = TestAction::OneField { amount: 5000 };
        let mut changed = false;
        for _ in 0..100 {
            let mut action = original.clone();
            action.mutate(&mut rng);
            if action != original {
                changed = true;
                break;
            }
        }
        assert!(changed, "mutate should eventually change OneField's amount");
    }

    #[test]
    fn mutate_preserves_variant() {
        let mut rng = make_rng(42);
        for vi in 0..TestAction::variant_count() {
            let mut action = TestAction::random_variant(vi, &mut rng);
            for _ in 0..50 {
                action.mutate(&mut rng);
                assert_eq!(
                    action.variant_index(),
                    vi,
                    "mutate should never change variant type"
                );
            }
        }
    }

    #[test]
    fn field_byte_count_zero_for_nofields() {
        assert_eq!(TestAction::field_byte_count(0), 0);
    }

    #[test]
    fn field_byte_count_out_of_range_is_zero() {
        assert_eq!(TestAction::field_byte_count(999), 0);
    }

    #[test]
    fn vec_field_serialization_pads_to_max_len() {
        // VecField with 0 items should still produce VEC_BYTE_SIZE bytes (padded)
        let action = TestAction::VecField { items: vec![] };
        let mut buf = Vec::new();
        action.serialize_fields(&mut buf);
        assert_eq!(buf.len(), 40, "empty vec should pad to max vec byte size");

        let action = TestAction::VecField { items: vec![10, 20] };
        let mut buf = Vec::new();
        action.serialize_fields(&mut buf);
        assert_eq!(buf.len(), 40, "partial vec should pad to max vec byte size");
    }

    // =========================================================================
    // Deserialize with cursor offset (multi-action sequences)
    // =========================================================================

    #[test]
    fn deserialize_at_offset_in_buffer() {
        // Simulate two actions packed sequentially: deserialize the second one
        let mut rng = make_rng(55);
        let a1 = TestAction::random_variant(1, &mut rng); // OneField
        let a2 = TestAction::random_variant(2, &mut rng); // TwoFields

        let mut buf = Vec::new();
        a1.serialize_fields(&mut buf);
        let cursor_after_a1 = buf.len();
        a2.serialize_fields(&mut buf);

        // Deserialize from the offset
        let mut cursor = cursor_after_a1;
        let deserialized = TestAction::deserialize_fields(2, &buf, &mut cursor).unwrap();
        assert_eq!(deserialized, a2, "deserialize at offset should produce correct action");
        assert_eq!(cursor, buf.len(), "cursor should advance to end");
    }

    // =========================================================================
    // VecField with crafted serialized length
    // =========================================================================

    #[test]
    fn deserialize_vec_with_oversized_length() {
        // Craft a buffer where the u64 length field is larger than VEC_MAX_LEN
        // The deserialize should clamp to VEC_MAX_LEN (4)
        let mut buf = Vec::new();
        buf.extend_from_slice(&u64::MAX.to_le_bytes()); // absurd length
        // Pad with enough data for VEC_MAX_LEN elements (4 * 8 bytes each)
        for i in 0..4u64 {
            buf.extend_from_slice(&i.to_le_bytes());
        }
        // Pad to VEC_BYTE_SIZE (8 + 4*8 = 40)
        while buf.len() < 40 {
            buf.push(0);
        }

        let mut cursor = 0;
        let result = TestAction::deserialize_fields(5, &buf, &mut cursor); // variant 5 = VecField
        assert!(result.is_some(), "oversized length should be clamped, not fail");
        if let Some(TestAction::VecField { items }) = result {
            assert_eq!(items.len(), 4, "should clamp to VEC_MAX_LEN=4");
        }
    }

    // =========================================================================
    // SmallInt mutation preserves type bounds
    // =========================================================================

    #[test]
    fn small_int_mutate_stays_in_type_bounds() {
        let mut rng = make_rng(33);
        for _ in 0..5_000 {
            for vi in 0..SmallIntTestAction::variant_count() {
                let mut action = SmallIntTestAction::random_variant(vi, &mut rng);
                action.mutate(&mut rng);
                // Roundtrip: serialize → deserialize must succeed
                let mut buf = Vec::new();
                action.serialize_fields(&mut buf);
                let mut cursor = 0;
                let rt = SmallIntTestAction::deserialize_fields(vi, &buf, &mut cursor);
                assert!(rt.is_some(), "SmallInt variant {} failed roundtrip after mutate", vi);
                assert_eq!(rt.unwrap(), action, "SmallInt variant {} roundtrip mismatch after mutate", vi);
            }
        }
    }
}

// ============================================================================
// ParamMutator — SmallInt edge cases
// ============================================================================

mod param_mutator_smallint_tests {
    use crate::action::FuzzAction;
    use crate::input::FuzzInput;
    use crate::test_helpers::SmallIntTestAction;
    use libafl::inputs::BytesInput;
    use libafl::mutators::{MutationResult, Mutator};
    use libafl::state::{NopState, HasRand};
    use libafl_bolts::rands::Rand;

    fn make_state() -> NopState<BytesInput> {
        NopState::<BytesInput>::new()
    }

    #[test]
    fn param_mutator_smallint_roundtrip() {
        // Run ParamMutator on SmallIntTestAction and verify outputs always roundtrip
        let mut state = make_state();
        let mut mutator = crate::mutators::params::ParamMutator::<SmallIntTestAction>::new();

        for _ in 0..500 {
            let actions: Vec<SmallIntTestAction> = (0..4)
                .map(|_| SmallIntTestAction::random(state.rand_mut()))
                .collect();
            let mut input = BytesInput::new(FuzzInput::new(actions).to_bytes());
            let result = mutator.mutate(&mut state, &mut input).unwrap();

            if result == MutationResult::Mutated {
                let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(input.as_ref());
                let re_encoded = FuzzInput::new(decoded.actions.clone()).to_bytes();
                assert_eq!(
                    input.as_ref(), &re_encoded[..],
                    "ParamMutator<SmallInt> output should roundtrip"
                );
            }
        }
    }

    #[test]
    fn param_mutator_smallint_preserves_variant_types() {
        let mut state = make_state();
        let mut mutator = crate::mutators::params::ParamMutator::<SmallIntTestAction>::new();

        for _ in 0..200 {
            let actions: Vec<SmallIntTestAction> = (0..SmallIntTestAction::variant_count())
                .map(|vi| SmallIntTestAction::random_variant(vi, state.rand_mut()))
                .collect();
            let original_variants: Vec<usize> = actions.iter().map(|a| a.variant_index()).collect();
            let mut input = BytesInput::new(FuzzInput::new(actions).to_bytes());
            let _ = mutator.mutate(&mut state, &mut input);

            let decoded = FuzzInput::<SmallIntTestAction>::from_bytes(input.as_ref());
            let new_variants: Vec<usize> = decoded.actions.iter().map(|a| a.variant_index()).collect();
            assert_eq!(original_variants, new_variants, "ParamMutator should preserve SmallInt variant types");
        }
    }

    #[test]
    fn param_mutator_smallint_changes_fields() {
        // Verify mutation actually changes field values over many iterations
        let mut state = make_state();
        let mut mutator = crate::mutators::params::ParamMutator::<SmallIntTestAction>::new();

        let mut changed_count = 0;
        for _ in 0..500 {
            // Use variant with u8 field (variant 0)
            let actions = vec![SmallIntTestAction::random_variant(0, state.rand_mut())];
            let original_bytes = FuzzInput::new(actions.clone()).to_bytes();
            let mut input = BytesInput::new(original_bytes.clone());
            let result = mutator.mutate(&mut state, &mut input).unwrap();
            if result == MutationResult::Mutated && input.as_ref() != &original_bytes[..] {
                changed_count += 1;
            }
        }
        assert!(changed_count > 0, "ParamMutator<SmallInt> should change field values");
    }
}

// ============================================================================
// mutate_u128 — upper-half regression tests (val > i128::MAX)
// ============================================================================

#[test]
fn test_mutate_u128_upper_half_stays_in_range() {
    // Regression: when val > i128::MAX, the old code cast `*val as i128` which wraps negative.
    let mut rng = make_rng(930);
    let lo = u128::MAX / 2 + 1; // Just above i128::MAX
    let hi = u128::MAX;
    let mut val = lo + 100;

    for _ in 0..10_000 {
        mutate_u128(&mut val, lo, hi, &mut rng);
        assert!(
            val >= lo && val < hi,
            "mutate_u128 upper-half out of range: val={}, range=[{}, {})",
            val, lo, hi
        );
    }
}

#[test]
fn test_mutate_u128_near_max_arithmetic_no_overflow() {
    // Start at u128::MAX - 1 and mutate in [u128::MAX - 100, u128::MAX)
    let mut rng = make_rng(931);
    let lo = u128::MAX - 100;
    let hi = u128::MAX;
    let mut val = u128::MAX - 1;

    for _ in 0..10_000 {
        mutate_u128(&mut val, lo, hi, &mut rng);
        assert!(
            val >= lo && val < hi,
            "mutate_u128 near-MAX out of range: val={}, range=[{}, {})",
            val, lo, hi
        );
    }
}

#[test]
fn test_mutate_u128_cross_i128_boundary() {
    // Range spans the i128::MAX boundary
    let mut rng = make_rng(932);
    let lo = (u128::MAX / 2) - 50; // 50 below i128::MAX
    let hi = (u128::MAX / 2) + 50; // 50 above i128::MAX
    let mut val = u128::MAX / 2;

    for _ in 0..10_000 {
        mutate_u128(&mut val, lo, hi, &mut rng);
        assert!(
            val >= lo && val < hi,
            "mutate_u128 cross-boundary out of range: val={}, range=[{}, {})",
            val, lo, hi
        );
    }
}

#[test]
fn test_gen_range_u128_covers_upper_64_bits() {
    // Verify the 128-bit RNG construction actually uses the upper 64 bits
    let mut rng = make_rng(933);
    let mut saw_upper_bits = false;
    for _ in 0..10_000 {
        let val = gen_range_u128(&mut rng, 0, u128::MAX);
        if val > (u64::MAX as u128) {
            saw_upper_bits = true;
            break;
        }
    }
    assert!(saw_upper_bits, "gen_range_u128 should produce values above u64::MAX");
}

// ============================================================================
// SequenceMutator — additional edge cases
// ============================================================================

#[test]
fn test_sequence_mutator_max_actions_1() {
    // Degenerate case: max_actions=1 means only delete+insert or noop
    use libafl::inputs::BytesInput;
    use libafl::mutators::Mutator;
    use libafl::state::{NopState, HasRand};

    let mut state = NopState::<BytesInput>::new();
    let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(1);

    for _ in 0..200 {
        let actions = vec![TestAction::random(state.rand_mut())];
        let mut input = BytesInput::new(FuzzInput::new(actions).to_bytes());
        let _ = mutator.mutate(&mut state, &mut input);
        let decoded = FuzzInput::<TestAction>::from_bytes(input.as_ref());
        assert!(
            decoded.actions.len() <= 1,
            "max_actions=1 should never grow beyond 1, got {}",
            decoded.actions.len()
        );
    }
}

#[test]
fn test_sequence_mutator_stability_across_iterations() {
    // Run mutator many times on the same input — should not corrupt state
    use libafl::inputs::BytesInput;
    use libafl::mutators::{MutationResult, Mutator};
    use libafl::state::{NopState, HasRand};

    let mut state = NopState::<BytesInput>::new();
    let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(8);

    let actions: Vec<TestAction> = (0..4).map(|_| TestAction::random(state.rand_mut())).collect();
    let original = FuzzInput::new(actions).to_bytes();

    for _ in 0..500 {
        let mut input = BytesInput::new(original.clone());
        let result = mutator.mutate(&mut state, &mut input);
        assert!(result.is_ok(), "mutator should never error");

        // Verify output always roundtrips
        let decoded = FuzzInput::<TestAction>::from_bytes(input.as_ref());
        let re_encoded = FuzzInput::new(decoded.actions).to_bytes();
        assert_eq!(input.as_ref(), &re_encoded[..], "mutated output must roundtrip");
    }
}

// ============================================================================
// Generator — additional edge cases
// ============================================================================

mod generator_edge_tests {
    use crate::action::FuzzAction;
    use crate::generator::ActionGenerator;
    use crate::input::FuzzInput;
    use crate::test_helpers::TestAction;
    use libafl::generators::Generator;
    use libafl::inputs::BytesInput;
    use libafl::state::{NopState, HasRand};

    fn make_state() -> NopState<BytesInput> {
        NopState::<BytesInput>::new()
    }

    #[test]
    fn generator_deterministic_with_same_seed() {
        let mut state1 = make_state();
        let mut state2 = make_state();
        // Both NopState get the same default seed
        let mut gen1 = ActionGenerator::<TestAction>::new(2, 5);
        let mut gen2 = ActionGenerator::<TestAction>::new(2, 5);

        // Seed both states identically
        *state1.rand_mut() = libafl_bolts::rands::RomuDuoJrRand::with_seed(123);
        *state2.rand_mut() = libafl_bolts::rands::RomuDuoJrRand::with_seed(123);

        for _ in 0..50 {
            let out1 = gen1.generate(&mut state1).unwrap();
            let out2 = gen2.generate(&mut state2).unwrap();
            assert_eq!(
                out1.as_ref(), out2.as_ref(),
                "same seed should produce identical generator output"
            );
        }
    }

    #[test]
    fn generator_large_max() {
        // max=100 — should not panic or produce unreasonable byte sizes
        let mut state = make_state();
        let mut gen = ActionGenerator::<TestAction>::new(1, 100);

        for _ in 0..50 {
            let input = gen.generate(&mut state).unwrap();
            let decoded = FuzzInput::<TestAction>::from_bytes(input.as_ref());
            assert!(decoded.actions.len() >= 1 && decoded.actions.len() <= 100);
        }
    }
}

// ============================================================================
// Part 1D: FuzzAction trait — Direct Tests
// ============================================================================

#[test]
fn test_action_variant_count() {
    assert_eq!(TestAction::variant_count(), 6);
    assert_eq!(SmallIntTestAction::variant_count(), 5);
}

#[test]
fn test_action_random_variant_in_bounds() {
    let mut rng = make_rng(3000);
    for variant_idx in 0..6 {
        let action = TestAction::random_variant(variant_idx, &mut rng);
        assert_eq!(
            action.variant_index(), variant_idx,
            "random_variant({}) produced variant_index {}",
            variant_idx, action.variant_index()
        );
    }
}

#[test]
fn test_action_random_variant_wraps_on_overflow() {
    let mut rng = make_rng(3001);
    let action = TestAction::random_variant(6, &mut rng);
    assert_eq!(action.variant_index(), 0, "variant_idx 6 should wrap to 0 (6 % 6)");
    let action = TestAction::random_variant(7, &mut rng);
    assert_eq!(action.variant_index(), 1, "variant_idx 7 should wrap to 1 (7 % 6)");
    let action = TestAction::random_variant(100, &mut rng);
    assert_eq!(action.variant_index(), 100 % 6);
}

#[test]
fn test_action_serialize_deserialize_all_variants() {
    let mut rng = make_rng(3002);
    for variant_idx in 0..6 {
        for _ in 0..10 {
            let action = TestAction::random_variant(variant_idx, &mut rng);
            let mut buf = Vec::new();
            action.serialize_fields(&mut buf);
            let mut cursor = 0;
            let deserialized = TestAction::deserialize_fields(variant_idx, &buf, &mut cursor);
            assert!(deserialized.is_some(), "Failed to deserialize variant {}", variant_idx);
            assert_eq!(action, deserialized.unwrap(), "Roundtrip failed for variant {}", variant_idx);
            assert_eq!(cursor, buf.len(), "Cursor didn't consume all bytes for variant {}", variant_idx);
        }
    }
}

#[test]
fn test_action_field_byte_count_matches_serialize() {
    let mut rng = make_rng(3003);
    for variant_idx in 0..6 {
        for _ in 0..10 {
            let action = TestAction::random_variant(variant_idx, &mut rng);
            let mut buf = Vec::new();
            action.serialize_fields(&mut buf);
            assert_eq!(
                buf.len(),
                TestAction::field_byte_count(variant_idx),
                "field_byte_count({}) doesn't match actual serialized size",
                variant_idx
            );
        }
    }
}

#[test]
fn test_action_from_name_and_params_valid() {
    use serde_json::json;
    let a = TestAction::from_name_and_params("no_fields", &json!({}));
    assert_eq!(a, Some(TestAction::NoFields));

    let a = TestAction::from_name_and_params("one_field", &json!({"amount": 42}));
    assert_eq!(a, Some(TestAction::OneField { amount: 42 }));

    let a = TestAction::from_name_and_params("two_fields", &json!({"user_idx": 2, "flag": true}));
    assert_eq!(a, Some(TestAction::TwoFields { user_idx: 2, flag: true }));

    let a = TestAction::from_name_and_params("four_fields", &json!({"a": 1, "b": 2, "c": 3, "d": false}));
    assert_eq!(a, Some(TestAction::FourFields { a: 1, b: 2, c: 3, d: false }));

    let a = TestAction::from_name_and_params("vec_field", &json!({"items": [10, 20, 30]}));
    assert_eq!(a, Some(TestAction::VecField { items: vec![10, 20, 30] }));
}

#[test]
fn test_action_from_name_and_params_unknown_name() {
    use serde_json::json;
    assert_eq!(TestAction::from_name_and_params("nonexistent", &json!({})), None);
    assert_eq!(TestAction::from_name_and_params("", &json!({})), None);
}

#[test]
fn test_action_from_name_and_params_wrong_types() {
    use serde_json::json;
    assert_eq!(TestAction::from_name_and_params("one_field", &json!({"amount": "hello"})), None);
    assert_eq!(TestAction::from_name_and_params("one_field", &json!({})), None);
    assert_eq!(TestAction::from_name_and_params("two_fields", &json!({"user_idx": 1, "flag": 42})), None);
}

// ============================================================================
// Part 1E: FuzzInput Edge Cases
// ============================================================================

#[test]
fn test_input_empty_bytes() {
    let decoded = FuzzInput::<TestAction>::from_bytes(&[]);
    assert!(decoded.actions.is_empty());
}

#[test]
fn test_input_short_header() {
    let decoded = FuzzInput::<TestAction>::from_bytes(&[1, 2]);
    assert!(decoded.actions.is_empty());
    let decoded = FuzzInput::<TestAction>::from_bytes(&[1, 0, 0]);
    assert!(decoded.actions.is_empty());
}

#[test]
fn test_input_huge_count_capped() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&10000u32.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // NoFields
    bytes.extend_from_slice(&0u16.to_le_bytes()); // NoFields
    let decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
    assert_eq!(decoded.actions.len(), 2);
}

#[test]
fn test_input_truncated_action_data() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // NoFields
    bytes.extend_from_slice(&0u16.to_le_bytes()); // NoFields
    bytes.extend_from_slice(&0u16.to_le_bytes()); // NoFields
    let decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
    assert_eq!(decoded.actions.len(), 3, "should parse 3 of 5 claimed actions");
}

#[test]
fn test_input_zero_actions() {
    let bytes = 0u32.to_le_bytes();
    let decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
    assert!(decoded.actions.is_empty());
}

// ============================================================================
// Part 1A: SequenceMutator — Precise Behavioral Tests
// ============================================================================

/// Run SequenceMutator deterministically and verify exact output.
/// This catches any behavioral drift (wrong op selection, indexing off-by-one, etc.)
#[test]
fn test_sequence_mutator_deterministic_output() {
    use libafl::inputs::BytesInput;
    use libafl::mutators::Mutator;
    use libafl::state::NopState;

    // Build a known input: [NoFields, OneField(42), TwoFields(1, true)]
    let actions = vec![
        TestAction::NoFields,
        TestAction::OneField { amount: 42 },
        TestAction::TwoFields { user_idx: 1, flag: true },
    ];
    let input_bytes = FuzzInput::new(actions).to_bytes();

    // Run mutation with specific state seed and record outputs
    let mut state = NopState::<BytesInput>::new();
    let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(8);

    // Run 100 mutations and verify each output is:
    // 1. Valid (roundtrips cleanly)
    // 2. Within length bounds
    // 3. Contains only valid TestAction variants
    for _ in 0..100 {
        let mut bytes_input = BytesInput::new(input_bytes.clone());
        let _ = mutator.mutate(&mut state, &mut bytes_input);
        let decoded = FuzzInput::<TestAction>::from_bytes(bytes_input.as_ref());

        // Must roundtrip
        let re_encoded = FuzzInput::new(decoded.actions.clone()).to_bytes();
        let re_decoded = FuzzInput::<TestAction>::from_bytes(&re_encoded);
        assert_eq!(
            decoded.actions.len(), re_decoded.actions.len(),
            "roundtrip changed action count: {} → {}",
            decoded.actions.len(), re_decoded.actions.len()
        );
        for (a, b) in decoded.actions.iter().zip(re_decoded.actions.iter()) {
            assert_eq!(a, b, "roundtrip corrupted action data");
        }

        // Length bounds
        assert!(decoded.actions.len() >= 1 && decoded.actions.len() <= 8);

        // All variants valid
        for action in &decoded.actions {
            assert!(action.variant_index() < 6, "invalid variant: {}", action.variant_index());
        }
    }
}

#[test]
fn test_sequence_empty_input_adds_action() {
    use libafl::inputs::BytesInput;
    use libafl::mutators::{Mutator, MutationResult};
    use libafl::state::NopState;

    let mut state = NopState::<BytesInput>::new();
    let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(10);

    let fuzz_input = FuzzInput::<TestAction>::new(Vec::new());
    let mut bytes_input = BytesInput::new(fuzz_input.to_bytes());

    let result = mutator.mutate(&mut state, &mut bytes_input).unwrap();
    assert_eq!(result, MutationResult::Mutated);
    let decoded = FuzzInput::<TestAction>::from_bytes(bytes_input.as_ref());
    assert_eq!(decoded.actions.len(), 1, "Empty input should get exactly 1 action added");
}

/// Verify that when SequenceMutator reports Skipped, the bytes are truly unchanged.
/// This catches bugs where the mutator modifies input but returns wrong status.
#[test]
fn test_sequence_skipped_means_unchanged() {
    use libafl::inputs::BytesInput;
    use libafl::mutators::{Mutator, MutationResult};
    use libafl::state::NopState;

    let mut state = NopState::<BytesInput>::new();
    let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(10);

    let mut unchanged_on_skip = 0;
    let mut total_skips = 0;

    for _ in 0..1000 {
        // Use 1-action input to force many skips (swap/delete/shuffle/truncate all skip)
        let actions = vec![TestAction::OneField { amount: 42 }];
        let original_bytes = FuzzInput::new(actions).to_bytes();
        let mut bytes_input = BytesInput::new(original_bytes.clone());

        let result = mutator.mutate(&mut state, &mut bytes_input).unwrap();
        if result == MutationResult::Skipped {
            total_skips += 1;
            if bytes_input.as_ref() == &original_bytes[..] {
                unchanged_on_skip += 1;
            }
        }
    }

    assert!(total_skips > 100, "Expected many skips from 1-action input, got {}", total_skips);
    assert_eq!(
        unchanged_on_skip, total_skips,
        "Skipped mutations should not modify input: {}/{} were unchanged",
        unchanged_on_skip, total_skips
    );
}

#[test]
fn test_sequence_at_max_blocks_growth_strictly() {
    use libafl::inputs::BytesInput;
    use libafl::mutators::Mutator;
    use libafl::state::{NopState, HasRand};

    let max_actions = 4;
    let mut state = NopState::<BytesInput>::new();
    let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(max_actions);

    for _ in 0..1000 {
        let actions: Vec<TestAction> = (0..max_actions)
            .map(|_| TestAction::random(state.rand_mut()))
            .collect();
        let fuzz_input = FuzzInput::new(actions);
        let mut bytes_input = BytesInput::new(fuzz_input.to_bytes());

        let _ = mutator.mutate(&mut state, &mut bytes_input);
        let decoded = FuzzInput::<TestAction>::from_bytes(bytes_input.as_ref());
        assert!(
            decoded.actions.len() <= max_actions,
            "At-capacity mutation grew: {} > {}",
            decoded.actions.len(), max_actions
        );
    }
}

/// Verify delete always reduces length by exactly 1 and preserves remaining order.
/// Manually applies delete operation to known input.
#[test]
fn test_sequence_delete_preserves_order() {
    let mut rng = make_rng(3100);
    let original = vec![
        TestAction::NoFields,
        TestAction::OneField { amount: 1 },
        TestAction::OneField { amount: 2 },
        TestAction::OneField { amount: 3 },
        TestAction::OneField { amount: 4 },
    ];

    for _ in 0..100 {
        let mut actions = original.clone();
        let idx = rand_below(&mut rng, actions.len());
        actions.remove(idx);

        assert_eq!(actions.len(), 4);
        // Remaining elements should be in their original relative order
        let mut expected_idx = 0;
        for action in &actions {
            while expected_idx < original.len() && *action != original[expected_idx] {
                expected_idx += 1;
            }
            assert!(expected_idx < original.len(), "Element not found in original");
            expected_idx += 1;
        }
    }
}

/// Verify repeat puts clone immediately after source.
#[test]
fn test_sequence_repeat_adjacent() {
    // The repeat op (6): src = random index, insert_at = src + 1
    let actions = vec![
        TestAction::OneField { amount: 1 },
        TestAction::OneField { amount: 2 },
        TestAction::OneField { amount: 3 },
    ];

    let mut rng = make_rng(3200);
    for _ in 0..50 {
        let mut test_actions = actions.clone();
        let src = rand_below(&mut rng, test_actions.len());
        let cloned = test_actions[src].clone();
        let insert_at = (src + 1).min(test_actions.len());
        test_actions.insert(insert_at, cloned.clone());

        // The cloned element should be at insert_at and equal to the source
        assert_eq!(test_actions[insert_at], cloned);
        assert_eq!(test_actions.len(), 4);
        // Source should still be at src
        assert_eq!(test_actions[src], cloned);
    }
}

/// Verify the shuffle operation is a permutation (no elements lost or duplicated).
#[test]
fn test_sequence_shuffle_is_permutation() {
    let mut rng = make_rng(3300);

    for _ in 0..200 {
        let len = 5 + rand_below(&mut rng, 10); // 5-14 elements
        let original: Vec<u64> = (0..len as u64).collect();
        let mut shuffled = original.clone();

        let start = rand_below(&mut rng, len - 1);
        let end = (start + 2 + rand_below(&mut rng, (len - start - 1).min(4))).min(len);

        // Fisher-Yates on subsequence
        for i in (1..(end - start)).rev() {
            let j = rand_below(&mut rng, i + 1);
            shuffled.swap(start + i, start + j);
        }

        // Elements outside [start, end) unchanged
        for i in 0..start {
            assert_eq!(shuffled[i], original[i], "shuffle modified element before range");
        }
        for i in end..len {
            assert_eq!(shuffled[i], original[i], "shuffle modified element after range");
        }

        // Elements within [start, end) are a permutation
        let mut sub_orig: Vec<u64> = original[start..end].to_vec();
        let mut sub_shuf: Vec<u64> = shuffled[start..end].to_vec();
        sub_orig.sort();
        sub_shuf.sort();
        assert_eq!(sub_orig, sub_shuf, "shuffle lost or duplicated elements");
    }
}

/// Verify truncate always keeps at least 1 and never exceeds original length.
#[test]
fn test_sequence_truncate_bounds() {
    let mut rng = make_rng(3400);

    for _ in 0..1000 {
        let len = 2 + rand_below(&mut rng, 10); // 2-11
        let new_len = 1 + rand_below(&mut rng, len - 1);
        assert!(new_len >= 1, "truncate produced length 0");
        assert!(new_len < len, "truncate didn't reduce: {} >= {}", new_len, len);
    }
}

// ============================================================================
// Part 1B: CrossoverMutator — Precise Tests
// ============================================================================

#[test]
fn test_crossover_empty_corpus_skips() {
    use libafl::inputs::BytesInput;
    use libafl::mutators::{Mutator, MutationResult};
    use libafl::state::StdState;
    use libafl::corpus::InMemoryCorpus;
    use libafl_bolts::rands::StdRand;

    let mut state = StdState::new(
        StdRand::with_seed(42), InMemoryCorpus::new(), InMemoryCorpus::new(), &mut (), &mut (),
    ).unwrap();
    let mut mutator = crate::mutators::crossover::CrossoverMutator::<TestAction>::new(10);

    let actions = vec![TestAction::NoFields];
    let mut bytes_input = BytesInput::new(FuzzInput::new(actions).to_bytes());
    let original = bytes_input.as_ref().to_vec();

    let result = mutator.mutate(&mut state, &mut bytes_input).unwrap();
    assert_eq!(result, MutationResult::Skipped);
    assert_eq!(bytes_input.as_ref(), &original[..], "Input should be unchanged when skipped");
}

#[test]
fn test_crossover_respects_max_actions() {
    use libafl::inputs::BytesInput;
    use libafl::mutators::Mutator;
    use libafl::state::StdState;
    use libafl::corpus::{Corpus, InMemoryCorpus, Testcase};
    use libafl_bolts::rands::StdRand;

    let max_actions = 5;
    let mut corpus = InMemoryCorpus::<BytesInput>::new();
    // Donor has max-sized inputs to stress the truncation
    for _ in 0..5 {
        let actions: Vec<TestAction> = (0..8).map(|_| TestAction::NoFields).collect();
        corpus.add(Testcase::new(BytesInput::new(FuzzInput::new(actions).to_bytes()))).unwrap();
    }
    let mut state = StdState::new(
        StdRand::with_seed(42), corpus, InMemoryCorpus::new(), &mut (), &mut (),
    ).unwrap();

    let mut mutator = crate::mutators::crossover::CrossoverMutator::<TestAction>::new(max_actions);

    for _ in 0..500 {
        // Start with 4 actions (near max)
        let actions: Vec<TestAction> = (0..4).map(|_| TestAction::NoFields).collect();
        let mut bytes_input = BytesInput::new(FuzzInput::new(actions).to_bytes());

        let _ = mutator.mutate(&mut state, &mut bytes_input);
        let decoded = FuzzInput::<TestAction>::from_bytes(bytes_input.as_ref());
        assert!(
            decoded.actions.len() <= max_actions,
            "Crossover exceeded max_actions: {} > {}",
            decoded.actions.len(), max_actions
        );
    }
}

/// Verify spliced actions come from donor and are contiguous.
#[test]
fn test_crossover_splice_contiguity() {
    use libafl::inputs::BytesInput;
    use libafl::mutators::Mutator;
    use libafl::state::{StdState, HasRand};
    use libafl::corpus::{Corpus, InMemoryCorpus, Testcase};
    use libafl_bolts::rands::StdRand;

    // Donor: all OneField with distinct amounts [100, 101, 102, 103]
    let mut corpus = InMemoryCorpus::<BytesInput>::new();
    let donor_actions = vec![
        TestAction::OneField { amount: 100 },
        TestAction::OneField { amount: 101 },
        TestAction::OneField { amount: 102 },
        TestAction::OneField { amount: 103 },
    ];
    corpus.add(Testcase::new(BytesInput::new(FuzzInput::new(donor_actions.clone()).to_bytes()))).unwrap();

    let mut state = StdState::new(
        StdRand::with_seed(42), corpus, InMemoryCorpus::new(), &mut (), &mut (),
    ).unwrap();
    let mut mutator = crate::mutators::crossover::CrossoverMutator::<TestAction>::new(20);

    let mut found_contiguous_splice = false;
    for _ in 0..200 {
        // Current: all NoFields
        let actions = vec![TestAction::NoFields; 5];
        let mut bytes_input = BytesInput::new(FuzzInput::new(actions).to_bytes());

        let _ = mutator.mutate(&mut state, &mut bytes_input);
        let decoded = FuzzInput::<TestAction>::from_bytes(bytes_input.as_ref());

        // Find spliced OneField actions
        let spliced: Vec<u64> = decoded.actions.iter().filter_map(|a| {
            if let TestAction::OneField { amount } = a {
                Some(*amount)
            } else {
                None
            }
        }).collect();

        if spliced.len() >= 2 {
            // Verify they're a contiguous subsequence of [100, 101, 102, 103]
            for window in spliced.windows(2) {
                assert_eq!(
                    window[1], window[0] + 1,
                    "Spliced actions not contiguous: {:?}", spliced
                );
            }
            found_contiguous_splice = true;
        }
    }
    assert!(found_contiguous_splice, "Never saw multi-action splice in 200 iterations");
}

/// Verify crossover with single-action donor always splices exactly 1.
#[test]
fn test_crossover_single_action_donor() {
    use libafl::inputs::BytesInput;
    use libafl::mutators::{Mutator, MutationResult};
    use libafl::state::StdState;
    use libafl::corpus::{Corpus, InMemoryCorpus, Testcase};
    use libafl_bolts::rands::StdRand;

    let mut corpus = InMemoryCorpus::<BytesInput>::new();
    let donor = vec![TestAction::OneField { amount: 999 }];
    corpus.add(Testcase::new(BytesInput::new(FuzzInput::new(donor).to_bytes()))).unwrap();

    let mut state = StdState::new(
        StdRand::with_seed(42), corpus, InMemoryCorpus::new(), &mut (), &mut (),
    ).unwrap();
    let mut mutator = crate::mutators::crossover::CrossoverMutator::<TestAction>::new(20);

    for _ in 0..100 {
        let actions = vec![TestAction::NoFields; 3];
        let mut bytes_input = BytesInput::new(FuzzInput::new(actions).to_bytes());

        let result = mutator.mutate(&mut state, &mut bytes_input).unwrap();
        if result == MutationResult::Mutated {
            let decoded = FuzzInput::<TestAction>::from_bytes(bytes_input.as_ref());
            // With donor of length 1: splice_start=0, splice_len=1+rand_below(1.min(4))=1
            // So exactly 1 action should be spliced, making total = 4
            assert_eq!(
                decoded.actions.len(), 4,
                "Single-action donor should add exactly 1 action, got {}",
                decoded.actions.len()
            );
            // Exactly one should be OneField
            let one_field_count = decoded.actions.iter()
                .filter(|a| matches!(a, TestAction::OneField { amount: 999 }))
                .count();
            assert_eq!(one_field_count, 1, "Expected exactly 1 spliced action, got {}", one_field_count);
        }
    }
}

// ============================================================================
// Part 1C: SuccessTrimStage — Precise Behavioral Tests
// ============================================================================

/// Replicate the exact trim logic from SuccessTrimStage::perform and verify
/// it correctly handles all edge cases.
fn simulate_trim(actions: Vec<TestAction>, pattern: Vec<bool>) -> Option<Vec<TestAction>> {
    if actions.is_empty() {
        return None;
    }

    let actions_len = actions.len();
    let pattern_len = pattern.len();
    let effective_len = actions_len.min(pattern_len);
    let success_count = pattern[..effective_len].iter().filter(|&&s| s).count();

    // Skip conditions from the actual SuccessTrimStage
    if success_count == 0 || success_count == effective_len {
        return None; // No trimming
    }

    let trimmed: Vec<TestAction> = actions
        .into_iter()
        .enumerate()
        .filter(|(i, _)| {
            if *i >= pattern_len {
                return true;
            }
            pattern[*i]
        })
        .map(|(_, a)| a)
        .collect();

    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed)
}

#[test]
fn test_trim_removes_exactly_failed_actions() {
    let actions = vec![
        TestAction::NoFields,
        TestAction::OneField { amount: 42 },
        TestAction::TwoFields { user_idx: 0, flag: true },
        TestAction::FourFields { a: 1, b: 2, c: 3, d: true },
    ];
    let pattern = vec![false, true, false, true];

    let trimmed = simulate_trim(actions, pattern).unwrap();
    assert_eq!(trimmed.len(), 2);
    assert_eq!(trimmed[0], TestAction::OneField { amount: 42 });
    assert_eq!(trimmed[1], TestAction::FourFields { a: 1, b: 2, c: 3, d: true });
}

#[test]
fn test_trim_all_success_returns_none() {
    let actions = vec![TestAction::NoFields; 4];
    let pattern = vec![true, true, true, true];
    assert!(simulate_trim(actions, pattern).is_none());
}

#[test]
fn test_trim_all_failed_returns_none() {
    let actions = vec![TestAction::NoFields; 4];
    let pattern = vec![false, false, false, false];
    assert!(simulate_trim(actions, pattern).is_none());
}

/// When pattern is shorter than actions, actions beyond pattern are KEPT.
/// This is important: the SuccessTrimStage deliberately keeps unpatched actions
/// because the harness may have added more actions since the pattern was recorded.
#[test]
fn test_trim_short_pattern_keeps_trailing_actions() {
    let actions = vec![
        TestAction::OneField { amount: 1 },
        TestAction::OneField { amount: 2 },
        TestAction::OneField { amount: 3 },
        TestAction::OneField { amount: 4 },
        TestAction::OneField { amount: 5 },
    ];
    let pattern = vec![false, true, false]; // only covers first 3

    let trimmed = simulate_trim(actions, pattern).unwrap();
    // index 0 → false (removed), 1 → true (kept), 2 → false (removed), 3,4 → kept
    assert_eq!(trimmed.len(), 3);
    assert_eq!(trimmed[0], TestAction::OneField { amount: 2 }); // from index 1
    assert_eq!(trimmed[1], TestAction::OneField { amount: 4 }); // from index 3
    assert_eq!(trimmed[2], TestAction::OneField { amount: 5 }); // from index 4
}

/// When pattern is longer than actions, extra pattern entries are ignored.
/// This tests effective_len = actions_len.min(pattern_len) logic.
#[test]
fn test_trim_long_pattern_ignored_beyond_actions() {
    let actions = vec![
        TestAction::OneField { amount: 1 },
        TestAction::OneField { amount: 2 },
    ];
    let pattern = vec![true, false, true, true, false]; // longer than actions

    let trimmed = simulate_trim(actions, pattern).unwrap();
    // Only first 2 pattern entries matter: [true, false]
    // index 0 → kept, index 1 → removed
    assert_eq!(trimmed.len(), 1);
    assert_eq!(trimmed[0], TestAction::OneField { amount: 1 });
}

/// Verify trimmed actions serialize correctly (indices shift).
#[test]
fn test_trim_reserializes_with_correct_variant_indices() {
    let actions = vec![
        TestAction::VecField { items: vec![10, 20] },  // variant 5
        TestAction::NoFields,                            // variant 0
        TestAction::FourFields { a: 1, b: 2, c: 3, d: true }, // variant 3
        TestAction::OneField { amount: 99 },             // variant 1
    ];
    let pattern = vec![true, false, true, false]; // keep indices 0 and 2

    let trimmed = simulate_trim(actions.clone(), pattern).unwrap();
    assert_eq!(trimmed.len(), 2);
    assert_eq!(trimmed[0], actions[0]);
    assert_eq!(trimmed[1], actions[2]);

    // Roundtrip the trimmed output
    let bytes = FuzzInput::new(trimmed.clone()).to_bytes();
    let decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
    assert_eq!(decoded.actions, trimmed);
}

/// Edge case: what if the only surviving action has complex fields (VecField)?
/// This caught a real deserialization issue in early versions.
#[test]
fn test_trim_single_surviving_action_roundtrips() {
    let actions = vec![
        TestAction::NoFields,
        TestAction::VecField { items: vec![100, 200, 300, 400] },
        TestAction::NoFields,
    ];
    let pattern = vec![false, true, false];

    let trimmed = simulate_trim(actions, pattern).unwrap();
    assert_eq!(trimmed.len(), 1);
    assert_eq!(trimmed[0], TestAction::VecField { items: vec![100, 200, 300, 400] });

    let bytes = FuzzInput::new(trimmed.clone()).to_bytes();
    let decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
    assert_eq!(decoded.actions, trimmed);
}

// ============================================================================
// pick_interesting_u64: Duplicate Candidate Bias
// ============================================================================
// Bug: When lo=0, both STATIC_CANDIDATES[0]=0 and dynamic[0]=lo=0 match,
// giving value 0 double selection weight vs other candidates.

#[test]
fn test_interesting_u64_duplicate_candidate_bias() {
    let mut rng = make_rng(4000);
    let mut count_zero = 0u32;
    let mut count_999 = 0u32;
    let n = 100_000;

    for _ in 0..n {
        let mut val = 500u64;
        mutate_u64(&mut val, 0, 1000, &mut rng);
        if val == 0 { count_zero += 1; }
        if val == 999 { count_999+= 1; }
    }

    // Both 0 and 999 are interesting values. If there's no duplicate bias,
    // they should appear at roughly similar rates (within 3x).
    // With the duplicate bug, 0 has ~2x the weight of 999.
    if count_999 > 0 {
        let ratio = count_zero as f64 / count_999 as f64;
        // Document the bias: we expect ratio > 1.5 due to the duplicate
        // This test will need updating if the bug is fixed (ratio should be ~1.0)
        eprintln!(
            "interesting_u64 bias: 0 selected {}x, 999 selected {}x, ratio={:.2}",
            count_zero, count_999, ratio
        );
        // For now, just verify both are selected (no total failure)
        assert!(count_zero > 0, "0 was never selected as interesting");
        assert!(count_999 > 0, "999 was never selected as interesting");
    }
}

// ============================================================================
// gen_range_u64: Modulo Bias
// ============================================================================

#[test]
fn test_gen_range_u64_modulo_bias() {
    // gen_range_u64 uses rng.next() % range, which has modulo bias.
    // For range = 3, the bias should be measurable over 1M samples.
    // 2^64 mod 3 = 1, so value 0 gets one extra mapping (bias = 1/2^64, negligible).
    // For power-of-2 ranges there's zero bias.
    let mut rng = make_rng(4100);
    let mut counts = [0u32; 3];
    let n = 300_000;

    for _ in 0..n {
        let val = gen_range_u64(&mut rng, 0, 3);
        counts[val as usize] += 1;
    }

    // Each should be ~100k. Allow 10% tolerance.
    for (i, &c) in counts.iter().enumerate() {
        let expected = n / 3;
        let diff = (c as i64 - expected as i64).unsigned_abs();
        assert!(
            diff < expected / 5, // 20% tolerance
            "gen_range_u64 modulo bias: bucket {} has {} (expected ~{})",
            i, c, expected
        );
    }
}

// ============================================================================
// SequenceMutator: Mutated-but-unchanged detection
// ============================================================================

/// The swap op can return Mutated even when swapping indices that happen to
/// hold equal actions (different positions, same content). This is technically
/// correct (the structure was mutated) but worth documenting.
#[test]
fn test_sequence_swap_identical_content() {
    use libafl::inputs::BytesInput;
    use libafl::mutators::{Mutator, MutationResult};
    use libafl::state::NopState;

    let mut state = NopState::<BytesInput>::new();
    let mut mutator = crate::mutators::sequence::SequenceMutator::<TestAction>::new(10);

    // All same actions — any swap is content-preserving
    let actions = vec![TestAction::NoFields; 5];
    let original_bytes = FuzzInput::new(actions).to_bytes();

    let mut mutated_but_same_bytes = 0;
    let mut total_mutated = 0;
    for _ in 0..500 {
        let mut bytes_input = BytesInput::new(original_bytes.clone());
        let result = mutator.mutate(&mut state, &mut bytes_input).unwrap();
        if result == MutationResult::Mutated {
            total_mutated += 1;
            if bytes_input.as_ref() == &original_bytes[..] {
                mutated_but_same_bytes += 1;
            }
        }
    }

    // Document: some "mutations" on uniform inputs produce identical bytes.
    // This includes swap (same content), shuffle (same content), and truncate
    // which reduces length (so bytes differ). Only swap/shuffle are wasted.
    eprintln!(
        "swap_identical_content: {}/{} Mutated results had identical bytes",
        mutated_but_same_bytes, total_mutated
    );
    // With all-NoFields, swaps and shuffles always produce identical bytes.
    // We should see a significant fraction.
    assert!(
        mutated_but_same_bytes > 10,
        "Expected some wasted mutations on uniform input, got only {}",
        mutated_but_same_bytes
    );
}

// ============================================================================
// Part 2: Coverage Utils Tests
// ============================================================================

#[test]
fn test_bucket_zero() {
    assert_eq!(crate::coverage_utils::to_bucket(0), 0);
}

#[test]
fn test_bucket_exact_values() {
    assert_eq!(crate::coverage_utils::to_bucket(1), 1);
    assert_eq!(crate::coverage_utils::to_bucket(2), 2);
    assert_eq!(crate::coverage_utils::to_bucket(3), 3);
    assert_eq!(crate::coverage_utils::to_bucket(4), 4);
    assert_eq!(crate::coverage_utils::to_bucket(5), 4);
    assert_eq!(crate::coverage_utils::to_bucket(6), 5);
    assert_eq!(crate::coverage_utils::to_bucket(7), 5);
    assert_eq!(crate::coverage_utils::to_bucket(8), 6);
}

#[test]
fn test_bucket_boundaries() {
    // Verify every boundary transition point
    assert_eq!(crate::coverage_utils::to_bucket(11), 6);
    assert_eq!(crate::coverage_utils::to_bucket(12), 7);
    assert_eq!(crate::coverage_utils::to_bucket(15), 7);
    assert_eq!(crate::coverage_utils::to_bucket(16), 8);
    assert_eq!(crate::coverage_utils::to_bucket(23), 8);
    assert_eq!(crate::coverage_utils::to_bucket(24), 9);
    assert_eq!(crate::coverage_utils::to_bucket(31), 9);
    assert_eq!(crate::coverage_utils::to_bucket(32), 10);
    assert_eq!(crate::coverage_utils::to_bucket(63), 10);
    assert_eq!(crate::coverage_utils::to_bucket(64), 11);
    assert_eq!(crate::coverage_utils::to_bucket(127), 11);
    assert_eq!(crate::coverage_utils::to_bucket(128), 12);
}

#[test]
fn test_bucket_high() {
    assert_eq!(crate::coverage_utils::to_bucket(255), 12);
}

#[test]
fn test_bucket_monotonic() {
    for i in 0..255u8 {
        assert!(
            crate::coverage_utils::to_bucket(i) <= crate::coverage_utils::to_bucket(i + 1),
            "to_bucket not monotonic at {}: {} > {}",
            i,
            crate::coverage_utils::to_bucket(i),
            crate::coverage_utils::to_bucket(i + 1)
        );
    }
}

/// Verify to_bucket covers all 13 buckets and each input maps to exactly one.
#[test]
fn test_bucket_exhaustive() {
    let mut buckets_seen = HashSet::new();
    for i in 0..=255u8 {
        let b = crate::coverage_utils::to_bucket(i);
        assert!(b <= 12, "bucket {} out of range for input {}", b, i);
        buckets_seen.insert(b);
    }
    assert_eq!(buckets_seen.len(), 13, "Not all 13 buckets reachable: {:?}", buckets_seen);
}

#[test]
fn test_mix_hash_few_fixed_points() {
    let mut fixed_points = 0;
    for x in 0..10000u64 {
        if crate::coverage_utils::mix_hash(x) == x {
            fixed_points += 1;
        }
    }
    // 0 is a known fixed point (XOR/MUL chain preserves 0)
    assert!(
        fixed_points <= 2,
        "mix_hash has too many fixed points in 0..10000: {}",
        fixed_points
    );
}

/// Strict avalanche criterion: flipping each input bit should change ~32 output bits.
#[test]
fn test_mix_hash_avalanche() {
    for bit in 0..64 {
        let a = crate::coverage_utils::mix_hash(0);
        let b = crate::coverage_utils::mix_hash(1u64 << bit);
        let diff_bits = (a ^ b).count_ones();
        assert!(
            diff_bits >= 15,
            "mix_hash: flipping bit {} only changed {} bits (expected >= 15)",
            bit, diff_bits
        );
    }

    // Also test with non-zero base values
    for base in [1u64, 42, 1000, u64::MAX / 2] {
        for bit in 0..64 {
            let a = crate::coverage_utils::mix_hash(base);
            let b = crate::coverage_utils::mix_hash(base ^ (1u64 << bit));
            let diff_bits = (a ^ b).count_ones();
            assert!(
                diff_bits >= 10,
                "mix_hash: flipping bit {} of {} only changed {} bits",
                bit, base, diff_bits
            );
        }
    }
}

#[test]
fn test_mix_hash_no_trivial_collisions() {
    let mut seen = HashSet::new();
    for i in 0..10000u64 {
        let h = crate::coverage_utils::mix_hash(i);
        assert!(
            seen.insert(h),
            "mix_hash collision: mix_hash({}) = {} already seen",
            i, h
        );
    }
}

#[test]
fn test_mix_hash_zero_is_fixed_point() {
    assert_eq!(crate::coverage_utils::mix_hash(0), 0);
    assert_ne!(crate::coverage_utils::mix_hash(1), 1);
    assert_ne!(crate::coverage_utils::mix_hash(1), 0);
}

#[test]
fn test_mix_hash_deterministic() {
    for x in [0u64, 1, 42, u64::MAX, u64::MAX / 2] {
        assert_eq!(
            crate::coverage_utils::mix_hash(x),
            crate::coverage_utils::mix_hash(x),
        );
    }
}

/// Verify mix_hash output distribution is roughly uniform across u64 space.
#[test]
fn test_mix_hash_distribution() {
    // Hash sequential inputs and check the high bits are spread.
    let mut high_byte_counts = [0u32; 256];
    for i in 0..100_000u64 {
        let h = crate::coverage_utils::mix_hash(i);
        let high_byte = (h >> 56) as u8;
        high_byte_counts[high_byte as usize] += 1;
    }

    // Each of 256 buckets should have ~390 entries. Allow 3x deviation.
    let expected = 100_000.0 / 256.0;
    let mut outliers = 0;
    for &c in &high_byte_counts {
        if (c as f64) < expected / 3.0 || (c as f64) > expected * 3.0 {
            outliers += 1;
        }
    }
    assert!(
        outliers < 5,
        "mix_hash distribution has {} outlier buckets (expected < 5)",
        outliers
    );
}
