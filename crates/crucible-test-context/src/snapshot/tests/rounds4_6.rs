use super::super::*;
use super::helpers::*;
use crate::{FastHashMap, FastHashSet};
use anchor_lang::prelude::Clock;
use anchor_lang::solana_program::instruction::{Instruction, AccountMeta};
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

// ---- Round 4: StatePool adversarial edge cases ----

// =========================================================================
// 1. Weight formula with extreme pick_counts (u32::MAX / 2)
// =========================================================================

#[test]
fn test_weight_formula_extreme_pick_count_no_nan_inf() {
    let mut pool = StatePool::new(10, 20);

    add_test_state(&mut pool, 0x0001, 0, None, "initial", None);
    add_test_state(&mut pool, 0x0002, 1, Some(0), "child", Some(0));

    let half_max = u32::MAX / 2;
    pool.states[0].pick_count.store(half_max, Ordering::Relaxed);
    pool.states[1].pick_count.store(1_000_000, Ordering::Relaxed);

    for rv in [0u64, u64::MAX / 2, u64::MAX] {
        let result = pool.pick_weighted(rv);
        assert!(result.is_some(), "pick_weighted should return Some with extreme pick_count");
        let idx = result.unwrap();
        assert!(idx == 0 || idx == 1);
    }

    let rng_vals = vec![0u64, u64::MAX / 3, u64::MAX / 3 * 2, u64::MAX];
    let mut out = Vec::new();
    let count = pool.pick_weighted_batch(&rng_vals, &mut out);
    assert_eq!(count, 4);
    assert_eq!(out.len(), 4);
    for &(_, _, state_idx, _, _, _, _, _) in &out {
        assert!(state_idx < pool.len());
    }
}

// =========================================================================
// 2. All active states have max violations — still picks something
// =========================================================================

#[test]
fn test_all_states_max_violations_still_picks() {
    let mut pool = StatePool::new(10, 20);
    add_test_state(&mut pool, 0x0001, 0, None, "a", None);
    add_test_state(&mut pool, 0x0002, 1, None, "b", None);
    add_test_state(&mut pool, 0x0003, 2, None, "c", None);

    for i in 0..3 {
        pool.states[i].violation_count = u32::MAX;
    }

    let result = pool.pick_weighted(42);
    assert!(result.is_some(), "should pick even when all states have max violations");
    let idx = result.unwrap();
    assert!(idx < pool.len());

    let rng_vals = vec![0u64, u64::MAX / 2, u64::MAX];
    let mut out = Vec::new();
    let count = pool.pick_weighted_batch(&rng_vals, &mut out);
    assert_eq!(count, 3);
}

// =========================================================================
// 3. Fingerprint boundary values: 0, u64::MAX, all-ones in bottom 17 bits
// =========================================================================

#[test]
fn test_fingerprint_boundary_values() {
    let mut pool = StatePool::new(100, 20);

    let added0 = add_test_state(&mut pool, 0u64, 0, None, "zero", None);
    assert!(added0, "fingerprint 0 should be added");

    let added_max = add_test_state(&mut pool, u64::MAX, 1, None, "max", None);
    assert!(added_max, "u64::MAX fingerprint should be accepted");

    // Same bottom 17 bits as u64::MAX (0x1FFFF) — should collide
    let fp_collision = 0x0000_0000_0001_FFFFu64;
    let rejected = add_test_state(&mut pool, fp_collision, 2, None, "collision", None);
    assert!(!rejected, "same bottom-17-bit fingerprint should be rejected");

    assert_eq!(pool.len(), 2);
    assert_eq!(pool.active_count(), 2);

    assert_eq!(pool.get(0).unwrap().fingerprint, 0u64);
    assert_eq!(pool.get(1).unwrap().fingerprint, u64::MAX);
}

// =========================================================================
// 4. mark_crashed on same index twice — idempotent
// =========================================================================

#[test]
fn test_mark_crashed_twice_idempotent() {
    let mut pool = StatePool::new(10, 20);
    add_test_state(&mut pool, 0x0001, 0, None, "a", None);
    add_test_state(&mut pool, 0x0002, 1, None, "b", None);
    add_test_state(&mut pool, 0x0003, 2, None, "c", None);

    assert_eq!(pool.active_count(), 3);

    pool.mark_crashed(1);
    assert_eq!(pool.active_count(), 2);
    assert_eq!(pool.crashed_count(), 1);

    pool.mark_crashed(1);
    assert_eq!(pool.active_count(), 2);
    assert_eq!(pool.crashed_count(), 1);

    pool.mark_crashed(1);
    assert_eq!(pool.active_count(), 2);
    assert_eq!(pool.crashed_count(), 1);

    assert!(pool.get(1).is_some());
}

// =========================================================================
// 5. mark_crashed on non-existent index — must not panic
// =========================================================================

#[test]
fn test_mark_crashed_nonexistent_index_no_panic() {
    let mut pool = StatePool::new(10, 20);
    add_test_state(&mut pool, 0x0001, 0, None, "only", None);

    pool.mark_crashed(1);
    pool.mark_crashed(999);
    pool.mark_crashed(usize::MAX);

    assert_eq!(pool.len(), 1);
    assert_eq!(pool.active_count(), 1);
}

// =========================================================================
// 6. Pool where all states are crashed — pick returns None
// =========================================================================

#[test]
fn test_all_states_crashed_pick_returns_none() {
    let mut pool = StatePool::new(10, 20);
    add_test_state(&mut pool, 0x0001, 0, None, "a", None);
    add_test_state(&mut pool, 0x0002, 1, None, "b", None);
    add_test_state(&mut pool, 0x0003, 2, None, "c", None);

    pool.mark_crashed(0);
    pool.mark_crashed(1);
    pool.mark_crashed(2);

    assert_eq!(pool.active_count(), 0);
    assert_eq!(pool.len(), 3);

    assert!(pool.pick_random(0).is_none());
    assert!(pool.pick_random(u64::MAX).is_none());
    assert!(pool.pick_weighted(0).is_none());
    assert!(pool.pick_weighted(u64::MAX).is_none());

    let rng_vals = vec![0u64, 1, 2, 3];
    let mut out = Vec::new();
    let count = pool.pick_weighted_batch(&rng_vals, &mut out);
    assert_eq!(count, 0);
    assert!(out.is_empty());
}

// =========================================================================
// 7. try_add at exact capacity boundary
// =========================================================================

#[test]
fn test_try_add_at_exact_capacity_boundary() {
    let cap = 4usize;
    let mut pool = StatePool::new(cap, 20);

    for i in 0..cap {
        let fp = (i as u64) << 1;
        let added = add_test_state(&mut pool, fp, i as u32, None, "", None);
        assert!(added, "should add state {i}");
    }

    assert!(pool.is_full());
    assert_eq!(pool.len(), cap);

    let overflow_fp = ((cap as u64) << 1) + 0x8000;
    let added = add_test_state(&mut pool, overflow_fp, cap as u32, None, "", None);
    assert!(added, "should evict weakest and add when pool is at capacity");
    // states vec grows (evicted entry preserved for parent chains), active stays bounded
    assert_eq!(pool.active_count(), cap);
}

// =========================================================================
// 8. pick_random distribution uniformity with 5 states
// =========================================================================

#[test]
fn test_pick_random_uniform_distribution() {
    let n = 5usize;
    let mut pool = StatePool::new(100, 20);
    for i in 0..n {
        let fp = (i as u64) << 1;
        add_test_state(&mut pool, fp, i as u32, None, "", None);
    }

    let iters = 100_000u64;
    let mut counts = vec![0u64; n];
    for seed in 0..iters {
        let rv = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let idx = pool.pick_random(rv).unwrap();
        counts[idx] += 1;
    }

    let expected = iters / n as u64;
    let lo = expected * 80 / 100;
    let hi = expected * 120 / 100;
    for (i, &c) in counts.iter().enumerate() {
        assert!(
            c >= lo && c <= hi,
            "state {i} picked {c} times; expected in [{lo}, {hi}]"
        );
    }
}

// =========================================================================
// 9. pick_weighted with single state (fast path) — pick_count increments
// =========================================================================

#[test]
fn test_pick_weighted_single_state_fast_path_increments() {
    let mut pool = StatePool::new(10, 20);
    add_test_state(&mut pool, 0x0001, 0, None, "sole", None);

    assert_eq!(pool.get(0).unwrap().pick_count.load(Ordering::SeqCst), 0);

    for expected_count in 1..=5u32 {
        let idx = pool.pick_weighted(expected_count as u64 * 1_000_000).unwrap();
        assert_eq!(idx, 0);
        let pc = pool.get(0).unwrap().pick_count.load(Ordering::SeqCst);
        assert_eq!(pc, expected_count, "pick_count should be {expected_count} after {expected_count} picks");
    }
}

// =========================================================================
// 10. Batch pick where some states get crashed between consecutive batches
// =========================================================================

#[test]
fn test_batch_pick_with_mid_iteration_crashes() {
    let mut pool = StatePool::new(100, 20);
    for i in 0u64..5 {
        let fp = i << 1;
        add_test_state(&mut pool, fp, i as u32, None, "", None);
    }
    assert_eq!(pool.active_count(), 5);

    let rng1: Vec<u64> = (0..4u64).map(|i| (i as u128 * u64::MAX as u128 / 4) as u64).collect();
    let mut out1 = Vec::new();
    let c1 = pool.pick_weighted_batch(&rng1, &mut out1);
    assert_eq!(c1, 4);
    assert_eq!(out1.len(), 4);
    for &(_, _, idx, _, _, _, _, _) in &out1 {
        assert!(idx < pool.len());
    }

    pool.mark_crashed(0);
    pool.mark_crashed(2);
    assert_eq!(pool.active_count(), 3);

    let rng2: Vec<u64> = (0..6u64).map(|i| i.wrapping_mul(9999999999999989u64)).collect();
    let mut out2 = Vec::new();
    let c2 = pool.pick_weighted_batch(&rng2, &mut out2);
    assert_eq!(c2, 6);
    let crashed: std::collections::HashSet<usize> = [0, 2].into_iter().collect();
    for &(_, _, idx, _, _, _, _, _) in &out2 {
        assert!(
            idx < pool.len(),
            "returned idx {idx} out of bounds"
        );
        assert!(
            !crashed.contains(&idx),
            "picked crashed state {idx}; should only pick from {{1, 3, 4}}"
        );
    }
}

// =========================================================================
// 11. reconstruct_variant_sequence with root state (no parent)
// =========================================================================

#[test]
fn test_reconstruct_variant_sequence_root_only() {
    let mut pool = StatePool::new(10, 20);

    add_test_state(&mut pool, 0x0001, 0, None, "root", None);

    let variants = pool.reconstruct_variant_sequence(0);
    assert!(
        variants.is_empty(),
        "root state with no action_variant should produce empty sequence, got {:?}", variants
    );
}

#[test]
fn test_reconstruct_variant_sequence_root_with_variant() {
    let mut pool = StatePool::new(10, 20);
    add_test_state(&mut pool, 0x0001, 0, None, "bootstrap", Some(42));

    let variants = pool.reconstruct_variant_sequence(0);
    assert_eq!(variants, vec![42u16], "root with variant should appear in sequence");
}

// =========================================================================
// 12. reconstruct_action_descriptions with empty action_desc — skips empty
// =========================================================================

#[test]
fn test_reconstruct_action_descriptions_skips_empty() {
    let mut pool = StatePool::new(10, 20);

    add_test_state(&mut pool, 0x0001, 0, None, "",          None);
    add_test_state(&mut pool, 0x0002, 1, Some(0), "step_a", Some(0));
    add_test_state(&mut pool, 0x0003, 2, Some(1), "",        Some(1));
    add_test_state(&mut pool, 0x0004, 3, Some(2), "step_b", Some(2));

    let descs = pool.reconstruct_action_descriptions(3);
    assert_eq!(descs, vec!["step_a", "step_b"],
        "empty action_desc entries should be skipped, got {:?}", descs);
}

#[test]
fn test_reconstruct_action_descriptions_all_empty() {
    let mut pool = StatePool::new(10, 20);

    add_test_state(&mut pool, 0x0001, 0, None, "",       None);
    add_test_state(&mut pool, 0x0002, 1, Some(0), "", Some(0));

    let descs = pool.reconstruct_action_descriptions(1);
    assert!(descs.is_empty(), "all-empty chain should produce empty vec");
}

// =========================================================================
// 13. novel_children crediting: parent->child->grandchild
// =========================================================================

#[test]
fn test_novel_children_chain_crediting() {
    let mut pool = StatePool::new(100, 20);

    add_test_state(&mut pool, 0x0001, 0, None, "root", None);
    assert_eq!(pool.get(0).unwrap().novel_children, 0);

    add_test_state(&mut pool, 0x0002, 1, Some(0), "child1", Some(0));
    assert_eq!(pool.get(0).unwrap().novel_children, 1, "root should have 1 novel child");
    assert_eq!(pool.get(1).unwrap().novel_children, 0);

    add_test_state(&mut pool, 0x0003, 1, Some(0), "child2", Some(1));
    assert_eq!(pool.get(0).unwrap().novel_children, 2, "root should have 2 novel children");

    add_test_state(&mut pool, 0x0004, 2, Some(1), "grand", Some(0));
    assert_eq!(pool.get(1).unwrap().novel_children, 1, "child1 should have 1 novel grandchild");
    assert_eq!(pool.get(0).unwrap().novel_children, 2, "root count unchanged by grandchild");

    add_test_state(&mut pool, 0x0005, 3, Some(3), "great", Some(2));
    assert_eq!(pool.get(3).unwrap().novel_children, 1);
    assert_eq!(pool.get(1).unwrap().novel_children, 1);
    assert_eq!(pool.get(0).unwrap().novel_children, 2);
}

// =========================================================================
// 14. is_novel_crash with 0 and u64::MAX hash values
// =========================================================================

#[test]
fn test_is_novel_crash_boundary_hashes() {
    let mut pool = StatePool::new(10, 20);

    assert!(pool.is_novel_crash(0), "hash 0 should be novel first time");
    assert!(!pool.is_novel_crash(0), "hash 0 should be duplicate second time");

    assert!(pool.is_novel_crash(u64::MAX), "hash u64::MAX should be novel first time");
    assert!(!pool.is_novel_crash(u64::MAX), "hash u64::MAX should be duplicate second time");

    assert_eq!(pool.unique_crash_count(), 2);

    for _ in 0..100 {
        pool.is_novel_crash(0);
        pool.is_novel_crash(u64::MAX);
    }
    assert_eq!(pool.unique_crash_count(), 2);
}

// =========================================================================
// 15. ActionStatsMap with many state classes — independent tracking
// =========================================================================

#[test]
fn test_action_stats_map_many_classes_independent() {
    let variant_count = 4usize;
    let mut map = ActionStatsMap::new(variant_count);

    for _ in 0..100 {
        map.record(10, 0, true);
        map.record(10, 1, false);
        map.record(10, 2, false);
        map.record(10, 3, false);

        map.record(20, 0, false);
        map.record(20, 1, false);
        map.record(20, 2, false);
        map.record(20, 3, true);
    }

    let eps = 50u64;

    let mut class10_counts = [0u32; 4];
    for i in 0..200u64 {
        let rv = i.wrapping_mul(6364136223846793005);
        if let Some(v) = map.pick_variant(10, rv, eps) {
            class10_counts[v] += 1;
        }
    }
    let most_picked_10 = class10_counts.iter().enumerate().max_by_key(|&(_, c)| c).unwrap().0;
    assert_eq!(most_picked_10, 0,
        "class 10: variant 0 should dominate, got counts={:?}", class10_counts);

    let mut class20_counts = [0u32; 4];
    for i in 0..200u64 {
        let rv = i.wrapping_mul(6364136223846793005);
        if let Some(v) = map.pick_variant(20, rv, eps) {
            class20_counts[v] += 1;
        }
    }
    let most_picked_20 = class20_counts.iter().enumerate().max_by_key(|&(_, c)| c).unwrap().0;
    assert_eq!(most_picked_20, 3,
        "class 20: variant 3 should dominate, got counts={:?}", class20_counts);

    assert_ne!(most_picked_10, most_picked_20,
        "different classes must produce independent tracking");

    let unknown = map.pick_variant(99, 12345, eps);
    assert!(unknown.is_none(), "class with no recordings should return None");

    for class in [10u16, 20, 99] {
        let eps_result = map.pick_variant(class, u64::MAX, 5);
        assert!(eps_result.is_none(),
            "epsilon path must return None for class {class}");
    }
}

// =========================================================================
// Bonus: pick_weighted with pick_count near u32::MAX for a 2-state pool
// =========================================================================

#[test]
fn test_pick_weighted_exhausted_vs_fresh() {
    let mut pool = StatePool::new(10, 20);
    // State 0: exhausted, but has novelty_bits=30
    pool.try_add(
        0x0001u64,
        SvmSnapshot::empty(make_test_clock(0)),
        0, None,
        make_action_bytes(1, &[0x01]),
        "exhausted".to_string(),
        None, vec![], None, 30, 30, true, None,
    );
    add_test_state(&mut pool, 0x0002, 1, None, "fresh", None);

    // Heavily-picked state (10000 picks) — novelty decayed significantly
    pool.states[0].pick_count.store(10_000, Ordering::Relaxed);
    // Fresh state: never picked → gets 1e6 priority
    pool.states[1].pick_count.store(0, Ordering::Relaxed);
    pool.total_picks.store(10_000, Ordering::Relaxed);

    let rng_vals: Vec<u64> = (0..1_000u64)
        .map(|i| i.wrapping_mul(6364136223846793005))
        .collect();
    let mut batch = Vec::new();
    pool.pick_weighted_batch(&rng_vals, &mut batch);

    let mut counts = [0u32; 2];
    for &(_, _, state_idx, _, _, _, _, _) in &batch {
        counts[state_idx] += 1;
    }

    // Fresh (never-picked, weight=1e6) should heavily dominate exhausted
    // (picks=10000, novelty_bits=30: effective_bits=30/101≈0.3, weight≈1.05)
    assert!(
        counts[1] > counts[0] * 3,
        "fresh state should dominate: counts={:?}", counts
    );
}

// =========================================================================
// Bonus: try_add fingerprint zero (dedup_key=0) — can only be added once
// =========================================================================

#[test]
fn test_try_add_fingerprint_zero_dedup() {
    let mut pool = StatePool::new(100, 20);

    let first = pool.try_add(
        0u64,
        SvmSnapshot::empty(make_test_clock(0)),
        0, None,
        make_action_bytes(1, &[0x00]),
        "zero_fp".to_string(),
        None, vec![], None, 0, 0, true, None,
    );
    assert!(first, "fingerprint 0 should be accepted first time");

    let second = pool.try_add(
        0x2_0000u64, // bottom 17 bits = 0, same dedup key as fingerprint 0
        SvmSnapshot::empty(make_test_clock(1)),
        1, None,
        make_action_bytes(1, &[0x01]),
        "fp_collision".to_string(),
        Some(0), vec![], None, 0, 0, true, None,
    );
    assert!(!second, "same dedup_key=0 should be rejected");

    assert_eq!(pool.len(), 1);
}

// =========================================================================
// Bonus: reconstruct_variant_sequence produces oldest-first order
// =========================================================================

#[test]
fn test_reconstruct_variant_sequence_oldest_first() {
    let mut pool = StatePool::new(100, 20);

    add_test_state(&mut pool, 0x0001, 0, None,      "r",  None);
    add_test_state(&mut pool, 0x0002, 1, Some(0),   "a", Some(10));
    add_test_state(&mut pool, 0x0003, 2, Some(1),   "b", Some(20));
    add_test_state(&mut pool, 0x0004, 3, Some(2),   "c", Some(30));
    add_test_state(&mut pool, 0x0005, 4, Some(3),   "d", Some(40));

    let variants = pool.reconstruct_variant_sequence(4);
    assert_eq!(variants, vec![10u16, 20, 30, 40]);
}

// ---- Round 5: Multi-worker simulation patterns ----

// ---------------------------------------------------------------------------
// Test 1 — Two workers alternating restore_selective / restore_selective_from
// ---------------------------------------------------------------------------
#[test]
fn test_two_workers_alternating_restore_paths() {
    let pk_shared = Pubkey::new_unique();
    let pk_a_only = Pubkey::new_unique();
    let pk_b_only = Pubkey::new_unique();

    let mut tracked = HashSet::new();
    tracked.insert(pk_shared);

    let mut svm_a = LiteSVM::new();
    svm_a.set_account(pk_shared, make_account(100, &[1, 2, 3, 4])).unwrap();
    let initial = SvmSnapshot::take(&svm_a, &tracked);

    let delta_a = make_pool_snapshot(vec![(pk_shared, 200), (pk_a_only, 500)]);
    let delta_b = make_pool_snapshot(vec![(pk_shared, 300), (pk_b_only, 777)]);

    let mut divergent_a: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm_a, &divergent_a, &delta_a);
    divergent_a.clear();
    divergent_a.extend(delta_a.accounts().keys().copied());

    assert_eq!(svm_a.get_account(&pk_shared).unwrap().lamports, 200,
        "selective restore should apply delta_a pk_shared=200");

    let mut prev_exec_dirty_a: FastHashSet<Pubkey> = FastHashSet::default();
    prev_exec_dirty_a.insert(pk_shared);
    divergent_a.extend(prev_exec_dirty_a.iter().copied());

    let prev_delta_a = Arc::new(delta_a.clone());
    initial.restore_selective_from(
        &mut svm_a,
        &divergent_a,
        &prev_delta_a,
        &delta_b,
        &prev_exec_dirty_a,
    );

    assert_eq!(svm_a.get_account(&pk_shared).unwrap().lamports, 300,
        "selective_from should apply delta_b pk_shared=300");

    let mut svm_b = LiteSVM::new();
    svm_b.set_account(pk_shared, make_account(100, &[1, 2, 3, 4])).unwrap();
    let divergent_b: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm_b, &divergent_b, &delta_b);

    assert_eq!(svm_b.get_account(&pk_shared).unwrap().lamports, 300,
        "worker B restore_selective gives delta_b state");

    assert_eq!(
        svm_a.get_account(&pk_shared).unwrap().lamports,
        svm_b.get_account(&pk_shared).unwrap().lamports,
        "both workers must produce identical pk_shared state"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — Worker picks delta A, creates CPI account, takes child delta,
//           then switches to delta B — CPI account must be cleaned up
// ---------------------------------------------------------------------------
#[test]
fn test_worker_cpi_account_cleanup_on_state_switch() {
    let pk_base = Pubkey::new_unique();
    let pk_cpi  = Pubkey::new_unique();

    let initial = make_pool_snapshot(vec![(pk_base, 1000)]);
    let delta_a = make_pool_snapshot(vec![(pk_base, 1100)]);
    let delta_b = make_pool_snapshot(vec![(pk_base, 900)]);

    let mut svm = LiteSVM::new();
    let divergent: FastHashSet<Pubkey> = FastHashSet::default();

    initial.restore_selective(&mut svm, &divergent, &delta_a);

    svm.set_account(pk_cpi, make_account(50, &[9])).unwrap();
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_cpi);
    dirty.mark_account_dirty(&pk_base);

    let child_delta = SvmSnapshot::take_delta(&svm, &delta_a, &dirty);
    assert!(child_delta.accounts().contains_key(&pk_cpi),
        "child delta must include CPI account");
    assert_eq!(child_delta.accounts()[&pk_cpi].lamports, 50);

    let mut divergent2: FastHashSet<Pubkey> = FastHashSet::default();
    divergent2.extend(delta_a.accounts().keys().copied());
    let prev_exec_dirty = dirty.dirty_accounts().clone();
    divergent2.extend(prev_exec_dirty.iter().copied());

    let prev_delta_arc = Arc::new(child_delta);
    initial.restore_selective_from(
        &mut svm,
        &divergent2,
        &prev_delta_arc,
        &delta_b,
        &prev_exec_dirty,
    );

    let cpi_lamps = svm.get_account(&pk_cpi).map(|a| a.lamports).unwrap_or(0);
    assert_eq!(cpi_lamps, 0,
        "CPI account must be zeroed when switching to delta_b that lacks it");

    assert_eq!(svm.get_account(&pk_base).unwrap().lamports, 900,
        "pk_base must reflect delta_b=900 after switch");
}

// ---------------------------------------------------------------------------
// Test 3 — Simulated batched flush: create 5 novel states locally, add all at once
// ---------------------------------------------------------------------------
#[test]
fn test_batched_flush_five_novel_states() {
    let mut pool = StatePool::new(100, 10);
    let clock = make_test_clock(1);

    let added = pool.try_add(
        1u64,
        SvmSnapshot::empty(clock.clone()),
        0, None,
        0u32.to_le_bytes().to_vec(),
        String::new(), None, vec![], None, 0, 0, true, None,
    );
    assert!(added, "initial state must be added");
    assert_eq!(pool.len(), 1);

    let novel: Vec<(u64, u32, usize)> = vec![
        (0xAABB_0011, 1, 0),
        (0xAABB_0022, 1, 1),
        (0xAABB_0033, 2, 2),
        (0xAABB_0044, 2, 3),
        (0xAABB_0055, 3, 4),
    ];

    let mut added_count = 0usize;
    for (i, (fp, depth, idx)) in novel.iter().enumerate() {
        let pk = Pubkey::new_unique();
        let delta = make_pool_snapshot(vec![(pk, i as u64 * 100)]);
        let ok = pool.try_add(
            *fp,
            delta,
            *depth,
            Some(0),
            (*depth as u32).to_le_bytes().to_vec(),
            format!("action_{}", idx),
            Some(*idx as u16),
            vec![*idx as u8],
            None,
            0, 0, true, None,
    );
        if ok { added_count += 1; }
    }

    assert_eq!(added_count, 5, "all 5 novel states should be added");
    assert_eq!(pool.len(), 6, "pool: initial + 5 novel states");
    assert_eq!(pool.active_count(), 6);

    let initial_entry = pool.get(0).unwrap();
    assert_eq!(initial_entry.novel_children, 5,
        "initial state should have 5 novel children");
}

// ---------------------------------------------------------------------------
// Test 4 — Worker alternating traced/fast SVM every 3 iterations (dual-SVM swap)
// ---------------------------------------------------------------------------
#[test]
fn test_worker_dual_svm_swap_every_3_iterations() {
    let pk = Pubkey::new_unique();
    let mut fast_svm = LiteSVM::new();
    let mut traced_svm = LiteSVM::new();
    fast_svm.set_account(pk, make_account(1, &[0xBB])).unwrap();
    traced_svm.set_account(pk, make_account(2, &[0xAA])).unwrap();

    let initial = make_pool_snapshot(vec![(pk, 500)]);
    let delta = make_pool_snapshot(vec![(pk, 500)]);

    let mut traced_divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta_arc: Option<Arc<SvmSnapshot>> = None;
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    let trace_interval = 3u64;
    let mut trace_count = 0u32;
    let mut fast_count = 0u32;

    for iteration in 1u64..=9 {
        let is_traced = iteration % trace_interval == 0;

        if is_traced {
            std::mem::swap(&mut fast_svm, &mut traced_svm);
            initial.restore_selective(&mut fast_svm, &traced_divergent, &delta);
            traced_divergent.clear();
            traced_divergent.extend(delta.accounts().keys().copied());
            traced_divergent.insert(pk);
            std::mem::swap(&mut fast_svm, &mut traced_svm);
            prev_delta_arc = None;
            trace_count += 1;
        } else {
            if let Some(ref prev) = prev_delta_arc {
                initial.restore_selective_from(
                    &mut fast_svm, &divergent, prev, &delta, &prev_exec_dirty,
                );
            } else {
                initial.restore_selective(&mut fast_svm, &divergent, &delta);
            }
            divergent.clear();
            divergent.extend(delta.accounts().keys().copied());
            prev_exec_dirty.clear();
            prev_exec_dirty.insert(pk);
            divergent.extend(prev_exec_dirty.iter().copied());
            prev_delta_arc = Some(Arc::new(delta.clone()));
            fast_count += 1;
        }
    }

    assert_eq!(trace_count, 3, "iterations 3,6,9 are traced");
    assert_eq!(fast_count, 6, "iterations 1,2,4,5,7,8 are fast");
    let _f = fast_svm.get_account(&pk);
    let _t = traced_svm.get_account(&pk);
}

// ---------------------------------------------------------------------------
// Test 5 — Three workers with overlapping CPI accounts, verify cleanup
// ---------------------------------------------------------------------------
#[test]
fn test_three_workers_overlapping_cpi_cleanup() {
    let pk_common = Pubkey::new_unique();
    let cpi_w1 = Pubkey::new_unique();
    let cpi_w2 = Pubkey::new_unique();
    let cpi_w3 = Pubkey::new_unique();

    let initial = make_pool_snapshot(vec![(pk_common, 1000)]);
    let mut svm = LiteSVM::new();

    let delta_w1 = {
        let mut m: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
        m.insert(pk_common, Arc::new(make_account(1100, &[])));
        m.insert(cpi_w1, Arc::new(make_account(50, &[1])));
        SvmSnapshot { accounts: m, sysvars: make_test_sysvars(5) }
    };
    let div: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &div, &delta_w1);

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.extend(delta_w1.accounts().keys().copied());
    let prev_exec_dirty: FastHashSet<Pubkey> = [cpi_w1, pk_common].iter().copied().collect();
    divergent.extend(prev_exec_dirty.iter().copied());

    let delta_w2 = {
        let mut m: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
        m.insert(pk_common, Arc::new(make_account(1200, &[])));
        m.insert(cpi_w2, Arc::new(make_account(75, &[2])));
        SvmSnapshot { accounts: m, sysvars: make_test_sysvars(6) }
    };
    let prev_delta = Arc::new(delta_w1);
    initial.restore_selective_from(&mut svm, &divergent, &prev_delta, &delta_w2, &prev_exec_dirty);

    assert_eq!(svm.get_account(&cpi_w1).map(|a| a.lamports).unwrap_or(0), 0,
        "cpi_w1 must be zeroed after switching to delta_w2");
    assert_eq!(svm.get_account(&cpi_w2).unwrap().lamports, 75);

    let mut divergent3: FastHashSet<Pubkey> = FastHashSet::default();
    divergent3.extend(delta_w2.accounts().keys().copied());
    let prev_exec_dirty2: FastHashSet<Pubkey> = [cpi_w2, pk_common].iter().copied().collect();
    divergent3.extend(prev_exec_dirty2.iter().copied());

    let delta_w3 = {
        let mut m: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
        m.insert(pk_common, Arc::new(make_account(800, &[])));
        m.insert(cpi_w3, Arc::new(make_account(99, &[3])));
        SvmSnapshot { accounts: m, sysvars: make_test_sysvars(7) }
    };
    let prev_delta2 = Arc::new(delta_w2);
    initial.restore_selective_from(&mut svm, &divergent3, &prev_delta2, &delta_w3, &prev_exec_dirty2);

    assert_eq!(svm.get_account(&cpi_w2).map(|a| a.lamports).unwrap_or(0), 0,
        "cpi_w2 must be zeroed after switching to delta_w3");
    assert_eq!(svm.get_account(&cpi_w3).unwrap().lamports, 99);
}

// ---------------------------------------------------------------------------
// Test 6 — divergent_keys as strict subset vs exact vs superset
// ---------------------------------------------------------------------------
#[test]
fn test_divergent_keys_subset_misses_account() {
    let pk_tracked   = Pubkey::new_unique();
    let pk_untracked = Pubkey::new_unique();

    let initial = make_pool_snapshot(vec![(pk_tracked, 100), (pk_untracked, 200)]);

    let mut svm = LiteSVM::new();
    svm.set_account(pk_tracked, make_account(999, &[])).unwrap();
    svm.set_account(pk_untracked, make_account(888, &[])).unwrap();

    let mut divergent_subset: FastHashSet<Pubkey> = FastHashSet::default();
    divergent_subset.insert(pk_tracked);

    let next_delta = make_pool_snapshot(vec![(pk_tracked, 100)]);
    initial.restore_selective(&mut svm, &divergent_subset, &next_delta);

    assert_eq!(svm.get_account(&pk_tracked).unwrap().lamports, 100,
        "pk_tracked restored via delta");
    assert_eq!(svm.get_account(&pk_untracked).unwrap().lamports, 888,
        "pk_untracked stays stale when not in divergent_keys (expected leakage)");

    svm.set_account(pk_tracked, make_account(999, &[])).unwrap();
    svm.set_account(pk_untracked, make_account(888, &[])).unwrap();

    let mut divergent_exact: FastHashSet<Pubkey> = FastHashSet::default();
    divergent_exact.insert(pk_tracked);
    divergent_exact.insert(pk_untracked);

    initial.restore_selective(&mut svm, &divergent_exact, &next_delta);

    assert_eq!(svm.get_account(&pk_untracked).unwrap().lamports, 200,
        "with exact divergent_keys, pk_untracked restored to initial=200");

    let pk_extra = Pubkey::new_unique();
    let mut divergent_superset = divergent_exact.clone();
    divergent_superset.insert(pk_extra);

    svm.set_account(pk_tracked, make_account(999, &[])).unwrap();
    svm.set_account(pk_untracked, make_account(888, &[])).unwrap();

    initial.restore_selective(&mut svm, &divergent_superset, &next_delta);

    assert_eq!(svm.get_account(&pk_tracked).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_untracked).unwrap().lamports, 200,
        "superset divergent_keys also restores pk_untracked correctly");
}

// ---------------------------------------------------------------------------
// Test 7 — Failed action still dirties accounts; prev_exec_dirty is set
// ---------------------------------------------------------------------------
#[test]
fn test_failed_action_still_records_exec_dirty() {
    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk1);
    dirty.mark_account_dirty(&pk2);

    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    prev_exec_dirty.clear();
    prev_exec_dirty.extend(dirty.dirty_accounts().iter().copied());

    assert!(prev_exec_dirty.contains(&pk1), "pk1 must be in exec_dirty even on failure");
    assert!(prev_exec_dirty.contains(&pk2), "pk2 must be in exec_dirty even on failure");

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.extend(prev_exec_dirty.iter().copied());
    assert!(divergent.contains(&pk1));
    assert!(divergent.contains(&pk2));

    let initial = make_pool_snapshot(vec![(pk1, 100), (pk2, 200)]);
    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(999, &[])).unwrap();
    svm.set_account(pk2, make_account(888, &[])).unwrap();

    let next_delta = SvmSnapshot::empty(make_test_clock(1));
    initial.restore_selective(&mut svm, &divergent, &next_delta);

    assert_eq!(svm.get_account(&pk1).unwrap().lamports, 100,
        "pk1 restored to initial after failure-path divergent tracking");
    assert_eq!(svm.get_account(&pk2).unwrap().lamports, 200,
        "pk2 restored to initial after failure-path divergent tracking");
}

// ---------------------------------------------------------------------------
// Test 8 — restore_selective_from with same Arc for prev and next delta
// ---------------------------------------------------------------------------
#[test]
fn test_restore_selective_from_same_arc_skips_unchanged() {
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();

    let initial = make_pool_snapshot(vec![(pk_a, 100), (pk_b, 200)]);
    let mut svm = LiteSVM::new();
    svm.set_account(pk_a, make_account(100, &[])).unwrap();
    svm.set_account(pk_b, make_account(200, &[])).unwrap();

    let arc_a = Arc::new(make_account(500, &[1, 2]));
    let arc_b = Arc::new(make_account(600, &[3, 4]));
    let mut delta_accounts: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
    delta_accounts.insert(pk_a, arc_a.clone());
    delta_accounts.insert(pk_b, arc_b.clone());
    let delta = Arc::new(SvmSnapshot {
        accounts: delta_accounts,
        sysvars: make_test_sysvars(10),
    });

    let divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let empty_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    let writes = initial.restore_selective_from(
        &mut svm,
        &divergent,
        &delta,
        &delta,
        &empty_exec_dirty,
    );
    assert_eq!(writes, 0,
        "identical Arc pointers + empty exec_dirty: zero set_account calls");

    svm.set_account(pk_a, make_account(999, &[])).unwrap();
    let mut exec_dirty_with_a: FastHashSet<Pubkey> = FastHashSet::default();
    exec_dirty_with_a.insert(pk_a);

    let writes2 = initial.restore_selective_from(
        &mut svm,
        &divergent,
        &delta,
        &delta,
        &exec_dirty_with_a,
    );
    assert_eq!(writes2, 1, "exec_dirty overrides Arc::ptr_eq for pk_a only");
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500,
        "pk_a must be restored from next_delta (=delta) despite same Arc");
}

// ---------------------------------------------------------------------------
// Test 9 — Worker creates deep chain: pick root -> delta -> pick child -> delta
// ---------------------------------------------------------------------------
#[test]
fn test_deep_chain_intermediate_arcs_preserved() {
    let mut pool = StatePool::new(50, 10);
    let clock = make_test_clock(1);
    let pk = Pubkey::new_unique();

    pool.try_add(
        0x0001, SvmSnapshot::empty(clock.clone()),
        0, None, 0u32.to_le_bytes().to_vec(),
        String::new(), None, vec![], None, 0, 0, true, None,
    );

    let child_snap = make_pool_snapshot(vec![(pk, 100)]);
    let child_arc_for_pk = child_snap.accounts()[&pk].clone();
    pool.try_add(
        0x0002, child_snap, 1, Some(0),
        1u32.to_le_bytes().to_vec(),
        "action_deposit".to_string(), Some(0), vec![42], None, 0, 0, true, None,
    );

    let gc_snap = make_pool_snapshot(vec![(pk, 200)]);
    let gc_arc_for_pk = gc_snap.accounts()[&pk].clone();
    pool.try_add(
        0x0003, gc_snap, 2, Some(1),
        2u32.to_le_bytes().to_vec(),
        "action_borrow".to_string(), Some(1), vec![77], None, 0, 0, true, None,
    );

    assert_eq!(pool.len(), 3);

    assert_eq!(pool.get(2).unwrap().parent_idx, Some(1));
    assert_eq!(pool.get(1).unwrap().parent_idx, Some(0));
    assert_eq!(pool.get(0).unwrap().parent_idx, None);

    assert_eq!(pool.get(0).unwrap().depth, 0);
    assert_eq!(pool.get(1).unwrap().depth, 1);
    assert_eq!(pool.get(2).unwrap().depth, 2);

    assert_eq!(pool.get(0).unwrap().novel_children, 1);
    assert_eq!(pool.get(1).unwrap().novel_children, 1);
    assert_eq!(pool.get(2).unwrap().novel_children, 0);

    let child_entry_arc = pool.get(1).unwrap().delta.accounts()[&pk].clone();
    let gc_entry_arc    = pool.get(2).unwrap().delta.accounts()[&pk].clone();
    assert_eq!(child_entry_arc.lamports, 100);
    assert_eq!(gc_entry_arc.lamports, 200);
    assert!(!Arc::ptr_eq(&child_entry_arc, &gc_entry_arc),
        "grandchild has a separate Arc from child for pk");
    assert!(Arc::ptr_eq(&child_arc_for_pk, &child_entry_arc),
        "Arc captured before pool insertion matches stored entry");
    let _ = gc_arc_for_pk;
}

// ---------------------------------------------------------------------------
// Test 10 — prev_exec_dirty union with divergent_keys produces correct superset
// ---------------------------------------------------------------------------
#[test]
fn test_exec_dirty_union_with_divergent_keys() {
    let pk_from_delta   = Pubkey::new_unique();
    let pk_from_exec_1  = Pubkey::new_unique();
    let pk_from_exec_2  = Pubkey::new_unique();

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_from_delta);

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_from_exec_1);
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    prev_exec_dirty.clear();
    prev_exec_dirty.extend(dirty.dirty_accounts().iter().copied());
    divergent.extend(prev_exec_dirty.iter().copied());

    assert!(divergent.contains(&pk_from_delta));
    assert!(divergent.contains(&pk_from_exec_1));
    assert_eq!(divergent.len(), 2);

    dirty.clear();
    dirty.mark_account_dirty(&pk_from_exec_2);
    prev_exec_dirty.clear();
    prev_exec_dirty.extend(dirty.dirty_accounts().iter().copied());
    divergent.extend(prev_exec_dirty.iter().copied());

    assert_eq!(divergent.len(), 3);
    assert!(divergent.contains(&pk_from_delta));
    assert!(divergent.contains(&pk_from_exec_1));
    assert!(divergent.contains(&pk_from_exec_2));

    let delta = make_pool_snapshot(vec![(pk_from_delta, 100)]);
    divergent.clear();
    divergent.extend(delta.accounts().keys().copied());

    assert!(divergent.contains(&pk_from_delta));
    assert!(!divergent.contains(&pk_from_exec_1),
        "exec-dirty keys cleared after restore");
    assert!(!divergent.contains(&pk_from_exec_2),
        "exec-dirty keys cleared after restore");
    assert_eq!(divergent.len(), 1);
}

// ---------------------------------------------------------------------------
// Test 11 — Worker picks same state 3 times; _from with same prev is idempotent
// ---------------------------------------------------------------------------
#[test]
fn test_same_state_picked_three_times_idempotent() {
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();

    let initial = make_pool_snapshot(vec![(pk_a, 100), (pk_b, 200)]);
    let mut svm = LiteSVM::new();

    let arc_a = Arc::new(make_account(500, &[1]));
    let arc_b = Arc::new(make_account(600, &[2]));
    let mut accts: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
    accts.insert(pk_a, arc_a.clone());
    accts.insert(pk_b, arc_b.clone());
    let delta = Arc::new(SvmSnapshot {
        accounts: accts,
        sysvars: make_test_sysvars(10),
    });

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &delta);
    divergent.clear();
    divergent.extend(delta.accounts().keys().copied());

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 600);

    svm.set_account(pk_a, make_account(777, &[9])).unwrap();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    prev_exec_dirty.insert(pk_a);
    divergent.extend(prev_exec_dirty.iter().copied());

    initial.restore_selective_from(&mut svm, &divergent, &delta, &delta, &prev_exec_dirty);
    divergent.clear();
    divergent.extend(delta.accounts().keys().copied());

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500,
        "pick 2: pk_a restored (exec-dirty overrides Arc::ptr_eq)");

    svm.set_account(pk_a, make_account(888, &[7])).unwrap();
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk_a);
    divergent.extend(prev_exec_dirty.iter().copied());

    initial.restore_selective_from(&mut svm, &divergent, &delta, &delta, &prev_exec_dirty);

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500,
        "pick 3: pk_a restored correctly (idempotent)");
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 600,
        "pk_b unchanged — Arc same and not exec-dirty");
}

// ---------------------------------------------------------------------------
// Test 12 — Traced SVM every 5th iteration; fast path iterations 1-4,6-9
// ---------------------------------------------------------------------------
#[test]
fn test_traced_svm_every_5th_iteration() {
    let pk = Pubkey::new_unique();
    let trace_interval = 5u64;

    let mut fast_svm = LiteSVM::new();
    let mut traced_svm = LiteSVM::new();
    fast_svm.set_account(pk, make_account(1, &[0xBB])).unwrap();
    traced_svm.set_account(pk, make_account(2, &[0xAA])).unwrap();

    let initial = make_pool_snapshot(vec![(pk, 100)]);
    let delta   = make_pool_snapshot(vec![(pk, 100)]);

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut traced_divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta_arc: Option<Arc<SvmSnapshot>> = None;
    let mut trace_count = 0u32;
    let mut fast_count = 0u32;

    for iteration in 1u64..=10 {
        let is_traced = iteration % trace_interval == 0;

        if is_traced {
            std::mem::swap(&mut fast_svm, &mut traced_svm);
            initial.restore_selective(&mut fast_svm, &traced_divergent, &delta);
            traced_divergent.clear();
            traced_divergent.extend(delta.accounts().keys().copied());
            traced_divergent.insert(pk);
            std::mem::swap(&mut fast_svm, &mut traced_svm);
            prev_delta_arc = None;
            trace_count += 1;
        } else {
            if let Some(ref prev) = prev_delta_arc {
                initial.restore_selective_from(
                    &mut fast_svm, &divergent, prev, &delta, &prev_exec_dirty,
                );
            } else {
                initial.restore_selective(&mut fast_svm, &divergent, &delta);
            }
            divergent.clear();
            divergent.extend(delta.accounts().keys().copied());
            prev_exec_dirty.clear();
            prev_exec_dirty.insert(pk);
            divergent.extend(prev_exec_dirty.iter().copied());
            prev_delta_arc = Some(Arc::new(delta.clone()));
            fast_count += 1;
        }
    }

    assert_eq!(trace_count, 2, "iterations 5 and 10 are traced");
    assert_eq!(fast_count, 8, "8 fast iterations");
}

// ---------------------------------------------------------------------------
// Test 13 — Delta from pool pick has tombstone account; verify zeroed after restore
// ---------------------------------------------------------------------------
#[test]
fn test_tombstone_account_deleted_after_restore() {
    let pk_alive = Pubkey::new_unique();
    let pk_tomb  = Pubkey::new_unique();

    let initial = {
        let mut m: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
        m.insert(pk_alive, Arc::new(make_account(500, &[1, 2, 3])));
        m.insert(pk_tomb,  Arc::new(make_account(100, &[4, 5, 6])));
        SvmSnapshot { accounts: m, sysvars: make_test_sysvars(1) }
    };

    let mut svm = LiteSVM::new();
    svm.set_account(pk_alive, make_account(500, &[1, 2, 3])).unwrap();
    svm.set_account(pk_tomb,  make_account(100, &[4, 5, 6])).unwrap();

    let delta = {
        let mut m: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
        m.insert(pk_alive, Arc::new(make_account(600, &[1, 2, 3])));
        m.insert(pk_tomb,  Arc::new(Account { lamports: 0, ..Default::default() }));
        SvmSnapshot { accounts: m, sysvars: make_test_sysvars(2) }
    };

    let divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &delta);

    assert_eq!(svm.get_account(&pk_alive).unwrap().lamports, 600);
    let tomb_lamps = svm.get_account(&pk_tomb).map(|a| a.lamports).unwrap_or(0);
    assert_eq!(tomb_lamps, 0,
        "tombstone account must have lamports=0 after restore");
}

// ---------------------------------------------------------------------------
// Test 14 — Worker restores A, exec creates X,Y,Z; restores B — X,Y,Z must be zeroed
// ---------------------------------------------------------------------------
#[test]
fn test_newly_created_accounts_zeroed_on_state_switch() {
    let pk_common = Pubkey::new_unique();
    let pk_x = Pubkey::new_unique();
    let pk_y = Pubkey::new_unique();
    let pk_z = Pubkey::new_unique();

    let initial = make_pool_snapshot(vec![(pk_common, 1000)]);
    let delta_a = make_pool_snapshot(vec![(pk_common, 1100)]);
    let delta_b = make_pool_snapshot(vec![(pk_common, 900)]);

    let mut svm = LiteSVM::new();
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();

    initial.restore_selective(&mut svm, &divergent, &delta_a);
    divergent.clear();
    divergent.extend(delta_a.accounts().keys().copied());

    svm.set_account(pk_x, make_account(111, &[1])).unwrap();
    svm.set_account(pk_y, make_account(222, &[2])).unwrap();
    svm.set_account(pk_z, make_account(333, &[3])).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_x);
    dirty.mark_account_dirty(&pk_y);
    dirty.mark_account_dirty(&pk_z);
    dirty.mark_account_dirty(&pk_common);

    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    prev_exec_dirty.extend(dirty.dirty_accounts().iter().copied());
    divergent.extend(prev_exec_dirty.iter().copied());

    let prev_delta = Arc::new(delta_a);
    initial.restore_selective_from(&mut svm, &divergent, &prev_delta, &delta_b, &prev_exec_dirty);

    assert_eq!(svm.get_account(&pk_x).map(|a| a.lamports).unwrap_or(0), 0,
        "pk_x must be zeroed after switching to delta_b");
    assert_eq!(svm.get_account(&pk_y).map(|a| a.lamports).unwrap_or(0), 0,
        "pk_y must be zeroed after switching to delta_b");
    assert_eq!(svm.get_account(&pk_z).map(|a| a.lamports).unwrap_or(0), 0,
        "pk_z must be zeroed after switching to delta_b");

    assert_eq!(svm.get_account(&pk_common).unwrap().lamports, 900,
        "pk_common must be at delta_b=900 after switch");
}

// ---------------------------------------------------------------------------
// Test 15 — Comprehensive 10-iteration worker simulation
// ---------------------------------------------------------------------------
#[test]
fn test_comprehensive_10_iteration_worker_simulation() {
    let pk_user  = Pubkey::new_unique();
    let pk_vault = Pubkey::new_unique();
    let pk_cpi_1 = Pubkey::new_unique();
    let pk_cpi_2 = Pubkey::new_unique();

    let initial = make_pool_snapshot(vec![(pk_user, 10_000), (pk_vault, 50_000)]);
    let delta_a  = make_pool_snapshot(vec![(pk_user, 9_000),  (pk_vault, 51_000)]);
    let delta_b  = make_pool_snapshot(vec![(pk_user, 8_000),  (pk_vault, 52_000)]);

    let mut svm = LiteSVM::new();
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta_arc: Option<Arc<SvmSnapshot>> = None;
    let mut traced_divergent: FastHashSet<Pubkey> = FastHashSet::default();

    let specs: &[(usize, bool, bool, Option<Pubkey>)] = &[
        (1, true,  false, None),
        (2, false, false, None),
        (1, true,  false, Some(pk_cpi_1)),
        (2, true,  false, None),
        (1, true,  true,  None),
        (2, true,  false, None),
        (1, false, false, Some(pk_cpi_2)),
        (2, true,  false, None),
        (1, true,  false, None),
        (2, true,  false, None),
    ];

    let deltas = [
        SvmSnapshot::empty(make_test_clock(1)),
        delta_a.clone(),
        delta_b.clone(),
    ];

    for (iter_idx, (delta_choice, success, is_traced, cpi_pk)) in specs.iter().enumerate() {
        let next_delta = &deltas[*delta_choice];

        if *is_traced {
            initial.restore_selective(&mut svm, &traced_divergent, next_delta);
            traced_divergent.clear();
            traced_divergent.extend(next_delta.accounts().keys().copied());
            if let Some(cpi) = cpi_pk {
                svm.set_account(*cpi, make_account(42, &[iter_idx as u8])).unwrap();
                traced_divergent.insert(*cpi);
            }
            traced_divergent.insert(pk_user);
            traced_divergent.insert(pk_vault);
            prev_delta_arc = None;
        } else {
            if let Some(ref prev) = prev_delta_arc {
                initial.restore_selective_from(
                    &mut svm, &divergent, prev, next_delta, &prev_exec_dirty,
                );
            } else {
                initial.restore_selective(&mut svm, &divergent, next_delta);
            }
            divergent.clear();
            divergent.extend(next_delta.accounts().keys().copied());

            if let Some(cpi) = cpi_pk {
                svm.set_account(*cpi, make_account(42, &[iter_idx as u8])).unwrap();
            }

            let mut dirty = DirtyTracker::new();
            dirty.mark_account_dirty(&pk_user);
            dirty.mark_account_dirty(&pk_vault);
            if let Some(cpi) = cpi_pk {
                dirty.mark_account_dirty(cpi);
            }

            prev_exec_dirty.clear();
            prev_exec_dirty.extend(dirty.dirty_accounts().iter().copied());
            divergent.extend(prev_exec_dirty.iter().copied());

            if *success {
                prev_delta_arc = Some(Arc::new(next_delta.clone()));
            } else {
                prev_delta_arc = None;
            }
        }

        if iter_idx == 3 {
            let lamps = svm.get_account(&pk_cpi_1).map(|a| a.lamports).unwrap_or(0);
            assert_eq!(lamps, 0,
                "iter 4: cpi_1 (created in iter 3) must be zeroed after switch to B");
        }

        if iter_idx == 7 {
            let lamps = svm.get_account(&pk_cpi_2).map(|a| a.lamports).unwrap_or(0);
            assert_eq!(lamps, 0,
                "iter 8: cpi_2 (created in iter 7 failure) must be zeroed after switch to B");
        }

        if *success && !*is_traced {
            let (exp_user, exp_vault) = if *delta_choice == 1 {
                (9_000u64, 51_000u64)
            } else if *delta_choice == 2 {
                (8_000u64, 52_000u64)
            } else {
                continue
            };
            assert_eq!(svm.get_account(&pk_user).map(|a| a.lamports).unwrap_or(0),
                exp_user, "iter {}: pk_user matches delta {}", iter_idx + 1, delta_choice);
            assert_eq!(svm.get_account(&pk_vault).map(|a| a.lamports).unwrap_or(0),
                exp_vault, "iter {}: pk_vault matches delta {}", iter_idx + 1, delta_choice);
        }
    }
}

// ---------------------------------------------------------------------------
// Test 16 — pick_weighted_batch: 512 picks, state with novelty_bits is favoured
// ---------------------------------------------------------------------------
#[test]
fn test_pick_weighted_batch_coverage_novel_favoured() {
    let mut pool = StatePool::new(200, 10);
    let clock = make_test_clock(1);

    pool.try_add(
        0xAA01, SvmSnapshot::empty(clock.clone()),
        0, None, 0u32.to_le_bytes().to_vec(),
        "state_0".into(), None, vec![], None, 0, 0, true, None,
    );
    pool.try_add(
        0xAA02, SvmSnapshot::empty(clock.clone()),
        1, Some(0), 1u32.to_le_bytes().to_vec(),
        "state_1".into(), Some(1), vec![1], None, 0, 0, true, None,
    );
    pool.try_add(
        0xAA03, SvmSnapshot::empty(clock.clone()),
        1, Some(0), 1u32.to_le_bytes().to_vec(),
        "state_2".into(), Some(2), vec![2], None, 10, 10, true, None,
    );
    pool.try_add(
        0xAA04, SvmSnapshot::empty(clock.clone()),
        1, Some(0), 1u32.to_le_bytes().to_vec(),
        "state_3".into(), Some(3), vec![3], None, 0, 0, true, None,
    );

    assert_eq!(pool.len(), 4);

    let rng_vals: Vec<u64> = (0u64..512)
        .map(|i| i.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(0xdeadbeef))
        .collect();
    let mut picks: Vec<(Arc<SvmSnapshot>, u32, usize, Arc<Vec<u8>>, Option<u16>, Arc<Vec<u8>>, u64, Option<Arc<dyn std::any::Any + Send + Sync>>)> = Vec::new();

    let n = pool.pick_weighted_batch(&rng_vals, &mut picks);
    assert_eq!(n, 512);

    let state2_count = picks.iter().filter(|(_, _, idx, _, _, _, _, _)| *idx == 2).count();
    let state0_count = picks.iter().filter(|(_, _, idx, _, _, _, _, _)| *idx == 0).count();
    let state1_count = picks.iter().filter(|(_, _, idx, _, _, _, _, _)| *idx == 1).count();
    let state3_count = picks.iter().filter(|(_, _, idx, _, _, _, _, _)| *idx == 3).count();

    // state0 is parent of all 3 children (including coverage-novel state2),
    // so it gets boosted novelty_bits + high novel_children exploit — may beat state2.
    // State2 with novelty_bits should beat non-parent, non-novel states (state1, state3).
    assert!(state2_count > state1_count,
        "novelty_bits state2 ({}) should beat state1 ({})", state2_count, state1_count);
    assert!(state2_count > state3_count,
        "novelty_bits state2 ({}) should beat state3 ({})", state2_count, state3_count);
    assert_eq!(state0_count + state1_count + state2_count + state3_count, 512);
}

// ---------------------------------------------------------------------------
// Test 17 — DirtyTracker: account promoted from read-only to writable
// ---------------------------------------------------------------------------
#[test]
fn test_dirty_tracker_account_promoted_to_writable() {
    let mut tracker = DirtyTracker::new();
    let fee_payer = Pubkey::new_unique();
    let prog = Pubkey::new_unique();
    let pk_ambiguous = Pubkey::new_unique();

    let ix1 = Instruction {
        program_id: prog,
        accounts: vec![AccountMeta::new_readonly(pk_ambiguous, false)],
        data: vec![],
    };
    tracker.record_tx(&[ix1], &fee_payer);
    assert!(!tracker.dirty_accounts().contains(&pk_ambiguous),
        "after tx1 (read-only): pk_ambiguous not yet writable");
    assert!(tracker.read_accounts().contains(&pk_ambiguous));

    let ix2 = Instruction {
        program_id: prog,
        accounts: vec![AccountMeta::new(pk_ambiguous, false)],
        data: vec![],
    };
    tracker.record_tx(&[ix2], &fee_payer);
    assert!(tracker.dirty_accounts().contains(&pk_ambiguous),
        "after tx2 (writable): pk_ambiguous must be in dirty set");
}

// ---------------------------------------------------------------------------
// Test 18 — take_delta propagates tombstones from parent delta
// ---------------------------------------------------------------------------
#[test]
fn test_take_delta_tombstone_propagation() {
    let pk_deleted = Pubkey::new_unique();
    let pk_child   = Pubkey::new_unique();

    let parent_delta = {
        let mut m: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
        m.insert(pk_deleted, Arc::new(Account { lamports: 0, ..Default::default() }));
        SvmSnapshot { accounts: m, sysvars: make_test_sysvars(3) }
    };

    let mut svm = LiteSVM::new();
    svm.set_account(pk_child, make_account(777, &[9])).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_child);

    let child_delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

    assert!(child_delta.accounts().contains_key(&pk_deleted),
        "tombstone from parent must propagate into child delta");
    assert_eq!(child_delta.accounts()[&pk_deleted].lamports, 0,
        "propagated tombstone must have lamports=0");

    assert!(child_delta.accounts().contains_key(&pk_child));
    assert_eq!(child_delta.accounts()[&pk_child].lamports, 777);
}

// ---------------------------------------------------------------------------
// Test 19 — record_violation reduces state's pick weight significantly
// ---------------------------------------------------------------------------
#[test]
fn test_record_violation_reduces_pick_weight() {
    // violation_count is tracked for diagnostics but no longer affects weight.
    // Violated states are removed from active set via mark_crashed() instead.
    let mut pool = StatePool::new(50, 10);
    let clock = make_test_clock(1);

    pool.try_add(
        0xAAAA, SvmSnapshot::empty(clock.clone()),
        0, None, 0u32.to_le_bytes().to_vec(), "state_0".into(), None, vec![], None, 0, 0, true, None,
    );
    pool.try_add(
        0xBBBB, SvmSnapshot::empty(clock.clone()),
        1, Some(0), 1u32.to_le_bytes().to_vec(), "state_1".into(), Some(1), vec![1], None, 0, 0, true, None,
    );

    for _ in 0..20 {
        pool.record_violation(1);
    }
    assert_eq!(pool.get(1).unwrap().violation_count, 20);

    // Both states should still be picked (violations don't affect weight anymore)
    let rng_vals: Vec<u64> = (0u64..1000)
        .map(|i| i.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407))
        .collect();
    let mut picks: Vec<(Arc<SvmSnapshot>, u32, usize, Arc<Vec<u8>>, Option<u16>, Arc<Vec<u8>>, u64, Option<Arc<dyn std::any::Any + Send + Sync>>)> = Vec::new();
    pool.pick_weighted_batch(&rng_vals, &mut picks);

    let state0_picks = picks.iter().filter(|(_, _, idx, _, _, _, _, _)| *idx == 0).count();
    let state1_picks = picks.iter().filter(|(_, _, idx, _, _, _, _, _)| *idx == 1).count();

    // Both should get substantial picks (violations don't affect weight)
    assert!(state0_picks > 100 && state1_picks > 100,
        "both states should get picks: state0={}, state1={}",
        state0_picks, state1_picks);
}

// ---------------------------------------------------------------------------
// Test 20 — restore_selective_from: account only in next_delta (not in prev)
// ---------------------------------------------------------------------------
#[test]
fn test_restore_selective_from_new_account_in_next_delta() {
    let pk_existing  = Pubkey::new_unique();
    let pk_new_only  = Pubkey::new_unique();

    let initial = make_pool_snapshot(vec![(pk_existing, 100)]);
    let mut svm = LiteSVM::new();
    svm.set_account(pk_existing, make_account(100, &[])).unwrap();

    let prev_delta = Arc::new(make_pool_snapshot(vec![(pk_existing, 200)]));

    let next_delta = {
        let mut m: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
        m.insert(pk_existing, Arc::new(make_account(300, &[])));
        m.insert(pk_new_only, Arc::new(make_account(555, &[7, 8])));
        SvmSnapshot { accounts: m, sysvars: make_test_sysvars(9) }
    };

    let divergent: FastHashSet<Pubkey> = [pk_existing].iter().copied().collect();
    let empty_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    let writes = initial.restore_selective_from(
        &mut svm,
        &divergent,
        &prev_delta,
        &next_delta,
        &empty_exec_dirty,
    );

    let _ = writes;

    let new_acc = svm.get_account(&pk_new_only).unwrap();
    assert_eq!(new_acc.lamports, 555,
        "account only in next_delta must always be written");

    let existing_acc = svm.get_account(&pk_existing).unwrap();
    assert_eq!(existing_acc.lamports, 300,
        "pk_existing updated to next_delta value");
}

// ---- Round 6: Snapshot/restore adversarial conditions ----

// Test 1: Large data account (10KB) in delta
#[test]
fn test_restore_selective_large_data_account_byte_for_byte() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();

    let big_data: Vec<u8> = (0u32..10240).map(|i| (i.wrapping_mul(37) ^ (i >> 3)) as u8).collect();
    let initial_lamports = 5_000_000u64;
    svm.set_account(pk, make_account(initial_lamports, &big_data)).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mutated_data: Vec<u8> = (0u32..10240).map(|i| (i.wrapping_mul(97) ^ 0xA5) as u8).collect();
    svm.set_account(pk, make_account(initial_lamports + 1, &mutated_data)).unwrap();

    let mut delta_accounts: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
    delta_accounts.insert(pk, Arc::new(make_account(initial_lamports + 1, &mutated_data)));
    let delta = SvmSnapshot {
        accounts: delta_accounts,
        sysvars: initial.sysvars.clone(),
    };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk);

    svm.set_account(pk, make_account(1, &[0xFF; 128])).unwrap();

    let count = initial.restore_selective(&mut svm, &divergent, &delta);
    assert_eq!(count, 1);

    let got = svm.get_account(&pk).unwrap();
    assert_eq!(got.lamports, initial_lamports + 1);
    assert_eq!(got.data.len(), 10240);
    for (i, (&expected, &actual)) in mutated_data.iter().zip(got.data.iter()).enumerate() {
        assert_eq!(actual, expected, "byte mismatch at index {}", i);
    }
}

// Test 2: 50 accounts, each with unique data
#[test]
fn test_take_full_fifty_accounts_all_compare() {
    let mut svm = LiteSVM::new();
    let count = 50usize;

    let pubkeys: Vec<Pubkey> = (0..count).map(|_| Pubkey::new_unique()).collect();
    let original_data: Vec<Vec<u8>> = (0..count)
        .map(|i| (0u8..8).map(|j| i as u8 ^ j ^ 0xC3).collect())
        .collect();
    let original_lamports: Vec<u64> = (0..count).map(|i| (i as u64 + 1) * 1000).collect();

    for (i, pk) in pubkeys.iter().enumerate() {
        svm.set_account(*pk, make_account(original_lamports[i], &original_data[i])).unwrap();
    }

    let tracked: HashSet<Pubkey> = pubkeys.iter().cloned().collect();
    let base = SvmSnapshot::take(&svm, &tracked);

    let mut dirty = DirtyTracker::new();
    for (i, pk) in pubkeys.iter().enumerate() {
        if i % 2 == 0 {
            let new_data: Vec<u8> = (0u8..8).map(|j| i as u8 ^ j ^ 0xFF).collect();
            svm.set_account(*pk, make_account(original_lamports[i] + 7, &new_data)).unwrap();
            dirty.mark_account_dirty(pk);
        }
    }

    let full = SvmSnapshot::take_full(&svm, &base, &dirty);
    assert_eq!(full.account_count(), count);

    for (i, pk) in pubkeys.iter().enumerate() {
        let acct = full.accounts().get(pk).expect("missing account in full snapshot");
        if i % 2 == 0 {
            let expected_data: Vec<u8> = (0u8..8).map(|j| i as u8 ^ j ^ 0xFF).collect();
            assert_eq!(acct.lamports, original_lamports[i] + 7, "lamports mismatch for dirty account {}", i);
            assert_eq!(acct.data, expected_data, "data mismatch for dirty account {}", i);
        } else {
            assert_eq!(acct.lamports, original_lamports[i], "lamports mismatch for clean account {}", i);
            assert_eq!(acct.data, original_data[i], "data mismatch for clean account {}", i);
        }
    }
}

// Test 3: Clock sysvar restoration
#[test]
fn test_clock_restored_in_restore_selective_and_selective_from() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(1_000_000, &[1, 2, 3])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);
    let initial_clock_slot = initial.clock().slot;

    let target_clock = Clock {
        slot: initial_clock_slot + 9999,
        epoch: 77,
        unix_timestamp: 123456789,
        epoch_start_timestamp: 111111,
        leader_schedule_epoch: 78,
    };
    let mut delta_accounts: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
    delta_accounts.insert(pk, Arc::new(make_account(2_000_000, &[9])));
    let delta = SvmSnapshot { accounts: delta_accounts, sysvars: clock_to_sysvars(&target_clock) };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk);

    initial.restore_selective(&mut svm, &divergent, &delta);
    let got_clock = svm.get_sysvar::<Clock>();
    assert_eq!(got_clock.slot, target_clock.slot, "restore_selective: wrong slot");
    assert_eq!(got_clock.epoch, target_clock.epoch, "restore_selective: wrong epoch");
    assert_eq!(got_clock.unix_timestamp, target_clock.unix_timestamp, "restore_selective: wrong timestamp");

    let prev_clock = Clock { slot: 11, epoch: 1, unix_timestamp: 1000, epoch_start_timestamp: 0, leader_schedule_epoch: 2 };
    let next_clock = Clock { slot: 42, epoch: 3, unix_timestamp: 9999, epoch_start_timestamp: 500, leader_schedule_epoch: 4 };

    let shared_arc = Arc::new(make_account(1_000_000, &[1, 2, 3]));
    let mut prev_accounts: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
    prev_accounts.insert(pk, shared_arc.clone());
    let prev_delta = SvmSnapshot { accounts: prev_accounts, sysvars: clock_to_sysvars(&prev_clock) };

    let mut next_accounts: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
    next_accounts.insert(pk, shared_arc.clone());
    let next_delta = SvmSnapshot { accounts: next_accounts, sysvars: clock_to_sysvars(&next_clock) };

    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective_from(&mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty);

    let got_clock2 = svm.get_sysvar::<Clock>();
    assert_eq!(got_clock2.slot, next_clock.slot, "restore_selective_from: wrong slot");
    assert_eq!(got_clock2.epoch, next_clock.epoch, "restore_selective_from: wrong epoch");
    assert_eq!(got_clock2.unix_timestamp, next_clock.unix_timestamp, "restore_selective_from: wrong timestamp");
}

// Test 4: take_delta with empty dirty tracker
#[test]
fn test_take_delta_empty_dirty_produces_arc_clone_of_parent() {
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    svm.set_account(pk_a, make_account(111, &[0xAA, 0xBB])).unwrap();
    svm.set_account(pk_b, make_account(222, &[0xCC, 0xDD])).unwrap();

    let arc_a = Arc::new(make_account(111, &[0xAA, 0xBB]));
    let arc_b = Arc::new(make_account(222, &[0xCC, 0xDD]));
    let mut parent_accounts: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
    parent_accounts.insert(pk_a, arc_a.clone());
    parent_accounts.insert(pk_b, arc_b.clone());
    let parent_clock = svm.get_sysvar::<Clock>();
    let parent_delta = SvmSnapshot { accounts: parent_accounts, sysvars: clock_to_sysvars(&parent_clock) };

    let dirty = DirtyTracker::new();
    let child_delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

    assert_eq!(child_delta.account_count(), 2);
    assert!(Arc::ptr_eq(&child_delta.accounts()[&pk_a], &arc_a),
        "take_delta with empty dirty should share Arc for pk_a");
    assert!(Arc::ptr_eq(&child_delta.accounts()[&pk_b], &arc_b),
        "take_delta with empty dirty should share Arc for pk_b");
}

// Test 5: take_delta when dirty account doesn't exist in SVM
#[test]
fn test_take_delta_missing_svm_account_produces_tombstone() {
    let mut svm = LiteSVM::new();
    let pk_exists = Pubkey::new_unique();
    let pk_deleted = Pubkey::new_unique();

    svm.set_account(pk_exists, make_account(500, &[0x01])).unwrap();

    let parent_delta = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_deleted);
    dirty.mark_account_dirty(&pk_exists);

    let delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

    assert!(delta.accounts().contains_key(&pk_exists));
    assert_eq!(delta.accounts()[&pk_exists].lamports, 500);

    assert!(delta.accounts().contains_key(&pk_deleted),
        "deleted account should be in delta as tombstone");
    let tombstone = &delta.accounts()[&pk_deleted];
    assert_eq!(tombstone.lamports, 0, "tombstone must have lamports=0");
    assert!(tombstone.data.is_empty(), "tombstone must have empty data");
    assert!(!tombstone.executable, "tombstone must not be executable");
}

// Test 6: take_full after chain of take_deltas
#[test]
fn test_take_full_after_delta_chain_no_phantom_accounts() {
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(100, &[1])).unwrap();
    svm.set_account(pk_b, make_account(200, &[2])).unwrap();
    svm.set_account(pk_c, make_account(300, &[3])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
    let base = SvmSnapshot::take(&svm, &tracked);
    let empty_delta = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    svm.set_account(pk_a, make_account(111, &[0xA1])).unwrap();
    let mut dirty1 = DirtyTracker::new();
    dirty1.mark_account_dirty(&pk_a);
    let delta1 = SvmSnapshot::take_delta(&svm, &empty_delta, &dirty1);

    svm.set_account(pk_b, make_account(222, &[0xB2])).unwrap();
    let mut dirty2 = DirtyTracker::new();
    dirty2.mark_account_dirty(&pk_b);
    let _delta2 = SvmSnapshot::take_delta(&svm, &delta1, &dirty2);

    let mut combined_dirty = DirtyTracker::new();
    combined_dirty.mark_account_dirty(&pk_a);
    combined_dirty.mark_account_dirty(&pk_b);

    let full = SvmSnapshot::take_full(&svm, &base, &combined_dirty);

    assert_eq!(full.account_count(), 3, "should have exactly 3 accounts: pk_a, pk_b, pk_c");
    assert!(full.accounts().contains_key(&pk_a));
    assert!(full.accounts().contains_key(&pk_b));
    assert!(full.accounts().contains_key(&pk_c));

    assert_eq!(full.accounts()[&pk_a].lamports, 111);
    assert_eq!(full.accounts()[&pk_b].lamports, 222);
    assert_eq!(full.accounts()[&pk_c].lamports, 300);
}

// Test 7: Multiple consecutive restores to same state (idempotency)
#[test]
fn test_restore_selective_idempotent_multiple_times() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    let original_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    svm.set_account(pk, make_account(42_000, &original_data)).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let delta = SvmSnapshot::empty(initial.clock().clone());

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk);

    for iteration in 0..5 {
        let garbage = vec![(iteration as u8) * 0x11; 16];
        svm.set_account(pk, make_account((iteration + 1) as u64 * 1000, &garbage)).unwrap();

        initial.restore_selective(&mut svm, &divergent, &delta);

        let got = svm.get_account(&pk).expect("account should exist after restore");
        assert_eq!(got.lamports, 42_000, "iteration {}: lamports mismatch", iteration);
        assert_eq!(got.data, original_data, "iteration {}: data mismatch", iteration);
    }
}

// Test 8: Restore with divergent_keys containing keys that don't exist anywhere
#[test]
fn test_restore_selective_phantom_divergent_keys_no_panic() {
    let mut svm = LiteSVM::new();
    let pk_real = Pubkey::new_unique();
    svm.set_account(pk_real, make_account(500, &[0x42])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_real].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let phantom1 = Pubkey::new_unique();
    let phantom2 = Pubkey::new_unique();
    let phantom3 = Pubkey::new_unique();

    let delta = SvmSnapshot::empty(initial.clock().clone());

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(phantom1);
    divergent.insert(phantom2);
    divergent.insert(phantom3);
    divergent.insert(pk_real);

    let count = initial.restore_selective(&mut svm, &divergent, &delta);

    assert_eq!(count, 4, "should count all 4 divergent keys");

    let got = svm.get_account(&pk_real).unwrap();
    assert_eq!(got.lamports, 500);
    assert_eq!(got.data, vec![0x42]);

    assert!(svm.get_account(&phantom1).is_none(), "phantom1 should not exist");
    assert!(svm.get_account(&phantom2).is_none(), "phantom2 should not exist");
    assert!(svm.get_account(&phantom3).is_none(), "phantom3 should not exist");
}

// Test 9: restore_selective_from where prev has many keys but next is empty
#[test]
fn test_restore_selective_from_empty_next_delta_restores_to_initial() {
    let mut svm = LiteSVM::new();
    let pks: Vec<Pubkey> = (0..8).map(|_| Pubkey::new_unique()).collect();

    for (i, pk) in pks.iter().enumerate() {
        svm.set_account(*pk, make_account((i as u64 + 1) * 100, &[i as u8])).unwrap();
    }

    let tracked: HashSet<Pubkey> = pks.iter().cloned().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut prev_accounts: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
    for (i, pk) in pks.iter().enumerate() {
        prev_accounts.insert(*pk, Arc::new(make_account(9999, &[0xBB, i as u8])));
    }
    let prev_delta = SvmSnapshot { accounts: prev_accounts, sysvars: initial.sysvars.clone() };

    let next_delta = SvmSnapshot::empty(initial.clock().clone());

    let divergent: FastHashSet<Pubkey> = pks.iter().cloned().collect();
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    for pk in &pks {
        svm.set_account(*pk, make_account(1, &[0xFF])).unwrap();
    }

    let count = initial.restore_selective_from(&mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty);

    assert_eq!(count, 8);

    for (i, pk) in pks.iter().enumerate() {
        let got = svm.get_account(pk).expect("account should exist");
        assert_eq!(got.lamports, (i as u64 + 1) * 100, "lamports mismatch for account {}", i);
        assert_eq!(got.data, vec![i as u8], "data mismatch for account {}", i);
    }
}

// Test 10: Account owner field changes
#[test]
fn test_restore_preserves_account_owner_field() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    let original_owner = Pubkey::new_unique();
    let modified_owner = Pubkey::new_unique();

    let original = Account {
        lamports: 1_000_000,
        data: vec![1, 2, 3, 4],
        owner: original_owner,
        executable: false,
        rent_epoch: 0,
    };
    svm.set_account(pk, original.clone()).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    assert_eq!(initial.accounts()[&pk].owner, original_owner, "snapshot should capture original owner");

    let mutated = Account {
        lamports: 2_000_000,
        data: vec![9, 8, 7, 6],
        owner: modified_owner,
        executable: false,
        rent_epoch: 0,
    };
    svm.set_account(pk, mutated).unwrap();
    assert_eq!(svm.get_account(&pk).unwrap().owner, modified_owner, "SVM should have modified owner");

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk);
    let restored = initial.restore(&mut svm, &dirty);
    assert_eq!(restored, 1);

    let got = svm.get_account(&pk).unwrap();
    assert_eq!(got.owner, original_owner, "owner must be restored to original");
    assert_eq!(got.lamports, 1_000_000, "lamports must be restored");
    assert_eq!(got.data, vec![1, 2, 3, 4], "data must be restored");
}

// Test 11: Account with zero-length data vs account with data=[0,0,0]
#[test]
fn test_snapshot_distinguishes_empty_vs_zero_data() {
    let mut svm = LiteSVM::new();
    let pk_empty = Pubkey::new_unique();
    let pk_zeros = Pubkey::new_unique();

    svm.set_account(pk_empty, make_account(1_000_000, &[])).unwrap();
    svm.set_account(pk_zeros, make_account(1_000_000, &[0, 0, 0])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_empty, pk_zeros].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let snap_empty = &initial.accounts()[&pk_empty];
    let snap_zeros = &initial.accounts()[&pk_zeros];
    assert_eq!(snap_empty.data.len(), 0, "empty account should have zero-length data");
    assert_eq!(snap_zeros.data.len(), 3, "zeros account should have 3-byte data");
    assert_eq!(snap_zeros.data, vec![0, 0, 0]);

    svm.set_account(pk_empty, make_account(1_000_000, &[0, 0, 0])).unwrap();
    svm.set_account(pk_zeros, make_account(1_000_000, &[])).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_empty);
    dirty.mark_account_dirty(&pk_zeros);
    initial.restore(&mut svm, &dirty);

    let _got_empty = svm.get_account(&pk_empty).unwrap();
    let got_zeros = svm.get_account(&pk_zeros).unwrap();

    assert_eq!(snap_empty.data.len(), 0, "snapshot preserved empty data length");
    assert_eq!(snap_zeros.data, vec![0u8, 0, 0], "snapshot preserved zero-byte data");

    assert_eq!(got_zeros.data, vec![0u8, 0, 0], "restored pk_zeros should have 3 zero bytes");
}

// Test 12: take_delta vs take_full asymmetry for tombstones
#[test]
fn test_take_delta_keeps_tombstone_take_full_removes_it() {
    let mut svm = LiteSVM::new();
    let pk_gone = Pubkey::new_unique();
    let pk_base = Pubkey::new_unique();

    svm.set_account(pk_gone, make_account(1_000_000, &[0xAA])).unwrap();
    svm.set_account(pk_base, make_account(500, &[0xBB])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_gone, pk_base].into_iter().collect();
    let base = SvmSnapshot::take(&svm, &tracked);

    let _ = svm.set_account(pk_gone, Account { lamports: 0, ..Default::default() });

    let mut dirty_delta = DirtyTracker::new();
    dirty_delta.mark_account_dirty(&pk_gone);

    let empty_parent = SvmSnapshot::empty(svm.get_sysvar::<Clock>());
    let delta = SvmSnapshot::take_delta(&svm, &empty_parent, &dirty_delta);
    assert!(delta.accounts().contains_key(&pk_gone),
        "take_delta should include tombstone for deleted account");
    assert_eq!(delta.accounts()[&pk_gone].lamports, 0,
        "tombstone in delta should have lamports=0");

    let mut dirty_full = DirtyTracker::new();
    dirty_full.mark_account_dirty(&pk_gone);
    let full = SvmSnapshot::take_full(&svm, &base, &dirty_full);
    assert!(!full.accounts().contains_key(&pk_gone),
        "take_full should remove deleted account from snapshot, not keep tombstone");
    assert!(full.accounts().contains_key(&pk_base));
}

// Test 13: Restore count return value verification
#[test]
fn test_restore_selective_count_matches_actual_writes() {
    let mut svm = LiteSVM::new();

    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();
    let pk_d = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(100, &[1])).unwrap();
    svm.set_account(pk_b, make_account(200, &[2])).unwrap();
    svm.set_account(pk_c, make_account(300, &[3])).unwrap();
    svm.set_account(pk_d, make_account(400, &[4])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c, pk_d].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut delta_accounts: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
    delta_accounts.insert(pk_a, Arc::new(make_account(111, &[0xA1])));
    delta_accounts.insert(pk_b, Arc::new(make_account(222, &[0xB2])));
    let delta = SvmSnapshot { accounts: delta_accounts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_a);
    divergent.insert(pk_b);
    divergent.insert(pk_c);
    divergent.insert(pk_d);

    svm.set_account(pk_a, make_account(1, &[0xFF])).unwrap();
    svm.set_account(pk_b, make_account(1, &[0xFF])).unwrap();
    svm.set_account(pk_c, make_account(1, &[0xFF])).unwrap();
    svm.set_account(pk_d, make_account(1, &[0xFF])).unwrap();

    let count = initial.restore_selective(&mut svm, &divergent, &delta);

    assert_eq!(count, 4, "2 initial restores (pk_c, pk_d) + 2 delta writes (pk_a, pk_b) = 4");

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 111, "pk_a from delta");
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 222, "pk_b from delta");
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300, "pk_c from initial");
    assert_eq!(svm.get_account(&pk_d).unwrap().lamports, 400, "pk_d from initial");
}

// Test 14: Snapshot of account that exists in SVM but not in tracked set
#[test]
fn test_take_only_captures_tracked_accounts_not_all_svm_accounts() {
    let mut svm = LiteSVM::new();
    let pk_tracked = Pubkey::new_unique();
    let pk_untracked = Pubkey::new_unique();
    let pk_also_untracked = Pubkey::new_unique();

    svm.set_account(pk_tracked, make_account(100, &[1])).unwrap();
    svm.set_account(pk_untracked, make_account(200, &[2])).unwrap();
    svm.set_account(pk_also_untracked, make_account(300, &[3])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_tracked].into_iter().collect();
    let snap = SvmSnapshot::take(&svm, &tracked);

    assert_eq!(snap.account_count(), 1, "snapshot should only contain tracked accounts");
    assert!(snap.accounts().contains_key(&pk_tracked));
    assert!(!snap.accounts().contains_key(&pk_untracked),
        "untracked account should NOT be in snapshot");
    assert!(!snap.accounts().contains_key(&pk_also_untracked),
        "untracked account should NOT be in snapshot");

    svm.set_account(pk_tracked, make_account(999, &[0xFF])).unwrap();
    svm.set_account(pk_untracked, make_account(888, &[0xEE])).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_tracked);
    snap.restore(&mut svm, &dirty);

    assert_eq!(svm.get_account(&pk_tracked).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_untracked).unwrap().lamports, 888,
        "untracked account should not be touched by restore");
}

// Test 15: DirtyTracker with clock_dirty flag
#[test]
fn test_dirty_tracker_clock_flag_drives_clock_restore() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(1_000_000, &[0x01])).unwrap();

    let snapshot_clock = Clock {
        slot: 50,
        epoch: 2,
        unix_timestamp: 500,
        epoch_start_timestamp: 100,
        leader_schedule_epoch: 3,
    };
    svm.set_sysvar(&snapshot_clock);

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    assert_eq!(initial.clock().slot, 50);
    assert_eq!(initial.clock().epoch, 2);

    let delta_clock = Clock {
        slot: 200,
        epoch: 8,
        unix_timestamp: 2000,
        epoch_start_timestamp: 1500,
        leader_schedule_epoch: 9,
    };
    let delta = SvmSnapshot { accounts: FastHashMap::default(), sysvars: clock_to_sysvars(&delta_clock) };

    let current_clock = Clock {
        slot: 999,
        epoch: 99,
        unix_timestamp: 9999,
        epoch_start_timestamp: 8888,
        leader_schedule_epoch: 100,
    };
    svm.set_sysvar(&current_clock);
    assert_eq!(svm.get_sysvar::<Clock>().slot, 999);

    let divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut dirty = DirtyTracker::new();
    dirty.mark_clock_dirty();
    assert!(dirty.is_clock_dirty());

    initial.restore_selective(&mut svm, &divergent, &delta);

    let after = svm.get_sysvar::<Clock>();
    assert_eq!(after.slot, delta_clock.slot, "clock slot should be from delta");
    assert_eq!(after.epoch, delta_clock.epoch, "clock epoch should be from delta");
    assert_eq!(after.unix_timestamp, delta_clock.unix_timestamp, "clock timestamp should be from delta");

    let new_clock = Clock { slot: 77, epoch: 5, unix_timestamp: 700, ..snapshot_clock };
    svm.set_sysvar(&new_clock);

    initial.restore(&mut svm, &dirty);
    let after_restore = svm.get_sysvar::<Clock>();
    assert_eq!(after_restore.slot, 50, "restore() with clock_dirty should restore snapshot clock slot");
    assert_eq!(after_restore.epoch, 2, "restore() with clock_dirty should restore snapshot clock epoch");

    // All sysvars are now always restored regardless of clock_dirty flag
    let dirty_no_clock = DirtyTracker::new();

    let advanced_clock = Clock { slot: 888, ..snapshot_clock };
    svm.set_sysvar(&advanced_clock);

    initial.restore(&mut svm, &dirty_no_clock);
    let after_no_flag = svm.get_sysvar::<Clock>();
    assert_eq!(after_no_flag.slot, 50, "restore() always restores sysvars now");
}
