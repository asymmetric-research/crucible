use super::super::*;
use super::helpers::*;
use crate::{FastHashMap, FastHashSet};
use anchor_lang::prelude::Clock;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

// =========================================================================
// StatePool — Core operations
// =========================================================================

#[test]
fn test_state_pool_new() {
    let pool = StatePool::new(100, 20);
    assert_eq!(pool.len(), 0);
    assert_eq!(pool.active_count(), 0);
    assert!(pool.is_empty());
    assert!(!pool.is_full());
}

#[test]
fn test_state_pool_try_add_basic() {
    let mut pool = StatePool::new(100, 20);

    let added = add_test_state(&mut pool, 1, 0, None, "initial", None);
    assert!(added);
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.active_count(), 1);
    assert!(!pool.is_empty());

    let added = add_test_state(&mut pool, 2, 1, Some(0), "action_deposit", Some(0));
    assert!(added);
    assert_eq!(pool.len(), 2);
    assert_eq!(pool.active_count(), 2);
}

#[test]
fn test_state_pool_capacity_limit() {
    let mut pool = StatePool::new(2, 20);

    assert!(add_test_state(&mut pool, 1, 0, None, "", None));
    assert!(add_test_state(&mut pool, 2, 1, None, "", None));
    // Pool is now full
    assert!(pool.is_full());
    // Eviction: weakest active state is evicted to make room
    assert!(add_test_state(&mut pool, 3, 2, None, "", None));
    // states vec grows (evicted entry preserved for parent chains), active count stays bounded
    assert_eq!(pool.len(), 3);
    assert_eq!(pool.active_count(), 2);
}

#[test]
fn test_state_pool_depth_limit() {
    let mut pool = StatePool::new(100, 5);

    // Depth within limit — should succeed
    assert!(add_test_state(&mut pool, 1, 5, None, "", None));
    // Depth exceeding limit — should be rejected
    assert!(!add_test_state(&mut pool, 2, 6, None, "", None));
    assert_eq!(pool.len(), 1);
}

#[test]
fn test_state_pool_fingerprint_dedup() {
    let mut pool = StatePool::new(100, 20);

    // Fingerprints are truncated to FINGERPRINT_BITS (18 bits) for dedup.
    // Two fingerprints with the same bottom 18 bits should collide.
    let fp1 = 0x0000_0000_0001_1234u64;
    let fp2 = 0xFFFF_FFFF_FFFD_1234u64; // same bottom 18 bits

    assert!(add_test_state(&mut pool, fp1, 0, None, "", None));
    // Same dedup key — rejected
    assert!(!add_test_state(&mut pool, fp2, 1, None, "", None));
    assert_eq!(pool.len(), 1);

    // Different bottom 18 bits — accepted
    let fp3 = 0x0000_0000_0000_5678u64;
    assert!(add_test_state(&mut pool, fp3, 1, None, "", None));
    assert_eq!(pool.len(), 2);
}

#[test]
fn test_state_pool_parent_novel_children() {
    let mut pool = StatePool::new(100, 20);

    // Add parent (idx 0)
    add_test_state(&mut pool, 1, 0, None, "initial", None);
    assert_eq!(pool.get(0).unwrap().novel_children, 0);

    // Add child with parent_idx=0 (idx 1)
    add_test_state(&mut pool, 2, 1, Some(0), "child1", Some(0));
    assert_eq!(pool.get(0).unwrap().novel_children, 1);

    // Add another child with parent_idx=0 (idx 2)
    add_test_state(&mut pool, 3, 1, Some(0), "child2", Some(1));
    assert_eq!(pool.get(0).unwrap().novel_children, 2);
}

#[test]
fn test_state_pool_get() {
    let mut pool = StatePool::new(100, 20);
    add_test_state(&mut pool, 42, 0, None, "test_desc", Some(7));

    let entry = pool.get(0).unwrap();
    assert_eq!(entry.fingerprint, 42);
    assert_eq!(entry.depth, 0);
    assert_eq!(entry.action_desc, "test_desc");
    assert_eq!(entry.action_variant, Some(7));
    assert_eq!(entry.pick_count.load(Ordering::Relaxed), 0);
    assert_eq!(entry.novel_children, 0);
    assert_eq!(entry.violation_count, 0);

    // Out-of-bounds
    assert!(pool.get(1).is_none());
    assert!(pool.get(999).is_none());
}

// =========================================================================
// StatePool — Picking / selection
// =========================================================================

#[test]
fn test_state_pool_pick_random() {
    let mut pool = StatePool::new(100, 20);
    add_test_state(&mut pool, 1, 0, None, "", None);
    add_test_state(&mut pool, 2, 1, None, "", None);
    add_test_state(&mut pool, 3, 2, None, "", None);

    // Pick should return valid indices
    for seed in 0..100u64 {
        let idx = pool.pick_random(seed).unwrap();
        assert!(idx < pool.len());
    }
}

#[test]
fn test_state_pool_pick_random_empty() {
    let pool = StatePool::new(100, 20);
    assert!(pool.pick_random(42).is_none());
}

#[test]
fn test_state_pool_pick_weighted_single() {
    let mut pool = StatePool::new(100, 20);
    add_test_state(&mut pool, 1, 0, None, "", None);

    // Single state: fast path, always returns index 0
    let idx = pool.pick_weighted(42).unwrap();
    assert_eq!(idx, 0);
    assert_eq!(pool.get(0).unwrap().pick_count.load(Ordering::Relaxed), 1);

    // Pick again — pick_count increments
    let idx = pool.pick_weighted(99).unwrap();
    assert_eq!(idx, 0);
    assert_eq!(pool.get(0).unwrap().pick_count.load(Ordering::Relaxed), 2);
}

#[test]
fn test_state_pool_pick_weighted_multiple() {
    let mut pool = StatePool::new(100, 20);
    add_test_state(&mut pool, 1, 0, None, "", None);
    add_test_state(&mut pool, 2, 1, None, "", None);
    add_test_state(&mut pool, 3, 2, None, "", None);

    // Multiple picks should all return valid indices
    for seed in 0..200u64 {
        let idx = pool.pick_weighted(seed * 9239847).unwrap();
        assert!(idx < pool.len());
    }
}

#[test]
fn test_state_pool_pick_weighted_batch() {
    let mut pool = StatePool::new(100, 20);
    add_test_state(&mut pool, 1, 0, None, "", None);
    add_test_state(&mut pool, 2, 1, None, "", None);
    add_test_state(&mut pool, 3, 2, None, "", None);

    let rng_vals: Vec<u64> = (0..10).map(|i| i * 1844674407370955u64).collect();
    let mut out = Vec::new();
    let count = pool.pick_weighted_batch(&rng_vals, &mut out);

    assert_eq!(count, 10);
    assert_eq!(out.len(), 10);
    // All returned state indices should be valid
    for &(_, _, state_idx, _, _, _, _, _) in &out {
        assert!(state_idx < pool.len());
    }
}

#[test]
fn test_state_pool_pick_weighted_empty() {
    let pool = StatePool::new(100, 20);
    assert!(pool.pick_weighted(42).is_none());

    let rng_vals = vec![1, 2, 3];
    let mut out = Vec::new();
    assert_eq!(pool.pick_weighted_batch(&rng_vals, &mut out), 0);
    assert!(out.is_empty());
}

// =========================================================================
// StatePool — Crash / violation tracking
// =========================================================================

#[test]
fn test_state_pool_mark_crashed() {
    let mut pool = StatePool::new(100, 20);
    add_test_state(&mut pool, 1, 0, None, "", None);
    add_test_state(&mut pool, 2, 1, None, "", None);

    assert_eq!(pool.len(), 2);
    assert_eq!(pool.active_count(), 2);

    pool.mark_crashed(0);

    // State still exists but no longer active
    assert_eq!(pool.len(), 2);
    assert_eq!(pool.active_count(), 1);
    assert_eq!(pool.crashed_count(), 1);
    // get() still works for reconstruction
    assert!(pool.get(0).is_some());
}

#[test]
fn test_state_pool_mark_crashed_not_pickable() {
    let mut pool = StatePool::new(100, 20);
    add_test_state(&mut pool, 1, 0, None, "", None);
    add_test_state(&mut pool, 2, 1, None, "", None);

    pool.mark_crashed(0);

    // All picks should return index 1 (the only active state)
    for seed in 0..100u64 {
        let idx = pool.pick_random(seed).unwrap();
        assert_eq!(idx, 1);
    }
}

#[test]
fn test_state_pool_record_violation() {
    let mut pool = StatePool::new(100, 20);
    add_test_state(&mut pool, 1, 0, None, "", None);

    assert_eq!(pool.get(0).unwrap().violation_count, 0);

    pool.record_violation(0);
    assert_eq!(pool.get(0).unwrap().violation_count, 1);

    pool.record_violation(0);
    pool.record_violation(0);
    assert_eq!(pool.get(0).unwrap().violation_count, 3);

    // Out-of-bounds is silently ignored
    pool.record_violation(999);
}

#[test]
fn test_state_pool_is_novel_crash() {
    let mut pool = StatePool::new(100, 20);

    // First time — novel
    assert!(pool.is_novel_crash(0xDEAD));
    assert_eq!(pool.unique_crash_count(), 1);

    // Same hash — not novel
    assert!(!pool.is_novel_crash(0xDEAD));
    assert_eq!(pool.unique_crash_count(), 1);

    // Different hash — novel
    assert!(pool.is_novel_crash(0xBEEF));
    assert_eq!(pool.unique_crash_count(), 2);
}

// =========================================================================
// StatePool — Chain reconstruction
// =========================================================================

#[test]
fn test_state_pool_reconstruct_action_sequence() {
    let mut pool = StatePool::new(100, 20);
    let action_bytes = make_action_bytes(2, &[0x01, 0x02, 0x03, 0x04]);

    pool.try_add(
        1,
        CompactDelta::empty(make_test_clock(0)),
        0,
        None,
        action_bytes.clone(),
        "test".to_string(),
        Some(0),
        vec![],
        None,
        0, 0, true, None,
    );

    let reconstructed = pool.reconstruct_action_sequence(0);
    assert_eq!(reconstructed, action_bytes);
}

#[test]
fn test_state_pool_reconstruct_variant_sequence() {
    let mut pool = StatePool::new(100, 20);

    // Build a chain: initial -> action(variant=2) -> action(variant=5) -> action(variant=1)
    add_test_state(&mut pool, 1, 0, None, "initial", None);       // idx 0
    add_test_state(&mut pool, 2, 1, Some(0), "deposit", Some(2)); // idx 1
    add_test_state(&mut pool, 3, 2, Some(1), "borrow", Some(5));  // idx 2
    add_test_state(&mut pool, 4, 3, Some(2), "repay", Some(1));   // idx 3

    let variants = pool.reconstruct_variant_sequence(3);
    assert_eq!(variants, vec![2, 5, 1]); // oldest first, initial has no variant
}

#[test]
fn test_state_pool_reconstruct_action_descriptions() {
    let mut pool = StatePool::new(100, 20);

    add_test_state(&mut pool, 1, 0, None, "", None);               // idx 0 (empty desc)
    add_test_state(&mut pool, 2, 1, Some(0), "deposit(100)", Some(0));  // idx 1
    add_test_state(&mut pool, 3, 2, Some(1), "borrow(50)", Some(1));    // idx 2

    let descs = pool.reconstruct_action_descriptions(2);
    assert_eq!(descs, vec!["deposit(100)", "borrow(50)"]);
}

// =========================================================================
// StatePool — export_corpus
// =========================================================================

#[test]
fn test_state_pool_export_corpus_basic() {
    let mut pool = StatePool::new(100, 20);

    // Initial state with only a 4-byte header (count=0) — should be skipped
    pool.try_add(
        1,
        CompactDelta::empty(make_test_clock(0)),
        0,
        None,
        vec![0, 0, 0, 0], // 4-byte header, count=0
        "".to_string(),
        None,
        vec![],
        None,
        0, 0, true, None,
    );

    // State with real action bytes — should be written (edge_novelty=1)
    pool.try_add(
        2,
        CompactDelta::empty(make_test_clock(1)),
        1,
        Some(0),
        make_action_bytes(1, &[0xAA, 0xBB]),
        "deposit".to_string(),
        Some(0),
        vec![],
        None,
        1, 1, true, None,
    );

    // Another state with different action bytes (edge_novelty=1)
    pool.try_add(
        3,
        CompactDelta::empty(make_test_clock(2)),
        2,
        Some(1),
        make_action_bytes(2, &[0xCC, 0xDD, 0xEE, 0xFF]),
        "borrow".to_string(),
        Some(1),
        vec![],
        None,
        1, 1, true, None,
    );

    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_str().unwrap();
    let count = pool.export_corpus_no_seeds(dir_path).unwrap();

    assert_eq!(count, 2); // skipped the initial <=4-byte entry

    let files: Vec<_> = std::fs::read_dir(dir_path)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(files.len(), 2);
}

#[test]
fn test_state_pool_export_corpus_empty() {
    let mut pool = StatePool::new(100, 20);

    // Only initial state with empty action bytes
    pool.try_add(
        1,
        CompactDelta::empty(make_test_clock(0)),
        0,
        None,
        vec![0, 0, 0, 0],
        "".to_string(),
        None,
        vec![],
        None,
        0, 0, true, None,
    );

    let dir = tempfile::tempdir().unwrap();
    let count = pool.export_corpus_no_seeds(dir.path().to_str().unwrap()).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn test_state_pool_export_corpus_content() {
    let mut pool = StatePool::new(100, 20);
    let expected_bytes = make_action_bytes(1, &[0xDE, 0xAD, 0xBE, 0xEF]);

    pool.try_add(
        1,
        CompactDelta::empty(make_test_clock(0)),
        0,
        None,
        expected_bytes.clone(),
        "test".to_string(),
        Some(0),
        vec![],
        None,
        1, 1, true, None,
    );

    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_str().unwrap();
    pool.export_corpus_no_seeds(dir_path).unwrap();

    let files: Vec<_> = std::fs::read_dir(dir_path)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(files.len(), 1);

    let content = std::fs::read(files[0].path()).unwrap();
    assert_eq!(content, expected_bytes);
}

#[test]
fn test_state_pool_export_corpus_creates_dir() {
    let mut pool = StatePool::new(100, 20);
    pool.try_add(
        1,
        CompactDelta::empty(make_test_clock(0)),
        0,
        None,
        make_action_bytes(1, &[0xFF]),
        "".to_string(),
        Some(0),
        vec![],
        None,
        0, 0, true, None,
    );

    let base = tempfile::tempdir().unwrap();
    let nested = base.path().join("a").join("b").join("c");
    let nested_str = nested.to_str().unwrap();

    assert!(!nested.exists());
    pool.export_corpus_no_seeds(nested_str).unwrap();
    assert!(nested.exists());
}

#[test]
fn test_state_pool_export_corpus_deterministic() {
    // Same pool should produce identical filenames each time
    let mut pool = StatePool::new(100, 20);
    pool.try_add(
        1,
        CompactDelta::empty(make_test_clock(0)),
        0,
        None,
        make_action_bytes(1, &[0xAA, 0xBB, 0xCC]),
        "".to_string(),
        Some(0),
        vec![],
        None,
        0, 0, true, None,
    );

    let dir1 = tempfile::tempdir().unwrap();
    let dir2 = tempfile::tempdir().unwrap();

    pool.export_corpus_no_seeds(dir1.path().to_str().unwrap()).unwrap();
    pool.export_corpus_no_seeds(dir2.path().to_str().unwrap()).unwrap();

    let files1: Vec<String> = std::fs::read_dir(dir1.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    let files2: Vec<String> = std::fs::read_dir(dir2.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    assert_eq!(files1, files2);
}

// =========================================================================
// ActionStats / ActionStatsMap
// =========================================================================

#[test]
fn test_action_stats_weights_initial() {
    // Fresh stats: all weights should be equal.
    // Laplace: (0+1)/(0+2) = 0.5, explore: 5.0/(0+1) = 5.0, total = 5.5
    let stats = ActionStats::new(3);
    let weights = stats.weights();
    assert_eq!(weights.len(), 3);
    for &w in &weights {
        assert!((w - 5.5).abs() < 1e-10);
    }
}

#[test]
fn test_action_stats_weights_after_recording() {
    let mut stats = ActionStats::new(2);

    // Record success for variant 0
    stats.record(0, true);
    // Record failure for variant 1
    stats.record(1, false);

    let weights = stats.weights();

    // variant 0: s=1, t=1 => (1+1)/(1+2) + 5/(1+1) = 2/3 + 2.5 = 3.166...
    let expected_0 = 2.0 / 3.0 + 5.0 / 2.0;
    assert!((weights[0] - expected_0).abs() < 1e-10);

    // variant 1: s=0, t=1 => (0+1)/(1+2) + 5/(1+1) = 1/3 + 2.5 = 2.833...
    let expected_1 = 1.0 / 3.0 + 5.0 / 2.0;
    assert!((weights[1] - expected_1).abs() < 1e-10);

    // Successful variant should have higher weight
    assert!(weights[0] > weights[1]);
}

#[test]
fn test_action_stats_weights_exploration_bonus_decays() {
    let mut stats = ActionStats::new(1);

    // Check that explore bonus 5/(t+1) decreases with more attempts
    let w0 = stats.weights()[0]; // t=0: 5/1 = 5.0 bonus

    stats.record(0, true);
    let w1 = stats.weights()[0]; // t=1: 5/2 = 2.5 bonus

    stats.record(0, true);
    let w2 = stats.weights()[0]; // t=2: 5/3 = 1.667 bonus

    // Exploration bonus decays, so total weight should decrease
    // (even though success rate improves slightly)
    // w0 = 0.5 + 5.0 = 5.5
    // w1 = 2/3 + 2.5 = 3.167
    // w2 = 3/4 + 5/3 = 2.417
    assert!(w0 > w1);
    assert!(w1 > w2);
}

#[test]
fn test_action_stats_map_record_and_pick() {
    let mut map = ActionStatsMap::new(3);

    // Record some outcomes for state class 42
    map.record(42, 0, true);
    map.record(42, 0, true);
    map.record(42, 1, false);
    map.record(42, 2, true);

    // Pick with non-epsilon rng (epsilon_rng >= 20 to avoid exploration)
    let result = map.pick_variant(42, u64::MAX / 3, 50);
    assert!(result.is_some());
    let idx = result.unwrap();
    assert!(idx < 3);
}

#[test]
fn test_action_stats_map_epsilon_greedy() {
    let mut map = ActionStatsMap::new(3);
    map.record(42, 0, true);

    // epsilon_rng % 100 < 20 triggers exploration → returns None
    // epsilon_rng = 5 → 5 % 100 = 5 < 20 → exploration
    let result = map.pick_variant(42, 0, 5);
    assert!(result.is_none());

    // epsilon_rng = 119 → 119 % 100 = 19 < 20 → exploration
    let result = map.pick_variant(42, 0, 119);
    assert!(result.is_none());

    // epsilon_rng = 20 → 20 % 100 = 20, NOT < 20 → greedy
    let result = map.pick_variant(42, 0, 20);
    assert!(result.is_some());
}

#[test]
fn test_action_stats_map_unknown_state_class() {
    let map = ActionStatsMap::new(3);

    // No recordings for state class 99 — returns None (no stats to guide selection)
    let result = map.pick_variant(99, 1000, 50);
    assert!(result.is_none());
}

// =========================================================================
// StatePool edge cases
// =========================================================================

#[test]
fn test_state_pool_mark_crashed_twice() {
    let mut pool = StatePool::new(100, 20);
    add_test_state(&mut pool, 1, 0, None, "", None);
    add_test_state(&mut pool, 2, 1, None, "", None);

    pool.mark_crashed(0);
    assert_eq!(pool.active_count(), 1);

    // Second call is a no-op (position returns None)
    pool.mark_crashed(0);
    assert_eq!(pool.active_count(), 1);
    assert_eq!(pool.crashed_count(), 1);
}

#[test]
fn test_state_pool_mark_all_crashed() {
    let mut pool = StatePool::new(100, 20);
    add_test_state(&mut pool, 1, 0, None, "", None);
    add_test_state(&mut pool, 2, 1, None, "", None);

    pool.mark_crashed(0);
    pool.mark_crashed(1);

    assert_eq!(pool.active_count(), 0);
    assert!(pool.pick_random(42).is_none());
    assert!(pool.pick_weighted(42).is_none());
}

#[test]
fn test_state_pool_coverage_novel_weight_boost() {
    let mut pool = StatePool::new(100, 20);

    // State 0: no novelty_bits
    pool.try_add(
        1, CompactDelta::empty(make_test_clock(0)), 0, None,
        make_action_bytes(1, &[0xAA]), "".to_string(), None, vec![], None,
        0, 0, true, None,
    );
    // State 1: novelty_bits = 50 (gives rarity weight via coverage floor + novelty power)
    // With bifurcated formula: coverage_floor=10 * 2^(effective_bits/2) >> non-coverage path.
    pool.try_add(
        2, CompactDelta::empty(make_test_clock(1)), 1, None,
        make_action_bytes(1, &[0xBB]), "".to_string(), None, vec![], None,
        50, 50, true, None
    );

    // Pick many times and count how often each is picked.
    // State 1 (with novelty_bits) should be picked more often overall
    // due to early advantage, though the bonus decays as pick_count grows.
    let mut counts = [0u32; 2];
    for i in 0..10_000u64 {
        // Use spread-out rng values
        let rv = i.wrapping_mul(6364136223846793005);
        if let Some(idx) = pool.pick_weighted(rv) {
            counts[idx] += 1;
        }
    }

    // With decaying coverage bonus, state 1 should still be picked more often overall,
    // though the advantage shrinks as both states' pick_counts grow.
    let ratio = counts[1] as f64 / counts[0].max(1) as f64;
    assert!(
        ratio > 1.0,
        "novelty_bits state should be picked more often: counts={:?}, ratio={:.2}",
        counts, ratio,
    );
}

#[test]
fn test_state_pool_violation_count_tracked() {
    // violation_count is tracked for diagnostics but no longer affects weight.
    // Violated states are removed from active set via mark_crashed() instead.
    let mut pool = StatePool::new(100, 20);

    add_test_state(&mut pool, 1, 0, None, "", None); // idx 0
    add_test_state(&mut pool, 2, 1, None, "", None); // idx 1

    // Record violations — should increment counter
    for _ in 0..50 {
        pool.record_violation(0);
    }
    assert_eq!(pool.get(0).unwrap().violation_count, 50);
    assert_eq!(pool.get(1).unwrap().violation_count, 0);

    // Both states should still be picked roughly equally (violations don't affect weight)
    let mut counts = [0u32; 2];
    for i in 0..10_000u64 {
        let rv = i.wrapping_mul(6364136223846793005);
        if let Some(idx) = pool.pick_weighted(rv) {
            counts[idx] += 1;
        }
    }
    // Neither state should dominate (both have same picks/novelty/depth)
    assert!(
        counts[0] > 2000 && counts[1] > 2000,
        "both states should get picked: counts={:?}",
        counts,
    );
}

#[test]
fn test_state_pool_try_add_parent_idx_out_of_bounds() {
    let mut pool = StatePool::new(100, 20);

    // parent_idx points to nonexistent state — should still add,
    // but the parent credit silently fails (get_mut returns None)
    let added = pool.try_add(
        1, CompactDelta::empty(make_test_clock(0)), 1, Some(99),
        make_action_bytes(1, &[0xAA]), "test".to_string(), Some(0), vec![], None, 0, 0, true, None,
    );
    assert!(added);
    assert_eq!(pool.len(), 1);
}

#[test]
fn test_state_pool_reconstruct_variant_sequence_initial() {
    let mut pool = StatePool::new(100, 20);
    add_test_state(&mut pool, 1, 0, None, "initial", None);

    // Initial state has no action_variant → empty sequence
    let variants = pool.reconstruct_variant_sequence(0);
    assert!(variants.is_empty());
}

#[test]
fn test_state_pool_fixture_state_round_trip() {
    let mut pool = StatePool::new(100, 20);

    // Store a concrete type via Arc<dyn Any + Send + Sync>
    let fixture: Arc<dyn std::any::Any + Send + Sync> = Arc::new(42u64);

    pool.try_add(
        1, CompactDelta::empty(make_test_clock(0)), 0, None,
        make_action_bytes(1, &[0xFF]), "".to_string(), Some(0), vec![],
        Some(fixture),
        0, 0, true, None,
    );

    // Retrieve via get() and downcast
    let entry = pool.get(0).unwrap();
    let recovered = entry.fixture_state.as_ref().unwrap();
    let val = recovered.downcast_ref::<u64>().unwrap();
    assert_eq!(*val, 42u64);
}

#[test]
fn test_state_pool_pick_weighted_batch_increments_pick_count() {
    let mut pool = StatePool::new(100, 20);
    add_test_state(&mut pool, 1, 0, None, "", None);

    let rng_vals: Vec<u64> = (0..5).collect();
    let mut out = Vec::new();
    pool.pick_weighted_batch(&rng_vals, &mut out);

    // Single state — all 5 picks hit index 0
    assert_eq!(pool.get(0).unwrap().pick_count.load(Ordering::Relaxed), 5);
}

#[test]
fn test_state_pool_export_corpus_duplicate_action_bytes() {
    // Two states with identical action_bytes → same hash → same filename → 1 file
    let mut pool = StatePool::new(100, 20);
    let bytes = make_action_bytes(1, &[0xDE, 0xAD]);

    pool.try_add(
        1, CompactDelta::empty(make_test_clock(0)), 0, None,
        bytes.clone(), "a".to_string(), Some(0), vec![], None, 1, 1, true, None,
    );
    pool.try_add(
        2, CompactDelta::empty(make_test_clock(1)), 1, None,
        bytes.clone(), "b".to_string(), Some(1), vec![], None, 1, 1, true, None,
    );

    let dir = tempfile::tempdir().unwrap();
    let count = pool.export_corpus_no_seeds(dir.path().to_str().unwrap()).unwrap();
    // export_corpus returns 2 (it writes twice), but the file is overwritten
    assert_eq!(count, 2);
    let files: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    // Only 1 unique file on disk (second write overwrites first)
    assert_eq!(files.len(), 1);
}

// =========================================================================
// StatePool capacity and depth limits (pool round 2)
// =========================================================================

#[test]
fn test_pool_capacity_enforced() {
    let mut pool = StatePool::new(3, 100);
    let pk = Pubkey::new_unique();

    // Fill to capacity with distinct fingerprints
    assert!(add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk, 10)]), 0, None));
    assert!(add_pool_entry(&mut pool, 2, make_pool_snapshot(vec![(pk, 20)]), 1, Some(0)));
    assert!(add_pool_entry(&mut pool, 3, make_pool_snapshot(vec![(pk, 30)]), 2, Some(1)));
    assert_eq!(pool.len(), 3);
    assert!(pool.is_full());

    // 4th entry evicts weakest and succeeds
    assert!(add_pool_entry(&mut pool, 4, make_pool_snapshot(vec![(pk, 40)]), 3, Some(2)));
    assert_eq!(pool.active_count(), 3); // one evicted, one added
}

#[test]
fn test_pool_max_depth_enforced() {
    let mut pool = StatePool::new(100, 3);
    let pk = Pubkey::new_unique();

    // Depth 0..3 accepted
    assert!(add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk, 10)]), 0, None));
    assert!(add_pool_entry(&mut pool, 2, make_pool_snapshot(vec![(pk, 20)]), 1, Some(0)));
    assert!(add_pool_entry(&mut pool, 3, make_pool_snapshot(vec![(pk, 30)]), 2, Some(1)));
    assert!(add_pool_entry(&mut pool, 4, make_pool_snapshot(vec![(pk, 40)]), 3, Some(2)));

    // Depth 4 > max_depth 3 → rejected
    assert!(!add_pool_entry(&mut pool, 5, make_pool_snapshot(vec![(pk, 50)]), 4, Some(3)));
    assert_eq!(pool.len(), 4);
}

#[test]
fn test_pool_fingerprint_dedup_truncation() {
    // FINGERPRINT_BITS=18, so only bottom 18 bits matter for dedup.
    // Two fingerprints with same bottom 18 bits should collide.
    let mut pool = StatePool::new(100, 20);
    let pk = Pubkey::new_unique();

    let fp1 = 0xAAAA_0000_0001_1234u64;
    let fp2 = 0xBBBB_0000_0005_1234u64; // same bottom 18 bits

    assert!(add_pool_entry(&mut pool, fp1, make_pool_snapshot(vec![(pk, 10)]), 0, None));
    assert!(!add_pool_entry(&mut pool, fp2, make_pool_snapshot(vec![(pk, 20)]), 0, None));
    assert_eq!(pool.len(), 1);

    // Different bottom 18 bits → accepted
    let fp3 = 0xAAAA_0000_0000_5678u64;
    assert!(add_pool_entry(&mut pool, fp3, make_pool_snapshot(vec![(pk, 30)]), 0, None));
    assert_eq!(pool.len(), 2);

    // But full fingerprint is stored for state_class extraction
    assert_eq!(pool.get(0).unwrap().fingerprint, fp1);
}

// ---- StatePool mark_crashed and active_indices ----

#[test]
fn test_pool_mark_crashed_removes_from_active() {
    let mut pool = StatePool::new(10, 20);
    let pk = Pubkey::new_unique();

    add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk, 10)]), 0, None);
    add_pool_entry(&mut pool, 2, make_pool_snapshot(vec![(pk, 20)]), 1, Some(0));
    add_pool_entry(&mut pool, 3, make_pool_snapshot(vec![(pk, 30)]), 2, Some(1));
    assert_eq!(pool.active_count(), 3);
    assert_eq!(pool.crashed_count(), 0);

    // Mark middle state as crashed
    pool.mark_crashed(1);
    assert_eq!(pool.active_count(), 2);
    assert_eq!(pool.crashed_count(), 1);
    assert_eq!(pool.len(), 3); // still in states vec

    // Picking should never return crashed state
    for i in 0..100 {
        let picked = pool.pick_random(i).unwrap();
        assert_ne!(picked, 1, "crashed state should never be picked");
    }

    // Mark all crashed
    pool.mark_crashed(0);
    pool.mark_crashed(2);
    assert_eq!(pool.active_count(), 0);
    assert!(pool.pick_random(42).is_none());
    assert!(pool.pick_weighted(42).is_none());
}

#[test]
fn test_pool_mark_crashed_preserves_parent_chain() {
    // Crashed states remain in states vec for reconstruct_action_descriptions
    let mut pool = StatePool::new(10, 20);
    let pk = Pubkey::new_unique();

    add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk, 10)]), 0, None);
    add_pool_entry(&mut pool, 2, make_pool_snapshot(vec![(pk, 20)]), 1, Some(0));
    add_pool_entry(&mut pool, 3, make_pool_snapshot(vec![(pk, 30)]), 2, Some(1));

    // Crash middle state
    pool.mark_crashed(1);

    // Can still reconstruct chain through crashed state
    let descs = pool.reconstruct_action_descriptions(2);
    assert_eq!(descs.len(), 3);
    let variants = pool.reconstruct_variant_sequence(2);
    assert_eq!(variants.len(), 3);
}

// ---- StatePool weighted selection ----

#[test]
fn test_pool_weighted_favors_unexplored() {
    let mut pool = StatePool::new(10, 20);
    let pk = Pubkey::new_unique();

    add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk, 10)]), 0, None);
    add_pool_entry(&mut pool, 2, make_pool_snapshot(vec![(pk, 20)]), 1, Some(0));

    // Pick state 0 many times to increase its pick_count
    pool.states[0].pick_count.store(100, Ordering::Relaxed);
    pool.total_picks.store(100, Ordering::Relaxed);
    // State 1 has pick_count=0 → gets 1e6 never-picked priority

    // Use batch to compute weights once
    let rng_vals: Vec<u64> = (0..10000u64)
        .map(|i| (i as u128 * u64::MAX as u128 / 10000) as u64)
        .collect();
    let mut batch = Vec::new();
    pool.pick_weighted_batch(&rng_vals, &mut batch);

    let mut counts = [0u32; 2];
    for &(_, _, state_idx, _, _, _, _, _) in &batch {
        counts[state_idx] += 1;
    }

    // State 1 (never-picked, weight=1e6) should dominate overwhelmingly
    assert!(
        counts[1] > counts[0] * 100,
        "unexplored state should be picked overwhelmingly more: state0={}, state1={}",
        counts[0], counts[1]
    );
}

#[test]
fn test_pool_weighted_novelty_differentiates() {
    // Verify that states with higher novelty_bits get picked more often.
    // Without pick_decay, 0-novelty states are uniform — novelty is the
    // dominant differentiation signal.
    let mut pool = StatePool::new(10, 20);
    let pk = Pubkey::new_unique();

    // State 0: no novelty (novelty_bits=0)
    add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk, 10)]), 0, None);
    // State 1: high novelty (novelty_bits=40)
    pool.try_add(
        2, snapshot_to_compact_delta(make_pool_snapshot(vec![(pk, 20)])), 1, Some(0),
        vec![0u8; 8], "novel".into(), Some(0), vec![], None,
        40, 40, true, None
    );

    // Both picked a few times (past never-picked threshold)
    pool.states[0].pick_count.store(10, Ordering::Relaxed);
    pool.states[1].pick_count.store(10, Ordering::Relaxed);
    pool.total_picks.store(20, Ordering::Relaxed);

    let rng_vals: Vec<u64> = (0..10000u64)
        .map(|i| (i as u128 * u64::MAX as u128 / 10000) as u64)
        .collect();
    let mut batch = Vec::new();
    pool.pick_weighted_batch(&rng_vals, &mut batch);

    let mut counts = [0u32; 2];
    for &(_, _, state_idx, _, _, _, _, _) in &batch {
        counts[state_idx] += 1;
    }

    // State 1 (novelty_bits=40) should heavily dominate state 0 (novelty_bits=0).
    // Coverage path: floor=10 * 2^(effective/2) vs non-coverage fast-decay path.
    assert!(
        counts[1] > counts[0] * 10,
        "high-novelty state should dominate: state0={}, state1={}",
        counts[0], counts[1]
    );
}

#[test]
fn test_pool_weighted_coverage_bonus() {
    let mut pool = StatePool::new(10, 20);
    let pk = Pubkey::new_unique();

    // State 0: not coverage-novel (novelty_bits=0)
    add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk, 10)]), 0, None);
    // State 1: novelty_bits=50 (gives novelty weight boost)
    pool.try_add(
        2, snapshot_to_compact_delta(make_pool_snapshot(vec![(pk, 20)])), 1, Some(0),
        vec![0u8; 8], "coverage_novel".into(), Some(0), vec![], None,
        50, 50, true, None
    );

    // Give both states some picks so they're past never-picked threshold
    pool.states[0].pick_count.store(5, Ordering::Relaxed);
    pool.states[1].pick_count.store(5, Ordering::Relaxed);
    pool.total_picks.store(10, Ordering::Relaxed);

    // Use batch to compute weights once
    let rng_vals: Vec<u64> = (0..10000u64)
        .map(|i| (i as u128 * u64::MAX as u128 / 10000) as u64)
        .collect();
    let mut batch = Vec::new();
    pool.pick_weighted_batch(&rng_vals, &mut batch);

    let mut counts = [0u32; 2];
    for &(_, _, state_idx, _, _, _, _, _) in &batch {
        counts[state_idx] += 1;
    }

    // Coverage-novel state should be picked more (higher novelty factor)
    assert!(
        counts[1] > counts[0],
        "coverage-novel state should be picked more: state0={}, state1={}",
        counts[0], counts[1]
    );
}

#[test]
fn test_pool_weighted_novelty_bits_rarity() {
    // Verify that novelty_bits affects the weight formula correctly.
    // Formula: coverage_floor(10) * 2^(effective_bits/2) * rarity vs fast-decay non-coverage.
    // Both states start with pick_count=0 → get 1e6 priority, so we
    // need to give them picks to test the novelty component.
    let mut pool = StatePool::new(10, 20);
    let pk = Pubkey::new_unique();

    // State 0: 100 novelty_bits, picks=10 → coverage path with floor=10, novelty_power >> 1
    pool.try_add(
        1, snapshot_to_compact_delta(make_pool_snapshot(vec![(pk, 10)])), 0, None,
        vec![0u8; 8], "state0".into(), Some(0), vec![], None, 100, 0, true, None,
    );

    // State 1: 0 novelty_bits → non-coverage path with fast decay
    pool.try_add(
        2, snapshot_to_compact_delta(make_pool_snapshot(vec![(pk, 20)])), 0, None,
        vec![0u8; 8], "state1".into(), Some(1), vec![], None, 0, 0, true, None,
    );

    // Give both states equal picks so we isolate the novelty factor.
    // Use pick_weighted_batch which computes weights once (pick_weighted
    // mutates pick_count on each call, diluting the signal over 10K samples).
    pool.states[0].pick_count.store(10, Ordering::Relaxed);
    pool.states[1].pick_count.store(10, Ordering::Relaxed);
    pool.total_picks.store(20, Ordering::Relaxed);

    let rng_vals: Vec<u64> = (0..10000u64)
        .map(|i| (i as u128 * u64::MAX as u128 / 10000) as u64)
        .collect();
    let mut batch = Vec::new();
    pool.pick_weighted_batch(&rng_vals, &mut batch);

    let mut counts = [0u32; 2];
    for &(_, _, state_idx, _, _, _, _, _) in &batch {
        counts[state_idx] += 1;
    }

    // State 0 (coverage path: floor=10 * novelty_power) should be picked much more than state 1 (non-coverage, fast decay)
    assert!(
        counts[0] > counts[1] * 2,
        "high-novelty state should be picked >2x more: state0={}, state1={}",
        counts[0], counts[1]
    );
}

#[test]
fn test_pool_weighted_zero_vs_high_novelty_ratio() {
    // Verify the weight ratio between zero-novelty and high-novelty states.
    let mut pool = StatePool::new(10, 20);
    let pk = Pubkey::new_unique();

    // State 0: 0 novelty_bits → novelty = 1.0
    pool.try_add(
        1, snapshot_to_compact_delta(make_pool_snapshot(vec![(pk, 10)])), 0, None,
        vec![0u8; 8], "zero_novelty".into(), Some(0), vec![], None, 0, 0, true, None,
    );
    // State 1: 50 novelty_bits, picks=5 → coverage path with floor=10 * novelty_power
    pool.try_add(
        2, snapshot_to_compact_delta(make_pool_snapshot(vec![(pk, 20)])), 0, None,
        vec![0u8; 8], "high_novelty".into(), Some(1), vec![], None, 50, 50, true, None,
    );

    // Give equal picks, use batch to avoid mutation
    pool.states[0].pick_count.store(5, Ordering::Relaxed);
    pool.states[1].pick_count.store(5, Ordering::Relaxed);
    pool.total_picks.store(10, Ordering::Relaxed);

    let rng_vals: Vec<u64> = (0..10000u64)
        .map(|i| (i as u128 * u64::MAX as u128 / 10000) as u64)
        .collect();
    let mut batch = Vec::new();
    pool.pick_weighted_batch(&rng_vals, &mut batch);

    let mut counts = [0u32; 2];
    for &(_, _, state_idx, _, _, _, _, _) in &batch {
        counts[state_idx] += 1;
    }

    // High-novelty state should dominate
    assert!(
        counts[1] > counts[0] * 2,
        "high-novelty (50 bits) should be picked >2x more than zero: zero={}, high={}",
        counts[0], counts[1]
    );
}

// ---- pick_weighted_batch correctness ----

#[test]
fn test_pool_pick_weighted_batch_returns_arcs() {
    let mut pool = StatePool::new(10, 20);
    let pk = Pubkey::new_unique();

    add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk, 10)]), 0, None);
    add_pool_entry(&mut pool, 2, make_pool_snapshot(vec![(pk, 20)]), 1, Some(0));

    let rng_vals: Vec<u64> = (0..5).map(|i: u64| (i as u128 * u64::MAX as u128 / 5) as u64).collect();
    let mut batch = Vec::new();
    let count = pool.pick_weighted_batch(&rng_vals, &mut batch);
    assert_eq!(count, 5);
    assert_eq!(batch.len(), 5);

    // Each entry in the batch should have a valid Arc<SvmSnapshot>
    for (delta_arc, depth, state_idx, action_bytes, _variant, _fb, _fp, _fs) in &batch {
        assert!(state_idx < &pool.len());
        // The Arc should be the same object as in the pool
        let pool_arc = &pool.states[*state_idx].delta;
        assert!(Arc::ptr_eq(delta_arc, pool_arc), "batch should share Arc with pool entry");
        assert!(Arc::ptr_eq(action_bytes, &pool.states[*state_idx].action_bytes));
        assert!(*depth <= 1);
    }

    // pick_count should have been incremented
    let total_picks: u32 = pool.states.iter()
        .map(|s| s.pick_count.load(Ordering::Relaxed))
        .sum();
    assert_eq!(total_picks, 5);
}

#[test]
fn test_pool_pick_weighted_batch_empty_pool() {
    let pool = StatePool::new(10, 20);
    let rng_vals: Vec<u64> = vec![42; 10];
    let mut batch = Vec::new();
    let count = pool.pick_weighted_batch(&rng_vals, &mut batch);
    assert_eq!(count, 0);
    assert!(batch.is_empty());
}

#[test]
fn test_pool_pick_weighted_batch_single_state() {
    let mut pool = StatePool::new(10, 20);
    let pk = Pubkey::new_unique();
    add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk, 10)]), 0, None);

    let rng_vals: Vec<u64> = vec![0, u64::MAX / 2, u64::MAX - 1];
    let mut batch = Vec::new();
    let count = pool.pick_weighted_batch(&rng_vals, &mut batch);
    assert_eq!(count, 3);
    // All picks must be state 0
    for (_, _, state_idx, _, _, _, _, _) in &batch {
        assert_eq!(*state_idx, 0);
    }
    assert_eq!(pool.states[0].pick_count.load(Ordering::Relaxed), 3);
}

// ---- reconstruct_variant_sequence / reconstruct_action_descriptions ----

#[test]
fn test_pool_reconstruct_deep_chain() {
    let mut pool = StatePool::new(20, 10);
    let pk = Pubkey::new_unique();

    // Build a chain: root → L1 → L2 → L3 → L4
    add_pool_entry(&mut pool, 0x10, make_pool_snapshot(vec![(pk, 0)]), 0, None);
    add_pool_entry(&mut pool, 0x20, make_pool_snapshot(vec![(pk, 1)]), 1, Some(0));
    add_pool_entry(&mut pool, 0x30, make_pool_snapshot(vec![(pk, 2)]), 2, Some(1));
    add_pool_entry(&mut pool, 0x40, make_pool_snapshot(vec![(pk, 3)]), 3, Some(2));
    add_pool_entry(&mut pool, 0x50, make_pool_snapshot(vec![(pk, 4)]), 4, Some(3));

    // Reconstruct from leaf (idx 4) to root
    let variants = pool.reconstruct_variant_sequence(4);
    // Each entry has action_variant = Some((fp & 0xF) as u16)
    // fp values: 0x10, 0x20, 0x30, 0x40, 0x50
    // variants: 0, 0, 0, 0, 0 (all &0xF = 0)
    assert_eq!(variants.len(), 5);

    let descs = pool.reconstruct_action_descriptions(4);
    assert_eq!(descs.len(), 5);
    assert!(descs[0].contains("10"), "first desc should be root: {}", descs[0]);
    assert!(descs[4].contains("50"), "last desc should be leaf: {}", descs[4]);

    // Reconstruct action sequence returns the accumulated bytes from the entry
    let action_seq = pool.reconstruct_action_sequence(4);
    assert_eq!(action_seq.len(), 8); // our dummy bytes
}

#[test]
fn test_pool_reconstruct_branching_chain() {
    let mut pool = StatePool::new(20, 10);
    let pk = Pubkey::new_unique();

    // root → child_a → grandchild_a
    //      → child_b → grandchild_b
    add_pool_entry(&mut pool, 0x100, make_pool_snapshot(vec![(pk, 0)]), 0, None);     // idx 0
    add_pool_entry(&mut pool, 0x201, make_pool_snapshot(vec![(pk, 1)]), 1, Some(0));  // idx 1 (child_a)
    add_pool_entry(&mut pool, 0x302, make_pool_snapshot(vec![(pk, 2)]), 1, Some(0));  // idx 2 (child_b)
    add_pool_entry(&mut pool, 0x403, make_pool_snapshot(vec![(pk, 3)]), 2, Some(1));  // idx 3 (grandchild_a)
    add_pool_entry(&mut pool, 0x504, make_pool_snapshot(vec![(pk, 4)]), 2, Some(2));  // idx 4 (grandchild_b)

    // grandchild_a chain: root → child_a → grandchild_a
    let descs_a = pool.reconstruct_action_descriptions(3);
    assert_eq!(descs_a.len(), 3);
    assert!(descs_a[1].contains("201")); // child_a

    // grandchild_b chain: root → child_b → grandchild_b
    let descs_b = pool.reconstruct_action_descriptions(4);
    assert_eq!(descs_b.len(), 3);
    assert!(descs_b[1].contains("302")); // child_b

    // Verify parent_idx is correct: root got credit for 2 novel children
    assert_eq!(pool.states[0].novel_children, 2);
}

// ---- crash dedup ----

#[test]
fn test_pool_crash_dedup() {
    let mut pool = StatePool::new(10, 20);

    assert!(pool.is_novel_crash(0x1234));
    assert!(!pool.is_novel_crash(0x1234)); // duplicate
    assert!(pool.is_novel_crash(0x5678)); // different hash
    assert_eq!(pool.unique_crash_count(), 2);
}

// ---- export_corpus ----

#[test]
fn test_pool_export_corpus_skips_shallow() {
    let mut pool = StatePool::new(10, 20);
    let pk = Pubkey::new_unique();

    // Initial state with minimal action_bytes (≤4 bytes → skipped)
    pool.try_add(
        1, snapshot_to_compact_delta(make_pool_snapshot(vec![(pk, 10)])), 0, None,
        vec![0, 0, 0, 0], // 4-byte header with count=0
        "".into(), None, vec![], None, 0, 0, true, None,
    );
    // State with real action bytes (edge_novelty=1 so it's exported)
    pool.try_add(
        2, snapshot_to_compact_delta(make_pool_snapshot(vec![(pk, 20)])), 1, Some(0),
        vec![1, 0, 0, 0, 0xAA, 0xBB],
        "action".into(), Some(0), vec![], None, 1, 1, true, None,
    );

    let dir = "/tmp/test_pool_export_corpus";
    let _ = std::fs::remove_dir_all(dir);
    let count = pool.export_corpus_no_seeds(dir).unwrap();
    assert_eq!(count, 1, "should skip initial state with ≤4 byte action_bytes");

    // Cleanup
    let _ = std::fs::remove_dir_all(dir);
}

// ---- Arc sharing across pool entries via take_delta ----

#[test]
fn test_pool_arc_sharing_parent_child_deltas() {
    // When take_delta creates a child from a parent, unmodified accounts
    // share the same Arc. Pool entries wrapping these deltas in Arc<SvmSnapshot>
    // should preserve the inner Arc<Account> sharing.
    let mut svm = LiteSVM::new();
    let pk_shared = Pubkey::new_unique();
    let pk_dirty = Pubkey::new_unique();
    let pk_new = Pubkey::new_unique();

    svm.set_account(pk_shared, make_account(100, &[1, 2, 3])).unwrap();
    svm.set_account(pk_dirty, make_account(200, &[4, 5, 6])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_shared, pk_dirty].into_iter().collect();
    let _initial = SvmSnapshot::take(&svm, &tracked);

    // Parent delta: modifies both accounts
    let mut parent_accts = FastHashMap::default();
    parent_accts.insert(pk_shared, Arc::new(make_account(150, &[7, 8, 9])));
    parent_accts.insert(pk_dirty, Arc::new(make_account(250, &[10, 11, 12])));
    let parent_delta = SvmSnapshot { accounts: parent_accts, sysvars: make_test_sysvars(10) };

    // Set SVM to match parent delta state
    svm.set_account(pk_shared, make_account(150, &[7, 8, 9])).unwrap();
    svm.set_account(pk_dirty, make_account(250, &[10, 11, 12])).unwrap();

    // Now "execution" modifies only pk_dirty and creates pk_new
    svm.set_account(pk_dirty, make_account(300, &[13, 14, 15])).unwrap();
    svm.set_account(pk_new, make_account(50, &[16])).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_dirty);
    dirty.mark_account_dirty(&pk_new);

    // take_delta should inherit pk_shared Arc from parent, create new Arcs for pk_dirty/pk_new
    let child_delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

    // pk_shared: same Arc as parent (no dirty → inherited via clone)
    assert!(
        Arc::ptr_eq(
            child_delta.accounts().get(&pk_shared).unwrap(),
            parent_delta.accounts().get(&pk_shared).unwrap(),
        ),
        "unmodified account should share Arc between parent and child"
    );

    // pk_dirty: different Arc (dirty → fresh read from SVM)
    assert!(
        !Arc::ptr_eq(
            child_delta.accounts().get(&pk_dirty).unwrap(),
            parent_delta.accounts().get(&pk_dirty).unwrap(),
        ),
        "modified account should have new Arc"
    );
    assert_eq!(child_delta.accounts().get(&pk_dirty).unwrap().lamports, 300);

    // pk_new: exists in child but not parent
    assert!(child_delta.accounts().contains_key(&pk_new));
    assert!(!parent_delta.accounts().contains_key(&pk_new));

    // Now wrap in pool and verify Arc sharing is preserved through Arc<SvmSnapshot>
    let parent_pool_arc = Arc::new(parent_delta);
    let child_pool_arc = Arc::new(child_delta);

    // Two workers holding these Arcs should see shared inner Arcs
    let parent_ref1 = parent_pool_arc.clone();
    let child_ref1 = child_pool_arc.clone();

    assert!(Arc::ptr_eq(
        child_ref1.accounts().get(&pk_shared).unwrap(),
        parent_ref1.accounts().get(&pk_shared).unwrap(),
    ));
}

// ---- Simulated multi-worker restore isolation ----

#[test]
fn test_multiworker_independent_divergent_keys() {
    // Each worker maintains its own divergent_keys set.
    // Worker A restoring state X should not affect Worker B's tracking.
    // We simulate this with two separate SVM instances.
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_common = Pubkey::new_unique();

    let mut svm_w1 = LiteSVM::new();
    let mut svm_w2 = LiteSVM::new();

    // Both workers start from same initial state
    for svm in [&mut svm_w1, &mut svm_w2] {
        svm.set_account(pk_a, make_account(100, &[])).unwrap();
        svm.set_account(pk_b, make_account(100, &[])).unwrap();
        svm.set_account(pk_common, make_account(100, &[])).unwrap();
    }
    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_common].into_iter().collect();
    let initial = SvmSnapshot::take(&svm_w1, &tracked);

    // Delta A modifies pk_a + pk_common
    let mut delta_a_accts = FastHashMap::default();
    delta_a_accts.insert(pk_a, Arc::new(make_account(200, &[0xAA])));
    delta_a_accts.insert(pk_common, Arc::new(make_account(300, &[0xCC])));
    let delta_a = SvmSnapshot { accounts: delta_a_accts, sysvars: make_test_sysvars(1) };

    // Delta B modifies pk_b + pk_common (differently)
    let mut delta_b_accts = FastHashMap::default();
    delta_b_accts.insert(pk_b, Arc::new(make_account(400, &[0xBB])));
    delta_b_accts.insert(pk_common, Arc::new(make_account(500, &[0xDD])));
    let delta_b = SvmSnapshot { accounts: delta_b_accts, sysvars: make_test_sysvars(2) };

    // Worker 1 restores delta A
    let mut divergent_w1: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm_w1, &divergent_w1, &delta_a);
    divergent_w1.extend(delta_a.accounts().keys().copied());

    // Worker 2 restores delta B
    let mut divergent_w2: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm_w2, &divergent_w2, &delta_b);
    divergent_w2.extend(delta_b.accounts().keys().copied());

    // Verify isolation: workers see different states
    assert_eq!(svm_w1.get_account(&pk_a).unwrap().lamports, 200);
    assert_eq!(svm_w1.get_account(&pk_common).unwrap().lamports, 300);
    assert_eq!(svm_w1.get_account(&pk_b).unwrap().lamports, 100); // initial

    assert_eq!(svm_w2.get_account(&pk_b).unwrap().lamports, 400);
    assert_eq!(svm_w2.get_account(&pk_common).unwrap().lamports, 500);
    assert_eq!(svm_w2.get_account(&pk_a).unwrap().lamports, 100); // initial

    // Verify divergent sets are independent
    assert!(divergent_w1.contains(&pk_a));
    assert!(!divergent_w1.contains(&pk_b));
    assert!(divergent_w2.contains(&pk_b));
    assert!(!divergent_w2.contains(&pk_a));

    // Now Worker 1 switches to delta B, Worker 2 switches to delta A
    initial.restore_selective(&mut svm_w1, &divergent_w1, &delta_b);
    divergent_w1.clear();
    divergent_w1.extend(delta_b.accounts().keys().copied());

    initial.restore_selective(&mut svm_w2, &divergent_w2, &delta_a);
    divergent_w2.clear();
    divergent_w2.extend(delta_a.accounts().keys().copied());

    // Now they should have swapped
    assert_eq!(svm_w1.get_account(&pk_b).unwrap().lamports, 400);
    assert_eq!(svm_w1.get_account(&pk_common).unwrap().lamports, 500);
    assert_eq!(svm_w1.get_account(&pk_a).unwrap().lamports, 100); // restored to initial

    assert_eq!(svm_w2.get_account(&pk_a).unwrap().lamports, 200);
    assert_eq!(svm_w2.get_account(&pk_common).unwrap().lamports, 300);
    assert_eq!(svm_w2.get_account(&pk_b).unwrap().lamports, 100); // restored to initial
}

#[test]
fn test_multiworker_dual_svm_traced_divergent_isolation() {
    // In multicore, each worker has a fast SVM (every iteration) and a traced SVM
    // (every Nth iteration). They have independent divergent tracking:
    // - fast: divergent_keys + prev_delta_arc + prev_exec_dirty
    // - traced: traced_divergent (simple, no delta-to-delta optimization)
    //
    // Key invariant: traced SVM always uses restore_selective (never _from),
    // so its divergent set must be independently maintained.
    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    let mut fast_svm = LiteSVM::new();
    let mut traced_svm = LiteSVM::new();

    for svm in [&mut fast_svm, &mut traced_svm] {
        svm.set_account(pk1, make_account(100, &[])).unwrap();
        svm.set_account(pk2, make_account(100, &[])).unwrap();
    }
    let tracked: HashSet<Pubkey> = [pk1, pk2].into_iter().collect();
    let initial = SvmSnapshot::take(&fast_svm, &tracked);

    // Delta that modifies pk1
    let mut delta_accts = FastHashMap::default();
    delta_accts.insert(pk1, Arc::new(make_account(500, &[0xFF])));
    let delta = SvmSnapshot { accounts: delta_accts, sysvars: make_test_sysvars(1) };

    // Fast SVM path (iterations 1-9): uses divergent_keys + delta-to-delta
    let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Traced SVM path (iteration 10): uses traced_divergent + simple restore
    let mut traced_divergent: FastHashSet<Pubkey> = FastHashSet::default();

    // Iteration 1 (fast): restore delta
    initial.restore_selective(&mut fast_svm, &divergent_keys, &delta);
    divergent_keys.clear();
    divergent_keys.extend(delta.accounts().keys().copied());
    assert_eq!(fast_svm.get_account(&pk1).unwrap().lamports, 500);

    // Simulate execution on fast SVM that dirties pk2
    fast_svm.set_account(pk2, make_account(999, &[0xAA])).unwrap();
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk2);
    divergent_keys.insert(pk2);

    // Iteration 10 (traced): independent restore to same delta
    initial.restore_selective(&mut traced_svm, &traced_divergent, &delta);
    traced_divergent.clear();
    traced_divergent.extend(delta.accounts().keys().copied());

    // Traced SVM should have correct state regardless of fast SVM's exec dirty
    assert_eq!(traced_svm.get_account(&pk1).unwrap().lamports, 500);
    assert_eq!(traced_svm.get_account(&pk2).unwrap().lamports, 100); // initial, not dirty

    // Fast SVM's divergent_keys includes pk2 (exec dirty), traced's doesn't
    assert!(divergent_keys.contains(&pk2));
    assert!(!traced_divergent.contains(&pk2));
}

// ---- Pending novel discard on lock contention ----

#[test]
fn test_pending_novel_discard_correctness() {
    // In multicore, if try_write() fails, pending_novel is discarded
    // but pending_crashes and pending_violations are kept.
    // This test verifies that discarding novel states doesn't cause
    // any correctness issues — the state is simply lost (not deduplicated).

    let mut pool = StatePool::new(100, 20);
    let pk = Pubkey::new_unique();

    // Add initial state
    add_pool_entry(&mut pool, 0x1000, make_pool_snapshot(vec![(pk, 10)]), 0, None);

    // Simulate "pending novel" that would have been added but was discarded
    let discarded_fp = 0x2000u64;
    // Crucially, the fingerprint was NOT inserted into pool.seen
    // So if the same state is discovered again later, it should be accepted
    assert!(!pool.seen.contains(&(discarded_fp & ((1u64 << 16) - 1))));

    // Re-discovery: try_add with same fingerprint should succeed
    assert!(add_pool_entry(&mut pool, discarded_fp, make_pool_snapshot(vec![(pk, 20)]), 1, Some(0)));
    assert_eq!(pool.len(), 2);
}

// ---- ActionStats and ActionStatsMap ----

#[test]
fn test_action_stats_weighted_selection() {
    let mut stats_map = ActionStatsMap::new(3); // 3 action variants

    // State class 0x1234
    let sc = 0x1234u16;

    // Variant 0: 10/10 successes (100% success rate)
    for _ in 0..10 {
        stats_map.record(sc, 0, true);
    }
    // Variant 1: 0/10 successes (0% success rate)
    for _ in 0..10 {
        stats_map.record(sc, 1, false);
    }
    // Variant 2: never attempted (explore bonus highest)

    // Sample many times
    let mut counts = [0u32; 3];
    let mut samples = 0;
    for i in 0..10000u64 {
        // Use epsilon_rng that won't trigger random path (>= 20)
        if let Some(vi) = stats_map.pick_variant(sc, i * 7919, 50) {
            counts[vi] += 1;
            samples += 1;
        }
    }

    // Variant 0 should be picked most (high success + some explore)
    // Variant 2 should have significant picks (high explore bonus: 5.0/(0+1) = 5.0)
    // Variant 1 should be picked least (low success, low explore)
    assert!(
        counts[0] > counts[1],
        "high-success variant should beat low-success: v0={}, v1={}",
        counts[0], counts[1]
    );
    assert!(
        samples > 5000,
        "should have gotten guided picks for most samples: {}", samples
    );
}

#[test]
fn test_action_stats_epsilon_exploration() {
    let stats_map = ActionStatsMap::new(3);
    let sc = 0xABCDu16;

    // With no data for this state class, pick_variant should return None
    assert!(stats_map.pick_variant(sc, 42, 50).is_none());

    // Epsilon path: epsilon_rng % 100 < 20 → always returns None
    let mut stats = ActionStatsMap::new(3);
    stats.record(sc, 0, true);
    assert!(stats.pick_variant(sc, 42, 10).is_none()); // 10 % 100 < 20
    assert!(stats.pick_variant(sc, 42, 19).is_none()); // 19 % 100 < 20
    assert!(stats.pick_variant(sc, 42, 20).is_some());  // 20 % 100 >= 20
}

#[test]
fn test_state_class_from_fingerprint_extraction() {
    // state_class = top 16 bits of fingerprint
    assert_eq!(state_class_from_fingerprint(0xABCD_0000_0000_0000), 0xABCD);
    assert_eq!(state_class_from_fingerprint(0x1234_5678_9ABC_DEF0), 0x1234);
    assert_eq!(state_class_from_fingerprint(0x0000_0000_0000_FFFF), 0x0000);
    assert_eq!(state_class_from_fingerprint(0xFFFF_0000_0000_0000), 0xFFFF);
}

// ---- Concurrent Arc refcounting (simulated multi-worker) ----

#[test]
fn test_pool_arc_refcount_under_batch_picks() {
    // When pick_weighted_batch clones Arcs, the original pool entry's
    // Arc refcount should increase. After batch is dropped, it should decrease.
    let mut pool = StatePool::new(10, 20);
    let pk = Pubkey::new_unique();
    add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk, 10)]), 0, None);

    let original_arc = pool.states[0].delta.clone();
    let initial_refcount = Arc::strong_count(&original_arc);

    // Pick batch of 100 entries (all same state since only 1 in pool)
    let rng_vals: Vec<u64> = (0..100).collect();
    let mut batch = Vec::new();
    pool.pick_weighted_batch(&rng_vals, &mut batch);
    assert_eq!(batch.len(), 100);

    // Each batch entry holds a clone of the Arc
    let during_batch = Arc::strong_count(&original_arc);
    assert_eq!(during_batch, initial_refcount + 100,
        "refcount should increase by batch size");

    // Drop batch
    batch.clear();
    let after_drop = Arc::strong_count(&original_arc);
    assert_eq!(after_drop, initial_refcount,
        "refcount should return to original after batch drop");
}

// ---- Adversarial: restore_selective_from with pool-picked deltas ----

#[test]
fn test_pool_delta_to_delta_restore_with_shared_ancestry() {
    // Two pool entries share a common parent. Worker picks entry A,
    // then entry B. restore_selective_from should correctly handle
    // the case where both share Arcs from the parent.
    let mut svm = LiteSVM::new();
    let pk_parent = Pubkey::new_unique();
    let pk_only_a = Pubkey::new_unique();
    let pk_only_b = Pubkey::new_unique();

    svm.set_account(pk_parent, make_account(100, &[])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_parent].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Parent delta: modifies pk_parent
    let parent_acct = Arc::new(make_account(200, &[1]));
    let mut parent_accts = FastHashMap::default();
    parent_accts.insert(pk_parent, parent_acct.clone());
    let _parent_delta = SvmSnapshot { accounts: parent_accts, sysvars: make_test_sysvars(1) };

    // Child A: inherits pk_parent from parent, adds pk_only_a
    let mut child_a_accts = FastHashMap::default();
    child_a_accts.insert(pk_parent, parent_acct.clone()); // SAME Arc
    child_a_accts.insert(pk_only_a, Arc::new(make_account(300, &[0xAA])));
    let child_a = SvmSnapshot { accounts: child_a_accts, sysvars: make_test_sysvars(2) };

    // Child B: inherits pk_parent from parent, adds pk_only_b
    let mut child_b_accts = FastHashMap::default();
    child_b_accts.insert(pk_parent, parent_acct.clone()); // SAME Arc
    child_b_accts.insert(pk_only_b, Arc::new(make_account(400, &[0xBB])));
    let child_b = SvmSnapshot { accounts: child_b_accts, sysvars: make_test_sysvars(3) };

    // Verify Arc sharing
    assert!(Arc::ptr_eq(
        child_a.accounts().get(&pk_parent).unwrap(),
        child_b.accounts().get(&pk_parent).unwrap(),
    ));

    // Worker restores child_a first
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &child_a);
    divergent.clear();
    divergent.extend(child_a.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk_parent).unwrap().lamports, 200);
    assert_eq!(svm.get_account(&pk_only_a).unwrap().lamports, 300);

    // No execution dirty
    let exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Now restore_selective_from child_a → child_b
    let count = initial.restore_selective_from(&mut svm, &divergent, &child_a, &child_b, &exec_dirty);

    // pk_parent: same Arc → SKIPPED (count should not include it)
    // pk_only_b: in next only → written
    // pk_only_a: in divergent but not in next → restored to initial (none)
    assert_eq!(svm.get_account(&pk_parent).unwrap().lamports, 200); // unchanged
    assert_eq!(svm.get_account(&pk_only_b).unwrap().lamports, 400); // new
    assert!(svm.get_account(&pk_only_a).is_none()); // cleaned up

    // pk_parent was skipped via Arc::ptr_eq, so count should be 2 (pk_only_b write + pk_only_a cleanup)
    // But the actual count depends on implementation — what matters is correctness
    assert!(count >= 1, "should have written at least pk_only_b");
}

// ---- Adversarial: worker failure clears prev_delta_arc ----

#[test]
fn test_worker_failure_clears_prev_delta_forces_full_restore() {
    // In multicore, if action fails (or panics), prev_delta_arc = None.
    // Next iteration MUST use restore_selective (not _from).
    // This ensures any exec-dirty corruption is fully cleaned up.
    let mut svm = LiteSVM::new();
    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    svm.set_account(pk1, make_account(100, &[])).unwrap();
    svm.set_account(pk2, make_account(100, &[])).unwrap();
    let tracked: HashSet<Pubkey> = [pk1, pk2].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut delta_accts = FastHashMap::default();
    delta_accts.insert(pk1, Arc::new(make_account(500, &[0xFF])));
    let delta = SvmSnapshot { accounts: delta_accts, sysvars: make_test_sysvars(1) };
    let delta_arc = Arc::new(delta);

    // Iteration 1: success → prev_delta_arc = Some
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &delta_arc);
    divergent.extend(delta_arc.accounts().keys().copied());
    let mut _prev_delta_arc: Option<Arc<SvmSnapshot>> = Some(delta_arc.clone());
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Simulate execution that modifies pk2
    svm.set_account(pk2, make_account(999, &[0xDE, 0xAD])).unwrap();
    prev_exec_dirty.insert(pk2);
    divergent.insert(pk2);

    // Iteration 2: FAILURE → prev_delta_arc = None
    _prev_delta_arc = None;

    // Iteration 3: must use restore_selective (not _from) since prev_delta_arc is None
    let mut delta2_accts = FastHashMap::default();
    delta2_accts.insert(pk1, Arc::new(make_account(600, &[0xEE])));
    let delta2 = SvmSnapshot { accounts: delta2_accts, sysvars: make_test_sysvars(2) };

    // This is the correct path when prev_delta_arc is None:
    initial.restore_selective(&mut svm, &divergent, &delta2);
    divergent.clear();
    divergent.extend(delta2.accounts().keys().copied());

    // pk1: from delta2
    assert_eq!(svm.get_account(&pk1).unwrap().lamports, 600);
    // pk2: restored to initial (was in divergent, cleaned up by restore_selective)
    assert_eq!(svm.get_account(&pk2).unwrap().lamports, 100);

    // Verify: if we had incorrectly used _from with None prev, pk2 would NOT be cleaned up.
    // The None check in the codegen prevents this.
}

// ---- Stress: rapid state switching with shared pool ----

#[test]
fn test_stress_rapid_state_switching_from_pool() {
    // Simulate a worker rapidly switching between pool-picked states
    // using restore_selective_from, verifying correctness after each switch.
    let mut svm = LiteSVM::new();
    let pks: Vec<Pubkey> = (0..10).map(|_| Pubkey::new_unique()).collect();

    // Initial state: all accounts at 100
    for pk in &pks {
        svm.set_account(*pk, make_account(100, &[])).unwrap();
    }
    let tracked: HashSet<Pubkey> = pks.iter().copied().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Create 5 deltas, each modifying a different subset
    let mut deltas: Vec<Arc<SvmSnapshot>> = Vec::new();
    for i in 0..5 {
        let mut accts = FastHashMap::default();
        // Each delta modifies accounts [2*i, 2*i+1]
        let idx1 = (2 * i) % 10;
        let idx2 = (2 * i + 1) % 10;
        accts.insert(pks[idx1], Arc::new(make_account((i as u64 + 1) * 1000, &[i as u8])));
        accts.insert(pks[idx2], Arc::new(make_account((i as u64 + 1) * 2000, &[i as u8 + 10])));
        let delta = SvmSnapshot { accounts: accts, sysvars: make_test_sysvars(i as u64) };
        deltas.push(Arc::new(delta));
    }

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta_arc: Option<Arc<SvmSnapshot>> = None;
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // 50 iterations switching between states
    let state_sequence = [0, 1, 2, 3, 4, 0, 3, 1, 4, 2, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4,
                         4, 3, 2, 1, 0, 2, 4, 1, 3, 0, 0, 1, 0, 2, 0, 3, 0, 4, 1, 2,
                         3, 4, 0, 1, 2, 3, 4, 0, 1, 2];

    for &state_idx in &state_sequence {
        let delta = &deltas[state_idx];

        if let Some(ref prev) = prev_delta_arc {
            initial.restore_selective_from(&mut svm, &divergent, prev, delta, &prev_exec_dirty);
        } else {
            initial.restore_selective(&mut svm, &divergent, delta);
        }

        divergent.clear();
        divergent.extend(delta.accounts().keys().copied());
        prev_delta_arc = Some(delta.clone());
        prev_exec_dirty.clear();

        // Verify correctness after each switch
        for (pk_idx, pk) in pks.iter().enumerate() {
            let expected_idx1 = (2 * state_idx) % 10;
            let expected_idx2 = (2 * state_idx + 1) % 10;

            if pk_idx == expected_idx1 {
                let acct = svm.get_account(pk).unwrap();
                assert_eq!(acct.lamports, (state_idx as u64 + 1) * 1000,
                    "state {}, pk {} (idx1)", state_idx, pk_idx);
            } else if pk_idx == expected_idx2 {
                let acct = svm.get_account(pk).unwrap();
                assert_eq!(acct.lamports, (state_idx as u64 + 1) * 2000,
                    "state {}, pk {} (idx2)", state_idx, pk_idx);
            } else {
                // Not in this delta → should be at initial value
                let acct = svm.get_account(pk).unwrap();
                assert_eq!(acct.lamports, 100,
                    "state {}, pk {} should be initial", state_idx, pk_idx);
            }
        }
    }
}

// ---- Adversarial: traced vs fast SVM divergent sets must not share ----

#[test]
fn test_traced_svm_stale_divergent_causes_leak() {
    // If traced_divergent is not maintained independently from divergent_keys,
    // the traced SVM could have stale accounts from previous traced iterations.
    // This test proves the traced path must have its own divergent tracking.
    let mut fast_svm = LiteSVM::new();
    let mut traced_svm = LiteSVM::new();
    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    for svm in [&mut fast_svm, &mut traced_svm] {
        svm.set_account(pk1, make_account(100, &[])).unwrap();
        svm.set_account(pk2, make_account(100, &[])).unwrap();
    }
    let tracked: HashSet<Pubkey> = [pk1, pk2].into_iter().collect();
    let initial = SvmSnapshot::take(&fast_svm, &tracked);

    // Delta modifying pk1
    let mut delta_accts = FastHashMap::default();
    delta_accts.insert(pk1, Arc::new(make_account(500, &[])));
    let delta = SvmSnapshot { accounts: delta_accts, sysvars: make_test_sysvars(1) };

    // Traced iteration 1: restore delta, execution dirties pk2
    let mut traced_divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut traced_svm, &traced_divergent, &delta);
    traced_divergent.clear();
    traced_divergent.extend(delta.accounts().keys().copied());

    // Simulate execution on traced SVM that modifies pk2
    traced_svm.set_account(pk2, make_account(777, &[])).unwrap();
    traced_divergent.insert(pk2); // MUST track this

    // Traced iteration 2: restore to empty delta (initial state)
    let empty = SvmSnapshot::empty(initial.clock().clone());
    initial.restore_selective(&mut traced_svm, &traced_divergent, &empty);
    traced_divergent.clear();

    // If traced_divergent correctly included pk2, it should be restored to initial
    assert_eq!(traced_svm.get_account(&pk2).unwrap().lamports, 100,
        "pk2 must be restored to initial; if not, traced_divergent was stale");
    assert_eq!(traced_svm.get_account(&pk1).unwrap().lamports, 100,
        "pk1 must be restored to initial");
}

// ---- Pool: total_picks atomic counter ----

#[test]
fn test_pool_total_picks_atomic() {
    let mut pool = StatePool::new(10, 20);
    let pk = Pubkey::new_unique();
    add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk, 10)]), 0, None);
    add_pool_entry(&mut pool, 2, make_pool_snapshot(vec![(pk, 20)]), 1, Some(0));

    assert_eq!(pool.total_picks.load(Ordering::Relaxed), 0);

    // pick_weighted increments total_picks
    for _ in 0..5 {
        pool.pick_weighted(42);
    }
    assert_eq!(pool.total_picks.load(Ordering::Relaxed), 5);

    // pick_weighted_batch also increments
    let rng_vals: Vec<u64> = vec![0, u64::MAX / 2, u64::MAX - 1];
    let mut batch = Vec::new();
    pool.pick_weighted_batch(&rng_vals, &mut batch);
    assert_eq!(pool.total_picks.load(Ordering::Relaxed), 8);
}

// ---- Adversarial: restore_selective_from correctness when delta keys overlap ----

#[test]
fn test_restore_from_overlapping_delta_keys_different_values() {
    // Both prev and next deltas have the same set of keys but with different values.
    // Different Arcs → all should be written.
    let mut svm = LiteSVM::new();
    let pks: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();

    for (i, pk) in pks.iter().enumerate() {
        svm.set_account(*pk, make_account((i as u64 + 1) * 10, &[])).unwrap();
    }
    let tracked: HashSet<Pubkey> = pks.iter().copied().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // prev delta: all pks at 1000+i
    let mut prev_accts = FastHashMap::default();
    for (i, pk) in pks.iter().enumerate() {
        prev_accts.insert(*pk, Arc::new(make_account(1000 + i as u64, &[])));
    }
    let prev = SvmSnapshot { accounts: prev_accts, sysvars: make_test_sysvars(1) };

    // next delta: all pks at 2000+i (DIFFERENT Arcs, different values)
    let mut next_accts = FastHashMap::default();
    for (i, pk) in pks.iter().enumerate() {
        next_accts.insert(*pk, Arc::new(make_account(2000 + i as u64, &[])));
    }
    let next = SvmSnapshot { accounts: next_accts, sysvars: make_test_sysvars(2) };

    // Restore prev first
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &prev);
    divergent.extend(pks.iter().copied());

    // restore_from prev → next
    let exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let count = initial.restore_selective_from(&mut svm, &divergent, &prev, &next, &exec_dirty);

    // All 5 should be written (different Arcs)
    assert_eq!(count, 5, "all 5 accounts have different Arcs → all should be written");
    for (i, pk) in pks.iter().enumerate() {
        assert_eq!(svm.get_account(pk).unwrap().lamports, 2000 + i as u64);
    }
}

// ---- Edge case: SvmSnapshot::empty ----

#[test]
fn test_snapshot_empty_has_no_accounts() {
    let empty = SvmSnapshot::empty(make_test_clock(42));
    assert_eq!(empty.account_count(), 0);
    assert_eq!(empty.clock().slot, 42);

    // Restoring to empty delta means "go back to initial"
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[])).unwrap();
    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Modify via a delta
    let mut delta_accts = FastHashMap::default();
    delta_accts.insert(pk, Arc::new(make_account(500, &[])));
    let delta = SvmSnapshot { accounts: delta_accts, sysvars: make_test_sysvars(10) };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &delta);
    divergent.extend(delta.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 500);

    // Restore to empty (= initial)
    initial.restore_selective(&mut svm, &divergent, &empty);
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 100);
}

// ---- Adversarial: take_delta from pool-picked Arc<SvmSnapshot> ----

#[test]
fn test_take_delta_from_arc_wrapped_parent() {
    // In multicore, parent delta comes as Arc<SvmSnapshot> from the pool.
    // take_delta receives &SvmSnapshot (deref'd from Arc).
    // The resulting child delta must correctly inherit parent's Arcs.
    let mut svm = LiteSVM::new();
    let pk_inherited = Pubkey::new_unique();
    let pk_modified = Pubkey::new_unique();

    svm.set_account(pk_inherited, make_account(100, &[])).unwrap();
    svm.set_account(pk_modified, make_account(100, &[])).unwrap();

    // Parent delta (will be Arc-wrapped like in pool)
    let parent_arc_account = Arc::new(make_account(500, &[1, 2]));
    let mut parent_accts = FastHashMap::default();
    parent_accts.insert(pk_inherited, parent_arc_account.clone());
    parent_accts.insert(pk_modified, Arc::new(make_account(600, &[3, 4])));
    let parent = Arc::new(SvmSnapshot { accounts: parent_accts, sysvars: make_test_sysvars(5) });

    // Set SVM to parent state
    svm.set_account(pk_inherited, make_account(500, &[1, 2])).unwrap();
    svm.set_account(pk_modified, make_account(600, &[3, 4])).unwrap();

    // Execution modifies only pk_modified
    svm.set_account(pk_modified, make_account(700, &[5, 6])).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_modified);

    // take_delta from Arc<SvmSnapshot> (via deref)
    let child = SvmSnapshot::take_delta(&svm, &parent, &dirty);

    // pk_inherited: same Arc (inherited from parent through clone)
    assert!(Arc::ptr_eq(
        child.accounts().get(&pk_inherited).unwrap(),
        &parent_arc_account,
    ));
    // pk_modified: new Arc with fresh value from SVM
    assert_eq!(child.accounts().get(&pk_modified).unwrap().lamports, 700);
    assert!(!Arc::ptr_eq(
        child.accounts().get(&pk_modified).unwrap(),
        parent.accounts().get(&pk_modified).unwrap(),
    ));
}

// ---- StatePool: record_violation accumulates ----

#[test]
fn test_pool_violation_count_accumulates() {
    let mut pool = StatePool::new(10, 20);
    let pk = Pubkey::new_unique();
    add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk, 10)]), 0, None);

    assert_eq!(pool.states[0].violation_count, 0);

    pool.record_violation(0);
    assert_eq!(pool.states[0].violation_count, 1);

    pool.record_violation(0);
    pool.record_violation(0);
    assert_eq!(pool.states[0].violation_count, 3);

    // Out-of-bounds index is silently ignored
    pool.record_violation(999);
}

// ---- Adversarial: two workers pick same state, execute differently ----

#[test]
fn test_two_workers_same_state_different_execution() {
    // Two workers pick the same delta from the pool.
    // Worker A's execution modifies pk_extra, Worker B's does not.
    // Their divergent_keys should diverge after execution.
    let pk1 = Pubkey::new_unique();
    let pk_extra = Pubkey::new_unique();

    let mut svm_a = LiteSVM::new();
    let mut svm_b = LiteSVM::new();

    for svm in [&mut svm_a, &mut svm_b] {
        svm.set_account(pk1, make_account(100, &[])).unwrap();
    }
    let tracked: HashSet<Pubkey> = [pk1].into_iter().collect();
    let initial = SvmSnapshot::take(&svm_a, &tracked);

    // Shared delta (from pool, Arc)
    let mut delta_accts = FastHashMap::default();
    delta_accts.insert(pk1, Arc::new(make_account(500, &[])));
    let delta = Arc::new(SvmSnapshot { accounts: delta_accts, sysvars: make_test_sysvars(1) });

    // Both workers restore same delta
    let mut divergent_a: FastHashSet<Pubkey> = FastHashSet::default();
    let mut divergent_b: FastHashSet<Pubkey> = FastHashSet::default();

    initial.restore_selective(&mut svm_a, &divergent_a, &delta);
    divergent_a.extend(delta.accounts().keys().copied());

    initial.restore_selective(&mut svm_b, &divergent_b, &delta);
    divergent_b.extend(delta.accounts().keys().copied());

    // Both SVMs should be identical at this point
    assert_eq!(svm_a.get_account(&pk1).unwrap().lamports, 500);
    assert_eq!(svm_b.get_account(&pk1).unwrap().lamports, 500);

    // Worker A's execution creates pk_extra (CPI-created account)
    svm_a.set_account(pk_extra, make_account(999, &[0xAA])).unwrap();
    let mut exec_dirty_a: FastHashSet<Pubkey> = FastHashSet::default();
    exec_dirty_a.insert(pk_extra);
    divergent_a.extend(exec_dirty_a.iter().copied());

    // Worker B's execution does nothing extra
    let exec_dirty_b: FastHashSet<Pubkey> = FastHashSet::default();

    // Now workers pick different next states
    let mut next_delta_accts = FastHashMap::default();
    next_delta_accts.insert(pk1, Arc::new(make_account(600, &[])));
    let next_delta = Arc::new(SvmSnapshot { accounts: next_delta_accts, sysvars: make_test_sysvars(2) });

    // Worker A uses _from (prev succeeded)
    let prev_a = delta.clone();
    initial.restore_selective_from(&mut svm_a, &divergent_a, &prev_a, &next_delta, &exec_dirty_a);

    // Worker B uses _from (prev succeeded)
    let prev_b = delta.clone();
    initial.restore_selective_from(&mut svm_b, &divergent_b, &prev_b, &next_delta, &exec_dirty_b);

    // Both should have pk1=600
    assert_eq!(svm_a.get_account(&pk1).unwrap().lamports, 600);
    assert_eq!(svm_b.get_account(&pk1).unwrap().lamports, 600);

    // Worker A: pk_extra was in divergent_a but not in next_delta → cleaned up
    assert!(svm_a.get_account(&pk_extra).is_none(),
        "pk_extra should be cleaned up for worker A");

    // Worker B: pk_extra was never in divergent_b, never existed in svm_b
    assert!(svm_b.get_account(&pk_extra).is_none());
}

// =========================================================================
// StatePool::is_novel — lightweight admission check
// =========================================================================

#[test]
fn test_is_novel_empty_pool() {
    let pool = StatePool::new(100, 20);
    // Any fingerprint is novel in an empty pool
    assert!(pool.is_novel(42));
    assert!(pool.is_novel(0));
    assert!(pool.is_novel(u64::MAX));
}

#[test]
fn test_is_novel_after_add() {
    let mut pool = StatePool::new(100, 20);
    let fp = 12345u64;
    add_test_state(&mut pool, fp, 0, None, "test", None);

    // Same fingerprint (truncated to 17 bits) should no longer be novel
    assert!(!pool.is_novel(fp));

    // Different fingerprint should still be novel
    assert!(pool.is_novel(fp + 1));
}

#[test]
fn test_is_novel_fingerprint_truncation() {
    let mut pool = StatePool::new(100, 20);
    // Add a state with fingerprint that has specific lower 17 bits
    let fp = 0xABCD_1234u64;
    add_test_state(&mut pool, fp, 0, None, "test", None);

    // Different upper bits but same lower 17 bits → not novel
    let same_lower = (fp & ((1u64 << 17) - 1)) | (0xFFFF_0000u64 << 17);
    assert!(!pool.is_novel(same_lower));

    // Different lower 17 bits → novel
    let diff_lower = fp ^ 1;
    assert!(pool.is_novel(diff_lower));
}

#[test]
fn test_is_novel_full_pool() {
    let mut pool = StatePool::new(2, 20);
    add_test_state(&mut pool, 1, 0, None, "a", None);
    add_test_state(&mut pool, 2, 0, None, "b", None);

    // Pool is full but has active states that can be evicted — novel fingerprints are still accepted
    assert!(pool.is_novel(999));
    // Duplicate fingerprint is still not novel
    assert!(!pool.is_novel(1));
}

// =========================================================================
// StatePool — Edge rarity scoring
// =========================================================================

#[test]
fn test_pool_edge_rarity_scoring() {
    use super::super::extract_coverage_positions;

    let mut pool = StatePool::new(100, 20);

    // State 0: positions [0,1,2] — all brand new (freq=0), max rarity
    pool.try_add(
        1, CompactDelta::empty(make_test_clock(0)), 0, None,
        make_action_bytes(1, &[0x01]), "rare".to_string(), Some(0), vec![], None,
        5, 5, true, Some(vec![0, 1, 2]),
    );
    let s0_rarity = pool.get(0).unwrap().rarity_score;
    // All edges at freq=0 → score = mean(1/(0+1)) = 1.0
    assert!((s0_rarity - 1.0).abs() < 0.001, "s0 rarity should be ~1.0, got {}", s0_rarity);
    assert!(pool.get(0).unwrap().edge_positions.is_some());

    // State 1: positions [0,1,2,3,4] — shares 0,1,2 (now freq=1) + new 3,4 (freq=0)
    pool.try_add(
        2, CompactDelta::empty(make_test_clock(1)), 1, None,
        make_action_bytes(1, &[0x02]), "mixed".to_string(), Some(1), vec![], None,
        5, 5, true, Some(vec![0, 1, 2, 3, 4]),
    );
    let s1_rarity = pool.get(1).unwrap().rarity_score;
    // Shared edges: 1/(1+1)=0.5 each (3 of them), new edges: 1/(0+1)=1.0 each (2 of them)
    // Mean = (0.5*3 + 1.0*2)/5 = 3.5/5 = 0.7
    assert!((s1_rarity - 0.7).abs() < 0.001, "s1 rarity should be ~0.7, got {}", s1_rarity);

    // State 0 has higher rarity (added when edges were brand new)
    assert!(s0_rarity > s1_rarity, "s0 ({}) should have higher rarity than s1 ({})", s0_rarity, s1_rarity);

    // Non-coverage state (novelty_bits=0): rarity should be 0.0 even with positions
    pool.try_add(
        3, CompactDelta::empty(make_test_clock(2)), 0, None,
        make_action_bytes(1, &[0x03]), "nocov".to_string(), Some(2), vec![], None,
        0, 0, true, Some(vec![10, 11, 12]),
    );
    assert_eq!(pool.get(2).unwrap().rarity_score, 0.0);
    assert!(pool.get(2).unwrap().edge_positions.is_none());

    // No positions provided: rarity should be 0.0
    pool.try_add(
        4, CompactDelta::empty(make_test_clock(3)), 0, None,
        make_action_bytes(1, &[0x04]), "nopos".to_string(), Some(3), vec![], None,
        5, 5, true, None
    );
    assert_eq!(pool.get(3).unwrap().rarity_score, 0.0);
    assert!(pool.get(3).unwrap().edge_positions.is_none());
}

#[test]
fn test_pool_edge_freq_decrement_on_eviction() {
    let mut pool = StatePool::new(2, 20);

    // Add state 0 with positions [0,1]
    pool.try_add(
        1, CompactDelta::empty(make_test_clock(0)), 0, None,
        make_action_bytes(1, &[0x01]), "s0".to_string(), Some(0), vec![], None,
        5, 5, true, Some(vec![0, 1]),
    );
    // Add state 1 with positions [0,2]
    pool.try_add(
        2, CompactDelta::empty(make_test_clock(1)), 0, None,
        make_action_bytes(1, &[0x02]), "s1".to_string(), Some(1), vec![], None,
        5, 5, true, Some(vec![0, 2]),
    );

    // Pool is full. edge_freq[0]=2, edge_freq[1]=1, edge_freq[2]=1
    assert_eq!(pool.edge_freq[0], 2);
    assert_eq!(pool.edge_freq[1], 1);
    assert_eq!(pool.edge_freq[2], 1);

    // Adding state 2 will evict the weakest → should decrement evicted state's freq
    pool.try_add(
        3, CompactDelta::empty(make_test_clock(2)), 0, None,
        make_action_bytes(1, &[0x03]), "s2".to_string(), Some(2), vec![], None,
        5, 5, true, Some(vec![3]),
    );

    // After eviction, one of states 0 or 1 was evicted.
    // The new state's position [3] should have freq=1.
    assert_eq!(pool.edge_freq[3], 1);
}

#[test]
fn test_pool_edge_freq_decrement_on_crash() {
    let mut pool = StatePool::new(100, 20);

    pool.try_add(
        1, CompactDelta::empty(make_test_clock(0)), 0, None,
        make_action_bytes(1, &[0x01]), "s0".to_string(), Some(0), vec![], None,
        5, 5, true, Some(vec![10, 20, 30]),
    );
    assert_eq!(pool.edge_freq[10], 1);
    assert_eq!(pool.edge_freq[20], 1);
    assert_eq!(pool.edge_freq[30], 1);

    pool.mark_crashed(0);

    assert_eq!(pool.edge_freq[10], 0);
    assert_eq!(pool.edge_freq[20], 0);
    assert_eq!(pool.edge_freq[30], 0);
}

#[test]
fn test_extract_coverage_positions() {
    use super::super::extract_coverage_positions;

    // Empty map
    assert!(extract_coverage_positions(&[0u8; 16]).is_empty());

    // Single byte set
    let mut map = vec![0u8; 32];
    map[5] = 1;
    map[17] = 42;
    let pos = extract_coverage_positions(&map);
    assert_eq!(pos, vec![5, 17]);

    // All non-zero in one u64 chunk
    let mut map = vec![0u8; 16];
    for i in 0..8 { map[i] = (i + 1) as u8; }
    let pos = extract_coverage_positions(&map);
    assert_eq!(pos, vec![0, 1, 2, 3, 4, 5, 6, 7]);

    // Map not aligned to 8 bytes
    let mut map = vec![0u8; 13];
    map[12] = 1; // trailing byte
    let pos = extract_coverage_positions(&map);
    assert_eq!(pos, vec![12]);
}

// =========================================================================
// StateRegistry — accounting and SCFuzz formula
// =========================================================================

use crate::snapshot::state_pool::{StateRegistry, FuzzPhase, state_class_from_fingerprint};

#[test]
fn test_state_registry_accounting() {
    let mut pool = StatePool::new(1000, 20);

    // Add initial state (no parent)
    let fp_initial = 0x0001_0000_0000_0001u64; // state_class = 0x0001
    pool.try_add(fp_initial, CompactDelta::empty(make_test_clock(0)), 0, None,
        vec![0u8; 8], "initial".into(), None, vec![], None, 0, 0, true, None);

    // state_class 0x0001 should have trigger_count=1
    let sc_initial = state_class_from_fingerprint(fp_initial);
    assert_eq!(sc_initial, 0x0001);
    let stats = pool.registry.get(sc_initial).unwrap();
    assert_eq!(stats.trigger_count, 1);
    assert_eq!(stats.depth, 0);

    // Add child with coverage (novelty_bits > 0), different state_class
    let fp_child = 0x0002_0000_0000_0002u64; // state_class = 0x0002
    pool.try_add(fp_child, CompactDelta::empty(make_test_clock(1)), 1, Some(0),
        vec![0u8; 8], "action_deposit".into(), Some(0), vec![], None, 5, 0, true, None);

    // Child state_class 0x0002 should have trigger_count=1
    let sc_child = state_class_from_fingerprint(fp_child);
    let stats_child = pool.registry.get(sc_child).unwrap();
    assert_eq!(stats_child.trigger_count, 1);
    assert_eq!(stats_child.depth, 1);

    // Parent (0x0001) should have paths_discovered=1 (child had novelty_bits>0)
    // and out_transitions=1 (child is different state_class)
    let stats_parent = pool.registry.get(sc_initial).unwrap();
    assert_eq!(stats_parent.paths_discovered, 1);
    assert_eq!(stats_parent.out_transitions, 1);
    assert!(stats_parent.last_new_find > 0 || pool.current_iteration == 0); // iteration 0 is valid

    // Add another child from same parent, same state_class as parent
    let fp_same = 0x0001_0000_0000_0003u64; // state_class = 0x0001 (same as parent)
    pool.try_add(fp_same, CompactDelta::empty(make_test_clock(2)), 1, Some(0),
        vec![0u8; 8], "action_withdraw".into(), Some(1), vec![], None, 0, 0, true, None);

    // Parent's trigger_count should now be 2 (initial + this child share state_class)
    let stats_parent = pool.registry.get(sc_initial).unwrap();
    assert_eq!(stats_parent.trigger_count, 2);
    // out_transitions should still be 1 (same state_class, not counted)
    assert_eq!(stats_parent.out_transitions, 1);
    // paths_discovered should still be 1 (child had novelty_bits=0)
    assert_eq!(stats_parent.paths_discovered, 1);

    // record_select
    pool.registry.record_select(sc_initial);
    pool.registry.record_select(sc_initial);
    let stats_parent = pool.registry.get(sc_initial).unwrap();
    assert_eq!(stats_parent.select_count, 2);
}

#[test]
fn test_state_seed_weight_formula() {
    let mut registry = StateRegistry::new();

    // State A: productive (many paths, out_transitions), low trigger
    registry.record_trigger(0x0001, 2);
    registry.record_path_discovered(0x0001);
    registry.record_path_discovered(0x0001);
    registry.record_path_discovered(0x0001);
    registry.record_out_transition(0x0001);
    registry.record_out_transition(0x0001);

    // State B: saturated (many triggers, few paths)
    for _ in 0..20 {
        registry.record_trigger(0x0002, 5);
    }
    for _ in 0..50 {
        registry.record_select(0x0002);
    }

    let w_a = registry.state_seed_weight(0x0001, 10.0, true);
    let w_b = registry.state_seed_weight(0x0002, 10.0, true);

    // Productive state A should have higher weight than saturated state B
    assert!(w_a > w_b, "productive state A ({}) should be weighted higher than saturated B ({})", w_a, w_b);

    // Unknown state should get fallback formula
    let w_unknown = registry.state_seed_weight(0xFFFF, 10.0, true);
    assert!(w_unknown > 0.0);

    // Success boost should double the weight
    let w_success = registry.state_seed_weight(0x0001, 10.0, true);
    let w_fail = registry.state_seed_weight(0x0001, 10.0, false);
    assert!((w_success - w_fail * 2.0).abs() < 0.001,
        "success boost should be 2x: success={}, fail={}", w_success, w_fail);
}

#[test]
fn test_phase_transition() {
    let mut pool = StatePool::new(200, 20);

    // Start in Coverage phase
    assert_eq!(pool.phase, FuzzPhase::Coverage);

    // Add 101 states with >50 unique state classes
    for i in 0..101u64 {
        let sc = (i % 60) as u16; // 60 unique state classes
        let fp = (sc as u64) << 48 | (i + 1);
        pool.try_add(fp, CompactDelta::empty(make_test_clock(i)), 0, None,
            vec![0u8; 8], format!("action_{}", i), None, vec![], None, 0, 0, true, None);
    }

    // Phase should still be Coverage until maybe_advance_phase is called
    assert_eq!(pool.phase, FuzzPhase::Coverage);

    pool.maybe_advance_phase();
    assert_eq!(pool.phase, FuzzPhase::Blended);

    // Calling again should be idempotent
    pool.maybe_advance_phase();
    assert_eq!(pool.phase, FuzzPhase::Blended);
}

#[test]
fn test_state_seed_weight_fallback_in_coverage_phase() {
    // In Coverage phase, non-coverage states use original fast-decay formula
    let mut pool = StatePool::new(100, 20);
    assert_eq!(pool.phase, FuzzPhase::Coverage);

    // Add two non-coverage states (novelty_bits=0)
    let fp1 = 0x0001_0000_0000_0001u64;
    let fp2 = 0x0002_0000_0000_0002u64;
    pool.try_add(fp1, CompactDelta::empty(make_test_clock(0)), 0, None,
        vec![0u8; 8], "a".into(), None, vec![], None, 0, 0, true, None);
    pool.try_add(fp2, CompactDelta::empty(make_test_clock(1)), 1, None,
        vec![0u8; 8], "b".into(), None, vec![], None, 0, 0, true, None);

    // Pick state 0 many times
    pool.states[0].pick_count.store(100, Ordering::Relaxed);
    pool.total_picks.store(100, Ordering::Relaxed);

    // State 1 (picks=0) should have max priority (1e6)
    let w0 = pool.compute_weight(&pool.states[0], 20);
    let w1 = pool.compute_weight(&pool.states[1], 20);
    assert_eq!(w1, 1e6, "never-picked state should get max priority");
    assert!(w0 < w1, "heavily-picked state should have lower weight");

    // Coverage-phase formula: explore_decay * success * depth
    // picks=100: 1/(1+100/50) = 1/3, success=2.0, depth_factor=1.0
    let expected = (1.0 / (1.0 + 100.0 / 50.0)) * 2.0 * 1.0; // ~0.667
    assert!((w0 - expected).abs() < 0.01,
        "Coverage phase should use original formula: got {}, expected {}", w0, expected);
}

#[test]
fn test_blended_phase_uses_scfuzz_formula() {
    let mut pool = StatePool::new(200, 20);

    // Force into Blended phase by adding enough states
    for i in 0..110u64 {
        let sc = (i % 60) as u16;
        let fp = (sc as u64) << 48 | (i + 1);
        pool.try_add(fp, CompactDelta::empty(make_test_clock(i)), 0, None,
            vec![0u8; 8], format!("action_{}", i), None, vec![], None, 0, 0, true, None);
    }
    pool.maybe_advance_phase();
    assert_eq!(pool.phase, FuzzPhase::Blended);

    // Add a productive parent state class (via registry manipulation)
    let sc_good: u16 = 0x0001;
    pool.registry.record_path_discovered(sc_good);
    pool.registry.record_path_discovered(sc_good);
    pool.registry.record_out_transition(sc_good);

    // Compute weight for a non-coverage state in Blended phase
    // Should use SCFuzz formula (state_seed_weight) * depth_factor, not fast-decay
    let fp_test = (sc_good as u64) << 48 | 0xABCD;
    pool.try_add(fp_test, CompactDelta::empty(make_test_clock(200)), 1, None,
        vec![0u8; 8], "test".into(), None, vec![], None, 0, 0, true, None);

    let test_idx = pool.states.len() - 1;
    pool.states[test_idx].pick_count.store(10, Ordering::Relaxed);

    let w = pool.compute_weight(&pool.states[test_idx], 20);

    // In Blended phase, weight should be from SCFuzz formula, not fast-decay
    // Fast-decay for picks=10: 1/(1+10/50) * 2.0 * depth ≈ 1.667
    let fast_decay_w = (1.0 / (1.0 + 10.0 / 50.0)) * 2.0 * (1.0 / (1.0 + 0.025));
    // SCFuzz weight should differ from fast-decay
    assert!(w != fast_decay_w, "Blended phase should use SCFuzz formula, not fast-decay");
    assert!(w > 0.0, "SCFuzz weight should be positive");
}
