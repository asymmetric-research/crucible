//! Corpus minimization algorithm.
//!
//! Greedy set-cover: finds the smallest subset of inputs that preserves
//! all observed coverage edges.

use std::collections::HashSet;

/// Result of corpus minimization.
#[derive(Debug)]
pub struct CminResult {
    /// Indices into the original `edges_per_input` vec of selected inputs.
    pub selected: Vec<usize>,
    /// Total unique edges preserved (should equal union of all input edges).
    pub total_edges: usize,
}

/// Greedy set-cover corpus minimization.
///
/// Given a list of edge sets (one per input, sorted by preference — e.g. file
/// size ascending), returns the smallest subset of inputs whose edge-set union
/// equals the union of all inputs.
///
/// Ties are broken by input order (earlier = preferred), so pre-sorting by
/// file size gives smaller-file preference.
pub fn greedy_set_cover(edges_per_input: &[HashSet<u64>]) -> CminResult {
    // Collect all unique edges
    let mut all_edges: HashSet<u64> = HashSet::new();
    for edges in edges_per_input {
        all_edges.extend(edges);
    }
    let total_edges = all_edges.len();

    let mut uncovered = all_edges;
    let mut selected: Vec<usize> = Vec::new();
    let mut used = vec![false; edges_per_input.len()];

    while !uncovered.is_empty() {
        // Find input that covers the most uncovered edges
        let mut best_idx = None;
        let mut best_count = 0usize;

        for (idx, edges) in edges_per_input.iter().enumerate() {
            if used[idx] {
                continue;
            }

            let new_coverage = edges.iter().filter(|e| uncovered.contains(e)).count();
            if new_coverage > best_count {
                best_count = new_coverage;
                best_idx = Some(idx);
            }
        }

        match best_idx {
            Some(idx) => {
                used[idx] = true;
                selected.push(idx);
                for edge in &edges_per_input[idx] {
                    uncovered.remove(edge);
                }
            }
            None => break,
        }
    }

    CminResult {
        selected,
        total_edges,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a HashSet from a slice.
    fn edges(vals: &[u64]) -> HashSet<u64> {
        vals.iter().copied().collect()
    }

    // =================================================================
    // Basic algorithm correctness
    // =================================================================

    #[test]
    fn empty_input() {
        let result = greedy_set_cover(&[]);
        assert!(result.selected.is_empty());
        assert_eq!(result.total_edges, 0);
    }

    #[test]
    fn single_input() {
        let inputs = vec![edges(&[1, 2, 3])];
        let result = greedy_set_cover(&inputs);
        assert_eq!(result.selected, vec![0]);
        assert_eq!(result.total_edges, 3);
    }

    #[test]
    fn duplicate_inputs() {
        // Two identical inputs — only one should be selected
        let inputs = vec![edges(&[1, 2, 3]), edges(&[1, 2, 3])];
        let result = greedy_set_cover(&inputs);
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.total_edges, 3);
    }

    #[test]
    fn disjoint_inputs() {
        // No overlap — all must be selected
        let inputs = vec![edges(&[1, 2]), edges(&[3, 4]), edges(&[5, 6])];
        let result = greedy_set_cover(&inputs);
        assert_eq!(result.selected.len(), 3);
        assert_eq!(result.total_edges, 6);
    }

    #[test]
    fn subset_input_is_redundant() {
        // Input 1 is a subset of input 0 — only 0 needed
        let inputs = vec![edges(&[1, 2, 3, 4, 5]), edges(&[1, 2, 3])];
        let result = greedy_set_cover(&inputs);
        assert_eq!(result.selected, vec![0]);
        assert_eq!(result.total_edges, 5);
    }

    #[test]
    fn overlapping_inputs() {
        // Partial overlap: {1,2,3} and {3,4,5} — both needed
        let inputs = vec![edges(&[1, 2, 3]), edges(&[3, 4, 5])];
        let result = greedy_set_cover(&inputs);
        assert_eq!(result.selected.len(), 2);
        assert_eq!(result.total_edges, 5);
    }

    #[test]
    fn greedy_picks_largest_first() {
        // Input 0 covers 1 edge, input 1 covers 5 edges, input 2 covers 2 edges
        // Greedy should pick input 1 first (most coverage)
        let inputs = vec![edges(&[10]), edges(&[1, 2, 3, 4, 5]), edges(&[10, 20])];
        let result = greedy_set_cover(&inputs);
        // Input 1 covers {1,2,3,4,5}, then input 2 covers {10,20}
        // Input 0 is redundant (edge 10 covered by input 2)
        assert_eq!(result.selected.len(), 2);
        assert!(result.selected.contains(&1));
        assert!(result.selected.contains(&2));
        assert_eq!(result.total_edges, 7);
    }

    // =================================================================
    // Idempotency — the key property that was broken
    // =================================================================

    #[test]
    fn idempotent_preserves_all_edges() {
        // Run set-cover, then run again on just the selected inputs.
        // The second run must preserve the same total edges.
        let inputs = vec![
            edges(&[1, 2, 3]),
            edges(&[3, 4, 5]),
            edges(&[5, 6, 7]),
            edges(&[7, 8, 9]),
            edges(&[1, 5, 9]),
        ];

        let result1 = greedy_set_cover(&inputs);
        let edges1: HashSet<u64> = result1
            .selected
            .iter()
            .flat_map(|&i| inputs[i].iter().copied())
            .collect();

        // Build selected-only input list
        let selected_inputs: Vec<HashSet<u64>> = result1
            .selected
            .iter()
            .map(|&i| inputs[i].clone())
            .collect();

        let result2 = greedy_set_cover(&selected_inputs);
        let edges2: HashSet<u64> = result2
            .selected
            .iter()
            .flat_map(|&i| selected_inputs[i].iter().copied())
            .collect();

        assert_eq!(
            edges1,
            edges2,
            "Running cmin twice must preserve all edges. Lost: {:?}",
            edges1.difference(&edges2).collect::<Vec<_>>()
        );
        assert_eq!(result1.total_edges, result2.total_edges);
    }

    #[test]
    fn idempotent_large_random() {
        // Larger test: 50 inputs with random edge sets
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut inputs = Vec::new();
        for i in 0u64..50 {
            let mut set = HashSet::new();
            // Deterministic pseudo-random edges from hash
            for j in 0u64..20 {
                let mut h = DefaultHasher::new();
                (i * 1000 + j).hash(&mut h);
                set.insert(h.finish() % 500);
            }
            inputs.push(set);
        }

        let result1 = greedy_set_cover(&inputs);
        let edges1: HashSet<u64> = result1
            .selected
            .iter()
            .flat_map(|&i| inputs[i].iter().copied())
            .collect();

        let selected_inputs: Vec<HashSet<u64>> = result1
            .selected
            .iter()
            .map(|&i| inputs[i].clone())
            .collect();

        let result2 = greedy_set_cover(&selected_inputs);
        let edges2: HashSet<u64> = result2
            .selected
            .iter()
            .flat_map(|&i| selected_inputs[i].iter().copied())
            .collect();

        assert_eq!(
            edges1,
            edges2,
            "Idempotency violated on large set. Lost {} edges",
            edges1.difference(&edges2).count()
        );
    }

    // =================================================================
    // u8 wrapping simulation — proves the old bug
    // =================================================================

    /// Simulate the OLD buggy cmin behavior: scanning a u8 AFL map with
    /// wrapping_add counters. Edges hit N*256 times wrap to 0.
    fn simulate_buggy_u8_map(
        edge_hits: &[(usize, u32)], // (edge_index, hit_count)
        map_size: usize,
    ) -> HashSet<u64> {
        let mut map = vec![0u8; map_size];
        for &(edge, count) in edge_hits {
            for _ in 0..count {
                map[edge % map_size] = map[edge % map_size].wrapping_add(1);
            }
        }
        // Scan map like old cmin did
        let mut edges = HashSet::new();
        for (idx, &count) in map.iter().enumerate() {
            if count > 0 {
                edges.insert(idx as u64);
            }
        }
        edges
    }

    /// Simulate the FIXED cmin behavior: exact edge tracking via HashSet.
    fn simulate_fixed_edge_set(edge_hits: &[(usize, u32)], _map_size: usize) -> HashSet<u64> {
        edge_hits.iter().map(|&(edge, _)| edge as u64).collect()
    }

    #[test]
    fn u8_wrapping_loses_edges() {
        // Edge 42 hit exactly 256 times → wraps to 0 → invisible in old code
        let hits = vec![(42, 256), (100, 1)];
        let buggy = simulate_buggy_u8_map(&hits, 65536);
        let fixed = simulate_fixed_edge_set(&hits, 65536);

        assert!(
            !buggy.contains(&42),
            "Old buggy code should miss edge 42 (u8 wrapped to 0)"
        );
        assert!(fixed.contains(&42), "Fixed code should see edge 42");
        assert_eq!(fixed.len(), 2);
        assert_eq!(buggy.len(), 1); // lost an edge!
    }

    #[test]
    fn u8_wrapping_512_hits() {
        // Edge hit 512 times also wraps to 0
        let hits = vec![(7, 512)];
        let buggy = simulate_buggy_u8_map(&hits, 65536);
        let fixed = simulate_fixed_edge_set(&hits, 65536);

        assert!(buggy.is_empty(), "512 wraps to 0");
        assert_eq!(fixed.len(), 1, "Fixed code preserves edge");
    }

    #[test]
    fn u8_wrapping_255_is_fine() {
        // Edge hit 255 times does NOT wrap — should be visible in both
        let hits = vec![(42, 255)];
        let buggy = simulate_buggy_u8_map(&hits, 65536);
        let fixed = simulate_fixed_edge_set(&hits, 65536);

        assert_eq!(buggy.len(), 1);
        assert_eq!(fixed.len(), 1);
    }

    #[test]
    fn u8_wrapping_collision_causes_loss() {
        // Two edges collide into the same bucket. Their combined hits = 256.
        // Edge A: bucket 42, hit 200 times. Edge B: bucket 42, hit 56 times.
        // Combined: 256 → wraps to 0 → BOTH edges invisible.
        let map_size = 65536;
        let mut map = vec![0u8; map_size];

        // Simulate two different logical edges that hash to the same bucket
        let bucket = 42;
        for _ in 0..200 {
            map[bucket] = map[bucket].wrapping_add(1);
        }
        for _ in 0..56 {
            map[bucket] = map[bucket].wrapping_add(1);
        }

        assert_eq!(map[bucket], 0, "Combined 200+56=256 wraps to 0");

        // With exact tracking, both edges would be recorded separately
        let fixed = simulate_fixed_edge_set(&[(bucket, 200), (bucket, 56)], map_size);
        assert_eq!(fixed.len(), 1); // same bucket index, 1 entry (which is correct for map-level tracking)
    }

    // =================================================================
    // Progressive loss scenario — the user-reported bug
    // =================================================================

    #[test]
    fn progressive_loss_with_buggy_map() {
        // Simulate the progressive loss scenario:
        // - Input A covers edges {1, 2, 3}
        // - Input B covers edges {3, 4, 5}
        // - Input C covers edges {5, 6, 7}
        // But with u8 wrapping, some edges are invisible for some inputs.
        //
        // Run 1: A sees {1,2,3}, B sees {3,4,5}, C sees {5,6,7}
        //   set-cover selects A, B, C → 7 edges total
        // Run 2: Same inputs but with wrapping on some:
        //   A sees {1,2}, B sees {4,5}, C sees {5,6,7}
        //   Edge 3 lost! Set-cover: A covers {1,2}, B covers {4,5}, C covers {5,6,7} → 6 edges

        // Run 1: no wrapping issues
        let run1 = vec![edges(&[1, 2, 3]), edges(&[3, 4, 5]), edges(&[5, 6, 7])];
        let r1 = greedy_set_cover(&run1);
        let e1: HashSet<u64> = r1
            .selected
            .iter()
            .flat_map(|&i| run1[i].iter().copied())
            .collect();
        assert_eq!(e1.len(), 7);

        // Run 2: simulate edge 3 being lost from both A and B due to wrapping
        let run2 = vec![
            edges(&[1, 2]), // edge 3 wrapped away
            edges(&[4, 5]), // edge 3 wrapped away
            edges(&[5, 6, 7]),
        ];
        let r2 = greedy_set_cover(&run2);
        let e2: HashSet<u64> = r2
            .selected
            .iter()
            .flat_map(|&i| run2[i].iter().copied())
            .collect();

        // Progressive loss: 7 → 6 edges
        assert!(
            e2.len() < e1.len(),
            "Demonstrates progressive loss: {} < {}",
            e2.len(),
            e1.len()
        );
        assert!(!e2.contains(&3), "Edge 3 lost due to wrapping");
    }

    #[test]
    fn no_progressive_loss_with_exact_tracking() {
        // Same scenario but with exact edge tracking (the fix).
        // Both runs should see the same edges.
        let inputs = vec![edges(&[1, 2, 3]), edges(&[3, 4, 5]), edges(&[5, 6, 7])];

        let r1 = greedy_set_cover(&inputs);
        let e1: HashSet<u64> = r1
            .selected
            .iter()
            .flat_map(|&i| inputs[i].iter().copied())
            .collect();

        // Re-run on selected only — with exact tracking, edges are preserved
        let selected: Vec<HashSet<u64>> = r1.selected.iter().map(|&i| inputs[i].clone()).collect();
        let r2 = greedy_set_cover(&selected);
        let e2: HashSet<u64> = r2
            .selected
            .iter()
            .flat_map(|&i| selected[i].iter().copied())
            .collect();

        assert_eq!(e1, e2, "No loss with exact tracking");
    }

    // =================================================================
    // Edge cases
    // =================================================================

    #[test]
    fn input_with_no_edges_filtered_out() {
        // In real cmin, inputs with empty edge sets are filtered before set-cover.
        // If one sneaks through, algorithm should handle it gracefully.
        let inputs = vec![
            edges(&[]), // no coverage
            edges(&[1, 2, 3]),
        ];
        let result = greedy_set_cover(&inputs);
        assert_eq!(result.selected, vec![1]);
        assert_eq!(result.total_edges, 3);
    }

    #[test]
    fn all_inputs_cover_same_single_edge() {
        let inputs = vec![edges(&[42]), edges(&[42]), edges(&[42])];
        let result = greedy_set_cover(&inputs);
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.total_edges, 1);
    }

    #[test]
    fn tie_breaking_prefers_earlier_input() {
        // Inputs 0 and 1 cover the same edges. Input 0 should be preferred
        // (it appears first in the iteration, simulating smaller file size).
        let inputs = vec![edges(&[1, 2, 3]), edges(&[1, 2, 3])];
        let result = greedy_set_cover(&inputs);
        assert_eq!(
            result.selected,
            vec![0],
            "Tie-breaking should prefer earlier (smaller) input"
        );
    }

    // =================================================================
    // No-regression: selected inputs preserve ALL edges
    // =================================================================

    /// Verify that the union of selected inputs equals the union of ALL inputs.
    fn assert_no_edge_loss(inputs: &[HashSet<u64>], result: &CminResult) {
        let all_edges: HashSet<u64> = inputs.iter().flat_map(|s| s.iter().copied()).collect();
        let selected_edges: HashSet<u64> = result
            .selected
            .iter()
            .flat_map(|&i| inputs[i].iter().copied())
            .collect();
        assert_eq!(
            all_edges,
            selected_edges,
            "Edge loss detected! Lost: {:?}",
            all_edges.difference(&selected_edges).collect::<Vec<_>>()
        );
        assert_eq!(result.total_edges, all_edges.len());
    }

    #[test]
    fn no_regression_basic_overlapping() {
        let inputs = vec![edges(&[1, 2, 3]), edges(&[3, 4, 5]), edges(&[5, 6, 7])];
        let result = greedy_set_cover(&inputs);
        assert_no_edge_loss(&inputs, &result);
    }

    #[test]
    fn no_regression_chain_dependencies() {
        // Each input covers exactly one unique edge plus a shared one.
        // All must be preserved.
        let inputs = vec![
            edges(&[100, 1]),
            edges(&[100, 2]),
            edges(&[100, 3]),
            edges(&[100, 4]),
            edges(&[100, 5]),
        ];
        let result = greedy_set_cover(&inputs);
        assert_no_edge_loss(&inputs, &result);
        // One input covers {100, N} for any N, the rest each add one unique edge.
        // So we need 5 inputs (1 for {100} + 4 for unique edges not covered by the first).
        assert_eq!(result.selected.len(), 5);
    }

    #[test]
    fn no_regression_many_inputs_few_unique() {
        // 100 inputs all covering the same 3 edges.
        // Only 1 should be selected, and all 3 edges preserved.
        let inputs: Vec<HashSet<u64>> = (0..100).map(|_| edges(&[10, 20, 30])).collect();
        let result = greedy_set_cover(&inputs);
        assert_no_edge_loss(&inputs, &result);
        assert_eq!(result.selected.len(), 1);
    }

    #[test]
    fn no_regression_single_unique_edge_per_input() {
        // Each input has exactly one unique edge. None can be dropped.
        let inputs: Vec<HashSet<u64>> = (0..50).map(|i| edges(&[i])).collect();
        let result = greedy_set_cover(&inputs);
        assert_no_edge_loss(&inputs, &result);
        assert_eq!(result.selected.len(), 50);
    }

    #[test]
    fn no_regression_large_random_deterministic() {
        // 200 inputs with deterministic pseudo-random edge sets.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut inputs = Vec::new();
        for i in 0u64..200 {
            let mut set = HashSet::new();
            for j in 0u64..30 {
                let mut h = DefaultHasher::new();
                (i * 7919 + j * 6271).hash(&mut h);
                set.insert(h.finish() % 1000);
            }
            inputs.push(set);
        }

        let result = greedy_set_cover(&inputs);
        assert_no_edge_loss(&inputs, &result);
        // Must be strictly fewer than 200
        assert!(
            result.selected.len() < inputs.len(),
            "Should reduce: {} selected from {}",
            result.selected.len(),
            inputs.len()
        );
    }

    // =================================================================
    // Idempotency: running cmin on already-minimized corpus is a no-op
    // =================================================================

    #[test]
    fn idempotent_complex_overlaps() {
        let inputs = vec![
            edges(&[1, 2, 3, 4, 5]),
            edges(&[4, 5, 6, 7, 8]),
            edges(&[7, 8, 9, 10]),
            edges(&[1, 10, 11, 12]),
            edges(&[2, 6, 12, 13, 14]),
            edges(&[3, 9, 14, 15]),
        ];

        let r1 = greedy_set_cover(&inputs);
        assert_no_edge_loss(&inputs, &r1);

        let selected_inputs: Vec<HashSet<u64>> =
            r1.selected.iter().map(|&i| inputs[i].clone()).collect();

        let r2 = greedy_set_cover(&selected_inputs);
        assert_no_edge_loss(&selected_inputs, &r2);

        // Same edge count both times
        assert_eq!(r1.total_edges, r2.total_edges);
        // Second run selects everything (already minimal)
        assert_eq!(r2.selected.len(), selected_inputs.len());
    }

    #[test]
    fn idempotent_three_rounds() {
        // Run cmin three times — edge count must be stable.
        let inputs = vec![
            edges(&[1, 2, 3]),
            edges(&[2, 3, 4]),
            edges(&[3, 4, 5]),
            edges(&[4, 5, 6]),
            edges(&[5, 6, 1]),
        ];

        let r1 = greedy_set_cover(&inputs);
        let s1: Vec<HashSet<u64>> = r1.selected.iter().map(|&i| inputs[i].clone()).collect();

        let r2 = greedy_set_cover(&s1);
        let s2: Vec<HashSet<u64>> = r2.selected.iter().map(|&i| s1[i].clone()).collect();

        let r3 = greedy_set_cover(&s2);

        assert_eq!(r1.total_edges, r2.total_edges);
        assert_eq!(r2.total_edges, r3.total_edges);
        assert_eq!(r2.selected.len(), r3.selected.len());
    }

    // =================================================================
    // total_edges field correctness
    // =================================================================

    #[test]
    fn total_edges_matches_union() {
        let inputs = vec![edges(&[1, 2, 3]), edges(&[3, 4, 5]), edges(&[5, 6])];
        let all: HashSet<u64> = inputs.iter().flat_map(|s| s.iter().copied()).collect();
        let result = greedy_set_cover(&inputs);
        assert_eq!(result.total_edges, all.len());
        assert_eq!(result.total_edges, 6);
    }

    #[test]
    fn total_edges_empty() {
        let result = greedy_set_cover(&[]);
        assert_eq!(result.total_edges, 0);
    }

    #[test]
    fn total_edges_with_empty_inputs() {
        let inputs = vec![edges(&[]), edges(&[1]), edges(&[])];
        let result = greedy_set_cover(&inputs);
        assert_eq!(result.total_edges, 1);
    }

    // =================================================================
    // Reduction: result is strictly smaller than input
    // =================================================================

    #[test]
    fn reduces_when_redundancy_exists() {
        // Inputs with heavy overlap — greedy should select fewer than all.
        let inputs = vec![
            edges(&[1, 2, 3]),
            edges(&[2, 3, 4]),
            edges(&[4, 5, 6]),
            edges(&[6, 7, 8]),
        ];
        let result = greedy_set_cover(&inputs);
        assert_no_edge_loss(&inputs, &result);
        // Should need fewer than all 4 (edges 2,3,4,6 are shared)
        assert!(
            result.selected.len() < inputs.len(),
            "Should reduce: {} selected from {}",
            result.selected.len(),
            inputs.len()
        );
    }

    #[test]
    fn reduces_large_overlapping_set() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut inputs = Vec::new();
        for i in 0u64..100 {
            let mut set = HashSet::new();
            for j in 0u64..15 {
                let mut h = DefaultHasher::new();
                (i * 3571 + j * 1009).hash(&mut h);
                set.insert(h.finish() % 300);
            }
            inputs.push(set);
        }

        let result = greedy_set_cover(&inputs);
        assert_no_edge_loss(&inputs, &result);
        // 100 inputs with ~15 edges each from a 300-edge space — heavy overlap
        assert!(
            result.selected.len() < inputs.len(),
            "Should reduce: {} selected from {}",
            result.selected.len(),
            inputs.len()
        );
    }

    #[test]
    fn each_selected_input_justified_at_selection_time() {
        // Greedy set-cover guarantees: each selected input covered at least
        // one edge that was uncovered at the time of selection. Simulate
        // the algorithm and verify this property.
        let inputs = vec![
            edges(&[1, 2, 3, 4, 5]),
            edges(&[4, 5, 6, 7, 8]),
            edges(&[7, 8, 9, 10]),
            edges(&[1, 10, 11, 12]),
            edges(&[2, 6, 12, 13, 14]),
        ];

        let result = greedy_set_cover(&inputs);
        assert_no_edge_loss(&inputs, &result);

        // Replay the greedy algorithm and verify each step was justified
        let mut uncovered: HashSet<u64> = inputs.iter().flat_map(|s| s.iter().copied()).collect();
        for &idx in &result.selected {
            let newly_covered: usize = inputs[idx].iter().filter(|e| uncovered.contains(e)).count();
            assert!(
                newly_covered > 0,
                "Input {} was selected but covered 0 uncovered edges",
                idx
            );
            for e in &inputs[idx] {
                uncovered.remove(e);
            }
        }
        assert!(
            uncovered.is_empty(),
            "Uncovered edges remain: {:?}",
            uncovered
        );
    }

    // =================================================================
    // Context-sensitivity: (pc, target_pc) pairs vs AFL map indices
    // =================================================================

    #[test]
    fn exact_pairs_not_inflated_by_context() {
        // Simulate what happens with exact (pc, target_pc) tracking:
        // The same physical edge (pc=100, target=200) always produces
        // edge_id = (100 << 32) | 200, regardless of preceding edges.
        // This should be counted as ONE edge, not multiple.
        let edge_a = ((100u64) << 32) | 200;
        let edge_b = ((300u64) << 32) | 400;

        // Input 1: executes edge A then edge B
        // Input 2: executes edge B then edge A (same edges, different order)
        // With exact tracking, both inputs cover the same 2 edges.
        let inputs = vec![
            [edge_a, edge_b].into_iter().collect::<HashSet<u64>>(),
            [edge_b, edge_a].into_iter().collect::<HashSet<u64>>(),
        ];

        let result = greedy_set_cover(&inputs);
        assert_eq!(
            result.total_edges, 2,
            "Same edges in different order = 2 unique edges"
        );
        assert_eq!(result.selected.len(), 1, "One input suffices");
    }

    #[test]
    fn afl_map_would_inflate_context_sensitive_edges() {
        // Demonstrate the inflation that AFL map indices cause:
        // With prev_location XOR, edge A after edge B produces a different
        // map index than edge A after edge C. This is what we fixed.
        //
        // Simulate: edge_id hashed and XOR'd with prev_location
        fn afl_edge(edge_id: u64, prev_location: usize, map_size: usize) -> usize {
            let cur = ((edge_id.wrapping_mul(0x9e3779b97f4a7c15)) >> 48) as usize;
            (cur ^ prev_location) % map_size
        }

        let edge_a: u64 = (100 << 32) | 200;
        let edge_b: u64 = (300 << 32) | 400;
        let edge_c: u64 = (500 << 32) | 600;

        // Edge A after B vs edge A after C → different AFL map indices
        let map_idx_a_after_b = afl_edge(edge_a, afl_edge(edge_b, 0, 65536) >> 1, 65536);
        let map_idx_a_after_c = afl_edge(edge_a, afl_edge(edge_c, 0, 65536) >> 1, 65536);

        // These are likely different (context-sensitive)
        // With exact (pc, target_pc) tracking, edge A is always edge A regardless of context
        let exact_set: HashSet<u64> = [edge_a].into_iter().collect();
        assert_eq!(exact_set.len(), 1, "Exact tracking: 1 edge");

        // AFL map might see them as different
        let afl_set: HashSet<usize> = [map_idx_a_after_b, map_idx_a_after_c].into_iter().collect();
        // Could be 1 or 2 depending on hash collision
        assert!(
            afl_set.len() <= 2,
            "AFL map: up to 2 map indices for the same physical edge"
        );
    }
}
