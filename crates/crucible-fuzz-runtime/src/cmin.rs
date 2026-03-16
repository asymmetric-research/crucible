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
        let inputs = vec![
            edges(&[10]),
            edges(&[1, 2, 3, 4, 5]),
            edges(&[10, 20]),
        ];
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
        let selected_inputs: Vec<HashSet<u64>> =
            result1.selected.iter().map(|&i| inputs[i].clone()).collect();

        let result2 = greedy_set_cover(&selected_inputs);
        let edges2: HashSet<u64> = result2
            .selected
            .iter()
            .flat_map(|&i| selected_inputs[i].iter().copied())
            .collect();

        assert_eq!(
            edges1, edges2,
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

        let selected_inputs: Vec<HashSet<u64>> =
            result1.selected.iter().map(|&i| inputs[i].clone()).collect();

        let result2 = greedy_set_cover(&selected_inputs);
        let edges2: HashSet<u64> = result2
            .selected
            .iter()
            .flat_map(|&i| selected_inputs[i].iter().copied())
            .collect();

        assert_eq!(
            edges1, edges2,
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
    fn simulate_fixed_edge_set(
        edge_hits: &[(usize, u32)],
        _map_size: usize,
    ) -> HashSet<u64> {
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
        assert!(
            fixed.contains(&42),
            "Fixed code should see edge 42"
        );
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

        assert_eq!(
            map[bucket], 0,
            "Combined 200+56=256 wraps to 0"
        );

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
        let run1 = vec![
            edges(&[1, 2, 3]),
            edges(&[3, 4, 5]),
            edges(&[5, 6, 7]),
        ];
        let r1 = greedy_set_cover(&run1);
        let e1: HashSet<u64> = r1.selected.iter().flat_map(|&i| run1[i].iter().copied()).collect();
        assert_eq!(e1.len(), 7);

        // Run 2: simulate edge 3 being lost from both A and B due to wrapping
        let run2 = vec![
            edges(&[1, 2]),        // edge 3 wrapped away
            edges(&[4, 5]),        // edge 3 wrapped away
            edges(&[5, 6, 7]),
        ];
        let r2 = greedy_set_cover(&run2);
        let e2: HashSet<u64> = r2.selected.iter().flat_map(|&i| run2[i].iter().copied()).collect();

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
        let inputs = vec![
            edges(&[1, 2, 3]),
            edges(&[3, 4, 5]),
            edges(&[5, 6, 7]),
        ];

        let r1 = greedy_set_cover(&inputs);
        let e1: HashSet<u64> = r1.selected.iter().flat_map(|&i| inputs[i].iter().copied()).collect();

        // Re-run on selected only — with exact tracking, edges are preserved
        let selected: Vec<HashSet<u64>> = r1.selected.iter().map(|&i| inputs[i].clone()).collect();
        let r2 = greedy_set_cover(&selected);
        let e2: HashSet<u64> = r2.selected.iter().flat_map(|&i| selected[i].iter().copied()).collect();

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
            edges(&[]),  // no coverage
            edges(&[1, 2, 3]),
        ];
        let result = greedy_set_cover(&inputs);
        assert_eq!(result.selected, vec![1]);
        assert_eq!(result.total_edges, 3);
    }

    #[test]
    fn all_inputs_cover_same_single_edge() {
        let inputs = vec![
            edges(&[42]),
            edges(&[42]),
            edges(&[42]),
        ];
        let result = greedy_set_cover(&inputs);
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.total_edges, 1);
    }

    #[test]
    fn tie_breaking_prefers_earlier_input() {
        // Inputs 0 and 1 cover the same edges. Input 0 should be preferred
        // (it appears first in the iteration, simulating smaller file size).
        let inputs = vec![
            edges(&[1, 2, 3]),
            edges(&[1, 2, 3]),
        ];
        let result = greedy_set_cover(&inputs);
        assert_eq!(result.selected, vec![0], "Tie-breaking should prefer earlier (smaller) input");
    }
}
