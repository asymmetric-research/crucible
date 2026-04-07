use crate::{FastHashMap, FastHashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use rustc_hash::FxHasher;

use super::svm_snapshot::{SvmSnapshot, FINGERPRINT_BITS};

// ============================================================================
// FingerprintBitmap — lock-free pre-check for fingerprint novelty
// ============================================================================

/// Lock-free bitmap for fast fingerprint novelty pre-checking.
///
/// Workers check this bitmap BEFORE doing expensive save-phase work
/// (take_delta, fixture clone under mutex, etc.). Since FINGERPRINT_BITS=17,
/// there are 131072 possible dedup keys → 16384 bytes of bitmap.
///
/// False negatives are impossible: if a fingerprint IS in the bitmap,
/// it was definitely already added to the pool.
/// False positives (bitmap says not-seen but pool has it) can occur in a
/// tiny race window but are harmless — `try_add()` does authoritative dedup.
pub struct FingerprintBitmap {
    /// 131072 bits = 16384 bytes, stored as 16384 AtomicU8 values.
    bits: Box<[AtomicU8; Self::SIZE]>,
}

impl FingerprintBitmap {
    const SIZE: usize = (1u64 << FINGERPRINT_BITS) as usize / 8;

    pub fn new() -> Self {
        // AtomicU8 is not Copy, so we init via Box
        let mut v: Vec<AtomicU8> = Vec::with_capacity(Self::SIZE);
        for _ in 0..Self::SIZE {
            v.push(AtomicU8::new(0));
        }
        Self {
            bits: v.into_boxed_slice().try_into().unwrap_or_else(|_| unreachable!()),
        }
    }

    /// Check if a fingerprint is likely already seen (lock-free).
    /// Returns true if definitely seen, false if possibly novel.
    #[inline]
    pub fn is_seen(&self, fingerprint: u64) -> bool {
        let key = (fingerprint & ((1u64 << FINGERPRINT_BITS) - 1)) as usize;
        let byte_idx = key / 8;
        let bit_idx = key % 8;
        (self.bits[byte_idx].load(Ordering::Relaxed) >> bit_idx) & 1 == 1
    }

    /// Mark a fingerprint as seen (called when pool.try_add succeeds).
    #[inline]
    pub fn mark(&self, fingerprint: u64) {
        let key = (fingerprint & ((1u64 << FINGERPRINT_BITS) - 1)) as usize;
        let byte_idx = key / 8;
        let bit_idx = key % 8;
        self.bits[byte_idx].fetch_or(1 << bit_idx, Ordering::Relaxed);
    }

    /// Number of bits set (for diagnostics).
    pub fn count_set(&self) -> usize {
        self.bits.iter()
            .map(|b| b.load(Ordering::Relaxed).count_ones() as usize)
            .sum()
    }
}

/// A single saved state in the state pool.
pub struct StateEntry {
    /// Fingerprint of the state (used for dedup).
    pub fingerprint: u64,
    /// Delta snapshot: only accounts differing from the initial state.
    /// Wrapped in Arc so that cloning under RwLock read lock is just an
    /// atomic refcount bump (~1ns) instead of a deep HashMap copy (~500μs).
    pub delta: Arc<SvmSnapshot>,
    /// Depth: number of actions from initial state.
    pub depth: u32,
    /// Index of the parent state in the pool (None for initial state).
    pub parent_idx: Option<usize>,
    /// Full accumulated action sequence in FuzzInput format:
    /// 4-byte LE count header + concatenated action bytes from root to this state.
    /// Arc-wrapped: never mutated after storage, cloned 512× per batch refill.
    pub action_bytes: Arc<Vec<u8>>,
    /// One-line description of the action that led to this state (for crash output).
    /// e.g. "action_deposit(user=0, amount=500) -> OK"
    pub action_desc: String,
    /// Variant index of the action that led to this state (for parent-action replay).
    /// None for the initial state.
    pub action_variant: Option<u16>,
    /// Serialized fields of the action that led to this state (for mutation replay).
    /// Arc-wrapped: cloned 512× per batch refill, Arc bump instead of heap copy.
    /// Empty for the initial state.
    pub action_field_bytes: Arc<Vec<u8>>,
    /// Type-erased fixture state stored alongside this pool entry.
    /// When restoring a state, the stored fixture (which has the correct mutable
    /// fields like `all_marginfi_accounts` for that point in the chain) is cloned
    /// instead of reusing a stale worker fixture that grows unboundedly.
    /// The SVM is swapped out before storage, making clones cheap.
    pub fixture_state: Option<Arc<dyn std::any::Any + Send + Sync>>,
    // --- Power scheduling fields ---
    /// Number of times this state was selected as parent (atomic for lock-free concurrent picking).
    pub pick_count: AtomicU32,
    /// Number of novel child states produced from this state.
    pub novel_children: u32,
    /// Number of times an action from this state produced an invariant violation.
    /// States exceeding the threshold are removed from the active pool.
    pub violation_count: u32,
    /// Number of novel coverage bits this state discovered (edges + state buckets).
    /// Higher = rarer seed. Used in power scheduling to favor seeds that
    /// cover unique edges, matching LibAFL's rarity-weighted scheduling.
    pub novelty_bits: u32,
    /// Edge coverage novelty bits (code-edge + hitcount novelty only, excludes field novelty).
    /// Used to gate the coverage power schedule: only states with real code coverage
    /// get the high coverage floor, preventing field-novel states from drowning the signal.
    pub edge_novelty: u32,
    /// Whether the action that produced this state succeeded (transaction committed).
    /// States from successful actions get a 2x weight boost in power scheduling
    /// since they represent real state changes, not error-path dead ends.
    pub action_succeeded: bool,
    /// Pool size at the time this state was added.
    /// States added later (when the pool is large and the bitmap is saturated) that
    /// still find novel bits are exploring rarer territory. Used as a fallback rarity proxy
    /// when edge_positions are not available.
    pub pool_size_at_add: u32,
    /// AFLFast-style edge rarity score: mean inverse frequency of this state's coverage positions.
    /// Computed at add-time from the pool's edge frequency table. Higher = rarer edges.
    /// 0.0 for non-coverage states or when no positions were provided.
    pub rarity_score: f64,
    /// Coverage map positions (non-zero entries) this state hit.
    /// Used to decrement edge_freq on eviction/crash. None for non-coverage states.
    pub edge_positions: Option<Arc<Vec<u16>>>,
    /// Precomputed n-gram rarity score for action-path scheduling.
    /// max(rarity_2, rarity_3, rarity_4) computed at add-time. Higher = rarer path.
    pub ngram_rarity: f64,
    /// N-gram keys for 2/3/4-gram frequency tracking.
    /// [0]=2-gram, [1]=3-gram, [2]=4-gram. 0 means N/A (state too shallow).
    pub ngram_keys: [u64; 3],
    /// Consecutive picks without producing a novel child. Resets to 0 when
    /// novel_children is incremented. Used for exponential weight decay:
    /// states that keep failing to produce novelty get deprioritized.
    pub barren_picks: u32,
}

// ============================================================================
// ActionStats — per-state-class action success tracking
// ============================================================================

/// Tracks per-(state_class, action_variant) success rates for guided action selection.
///
/// State class = top 16 bits of the parent state's fingerprint, bucketing similar
/// states together. For each class, we track how many times each action variant
/// succeeded vs was attempted, enabling epsilon-greedy selection that avoids
/// wasting iterations on actions that always fail from a given state.
pub struct ActionStats {
    /// `[variant_idx] -> (successes, attempts)`
    counts: Vec<[u32; 2]>,
}

impl ActionStats {
    pub(crate) fn new(variant_count: usize) -> Self {
        Self {
            counts: vec![[0; 2]; variant_count],
        }
    }

    pub(crate) fn record(&mut self, variant_idx: usize, success: bool) {
        if let Some(entry) = self.counts.get_mut(variant_idx) {
            entry[1] += 1; // attempts
            if success {
                entry[0] += 1; // successes
            }
        }
    }

    /// Compute selection weights using Laplace smoothing + exploration bonus.
    ///
    /// Base weight: `(s+1)/(t+2)` (Laplace smoothing — never zero).
    /// Exploration bonus: `5.0 / (t+1)` — decays with attempts, giving
    /// never-attempted variants ~11x the weight of well-explored ones.
    /// This ensures rare actions (e.g. liquidation) get tried from every
    /// state class instead of being starved by high-success-rate variants.
    pub(crate) fn weights(&self) -> Vec<f64> {
        self.counts
            .iter()
            .map(|[s, t]| {
                let success_rate = (*s as f64 + 1.0) / (*t as f64 + 2.0);
                let explore_bonus = 5.0 / (*t as f64 + 1.0);
                success_rate + explore_bonus
            })
            .collect()
    }

    /// Read-only access to raw counts for debug export.
    pub fn counts_ref(&self) -> &[[u32; 2]] {
        &self.counts
    }
}

/// Thread-local action stats map: state_class (u16) -> ActionStats.
/// Each worker maintains its own map to avoid synchronization overhead.
pub struct ActionStatsMap {
    map: FastHashMap<u16, ActionStats>,
    variant_count: usize,
}

impl ActionStatsMap {
    pub fn new(variant_count: usize) -> Self {
        Self {
            map: FastHashMap::default(),
            variant_count,
        }
    }

    /// Record an action outcome for the given state class.
    pub fn record(&mut self, state_class: u16, variant_idx: usize, success: bool) {
        self.map
            .entry(state_class)
            .or_insert_with(|| ActionStats::new(self.variant_count))
            .record(variant_idx, success);
    }

    /// Get action stats for a specific state class (for debug export).
    pub fn get_stats(&self, state_class: u16) -> Option<&ActionStats> {
        self.map.get(&state_class)
    }

    /// Iterate over all state classes and their stats.
    pub fn iter_classes(&self) -> impl Iterator<Item = (u16, &ActionStats)> {
        self.map.iter().map(|(&sc, stats)| (sc, stats))
    }

    /// Aggregate counts across all state classes into a single vec.
    pub fn aggregate_all(&self) -> Vec<[u32; 2]> {
        let mut agg = vec![[0u32; 2]; self.variant_count];
        for stats in self.map.values() {
            for (i, [s, t]) in stats.counts_ref().iter().enumerate() {
                if let Some(entry) = agg.get_mut(i) {
                    entry[0] += s;
                    entry[1] += t;
                }
            }
        }
        agg
    }

    /// Pick a variant index using epsilon-greedy weighted selection.
    /// `epsilon_pct` = percentage of time to pick purely randomly (0-100).
    /// Returns the chosen variant index.
    pub fn pick_variant(&self, state_class: u16, rng_val: u64, epsilon_rng: u64) -> Option<usize> {
        // Epsilon-greedy: 20% pure random exploration (up from 10%).
        // Higher epsilon gives rare action sequences more chances to be discovered,
        // breaking coverage plateaus in complex protocols.
        if (epsilon_rng % 100) < 20 {
            return None; // caller should use FuzzAction::random()
        }

        let stats = self.map.get(&state_class)?;
        let weights = stats.weights();

        // Weighted sample via cumulative sum + binary search
        let total: f64 = weights.iter().sum();
        if total <= 0.0 {
            return None;
        }
        let target = (rng_val as f64 / u64::MAX as f64) * total;
        let mut cumulative = 0.0;
        for (i, &w) in weights.iter().enumerate() {
            cumulative += w;
            if target <= cumulative {
                return Some(i);
            }
        }
        // Floating point edge case: return last variant
        Some(weights.len() - 1)
    }
}

/// Extract state class (top 16 bits) from a fingerprint for ActionStats bucketing.
#[inline]
pub fn state_class_from_fingerprint(fingerprint: u64) -> u16 {
    (fingerprint >> 48) as u16
}

// ============================================================================
// StateRegistry — per-state-bucket statistics for SCFuzz-inspired scheduling
// ============================================================================

/// Per-state-bucket statistics for SCFuzz-inspired scheduling.
pub struct StateStats {
    /// Times any pool entry with this state_class was added.
    pub trigger_count: u32,
    /// Times a seed at this state_class was picked as parent.
    pub select_count: u32,
    /// New-coverage children produced from seeds at this state.
    pub paths_discovered: u32,
    /// Unique other state_classes reachable from here.
    pub out_transitions: u32,
    /// Minimum depth of any entry at this state_class.
    pub depth: u32,
    /// Iteration of last novel child from here.
    pub last_new_find: u64,
}

impl StateStats {
    fn new(depth: u32) -> Self {
        Self {
            trigger_count: 0,
            select_count: 0,
            paths_discovered: 0,
            out_transitions: 0,
            depth,
            last_new_find: 0,
        }
    }
}

/// Global registry of per-state-class statistics.
///
/// Uses `state_class` (top 16 bits of fingerprint) as the key, grouping
/// multiple pool entries per bucket for meaningful aggregate statistics.
pub struct StateRegistry {
    map: FastHashMap<u16, StateStats>,
}

impl StateRegistry {
    pub fn new() -> Self {
        Self { map: FastHashMap::default() }
    }

    /// Number of state classes tracked.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Get stats for a state class.
    pub fn get(&self, state_class: u16) -> Option<&StateStats> {
        self.map.get(&state_class)
    }

    fn get_or_insert(&mut self, state_class: u16, depth: u32) -> &mut StateStats {
        self.map.entry(state_class).or_insert_with(|| StateStats::new(depth))
    }

    /// Record that a new pool entry was added with this state_class.
    pub fn record_trigger(&mut self, state_class: u16, depth: u32) {
        let stats = self.get_or_insert(state_class, depth);
        stats.trigger_count += 1;
        stats.depth = stats.depth.min(depth);
    }

    /// Record that a seed at this state_class was picked as parent.
    pub fn record_select(&mut self, state_class: u16) {
        if let Some(stats) = self.map.get_mut(&state_class) {
            stats.select_count += 1;
        }
    }

    /// Record that a seed at parent_sc produced a new-coverage child.
    pub fn record_path_discovered(&mut self, parent_sc: u16) {
        if let Some(stats) = self.map.get_mut(&parent_sc) {
            stats.paths_discovered += 1;
        }
    }

    /// Record that a child at a different state_class was reached from parent_sc.
    pub fn record_out_transition(&mut self, parent_sc: u16) {
        if let Some(stats) = self.map.get_mut(&parent_sc) {
            stats.out_transitions += 1;
        }
    }

    /// Record the iteration at which a novel child was last found from parent_sc.
    pub fn record_new_find(&mut self, parent_sc: u16, iteration: u64) {
        if let Some(stats) = self.map.get_mut(&parent_sc) {
            stats.last_new_find = iteration;
        }
    }

    /// SCFuzz-inspired weight formula for non-coverage states.
    ///
    /// Combines productivity, depth, branching (numerator) against
    /// log-log penalty for saturated/over-selected states (denominator),
    /// with success boost and UCB-style pick bonus.
    pub fn state_seed_weight(&self, state_class: u16, picks: f64, action_succeeded: bool) -> f64 {
        let stats = match self.map.get(&state_class) {
            Some(s) => s,
            None => {
                // No stats yet — exploration priority with original decay
                let success_boost = if action_succeeded { 2.0 } else { 1.0 };
                return (1.0 / (1.0 + picks / 50.0)) * success_boost;
            }
        };

        // Numerator: productivity × depth × branching
        let numerator = (stats.paths_discovered as f64 + 1.0)
            * (stats.depth.min(100) as f64 + 1.0)
            * (stats.out_transitions as f64 + 1.0);

        // Denominator: log-log penalty for saturated/over-selected states
        let denominator = (stats.trigger_count as f64 + 2.0).ln().max(1.0)
            * (stats.select_count as f64 + 2.0);

        let base = numerator / denominator;

        let success_boost = if action_succeeded { 2.0 } else { 1.0 };
        let pick_decay = 1.0 + 1.0 / (1.0 + picks).sqrt(); // UCB-style bonus

        base * success_boost * pick_decay
    }
}

/// Fuzz phase: determines which weight formula to use for non-coverage states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FuzzPhase {
    /// Bootstrap phase: insufficient registry data, use original fast-decay formula.
    Coverage,
    /// Blended phase: enough data to use SCFuzz formula for non-coverage states.
    Blended,
}

/// Extract non-zero positions from a coverage map using u64 fast-skip.
///
/// Returns the indices of all non-zero bytes in the map. Used to track which
/// coverage map positions a state exercised, for AFLFast-style edge rarity scoring.
pub fn extract_coverage_positions(map: &[u8]) -> Vec<u16> {
    let mut positions = Vec::with_capacity(512);
    let mut i = 0usize;
    while i + 8 <= map.len() {
        let chunk = u64::from_ne_bytes(map[i..i+8].try_into().unwrap());
        if chunk != 0 {
            for j in 0..8 {
                if map[i + j] != 0 {
                    positions.push((i + j) as u16);
                }
            }
        }
        i += 8;
    }
    // Handle trailing bytes
    while i < map.len() {
        if map[i] != 0 { positions.push(i as u16); }
        i += 1;
    }
    positions
}

// ============================================================================
// StatePool — bounded pool of saved SVM states for stateful fuzzing
// ============================================================================

/// Bounded pool of saved SVM states for ItyFuzz-style stateful fuzzing.
///
/// States are deduplicated by fingerprint. The pool has a configurable capacity
/// and memory limit.
///
/// States that lead to invariant violations are removed from the pickable set
/// (`active_indices`) but kept in `states` for crash reconstruction via parent chains.
pub struct StatePool {
    pub(crate) states: Vec<StateEntry>,
    pub(crate) seen: FastHashSet<u64>,
    /// Indices into `states` that are still eligible for picking.
    /// Crashed states are removed from this vec (swap_remove) so they're never picked again.
    active_indices: Vec<usize>,
    /// Hashes of crash input bytes already written. Prevents duplicate crash files.
    crash_hashes: FastHashSet<u64>,
    capacity: usize,
    /// Maximum depth (action chain length) for states in the pool.
    /// States deeper than this are rejected to bound per-iteration cost.
    max_depth: u32,
    /// Total picks across all states (atomic for lock-free concurrent picking).
    pub(crate) total_picks: AtomicU64,
    /// AFLFast-style edge frequency table: how many active states hit each coverage map position.
    /// 65536 entries (128KB). Incremented on add, decremented on eviction/crash.
    pub(crate) edge_freq: Vec<u16>,
    /// N-gram frequency tables: [0]=2-gram, [1]=3-gram, [2]=4-gram.
    /// Key: FxHash of variant sequence. Value: count of active states with this n-gram.
    /// Used to compute action-path rarity at add-time.
    ngram_freq: [FastHashMap<u64, u32>; 3],
    /// Per-state-class statistics for SCFuzz-inspired scheduling.
    pub(crate) registry: StateRegistry,
    /// Current fuzz phase (Coverage bootstrap vs Blended with SCFuzz formula).
    pub(crate) phase: FuzzPhase,
    /// Current iteration counter (set by the fuzzing loop).
    pub(crate) current_iteration: u64,
    /// Counter for periodic n-gram rarity refresh.
    ngram_refresh_counter: u32,
}

impl StatePool {
    /// Create a new state pool with the given capacity and max depth.
    ///
    /// `max_depth` caps how deep any state lineage can go. States with
    /// `depth > max_depth` are rejected by `try_add()`, bounding the number
    /// of accounts any single chain can create and keeping per-iteration cost flat.
    pub fn new(capacity: usize, max_depth: u32) -> Self {
        Self {
            states: Vec::with_capacity(capacity.min(1024)), // pre-alloc up to 1K
            seen: FastHashSet::default(),
            active_indices: Vec::with_capacity(capacity.min(1024)),
            crash_hashes: FastHashSet::default(),
            capacity,
            max_depth,
            total_picks: AtomicU64::new(0),
            edge_freq: vec![0u16; 65536],
            ngram_freq: [
                FastHashMap::default(),
                FastHashMap::default(),
                FastHashMap::default(),
            ],
            registry: StateRegistry::new(),
            phase: FuzzPhase::Coverage,
            current_iteration: 0,
            ngram_refresh_counter: 0,
        }
    }

    /// Compute n-gram keys for a new state being added.
    /// Walks parent chain up to 3 levels back (for 4-gram).
    /// Returns [2-gram_key, 3-gram_key, 4-gram_key] where 0 means N/A.
    fn compute_ngram_keys(&self, action_variant: Option<u16>, parent_idx: Option<usize>) -> [u64; 3] {
        let self_variant = match action_variant {
            Some(v) => v,
            None => return [0; 3],
        };

        // Collect up to 3 ancestor variants
        let mut ancestors: [u16; 3] = [0; 3];
        let mut ancestor_count = 0usize;
        let mut cur_idx = parent_idx;
        while ancestor_count < 3 {
            let idx = match cur_idx {
                Some(i) if i < self.states.len() => i,
                _ => break,
            };
            match self.states[idx].action_variant {
                Some(v) => {
                    ancestors[ancestor_count] = v;
                    ancestor_count += 1;
                    cur_idx = self.states[idx].parent_idx;
                }
                None => break,
            }
        }

        let mut keys = [0u64; 3];

        if ancestor_count >= 1 {
            let mut h = FxHasher::default();
            ancestors[0].hash(&mut h);
            self_variant.hash(&mut h);
            keys[0] = h.finish();
        }
        if ancestor_count >= 2 {
            let mut h = FxHasher::default();
            ancestors[1].hash(&mut h);
            ancestors[0].hash(&mut h);
            self_variant.hash(&mut h);
            keys[1] = h.finish();
        }
        if ancestor_count >= 3 {
            let mut h = FxHasher::default();
            ancestors[2].hash(&mut h);
            ancestors[1].hash(&mut h);
            ancestors[0].hash(&mut h);
            self_variant.hash(&mut h);
            keys[2] = h.finish();
        }

        keys
    }

    /// Compute n-gram rarity score from frequency tables.
    /// Returns max(rarity_2, rarity_3, rarity_4), clamped to [0.1, 50.0].
    /// Uses max_freq/count ratio for strong differentiation: a unique 4-gram
    /// vs the most common one can get up to 36x boost.
    fn compute_ngram_rarity(&self, keys: &[u64; 3]) -> f64 {
        let mut max_rarity = 1.0_f64;

        for (level, &key) in keys.iter().enumerate() {
            if key == 0 { continue; }

            let freq_map = &self.ngram_freq[level];
            let count = freq_map.get(&key).copied().unwrap_or(1) as f64;

            // Use max frequency as reference (not mean) for stronger differentiation.
            // mean_freq/count collapses when the freq table is dense (many entries near mean).
            // max_freq/count creates a much wider spread: unique sequences vs the most
            // common one get massive boosts, and common sequences get demoted below 1.0.
            let max_freq = freq_map.values().copied().max().unwrap_or(1) as f64;

            let ratio = max_freq / count;
            let rarity = match level {
                0 => ratio.powf(0.4),    // 2-gram: dampened
                1 => ratio.powf(0.5),    // 3-gram: moderate
                _ => ratio.powf(0.6),    // 4-gram: strongest signal
            };

            max_rarity = max_rarity.max(rarity);
        }

        max_rarity.clamp(0.1, 50.0)
    }

    /// Try to add a new state. Returns true if the state was novel and added.
    /// If `parent_idx` is Some, increments the parent's `novel_children` counter.
    /// `novelty_bits` is the number of new coverage bits this state discovered
    /// (edges + hitcount buckets + state buckets). Higher = rarer seed.
    pub fn try_add(
        &mut self,
        fingerprint: u64,
        delta: SvmSnapshot,
        depth: u32,
        parent_idx: Option<usize>,
        action_bytes: Vec<u8>,
        action_desc: String,
        action_variant: Option<u16>,
        action_field_bytes: Vec<u8>,
        fixture_state: Option<Arc<dyn std::any::Any + Send + Sync>>,
        novelty_bits: u32,
        edge_novelty: u32,
        action_succeeded: bool,
        coverage_positions: Option<Vec<u16>>,
    ) -> bool {
        if self.states.len() >= self.capacity {
            // Evict the lowest-weighted active state to make room
            if let Some(evict_pos) = self.find_weakest_active() {
                let evict_idx = self.active_indices[evict_pos];
                self.active_indices.swap_remove(evict_pos);
                let evict_dedup = self.states[evict_idx].fingerprint & ((1u64 << FINGERPRINT_BITS) - 1);
                self.seen.remove(&evict_dedup);
                // Decrement edge frequency for evicted state
                if let Some(ref positions) = self.states[evict_idx].edge_positions {
                    for &pos in positions.iter() {
                        self.edge_freq[pos as usize] = self.edge_freq[pos as usize].saturating_sub(1);
                    }
                }
                // Decrement n-gram frequencies
                for (level, &key) in self.states[evict_idx].ngram_keys.iter().enumerate() {
                    if key != 0 {
                        if let Some(count) = self.ngram_freq[level].get_mut(&key) {
                            *count = count.saturating_sub(1);
                        }
                    }
                }
            } else {
                return false;
            }
        }
        if depth > self.max_depth {
            return false; // too deep — cap action chain length
        }
        // Truncate fingerprint for dedup to force collisions.
        // Full fingerprint is still stored in the entry for state_class extraction.
        let dedup_key = fingerprint & ((1u64 << FINGERPRINT_BITS) - 1);
        if !self.seen.insert(dedup_key) {
            return false; // already seen this fingerprint class
        }
        let idx = self.states.len();
        let pool_size_at_add = idx as u32;

        // Compute edge rarity score and update frequency table
        let (rarity_score, edge_positions) = if let Some(positions) = coverage_positions {
            if !positions.is_empty() && novelty_bits > 0 {
                // Mean inverse frequency: rare edges → higher score
                let score: f64 = positions.iter()
                    .map(|&pos| 1.0 / (self.edge_freq[pos as usize] as f64 + 1.0))
                    .sum::<f64>() / positions.len() as f64;
                // Increment frequency table for this state's positions
                for &pos in &positions {
                    self.edge_freq[pos as usize] = self.edge_freq[pos as usize].saturating_add(1);
                }
                (score, Some(Arc::new(positions)))
            } else {
                (0.0, None)
            }
        } else {
            (0.0, None)
        };

        // Compute n-gram keys and rarity score.
        let ngram_keys = self.compute_ngram_keys(action_variant, parent_idx);
        for (level, &key) in ngram_keys.iter().enumerate() {
            if key != 0 {
                *self.ngram_freq[level].entry(key).or_insert(0) += 1;
            }
        }
        let ngram_rarity = self.compute_ngram_rarity(&ngram_keys);

        self.states.push(StateEntry {
            fingerprint,
            delta: Arc::new(delta),
            depth,
            parent_idx,
            action_bytes: Arc::new(action_bytes),
            action_desc,
            action_variant,
            action_field_bytes: Arc::new(action_field_bytes),
            fixture_state,
            pick_count: AtomicU32::new(0),
            novel_children: 0,
            violation_count: 0,
            novelty_bits,
            edge_novelty,
            action_succeeded,
            pool_size_at_add,
            rarity_score,
            edge_positions,
            ngram_rarity,
            ngram_keys,
            barren_picks: 0,
        });
        // Only add to active set if depth < max_depth.
        // States at max_depth can't extend further — keep them in `states` + `seen`
        // for dedup and parent chain reconstruction, but don't waste picks on them.
        if depth < self.max_depth {
            self.active_indices.push(idx);
        }
        // Credit parent for producing a novel child and reset barren counter
        if let Some(pidx) = parent_idx {
            if let Some(parent) = self.states.get_mut(pidx) {
                parent.novel_children += 1;
                parent.barren_picks = 0;
            }
        }

        // Registry accounting
        let child_sc = state_class_from_fingerprint(fingerprint);
        self.registry.record_trigger(child_sc, depth);
        if let Some(pidx) = parent_idx {
            if let Some(parent) = self.states.get(pidx) {
                let parent_sc = state_class_from_fingerprint(parent.fingerprint);
                if novelty_bits > 0 {
                    self.registry.record_path_discovered(parent_sc);
                }
                if child_sc != parent_sc {
                    self.registry.record_out_transition(parent_sc);
                }
                self.registry.record_new_find(parent_sc, self.current_iteration);
            }
        }

        true
    }

    /// Check if a fingerprint would be novel (not yet in the seen set).
    /// Used as a lightweight admission gate before computing expensive deltas.
    pub fn is_novel(&self, fingerprint: u64) -> bool {
        if self.states.len() >= self.capacity && self.active_indices.is_empty() {
            return false; // full with no evictable states
        }
        let dedup_key = fingerprint & ((1u64 << FINGERPRINT_BITS) - 1);
        !self.seen.contains(&dedup_key)
    }

    /// Pick a random active state index using the given random value (uniform).
    /// Returns None if no active (non-crashed) states remain.
    /// Build cumulative weight array for all active states. Returns (cumulative, total).
    /// Reuse this for multiple picks within the same batch to avoid O(n) recomputation.
    pub fn build_weight_distribution(&self) -> (Vec<f64>, f64) {
        let n = self.active_indices.len();
        let tp = self.total_picks.load(Ordering::Relaxed) as f64;
        let mut cumulative = Vec::with_capacity(n);
        let mut total: f64 = 0.0;
        for &idx in &self.active_indices {
            let w = self.compute_weight(&self.states[idx], tp, self.max_depth);
            total += w;
            cumulative.push(total);
        }
        (cumulative, total)
    }

    /// Sample one state from a pre-built weight distribution. O(log n).
    /// Does NOT increment pick_count or total_picks.
    pub fn sample_from_distribution(&self, cumulative: &[f64], total: f64, rand_val: u64) -> Option<usize> {
        if cumulative.is_empty() || total <= 0.0 {
            return self.pick_random(rand_val);
        }
        let target = (rand_val as f64 / u64::MAX as f64) * total;
        let pos = match cumulative.binary_search_by(|w| w.partial_cmp(&target).unwrap()) {
            Ok(i) => i,
            Err(i) => i.min(cumulative.len() - 1),
        };
        Some(self.active_indices[pos])
    }

    pub fn pick_random(&self, rand_val: u64) -> Option<usize> {
        if self.active_indices.is_empty() {
            None
        } else {
            let pos = rand_val as usize % self.active_indices.len();
            Some(self.active_indices[pos])
        }
    }

    /// Pick an active state using bifurcated power scheduling.
    ///
    /// Coverage states (novel>0): 10x floor + steep exponential + rarity bonus.
    /// Non-coverage states (novel=0): fast explore_decay only.
    ///
    /// Never-picked states get maximum priority. Returns None if no active states.
    pub fn pick_weighted(&self, rand_val: u64) -> Option<usize> {
        if self.active_indices.is_empty() {
            return None;
        }
        self.total_picks.fetch_add(1, Ordering::Relaxed);

        let n = self.active_indices.len();
        if n == 1 {
            let idx = self.active_indices[0];
            self.states[idx].pick_count.fetch_add(1, Ordering::Relaxed);
            return Some(idx);
        }

        let tp = self.total_picks.load(Ordering::Relaxed) as f64;
        let mut cumulative = Vec::with_capacity(n);
        let mut total: f64 = 0.0;
        for &idx in &self.active_indices {
            let w = self.compute_weight(&self.states[idx], tp, self.max_depth);
            total += w;
            cumulative.push(total);
        }

        // If all weights are zero (e.g. all states at max depth), fall back to uniform random
        if total <= 0.0 {
            let pos = rand_val as usize % n;
            let idx = self.active_indices[pos];
            self.states[idx].pick_count.fetch_add(1, Ordering::Relaxed);
            return Some(idx);
        }

        let target = (rand_val as f64 / u64::MAX as f64) * total;
        let pos = match cumulative.binary_search_by(|w| w.partial_cmp(&target).unwrap()) {
            Ok(i) => i,
            Err(i) => i.min(n - 1),
        };
        let idx = self.active_indices[pos];
        self.states[idx].pick_count.fetch_add(1, Ordering::Relaxed);
        Some(idx)
    }

    /// Compute selection weight for a single state entry (bifurcated power schedule).
    ///
    /// Two paths based on whether the state discovered any novel coverage:
    ///
    /// **Coverage states (novelty_bits > 0)**: 10x floor + steep exponential + rarity bonus.
    /// NO explore_decay — well-explored coverage states retain weight from floor + rarity.
    /// - Coverage floor: 10x base ensures ANY coverage state dominates non-coverage.
    /// - Novelty power: `2^(effective_bits/2)` — steeper than old `/4` divisor.
    /// - Rarity bonus: `log2(1 + pool_size_at_add/100)` — states added late found rarer territory.
    /// - Productivity with moderate decay: `sqrt(1 + novel_children)` halving at 500 picks.
    ///
    /// **Non-coverage states (novelty_bits = 0)**: Fast explore_decay only.
    /// Brief exploration, then deprioritize. Halves every 50 picks.
    ///
    /// Common factors: success boost (2x) and depth preference (shallow bias).
    /// Never-picked states get maximum priority. Max-depth states get zero weight.
    #[inline]
    pub(crate) fn compute_weight(&self, s: &StateEntry, _total_picks: f64, max_depth: u32) -> f64 {
        // Max-depth states can't extend — don't pick them as parents
        if s.depth >= max_depth {
            return 0.0;
        }

        let picks = s.pick_count.load(Ordering::Relaxed) as f64;

        if picks < 1.0 {
            return 1e6; // never-picked = top priority
        }

        // Common factors (no decay, structural signals)
        let success_boost = if s.action_succeeded { 2.0 } else { 1.0 };
        let depth_factor = 1.0 / (1.0 + 0.025 * s.depth as f64);

        // Barren decay: exponential weight reduction for states that keep failing
        // to produce novel children. Halves every 50 barren picks.
        // A state with 200 consecutive barren picks gets 0.0625x weight (1/16).
        let barren_decay = 1.0 / (1.0 + s.barren_picks as f64 / 50.0);

        // N-gram action-path rarity: precomputed at add-time from 2/3/4-gram frequency tables.
        // States reached via rare action sequences get higher weight. The longest matching
        // rare n-gram dominates (e.g., a rare 4-gram like advance→deactivate→withdraw→delegate
        // gives up to 25x boost vs max 4x from a 2-gram).
        let ngram_rarity = s.ngram_rarity;

        // Gate coverage power schedule on EDGE coverage, not combined novelty.
        // Field-novel states use SCFuzz formula with a modest bonus.
        if s.edge_novelty == 0 {
            if s.novelty_bits > 0 {
                // Field-novel only: minimum exploration floor + depth bonus.
                // Deeper states explored rarer territory and deserve more picks.
                // The floor ensures every field-novel state gets enough picks to
                // potentially discover edge coverage in its children.
                let depth_bonus = 2.0 + 0.5 * s.depth as f64;  // depth 0 → 2x, depth 7 → 5.5x
                // Productive parents get a strong boost: if children found novel coverage,
                // this state is a valuable stepping stone (e.g., advance_slots intermediates
                // whose children discover new deactivation/withdrawal code paths).
                let child_bonus = if s.novel_children > 0 {
                    (2.0 + s.novel_children as f64 * 5.0).sqrt()
                } else {
                    1.0
                };
                let explore_decay = 1.0 / (1.0 + picks / 200.0);  // slower decay: halves at 200

                match self.phase {
                    FuzzPhase::Coverage => {
                        return depth_bonus * child_bonus * explore_decay * ngram_rarity * barren_decay * success_boost * depth_factor;
                    }
                    FuzzPhase::Blended => {
                        let sc = state_class_from_fingerprint(s.fingerprint);
                        let scfuzz = self.registry.state_seed_weight(sc, picks, s.action_succeeded);
                        // Take max of SCFuzz and exploration floor — don't let SCFuzz zero out exploration
                        let base = scfuzz.max(depth_bonus * explore_decay);
                        return base * child_bonus * ngram_rarity * barren_decay * depth_factor;
                    }
                }
            }
            // novelty_bits == 0: no novelty at all — unchanged
            match self.phase {
                FuzzPhase::Coverage => {
                    let explore_decay = 1.0 / (1.0 + picks / 50.0);
                    return explore_decay * ngram_rarity * barren_decay * success_boost * depth_factor;
                }
                FuzzPhase::Blended => {
                    let sc = state_class_from_fingerprint(s.fingerprint);
                    return self.registry.state_seed_weight(sc, picks, s.action_succeeded) * ngram_rarity * barren_decay * depth_factor;
                }
            }
        }

        // --- Edge coverage states: power schedule ---

        // 1. Coverage floor: exponential decay from 1000x → 2x based on pool fill fraction.
        //    Early: coverage states massively dominate scheduling for fast discovery.
        //    Late: decays so stateful signals (SCFuzz) take over for deeper exploration.
        //    Self-calibrating: tied to fill fraction (pool_size/capacity), not absolute count.
        let fill_frac = self.states.len() as f64 / self.capacity.max(1) as f64;
        let coverage_floor = 2.0 + 998.0 * (-fill_frac * 6.0).exp();

        // 2. Novelty power: 2^(effective_bits/2) — steeper than old /4.
        //    novel=1→1.41, novel=10→32, novel=50→capped at 2^40.
        //    At picks=500 with budget=300: novel=50 effective=12.5→2^6.25≈76x.
        let novelty_budget = 300.0;
        let effective_bits = s.edge_novelty as f64 / (1.0 + picks / novelty_budget);
        let novelty_power = 2.0_f64.powf((effective_bits / 2.0).min(40.0));

        // 3. Rarity bonus: AFLFast-style edge rarity score.
        //    Uses precomputed mean inverse frequency of this state's coverage positions.
        //    Falls back to pool_size_at_add proxy when no positions were provided.
        let rarity = if s.rarity_score > 0.0 {
            // Scale: score=1.0 (all unique edges) → ~3.0, score=0.01 (all common) → ~1.2
            (1.0 + s.rarity_score * 20.0).ln().max(1.0)
        } else {
            // Fallback for states without edge positions (seeds, no-tracing mode)
            (1.0 + s.pool_size_at_add as f64 / 100.0).log2().clamp(1.0, 3.0)
        };

        // 4. Productivity with moderate decay (halves at 500 picks).
        let productivity_raw = (1.0 + s.novel_children as f64).sqrt();
        let productivity_decay = 1.0 / (1.0 + picks / 500.0);
        let productivity = 1.0 + (productivity_raw - 1.0) * productivity_decay;

        coverage_floor * novelty_power * rarity * productivity * ngram_rarity * barren_decay * success_boost * depth_factor
    }

    /// Fill a batch of picks using weighted selection. Returns the number of picks made.
    /// More efficient than calling pick_weighted() in a loop because it computes
    /// weights once and samples multiple times.
    /// Fill a batch of picks using weighted selection. Returns the number of picks made.
    /// More efficient than calling pick_weighted() in a loop because it computes
    /// weights once and samples multiple times.
    ///
    /// Output tuple: (delta, depth, state_idx, action_bytes, parent_variant, parent_field_bytes, fingerprint, fixture_state)
    pub fn pick_weighted_batch(
        &self,
        rng_vals: &[u64],
        out: &mut Vec<(Arc<SvmSnapshot>, u32, usize, Arc<Vec<u8>>, Option<u16>, Arc<Vec<u8>>, u64, Option<Arc<dyn std::any::Any + Send + Sync>>)>,
    ) -> usize {
        if self.active_indices.is_empty() {
            return 0;
        }

        let n = self.active_indices.len();

        // Build cumulative weight array once
        let tp = self.total_picks.load(Ordering::Relaxed) as f64;
        let mut cumulative = Vec::with_capacity(n);
        let mut total: f64 = 0.0;
        for &idx in &self.active_indices {
            let w = self.compute_weight(&self.states[idx], tp, self.max_depth);
            total += w;
            cumulative.push(total);
        }

        // If all weights are zero, fall back to uniform random
        if total <= 0.0 {
            let mut count = 0;
            for &rv in rng_vals {
                let pos = rv as usize % n;
                let idx = self.active_indices[pos];
                self.states[idx].pick_count.fetch_add(1, Ordering::Relaxed);
                self.total_picks.fetch_add(1, Ordering::Relaxed);
                let entry = &self.states[idx];
                out.push((
                    entry.delta.clone(), entry.depth, idx,
                    entry.action_bytes.clone(), entry.action_variant,
                    entry.action_field_bytes.clone(), entry.fingerprint,
                    entry.fixture_state.clone(),
                ));
                count += 1;
            }
            return count;
        }

        let mut count = 0;
        for &rv in rng_vals {
            let target = (rv as f64 / u64::MAX as f64) * total;
            let pos = match cumulative.binary_search_by(|w| w.partial_cmp(&target).unwrap()) {
                Ok(i) => i,
                Err(i) => i.min(n - 1),
            };
            let idx = self.active_indices[pos];
            self.states[idx].pick_count.fetch_add(1, Ordering::Relaxed);
            self.total_picks.fetch_add(1, Ordering::Relaxed);

            let entry = &self.states[idx];
            out.push((
                entry.delta.clone(),
                entry.depth,
                idx,
                entry.action_bytes.clone(),
                entry.action_variant,
                entry.action_field_bytes.clone(),
                entry.fingerprint,
                entry.fixture_state.clone(),
            ));
            count += 1;
        }
        count
    }

    /// Get a reference to a state entry.
    pub fn get(&self, idx: usize) -> Option<&StateEntry> {
        self.states.get(idx)
    }

    /// Total number of states in the pool (including crashed).
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Number of active (non-crashed) states eligible for picking.
    pub fn active_count(&self) -> usize {
        self.active_indices.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Whether the pool is at capacity.
    pub fn is_full(&self) -> bool {
        self.states.len() >= self.capacity
    }

    /// Remove a state from the pickable set (after a crash).
    /// The state remains in `states` for parent chain reconstruction.
    pub fn mark_crashed(&mut self, state_idx: usize) {
        if let Some(pos) = self.active_indices.iter().position(|&i| i == state_idx) {
            self.active_indices.swap_remove(pos);
            // Decrement edge frequency for crashed state
            if let Some(ref positions) = self.states[state_idx].edge_positions {
                for &pos in positions.iter() {
                    self.edge_freq[pos as usize] = self.edge_freq[pos as usize].saturating_sub(1);
                }
            }
            // Decrement n-gram frequencies for crashed state
            for (level, &key) in self.states[state_idx].ngram_keys.iter().enumerate() {
                if key != 0 {
                    if let Some(count) = self.ngram_freq[level].get_mut(&key) {
                        *count = count.saturating_sub(1);
                    }
                }
            }
        }
    }

    /// Record a violation against a state. Increments violation_count for diagnostics.
    /// Note: violation_count is no longer used in weight calculation (violations are
    /// too rare to matter for scheduling). States are removed via mark_crashed() instead.
    pub fn record_violation(&mut self, state_idx: usize) {
        if let Some(entry) = self.states.get_mut(state_idx) {
            entry.violation_count += 1;
        }
    }

    /// Check if the fuzz phase should advance from Coverage to Blended.
    /// Called periodically (e.g., at batch boundaries) to transition once
    /// enough states and state classes have been observed.
    pub fn maybe_advance_phase(&mut self) {
        if matches!(self.phase, FuzzPhase::Coverage)
            && self.states.len() > 100
            && self.registry.len() > 50
        {
            self.phase = FuzzPhase::Blended;
        }
        // Periodically refresh n-gram rarity scores from current frequency tables.
        // Every 200 batch boundaries (~12800 iterations). O(active_states) pass.
        self.ngram_refresh_counter += 1;
        if self.ngram_refresh_counter >= 200 {
            self.ngram_refresh_counter = 0;
            self.refresh_ngram_rarity();
        }
    }

    /// Recompute ngram_rarity for all active states from current frequency tables.
    fn refresh_ngram_rarity(&mut self) {
        for &idx in &self.active_indices {
            let keys = self.states[idx].ngram_keys;
            let rarity = self.compute_ngram_rarity(&keys);
            self.states[idx].ngram_rarity = rarity;
        }
    }

    /// Record a barren pick (no novel child produced). Increments the state's
    /// consecutive barren counter, which causes exponential weight decay.
    pub fn record_barren_pick(&mut self, state_idx: usize) {
        if let Some(entry) = self.states.get_mut(state_idx) {
            entry.barren_picks = entry.barren_picks.saturating_add(1);
        }
    }

    /// Mutable access to the state registry (for flushing pending selects from macro codegen).
    pub fn registry_mut(&mut self) -> &mut StateRegistry {
        &mut self.registry
    }

    /// Set the current iteration counter (called from macro codegen at batch boundaries).
    pub fn set_current_iteration(&mut self, iteration: u64) {
        self.current_iteration = iteration;
    }

    /// Find the position (in `active_indices`) of the weakest active state for eviction.
    /// Returns None if no active states exist.
    fn find_weakest_active(&self) -> Option<usize> {
        if self.active_indices.is_empty() {
            return None;
        }
        let tp = self.total_picks.load(Ordering::Relaxed) as f64;

        // First pass: find weakest among states with NO novel children.
        // States whose children found new coverage are valuable stepping stones
        // (e.g., advance_slots intermediates) and should be protected from eviction.
        let mut min_weight = f64::MAX;
        let mut min_pos: Option<usize> = None;
        for (pos, &idx) in self.active_indices.iter().enumerate() {
            if self.states[idx].novel_children > 0 { continue; }
            let w = self.compute_weight(&self.states[idx], tp, self.max_depth);
            if w < min_weight {
                min_weight = w;
                min_pos = Some(pos);
            }
        }

        // Fallback: if all active states have novel children, evict the weakest overall.
        if min_pos.is_none() {
            for (pos, &idx) in self.active_indices.iter().enumerate() {
                let w = self.compute_weight(&self.states[idx], tp, self.max_depth);
                if w < min_weight {
                    min_weight = w;
                    min_pos = Some(pos);
                }
            }
        }

        min_pos
    }

    /// Check if a crash is novel by its action sequence hash.
    /// Returns true if this is the first time we've seen this sequence (should write crash file).
    /// Returns false if duplicate (skip writing).
    pub fn is_novel_crash(&mut self, input_hash: u64) -> bool {
        self.crash_hashes.insert(input_hash)
    }

    /// Number of unique crashes seen.
    pub fn unique_crash_count(&self) -> usize {
        self.crash_hashes.len()
    }

    /// Number of crashed (removed) states.
    pub fn crashed_count(&self) -> usize {
        self.states.len() - self.active_indices.len()
    }

    /// Write all pool entries' action sequences to disk as FuzzInput binary files.
    /// Returns the number of files written. Skips the initial state (depth 0, empty actions).
    pub fn export_corpus(&self, dir: &str) -> std::io::Result<usize> {
        std::fs::create_dir_all(dir)?;
        let mut count = 0;
        for entry in &self.states {
            // Skip initial empty state (just a 4-byte header with count=0)
            if entry.action_bytes.len() <= 4 { continue; }
            let mut hasher = FxHasher::default();
            entry.action_bytes.hash(&mut hasher);
            let hash = hasher.finish();
            let path = format!("{}/corpus_{:016x}", dir, hash);
            std::fs::write(&path, &*entry.action_bytes)?;
            count += 1;
        }
        Ok(count)
    }

    /// Dump pool state to a single human-readable report file for debugging.
    ///
    /// Includes: state index table with weights, action sequence n-gram tree,
    /// depth/weight distributions, and action stats if provided.
    ///
    /// `action_stats`: optional per-state-class action success rates from the worker.
    pub fn export_pool_debug(
        &self,
        dir: &str,
        action_stats: Option<&ActionStatsMap>,
    ) -> std::io::Result<usize> {
        use std::fmt::Write as FmtWrite;
        std::fs::create_dir_all(dir)?;

        let active_set: FastHashSet<usize> = self.active_indices.iter().copied().collect();
        let tp = self.total_picks.load(Ordering::Relaxed);
        let tp_f = tp as f64;

        // Pre-compute weights for all active states
        let mut weights: FastHashMap<usize, f64> = FastHashMap::default();
        let mut total_weight: f64 = 0.0;
        for &idx in &self.active_indices {
            let w = self.compute_weight(&self.states[idx], tp_f, self.max_depth);
            weights.insert(idx, w);
            total_weight += w;
        }

        let mut out = String::with_capacity(self.states.len() * 200 + 8192);

        // ================================================================
        // Header
        // ================================================================
        let _ = writeln!(out, "State Pool Report — {} states ({} active, {} evicted/crashed), {} total picks",
            self.states.len(), self.active_indices.len(),
            self.states.len() - self.active_indices.len(), tp);
        let _ = writeln!(out, "{}\n", "=".repeat(80));

        // ================================================================
        // Section 1: State index table with weights
        // ================================================================
        let _ = writeln!(out, "STATE INDEX");
        let _ = writeln!(out, "-----------");
        let _ = writeln!(out, "{:<6} {:<4} {:<6} {:<8} {:<10} {:<7} {:<18} {:<5} {:<5} {:<5} {:<5} {:<5} {:<5} {:<5} {:<7} {:<6} {}",
            "idx", "dep", "actv", "picks", "weight", "prob%", "fingerprint", "novl", "ecov", "type", "chld", "viol", "ok", "psz", "rarity", "ngram", "action");

        for (idx, entry) in self.states.iter().enumerate() {
            let active = if active_set.contains(&idx) { "yes" } else { "-" };
            let picks = entry.pick_count.load(Ordering::Relaxed);
            let w = weights.get(&idx).copied().unwrap_or(0.0);
            let prob = if total_weight > 0.0 { w / total_weight * 100.0 } else { 0.0 };
            let wtype = if entry.edge_novelty > 0 { "edge" } else if entry.novelty_bits > 0 { "fld" } else { "none" };
            let _ = writeln!(out, "{:<6} {:<4} {:<6} {:<8} {:<10.2} {:<7.3} {:018x} {:<5} {:<5} {:<5} {:<5} {:<5} {:<5} {:<5} {:<7.4} {:<6.1} {}",
                idx, entry.depth, active, picks, w, prob, entry.fingerprint,
                entry.novelty_bits, entry.edge_novelty, wtype, entry.novel_children, entry.violation_count,
                if entry.action_succeeded { "ok" } else { "fail" },
                entry.pool_size_at_add,
                entry.rarity_score,
                entry.ngram_rarity,
                if entry.action_desc.is_empty() { "(initial)".to_string() } else {
                    entry.action_desc.lines().collect::<Vec<_>>().join(" | ")
                });
        }
        let _ = writeln!(out, "");

        // ================================================================
        // Section 2: Action sequence n-gram tree
        // ================================================================
        let _ = writeln!(out, "ACTION SEQUENCE TREE (n-gram)");
        let _ = writeln!(out, "----------------------------");
        let _ = writeln!(out, "Shows which action sequences exist in the pool as a prefix tree.");
        let _ = writeln!(out, "Each node: action_name [Nx (P%)] with annotations.\n");
        self.write_ngram_tree(&mut out, &active_set);
        let _ = writeln!(out, "");

        // ================================================================
        // Section 3: Depth distribution
        // ================================================================
        let _ = writeln!(out, "DEPTH DISTRIBUTION");
        let _ = writeln!(out, "------------------");
        let max_depth = self.states.iter().map(|s| s.depth).max().unwrap_or(0);
        for d in 0..=max_depth {
            let total = self.states.iter().filter(|s| s.depth == d as u32).count();
            let active = self.active_indices.iter()
                .filter(|&&i| self.states[i].depth == d as u32).count();
            if total > 0 {
                let _ = writeln!(out, "  depth {:<3}: {:>4} total, {:>4} active", d, total, active);
            }
        }
        let _ = writeln!(out, "");

        // ================================================================
        // Section 4: Weight distribution
        // ================================================================
        let _ = writeln!(out, "WEIGHT DISTRIBUTION (active states)");
        let _ = writeln!(out, "------------------------------------");
        if !self.active_indices.is_empty() {
            let mut sorted_weights: Vec<(usize, f64)> = self.active_indices.iter()
                .map(|&idx| (idx, weights.get(&idx).copied().unwrap_or(0.0)))
                .collect();
            sorted_weights.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

            let _ = writeln!(out, "  Top 15:");
            for (rank, (idx, w)) in sorted_weights.iter().take(15).enumerate() {
                let entry = &self.states[*idx];
                let prob = if total_weight > 0.0 { w / total_weight * 100.0 } else { 0.0 };
                let _ = writeln!(out, "    {:>3}. #{:<5} w={:<9.2} p={:.3}%  d={}  picks={}  novel={}  {}",
                    rank + 1, idx, w, prob, entry.depth,
                    entry.pick_count.load(Ordering::Relaxed),
                    entry.novelty_bits,
                    if entry.action_desc.is_empty() { "(initial)" } else {
                        entry.action_desc.lines().next().unwrap_or("")
                    });
            }

            if sorted_weights.len() > 15 {
                let _ = writeln!(out, "\n  Bottom 10:");
                let start = sorted_weights.len().saturating_sub(10);
                for (i, (idx, w)) in sorted_weights[start..].iter().enumerate() {
                    let entry = &self.states[*idx];
                    let prob = if total_weight > 0.0 { w / total_weight * 100.0 } else { 0.0 };
                    let _ = writeln!(out, "    {:>3}. #{:<5} w={:<9.4} p={:.4}%  d={}  picks={}  novel={}  {}",
                        start + i + 1, idx, w, prob, entry.depth,
                        entry.pick_count.load(Ordering::Relaxed),
                        entry.novelty_bits,
                        if entry.action_desc.is_empty() { "(initial)" } else {
                            entry.action_desc.lines().next().unwrap_or("")
                        });
                }
            }

            let pcts = [10, 25, 50, 75, 90];
            let _ = writeln!(out, "\n  Percentiles:");
            for &p in &pcts {
                let i = (sorted_weights.len() * p / 100).min(sorted_weights.len() - 1);
                let _ = writeln!(out, "    p{}: w={:.4}, p={:.4}%",
                    p, sorted_weights[i].1,
                    if total_weight > 0.0 { sorted_weights[i].1 / total_weight * 100.0 } else { 0.0 });
            }
        }
        let _ = writeln!(out, "");

        // ================================================================
        // Section 5: Action stats
        // ================================================================
        if let Some(stats_map) = action_stats {
            let _ = writeln!(out, "ACTION STATS (aggregated across all state classes)");
            let _ = writeln!(out, "-------------------------------------------------");
            let all_stats = stats_map.aggregate_all();
            // Build variant name lookup from pool entries' action_desc
            let variant_names = self.infer_variant_names();
            for (vi, [s, t]) in all_stats.iter().enumerate() {
                let name = variant_names.get(&(vi as u16)).map(|s| s.as_str()).unwrap_or("?");
                let rate = if *t > 0 { *s as f64 / *t as f64 * 100.0 } else { 0.0 };
                let _ = writeln!(out, "  {:<3} {:<30} {:>6}/{:<6} ({:>5.1}% ok)",
                    vi, name, s, t, rate);
            }
            let total_attempts: u32 = all_stats.iter().map(|[_, t]| t).sum();
            let total_successes: u32 = all_stats.iter().map(|[s, _]| s).sum();
            if total_attempts > 0 {
                let _ = writeln!(out, "  {:<34} {:>6}/{:<6} ({:>5.1}% ok)",
                    "TOTAL", total_successes, total_attempts,
                    total_successes as f64 / total_attempts as f64 * 100.0);
            }

            // Top state classes by attempt count
            let _ = writeln!(out, "\n  Top state classes (by attempts):");
            let mut class_totals: Vec<(u16, u32)> = stats_map.iter_classes()
                .map(|(sc, stats)| {
                    let total: u32 = stats.counts_ref().iter().map(|[_, t]| t).sum();
                    (sc, total)
                })
                .collect();
            class_totals.sort_by(|a, b| b.1.cmp(&a.1));
            for (sc, total_att) in class_totals.iter().take(15) {
                if let Some(stats) = stats_map.get_stats(*sc) {
                    let _ = writeln!(out, "\n    class {:04x} ({} attempts):", sc, total_att);
                    for (vi, count) in stats.counts_ref().iter().enumerate() {
                        if count[1] == 0 { continue; }
                        let name = variant_names.get(&(vi as u16)).map(|s| s.as_str()).unwrap_or("?");
                        let rate = count[0] as f64 / count[1] as f64 * 100.0;
                        let _ = writeln!(out, "      {:<3} {:<28} {:>5}/{:<5} ({:>5.1}% ok)",
                            vi, name, count[0], count[1], rate);
                    }
                }
            }
        }

        // ================================================================
        // Section 6: State Registry (SCFuzz stats)
        // ================================================================
        let _ = writeln!(out, "\nSTATE REGISTRY (phase: {:?}, {} classes)", self.phase, self.registry.len());
        let _ = writeln!(out, "--------------");
        if !self.registry.map.is_empty() {
            let _ = writeln!(out, "{:<6} {:<8} {:<8} {:<8} {:<8} {:<6} {:<12} {:<10}",
                "class", "trigger", "select", "paths", "out_tx", "depth", "last_find", "weight");
            // Sort by state_seed_weight descending, show top 30
            let mut entries: Vec<(u16, f64)> = self.registry.map.iter()
                .map(|(&sc, _)| {
                    (sc, self.registry.state_seed_weight(sc, 10.0, true))
                })
                .collect();
            entries.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            for (sc, w) in entries.iter().take(30) {
                if let Some(stats) = self.registry.get(*sc) {
                    let _ = writeln!(out, "{:04x}   {:<8} {:<8} {:<8} {:<8} {:<6} {:<12} {:<10.2}",
                        sc, stats.trigger_count, stats.select_count,
                        stats.paths_discovered, stats.out_transitions,
                        stats.depth, stats.last_new_find, w);
                }
            }
            if entries.len() > 30 {
                let _ = writeln!(out, "  ... {} more classes", entries.len() - 30);
            }
        }
        let _ = writeln!(out, "");

        std::fs::write(format!("{}/pool_report.txt", dir), &out)?;
        Ok(self.states.len())
    }

    /// Extract action name from action_desc, stripping params and outcome.
    /// "delegate_stake(authority=2) -> OK" → "delegate_stake"
    /// "delegate_stake -> OK" → "delegate_stake"
    fn action_name_from_desc(desc: &str) -> &str {
        // Strip " -> OK" / " -> FAIL" suffix first
        let base = desc.split(" -> ").next().unwrap_or(desc);
        // Strip params: "delegate_stake(authority=2)" → "delegate_stake"
        base.split('(').next().unwrap_or(base).trim()
    }

    /// Infer variant_idx -> name mapping from pool entries' action_desc strings.
    fn infer_variant_names(&self) -> FastHashMap<u16, String> {
        let mut names: FastHashMap<u16, String> = FastHashMap::default();
        for entry in &self.states {
            if let Some(vi) = entry.action_variant {
                names.entry(vi).or_insert_with(|| {
                    Self::action_name_from_desc(&entry.action_desc).to_string()
                });
            }
        }
        names
    }

    /// Write an n-gram prefix tree of action sequences in the pool.
    ///
    /// Each path root→leaf represents one pool state's full action chain.
    /// Branches are merged when they share a prefix, showing counts and annotations:
    /// - `[Nx (P%)]`: N states share this prefix, P% of total pool
    /// - `CRASHED Nx`: N of those states triggered invariant violations
    /// - `TERMINAL`: this is a leaf (pool state), not just a prefix
    fn write_ngram_tree(&self, out: &mut String, active_set: &FastHashSet<usize>) {
        // Build trie from action chains
        // Each node: action_name -> TrieNode
        struct TrieNode {
            children: FastHashMap<String, TrieNode>,
            count: usize,       // how many chains pass through
            terminal: usize,    // how many chains end here (= pool states at this depth)
            crashed: usize,     // terminal states that are crashed
            novel_bits: u32,    // sum of novelty_bits for terminal states
        }
        impl TrieNode {
            fn new() -> Self {
                Self { children: FastHashMap::default(), count: 0, terminal: 0, crashed: 0, novel_bits: 0 }
            }
        }

        let mut root = TrieNode::new();
        let total = self.states.len();

        for (idx, entry) in self.states.iter().enumerate() {
            // Reconstruct action chain for this state
            let mut chain = Vec::new();
            let mut cur = idx;
            loop {
                let e = &self.states[cur];
                if !e.action_desc.is_empty() {
                    chain.push(Self::action_name_from_desc(&e.action_desc).to_string());
                }
                match e.parent_idx {
                    Some(p) => cur = p,
                    None => break,
                }
            }
            chain.reverse();

            if chain.is_empty() { continue; } // skip initial state

            let is_crashed = !active_set.contains(&idx);
            let mut node = &mut root;
            for name in &chain {
                node.count += 1;
                node = node.children.entry(name.clone()).or_insert_with(TrieNode::new);
            }
            node.count += 1;
            node.terminal += 1;
            if is_crashed { node.crashed += 1; }
            node.novel_bits += entry.novelty_bits;
        }

        // Render trie
        fn render(node: &TrieNode, out: &mut String, prefix: &str, total: usize, max_depth: usize) {
            use std::fmt::Write as FmtWrite;
            if max_depth == 0 { return; }
            let mut children: Vec<(&String, &TrieNode)> = node.children.iter().collect();
            children.sort_by(|a, b| b.1.count.cmp(&a.1.count));

            let show_limit = 15;
            let hidden = if children.len() > show_limit { children.len() - show_limit } else { 0 };

            for (i, (name, child)) in children.iter().take(show_limit).enumerate() {
                let is_last = i == children.len().min(show_limit) - 1 && hidden == 0;
                let connector = if is_last { "\\--" } else { "|--" };
                let pct = if total > 0 { child.count as f64 / total as f64 * 100.0 } else { 0.0 };

                let mut annotation = format!("[{}x ({:.0}%)", child.count, pct);
                if child.novel_bits > 0 {
                    let _ = write!(annotation, "  novel:{}", child.novel_bits);
                }
                if child.crashed > 0 {
                    let _ = write!(annotation, "  CRASHED:{}x", child.crashed);
                }
                if child.terminal > 0 {
                    let _ = write!(annotation, "  TERMINAL:{}x", child.terminal);
                }
                annotation.push(']');

                let _ = writeln!(out, "{}{}  {}  {}", prefix, connector, name, annotation);

                let child_prefix = if is_last {
                    format!("{}    ", prefix)
                } else {
                    format!("{}|   ", prefix)
                };
                render(child, out, &child_prefix, total, max_depth - 1);
            }
            if hidden > 0 {
                let _ = writeln!(out, "{}    ... +{} more branches", prefix, hidden);
            }
        }

        render(&root, out, "  ", total, 10);
    }

    /// Return the full accumulated action sequence for a state.
    /// Each entry stores the complete FuzzInput bytes (4-byte count header +
    /// all action bytes from root to this state), so no chain walking needed.
    pub fn reconstruct_action_sequence(&self, state_idx: usize) -> Vec<u8> {
        (*self.states[state_idx].action_bytes).clone()
    }

    /// Walk the parent chain and return the sequence of action variant indices (oldest first).
    /// Used for coarse crash deduplication — same action types = same crash class.
    pub fn reconstruct_variant_sequence(&self, state_idx: usize) -> Vec<u16> {
        let mut chain = Vec::new();
        let mut idx = state_idx;
        loop {
            let entry = &self.states[idx];
            if let Some(v) = entry.action_variant {
                chain.push(v);
            }
            match entry.parent_idx {
                Some(parent) => idx = parent,
                None => break,
            }
        }
        chain.reverse();
        chain
    }

    /// Walk the parent chain and return (variant_idx, field_bytes) pairs for each action (oldest first).
    /// Used by subsequence splice to extract action parameters from existing pool states.
    pub fn reconstruct_variant_field_sequence(&self, state_idx: usize) -> Vec<(usize, Arc<Vec<u8>>)> {
        let mut chain = Vec::new();
        let mut idx = state_idx;
        loop {
            let entry = &self.states[idx];
            if let Some(v) = entry.action_variant {
                chain.push((v as usize, entry.action_field_bytes.clone()));
            }
            match entry.parent_idx {
                Some(parent) => idx = parent,
                None => break,
            }
        }
        chain.reverse();
        chain
    }

    /// Walk the parent chain from a state back to root and return the full
    /// sequence of action descriptions (oldest first).
    ///
    /// Each entry's `action_desc` may contain multiple newline-separated lines
    /// (one per action in a multi-action chain). This method splits them so
    /// the returned Vec has one entry per action, not one per pool state.
    pub fn reconstruct_action_descriptions(&self, state_idx: usize) -> Vec<String> {
        let mut chain = Vec::new();
        let mut idx = state_idx;
        loop {
            let entry = &self.states[idx];
            if !entry.action_desc.is_empty() {
                // action_desc may contain multiple lines (one per chain action)
                for line in entry.action_desc.lines() {
                    if !line.is_empty() {
                        chain.push(line.to_string());
                    }
                }
            }
            match entry.parent_idx {
                Some(parent) => idx = parent,
                None => break,
            }
        }
        chain.reverse();
        chain
    }
}
