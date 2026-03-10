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
/// (take_delta, fixture clone under mutex, etc.). Since FINGERPRINT_BITS=16,
/// there are 65536 possible dedup keys → 8192 bytes of bitmap.
///
/// False negatives are impossible: if a fingerprint IS in the bitmap,
/// it was definitely already added to the pool.
/// False positives (bitmap says not-seen but pool has it) can occur in a
/// tiny race window but are harmless — `try_add()` does authoritative dedup.
pub struct FingerprintBitmap {
    /// 65536 bits = 8192 bytes, stored as 8192 AtomicU8 values.
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
    /// Whether the action that produced this state succeeded (transaction committed).
    /// States from successful actions get a 5x weight boost in power scheduling
    /// since they represent real state changes, not error-path dead ends.
    pub action_succeeded: bool,
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
        }
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
        action_succeeded: bool,
    ) -> bool {
        if self.states.len() >= self.capacity {
            return false;
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
            action_succeeded,
        });
        self.active_indices.push(idx);
        // Credit parent for producing a novel child
        if let Some(pidx) = parent_idx {
            if let Some(parent) = self.states.get_mut(pidx) {
                parent.novel_children += 1;
            }
        }
        true
    }

    /// Pick a random active state index using the given random value (uniform).
    /// Returns None if no active (non-crashed) states remain.
    pub fn pick_random(&self, rand_val: u64) -> Option<usize> {
        if self.active_indices.is_empty() {
            None
        } else {
            let pos = rand_val as usize % self.active_indices.len();
            Some(self.active_indices[pos])
        }
    }

    /// Pick an active state using UCB1-inspired scheduling.
    ///
    /// Treats seed selection as a multi-armed bandit problem:
    ///
    ///   weight = (reward_rate + exploration_bonus) * violation_penalty
    ///
    /// - reward_rate = novel_children / picks — how productive this state is
    /// - exploration_bonus = sqrt(2 * ln(total_picks) / picks) — UCB1 bonus
    /// - violation_penalty = 1 / (violation_count + 1)
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
            let w = Self::compute_weight(&self.states[idx], tp);
            total += w;
            cumulative.push(total);
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

    /// Compute selection weight for a single state entry (UCB1-inspired).
    ///
    /// Stateful mode differs from stateless: each "seed" is a saved SVM state,
    /// and its value depends on what random actions you try from it — not known
    /// at creation time. We treat seed selection as a multi-armed bandit:
    ///
    /// - **Exploitation**: `novel_children / picks` — reward rate. States that
    ///   keep producing coverage-novel children are valuable.
    /// - **Exploration**: `sqrt(ln(total_picks) / picks)` — UCB1 bonus. States
    ///   that haven't been tried much get a bonus that shrinks as we learn more.
    /// - **Violation penalty**: crash-prone states get deprioritized.
    ///
    /// Never-picked states get maximum priority to ensure they're tried at least once.
    #[inline]
    fn compute_weight(s: &StateEntry, total_picks: f64) -> f64 {
        let picks = s.pick_count.load(Ordering::Relaxed) as f64;
        let violation_penalty = 1.0 / (s.violation_count as f64 + 1.0);

        if picks < 1.0 {
            // Never-picked states get top priority
            return 1e6 * violation_penalty;
        }

        // Exploitation: reward rate — how often does picking this state
        // produce a novel child? Range: 0.0 to ~1.0 for highly productive states.
        let reward_rate = s.novel_children as f64 / picks;

        // Exploration: UCB1-style bonus for under-explored states.
        // sqrt(2 * ln(total) / picks) — classic upper confidence bound.
        // At total=10000, picks=10: bonus = sqrt(2*9.2/10) = 1.36
        // At total=10000, picks=1000: bonus = sqrt(2*9.2/1000) = 0.14
        let ln_total = if total_picks > 1.0 { total_picks.ln() } else { 1.0 };
        let explore = (2.0 * ln_total / picks).sqrt();

        // Combine: reward_rate and explore are additive (UCB1 formula),
        // then scaled by violation penalty and success boost.
        // States from successful actions get 5x weight — they represent real
        // state changes and are more productive parents than error-path states.
        let success_boost = if s.action_succeeded { 5.0 } else { 1.0 };
        (reward_rate + explore) * violation_penalty * success_boost
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
            let w = Self::compute_weight(&self.states[idx], tp);
            total += w;
            cumulative.push(total);
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
        }
    }

    /// Record a violation against a state. Increments violation_count which reduces
    /// the state's selection weight via the penalty factor `1/(violation_count+1)`.
    ///
    /// No hard removal — the weight penalty handles deprioritization smoothly.
    /// States with many violations get near-zero weight naturally:
    /// - 1 violation: 0.5x weight
    /// - 5 violations: 0.17x weight
    /// - 20 violations: 0.048x weight
    pub fn record_violation(&mut self, state_idx: usize) {
        if let Some(entry) = self.states.get_mut(state_idx) {
            entry.violation_count += 1;
        }
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

    /// Walk the parent chain from a state back to root and return the full
    /// sequence of action descriptions (oldest first).
    pub fn reconstruct_action_descriptions(&self, state_idx: usize) -> Vec<String> {
        let mut chain = Vec::new();
        let mut idx = state_idx;
        loop {
            let entry = &self.states[idx];
            if !entry.action_desc.is_empty() {
                chain.push(entry.action_desc.clone());
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
