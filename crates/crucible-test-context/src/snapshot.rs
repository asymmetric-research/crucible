//! Dirty account tracking and snapshot/restore for fast fuzzing iterations.
//!
//! Instead of cloning the entire LiteSVM state each iteration (O(all_accounts)),
//! this module tracks which accounts were modified and restores only those
//! (O(dirty_accounts), typically ~5-20 vs ~50-200+ total).
//!
//! # Architecture
//!
//! - **DirtyTracker** — accumulates writable accounts across all transactions in an iteration
//! - **SvmSnapshot** — captures account state at setup time, restores only dirty accounts
//! - **TxTaintRecord** — per-transaction read/write sets for taint analysis
//! - **AccountDiff** — opt-in before/after diffs (behind `FUZZ_TAINT_DIFFS=1`)
//! - **IterationTaintLog** — collects TxTaintRecords across an iteration

use crate::{FastHashMap, FastHashSet};
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::prelude::Clock;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rustc_hash::FxHasher;

// ============================================================================
// DirtyTracker — zero-alloc hot path
// ============================================================================

/// Tracks which accounts have been written during the current iteration.
///
/// Accumulates dirty accounts across all transactions. Cleared at `begin_iteration()`.
/// The hot path (`record_tx`) is just FxHashSet inserts — zero allocation after warmup.
pub struct DirtyTracker {
    /// Writable accounts (includes fee payers). FxHash for speed.
    writable: FastHashSet<Pubkey>,
    /// Read-only accounts (includes program_ids). FxHash for speed.
    read_only: FastHashSet<Pubkey>,
    /// Whether slot/clock was modified this iteration.
    clock_dirty: bool,
}

impl DirtyTracker {
    pub fn new() -> Self {
        Self {
            writable: FastHashSet::default(),
            read_only: FastHashSet::default(),
            clock_dirty: false,
        }
    }

    /// Record all instructions in a tx. Handles multi-instruction batches.
    /// Hot path — just HashSet inserts, zero allocation after initial capacity.
    #[inline]
    pub fn record_tx(&mut self, instructions: &[Instruction], fee_payer: &Pubkey) {
        self.writable.insert(*fee_payer);
        for ix in instructions {
            self.read_only.insert(ix.program_id);
            for meta in &ix.accounts {
                if meta.is_writable {
                    self.writable.insert(meta.pubkey);
                } else {
                    self.read_only.insert(meta.pubkey);
                }
            }
        }
    }

    /// Mark the clock sysvar as dirty (called by warp_to_slot/advance_slots).
    pub fn mark_clock_dirty(&mut self) {
        self.clock_dirty = true;
    }

    /// Mark a specific account as dirty (called by write_account, etc.).
    pub fn mark_account_dirty(&mut self, pubkey: &Pubkey) {
        self.writable.insert(*pubkey);
    }

    /// Get the set of dirty (writable) accounts.
    pub fn dirty_accounts(&self) -> &FastHashSet<Pubkey> {
        &self.writable
    }

    /// Get the set of read-only accounts.
    pub fn read_accounts(&self) -> &FastHashSet<Pubkey> {
        &self.read_only
    }

    /// Number of dirty accounts.
    pub fn dirty_count(&self) -> usize {
        self.writable.len()
    }

    /// Whether the clock sysvar was modified.
    pub fn is_clock_dirty(&self) -> bool {
        self.clock_dirty
    }

    /// Clear all tracking state (called at start of each iteration).
    pub fn clear(&mut self) {
        self.writable.clear();
        self.read_only.clear();
        self.clock_dirty = false;
    }
}

impl Clone for DirtyTracker {
    fn clone(&self) -> Self {
        // Fresh tracker for cloned contexts — no need to carry dirty state
        Self::new()
    }
}

// ============================================================================
// AccountDiff — opt-in per-tx before/after (behind FUZZ_TAINT_DIFFS=1)
// ============================================================================

/// Before/after diff for a single account across a transaction.
/// Only collected when `FUZZ_TAINT_DIFFS=1` is set.
pub struct AccountDiff {
    pub pubkey: Pubkey,
    /// Account state before the transaction. None if account didn't exist.
    pub pre: Option<Account>,
    /// Account state after the transaction. None if account was deleted.
    pub post: Option<Account>,
}

impl AccountDiff {
    /// Whether the account data actually changed.
    pub fn is_changed(&self) -> bool {
        self.pre != self.post
    }

    /// Whether the account was created by this transaction.
    pub fn was_created(&self) -> bool {
        self.pre.is_none() && self.post.is_some()
    }

    /// Whether the account was deleted by this transaction.
    pub fn was_deleted(&self) -> bool {
        self.pre.is_some() && self.post.is_none()
    }

    /// Lamports before and after. Returns (pre_lamports, post_lamports).
    pub fn lamports_delta(&self) -> (u64, u64) {
        let pre = self.pre.as_ref().map(|a| a.lamports).unwrap_or(0);
        let post = self.post.as_ref().map(|a| a.lamports).unwrap_or(0);
        (pre, post)
    }

    /// Byte ranges in data that differ. Returns vec of (offset, len).
    /// Compares overlapping portion and reports any trailing data as changed.
    pub fn changed_data_ranges(&self) -> Vec<(usize, usize)> {
        let pre_data = self.pre.as_ref().map(|a| a.data.as_slice()).unwrap_or(&[]);
        let post_data = self.post.as_ref().map(|a| a.data.as_slice()).unwrap_or(&[]);

        let mut ranges = Vec::new();
        let min_len = pre_data.len().min(post_data.len());
        let mut i = 0;

        while i < min_len {
            if pre_data[i] != post_data[i] {
                let start = i;
                while i < min_len && pre_data[i] != post_data[i] {
                    i += 1;
                }
                ranges.push((start, i - start));
            } else {
                i += 1;
            }
        }

        // Report any trailing data (different lengths) as a single range
        let max_len = pre_data.len().max(post_data.len());
        if max_len > min_len {
            ranges.push((min_len, max_len - min_len));
        }

        ranges
    }
}

// ============================================================================
// TxTaintRecord — per-transaction read/write sets
// ============================================================================

/// Per-transaction record of which accounts were read and written.
/// Only recorded for successful transactions.
pub struct TxTaintRecord {
    /// Read-only AccountMetas + program_ids.
    pub read_accounts: Vec<Pubkey>,
    /// Writable AccountMetas + fee_payer.
    pub write_accounts: Vec<Pubkey>,
    /// Program IDs invoked.
    pub programs: Vec<Pubkey>,
    /// Before/after diffs. None when FUZZ_TAINT_DIFFS is off.
    pub diffs: Option<Vec<AccountDiff>>,
}

// ============================================================================
// IterationTaintLog — collects TxTaintRecords for an iteration
// ============================================================================

/// Collects TxTaintRecords across all transactions in an iteration.
pub struct IterationTaintLog {
    pub records: Vec<TxTaintRecord>,
    /// Whether to collect before/after diffs (from FUZZ_TAINT_DIFFS env var).
    collect_diffs: bool,
}

impl IterationTaintLog {
    pub fn new() -> Self {
        let collect_diffs = std::env::var("FUZZ_TAINT_DIFFS").is_ok();
        Self {
            records: Vec::new(),
            collect_diffs,
        }
    }

    /// Whether diffs collection is enabled.
    pub fn collects_diffs(&self) -> bool {
        self.collect_diffs
    }

    /// Push a taint record.
    pub fn push(&mut self, record: TxTaintRecord) {
        self.records.push(record);
    }

    /// Number of taint records collected so far.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether taint log is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Clear all records (called at start of each iteration).
    pub fn clear(&mut self) {
        self.records.clear();
    }
}

impl Clone for IterationTaintLog {
    fn clone(&self) -> Self {
        // Fresh log for cloned contexts
        Self {
            records: Vec::new(),
            collect_diffs: self.collect_diffs,
        }
    }
}

// ============================================================================
// SvmSnapshot — fast restore of only dirty accounts
// ============================================================================

/// Snapshot of account state at setup time. Restores only dirty accounts
/// instead of cloning the entire SVM.
///
/// Accounts are wrapped in `Arc<Account>` so that cloning snapshots (e.g. in
/// `take_delta`) only bumps reference counts instead of deep-copying every
/// account's `data: Vec<u8>`.  The owned clone is deferred to `restore*`
/// methods where `svm.set_account` actually needs an owned `Account`.
#[derive(Clone)]
pub struct SvmSnapshot {
    /// Account data at snapshot time. FxHash for fast lookups during restore.
    /// Arc-wrapped to make snapshot cloning O(n * 40B) instead of O(n * avg_data_len).
    accounts: FastHashMap<Pubkey, Arc<Account>>,
    /// Full Clock sysvar at snapshot time.
    clock: Clock,
}

impl SvmSnapshot {
    /// Snapshot all tracked accounts + Clock. Called once after setup.
    pub fn take(svm: &LiteSVM, tracked_accounts: &HashSet<Pubkey>) -> Self {
        let mut accounts = FastHashMap::default();
        accounts.reserve(tracked_accounts.len());
        for pubkey in tracked_accounts {
            if let Some(account) = svm.get_account(pubkey) {
                accounts.insert(*pubkey, Arc::new(account));
            }
        }
        let clock = svm.get_sysvar::<Clock>();
        Self { accounts, clock }
    }

    /// Restore only dirty accounts from snapshot. Returns count of accounts restored.
    ///
    /// Handles three cases:
    /// - **Modified**: existed at snapshot, data changed → restore original
    /// - **Deleted**: existed at snapshot, now gone → restore original
    /// - **Created**: not in snapshot, created during iteration → remove (set lamports=0)
    pub fn restore(&self, svm: &mut LiteSVM, dirty: &DirtyTracker) -> usize {
        let mut count = 0;
        for pubkey in dirty.dirty_accounts() {
            match self.accounts.get(pubkey) {
                Some(original) => {
                    // Existed at snapshot — restore original (covers modified + deleted)
                    let _ = svm.set_account(*pubkey, (**original).clone());
                }
                None => {
                    // Created during iteration — remove by zeroing
                    let _ = svm.set_account(
                        *pubkey,
                        Account {
                            lamports: 0,
                            ..Default::default()
                        },
                    );
                }
            }
            count += 1;
        }
        if dirty.is_clock_dirty() {
            svm.set_sysvar(&self.clock);
        }
        count
    }

    /// Get the number of snapshotted accounts.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Take a full snapshot by cloning a base snapshot's accounts then overwriting
    /// dirty ones from the current SVM. Captures the complete state after an action.
    pub fn take_full(
        svm: &LiteSVM,
        base_snapshot: &SvmSnapshot,
        dirty: &DirtyTracker,
    ) -> Self {
        let mut accounts = base_snapshot.accounts.clone();
        // Overwrite dirty accounts with current SVM state
        for pubkey in dirty.dirty_accounts() {
            if let Some(account) = svm.get_account(pubkey) {
                accounts.insert(*pubkey, Arc::new(account));
            } else {
                // Account was deleted — remove from snapshot
                accounts.remove(pubkey);
            }
        }
        let clock = svm.get_sysvar::<Clock>();
        Self { accounts, clock }
    }

    /// Snapshot ALL accounts in the SVM, not just tracked ones.
    /// Used for the initial snapshot in stateful multicore mode where workers
    /// share a pool built from the main thread's setup. Captures everything
    /// via `svm.accounts_db().inner` so no accounts are missing when a worker
    /// restores from a snapshot that was taken on the main thread.
    pub fn take_all(svm: &LiteSVM) -> Self {
        let db = svm.accounts_db();
        let mut accounts = FastHashMap::default();
        accounts.reserve(db.inner.len());
        for (pubkey, _) in &db.inner {
            // Convert AccountSharedData → Account via get_account() which
            // returns the owned Account type we store in snapshots.
            if let Some(account) = svm.get_account(pubkey) {
                accounts.insert(*pubkey, Arc::new(account));
            }
        }
        let clock = svm.get_sysvar::<Clock>();
        Self { accounts, clock }
    }

    /// Restore ALL accounts in snapshot to the SVM (full state restore).
    /// Used by stateful mode to jump to a saved state. Returns account count.
    pub fn restore_full(&self, svm: &mut LiteSVM) -> usize {
        for (pubkey, account) in &self.accounts {
            let _ = svm.set_account(*pubkey, (**account).clone());
        }
        svm.set_sysvar(&self.clock);
        self.accounts.len()
    }

    /// Restore only the given set of keys to initial state, then overlay a delta.
    ///
    /// This is the fast path for stateful mode: instead of restoring ALL ~200
    /// initial accounts every iteration, we only restore accounts that diverged
    /// from initial in the previous iteration (~10-30 accounts), then overlay
    /// the new delta (~20-50 accounts). Returns count of set_account calls.
    ///
    /// `divergent_keys` = accounts that currently differ from initial in the SVM
    /// (i.e., previous delta keys + previous dirty tracker keys).
    pub fn restore_selective(
        &self,
        svm: &mut LiteSVM,
        divergent_keys: &FastHashSet<Pubkey>,
        delta: &SvmSnapshot,
    ) -> usize {
        let mut count = 0;

        // 1. Restore divergent accounts to initial state (skip those in delta —
        //    they'll be overwritten in step 2 anyway)
        for pubkey in divergent_keys {
            if delta.accounts.contains_key(pubkey) {
                continue; // will be set by delta below
            }
            if let Some(initial_account) = self.accounts.get(pubkey) {
                let _ = svm.set_account(*pubkey, (**initial_account).clone());
            } else {
                // Account was created during prev iteration but doesn't exist in initial — zero it
                let _ = svm.set_account(*pubkey, Account { lamports: 0, ..Default::default() });
            }
            count += 1;
        }

        // 2. Overlay delta (accounts that differ from initial in the target state)
        for (pubkey, account) in &delta.accounts {
            let _ = svm.set_account(*pubkey, (**account).clone());
            count += 1;
        }

        // 3. Set clock from delta (target state's clock)
        svm.set_sysvar(&delta.clock);

        count
    }

    /// Restore SVM state using delta-to-delta comparison to skip redundant set_account calls.
    ///
    /// When consecutive iterations pick states that share common ancestry, many delta
    /// accounts will point to the same `Arc<Account>` (same pointer). By comparing Arc
    /// pointers between prev_delta and next_delta, we skip `svm.set_account()` for
    /// accounts that are already correct in the SVM from the previous iteration.
    ///
    /// `prev_exec_dirty` contains accounts that were writable in the previous iteration's
    /// transactions. These accounts may have been modified by execution, so the SVM may
    /// NOT have the prev_delta value for them — they must always be restored even if the
    /// Arc pointers match.
    ///
    /// Returns count of set_account calls actually made.
    pub fn restore_selective_from(
        &self,
        svm: &mut LiteSVM,
        divergent_keys: &FastHashSet<Pubkey>,
        prev_delta: &SvmSnapshot,
        next_delta: &SvmSnapshot,
        prev_exec_dirty: &FastHashSet<Pubkey>,
    ) -> usize {
        let mut count = 0;

        // 1. Divergent accounts not in next_delta → restore to initial
        for pubkey in divergent_keys {
            if next_delta.accounts.contains_key(pubkey) {
                continue; // will be handled in step 2
            }
            if let Some(initial_account) = self.accounts.get(pubkey) {
                let _ = svm.set_account(*pubkey, (**initial_account).clone());
            } else {
                let _ = svm.set_account(*pubkey, Account { lamports: 0, ..Default::default() });
            }
            count += 1;
        }

        // 2. Delta accounts — skip if same Arc as prev_delta AND not dirtied by execution
        for (pubkey, next_acct) in &next_delta.accounts {
            if !prev_exec_dirty.contains(pubkey) {
                if let Some(prev_acct) = prev_delta.accounts.get(pubkey) {
                    if Arc::ptr_eq(prev_acct, next_acct) {
                        // Same Arc, not dirtied by execution → SVM already has correct value
                        continue;
                    }
                }
            }
            let _ = svm.set_account(*pubkey, (**next_acct).clone());
            count += 1;
        }

        // 3. Set clock from next delta
        svm.set_sysvar(&next_delta.clock);

        count
    }

    /// Get a reference to the internal accounts map.
    pub fn accounts(&self) -> &FastHashMap<Pubkey, Arc<Account>> {
        &self.accounts
    }

    /// Get a reference to the stored Clock sysvar.
    pub fn clock(&self) -> &Clock {
        &self.clock
    }

    /// Create an empty snapshot (no accounts differ from initial state).
    /// Used as the initial delta in the state pool.
    pub fn empty(clock: Clock) -> Self {
        Self {
            accounts: FastHashMap::default(),
            clock,
        }
    }

    /// Create a delta snapshot containing only accounts that differ from the initial state.
    /// Starts from parent's delta (accounts already different from initial),
    /// then updates with this action's dirty accounts read from SVM.
    ///
    /// With `Arc<Account>`, cloning the parent map is O(n * 40B) — just Pubkey copies
    /// + Arc refcount bumps — instead of O(n * avg_account_data_len) deep copies.
    /// Only the newly dirty accounts (from this action) allocate fresh `Arc`s.
    pub fn take_delta(
        svm: &LiteSVM,
        parent_delta: &SvmSnapshot,
        dirty: &DirtyTracker,
    ) -> Self {
        // Clone parent's delta — cheap with Arc<Account>: only bumps refcounts
        let mut accounts = parent_delta.accounts.clone();
        // Update/add dirty accounts from current SVM state
        for pk in dirty.dirty_accounts() {
            match svm.get_account(pk) {
                Some(acct) => { accounts.insert(*pk, Arc::new(acct)); }
                None => {
                    // Account deleted — store tombstone so restore_full zeroes it
                    accounts.insert(*pk, Arc::new(Account { lamports: 0, ..Default::default() }));
                }
            }
        }
        let clock = svm.get_sysvar::<Clock>();
        Self { accounts, clock }
    }
}

// ============================================================================
// State Fingerprinting — bucketed hashing for state novelty detection
// ============================================================================

/// Coarse bucketing for u64 values (3 buckets: 0-2).
///
/// Extremely coarse to minimize fingerprint noise from fields that change
/// every transaction (timestamps, slot counters, accumulated interest).
/// Only distinguishes: zero, moderate (fits in u32), and large (>u32).
///
/// Buckets: 0=zero, 1=moderate(1..4B), 2=large(>4B)
#[inline]
fn log2_bucket(val: u64) -> u8 {
    if val == 0 { return 0; }
    if val <= u32::MAX as u64 { return 1; }
    2
}

/// Number of bits in the final fingerprint for dedup. Controls novel rate:
/// - Too many bits → every state is "novel", pool grows unbounded
/// - Too few bits → states collapse, pool stays tiny
/// 16 bits = 65536 possible fingerprints.
const FINGERPRINT_BITS: u32 = 16;

/// Maximum number of u64 words to sample per account for fingerprinting.
/// 8 words with 3 buckets: captures balance structure while ignoring noise.
const FINGERPRINT_WORDS_PER_ACCOUNT: usize = 8;

/// Compute an absolute state fingerprint from the current SVM state.
///
/// Samples evenly-spaced u64 words per dirty account with coarse bucketing.
/// The hash is truncated to FINGERPRINT_BITS for dedup (in StatePool::try_add)
/// while the full 64-bit value is kept for state_class action selection.
pub fn compute_state_fingerprint_from_snapshot(
    svm: &LiteSVM,
    dirty: &DirtyTracker,
) -> u64 {
    if dirty.dirty_accounts().is_empty() {
        return 0;
    }

    // Hash each dirty account into a FxHasher.
    // Every u64 word is bucketed and hashed with its position index, giving
    // full visibility into account data changes.
    let mut hasher = FxHasher::default();

    // Hash account count first (different account sets = different state)
    (dirty.dirty_accounts().len() as u64).hash(&mut hasher);

    for pubkey in dirty.dirty_accounts() {
        let account = svm.get_account(pubkey);
        let lamports = account.as_ref().map(|a| a.lamports).unwrap_or(0);
        let data = account.as_ref().map(|a| a.data.as_slice()).unwrap_or(&[]);

        // Hash pubkey identity (first 8 bytes) so same data at different accounts differs
        let pk_bytes = pubkey.as_ref();
        let pk_prefix = u64::from_le_bytes(pk_bytes[0..8].try_into().unwrap());
        pk_prefix.hash(&mut hasher);

        // Hash lamports bucket
        log2_bucket(lamports).hash(&mut hasher);

        // Hash data length bucket
        log2_bucket(data.len() as u64).hash(&mut hasher);

        // Sample evenly-spaced words — covers balance fields without noise
        let total_words = data.len() / 8;
        if total_words > 0 {
            let sample_count = total_words.min(FINGERPRINT_WORDS_PER_ACCOUNT);
            for i in 0..sample_count {
                let word_idx = if sample_count < total_words {
                    i * total_words / sample_count
                } else {
                    i
                };
                let pos = word_idx * 8;
                let val = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
                (word_idx as u16, log2_bucket(val)).hash(&mut hasher);
            }
        }
    }

    hasher.finish()
}

// ============================================================================
// StatePool — bounded pool of saved SVM states for stateful fuzzing
// ============================================================================

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
    /// Whether this state was added because it discovered new coverage edges.
    /// States on the coverage frontier get a 3x boost in selection weight,
    /// encouraging deeper exploration of states that expand coverage.
    pub coverage_novel: bool,
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
    fn new(variant_count: usize) -> Self {
        Self {
            counts: vec![[0; 2]; variant_count],
        }
    }

    fn record(&mut self, variant_idx: usize, success: bool) {
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
    fn weights(&self) -> Vec<f64> {
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
    states: Vec<StateEntry>,
    seen: FastHashSet<u64>,
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
    total_picks: AtomicU64,
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
    /// `coverage_novel` indicates whether this state was saved because it discovered
    /// new coverage edges (gives 3x weight boost in selection).
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
        coverage_novel: bool,
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
            coverage_novel,
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

    /// Pick an active state using power-schedule weighting.
    ///
    /// Weight = exploration_bonus * productivity_bonus:
    /// - exploration_bonus = 1 / (pick_count + 1)  — favors underexplored states
    /// - productivity_bonus = ln(novel_children + 2) — favors states that produced children
    ///
    /// Returns None if no active states remain. Increments the picked state's pick_count.
    pub fn pick_weighted(&self, rand_val: u64) -> Option<usize> {
        if self.active_indices.is_empty() {
            return None;
        }
        self.total_picks.fetch_add(1, Ordering::Relaxed);

        // Compute cumulative weights for active states
        let n = self.active_indices.len();
        // Fast path: single state
        if n == 1 {
            let idx = self.active_indices[0];
            self.states[idx].pick_count.fetch_add(1, Ordering::Relaxed);
            return Some(idx);
        }

        // Build cumulative weight array
        let mut cumulative = Vec::with_capacity(n);
        let mut total: f64 = 0.0;
        for &idx in &self.active_indices {
            let s = &self.states[idx];
            let explore = 1.0 / (s.pick_count.load(Ordering::Relaxed) as f64 + 1.0);
            let exploit = (s.novel_children as f64 + 2.0).ln();
            let violation_penalty = 1.0 / (s.violation_count as f64 + 1.0);
            let coverage_bonus = if s.coverage_novel { 3.0 } else { 1.0 };
            let weight = explore * exploit * violation_penalty * coverage_bonus;
            total += weight;
            cumulative.push(total);
        }

        // Weighted sample
        let target = (rand_val as f64 / u64::MAX as f64) * total;
        let pos = match cumulative.binary_search_by(|w| w.partial_cmp(&target).unwrap()) {
            Ok(i) => i,
            Err(i) => i.min(n - 1),
        };
        let idx = self.active_indices[pos];
        self.states[idx].pick_count.fetch_add(1, Ordering::Relaxed);
        Some(idx)
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
        let mut cumulative = Vec::with_capacity(n);
        let mut total: f64 = 0.0;
        for &idx in &self.active_indices {
            let s = &self.states[idx];
            let explore = 1.0 / (s.pick_count.load(Ordering::Relaxed) as f64 + 1.0);
            let exploit = (s.novel_children as f64 + 2.0).ln();
            let violation_penalty = 1.0 / (s.violation_count as f64 + 1.0);
            let coverage_bonus = if s.coverage_novel { 3.0 } else { 1.0 };
            total += explore * exploit * violation_penalty * coverage_bonus;
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

// ============================================================================
// Helper functions for taint recording in send paths
// ============================================================================

/// Snapshot writable accounts before a transaction executes.
/// Only called when `FUZZ_TAINT_DIFFS=1` is set.
pub fn snapshot_writable_accounts(
    svm: &LiteSVM,
    instructions: &[Instruction],
    fee_payer: &Pubkey,
) -> FastHashMap<Pubkey, Option<Account>> {
    let mut pre = FastHashMap::default();
    pre.insert(*fee_payer, svm.get_account(fee_payer));
    for ix in instructions {
        for meta in &ix.accounts {
            if meta.is_writable {
                pre.entry(meta.pubkey)
                    .or_insert_with(|| svm.get_account(&meta.pubkey));
            }
        }
    }
    pre
}

/// Build a TxTaintRecord from instruction metadata.
/// Diffs are populated only if `pre_state` is Some (i.e., FUZZ_TAINT_DIFFS=1).
#[allow(dead_code)]
pub fn build_taint_record(
    svm: &LiteSVM,
    instructions: &[Instruction],
    fee_payer: &Pubkey,
    pre_state: Option<&FastHashMap<Pubkey, Option<Account>>>,
) -> TxTaintRecord {
    let mut read_accounts = Vec::new();
    let mut write_accounts = vec![*fee_payer];
    let mut programs = Vec::new();

    for ix in instructions {
        programs.push(ix.program_id);
        read_accounts.push(ix.program_id);
        for meta in &ix.accounts {
            if meta.is_writable {
                write_accounts.push(meta.pubkey);
            } else {
                read_accounts.push(meta.pubkey);
            }
        }
    }

    let diffs = pre_state.map(|pre| {
        pre.iter()
            .map(|(pubkey, pre_account)| AccountDiff {
                pubkey: *pubkey,
                pre: pre_account.clone(),
                post: svm.get_account(pubkey),
            })
            .collect()
    });

    TxTaintRecord {
        read_accounts,
        write_accounts,
        programs,
        diffs,
    }
}

/// Captured transaction metadata before instructions are consumed by send.
/// This allows building taint records even after instructions are moved.
pub struct CapturedTxMeta {
    pub read_accounts: Vec<Pubkey>,
    pub write_accounts: Vec<Pubkey>,
    pub programs: Vec<Pubkey>,
}

/// Capture metadata from instructions before they are consumed by send.
pub fn capture_tx_meta(instructions: &[Instruction], fee_payer: &Pubkey) -> CapturedTxMeta {
    let mut read_accounts = Vec::new();
    let mut write_accounts = vec![*fee_payer];
    let mut programs = Vec::new();

    for ix in instructions {
        programs.push(ix.program_id);
        read_accounts.push(ix.program_id);
        for meta in &ix.accounts {
            if meta.is_writable {
                write_accounts.push(meta.pubkey);
            } else {
                read_accounts.push(meta.pubkey);
            }
        }
    }

    CapturedTxMeta {
        read_accounts,
        write_accounts,
        programs,
    }
}

/// Build a TxTaintRecord from captured metadata and optional pre-state.
/// Used after instructions have been consumed by send.
pub fn build_taint_record_from_captured(
    svm: &LiteSVM,
    meta: CapturedTxMeta,
    pre_state: Option<&FastHashMap<Pubkey, Option<Account>>>,
) -> TxTaintRecord {
    let diffs = pre_state.map(|pre| {
        pre.iter()
            .map(|(pubkey, pre_account)| AccountDiff {
                pubkey: *pubkey,
                pre: pre_account.clone(),
                post: svm.get_account(pubkey),
            })
            .collect()
    });

    TxTaintRecord {
        read_accounts: meta.read_accounts,
        write_accounts: meta.write_accounts,
        programs: meta.programs,
        diffs,
    }
}

// ============================================================================
// Per-Action Taint Summary Builder
// ============================================================================

use crate::{ActionTaintSummary, AccountChangeSummary, AccountChangeKind};

/// Build a taint summary from TxTaintRecords in a range of the iteration log.
///
/// `start_idx..end_idx` covers the transactions produced by a single action dispatch.
/// Returns `None` if taint tracking is disabled (no records and no diffs).
pub fn build_action_taint_summary(
    log: &IterationTaintLog,
    start_idx: usize,
    end_idx: usize,
) -> Option<ActionTaintSummary> {
    let tx_count = end_idx.saturating_sub(start_idx);

    // If no transactions were recorded and we're not collecting diffs, skip
    if tx_count == 0 && !log.collects_diffs() {
        return None;
    }

    let mut written = FastHashSet::default();
    let mut read = FastHashSet::default();

    for record in log.records.get(start_idx..end_idx).unwrap_or(&[]) {
        for pk in &record.write_accounts {
            written.insert(*pk);
        }
        for pk in &record.read_accounts {
            read.insert(*pk);
        }
    }

    // Remove written accounts from read set (if you write it, it's not read-only)
    for pk in &written {
        read.remove(pk);
    }

    let written_accounts: Vec<String> = written.iter().map(|pk| pk.to_string()).collect();
    let read_accounts: Vec<String> = read.iter().map(|pk| pk.to_string()).collect();

    // Build account change details if diffs are available
    let account_changes = if log.collects_diffs() {
        build_account_changes(log, start_idx, end_idx)
    } else {
        None
    };

    Some(ActionTaintSummary {
        tx_count,
        written_accounts,
        read_accounts,
        account_changes,
    })
}

/// Merge per-tx AccountDiffs into per-account change summaries.
/// For each account, uses the first pre-state and last post-state across all txs.
fn build_account_changes(
    log: &IterationTaintLog,
    start_idx: usize,
    end_idx: usize,
) -> Option<Vec<AccountChangeSummary>> {
    use solana_pubkey::Pubkey;
    use solana_account::Account;

    // Collect first pre and last post per pubkey
    let mut first_pre: FastHashMap<Pubkey, Option<Account>> = FastHashMap::default();
    let mut last_post: FastHashMap<Pubkey, Option<Account>> = FastHashMap::default();

    for record in log.records.get(start_idx..end_idx).unwrap_or(&[]) {
        if let Some(ref diffs) = record.diffs {
            for diff in diffs {
                first_pre.entry(diff.pubkey).or_insert_with(|| diff.pre.clone());
                last_post.insert(diff.pubkey, diff.post.clone());
            }
        }
    }

    if first_pre.is_empty() {
        return None;
    }

    let mut changes = Vec::new();
    for (pubkey, pre) in &first_pre {
        let post = last_post.get(pubkey).cloned().flatten();
        let pre_ref = pre.as_ref();

        // Determine change kind
        let kind = match (pre_ref, &post) {
            (None, Some(_)) => AccountChangeKind::Created,
            (Some(_), None) => AccountChangeKind::Deleted,
            _ => AccountChangeKind::Modified,
        };

        // Compute lamports
        let pre_lamports = pre_ref.map(|a| a.lamports).unwrap_or(0);
        let post_lamports = post.as_ref().map(|a| a.lamports).unwrap_or(0);

        // Build a temporary AccountDiff to reuse changed_data_ranges()
        let temp_diff = AccountDiff {
            pubkey: *pubkey,
            pre: pre.clone(),
            post: post.clone(),
        };

        // Skip unchanged accounts
        if !temp_diff.is_changed() {
            continue;
        }

        let changed_ranges = temp_diff.changed_data_ranges();

        // Try semantic diff via schema registry
        let field_diffs = if let (Some(pre_acc), Some(post_acc)) = (pre_ref, &post) {
            crate::schema::lookup_diff_fn(&post_acc.data)
                .and_then(|diff_fn| {
                    let deltas = diff_fn(&pre_acc.data, &post_acc.data);
                    if deltas.is_empty() { None } else { Some(deltas) }
                })
        } else {
            None
        };

        changes.push(AccountChangeSummary {
            pubkey: pubkey.to_string(),
            kind,
            lamports: (pre_lamports, post_lamports),
            changed_ranges,
            field_diffs,
        });
    }

    if changes.is_empty() { None } else { Some(changes) }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::instruction::AccountMeta;

    #[test]
    fn test_dirty_tracker_record_tx() {
        let mut tracker = DirtyTracker::new();
        let fee_payer = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let writable_acc = Pubkey::new_unique();
        let readonly_acc = Pubkey::new_unique();

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(writable_acc, false),
                AccountMeta::new_readonly(readonly_acc, false),
            ],
            data: vec![],
        };

        tracker.record_tx(&[ix], &fee_payer);

        // fee_payer + writable_acc should be in writable set
        assert!(tracker.dirty_accounts().contains(&fee_payer));
        assert!(tracker.dirty_accounts().contains(&writable_acc));
        assert!(!tracker.dirty_accounts().contains(&readonly_acc));

        // program_id + readonly_acc should be in read_only set
        assert!(tracker.read_accounts().contains(&program_id));
        assert!(tracker.read_accounts().contains(&readonly_acc));

        assert_eq!(tracker.dirty_count(), 2);
        assert!(!tracker.is_clock_dirty());
    }

    #[test]
    fn test_dirty_tracker_accumulates() {
        let mut tracker = DirtyTracker::new();
        let fee_payer = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();

        let acc1 = Pubkey::new_unique();
        let acc2 = Pubkey::new_unique();

        let ix1 = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(acc1, false)],
            data: vec![],
        };
        let ix2 = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(acc2, false)],
            data: vec![],
        };

        tracker.record_tx(&[ix1], &fee_payer);
        tracker.record_tx(&[ix2], &fee_payer);

        // Both accounts + fee_payer should be tracked
        assert_eq!(tracker.dirty_count(), 3); // fee_payer, acc1, acc2
        assert!(tracker.dirty_accounts().contains(&acc1));
        assert!(tracker.dirty_accounts().contains(&acc2));
    }

    #[test]
    fn test_dirty_tracker_multi_instruction_batch() {
        let mut tracker = DirtyTracker::new();
        let fee_payer = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();

        let acc1 = Pubkey::new_unique();
        let acc2 = Pubkey::new_unique();

        let ix1 = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(acc1, false)],
            data: vec![],
        };
        let ix2 = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(acc2, false)],
            data: vec![],
        };

        // Record multi-instruction batch in a single call
        tracker.record_tx(&[ix1, ix2], &fee_payer);

        assert_eq!(tracker.dirty_count(), 3); // fee_payer, acc1, acc2
    }

    #[test]
    fn test_dirty_tracker_clear() {
        let mut tracker = DirtyTracker::new();
        let fee_payer = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();

        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(Pubkey::new_unique(), false)],
            data: vec![],
        };

        tracker.record_tx(&[ix], &fee_payer);
        tracker.mark_clock_dirty();

        assert!(tracker.dirty_count() > 0);
        assert!(tracker.is_clock_dirty());

        tracker.clear();

        assert_eq!(tracker.dirty_count(), 0);
        assert!(!tracker.is_clock_dirty());
        assert!(tracker.read_accounts().is_empty());
    }

    #[test]
    fn test_dirty_tracker_mark_account() {
        let mut tracker = DirtyTracker::new();
        let pubkey = Pubkey::new_unique();

        tracker.mark_account_dirty(&pubkey);
        assert!(tracker.dirty_accounts().contains(&pubkey));
        assert_eq!(tracker.dirty_count(), 1);
    }

    #[test]
    fn test_account_diff_unchanged() {
        let account = Account {
            lamports: 100,
            data: vec![1, 2, 3],
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        };
        let diff = AccountDiff {
            pubkey: Pubkey::new_unique(),
            pre: Some(account.clone()),
            post: Some(account),
        };
        assert!(!diff.is_changed());
        assert!(!diff.was_created());
        assert!(!diff.was_deleted());
        assert_eq!(diff.lamports_delta(), (100, 100));
        assert!(diff.changed_data_ranges().is_empty());
    }

    #[test]
    fn test_account_diff_created() {
        let diff = AccountDiff {
            pubkey: Pubkey::new_unique(),
            pre: None,
            post: Some(Account {
                lamports: 100,
                data: vec![1, 2, 3],
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            }),
        };
        assert!(diff.is_changed());
        assert!(diff.was_created());
        assert!(!diff.was_deleted());
        assert_eq!(diff.lamports_delta(), (0, 100));
    }

    #[test]
    fn test_account_diff_deleted() {
        let diff = AccountDiff {
            pubkey: Pubkey::new_unique(),
            pre: Some(Account {
                lamports: 100,
                data: vec![1, 2, 3],
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            }),
            post: None,
        };
        assert!(diff.is_changed());
        assert!(!diff.was_created());
        assert!(diff.was_deleted());
        assert_eq!(diff.lamports_delta(), (100, 0));
    }

    #[test]
    fn test_account_diff_data_changes() {
        let diff = AccountDiff {
            pubkey: Pubkey::new_unique(),
            pre: Some(Account {
                lamports: 100,
                data: vec![1, 2, 3, 4, 5],
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            }),
            post: Some(Account {
                lamports: 100,
                data: vec![1, 9, 3, 9, 5],
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            }),
        };
        let ranges = diff.changed_data_ranges();
        // Bytes at index 1 and 3 changed (non-contiguous)
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], (1, 1));
        assert_eq!(ranges[1], (3, 1));
    }

    #[test]
    fn test_account_diff_length_change() {
        let diff = AccountDiff {
            pubkey: Pubkey::new_unique(),
            pre: Some(Account {
                lamports: 100,
                data: vec![1, 2, 3],
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            }),
            post: Some(Account {
                lamports: 100,
                data: vec![1, 2, 3, 4, 5],
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            }),
        };
        let ranges = diff.changed_data_ranges();
        // Trailing 2 bytes are "new"
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (3, 2));
    }

    #[test]
    fn test_iteration_taint_log() {
        let mut log = IterationTaintLog::new();
        assert!(log.records.is_empty());

        let record = TxTaintRecord {
            read_accounts: vec![Pubkey::new_unique()],
            write_accounts: vec![Pubkey::new_unique()],
            programs: vec![Pubkey::new_unique()],
            diffs: None,
        };
        log.push(record);
        assert_eq!(log.records.len(), 1);

        log.clear();
        assert!(log.records.is_empty());
    }

    #[test]
    fn test_dirty_tracker_clone_is_fresh() {
        let mut tracker = DirtyTracker::new();
        tracker.mark_account_dirty(&Pubkey::new_unique());
        tracker.mark_clock_dirty();

        let cloned = tracker.clone();
        assert_eq!(cloned.dirty_count(), 0);
        assert!(!cloned.is_clock_dirty());
    }

    // -------------------------------------------------------------------------
    // build_action_taint_summary tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_taint_summary_empty_log() {
        let log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: false,
        };
        // No txs and no diffs → None
        let result = build_action_taint_summary(&log, 0, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_taint_summary_single_tx() {
        let pk_write = Pubkey::new_unique();
        let pk_read = Pubkey::new_unique();
        let pk_prog = Pubkey::new_unique();

        let mut log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: false,
        };
        log.push(TxTaintRecord {
            read_accounts: vec![pk_read, pk_prog],
            write_accounts: vec![pk_write],
            programs: vec![pk_prog],
            diffs: None,
        });

        let summary = build_action_taint_summary(&log, 0, 1).unwrap();
        assert_eq!(summary.tx_count, 1);
        assert_eq!(summary.written_accounts.len(), 1);
        assert!(summary.written_accounts.contains(&pk_write.to_string()));
        // pk_read and pk_prog should be in read set (not in write set)
        assert!(summary.read_accounts.contains(&pk_read.to_string()));
        assert!(summary.account_changes.is_none());
    }

    #[test]
    fn test_taint_summary_multi_tx() {
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let pk_c = Pubkey::new_unique();

        let mut log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: false,
        };

        // Tx 0: writes A, reads B
        log.push(TxTaintRecord {
            read_accounts: vec![pk_b],
            write_accounts: vec![pk_a],
            programs: vec![],
            diffs: None,
        });

        // Tx 1: writes B, reads C
        log.push(TxTaintRecord {
            read_accounts: vec![pk_c],
            write_accounts: vec![pk_b],
            programs: vec![],
            diffs: None,
        });

        let summary = build_action_taint_summary(&log, 0, 2).unwrap();
        assert_eq!(summary.tx_count, 2);
        // A and B are written
        assert!(summary.written_accounts.contains(&pk_a.to_string()));
        assert!(summary.written_accounts.contains(&pk_b.to_string()));
        // B is written so not in read set; C is only read
        assert!(!summary.read_accounts.contains(&pk_b.to_string()));
        assert!(summary.read_accounts.contains(&pk_c.to_string()));
    }

    #[test]
    fn test_taint_summary_with_diffs() {
        let pk = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let pre_account = Account {
            lamports: 100,
            data: vec![1, 2, 3, 4],
            owner,
            executable: false,
            rent_epoch: 0,
        };
        let post_account = Account {
            lamports: 200,
            data: vec![1, 9, 3, 4],
            owner,
            executable: false,
            rent_epoch: 0,
        };

        let mut log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: true,
        };
        log.push(TxTaintRecord {
            read_accounts: vec![],
            write_accounts: vec![pk],
            programs: vec![],
            diffs: Some(vec![AccountDiff {
                pubkey: pk,
                pre: Some(pre_account),
                post: Some(post_account),
            }]),
        });

        let summary = build_action_taint_summary(&log, 0, 1).unwrap();
        assert_eq!(summary.tx_count, 1);
        let changes = summary.account_changes.unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].lamports, (100, 200));
        assert!(matches!(changes[0].kind, AccountChangeKind::Modified));
        // Byte 1 changed
        assert!(changes[0].changed_ranges.contains(&(1, 1)));
    }

    #[test]
    fn test_taint_summary_range_slicing() {
        // log has 3 records, but we only look at index 1..2
        let pk_before = Pubkey::new_unique();
        let pk_target = Pubkey::new_unique();
        let pk_after = Pubkey::new_unique();

        let mut log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: false,
        };

        log.push(TxTaintRecord {
            read_accounts: vec![],
            write_accounts: vec![pk_before],
            programs: vec![],
            diffs: None,
        });
        log.push(TxTaintRecord {
            read_accounts: vec![],
            write_accounts: vec![pk_target],
            programs: vec![],
            diffs: None,
        });
        log.push(TxTaintRecord {
            read_accounts: vec![],
            write_accounts: vec![pk_after],
            programs: vec![],
            diffs: None,
        });

        let summary = build_action_taint_summary(&log, 1, 2).unwrap();
        assert_eq!(summary.tx_count, 1);
        assert!(summary.written_accounts.contains(&pk_target.to_string()));
        assert!(!summary.written_accounts.contains(&pk_before.to_string()));
        assert!(!summary.written_accounts.contains(&pk_after.to_string()));
    }

    #[test]
    fn test_taint_log_len() {
        let mut log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: false,
        };
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());

        log.push(TxTaintRecord {
            read_accounts: vec![],
            write_accounts: vec![],
            programs: vec![],
            diffs: None,
        });
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }

    #[test]
    fn test_taint_summary_created_account() {
        let pk = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let mut log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: true,
        };
        log.push(TxTaintRecord {
            read_accounts: vec![],
            write_accounts: vec![pk],
            programs: vec![],
            diffs: Some(vec![AccountDiff {
                pubkey: pk,
                pre: None,
                post: Some(Account {
                    lamports: 1_000_000,
                    data: vec![0; 32],
                    owner,
                    executable: false,
                    rent_epoch: 0,
                }),
            }]),
        });

        let summary = build_action_taint_summary(&log, 0, 1).unwrap();
        let changes = summary.account_changes.unwrap();
        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0].kind, AccountChangeKind::Created));
        assert_eq!(changes[0].lamports, (0, 1_000_000));
    }

    #[test]
    fn test_taint_summary_deleted_account() {
        let pk = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let mut log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: true,
        };
        log.push(TxTaintRecord {
            read_accounts: vec![],
            write_accounts: vec![pk],
            programs: vec![],
            diffs: Some(vec![AccountDiff {
                pubkey: pk,
                pre: Some(Account {
                    lamports: 500,
                    data: vec![1, 2, 3],
                    owner,
                    executable: false,
                    rent_epoch: 0,
                }),
                post: None,
            }]),
        });

        let summary = build_action_taint_summary(&log, 0, 1).unwrap();
        let changes = summary.account_changes.unwrap();
        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0].kind, AccountChangeKind::Deleted));
        assert_eq!(changes[0].lamports, (500, 0));
    }

    #[test]
    fn test_taint_summary_overlapping_writes_across_txs() {
        // Same account written in two txs — should merge first pre / last post
        let pk = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let mut log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: true,
        };

        // Tx 0: account goes 100 -> 200 lamports, data[0] changes 1 -> 5
        log.push(TxTaintRecord {
            read_accounts: vec![],
            write_accounts: vec![pk],
            programs: vec![],
            diffs: Some(vec![AccountDiff {
                pubkey: pk,
                pre: Some(Account {
                    lamports: 100,
                    data: vec![1, 2, 3],
                    owner,
                    executable: false,
                    rent_epoch: 0,
                }),
                post: Some(Account {
                    lamports: 200,
                    data: vec![5, 2, 3],
                    owner,
                    executable: false,
                    rent_epoch: 0,
                }),
            }]),
        });

        // Tx 1: account goes 200 -> 300 lamports, data[2] changes 3 -> 9
        log.push(TxTaintRecord {
            read_accounts: vec![],
            write_accounts: vec![pk],
            programs: vec![],
            diffs: Some(vec![AccountDiff {
                pubkey: pk,
                pre: Some(Account {
                    lamports: 200,
                    data: vec![5, 2, 3],
                    owner,
                    executable: false,
                    rent_epoch: 0,
                }),
                post: Some(Account {
                    lamports: 300,
                    data: vec![5, 2, 9],
                    owner,
                    executable: false,
                    rent_epoch: 0,
                }),
            }]),
        });

        let summary = build_action_taint_summary(&log, 0, 2).unwrap();
        assert_eq!(summary.tx_count, 2);
        let changes = summary.account_changes.unwrap();
        assert_eq!(changes.len(), 1); // Only one account
        // Should use first pre (100) and last post (300)
        assert_eq!(changes[0].lamports, (100, 300));
        assert!(matches!(changes[0].kind, AccountChangeKind::Modified));
        // data[0]: 1->5 and data[2]: 3->9 are both changed relative to first pre vs last post
        assert!(changes[0].changed_ranges.contains(&(0, 1)));
        assert!(changes[0].changed_ranges.contains(&(2, 1)));
    }

    #[test]
    fn test_taint_summary_unchanged_account_skipped() {
        // Account is in diffs but pre == post (unchanged) — should be filtered out
        let pk = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let account = Account {
            lamports: 100,
            data: vec![1, 2, 3],
            owner,
            executable: false,
            rent_epoch: 0,
        };

        let mut log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: true,
        };
        log.push(TxTaintRecord {
            read_accounts: vec![],
            write_accounts: vec![pk],
            programs: vec![],
            diffs: Some(vec![AccountDiff {
                pubkey: pk,
                pre: Some(account.clone()),
                post: Some(account),
            }]),
        });

        let summary = build_action_taint_summary(&log, 0, 1).unwrap();
        // account_changes should be None since the only account was unchanged
        assert!(summary.account_changes.is_none());
    }

    #[test]
    fn test_taint_summary_zero_tx_with_diffs_enabled() {
        // No txs but collect_diffs is true → should return Some with tx_count=0
        let log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: true,
        };

        let summary = build_action_taint_summary(&log, 0, 0).unwrap();
        assert_eq!(summary.tx_count, 0);
        assert!(summary.written_accounts.is_empty());
        assert!(summary.read_accounts.is_empty());
        assert!(summary.account_changes.is_none());
    }

    #[test]
    fn test_taint_summary_write_removes_from_read_set() {
        // Account appears in both read and write sets across txs —
        // should be in written_accounts only (removed from read_accounts)
        let pk_both = Pubkey::new_unique();
        let pk_read_only = Pubkey::new_unique();

        let mut log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: false,
        };

        // Tx 0: reads pk_both and pk_read_only
        log.push(TxTaintRecord {
            read_accounts: vec![pk_both, pk_read_only],
            write_accounts: vec![],
            programs: vec![],
            diffs: None,
        });

        // Tx 1: writes pk_both
        log.push(TxTaintRecord {
            read_accounts: vec![],
            write_accounts: vec![pk_both],
            programs: vec![],
            diffs: None,
        });

        let summary = build_action_taint_summary(&log, 0, 2).unwrap();
        // pk_both was written, so it should NOT be in read_accounts
        assert!(summary.written_accounts.contains(&pk_both.to_string()));
        assert!(!summary.read_accounts.contains(&pk_both.to_string()));
        // pk_read_only should only be in read_accounts
        assert!(summary.read_accounts.contains(&pk_read_only.to_string()));
        assert!(!summary.written_accounts.contains(&pk_read_only.to_string()));
    }

    #[test]
    fn test_taint_summary_multiple_accounts_in_diffs() {
        // Two different accounts modified in same tx
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let mut log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: true,
        };
        log.push(TxTaintRecord {
            read_accounts: vec![],
            write_accounts: vec![pk_a, pk_b],
            programs: vec![],
            diffs: Some(vec![
                AccountDiff {
                    pubkey: pk_a,
                    pre: Some(Account {
                        lamports: 100,
                        data: vec![1, 2],
                        owner,
                        executable: false,
                        rent_epoch: 0,
                    }),
                    post: Some(Account {
                        lamports: 200,
                        data: vec![1, 2],
                        owner,
                        executable: false,
                        rent_epoch: 0,
                    }),
                },
                AccountDiff {
                    pubkey: pk_b,
                    pre: Some(Account {
                        lamports: 50,
                        data: vec![0, 0, 0],
                        owner,
                        executable: false,
                        rent_epoch: 0,
                    }),
                    post: Some(Account {
                        lamports: 50,
                        data: vec![0, 1, 0],
                        owner,
                        executable: false,
                        rent_epoch: 0,
                    }),
                },
            ]),
        });

        let summary = build_action_taint_summary(&log, 0, 1).unwrap();
        let changes = summary.account_changes.unwrap();
        assert_eq!(changes.len(), 2);

        // Find each account's change
        let change_a = changes.iter().find(|c| c.pubkey == pk_a.to_string()).unwrap();
        let change_b = changes.iter().find(|c| c.pubkey == pk_b.to_string()).unwrap();

        // Account A: only lamports changed
        assert_eq!(change_a.lamports, (100, 200));
        assert!(change_a.changed_ranges.is_empty()); // data unchanged

        // Account B: only data[1] changed
        assert_eq!(change_b.lamports, (50, 50));
        assert_eq!(change_b.changed_ranges, vec![(1, 1)]);
    }

    #[test]
    fn test_taint_summary_out_of_bounds_range() {
        // If start_idx == end_idx (empty range), should behave like no txs
        let mut log = IterationTaintLog {
            records: Vec::new(),
            collect_diffs: false,
        };
        log.push(TxTaintRecord {
            read_accounts: vec![Pubkey::new_unique()],
            write_accounts: vec![Pubkey::new_unique()],
            programs: vec![],
            diffs: None,
        });

        // Range 5..5 is empty, beyond log size — should return None
        let result = build_action_taint_summary(&log, 5, 5);
        assert!(result.is_none());
    }

    // =========================================================================
    // Fingerprinting helpers
    // =========================================================================

    #[test]
    fn test_log2_bucket() {
        assert_eq!(log2_bucket(0), 0);
        assert_eq!(log2_bucket(1), 1);
        assert_eq!(log2_bucket(100), 1);
        assert_eq!(log2_bucket(u32::MAX as u64), 1);
        assert_eq!(log2_bucket(u32::MAX as u64 + 1), 2);
        assert_eq!(log2_bucket(u64::MAX), 2);
    }

    #[test]
    fn test_state_class_from_fingerprint() {
        // Top 16 bits of 0xABCD_0000_0000_0000 should be 0xABCD
        assert_eq!(state_class_from_fingerprint(0xABCD_0000_0000_0000), 0xABCD);
        assert_eq!(state_class_from_fingerprint(0), 0);
        assert_eq!(state_class_from_fingerprint(u64::MAX), 0xFFFF);
        // Lower bits shouldn't affect state class
        assert_eq!(
            state_class_from_fingerprint(0xDEAD_1234_5678_9ABC),
            0xDEAD
        );
    }

    // =========================================================================
    // SvmSnapshot — unit tests (no SVM needed)
    // =========================================================================

    #[test]
    fn test_svm_snapshot_empty() {
        let clock = Clock {
            slot: 42,
            epoch_start_timestamp: 1000,
            epoch: 5,
            leader_schedule_epoch: 6,
            unix_timestamp: 2000,
        };
        let snap = SvmSnapshot::empty(clock.clone());
        assert_eq!(snap.account_count(), 0);
        assert_eq!(snap.clock().slot, 42);
        assert_eq!(snap.clock().unix_timestamp, 2000);
    }

    #[test]
    fn test_svm_snapshot_accounts_and_clock() {
        let clock = Clock {
            slot: 100,
            epoch_start_timestamp: 0,
            epoch: 1,
            leader_schedule_epoch: 2,
            unix_timestamp: 5000,
        };
        let mut accounts = FastHashMap::default();
        let pk = Pubkey::new_unique();
        accounts.insert(pk, Arc::new(Account {
            lamports: 999,
            data: vec![1, 2, 3],
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        }));
        let snap = SvmSnapshot { accounts, clock };
        assert_eq!(snap.account_count(), 1);
        assert!(snap.accounts().contains_key(&pk));
        assert_eq!(snap.accounts()[&pk].lamports, 999);
        assert_eq!(snap.clock().slot, 100);
    }

    // =========================================================================
    // StatePool — helpers
    // =========================================================================

    /// Create a test Clock with a unique slot for unique fingerprints.
    fn make_test_clock(slot: u64) -> Clock {
        Clock {
            slot,
            epoch_start_timestamp: 0,
            epoch: 0,
            leader_schedule_epoch: 0,
            unix_timestamp: slot as i64,
        }
    }

    /// Build action_bytes in the FuzzInput format: 4-byte LE count header + payload.
    fn make_action_bytes(count: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = count.to_le_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes
    }

    /// Add a simple state to the pool with the given fingerprint and depth.
    /// Returns true if added.
    fn add_test_state(
        pool: &mut StatePool,
        fingerprint: u64,
        depth: u32,
        parent_idx: Option<usize>,
        action_desc: &str,
        action_variant: Option<u16>,
    ) -> bool {
        let action_bytes = make_action_bytes(1, &[0xAA, 0xBB]);
        pool.try_add(
            fingerprint,
            SvmSnapshot::empty(make_test_clock(depth as u64)),
            depth,
            parent_idx,
            action_bytes,
            action_desc.to_string(),
            action_variant,
            vec![0xCC],
            None,
            false,
        )
    }

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
        assert!(!add_test_state(&mut pool, 3, 2, None, "", None));
        assert_eq!(pool.len(), 2);
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

        // Fingerprints are truncated to FINGERPRINT_BITS (16 bits) for dedup.
        // Two fingerprints with the same bottom 16 bits should collide.
        let fp1 = 0x0000_0000_0000_1234u64;
        let fp2 = 0xFFFF_FFFF_FFFF_1234u64; // same bottom 16 bits

        assert!(add_test_state(&mut pool, fp1, 0, None, "", None));
        // Same dedup key — rejected
        assert!(!add_test_state(&mut pool, fp2, 1, None, "", None));
        assert_eq!(pool.len(), 1);

        // Different bottom 16 bits — accepted
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
        let mut pool = StatePool::new(100, 20);
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
            SvmSnapshot::empty(make_test_clock(0)),
            0,
            None,
            action_bytes.clone(),
            "test".to_string(),
            Some(0),
            vec![],
            None,
            false,
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
            SvmSnapshot::empty(make_test_clock(0)),
            0,
            None,
            vec![0, 0, 0, 0], // 4-byte header, count=0
            "".to_string(),
            None,
            vec![],
            None,
            false,
        );

        // State with real action bytes — should be written
        pool.try_add(
            2,
            SvmSnapshot::empty(make_test_clock(1)),
            1,
            Some(0),
            make_action_bytes(1, &[0xAA, 0xBB]),
            "deposit".to_string(),
            Some(0),
            vec![],
            None,
            false,
        );

        // Another state with different action bytes
        pool.try_add(
            3,
            SvmSnapshot::empty(make_test_clock(2)),
            2,
            Some(1),
            make_action_bytes(2, &[0xCC, 0xDD, 0xEE, 0xFF]),
            "borrow".to_string(),
            Some(1),
            vec![],
            None,
            false,
        );

        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();
        let count = pool.export_corpus(dir_path).unwrap();

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
            SvmSnapshot::empty(make_test_clock(0)),
            0,
            None,
            vec![0, 0, 0, 0],
            "".to_string(),
            None,
            vec![],
            None,
            false,
        );

        let dir = tempfile::tempdir().unwrap();
        let count = pool.export_corpus(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_state_pool_export_corpus_content() {
        let mut pool = StatePool::new(100, 20);
        let expected_bytes = make_action_bytes(1, &[0xDE, 0xAD, 0xBE, 0xEF]);

        pool.try_add(
            1,
            SvmSnapshot::empty(make_test_clock(0)),
            0,
            None,
            expected_bytes.clone(),
            "test".to_string(),
            Some(0),
            vec![],
            None,
            false,
        );

        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();
        pool.export_corpus(dir_path).unwrap();

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
            SvmSnapshot::empty(make_test_clock(0)),
            0,
            None,
            make_action_bytes(1, &[0xFF]),
            "".to_string(),
            Some(0),
            vec![],
            None,
            false,
        );

        let base = tempfile::tempdir().unwrap();
        let nested = base.path().join("a").join("b").join("c");
        let nested_str = nested.to_str().unwrap();

        assert!(!nested.exists());
        pool.export_corpus(nested_str).unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn test_state_pool_export_corpus_deterministic() {
        // Same pool should produce identical filenames each time
        let mut pool = StatePool::new(100, 20);
        pool.try_add(
            1,
            SvmSnapshot::empty(make_test_clock(0)),
            0,
            None,
            make_action_bytes(1, &[0xAA, 0xBB, 0xCC]),
            "".to_string(),
            Some(0),
            vec![],
            None,
            false,
        );

        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();

        pool.export_corpus(dir1.path().to_str().unwrap()).unwrap();
        pool.export_corpus(dir2.path().to_str().unwrap()).unwrap();

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
    // SvmSnapshot — LiteSVM integration tests
    // =========================================================================

    /// Helper: create a non-executable test account with the given lamports and data.
    fn make_account(lamports: u64, data: &[u8]) -> Account {
        Account {
            lamports,
            data: data.to_vec(),
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        }
    }

    #[test]
    fn test_svm_snapshot_take_and_restore_round_trip() {
        let mut svm = LiteSVM::new();
        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();
        let acct1 = make_account(1000, &[1, 2, 3]);
        let acct2 = make_account(2000, &[4, 5, 6, 7]);
        svm.set_account(pk1, acct1.clone()).unwrap();
        svm.set_account(pk2, acct2.clone()).unwrap();

        // Snapshot both accounts
        let tracked: HashSet<Pubkey> = [pk1, pk2].into_iter().collect();
        let snap = SvmSnapshot::take(&svm, &tracked);
        assert_eq!(snap.account_count(), 2);

        // Mutate accounts in the SVM
        svm.set_account(pk1, make_account(9999, &[0xFF])).unwrap();
        svm.set_account(pk2, make_account(0, &[])).unwrap();
        assert_eq!(svm.get_account(&pk1).unwrap().lamports, 9999);

        // Restore via dirty tracker that marks both as dirty
        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk1);
        dirty.mark_account_dirty(&pk2);
        let restored = snap.restore(&mut svm, &dirty);
        assert_eq!(restored, 2);

        // Verify original state is back
        let got1 = svm.get_account(&pk1).unwrap();
        assert_eq!(got1.lamports, acct1.lamports);
        assert_eq!(got1.data, acct1.data);
        let got2 = svm.get_account(&pk2).unwrap();
        assert_eq!(got2.lamports, acct2.lamports);
        assert_eq!(got2.data, acct2.data);
    }

    #[test]
    fn test_svm_snapshot_restore_removes_created_accounts() {
        let mut svm = LiteSVM::new();
        let pk_original = Pubkey::new_unique();
        svm.set_account(pk_original, make_account(100, &[1])).unwrap();

        let tracked: HashSet<Pubkey> = [pk_original].into_iter().collect();
        let snap = SvmSnapshot::take(&svm, &tracked);

        // Create a new account that wasn't in the snapshot
        let pk_new = Pubkey::new_unique();
        svm.set_account(pk_new, make_account(500, &[9, 9])).unwrap();
        assert!(svm.get_account(&pk_new).is_some());

        // Restore — pk_new gets zeroed (lamports=0), which LiteSVM treats as deleted
        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk_new);
        snap.restore(&mut svm, &dirty);

        // LiteSVM returns None for zero-lamport accounts (they don't "exist")
        assert!(svm.get_account(&pk_new).is_none());
    }

    #[test]
    fn test_svm_snapshot_restore_clock() {
        let mut svm = LiteSVM::new();
        let original_clock = svm.get_sysvar::<Clock>();

        let tracked: HashSet<Pubkey> = HashSet::new();
        let snap = SvmSnapshot::take(&svm, &tracked);

        // Advance the clock
        let new_clock = Clock {
            slot: original_clock.slot + 100,
            epoch: original_clock.epoch + 1,
            unix_timestamp: original_clock.unix_timestamp + 60,
            ..original_clock
        };
        svm.set_sysvar(&new_clock);
        assert_eq!(svm.get_sysvar::<Clock>().slot, new_clock.slot);

        // Restore with clock_dirty flag
        let mut dirty = DirtyTracker::new();
        dirty.mark_clock_dirty();
        snap.restore(&mut svm, &dirty);

        let restored_clock = svm.get_sysvar::<Clock>();
        assert_eq!(restored_clock.slot, original_clock.slot);
    }

    #[test]
    fn test_svm_snapshot_restore_skips_clean_clock() {
        let mut svm = LiteSVM::new();
        let original_clock = svm.get_sysvar::<Clock>();

        let tracked: HashSet<Pubkey> = HashSet::new();
        let snap = SvmSnapshot::take(&svm, &tracked);

        // Advance the clock
        let new_clock = Clock {
            slot: original_clock.slot + 100,
            ..original_clock
        };
        svm.set_sysvar(&new_clock);

        // Restore WITHOUT clock_dirty flag — clock should NOT be restored
        let dirty = DirtyTracker::new();
        snap.restore(&mut svm, &dirty);

        let after = svm.get_sysvar::<Clock>();
        assert_eq!(after.slot, new_clock.slot); // still advanced
    }

    #[test]
    fn test_svm_snapshot_take_all() {
        let mut svm = LiteSVM::new();
        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();
        svm.set_account(pk1, make_account(100, &[1])).unwrap();
        svm.set_account(pk2, make_account(200, &[2])).unwrap();

        let snap = SvmSnapshot::take_all(&svm);
        // Should capture at least our 2 accounts (plus any sysvar/builtin accounts)
        assert!(snap.account_count() >= 2);
        assert!(snap.accounts().contains_key(&pk1));
        assert!(snap.accounts().contains_key(&pk2));
        assert_eq!(snap.accounts()[&pk1].lamports, 100);
    }

    #[test]
    fn test_svm_snapshot_restore_full_round_trip() {
        let mut svm = LiteSVM::new();
        let pk = Pubkey::new_unique();
        svm.set_account(pk, make_account(777, &[0xAB, 0xCD])).unwrap();

        // take_all captures everything
        let snap = SvmSnapshot::take_all(&svm);

        // Mutate to different (non-zero) value — LiteSVM deletes zero-lamport accounts
        svm.set_account(pk, make_account(1, &[0xFF])).unwrap();
        assert_eq!(svm.get_account(&pk).unwrap().lamports, 1);

        // restore_full writes everything back
        let count = snap.restore_full(&mut svm);
        assert!(count >= 1);
        assert_eq!(svm.get_account(&pk).unwrap().lamports, 777);
        assert_eq!(svm.get_account(&pk).unwrap().data, vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_svm_snapshot_take_delta() {
        let mut svm = LiteSVM::new();
        let pk_initial = Pubkey::new_unique();
        let pk_changed = Pubkey::new_unique();
        svm.set_account(pk_initial, make_account(100, &[1])).unwrap();
        svm.set_account(pk_changed, make_account(200, &[2])).unwrap();

        // Parent delta is empty (initial state)
        let parent_delta = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

        // Simulate an action that modifies pk_changed
        svm.set_account(pk_changed, make_account(999, &[9, 9, 9])).unwrap();

        // Track which accounts were dirty
        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk_changed);

        let delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

        // Delta should contain only the changed account
        assert_eq!(delta.account_count(), 1);
        assert!(delta.accounts().contains_key(&pk_changed));
        assert!(!delta.accounts().contains_key(&pk_initial));
        assert_eq!(delta.accounts()[&pk_changed].lamports, 999);
    }

    #[test]
    fn test_svm_snapshot_take_delta_inherits_parent() {
        let mut svm = LiteSVM::new();
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        svm.set_account(pk_a, make_account(100, &[1])).unwrap();
        svm.set_account(pk_b, make_account(200, &[2])).unwrap();

        let empty_delta = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

        // Action 1: modifies pk_a
        svm.set_account(pk_a, make_account(111, &[0xAA])).unwrap();
        let mut dirty1 = DirtyTracker::new();
        dirty1.mark_account_dirty(&pk_a);
        let delta1 = SvmSnapshot::take_delta(&svm, &empty_delta, &dirty1);
        assert_eq!(delta1.account_count(), 1); // only pk_a

        // Action 2: modifies pk_b, parent is delta1
        svm.set_account(pk_b, make_account(222, &[0xBB])).unwrap();
        let mut dirty2 = DirtyTracker::new();
        dirty2.mark_account_dirty(&pk_b);
        let delta2 = SvmSnapshot::take_delta(&svm, &delta1, &dirty2);

        // Delta2 should inherit pk_a from delta1 AND have pk_b
        assert_eq!(delta2.account_count(), 2);
        assert_eq!(delta2.accounts()[&pk_a].lamports, 111);
        assert_eq!(delta2.accounts()[&pk_b].lamports, 222);
    }

    #[test]
    fn test_svm_snapshot_restore_selective() {
        let mut svm = LiteSVM::new();
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let pk_c = Pubkey::new_unique();

        // Initial state
        svm.set_account(pk_a, make_account(100, &[1])).unwrap();
        svm.set_account(pk_b, make_account(200, &[2])).unwrap();
        svm.set_account(pk_c, make_account(300, &[3])).unwrap();

        let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // Build a delta where pk_a=111, pk_b=222 (pk_c unchanged from initial)
        let mut delta_accounts = FastHashMap::default();
        delta_accounts.insert(pk_a, Arc::new(make_account(111, &[0xAA])));
        delta_accounts.insert(pk_b, Arc::new(make_account(222, &[0xBB])));
        let delta = SvmSnapshot {
            accounts: delta_accounts,
            clock: initial.clock().clone(),
        };

        // Scramble SVM state (simulates previous iteration left garbage)
        svm.set_account(pk_a, make_account(0, &[])).unwrap();
        svm.set_account(pk_b, make_account(0, &[])).unwrap();
        svm.set_account(pk_c, make_account(0, &[])).unwrap();

        // divergent_keys = all 3 accounts (they all differ from initial)
        let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
        divergent.insert(pk_a);
        divergent.insert(pk_b);
        divergent.insert(pk_c);

        let count = initial.restore_selective(&mut svm, &divergent, &delta);
        // pk_c restored to initial (1 call), pk_a and pk_b from delta (2 calls) = 3
        assert_eq!(count, 3);

        // pk_a and pk_b should be delta values
        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 111);
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 222);
        // pk_c should be initial value
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);
    }

    #[test]
    fn test_svm_snapshot_restore_selective_from_skips_shared_arcs() {
        let mut svm = LiteSVM::new();
        let pk_shared = Pubkey::new_unique();
        let pk_changed = Pubkey::new_unique();

        svm.set_account(pk_shared, make_account(100, &[1])).unwrap();
        svm.set_account(pk_changed, make_account(200, &[2])).unwrap();

        let tracked: HashSet<Pubkey> = [pk_shared, pk_changed].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // Build prev_delta and next_delta that SHARE an Arc for pk_shared
        let shared_arc = Arc::new(make_account(555, &[5, 5, 5]));
        let mut prev_accounts = FastHashMap::default();
        prev_accounts.insert(pk_shared, shared_arc.clone());
        prev_accounts.insert(pk_changed, Arc::new(make_account(888, &[8])));
        let prev_delta = SvmSnapshot {
            accounts: prev_accounts,
            clock: initial.clock().clone(),
        };

        let mut next_accounts = FastHashMap::default();
        next_accounts.insert(pk_shared, shared_arc.clone()); // same Arc!
        next_accounts.insert(pk_changed, Arc::new(make_account(999, &[9])));
        let next_delta = SvmSnapshot {
            accounts: next_accounts,
            clock: initial.clock().clone(),
        };

        // Set SVM to prev_delta values (simulate previous iteration)
        svm.set_account(pk_shared, make_account(555, &[5, 5, 5])).unwrap();
        svm.set_account(pk_changed, make_account(888, &[8])).unwrap();

        let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
        divergent.insert(pk_shared);
        divergent.insert(pk_changed);

        // No accounts were dirtied by execution (clean transition)
        let prev_exec_dirty = FastHashSet::default();

        let count = initial.restore_selective_from(
            &mut svm,
            &divergent,
            &prev_delta,
            &next_delta,
            &prev_exec_dirty,
        );

        // pk_shared shares Arc AND wasn't exec-dirtied → skipped (0 calls)
        // pk_changed has different Arc → set_account (1 call)
        assert_eq!(count, 1);

        // pk_shared should still have prev value (unchanged — that's the point)
        assert_eq!(svm.get_account(&pk_shared).unwrap().lamports, 555);
        // pk_changed should have next value
        assert_eq!(svm.get_account(&pk_changed).unwrap().lamports, 999);
    }

    #[test]
    fn test_svm_snapshot_restore_selective_from_respects_exec_dirty() {
        let mut svm = LiteSVM::new();
        let pk = Pubkey::new_unique();
        svm.set_account(pk, make_account(100, &[1])).unwrap();

        let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // Both deltas share the same Arc for pk
        let shared_arc = Arc::new(make_account(500, &[5]));
        let mut delta_accounts = FastHashMap::default();
        delta_accounts.insert(pk, shared_arc.clone());
        let prev_delta = SvmSnapshot {
            accounts: delta_accounts.clone(),
            clock: initial.clock().clone(),
        };
        let next_delta = SvmSnapshot {
            accounts: delta_accounts,
            clock: initial.clock().clone(),
        };

        // Simulate execution dirtied pk (SVM now has garbage, not the delta value)
        svm.set_account(pk, make_account(0, &[0xFF, 0xFF])).unwrap();

        let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
        divergent.insert(pk);

        // Mark pk as exec-dirtied
        let mut prev_exec_dirty = FastHashSet::default();
        prev_exec_dirty.insert(pk);

        let count = initial.restore_selective_from(
            &mut svm,
            &divergent,
            &prev_delta,
            &next_delta,
            &prev_exec_dirty,
        );

        // Even though Arc pointers are the same, exec_dirty forces a write
        assert_eq!(count, 1);
        assert_eq!(svm.get_account(&pk).unwrap().lamports, 500);
    }

    // =========================================================================
    // DirtyTracker + SvmSnapshot integration — the fuzz iteration loop
    // =========================================================================

    #[test]
    fn test_dirty_tracker_snapshot_iteration_cycle() {
        // Simulates the core fuzz loop:
        // 1. Setup initial state & snapshot
        // 2. Execute actions (mutate accounts)
        // 3. Dirty tracker records what changed
        // 4. Restore snapshot
        // 5. Verify initial state is back
        let mut svm = LiteSVM::new();
        let pk_user = Pubkey::new_unique();
        let pk_vault = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();

        // Both accounts must have non-zero lamports — LiteSVM deletes zero-lamport accounts
        svm.set_account(pk_user, make_account(1_000_000, &[0; 32])).unwrap();
        svm.set_account(pk_vault, make_account(1, &[0; 64])).unwrap();

        let tracked: HashSet<Pubkey> = [pk_user, pk_vault].into_iter().collect();
        let snap = SvmSnapshot::take(&svm, &tracked);

        // --- Iteration 1: simulate deposit ---
        let mut dirty = DirtyTracker::new();
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(pk_user, true),
                AccountMeta::new(pk_vault, false),
            ],
            data: vec![0x01], // deposit instruction
        };
        let fee_payer = Pubkey::new_unique();
        dirty.record_tx(&[ix], &fee_payer);

        // Simulate the state change (normally done by SVM execution)
        svm.set_account(pk_user, make_account(500_000, &[0; 32])).unwrap();
        svm.set_account(pk_vault, make_account(500_001, &[0; 64])).unwrap();

        // Verify dirty tracker caught the right accounts
        assert!(dirty.dirty_accounts().contains(&pk_user));
        assert!(dirty.dirty_accounts().contains(&pk_vault));

        // Restore
        snap.restore(&mut svm, &dirty);
        assert_eq!(svm.get_account(&pk_user).unwrap().lamports, 1_000_000);
        assert_eq!(svm.get_account(&pk_vault).unwrap().lamports, 1);

        // --- Iteration 2: different action, same snapshot ---
        dirty.clear();
        let ix2 = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(pk_vault, false)],
            data: vec![0x02],
        };
        dirty.record_tx(&[ix2], &fee_payer);
        svm.set_account(pk_vault, make_account(999_999, &[0xFF; 64])).unwrap();

        snap.restore(&mut svm, &dirty);
        assert_eq!(svm.get_account(&pk_vault).unwrap().lamports, 1);
        assert_eq!(svm.get_account(&pk_vault).unwrap().data, vec![0; 64]);
        // pk_user was NOT dirty in iteration 2, should be unchanged from initial
        assert_eq!(svm.get_account(&pk_user).unwrap().lamports, 1_000_000);
    }

    #[test]
    fn test_take_full_captures_dirty_and_base() {
        let mut svm = LiteSVM::new();
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();

        svm.set_account(pk_a, make_account(100, &[1])).unwrap();
        svm.set_account(pk_b, make_account(200, &[2])).unwrap();

        let tracked: HashSet<Pubkey> = [pk_a, pk_b].into_iter().collect();
        let base = SvmSnapshot::take(&svm, &tracked);

        // Modify pk_a only
        svm.set_account(pk_a, make_account(999, &[9, 9])).unwrap();
        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk_a);

        let full = SvmSnapshot::take_full(&svm, &base, &dirty);

        // Full snapshot should have BOTH accounts
        assert_eq!(full.account_count(), 2);
        // pk_a should have the new value
        assert_eq!(full.accounts()[&pk_a].lamports, 999);
        // pk_b should have the original value (from base)
        assert_eq!(full.accounts()[&pk_b].lamports, 200);
    }

    // =========================================================================
    // StatePool — edge cases
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

        // State 0: NOT coverage_novel
        pool.try_add(
            1, SvmSnapshot::empty(make_test_clock(0)), 0, None,
            make_action_bytes(1, &[0xAA]), "".to_string(), None, vec![], None,
            false,
        );
        // State 1: coverage_novel = true (3x weight boost)
        pool.try_add(
            2, SvmSnapshot::empty(make_test_clock(1)), 1, None,
            make_action_bytes(1, &[0xBB]), "".to_string(), None, vec![], None,
            true,
        );

        // Pick many times and count how often each is picked.
        // State 1 (coverage_novel) should be picked ~3x more often.
        let mut counts = [0u32; 2];
        for i in 0..10_000u64 {
            // Use spread-out rng values
            let rv = i.wrapping_mul(6364136223846793005);
            if let Some(idx) = pool.pick_weighted(rv) {
                counts[idx] += 1;
            }
        }

        // With 3x weight boost, state 1 should get picked roughly 3x as often.
        // Allow generous tolerance: ratio should be > 1.5x at minimum.
        let ratio = counts[1] as f64 / counts[0].max(1) as f64;
        assert!(
            ratio > 1.5,
            "coverage_novel state should be picked more often: counts={:?}, ratio={:.2}",
            counts, ratio,
        );
    }

    #[test]
    fn test_state_pool_violation_penalty_reduces_picks() {
        let mut pool = StatePool::new(100, 20);

        add_test_state(&mut pool, 1, 0, None, "", None); // idx 0
        add_test_state(&mut pool, 2, 1, None, "", None); // idx 1

        // Give state 0 a ton of violations
        for _ in 0..50 {
            pool.record_violation(0);
        }

        // Pick many times — state 0 should be heavily penalized
        let mut counts = [0u32; 2];
        for i in 0..10_000u64 {
            let rv = i.wrapping_mul(6364136223846793005);
            if let Some(idx) = pool.pick_weighted(rv) {
                counts[idx] += 1;
            }
        }

        // State 0 has penalty 1/(50+1) ≈ 0.02x weight. State 1 should dominate.
        assert!(
            counts[1] > counts[0] * 5,
            "violated state should be rarely picked: counts={:?}",
            counts,
        );
    }

    #[test]
    fn test_state_pool_try_add_parent_idx_out_of_bounds() {
        let mut pool = StatePool::new(100, 20);

        // parent_idx points to nonexistent state — should still add,
        // but the parent credit silently fails (get_mut returns None)
        let added = pool.try_add(
            1, SvmSnapshot::empty(make_test_clock(0)), 1, Some(99),
            make_action_bytes(1, &[0xAA]), "test".to_string(), Some(0), vec![], None, false,
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
            1, SvmSnapshot::empty(make_test_clock(0)), 0, None,
            make_action_bytes(1, &[0xFF]), "".to_string(), Some(0), vec![],
            Some(fixture),
            false,
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
            1, SvmSnapshot::empty(make_test_clock(0)), 0, None,
            bytes.clone(), "a".to_string(), Some(0), vec![], None, false,
        );
        pool.try_add(
            2, SvmSnapshot::empty(make_test_clock(1)), 1, None,
            bytes.clone(), "b".to_string(), Some(1), vec![], None, false,
        );

        let dir = tempfile::tempdir().unwrap();
        let count = pool.export_corpus(dir.path().to_str().unwrap()).unwrap();
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
    // capture_tx_meta — pure data, no SVM needed
    // =========================================================================

    #[test]
    fn test_capture_tx_meta() {
        let fee_payer = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let writable = Pubkey::new_unique();
        let readonly = Pubkey::new_unique();

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(writable, false),
                AccountMeta::new_readonly(readonly, false),
            ],
            data: vec![1, 2, 3],
        };

        let meta = capture_tx_meta(&[ix], &fee_payer);

        assert!(meta.write_accounts.contains(&fee_payer));
        assert!(meta.write_accounts.contains(&writable));
        assert!(!meta.write_accounts.contains(&readonly));
        assert!(meta.read_accounts.contains(&readonly));
        assert!(meta.read_accounts.contains(&program_id));
        assert!(meta.programs.contains(&program_id));
    }

    #[test]
    fn test_capture_tx_meta_multi_instruction() {
        let fee_payer = Pubkey::new_unique();
        let prog1 = Pubkey::new_unique();
        let prog2 = Pubkey::new_unique();
        let acc_a = Pubkey::new_unique();
        let acc_b = Pubkey::new_unique();

        let ix1 = Instruction {
            program_id: prog1,
            accounts: vec![AccountMeta::new(acc_a, false)],
            data: vec![],
        };
        let ix2 = Instruction {
            program_id: prog2,
            accounts: vec![AccountMeta::new_readonly(acc_b, false)],
            data: vec![],
        };

        let meta = capture_tx_meta(&[ix1, ix2], &fee_payer);

        assert_eq!(meta.programs, vec![prog1, prog2]);
        assert!(meta.write_accounts.contains(&acc_a));
        assert!(meta.read_accounts.contains(&acc_b));
    }

    // =========================================================================
    // compute_state_fingerprint — integration with LiteSVM
    // =========================================================================

    #[test]
    fn test_fingerprint_empty_dirty_set() {
        let svm = LiteSVM::new();
        let dirty = DirtyTracker::new();
        assert_eq!(compute_state_fingerprint_from_snapshot(&svm, &dirty), 0);
    }

    #[test]
    fn test_fingerprint_changes_with_data() {
        let mut svm = LiteSVM::new();
        let pk = Pubkey::new_unique();

        // Use data that crosses log2_bucket boundaries:
        // [0,0,0,0,0,0,0,0] → u64 LE = 0 → bucket 0
        svm.set_account(pk, make_account(1000, &[0, 0, 0, 0, 0, 0, 0, 0])).unwrap();

        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk);

        let fp1 = compute_state_fingerprint_from_snapshot(&svm, &dirty);
        assert_ne!(fp1, 0); // non-zero because pubkey + lamports also contribute

        // [1,0,0,0,0,0,0,0] → u64 LE = 1 → bucket 1 (different from bucket 0)
        svm.set_account(pk, make_account(1000, &[1, 0, 0, 0, 0, 0, 0, 0])).unwrap();
        let fp2 = compute_state_fingerprint_from_snapshot(&svm, &dirty);

        assert_ne!(fp1, fp2, "data crossing bucket boundaries should produce different fingerprints");

        // Also test lamports bucket boundary:
        // lamports=0 (bucket 0) vs lamports=1 (bucket 1)
        svm.set_account(pk, make_account(1, &[0; 8])).unwrap();
        let fp3 = compute_state_fingerprint_from_snapshot(&svm, &dirty);
        // fp1 had lamports=1000 (bucket 1), fp3 has lamports=1 (bucket 1) — same bucket
        // but fp1 had data bucket 0 and fp3 has data bucket 0 → same
        // Compare against a big lamports value that crosses into bucket 2
        svm.set_account(pk, make_account(u64::MAX, &[0; 8])).unwrap();
        let fp4 = compute_state_fingerprint_from_snapshot(&svm, &dirty);
        assert_ne!(fp3, fp4, "lamports crossing bucket boundary should change fingerprint");
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let mut svm = LiteSVM::new();
        let pk = Pubkey::new_unique();
        svm.set_account(pk, make_account(500, &[0xAB; 16])).unwrap();

        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk);

        let fp1 = compute_state_fingerprint_from_snapshot(&svm, &dirty);
        let fp2 = compute_state_fingerprint_from_snapshot(&svm, &dirty);
        assert_eq!(fp1, fp2, "same state should produce same fingerprint");
    }

    // =========================================================================
    // Multi-step state chains (A→B→C)
    // =========================================================================

    #[test]
    fn test_delta_chain_three_levels_same_account() {
        // Account X modified at every level: 100→200→300→400.
        // take_delta at each step. restore_full from each delta yields correct value.
        // restore_selective from delta_C back to delta_A correctly reverts X.
        let mut svm = LiteSVM::new();
        let pk_x = Pubkey::new_unique();

        // Initial state: X=100
        svm.set_account(pk_x, make_account(100, &[0x01])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_x].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);
        let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

        // Action A: X → 200
        svm.set_account(pk_x, make_account(200, &[0x02])).unwrap();
        let mut dirty_a = DirtyTracker::new();
        dirty_a.mark_account_dirty(&pk_x);
        let delta_a = SvmSnapshot::take_delta(&svm, &delta_root, &dirty_a);
        assert_eq!(delta_a.accounts()[&pk_x].lamports, 200);

        // Action B: X → 300 (parent = delta_a)
        svm.set_account(pk_x, make_account(300, &[0x03])).unwrap();
        let mut dirty_b = DirtyTracker::new();
        dirty_b.mark_account_dirty(&pk_x);
        let delta_b = SvmSnapshot::take_delta(&svm, &delta_a, &dirty_b);
        assert_eq!(delta_b.accounts()[&pk_x].lamports, 300);

        // Action C: X → 400 (parent = delta_b)
        svm.set_account(pk_x, make_account(400, &[0x04])).unwrap();
        let mut dirty_c = DirtyTracker::new();
        dirty_c.mark_account_dirty(&pk_x);
        let delta_c = SvmSnapshot::take_delta(&svm, &delta_b, &dirty_c);
        assert_eq!(delta_c.accounts()[&pk_x].lamports, 400);

        // restore_full from delta_a → X=200
        delta_a.restore_full(&mut svm);
        assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 200);

        // restore_full from delta_b → X=300
        delta_b.restore_full(&mut svm);
        assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 300);

        // restore_full from delta_c → X=400
        delta_c.restore_full(&mut svm);
        assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 400);

        // restore_selective from delta_C state back to delta_A:
        // SVM currently has delta_C values. divergent = {pk_x} (delta_C's key).
        let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
        divergent.insert(pk_x);
        initial.restore_selective(&mut svm, &divergent, &delta_a);
        assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 200);
    }

    #[test]
    fn test_delta_chain_middle_deletes_account() {
        // Action A creates X. Action B deletes X (tombstone in delta_B).
        // Action C adds Y. Verify delta_B has tombstone, restore_full zeroes X.
        let mut svm = LiteSVM::new();
        let pk_x = Pubkey::new_unique();
        let pk_y = Pubkey::new_unique();

        // Initial: X=100
        svm.set_account(pk_x, make_account(100, &[1])).unwrap();
        let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

        // Action A: X → 200
        svm.set_account(pk_x, make_account(200, &[2])).unwrap();
        let mut dirty_a = DirtyTracker::new();
        dirty_a.mark_account_dirty(&pk_x);
        let delta_a = SvmSnapshot::take_delta(&svm, &delta_root, &dirty_a);

        // Action B: delete X (simulate by setting lamports=0, which makes get_account return None)
        svm.set_account(pk_x, Account { lamports: 0, ..Default::default() }).unwrap();
        let mut dirty_b = DirtyTracker::new();
        dirty_b.mark_account_dirty(&pk_x);
        let delta_b = SvmSnapshot::take_delta(&svm, &delta_a, &dirty_b);

        // Delta B should have X as tombstone (lamports=0)
        assert!(delta_b.accounts().contains_key(&pk_x));
        assert_eq!(delta_b.accounts()[&pk_x].lamports, 0);

        // Action C: add Y=500 (parent = delta_b)
        svm.set_account(pk_y, make_account(500, &[5])).unwrap();
        let mut dirty_c = DirtyTracker::new();
        dirty_c.mark_account_dirty(&pk_y);
        let delta_c = SvmSnapshot::take_delta(&svm, &delta_b, &dirty_c);
        assert!(delta_c.accounts().contains_key(&pk_y));
        assert_eq!(delta_c.accounts()[&pk_y].lamports, 500);
        // X tombstone inherited from delta_b
        assert_eq!(delta_c.accounts()[&pk_x].lamports, 0);

        // Restore to a state where X existed first
        svm.set_account(pk_x, make_account(999, &[9])).unwrap();
        // restore_full from delta_b should zero X
        delta_b.restore_full(&mut svm);
        // LiteSVM treats zero-lamport as deleted
        assert!(svm.get_account(&pk_x).is_none());
    }

    #[test]
    fn test_delta_chain_sibling_branches() {
        // delta_A is parent. delta_B (from A) modifies X. delta_C (also from A) modifies Y.
        // Both inherit unchanged accounts from A via Arc clone.
        // restore_selective_from(prev=delta_B, next=delta_C) should skip shared Arcs.
        let mut svm = LiteSVM::new();
        let pk_base = Pubkey::new_unique();
        let pk_x = Pubkey::new_unique();
        let pk_y = Pubkey::new_unique();

        // Initial
        svm.set_account(pk_base, make_account(100, &[1])).unwrap();
        svm.set_account(pk_x, make_account(200, &[2])).unwrap();
        svm.set_account(pk_y, make_account(300, &[3])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_base, pk_x, pk_y].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);
        let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

        // Action A: modify base → 111
        svm.set_account(pk_base, make_account(111, &[0xAA])).unwrap();
        let mut dirty_a = DirtyTracker::new();
        dirty_a.mark_account_dirty(&pk_base);
        let delta_a = SvmSnapshot::take_delta(&svm, &delta_root, &dirty_a);

        // Sibling B (from delta_a): modify X → 222
        svm.set_account(pk_x, make_account(222, &[0xBB])).unwrap();
        let mut dirty_b = DirtyTracker::new();
        dirty_b.mark_account_dirty(&pk_x);
        let delta_b = SvmSnapshot::take_delta(&svm, &delta_a, &dirty_b);

        // Reset X for sibling C
        svm.set_account(pk_x, make_account(200, &[2])).unwrap();

        // Sibling C (from delta_a): modify Y → 333
        svm.set_account(pk_y, make_account(333, &[0xCC])).unwrap();
        let mut dirty_c = DirtyTracker::new();
        dirty_c.mark_account_dirty(&pk_y);
        let delta_c = SvmSnapshot::take_delta(&svm, &delta_a, &dirty_c);

        // Both siblings share the same Arc for pk_base (inherited from delta_a)
        assert!(Arc::ptr_eq(
            &delta_b.accounts()[&pk_base],
            &delta_c.accounts()[&pk_base],
        ));

        // delta_b has X=222, delta_c has Y=333
        assert_eq!(delta_b.accounts()[&pk_x].lamports, 222);
        assert!(!delta_b.accounts().contains_key(&pk_y));
        assert_eq!(delta_c.accounts()[&pk_y].lamports, 333);
        assert!(!delta_c.accounts().contains_key(&pk_x));

        // Set SVM to delta_b state
        delta_b.restore_full(&mut svm);
        assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 222);

        // restore_selective_from: prev=delta_B, next=delta_C
        let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
        for pk in delta_b.accounts().keys() {
            divergent.insert(*pk);
        }
        let prev_exec_dirty = FastHashSet::default();

        let count = initial.restore_selective_from(
            &mut svm, &divergent, &delta_b, &delta_c, &prev_exec_dirty,
        );

        // pk_base shares Arc → skipped. X is in divergent but not in delta_c → restored to initial.
        // Y is in delta_c but not in delta_b → unconditional write.
        // So count should be 2 (X restored to initial + Y from delta_c)
        assert_eq!(count, 2);

        // Verify final state
        assert_eq!(svm.get_account(&pk_base).unwrap().lamports, 111); // shared, unchanged
        assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 200); // restored to initial
        assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 333); // from delta_c
    }

    // =========================================================================
    // restore_selective / restore_selective_from edge cases
    // =========================================================================

    #[test]
    fn test_restore_selective_divergent_not_in_initial_or_delta() {
        // divergent_keys contains an account that exists in neither initial nor delta.
        // This is a CPI-created account from a prior iteration. Should be zeroed.
        let mut svm = LiteSVM::new();
        let pk_initial = Pubkey::new_unique();
        let pk_cpi = Pubkey::new_unique();

        svm.set_account(pk_initial, make_account(100, &[1])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_initial].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // CPI-created account in SVM (not in initial snapshot)
        svm.set_account(pk_cpi, make_account(999, &[9, 9])).unwrap();

        // Delta doesn't include pk_cpi either
        let delta = SvmSnapshot::empty(initial.clock().clone());

        // divergent includes pk_cpi (from previous iteration's dirty tracker)
        let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
        divergent.insert(pk_cpi);

        initial.restore_selective(&mut svm, &divergent, &delta);

        // pk_cpi should be zeroed (deleted) — not in initial, not in delta
        assert!(svm.get_account(&pk_cpi).is_none());
    }

    #[test]
    fn test_restore_selective_from_next_has_new_accounts() {
        // prev_delta has {X}, next_delta has {X, Y}. Y is brand new.
        // Step 2 finds Y not in prev_delta → unconditional write.
        let mut svm = LiteSVM::new();
        let pk_x = Pubkey::new_unique();
        let pk_y = Pubkey::new_unique();

        svm.set_account(pk_x, make_account(100, &[1])).unwrap();
        svm.set_account(pk_y, make_account(200, &[2])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_x, pk_y].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // prev_delta: only X=500
        let mut prev_accounts = FastHashMap::default();
        prev_accounts.insert(pk_x, Arc::new(make_account(500, &[5])));
        let prev_delta = SvmSnapshot { accounts: prev_accounts, clock: initial.clock().clone() };

        // next_delta: X=500 (same Arc) + Y=700 (new)
        let shared_x = prev_delta.accounts()[&pk_x].clone();
        let mut next_accounts = FastHashMap::default();
        next_accounts.insert(pk_x, shared_x);
        next_accounts.insert(pk_y, Arc::new(make_account(700, &[7])));
        let next_delta = SvmSnapshot { accounts: next_accounts, clock: initial.clock().clone() };

        // SVM starts at prev_delta state
        svm.set_account(pk_x, make_account(500, &[5])).unwrap();

        let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
        divergent.insert(pk_x);
        let prev_exec_dirty = FastHashSet::default();

        let count = initial.restore_selective_from(
            &mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty,
        );

        // X: shared Arc, not exec-dirty → skipped
        // Y: in next_delta, not in prev_delta → written (1 call)
        assert_eq!(count, 1);
        assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 500);
        assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 700);
    }

    #[test]
    fn test_restore_selective_from_prev_accounts_not_in_divergent() {
        // prev_delta has {X, Y}, next_delta has {X}. Y is in prev_delta but NOT in
        // divergent_keys. After restore, Y retains prev_delta's value (stale) — documents
        // the contract that callers MUST include all prev_delta keys in divergent_keys.
        let mut svm = LiteSVM::new();
        let pk_x = Pubkey::new_unique();
        let pk_y = Pubkey::new_unique();

        svm.set_account(pk_x, make_account(100, &[1])).unwrap();
        svm.set_account(pk_y, make_account(200, &[2])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_x, pk_y].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        let mut prev_accounts = FastHashMap::default();
        prev_accounts.insert(pk_x, Arc::new(make_account(500, &[5])));
        prev_accounts.insert(pk_y, Arc::new(make_account(600, &[6])));
        let prev_delta = SvmSnapshot { accounts: prev_accounts, clock: initial.clock().clone() };

        let mut next_accounts = FastHashMap::default();
        next_accounts.insert(pk_x, Arc::new(make_account(700, &[7])));
        // next_delta does NOT have Y
        let next_delta = SvmSnapshot { accounts: next_accounts, clock: initial.clock().clone() };

        // SVM at prev_delta state
        svm.set_account(pk_x, make_account(500, &[5])).unwrap();
        svm.set_account(pk_y, make_account(600, &[6])).unwrap();

        // BUG: divergent only includes pk_x, not pk_y (caller error)
        let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
        divergent.insert(pk_x);
        // NOT: divergent.insert(pk_y);
        let prev_exec_dirty = FastHashSet::default();

        initial.restore_selective_from(
            &mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty,
        );

        // X: in divergent AND in next_delta → skipped in step 1, written with next_delta value in step 2
        assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 700);
        // Y: NOT in divergent → never touched in step 1. NOT in next_delta → never touched in step 2.
        // Still has prev_delta stale value (600).
        // This documents the contract: callers MUST include prev_delta keys in divergent.
        assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 600);
    }

    #[test]
    fn test_restore_selective_empty_divergent_with_delta() {
        // First-iteration case: divergent_keys is empty, delta has 3 accounts.
        // Step 1 is a no-op. Step 2 writes all 3 delta accounts.
        let mut svm = LiteSVM::new();
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let pk_c = Pubkey::new_unique();

        svm.set_account(pk_a, make_account(10, &[1])).unwrap();
        svm.set_account(pk_b, make_account(20, &[2])).unwrap();
        svm.set_account(pk_c, make_account(30, &[3])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // Delta with different values for all 3
        let mut delta_accounts = FastHashMap::default();
        delta_accounts.insert(pk_a, Arc::new(make_account(111, &[0xAA])));
        delta_accounts.insert(pk_b, Arc::new(make_account(222, &[0xBB])));
        delta_accounts.insert(pk_c, Arc::new(make_account(333, &[0xCC])));
        let delta = SvmSnapshot { accounts: delta_accounts, clock: initial.clock().clone() };

        // Empty divergent (first iteration, SVM has initial state)
        let divergent: FastHashSet<Pubkey> = FastHashSet::default();

        let count = initial.restore_selective(&mut svm, &divergent, &delta);

        // Step 1: 0 (empty divergent). Step 2: 3 (all delta accounts).
        assert_eq!(count, 3);
        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 111);
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 222);
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 333);
    }

    // =========================================================================
    // take_delta edge cases
    // =========================================================================

    #[test]
    fn test_take_delta_empty_dirty_tracker() {
        // Parent delta has {X=100, Y=200}. Dirty tracker is empty.
        // Result should be an exact clone with Arc pointers being ptr_eq.
        let mut svm = LiteSVM::new();
        let pk_x = Pubkey::new_unique();
        let pk_y = Pubkey::new_unique();

        svm.set_account(pk_x, make_account(100, &[1])).unwrap();
        svm.set_account(pk_y, make_account(200, &[2])).unwrap();

        let mut parent_accounts = FastHashMap::default();
        parent_accounts.insert(pk_x, Arc::new(make_account(100, &[1])));
        parent_accounts.insert(pk_y, Arc::new(make_account(200, &[2])));
        let parent_delta = SvmSnapshot {
            accounts: parent_accounts,
            clock: svm.get_sysvar::<Clock>(),
        };

        let dirty = DirtyTracker::new(); // empty
        let new_delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

        // Same number of accounts
        assert_eq!(new_delta.account_count(), 2);
        assert_eq!(new_delta.accounts()[&pk_x].lamports, 100);
        assert_eq!(new_delta.accounts()[&pk_y].lamports, 200);

        // Arc pointers should be identical (no new allocations)
        assert!(Arc::ptr_eq(
            &new_delta.accounts()[&pk_x],
            &parent_delta.accounts()[&pk_x],
        ));
        assert!(Arc::ptr_eq(
            &new_delta.accounts()[&pk_y],
            &parent_delta.accounts()[&pk_y],
        ));
    }

    #[test]
    fn test_take_delta_overwrites_parent_value() {
        // Parent delta has X=200. Action modifies X to 300. Dirty tracker has X.
        // New delta should have X=300 with a NEW Arc (not ptr_eq with parent).
        let mut svm = LiteSVM::new();
        let pk_x = Pubkey::new_unique();

        svm.set_account(pk_x, make_account(300, &[3])).unwrap();

        let mut parent_accounts = FastHashMap::default();
        parent_accounts.insert(pk_x, Arc::new(make_account(200, &[2])));
        let parent_delta = SvmSnapshot {
            accounts: parent_accounts,
            clock: svm.get_sysvar::<Clock>(),
        };

        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk_x);

        let new_delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

        assert_eq!(new_delta.accounts()[&pk_x].lamports, 300);
        // Must be a NEW Arc (different allocation from parent)
        assert!(!Arc::ptr_eq(
            &new_delta.accounts()[&pk_x],
            &parent_delta.accounts()[&pk_x],
        ));
    }

    #[test]
    fn test_take_delta_deletes_account_from_parent() {
        // Parent delta has X=200. Action deletes X from SVM.
        // Dirty tracker has X, SVM returns None. New delta should have X as tombstone.
        let svm = LiteSVM::new();
        let pk_x = Pubkey::new_unique();

        // SVM has X deleted (zero lamports → None)
        // Don't set pk_x in SVM at all (get_account returns None)

        let mut parent_accounts = FastHashMap::default();
        parent_accounts.insert(pk_x, Arc::new(make_account(200, &[2])));
        let parent_delta = SvmSnapshot {
            accounts: parent_accounts,
            clock: svm.get_sysvar::<Clock>(),
        };

        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk_x);

        let new_delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

        // X should be present as tombstone (lamports=0)
        assert!(new_delta.accounts().contains_key(&pk_x));
        assert_eq!(new_delta.accounts()[&pk_x].lamports, 0);
    }

    // =========================================================================
    // take_full edge cases
    // =========================================================================

    #[test]
    fn test_take_full_deleted_account_removes_key() {
        // Base has {X=100, Y=200}. Dirty tracker marks X. SVM's X is deleted.
        // take_full should REMOVE X from the map (not insert tombstone).
        let mut svm = LiteSVM::new();
        let pk_x = Pubkey::new_unique();
        let pk_y = Pubkey::new_unique();

        svm.set_account(pk_y, make_account(200, &[2])).unwrap();
        // X is NOT in SVM (deleted)

        let mut base_accounts = FastHashMap::default();
        base_accounts.insert(pk_x, Arc::new(make_account(100, &[1])));
        base_accounts.insert(pk_y, Arc::new(make_account(200, &[2])));
        let base = SvmSnapshot {
            accounts: base_accounts,
            clock: svm.get_sysvar::<Clock>(),
        };

        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk_x);

        let full = SvmSnapshot::take_full(&svm, &base, &dirty);

        // X should be REMOVED (not tombstoned) — asymmetry with take_delta
        assert!(!full.accounts().contains_key(&pk_x));
        // Y should remain from base
        assert_eq!(full.accounts()[&pk_y].lamports, 200);
        assert_eq!(full.account_count(), 1);
    }

    #[test]
    fn test_take_full_adds_new_cpi_account() {
        // Base has {X=100}. Dirty tracker marks Y (CPI-created). SVM has Y=500.
        // take_full should produce {X=100, Y=500}.
        let mut svm = LiteSVM::new();
        let pk_x = Pubkey::new_unique();
        let pk_y = Pubkey::new_unique();

        svm.set_account(pk_x, make_account(100, &[1])).unwrap();
        svm.set_account(pk_y, make_account(500, &[5])).unwrap();

        let mut base_accounts = FastHashMap::default();
        base_accounts.insert(pk_x, Arc::new(make_account(100, &[1])));
        let base = SvmSnapshot {
            accounts: base_accounts,
            clock: svm.get_sysvar::<Clock>(),
        };

        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk_y);

        let full = SvmSnapshot::take_full(&svm, &base, &dirty);

        assert_eq!(full.account_count(), 2);
        assert_eq!(full.accounts()[&pk_x].lamports, 100);
        assert_eq!(full.accounts()[&pk_y].lamports, 500);
    }

    // =========================================================================
    // DirtyTracker edge cases
    // =========================================================================

    #[test]
    fn test_dirty_tracker_same_key_writable_and_program() {
        // Same Pubkey appears as writable AccountMeta in one instruction AND as
        // program_id in another. Should be in both writable and read_only sets.
        let mut tracker = DirtyTracker::new();
        let fee_payer = Pubkey::new_unique();
        let dual_key = Pubkey::new_unique();
        let other_program = Pubkey::new_unique();

        // Instruction 1: dual_key is writable account
        let ix1 = Instruction {
            program_id: other_program,
            accounts: vec![AccountMeta::new(dual_key, false)],
            data: vec![],
        };
        // Instruction 2: dual_key is the program_id
        let ix2 = Instruction {
            program_id: dual_key,
            accounts: vec![],
            data: vec![],
        };

        tracker.record_tx(&[ix1, ix2], &fee_payer);

        // dual_key should be in BOTH sets
        assert!(tracker.dirty_accounts().contains(&dual_key), "should be in writable set");
        assert!(tracker.read_accounts().contains(&dual_key), "should be in read_only set");
        // dirty_accounts() (writable) is what restore uses
        assert!(tracker.dirty_accounts().contains(&dual_key));
    }

    #[test]
    fn test_restore_with_fee_payer_not_in_snapshot() {
        // Fee payer is recorded as dirty (always writable) but didn't exist at
        // snapshot time. restore hits the "created during iteration" path and zeroes it.
        let mut svm = LiteSVM::new();
        let pk_initial = Pubkey::new_unique();
        let pk_fee_payer = Pubkey::new_unique();

        svm.set_account(pk_initial, make_account(100, &[1])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_initial].into_iter().collect();
        let snap = SvmSnapshot::take(&svm, &tracked);

        // Fee payer created during iteration
        svm.set_account(pk_fee_payer, make_account(1_000_000, &[0xFF; 32])).unwrap();

        let program_id = Pubkey::new_unique();
        let mut dirty = DirtyTracker::new();
        let ix = Instruction {
            program_id,
            accounts: vec![],
            data: vec![],
        };
        dirty.record_tx(&[ix], &pk_fee_payer);

        // Fee payer should be in dirty set
        assert!(dirty.dirty_accounts().contains(&pk_fee_payer));

        snap.restore(&mut svm, &dirty);

        // Fee payer should be zeroed (deleted) since it wasn't in the snapshot
        assert!(svm.get_account(&pk_fee_payer).is_none());
    }

    // =========================================================================
    // Clock handling
    // =========================================================================

    #[test]
    fn test_restore_selective_from_different_clocks() {
        // prev_delta.clock.slot=100, next_delta.clock.slot=200.
        // After restore_selective_from, SVM clock should be 200.
        let mut svm = LiteSVM::new();
        let pk = Pubkey::new_unique();
        svm.set_account(pk, make_account(100, &[1])).unwrap();

        let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        let prev_delta = SvmSnapshot {
            accounts: FastHashMap::default(),
            clock: make_test_clock(100),
        };
        let next_delta = SvmSnapshot {
            accounts: FastHashMap::default(),
            clock: make_test_clock(200),
        };

        let divergent: FastHashSet<Pubkey> = FastHashSet::default();
        let prev_exec_dirty = FastHashSet::default();

        initial.restore_selective_from(
            &mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty,
        );

        let clock = svm.get_sysvar::<Clock>();
        assert_eq!(clock.slot, 200);
        assert_eq!(clock.unix_timestamp, 200); // make_test_clock sets unix_timestamp = slot
    }

    #[test]
    fn test_restore_selective_always_sets_clock() {
        // Even if clock was NOT dirty in the current iteration, restore_selective
        // unconditionally writes the delta's clock. This differs from restore()
        // which checks is_clock_dirty().
        let mut svm = LiteSVM::new();
        let pk = Pubkey::new_unique();
        svm.set_account(pk, make_account(100, &[1])).unwrap();

        let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // Set SVM clock to something different
        svm.set_sysvar(&make_test_clock(999));
        assert_eq!(svm.get_sysvar::<Clock>().slot, 999);

        // Delta has clock at slot 42
        let delta = SvmSnapshot {
            accounts: FastHashMap::default(),
            clock: make_test_clock(42),
        };

        let divergent: FastHashSet<Pubkey> = FastHashSet::default();

        // restore_selective always sets clock, even with empty divergent
        initial.restore_selective(&mut svm, &divergent, &delta);

        assert_eq!(svm.get_sysvar::<Clock>().slot, 42);
    }

    // =========================================================================
    // Multi-iteration + dirty tracker
    // =========================================================================

    #[test]
    fn test_multi_iteration_dirty_overlap() {
        // Run 3 iterations against the same snapshot with overlapping dirty sets.
        // After each restore, ALL accounts should be back to snapshot values.
        let mut svm = LiteSVM::new();
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let pk_c = Pubkey::new_unique();

        let acct_a = make_account(100, &[1]);
        let acct_b = make_account(200, &[2]);
        let acct_c = make_account(300, &[3]);
        svm.set_account(pk_a, acct_a.clone()).unwrap();
        svm.set_account(pk_b, acct_b.clone()).unwrap();
        svm.set_account(pk_c, acct_c.clone()).unwrap();

        let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
        let snap = SvmSnapshot::take(&svm, &tracked);
        let mut dirty = DirtyTracker::new();

        // --- Iteration 1: dirties {A, B} ---
        dirty.clear();
        svm.set_account(pk_a, make_account(999, &[0xAA])).unwrap();
        svm.set_account(pk_b, make_account(888, &[0xBB])).unwrap();
        dirty.mark_account_dirty(&pk_a);
        dirty.mark_account_dirty(&pk_b);
        snap.restore(&mut svm, &dirty);

        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);

        // --- Iteration 2: dirties {B, C} ---
        dirty.clear();
        svm.set_account(pk_b, make_account(777, &[0xBB])).unwrap();
        svm.set_account(pk_c, make_account(666, &[0xCC])).unwrap();
        dirty.mark_account_dirty(&pk_b);
        dirty.mark_account_dirty(&pk_c);
        snap.restore(&mut svm, &dirty);

        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);

        // --- Iteration 3: dirties {A, C} ---
        dirty.clear();
        svm.set_account(pk_a, make_account(555, &[0xAA])).unwrap();
        svm.set_account(pk_c, make_account(444, &[0xCC])).unwrap();
        dirty.mark_account_dirty(&pk_a);
        dirty.mark_account_dirty(&pk_c);
        snap.restore(&mut svm, &dirty);

        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);
    }

    #[test]
    fn test_delta_chain_restore_full_at_each_level() {
        // Build A→B→C chain. Call restore_full from each delta and verify
        // each produces the exact state at that level — not a mix.
        let mut svm = LiteSVM::new();
        let pk_x = Pubkey::new_unique();
        let pk_y = Pubkey::new_unique();
        let pk_z = Pubkey::new_unique();

        svm.set_account(pk_x, make_account(10, &[1])).unwrap();
        svm.set_account(pk_y, make_account(20, &[2])).unwrap();
        svm.set_account(pk_z, make_account(30, &[3])).unwrap();

        let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

        // Action A: modify X → 100, add Z → 300
        svm.set_account(pk_x, make_account(100, &[0xA1])).unwrap();
        let mut dirty_a = DirtyTracker::new();
        dirty_a.mark_account_dirty(&pk_x);
        let delta_a = SvmSnapshot::take_delta(&svm, &delta_root, &dirty_a);

        // Action B: modify Y → 200 (parent = delta_a)
        svm.set_account(pk_y, make_account(200, &[0xB2])).unwrap();
        let mut dirty_b = DirtyTracker::new();
        dirty_b.mark_account_dirty(&pk_y);
        let delta_b = SvmSnapshot::take_delta(&svm, &delta_a, &dirty_b);

        // Action C: modify Z → 300 (parent = delta_b)
        svm.set_account(pk_z, make_account(300, &[0xC3])).unwrap();
        let mut dirty_c = DirtyTracker::new();
        dirty_c.mark_account_dirty(&pk_z);
        let delta_c = SvmSnapshot::take_delta(&svm, &delta_b, &dirty_c);

        // Scramble SVM
        svm.set_account(pk_x, make_account(1, &[0])).unwrap();
        svm.set_account(pk_y, make_account(1, &[0])).unwrap();
        svm.set_account(pk_z, make_account(1, &[0])).unwrap();

        // Restore from delta_a: only X=100
        delta_a.restore_full(&mut svm);
        assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100);
        // Y and Z not in delta_a, so SVM still has scrambled values for them
        // (restore_full only writes what's in the delta)

        // Scramble again
        svm.set_account(pk_x, make_account(1, &[0])).unwrap();
        svm.set_account(pk_y, make_account(1, &[0])).unwrap();
        svm.set_account(pk_z, make_account(1, &[0])).unwrap();

        // Restore from delta_b: X=100 (inherited from A), Y=200
        delta_b.restore_full(&mut svm);
        assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100);
        assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 200);

        // Scramble again
        svm.set_account(pk_x, make_account(1, &[0])).unwrap();
        svm.set_account(pk_y, make_account(1, &[0])).unwrap();
        svm.set_account(pk_z, make_account(1, &[0])).unwrap();

        // Restore from delta_c: X=100 (inherited), Y=200 (inherited), Z=300
        delta_c.restore_full(&mut svm);
        assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100);
        assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 200);
        assert_eq!(svm.get_account(&pk_z).unwrap().lamports, 300);
    }

    // =========================================================================
    // Gap 1: restore_selective → restore_selective_from transition
    //
    // The real fuzzer uses restore_selective on iteration 1 (no prev_delta),
    // then switches to restore_selective_from on iteration 2+. This test
    // exercises the exact handoff with real divergent_keys accumulation.
    // =========================================================================

    #[test]
    fn test_restore_selective_to_from_transition() {
        let mut svm = LiteSVM::new();
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let pk_c = Pubkey::new_unique();

        // Initial state
        svm.set_account(pk_a, make_account(100, &[1])).unwrap();
        svm.set_account(pk_b, make_account(200, &[2])).unwrap();
        svm.set_account(pk_c, make_account(300, &[3])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // State variables matching the real loop
        let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
        let mut prev_delta_arc: Option<SvmSnapshot> = None;
        let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

        // --- Build two pool states ---
        // State 0 (initial): empty delta
        let _delta_0 = SvmSnapshot::empty(initial.clock().clone());

        // State 1: pk_a=500 (from action on state 0)
        let mut delta_1_accounts = FastHashMap::default();
        delta_1_accounts.insert(pk_a, Arc::new(make_account(500, &[5])));
        let delta_1 = SvmSnapshot { accounts: delta_1_accounts, clock: make_test_clock(10) };

        // State 2: pk_a=500 (inherited), pk_b=600 (from action on state 1)
        let mut delta_2_accounts = FastHashMap::default();
        delta_2_accounts.insert(pk_a, delta_1.accounts()[&pk_a].clone()); // same Arc
        delta_2_accounts.insert(pk_b, Arc::new(make_account(600, &[6])));
        let delta_2 = SvmSnapshot { accounts: delta_2_accounts, clock: make_test_clock(20) };

        // === ITERATION 1: Pick state 1, use restore_selective ===
        // (prev_delta_arc is None)
        assert!(prev_delta_arc.is_none());
        initial.restore_selective(&mut svm, &divergent_keys, &delta_1);

        // Real loop: divergent_keys = delta.keys()
        divergent_keys.clear();
        divergent_keys.extend(delta_1.accounts().keys().copied());

        // Verify SVM state after restore
        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500);
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200); // initial
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300); // initial

        // Simulate action execution: dirtied pk_a and pk_c
        svm.set_account(pk_a, make_account(550, &[0xAA])).unwrap();
        svm.set_account(pk_c, make_account(350, &[0xCC])).unwrap();
        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk_a);
        dirty.mark_account_dirty(&pk_c);

        // Real loop end: update tracking variables
        let action_succeeded = true;
        prev_exec_dirty.clear();
        if action_succeeded {
            prev_exec_dirty.extend(dirty.dirty_accounts().iter().copied());
            divergent_keys.extend(prev_exec_dirty.iter().copied());
        }
        prev_delta_arc = Some(delta_1.clone());

        // divergent_keys should now be {pk_a, pk_c} (delta_1 keys ∪ dirty accounts)
        assert!(divergent_keys.contains(&pk_a));
        assert!(divergent_keys.contains(&pk_c));
        assert!(!divergent_keys.contains(&pk_b)); // not in delta_1, not dirtied

        // === ITERATION 2: Pick state 2, use restore_selective_from ===
        assert!(prev_delta_arc.is_some());
        let prev = prev_delta_arc.as_ref().unwrap();
        initial.restore_selective_from(
            &mut svm, &divergent_keys, prev, &delta_2, &prev_exec_dirty,
        );

        // Real loop: divergent_keys = delta.keys()
        divergent_keys.clear();
        divergent_keys.extend(delta_2.accounts().keys().copied());

        // Verify SVM state:
        // pk_a: in delta_2 (500). Same Arc as delta_1. But pk_a IS in prev_exec_dirty
        //        → forced write → SVM gets 500 (correct, overwriting the 550 from execution)
        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500);
        // pk_b: in delta_2 (600). NOT in prev_delta (delta_1). → unconditional write
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 600);
        // pk_c: in divergent_keys, NOT in delta_2 → restored to initial (300)
        //        (was 350 after execution, needs to be reset)
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);
        // Clock should be from delta_2
        assert_eq!(svm.get_sysvar::<Clock>().slot, 20);
    }

    // =========================================================================
    // Gap 2: divergent_keys = delta.keys() ∪ prev_exec_dirty
    //
    // Tests the exact union computation. Specifically: an account that's in
    // prev_exec_dirty but NOT in any delta still gets restored to initial.
    // =========================================================================

    #[test]
    fn test_divergent_keys_union_exec_dirty_outside_delta() {
        let mut svm = LiteSVM::new();
        let pk_a = Pubkey::new_unique();
        let pk_cpi = Pubkey::new_unique();

        svm.set_account(pk_a, make_account(100, &[1])).unwrap();
        // pk_cpi does NOT exist initially (CPI-created during iteration)
        let tracked: HashSet<Pubkey> = [pk_a].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
        let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

        // Delta has pk_a=500 only
        let mut delta_accounts = FastHashMap::default();
        delta_accounts.insert(pk_a, Arc::new(make_account(500, &[5])));
        let delta = SvmSnapshot { accounts: delta_accounts, clock: initial.clock().clone() };

        // === Iteration 1: restore_selective ===
        initial.restore_selective(&mut svm, &divergent_keys, &delta);
        divergent_keys.clear();
        divergent_keys.extend(delta.accounts().keys().copied());

        // Simulate execution: pk_a modified + CPI creates pk_cpi
        svm.set_account(pk_a, make_account(550, &[0xAA])).unwrap();
        svm.set_account(pk_cpi, make_account(999, &[9, 9])).unwrap();
        prev_exec_dirty.clear();
        prev_exec_dirty.insert(pk_a);
        prev_exec_dirty.insert(pk_cpi);
        divergent_keys.extend(prev_exec_dirty.iter().copied());

        // divergent_keys = {pk_a} (from delta) ∪ {pk_a, pk_cpi} (from exec dirty) = {pk_a, pk_cpi}
        assert!(divergent_keys.contains(&pk_a));
        assert!(divergent_keys.contains(&pk_cpi));

        // === Iteration 2: pick a state with empty delta (initial state) ===
        let empty_delta = SvmSnapshot::empty(initial.clock().clone());
        let prev_delta = delta.clone();

        initial.restore_selective_from(
            &mut svm, &divergent_keys, &prev_delta, &empty_delta, &prev_exec_dirty,
        );

        // pk_a: in divergent, NOT in empty_delta → restored to initial (100)
        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
        // pk_cpi: in divergent, NOT in empty_delta, NOT in initial → zeroed (deleted)
        assert!(svm.get_account(&pk_cpi).is_none());
    }

    #[test]
    fn test_divergent_keys_prev_exec_dirty_account_in_initial() {
        // Account in prev_exec_dirty that IS in initial snapshot and is NOT in
        // either delta. After restore, it should be back to initial value.
        let mut svm = LiteSVM::new();
        let pk_target = Pubkey::new_unique();
        let pk_delta = Pubkey::new_unique();

        svm.set_account(pk_target, make_account(100, &[1])).unwrap();
        svm.set_account(pk_delta, make_account(200, &[2])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_target, pk_delta].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // prev_delta only has pk_delta=500
        let mut prev_accounts = FastHashMap::default();
        prev_accounts.insert(pk_delta, Arc::new(make_account(500, &[5])));
        let prev_delta = SvmSnapshot { accounts: prev_accounts, clock: initial.clock().clone() };

        // next_delta also only has pk_delta=500 (same state picked again)
        let next_delta = prev_delta.clone();

        // divergent_keys = {pk_delta} (from prev delta) ∪ {pk_target} (from prev exec dirty)
        let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
        divergent_keys.insert(pk_delta);
        divergent_keys.insert(pk_target);

        // pk_target was exec-dirty (modified by previous action)
        let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
        prev_exec_dirty.insert(pk_target);

        // SVM must be consistent with prev_delta state (simulating previous restore wrote it).
        // pk_delta was set to 500 by the previous restore_selective call.
        svm.set_account(pk_delta, make_account(500, &[5])).unwrap();
        // pk_target was modified by execution AFTER prev restore (SVM has garbage 999)
        svm.set_account(pk_target, make_account(999, &[9])).unwrap();

        initial.restore_selective_from(
            &mut svm, &divergent_keys, &prev_delta, &next_delta, &prev_exec_dirty,
        );

        // pk_target: in divergent, NOT in next_delta → restored to initial (100)
        assert_eq!(svm.get_account(&pk_target).unwrap().lamports, 100);
        // pk_delta: in both deltas, same Arc, NOT in prev_exec_dirty → skipped.
        // SVM already has the correct value (500) from the previous restore.
        assert_eq!(svm.get_account(&pk_delta).unwrap().lamports, 500);
    }

    // =========================================================================
    // Gap 3: Same state picked consecutively
    //
    // When the pool returns the same state twice in a row, prev_delta == next_delta
    // (identical object). All Arcs are ptr_eq. Only prev_exec_dirty accounts
    // get written. This is the hot path.
    // =========================================================================

    #[test]
    fn test_same_state_picked_consecutively() {
        let mut svm = LiteSVM::new();
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let pk_c = Pubkey::new_unique();

        svm.set_account(pk_a, make_account(100, &[1])).unwrap();
        svm.set_account(pk_b, make_account(200, &[2])).unwrap();
        svm.set_account(pk_c, make_account(300, &[3])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // Build a state delta: pk_a=500, pk_b=600
        let mut delta_accounts = FastHashMap::default();
        delta_accounts.insert(pk_a, Arc::new(make_account(500, &[5])));
        delta_accounts.insert(pk_b, Arc::new(make_account(600, &[6])));
        let delta = SvmSnapshot { accounts: delta_accounts, clock: make_test_clock(50) };

        // === Iteration 1: restore_selective (no prev) ===
        let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
        initial.restore_selective(&mut svm, &divergent_keys, &delta);
        divergent_keys.clear();
        divergent_keys.extend(delta.accounts().keys().copied());

        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500);
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 600);
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);

        // Simulate execution: dirtied pk_a and pk_c
        svm.set_account(pk_a, make_account(555, &[0xAA])).unwrap();
        svm.set_account(pk_c, make_account(333, &[0xCC])).unwrap();
        let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
        prev_exec_dirty.insert(pk_a);
        prev_exec_dirty.insert(pk_c);
        divergent_keys.extend(prev_exec_dirty.iter().copied());

        // === Iteration 2: SAME state picked again ===
        // prev_delta and next_delta are the same object → all Arcs are ptr_eq
        let count = initial.restore_selective_from(
            &mut svm, &divergent_keys, &delta, &delta, &prev_exec_dirty,
        );

        // pk_a: same Arc, BUT in prev_exec_dirty → forced write (1 call)
        // pk_b: same Arc, NOT in prev_exec_dirty → skipped (0 calls)
        // pk_c: in divergent, NOT in delta → restored to initial (1 call)
        assert_eq!(count, 2); // pk_a + pk_c

        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500); // delta value restored
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 600); // untouched, still correct
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300); // back to initial
    }

    // =========================================================================
    // Gap 4: Tombstone in delta overlaid via restore_selective
    //
    // When a delta contains a tombstone (lamports=0) and the SVM has a live
    // account at that key (from CPI in a prior iteration), restore_selective
    // step 2 should zero it.
    // =========================================================================

    #[test]
    fn test_restore_selective_tombstone_overlay() {
        let mut svm = LiteSVM::new();
        let pk_live = Pubkey::new_unique();
        let pk_tombstoned = Pubkey::new_unique();

        svm.set_account(pk_live, make_account(100, &[1])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_live].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // Delta has a tombstone for pk_tombstoned (account was deleted in this state)
        let mut delta_accounts = FastHashMap::default();
        delta_accounts.insert(pk_tombstoned, Arc::new(Account { lamports: 0, ..Default::default() }));
        let delta = SvmSnapshot { accounts: delta_accounts, clock: initial.clock().clone() };

        // SVM has a live account at pk_tombstoned (CPI-created in prior iteration)
        svm.set_account(pk_tombstoned, make_account(999, &[9, 9])).unwrap();
        assert!(svm.get_account(&pk_tombstoned).is_some());

        let divergent: FastHashSet<Pubkey> = FastHashSet::default();
        initial.restore_selective(&mut svm, &divergent, &delta);

        // Tombstone written by step 2 → LiteSVM treats zero-lamport as deleted
        assert!(svm.get_account(&pk_tombstoned).is_none());
    }

    #[test]
    fn test_restore_selective_from_tombstone_overlay() {
        // Same as above but via restore_selective_from path.
        // Tombstone is in next_delta, SVM has live account.
        let mut svm = LiteSVM::new();
        let pk = Pubkey::new_unique();

        svm.set_account(pk, make_account(100, &[1])).unwrap();
        let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // prev_delta: pk=500 (live)
        let mut prev_accounts = FastHashMap::default();
        prev_accounts.insert(pk, Arc::new(make_account(500, &[5])));
        let prev_delta = SvmSnapshot { accounts: prev_accounts, clock: initial.clock().clone() };

        // next_delta: pk=tombstone (deleted in this state)
        let mut next_accounts = FastHashMap::default();
        next_accounts.insert(pk, Arc::new(Account { lamports: 0, ..Default::default() }));
        let next_delta = SvmSnapshot { accounts: next_accounts, clock: initial.clock().clone() };

        // SVM has pk=500 (from prev_delta restore)
        svm.set_account(pk, make_account(500, &[5])).unwrap();

        let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
        divergent.insert(pk);
        let prev_exec_dirty = FastHashSet::default();

        initial.restore_selective_from(
            &mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty,
        );

        // pk: in next_delta (tombstone), different Arc from prev_delta → written
        assert!(svm.get_account(&pk).is_none());
    }

    // =========================================================================
    // Gap 5: Failed action leaves prev_exec_dirty empty
    //
    // If the action fails, prev_exec_dirty stays cleared. On next iteration,
    // restore_selective_from skips more Arcs. But the DirtyTracker still
    // recorded writable accounts from the instructions. The real code only
    // populates prev_exec_dirty on success.
    // =========================================================================

    #[test]
    fn test_failed_action_empty_prev_exec_dirty() {
        let mut svm = LiteSVM::new();
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();

        svm.set_account(pk_a, make_account(100, &[1])).unwrap();
        svm.set_account(pk_b, make_account(200, &[2])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_a, pk_b].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // State delta: pk_a=500
        let mut delta_accounts = FastHashMap::default();
        delta_accounts.insert(pk_a, Arc::new(make_account(500, &[5])));
        let delta = SvmSnapshot { accounts: delta_accounts, clock: make_test_clock(10) };

        // === Iteration 1: restore + execute (action SUCCEEDS) ===
        let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
        initial.restore_selective(&mut svm, &divergent_keys, &delta);
        divergent_keys.clear();
        divergent_keys.extend(delta.accounts().keys().copied());

        // Action modifies pk_a and pk_b
        svm.set_account(pk_a, make_account(550, &[0xAA])).unwrap();
        svm.set_account(pk_b, make_account(250, &[0xBB])).unwrap();

        let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
        // Action succeeded → populate prev_exec_dirty
        prev_exec_dirty.insert(pk_a);
        prev_exec_dirty.insert(pk_b);
        divergent_keys.extend(prev_exec_dirty.iter().copied());
        let prev_delta = delta.clone();

        // === Iteration 2: same state picked, action FAILS ===
        initial.restore_selective_from(
            &mut svm, &divergent_keys, &prev_delta, &delta, &prev_exec_dirty,
        );
        divergent_keys.clear();
        divergent_keys.extend(delta.accounts().keys().copied());

        // Verify state is correct after restore
        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500);
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200); // back to initial

        // Simulate FAILED action: SVM was modified but action_succeeded = false
        svm.set_account(pk_a, make_account(777, &[0xFF])).unwrap();
        svm.set_account(pk_b, make_account(888, &[0xEE])).unwrap();

        // Failed action: prev_exec_dirty stays EMPTY (real loop clears it)
        prev_exec_dirty.clear();
        // divergent_keys NOT extended (action failed)
        let prev_delta_2 = delta.clone();

        // === Iteration 3: same state picked again ===
        // prev_exec_dirty is EMPTY. pk_a has same Arc in both deltas → SKIPPED.
        // But SVM has pk_a=777 (garbage from failed execution)!
        let count = initial.restore_selective_from(
            &mut svm, &divergent_keys, &prev_delta_2, &delta, &prev_exec_dirty,
        );

        // pk_a: same Arc, NOT in prev_exec_dirty → SKIPPED. SVM still has 777 (STALE!)
        // pk_b: NOT in divergent_keys (only delta keys = {pk_a}). NOT in delta. Never touched.
        //        SVM has 888 (STALE from failed execution!)
        //
        // This documents a KNOWN LIMITATION: failed actions can leave SVM in a dirty
        // state that is not detected by the Arc skip optimization. The real fuzzer
        // accepts this trade-off because:
        //   1. Failed actions typically don't modify SVM state (tx reverts)
        //   2. The DirtyTracker records intended writes, not actual writes
        //   3. The performance gain of skipping is worth occasional stale reads
        assert_eq!(count, 0); // everything skipped
        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 777); // stale!
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 888); // stale!
    }

    // =========================================================================
    // Gap 6: Deeper chains (5 levels) with mixed modifications
    //
    // Real chains go 5-20 levels deep. Tests accumulation bugs:
    // - Divergent keys growing correctly
    // - Arc pointers shared across multiple levels
    // - Accounts modified at some levels but not others
    // - State restored correctly after jumping between deep chain nodes
    // =========================================================================

    #[test]
    fn test_deep_chain_five_levels() {
        let mut svm = LiteSVM::new();
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let pk_c = Pubkey::new_unique();
        let pk_d = Pubkey::new_unique();
        let pk_e = Pubkey::new_unique();
        let pks = [pk_a, pk_b, pk_c, pk_d, pk_e];

        // Initial state: each account has lamports = 10 * (index+1)
        for (i, pk) in pks.iter().enumerate() {
            svm.set_account(*pk, make_account((i as u64 + 1) * 10, &[i as u8])).unwrap();
        }
        let tracked: HashSet<Pubkey> = pks.iter().copied().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

        // Level 1: modify A → 100
        svm.set_account(pk_a, make_account(100, &[0x01])).unwrap();
        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk_a);
        let delta_1 = SvmSnapshot::take_delta(&svm, &delta_root, &dirty);
        assert_eq!(delta_1.account_count(), 1);

        // Level 2: modify B → 200 (parent=delta_1)
        svm.set_account(pk_b, make_account(200, &[0x02])).unwrap();
        dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk_b);
        let delta_2 = SvmSnapshot::take_delta(&svm, &delta_1, &dirty);
        assert_eq!(delta_2.account_count(), 2);
        // A inherited from delta_1 via Arc
        assert!(Arc::ptr_eq(&delta_2.accounts()[&pk_a], &delta_1.accounts()[&pk_a]));

        // Level 3: modify C → 300 (parent=delta_2)
        svm.set_account(pk_c, make_account(300, &[0x03])).unwrap();
        dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk_c);
        let delta_3 = SvmSnapshot::take_delta(&svm, &delta_2, &dirty);
        assert_eq!(delta_3.account_count(), 3);
        // A and B inherited via Arc from delta_2
        assert!(Arc::ptr_eq(&delta_3.accounts()[&pk_a], &delta_1.accounts()[&pk_a]));
        assert!(Arc::ptr_eq(&delta_3.accounts()[&pk_b], &delta_2.accounts()[&pk_b]));

        // Level 4: modify A AGAIN → 400 (parent=delta_3)
        svm.set_account(pk_a, make_account(400, &[0x04])).unwrap();
        dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk_a);
        let delta_4 = SvmSnapshot::take_delta(&svm, &delta_3, &dirty);
        assert_eq!(delta_4.account_count(), 3);
        // A is a NEW Arc (overwritten), B and C inherited
        assert!(!Arc::ptr_eq(&delta_4.accounts()[&pk_a], &delta_3.accounts()[&pk_a]));
        assert!(Arc::ptr_eq(&delta_4.accounts()[&pk_b], &delta_2.accounts()[&pk_b]));
        assert!(Arc::ptr_eq(&delta_4.accounts()[&pk_c], &delta_3.accounts()[&pk_c]));

        // Level 5: modify D and E → 500, 600 (parent=delta_4)
        svm.set_account(pk_d, make_account(500, &[0x05])).unwrap();
        svm.set_account(pk_e, make_account(600, &[0x06])).unwrap();
        dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk_d);
        dirty.mark_account_dirty(&pk_e);
        let delta_5 = SvmSnapshot::take_delta(&svm, &delta_4, &dirty);
        assert_eq!(delta_5.account_count(), 5); // all accounts now in delta

        // --- Now test restore_full at each level ---

        // Scramble SVM
        for pk in &pks {
            svm.set_account(*pk, make_account(1, &[0])).unwrap();
        }

        // restore_full from delta_2: A=100, B=200
        delta_2.restore_full(&mut svm);
        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);

        // restore_full from delta_5: A=400, B=200, C=300, D=500, E=600
        delta_5.restore_full(&mut svm);
        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 400); // overwritten at level 4
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);
        assert_eq!(svm.get_account(&pk_d).unwrap().lamports, 500);
        assert_eq!(svm.get_account(&pk_e).unwrap().lamports, 600);

        // --- Test restore_selective jumping from deep to shallow ---
        // SVM is at delta_5 state. Jump to delta_2 (A=100, B=200 only).
        let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
        for pk in delta_5.accounts().keys() {
            divergent.insert(*pk);
        }

        initial.restore_selective(&mut svm, &divergent, &delta_2);

        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
        // C, D, E: in divergent but NOT in delta_2 → restored to initial
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 30); // initial
        assert_eq!(svm.get_account(&pk_d).unwrap().lamports, 40); // initial
        assert_eq!(svm.get_account(&pk_e).unwrap().lamports, 50); // initial
    }

    #[test]
    fn test_deep_chain_selective_from_between_levels() {
        // Jump between delta_3 and delta_5 using restore_selective_from.
        // Tests Arc sharing across 3+ levels.
        let mut svm = LiteSVM::new();
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let pk_c = Pubkey::new_unique();
        let pk_d = Pubkey::new_unique();

        svm.set_account(pk_a, make_account(10, &[1])).unwrap();
        svm.set_account(pk_b, make_account(20, &[2])).unwrap();
        svm.set_account(pk_c, make_account(30, &[3])).unwrap();
        svm.set_account(pk_d, make_account(40, &[4])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c, pk_d].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

        // Build chain: root → 1(A=100) → 2(B=200) → 3(C=300) → 4(A=400) → 5(D=500)
        svm.set_account(pk_a, make_account(100, &[0x11])).unwrap();
        let mut d = DirtyTracker::new();
        d.mark_account_dirty(&pk_a);
        let delta_1 = SvmSnapshot::take_delta(&svm, &delta_root, &d);

        svm.set_account(pk_b, make_account(200, &[0x22])).unwrap();
        d = DirtyTracker::new();
        d.mark_account_dirty(&pk_b);
        let delta_2 = SvmSnapshot::take_delta(&svm, &delta_1, &d);

        svm.set_account(pk_c, make_account(300, &[0x33])).unwrap();
        d = DirtyTracker::new();
        d.mark_account_dirty(&pk_c);
        let delta_3 = SvmSnapshot::take_delta(&svm, &delta_2, &d);

        svm.set_account(pk_a, make_account(400, &[0x44])).unwrap();
        d = DirtyTracker::new();
        d.mark_account_dirty(&pk_a);
        let delta_4 = SvmSnapshot::take_delta(&svm, &delta_3, &d);

        svm.set_account(pk_d, make_account(500, &[0x55])).unwrap();
        d = DirtyTracker::new();
        d.mark_account_dirty(&pk_d);
        let delta_5 = SvmSnapshot::take_delta(&svm, &delta_4, &d);

        // Reset SVM to initial state before starting the simulated loop.
        // Chain building left the SVM at the level-5 state. In the real fuzzer,
        // the SVM starts at initial before the first iteration.
        initial.restore_full(&mut svm);

        // === Simulated loop: iteration 1 picks delta_3 ===
        let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
        initial.restore_selective(&mut svm, &divergent_keys, &delta_3);
        divergent_keys.clear();
        divergent_keys.extend(delta_3.accounts().keys().copied());

        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);
        assert_eq!(svm.get_account(&pk_d).unwrap().lamports, 40); // initial

        // Simulate execution: dirtied pk_a
        svm.set_account(pk_a, make_account(150, &[0xAA])).unwrap();
        let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
        prev_exec_dirty.insert(pk_a);
        divergent_keys.extend(prev_exec_dirty.iter().copied());

        // === Iteration 2: jump to delta_5 ===
        let count = initial.restore_selective_from(
            &mut svm, &divergent_keys, &delta_3, &delta_5, &prev_exec_dirty,
        );

        // Analyze what happens:
        // delta_3 has: {A=100, B=200, C=300}
        // delta_5 has: {A=400, B=200, C=300, D=500}
        //
        // Step 1 (divergent not in delta_5): nothing (all divergent keys are in delta_5)
        // Step 2 (delta_5 accounts):
        //   A: prev_exec_dirty contains A → forced write (400). Count +1.
        //   B: Arc::ptr_eq(delta_3[B], delta_5[B])? Both inherited from delta_2 → YES. Skip.
        //   C: Arc::ptr_eq(delta_3[C], delta_5[C])? delta_3 created C, delta_5 inherited → YES. Skip.
        //   D: NOT in delta_3 → unconditional write (500). Count +1.
        assert_eq!(count, 2);

        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 400); // forced write
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200); // skipped (correct)
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300); // skipped (correct)
        assert_eq!(svm.get_account(&pk_d).unwrap().lamports, 500); // new in delta_5
    }

    // =========================================================================
    // Full mini-fuzzing-loop integration test
    //
    // Runs 4 iterations mimicking the exact real loop:
    //   Iter 1: restore_selective (no prev), execute, succeed
    //   Iter 2: restore_selective_from (same state), execute, succeed
    //   Iter 3: restore_selective_from (different state), execute, FAIL
    //   Iter 4: restore_selective_from (jump to shallow state), execute, succeed
    // Verifies all 6 gaps in a single realistic scenario.
    // =========================================================================

    #[test]
    fn test_full_mini_fuzzing_loop() {
        let mut svm = LiteSVM::new();
        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();
        let pk_c = Pubkey::new_unique();

        svm.set_account(pk_a, make_account(10, &[1])).unwrap();
        svm.set_account(pk_b, make_account(20, &[2])).unwrap();
        svm.set_account(pk_c, make_account(30, &[3])).unwrap();
        let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
        let initial = SvmSnapshot::take(&svm, &tracked);

        // Pool states (pre-built):
        // State 0 (initial): empty delta
        let state_0 = SvmSnapshot::empty(initial.clock().clone());
        // State 1: A=100 (from action on state 0)
        let mut s1_accounts = FastHashMap::default();
        s1_accounts.insert(pk_a, Arc::new(make_account(100, &[0x11])));
        let state_1 = SvmSnapshot { accounts: s1_accounts, clock: make_test_clock(10) };
        // State 2: A=100 (inherited from state 1), B=200
        let mut s2_accounts = FastHashMap::default();
        s2_accounts.insert(pk_a, state_1.accounts()[&pk_a].clone()); // same Arc
        s2_accounts.insert(pk_b, Arc::new(make_account(200, &[0x22])));
        let state_2 = SvmSnapshot { accounts: s2_accounts, clock: make_test_clock(20) };

        // Loop state
        let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
        let mut prev_delta_arc: Option<SvmSnapshot> = None;
        let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

        // ====== ITERATION 1: pick state_1, restore_selective ======
        {
            let delta = &state_1;
            assert!(prev_delta_arc.is_none());
            initial.restore_selective(&mut svm, &divergent_keys, delta);
            divergent_keys.clear();
            divergent_keys.extend(delta.accounts().keys().copied());

            assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
            assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 20);
            assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 30);

            // Execute: modify A, success
            svm.set_account(pk_a, make_account(150, &[0xAA])).unwrap();
            let action_succeeded = true;
            prev_exec_dirty.clear();
            if action_succeeded {
                prev_exec_dirty.insert(pk_a);
                divergent_keys.extend(prev_exec_dirty.iter().copied());
            }
            prev_delta_arc = Some(delta.clone());
        }

        // ====== ITERATION 2: pick state_1 AGAIN (same state), restore_selective_from ======
        {
            let delta = &state_1;
            let prev = prev_delta_arc.as_ref().unwrap();
            let count = initial.restore_selective_from(
                &mut svm, &divergent_keys, prev, delta, &prev_exec_dirty,
            );
            divergent_keys.clear();
            divergent_keys.extend(delta.accounts().keys().copied());

            // A: same Arc, BUT in prev_exec_dirty → forced write
            assert_eq!(count, 1); // only A written
            assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
            assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 20);
            assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 30);

            // Execute: modify B and C, success
            svm.set_account(pk_b, make_account(25, &[0xBB])).unwrap();
            svm.set_account(pk_c, make_account(35, &[0xCC])).unwrap();
            let action_succeeded = true;
            prev_exec_dirty.clear();
            if action_succeeded {
                prev_exec_dirty.insert(pk_b);
                prev_exec_dirty.insert(pk_c);
                divergent_keys.extend(prev_exec_dirty.iter().copied());
            }
            prev_delta_arc = Some(delta.clone());
        }

        // ====== ITERATION 3: pick state_2 (different state), action FAILS ======
        {
            let delta = &state_2;
            let prev = prev_delta_arc.as_ref().unwrap();
            initial.restore_selective_from(
                &mut svm, &divergent_keys, prev, delta, &prev_exec_dirty,
            );
            divergent_keys.clear();
            divergent_keys.extend(delta.accounts().keys().copied());

            // A: same Arc between state_1 and state_2 → skip? No! B and C are in prev_exec_dirty,
            //    but A is NOT → skip is correct. A should still be 100.
            assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
            // B: in delta_2 (200), different from state_1 (no B) → unconditional write
            assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
            // C: in divergent (from prev exec dirty), NOT in delta_2 → restored to initial
            assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 30);

            // Execute: modify A, but action FAILS
            svm.set_account(pk_a, make_account(999, &[0xFF])).unwrap();
            let action_succeeded = false;
            prev_exec_dirty.clear();
            if action_succeeded {
                // NOT executed — prev_exec_dirty stays empty
                unreachable!();
            }
            // divergent_keys NOT extended (action failed)
            prev_delta_arc = Some(delta.clone());
        }

        // ====== ITERATION 4: jump to state_0 (shallow), restore_selective_from ======
        {
            let delta = &state_0;
            let prev = prev_delta_arc.as_ref().unwrap();
            initial.restore_selective_from(
                &mut svm, &divergent_keys, prev, delta, &prev_exec_dirty,
            );
            divergent_keys.clear();
            divergent_keys.extend(delta.accounts().keys().copied());

            // state_0 is empty delta → all divergent keys restored to initial
            // divergent_keys was {A, B} from state_2. state_0 is empty.
            // Step 1: A and B both not in empty delta → restored to initial
            // Step 2: empty delta → nothing
            // BUT: A was modified to 999 in failed iteration 3, and prev_exec_dirty is EMPTY.
            // Since state_2[A] and state_0 don't share Arcs (state_0 is empty),
            // A is in divergent → restored to initial via step 1. Good.
            assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 10); // initial
            assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 20); // initial
            assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 30); // initial (untouched)
        }
    }
}
