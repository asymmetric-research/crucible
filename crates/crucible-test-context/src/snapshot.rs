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
#[derive(Clone)]
pub struct SvmSnapshot {
    /// Account data at snapshot time. FxHash for fast lookups during restore.
    accounts: FastHashMap<Pubkey, Account>,
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
                accounts.insert(*pubkey, account);
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
                    let _ = svm.set_account(*pubkey, original.clone());
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
                accounts.insert(*pubkey, account);
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
                accounts.insert(*pubkey, account);
            }
        }
        let clock = svm.get_sysvar::<Clock>();
        Self { accounts, clock }
    }

    /// Restore ALL accounts in snapshot to the SVM (full state restore).
    /// Used by stateful mode to jump to a saved state. Returns account count.
    pub fn restore_full(&self, svm: &mut LiteSVM) -> usize {
        for (pubkey, account) in &self.accounts {
            let _ = svm.set_account(*pubkey, account.clone());
        }
        svm.set_sysvar(&self.clock);
        self.accounts.len()
    }

    /// Get a reference to the internal accounts map.
    pub fn accounts(&self) -> &FastHashMap<Pubkey, Account> {
        &self.accounts
    }
}

// ============================================================================
// State Fingerprinting — bucketed hashing for state novelty detection
// ============================================================================

/// AFL-style log2 bucketing for integer values.
/// Maps value ranges to bucket indices: 0→0, 1→1, 2-3→2, 4-7→3, 8-15→4, etc.
#[inline]
fn log2_bucket(val: u64) -> u8 {
    if val == 0 {
        0
    } else {
        (64 - val.leading_zeros()) as u8
    }
}

/// Compute a state fingerprint from dirty account diffs.
///
/// Uses byte-range diffing: each contiguous changed byte range is treated as a field.
/// Ranges of 1, 2, 4, or 8 bytes are interpreted as LE integers and log2-bucketed.
/// Other sizes are hashed directly.
///
/// The fingerprint combines all (pubkey, offset, bucketed_value) tuples via FxHasher,
/// sorted by pubkey+offset for determinism.
pub fn compute_state_fingerprint(
    svm: &LiteSVM,
    dirty: &DirtyTracker,
    pre_states: &FastHashMap<Pubkey, Option<Account>>,
) -> u64 {
    // Collect (pubkey, offset, hash_value) tuples
    let mut tuples: Vec<(Pubkey, usize, u64)> = Vec::new();

    for pubkey in dirty.dirty_accounts() {
        let pre_account = pre_states.get(pubkey).and_then(|opt| opt.clone());
        let post_account = svm.get_account(pubkey);

        // Bucket lamports change
        let pre_lamports = pre_account.as_ref().map(|a| a.lamports).unwrap_or(0);
        let post_lamports = post_account.as_ref().map(|a| a.lamports).unwrap_or(0);
        if pre_lamports != post_lamports {
            tuples.push((*pubkey, usize::MAX, log2_bucket(post_lamports) as u64));
        }

        // Find changed byte ranges (reuse AccountDiff logic)
        let diff = AccountDiff {
            pubkey: *pubkey,
            pre: pre_account,
            post: post_account.clone(),
        };
        let post_data = post_account
            .as_ref()
            .map(|a| a.data.as_slice())
            .unwrap_or(&[]);

        for (offset, len) in diff.changed_data_ranges() {
            let range_end = offset + len;
            let hash_val = match len {
                1 if range_end <= post_data.len() => {
                    log2_bucket(post_data[offset] as u64) as u64
                }
                2 if range_end <= post_data.len() => {
                    let val = u16::from_le_bytes(
                        post_data[offset..range_end].try_into().unwrap(),
                    );
                    log2_bucket(val as u64) as u64
                }
                4 if range_end <= post_data.len() => {
                    let val = u32::from_le_bytes(
                        post_data[offset..range_end].try_into().unwrap(),
                    );
                    log2_bucket(val as u64) as u64
                }
                8 if range_end <= post_data.len() => {
                    let val = u64::from_le_bytes(
                        post_data[offset..range_end].try_into().unwrap(),
                    );
                    log2_bucket(val) as u64
                }
                _ => {
                    // Non-integer size — hash raw bytes directly
                    let end = range_end.min(post_data.len());
                    if offset < end {
                        let mut h = FxHasher::default();
                        post_data[offset..end].hash(&mut h);
                        h.finish()
                    } else {
                        0
                    }
                }
            };
            tuples.push((*pubkey, offset, hash_val));
        }
    }

    // Sort for determinism
    tuples.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    // Combine into final fingerprint
    let mut hasher = FxHasher::default();
    for (pubkey, offset, val) in &tuples {
        pubkey.hash(&mut hasher);
        offset.hash(&mut hasher);
        val.hash(&mut hasher);
    }
    hasher.finish()
}

/// Snapshot writable accounts from dirty tracker (for fingerprinting pre-state).
/// Similar to snapshot_writable_accounts but uses the DirtyTracker's writable set
/// from before the action was executed. Called before executing an action in stateful mode.
pub fn snapshot_dirty_accounts(
    svm: &LiteSVM,
    accounts: &FastHashSet<Pubkey>,
) -> FastHashMap<Pubkey, Option<Account>> {
    let mut pre = FastHashMap::default();
    pre.reserve(accounts.len());
    for pubkey in accounts {
        pre.insert(*pubkey, svm.get_account(pubkey));
    }
    pre
}

// ============================================================================
// StatePool — bounded pool of saved SVM states for stateful fuzzing
// ============================================================================

/// A single saved state in the state pool.
pub struct StateEntry {
    /// Fingerprint of the state (used for dedup).
    pub fingerprint: u64,
    /// Full snapshot of all accounts at this state.
    pub snapshot: SvmSnapshot,
    /// Depth: number of actions from initial state.
    pub depth: u32,
    /// Index of the parent state in the pool (None for initial state).
    pub parent_idx: Option<usize>,
    /// Serialized single action that produced this state (variant u16 + field bytes).
    pub action_bytes: Vec<u8>,
}

/// Bounded pool of saved SVM states for ItyFuzz-style stateful fuzzing.
///
/// States are deduplicated by fingerprint. The pool has a configurable capacity
/// and memory limit.
pub struct StatePool {
    states: Vec<StateEntry>,
    seen: FastHashSet<u64>,
    capacity: usize,
}

impl StatePool {
    /// Create a new state pool with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            states: Vec::with_capacity(capacity.min(1024)), // pre-alloc up to 1K
            seen: FastHashSet::default(),
            capacity,
        }
    }

    /// Try to add a new state. Returns true if the state was novel and added.
    pub fn try_add(
        &mut self,
        fingerprint: u64,
        snapshot: SvmSnapshot,
        depth: u32,
        parent_idx: Option<usize>,
        action_bytes: Vec<u8>,
    ) -> bool {
        if self.states.len() >= self.capacity {
            return false;
        }
        if !self.seen.insert(fingerprint) {
            return false; // already seen this fingerprint
        }
        self.states.push(StateEntry {
            fingerprint,
            snapshot,
            depth,
            parent_idx,
            action_bytes,
        });
        true
    }

    /// Pick a random state index using the given random value.
    /// Returns None if the pool is empty.
    pub fn pick_random(&self, rand_val: u64) -> Option<usize> {
        if self.states.is_empty() {
            None
        } else {
            Some(rand_val as usize % self.states.len())
        }
    }

    /// Get a reference to a state entry.
    pub fn get(&self, idx: usize) -> Option<&StateEntry> {
        self.states.get(idx)
    }

    /// Number of states in the pool.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Whether the pool is at capacity.
    pub fn is_full(&self) -> bool {
        self.states.len() >= self.capacity
    }

    /// Reconstruct a full action sequence from a state index back to the root.
    /// Returns the concatenated action bytes in FuzzInput format:
    /// 4-byte count header + concatenated action bytes.
    pub fn reconstruct_action_sequence(&self, state_idx: usize) -> Vec<u8> {
        // Walk parent chain to collect action bytes
        let mut chain: Vec<&[u8]> = Vec::new();
        let mut idx = state_idx;
        loop {
            let entry = &self.states[idx];
            if !entry.action_bytes.is_empty() {
                chain.push(&entry.action_bytes);
            }
            match entry.parent_idx {
                Some(parent) => idx = parent,
                None => break,
            }
        }
        // Reverse so root actions come first
        chain.reverse();

        // Build FuzzInput bytes: 4-byte count + concatenated action bytes
        let count = chain.len() as u32;
        let total_size = 4 + chain.iter().map(|b| b.len()).sum::<usize>();
        let mut buf = Vec::with_capacity(total_size);
        buf.extend_from_slice(&count.to_le_bytes());
        for action_bytes in chain {
            buf.extend_from_slice(action_bytes);
        }
        buf
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
}
