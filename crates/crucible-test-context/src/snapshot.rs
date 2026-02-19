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
}
