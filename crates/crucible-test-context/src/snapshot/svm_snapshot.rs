use crate::{FastHashMap, FastHashSet};
use anchor_lang::prelude::sysvar::SysvarId;
use anchor_lang::prelude::{Clock, EpochSchedule, StakeHistory};
use litesvm::LiteSVM;
use rustc_hash::FxHasher;
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_sysvar::epoch_rewards::EpochRewards;
use solana_sysvar::last_restart_slot::LastRestartSlot;
use solana_sysvar::rent::Rent;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use super::dirty_tracker::{CreationTracker, DirtyTracker};

const SYSVAR_OWNER: Pubkey = Pubkey::from_str_const("Sysvar1111111111111111111111111111111111111");

/// Managed sysvars are small enough to copy into every state delta and can
/// change as a test advances. SlotHashes and SlotHistory are intentionally not
/// included: together they add roughly 150 KiB to every state-pool entry.
fn managed_sysvar_ids() -> [Pubkey; 8] {
    [
        Clock::id(),
        EpochRewards::id(),
        EpochSchedule::id(),
        solana_sysvar::fees::id(),
        LastRestartSlot::id(),
        solana_sysvar::recent_blockhashes::id(),
        Rent::id(),
        StakeHistory::id(),
    ]
}

fn clock_account(clock: &Clock) -> Account {
    Account {
        lamports: 1,
        data: wincode::serialize(clock).expect("snapshot: failed to wincode-serialize Clock"),
        owner: SYSVAR_OWNER,
        executable: false,
        rent_epoch: 0,
    }
}

fn clock_from_sysvars(sysvars: &[(Pubkey, Option<Account>)], snapshot_kind: &str) -> Clock {
    let account = sysvars
        .iter()
        .find_map(|(id, account)| (id == &Clock::id()).then_some(account))
        .unwrap_or_else(|| panic!("{snapshot_kind}: Clock sysvar is missing"))
        .as_ref()
        .unwrap_or_else(|| panic!("{snapshot_kind}: Clock sysvar account is absent"));

    wincode::deserialize(&account.data)
        .unwrap_or_else(|error| panic!("{snapshot_kind}: invalid wincode Clock data: {error:?}"))
}

fn restore_account_checked(svm: &mut LiteSVM, pubkey: Pubkey, account: Account, operation: &str) {
    svm.set_account(pubkey, account).unwrap_or_else(|error| {
        panic!("snapshot: {operation} failed for account {pubkey}: {error:?}")
    });
}

/// LiteSVM 0.15 registers executable accounts in its program cache as they are
/// written. ProgramData must therefore be present before its executable Program
/// account. Sorting non-executables first also makes restore order independent
/// of FxHashMap iteration order.
fn restore_accounts_in_runtime_order(
    svm: &mut LiteSVM,
    mut accounts: Vec<(Pubkey, Account)>,
    operation: &str,
) -> usize {
    accounts.sort_unstable_by(|(left_key, left), (right_key, right)| {
        left.executable
            .cmp(&right.executable)
            .then_with(|| left_key.cmp(right_key))
    });
    let count = accounts.len();
    for (pubkey, account) in accounts {
        restore_account_checked(svm, pubkey, account, operation);
    }
    count
}

fn restore_sysvars_checked(
    svm: &mut LiteSVM,
    sysvars: &[(Pubkey, Option<Account>)],
    operation: &str,
) -> usize {
    let mut ordered = sysvars.to_vec();
    ordered.sort_unstable_by_key(|(pubkey, _)| *pubkey);
    for (pubkey, account) in ordered {
        let account = account.unwrap_or_else(|| {
            panic!("snapshot: {operation} cannot restore absent sysvar account {pubkey}")
        });
        restore_account_checked(svm, pubkey, account, operation);
    }
    sysvars.len()
}

fn is_snapshot_sysvar(pubkey: &Pubkey, sysvars: &[(Pubkey, Option<Account>)]) -> bool {
    sysvars.iter().any(|(sysvar, _)| sysvar == pubkey)
}

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
    pub(crate) accounts: FastHashMap<Pubkey, Arc<Account>>,
    /// Full sysvar accounts at snapshot time (preserves lamports, owner, etc.).
    pub sysvars: Vec<(Pubkey, Option<Account>)>,
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
        let sysvars = Self::take_sysvars(svm);
        Self { accounts, sysvars }
    }

    /// Restore only dirty accounts from snapshot. Returns count of accounts restored.
    ///
    /// Handles three cases:
    /// - **Modified**: existed at snapshot, data changed → restore original
    /// - **Deleted**: existed at snapshot, now gone → restore original
    /// - **Created**: not in snapshot, created during iteration → remove (set lamports=0)
    pub fn restore(&self, svm: &mut LiteSVM, dirty: &DirtyTracker) -> usize {
        self.restore_sysvars(svm);
        let mut accounts = Vec::with_capacity(dirty.dirty_accounts().len());
        for pubkey in dirty.dirty_accounts() {
            if is_snapshot_sysvar(pubkey, &self.sysvars) {
                continue;
            }
            match self.accounts.get(pubkey) {
                Some(original) => {
                    // Existed at snapshot — restore original (covers modified + deleted)
                    accounts.push((*pubkey, (**original).clone()));
                }
                None => {
                    // Created during iteration — remove by zeroing.
                    // Skip executable (program) accounts: zeroing them removes from
                    // accounts_db but NOT from programs_cache, causing a desync that
                    // panics in litesvm (lib.rs:981 unwrap on None).
                    if let Some(existing) = svm.get_account(pubkey) {
                        if existing.executable {
                            continue;
                        }
                    }
                    accounts.push((
                        *pubkey,
                        Account {
                            lamports: 0,
                            ..Default::default()
                        },
                    ));
                }
            }
        }
        restore_accounts_in_runtime_order(svm, accounts, "restore dirty account")
    }

    /// Get the number of snapshotted accounts.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Whether an account existed in this snapshot (pre-existing vs created later).
    #[inline]
    pub fn contains_account(&self, pubkey: &Pubkey) -> bool {
        self.accounts.contains_key(pubkey)
    }

    /// Estimate heap bytes owned by this snapshot (HashMap overhead + Account data).
    /// Does NOT follow Arc pointers — shared Account data is counted per-reference.
    /// Use `estimated_heap_bytes_unique` for deduplicated accounting.
    pub fn estimated_heap_bytes(&self) -> usize {
        // HashMap overhead: ~80 bytes per entry (key + value + hash + metadata)
        let map_overhead = self.accounts.len() * 80;
        // Account data behind Arc pointers (counted per-reference, not deduplicated)
        let account_data: usize = self
            .accounts
            .values()
            .map(|a| std::mem::size_of::<Account>() + a.data.len())
            .sum();
        // Sysvar data
        let sysvar_data: usize = self
            .sysvars
            .iter()
            .map(|(_, opt)| match opt {
                Some(a) => std::mem::size_of::<Account>() + a.data.len(),
                None => 0,
            })
            .sum();
        map_overhead + account_data + sysvar_data
    }

    /// Take a full snapshot by cloning a base snapshot's accounts then overwriting
    /// dirty ones from the current SVM. Captures the complete state after an action.
    pub fn take_full(svm: &LiteSVM, base_snapshot: &SvmSnapshot, dirty: &DirtyTracker) -> Self {
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
        let sysvars = Self::take_sysvars(svm);
        Self { accounts, sysvars }
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
        let sysvars = Self::take_sysvars(svm);
        Self { accounts, sysvars }
    }

    /// Restore ALL accounts in snapshot to the SVM (full state restore).
    /// Used by stateful mode to jump to a saved state. Returns account count.
    pub fn restore_full(&self, svm: &mut LiteSVM) -> usize {
        self.restore_sysvars(svm);
        let accounts = self
            .accounts
            .iter()
            .filter(|(pubkey, _)| !is_snapshot_sysvar(pubkey, &self.sysvars))
            .map(|(pubkey, account)| (*pubkey, (**account).clone()))
            .collect();
        restore_accounts_in_runtime_order(svm, accounts, "restore full account");
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
        // Sysvars are authoritative and must be present before account/program restores.
        delta.restore_sysvars(svm);
        let mut accounts =
            self.collect_divergent_restores(svm, divergent_keys, &delta.accounts, &delta.sysvars);

        // Overlay delta (accounts that differ from initial in the target state).
        for (pubkey, account) in &delta.accounts {
            if !is_snapshot_sysvar(pubkey, &delta.sysvars) {
                accounts.push((*pubkey, (**account).clone()));
            }
        }
        restore_accounts_in_runtime_order(svm, accounts, "restore selective account")
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
        next_delta.restore_sysvars(svm);
        let mut accounts = self.collect_divergent_restores(
            svm,
            divergent_keys,
            &next_delta.accounts,
            &next_delta.sysvars,
        );

        // 2. Delta accounts — skip if same Arc as prev_delta AND not dirtied by execution
        for (pubkey, next_acct) in &next_delta.accounts {
            if is_snapshot_sysvar(pubkey, &next_delta.sysvars) {
                continue;
            }
            if !prev_exec_dirty.contains(pubkey) {
                if let Some(prev_acct) = prev_delta.accounts.get(pubkey) {
                    if Arc::ptr_eq(prev_acct, next_acct) {
                        // Same Arc, not dirtied by execution → SVM already has correct value
                        continue;
                    }
                }
            }
            accounts.push((*pubkey, (**next_acct).clone()));
        }
        restore_accounts_in_runtime_order(svm, accounts, "restore selective account from delta")
    }

    /// Shared step 1: restore divergent accounts to initial state.
    /// Accounts present in `delta_keys` are skipped (they'll be set by the delta overlay).
    /// Executable (program) accounts are never zeroed to avoid litesvm desync.
    fn collect_divergent_restores(
        &self,
        svm: &LiteSVM,
        divergent_keys: &FastHashSet<Pubkey>,
        delta_keys: &FastHashMap<Pubkey, Arc<Account>>,
        target_sysvars: &[(Pubkey, Option<Account>)],
    ) -> Vec<(Pubkey, Account)> {
        let mut accounts = Vec::with_capacity(divergent_keys.len());
        for pubkey in divergent_keys {
            if delta_keys.contains_key(pubkey) || is_snapshot_sysvar(pubkey, target_sysvars) {
                continue; // will be set by delta overlay
            }
            if let Some(initial_account) = self.accounts.get(pubkey) {
                accounts.push((*pubkey, (**initial_account).clone()));
            } else {
                // Account was created during prev iteration but doesn't exist in initial — zero it.
                // Skip executable (program) accounts: zeroing them removes from accounts_db but
                // NOT from programs_cache, causing a desync that panics in litesvm (lib.rs:981).
                if let Some(existing) = svm.get_account(pubkey) {
                    if existing.executable {
                        continue;
                    }
                }
                accounts.push((
                    *pubkey,
                    Account {
                        lamports: 0,
                        ..Default::default()
                    },
                ));
            }
        }
        accounts
    }

    /// Get a reference to the internal accounts map.
    pub fn accounts(&self) -> &FastHashMap<Pubkey, Arc<Account>> {
        &self.accounts
    }

    /// Hash the SVM state for the accounts tracked by this snapshot.
    /// Used for save/restore verification: hash at save time, hash again after restore,
    /// if they differ the snapshot is lossy.
    pub fn hash_tracked_state(&self, svm: &LiteSVM) -> u64 {
        use rustc_hash::FxHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = FxHasher::default();
        // Sort keys for deterministic order
        let mut keys: Vec<_> = self.accounts.keys().copied().collect();
        keys.sort();
        for pk in &keys {
            pk.hash(&mut hasher);
            if let Some(acct) = svm.get_account(pk) {
                acct.lamports.hash(&mut hasher);
                acct.data.hash(&mut hasher);
                acct.owner.hash(&mut hasher);
                acct.executable.hash(&mut hasher);
                acct.rent_epoch.hash(&mut hasher);
            } else {
                0u8.hash(&mut hasher);
            }
        }
        hasher.finish()
    }

    /// Get the stored Clock sysvar by deserializing from sysvars.
    pub fn clock(&self) -> Clock {
        clock_from_sysvars(&self.sysvars, "SvmSnapshot")
    }

    /// Minimal tombstone snapshot with zero allocations.
    /// Used to free memory from evicted pool entries while keeping the slot alive
    /// for parent-chain reconstruction.
    pub fn tombstone() -> Self {
        Self {
            accounts: FastHashMap::default(),
            sysvars: Vec::new(),
        }
    }

    /// Create an empty snapshot (no accounts differ from initial state).
    /// Used as the initial delta in the state pool.
    pub fn empty(clock: Clock) -> Self {
        Self {
            accounts: FastHashMap::default(),
            sysvars: vec![(Clock::id(), Some(clock_account(&clock)))],
        }
    }

    /// Create a delta snapshot containing only accounts that differ from the initial state.
    /// Starts from parent's delta (accounts already different from initial),
    /// then updates with this action's dirty accounts read from SVM.
    ///
    /// With `Arc<Account>`, cloning the parent map is O(n * 40B) — just Pubkey copies
    /// + Arc refcount bumps — instead of O(n * avg_account_data_len) deep copies.
    /// Only the newly dirty accounts (from this action) allocate fresh `Arc`s.
    pub fn take_delta(svm: &LiteSVM, parent_delta: &SvmSnapshot, dirty: &DirtyTracker) -> Self {
        // Clone parent's delta — cheap with Arc<Account>: only bumps refcounts
        let mut accounts = parent_delta.accounts.clone();
        // Update/add dirty accounts from current SVM state
        for pk in dirty.dirty_accounts() {
            match svm.get_account(pk) {
                Some(acct) => {
                    accounts.insert(*pk, Arc::new(acct));
                }
                None => {
                    // Account deleted — store tombstone so restore_full zeroes it
                    accounts.insert(
                        *pk,
                        Arc::new(Account {
                            lamports: 0,
                            ..Default::default()
                        }),
                    );
                }
            }
        }
        let sysvars = Self::take_sysvars(svm);
        Self { accounts, sysvars }
    }

    /// Build a delta from pre-read accounts that differ from initial.
    ///
    /// `changed_accounts` contains (pubkey, Account) for every dirty account whose data
    /// actually differs from the initial snapshot. These are collected during fingerprint
    /// computation (which already reads and compares every dirty account), avoiding a
    /// redundant `svm.get_account()` + 1MB comparison per account in `take_delta`.
    ///
    /// Parent delta entries for accounts NOT in `changed_accounts` are dropped — the
    /// action restored them to initial state.
    pub fn take_delta_from_changed(
        svm: &LiteSVM,
        changed_accounts: FastHashMap<Pubkey, Arc<Account>>,
    ) -> Self {
        let sysvars = Self::take_sysvars(svm);
        Self {
            accounts: changed_accounts,
            sysvars,
        }
    }

    fn take_sysvars(svm: &LiteSVM) -> Vec<(Pubkey, Option<Account>)> {
        managed_sysvar_ids()
            .iter()
            .map(|sysvar| (*sysvar, svm.get_account(sysvar)))
            .collect()
    }

    fn restore_sysvars(&self, svm: &mut LiteSVM) -> usize {
        restore_sysvars_checked(svm, &self.sysvars, "restore SvmSnapshot sysvar")
    }
}

// ============================================================================
// CompactDelta — word-level diffs for memory-efficient state pool storage
// ============================================================================

/// Patch for a single account relative to the initial snapshot.
#[derive(Clone, Debug)]
pub enum AccountPatch {
    /// Full account data (for created, deleted, or resized accounts).
    Full(Arc<Account>),
    /// Diff relative to initial: only u64 words that changed.
    /// `word_index` = byte_offset / 8. Tail bytes handled by reading
    /// a partial u64 from the source data.
    Diff {
        lamports: u64,
        /// (word_index, new_u64_value) sorted by word_index.
        patches: Vec<(u32, u64)>,
    },
}

impl AccountPatch {
    /// Estimated heap bytes for this patch.
    pub fn estimated_heap_bytes(&self) -> usize {
        match self {
            AccountPatch::Full(arc) => std::mem::size_of::<Account>() + arc.data.len(),
            AccountPatch::Diff { patches, .. } => patches.len() * 12, // (u32, u64) = 12 bytes
        }
    }

    /// Whether this is a Diff variant (for diagnostics).
    pub fn is_diff(&self) -> bool {
        matches!(self, AccountPatch::Diff { .. })
    }

    /// Reconstruct the full Account by applying this patch to the initial account.
    /// Returns None if the initial account is missing and this is a Diff patch.
    pub fn reconstruct(&self, initial_account: Option<&Account>) -> Option<Account> {
        match self {
            AccountPatch::Full(arc) => Some((**arc).clone()),
            AccountPatch::Diff { lamports, patches } => {
                let init = initial_account?;
                let mut acct = init.clone();
                acct.lamports = *lamports;
                let data = &mut acct.data;
                for &(word_idx, val) in patches {
                    let offset = word_idx as usize * 8;
                    if offset >= data.len() {
                        return None;
                    }
                    let end = (offset + 8).min(data.len());
                    let bytes = val.to_le_bytes();
                    data[offset..end].copy_from_slice(&bytes[..end - offset]);
                }
                Some(acct)
            }
        }
    }
}

/// Compact delta snapshot storing only changed u64 words per account.
///
/// Replaces `Arc<SvmSnapshot>` in `StateEntry.delta` for massive memory savings
/// with protocols that have large accounts (e.g., 1MB orderbooks where only
/// ~50 u64 words change per action → 600 bytes instead of 1MB).
///
/// All diffs are relative to the initial snapshot. Restore requires the initial
/// snapshot to reconstruct full accounts before calling `svm.set_account()`.
#[derive(Clone)]
pub struct CompactDelta {
    pub(crate) accounts: FastHashMap<Pubkey, AccountPatch>,
    pub(crate) sysvars: Vec<(Pubkey, Option<Account>)>,
}

impl CompactDelta {
    /// Empty delta for evicted/crashed states (frees memory).
    pub fn tombstone() -> Self {
        Self {
            accounts: FastHashMap::default(),
            sysvars: Vec::new(),
        }
    }

    /// Initial delta (no account changes, just a synthetic Clock sysvar).
    ///
    /// Production state pools should use [`Self::from_initial`] so every
    /// managed sysvar is inherited from the setup snapshot.
    pub fn empty(clock: Clock) -> Self {
        Self {
            accounts: FastHashMap::default(),
            sysvars: vec![(Clock::id(), Some(clock_account(&clock)))],
        }
    }

    /// Construct the root delta from the complete setup snapshot.
    ///
    /// This keeps Clock, EpochRewards, EpochSchedule, Fees, LastRestartSlot,
    /// RecentBlockhashes, Rent, and StakeHistory identical to the initial SVM.
    /// SlotHashes and SlotHistory are deliberately not managed by compact
    /// deltas because of their size.
    pub fn from_initial(initial: &SvmSnapshot) -> Self {
        // Validate the most frequently consumed sysvar up front rather than
        // allowing corrupt root state to become a default Clock later.
        let _ = initial.clock();
        Self {
            accounts: FastHashMap::default(),
            sysvars: initial.sysvars.clone(),
        }
    }

    /// Build a compact delta from pre-collected changed accounts.
    ///
    /// For each account in `changed`, compares against `initial` to determine
    /// whether to store a Full copy or a u64-word diff. Accounts with the same
    /// data length as initial get word diffs; created/deleted/resized get Full.
    pub fn from_changed(
        initial: &SvmSnapshot,
        changed: FastHashMap<Pubkey, Arc<Account>>,
        svm: &LiteSVM,
    ) -> Self {
        let mut accounts = FastHashMap::default();
        accounts.reserve(changed.len());

        for (pk, arc_acct) in changed {
            let patch = match initial.accounts.get(&pk) {
                Some(init_arc)
                    if init_arc.data.len() == arc_acct.data.len()
                        && init_arc.owner == arc_acct.owner
                        && init_arc.executable == arc_acct.executable
                        && init_arc.rent_epoch == arc_acct.rent_epoch =>
                {
                    // Same size + same metadata — compute u64 word diff
                    let init_data = &init_arc.data;
                    let cur_data = &arc_acct.data;
                    let mut patches = Vec::new();
                    let num_full_words = cur_data.len() / 8;

                    // Compare full u64 words
                    for wi in 0..num_full_words {
                        let off = wi * 8;
                        let init_word =
                            u64::from_le_bytes(init_data[off..off + 8].try_into().unwrap());
                        let cur_word =
                            u64::from_le_bytes(cur_data[off..off + 8].try_into().unwrap());
                        if init_word != cur_word {
                            patches.push((wi as u32, cur_word));
                        }
                    }

                    // Handle tail bytes (data.len() % 8 != 0)
                    let tail_start = num_full_words * 8;
                    if tail_start < cur_data.len() {
                        let mut init_tail = [0u8; 8];
                        let mut cur_tail = [0u8; 8];
                        let tail_len = cur_data.len() - tail_start;
                        init_tail[..tail_len].copy_from_slice(&init_data[tail_start..]);
                        cur_tail[..tail_len].copy_from_slice(&cur_data[tail_start..]);
                        if init_tail != cur_tail {
                            patches.push((num_full_words as u32, u64::from_le_bytes(cur_tail)));
                        }
                    }

                    AccountPatch::Diff {
                        lamports: arc_acct.lamports,
                        patches,
                    }
                }
                _ => {
                    // Created, deleted, or resized — store full account
                    AccountPatch::Full(arc_acct)
                }
            };
            accounts.insert(pk, patch);
        }

        let sysvars = SvmSnapshot::take_sysvars(svm);
        Self { accounts, sysvars }
    }

    /// Build a compact delta by reading dirty accounts from the SVM.
    /// Handles both existing accounts (compared against initial for Diff/Full)
    /// and deleted accounts (stored as zero-lamport tombstone).
    /// Equivalent to the old `SvmSnapshot::take_delta` for per-execution deltas.
    pub fn from_dirty(
        initial: &SvmSnapshot,
        svm: &LiteSVM,
        dirty_accounts: &FastHashSet<Pubkey>,
    ) -> Self {
        let mut changed: FastHashMap<Pubkey, Arc<Account>> = FastHashMap::default();
        for pk in dirty_accounts {
            match svm.get_account(pk) {
                Some(acct) => {
                    changed.insert(*pk, Arc::new(acct));
                }
                None => {
                    changed.insert(
                        *pk,
                        Arc::new(Account {
                            lamports: 0,
                            ..Default::default()
                        }),
                    );
                }
            }
        }
        Self::from_changed(initial, changed, svm)
    }

    /// Build a compact delta from pre-built patches (from `fingerprint_and_collect_changed`).
    pub fn from_patches(svm: &LiteSVM, patches: FastHashMap<Pubkey, AccountPatch>) -> Self {
        let sysvars = SvmSnapshot::take_sysvars(svm);
        Self {
            accounts: patches,
            sysvars,
        }
    }

    /// Build a child delta by inheriting parent patches and overlaying new changes.
    ///
    /// Mirrors the semantics of the old `SvmSnapshot::take_delta`:
    /// - Parent accounts NOT re-dirtied → inherited (still at parent value)
    /// - Dirty accounts in `new_patches` → use new value (overrides parent)
    /// - Parent accounts re-dirtied but NOT in `new_patches` → dropped (returned to initial)
    pub fn child_delta(
        parent: &CompactDelta,
        new_patches: FastHashMap<Pubkey, AccountPatch>,
        dirty_accounts: &FastHashSet<Pubkey>,
        svm: &LiteSVM,
    ) -> Self {
        Self::child_delta_inner(parent, new_patches, dirty_accounts, svm)
    }

    /// Build a child delta from per-execution CompactDelta + parent.
    /// Convenience wrapper that extracts patches from `exec_delta` and merges with parent.
    pub fn child_delta_from(
        parent: &CompactDelta,
        exec_delta: CompactDelta,
        dirty_accounts: &FastHashSet<Pubkey>,
        svm: &LiteSVM,
    ) -> Self {
        Self::child_delta_inner(parent, exec_delta.accounts, dirty_accounts, svm)
    }

    fn child_delta_inner(
        parent: &CompactDelta,
        new_patches: FastHashMap<Pubkey, AccountPatch>,
        dirty_accounts: &FastHashSet<Pubkey>,
        svm: &LiteSVM,
    ) -> Self {
        let mut accounts = FastHashMap::default();
        accounts.reserve(parent.accounts.len() + new_patches.len());

        // Inherit parent patches for accounts not re-dirtied in this execution
        for (pk, patch) in &parent.accounts {
            if !dirty_accounts.contains(pk) {
                accounts.insert(*pk, patch.clone());
            }
        }

        // Overlay new patches (dirty + different from initial)
        for (pk, patch) in new_patches {
            accounts.insert(pk, patch);
        }

        let sysvars = SvmSnapshot::take_sysvars(svm);
        Self { accounts, sysvars }
    }

    /// Iterator over account pubkeys in this delta.
    pub fn keys(&self) -> impl Iterator<Item = &Pubkey> {
        self.accounts.keys()
    }

    /// Number of accounts in this delta.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Estimated heap bytes for memory profiling.
    pub fn estimated_heap_bytes(&self) -> usize {
        let map_overhead = self.accounts.len() * 80;
        let patch_data: usize = self
            .accounts
            .values()
            .map(|p| p.estimated_heap_bytes())
            .sum();
        let sysvar_data: usize = self
            .sysvars
            .iter()
            .map(|(_, opt)| match opt {
                Some(a) => std::mem::size_of::<Account>() + a.data.len(),
                None => 0,
            })
            .sum();
        map_overhead + patch_data + sysvar_data
    }

    /// Get the stored Clock sysvar.
    pub fn clock(&self) -> Clock {
        clock_from_sysvars(&self.sysvars, "CompactDelta")
    }

    /// Reconstruct a full Account for the given pubkey by applying the patch
    /// on top of the initial snapshot. Returns None if not in this delta.
    pub fn reconstruct_account(&self, initial: &SvmSnapshot, pubkey: &Pubkey) -> Option<Account> {
        let patch = self.accounts.get(pubkey)?;
        patch.reconstruct(initial.accounts.get(pubkey).map(|a| a.as_ref()))
    }

    /// Restore SVM state from this delta. Resets divergent accounts to initial,
    /// then applies patches. Returns number of set_account calls.
    pub fn restore_selective(
        &self,
        initial: &SvmSnapshot,
        svm: &mut LiteSVM,
        divergent_keys: &FastHashSet<Pubkey>,
    ) -> usize {
        self.restore_sysvars(svm);
        let mut accounts = self.collect_divergent_restores(initial, svm, divergent_keys);

        // Apply patches after resetting accounts not represented by the target delta.
        for (pubkey, patch) in &self.accounts {
            if is_snapshot_sysvar(pubkey, &self.sysvars) {
                continue;
            }
            let account = patch
                .reconstruct(initial.accounts.get(pubkey).map(Arc::as_ref))
                .unwrap_or_else(|| {
                    panic!(
                        "CompactDelta: cannot reconstruct patch for {pubkey}; initial account is missing or patch data is invalid"
                    )
                });
            accounts.push((*pubkey, account));
        }
        restore_accounts_in_runtime_order(svm, accounts, "restore CompactDelta account")
    }

    /// Optimized restore using delta-to-delta comparison.
    ///
    /// Skips `svm.set_account()` for accounts whose patch is identical between
    /// `prev_delta` and this delta AND were not dirtied by the previous execution.
    pub fn restore_selective_from(
        &self,
        initial: &SvmSnapshot,
        svm: &mut LiteSVM,
        divergent_keys: &FastHashSet<Pubkey>,
        prev_delta: &CompactDelta,
        prev_exec_dirty: &FastHashSet<Pubkey>,
    ) -> usize {
        self.restore_sysvars(svm);
        let mut accounts = self.collect_divergent_restores(initial, svm, divergent_keys);

        // Apply patches, skipping unchanged ones.
        for (pubkey, next_patch) in &self.accounts {
            if is_snapshot_sysvar(pubkey, &self.sysvars) {
                continue;
            }
            // Skip if not dirtied by execution AND patch is identical to prev
            if !prev_exec_dirty.contains(pubkey) {
                if let Some(prev_patch) = prev_delta.accounts.get(pubkey) {
                    if patches_equal(prev_patch, next_patch) {
                        continue; // SVM already has correct value
                    }
                }
            }
            let account = next_patch
                .reconstruct(initial.accounts.get(pubkey).map(Arc::as_ref))
                .unwrap_or_else(|| {
                    panic!(
                        "CompactDelta: cannot reconstruct patch for {pubkey}; initial account is missing or patch data is invalid"
                    )
                });
            accounts.push((*pubkey, account));
        }
        restore_accounts_in_runtime_order(svm, accounts, "restore CompactDelta account from delta")
    }

    /// Per-account size info for diagnostics. Returns (pubkey_short, patch_bytes) pairs.
    pub fn accounts_report_info(&self) -> Vec<(String, usize)> {
        self.accounts
            .iter()
            .map(|(pk, patch)| {
                let pk_str = pk.to_string();
                let short = format!(
                    "{}..{}",
                    &pk_str[..4],
                    &pk_str[pk_str.len().saturating_sub(4)..]
                );
                let bytes = patch.estimated_heap_bytes();
                (short, bytes)
            })
            .collect()
    }

    /// Total sysvar data bytes.
    pub fn sysvar_data_bytes(&self) -> usize {
        self.sysvars
            .iter()
            .map(|(_, opt)| opt.as_ref().map(|a| a.data.len()).unwrap_or(0))
            .sum()
    }

    fn restore_sysvars(&self, svm: &mut LiteSVM) {
        restore_sysvars_checked(svm, &self.sysvars, "restore CompactDelta sysvar");
    }

    fn collect_divergent_restores(
        &self,
        initial: &SvmSnapshot,
        svm: &LiteSVM,
        divergent_keys: &FastHashSet<Pubkey>,
    ) -> Vec<(Pubkey, Account)> {
        let mut accounts = Vec::with_capacity(divergent_keys.len());
        for pubkey in divergent_keys {
            if self.accounts.contains_key(pubkey) || is_snapshot_sysvar(pubkey, &self.sysvars) {
                continue;
            }
            if let Some(original) = initial.accounts.get(pubkey) {
                accounts.push((*pubkey, (**original).clone()));
            } else {
                if svm
                    .get_account(pubkey)
                    .is_some_and(|account| account.executable)
                {
                    continue;
                }
                accounts.push((
                    *pubkey,
                    Account {
                        lamports: 0,
                        ..Default::default()
                    },
                ));
            }
        }
        accounts
    }
}

/// Compare two patches for equality (used in restore_selective_from optimization).
fn patches_equal(a: &AccountPatch, b: &AccountPatch) -> bool {
    match (a, b) {
        (AccountPatch::Full(a_arc), AccountPatch::Full(b_arc)) => Arc::ptr_eq(a_arc, b_arc),
        (
            AccountPatch::Diff {
                lamports: la,
                patches: pa,
            },
            AccountPatch::Diff {
                lamports: lb,
                patches: pb,
            },
        ) => la == lb && pa == pb,
        _ => false,
    }
}

// ============================================================================
// State Fingerprinting — bucketed hashing for state novelty detection
// ============================================================================

/// Per-magnitude exponential value bucketing (16 buckets: 0-15).
///
/// 0, 1 get individual buckets (critical for flags/booleans).
/// Then each order of magnitude (decade) gets one bucket:
/// 2-9, 10-99, 100-999, 1K-9K, 10K-99K, 100K-999K,
/// 1M-9M, 10M-99M, 100M-999M, 1B-9B, 10B-99B, 100B-999B, 1T-9T, >10T.
///
/// Total: 16 buckets covering the full u64 range.
/// Naturally adaptive: u8-range values only use ~6, u64-range use all 16.
#[inline]
pub fn value_bucket(val: u64) -> u8 {
    match val {
        0 => 0,
        1 => 1,
        2..=9 => 2,
        10..=99 => 3,
        100..=999 => 4,
        1_000..=9_999 => 5,
        10_000..=99_999 => 6,
        100_000..=999_999 => 7,
        1_000_000..=9_999_999 => 8,
        10_000_000..=99_999_999 => 9,
        100_000_000..=999_999_999 => 10,
        1_000_000_000..=9_999_999_999 => 11,
        10_000_000_000..=99_999_999_999 => 12,
        100_000_000_000..=999_999_999_999 => 13,
        1_000_000_000_000..=9_999_999_999_999 => 14,
        _ => 15,
    }
}

/// Fine-grained slot bucketing (~65 buckets).
///
/// Individual granularity at 1-9 (so advance_slots(1) vs advance_slots(5) produce
/// different fingerprints), then per-decade above that. This ensures that from a
/// starting slot like 1600, various advance_slots values can produce ~13 distinct
/// buckets (vs 0-1 with the old 8-bucket system).
///
/// Buckets: 0=zero, 1-9=individual, 10-18=per-10, 19-27=per-100,
///          28-36=per-1K, 37-45=per-10K, 46-54=per-100K, 55-63=per-1M, 64=10M+
#[inline]
pub fn slot_bucket(val: u64) -> u8 {
    match val {
        0 => 0,
        1..=9 => val as u8,                           // buckets 1-9 (individual)
        10..=99 => 9 + (val / 10) as u8,              // buckets 10-18 (per-10)
        100..=999 => 18 + (val / 100) as u8,          // buckets 19-27 (per-100)
        1_000..=9_999 => 27 + (val / 1_000) as u8,    // buckets 28-36 (per-1K)
        10_000..=99_999 => 36 + (val / 10_000) as u8, // buckets 37-45 (per-10K)
        100_000..=999_999 => 45 + (val / 100_000) as u8, // buckets 46-54 (per-100K)
        1_000_000..=9_999_999 => 54 + (val / 1_000_000) as u8, // buckets 55-63 (per-1M)
        _ => 64,                                      // 10M+ overflow
    }
}

/// Differential bucketing for slot changes from initial (~49 buckets).
/// Buckets: 0-9 individual, 10-99 per-10, 100-999 per-100, 1K-9K per-1K,
///          10K-99K per-10K, 100K-999K per-100K, ≥1M overflow.
#[inline]
pub fn slot_diff_bucket(diff: u64) -> u8 {
    match diff {
        0..=9 => diff as u8,                              // buckets 0-9
        10..=99 => 9 + (diff / 10) as u8,                 // buckets 10-18
        100..=999 => 18 + (diff / 100) as u8,             // buckets 19-27
        1_000..=9_999 => 27 + (diff / 1_000) as u8,       // buckets 28-36
        10_000..=99_999 => 36 + (diff / 10_000) as u8,    // buckets 37-45
        100_000..=999_999 => 45 + (diff / 100_000) as u8, // buckets 46-54
        _ => 55,                                          // overflow (≥1M)
    }
}

/// Default/minimum number of bits in the final fingerprint for dedup. Controls novel rate:
/// - Too many bits → every state is "novel", pool grows unbounded
/// - Too few bits → states collapse, pool stays tiny
/// 18 bits = 256K possible fingerprints (32KB bitmap).
///
/// This is the floor: the actual dedup width is derived at runtime from the
/// configured pool capacity (`--pool-size`) via
/// `state_pool::fingerprint_bits_for_capacity`, so larger pools get a
/// proportionally larger distinct-state ceiling.
pub(super) const FINGERPRINT_BITS: u32 = 18;

/// Stable identity hash for an account in fingerprint/novelty hashing.
///
/// - Accounts present in the initial snapshot are keyed by **pubkey** (stable
///   across runs by construction).
/// - Accounts created during fuzzing are keyed by **creation ordinal + owner +
///   canonical type prefix**. Fresh keypairs/PDAs/ATAs get a different pubkey
///   every run, so hashing the pubkey would make semantically identical states
///   hash as novel; the creation ordinal is deterministic for a replayed action
///   sequence. Salting with owner + discriminator/fallback prefix prevents
///   over-collapse when different inputs create different account types at the
///   same ordinal, while embedded created pubkeys are canonicalized before any
///   fallback bytes are hashed.
pub fn account_identity_hash(
    pubkey: &Pubkey,
    account: Option<&Account>,
    creation: &CreationTracker,
    initial: &SvmSnapshot,
) -> u64 {
    let mut h = FxHasher::default();
    if initial.accounts.contains_key(pubkey) {
        pubkey.hash(&mut h);
    } else if let Some(ordinal) = creation.ordinal(pubkey) {
        ordinal.hash(&mut h);
        if let Some(acct) = account {
            acct.owner.hash(&mut h);
            if let Some(disc_len) = crate::schema::lookup_registered_discriminator_len(&acct.data) {
                acct.data[..disc_len.min(acct.data.len())].hash(&mut h);
            } else if let Some(disc_len) = crate::schema::fallback_discriminator_len(&acct.data) {
                let canonical_data = canonicalize_created_pubkeys(&acct.data, creation);
                let hash_data = canonical_data.as_deref().unwrap_or(&acct.data);
                hash_data[..disc_len.min(hash_data.len())].hash(&mut h);
            } else {
                acct.data.len().hash(&mut h);
            }
        }
    } else {
        // Not in initial and no ordinal recorded (caller without creation
        // tracking) — fall back to pubkey identity.
        pubkey.hash(&mut h);
    }
    h.finish()
}

/// Replace embedded created pubkeys with deterministic ordinal markers before
/// hashing account data. This keeps fingerprints stable when an account stores
/// freshly-created account keys in its fields.
fn canonicalize_created_pubkeys(data: &[u8], creation: &CreationTracker) -> Option<Vec<u8>> {
    if creation.is_empty() || data.len() < 32 {
        return None;
    }

    let mut first_byte_candidates = [false; 256];
    for pubkey in creation.pubkeys() {
        first_byte_candidates[pubkey.to_bytes()[0] as usize] = true;
    }

    let mut canonical = None;
    let mut i = 0usize;
    while i + 32 <= data.len() {
        if !first_byte_candidates[data[i] as usize] {
            i += 1;
            continue;
        }
        if let Some(ordinal) = creation.ordinal_for_bytes(&data[i..i + 32]) {
            let out = canonical.get_or_insert_with(|| data.to_vec());
            out[i..i + 32].copy_from_slice(&canonical_created_pubkey_marker(ordinal));
            i += 32;
        } else {
            i += 1;
        }
    }
    canonical
}

fn canonical_created_pubkey_marker(ordinal: u32) -> [u8; 32] {
    let mut marker = [0xA5u8; 32];
    marker[..8].copy_from_slice(b"CRUCPUBK");
    for (chunk_idx, chunk) in marker[8..].chunks_exact_mut(4).enumerate() {
        let value = ordinal.wrapping_add((chunk_idx as u32).wrapping_mul(0x9E37_79B9));
        for (dst, src) in chunk.iter_mut().zip(value.to_le_bytes()) {
            *dst = if src == 0 { 0x7F } else { src };
        }
    }
    marker
}

/// Sort dirty accounts for deterministic hash ordering: pre-existing accounts
/// (and any without a creation ordinal) sorted by pubkey, then created accounts
/// in creation order. Created accounts must NOT be ordered by their random
/// pubkeys — that would make the hash order (and thus the fingerprint) vary
/// across runs for identical states.
fn sort_dirty_for_fingerprint<'a>(
    dirty: &'a DirtyTracker,
    creation: &CreationTracker,
) -> Vec<&'a Pubkey> {
    let mut sorted_dirty: Vec<&Pubkey> = dirty.dirty_accounts().iter().collect();
    sorted_dirty.sort();
    // Stable sort: pubkey order is preserved within the no-ordinal group.
    sorted_dirty.sort_by_key(|pk| match creation.ordinal(pk) {
        None => (0u8, 0u32),
        Some(ord) => (1u8, ord),
    });
    sorted_dirty
}

/// Compute an absolute state fingerprint from the current SVM state.
///
/// Uses field-boundary-aware diffing against initial state for layout-aware bucketing.
/// The hash is truncated to the pool's runtime dedup width (in StatePool::try_add)
/// while the full 64-bit value is kept for state_class action selection.
///
/// `creation` maps accounts created along this state's lineage to their
/// deterministic creation ordinals (see `account_identity_hash`).
pub fn compute_state_fingerprint_from_snapshot(
    svm: &LiteSVM,
    dirty: &DirtyTracker,
    initial: &SvmSnapshot,
    creation: &CreationTracker,
) -> u64 {
    let mut hasher = FxHasher::default();

    // Use differential slot: how much slot advanced from initial, not absolute value.
    let clock: Clock = svm.get_sysvar();
    let initial_clock = initial.clock();
    let slot_diff = clock.slot.saturating_sub(initial_clock.slot);
    slot_diff_bucket(slot_diff).hash(&mut hasher);
    clock.epoch.hash(&mut hasher);

    // If the harness explicitly advanced the clock (warp_to_slot/advance_slots),
    // include the exact target slot in the fingerprint. This ensures each distinct
    // clock advance produces a unique state, even when slot_diff_bucket collapses
    // multiple values into the same bucket. Without this, advance_slots(3000) and
    // advance_slots(5000) could produce identical fingerprints.
    if let Some(target) = dirty.clock_target_slot {
        target.hash(&mut hasher);
    }

    if dirty.dirty_accounts().is_empty() {
        return hasher.finish();
    }

    // Sort dirty accounts for deterministic hash ordering.
    // FxHasher is order-dependent, so iterating a HashSet (non-deterministic order)
    // would produce different fingerprints for the same logical state.
    let sorted_dirty = sort_dirty_for_fingerprint(dirty, creation);

    // Hash account count first (different account sets = different state)
    (sorted_dirty.len() as u64).hash(&mut hasher);

    for pubkey in &sorted_dirty {
        let account = svm.get_account(pubkey);
        let lamports = account.as_ref().map(|a| a.lamports).unwrap_or(0);
        let data = account.as_ref().map(|a| a.data.as_slice()).unwrap_or(&[]);
        let owner = account.as_ref().map(|a| a.owner).unwrap_or_default();
        let executable = account.as_ref().is_some_and(|a| a.executable);
        let rent_epoch = account.as_ref().map(|a| a.rent_epoch).unwrap_or(0);
        let canonical_data = canonicalize_created_pubkeys(data, creation);
        let hash_data = canonical_data.as_deref().unwrap_or(data);

        // Per-account identity: pubkey for pre-existing accounts, creation
        // ordinal (+ owner + discriminator) for accounts created during fuzzing.
        account_identity_hash(pubkey, account.as_ref(), creation, initial).hash(&mut hasher);

        // Hash absolute lamports bucket (not differential)
        value_bucket(lamports).hash(&mut hasher);

        // Hash data length bucket
        value_bucket(data.len() as u64).hash(&mut hasher);
        owner.hash(&mut hasher);
        executable.hash(&mut hasher);
        rent_epoch.hash(&mut hasher);

        // Field-boundary-aware diffing: find contiguous changed regions vs initial
        let init_data = initial
            .accounts
            .get(pubkey)
            .map(|a| a.data.as_slice())
            .unwrap_or(&[]);
        let min_len = hash_data.len().min(init_data.len());
        let mut i = 0usize;
        while i < min_len {
            if hash_data[i] != init_data[i] {
                let start = i;
                while i < min_len && hash_data[i] != init_data[i] {
                    i += 1;
                }
                let val = read_region_value(&hash_data[start..i]);
                (start as u32, value_bucket(val)).hash(&mut hasher);
            } else {
                i += 1;
            }
        }
        // Handle data beyond init_data (new/grown accounts): diff against zero.
        if hash_data.len() > min_len {
            let mut i = min_len;
            while i < hash_data.len() {
                if hash_data[i] != 0 {
                    let start = i;
                    while i < hash_data.len() && hash_data[i] != 0 {
                        i += 1;
                    }
                    let val = read_region_value(&hash_data[start..i]);
                    (start as u32, value_bucket(val)).hash(&mut hasher);
                } else {
                    i += 1;
                }
            }
        }
        // Resize entry: signal that the account changed size
        if data.len() != init_data.len() {
            (min_len as u32, value_bucket(data.len() as u64)).hash(&mut hasher);
        }
    }

    hasher.finish()
}

/// Compute fingerprint, collect compact patches, AND check field novelty in a single pass.
///
/// Combines three previously separate operations:
/// 1. State fingerprinting (bucketed hash of changed regions)
/// 2. CompactDelta patch collection (u64-word diffs for pool storage)
/// 3. Field novelty detection (bitmap of seen per-field value buckets)
///
/// Pass `field_bitmap_ptr` as null to skip field novelty (non-stateful modes).
///
/// `creation` maps accounts created along this state's lineage to their
/// deterministic creation ordinals (see `account_identity_hash`).
///
/// Returns (fingerprint, patches_map, field_novel_bits).
pub unsafe fn fingerprint_and_collect_changed(
    svm: &LiteSVM,
    dirty: &DirtyTracker,
    initial: &SvmSnapshot,
    creation: &CreationTracker,
    field_bitmap_ptr: *mut u8,
    field_bitmap_len: usize,
) -> (u64, FastHashMap<Pubkey, AccountPatch>, u32) {
    let do_field_novelty = !field_bitmap_ptr.is_null();
    let total_bits = if do_field_novelty {
        field_bitmap_len * 8
    } else {
        0
    };
    let mut field_novel_count: u32 = 0;

    let mut hasher = FxHasher::default();
    let mut changed: FastHashMap<Pubkey, AccountPatch> = FastHashMap::default();

    let clock: Clock = svm.get_sysvar();
    let initial_clock = initial.clock();
    let slot_diff = clock.slot.saturating_sub(initial_clock.slot);
    let sdb = slot_diff_bucket(slot_diff);
    slot_diff_bucket(slot_diff).hash(&mut hasher);
    clock.epoch.hash(&mut hasher);

    if let Some(target) = dirty.clock_target_slot {
        target.hash(&mut hasher);
    }

    // Field novelty: clock checks
    if do_field_novelty && (slot_diff > 0 || clock.epoch != initial_clock.epoch) {
        field_novel_count += check_and_set_bit_atomic(
            field_bitmap_ptr,
            total_bits,
            field_hash(CLOCK_TYPE_KEY, 0, sdb),
        );
        field_novel_count += check_and_set_bit_atomic(
            field_bitmap_ptr,
            total_bits,
            field_hash(CLOCK_TYPE_KEY, 1, value_bucket(clock.epoch)),
        );
        if let Some(target) = dirty.clock_target_slot {
            field_novel_count += check_and_set_bit_atomic(
                field_bitmap_ptr,
                total_bits,
                field_hash(CLOCK_TYPE_KEY, 2, slot_bucket(target)),
            );
        }
    }

    if dirty.dirty_accounts().is_empty() {
        return (hasher.finish(), changed, field_novel_count);
    }

    let sorted_dirty = sort_dirty_for_fingerprint(dirty, creation);
    (sorted_dirty.len() as u64).hash(&mut hasher);

    // Per-account identity hashes, collected for the set-novelty pass below.
    let mut identities: Vec<u64> = Vec::with_capacity(sorted_dirty.len());

    for pubkey in &sorted_dirty {
        let account = svm.get_account(pubkey);
        let lamports = account.as_ref().map(|a| a.lamports).unwrap_or(0);
        let data = account.as_ref().map(|a| a.data.as_slice()).unwrap_or(&[]);
        let owner = account.as_ref().map(|a| a.owner).unwrap_or_default();
        let executable = account.as_ref().is_some_and(|a| a.executable);
        let rent_epoch = account.as_ref().map(|a| a.rent_epoch).unwrap_or(0);
        let canonical_data = canonicalize_created_pubkeys(data, creation);
        let hash_data = canonical_data.as_deref().unwrap_or(data);

        // Per-account identity: pubkey for pre-existing accounts, creation
        // ordinal (+ owner + discriminator) for accounts created during fuzzing.
        let identity = account_identity_hash(pubkey, account.as_ref(), creation, initial);
        identities.push(identity);
        identity.hash(&mut hasher);
        value_bucket(lamports).hash(&mut hasher);
        value_bucket(data.len() as u64).hash(&mut hasher);
        owner.hash(&mut hasher);
        executable.hash(&mut hasher);
        rent_epoch.hash(&mut hasher);

        let init_account = initial.accounts.get(pubkey);
        let init_data = init_account.map(|a| a.data.as_slice()).unwrap_or(&[]);
        let init_lamports = init_account.map(|a| a.lamports).unwrap_or(0);
        let same_size = data.len() == init_data.len();

        let type_key = identity;

        // Field novelty: combined account×clock + lamports
        if do_field_novelty {
            if slot_diff > 0 {
                field_novel_count += check_and_set_bit_atomic(
                    field_bitmap_ptr,
                    total_bits,
                    field_hash(type_key, LAMPORTS_SENTINEL - 1, sdb),
                );
            }
            field_novel_count += check_and_set_bit_atomic(
                field_bitmap_ptr,
                total_bits,
                field_hash(type_key, LAMPORTS_SENTINEL, value_bucket(lamports)),
            );
        }

        // Walk bytes for changed regions: fingerprint + field novelty + patch collection
        let min_len = hash_data.len().min(init_data.len());
        let mut any_diff = false;
        let mut i = 0usize;
        while i < min_len {
            if hash_data[i] != init_data[i] {
                any_diff = true;
                let start = i;
                while i < min_len && hash_data[i] != init_data[i] {
                    i += 1;
                }
                let val = read_region_value(&hash_data[start..i]);
                let vb = value_bucket(val);
                (start as u32, vb).hash(&mut hasher);
                if do_field_novelty {
                    field_novel_count += check_and_set_bit_atomic(
                        field_bitmap_ptr,
                        total_bits,
                        field_hash(type_key, start as u32, vb),
                    );
                }
            } else {
                i += 1;
            }
        }
        if hash_data.len() > min_len {
            any_diff = true;
            let mut i = min_len;
            while i < hash_data.len() {
                if hash_data[i] != 0 {
                    let start = i;
                    while i < hash_data.len() && hash_data[i] != 0 {
                        i += 1;
                    }
                    let val = read_region_value(&hash_data[start..i]);
                    let vb = value_bucket(val);
                    (start as u32, vb).hash(&mut hasher);
                    if do_field_novelty {
                        field_novel_count += check_and_set_bit_atomic(
                            field_bitmap_ptr,
                            total_bits,
                            field_hash(type_key, start as u32, vb),
                        );
                    }
                } else {
                    i += 1;
                }
            }
        }
        if !same_size {
            any_diff = true;
            (min_len as u32, value_bucket(data.len() as u64)).hash(&mut hasher);
            if do_field_novelty {
                field_novel_count += check_and_set_bit_atomic(
                    field_bitmap_ptr,
                    total_bits,
                    field_hash(type_key, min_len as u32, value_bucket(data.len() as u64)),
                );
            }
        }
        if lamports != init_lamports {
            any_diff = true;
        }
        // Metadata changes must use Full (Diff only stores lamports + data).
        let cur_owner = owner;
        let init_owner = init_account.map(|a| a.owner).unwrap_or_default();
        let cur_executable = executable;
        let init_executable = init_account.map(|a| a.executable).unwrap_or(false);
        let cur_rent_epoch = rent_epoch;
        let init_rent_epoch = init_account.map(|a| a.rent_epoch).unwrap_or(0);
        let metadata_changed = cur_owner != init_owner
            || cur_executable != init_executable
            || cur_rent_epoch != init_rent_epoch;
        if metadata_changed {
            any_diff = true;
        }

        // Field novelty: per-identity and per-identity×clock
        if do_field_novelty {
            let mut id_hasher = FxHasher::default();
            identity.hash(&mut id_hasher);
            value_bucket(lamports).hash(&mut id_hasher);
            value_bucket(data.len() as u64).hash(&mut id_hasher);
            field_novel_count +=
                check_and_set_bit_atomic(field_bitmap_ptr, total_bits, id_hasher.finish());

            if slot_diff > 0 {
                let mut id_clock_hasher = FxHasher::default();
                identity.hash(&mut id_clock_hasher);
                value_bucket(lamports).hash(&mut id_clock_hasher);
                sdb.hash(&mut id_clock_hasher);
                field_novel_count += check_and_set_bit_atomic(
                    field_bitmap_ptr,
                    total_bits,
                    id_clock_hasher.finish(),
                );
            }
        }

        if any_diff {
            // Build patch while data/init_data are still borrowed, then consume account
            // Use Diff only when size and all metadata are unchanged; otherwise Full.
            let patch = if same_size && init_account.is_some() && !metadata_changed {
                // Same-size account: build u64-word diff
                let mut patches = Vec::new();
                let num_full_words = data.len() / 8;
                for wi in 0..num_full_words {
                    let off = wi * 8;
                    let init_word = u64::from_le_bytes(init_data[off..off + 8].try_into().unwrap());
                    let cur_word = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
                    if init_word != cur_word {
                        patches.push((wi as u32, cur_word));
                    }
                }
                // Tail bytes
                let tail_start = num_full_words * 8;
                if tail_start < data.len() {
                    let mut init_tail = [0u8; 8];
                    let mut cur_tail = [0u8; 8];
                    let tail_len = data.len() - tail_start;
                    init_tail[..tail_len].copy_from_slice(&init_data[tail_start..]);
                    cur_tail[..tail_len].copy_from_slice(&data[tail_start..]);
                    if init_tail != cur_tail {
                        patches.push((num_full_words as u32, u64::from_le_bytes(cur_tail)));
                    }
                }
                Some(AccountPatch::Diff { lamports, patches })
            } else {
                None // will use Full below
            };
            // Now data borrow is released — safe to consume account
            if let Some(patch) = patch {
                changed.insert(**pubkey, patch);
            } else if let Some(acct) = account {
                changed.insert(**pubkey, AccountPatch::Full(Arc::new(acct)));
            } else {
                // Deleted account: was in initial but now absent from SVM.
                // Store a zero-lamport tombstone so restore correctly zeroes it.
                changed.insert(
                    **pubkey,
                    AccountPatch::Full(Arc::new(Account {
                        lamports: 0,
                        ..Default::default()
                    })),
                );
            }
        }
    }

    // Field novelty: combined set of dirty account identities (stable across
    // runs, unlike raw pubkeys of accounts created during fuzzing)
    if do_field_novelty && sorted_dirty.len() > 1 {
        let mut set_hasher = FxHasher::default();
        for identity in &identities {
            identity.hash(&mut set_hasher);
        }
        field_novel_count +=
            check_and_set_bit_atomic(field_bitmap_ptr, total_bits, set_hasher.finish());

        if slot_diff > 0 {
            let mut set_clock_hasher = FxHasher::default();
            for identity in &identities {
                identity.hash(&mut set_clock_hasher);
            }
            sdb.hash(&mut set_clock_hasher);
            field_novel_count +=
                check_and_set_bit_atomic(field_bitmap_ptr, total_bits, set_clock_hasher.finish());
        }
    }

    (hasher.finish(), changed, field_novel_count)
}

/// Derive a u64 key from a pubkey for per-account identity in novelty/fingerprint hashing.
/// Uses the first 8 bytes of the pubkey as a fast, collision-resistant key.
#[inline]
fn pubkey_key(pubkey: &Pubkey) -> u64 {
    u64::from_le_bytes(pubkey.to_bytes()[0..8].try_into().unwrap())
}

/// Size of the field novelty bitmap in bytes (128KB = 1M bits).
/// Tracks per-(account, offset, value_bucket) combinations for fine-grained
/// state novelty detection.
pub const FIELD_NOVELTY_BITMAP_SIZE: usize = 1 << 17;

// ============================================================================
// Per-Field Novelty — diff each account against initial, track changed regions
// ============================================================================

/// Sentinel offset for lamports novelty (cannot collide with real data offsets).
const LAMPORTS_SENTINEL: u32 = u32::MAX;

/// Type key for clock sysvar novelty (cannot collide with real account type keys).
const CLOCK_TYPE_KEY: u64 = u64::MAX - 1;

/// Read a changed byte region as a u64 value for bucketing.
/// Short regions are read as native integers; long regions are hashed.
#[inline]
fn read_region_value(region: &[u8]) -> u64 {
    match region.len() {
        0 => 0,
        1 => region[0] as u64,
        2 => u16::from_le_bytes(region[0..2].try_into().unwrap()) as u64,
        3..=4 => {
            let mut buf = [0u8; 4];
            buf[..region.len()].copy_from_slice(region);
            u32::from_le_bytes(buf) as u64
        }
        5..=8 => {
            let mut buf = [0u8; 8];
            buf[..region.len()].copy_from_slice(region);
            u64::from_le_bytes(buf)
        }
        _ => {
            // Hash longer regions (pubkeys, byte arrays, etc.)
            let mut h = FxHasher::default();
            region.hash(&mut h);
            h.finish()
        }
    }
}

/// Combine (account_type_key, offset, value_bucket) into a hash for bitmap indexing.
#[inline]
fn field_hash(type_key: u64, offset: u32, bucket: u8) -> u64 {
    let mut h = FxHasher::default();
    type_key.hash(&mut h);
    offset.hash(&mut h);
    bucket.hash(&mut h);
    h.finish()
}

/// Atomically check and set a bit in a bitmap. Returns 1 if the bit was new, 0 otherwise.
///
/// Uses `AtomicU8::fetch_or` with `Relaxed` ordering — negligible overhead on
/// uncontended cache lines, so the same function works for both singlecore and multicore.
///
/// # Safety
/// `bitmap_ptr` must point to a valid region of at least `ceil(total_bits/8)` bytes.
#[inline]
unsafe fn check_and_set_bit_atomic(bitmap_ptr: *mut u8, total_bits: usize, hash: u64) -> u32 {
    use std::sync::atomic::{AtomicU8, Ordering};
    let idx = hash as usize % total_bits;
    let byte_ptr = bitmap_ptr.add(idx / 8) as *const AtomicU8;
    let bit_mask = 1u8 << (idx % 8);
    let prev = (*byte_ptr).fetch_or(bit_mask, Ordering::Relaxed);
    if prev & bit_mask == 0 {
        1
    } else {
        0
    }
}

/// Check per-field state novelty by diffing each dirty account against initial state.
///
/// For each dirty account, walks bytes to find contiguous changed regions (runs of
/// differing bytes), classifies each by size → integer type, reads the value, and
/// checks if `(account_type, offset, value_bucket(value))` has been seen before.
///
/// Uses atomic bitmap operations so the same function works for both singlecore
/// (local `&mut [u8]`) and multicore (shared `*mut u8`) modes.
///
/// Returns the count of novel (previously-unseen) field states.
///
/// # Safety
/// `bitmap_ptr` must point to a valid region of `bitmap_len` bytes.
/// For multicore, this region must be shared memory accessed only via atomics.
pub unsafe fn check_field_novelty(
    svm: &LiteSVM,
    dirty: &super::DirtyTracker,
    initial: &SvmSnapshot,
    bitmap_ptr: *mut u8,
    bitmap_len: usize,
) -> u32 {
    debug_assert_eq!(
        bitmap_len, FIELD_NOVELTY_BITMAP_SIZE,
        "check_field_novelty: bitmap_len ({}) must equal FIELD_NOVELTY_BITMAP_SIZE ({})",
        bitmap_len, FIELD_NOVELTY_BITMAP_SIZE
    );
    let mut novel_count: u32 = 0;
    let total_bits = bitmap_len * 8;

    // Read clock once for both clock novelty and combined account×clock novelty.
    let clock: Clock = svm.get_sysvar();
    let initial_clock = initial.clock();
    let slot_diff = clock.slot.saturating_sub(initial_clock.slot);
    let sdb = slot_diff_bucket(slot_diff);

    // Detect clock changes by comparing against initial snapshot.
    // This catches ALL clock modifications regardless of how the harness sets
    // the clock (ctx.advance_slots, svm.set_sysvar, etc.) without relying on
    // DirtyTracker's clock_dirty flag.
    if slot_diff > 0 || clock.epoch != initial_clock.epoch {
        novel_count +=
            check_and_set_bit_atomic(bitmap_ptr, total_bits, field_hash(CLOCK_TYPE_KEY, 0, sdb));
        novel_count += check_and_set_bit_atomic(
            bitmap_ptr,
            total_bits,
            field_hash(CLOCK_TYPE_KEY, 1, value_bucket(clock.epoch)),
        );

        // If the harness explicitly called warp_to_slot/advance_slots, use the exact
        // target slot for novelty. Each distinct clock advance is a unique state —
        // "advance to slot 3000" and "advance to slot 50000" produce different program
        // behavior (e.g., epoch-dependent stake activation) even if their slot_diff_bucket
        // is the same. Use slot_bucket (not slot_diff_bucket) for finer discrimination.
        if let Some(target) = dirty.clock_target_slot {
            novel_count += check_and_set_bit_atomic(
                bitmap_ptr,
                total_bits,
                field_hash(CLOCK_TYPE_KEY, 2, slot_bucket(target)),
            );
        }
    }

    // Collect pubkeys for combined set novelty (computed after per-account loop).
    let mut __dirty_pubkeys: Vec<&Pubkey> = Vec::with_capacity(dirty.dirty_accounts().len());

    for pubkey in dirty.dirty_accounts() {
        let account = svm.get_account(pubkey);
        let cur_data = account.as_ref().map(|a| a.data.as_slice()).unwrap_or(&[]);
        let cur_lamports = account.as_ref().map(|a| a.lamports).unwrap_or(0);

        // Per-pubkey identity key: each account tracked individually.
        let type_key = pubkey_key(pubkey);
        __dirty_pubkeys.push(pubkey);

        // Combined account×clock novelty: "this account is dirty at this time depth."
        if slot_diff > 0 {
            novel_count += check_and_set_bit_atomic(
                bitmap_ptr,
                total_bits,
                field_hash(type_key, LAMPORTS_SENTINEL - 1, sdb),
            );
        }

        // Check lamports novelty
        novel_count += check_and_set_bit_atomic(
            bitmap_ptr,
            total_bits,
            field_hash(type_key, LAMPORTS_SENTINEL, value_bucket(cur_lamports)),
        );

        let init_data = initial
            .accounts
            .get(pubkey)
            .map(|a| a.data.as_slice())
            .unwrap_or(&[]);

        // Walk bytes, find contiguous changed regions
        let min_len = cur_data.len().min(init_data.len());
        let mut i = 0usize;
        while i < min_len {
            if cur_data[i] != init_data[i] {
                let start = i;
                while i < min_len && cur_data[i] != init_data[i] {
                    i += 1;
                }
                let val = read_region_value(&cur_data[start..i]);
                novel_count += check_and_set_bit_atomic(
                    bitmap_ptr,
                    total_bits,
                    field_hash(type_key, start as u32, value_bucket(val)),
                );
            } else {
                i += 1;
            }
        }

        // Handle data beyond init_data (new/grown accounts): diff against zero.
        // Without this, two new accounts of the same type with same lamports/length
        // but different data would produce identical novelty contributions.
        if cur_data.len() > min_len {
            let mut i = min_len;
            while i < cur_data.len() {
                if cur_data[i] != 0 {
                    let start = i;
                    while i < cur_data.len() && cur_data[i] != 0 {
                        i += 1;
                    }
                    let val = read_region_value(&cur_data[start..i]);
                    novel_count += check_and_set_bit_atomic(
                        bitmap_ptr,
                        total_bits,
                        field_hash(type_key, start as u32, value_bucket(val)),
                    );
                } else {
                    i += 1;
                }
            }
        }

        // Trailing bytes (account grew or shrank) — resize signal
        if cur_data.len() != init_data.len() {
            novel_count += check_and_set_bit_atomic(
                bitmap_ptr,
                total_bits,
                field_hash(
                    type_key,
                    min_len as u32,
                    value_bucket(cur_data.len() as u64),
                ),
            );
        }

        // Per-identity novelty: (pubkey, lamports_bucket, data_len_bucket)
        // Distinguishes individual accounts, not just account types.
        // "stake_account_A at 64B lamports" is distinct from "stake_account_B at 64B lamports".
        {
            let mut id_hasher = FxHasher::default();
            pubkey.hash(&mut id_hasher);
            value_bucket(cur_lamports).hash(&mut id_hasher);
            value_bucket(cur_data.len() as u64).hash(&mut id_hasher);
            novel_count += check_and_set_bit_atomic(bitmap_ptr, total_bits, id_hasher.finish());
        }

        // Per-identity × clock: "this specific account at this time depth."
        // Captures "stake_account_A delegated + epoch 7" as distinct from epoch 0.
        if slot_diff > 0 {
            let mut id_clock_hasher = FxHasher::default();
            pubkey.hash(&mut id_clock_hasher);
            value_bucket(cur_lamports).hash(&mut id_clock_hasher);
            sdb.hash(&mut id_clock_hasher);
            novel_count +=
                check_and_set_bit_atomic(bitmap_ptr, total_bits, id_clock_hasher.finish());
        }
    }

    // Combined set novelty: hash the sorted set of dirty pubkeys together.
    // "{stake_A, stake_B, vote_V} dirty together" is distinct from
    // "{stake_A, stake_C, vote_V} dirty together", unlike the old type_key
    // approach which collapsed all accounts of the same type.
    if __dirty_pubkeys.len() > 1 {
        __dirty_pubkeys.sort();
        let mut set_hasher = FxHasher::default();
        for pk in &__dirty_pubkeys {
            pk.hash(&mut set_hasher);
        }
        novel_count += check_and_set_bit_atomic(bitmap_ptr, total_bits, set_hasher.finish());

        // Combined set × clock: same pubkey combination at a different
        // time depth is novel (e.g. {stake_A, vote_V} dirty at epoch 7 vs epoch 0).
        if slot_diff > 0 {
            let mut set_clock_hasher = FxHasher::default();
            for pk in &__dirty_pubkeys {
                pk.hash(&mut set_clock_hasher);
            }
            sdb.hash(&mut set_clock_hasher);
            novel_count +=
                check_and_set_bit_atomic(bitmap_ptr, total_bits, set_clock_hasher.finish());
        }
    }

    novel_count
}
