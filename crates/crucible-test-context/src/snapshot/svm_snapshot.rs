use crate::{FastHashMap, FastHashSet};
use anchor_lang::prelude::Clock;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use rustc_hash::FxHasher;

use super::dirty_tracker::DirtyTracker;

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
    /// Full Clock sysvar at snapshot time.
    pub(crate) clock: Clock,
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

/// Fine-grained value bucketing (11 buckets: 0-10).
///
/// Finer than the old `log2_bucket` at low values where distinct token
/// amounts, user counts, and small balances need to produce different
/// fingerprints. Collapses large values (>1B) since the exact magnitude
/// rarely matters for state novelty.
///
/// Buckets: 0=zero, 1=one, 2=two, 3=3-10, 4=11-100, 5=101-1K,
///          6=1K-10K, 7=10K-100K, 8=100K-1M, 9=1M-1B, 10=>1B
#[inline]
pub fn value_bucket(val: u64) -> u8 {
    match val {
        0 => 0,
        1 => 1,
        2 => 2,
        3..=10 => 3,
        11..=100 => 4,
        101..=1_000 => 5,
        1_001..=10_000 => 6,
        10_001..=100_000 => 7,
        100_001..=1_000_000 => 8,
        1_000_001..=1_000_000_000 => 9,
        _ => 10,
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
        1..=9 => val as u8,                                        // buckets 1-9 (individual)
        10..=99 => 9 + (val / 10) as u8,                           // buckets 10-18 (per-10)
        100..=999 => 18 + (val / 100) as u8,                       // buckets 19-27 (per-100)
        1_000..=9_999 => 27 + (val / 1_000) as u8,                 // buckets 28-36 (per-1K)
        10_000..=99_999 => 36 + (val / 10_000) as u8,              // buckets 37-45 (per-10K)
        100_000..=999_999 => 45 + (val / 100_000) as u8,           // buckets 46-54 (per-100K)
        1_000_000..=9_999_999 => 54 + (val / 1_000_000) as u8,     // buckets 55-63 (per-1M)
        _ => 64,                                                    // 10M+ overflow
    }
}

/// Differential bucketing for slot changes from initial (~31 buckets).
/// Buckets: 0-9 individual, 10-90 per-10, 100-900 per-100, 1000-2000 per-1000, >2000 overflow.
#[inline]
pub fn slot_diff_bucket(diff: u64) -> u8 {
    match diff {
        0..=9 => diff as u8,                          // buckets 0-9
        10..=99 => 9 + (diff / 10) as u8,             // buckets 10-18
        100..=999 => 18 + (diff / 100) as u8,         // buckets 19-27
        1000..=2000 => 27 + (diff / 1000) as u8,      // buckets 28-29
        _ => 30,                                       // overflow
    }
}

/// Differential bucketing for lamports changes from initial (~65 buckets).
/// Same as slot_diff_bucket but extends to larger magnitudes for lamport amounts.
#[inline]
pub fn lamports_diff_bucket(diff: u64) -> u8 {
    match diff {
        0..=9 => diff as u8,                              // 0-9
        10..=99 => 9 + (diff / 10) as u8,                 // 10-18
        100..=999 => 18 + (diff / 100) as u8,              // 19-27
        1000..=9999 => 27 + (diff / 1000) as u8,           // 28-36
        10_000..=99_999 => 36 + (diff / 10_000) as u8,     // 37-45
        100_000..=999_999 => 45 + (diff / 100_000) as u8,  // 46-54
        1_000_000..=9_999_999 => 54 + (diff / 1_000_000) as u8, // 55-63
        _ => 64,                                            // overflow
    }
}

/// Number of bits in the final fingerprint for dedup. Controls novel rate:
/// - Too many bits → every state is "novel", pool grows unbounded
/// - Too few bits → states collapse, pool stays tiny
/// 16 bits = 64K possible fingerprints (8KB bitmap).
pub(super) const FINGERPRINT_BITS: u32 = 16;

/// Maximum number of u64 words to sample per account for fingerprinting.
const FINGERPRINT_WORDS_PER_ACCOUNT: usize = 12;

/// Compute an absolute state fingerprint from the current SVM state.
///
/// Samples evenly-spaced u64 words per dirty account with coarse bucketing.
/// The hash is truncated to FINGERPRINT_BITS for dedup (in StatePool::try_add)
/// while the full 64-bit value is kept for state_class action selection.
pub fn compute_state_fingerprint_from_snapshot(
    svm: &LiteSVM,
    dirty: &DirtyTracker,
    initial: &SvmSnapshot,
) -> u64 {
    // Hash each dirty account into a FxHasher.
    // Every u64 word is bucketed and hashed with its position index, giving
    // full visibility into account data changes.
    let mut hasher = FxHasher::default();

    // Use differential slot: how much slot advanced from initial, not absolute value.
    // This makes the fingerprint capture the *change* rather than the absolute slot,
    // which is much more meaningful for state novelty detection.
    let clock: Clock = svm.get_sysvar();
    let slot_diff = clock.slot.saturating_sub(initial.clock.slot);
    slot_diff_bucket(slot_diff).hash(&mut hasher);
    clock.epoch.hash(&mut hasher);

    if dirty.dirty_accounts().is_empty() {
        // Only clock state changed — return a non-zero fingerprint
        // so the state gets considered for pool addition.
        return hasher.finish();
    }

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

        // Hash lamports differential bucket (change from initial)
        let initial_lamports = initial.accounts.get(pubkey).map(|a| a.lamports).unwrap_or(0);
        let lamports_diff = (lamports as i128 - initial_lamports as i128).unsigned_abs() as u64;
        lamports_diff_bucket(lamports_diff).hash(&mut hasher);

        // Hash data length bucket
        value_bucket(data.len() as u64).hash(&mut hasher);

        // Hash sampled data words with coarse bucketing.
        // Evenly-spaced sampling captures structure without hashing every byte.
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
                (word_idx as u16, value_bucket(val)).hash(&mut hasher);
            }
        }
    }

    hasher.finish()
}

/// Size of the state coverage bitmap in bytes (64KB — same as edge coverage map).
pub const STATE_COV_BITMAP_SIZE: usize = 1 << 16;

/// Check state coverage: slot bucket and per-account lamports buckets.
///
/// Hashes each novel (slot_bucket) and (pubkey, lamports_bucket) pair into
/// bit positions in `bitmap`. Returns the number of new bits set (0 = no novelty).
///
/// This gives stateful mode a coverage signal for state transitions that
/// mirrors the hitcount bucketing used for code edges: a new lamports bucket
/// or slot bucket counts as "new coverage" and triggers pool addition.
pub fn check_state_coverage(
    svm: &LiteSVM,
    dirty: &super::DirtyTracker,
    initial: &SvmSnapshot,
    bitmap: &mut [u8],
) -> u32 {
    let mut novel_bits: u32 = 0;

    // Slot differential bucket
    let clock: Clock = svm.get_sysvar();
    let slot_diff = clock.slot.saturating_sub(initial.clock.slot);
    let sb = slot_diff_bucket(slot_diff) as usize;
    let h = sb.wrapping_mul(0x9e3779b9) % (bitmap.len() * 8);
    let byte_idx = h / 8;
    let bit_mask = 1u8 << (h % 8);
    if bitmap[byte_idx] & bit_mask == 0 {
        bitmap[byte_idx] |= bit_mask;
        novel_bits += 1;
    }

    // Per-account lamports differential buckets
    for pubkey in dirty.dirty_accounts() {
        let account = svm.get_account(pubkey);
        let lamports = account.as_ref().map(|a| a.lamports).unwrap_or(0);
        let initial_lamports = initial.accounts.get(pubkey).map(|a| a.lamports).unwrap_or(0);
        let lamports_diff = (lamports as i128 - initial_lamports as i128).unsigned_abs() as u64;
        let lb = lamports_diff_bucket(lamports_diff) as usize;
        let pk_bytes = pubkey.as_ref();
        let pk_prefix = u32::from_le_bytes(pk_bytes[0..4].try_into().unwrap()) as usize;
        let h = pk_prefix.wrapping_mul(0x9e3779b9) ^ lb.wrapping_mul(0x517cc1b7);
        let h = h % (bitmap.len() * 8);
        let byte_idx = h / 8;
        let bit_mask = 1u8 << (h % 8);
        if bitmap[byte_idx] & bit_mask == 0 {
            bitmap[byte_idx] |= bit_mask;
            novel_bits += 1;
        }
    }

    novel_bits
}

/// Atomic variant of [`check_state_coverage`] for multicore mode.
///
/// Uses `AtomicU8::fetch_or` on a shared bitmap so that only one worker
/// "wins" each novel bit — preventing N× duplicate state additions.
///
/// # Safety
/// `bitmap_ptr` must point to a valid, shared-memory region of `bitmap_len` bytes
/// that is only accessed via atomic operations.
pub unsafe fn check_state_coverage_atomic(
    svm: &LiteSVM,
    dirty: &super::DirtyTracker,
    initial: &SvmSnapshot,
    bitmap_ptr: *mut u8,
    bitmap_len: usize,
) -> u32 {
    use std::sync::atomic::{AtomicU8, Ordering};

    let mut novel_bits: u32 = 0;
    let total_bits = bitmap_len * 8;

    // Slot differential bucket
    let clock: Clock = svm.get_sysvar();
    let slot_diff = clock.slot.saturating_sub(initial.clock.slot);
    let sb = slot_diff_bucket(slot_diff) as usize;
    let h = sb.wrapping_mul(0x9e3779b9) % total_bits;
    let byte_idx = h / 8;
    let bit_mask = 1u8 << (h % 8);
    let byte_ptr = bitmap_ptr.add(byte_idx) as *const AtomicU8;
    let prev = (*byte_ptr).fetch_or(bit_mask, Ordering::Relaxed);
    if prev & bit_mask == 0 {
        novel_bits += 1;
    }

    // Per-account lamports differential buckets
    for pubkey in dirty.dirty_accounts() {
        let account = svm.get_account(pubkey);
        let lamports = account.as_ref().map(|a| a.lamports).unwrap_or(0);
        let initial_lamports = initial.accounts.get(pubkey).map(|a| a.lamports).unwrap_or(0);
        let lamports_diff = (lamports as i128 - initial_lamports as i128).unsigned_abs() as u64;
        let lb = lamports_diff_bucket(lamports_diff) as usize;
        let pk_bytes = pubkey.as_ref();
        let pk_prefix = u32::from_le_bytes(pk_bytes[0..4].try_into().unwrap()) as usize;
        let h = pk_prefix.wrapping_mul(0x9e3779b9) ^ lb.wrapping_mul(0x517cc1b7);
        let h = h % total_bits;
        let byte_idx = h / 8;
        let bit_mask = 1u8 << (h % 8);
        let byte_ptr = bitmap_ptr.add(byte_idx) as *const AtomicU8;
        let prev = (*byte_ptr).fetch_or(bit_mask, Ordering::Relaxed);
        if prev & bit_mask == 0 {
            novel_bits += 1;
        }
    }

    novel_bits
}

