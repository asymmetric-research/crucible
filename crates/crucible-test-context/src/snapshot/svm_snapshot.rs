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

/// Number of bits in the final fingerprint for dedup. Controls novel rate:
/// - Too many bits → every state is "novel", pool grows unbounded
/// - Too few bits → states collapse, pool stays tiny
/// 17 bits = 128K possible fingerprints (16KB bitmap).
pub(super) const FINGERPRINT_BITS: u32 = 17;

/// Compute an absolute state fingerprint from the current SVM state.
///
/// Uses field-boundary-aware diffing against initial state for layout-aware bucketing.
/// The hash is truncated to FINGERPRINT_BITS for dedup (in StatePool::try_add)
/// while the full 64-bit value is kept for state_class action selection.
pub fn compute_state_fingerprint_from_snapshot(
    svm: &LiteSVM,
    dirty: &DirtyTracker,
    initial: &SvmSnapshot,
) -> u64 {
    let mut hasher = FxHasher::default();

    // Use differential slot: how much slot advanced from initial, not absolute value.
    let clock: Clock = svm.get_sysvar();
    let slot_diff = clock.slot.saturating_sub(initial.clock.slot);
    slot_diff_bucket(slot_diff).hash(&mut hasher);
    clock.epoch.hash(&mut hasher);

    if dirty.dirty_accounts().is_empty() {
        return hasher.finish();
    }

    // Hash account count first (different account sets = different state)
    (dirty.dirty_accounts().len() as u64).hash(&mut hasher);

    for pubkey in dirty.dirty_accounts() {
        let account = svm.get_account(pubkey);
        let lamports = account.as_ref().map(|a| a.lamports).unwrap_or(0);
        let data = account.as_ref().map(|a| a.data.as_slice()).unwrap_or(&[]);

        // Use account type key (discriminant) instead of pubkey prefix.
        // Collapses all accounts of the same type, so "has any Token account
        // reached balance bucket 5?" rather than per-account tracking.
        let type_key = account_type_key(data);
        type_key.hash(&mut hasher);

        // Hash absolute lamports bucket (not differential)
        value_bucket(lamports).hash(&mut hasher);

        // Hash data length bucket
        value_bucket(data.len() as u64).hash(&mut hasher);

        // Field-boundary-aware diffing: find contiguous changed regions vs initial
        let init_data = initial.accounts.get(pubkey).map(|a| a.data.as_slice()).unwrap_or(&[]);
        let min_len = data.len().min(init_data.len());
        let mut i = 0usize;
        while i < min_len {
            if data[i] != init_data[i] {
                let start = i;
                while i < min_len && data[i] != init_data[i] { i += 1; }
                let val = read_region_value(&data[start..i]);
                (start as u32, value_bucket(val)).hash(&mut hasher);
            } else {
                i += 1;
            }
        }
        // Handle data beyond init_data (new/grown accounts): diff against zero.
        // Without this, two new accounts of the same type with same lamports/length
        // but different data would produce identical fingerprints.
        if data.len() > min_len {
            let mut i = min_len;
            while i < data.len() {
                if data[i] != 0 {
                    let start = i;
                    while i < data.len() && data[i] != 0 { i += 1; }
                    let val = read_region_value(&data[start..i]);
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

/// Extract account type key from account data.
///
/// Accounts with ≥8 bytes: first 8 bytes = Anchor discriminant (sha256 of type name).
/// SPL Token accounts (165 bytes, no Anchor disc): first 8 bytes = mint pubkey prefix → groups by mint.
/// Accounts with <8 bytes: hash(data_len, available_bytes) as discriminant.
/// Empty/zero accounts: fixed sentinel value (0).
#[inline]
fn account_type_key(data: &[u8]) -> u64 {
    if data.len() >= 8 {
        u64::from_le_bytes(data[0..8].try_into().unwrap())
    } else if data.is_empty() {
        0
    } else {
        let mut h = FxHasher::default();
        (data.len() as u64).hash(&mut h);
        data.hash(&mut h);
        h.finish()
    }
}

/// Size of the account novelty bitmap in bytes (64KB = 512K bits).
pub const ACCOUNT_NOVELTY_BITMAP_SIZE: usize = 1 << 16;

/// Size of the field novelty bitmap in bytes (128KB = 1M bits).
/// Tracks per-(account, offset, value_bucket) combinations for fine-grained
/// state novelty detection.
pub const FIELD_NOVELTY_BITMAP_SIZE: usize = 1 << 17;

/// Maximum number of u64 words to sample per account for novelty checking.
const NOVELTY_WORDS_PER_ACCOUNT: usize = 8;

/// Check per-account state novelty using exponential bucketing.
///
/// For each dirty account, exponentially bins the absolute lamports, data length,
/// and sampled data words using `value_bucket()`. The combination is hashed per-account
/// into a bitmap position. Returns the count of novel (previously-unseen) account states.
///
/// Uses atomic bitmap operations so the same function works for both singlecore
/// (local `&mut [u8]`) and multicore (shared `*mut u8`) modes.
///
/// # Safety
/// `bitmap_ptr` must point to a valid region of `bitmap_len` bytes.
/// For multicore, this region must be shared memory accessed only via atomics.
pub unsafe fn check_account_state_novelty(
    svm: &LiteSVM,
    dirty: &super::DirtyTracker,
    bitmap_ptr: *mut u8,
    bitmap_len: usize,
) -> u32 {
    let mut novel_count: u32 = 0;
    let total_bits = bitmap_len * 8;

    for pubkey in dirty.dirty_accounts() {
        let account = svm.get_account(pubkey);
        let lamports = account.as_ref().map(|a| a.lamports).unwrap_or(0);
        let data = account.as_ref().map(|a| a.data.as_slice()).unwrap_or(&[]);

        let h = account_state_hash(lamports, data);
        novel_count += check_and_set_bit_atomic(bitmap_ptr, total_bits, h);
    }

    novel_count
}

/// Hash an account's type + exponentially-binned state into a single u64.
/// Used by both local and atomic novelty checks.
#[inline]
fn account_state_hash(lamports: u64, data: &[u8]) -> u64 {
    let mut hasher = FxHasher::default();

    // Account type key (discriminant) instead of pubkey prefix
    account_type_key(data).hash(&mut hasher);

    // Exponentially binned absolute state fields
    value_bucket(lamports).hash(&mut hasher);
    value_bucket(data.len() as u64).hash(&mut hasher);

    // Sample evenly-spaced data words, each exponentially binned.
    let total_words = data.len() / 8;
    if total_words > 0 {
        let sample_count = total_words.min(NOVELTY_WORDS_PER_ACCOUNT);
        for i in 0..sample_count {
            let word_idx = if sample_count < total_words {
                i * total_words / sample_count
            } else {
                i
            };
            let pos = word_idx * 8;
            let val = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            value_bucket(val).hash(&mut hasher);
        }
    }

    hasher.finish()
}

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
    if prev & bit_mask == 0 { 1 } else { 0 }
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
    let mut novel_count: u32 = 0;
    let total_bits = bitmap_len * 8;

    // Read clock once for both clock novelty and combined account×clock novelty.
    let clock: Clock = svm.get_sysvar();
    let slot_diff = clock.slot.saturating_sub(initial.clock.slot);
    let sdb = slot_diff_bucket(slot_diff);

    // Detect clock changes by comparing against initial snapshot.
    // This catches ALL clock modifications regardless of how the harness sets
    // the clock (ctx.advance_slots, svm.set_sysvar, etc.) without relying on
    // DirtyTracker's clock_dirty flag.
    if slot_diff > 0 || clock.epoch != initial.clock.epoch {
        novel_count += check_and_set_bit_atomic(
            bitmap_ptr, total_bits,
            field_hash(CLOCK_TYPE_KEY, 0, sdb),
        );
        novel_count += check_and_set_bit_atomic(
            bitmap_ptr, total_bits,
            field_hash(CLOCK_TYPE_KEY, 1, value_bucket(clock.epoch)),
        );
    }

    // Collect pubkeys for combined set novelty (computed after per-account loop).
    let mut __dirty_pubkeys: Vec<&Pubkey> = Vec::with_capacity(dirty.dirty_accounts().len());

    for pubkey in dirty.dirty_accounts() {
        let account = svm.get_account(pubkey);
        let cur_data = account.as_ref().map(|a| a.data.as_slice()).unwrap_or(&[]);
        let cur_lamports = account.as_ref().map(|a| a.lamports).unwrap_or(0);

        // Use account type key (discriminant) instead of pubkey prefix
        let type_key = account_type_key(cur_data);
        __dirty_pubkeys.push(pubkey);

        // Combined account×clock novelty: "this account type is dirty at this time depth."
        // Captures cross-product states like "Stake account modified + epoch 7" that are
        // novel even when each dimension was seen independently.
        // Cost: ~16 account types × ~31 slot buckets = ~500 combinations (trivial).
        if slot_diff > 0 {
            novel_count += check_and_set_bit_atomic(
                bitmap_ptr, total_bits,
                field_hash(type_key, LAMPORTS_SENTINEL - 1, sdb),
            );
        }

        // Check lamports novelty
        novel_count += check_and_set_bit_atomic(
            bitmap_ptr, total_bits,
            field_hash(type_key, LAMPORTS_SENTINEL, value_bucket(cur_lamports)),
        );

        let init_data = initial.accounts.get(pubkey)
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
                    bitmap_ptr, total_bits,
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
                    while i < cur_data.len() && cur_data[i] != 0 { i += 1; }
                    let val = read_region_value(&cur_data[start..i]);
                    novel_count += check_and_set_bit_atomic(
                        bitmap_ptr, total_bits,
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
                bitmap_ptr, total_bits,
                field_hash(type_key, min_len as u32, value_bucket(cur_data.len() as u64)),
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
            novel_count += check_and_set_bit_atomic(
                bitmap_ptr, total_bits, id_hasher.finish(),
            );
        }

        // Per-identity × clock: "this specific account at this time depth."
        // Captures "stake_account_A delegated + epoch 7" as distinct from epoch 0.
        if slot_diff > 0 {
            let mut id_clock_hasher = FxHasher::default();
            pubkey.hash(&mut id_clock_hasher);
            value_bucket(cur_lamports).hash(&mut id_clock_hasher);
            sdb.hash(&mut id_clock_hasher);
            novel_count += check_and_set_bit_atomic(
                bitmap_ptr, total_bits, id_clock_hasher.finish(),
            );
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
        novel_count += check_and_set_bit_atomic(
            bitmap_ptr, total_bits, set_hasher.finish(),
        );

        // Combined set × clock: same pubkey combination at a different
        // time depth is novel (e.g. {stake_A, vote_V} dirty at epoch 7 vs epoch 0).
        if slot_diff > 0 {
            let mut set_clock_hasher = FxHasher::default();
            for pk in &__dirty_pubkeys {
                pk.hash(&mut set_clock_hasher);
            }
            sdb.hash(&mut set_clock_hasher);
            novel_count += check_and_set_bit_atomic(
                bitmap_ptr, total_bits, set_clock_hasher.finish(),
            );
        }
    }

    novel_count
}

