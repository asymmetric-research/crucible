use crate::{FastHashMap, FastHashSet};
use anchor_lang::prelude::{Clock, EpochSchedule, SlotHashes, SlotHistory, StakeHistory};
use anchor_lang::prelude::sysvar::SysvarId;
use litesvm::LiteSVM;
use solana_account::{Account, ReadableAccount};
use solana_pubkey::Pubkey;
use solana_sysvar::epoch_rewards::EpochRewards;
use solana_sysvar::fees::Fees;
use solana_sysvar::last_restart_slot::LastRestartSlot;
use solana_sysvar::recent_blockhashes::RecentBlockhashes;
use solana_sysvar::rent::Rent;
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
        let mut count = 0;
        for pubkey in dirty.dirty_accounts() {
            match self.accounts.get(pubkey) {
                Some(original) => {
                    // Existed at snapshot — restore original (covers modified + deleted)
                    let _ = svm.set_account(*pubkey, (**original).clone());
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
        self.restore_sysvars(svm);
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
        for (pubkey, account) in &self.accounts {
            let _ = svm.set_account(*pubkey, (**account).clone());
        }
        self.restore_sysvars(svm);
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
                // Account was created during prev iteration but doesn't exist in initial — zero it.
                // Skip executable (program) accounts: zeroing them removes from accounts_db but
                // NOT from programs_cache, causing a desync that panics in litesvm (lib.rs:981).
                if let Some(existing) = svm.get_account(pubkey) {
                    if existing.executable {
                        continue;
                    }
                }
                let _ = svm.set_account(*pubkey, Account { lamports: 0, ..Default::default() });
            }
            count += 1;
        }

        // 2. Overlay delta (accounts that differ from initial in the target state)
        for (pubkey, account) in &delta.accounts {
            let _ = svm.set_account(*pubkey, (**account).clone());
            count += 1;
        }

        // 3. Restore sysvars from delta
        delta.restore_sysvars(svm);

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
                // Skip executable (program) accounts — see restore_selective comment.
                if let Some(existing) = svm.get_account(pubkey) {
                    if existing.executable {
                        continue;
                    }
                }
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

        // 3. Restore sysvars from next delta
        next_delta.restore_sysvars(svm);

        count
    }

    /// Get a reference to the internal accounts map.
    pub fn accounts(&self) -> &FastHashMap<Pubkey, Arc<Account>> {
        &self.accounts
    }

    /// Hash the SVM state for the accounts tracked by this snapshot.
    /// Used for save/restore verification: hash at save time, hash again after restore,
    /// if they differ the snapshot is lossy.
    pub fn hash_tracked_state(&self, svm: &LiteSVM) -> u64 {
        use std::hash::{Hash, Hasher};
        use rustc_hash::FxHasher;
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
            } else {
                0u8.hash(&mut hasher);
            }
        }
        hasher.finish()
    }

    /// Get the stored Clock sysvar by deserializing from sysvars.
    pub fn clock(&self) -> Clock {
        let clock_id = Clock::id();
        for (id, account) in &self.sysvars {
            if id == &clock_id {
                if let Some(acct) = account {
                    if let Ok(clock) = bincode::deserialize::<Clock>(&acct.data) {
                        return clock;
                    }
                }
            }
        }
        Clock::default()
    }

    /// Create an empty snapshot (no accounts differ from initial state).
    /// Used as the initial delta in the state pool.
    pub fn empty(clock: Clock) -> Self {
        let clock_data = bincode::serialize(&clock).unwrap_or_default();
        Self {
            accounts: FastHashMap::default(),
            sysvars: vec![(Clock::id(), Some(Account {
                lamports: 1,
                data: clock_data,
                owner: Pubkey::from_str_const("Sysvar1111111111111111111111111111111111111"),
                executable: false,
                rent_epoch: 0,
            }))],
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
        let sysvars = Self::take_sysvars(svm);
        Self { accounts, sysvars }
    }

    fn take_sysvars(svm: &LiteSVM) -> Vec<(Pubkey, Option<Account>)> {
        [
            Clock::id(),
            EpochRewards::id(),
            // EpochSchedule::id(),  // Static after genesis — no need to snapshot
            Fees::id(),
            LastRestartSlot::id(),
            RecentBlockhashes::id(),
            Rent::id(),
            // SlotHashes::id(),    // 20 KB — consensus/vote verification, not used by programs
            // SlotHistory::id(),   // 131 KB — slot occupancy bitvector, irrelevant for fuzzing
            StakeHistory::id(),
        ]
        .iter()
        .map(|sysvar| (*sysvar, svm.get_account(sysvar)))
        .collect()
    }

    fn restore_sysvars(&self, svm: &mut LiteSVM) -> usize {
        for (sysvar, account) in &self.sysvars {
            if let Some(acct) = account {
                let _ = svm.set_account(*sysvar, acct.clone());
            } else {
                let _ = svm.set_account(
                    *sysvar,
                    Account { lamports: 0, ..Default::default() },
                );
            }
        }
        self.sysvars.len()
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

/// Differential bucketing for slot changes from initial (~49 buckets).
/// Buckets: 0-9 individual, 10-99 per-10, 100-999 per-100, 1K-9K per-1K,
///          10K-99K per-10K, 100K-999K per-100K, ≥1M overflow.
#[inline]
pub fn slot_diff_bucket(diff: u64) -> u8 {
    match diff {
        0..=9 => diff as u8,                                // buckets 0-9
        10..=99 => 9 + (diff / 10) as u8,                   // buckets 10-18
        100..=999 => 18 + (diff / 100) as u8,               // buckets 19-27
        1_000..=9_999 => 27 + (diff / 1_000) as u8,         // buckets 28-36
        10_000..=99_999 => 36 + (diff / 10_000) as u8,      // buckets 37-45
        100_000..=999_999 => 45 + (diff / 100_000) as u8,   // buckets 46-54
        _ => 55,                                             // overflow (≥1M)
    }
}

/// Number of bits in the final fingerprint for dedup. Controls novel rate:
/// - Too many bits → every state is "novel", pool grows unbounded
/// - Too few bits → states collapse, pool stays tiny
/// 18 bits = 256K possible fingerprints (32KB bitmap).
pub(super) const FINGERPRINT_BITS: u32 = 18;

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
    let mut sorted_dirty: Vec<&Pubkey> = dirty.dirty_accounts().iter().collect();
    sorted_dirty.sort();

    // Hash account count first (different account sets = different state)
    (sorted_dirty.len() as u64).hash(&mut hasher);

    for pubkey in &sorted_dirty {
        let account = svm.get_account(pubkey);
        let lamports = account.as_ref().map(|a| a.lamports).unwrap_or(0);
        let data = account.as_ref().map(|a| a.data.as_slice()).unwrap_or(&[]);

        // Per-pubkey identity: each account is tracked individually.
        pubkey.hash(&mut hasher);

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
    let initial_clock = initial.clock();
    let slot_diff = clock.slot.saturating_sub(initial_clock.slot);
    let sdb = slot_diff_bucket(slot_diff);

    // Detect clock changes by comparing against initial snapshot.
    // This catches ALL clock modifications regardless of how the harness sets
    // the clock (ctx.advance_slots, svm.set_sysvar, etc.) without relying on
    // DirtyTracker's clock_dirty flag.
    if slot_diff > 0 || clock.epoch != initial_clock.epoch {
        novel_count += check_and_set_bit_atomic(
            bitmap_ptr, total_bits,
            field_hash(CLOCK_TYPE_KEY, 0, sdb),
        );
        novel_count += check_and_set_bit_atomic(
            bitmap_ptr, total_bits,
            field_hash(CLOCK_TYPE_KEY, 1, value_bucket(clock.epoch)),
        );

        // If the harness explicitly called warp_to_slot/advance_slots, use the exact
        // target slot for novelty. Each distinct clock advance is a unique state —
        // "advance to slot 3000" and "advance to slot 50000" produce different program
        // behavior (e.g., epoch-dependent stake activation) even if their slot_diff_bucket
        // is the same. Use slot_bucket (not slot_diff_bucket) for finer discrimination.
        if let Some(target) = dirty.clock_target_slot {
            novel_count += check_and_set_bit_atomic(
                bitmap_ptr, total_bits,
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

