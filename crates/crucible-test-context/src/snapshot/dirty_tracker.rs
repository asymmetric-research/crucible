use crate::{FastHashMap, FastHashSet};
use anchor_lang::solana_program::instruction::Instruction;
use solana_pubkey::Pubkey;

use super::svm_snapshot::SvmSnapshot;

/// Maps accounts created along a state's lineage to their **creation ordinal**:
/// the position in the deterministic creation sequence (0, 1, 2, …).
///
/// The state fingerprint must identify a newly-created account by its position
/// in the creation sequence, not its random pubkey — the Nth account created by
/// a replayed action sequence is the Nth in every run, even though its pubkey
/// differs each run. Accounts already present in the initial snapshot keep
/// pubkey identity (stable by construction) and never enter this tracker.
///
/// The tracker is **lineage-relative**: each saved pool state carries the
/// tracker covering all accounts created along its path from the initial state,
/// and each iteration extends its parent's tracker with the accounts it creates.
/// Ordinals are assigned in sequential first-write order (never from HashMap
/// iteration, whose order varies across processes).
#[derive(Clone, Default)]
pub struct CreationTracker {
    /// pubkey → creation ordinal. Keys are this process's pubkeys (valid for
    /// restore lookups); across processes the keys differ but the ordinals
    /// are identical, so fingerprints match.
    ordinals: FastHashMap<Pubkey, u32>,
    /// Next ordinal to assign.
    next: u32,
}

impl CreationTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creation ordinal for an account, if it was created along this lineage.
    #[inline]
    pub fn ordinal(&self, pubkey: &Pubkey) -> Option<u32> {
        self.ordinals.get(pubkey).copied()
    }

    /// Creation ordinal for a raw 32-byte pubkey, if it was created along this lineage.
    #[inline]
    pub fn ordinal_for_bytes(&self, bytes: &[u8]) -> Option<u32> {
        let bytes: [u8; 32] = bytes.try_into().ok()?;
        self.ordinal(&Pubkey::new_from_array(bytes))
    }

    pub(crate) fn pubkeys(&self) -> impl Iterator<Item = &Pubkey> {
        self.ordinals.keys()
    }

    /// Record an account creation, assigning the next ordinal.
    /// Idempotent: an already-tracked account keeps its original ordinal.
    pub fn observe(&mut self, pubkey: Pubkey) -> u32 {
        match self.ordinals.entry(pubkey) {
            std::collections::hash_map::Entry::Occupied(e) => *e.get(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let ord = self.next;
                e.insert(ord);
                self.next += 1;
                ord
            }
        }
    }

    /// Number of tracked creations.
    pub fn len(&self) -> usize {
        self.ordinals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ordinals.is_empty()
    }

    /// Build the tracker for the state reached this iteration: the parent
    /// state's tracker extended with accounts first written this iteration,
    /// in deterministic first-mark order, skipping accounts that exist in the
    /// initial snapshot (those keep pubkey identity).
    pub fn extended_with_iteration(
        base: &CreationTracker,
        dirty: &DirtyTracker,
        initial: &SvmSnapshot,
    ) -> CreationTracker {
        let mut tracker = base.clone();
        for pubkey in dirty.mark_order() {
            if !initial.contains_account(pubkey) {
                tracker.observe(*pubkey);
            }
        }
        tracker
    }
}

/// Tracks which accounts have been written during the current iteration.
///
/// Accumulates dirty accounts across all transactions. Cleared at `begin_iteration()`.
/// The hot path (`record_tx`) is just FxHashSet inserts — zero allocation after warmup.
pub struct DirtyTracker {
    /// Writable accounts (includes fee payers). FxHash for speed.
    writable: FastHashSet<Pubkey>,
    /// Writable accounts in first-mark order. Drives deterministic creation-
    /// ordinal assignment in `CreationTracker::extended_with_iteration` — the
    /// order accounts are first written is a function of the (deterministically
    /// replayed) action input, unlike HashSet iteration order.
    mark_order: Vec<Pubkey>,
    /// Read-only accounts (includes program_ids). FxHash for speed.
    read_only: FastHashSet<Pubkey>,
    /// Whether slot/clock was modified this iteration.
    clock_dirty: bool,
    /// Target slot from the most recent warp_to_slot/advance_slots.
    /// Used by the stateful novelty system: each distinct slot target produces
    /// a unique fingerprint contribution, ensuring clock advances are never
    /// collapsed into the same state even when slot_diff_bucket is the same.
    pub clock_target_slot: Option<u64>,
}

impl DirtyTracker {
    pub fn new() -> Self {
        Self {
            writable: FastHashSet::default(),
            mark_order: Vec::new(),
            read_only: FastHashSet::default(),
            clock_dirty: false,
            clock_target_slot: None,
        }
    }

    /// Insert into the writable set, recording first-mark order.
    #[inline]
    fn insert_writable(&mut self, pubkey: Pubkey) {
        if self.writable.insert(pubkey) {
            self.mark_order.push(pubkey);
        }
    }

    /// Record all instructions in a tx. Handles multi-instruction batches.
    /// Hot path — just HashSet inserts, zero allocation after initial capacity.
    #[inline]
    pub fn record_tx(&mut self, instructions: &[Instruction], fee_payer: &Pubkey) {
        self.insert_writable(*fee_payer);
        for ix in instructions {
            self.read_only.insert(ix.program_id);
            for meta in &ix.accounts {
                if meta.is_writable {
                    self.insert_writable(meta.pubkey);
                } else {
                    self.read_only.insert(meta.pubkey);
                }
            }
        }
    }

    /// Mark the clock sysvar as dirty (called by warp_to_slot/advance_slots).
    pub fn mark_clock_dirty(&mut self, target_slot: u64) {
        self.clock_dirty = true;
        self.clock_target_slot = Some(target_slot);
    }

    /// Mark a specific account as dirty (called by write_account, etc.).
    pub fn mark_account_dirty(&mut self, pubkey: &Pubkey) {
        self.insert_writable(*pubkey);
    }

    /// Get the set of dirty (writable) accounts.
    pub fn dirty_accounts(&self) -> &FastHashSet<Pubkey> {
        &self.writable
    }

    /// Writable accounts in deterministic first-mark order.
    pub fn mark_order(&self) -> &[Pubkey] {
        &self.mark_order
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
        self.mark_order.clear();
        self.read_only.clear();
        self.clock_dirty = false;
        self.clock_target_slot = None;
    }
}

impl Clone for DirtyTracker {
    fn clone(&self) -> Self {
        // NOTE: Intentionally returns a fresh tracker, not a copy of `self`.
        // Cloned contexts start a new iteration with no dirty state — carrying
        // over the parent's dirty set would cause incorrect snapshot restoration.
        Self::new()
    }
}
