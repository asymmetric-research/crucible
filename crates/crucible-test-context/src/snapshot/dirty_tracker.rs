use crate::FastHashSet;
use anchor_lang::solana_program::instruction::Instruction;
use solana_pubkey::Pubkey;

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
