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
//! - **AccountDiff** — before/after diffs for account state comparison

pub mod account_diff;
pub mod dirty_tracker;
pub mod state_pool;
pub mod svm_snapshot;

pub use account_diff::AccountDiff;
pub use dirty_tracker::DirtyTracker;
pub use state_pool::{
    extract_coverage_positions, state_class_from_fingerprint, ActionStats, ActionStatsMap,
    FingerprintBitmap, FuzzPhase, PoolMemoryStats, StateEntry, StatePool, StateRegistry,
    StateStats,
};
pub use svm_snapshot::{
    check_field_novelty, compute_state_fingerprint_from_snapshot, fingerprint_and_collect_changed,
    slot_bucket, slot_diff_bucket, value_bucket, AccountPatch, CompactDelta, SvmSnapshot,
    FIELD_NOVELTY_BITMAP_SIZE,
};

#[cfg(test)]
mod tests;
