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

pub mod dirty_tracker;
pub mod account_diff;
pub mod taint;
pub mod svm_snapshot;
pub mod state_pool;

pub use dirty_tracker::DirtyTracker;
pub use account_diff::AccountDiff;
pub use taint::{
    TxTaintRecord, IterationTaintLog, CapturedTxMeta,
    snapshot_writable_accounts, build_taint_record, build_taint_record_from_captured,
    capture_tx_meta, build_action_taint_summary,
};
pub use svm_snapshot::{SvmSnapshot, compute_state_fingerprint_from_snapshot, value_bucket, slot_bucket, slot_diff_bucket, lamports_diff_bucket, check_state_coverage, check_state_coverage_atomic, STATE_COV_BITMAP_SIZE};
pub use state_pool::{
    StateEntry, ActionStats, ActionStatsMap, StatePool,
    FingerprintBitmap, state_class_from_fingerprint,
};

#[cfg(test)]
mod tests;
