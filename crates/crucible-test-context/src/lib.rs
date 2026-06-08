use litesvm::LiteSVM;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;

// Fast hashing for hot-path coverage collections (10-50x faster than SipHash for integers)
pub use rustc_hash::{FxBuildHasher, FxHashMap, FxHashSet};

/// Type alias for fast HashSet (uses FxHash)
pub type FastHashSet<T> = FxHashSet<T>;
/// Type alias for fast HashMap (uses FxHash)
pub type FastHashMap<K, V> = FxHashMap<K, V>;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_message::inner_instruction::InnerInstructionsList;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction_context::TransactionReturnData;
use solana_transaction_error::TransactionError;

// Re-export types from anchor-lang for anchor program interactions
pub use crate::account_builders::AccountBuilderBase;
pub use crate::account_builders::GenericAccountBuilder;
pub use crate::account_builders::MintAccountBuilder;
pub use crate::account_builders::TokenAccountBuilder;
pub use crate::account_mutation::{reset_probed_account_mutations, AccountMutationConfig};
pub use crate::instruction_builder::InstructionBuilder;
pub use crate::mock_oracles::{
    MockPythOracleBuilder, PriceFeedMessage, PriceUpdateV2, VerificationLevel,
    DEFAULT_PYTH_RECEIVER_ID, PYTH_DISCRIMINATOR,
};
pub use crate::program_builder::ProgramBuilder;
pub use crate::transaction_builder::TransactionBuilder;
use anchor_lang::prelude::{Clock, Rent};
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::program_pack::Pack;
use anchor_lang::solana_program::system_program;
use anchor_lang::{AnchorDeserialize, AnchorSerialize, Discriminator};
use anyhow::{Context, Result};
use spl_token::solana_program::program_option::COption;

mod account_builders;
mod account_mutation;
mod instruction_builder;
mod program_builder;
pub mod schema;
pub mod snapshot;

// Re-export schema types for generated code (register_schemas())
pub use schema::{register_account_discriminators, register_account_schemas, AccountSchema};
mod transaction_builder;

// Coverage analysis and visualization
pub mod coverage;

// Re-export coverage types for backward compatibility
pub use coverage::{
    build_cached_analysis, extract_functions, generate_bytecode_lcov, generate_coverage_html,
    generate_coverage_html_cached, generate_source_lcov,
};
pub use coverage::{build_dwarf_source_map, DwarfSourceMap, SourceLocation};
pub use coverage::{
    CachedFunctionInfo, CachedProgramAnalysis, CoverageStats, CoverageWriteStats, FunctionInfo,
    ReachableAnalysis,
};

pub use litesvm::InvocationInspectCallback;
// Re-export litesvm for generated code (stateful mode creates placeholder SVMs)
pub use litesvm;

// Re-export serde_json for generated code
pub use serde_json;

// RPC account cloning (optional, requires `rpc-clone` feature)
#[cfg(feature = "rpc-clone")]
pub mod rpc_clone;
#[cfg(feature = "rpc-clone")]
pub use rpc_clone::AccountCloner;

// ============================================================================
// Global Action Counter (for monitor: actions/exec metric)
// ============================================================================

/// Global counter of total actions dispatched across all iterations.
/// Used with TOTAL_EXECUTIONS to compute average actions per execution.
pub static TOTAL_ACTIONS_DISPATCHED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Global counter of total actions that succeeded across all iterations.
/// Used by monitor to display success rate (ok/total).
pub static TOTAL_ACTIONS_SUCCEEDED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Total number of action variants available (set once at startup).
/// Used by monitor to display "discovered: N/M actions".
pub static TOTAL_ACTION_VARIANTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Increment the global action counter by one.
/// Also increments the thread-local per-iteration counter for accurate
/// multicore exec/sec reporting (global atomic has cross-thread noise).
#[inline]
pub fn increment_action_count() {
    TOTAL_ACTIONS_DISPATCHED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    ITERATION_DISPATCH_COUNT.with(|c| c.set(c.get() + 1));
}

/// Increment the global succeeded action counter by one.
#[inline]
pub fn increment_action_success_count() {
    TOTAL_ACTIONS_SUCCEEDED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

// ============================================================================
// Thread-Local State
// ============================================================================

use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};

thread_local! {
    // Invariant violation tracking for fuzz_assert! macros
    static VIOLATION: RefCell<Option<String>> = RefCell::new(None);
    // Whether the recorded violation came from the account-mutation engine (vs an invariant).
    // Set atomically with VIOLATION so it always matches the stored (first-wins) violation.
    static VIOLATION_FROM_MUTATION: Cell<bool> = const { Cell::new(false) };
    // Stable account-mutation finding identity/message for metadata and replay. The ID omits
    // per-run pubkeys, so replay can target the same CC class + instruction even with fresh setup keys.
    static MUTATION_FINDING_ID: RefCell<Option<String>> = RefCell::new(None);
    static MUTATION_FINDING_MESSAGE: RefCell<Option<String>> = RefCell::new(None);
    static EXPECTED_MUTATION_FINDING_ID: RefCell<Option<String>> = RefCell::new(None);
    // Per-instruction coverage tracking
    static CURRENT_INSTRUCTION: RefCell<Option<String>> = RefCell::new(None);
    // Crash metadata
    static ACTION_HISTORY: RefCell<Vec<ActionRecord>> = RefCell::new(Vec::new());
    static CURRENT_TEST_NAME: RefCell<Option<String>> = RefCell::new(None);
    static CURRENT_ITERATION: RefCell<u64> = RefCell::new(0);
    // Early exit tracking: total actions in sequence and which action triggered the violation
    static TOTAL_ACTIONS_IN_SEQUENCE: RefCell<usize> = RefCell::new(0);
    static VIOLATION_ACTION_INDEX: RefCell<Option<usize>> = RefCell::new(None);
    // Error code passthrough from tx_result_to_outcome to push_action_record
    static LAST_ERROR_CODE: Cell<Option<u32>> = const { Cell::new(None) };
    // Per-iteration action dispatch count (thread-local, no cross-thread noise).
    // Reset before each fn_name() call, read after to get accurate per-iteration count.
    static ITERATION_DISPATCH_COUNT: Cell<u64> = const { Cell::new(0) };
    // Success-seeking: tracks which action variant indices have ever succeeded
    static SUCCEEDED_VARIANTS: RefCell<HashSet<usize>> = RefCell::new(HashSet::new());
    // Cached env var: FUZZ_DEBUG (checked once per thread, avoids syscall on every send_batch)
    static FUZZ_DEBUG: Cell<bool> = Cell::new(false);
    // Stateful chain mode: when true, action loops break on first failure
    static STATEFUL_CHAIN_MODE: Cell<bool> = const { Cell::new(false) };
    // Corpus loading phase: suppress monitor output during loading
    static CORPUS_LOADING: Cell<bool> = const { Cell::new(false) };
}

// Sentinel: has FUZZ_DEBUG TLS been initialized on this thread?
thread_local! {
    static FUZZ_DEBUG_INIT: Cell<bool> = const { Cell::new(false) };
}

/// Check FUZZ_DEBUG env var (cached per-thread after first call).
#[inline]
fn is_fuzz_debug() -> bool {
    FUZZ_DEBUG_INIT.with(|init| {
        if !init.get() {
            let val = std::env::var("FUZZ_DEBUG").is_ok();
            FUZZ_DEBUG.with(|c| c.set(val));
            init.set(true);
            val
        } else {
            FUZZ_DEBUG.with(|c| c.get())
        }
    })
}

/// Set stateful chain mode flag. When true, invariant test loops break on
/// first action failure (failed actions produce dead-end states in stateful mode).
#[inline]
pub fn set_stateful_chain_mode(v: bool) {
    STATEFUL_CHAIN_MODE.with(|f| f.set(v));
}

/// Check if stateful chain mode is active.
#[inline]
pub fn is_stateful_chain_mode() -> bool {
    STATEFUL_CHAIN_MODE.with(|f| f.get())
}

/// Check FUZZ_DEBUG_REPLAY env var (cached per-thread).
#[inline]
pub fn is_debug_replay() -> bool {
    // Simple check — not on hot path (only used in replay mode)
    std::env::var("FUZZ_DEBUG_REPLAY").is_ok()
}

/// Hash SVM state for tracked accounts. Returns (hash, clock_slot).
/// Accounts sorted by (lamports, data_len, data_hash) for cross-run stability.
pub fn compute_svm_debug_hash(
    svm: &litesvm::LiteSVM,
    tracked_accounts: &[solana_pubkey::Pubkey],
) -> (u64, u64) {
    use anchor_lang::prelude::Clock;
    use rustc_hash::FxHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = FxHasher::default();
    let clock: Clock = svm.get_sysvar();
    let slot = clock.slot;
    clock.slot.hash(&mut hasher);
    clock.epoch.hash(&mut hasher);
    let mut entries: Vec<(u64, usize, u64)> = Vec::with_capacity(tracked_accounts.len());
    for pubkey in tracked_accounts {
        if let Some(acct) = svm.get_account(pubkey) {
            let mut dh = FxHasher::default();
            acct.data.hash(&mut dh);
            entries.push((acct.lamports, acct.data.len(), dh.finish()));
        }
    }
    entries.sort();
    for (lamports, data_len, data_hash) in &entries {
        lamports.hash(&mut hasher);
        data_len.hash(&mut hasher);
        data_hash.hash(&mut hasher);
    }
    (hasher.finish(), slot)
}

/// Set corpus loading flag (suppresses monitor output during loading).
pub fn set_corpus_loading(v: bool) {
    CORPUS_LOADING.with(|f| f.set(v));
}

/// Check if corpus loading is in progress.
#[inline]
pub fn is_corpus_loading() -> bool {
    CORPUS_LOADING.with(|f| f.get())
}

#[doc(hidden)]
/// Set the current Anchor instruction name (for coverage tracking)
pub fn set_current_instruction(name: Option<String>) {
    CURRENT_INSTRUCTION.with(|c| {
        *c.borrow_mut() = name;
    });
}

/// Get the current Anchor instruction name
pub fn get_current_instruction() -> Option<String> {
    CURRENT_INSTRUCTION.with(|c| c.borrow().clone())
}

/// Set the last error code from a transaction result (called by tx_result_to_outcome)
pub fn set_last_error_code(code: Option<u32>) {
    LAST_ERROR_CODE.with(|c| c.set(code));
}

/// Take the last error code, resetting it to None (called by push_action_record)
fn take_last_error_code() -> Option<u32> {
    LAST_ERROR_CODE.with(|c| c.replace(None))
}

// ============================================================================
// Action History Tracking (for .meta.json crash metadata)
// ============================================================================

/// A single field-level semantic diff (used by schema registry for rich crash output).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldDelta {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

/// Record of a single action execution for crash metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionRecord {
    /// Action name (e.g., "action_deposit")
    pub name: String,
    /// Action parameters as JSON object (with constrained/modulo'd values)
    pub params: serde_json::Value,
    /// Whether the action succeeded (from Result return value)
    pub success: bool,
    /// Error code from the last transaction (e.g., Custom(6051) → Some(6051))
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<u32>,
}

/// Complete crash metadata for .meta.json files
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrashMetadata {
    /// Name of the test that was running
    pub test_name: String,
    /// Timestamp when crash was detected (ISO 8601)
    pub timestamp: String,
    /// Fuzzer iteration number
    pub iteration: u64,
    /// Fuzzer seed (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    /// Sequence of actions that led to the crash
    pub actions: Vec<ActionRecord>,
    /// True if the finding came from the account-mutation engine. Replay must re-enable the
    /// engine (set `FUZZ_MUTATE_ACCOUNTS`) for such crashes to reproduce.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mutation_finding: bool,
    /// Stable mutation finding identity: `<class>:<program_id>:<instruction-discriminator>`.
    /// Used by replay/tmin to avoid stopping on an earlier, different mutation bug in the same input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_finding_id: Option<String>,
    /// Human-readable finding observed when the crash was first written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_finding_message: Option<String>,
}

/// Set the current test name (called at test start)
pub fn set_current_test_name(name: &str) {
    CURRENT_TEST_NAME.with(|t| {
        *t.borrow_mut() = Some(name.to_string());
    });
}

/// Get the current test name
pub fn get_current_test_name() -> Option<String> {
    CURRENT_TEST_NAME.with(|t| t.borrow().clone())
}

/// Set the current iteration number
pub fn set_current_iteration(iteration: u64) {
    CURRENT_ITERATION.with(|i| {
        *i.borrow_mut() = iteration;
    });
}

/// Get the current iteration number
pub fn get_current_iteration() -> u64 {
    CURRENT_ITERATION.with(|i| *i.borrow())
}

/// Push an action record to the history and update cumulative stats.
pub fn push_action_record(name: &str, params: serde_json::Value, success: bool) {
    let error_code = take_last_error_code();
    ACTION_HISTORY.with(|h| {
        h.borrow_mut().push(ActionRecord {
            name: name.to_string(),
            params,
            success,
            error_code,
        });
    });
}

/// Lite action record: only records name and success, defers JSON params.
/// Avoids serde_json::Value allocation on every action of every iteration.
/// The params field is set to `null` and should be backfilled via
/// `backfill_action_params` only when needed (crash/violation).
pub fn push_action_record_lite(name: &str, success: bool) {
    let error_code = take_last_error_code();
    ACTION_HISTORY.with(|h| {
        h.borrow_mut().push(ActionRecord {
            name: name.to_string(),
            params: serde_json::Value::Null,
            success,
            error_code,
        });
    });
}

/// Backfill the params for a specific action record in the history.
pub fn backfill_action_params(index: usize, params: serde_json::Value) {
    ACTION_HISTORY.with(|h| {
        let mut history = h.borrow_mut();
        if let Some(record) = history.get_mut(index) {
            record.params = params;
        }
    });
}

/// Get a copy of the action history
pub fn get_action_history() -> Vec<ActionRecord> {
    ACTION_HISTORY.with(|h| h.borrow().clone())
}

/// Check if the first action in history succeeded.
/// Avoids cloning the entire history Vec — O(1) instead of O(n).
#[inline]
pub fn get_first_action_success() -> Option<bool> {
    ACTION_HISTORY.with(|h| h.borrow().first().map(|r| r.success))
}

/// Clear the action history (called at start of each iteration)
pub fn clear_action_history() {
    ACTION_HISTORY.with(|h| h.borrow_mut().clear());
}

/// Reset the per-iteration dispatch counter (call before fn_name).
#[inline]
pub fn reset_iteration_dispatch_count() {
    ITERATION_DISPATCH_COUNT.with(|c| c.set(0));
}

/// Get the per-iteration dispatch count (call after fn_name).
/// Returns at least 1 to avoid zero-counting iterations.
#[inline]
pub fn get_iteration_dispatch_count() -> u64 {
    ITERATION_DISPATCH_COUNT.with(|c| c.get().max(1))
}

// ============================================================================
// send_batch sub-phase profiling (TLS accumulators)
// ============================================================================

thread_local! {
    pub(crate) static SEND_BATCH_PRE_NS: Cell<u64> = const { Cell::new(0) };   // dirty_tracker
    pub(crate) static SEND_BATCH_SVM_NS: Cell<u64> = const { Cell::new(0) };   // send_transaction (total)
    pub(crate) static SEND_BATCH_POST_NS: Cell<u64> = const { Cell::new(0) };  // tx_result_to_outcome
    // Sub-breakdown of send_transaction:
    pub(crate) static SEND_TX_BLOCKHASH_NS: Cell<u64> = const { Cell::new(0) }; // expire_blockhash + latest_blockhash
    pub(crate) static SEND_TX_SIGN_NS: Cell<u64> = const { Cell::new(0) };      // message + signing
    pub(crate) static SEND_TX_EXEC_NS: Cell<u64> = const { Cell::new(0) };      // svm.send_transaction
}

/// Reset send_batch sub-phase accumulators (call before fn_name).
#[inline]
pub fn reset_send_batch_timers() {
    SEND_BATCH_PRE_NS.with(|c| c.set(0));
    SEND_BATCH_SVM_NS.with(|c| c.set(0));
    SEND_BATCH_POST_NS.with(|c| c.set(0));
    SEND_TX_BLOCKHASH_NS.with(|c| c.set(0));
    SEND_TX_SIGN_NS.with(|c| c.set(0));
    SEND_TX_EXEC_NS.with(|c| c.set(0));
}

/// Get send_batch sub-phase timers: (pre_ns, svm_ns, post_ns).
#[inline]
pub fn get_send_batch_timers() -> (u64, u64, u64) {
    (
        SEND_BATCH_PRE_NS.with(|c| c.get()),
        SEND_BATCH_SVM_NS.with(|c| c.get()),
        SEND_BATCH_POST_NS.with(|c| c.get()),
    )
}

/// Get send_transaction sub-breakdown: (blockhash_ns, sign_ns, exec_ns).
#[inline]
pub fn get_send_tx_breakdown() -> (u64, u64, u64) {
    (
        SEND_TX_BLOCKHASH_NS.with(|c| c.get()),
        SEND_TX_SIGN_NS.with(|c| c.get()),
        SEND_TX_EXEC_NS.with(|c| c.get()),
    )
}

/// Set the total number of actions in the current sequence (for early exit tracking)
pub fn set_total_actions(count: usize) {
    TOTAL_ACTIONS_IN_SEQUENCE.with(|t| *t.borrow_mut() = count);
}

/// Record which action index triggered a violation (only records first violation)
pub fn set_violation_action_index(idx: usize) {
    VIOLATION_ACTION_INDEX.with(|v| {
        let mut guard = v.borrow_mut();
        if guard.is_none() {
            *guard = Some(idx);
        }
    });
}

/// Get the action index that triggered the violation (if any)
pub fn get_violation_action_index() -> Option<usize> {
    VIOLATION_ACTION_INDEX.with(|v| *v.borrow())
}

/// Clear all violation tracking state (called at start of each iteration)
pub fn clear_violation_tracking() {
    TOTAL_ACTIONS_IN_SEQUENCE.with(|t| *t.borrow_mut() = 0);
    VIOLATION_ACTION_INDEX.with(|v| *v.borrow_mut() = None);
}

fn clear_current_violation() {
    VIOLATION.with(|v| *v.borrow_mut() = None);
    VIOLATION_FROM_MUTATION.with(|m| m.set(false));
    MUTATION_FINDING_ID.with(|id| *id.borrow_mut() = None);
    MUTATION_FINDING_MESSAGE.with(|msg| *msg.borrow_mut() = None);
}

/// Clear all per-iteration state: action history + violation tracking.
/// Convenience wrapper — call at the start of each fuzzing iteration.
#[inline]
pub fn clear_iteration_state() {
    clear_action_history();
    clear_violation_tracking();
    clear_current_violation();
}

// ============================================================================
// Success-Seeking Mutation State
// ============================================================================

/// Check if a given action variant index has ever succeeded.
pub fn has_variant_succeeded(variant_idx: usize) -> bool {
    SUCCEEDED_VARIANTS.with(|s| s.borrow().contains(&variant_idx))
}

/// Mark an action variant index as having succeeded at least once.
pub fn mark_variant_succeeded(variant_idx: usize) {
    SUCCEEDED_VARIANTS.with(|s| {
        s.borrow_mut().insert(variant_idx);
    });
}

/// Get the number of action variants that have ever succeeded.
pub fn succeeded_variant_count() -> usize {
    SUCCEEDED_VARIANTS.with(|s| s.borrow().len())
}

/// Parse an action description string like "withdraw(authority=null, lamports=5) -> OK"
/// back into an ActionRecord. Used by stateful mode to reconstruct full crash metadata
/// from pool descriptions.
pub fn parse_action_desc(desc: &str) -> ActionRecord {
    let (body, success) = if let Some(body) = desc.strip_suffix(" -> OK") {
        (body, true)
    } else if let Some(body) = desc.strip_suffix(" -> FAIL") {
        (body, false)
    } else {
        (desc, true)
    };
    let (name, params) = if let Some(paren) = body.find('(') {
        let name = &body[..paren];
        let params_str = body[paren + 1..].trim_end_matches(')');
        let mut map = serde_json::Map::new();
        for part in params_str.split(", ") {
            if let Some(eq) = part.find('=') {
                let key = &part[..eq];
                let val_str = &part[eq + 1..];
                let val = if val_str == "null" {
                    serde_json::Value::Null
                } else if val_str == "true" {
                    serde_json::Value::Bool(true)
                } else if val_str == "false" {
                    serde_json::Value::Bool(false)
                } else if let Ok(n) = val_str.parse::<u64>() {
                    serde_json::Value::Number(n.into())
                } else if let Ok(n) = val_str.parse::<i64>() {
                    serde_json::Value::Number(n.into())
                } else {
                    serde_json::Value::String(val_str.to_string())
                };
                map.insert(key.to_string(), val);
            }
        }
        (name.to_string(), serde_json::Value::Object(map))
    } else {
        (
            body.to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        )
    };
    ActionRecord {
        name,
        params,
        success,
        error_code: None,
    }
}

/// Build crash metadata from current state
pub fn build_crash_metadata(seed: Option<u64>) -> CrashMetadata {
    let timestamp = chrono_lite_timestamp();
    CrashMetadata {
        test_name: get_current_test_name().unwrap_or_else(|| "unknown".to_string()),
        timestamp,
        iteration: get_current_iteration(),
        seed,
        actions: get_action_history(),
        mutation_finding: violation_from_mutation(),
        mutation_finding_id: mutation_finding_id(),
        mutation_finding_message: mutation_finding_message(),
    }
}

/// Print the action sequence to stderr (for debugging crashes)
/// Format the current action sequence from TLS history into a string.
/// Must be called on the same thread that executed the actions (reads TLS).
pub fn format_action_sequence() -> String {
    use std::fmt::Write;

    let history = get_action_history();
    let total_actions = TOTAL_ACTIONS_IN_SEQUENCE.with(|t| *t.borrow());
    let violation_idx = get_violation_action_index();

    if history.is_empty() && total_actions == 0 {
        return String::new();
    }

    let executed = history.len();
    let skipped = total_actions.saturating_sub(executed);

    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n=== FUZZ SEQUENCE ({} executed, {} skipped) ===",
        executed, skipped
    );

    for (i, record) in history.iter().enumerate() {
        let params_str = if let serde_json::Value::Object(map) = &record.params {
            map.iter()
                .map(|(k, v)| format!("{}={}", k, format_json_value(v)))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            String::new()
        };

        let status = if record.success { "OK" } else { "FAIL" };
        let violation_marker = if violation_idx == Some(i) {
            " [VIOLATION]"
        } else {
            ""
        };

        if params_str.is_empty() {
            let _ = writeln!(
                out,
                "  {}. {} -> {}{}",
                i + 1,
                record.name,
                status,
                violation_marker
            );
        } else {
            let _ = writeln!(
                out,
                "  {}. {}({}) -> {}{}",
                i + 1,
                record.name,
                params_str,
                status,
                violation_marker
            );
        }
    }

    if skipped > 0 {
        let _ = writeln!(
            out,
            "  ... {} action(s) not executed (stopped on violation)",
            skipped
        );
    }

    let _ = writeln!(out, "================================");
    out
}

pub fn print_action_sequence() {
    let s = format_action_sequence();
    if !s.is_empty() {
        eprint!("{}", s);
    }
}

/// Format a JSON value for display (compact format)
pub fn format_json_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => format!("\"{}\"", s),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_json_value).collect();
            format!("[{}]", items.join(", "))
        }
        serde_json::Value::Object(obj) => {
            let items: Vec<String> = obj
                .iter()
                .map(|(k, v)| format!("{}: {}", k, format_json_value(v)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
    }
}

/// Format the most recent action from TLS history as a one-line summary.
/// e.g. "action_deposit(user=0, amount=500) -> OK"
/// Returns empty string if no action in history.
pub fn format_last_action_oneline() -> String {
    let history = get_action_history();
    match history.last() {
        Some(record) => {
            let params_str = if let serde_json::Value::Object(map) = &record.params {
                map.iter()
                    .map(|(k, v)| format!("{}={}", k, format_json_value(v)))
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                String::new()
            };
            let status = if record.success { "OK" } else { "FAIL" };
            if params_str.is_empty() {
                format!("{} -> {}", record.name, status)
            } else {
                format!("{}({}) -> {}", record.name, params_str, status)
            }
        }
        None => String::new(),
    }
}

/// Format ALL actions in the current history as one-line descriptions, newline-separated.
/// Used by stateful mode to store the full chain description in a single `action_desc` field.
pub fn format_all_actions_oneline() -> String {
    let history = get_action_history();
    let mut lines = Vec::with_capacity(history.len());
    for record in &history {
        let params_str = if let serde_json::Value::Object(map) = &record.params {
            map.iter()
                .map(|(k, v)| format!("{}={}", k, format_json_value(v)))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            String::new()
        };
        let status = if record.success { "OK" } else { "FAIL" };
        if params_str.is_empty() {
            lines.push(format!("{} -> {}", record.name, status));
        } else {
            lines.push(format!("{}({}) -> {}", record.name, params_str, status));
        }
    }
    lines.join("\n")
}

/// Write crash metadata to a .meta.json file and save input bytes for replay
pub fn write_crash_metadata(
    crash_dir: &str,
    input_hash: u64,
    seed: Option<u64>,
    input_bytes: &[u8],
) {
    write_crash_metadata_with_actions(crash_dir, input_hash, seed, input_bytes, None)
}

/// Write crash metadata with an explicit full action chain (for stateful mode).
/// If `full_actions` is Some, it overrides the TLS action history.
pub fn write_crash_metadata_with_actions(
    crash_dir: &str,
    input_hash: u64,
    seed: Option<u64>,
    input_bytes: &[u8],
    full_actions: Option<Vec<ActionRecord>>,
) {
    let crash_id = format!("crash_{:016x}", input_hash);
    let mut metadata = build_crash_metadata(seed);
    if let Some(actions) = full_actions {
        metadata.actions = actions;
    }
    let meta_dir = std::env::var("FUZZ_META_DIR").unwrap_or_else(|_| crash_dir.to_string());
    let meta_filename = format!("{}/{}.meta.json", meta_dir, crash_id);
    let input_filename = format!("{}/{}", crash_dir, crash_id);

    // Save the input bytes for replay
    if let Err(e) = std::fs::write(&input_filename, input_bytes) {
        eprintln!(
            "[META] Failed to write crash input {}: {}",
            input_filename, e
        );
    }

    // Save the metadata
    match serde_json::to_string_pretty(&metadata) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&meta_filename, json) {
                eprintln!("[META] Failed to write {}: {}", meta_filename, e);
            }
        }
        Err(e) => {
            eprintln!("[META] Failed to serialize metadata: {}", e);
        }
    }
}

/// Write crash metadata for a known crash ID (used by tmin to update metadata in place)
pub fn write_crash_metadata_for_id(crash_dir: &str, crash_id: &str, seed: Option<u64>) {
    let metadata = build_crash_metadata(seed);
    let meta_filename = format!("{}/{}.meta.json", crash_dir, crash_id);

    match serde_json::to_string_pretty(&metadata) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&meta_filename, json) {
                eprintln!("[META] Failed to write {}: {}", meta_filename, e);
            }
        }
        Err(e) => {
            eprintln!("[META] Failed to serialize metadata: {}", e);
        }
    }
}

// ============================================================================
// Action Result Trait (for Feature 2: actions return Result)
// ============================================================================

/// Trait to normalize action return values to success/failure.
/// Allows actions to return either `()` (always success) or `Result<(), E>` (success/failure).
pub trait IntoActionSuccess {
    fn into_success(self) -> bool;
}

impl IntoActionSuccess for () {
    fn into_success(self) -> bool {
        true
    }
}

impl<T, E> IntoActionSuccess for Result<T, E> {
    fn into_success(self) -> bool {
        self.is_ok()
    }
}

impl IntoActionSuccess for bool {
    fn into_success(self) -> bool {
        self
    }
}

/// Simple timestamp function (avoids chrono dependency)
fn chrono_lite_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Basic ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
    // This is a simplified calculation - not accounting for leap years perfectly
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Approximate year/month/day calculation
    let mut year = 1970;
    let mut remaining_days = days_since_epoch as i64;
    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            366
        } else {
            365
        };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for days_in_month in days_in_months {
        if remaining_days < days_in_month as i64 {
            break;
        }
        remaining_days -= days_in_month as i64;
        month += 1;
    }
    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

// ============================================================================
// Discriminator-based instruction detection
// ============================================================================

use std::sync::OnceLock;

/// Global map from discriminator bytes to instruction name.
/// Supports both 8-byte (Anchor/borsh) and 4-byte (native/bincode) discriminators.
/// Populated once at harness startup via `register_instruction_discriminators()`.
/// Uses OnceLock for lock-free reads after initialization (single-threaded).
static DISCRIMINATOR_MAP: OnceLock<(usize, HashMap<Vec<u8>, String>)> = OnceLock::new();

/// Register instruction discriminators for per-instruction coverage tracking.
/// Call this once at harness initialization with discriminators from the program's IDL.
/// Supports variable-length discriminators (4 bytes for bincode, 8 bytes for Anchor).
/// Subsequent calls are ignored (OnceLock can only be set once).
///
/// Example:
/// ```ignore
/// register_instruction_discriminators(&[
///     ("deposit", vec![171, 94, 235, 200, 28, 230, 215, 98]),
///     ("borrow", vec![4, 126, 116, 45, 173, 75, 231, 84]),
/// ]);
/// ```
pub fn register_instruction_discriminators(discriminators: &[(&str, Vec<u8>)]) {
    // Determine discriminator length from first entry (all must be same length)
    let disc_len = discriminators.first().map(|(_, d)| d.len()).unwrap_or(8);
    let map: HashMap<Vec<u8>, String> = discriminators
        .iter()
        .map(|(name, disc)| (disc.clone(), name.to_string()))
        .collect();
    let _ = DISCRIMINATOR_MAP.set((disc_len, map));
}

/// Look up instruction name from discriminator bytes at the start of instruction data.
/// Automatically uses the correct discriminator length (4 or 8 bytes).
/// Returns None if discriminator is not registered or if the data is too short.
/// Lock-free after initialization.
pub fn lookup_instruction_by_discriminator(instruction_data: &[u8]) -> Option<String> {
    let (disc_len, map) = DISCRIMINATOR_MAP.get()?;
    if instruction_data.len() < *disc_len {
        return None;
    }
    let disc = instruction_data[..*disc_len].to_vec();
    map.get(&disc).cloned()
}

/// Get all registered discriminators (for debugging)
pub fn get_registered_discriminators() -> Vec<(String, Vec<u8>)> {
    DISCRIMINATOR_MAP
        .get()
        .map(|(_, map)| map.iter().map(|(k, v)| (v.clone(), k.clone())).collect())
        .unwrap_or_default()
}

// ============================================================================

/// Record an invariant violation (used by fuzz_assert! macros)
pub fn record_violation(msg: String) {
    VIOLATION.with(|v| {
        // Use a single mutable borrow to avoid any RefCell borrow conflicts
        let mut guard = v.borrow_mut();
        if guard.is_none() {
            *guard = Some(msg);
            VIOLATION_FROM_MUTATION.with(|m| m.set(false));
            MUTATION_FINDING_ID.with(|id| *id.borrow_mut() = None);
            MUTATION_FINDING_MESSAGE.with(|mutation_msg| *mutation_msg.borrow_mut() = None);
        }
    });
}

/// Record a violation produced by the account-mutation engine. Identical to
/// [`record_violation`] but also flags the violation's origin so crash metadata can mark it
/// (and replay can re-enable the engine).
pub(crate) fn record_mutation_violation(msg: String, id: String) {
    VIOLATION.with(|v| {
        let mut guard = v.borrow_mut();
        if guard.is_none() {
            MUTATION_FINDING_ID.with(|finding_id| *finding_id.borrow_mut() = Some(id));
            MUTATION_FINDING_MESSAGE
                .with(|finding_msg| *finding_msg.borrow_mut() = Some(msg.clone()));
            *guard = Some(msg);
            VIOLATION_FROM_MUTATION.with(|m| m.set(true));
        }
    });
}

/// Whether the currently-recorded violation was produced by the account-mutation engine.
pub fn violation_from_mutation() -> bool {
    VIOLATION_FROM_MUTATION.with(|m| m.get())
}

/// Stable identity of the current account-mutation finding, if any.
pub fn mutation_finding_id() -> Option<String> {
    if violation_from_mutation() {
        MUTATION_FINDING_ID.with(|id| id.borrow().clone())
    } else {
        None
    }
}

/// Human-readable current account-mutation finding, if any.
pub fn mutation_finding_message() -> Option<String> {
    if violation_from_mutation() {
        MUTATION_FINDING_MESSAGE.with(|msg| msg.borrow().clone())
    } else {
        None
    }
}

/// Restrict replay/tmin to the original account-mutation finding identity.
pub fn set_expected_mutation_finding_id(id: Option<String>) {
    EXPECTED_MUTATION_FINDING_ID.with(|expected| *expected.borrow_mut() = id);
}

/// Current replay/tmin mutation finding identity filter.
pub fn expected_mutation_finding_id() -> Option<String> {
    EXPECTED_MUTATION_FINDING_ID.with(|expected| expected.borrow().clone())
}

/// Load `mutation_finding_id` from the `.meta.json` associated with a crash input path.
pub fn load_expected_mutation_finding_id_from_metadata(input_path: &str) {
    set_expected_mutation_finding_id(None);

    let input = std::path::Path::new(input_path);
    let mut candidates = Vec::new();
    if let Some(name) = input.file_name().and_then(|n| n.to_str()) {
        if let Ok(meta_dir) = std::env::var("FUZZ_META_DIR") {
            candidates.push(std::path::Path::new(&meta_dir).join(format!("{name}.meta.json")));
        }
    }
    candidates.push(std::path::PathBuf::from(format!("{input_path}.meta.json")));

    for path in candidates {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if let Some(id) = meta.get("mutation_finding_id").and_then(|v| v.as_str()) {
            set_expected_mutation_finding_id(Some(id.to_string()));
            return;
        }
    }
}

/// Take the current violation (clearing it). Returns Some if violated.
pub fn take_violation() -> Option<String> {
    VIOLATION.with(|v| v.borrow_mut().take())
}

/// Check if a violation has been recorded (without consuming it)
pub fn has_violation() -> bool {
    VIOLATION.with(|v| v.borrow().is_some())
}

/// Assert a condition is true
#[macro_export]
macro_rules! fuzz_assert {
    ($cond:expr $(,)?) => {
        if !($cond) {
            $crate::record_violation(format!(
                "Assertion failed: {} at {}:{}",
                stringify!($cond), file!(), line!()
            ));
        }
    };
    ($cond:expr, $($arg:tt)+) => {
        if !($cond) {
            $crate::record_violation(format!($($arg)+));
        }
    };
}

/// Assert two values are equal
#[macro_export]
macro_rules! fuzz_assert_eq {
    ($left:expr, $right:expr $(,)?) => {
        if $left != $right {
            $crate::record_violation(format!(
                "Assertion failed: {} == {} ({:?} != {:?}) at {}:{}",
                stringify!($left), stringify!($right), $left, $right, file!(), line!()
            ));
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        if $left != $right {
            $crate::record_violation(format!($($arg)+));
        }
    };
}

/// Assert two values are not equal
#[macro_export]
macro_rules! fuzz_assert_ne {
    ($left:expr, $right:expr $(,)?) => {
        if $left == $right {
            $crate::record_violation(format!(
                "Assertion failed: {} != {} ({:?} == {:?}) at {}:{}",
                stringify!($left), stringify!($right), $left, $right, file!(), line!()
            ));
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        if $left == $right {
            $crate::record_violation(format!($($arg)+));
        }
    };
}

/// Assert a < b
#[macro_export]
macro_rules! fuzz_assert_lt {
    ($left:expr, $right:expr $(,)?) => {
        if !($left < $right) {
            $crate::record_violation(format!(
                "Assertion failed: {} < {} ({:?} >= {:?}) at {}:{}",
                stringify!($left), stringify!($right), $left, $right, file!(), line!()
            ));
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        if !($left < $right) {
            $crate::record_violation(format!($($arg)+));
        }
    };
}

/// Assert a <= b
#[macro_export]
macro_rules! fuzz_assert_le {
    ($left:expr, $right:expr $(,)?) => {
        if !($left <= $right) {
            $crate::record_violation(format!(
                "Assertion failed: {} <= {} ({:?} > {:?}) at {}:{}",
                stringify!($left), stringify!($right), $left, $right, file!(), line!()
            ));
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        if !($left <= $right) {
            $crate::record_violation(format!($($arg)+));
        }
    };
}

/// Assert a > b
#[macro_export]
macro_rules! fuzz_assert_gt {
    ($left:expr, $right:expr $(,)?) => {
        if !($left > $right) {
            $crate::record_violation(format!(
                "Assertion failed: {} > {} ({:?} <= {:?}) at {}:{}",
                stringify!($left), stringify!($right), $left, $right, file!(), line!()
            ));
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        if !($left > $right) {
            $crate::record_violation(format!($($arg)+));
        }
    };
}

/// Assert a >= b
#[macro_export]
macro_rules! fuzz_assert_ge {
    ($left:expr, $right:expr $(,)?) => {
        if !($left >= $right) {
            $crate::record_violation(format!(
                "Assertion failed: {} >= {} ({:?} < {:?}) at {}:{}",
                stringify!($left), stringify!($right), $left, $right, file!(), line!()
            ));
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        if !($left >= $right) {
            $crate::record_violation(format!($($arg)+));
        }
    };
}

/// Assert two values are approximately equal within a delta (absolute difference)
#[macro_export]
macro_rules! fuzz_assert_approx_eq {
    ($left:expr, $right:expr, $delta:expr $(,)?) => {{
        let diff = if $left > $right { $left - $right } else { $right - $left };
        if diff > $delta {
            $crate::record_violation(format!(
                "Assertion failed: |{} - {}| <= {} (|{:?} - {:?}| = {:?} > {:?}) at {}:{}",
                stringify!($left), stringify!($right), stringify!($delta),
                $left, $right, diff, $delta, file!(), line!()
            ));
        }
    }};
    ($left:expr, $right:expr, $delta:expr, $($arg:tt)+) => {{
        let diff = if $left > $right { $left - $right } else { $right - $left };
        if diff > $delta {
            $crate::record_violation(format!($($arg)+));
        }
    }};
}

// Mock oracles for testing
mod mock_oracles;

/// Parsed transaction outcome from litesvm execution
#[derive(Debug, Clone)]
pub enum TxOutcome {
    /// Transaction executed successfully
    Success {
        compute_units: u64,
        logs: Vec<String>,
        signature: Signature,
        inner_instructions: InnerInstructionsList,
        return_data: TransactionReturnData,
        fee: u64,
    },
    /// Transaction failed with program error
    ProgramError {
        /// Raw error from SVM
        error: TransactionError,
        /// Parsed error code (e.g., 6051 from Custom(6051))
        error_code: Option<u32>,
        /// Instruction index that failed
        instruction_index: Option<u8>,
        logs: Vec<String>,
        signature: Signature,
        inner_instructions: InnerInstructionsList,
        return_data: TransactionReturnData,
        fee: u64,
    },
}

/// Error type for TxOutcome::into_result()
#[derive(Debug, Clone)]
pub struct TxError {
    pub error: TransactionError,
    pub error_code: Option<u32>,
    pub instruction_index: Option<u8>,
    pub logs: Vec<String>,
    pub signature: Signature,
    pub inner_instructions: InnerInstructionsList,
    pub return_data: TransactionReturnData,
    pub fee: u64,
}

impl std::error::Error for TxError {}

impl std::fmt::Display for TxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Transaction failed")?;
        if let Some(code) = self.error_code {
            write!(f, " (error code: {})", code)?;
        }
        if let Some(idx) = self.instruction_index {
            write!(f, " at instruction {}", idx)?;
        }
        Ok(())
    }
}

impl TxOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, TxOutcome::Success { .. })
    }

    pub fn is_error(&self) -> bool {
        matches!(self, TxOutcome::ProgramError { .. })
    }

    pub fn error_code(&self) -> Option<u32> {
        match self {
            TxOutcome::ProgramError { error_code, .. } => *error_code,
            _ => None,
        }
    }

    pub fn logs(&self) -> &[String] {
        match self {
            TxOutcome::Success { logs, .. } => logs,
            TxOutcome::ProgramError { logs, .. } => logs,
        }
    }

    pub fn compute_units(&self) -> Option<u64> {
        match self {
            TxOutcome::Success { compute_units, .. } => Some(*compute_units),
            _ => None,
        }
    }

    pub fn signature(&self) -> &Signature {
        match self {
            TxOutcome::Success { signature, .. } => signature,
            TxOutcome::ProgramError { signature, .. } => signature,
        }
    }

    pub fn fee(&self) -> u64 {
        match self {
            TxOutcome::Success { fee, .. } => *fee,
            TxOutcome::ProgramError { fee, .. } => *fee,
        }
    }

    pub fn inner_instructions(&self) -> &InnerInstructionsList {
        match self {
            TxOutcome::Success {
                inner_instructions, ..
            } => inner_instructions,
            TxOutcome::ProgramError {
                inner_instructions, ..
            } => inner_instructions,
        }
    }

    pub fn return_data(&self) -> &TransactionReturnData {
        match self {
            TxOutcome::Success { return_data, .. } => return_data,
            TxOutcome::ProgramError { return_data, .. } => return_data,
        }
    }

    /// Unwrap success or panic with detailed error message including logs
    pub fn unwrap(self) {
        match self {
            TxOutcome::Success { .. } => {}
            TxOutcome::ProgramError {
                error,
                error_code,
                logs,
                ..
            } => {
                let mut msg = format!("Transaction failed: {:?}", error);
                if let Some(code) = error_code {
                    msg.push_str(&format!(" (code: {})", code));
                }
                msg.push_str("\nLogs:\n");
                for log in &logs {
                    msg.push_str(&format!("  {}\n", log));
                }
                panic!("{}", msg);
            }
        }
    }

    /// Expect success or panic with custom message
    pub fn expect(self, msg: &str) {
        match self {
            TxOutcome::Success { .. } => {}
            TxOutcome::ProgramError { logs, .. } => {
                let mut full_msg = format!("{}\nLogs:\n", msg);
                for log in &logs {
                    full_msg.push_str(&format!("  {}\n", log));
                }
                panic!("{}", full_msg);
            }
        }
    }

    /// Convert to Result for ? operator compatibility
    pub fn into_result(self) -> std::result::Result<(), TxError> {
        match self {
            TxOutcome::Success { .. } => Ok(()),
            TxOutcome::ProgramError {
                error,
                error_code,
                instruction_index,
                logs,
                signature,
                inner_instructions,
                return_data,
                fee,
            } => Err(TxError {
                error,
                error_code,
                instruction_index,
                logs,
                signature,
                inner_instructions,
                return_data,
                fee,
            }),
        }
    }
}

/// Parse litesvm TransactionError to extract error code.
/// Extracts Custom(N) error codes from InstructionError variants.
pub fn parse_error_code(err: &TransactionError) -> Option<u32> {
    use solana_instruction::error::InstructionError;
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => Some(*code),
        _ => None,
    }
}

/// Parse litesvm TransactionError to extract instruction index.
pub fn parse_instruction_index(err: &TransactionError) -> Option<u8> {
    match err {
        TransactionError::InstructionError(idx, _) => Some(*idx),
        _ => None,
    }
}

/// Convert litesvm transaction result to TxOutcome
pub fn tx_result_to_outcome(result: litesvm::types::TransactionResult) -> TxOutcome {
    let outcome = match result {
        Ok(meta) => TxOutcome::Success {
            compute_units: meta.compute_units_consumed,
            logs: meta.logs,
            signature: meta.signature,
            inner_instructions: meta.inner_instructions,
            return_data: meta.return_data,
            fee: meta.fee,
        },
        Err(failed) => {
            let error_code = parse_error_code(&failed.err);
            let instruction_index = parse_instruction_index(&failed.err);
            TxOutcome::ProgramError {
                error: failed.err,
                error_code,
                instruction_index,
                logs: failed.meta.logs,
                signature: failed.meta.signature,
                inner_instructions: failed.meta.inner_instructions,
                return_data: failed.meta.return_data,
                fee: failed.meta.fee,
            }
        }
    };
    // Store error code in TLS for push_action_record to pick up
    set_last_error_code(outcome.error_code());
    outcome
}

// Re-export types needed by generated code
pub mod fuzz_types {
    pub use solana_program_runtime::invoke_context::{Executable, InvokeContext};
    pub use solana_pubkey::Pubkey;
    pub use solana_sbpf::ebpf;
    pub use solana_sbpf::static_analysis::Analysis;
    pub use solana_transaction::sanitized::SanitizedTransaction;
    pub use solana_transaction_context::{IndexOfAccount, InstructionContext};
}

/// Stores program data for reloading into debuggable SVMs
#[derive(Clone)]
pub struct ProgramData {
    pub program_id: Pubkey,
    pub data: Vec<u8>,
}

pub struct TestContext {
    pub svm: LiteSVM,
    pub pending_instructions: Vec<Instruction>,
    pending_signers: Vec<Keypair>,
    /// Programs loaded into this context (for reloading into debuggable SVMs).
    /// Arc-wrapped so cloning doesn't deep-copy program binaries (~1-2MB each).
    programs: std::sync::Arc<Vec<ProgramData>>,
    /// Account pubkeys that have been set (for copying to debuggable SVMs)
    tracked_accounts: Arc<HashSet<Pubkey>>,
    /// Total CFG edges and instructions per program (for coverage percentage calculation).
    /// Arc-wrapped: set once during setup, shared cheaply across multicore fixture clones.
    /// Value is (total_edges, total_instructions).
    program_coverage_totals: Arc<HashMap<Pubkey, (usize, usize)>>,
    /// Snapshot of initial state for fast restore (always-on in fuzz mode)
    pub snapshot: Option<snapshot::SvmSnapshot>,
    /// Tracks dirty accounts across all transactions in an iteration
    pub dirty_tracker: snapshot::DirtyTracker,
    /// Optional preflight engine that mutates account owners to detect missing owner checks.
    account_mutation: account_mutation::AccountMutationConfig,
    /// Whether signature verification is enabled on the SVM.
    /// When false (default for fuzzing), transactions use dummy signatures
    /// to skip ed25519 computation (~77µs per tx).
    pub sigverify: bool,
}

impl Clone for TestContext {
    fn clone(&self) -> Self {
        Self {
            svm: self.svm.clone(),
            pending_instructions: self.pending_instructions.clone(),
            pending_signers: self
                .pending_signers
                .iter()
                .map(|k| k.insecure_clone())
                .collect(),
            programs: self.programs.clone(),
            tracked_accounts: self.tracked_accounts.clone(),
            program_coverage_totals: self.program_coverage_totals.clone(),
            // Snapshot is not cloned — only the template fixture owns it
            snapshot: None,
            // Fresh tracker for each clone
            dirty_tracker: self.dirty_tracker.clone(),
            account_mutation: self.account_mutation.clone(),
            sigverify: self.sigverify,
        }
    }
}

/// Empty callback that does nothing - used during setup to avoid DefaultRegisterTracingCallback
/// trying to find .so files on disk for built-in programs.
pub struct EmptyInvocationCallback;

impl InvocationInspectCallback for EmptyInvocationCallback {
    fn before_invocation(
        &self,
        _tx: &solana_transaction::sanitized::SanitizedTransaction,
        _program_indices: &[solana_transaction_context::IndexOfAccount],
        _invoke_context: &solana_program_runtime::invoke_context::InvokeContext,
    ) {
    }

    fn after_invocation(
        &self,
        _invoke_context: &solana_program_runtime::invoke_context::InvokeContext,
        _register_tracing_enabled: bool,
    ) {
    }
}

impl TestContext {
    pub fn new() -> Self {
        // When CRUCIBLE_FUZZ_DEBUGGABLE is set (by the fuzz macro), create a debuggable SVM
        // so programs are loaded with register tracing support baked in.
        // Use EmptyInvocationCallback to suppress "Error collecting register tracing" messages
        // from DefaultRegisterTracingCallback trying to find .so files for built-in programs.
        let svm = if std::env::var("CRUCIBLE_FUZZ_DEBUGGABLE").is_ok() {
            let mut svm = LiteSVM::new_debuggable(true)
                .with_transaction_history(0)
                .with_sigverify(false)
                .with_blockhash_check(false);
            svm.set_invocation_inspect_callback(EmptyInvocationCallback);
            svm
        } else {
            LiteSVM::new()
                .with_transaction_history(0)
                .with_sigverify(false)
                .with_blockhash_check(false)
        };

        Self {
            svm,
            pending_instructions: Vec::new(),
            pending_signers: Vec::new(),
            programs: std::sync::Arc::new(Vec::new()),
            tracked_accounts: Arc::new(HashSet::new()),
            program_coverage_totals: Arc::new(HashMap::new()),
            snapshot: None,
            dirty_tracker: snapshot::DirtyTracker::new(),
            account_mutation: account_mutation::config_from_env(),
            sigverify: false,
        }
    }

    pub fn with_invocation_callback<C: InvocationInspectCallback + 'static>(callback: C) -> Self {
        let mut svm = LiteSVM::new_debuggable(true)
            .with_transaction_history(0)
            .with_sigverify(false)
            .with_blockhash_check(false);
        svm.set_invocation_inspect_callback(callback);
        Self {
            svm,
            pending_instructions: Vec::new(),
            pending_signers: Vec::new(),
            programs: std::sync::Arc::new(Vec::new()),
            tracked_accounts: Arc::new(HashSet::new()),
            program_coverage_totals: Arc::new(HashMap::new()),
            snapshot: None,
            dirty_tracker: snapshot::DirtyTracker::new(),
            account_mutation: account_mutation::config_from_env(),
            sigverify: false,
        }
    }

    pub fn with_compute_budget(mut self, compute_unit_limit: u64) -> Self {
        use solana_compute_budget::compute_budget::ComputeBudget;
        let mut budget = ComputeBudget::new_with_defaults(true, true);
        budget.compute_unit_limit = compute_unit_limit;
        self.svm = self.svm.with_compute_budget(budget);
        self
    }

    /// Analyze a program binary and return (total_edges, total_instructions).
    /// Only counts reachable code from the program entrypoint via BFS.
    /// Only counts edges from conditional jump instructions (matching runtime tracking).
    /// Used for coverage percentage calculation.
    pub fn analyze_program_coverage(program_data: &[u8]) -> Option<(usize, usize)> {
        use solana_sbpf::ebpf;
        use solana_sbpf::elf::Executable;
        use solana_sbpf::program::BuiltinProgram;
        use solana_sbpf::static_analysis::Analysis;
        use solana_sbpf::vm::ContextObject;

        struct DummyContext;
        impl ContextObject for DummyContext {
            fn consume(&mut self, _amount: u64) {}
            fn get_remaining(&self) -> u64 {
                0
            }
        }

        let loader = Arc::new(BuiltinProgram::<DummyContext>::new_mock());
        let executable = Executable::from_elf(program_data, loader).ok()?;
        let analysis = Analysis::from_executable(&executable).ok()?;

        // BFS from entrypoint + all registered function entries to find reachable CFG nodes.
        // Function entries are seeded because CALL targets are encoded in instruction
        // immediates, not in cfg_node.destinations.
        let mut visited = HashSet::new();
        let mut queue = std::collections::VecDeque::new();

        // Seed with program entrypoint
        if analysis.cfg_nodes.contains_key(&analysis.entrypoint) {
            visited.insert(analysis.entrypoint);
            queue.push_back(analysis.entrypoint);
        }

        // Seed all function entry points (reachable via CALL instructions).
        // analysis.functions maps PC → (key, name); cfg_nodes are keyed by node index.
        for (&pc, _) in &analysis.functions {
            if analysis.cfg_nodes.contains_key(&pc) {
                if visited.insert(pc) {
                    queue.push_back(pc);
                }
            }
        }

        while let Some(node_id) = queue.pop_front() {
            if let Some(cfg_node) = analysis.cfg_nodes.get(&node_id) {
                for &dest in &cfg_node.destinations {
                    if visited.insert(dest) {
                        queue.push_back(dest);
                    }
                }
            }
        }

        // Count edges and instructions only for reachable nodes
        let mut total_conditional: usize = 0;
        let mut total_instructions: usize = 0;
        for (&node_id, cfg_node) in &analysis.cfg_nodes {
            if !visited.contains(&node_id) {
                continue;
            }

            total_instructions += cfg_node.instructions.end - cfg_node.instructions.start;

            if cfg_node.instructions.is_empty() {
                continue;
            }

            let last_insn = &analysis.instructions[cfg_node.instructions.end - 1];
            let is_jmp = last_insn.opc & 7 == ebpf::BPF_JMP;
            if is_jmp {
                let opc = last_insn.opc;
                let is_conditional = opc != 0x05 && opc != 0x85 && opc != 0x8d && opc != 0x95;
                if is_conditional {
                    total_conditional += cfg_node.destinations.len();
                }
            }
        }

        Some((total_conditional, total_instructions))
    }

    pub fn add_program(&mut self, program_id: &Pubkey, program_path: &str) -> Result<()> {
        let actual_path = if let Ok(override_path) = std::env::var("FUZZ_PROGRAM_SO") {
            eprintln!(
                "[COVERAGE] Program binary override: {} -> {}",
                program_path, override_path
            );
            override_path
        } else {
            program_path.to_string()
        };
        let program_data = std::fs::read(&actual_path)?;
        self.add_program_from_bytes(program_id, &program_data)
    }

    /// Load a program from raw ELF bytes into the SVM.
    ///
    /// Same as `add_program()` but takes `&[u8]` instead of a file path.
    /// Runs coverage analysis and stores program data for debuggable SVM reloading.
    pub fn add_program_from_bytes(
        &mut self,
        program_id: &Pubkey,
        program_data: &[u8],
    ) -> Result<()> {
        // Honor FUZZ_PROGRAM_SO override even when the caller supplies raw
        // bytes (e.g. `rpc_clone` cloning an executable program from mainnet).
        // Without this, `--program-so` silently does nothing for rpc-cloned
        // programs and coverage replay ends up executing the wrong binary.
        let override_bytes;
        let program_data: &[u8] = if let Ok(override_path) = std::env::var("FUZZ_PROGRAM_SO") {
            eprintln!(
                "[COVERAGE] Program binary override: <{} bytes> -> {}",
                program_data.len(),
                override_path
            );
            override_bytes = std::fs::read(&override_path).with_context(|| {
                format!("failed to read FUZZ_PROGRAM_SO override at {override_path}")
            })?;
            &override_bytes
        } else {
            program_data
        };

        // Run static analysis to get total edge and instruction count for coverage percentages
        if let Some((total_edges, total_instructions)) =
            Self::analyze_program_coverage(program_data)
        {
            Arc::make_mut(&mut self.program_coverage_totals)
                .insert(*program_id, (total_edges, total_instructions));
        }

        self.svm
            .add_program(program_id.clone(), program_data)
            .map_err(|e| anyhow::anyhow!("failed to load program {}: {:?}", program_id, e))?;
        // Store program data for reloading into debuggable SVMs
        std::sync::Arc::make_mut(&mut self.programs).push(ProgramData {
            program_id: *program_id,
            data: program_data.to_vec(),
        });
        Ok(())
    }

    /// Create an `AccountCloner` for fetching accounts from a Solana RPC endpoint.
    ///
    /// Accounts are cached to `.fuzz-cache/accounts/` by default.
    /// Requires the `rpc-clone` feature.
    #[cfg(feature = "rpc-clone")]
    pub fn clone_from_rpc(&mut self, rpc_url: &str) -> AccountCloner<'_> {
        AccountCloner::new(self, rpc_url)
    }

    pub fn from_svm(svm: LiteSVM) -> Self {
        Self {
            svm,
            pending_instructions: Vec::new(),
            pending_signers: Vec::new(),
            programs: std::sync::Arc::new(Vec::new()),
            tracked_accounts: Arc::new(HashSet::new()),
            program_coverage_totals: Arc::new(HashMap::new()),
            snapshot: None,
            dirty_tracker: snapshot::DirtyTracker::new(),
            account_mutation: account_mutation::config_from_env(),
            sigverify: false,
        }
    }

    pub fn into_svm(self) -> LiteSVM {
        self.svm
    }

    /// Clone this context and set an invocation callback for coverage tracking.
    /// The source SVM must have been created with debuggable mode (via CRUCIBLE_FUZZ_DEBUGGABLE env var)
    /// for register tracing to work. Cloning preserves the debuggable state and loaded programs.
    ///
    /// NOTE: For better performance in fuzzing loops, prefer using `set_invocation_callback` after
    /// cloning the fixture instead of this method. This method performs an additional SVM clone
    /// beyond the fixture clone, which can be expensive.
    pub fn clone_with_invocation_callback<C: InvocationInspectCallback + 'static>(
        &self,
        callback: C,
    ) -> Self {
        // Just clone the SVM directly and set callback - don't use builder methods
        // as they may create a fresh SVM and lose account data
        let mut cloned_svm = self.svm.clone();
        cloned_svm.set_invocation_inspect_callback(callback);

        Self {
            svm: cloned_svm,
            pending_instructions: self.pending_instructions.clone(),
            pending_signers: self
                .pending_signers
                .iter()
                .map(|k| k.insecure_clone())
                .collect(),
            programs: self.programs.clone(),
            tracked_accounts: self.tracked_accounts.clone(),
            program_coverage_totals: self.program_coverage_totals.clone(),
            snapshot: None,
            dirty_tracker: snapshot::DirtyTracker::new(),
            account_mutation: self.account_mutation.clone(),
            sigverify: false,
        }
    }

    /// Set an invocation callback for coverage tracking on this context.
    /// Unlike `clone_with_invocation_callback`, this modifies the context in place
    /// without performing an additional SVM clone.
    ///
    /// The SVM must have been created with debuggable mode (via CRUCIBLE_FUZZ_DEBUGGABLE env var)
    /// for register tracing to work.
    ///
    /// Usage pattern for fuzzing loops:
    /// ```ignore
    /// let mut fixture = template_fixture.clone();  // Single clone
    /// fixture.ctx.set_invocation_callback(callback);  // No additional clone
    /// ```
    pub fn set_invocation_callback<C: InvocationInspectCallback + 'static>(&mut self, callback: C) {
        self.svm.set_invocation_inspect_callback(callback);
    }

    /// Track an account pubkey so it gets copied when cloning with invocation callback.
    /// Called internally by account builders.
    pub fn track_account(&mut self, pubkey: Pubkey) {
        Arc::make_mut(&mut self.tracked_accounts).insert(pubkey);
    }

    /// Enable account-mutation probes.
    ///
    /// The first time each instruction type executes with a succeeding baseline transaction, its
    /// accounts are probed for missing constraint checks (owner, ...). Probes run on cloned SVMs
    /// and never change the real transaction's outcome.
    pub fn enable_account_mutation(&mut self) -> &mut Self {
        self.account_mutation.enable();
        self
    }

    /// Disable account-mutation probes.
    pub fn disable_account_mutation(&mut self) -> &mut Self {
        self.account_mutation.disable();
        self
    }

    /// Set whether owner mutation should skip off-curve account addresses.
    ///
    /// This is enabled by default because mutating owner in-place at a
    /// key-pinned PDA fabricates a state attackers cannot normally create.
    /// Set this to `false` only when the harness intentionally wants to probe
    /// reachable wrong-owner PDA states.
    pub fn set_owner_mutation_skip_pdas(&mut self, skip_pdas: bool) -> &mut Self {
        self.account_mutation.set_skip_pda_candidates(skip_pdas);
        self
    }

    /// Mark an account as unverified for account-mutation identity probes.
    ///
    /// Unverified accounts are skipped by owner/PDA probes because their
    /// identity is not security-relevant for the harness.
    pub fn mark_owner_unverified(&mut self, pubkey: Pubkey) -> &mut Self {
        self.account_mutation.mark_unverified(pubkey);
        self
    }

    /// Mark multiple accounts as unverified for owner mutation.
    pub fn mark_owners_unverified<I, P>(&mut self, pubkeys: I) -> &mut Self
    where
        I: IntoIterator<Item = P>,
        P: std::borrow::Borrow<Pubkey>,
    {
        for pubkey in pubkeys {
            self.account_mutation.mark_unverified(*pubkey.borrow());
        }
        self
    }

    pub(crate) fn maybe_probe_account_mutation(
        &self,
        instructions: &[Instruction],
        signers: &[&Keypair],
        payer: &Keypair,
    ) {
        account_mutation::maybe_probe_account_mutation(
            &self.svm,
            &self.account_mutation,
            self.tracked_accounts.as_ref(),
            instructions,
            signers,
            payer,
            self.sigverify,
        );
    }

    /// Get count of tracked accounts (for debugging)
    pub fn tracked_accounts_count(&self) -> usize {
        self.tracked_accounts.len()
    }

    /// Get count of loaded programs (for debugging)
    pub fn programs_count(&self) -> usize {
        self.programs.len()
    }

    /// Get total number of accounts in the SVM's internal HashMap.
    /// Used to detect unbounded account growth across fuzzing iterations.
    pub fn svm_account_count(&self) -> usize {
        self.svm.accounts_db().inner.len()
    }

    /// Check if a specific account exists in the SVM (for debugging)
    pub fn account_exists(&self, pubkey: &Pubkey) -> bool {
        self.svm.get_account(pubkey).is_some()
    }

    /// Get the total CFG edge and instruction counts for all loaded programs.
    /// Returns HashMap<Pubkey, (total_edges, total_instructions)>
    /// Used by the fuzzer to calculate coverage percentages.
    pub fn get_program_coverage_totals(&self) -> &HashMap<Pubkey, (usize, usize)> {
        &self.program_coverage_totals
    }

    /// Get program binaries for CFG analysis.
    /// Returns a map from program pubkey to binary data.
    /// Used by the fuzzer for per-instruction CFG divergence analysis.
    pub fn get_program_binaries(&self) -> HashMap<Pubkey, Vec<u8>> {
        self.programs
            .iter()
            .map(|p| (p.program_id, p.data.clone()))
            .collect()
    }

    /// Get program binary by pubkey (for CFG analysis).
    pub fn get_program_binary(&self, pubkey: &Pubkey) -> Option<&[u8]> {
        self.programs
            .iter()
            .find(|p| &p.program_id == pubkey)
            .map(|p| p.data.as_slice())
    }

    // =========================================================================
    // Snapshot/Restore API (always-on in fuzz mode)
    // =========================================================================

    /// Take a snapshot of ALL accounts in the SVM.
    /// Called once after setup, before the fuzz loop begins.
    pub fn take_snapshot(&mut self) {
        // Sync tracked_accounts with everything in the SVM so that
        // tracked_accounts_count() reflects reality (used in diagnostics).
        let db_keys: Vec<Pubkey> = self.svm.accounts_db().inner.keys().copied().collect();
        {
            let tracked = Arc::make_mut(&mut self.tracked_accounts);
            for pubkey in &db_keys {
                tracked.insert(*pubkey);
            }
        }
        // Snapshot ALL accounts — not just tracked/dirty ones.
        // This is the same approach used by stateful multicore mode (take_all)
        // and costs only a one-time O(all_accounts) at setup. Per-iteration
        // restore remains O(dirty) since it only touches dirty_tracker accounts.
        self.snapshot = Some(snapshot::SvmSnapshot::take_all(&self.svm));
        // Clear the dirty tracker so it's fresh for the first iteration
        self.dirty_tracker.clear();
    }

    /// Prepare for a new iteration: clear dirty tracker and pending state.
    /// Called at the start of each fuzzing iteration.
    pub fn begin_iteration(&mut self) {
        self.dirty_tracker.clear();
        // Clear pending instructions/signers from previous iteration
        self.pending_instructions.clear();
        self.pending_signers.clear();
    }

    /// Restore only dirty accounts from snapshot. Returns count restored.
    /// Much faster than full SVM clone when only ~5-20 accounts were modified.
    pub fn restore_snapshot(&mut self) -> usize {
        if let Some(ref snap) = self.snapshot {
            snap.restore(&mut self.svm, &self.dirty_tracker)
        } else {
            0
        }
    }

    /// Whether a snapshot has been taken.
    pub fn has_snapshot(&self) -> bool {
        self.snapshot.is_some()
    }

    /// Get the dirty tracker for the current iteration.
    pub fn dirty_tracker(&self) -> &snapshot::DirtyTracker {
        &self.dirty_tracker
    }

    /// Account Creation Helpers

    // Create a basic default account
    pub fn create_account(&mut self) -> GenericAccountBuilder<'_> {
        GenericAccountBuilder {
            ctx: self,
            address: Pubkey::default(),
            account_state: Account {
                lamports: 0,
                data: vec![],
                owner: system_program::id(),
                executable: false,
                rent_epoch: 0,
            },
            owner_unverified: false,
        }
    }

    // Create a mint account
    pub fn create_mint(&mut self) -> MintAccountBuilder<'_> {
        let rent = Rent::default();
        MintAccountBuilder {
            ctx: self,
            address: Pubkey::default(),
            account_state: Account {
                lamports: rent.minimum_balance(spl_token::state::Mint::LEN),
                data: vec![0; spl_token::state::Mint::LEN],
                owner: spl_token::id(),
                executable: false,
                rent_epoch: 0,
            },
            owner_unverified: false,
            mint: spl_token::state::Mint {
                mint_authority: COption::None,
                supply: 0,
                decimals: 0,
                is_initialized: true,
                freeze_authority: COption::None,
            },
        }
    }
    pub fn create_token_account(&mut self) -> TokenAccountBuilder<'_> {
        let rent = Rent::default();
        TokenAccountBuilder {
            ctx: self,
            address: Pubkey::default(),
            account_state: Account {
                lamports: rent.minimum_balance(spl_token::state::Account::LEN),
                data: vec![0; spl_token::state::Account::LEN],
                owner: spl_token::id(),
                executable: false,
                rent_epoch: 0,
            },
            owner_unverified: false,
            token_state: spl_token::state::Account {
                mint: Pubkey::default(),
                owner: Pubkey::default(),
                amount: 0,
                delegate: COption::None,
                state: spl_token::state::AccountState::Initialized,
                is_native: COption::None,
                delegated_amount: 0,
                close_authority: COption::None,
            },
        }
    }

    /// Transfer tokens between accounts
    pub fn transfer_tokens(
        &mut self,
        from: &Pubkey,
        to: &Pubkey,
        owner: &Keypair,
        amount: u64,
    ) -> anyhow::Result<()> {
        self.raw_call(spl_token::instruction::transfer(
            &spl_token::id(),
            from,
            to,
            &owner.pubkey(),
            &[],
            amount,
        )?)
        .signers(&[owner])
        .send()?;
        Ok(())
    }

    pub fn mint_to(
        &mut self,
        mint: &Pubkey,
        destination: &Pubkey,
        amount: u64,
        authority: &Rc<Keypair>,
    ) -> anyhow::Result<()> {
        self.raw_call(spl_token::instruction::mint_to(
            &spl_token::id(),
            mint,
            destination,
            &authority.pubkey(),
            &[],
            amount,
        )?)
        .signers(&[&**authority])
        .send()?;
        Ok(())
    }

    pub fn warp_to_slot(&mut self, slot: u64) {
        self.dirty_tracker.mark_clock_dirty(slot);
        self.svm.warp_to_slot(slot);
    }

    pub fn advance_slots(&mut self, slots: u64) {
        let current_slot = self.slot();
        let target_slot = current_slot + slots;
        self.dirty_tracker.mark_clock_dirty(target_slot);
        self.svm.warp_to_slot(target_slot);
    }

    pub fn set_sysvar<T>(&mut self, sysvar: &T) -> ()
    where
        T: solana_sysvar::SysvarSerialize,
    {
        self.svm.set_sysvar::<T>(sysvar);
    }

    /// Getters

    pub fn slot(&self) -> u64 {
        self.svm.get_sysvar::<Clock>().slot
    }

    /// Returns the slot that the next transaction will likely see (current + 1)
    pub fn next_slot(&self) -> u64 {
        self.slot() + 1
    }

    // =========================================================================
    // Account Read/Write API
    //
    // **Raw Account** (any format):
    //   - `read_account` / `get_account` — returns raw `Account`
    //   - `write_account` — sets raw `Account`
    //   - `update_account` — closure-based read-modify-write on raw bytes
    //
    // **Anchor / Borsh** (`#[account]` structs):
    //   - `read_anchor_account<T>` — auto discriminator via `T::DISCRIMINATOR`
    //   - `read_account_with_discriminator<T>` — explicit discriminator length
    //   - `write_anchor_account<T>` — serializes with discriminator
    //
    // **Zero-Copy / Bytemuck** (`#[account(zero_copy)]` structs):
    //   - `read_zero_copy_account<T>` — 8-byte discriminator (standard Anchor)
    //   - `read_zero_copy_account_with_discriminator<T>` — explicit discriminator length
    //   - `write_zero_copy_account<T>` — preserves 8-byte discriminator
    //   - `write_zero_copy_account_with_discriminator<T>` — explicit discriminator length
    //
    // **Utilities:**
    //   - `account_has_data` — existence + minimum size check
    //   - `token_balance` — SPL token amount shorthand
    // =========================================================================

    /// Check if account exists AND has at least `min_size` bytes of data
    pub fn account_has_data(&self, pubkey: &Pubkey, min_size: usize) -> bool {
        self.svm
            .get_account(pubkey)
            .map(|acc| acc.data.len() >= min_size)
            .unwrap_or(false)
    }

    pub fn get_account(&self, address: &Pubkey) -> Result<Account> {
        self.read_account(address)
    }

    // Read an account at a Pubkey
    pub fn read_account(&self, address: &Pubkey) -> Result<Account> {
        self.svm
            .get_account(address)
            .ok_or_else(|| anyhow::anyhow!("Account not found: {}", address))
    }

    /// Read anchor account at address and deserialize the data.
    /// Uses the type's DISCRIMINATOR to determine how many bytes to skip.
    pub fn read_anchor_account<T: AnchorDeserialize + Discriminator>(
        &self,
        address: &Pubkey,
    ) -> Result<T> {
        let account = self.read_account(address)?;
        let disc_len = T::DISCRIMINATOR.len();

        if account.data.len() < disc_len {
            return Err(anyhow::anyhow!(
                "Account data too small for discriminator (need {} bytes, got {})",
                disc_len,
                account.data.len()
            ));
        }

        // Deserialize from bytes after discriminator
        T::deserialize(&mut &account.data[disc_len..])
            .map_err(|e| anyhow::anyhow!("Failed to deserialize account: {}", e))
    }

    /// Read account with explicit discriminator length (for non-standard accounts).
    pub fn read_account_with_discriminator<T: AnchorDeserialize>(
        &self,
        address: &Pubkey,
        discriminator_len: usize,
    ) -> Result<T> {
        let account = self.read_account(address)?;

        if account.data.len() < discriminator_len {
            return Err(anyhow::anyhow!(
                "Account data too small for discriminator (need {} bytes, got {})",
                discriminator_len,
                account.data.len()
            ));
        }

        T::deserialize(&mut &account.data[discriminator_len..])
            .map_err(|e| anyhow::anyhow!("Failed to deserialize account: {}", e))
    }

    pub fn token_balance(&self, token_account: &Pubkey) -> u64 {
        self.svm
            .get_account(token_account)
            .and_then(|acc| spl_token::state::Account::unpack(&acc.data).ok())
            .map(|state| state.amount)
            .unwrap_or(0)
    }

    /// Setters

    // Write account directly to SVM
    pub fn write_account(&mut self, address: &Pubkey, account: Account) -> Result<()> {
        Arc::make_mut(&mut self.tracked_accounts).insert(*address);
        self.dirty_tracker.mark_account_dirty(address);
        let _ = self.svm.set_account(*address, account);
        Ok(())
    }

    // Serialize with discriminator, write to SVM
    pub fn write_anchor_account<T: AnchorSerialize + Discriminator>(
        &mut self,
        address: &Pubkey,
        data: &T,
    ) -> Result<()> {
        // Read existing account to preserve lamports, owner, etc.
        let mut account = self.read_account(address)?;

        // Build new data: discriminator + serialized T
        let mut account_data = T::DISCRIMINATOR.to_vec();
        data.serialize(&mut account_data)?;

        // Update account data and write back
        account.data = account_data;
        self.dirty_tracker.mark_account_dirty(address);
        let _ = self.svm.set_account(*address, account);

        Ok(())
    }

    /// Read a zero-copy account (skips 8-byte discriminator).
    ///
    /// Read a zero-copy account with standard 8-byte discriminator.
    ///
    /// Use this for accounts with `#[account(zero_copy)]` attribute which use
    /// bytemuck for serialization instead of Borsh.
    ///
    /// # Example
    /// ```ignore
    /// let reserve: Reserve = ctx.read_zero_copy_account(&reserve_addr)?;
    /// println!("Reserve slot: {}", reserve.last_update.slot);
    /// ```
    pub fn read_zero_copy_account<T: bytemuck::Pod>(&self, address: &Pubkey) -> Result<T> {
        self.read_zero_copy_account_with_discriminator(address, 8)
    }

    /// Read a zero-copy account with explicit discriminator length.
    ///
    /// Use this for accounts with non-standard discriminator sizes.
    ///
    /// # Example
    /// ```ignore
    /// // For accounts with 1-byte discriminator
    /// let vault: StarVault = ctx.read_zero_copy_account_with_discriminator(&vault_addr, 1)?;
    /// ```
    pub fn read_zero_copy_account_with_discriminator<T: bytemuck::Pod>(
        &self,
        address: &Pubkey,
        discriminator_len: usize,
    ) -> Result<T> {
        let account = self.read_account(address)?;
        let required_size = discriminator_len + std::mem::size_of::<T>();
        if account.data.len() < required_size {
            return Err(anyhow::anyhow!(
                "Account data too small for zero-copy struct: got {} bytes, need {} bytes (discriminator: {})",
                account.data.len(),
                required_size,
                discriminator_len
            ));
        }
        Ok(*bytemuck::from_bytes::<T>(
            &account.data[discriminator_len..discriminator_len + std::mem::size_of::<T>()],
        ))
    }

    /// Write a zero-copy account (preserves 8-byte discriminator).
    ///
    /// Use this for accounts with `#[account(zero_copy)]` attribute which use
    /// bytemuck for serialization instead of Borsh.
    ///
    /// # Example
    /// ```ignore
    /// let mut reserve: Reserve = ctx.read_zero_copy_account(&reserve_addr)?;
    /// reserve.last_update.mark_fresh(current_slot);
    /// ctx.write_zero_copy_account(&reserve_addr, &reserve)?;
    /// ```
    pub fn write_zero_copy_account<T: bytemuck::Pod>(
        &mut self,
        address: &Pubkey,
        data: &T,
    ) -> Result<()> {
        self.write_zero_copy_account_with_discriminator(address, data, 8)
    }

    /// Write a zero-copy account with explicit discriminator length.
    pub fn write_zero_copy_account_with_discriminator<T: bytemuck::Pod>(
        &mut self,
        address: &Pubkey,
        data: &T,
        discriminator_len: usize,
    ) -> Result<()> {
        let mut account = self.read_account(address)?;
        let bytes = bytemuck::bytes_of(data);
        let required_size = discriminator_len + bytes.len();
        if account.data.len() < required_size {
            return Err(anyhow::anyhow!(
                "Account data too small for zero-copy struct: got {} bytes, need {} bytes",
                account.data.len(),
                required_size
            ));
        }
        account.data[discriminator_len..discriminator_len + bytes.len()].copy_from_slice(bytes);
        Arc::make_mut(&mut self.tracked_accounts).insert(*address);
        self.dirty_tracker.mark_account_dirty(address);
        let _ = self.svm.set_account(*address, account);
        Ok(())
    }

    /// Update account data using a closure. Enables atomic read-modify-write pattern.
    ///
    /// # Example
    /// ```ignore
    /// ctx.update_account(&reserve_pubkey, |data| {
    ///     // Modify data in place (e.g., using bytemuck)
    ///     let reserve: &mut Reserve = bytemuck::from_bytes_mut(&mut data[8..]);
    ///     reserve.config.loan_to_value_pct = 80;
    /// })?;
    /// ```
    pub fn update_account<F>(&mut self, pubkey: &Pubkey, f: F) -> Result<()>
    where
        F: FnOnce(&mut Vec<u8>),
    {
        let mut account = self.read_account(pubkey)?;
        f(&mut account.data);
        self.write_account(pubkey, account)
    }

    /// Callers - each returns a builder

    // Escape hatch for raw instructions
    pub fn raw_call(&mut self, instruction: Instruction) -> InstructionBuilder<'_> {
        InstructionBuilder {
            ctx: self,
            instruction,
            signers: vec![],
            fee_payer: None,
        }
    }

    // For calling Anchor programs dynamically
    pub fn program(&mut self, program_id: Pubkey) -> ProgramBuilder<'_> {
        ProgramBuilder {
            ctx: self,
            instruction: Instruction {
                program_id,
                accounts: vec![],
                data: vec![],
            },
            signers: vec![],
            fee_payer: None, // Use first signer by default
        }
    }

    // For batching multiple instructions
    pub fn transaction(&mut self) -> TransactionBuilder<'_> {
        TransactionBuilder {
            ctx: self,
            instructions: vec![],
            signers: vec![],
        }
    }

    pub fn send_batch(&mut self) -> Result<Option<TxOutcome>> {
        // Empty queue is a noop
        if self.pending_instructions.is_empty() {
            return Ok(None);
        }

        let debug = is_fuzz_debug();
        let num_ixs = self.pending_instructions.len();

        // Deduplicate signers while preserving order (first = fee payer)
        let mut seen = std::collections::HashSet::new();
        let unique_signers: Vec<&Keypair> = self
            .pending_signers
            .iter()
            .filter(|k| seen.insert(k.pubkey()))
            .collect();

        let fee_payer_pubkey = unique_signers
            .first()
            .map(|k| k.pubkey())
            .unwrap_or_default();

        let fee_payer = unique_signers.first().map(|k| *k).ok_or(anyhow::anyhow!(
            "At least one signer required for send_batch. The first signer is the fee payer."
        ))?;

        if debug {
            eprintln!("[TX] Sending batch with {} instructions", num_ixs);
            for (i, ix) in self.pending_instructions.iter().enumerate() {
                eprintln!("[TX]   ix[{}]: program={}", i, ix.program_id);
            }
        }

        // Pre-tx: dirty tracking
        let __t_pre = std::time::Instant::now();
        self.dirty_tracker
            .record_tx(&self.pending_instructions, &fee_payer_pubkey);
        SEND_BATCH_PRE_NS.with(|c| c.set(c.get() + __t_pre.elapsed().as_nanos() as u64));

        // Owner-mutation probe runs on a cloned SVM and never replaces the real outcome.
        self.maybe_probe_account_mutation(&self.pending_instructions, &unique_signers, fee_payer);

        // SVM execution: send transaction
        let __t_svm = std::time::Instant::now();
        let instructions = std::mem::take(&mut self.pending_instructions);
        let result = instruction_builder::send_transaction(
            &mut self.svm,
            instructions,
            &unique_signers,
            fee_payer,
            self.sigverify,
        )?;
        SEND_BATCH_SVM_NS.with(|c| c.set(c.get() + __t_svm.elapsed().as_nanos() as u64));

        // Post-tx: outcome parsing
        let __t_post = std::time::Instant::now();
        let outcome = tx_result_to_outcome(result);

        // Track tx success/failure for monitor display (works for all modes)
        increment_action_count();
        if outcome.is_success() {
            increment_action_success_count();
        }

        if debug {
            match &outcome {
                TxOutcome::Success {
                    compute_units,
                    logs,
                    ..
                } => {
                    eprintln!("[TX] SUCCESS - compute_units={}, logs:", compute_units);
                    for log in logs {
                        eprintln!("[TX]   {}", log);
                    }
                }
                TxOutcome::ProgramError {
                    error,
                    error_code,
                    logs,
                    ..
                } => {
                    eprintln!("[TX] FAILED - error: {:?}", error);
                    if let Some(code) = error_code {
                        eprintln!("[TX]   error code: {}", code);
                    }
                    eprintln!("[TX]   logs:");
                    for log in logs {
                        eprintln!("[TX]   {}", log);
                    }
                }
            }
        }
        SEND_BATCH_POST_NS.with(|c| c.set(c.get() + __t_post.elapsed().as_nanos() as u64));

        // Clear signers queue (pending_instructions already taken via std::mem::take)
        self.pending_signers.clear();

        Ok(Some(outcome))
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Violation tracking tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_violation_tracking_basic() {
        // Clear any existing violation
        let _ = take_violation();

        // No violation initially
        assert!(!has_violation());
        assert!(take_violation().is_none());

        // Record a violation
        record_violation("test violation".to_string());

        // Violation should be recorded
        assert!(has_violation());

        // Taking the violation should return it and clear it
        let v = take_violation();
        assert_eq!(v, Some("test violation".to_string()));
        assert!(!has_violation());
        assert!(take_violation().is_none());
    }

    #[test]
    fn test_violation_only_records_first() {
        let _ = take_violation();

        record_violation("first".to_string());
        record_violation("second".to_string());
        record_violation("third".to_string());

        // Only the first violation should be recorded
        let v = take_violation();
        assert_eq!(v, Some("first".to_string()));
    }

    // -------------------------------------------------------------------------
    // Action history tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_action_history() {
        clear_action_history();

        assert!(get_action_history().is_empty());

        push_action_record("action_deposit", serde_json::json!({"amount": 100}), true);
        push_action_record("action_withdraw", serde_json::json!({"amount": 50}), false);

        let history = get_action_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].name, "action_deposit");
        assert!(history[0].success);
        assert_eq!(history[0].error_code, None);
        assert_eq!(history[1].name, "action_withdraw");
        assert!(!history[1].success);
        assert_eq!(history[1].error_code, None);

        // Test with error code passthrough
        clear_action_history();
        set_last_error_code(Some(6051));
        push_action_record("action_borrow", serde_json::json!({}), false);
        let history = get_action_history();
        assert_eq!(history[0].error_code, Some(6051));
        // Verify TLS is cleared after take
        push_action_record("action_deposit", serde_json::json!({}), true);
        let history = get_action_history();
        assert_eq!(history[1].error_code, None);

        clear_action_history();
        assert!(get_action_history().is_empty());
    }

    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    // Violation action index tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_violation_action_index() {
        clear_violation_tracking();

        assert!(get_violation_action_index().is_none());

        set_total_actions(5);
        set_violation_action_index(2);

        assert_eq!(get_violation_action_index(), Some(2));

        // Only records first violation index
        set_violation_action_index(3);
        assert_eq!(get_violation_action_index(), Some(2));

        clear_violation_tracking();
        assert!(get_violation_action_index().is_none());
    }

    // -------------------------------------------------------------------------
    // IntoActionSuccess trait tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_into_action_success_unit() {
        assert!(().into_success());
    }

    #[test]
    fn test_into_action_success_result() {
        let ok: Result<(), &str> = Ok(());
        let err: Result<(), &str> = Err("error");

        assert!(ok.into_success());
        assert!(!err.into_success());
    }

    #[test]
    fn test_into_action_success_bool() {
        assert!(true.into_success());
        assert!(!false.into_success());
    }

    // -------------------------------------------------------------------------
    // Iteration tracking tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_iteration_tracking() {
        set_current_iteration(42);
        assert_eq!(get_current_iteration(), 42);

        set_current_iteration(100);
        assert_eq!(get_current_iteration(), 100);
    }

    #[test]
    fn test_test_name_tracking() {
        set_current_test_name("my_test");
        assert_eq!(get_current_test_name(), Some("my_test".to_string()));
    }

    // -------------------------------------------------------------------------
    // Crash metadata tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_build_crash_metadata() {
        clear_action_history();
        set_current_test_name("test_func");
        set_current_iteration(999);

        push_action_record("action_a", serde_json::json!({"x": 1}), true);

        let meta = build_crash_metadata(Some(12345));

        assert_eq!(meta.test_name, "test_func");
        assert_eq!(meta.iteration, 999);
        assert_eq!(meta.seed, Some(12345));
        assert_eq!(meta.actions.len(), 1);
        assert_eq!(meta.actions[0].name, "action_a");
        assert_eq!(meta.actions[0].error_code, None);
    }

    // -------------------------------------------------------------------------
    // TxOutcome tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_tx_outcome_helpers() {
        let success = TxOutcome::Success {
            compute_units: 100,
            logs: vec!["log1".to_string()],
            signature: Signature::default(),
            inner_instructions: vec![],
            return_data: TransactionReturnData::default(),
            fee: 5000,
        };

        assert!(success.is_success());
        assert!(!success.is_error());
        assert!(success.error_code().is_none());
        assert_eq!(success.compute_units(), Some(100));
        assert_eq!(success.logs().len(), 1);
        assert_eq!(success.fee(), 5000);

        let error = TxOutcome::ProgramError {
            error: TransactionError::AccountInUse,
            error_code: Some(6051),
            instruction_index: Some(0),
            logs: vec!["error log".to_string()],
            signature: Signature::default(),
            inner_instructions: vec![],
            return_data: TransactionReturnData::default(),
            fee: 0,
        };

        assert!(!error.is_success());
        assert!(error.is_error());
        assert_eq!(error.error_code(), Some(6051));
        assert!(error.compute_units().is_none());
        assert_eq!(error.fee(), 0);
    }

    #[test]
    fn test_tx_outcome_into_result() {
        let success = TxOutcome::Success {
            compute_units: 100,
            logs: vec![],
            signature: Signature::default(),
            inner_instructions: vec![],
            return_data: TransactionReturnData::default(),
            fee: 0,
        };
        assert!(success.into_result().is_ok());

        let error = TxOutcome::ProgramError {
            error: TransactionError::AccountInUse,
            error_code: Some(6051),
            instruction_index: Some(0),
            logs: vec![],
            signature: Signature::default(),
            inner_instructions: vec![],
            return_data: TransactionReturnData::default(),
            fee: 0,
        };
        let err = error.into_result().unwrap_err();
        assert_eq!(err.error_code, Some(6051));
        assert_eq!(err.fee, 0);
    }

    // -------------------------------------------------------------------------
    // format_json_value tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_format_json_value() {
        assert_eq!(format_json_value(&serde_json::json!(null)), "null");
        assert_eq!(format_json_value(&serde_json::json!(true)), "true");
        assert_eq!(format_json_value(&serde_json::json!(42)), "42");
        assert_eq!(format_json_value(&serde_json::json!("hello")), "\"hello\"");
        assert_eq!(
            format_json_value(&serde_json::json!([1, 2, 3])),
            "[1, 2, 3]"
        );
        assert_eq!(format_json_value(&serde_json::json!({"a": 1})), "{a: 1}");
    }

    // -------------------------------------------------------------------------
    // Snapshot/Restore integration tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_snapshot_basic_roundtrip() {
        let mut ctx = TestContext::new();

        // Write some accounts
        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        ctx.write_account(
            &pk1,
            Account {
                lamports: 1_000_000,
                data: vec![1, 2, 3, 4],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        ctx.write_account(
            &pk2,
            Account {
                lamports: 2_000_000,
                data: vec![10, 20, 30],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Take snapshot
        ctx.take_snapshot();
        assert!(ctx.has_snapshot());

        // Begin iteration (clears dirty tracker)
        ctx.begin_iteration();

        // Modify accounts
        ctx.write_account(
            &pk1,
            Account {
                lamports: 999,
                data: vec![99, 99, 99, 99],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        ctx.write_account(
            &pk2,
            Account {
                lamports: 0,
                data: vec![],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Verify accounts are modified
        let acc1 = ctx.read_account(&pk1).unwrap();
        assert_eq!(acc1.lamports, 999);
        assert_eq!(acc1.data, vec![99, 99, 99, 99]);

        // Restore snapshot
        let restored = ctx.restore_snapshot();
        assert_eq!(restored, 2); // 2 dirty accounts

        // Verify accounts are back to original state
        let acc1 = ctx.read_account(&pk1).unwrap();
        assert_eq!(acc1.lamports, 1_000_000);
        assert_eq!(acc1.data, vec![1, 2, 3, 4]);

        let acc2 = ctx.read_account(&pk2).unwrap();
        assert_eq!(acc2.lamports, 2_000_000);
        assert_eq!(acc2.data, vec![10, 20, 30]);
    }

    #[test]
    fn test_snapshot_created_account_removed_on_restore() {
        let mut ctx = TestContext::new();

        // Write one initial account
        let pk_initial = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        ctx.write_account(
            &pk_initial,
            Account {
                lamports: 1_000_000,
                data: vec![1, 2, 3],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        ctx.take_snapshot();
        ctx.begin_iteration();

        // Create a new account that didn't exist at snapshot time
        let pk_new = Pubkey::new_unique();
        ctx.write_account(
            &pk_new,
            Account {
                lamports: 500_000,
                data: vec![42],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Verify new account exists
        assert!(ctx.read_account(&pk_new).is_ok());

        // Restore: new account should be zeroed out
        ctx.restore_snapshot();

        // Account should now be zeroed (lamports=0 means effectively deleted)
        let acc = ctx.svm.get_account(&pk_new);
        match acc {
            Some(a) => assert_eq!(a.lamports, 0, "Created account should be zeroed on restore"),
            None => {} // Also acceptable — SVM may remove zero-lamport accounts
        }

        // Initial account should still be intact
        let acc_initial = ctx.read_account(&pk_initial).unwrap();
        assert_eq!(acc_initial.lamports, 1_000_000);
    }

    #[test]
    fn test_snapshot_clock_restore() {
        let mut ctx = TestContext::new();

        // Set a known slot before snapshot
        ctx.warp_to_slot(100);
        let original_slot = ctx.slot();
        assert_eq!(original_slot, 100);

        ctx.take_snapshot();
        ctx.begin_iteration();

        // Advance the clock
        ctx.warp_to_slot(500);
        assert_eq!(ctx.slot(), 500);

        // Restore snapshot
        ctx.restore_snapshot();

        // Clock should be back to original
        assert_eq!(ctx.slot(), 100);
    }

    #[test]
    fn test_snapshot_multiple_iterations() {
        let mut ctx = TestContext::new();

        let pk = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        ctx.write_account(
            &pk,
            Account {
                lamports: 1_000_000,
                data: vec![0; 32],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        ctx.take_snapshot();

        // Simulate multiple fuzzing iterations
        for i in 0..5 {
            ctx.begin_iteration();

            // Each iteration modifies the account differently
            ctx.write_account(
                &pk,
                Account {
                    lamports: (i + 1) * 100,
                    data: vec![i as u8; 32],
                    owner,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();

            // Verify modification took effect
            let acc = ctx.read_account(&pk).unwrap();
            assert_eq!(acc.lamports, (i + 1) * 100);

            // Restore to original
            ctx.restore_snapshot();

            // Verify restoration
            let acc = ctx.read_account(&pk).unwrap();
            assert_eq!(acc.lamports, 1_000_000, "Failed on iteration {}", i);
            assert_eq!(acc.data, vec![0; 32], "Failed on iteration {}", i);
        }
    }

    #[test]
    fn test_snapshot_dirty_tracker_tracks_write_account() {
        let mut ctx = TestContext::new();

        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        ctx.write_account(
            &pk1,
            Account {
                lamports: 100,
                data: vec![],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        ctx.write_account(
            &pk2,
            Account {
                lamports: 200,
                data: vec![],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Both should be tracked as dirty
        assert!(ctx.dirty_tracker.dirty_accounts().contains(&pk1));
        assert!(ctx.dirty_tracker.dirty_accounts().contains(&pk2));
        assert_eq!(ctx.dirty_tracker.dirty_count(), 2);

        // begin_iteration clears the tracker and pending state
        ctx.begin_iteration();
        assert_eq!(ctx.dirty_tracker.dirty_count(), 0);
        assert!(ctx.pending_instructions.is_empty());
    }

    #[test]
    fn test_snapshot_dirty_tracker_tracks_clock() {
        let mut ctx = TestContext::new();

        assert!(!ctx.dirty_tracker.is_clock_dirty());

        ctx.warp_to_slot(100);
        assert!(ctx.dirty_tracker.is_clock_dirty());

        ctx.begin_iteration();
        assert!(!ctx.dirty_tracker.is_clock_dirty());

        ctx.advance_slots(10);
        assert!(ctx.dirty_tracker.is_clock_dirty());
    }

    #[test]
    fn test_snapshot_no_snapshot_returns_zero() {
        let mut ctx = TestContext::new();

        // Without taking a snapshot, restore should return 0
        assert!(!ctx.has_snapshot());
        let restored = ctx.restore_snapshot();
        assert_eq!(restored, 0);
    }

    #[test]
    fn test_snapshot_unmodified_accounts_untouched() {
        let mut ctx = TestContext::new();

        let pk_modified = Pubkey::new_unique();
        let pk_untouched = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        ctx.write_account(
            &pk_modified,
            Account {
                lamports: 100,
                data: vec![1, 2, 3],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        ctx.write_account(
            &pk_untouched,
            Account {
                lamports: 200,
                data: vec![4, 5, 6],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        ctx.take_snapshot();
        ctx.begin_iteration();

        // Only modify one account
        ctx.write_account(
            &pk_modified,
            Account {
                lamports: 999,
                data: vec![9, 9, 9],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Only 1 dirty account (pk_modified) should be restored
        let restored = ctx.restore_snapshot();
        assert_eq!(restored, 1);

        // Modified account restored
        let acc = ctx.read_account(&pk_modified).unwrap();
        assert_eq!(acc.lamports, 100);

        // Untouched account still has original data
        let acc = ctx.read_account(&pk_untouched).unwrap();
        assert_eq!(acc.lamports, 200);
        assert_eq!(acc.data, vec![4, 5, 6]);
    }

    #[test]
    fn test_snapshot_clone_does_not_inherit_snapshot() {
        let mut ctx = TestContext::new();

        let pk = Pubkey::new_unique();
        ctx.write_account(
            &pk,
            Account {
                lamports: 100,
                data: vec![],
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        ctx.take_snapshot();
        assert!(ctx.has_snapshot());

        // Clone should NOT have a snapshot
        let cloned = ctx.clone();
        assert!(!cloned.has_snapshot());

        // Clone should have a fresh dirty tracker
        assert_eq!(cloned.dirty_tracker.dirty_count(), 0);
    }

    #[test]
    fn test_snapshot_includes_dirty_tracker_accounts() {
        // Simulates CPI-created accounts: dirty tracker tracks them during setup
        // but they're not in tracked_accounts. take_snapshot() should include them.
        let mut ctx = TestContext::new();

        let pk_tracked = Pubkey::new_unique();
        let pk_cpi = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        // This goes through write_account → tracked_accounts
        ctx.write_account(
            &pk_tracked,
            Account {
                lamports: 100,
                data: vec![1],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Simulate a CPI-created account: manually set in SVM and mark dirty
        // (In real usage, this happens via record_tx during a send() call)
        let _ = ctx.svm.set_account(
            pk_cpi,
            Account {
                lamports: 200,
                data: vec![2],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        );
        ctx.dirty_tracker.mark_account_dirty(&pk_cpi);

        // take_snapshot should include pk_cpi even though it's not in tracked_accounts
        ctx.take_snapshot();
        assert!(ctx.has_snapshot());

        ctx.begin_iteration();

        // Modify the CPI-created account
        let _ = ctx.svm.set_account(
            pk_cpi,
            Account {
                lamports: 999,
                data: vec![9],
                owner,
                executable: false,
                rent_epoch: 0,
            },
        );
        ctx.dirty_tracker.mark_account_dirty(&pk_cpi);

        // Restore should bring it back
        ctx.restore_snapshot();
        let acc = ctx.svm.get_account(&pk_cpi).unwrap();
        assert_eq!(acc.lamports, 200);
        assert_eq!(acc.data, vec![2]);
    }

    #[test]
    fn test_snapshot_programs_arc_clone() {
        let mut ctx = TestContext::new();

        // Verify programs field uses Arc (clone is cheap)
        let pk = Pubkey::new_unique();
        ctx.write_account(
            &pk,
            Account {
                lamports: 100,
                data: vec![0; 1024],
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Clone should share program data via Arc
        let cloned = ctx.clone();
        assert_eq!(ctx.programs_count(), cloned.programs_count());
    }

    // =========================================================================
    // parse_error_code — TransactionError → Custom(N)
    // =========================================================================

    #[test]
    fn parse_error_code_custom() {
        use solana_instruction::error::InstructionError;
        let err = TransactionError::InstructionError(0, InstructionError::Custom(6051));
        assert_eq!(parse_error_code(&err), Some(6051));
    }

    #[test]
    fn parse_error_code_custom_zero() {
        use solana_instruction::error::InstructionError;
        let err = TransactionError::InstructionError(1, InstructionError::Custom(0));
        assert_eq!(parse_error_code(&err), Some(0));
    }

    #[test]
    fn parse_error_code_custom_large() {
        use solana_instruction::error::InstructionError;
        let err = TransactionError::InstructionError(0, InstructionError::Custom(u32::MAX));
        assert_eq!(parse_error_code(&err), Some(u32::MAX));
    }

    #[test]
    fn parse_error_code_non_custom_instruction_error() {
        use solana_instruction::error::InstructionError;
        let err = TransactionError::InstructionError(0, InstructionError::GenericError);
        assert_eq!(parse_error_code(&err), None);
    }

    #[test]
    fn parse_error_code_non_instruction_error() {
        let err = TransactionError::AccountInUse;
        assert_eq!(parse_error_code(&err), None);
    }

    // =========================================================================
    // parse_instruction_index — TransactionError → instruction index
    // =========================================================================

    #[test]
    fn parse_instruction_index_basic() {
        use solana_instruction::error::InstructionError;
        let err = TransactionError::InstructionError(0, InstructionError::Custom(42));
        assert_eq!(parse_instruction_index(&err), Some(0));
    }

    #[test]
    fn parse_instruction_index_nonzero() {
        use solana_instruction::error::InstructionError;
        let err = TransactionError::InstructionError(3, InstructionError::GenericError);
        assert_eq!(parse_instruction_index(&err), Some(3));
    }

    #[test]
    fn parse_instruction_index_max_u8() {
        use solana_instruction::error::InstructionError;
        let err = TransactionError::InstructionError(255, InstructionError::Custom(1));
        assert_eq!(parse_instruction_index(&err), Some(255));
    }

    #[test]
    fn parse_instruction_index_non_instruction_error() {
        let err = TransactionError::AccountInUse;
        assert_eq!(parse_instruction_index(&err), None);
    }

    // =========================================================================
    // format_action_sequence — TLS action history formatting
    // =========================================================================

    /// Helper: clear all TLS state used by format_action_sequence / format_last_action_oneline
    fn clear_format_tls() {
        clear_action_history();
        clear_violation_tracking();
    }

    #[test]
    fn format_action_sequence_empty() {
        clear_format_tls();
        let out = format_action_sequence();
        assert!(out.is_empty(), "expected empty for no history: {:?}", out);
    }

    #[test]
    fn format_action_sequence_single_ok() {
        clear_format_tls();
        set_total_actions(1);
        push_action_record("action_deposit", serde_json::json!({"amount": 500}), true);

        let out = format_action_sequence();
        assert!(out.contains("1 executed, 0 skipped"), "header: {out}");
        assert!(
            out.contains("action_deposit(amount=500) -> OK"),
            "body: {out}"
        );
    }

    #[test]
    fn format_action_sequence_single_fail() {
        clear_format_tls();
        set_total_actions(1);
        push_action_record("action_withdraw", serde_json::json!({}), false);

        let out = format_action_sequence();
        assert!(out.contains("action_withdraw -> FAIL"), "body: {out}");
    }

    #[test]
    fn format_action_sequence_multiple_params() {
        clear_format_tls();
        set_total_actions(3);
        push_action_record(
            "action_deposit",
            serde_json::json!({"user": 0, "amount": 100}),
            true,
        );
        push_action_record("action_borrow", serde_json::json!({"user": 1}), true);
        push_action_record("action_repay", serde_json::json!({}), false);

        let out = format_action_sequence();
        assert!(out.contains("3 executed, 0 skipped"), "header: {out}");
        assert!(out.contains("1. action_deposit("), "first: {out}");
        assert!(
            out.contains("2. action_borrow(user=1) -> OK"),
            "second: {out}"
        );
        assert!(out.contains("3. action_repay -> FAIL"), "third: {out}");
    }

    #[test]
    fn format_action_sequence_with_violation_marker() {
        clear_format_tls();
        set_total_actions(3);
        push_action_record("action_a", serde_json::json!({}), true);
        push_action_record("action_b", serde_json::json!({}), true);
        // Action at index 1 triggered the violation
        set_violation_action_index(1);

        let out = format_action_sequence();
        assert!(out.contains("2 executed, 1 skipped"), "header: {out}");
        assert!(
            !out.contains("1. action_a")
                || !out.contains("[VIOLATION]")
                || out.contains("action_a -> OK\n")
                || !out.matches("[VIOLATION]").count() > 1,
            "violation should only be on action_b"
        );
        assert!(
            out.contains("action_b -> OK [VIOLATION]"),
            "violation marker: {out}"
        );
        assert!(out.contains("1 action(s) not executed"), "skipped: {out}");
    }

    #[test]
    fn format_action_sequence_skipped_actions() {
        clear_format_tls();
        set_total_actions(10);
        push_action_record("action_only", serde_json::json!({}), true);

        let out = format_action_sequence();
        assert!(out.contains("1 executed, 9 skipped"), "header: {out}");
        assert!(out.contains("9 action(s) not executed"), "footer: {out}");
    }

    #[test]
    fn format_action_sequence_no_params_no_parens() {
        clear_format_tls();
        set_total_actions(1);
        // Null params (from push_action_record_lite)
        ACTION_HISTORY.with(|h| {
            h.borrow_mut().push(ActionRecord {
                name: "action_foo".to_string(),
                params: serde_json::Value::Null,
                success: true,
                error_code: None,
            });
        });

        let out = format_action_sequence();
        // Should NOT have parentheses for null params
        assert!(out.contains("action_foo -> OK"), "body: {out}");
        assert!(
            !out.contains("action_foo("),
            "should not have parens: {out}"
        );
    }

    // =========================================================================
    // format_last_action_oneline — last action summary
    // =========================================================================

    #[test]
    fn format_last_action_oneline_empty() {
        clear_format_tls();
        let out = format_last_action_oneline();
        assert!(out.is_empty());
    }

    #[test]
    fn format_last_action_oneline_success_with_params() {
        clear_format_tls();
        push_action_record("action_deposit", serde_json::json!({"amount": 42}), true);

        let out = format_last_action_oneline();
        assert_eq!(out, "action_deposit(amount=42) -> OK");
    }

    #[test]
    fn format_last_action_oneline_fail_no_params() {
        clear_format_tls();
        push_action_record("action_withdraw", serde_json::json!({}), false);

        let out = format_last_action_oneline();
        assert_eq!(out, "action_withdraw -> FAIL");
    }

    #[test]
    fn format_last_action_oneline_returns_last() {
        clear_format_tls();
        push_action_record("action_first", serde_json::json!({}), true);
        push_action_record("action_second", serde_json::json!({"x": 1}), false);

        let out = format_last_action_oneline();
        assert!(
            out.starts_with("action_second"),
            "should return last: {out}"
        );
        assert!(out.contains("FAIL"), "last was failure: {out}");
    }

    #[test]
    fn format_last_action_oneline_null_params() {
        clear_format_tls();
        ACTION_HISTORY.with(|h| {
            h.borrow_mut().push(ActionRecord {
                name: "action_lite".to_string(),
                params: serde_json::Value::Null,
                success: true,
                error_code: None,
            });
        });

        let out = format_last_action_oneline();
        assert_eq!(out, "action_lite -> OK");
    }

    // =========================================================================
    // format_json_value — compact JSON formatting (tested via format_action_sequence)
    // =========================================================================

    #[test]
    fn format_action_sequence_nested_params() {
        clear_format_tls();
        set_total_actions(1);
        push_action_record(
            "action_complex",
            serde_json::json!({"arr": [1, 2], "flag": true, "label": "hi"}),
            true,
        );

        let out = format_action_sequence();
        assert!(out.contains("arr=[1, 2]"), "array param: {out}");
        assert!(out.contains("flag=true"), "bool param: {out}");
        assert!(out.contains("label=\"hi\""), "string param: {out}");
    }

    // =========================================================================
    // write_crash_metadata — file I/O
    // =========================================================================

    #[test]
    fn write_crash_metadata_creates_files() {
        let tmp = tempfile::tempdir().unwrap();
        let crash_dir = tmp.path().to_str().unwrap();

        // Set up TLS state
        clear_format_tls();
        set_current_test_name("my_test");
        set_current_iteration(42);
        push_action_record("action_a", serde_json::json!({"x": 1}), true);

        let input_bytes = b"crash_input_data";
        let hash: u64 = 0xDEADBEEF;
        write_crash_metadata(crash_dir, hash, Some(999), input_bytes);

        let crash_id = format!("crash_{:016x}", hash);

        // Check input file exists and matches
        let input_path = tmp.path().join(&crash_id);
        assert!(input_path.exists(), "input file should exist");
        assert_eq!(std::fs::read(&input_path).unwrap(), input_bytes);

        // Check metadata file exists and is valid JSON
        let meta_path = tmp.path().join(format!("{}.meta.json", crash_id));
        assert!(meta_path.exists(), "meta file should exist");
        let meta_str = std::fs::read_to_string(&meta_path).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&meta_str).unwrap();

        assert_eq!(meta["test_name"], "my_test");
        assert_eq!(meta["iteration"], 42);
        assert_eq!(meta["seed"], 999);
        assert_eq!(meta["actions"].as_array().unwrap().len(), 1);
        assert_eq!(meta["actions"][0]["name"], "action_a");
    }

    #[test]
    fn write_crash_metadata_no_seed() {
        let tmp = tempfile::tempdir().unwrap();
        let crash_dir = tmp.path().to_str().unwrap();

        clear_format_tls();
        set_current_test_name("test2");

        write_crash_metadata(crash_dir, 0x1234, None, b"data");

        let meta_path = tmp.path().join("crash_0000000000001234.meta.json");
        let meta_str = std::fs::read_to_string(&meta_path).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&meta_str).unwrap();

        // seed should be absent (skip_serializing_if = None)
        assert!(
            meta.get("seed").is_none() || meta["seed"].is_null(),
            "seed should be absent or null: {:?}",
            meta.get("seed")
        );
    }

    // =========================================================================
    // write_crash_metadata_for_id — update metadata in place
    // =========================================================================

    #[test]
    fn write_crash_metadata_for_id_creates_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let crash_dir = tmp.path().to_str().unwrap();

        clear_format_tls();
        set_current_test_name("tmin_test");
        set_current_iteration(7);
        push_action_record("action_min", serde_json::json!({}), false);

        write_crash_metadata_for_id(crash_dir, "crash_abc", Some(55));

        let meta_path = tmp.path().join("crash_abc.meta.json");
        assert!(meta_path.exists(), "meta file should exist");
        let meta: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();

        assert_eq!(meta["test_name"], "tmin_test");
        assert_eq!(meta["seed"], 55);
        assert_eq!(meta["actions"][0]["name"], "action_min");
        assert_eq!(meta["actions"][0]["success"], false);
    }

    // =========================================================================
    // IntoActionSuccess trait
    // =========================================================================

    #[test]
    fn into_action_success_unit() {
        assert!(().into_success());
    }

    #[test]
    fn into_action_success_result_ok() {
        let r: Result<(), String> = Ok(());
        assert!(r.into_success());
    }

    #[test]
    fn into_action_success_result_err() {
        let r: Result<(), &str> = Err("boom");
        assert!(!r.into_success());
    }

    #[test]
    fn into_action_success_bool() {
        assert!(true.into_success());
        assert!(!false.into_success());
    }

    // =========================================================================
    // Action history helpers
    // =========================================================================

    #[test]
    fn action_history_push_and_clear() {
        clear_action_history();
        push_action_record("a1", serde_json::json!({}), true);
        push_action_record("a2", serde_json::json!({"k": "v"}), false);
        let h = get_action_history();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].name, "a1");
        assert!(h[0].success);
        assert_eq!(h[1].name, "a2");
        assert!(!h[1].success);

        clear_action_history();
        assert!(get_action_history().is_empty());
    }

    #[test]
    fn backfill_action_params_updates_entry() {
        clear_action_history();
        push_action_record_lite("action_x", true);
        let h = get_action_history();
        assert!(h[0].params.is_null(), "lite record should have null params");

        backfill_action_params(0, serde_json::json!({"filled": true}));
        let h = get_action_history();
        assert_eq!(h[0].params["filled"], true);
    }

    #[test]
    fn backfill_action_params_out_of_bounds_noop() {
        clear_action_history();
        push_action_record_lite("a", true);
        // Should not panic on out-of-bounds index
        backfill_action_params(99, serde_json::json!({"x": 1}));
        let h = get_action_history();
        assert!(h[0].params.is_null(), "original should be unchanged");
    }

    // =========================================================================
    // Violation tracking (index + clearing)
    // =========================================================================

    #[test]
    fn violation_action_index_only_records_first() {
        clear_violation_tracking();
        set_violation_action_index(3);
        set_violation_action_index(7); // should be ignored
        assert_eq!(get_violation_action_index(), Some(3));
    }

    #[test]
    fn clear_violation_tracking_resets_all() {
        set_total_actions(10);
        set_violation_action_index(5);
        clear_violation_tracking();

        assert_eq!(get_violation_action_index(), None);
        // total_actions is internal, but format_action_sequence will show 0 skipped
        clear_action_history();
        let out = format_action_sequence();
        assert!(out.is_empty(), "should be empty after full clear");
    }

    // =========================================================================
    // Success-seeking helpers
    // =========================================================================

    #[test]
    fn succeeded_variants_tracking() {
        // Clear state
        SUCCEEDED_VARIANTS.with(|s| s.borrow_mut().clear());

        assert!(!has_variant_succeeded(0));
        assert!(!has_variant_succeeded(1));
        assert_eq!(succeeded_variant_count(), 0);

        mark_variant_succeeded(0);
        assert!(has_variant_succeeded(0));
        assert!(!has_variant_succeeded(1));
        assert_eq!(succeeded_variant_count(), 1);

        mark_variant_succeeded(0); // duplicate
        assert_eq!(succeeded_variant_count(), 1);

        mark_variant_succeeded(5);
        assert_eq!(succeeded_variant_count(), 2);
    }

    // =========================================================================
    // Dispatch counting
    // =========================================================================

    #[test]
    fn dispatch_count_reset_and_increment() {
        reset_iteration_dispatch_count();
        // min is 1 even when 0 dispatches
        assert_eq!(get_iteration_dispatch_count(), 1);

        increment_action_count();
        increment_action_count();
        assert_eq!(get_iteration_dispatch_count(), 2);

        reset_iteration_dispatch_count();
        assert_eq!(get_iteration_dispatch_count(), 1);
    }

    // =========================================================================
    // build_crash_metadata
    // =========================================================================

    #[test]
    fn build_crash_metadata_captures_tls() {
        clear_format_tls();
        set_current_test_name("crash_test");
        set_current_iteration(99);
        push_action_record("act_a", serde_json::json!({"p": 1}), true);
        push_action_record("act_b", serde_json::json!({}), false);

        let meta = build_crash_metadata(Some(12345));
        assert_eq!(meta.test_name, "crash_test");
        assert_eq!(meta.iteration, 99);
        assert_eq!(meta.seed, Some(12345));
        assert_eq!(meta.actions.len(), 2);
        assert_eq!(meta.actions[0].name, "act_a");
        assert!(meta.actions[0].success);
        assert_eq!(meta.actions[1].name, "act_b");
        assert!(!meta.actions[1].success);
    }

    #[test]
    fn build_crash_metadata_no_test_name() {
        clear_format_tls();
        CURRENT_TEST_NAME.with(|t| *t.borrow_mut() = None);

        let meta = build_crash_metadata(None);
        assert_eq!(meta.test_name, "unknown");
        assert!(meta.seed.is_none());
    }

    #[test]
    fn mutation_finding_flag_round_trips_through_crash_metadata() {
        // A plain invariant violation is not a mutation finding.
        let _ = take_violation();
        record_violation("plain invariant".to_string());
        assert!(!build_crash_metadata(None).mutation_finding);

        // An account-mutation finding is, and the replay identity survives serde.
        let _ = take_violation();
        record_mutation_violation(
            "[CC-1 owner] ...".to_string(),
            "CC-1 owner:Program:disc".to_string(),
        );
        let meta = build_crash_metadata(None);
        assert!(meta.mutation_finding);
        assert_eq!(
            meta.mutation_finding_id.as_deref(),
            Some("CC-1 owner:Program:disc")
        );
        assert_eq!(
            meta.mutation_finding_message.as_deref(),
            Some("[CC-1 owner] ...")
        );
        let json = serde_json::to_string(&meta).unwrap();
        let back: CrashMetadata = serde_json::from_str(&json).unwrap();
        assert!(back.mutation_finding);
        assert_eq!(
            back.mutation_finding_id.as_deref(),
            Some("CC-1 owner:Program:disc")
        );

        let _ = take_violation();
        clear_iteration_state();
    }

    // =========================================================================
    // GenericAccountBuilder
    // =========================================================================

    #[test]
    fn generic_builder_create_basic() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let addr = ctx
            .create_account()
            .pubkey(pk)
            .owner(owner)
            .lamports(1_000_000)
            .size(128)
            .create()
            .unwrap();

        assert_eq!(addr, pk);
        let acc = ctx.svm.get_account(&pk).unwrap();
        assert_eq!(acc.owner, owner);
        assert_eq!(acc.lamports, 1_000_000);
        assert_eq!(acc.data.len(), 128);
        assert!(!acc.executable);
    }

    #[test]
    fn generic_builder_with_data() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();
        let data = vec![1, 2, 3, 4, 5];

        ctx.create_account()
            .pubkey(pk)
            .lamports(1)
            .data(&data)
            .create()
            .unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        assert_eq!(acc.data, data);
    }

    #[test]
    fn generic_builder_default_address_errors() {
        let mut ctx = TestContext::new();
        let err = ctx.create_account().lamports(100).create().unwrap_err();

        assert!(
            err.to_string().contains("Address must be set"),
            "expected address error: {}",
            err
        );
    }

    #[test]
    fn generic_builder_tracks_account() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();
        let before = ctx.tracked_accounts_count();

        ctx.create_account().pubkey(pk).create().unwrap();

        assert_eq!(ctx.tracked_accounts_count(), before + 1);
    }

    // =========================================================================
    // MintAccountBuilder
    // =========================================================================

    #[test]
    fn mint_builder_create_basic() {
        let mut ctx = TestContext::new();
        let mint_pk = Pubkey::new_unique();
        let authority = Pubkey::new_unique();

        let addr = ctx
            .create_mint()
            .pubkey(mint_pk)
            .mint_authority(authority)
            .decimals(6)
            .supply(1_000_000)
            .create()
            .unwrap();

        assert_eq!(addr, mint_pk);

        let acc = ctx.svm.get_account(&mint_pk).unwrap();
        assert_eq!(acc.owner, spl_token::id());
        assert_eq!(acc.data.len(), spl_token::state::Mint::LEN);

        // Deserialize and verify packed state
        let mint = spl_token::state::Mint::unpack(&acc.data).unwrap();
        assert_eq!(mint.decimals, 6);
        assert_eq!(mint.supply, 1_000_000);
        assert_eq!(mint.mint_authority, COption::Some(authority));
        assert!(mint.is_initialized);
    }

    #[test]
    fn mint_builder_default_is_initialized() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();

        ctx.create_mint().pubkey(pk).create().unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        let mint = spl_token::state::Mint::unpack(&acc.data).unwrap();
        assert!(mint.is_initialized, "default mint should be initialized");
    }

    #[test]
    fn mint_builder_freeze_authority() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();
        let freeze_auth = Pubkey::new_unique();

        ctx.create_mint()
            .pubkey(pk)
            .freeze_authority(Some(freeze_auth))
            .create()
            .unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        let mint = spl_token::state::Mint::unpack(&acc.data).unwrap();
        assert_eq!(mint.freeze_authority, COption::Some(freeze_auth));
    }

    #[test]
    fn mint_builder_freeze_authority_none() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();

        ctx.create_mint()
            .pubkey(pk)
            .freeze_authority(None)
            .create()
            .unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        let mint = spl_token::state::Mint::unpack(&acc.data).unwrap();
        assert_eq!(mint.freeze_authority, COption::None);
    }

    #[test]
    fn mint_builder_default_address_errors() {
        let mut ctx = TestContext::new();
        let err = ctx.create_mint().decimals(9).create().unwrap_err();

        assert!(
            err.to_string().contains("Address must be set"),
            "expected address error: {}",
            err
        );
    }

    #[test]
    fn mint_builder_has_rent_exempt_lamports() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();

        ctx.create_mint().pubkey(pk).create().unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        let rent = Rent::default();
        let min_lamports = rent.minimum_balance(spl_token::state::Mint::LEN);
        assert_eq!(
            acc.lamports, min_lamports,
            "mint should have rent-exempt lamports by default"
        );
    }

    // =========================================================================
    // TokenAccountBuilder
    // =========================================================================

    #[test]
    fn token_builder_create_basic() {
        let mut ctx = TestContext::new();
        let token_pk = Pubkey::new_unique();
        let mint_pk = Pubkey::new_unique();
        let owner_pk = Pubkey::new_unique();

        let addr = ctx
            .create_token_account()
            .pubkey(token_pk)
            .mint(mint_pk)
            .token_owner(owner_pk)
            .amount(500)
            .create()
            .unwrap();

        assert_eq!(addr, token_pk);

        let acc = ctx.svm.get_account(&token_pk).unwrap();
        assert_eq!(acc.owner, spl_token::id());
        assert_eq!(acc.data.len(), spl_token::state::Account::LEN);

        let token = spl_token::state::Account::unpack(&acc.data).unwrap();
        assert_eq!(token.mint, mint_pk);
        assert_eq!(token.owner, owner_pk);
        assert_eq!(token.amount, 500);
        assert_eq!(token.state, spl_token::state::AccountState::Initialized);
    }

    #[test]
    fn token_builder_missing_mint_errors() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let err = ctx
            .create_token_account()
            .pubkey(pk)
            .token_owner(owner)
            .create()
            .unwrap_err();

        assert!(
            err.to_string().contains("Mint must be set"),
            "expected mint error: {}",
            err
        );
    }

    #[test]
    fn token_builder_missing_owner_errors() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let err = ctx
            .create_token_account()
            .pubkey(pk)
            .mint(mint)
            .create()
            .unwrap_err();

        assert!(
            err.to_string().contains("Owner must be set"),
            "expected owner error: {}",
            err
        );
    }

    #[test]
    fn token_builder_default_address_errors() {
        let mut ctx = TestContext::new();
        let mint = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let err = ctx
            .create_token_account()
            .mint(mint)
            .token_owner(owner)
            .create()
            .unwrap_err();

        assert!(
            err.to_string().contains("Address must be set"),
            "expected address error: {}",
            err
        );
    }

    #[test]
    fn token_builder_delegate() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let delegate = Pubkey::new_unique();

        ctx.create_token_account()
            .pubkey(pk)
            .mint(mint)
            .token_owner(owner)
            .delegate(Some(delegate))
            .delegated_amount(100)
            .create()
            .unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        let token = spl_token::state::Account::unpack(&acc.data).unwrap();
        assert_eq!(token.delegate, COption::Some(delegate));
        assert_eq!(token.delegated_amount, 100);
    }

    #[test]
    fn token_builder_close_authority() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let close_auth = Pubkey::new_unique();

        ctx.create_token_account()
            .pubkey(pk)
            .mint(mint)
            .token_owner(owner)
            .close_authority(Some(close_auth))
            .create()
            .unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        let token = spl_token::state::Account::unpack(&acc.data).unwrap();
        assert_eq!(token.close_authority, COption::Some(close_auth));
    }

    #[test]
    fn token_builder_is_native() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        ctx.create_token_account()
            .pubkey(pk)
            .mint(mint)
            .token_owner(owner)
            .is_native(Some(1_000_000))
            .create()
            .unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        let token = spl_token::state::Account::unpack(&acc.data).unwrap();
        assert_eq!(token.is_native, COption::Some(1_000_000));
    }

    #[test]
    fn token_builder_has_rent_exempt_lamports() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        ctx.create_token_account()
            .pubkey(pk)
            .mint(mint)
            .token_owner(owner)
            .create()
            .unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        let rent = Rent::default();
        let min_lamports = rent.minimum_balance(spl_token::state::Account::LEN);
        assert_eq!(
            acc.lamports, min_lamports,
            "token account should have rent-exempt lamports by default"
        );
    }

    // =========================================================================
    // AccountBuilderBase trait — shared builder methods
    // =========================================================================

    #[test]
    fn builder_rent_epoch() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();

        ctx.create_account()
            .pubkey(pk)
            .lamports(1)
            .rent_epoch(42)
            .create()
            .unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        assert_eq!(acc.rent_epoch, 42);
    }

    #[test]
    fn builder_lamports_override_on_mint() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();

        // Override default rent-exempt lamports
        ctx.create_mint().pubkey(pk).lamports(999).create().unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        assert_eq!(acc.lamports, 999);
    }

    // =========================================================================
    // Account builder — deeper edge cases
    // =========================================================================

    #[test]
    fn generic_builder_overwrite_same_pubkey() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();

        // First create
        ctx.create_account()
            .pubkey(pk)
            .lamports(100)
            .data(&[1, 2, 3])
            .create()
            .unwrap();
        let acc1 = ctx.svm.get_account(&pk).unwrap();
        assert_eq!(acc1.data, vec![1, 2, 3]);

        // Second create overwrites
        ctx.create_account()
            .pubkey(pk)
            .lamports(200)
            .data(&[4, 5])
            .create()
            .unwrap();
        let acc2 = ctx.svm.get_account(&pk).unwrap();
        assert_eq!(acc2.data, vec![4, 5]);
        assert_eq!(acc2.lamports, 200);
    }

    #[test]
    fn mint_builder_zero_decimals() {
        // NFT use case: 0 decimals is valid
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();

        ctx.create_mint().pubkey(pk).decimals(0).create().unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        let mint = spl_token::state::Mint::unpack(&acc.data).unwrap();
        assert_eq!(mint.decimals, 0);
    }

    #[test]
    fn token_builder_max_amount() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        ctx.create_token_account()
            .pubkey(pk)
            .mint(mint)
            .token_owner(owner)
            .amount(u64::MAX)
            .create()
            .unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        let token = spl_token::state::Account::unpack(&acc.data).unwrap();
        assert_eq!(token.amount, u64::MAX);
    }

    #[test]
    fn token_builder_frozen_state() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        ctx.create_token_account()
            .pubkey(pk)
            .mint(mint)
            .token_owner(owner)
            .state(spl_token::state::AccountState::Frozen)
            .create()
            .unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        let token = spl_token::state::Account::unpack(&acc.data).unwrap();
        assert_eq!(token.state, spl_token::state::AccountState::Frozen);
    }

    #[test]
    fn builder_chaining_order_independent() {
        let mut ctx = TestContext::new();
        let mint = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();

        // Order 1: mint → pubkey → token_owner → amount
        ctx.create_token_account()
            .mint(mint)
            .pubkey(pk1)
            .token_owner(owner)
            .amount(42)
            .create()
            .unwrap();

        // Order 2: amount → token_owner → pubkey → mint
        ctx.create_token_account()
            .amount(42)
            .token_owner(owner)
            .pubkey(pk2)
            .mint(mint)
            .create()
            .unwrap();

        let acc1 = ctx.svm.get_account(&pk1).unwrap();
        let acc2 = ctx.svm.get_account(&pk2).unwrap();
        let token1 = spl_token::state::Account::unpack(&acc1.data).unwrap();
        let token2 = spl_token::state::Account::unpack(&acc2.data).unwrap();

        assert_eq!(token1.mint, token2.mint);
        assert_eq!(token1.owner, token2.owner);
        assert_eq!(token1.amount, token2.amount);
    }

    #[test]
    fn generic_builder_zero_length_data_with_lamports() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();

        ctx.create_account()
            .pubkey(pk)
            .lamports(1_000_000)
            .size(0) // zero-length data
            .create()
            .unwrap();

        let acc = ctx.svm.get_account(&pk).unwrap();
        assert_eq!(acc.lamports, 1_000_000);
        assert!(acc.data.is_empty());
    }

    // =========================================================================
    // format_action_sequence — deeper edge cases
    // =========================================================================

    #[test]
    fn format_action_sequence_violation_at_index_0() {
        clear_format_tls();
        set_total_actions(2);
        push_action_record("action_first", serde_json::json!({}), false);
        push_action_record("action_second", serde_json::json!({}), true);
        set_violation_action_index(0);

        let out = format_action_sequence();
        assert!(
            out.contains("action_first -> FAIL [VIOLATION]"),
            "violation should be on first: {out}"
        );
        assert!(
            !out.contains("action_second -> OK [VIOLATION]"),
            "second should not have marker: {out}"
        );
    }

    #[test]
    fn format_action_sequence_deeply_nested_params() {
        clear_format_tls();
        set_total_actions(1);
        push_action_record(
            "action_nested",
            serde_json::json!({"a": {"b": {"c": 1}}}),
            true,
        );

        let out = format_action_sequence();
        // format_json_value should recurse into nested objects
        assert!(out.contains("a={"), "nested object: {out}");
        assert!(out.contains("c: 1"), "deeply nested value: {out}");
    }

    #[test]
    fn format_action_sequence_total_0_with_actions() {
        // Inconsistent state: total_actions = 0 but history has entries
        clear_format_tls();
        // Don't call set_total_actions — defaults to 0
        push_action_record("orphan", serde_json::json!({}), true);

        let out = format_action_sequence();
        // Should still format (total_actions=0 but history non-empty → skipped = 0 - 1 = saturating_sub → 0)
        assert!(
            out.contains("1 executed, 0 skipped"),
            "should handle mismatch: {out}"
        );
    }

    #[test]
    fn format_action_sequence_many_actions() {
        clear_format_tls();
        set_total_actions(50);
        for i in 0..50 {
            push_action_record(
                &format!("action_{}", i),
                serde_json::json!({"i": i}),
                i % 3 != 0,
            );
        }

        let out = format_action_sequence();
        assert!(out.contains("50 executed, 0 skipped"), "header: {out}");
        assert!(out.contains("1. action_0"), "first: {out}");
        assert!(out.contains("50. action_49"), "last: {out}");
    }

    #[test]
    fn format_last_action_oneline_multiple_params_ordering() {
        clear_format_tls();
        // serde_json::json! with ordered keys
        push_action_record(
            "action_multi",
            serde_json::json!({"amount": 100, "user": 2}),
            true,
        );
        let out = format_last_action_oneline();
        // Should have both params
        assert!(out.contains("amount=100"), "amount: {out}");
        assert!(out.contains("user=2"), "user: {out}");
        assert!(out.contains("-> OK"), "status: {out}");
    }

    // =========================================================================
    // Regression: push_action_record preserves params in output
    // (was broken when push_action_record_lite was used instead, dropping params)
    // =========================================================================

    #[test]
    fn action_record_includes_params_in_sequence() {
        clear_format_tls();
        set_total_actions(3);
        push_action_record(
            "delegate_stake",
            serde_json::json!({"authority": null, "stake_account": 1340788527u64, "vote_account": 640494879u64}),
            true,
        );
        push_action_record("advance_slots", serde_json::json!({"slots": 54177}), true);
        push_action_record(
            "withdraw",
            serde_json::json!({"stake_account": 3, "lamports": 1000, "leave_reserve": true}),
            false,
        );

        let out = format_action_sequence();
        // All params must appear in the output
        assert!(
            out.contains("authority=null"),
            "authority param missing: {out}"
        );
        assert!(
            out.contains("stake_account=1340788527"),
            "stake_account param missing: {out}"
        );
        assert!(
            out.contains("vote_account=640494879"),
            "vote_account param missing: {out}"
        );
        assert!(out.contains("slots=54177"), "slots param missing: {out}");
        assert!(
            out.contains("leave_reserve=true"),
            "leave_reserve param missing: {out}"
        );
        assert!(
            out.contains("lamports=1000"),
            "lamports param missing: {out}"
        );
        // Status markers
        assert!(
            out.contains("delegate_stake(") && out.contains(") -> OK"),
            "delegate_stake format: {out}"
        );
        assert!(
            out.contains("withdraw(") && out.contains(") -> FAIL"),
            "withdraw format: {out}"
        );
    }

    #[test]
    fn action_record_params_in_oneline() {
        clear_format_tls();
        push_action_record(
            "move_lamports",
            serde_json::json!({"dest_account": 42, "lamports": null, "stake_account": 99}),
            true,
        );

        let out = format_last_action_oneline();
        assert!(out.contains("move_lamports("), "should have parens: {out}");
        assert!(out.contains("dest_account=42"), "dest_account: {out}");
        assert!(out.contains("lamports=null"), "lamports null: {out}");
        assert!(out.contains("stake_account=99"), "stake_account: {out}");
        assert!(out.contains("-> OK"), "status: {out}");
    }

    #[test]
    fn action_record_lite_omits_params_regression() {
        // Verify that push_action_record_lite (the old path) does NOT include params.
        // This test documents the regression that was fixed.
        clear_format_tls();
        set_total_actions(1);
        push_action_record_lite("delegate_stake", true);

        let out = format_action_sequence();
        // Lite records have no params — should NOT have parentheses
        assert!(
            out.contains("delegate_stake -> OK"),
            "should have no params: {out}"
        );
        assert!(
            !out.contains("delegate_stake("),
            "should not have parens: {out}"
        );
    }

    // =========================================================================
    // parse_error_code — additional variant coverage
    // =========================================================================

    #[test]
    fn parse_error_code_anchor_custom_6000() {
        use solana_instruction::error::InstructionError;
        let err = TransactionError::InstructionError(0, InstructionError::Custom(6000));
        assert_eq!(parse_error_code(&err), Some(6000));
    }

    #[test]
    fn parse_error_code_insufficient_funds() {
        use solana_instruction::error::InstructionError;
        let err = TransactionError::InstructionError(0, InstructionError::InsufficientFunds);
        assert_eq!(
            parse_error_code(&err),
            None,
            "InsufficientFunds has no Custom(N)"
        );
    }

    #[test]
    fn parse_error_code_account_already_initialized() {
        use solana_instruction::error::InstructionError;
        let err =
            TransactionError::InstructionError(2, InstructionError::AccountAlreadyInitialized);
        assert_eq!(parse_error_code(&err), None);
        // But instruction index should still parse
        assert_eq!(parse_instruction_index(&err), Some(2));
    }

    // =========================================================================
    // parse_error_code + parse_instruction_index — structural matching
    // =========================================================================

    #[test]
    fn parse_error_code_duplicate_instruction() {
        // DuplicateInstruction is NOT InstructionError — should return None
        let err = TransactionError::DuplicateInstruction(2);
        assert_eq!(parse_error_code(&err), None);
        assert_eq!(parse_instruction_index(&err), None);
    }

    #[test]
    fn parse_instruction_index_with_non_custom_error() {
        use solana_instruction::error::InstructionError;
        // InstructionError that's not Custom — index should still be extracted
        let err =
            TransactionError::InstructionError(4, InstructionError::ComputationalBudgetExceeded);
        assert_eq!(parse_error_code(&err), None);
        assert_eq!(parse_instruction_index(&err), Some(4));
    }

    #[test]
    fn parse_error_code_custom_one() {
        use solana_instruction::error::InstructionError;
        // Custom(1) — smallest non-zero
        let err = TransactionError::InstructionError(0, InstructionError::Custom(1));
        assert_eq!(parse_error_code(&err), Some(1));
    }

    #[test]
    fn parse_both_from_same_error() {
        use solana_instruction::error::InstructionError;
        // Both error code and instruction index from a single error
        let err = TransactionError::InstructionError(7, InstructionError::Custom(9999));
        assert_eq!(parse_error_code(&err), Some(9999));
        assert_eq!(parse_instruction_index(&err), Some(7));
    }

    #[test]
    fn tx_result_to_outcome_success() {
        use litesvm::types::TransactionMetadata;
        let meta = TransactionMetadata {
            compute_units_consumed: 42,
            logs: vec!["log".to_string()],
            ..Default::default()
        };
        let outcome = tx_result_to_outcome(Ok(meta));
        assert!(outcome.is_success());
        assert_eq!(outcome.compute_units(), Some(42));
        assert_eq!(outcome.error_code(), None);
    }

    #[test]
    fn tx_result_to_outcome_error_sets_tls() {
        use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
        use solana_instruction::error::InstructionError;
        let failed = FailedTransactionMetadata {
            err: TransactionError::InstructionError(1, InstructionError::Custom(6051)),
            meta: TransactionMetadata {
                logs: vec!["err log".to_string()],
                ..Default::default()
            },
        };
        let outcome = tx_result_to_outcome(Err(failed));
        assert!(outcome.is_error());
        assert_eq!(outcome.error_code(), Some(6051));
        // TLS should have been set
        let tls_code = take_last_error_code();
        assert_eq!(tls_code, Some(6051));
    }

    // =========================================================================
    // Snapshot — deeper edge cases
    // =========================================================================

    #[test]
    fn test_snapshot_multiple_writes_same_account() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();

        // Initial state
        ctx.write_account(
            &pk,
            Account {
                lamports: 100,
                data: vec![1],
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        ctx.dirty_tracker.mark_account_dirty(&pk);

        ctx.take_snapshot();

        // Write #1 during iteration
        ctx.write_account(
            &pk,
            Account {
                lamports: 200,
                data: vec![2],
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        ctx.dirty_tracker.mark_account_dirty(&pk);

        // Write #2 during iteration
        ctx.write_account(
            &pk,
            Account {
                lamports: 300,
                data: vec![3],
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        ctx.dirty_tracker.mark_account_dirty(&pk);

        // Restore should go back to snapshot state (lamports=100, data=[1])
        ctx.restore_snapshot();
        let acc = ctx.svm.get_account(&pk).unwrap();
        assert_eq!(
            acc.lamports, 100,
            "restore should use snapshot value, not intermediate"
        );
        assert_eq!(acc.data, vec![1]);
    }

    #[test]
    fn test_snapshot_large_account_data_integrity() {
        let mut ctx = TestContext::new();
        let pk = Pubkey::new_unique();

        // Create a large account (10KB)
        let original_data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        ctx.write_account(
            &pk,
            Account {
                lamports: 1_000_000,
                data: original_data.clone(),
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        ctx.dirty_tracker.mark_account_dirty(&pk);

        ctx.take_snapshot();

        // Modify during iteration
        ctx.write_account(
            &pk,
            Account {
                lamports: 1_000_000,
                data: vec![0xFF; 10_000],
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        ctx.dirty_tracker.mark_account_dirty(&pk);

        ctx.restore_snapshot();
        let acc = ctx.svm.get_account(&pk).unwrap();
        assert_eq!(
            acc.data, original_data,
            "10KB data should be perfectly restored"
        );
    }

    // -------------------------------------------------------------------------
    // add_program() FUZZ_PROGRAM_SO override tests
    // -------------------------------------------------------------------------

    // Env var mutex: these tests manipulate FUZZ_PROGRAM_SO so must not run concurrently.
    use std::sync::Mutex;
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// Find any valid SBF .so in the repo for testing.
    fn find_test_so() -> String {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data/staking.so")
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn test_add_program_override_env_var() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let so_path = find_test_so();

        // Set override to the known-good .so
        std::env::set_var("FUZZ_PROGRAM_SO", &so_path);

        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_unique();

        // Call with a bogus path — override should redirect to the real .so
        let result = ctx.add_program(&program_id, "/nonexistent/bogus.so");
        std::env::remove_var("FUZZ_PROGRAM_SO");

        assert!(
            result.is_ok(),
            "Override should load from FUZZ_PROGRAM_SO, not the bogus path"
        );
    }

    #[test]
    fn test_add_program_normal_path() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("FUZZ_PROGRAM_SO");

        let so_path = find_test_so();
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_unique();

        let result = ctx.add_program(&program_id, &so_path);
        assert!(
            result.is_ok(),
            "Normal add_program should work without override"
        );
    }

    #[test]
    fn test_add_program_override_nonexistent_errors() {
        let _lock = ENV_MUTEX.lock().unwrap();

        // Point override to a nonexistent file
        std::env::set_var("FUZZ_PROGRAM_SO", "/tmp/does_not_exist_xyz.so");

        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_unique();

        let result = ctx.add_program(&program_id, "/also/bogus.so");
        std::env::remove_var("FUZZ_PROGRAM_SO");

        assert!(
            result.is_err(),
            "Override pointing to nonexistent file should error"
        );
    }

    // -------------------------------------------------------------------------
    // Test ProgramBuilder
    // -------------------------------------------------------------------------

    #[test]
    fn test_program_builder_fee_payer() {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_unique();
        let fee_payer = Keypair::new();
        let signer = Keypair::new();

        let builder = ctx
            .program(program_id)
            .fee_payer(&fee_payer)
            .signers(&[&signer]);

        assert_eq!(builder.fee_payer, Some(fee_payer.insecure_clone()));

        let builder = ctx
            .program(program_id)
            .signers(&[&signer])
            .fee_payer(&fee_payer);

        assert_eq!(builder.fee_payer, Some(fee_payer));
    }

    // =========================================================================
    // Change 1: TxOutcome new fields — signature, inner_instructions,
    //           return_data, fee are populated from litesvm metadata
    // =========================================================================

    #[test]
    fn tx_result_to_outcome_success_preserves_all_metadata() {
        use litesvm::types::TransactionMetadata;
        use solana_message::compiled_instruction::CompiledInstruction;
        use solana_message::inner_instruction::InnerInstruction;

        let sig = Signature::from([1u8; 64]);
        let return_program = Pubkey::new_unique();
        let inner_ix = InnerInstruction {
            instruction: CompiledInstruction {
                program_id_index: 2,
                accounts: vec![0, 1],
                data: vec![0xAB, 0xCD],
            },
            stack_height: 2,
        };

        let meta = TransactionMetadata {
            signature: sig,
            logs: vec!["Program invoked".to_string()],
            inner_instructions: vec![vec![inner_ix]],
            compute_units_consumed: 12345,
            return_data: TransactionReturnData {
                program_id: return_program,
                data: vec![1, 2, 3, 4],
            },
            fee: 5000,
        };

        let outcome = tx_result_to_outcome(Ok(meta));

        // Verify all fields are preserved, not just compute_units and logs
        assert!(outcome.is_success());
        assert_eq!(outcome.compute_units(), Some(12345));
        assert_eq!(outcome.logs(), &["Program invoked"]);
        assert_eq!(*outcome.signature(), sig);
        assert_eq!(outcome.fee(), 5000);
        assert_eq!(outcome.return_data().program_id, return_program);
        assert_eq!(outcome.return_data().data, vec![1, 2, 3, 4]);
        assert_eq!(outcome.inner_instructions().len(), 1);
        assert_eq!(outcome.inner_instructions()[0].len(), 1);
        assert_eq!(outcome.inner_instructions()[0][0].stack_height, 2);
        assert_eq!(
            outcome.inner_instructions()[0][0].instruction.data,
            vec![0xAB, 0xCD]
        );
    }

    #[test]
    fn tx_result_to_outcome_error_preserves_all_metadata() {
        use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
        use solana_instruction::error::InstructionError;

        let sig = Signature::from([1u8; 64]);
        let failed = FailedTransactionMetadata {
            err: TransactionError::InstructionError(2, InstructionError::Custom(9999)),
            meta: TransactionMetadata {
                signature: sig,
                logs: vec!["Program failed".to_string()],
                inner_instructions: vec![vec![], vec![]],
                compute_units_consumed: 500,
                return_data: TransactionReturnData {
                    program_id: Pubkey::new_unique(),
                    data: vec![0xFF],
                },
                fee: 7500,
            },
        };

        let outcome = tx_result_to_outcome(Err(failed));

        assert!(outcome.is_error());
        assert_eq!(outcome.error_code(), Some(9999));
        assert_eq!(*outcome.signature(), sig);
        assert_eq!(outcome.fee(), 7500);
        assert_eq!(outcome.return_data().data, vec![0xFF]);
        assert_eq!(outcome.inner_instructions().len(), 2);
        assert_eq!(outcome.logs(), &["Program failed"]);
    }

    #[test]
    fn tx_outcome_into_result_preserves_new_fields_in_tx_error() {
        let sig = Signature::from([1u8; 64]);
        let return_program = Pubkey::new_unique();

        let error = TxOutcome::ProgramError {
            error: TransactionError::AccountInUse,
            error_code: Some(42),
            instruction_index: Some(3),
            logs: vec!["log".to_string()],
            signature: sig,
            inner_instructions: vec![vec![]],
            return_data: TransactionReturnData {
                program_id: return_program,
                data: vec![10, 20],
            },
            fee: 3000,
        };

        let err = error.into_result().unwrap_err();

        // All fields must survive the TxOutcome → TxError conversion
        assert_eq!(err.error_code, Some(42));
        assert_eq!(err.instruction_index, Some(3));
        assert_eq!(err.signature, sig);
        assert_eq!(err.fee, 3000);
        assert_eq!(err.return_data.program_id, return_program);
        assert_eq!(err.return_data.data, vec![10, 20]);
        assert_eq!(err.inner_instructions.len(), 1);
        assert_eq!(err.logs, vec!["log"]);
    }

    #[test]
    fn tx_outcome_accessors_agree_across_variants() {
        // Both variants should return the same values through accessors
        let sig = Signature::from([1u8; 64]);
        let rd = TransactionReturnData {
            program_id: Pubkey::new_unique(),
            data: vec![42],
        };

        let success = TxOutcome::Success {
            compute_units: 0,
            logs: vec![],
            signature: sig,
            inner_instructions: vec![],
            return_data: rd.clone(),
            fee: 100,
        };

        let error = TxOutcome::ProgramError {
            error: TransactionError::AccountInUse,
            error_code: None,
            instruction_index: None,
            logs: vec![],
            signature: sig,
            inner_instructions: vec![],
            return_data: rd.clone(),
            fee: 100,
        };

        assert_eq!(*success.signature(), *error.signature());
        assert_eq!(success.fee(), error.fee());
        assert_eq!(success.return_data().data, error.return_data().data);
        assert_eq!(
            success.inner_instructions().len(),
            error.inner_instructions().len()
        );
    }

    // =========================================================================
    // Change 2: Arc-wrapped program_coverage_totals — shared across clones,
    //           only mutable during setup via Arc::make_mut
    // =========================================================================

    #[test]
    fn program_coverage_totals_shared_across_clones() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("FUZZ_PROGRAM_SO");

        let so_path = find_test_so();
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_unique();
        ctx.add_program(&program_id, &so_path).unwrap();

        // Verify totals were populated
        let totals = ctx.get_program_coverage_totals();
        assert!(
            totals.contains_key(&program_id),
            "program should have coverage totals"
        );
        let (edges, instrs) = totals[&program_id];
        assert!(edges > 0, "should have edges: {}", edges);
        assert!(instrs > 0, "should have instructions: {}", instrs);

        // Clone and verify it's the same Arc (cheap pointer clone, not deep copy)
        let cloned = ctx.clone();
        let cloned_totals = cloned.get_program_coverage_totals();
        assert_eq!(
            cloned_totals[&program_id],
            (edges, instrs),
            "clone must have identical coverage totals"
        );

        // Arc::ptr_eq would be ideal but we only have &HashMap. Verify via
        // the value equality at minimum — the type is Arc<HashMap> so clone
        // is O(1) pointer bump, not O(n) deep copy.
    }

    #[test]
    fn program_coverage_totals_empty_without_program() {
        let ctx = TestContext::new();
        assert!(
            ctx.get_program_coverage_totals().is_empty(),
            "fresh context should have no coverage totals"
        );

        let cloned = ctx.clone();
        assert!(
            cloned.get_program_coverage_totals().is_empty(),
            "clone of fresh context should also be empty"
        );
    }

    // =========================================================================
    // Change 3: Entry-point-aware analyze_program_coverage — BFS from
    //           entrypoint + function entries, only counting reachable code
    // =========================================================================

    #[test]
    fn analyze_program_coverage_returns_nonzero_for_valid_binary() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("FUZZ_PROGRAM_SO");

        let so_path = find_test_so();
        let program_data = std::fs::read(&so_path).unwrap();

        let result = TestContext::analyze_program_coverage(&program_data);
        assert!(
            result.is_some(),
            "valid SBF binary should produce coverage data"
        );

        let (edges, instructions) = result.unwrap();
        assert!(edges > 0, "should have conditional edges: {}", edges);
        assert!(
            instructions > 0,
            "should have instructions: {}",
            instructions
        );

        // Sanity: edges should be less than instructions (not every instruction
        // is a conditional branch — conditional branches produce 2 edges each)
        assert!(
            edges < instructions * 2,
            "edges ({}) should be < 2*instructions ({})",
            edges,
            instructions
        );
    }

    #[test]
    fn analyze_program_coverage_reachable_subset_of_total() {
        // The BFS-based analysis should count FEWER instructions than the total
        // number of instructions in the binary, because it excludes unreachable
        // code (linker stubs, unused library functions, etc.)
        use solana_sbpf::elf::Executable;
        use solana_sbpf::program::BuiltinProgram;
        use solana_sbpf::static_analysis::Analysis;
        use solana_sbpf::vm::ContextObject;

        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("FUZZ_PROGRAM_SO");

        let so_path = find_test_so();
        let program_data = std::fs::read(&so_path).unwrap();

        // Get our BFS-based count
        let (bfs_edges, bfs_instructions) =
            TestContext::analyze_program_coverage(&program_data).unwrap();

        // Get the raw total from the analysis (all nodes, including unreachable)
        struct DummyContext;
        impl ContextObject for DummyContext {
            fn consume(&mut self, _amount: u64) {}
            fn get_remaining(&self) -> u64 {
                0
            }
        }
        let loader = Arc::new(BuiltinProgram::<DummyContext>::new_mock());
        let executable = Executable::from_elf(&program_data, loader).unwrap();
        let analysis = Analysis::from_executable(&executable).unwrap();
        let total_all_instructions = analysis.instructions.len();

        // BFS count should be <= total (strictly less if any dead code exists)
        assert!(
            bfs_instructions <= total_all_instructions,
            "BFS instructions ({}) should be <= total instructions ({})",
            bfs_instructions,
            total_all_instructions
        );

        // For a real program binary there should be at least some unreachable
        // code (linker stubs, panic handlers, etc.)
        // We don't assert strictly less because small programs may have no dead code.
        eprintln!(
            "[TEST] BFS reachable: {} instructions, {} edges. Total in binary: {} instructions. \
             Excluded: {} instructions ({:.1}%)",
            bfs_instructions,
            bfs_edges,
            total_all_instructions,
            total_all_instructions - bfs_instructions,
            ((total_all_instructions - bfs_instructions) as f64 / total_all_instructions as f64)
                * 100.0
        );
    }

    #[test]
    fn analyze_program_coverage_returns_none_for_garbage() {
        let garbage = vec![0u8; 64];
        assert!(
            TestContext::analyze_program_coverage(&garbage).is_none(),
            "garbage bytes should not parse as valid SBF"
        );
    }

    #[test]
    fn analyze_program_coverage_returns_none_for_empty() {
        assert!(
            TestContext::analyze_program_coverage(&[]).is_none(),
            "empty bytes should not parse as valid SBF"
        );
    }

    #[test]
    fn analyze_program_coverage_edges_only_from_conditional_jumps() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("FUZZ_PROGRAM_SO");

        let so_path = find_test_so();
        let program_data = std::fs::read(&so_path).unwrap();

        let (edges, _) = TestContext::analyze_program_coverage(&program_data).unwrap();

        // Edges come from conditional jumps, each producing 2 edges (taken/not-taken).
        // So edge count should always be even.
        assert_eq!(
            edges % 2,
            0,
            "edge count ({}) should be even (each conditional branch = 2 edges)",
            edges
        );
    }

    // =========================================================================
    // Fee payer / signer resolution regression tests
    // =========================================================================

    /// Helper: create a funded keypair in the test context
    fn fund_keypair(ctx: &mut TestContext) -> Keypair {
        let kp = Keypair::new();
        ctx.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
        kp
    }

    #[test]
    fn account_mutation_enabled_keeps_real_tx_outcome() {
        // The probe runs on a clone and must never change the real transaction's result. The
        // dataless system recipient is also (correctly) not a candidate, so no violation fires.
        let _ = take_violation();
        reset_probed_account_mutations();
        let mut ctx = TestContext::new();
        let payer = fund_keypair(&mut ctx);
        let recipient = Keypair::new().pubkey();
        ctx.svm.airdrop(&recipient, 1).unwrap();

        ctx.enable_account_mutation();

        let original_owner = ctx.svm.get_account(&recipient).unwrap().owner;
        let before_balance = ctx.svm.get_balance(&recipient).unwrap_or(0);
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &payer.pubkey(),
            &recipient,
            1000,
        );

        let outcome = ctx.raw_call(ix).signers(&[&payer]).send().unwrap();

        assert!(outcome.is_success());
        assert_eq!(
            ctx.svm.get_balance(&recipient).unwrap_or(0),
            before_balance + 1000
        );
        assert_eq!(
            ctx.svm.get_account(&recipient).unwrap().owner,
            original_owner
        );
        assert!(!has_violation());
    }

    #[test]
    fn account_mutation_probe_runs_in_send_batch_path() {
        // Same guarantee through the send_batch hook.
        let _ = take_violation();
        reset_probed_account_mutations();
        let mut ctx = TestContext::new();
        let payer = fund_keypair(&mut ctx);
        let recipient = Keypair::new().pubkey();
        ctx.svm.airdrop(&recipient, 1).unwrap();

        ctx.enable_account_mutation();

        let before_balance = ctx.svm.get_balance(&recipient).unwrap_or(0);
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &payer.pubkey(),
            &recipient,
            2000,
        );

        ctx.pending_instructions.push(ix);
        ctx.pending_signers.push(payer.insecure_clone());
        let outcome = ctx.send_batch().unwrap().expect("batch should send");

        assert!(outcome.is_success());
        assert_eq!(
            ctx.svm.get_balance(&recipient).unwrap_or(0),
            before_balance + 2000
        );
        assert!(!has_violation());
    }

    #[test]
    fn raw_call_with_signers_no_fee_payer() {
        // Regression: raw_call().signers(&[payer]).send() should use first signer as fee payer
        let mut ctx = TestContext::new();
        let payer = fund_keypair(&mut ctx);
        let recipient = Pubkey::new_unique();

        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &payer.pubkey(),
            &recipient,
            1000,
        );
        let result = ctx.raw_call(ix).signers(&[&payer]).send();
        assert!(
            result.is_ok(),
            "raw_call with signers should succeed: {:?}",
            result.err()
        );
        assert!(result.unwrap().is_success());
    }

    #[test]
    fn raw_call_with_explicit_fee_payer() {
        // fee_payer() should be used even if it's not in signers list
        let mut ctx = TestContext::new();
        let payer = fund_keypair(&mut ctx);
        let recipient = Pubkey::new_unique();

        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &payer.pubkey(),
            &recipient,
            1000,
        );
        let result = ctx.raw_call(ix).fee_payer(&payer).send();
        assert!(
            result.is_ok(),
            "raw_call with fee_payer should succeed: {:?}",
            result.err()
        );
        assert!(result.unwrap().is_success());
    }

    #[test]
    fn raw_call_fee_payer_prepended_to_signers() {
        // When fee_payer is set AND signers are set, fee_payer should be prepended
        let mut ctx = TestContext::new();
        let payer = fund_keypair(&mut ctx);
        let other_signer = fund_keypair(&mut ctx);
        let recipient = Pubkey::new_unique();

        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &payer.pubkey(),
            &recipient,
            1000,
        );
        let result = ctx
            .raw_call(ix)
            .fee_payer(&payer)
            .signers(&[&other_signer])
            .send();
        assert!(
            result.is_ok(),
            "fee_payer + signers should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn raw_call_no_signers_no_fee_payer_errors() {
        // No signers and no fee payer should error
        let mut ctx = TestContext::new();
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            1000,
        );
        let result = ctx.raw_call(ix).send();
        assert!(result.is_err(), "should error with no signers");
    }

    #[test]
    fn raw_call_duplicate_fee_payer_signer_no_double_sign() {
        // fee_payer same as first signer — should not duplicate
        let mut ctx = TestContext::new();
        let payer = fund_keypair(&mut ctx);
        let recipient = Pubkey::new_unique();

        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &payer.pubkey(),
            &recipient,
            1000,
        );
        let result = ctx.raw_call(ix).fee_payer(&payer).signers(&[&payer]).send();
        assert!(
            result.is_ok(),
            "duplicate fee_payer/signer should not cause double-sign error: {:?}",
            result.err()
        );
        assert!(result.unwrap().is_success());
    }

    #[test]
    fn send_batch_with_signers() {
        // send_batch uses pending_signers[0] as fee payer
        let mut ctx = TestContext::new();
        let payer = fund_keypair(&mut ctx);
        let recipient = Pubkey::new_unique();

        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &payer.pubkey(),
            &recipient,
            2000,
        );
        ctx.pending_instructions.push(ix);
        ctx.pending_signers.push(payer.insecure_clone());
        let result = ctx.send_batch();
        assert!(
            result.is_ok(),
            "send_batch should succeed: {:?}",
            result.err()
        );
        let outcome = result.unwrap();
        assert!(outcome.is_some());
        assert!(outcome.unwrap().is_success());
        assert_eq!(ctx.svm.get_balance(&recipient).unwrap_or(0), 2000);
    }

    // =========================================================================
    // Dummy signing regression tests
    // =========================================================================

    #[test]
    fn sigverify_false_uses_dummy_signatures() {
        // Default sigverify=false should still execute transactions successfully
        let mut ctx = TestContext::new();
        assert!(!ctx.sigverify, "default sigverify should be false");
        let payer = fund_keypair(&mut ctx);
        let recipient = Pubkey::new_unique();

        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &payer.pubkey(),
            &recipient,
            1000,
        );
        let result = ctx.raw_call(ix).signers(&[&payer]).send();
        assert!(result.is_ok());
        assert!(result.unwrap().is_success());
    }

    #[test]
    fn sigverify_true_uses_real_signatures() {
        let mut ctx = TestContext::new();
        ctx.sigverify = true;
        // Re-enable sigverify on the SVM too
        ctx.svm = ctx.svm.with_sigverify(true);
        let payer = fund_keypair(&mut ctx);
        let recipient = Pubkey::new_unique();

        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &payer.pubkey(),
            &recipient,
            1000,
        );
        let result = ctx.raw_call(ix).signers(&[&payer]).send();
        assert!(
            result.is_ok(),
            "real signing should work: {:?}",
            result.err()
        );
        assert!(result.unwrap().is_success());
    }

    #[test]
    fn multiple_transactions_with_dummy_signing() {
        // Verify dummy signing works across multiple sequential transactions
        let mut ctx = TestContext::new();
        let payer = fund_keypair(&mut ctx);
        let recipient = Pubkey::new_unique();

        for i in 0..5 {
            let ix = anchor_lang::solana_program::system_instruction::transfer(
                &payer.pubkey(),
                &recipient,
                1000,
            );
            let result = ctx.raw_call(ix).signers(&[&payer]).send();
            assert!(
                result.is_ok(),
                "tx {} should succeed: {:?}",
                i,
                result.err()
            );
            assert!(
                result.unwrap().is_success(),
                "tx {} should be successful",
                i
            );
        }

        // Verify lamports moved
        let balance = ctx.svm.get_balance(&recipient).unwrap_or(0);
        assert_eq!(
            balance, 5000,
            "recipient should have 5000 lamports after 5 transfers"
        );
    }

    // =========================================================================
    // Sysvar snapshot regression tests
    // =========================================================================

    #[test]
    fn sysvar_snapshot_excludes_large_sysvars() {
        // SlotHistory (131KB) and SlotHashes (20KB) should NOT be in snapshots
        use anchor_lang::prelude::sysvar::SysvarId;
        use anchor_lang::prelude::Clock;

        let ctx = TestContext::new();
        let snapshot = snapshot::SvmSnapshot::take_all(&ctx.svm);

        let sysvar_pubkeys: Vec<_> = snapshot.sysvars.iter().map(|(pk, _)| *pk).collect();

        // Clock should be present
        assert!(
            sysvar_pubkeys.contains(&Clock::id()),
            "Clock should be in snapshot"
        );

        // SlotHistory and SlotHashes should NOT be present
        let slot_history_id =
            solana_pubkey::Pubkey::from_str_const("SysvarS1otHistory11111111111111111111111111");
        let slot_hashes_id =
            solana_pubkey::Pubkey::from_str_const("SysvarS1otHashes111111111111111111111111111");
        assert!(
            !sysvar_pubkeys.contains(&slot_history_id),
            "SlotHistory (131KB) should be excluded from snapshots"
        );
        assert!(
            !sysvar_pubkeys.contains(&slot_hashes_id),
            "SlotHashes (20KB) should be excluded from snapshots"
        );
    }

    // =========================================================================
    // Clock target slot tracking regression tests
    // =========================================================================

    #[test]
    fn advance_slots_records_target_slot() {
        let mut ctx = TestContext::new();
        ctx.advance_slots(500);
        assert_eq!(
            ctx.dirty_tracker.clock_target_slot,
            Some(500 + ctx.slot() - 500)
        );
        assert!(ctx.dirty_tracker.is_clock_dirty());
    }

    #[test]
    fn warp_to_slot_records_target_slot() {
        let mut ctx = TestContext::new();
        ctx.warp_to_slot(12345);
        assert_eq!(ctx.dirty_tracker.clock_target_slot, Some(12345));
        assert!(ctx.dirty_tracker.is_clock_dirty());
    }

    #[test]
    fn dirty_tracker_clear_resets_clock_target() {
        let mut ctx = TestContext::new();
        ctx.advance_slots(100);
        assert!(ctx.dirty_tracker.clock_target_slot.is_some());
        ctx.dirty_tracker.clear();
        assert!(ctx.dirty_tracker.clock_target_slot.is_none());
        assert!(!ctx.dirty_tracker.is_clock_dirty());
    }

    // === Regression: corpus_loading flag suppresses monitor output ===

    #[test]
    fn corpus_loading_flag_defaults_false() {
        assert!(!is_corpus_loading());
    }

    #[test]
    fn corpus_loading_flag_roundtrip() {
        set_corpus_loading(true);
        assert!(is_corpus_loading());
        set_corpus_loading(false);
        assert!(!is_corpus_loading());
    }
}
