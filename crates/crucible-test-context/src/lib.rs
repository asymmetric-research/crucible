use std::rc::Rc;
use std::sync::Arc;
use std::collections::{HashSet, HashMap};
use litesvm::LiteSVM;

// Fast hashing for hot-path coverage collections (10-50x faster than SipHash for integers)
pub use rustc_hash::{FxHashMap, FxHashSet, FxBuildHasher};

/// Type alias for fast HashSet (uses FxHash)
pub type FastHashSet<T> = FxHashSet<T>;
/// Type alias for fast HashMap (uses FxHash)
pub type FastHashMap<K, V> = FxHashMap<K, V>;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_pubkey::Pubkey;
use solana_transaction_error::TransactionError;

// Re-export types from anchor-lang for anchor program interactions
use anchor_lang::prelude::{Clock, Rent};
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::system_program;
use anchor_lang::{
    AnchorDeserialize,
    AnchorSerialize,
    Discriminator,
};
use spl_token::solana_program::program_option::COption;
use anchor_lang::solana_program::program_pack::Pack;
use anyhow::Result;
pub use crate::account_builders::MintAccountBuilder;
pub use crate::account_builders::GenericAccountBuilder;
pub use crate::account_builders::TokenAccountBuilder;
pub use crate::instruction_builder::InstructionBuilder;
pub use crate::transaction_builder::TransactionBuilder;
pub use crate::program_builder::ProgramBuilder;
pub use crate::account_builders::AccountBuilderBase;
pub use crate::mock_oracles::{
    MockPythOracleBuilder,
    PriceUpdateV2,
    PriceFeedMessage,
    VerificationLevel,
    DEFAULT_PYTH_RECEIVER_ID,
    PYTH_DISCRIMINATOR,
};

mod account_builders;
mod instruction_builder;
mod program_builder;
pub mod snapshot;
mod transaction_builder;

// Coverage analysis and visualization
pub mod coverage;

// Re-export coverage types for backward compatibility
pub use coverage::{FunctionInfo, ReachableAnalysis, CoverageStats, CoverageWriteStats, CachedFunctionInfo, CachedProgramAnalysis};
pub use coverage::{extract_functions, generate_bytecode_lcov, generate_source_lcov, generate_coverage_html, build_cached_analysis, generate_coverage_html_cached};
pub use coverage::{DwarfSourceMap, SourceLocation, build_dwarf_source_map};

pub use litesvm::InvocationInspectCallback;

// Re-export serde_json for generated code
pub use serde_json;

// ============================================================================
// Global Action Counter (for monitor: actions/exec metric)
// ============================================================================

/// Global counter of total actions dispatched across all iterations.
/// Used with TOTAL_EXECUTIONS to compute average actions per execution.
pub static TOTAL_ACTIONS_DISPATCHED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Increment the global action counter by one.
#[inline]
pub fn increment_action_count() {
    TOTAL_ACTIONS_DISPATCHED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

// ============================================================================
// Thread-Local State
// ============================================================================

use std::cell::{Cell, RefCell};
use serde::{Serialize, Deserialize};

thread_local! {
    // Invariant violation tracking for fuzz_assert! macros
    static VIOLATION: RefCell<Option<String>> = RefCell::new(None);
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
    // Record in per-iteration history (for crash metadata)
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

/// Clear the action history (called at start of each iteration)
pub fn clear_action_history() {
    ACTION_HISTORY.with(|h| h.borrow_mut().clear());
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

/// Build crash metadata from current state
pub fn build_crash_metadata(seed: Option<u64>) -> CrashMetadata {
    let timestamp = chrono_lite_timestamp();
    CrashMetadata {
        test_name: get_current_test_name().unwrap_or_else(|| "unknown".to_string()),
        timestamp,
        iteration: get_current_iteration(),
        seed,
        actions: get_action_history(),
    }
}

/// Print the action sequence to stderr (for debugging crashes)
pub fn print_action_sequence() {
    let history = get_action_history();
    let total_actions = TOTAL_ACTIONS_IN_SEQUENCE.with(|t| *t.borrow());
    let violation_idx = get_violation_action_index();

    if history.is_empty() && total_actions == 0 {
        return;
    }

    let executed = history.len();
    let skipped = total_actions.saturating_sub(executed);

    eprintln!("\n=== FUZZ SEQUENCE ({} executed, {} skipped) ===", executed, skipped);
    for (i, record) in history.iter().enumerate() {
        // Format params as key=value pairs
        let params_str = if let serde_json::Value::Object(map) = &record.params {
            map.iter()
                .map(|(k, v)| format!("{}={}", k, format_json_value(v)))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            String::new()
        };

        let status = if record.success { "OK" } else { "FAIL" };

        // Mark the action that triggered the violation
        let violation_marker = if violation_idx == Some(i) { " [VIOLATION]" } else { "" };

        if params_str.is_empty() {
            eprintln!("  {}. {} -> {}{}", i + 1, record.name, status, violation_marker);
        } else {
            eprintln!("  {}. {}({}) -> {}{}", i + 1, record.name, params_str, status, violation_marker);
        }
    }

    // Show skipped actions
    if skipped > 0 {
        eprintln!("  ... {} action(s) not executed (stopped on violation)", skipped);
    }

    eprintln!("================================\n");
}

/// Format a JSON value for display (compact format)
fn format_json_value(v: &serde_json::Value) -> String {
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
            let items: Vec<String> = obj.iter()
                .map(|(k, v)| format!("{}: {}", k, format_json_value(v)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
    }
}

/// Write crash metadata to a .meta.json file and save input bytes for replay
pub fn write_crash_metadata(crash_dir: &str, input_hash: u64, seed: Option<u64>, input_bytes: &[u8]) {
    let crash_id = format!("crash_{:016x}", input_hash);
    let metadata = build_crash_metadata(seed);
    let meta_filename = format!("{}/{}.meta.json", crash_dir, crash_id);
    let input_filename = format!("{}/{}", crash_dir, crash_id);

    // Save the input bytes for replay
    if let Err(e) = std::fs::write(&input_filename, input_bytes) {
        eprintln!("[META] Failed to write crash input {}: {}", input_filename, e);
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
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
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

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hours, minutes, seconds)
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
    DISCRIMINATOR_MAP.get()
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
        }
    });
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
    },
    /// Transaction failed with program error
    ProgramError {
        /// Raw error from SVM
        error: TransactionError,
        /// Parsed error code (e.g., 6051 from Custom(6051))
        error_code: Option<u32>,
        /// Instruction index that failed
        instruction_index: Option<u8>,
        /// Program logs up to failure
        logs: Vec<String>,
    },
}

/// Error type for TxOutcome::into_result()
#[derive(Debug, Clone)]
pub struct TxError {
    pub error: TransactionError,
    pub error_code: Option<u32>,
    pub instruction_index: Option<u8>,
    pub logs: Vec<String>,
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

    /// Unwrap success or panic with detailed error message including logs
    pub fn unwrap(self) {
        match self {
            TxOutcome::Success { .. } => {}
            TxOutcome::ProgramError { error, error_code, logs, .. } => {
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
            TxOutcome::ProgramError { error, error_code, instruction_index, logs } => {
                Err(TxError { error, error_code, instruction_index, logs })
            }
        }
    }
}

/// Parse litesvm TransactionError to extract error code
/// Extracts Custom(N) error codes from InstructionError variants
pub fn parse_error_code(err: &TransactionError) -> Option<u32> {
    let debug_str = format!("{:?}", err);
    if let Some(custom_start) = debug_str.find("Custom(") {
        let after_custom = &debug_str[custom_start + 7..];
        if let Some(end) = after_custom.find(')') {
            return after_custom[..end].parse().ok();
        }
    }
    None
}

/// Parse litesvm TransactionError to extract instruction index
pub fn parse_instruction_index(err: &TransactionError) -> Option<u8> {
    let debug_str = format!("{:?}", err);
    if let Some(start) = debug_str.find("InstructionError(") {
        let after_prefix = &debug_str[start + 17..];
        if let Some(comma) = after_prefix.find(',') {
            return after_prefix[..comma].trim().parse().ok();
        }
    }
    None
}

/// Convert litesvm transaction result to TxOutcome
pub fn tx_result_to_outcome(result: litesvm::types::TransactionResult) -> TxOutcome {
    let outcome = match result {
        Ok(meta) => TxOutcome::Success {
            compute_units: meta.compute_units_consumed,
            logs: meta.logs,
        },
        Err(failed) => TxOutcome::ProgramError {
            error: failed.err.clone(),
            error_code: parse_error_code(&failed.err),
            instruction_index: parse_instruction_index(&failed.err),
            logs: failed.meta.logs,
        },
    };
    // Store error code in TLS for push_action_record to pick up
    set_last_error_code(outcome.error_code());
    outcome
}

// Re-export types needed by generated code
pub mod fuzz_types {
    pub use solana_transaction::sanitized::SanitizedTransaction;
    pub use solana_transaction_context::{IndexOfAccount, InstructionContext};
    pub use solana_program_runtime::invoke_context::{InvokeContext, Executable};
    pub use solana_sbpf::ebpf;
    pub use solana_sbpf::static_analysis::Analysis;
    pub use solana_pubkey::Pubkey;
}

/// Count reachable code from a given entry PC using static CFG analysis.
/// Returns (instructions, branches, edges) or None if analysis fails.
/// Used by the fuzzer for per-instruction totals computation.
pub fn count_reachable_from_pc(program_data: &[u8], entry_pc: usize) -> Option<(usize, usize, usize)> {
    use solana_sbpf::elf::Executable;
    use solana_sbpf::program::BuiltinProgram;
    use solana_sbpf::static_analysis::Analysis;
    use solana_sbpf::vm::ContextObject;
    use solana_sbpf::ebpf;

    // Minimal ContextObject for static analysis
    struct DummyContext;
    impl ContextObject for DummyContext {
        fn consume(&mut self, _amount: u64) {}
        fn get_remaining(&self) -> u64 { 0 }
    }

    let loader = Arc::new(BuiltinProgram::<DummyContext>::new_mock());
    let executable = Executable::from_elf(program_data, loader).ok()?;
    let analysis = Analysis::from_executable(&executable).ok()?;
    let sbpf_version = executable.get_sbpf_version();

    // Build function key → entry PC map from analysis.functions
    // analysis.functions: BTreeMap<usize, (u32, String)> maps PC → (function_key, name)
    let mut key_to_pc: HashMap<u32, usize> = HashMap::new();
    for (pc, (key, _name)) in &analysis.functions {
        key_to_pc.insert(*key, *pc);
    }

    // Build a map from PC to node index for quick lookup
    let mut pc_to_node: HashMap<usize, usize> = HashMap::new();
    for (node_idx, cfg_node) in analysis.cfg_nodes.iter() {
        if !cfg_node.instructions.is_empty() {
            let first_pc = analysis.instructions[cfg_node.instructions.start].ptr;
            pc_to_node.insert(first_pc, *node_idx);
        }
    }

    // Find the CFG node containing entry_pc
    let mut start_node = None;
    for (node_idx, cfg_node) in analysis.cfg_nodes.iter() {
        if !cfg_node.instructions.is_empty() {
            let first_pc = analysis.instructions[cfg_node.instructions.start].ptr;
            let last_pc = analysis.instructions[cfg_node.instructions.end - 1].ptr;
            if entry_pc >= first_pc && entry_pc <= last_pc {
                start_node = Some(*node_idx);
                break;
            }
        }
    }
    let start_node = start_node?;

    // BFS from start_node to count all reachable code, following CALL instructions
    let mut visited = HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(start_node);
    visited.insert(start_node);

    let mut total_instructions = 0usize;
    let mut total_branches = 0usize;
    let mut total_edges = 0usize;

    while let Some(node_idx) = queue.pop_front() {
        if let Some(cfg_node) = analysis.cfg_nodes.get(&node_idx) {
            // Count instructions in this node
            let node_instr_count = cfg_node.instructions.end - cfg_node.instructions.start;
            total_instructions += node_instr_count;

            // Process each instruction looking for CALLs and conditional branches
            for insn_idx in cfg_node.instructions.clone() {
                let insn = &analysis.instructions[insn_idx];
                let opc = insn.opc;

                // Check for CALL instruction (0x85) - follow the call target
                // Use function registry to resolve CALL targets correctly
                if opc == 0x85 {
                    // Calculate function key using SBPF version-specific logic
                    let key = sbpf_version.calculate_call_imm_target_pc(insn.ptr, insn.imm);
                    if let Some(&target_pc) = key_to_pc.get(&key) {
                        if let Some(&target_node) = pc_to_node.get(&target_pc) {
                            if visited.insert(target_node) {
                                queue.push_back(target_node);
                            }
                        }
                    }
                }

                // Check for conditional branches
                let is_jmp = opc & 7 == ebpf::BPF_JMP;
                if is_jmp {
                    let is_conditional = opc != 0x05 && opc != 0x85 && opc != 0x8d && opc != 0x95;
                    if is_conditional {
                        total_branches += 1;
                        total_edges += 2; // Conditional branches have 2 edges (taken/not-taken)
                    }
                }
            }

            // Enqueue unvisited CFG successors (for jumps within same function)
            for &dest in &cfg_node.destinations {
                if visited.insert(dest) {
                    queue.push_back(dest);
                }
            }
        }
    }

    eprintln!("[DEBUG] count_reachable_from_pc(0x{:x}): {} nodes, {} instructions, {} branches, {} edges",
        entry_pc, visited.len(), total_instructions, total_branches, total_edges);

    Some((total_instructions, total_branches, total_edges))
}

// LCOV and coverage functions moved to coverage module
// Re-exported at top of file for backward compatibility

// CFG visualization moved to coverage/html.rs (generate_coverage_html)

// ============================================================================
// CFG Analysis
// ============================================================================

// ReachableAnalysis struct moved to coverage/types.rs and re-exported above

/// Extended CFG analysis that returns both counts and sets of reachable code.
/// Used for filtering visited coverage to only include code within the handler's scope.
pub fn analyze_reachable_from_pc(program_data: &[u8], entry_pc: usize) -> Option<ReachableAnalysis> {
    use solana_sbpf::elf::Executable;
    use solana_sbpf::program::BuiltinProgram;
    use solana_sbpf::static_analysis::Analysis;
    use solana_sbpf::vm::ContextObject;
    use solana_sbpf::ebpf;

    struct DummyContext;
    impl ContextObject for DummyContext {
        fn consume(&mut self, _amount: u64) {}
        fn get_remaining(&self) -> u64 { 0 }
    }

    let loader = Arc::new(BuiltinProgram::<DummyContext>::new_mock());
    let executable = Executable::from_elf(program_data, loader).ok()?;
    let analysis = Analysis::from_executable(&executable).ok()?;
    let sbpf_version = executable.get_sbpf_version();

    // Build function key → entry PC map
    let mut key_to_pc: HashMap<u32, usize> = HashMap::new();
    for (pc, (key, _name)) in &analysis.functions {
        key_to_pc.insert(*key, *pc);
    }

    // Build PC → node index map
    let mut pc_to_node: HashMap<usize, usize> = HashMap::new();
    for (node_idx, cfg_node) in analysis.cfg_nodes.iter() {
        if !cfg_node.instructions.is_empty() {
            let first_pc = analysis.instructions[cfg_node.instructions.start].ptr;
            pc_to_node.insert(first_pc, *node_idx);
        }
    }

    // Find starting node
    let start_node = analysis.cfg_nodes.iter()
        .find(|(_, cfg_node)| {
            if cfg_node.instructions.is_empty() { return false; }
            let first_pc = analysis.instructions[cfg_node.instructions.start].ptr;
            let last_pc = analysis.instructions[cfg_node.instructions.end - 1].ptr;
            entry_pc >= first_pc && entry_pc <= last_pc
        })
        .map(|(idx, _)| *idx)?;

    // BFS to collect all reachable code
    let mut visited_nodes = HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(start_node);
    visited_nodes.insert(start_node);

    let mut result = ReachableAnalysis::default();

    while let Some(node_idx) = queue.pop_front() {
        if let Some(cfg_node) = analysis.cfg_nodes.get(&node_idx) {
            for insn_idx in cfg_node.instructions.clone() {
                let insn = &analysis.instructions[insn_idx];
                let opc = insn.opc;
                let pc = insn.ptr;

                // Record this PC as reachable
                result.reachable_pcs.insert(pc);
                result.total_instructions += 1;

                // Handle CALL instructions
                if opc == 0x85 {
                    let key = sbpf_version.calculate_call_imm_target_pc(pc, insn.imm);
                    if let Some(&target_pc) = key_to_pc.get(&key) {
                        if let Some(&target_node) = pc_to_node.get(&target_pc) {
                            if visited_nodes.insert(target_node) {
                                queue.push_back(target_node);
                            }
                        }
                    }
                }

                // Handle conditional branches
                let is_jmp = opc & 7 == ebpf::BPF_JMP;
                if is_jmp {
                    let is_conditional = opc != 0x05 && opc != 0x85 && opc != 0x8d && opc != 0x95;
                    if is_conditional {
                        result.reachable_branch_pcs.insert(pc);
                        result.total_branches += 1;

                        // Calculate both edge targets (taken and not-taken)
                        let offset = insn.off as i64;
                        let next_pc = pc + 8; // Fall-through (not-taken)
                        let target_pc = ((pc as i64) + 8 + offset * 8) as usize; // Taken

                        // Record edges as (source_pc << 32) | target_pc
                        let edge_taken = ((pc as u64) << 32) | (target_pc as u64);
                        let edge_not_taken = ((pc as u64) << 32) | (next_pc as u64);
                        result.reachable_edges.insert(edge_taken);
                        result.reachable_edges.insert(edge_not_taken);
                        result.total_edges += 2;
                    }
                }
            }

            // Follow CFG successors
            for &dest in &cfg_node.destinations {
                if visited_nodes.insert(dest) {
                    queue.push_back(dest);
                }
            }
        }
    }

    eprintln!("[DEBUG] analyze_reachable_from_pc(0x{:x}): {} nodes, {} PCs, {} branches, {} edges",
        entry_pc, visited_nodes.len(), result.reachable_pcs.len(), result.total_branches, result.total_edges);

    Some(result)
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
    tracked_accounts: HashSet<Pubkey>,
    /// Total CFG edges and instructions per program (for coverage percentage calculation)
    /// Value is (total_edges, total_instructions)
    program_coverage_totals: HashMap<Pubkey, (usize, usize)>,
    /// Snapshot of initial state for fast restore (always-on in fuzz mode)
    pub snapshot: Option<snapshot::SvmSnapshot>,
    /// Tracks dirty accounts across all transactions in an iteration
    pub dirty_tracker: snapshot::DirtyTracker,
    /// Per-transaction taint records for the current iteration
    pub taint_log: snapshot::IterationTaintLog,
}

impl Clone for TestContext {
    fn clone(&self) -> Self {
        Self {
            svm: self.svm.clone(),
            pending_instructions: self.pending_instructions.clone(),
            pending_signers: self.pending_signers.iter().map(|k| k.insecure_clone()).collect(),
            programs: self.programs.clone(),
            tracked_accounts: self.tracked_accounts.clone(),
            program_coverage_totals: self.program_coverage_totals.clone(),
            // Snapshot is not cloned — only the template fixture owns it
            snapshot: None,
            // Fresh tracker/log for each clone
            dirty_tracker: self.dirty_tracker.clone(),
            taint_log: self.taint_log.clone(),
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
    ) {}

    fn after_invocation(
        &self,
        _invoke_context: &solana_program_runtime::invoke_context::InvokeContext,
        _register_tracing_enabled: bool,
    ) {}
}

impl TestContext {
    pub fn new() -> Self {
        // When ANCHOR_FUZZ_DEBUGGABLE is set (by the fuzz macro), create a debuggable SVM
        // so programs are loaded with register tracing support baked in.
        // Use EmptyInvocationCallback to suppress "Error collecting register tracing" messages
        // from DefaultRegisterTracingCallback trying to find .so files for built-in programs.
        let svm = if std::env::var("ANCHOR_FUZZ_DEBUGGABLE").is_ok() {
            let mut svm = LiteSVM::new_debuggable(true);
            svm.set_invocation_inspect_callback(EmptyInvocationCallback);
            svm
        } else {
            LiteSVM::new()
        };

        Self {
            svm,
            pending_instructions: Vec::new(),
            pending_signers: Vec::new(),
            programs: std::sync::Arc::new(Vec::new()),
            tracked_accounts: HashSet::new(),
            program_coverage_totals: HashMap::new(),
            snapshot: None,
            dirty_tracker: snapshot::DirtyTracker::new(),
            taint_log: snapshot::IterationTaintLog::new(),
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
            tracked_accounts: HashSet::new(),
            program_coverage_totals: HashMap::new(),
            snapshot: None,
            dirty_tracker: snapshot::DirtyTracker::new(),
            taint_log: snapshot::IterationTaintLog::new(),
        }
    }

    /// Analyze a program binary and return (total_edges, total_instructions).
    /// Only counts edges from conditional jump instructions (matching runtime tracking).
    /// Used for coverage percentage calculation.
    pub fn analyze_program_coverage(program_data: &[u8]) -> Option<(usize, usize)> {
        use solana_sbpf::elf::Executable;
        use solana_sbpf::program::BuiltinProgram;
        use solana_sbpf::static_analysis::Analysis;
        use solana_sbpf::vm::ContextObject;
        use solana_sbpf::ebpf;

        // Minimal ContextObject implementation for static analysis
        struct DummyContext;
        impl ContextObject for DummyContext {
            fn consume(&mut self, _amount: u64) {}
            fn get_remaining(&self) -> u64 { 0 }
        }

        // Create a dummy loader for parsing
        let loader = Arc::new(BuiltinProgram::<DummyContext>::new_mock());

        // Load as executable (may fail for invalid binaries)
        let executable = Executable::from_elf(program_data, loader).ok()?;

        // Run static analysis
        let analysis = Analysis::from_executable(&executable).ok()?;

        // Count conditional jump edges for coverage percentage calculation
        // Only count BPF_JMP edges (matching runtime tracking in process_trace)
        let mut total_conditional: usize = 0;
        for cfg_node in analysis.cfg_nodes.values() {
            if cfg_node.instructions.is_empty() {
                continue;
            }

            // Get last instruction (the terminator)
            let last_insn = &analysis.instructions[cfg_node.instructions.end - 1];

            // Same check as runtime: opc & 7 == BPF_JMP
            let is_jmp = last_insn.opc & 7 == ebpf::BPF_JMP;

            if is_jmp {
                let opc = last_insn.opc;
                // Only count conditional jumps for coverage purposes
                // Exclude: CALL (0x85), EXIT (0x95), JA unconditional (0x05), CALLX (0x8d)
                let is_conditional = opc != 0x05 && opc != 0x85 && opc != 0x8d && opc != 0x95;
                if is_conditional {
                    total_conditional += cfg_node.destinations.len();
                }
            }
        }

        let total_instructions = analysis.instructions.len();

        Some((total_conditional, total_instructions))
    }

    pub fn add_program(&mut self, program_id: &Pubkey, program_path: &str) -> Result<()> {
        let program_data = std::fs::read(program_path)?;

        // Run static analysis to get total edge and instruction count for coverage percentages
        if let Some((total_edges, total_instructions)) = Self::analyze_program_coverage(&program_data) {
            self.program_coverage_totals.insert(*program_id, (total_edges, total_instructions));
        }

        self.svm.add_program(program_id.clone(), &program_data);
        // Store program data for reloading into debuggable SVMs
        std::sync::Arc::make_mut(&mut self.programs).push(ProgramData {
            program_id: *program_id,
            data: program_data,
        });
        Ok(())
    }

    pub fn from_svm(svm: LiteSVM) -> Self {
        Self {
            svm,
            pending_instructions: Vec::new(),
            pending_signers: Vec::new(),
            programs: std::sync::Arc::new(Vec::new()),
            tracked_accounts: HashSet::new(),
            program_coverage_totals: HashMap::new(),
            snapshot: None,
            dirty_tracker: snapshot::DirtyTracker::new(),
            taint_log: snapshot::IterationTaintLog::new(),
        }
    }

    pub fn into_svm(self) -> LiteSVM {
        self.svm
    }

    /// Clone this context and set an invocation callback for coverage tracking.
    /// The source SVM must have been created with debuggable mode (via ANCHOR_FUZZ_DEBUGGABLE env var)
    /// for register tracing to work. Cloning preserves the debuggable state and loaded programs.
    ///
    /// NOTE: For better performance in fuzzing loops, prefer using `set_invocation_callback` after
    /// cloning the fixture instead of this method. This method performs an additional SVM clone
    /// beyond the fixture clone, which can be expensive.
    pub fn clone_with_invocation_callback<C: InvocationInspectCallback + 'static>(&self, callback: C) -> Self {
        // Just clone the SVM directly and set callback - don't use builder methods
        // as they may create a fresh SVM and lose account data
        let mut cloned_svm = self.svm.clone();
        cloned_svm.set_invocation_inspect_callback(callback);

        Self {
            svm: cloned_svm,
            pending_instructions: self.pending_instructions.clone(),
            pending_signers: self.pending_signers.iter().map(|k| k.insecure_clone()).collect(),
            programs: self.programs.clone(),
            tracked_accounts: self.tracked_accounts.clone(),
            program_coverage_totals: self.program_coverage_totals.clone(),
            snapshot: None,
            dirty_tracker: snapshot::DirtyTracker::new(),
            taint_log: snapshot::IterationTaintLog::new(),
        }
    }

    /// Set an invocation callback for coverage tracking on this context.
    /// Unlike `clone_with_invocation_callback`, this modifies the context in place
    /// without performing an additional SVM clone.
    ///
    /// The SVM must have been created with debuggable mode (via ANCHOR_FUZZ_DEBUGGABLE env var)
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
        self.tracked_accounts.insert(pubkey);
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
        self.programs.iter()
            .map(|p| (p.program_id, p.data.clone()))
            .collect()
    }

    /// Get program binary by pubkey (for CFG analysis).
    pub fn get_program_binary(&self, pubkey: &Pubkey) -> Option<&[u8]> {
        self.programs.iter()
            .find(|p| &p.program_id == pubkey)
            .map(|p| p.data.as_slice())
    }

    // =========================================================================
    // Snapshot/Restore API (always-on in fuzz mode)
    // =========================================================================

    /// Take a snapshot of all tracked accounts + Clock sysvar.
    /// Called once after setup, before the fuzz loop begins.
    ///
    /// Also includes accounts that were touched during setup transactions
    /// (from the dirty tracker), which captures CPI-created accounts like PDAs
    /// that aren't in `tracked_accounts`.
    pub fn take_snapshot(&mut self) {
        // Merge dirty tracker accounts into tracked set so CPI-created accounts
        // (e.g., PDAs created by Initialize instructions) are included in the snapshot
        for pubkey in self.dirty_tracker.dirty_accounts() {
            self.tracked_accounts.insert(*pubkey);
        }
        self.snapshot = Some(snapshot::SvmSnapshot::take(&self.svm, &self.tracked_accounts));
        // Clear the dirty tracker so it's fresh for the first iteration
        self.dirty_tracker.clear();
    }

    /// Prepare for a new iteration: clear dirty tracker, taint log, and pending state.
    /// Called at the start of each fuzzing iteration.
    pub fn begin_iteration(&mut self) {
        self.dirty_tracker.clear();
        self.taint_log.clear();
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

    /// Get the taint log for the current iteration.
    pub fn taint_log(&self) -> &snapshot::IterationTaintLog {
        &self.taint_log
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
        self.dirty_tracker.mark_clock_dirty();
        self.svm.warp_to_slot(slot);
    }

    pub fn advance_slots(&mut self, slots: u64) {
        self.dirty_tracker.mark_clock_dirty();
        let current_slot = self.slot();
        let target_slot = current_slot + slots;
        self.svm.warp_to_slot(target_slot);
    }

    /// Getters

    pub fn slot(&self) -> u64 {
        self.svm.get_sysvar::<Clock>().slot
    }

    /// Returns the slot that the next transaction will likely see (current + 1)
    pub fn next_slot(&self) -> u64 {
        self.slot() + 1
    }

    /// Check if account exists AND has at least `min_size` bytes of data
    pub fn account_has_data(&self, pubkey: &Pubkey, min_size: usize) -> bool {
        self.svm.get_account(pubkey)
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
    pub fn read_anchor_account<T: AnchorDeserialize + Discriminator>(&self, address: &Pubkey) -> Result<T> {
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
        self.tracked_accounts.insert(*address);
        self.dirty_tracker.mark_account_dirty(address);
        let _ = self.svm.set_account(*address, account);
        Ok(())
    }
    
    // Serialize with discriminator, write to SVM
    pub fn write_anchor_account<T: AnchorSerialize + Discriminator>(
        &mut self,
        address: &Pubkey,
        data: &T
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
        Ok(*bytemuck::from_bytes::<T>(&account.data[discriminator_len..discriminator_len + std::mem::size_of::<T>()]))
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
    pub fn write_zero_copy_account<T: bytemuck::Pod>(&mut self, address: &Pubkey, data: &T) -> Result<()> {
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
        self.tracked_accounts.insert(*address);
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

        let debug = std::env::var("FUZZ_DEBUG").is_ok();
        let num_ixs = self.pending_instructions.len();

        // Deduplicate signers while preserving order (first = fee payer)
        let mut seen = std::collections::HashSet::new();
        let unique_signers: Vec<&Keypair> = self.pending_signers
            .iter()
            .filter(|k| seen.insert(k.pubkey()))
            .collect();

        let fee_payer = unique_signers.first().map(|k| k.pubkey()).unwrap_or_default();

        if debug {
            eprintln!("[TX] Sending batch with {} instructions", num_ixs);
            for (i, ix) in self.pending_instructions.iter().enumerate() {
                eprintln!("[TX]   ix[{}]: program={}", i, ix.program_id);
            }
        }

        // Record dirty accounts + capture metadata before instructions are consumed
        self.dirty_tracker.record_tx(&self.pending_instructions, &fee_payer);
        let captured = snapshot::capture_tx_meta(&self.pending_instructions, &fee_payer);
        let pre_state = if self.taint_log.collects_diffs() {
            Some(snapshot::snapshot_writable_accounts(
                &self.svm,
                &self.pending_instructions,
                &fee_payer,
            ))
        } else {
            None
        };

        // Send transaction with all queued instructions (take ownership to avoid clone)
        let instructions = std::mem::take(&mut self.pending_instructions);
        let result = instruction_builder::send_transaction(
            &mut self.svm,
            instructions,
            &unique_signers
        )?;

        let outcome = tx_result_to_outcome(result);

        if debug {
            match &outcome {
                TxOutcome::Success { compute_units, logs } => {
                    eprintln!("[TX] SUCCESS - compute_units={}, logs:", compute_units);
                    for log in logs {
                        eprintln!("[TX]   {}", log);
                    }
                }
                TxOutcome::ProgramError { error, error_code, logs, .. } => {
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

        // Build taint record from captured metadata (only for successful txs)
        if outcome.is_success() {
            let taint = snapshot::build_taint_record_from_captured(
                &self.svm, captured, pre_state.as_ref(),
            );
            self.taint_log.push(taint);
        }

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
        };

        assert!(success.is_success());
        assert!(!success.is_error());
        assert!(success.error_code().is_none());
        assert_eq!(success.compute_units(), Some(100));
        assert_eq!(success.logs().len(), 1);

        let error = TxOutcome::ProgramError {
            error: TransactionError::AccountInUse,
            error_code: Some(6051),
            instruction_index: Some(0),
            logs: vec!["error log".to_string()],
        };

        assert!(!error.is_success());
        assert!(error.is_error());
        assert_eq!(error.error_code(), Some(6051));
        assert!(error.compute_units().is_none());
    }

    #[test]
    fn test_tx_outcome_into_result() {
        let success = TxOutcome::Success {
            compute_units: 100,
            logs: vec![],
        };
        assert!(success.into_result().is_ok());

        let error = TxOutcome::ProgramError {
            error: TransactionError::AccountInUse,
            error_code: Some(6051),
            instruction_index: Some(0),
            logs: vec![],
        };
        assert!(error.into_result().is_err());
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
        assert_eq!(format_json_value(&serde_json::json!([1, 2, 3])), "[1, 2, 3]");
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

        ctx.write_account(&pk1, Account {
            lamports: 1_000_000,
            data: vec![1, 2, 3, 4],
            owner,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        ctx.write_account(&pk2, Account {
            lamports: 2_000_000,
            data: vec![10, 20, 30],
            owner,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        // Take snapshot
        ctx.take_snapshot();
        assert!(ctx.has_snapshot());

        // Begin iteration (clears dirty tracker)
        ctx.begin_iteration();

        // Modify accounts
        ctx.write_account(&pk1, Account {
            lamports: 999,
            data: vec![99, 99, 99, 99],
            owner,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        ctx.write_account(&pk2, Account {
            lamports: 0,
            data: vec![],
            owner,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

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
        ctx.write_account(&pk_initial, Account {
            lamports: 1_000_000,
            data: vec![1, 2, 3],
            owner,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        ctx.take_snapshot();
        ctx.begin_iteration();

        // Create a new account that didn't exist at snapshot time
        let pk_new = Pubkey::new_unique();
        ctx.write_account(&pk_new, Account {
            lamports: 500_000,
            data: vec![42],
            owner,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

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

        ctx.write_account(&pk, Account {
            lamports: 1_000_000,
            data: vec![0; 32],
            owner,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        ctx.take_snapshot();

        // Simulate multiple fuzzing iterations
        for i in 0..5 {
            ctx.begin_iteration();

            // Each iteration modifies the account differently
            ctx.write_account(&pk, Account {
                lamports: (i + 1) * 100,
                data: vec![i as u8; 32],
                owner,
                executable: false,
                rent_epoch: 0,
            }).unwrap();

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

        ctx.write_account(&pk1, Account {
            lamports: 100,
            data: vec![],
            owner,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        ctx.write_account(&pk2, Account {
            lamports: 200,
            data: vec![],
            owner,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

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

        ctx.write_account(&pk_modified, Account {
            lamports: 100,
            data: vec![1, 2, 3],
            owner,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        ctx.write_account(&pk_untouched, Account {
            lamports: 200,
            data: vec![4, 5, 6],
            owner,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        ctx.take_snapshot();
        ctx.begin_iteration();

        // Only modify one account
        ctx.write_account(&pk_modified, Account {
            lamports: 999,
            data: vec![9, 9, 9],
            owner,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

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
        ctx.write_account(&pk, Account {
            lamports: 100,
            data: vec![],
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        }).unwrap();

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
        ctx.write_account(&pk_tracked, Account {
            lamports: 100,
            data: vec![1],
            owner,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        // Simulate a CPI-created account: manually set in SVM and mark dirty
        // (In real usage, this happens via record_tx during a send() call)
        let _ = ctx.svm.set_account(pk_cpi, Account {
            lamports: 200,
            data: vec![2],
            owner,
            executable: false,
            rent_epoch: 0,
        });
        ctx.dirty_tracker.mark_account_dirty(&pk_cpi);

        // take_snapshot should include pk_cpi even though it's not in tracked_accounts
        ctx.take_snapshot();
        assert!(ctx.has_snapshot());

        ctx.begin_iteration();

        // Modify the CPI-created account
        let _ = ctx.svm.set_account(pk_cpi, Account {
            lamports: 999,
            data: vec![9],
            owner,
            executable: false,
            rent_epoch: 0,
        });
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
        ctx.write_account(&pk, Account {
            lamports: 100,
            data: vec![0; 1024],
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        // Clone should share program data via Arc
        let cloned = ctx.clone();
        assert_eq!(ctx.programs_count(), cloned.programs_count());
    }
}

