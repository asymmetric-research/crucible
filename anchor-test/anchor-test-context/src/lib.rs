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
mod transaction_builder;

// Coverage analysis and visualization
pub mod coverage;

// Re-export coverage types for backward compatibility
pub use coverage::{FunctionInfo, ReachableAnalysis, CoverageStats, CoverageWriteStats, CachedFunctionInfo, CachedProgramAnalysis};
pub use coverage::{extract_functions, generate_bytecode_lcov, generate_coverage_html, build_cached_analysis, generate_coverage_html_cached};

pub use litesvm::InvocationInspectCallback;

// Re-export serde_json for generated code
pub use serde_json;

// ============================================================================
// Thread-Local State
// ============================================================================

use std::cell::RefCell;
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
    // Record in per-iteration history (for crash metadata)
    ACTION_HISTORY.with(|h| {
        h.borrow_mut().push(ActionRecord {
            name: name.to_string(),
            params,
            success,
        });
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
    if history.is_empty() {
        return;
    }

    eprintln!("\n=== FUZZ SEQUENCE ({} actions) ===", history.len());
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
        if params_str.is_empty() {
            eprintln!("  {}. {} -> {}", i + 1, record.name, status);
        } else {
            eprintln!("  {}. {}({}) -> {}", i + 1, record.name, params_str, status);
        }
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

/// Write crash metadata to a .meta.json file
pub fn write_crash_metadata(crash_dir: &str, input_hash: u64, seed: Option<u64>) {
    let metadata = build_crash_metadata(seed);
    let filename = format!("{}/crash_{:016x}.meta.json", crash_dir, input_hash);

    match serde_json::to_string_pretty(&metadata) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&filename, json) {
                eprintln!("[META] Failed to write {}: {}", filename, e);
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

/// Global map from Anchor discriminator (8 bytes) to instruction name.
/// Populated once at harness startup via `register_instruction_discriminators()`.
/// Uses OnceLock for lock-free reads after initialization (single-threaded).
static DISCRIMINATOR_MAP: OnceLock<HashMap<[u8; 8], String>> = OnceLock::new();

/// Register instruction discriminators for per-instruction coverage tracking.
/// Call this once at harness initialization with discriminators from the program's IDL.
/// Subsequent calls are ignored (OnceLock can only be set once).
///
/// Example:
/// ```ignore
/// register_instruction_discriminators(&[
///     ("deposit", [171, 94, 235, 200, 28, 230, 215, 98]),
///     ("borrow", [4, 126, 116, 45, 173, 75, 231, 84]),
/// ]);
/// ```
pub fn register_instruction_discriminators(discriminators: &[(&str, [u8; 8])]) {
    let map: HashMap<[u8; 8], String> = discriminators
        .iter()
        .map(|(name, disc)| (*disc, name.to_string()))
        .collect();
    let _ = DISCRIMINATOR_MAP.set(map);
}

/// Look up instruction name from an 8-byte discriminator.
/// Returns None if discriminator is not registered or if the data is too short.
/// Lock-free after initialization.
pub fn lookup_instruction_by_discriminator(instruction_data: &[u8]) -> Option<String> {
    if instruction_data.len() < 8 {
        return None;
    }
    let disc: [u8; 8] = instruction_data[0..8].try_into().ok()?;
    DISCRIMINATOR_MAP.get()?.get(&disc).cloned()
}

/// Get all registered discriminators (for debugging)
pub fn get_registered_discriminators() -> Vec<(String, [u8; 8])> {
    DISCRIMINATOR_MAP.get()
        .map(|map| map.iter().map(|(k, v)| (v.clone(), *k)).collect())
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
    match result {
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
    }
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
    /// Programs loaded into this context (for reloading into debuggable SVMs)
    programs: Vec<ProgramData>,
    /// Account pubkeys that have been set (for copying to debuggable SVMs)
    tracked_accounts: HashSet<Pubkey>,
    /// Total CFG edges and instructions per program (for coverage percentage calculation)
    /// Value is (total_edges, total_instructions)
    program_coverage_totals: HashMap<Pubkey, (usize, usize)>,
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
            programs: Vec::new(),
            tracked_accounts: HashSet::new(),
            program_coverage_totals: HashMap::new(),
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
            programs: Vec::new(),
            tracked_accounts: HashSet::new(),
            program_coverage_totals: HashMap::new(),
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

        // Track stats by opcode for diagnostics: (count, all_dests, conditional_dests)
        let mut stats: std::collections::HashMap<u8, (usize, usize, usize)> = std::collections::HashMap::new();

        // Count only BPF_JMP edges (matching runtime tracking in process_trace)
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

                let entry = stats.entry(opc).or_insert((0, 0, 0)); // (count, all_dests, conditional_dests)
                entry.0 += 1;
                entry.1 += cfg_node.destinations.len();
                if is_conditional {
                    entry.2 += cfg_node.destinations.len();
                }
            }
        }

        // Print diagnostic breakdown
        eprintln!("[STATIC] Edge analysis breakdown by opcode:");
        let mut sorted_stats: Vec<_> = stats.iter().collect();
        sorted_stats.sort_by_key(|(opc, _)| *opc);
        for (opc, (count, dests, _cond_dests)) in &sorted_stats {
            let name = match *opc {
                0x05 => "JA (unconditional)",
                0x85 => "CALL",
                0x8d => "CALLX (indirect)",
                0x95 => "EXIT",
                0x15 => "JEQ (==)",
                0x1d => "JEQ reg",
                0x25 => "JGT (>)",
                0x2d => "JGT reg",
                0x35 => "JGE (>=)",
                0x3d => "JGE reg",
                0x45 => "JSET (&)",
                0x4d => "JSET reg",
                0x55 => "JNE (!=)",
                0x5d => "JNE reg",
                0x65 => "JSGT (signed >)",
                0x6d => "JSGT reg",
                0x75 => "JSGE (signed >=)",
                0x7d => "JSGE reg",
                0xa5 => "JLT (<)",
                0xad => "JLT reg",
                0xb5 => "JLE (<=)",
                0xbd => "JLE reg",
                0xc5 => "JSLT (signed <)",
                0xcd => "JSLT reg",
                0xd5 => "JSLE (signed <=)",
                0xdd => "JSLE reg",
                _ => "unknown",
            };
            let is_excluded = **opc == 0x05 || **opc == 0x85 || **opc == 0x8d || **opc == 0x95;
            let marker = if is_excluded { " [excluded]" } else { "" };
            let avg = if *count > 0 { *dests as f64 / *count as f64 } else { 0.0 };
            eprintln!("[STATIC]   {:#04x} {:18}: {:5} nodes, {:6} edges (avg {:.1}){}",
                opc, name, count, dests, avg, marker);
        }

        let total_all: usize = stats.values().map(|(_, d, _)| d).sum();
        let total_conditional: usize = stats.values().map(|(_, _, c)| c).sum();
        eprintln!("[STATIC] Total edges: {} (all) / {} (conditional only)", total_all, total_conditional);

        // Show PC range distribution to help identify unreached code regions
        let mut pc_ranges: Vec<usize> = Vec::new();
        for cfg_node in analysis.cfg_nodes.values() {
            if !cfg_node.instructions.is_empty() {
                let last_insn = &analysis.instructions[cfg_node.instructions.end - 1];
                let is_jmp = last_insn.opc & 7 == ebpf::BPF_JMP;
                let opc = last_insn.opc;
                let is_conditional = is_jmp && opc != 0x05 && opc != 0x85 && opc != 0x8d && opc != 0x95;
                if is_conditional {
                    pc_ranges.push(last_insn.ptr);
                }
            }
        }
        pc_ranges.sort();
        if !pc_ranges.is_empty() {
            let min_pc = pc_ranges[0];
            let max_pc = pc_ranges[pc_ranges.len() - 1];
            let quartiles = [
                pc_ranges[pc_ranges.len() / 4],
                pc_ranges[pc_ranges.len() / 2],
                pc_ranges[3 * pc_ranges.len() / 4],
            ];
            eprintln!("[STATIC] Conditional jump PC range: {} - {} (quartiles: {}, {}, {})",
                min_pc, max_pc, quartiles[0], quartiles[1], quartiles[2]);
        }

        let total_instructions = analysis.instructions.len();
        eprintln!("[STATIC] Total instructions: {}", total_instructions);

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
        self.programs.push(ProgramData {
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
            programs: Vec::new(),
            tracked_accounts: HashSet::new(),
            program_coverage_totals: HashMap::new(),
        }
    }

    pub fn into_svm(self) -> LiteSVM {
        self.svm
    }

    /// Clone this context and set an invocation callback for coverage tracking.
    /// The source SVM must have been created with debuggable mode (via ANCHOR_FUZZ_DEBUGGABLE env var)
    /// for register tracing to work. Cloning preserves the debuggable state and loaded programs.
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
        }
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
        self.svm.warp_to_slot(slot);
    }
    
    pub fn advance_slots(&mut self, slots: u64) {
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

        if debug {
            eprintln!("[TX] Sending batch with {} instructions", num_ixs);
            for (i, ix) in self.pending_instructions.iter().enumerate() {
                eprintln!("[TX]   ix[{}]: program={}", i, ix.program_id);
            }
        }

        // Send transaction with all queued instructions
        let result = instruction_builder::send_transaction(
            &mut self.svm,
            self.pending_instructions.clone(),
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

        // Clear queue regardless of success/failure
        self.pending_instructions.clear();
        self.pending_signers.clear();

        Ok(Some(outcome))
    }
}

