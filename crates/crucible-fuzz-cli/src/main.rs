use std::env::current_dir;
use std::fs::{self, create_dir_all};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

// ============================================================================
// CLI Definition
// ============================================================================

#[derive(Parser)]
#[command(name = "crucible", about = "Solana smart contract fuzzing framework")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new fuzz harness for a program
    Init {
        /// Program name
        program_name: String,
    },
    /// Run a fuzz test
    Run {
        /// Program name
        program_name: String,
        /// Test name (corresponds to a Cargo feature)
        test_name: String,
        /// Build in release mode
        #[arg(long)]
        release: bool,
        /// Enable LCOV coverage output (single-core only)
        #[arg(long)]
        coverage: bool,
        /// Stop after N seconds
        #[arg(long)]
        timeout: Option<u64>,
        /// Run N parallel fuzzer workers
        #[arg(long, short = 'j')]
        cores: Option<usize>,
        /// Load seed corpus from directory
        #[arg(long)]
        corpus_in: Option<PathBuf>,
        /// Write corpus to directory
        #[arg(long)]
        corpus_out: Option<PathBuf>,
        /// Custom crash output directory
        #[arg(long)]
        crashes_dir: Option<PathBuf>,
        /// Replay a single input file
        #[arg(long)]
        input: Option<PathBuf>,
        /// Validate setup without fuzzing
        #[arg(long)]
        dry_run: bool,
        /// Random seed for reproducible fuzzing
        #[arg(long)]
        seed: Option<u64>,
        /// Stop fuzzing on first crash
        #[arg(long)]
        stop_on_crash: bool,
        /// Maximum number of actions per fuzzer iteration
        #[arg(long, default_value = "10")]
        max_actions: usize,
        /// Disable SVM register tracing for higher throughput (no coverage guidance)
        #[arg(long)]
        no_tracing: bool,
        /// ItyFuzz-style stateful fuzzing: single action per iteration with state pool
        #[arg(long)]
        stateful: bool,
        /// Maximum state depth (action chain length) in stateful mode (default: 15)
        #[arg(long)]
        max_depth: Option<u32>,
        /// Track per-action read/write account sets (cheap)
        #[arg(long)]
        taint: bool,
        /// Track per-action byte-level account diffs (implies --taint)
        #[arg(long)]
        taint_diffs: bool,
        /// Path to debug binary with DWARF symbols (for source-level coverage with --coverage)
        #[arg(long)]
        symbols: Option<PathBuf>,
    },
    /// List available fuzz tests
    List {
        /// Program name (omit to list all)
        program_name: Option<String>,
    },
    /// View/replay crashes
    Show {
        /// Program name (use "." to auto-detect)
        program_name: String,
        /// Crash file to inspect
        crash_file: Option<String>,
        /// Actually replay the crash (requires compiled binary)
        #[arg(long)]
        replay: bool,
        /// Batch-regenerate .meta.json for all crashes (requires --replay)
        #[arg(long)]
        regen: bool,
    },
    /// Minimize a crash to smallest reproducing action sequence
    Tmin {
        /// Program name
        program_name: String,
        /// Test name
        test_name: String,
        /// Crash file to minimize (filename only, not full path)
        crash_file: Option<String>,
        /// Minimize all crashes for this test
        #[arg(long)]
        all: bool,
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Minimize corpus to smallest set preserving coverage
    Cmin {
        /// Program name
        program_name: String,
        /// Test name
        test_name: String,
        /// Input corpus directory (positional)
        corpus_dir: Option<PathBuf>,
        /// Input corpus directory (flag alternative)
        #[arg(long)]
        corpus_in: Option<PathBuf>,
        /// Output directory (default: overwrite input)
        #[arg(long)]
        corpus_out: Option<PathBuf>,
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
}

// ============================================================================
// Crash Metadata Types
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CrashMetadata {
    test_name: String,
    timestamp: String,
    iteration: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    actions: Vec<ActionRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActionRecord {
    name: String,
    params: serde_json::Value,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    taint: Option<ActionTaintSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActionTaintSummary {
    tx_count: usize,
    written_accounts: Vec<String>,
    read_accounts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_changes: Option<Vec<AccountChangeSummary>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AccountChangeSummary {
    pubkey: String,
    kind: AccountChangeKind,
    lamports: (u64, u64),
    changed_ranges: Vec<(usize, usize)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    field_diffs: Option<Vec<FieldDelta>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum AccountChangeKind {
    Created,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FieldDelta {
    field: String,
    old_value: String,
    new_value: String,
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { program_name } => fuzz_init(&program_name),
        Commands::Run {
            program_name,
            test_name,
            release,
            coverage,
            timeout,
            cores,
            corpus_in,
            corpus_out,
            crashes_dir,
            input,
            dry_run,
            seed,
            stop_on_crash,
            max_actions,
            no_tracing,
            stateful,
            max_depth,
            taint,
            taint_diffs,
            symbols,
        } => fuzz_run(
            &program_name,
            &test_name,
            release,
            coverage,
            timeout,
            corpus_in,
            corpus_out,
            crashes_dir,
            input,
            dry_run,
            cores,
            seed,
            stop_on_crash,
            max_actions,
            no_tracing,
            stateful,
            max_depth,
            taint,
            taint_diffs,
            symbols,
        ),
        Commands::List { program_name } => fuzz_list(program_name.as_deref()),
        Commands::Show {
            program_name,
            crash_file,
            replay,
            regen,
        } => fuzz_show(&program_name, crash_file.as_deref(), replay, regen),
        Commands::Tmin {
            program_name,
            test_name,
            crash_file,
            all,
            release,
        } => fuzz_tmin(&program_name, &test_name, crash_file.as_deref(), all, release),
        Commands::Cmin {
            program_name,
            test_name,
            corpus_dir,
            corpus_in,
            corpus_out,
            release,
        } => {
            let input = corpus_in.or(corpus_dir);
            let input = input.as_deref().ok_or_else(|| {
                anyhow::anyhow!("Corpus directory required. Provide as positional arg or --corpus-in")
            })?;
            fuzz_cmin(&program_name, &test_name, input, corpus_out.as_deref(), release)
        }
    }
}

// ============================================================================
// Init Command
// ============================================================================

fn fuzz_init(program_name: &str) -> Result<()> {
    let cwd = current_dir()?;
    let fuzz_dir = cwd.join("fuzz");

    // Create fuzz/ directory and .gitignore
    if !fuzz_dir.exists() {
        create_dir_all(&fuzz_dir)?;
        fs::write(fuzz_dir.join(".gitignore"), "*/target/\n*/crashes/\n.fuzz-cache/\n")
            .context("Failed to create .gitignore")?;
    }

    // Create standalone fuzz package
    let fuzz_program_path = fuzz_dir.join(program_name);
    if fuzz_program_path.exists() {
        bail!("{} already exists", fuzz_program_path.display());
    }

    let src_dir = fuzz_program_path.join("src");
    create_dir_all(&src_dir)?;

    let idls_dir = fuzz_program_path.join("idls");
    create_dir_all(&idls_dir)?;

    fs::write(
        fuzz_program_path.join("Cargo.toml"),
        generate_cargo_toml(program_name),
    )
    .context("Failed to write Cargo.toml")?;

    fs::write(
        fuzz_program_path.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"stable\"\n",
    )
    .context("Failed to write rust-toolchain.toml")?;

    fs::write(src_dir.join("main.rs"), generate_harness(program_name))
        .context("Failed to write harness")?;

    fs::write(idls_dir.join("README.md"), generate_idl_readme(program_name))
        .context("Failed to write IDL README")?;

    println!("\nCreated fuzz harness at: fuzz/{}/", program_name);
    println!("\nNext steps:");
    println!(
        "  1. Copy your IDL to: fuzz/{}/idls/{}.json",
        program_name, program_name
    );
    println!("     (Run `anchor idl convert` if using legacy IDL format)");
    println!(
        "  2. Ensure program binary exists at: target/deploy/{}.so",
        program_name
    );
    println!(
        "  3. Implement action_* methods in: fuzz/{}/src/main.rs",
        program_name
    );
    println!("  4. Run: crucible run {} invariant_test --release", program_name);

    Ok(())
}

fn generate_cargo_toml(program_name: &str) -> String {
    let repo = "https://github.com/asymmetric-research/crucible";
    let branch = "main";

    format!(
        r#"[package]
name = "{program_name}_fuzz"
version = "0.1.0"
edition = "2021"

[workspace]
# Standalone workspace - isolated from parent project to avoid Solana version conflicts

[dependencies]
# Fuzzing framework
crucible-fuzzer = {{ git = "{repo}", branch = "{branch}" }}
crucible-test-context = {{ git = "{repo}", branch = "{branch}" }}
crucible-idl-gen = {{ git = "{repo}", branch = "{branch}" }}

# Anchor (v3-compatible fork with solana-sysvar ~3.1 fix)
anchor-lang = {{ git = "https://github.com/asymmetric-research/anchor-fuzzing", branch = "feature/fuzzing" }}

# Solana v3.x (required for litesvm 0.9.0)
solana-pubkey = "3.0"
solana-keypair = "3.1"
solana-signer = "3.0"
solana-program = "3.0"
solana-message = "3.0"
solana-signature = "3.1"
solana-instruction = "3.1"

# Fuzzing
libafl = {{ version = "0.15.1", features = ["std", "cli", "prelude"] }}
libafl_bolts = {{ version = "0.15.1", features = ["std"] }}
arbitrary = {{ version = "1", features = ["derive"] }}

# Utilities
anyhow = "1.0"
bytemuck = "1.14"
ctor = "0.6"

[features]
invariant_test = []
"#
    )
}

fn generate_harness(program_name: &str) -> String {
    let fixture_name = to_pascal_case(program_name);
    format!(
        r#"use crucible_fuzzer::*;
use anchor_lang::prelude::*;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_pubkey::Pubkey;
use anchor_lang::system_program;
use std::rc::Rc;

// Generate types from IDL (no crate dependency - avoids version conflicts)
crucible_idl_gen::declare_fuzz_program!("idls/{program_name}.json");

use {program_name}::instruction;
use {program_name}::accounts;

#[derive(Clone)]
struct {fixture_name} {{
    ctx: TestContext,
    program_id: Pubkey,
    admin: Rc<Keypair>,
    // TODO: Add your state here (users, accounts, etc.)
}}

#[fuzz_fixture]
impl {fixture_name} {{
    /// Called ONCE to setup initial state (programs + accounts)
    pub fn setup() -> Self {{
        let mut ctx = TestContext::new();
        let program_id = {program_name}::ID;

        // Load program binary (built separately from fuzz harness)
        ctx.add_program(&program_id, "../../target/deploy/{program_name}.so").unwrap();

        // Create admin account
        let admin = Rc::new(Keypair::new());
        ctx.create_account()
            .pubkey(admin.pubkey())
            .lamports(100_000_000_000)
            .owner(system_program::ID)
            .create()
            .unwrap();

        // TODO: Initialize your program state here

        Self {{ ctx, program_id, admin }}
    }}

    /// ACTIONS - Define actions that the fuzzer can call
    pub fn action_noop(&mut self) {{
        // Placeholder - replace with real actions
    }}

    // TODO: Add your actions here
}}

#[invariant_test]
fn invariant_test(fixture: &mut {fixture_name}) {{
    // TODO: Add invariant checks that should hold after every action
}}
"#,
    )
}

fn generate_idl_readme(program_name: &str) -> String {
    format!(
        r#"# IDL Files

Place your program's IDL JSON file here as `{program_name}.json`.

## Generating IDL

If you have the legacy (v0.29) IDL format:
```bash
anchor idl convert target/idl/{program_name}.json -o fuzz/{program_name}/idls/{program_name}.json
```

If you have the new IDL format (v0.30+), copy it directly.
"#
    )
}

fn to_pascal_case(s: &str) -> String {
    s.split(|c: char| c == '_' || c == '-')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect()
}

// ============================================================================
// Run Command
// ============================================================================

fn fuzz_run(
    program_name: &str,
    test_name: &str,
    release: bool,
    coverage: bool,
    timeout: Option<u64>,
    corpus_in: Option<PathBuf>,
    corpus_out: Option<PathBuf>,
    crashes_dir: Option<PathBuf>,
    input: Option<PathBuf>,
    dry_run: bool,
    cores: Option<usize>,
    seed: Option<u64>,
    stop_on_crash: bool,
    max_actions: usize,
    no_tracing: bool,
    stateful: bool,
    max_depth: Option<u32>,
    taint: bool,
    taint_diffs: bool,
    symbols: Option<PathBuf>,
) -> Result<()> {
    let cwd = current_dir()?;
    let fuzz_dir = resolve_fuzz_dir(&cwd, program_name)?;

    let mut args = vec!["run".to_string()];
    if release {
        args.push("--release".to_string());
    }
    args.extend(["--features".to_string(), test_name.to_string()]);

    if coverage {
        args.push("--".to_string());
        args.push("--coverage".to_string());
    }

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&fuzz_dir)
        .env("RUSTUP_TOOLCHAIN", "stable")
        .args(&args);

    if let Some(timeout_secs) = timeout {
        cmd.env("FUZZ_TIMEOUT_SECS", timeout_secs.to_string());
        println!("[FUZZ] Running with {}s timeout", timeout_secs);
    }

    if let Some(ref corpus_in_path) = corpus_in {
        let abs_path = resolve_path(&cwd, corpus_in_path);
        let has_inputs = abs_path.exists()
            && fs::read_dir(&abs_path)
                .map(|mut d| d.any(|e| e.is_ok()))
                .unwrap_or(false);
        if has_inputs {
            cmd.env("FUZZ_CORPUS_IN", abs_path);
            println!("[FUZZ] Loading corpus from: {}", corpus_in_path.display());
        } else if abs_path.exists() {
            println!(
                "[FUZZ] Corpus directory is empty, skipping: {}",
                corpus_in_path.display()
            );
        } else {
            println!(
                "[FUZZ] Corpus directory does not exist, skipping: {}",
                corpus_in_path.display()
            );
        }
    }

    if let Some(ref corpus_out_path) = corpus_out {
        let abs_path = resolve_path(&cwd, corpus_out_path);
        cmd.env("FUZZ_CORPUS_OUT", abs_path);
        println!("[FUZZ] Writing corpus to: {}", corpus_out_path.display());
    }

    let crashes_abs_path = if let Some(ref crashes_path) = crashes_dir {
        resolve_path(&cwd, crashes_path)
    } else {
        fuzz_dir.join("crashes").join(test_name)
    };
    cmd.env("FUZZ_CRASHES_DIR", &crashes_abs_path);
    println!("[FUZZ] Crashes directory: {}", crashes_abs_path.display());

    if let Some(ref input_path) = input {
        let abs_path = resolve_path(&cwd, input_path);
        cmd.env("FUZZ_INPUT_FILE", abs_path);
        // Auto-enable taint diffs on input replay for rich output
        cmd.env("FUZZ_TAINT_DIFFS", "1");
        println!("[FUZZ] Replaying input: {}", input_path.display());
    }

    if dry_run {
        cmd.env("FUZZ_DRY_RUN", "1");
        println!("[FUZZ] Dry-run mode: validating setup");
    }

    if let Some(num_cores) = cores {
        cmd.env("FUZZ_CORES", num_cores.to_string());
        println!("[FUZZ] Multi-core mode: {} parallel workers", num_cores);
    }

    if let Some(seed_val) = seed {
        cmd.env("FUZZ_SEED", seed_val.to_string());
        println!("[FUZZ] Using seed: {}", seed_val);
    }

    if stop_on_crash {
        cmd.env("FUZZ_STOP_ON_CRASH", "1");
        println!("[FUZZ] Stop-on-crash enabled");
    }

    if no_tracing {
        cmd.env("FUZZ_NO_TRACING", "1");
        println!("[FUZZ] Tracing disabled: no coverage guidance, maximum throughput");
    }

    if stateful {
        cmd.env("FUZZ_STATEFUL", "1");
        println!("[FUZZ] Stateful mode: ItyFuzz-style single action per iteration with state pool");
    }

    if let Some(depth) = max_depth {
        cmd.env("FUZZ_MAX_DEPTH", depth.to_string());
        println!("[FUZZ] Max state depth: {}", depth);
    }

    if taint_diffs {
        // --taint-diffs implies --taint (FUZZ_TAINT_DIFFS enables both)
        cmd.env("FUZZ_TAINT_DIFFS", "1");
        println!("[FUZZ] Taint diffs enabled: per-action byte-level account diffs");
    } else if taint {
        cmd.env("FUZZ_TAINT", "1");
        println!("[FUZZ] Taint enabled: per-action read/write account tracking");
    }

    if let Some(ref symbols_path) = symbols {
        let abs_path = resolve_path(&cwd, symbols_path);
        // Canonicalize to resolve symlinks and ".." so DWARF workspace-root detection works
        let canonical = abs_path.canonicalize().unwrap_or(abs_path);
        cmd.env("FUZZ_SYMBOLS", &canonical);
        println!("[FUZZ] Debug symbols: {}", canonical.display());
    }

    cmd.env("FUZZ_MAX_ACTIONS", max_actions.to_string());
    println!("[FUZZ] Max actions per iteration: {}", max_actions);

    if coverage && corpus_in.is_some() && timeout.is_none() && !dry_run && input.is_none() {
        cmd.env("FUZZ_COVERAGE_ONLY", "1");
        println!("[FUZZ] Coverage-only mode: generating coverage from corpus");
    }

    let status = cmd.status().context("Failed to run cargo")?;
    if !status.success() {
        match status.code() {
            Some(code) => bail!("Fuzz command failed with exit code {}", code),
            None => bail!("Fuzz command killed by signal"),
        }
    }

    Ok(())
}

// ============================================================================
// List Command
// ============================================================================

fn fuzz_list(program_name: Option<&str>) -> Result<()> {
    let cwd = current_dir()?;
    let fuzz_root = cwd.join("fuzz");

    match program_name {
        Some(name) => {
            let fuzz_dir = fuzz_root.join(name);
            if !fuzz_dir.exists() {
                bail!(
                    "Fuzz directory for {} does not exist. Run `crucible init {}` first.",
                    name,
                    name
                );
            }
            list_program_tests(&fuzz_dir, name)?;
        }
        None => {
            if !fuzz_root.exists() {
                println!("No fuzz/ directory found. Run `crucible init <program>` to create one.");
                return Ok(());
            }

            let mut found = false;
            for entry in fs::read_dir(&fuzz_root)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() && path.join("Cargo.toml").exists() {
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");
                    found = true;
                    list_program_tests(&path, name)?;
                }
            }

            if !found {
                println!("No fuzz harnesses found in fuzz/ directory.");
            }
        }
    }

    Ok(())
}

fn list_program_tests(fuzz_dir: &Path, program_name: &str) -> Result<()> {
    let cargo_toml_path = fuzz_dir.join("Cargo.toml");
    if !cargo_toml_path.exists() {
        bail!("Cargo.toml not found at {}", cargo_toml_path.display());
    }

    let content = fs::read_to_string(&cargo_toml_path).context("Failed to read Cargo.toml")?;

    let mut in_features = false;
    let mut tests = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[features]" {
            in_features = true;
            continue;
        }
        if in_features && trimmed.starts_with('[') && !trimmed.starts_with("[features") {
            break;
        }
        if in_features && !trimmed.is_empty() && !trimmed.starts_with('#') {
            if let Some(eq_pos) = trimmed.find('=') {
                let feature_name = trimmed[..eq_pos].trim();
                if !feature_name.is_empty()
                    && feature_name != "default"
                    && feature_name != "fuzz_single"
                {
                    tests.push(feature_name.to_string());
                }
            }
        }
    }

    println!("\n=== {} ===", program_name);
    if tests.is_empty() {
        println!("  No fuzz tests found (add features to Cargo.toml)");
    } else {
        for test in &tests {
            println!("  - {}", test);
        }
        println!();
        println!(
            "Run with: crucible run {} <test_name> --release",
            program_name
        );
    }

    Ok(())
}

// ============================================================================
// Show Command
// ============================================================================

fn fuzz_show(program_name: &str, crash_file: Option<&str>, replay: bool, regen: bool) -> Result<()> {
    if regen && !replay {
        bail!("--regen requires --replay. Usage: crucible show {} --replay --regen", program_name);
    }

    let cwd = current_dir()?;

    let (fuzz_dir, display_name) = if program_name == "." {
        if cwd.join("Cargo.toml").exists() && cwd.join("src").exists() {
            let name = cwd
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            (cwd.clone(), name)
        } else {
            bail!("Cannot auto-detect fuzz harness. Run from within fuzz harness directory or specify program name.");
        }
    } else {
        let fuzz_dir = resolve_fuzz_dir(&cwd, program_name)?;
        let display_name = fuzz_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(program_name)
            .to_string();
        (fuzz_dir, display_name)
    };

    match crash_file {
        None if replay && regen => regen_crashes(&fuzz_dir, &display_name),
        None => list_crashes(&fuzz_dir, &display_name),
        Some(crash_name) if !replay => show_crash_metadata(&fuzz_dir, &display_name, crash_name),
        Some(crash_name) => replay_crash(&fuzz_dir, &display_name, crash_name),
    }
}

fn list_crashes(fuzz_dir: &Path, program_name: &str) -> Result<()> {
    let crashes_dir = fuzz_dir.join("crashes");
    if !crashes_dir.exists() {
        println!("No crashes directory found at: {}", crashes_dir.display());
        println!("Run the fuzzer first to generate crashes.");
        return Ok(());
    }

    // Collect crashes with metadata (.meta.json) and raw crash files (LibAFL-only)
    let mut crashes_with_meta: Vec<(String, String, CrashMetadata)> = Vec::new();
    let mut raw_crashes: Vec<(String, String, u64)> = Vec::new(); // (crash_id, test_name, file_size)

    for entry in fs::read_dir(&crashes_dir)? {
        let entry = entry?;
        let test_dir = entry.path();
        if !test_dir.is_dir() {
            continue;
        }

        let test_name = test_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        // First pass: collect .meta.json crash IDs
        let mut meta_ids = std::collections::HashSet::new();
        for file_entry in fs::read_dir(&test_dir)? {
            let file_entry = file_entry?;
            let file_path = file_entry.path();
            let filename = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if filename.ends_with(".meta.json") {
                if let Ok(content) = fs::read_to_string(&file_path) {
                    if let Ok(meta) = serde_json::from_str::<CrashMetadata>(&content) {
                        let crash_id = filename
                            .strip_suffix(".meta.json")
                            .unwrap_or(filename)
                            .to_string();
                        meta_ids.insert(crash_id.clone());
                        crashes_with_meta.push((crash_id, test_name.clone(), meta));
                    }
                }
            }
        }

        // Second pass: collect raw crash files without .meta.json
        for file_entry in fs::read_dir(&test_dir)? {
            let file_entry = file_entry?;
            let file_path = file_entry.path();
            let filename = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if filename.starts_with('.')
                || filename.ends_with(".metadata")
                || filename.ends_with(".meta.json")
            {
                continue;
            }
            if !file_path.is_file() {
                continue;
            }
            // Skip if we already have metadata for this crash
            if meta_ids.contains(&filename) {
                continue;
            }
            let file_size = file_path.metadata().map(|m| m.len()).unwrap_or(0);
            raw_crashes.push((filename, test_name.clone(), file_size));
        }
    }

    // Deduplicate: remove raw crashes whose content matches a crash with metadata
    {
        use std::collections::HashSet;
        use std::hash::{Hash, Hasher};

        let mut meta_content_hashes: HashSet<u64> = HashSet::new();
        for (crash_id, test_name, _meta) in &crashes_with_meta {
            let crash_path = crashes_dir.join(test_name).join(crash_id);
            if let Ok(bytes) = fs::read(&crash_path) {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                bytes.hash(&mut hasher);
                meta_content_hashes.insert(hasher.finish());
            }
        }

        raw_crashes.retain(|(filename, test_name, _size)| {
            let crash_path = crashes_dir.join(test_name).join(filename);
            if let Ok(bytes) = fs::read(&crash_path) {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                bytes.hash(&mut hasher);
                !meta_content_hashes.contains(&hasher.finish())
            } else {
                true // keep if we can't read it
            }
        });
    }

    if crashes_with_meta.is_empty() && raw_crashes.is_empty() {
        println!(
            "No crashes found for {} in: {}",
            program_name,
            crashes_dir.display()
        );
        return Ok(());
    }

    let total = crashes_with_meta.len() + raw_crashes.len();
    println!(
        "\n=== Crashes for {} ({} total) ===\n",
        program_name, total
    );

    // Show crashes with metadata first
    if !crashes_with_meta.is_empty() {
        crashes_with_meta.sort_by(|a, b| b.2.timestamp.cmp(&a.2.timestamp));
        for (i, (crash_id, test_name, meta)) in crashes_with_meta.iter().enumerate() {
            println!(
                "  {}. {} ({}, test: {}, {} actions)",
                i + 1,
                crash_id,
                meta.timestamp,
                test_name,
                meta.actions.len()
            );
        }
    }

    // Show raw crashes (no metadata)
    if !raw_crashes.is_empty() {
        raw_crashes.sort_by(|a, b| a.0.cmp(&b.0));
        let offset = crashes_with_meta.len();
        for (i, (crash_id, test_name, size)) in raw_crashes.iter().enumerate() {
            println!(
                "  {}. {} (test: {}, {} bytes, no metadata)",
                offset + i + 1,
                crash_id,
                test_name,
                size
            );
        }
    }

    println!();
    println!(
        "To view a crash: crucible show {} <crash_id>",
        program_name
    );
    println!(
        "To replay a crash: crucible show {} <crash_id> --replay",
        program_name
    );

    Ok(())
}

fn show_crash_metadata(fuzz_dir: &Path, program_name: &str, crash_name: &str) -> Result<()> {
    let crashes_dir = fuzz_dir.join("crashes");

    // Search for .meta.json and/or raw crash file
    let mut meta_path = None;
    let mut crash_binary_path = None;
    if let Ok(entries) = fs::read_dir(&crashes_dir) {
        for entry in entries.flatten() {
            let test_dir = entry.path();
            if !test_dir.is_dir() {
                continue;
            }
            let meta_candidate = test_dir.join(format!("{}.meta.json", crash_name));
            if meta_candidate.exists() {
                meta_path = Some(meta_candidate);
            }
            let binary_candidate = test_dir.join(crash_name);
            if binary_candidate.exists() && binary_candidate.is_file() {
                crash_binary_path = Some(binary_candidate);
            }
        }
    }

    // If we have metadata, show the rich view
    if let Some(meta_path) = meta_path {
        let content = fs::read_to_string(&meta_path).context("Failed to read crash metadata")?;
        let meta: CrashMetadata =
            serde_json::from_str(&content).context("Failed to parse crash metadata")?;

        println!("\n=== Crash: {} ===", crash_name);
        println!("Test: {}", meta.test_name);
        println!("Timestamp: {}", meta.timestamp);
        println!("Iteration: {}", meta.iteration);
        if let Some(seed) = meta.seed {
            println!("Seed: {}", seed);
        }

        println!("\n=== Action Sequence ({} actions) ===", meta.actions.len());
        for (i, action) in meta.actions.iter().enumerate() {
            let params_str = if let serde_json::Value::Object(map) = &action.params {
                map.iter()
                    .map(|(k, v)| format!("{}={}", k, format_json_compact(v)))
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                String::new()
            };

            let status = if action.success {
                "OK".to_string()
            } else if let Some(code) = action.error_code {
                format!("FAIL({})", code)
            } else {
                "FAIL".to_string()
            };

            if params_str.is_empty() {
                println!("  {}. {} -> {}", i + 1, action.name, status);
            } else {
                println!("  {}. {}({}) -> {}", i + 1, action.name, params_str, status);
            }

            // Print taint info if available
            if let Some(ref taint) = action.taint {
                if let Some(ref changes) = taint.account_changes {
                    for change in changes {
                        let short_key = &change.pubkey[..8.min(change.pubkey.len())];
                        let mut parts = Vec::new();

                        // Lamports change
                        let (pre_l, post_l) = change.lamports;
                        if pre_l != post_l {
                            let delta = post_l as i128 - pre_l as i128;
                            let sign = if delta >= 0 { "+" } else { "" };
                            parts.push(format!("{}{}lamports", sign, delta));
                        }

                        // Field diffs take priority over byte ranges
                        if let Some(ref field_diffs) = change.field_diffs {
                            for fd in field_diffs {
                                parts.push(format!(
                                    "{}: {} -> {}",
                                    fd.field, fd.old_value, fd.new_value
                                ));
                            }
                        } else if !change.changed_ranges.is_empty() {
                            let ranges_str: Vec<String> = change
                                .changed_ranges
                                .iter()
                                .map(|(off, len)| format!("data[{}..{}]", off, off + len))
                                .collect();
                            parts.push(ranges_str.join(", "));
                        }

                        let kind_str = match change.kind {
                            AccountChangeKind::Created => "created",
                            AccountChangeKind::Modified => "modified",
                            AccountChangeKind::Deleted => "deleted",
                        };

                        if parts.is_empty() {
                            println!("     {}...({}) {}", short_key, kind_str, change.pubkey);
                        } else {
                            println!("     {}...({})", short_key, parts.join(", "));
                        }
                    }
                } else if !taint.written_accounts.is_empty() {
                    let short_keys: Vec<String> = taint
                        .written_accounts
                        .iter()
                        .map(|k| format!("{}...", &k[..8.min(k.len())]))
                        .collect();
                    println!("     wrote: {}", short_keys.join(", "));
                }
            }
        }
        println!("================================\n");
        println!(
            "To replay this crash: crucible show {} {} --replay",
            program_name, crash_name
        );

        return Ok(());
    }

    // No metadata — show raw crash info if binary exists
    if let Some(binary_path) = crash_binary_path {
        let bytes = fs::read(&binary_path).context("Failed to read crash file")?;
        println!("\n=== Crash: {} (no metadata) ===", crash_name);
        println!("Size: {} bytes", bytes.len());
        println!("Path: {}", binary_path.display());

        // Show hex preview
        let preview_len = bytes.len().min(64);
        let hex: String = bytes[..preview_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        println!("\nHex preview: {}{}", hex, if bytes.len() > 64 { " ..." } else { "" });

        println!("\nNote: No .meta.json found. This crash was likely from a panic,");
        println!("not an invariant violation. Use --replay to reproduce it.");
        println!(
            "\nTo replay: crucible show {} {} --replay",
            program_name, crash_name
        );

        return Ok(());
    }

    bail!(
        "Crash not found: {}\n\
         Looking in: {}/crashes/*/\n\
         Use `crucible show {}` to list available crashes.",
        crash_name,
        fuzz_dir.display(),
        program_name
    )
}

fn format_json_compact(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => format!("\"{}\"", s),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_json_compact).collect();
            format!("[{}]", items.join(", "))
        }
        serde_json::Value::Object(obj) => {
            let items: Vec<String> = obj
                .iter()
                .map(|(k, v)| format!("{}: {}", k, format_json_compact(v)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
    }
}

fn replay_crash(fuzz_dir: &Path, program_name: &str, crash_name: &str) -> Result<()> {
    let crashes_dir = fuzz_dir.join("crashes");
    let mut crash_path = None;
    let mut test_name: Option<String> = None;
    let mut found_metadata_only = false;
    let mut available_inputs: Vec<String> = Vec::new();

    if let Ok(entries) = fs::read_dir(&crashes_dir) {
        for entry in entries.flatten() {
            let test_dir = entry.path();
            if !test_dir.is_dir() {
                continue;
            }

            let dir_name = test_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();

            let candidate = test_dir.join(crash_name);
            if candidate.exists() && candidate.is_file() {
                crash_path = Some(candidate);
                test_name = Some(dir_name);
                break;
            }

            for ext in &["", ".bin"] {
                let candidate = test_dir.join(format!("{}{}", crash_name, ext));
                if candidate.exists() && candidate.is_file() {
                    crash_path = Some(candidate);
                    test_name = Some(dir_name.clone());
                    break;
                }
            }
            if crash_path.is_some() {
                break;
            }

            let meta_path = test_dir.join(format!("{}.meta.json", crash_name));
            if meta_path.exists() && crash_path.is_none() {
                found_metadata_only = true;
                if let Ok(dir_entries) = fs::read_dir(&test_dir) {
                    for dir_entry in dir_entries.flatten() {
                        let path = dir_entry.path();
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if !name.starts_with('.')
                                && !name.ends_with(".meta.json")
                                && !name.ends_with(".metadata")
                                && path.is_file()
                            {
                                available_inputs.push(name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    let crash_path = crash_path.ok_or_else(|| {
        if found_metadata_only {
            let mut msg = format!(
                "Crash metadata found for '{}', but input bytes file is missing.\n\
                 This crash was created before input bytes were saved alongside metadata.\n\n",
                crash_name
            );
            if !available_inputs.is_empty() {
                msg.push_str("Available crash input files that can be replayed:\n");
                for (i, input) in available_inputs.iter().take(5).enumerate() {
                    msg.push_str(&format!("  {}. {}\n", i + 1, input));
                }
                if available_inputs.len() > 5 {
                    msg.push_str(&format!("  ... and {} more\n", available_inputs.len() - 5));
                }
                msg.push_str(&format!(
                    "\nTry: crucible show {} <input_name> --replay",
                    program_name
                ));
            }
            anyhow::anyhow!(msg)
        } else {
            anyhow::anyhow!(
                "Crash file not found: {}\n\
                 Looking in: {}/crashes/*/\n\
                 Use `crucible show {}` to list available crashes.",
                crash_name,
                fuzz_dir.display(),
                program_name
            )
        }
    })?;

    // Rebuild binary with the correct test feature to ensure action enum matches.
    // Without this, the binary may have been last compiled for a different test,
    // causing action variant indices to be misinterpreted during deserialization.
    let test_feature = test_name.as_deref().unwrap_or("");
    if !test_feature.is_empty() {
        println!("[REPLAY] Building with --features {} ...", test_feature);
        // Try release first, fall back to debug
        let build_status = Command::new("cargo")
            .current_dir(fuzz_dir)
            .env("RUSTUP_TOOLCHAIN", "stable")
            .args(["build", "--release", "--features", test_feature])
            .status()
            .context("Failed to build fuzz harness for replay")?;

        if !build_status.success() {
            // Try debug build
            let build_status = Command::new("cargo")
                .current_dir(fuzz_dir)
                .env("RUSTUP_TOOLCHAIN", "stable")
                .args(["build", "--features", test_feature])
                .status()
                .context("Failed to build fuzz harness for replay")?;

            if !build_status.success() {
                bail!("Failed to build fuzz harness with --features {}", test_feature);
            }
        }
    }

    let binary_path = find_fuzz_binary(fuzz_dir, program_name, "release")
        .or_else(|_| find_fuzz_binary(fuzz_dir, program_name, "debug"))?;

    println!("Replaying crash: {}", crash_path.display());
    println!("Using binary: {}\n", binary_path.display());

    let status = Command::new(&binary_path)
        .current_dir(fuzz_dir)
        .env("FUZZ_INPUT_FILE", &crash_path)
        // Auto-enable full taint diffs on replay for rich crash output
        .env("FUZZ_TAINT_DIFFS", "1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("Failed to run replay")?;

    if !status.success() {
        if status.code() == Some(1) {
            println!("\nCrash successfully reproduced!");
        } else {
            bail!("Replay failed with exit code: {:?}", status.code());
        }
    } else {
        println!("\nReplay completed without crash.");
        println!(
            "Note: If you expected a crash, the input may be from a different harness version."
        );
    }

    Ok(())
}

// ============================================================================
// Tmin Command
// ============================================================================

fn fuzz_tmin(
    program_name: &str,
    test_name: &str,
    crash_file: Option<&str>,
    all: bool,
    release: bool,
) -> Result<()> {
    let cwd = current_dir()?;
    let fuzz_dir = resolve_fuzz_dir(&cwd, program_name)?;

    // Auto-detect: if test_name looks like a crash ID and no crash_file was given,
    // search all test directories for it. Allows: crucible tmin stake crash_abc123
    let (test_name, crash_file) = if crash_file.is_none() && !all && test_name.starts_with("crash_") {
        let crashes_root = fuzz_dir.join("crashes");
        let mut found_test = None;
        if crashes_root.is_dir() {
            if let Ok(entries) = fs::read_dir(&crashes_root) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        if entry.path().join(test_name).exists() {
                            found_test = Some(entry.file_name().to_string_lossy().to_string());
                            break;
                        }
                    }
                }
            }
        }
        match found_test {
            Some(t) => (t, Some(test_name.to_string())),
            None => bail!(
                "Could not find crash '{}' in any test directory under: {}\n\
                 Usage: crucible tmin {} <test_name> {} --release",
                test_name, crashes_root.display(), program_name, test_name
            ),
        }
    } else {
        (test_name.to_string(), crash_file.map(|s| s.to_string()))
    };
    let test_name = &test_name;
    let crash_file = crash_file.as_deref();

    let crashes_dir = fuzz_dir.join("crashes").join(test_name);

    if !crashes_dir.exists() {
        bail!(
            "No crashes directory found at: {}\nRun the fuzzer first to generate crashes.",
            crashes_dir.display()
        );
    }

    // Collect crash files to minimize
    let crash_files: Vec<(String, PathBuf)> = if all {
        // Find all crash binary files (those with a corresponding .meta.json)
        let mut files = Vec::new();
        for entry in fs::read_dir(&crashes_dir)? {
            let entry = entry?;
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".meta.json") {
                    let crash_id = name.strip_suffix(".meta.json").unwrap().to_string();
                    let binary_path = crashes_dir.join(&crash_id);
                    if binary_path.exists() && binary_path.is_file() {
                        files.push((crash_id, binary_path));
                    }
                }
            }
        }
        if files.is_empty() {
            bail!("No crash files found in: {}", crashes_dir.display());
        }
        files.sort_by(|a, b| a.0.cmp(&b.0));
        println!("[TMIN] Found {} crash(es) to minimize", files.len());
        files
    } else {
        let crash_name = crash_file.ok_or_else(|| {
            anyhow::anyhow!(
                "Provide a crash file or use --all to minimize all crashes.\n\
                 Usage: crucible tmin {} {} <crash_id> --release\n\
                 Usage: crucible tmin {} {} --all --release",
                program_name, test_name, program_name, test_name
            )
        })?;
        let binary_path = crashes_dir.join(crash_name);
        if !binary_path.exists() {
            bail!(
                "Crash file not found: {}\nLooking in: {}\nUse `crucible show {}` to list available crashes.",
                crash_name,
                crashes_dir.display(),
                program_name
            );
        }
        vec![(crash_name.to_string(), binary_path)]
    };

    // Build the binary
    let mut build_args = vec!["build".to_string()];
    if release {
        build_args.push("--release".to_string());
    }
    build_args.extend(["--features".to_string(), test_name.to_string()]);

    println!(
        "[TMIN] Building {} harness...",
        if release { "release" } else { "debug" }
    );

    let build_status = Command::new("cargo")
        .current_dir(&fuzz_dir)
        .env("RUSTUP_TOOLCHAIN", "stable")
        .args(&build_args)
        .status()
        .context("Failed to build fuzz harness")?;

    if !build_status.success() {
        bail!("Build failed");
    }

    let profile = if release { "release" } else { "debug" };
    let binary_path = find_fuzz_binary(&fuzz_dir, program_name, profile)?;

    // Minimize crash(es)
    if all {
        // --all mode: single process invocation, binary iterates all crashes internally
        // This avoids re-running setup() for each crash (major perf win)
        println!("[TMIN] Minimizing all {} crashes in a single process...", crash_files.len());
        let status = Command::new(&binary_path)
            .current_dir(&fuzz_dir)
            .env("FUZZ_TMIN_ALL_DIR", &crashes_dir)
            .env("FUZZ_CRASHES_DIR", &crashes_dir)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .context("Failed to run crash minimization")?;

        if !status.success() {
            bail!("Crash minimization failed (exit code: {:?})", status.code());
        }
    } else {
        // Single crash mode
        let (crash_id, crash_path) = &crash_files[0];
        println!("\n[TMIN] Minimizing: {}", crash_id);

        let status = Command::new(&binary_path)
            .current_dir(&fuzz_dir)
            .env("FUZZ_TMIN_FILE", crash_path)
            .env("FUZZ_TMIN_CRASH_ID", crash_id)
            .env("FUZZ_CRASHES_DIR", &crashes_dir)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .context("Failed to run crash minimization")?;

        if !status.success() {
            eprintln!(
                "[TMIN] Warning: minimization failed for {} (exit code: {:?})",
                crash_id,
                status.code()
            );
        }
    }

    Ok(())
}

fn regen_crashes(fuzz_dir: &Path, program_name: &str) -> Result<()> {
    let crashes_dir = fuzz_dir.join("crashes");
    if !crashes_dir.exists() {
        bail!(
            "No crashes directory found at: {}\nRun the fuzzer first to generate crashes.",
            crashes_dir.display()
        );
    }

    // Find the binary (try release then debug)
    let binary_path = find_fuzz_binary(fuzz_dir, program_name, "release")
        .or_else(|_| find_fuzz_binary(fuzz_dir, program_name, "debug"))?;

    // Iterate all test subdirectories in crashes/
    let mut total_ok = 0usize;
    let mut total_fail = 0usize;
    let mut total_count = 0usize;

    let mut test_dirs: Vec<_> = fs::read_dir(&crashes_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    test_dirs.sort_by_key(|e| e.file_name());

    for test_entry in &test_dirs {
        let test_dir = test_entry.path();
        let test_name = test_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Collect crash binary files (skip metadata/hidden)
        let mut crash_files: Vec<(String, PathBuf)> = Vec::new();
        for entry in fs::read_dir(&test_dir)? {
            let entry = entry?;
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.')
                    || name.ends_with(".metadata")
                    || name.ends_with(".meta.json")
                {
                    continue;
                }
                if path.is_file() {
                    crash_files.push((name.to_string(), path));
                }
            }
        }

        if crash_files.is_empty() {
            continue;
        }

        crash_files.sort_by(|a, b| a.0.cmp(&b.0));
        println!(
            "\n[REGEN] {} — {} crash(es)",
            test_name,
            crash_files.len()
        );

        for (idx, (crash_id, crash_path)) in crash_files.iter().enumerate() {
            total_count += 1;
            print!(
                "[REGEN] {}/{} {}... ",
                idx + 1,
                crash_files.len(),
                crash_id
            );

            let status = Command::new(&binary_path)
                .current_dir(fuzz_dir)
                .env("FUZZ_INPUT_FILE", crash_path)
                .env("FUZZ_TAINT_DIFFS", "1")
                .env("FUZZ_CRASHES_DIR", &test_dir)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            match status {
                Ok(s) => {
                    // Exit code 1 = crash reproduced (expected), 0 = no crash (still OK, metadata updated)
                    if s.success() || s.code() == Some(1) {
                        println!("OK");
                        total_ok += 1;
                    } else {
                        println!("FAIL (exit {})", s.code().unwrap_or(-1));
                        total_fail += 1;
                    }
                }
                Err(e) => {
                    println!("FAIL ({})", e);
                    total_fail += 1;
                }
            }
        }
    }

    if total_count == 0 {
        println!("No crash files found in: {}", crashes_dir.display());
    } else {
        println!(
            "\n[REGEN] Done. {} OK, {} failed out of {} total",
            total_ok, total_fail, total_count
        );
    }

    Ok(())
}

// ============================================================================
// Cmin Command
// ============================================================================

fn fuzz_cmin(
    program_name: &str,
    test_name: &str,
    corpus_in: &Path,
    corpus_out: Option<&Path>,
    release: bool,
) -> Result<()> {
    let cwd = current_dir()?;
    let fuzz_dir = resolve_fuzz_dir(&cwd, program_name)?;

    let corpus_in_abs = resolve_path(&cwd, corpus_in);
    if !corpus_in_abs.exists() {
        bail!(
            "Corpus directory does not exist: {}",
            corpus_in_abs.display()
        );
    }

    let input_count = fs::read_dir(&corpus_in_abs)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            if !path.is_file() {
                return false;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            !name.starts_with('.')
                && !name.ends_with(".metadata")
                && !name.ends_with(".meta.json")
        })
        .count();

    if input_count == 0 {
        bail!("No corpus inputs found in: {}", corpus_in_abs.display());
    }

    println!(
        "[CMIN] Minimizing corpus: {} ({} inputs)",
        corpus_in_abs.display(),
        input_count
    );

    let corpus_out_abs = corpus_out
        .map(|p| resolve_path(&cwd, p))
        .unwrap_or_else(|| corpus_in_abs.clone());

    if corpus_out_abs != corpus_in_abs {
        fs::create_dir_all(&corpus_out_abs)?;
        println!("[CMIN] Output directory: {}", corpus_out_abs.display());
    }

    let mut build_args = vec!["build".to_string()];
    if release {
        build_args.push("--release".to_string());
    }
    build_args.extend(["--features".to_string(), test_name.to_string()]);

    println!(
        "[CMIN] Building {} harness...",
        if release { "release" } else { "debug" }
    );

    let build_status = Command::new("cargo")
        .current_dir(&fuzz_dir)
        .env("RUSTUP_TOOLCHAIN", "stable")
        .args(&build_args)
        .status()
        .context("Failed to build fuzz harness")?;

    if !build_status.success() {
        bail!("Build failed");
    }

    let profile = if release { "release" } else { "debug" };
    let binary_path = find_fuzz_binary(&fuzz_dir, program_name, profile)?;

    println!("[CMIN] Running corpus minimization...");

    let status = Command::new(&binary_path)
        .current_dir(&fuzz_dir)
        .env("FUZZ_CMIN", "1")
        .env("FUZZ_CORPUS_IN", &corpus_in_abs)
        .env("FUZZ_CORPUS_OUT", &corpus_out_abs)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("Failed to run corpus minimization")?;

    if !status.success() {
        bail!(
            "Corpus minimization failed with exit code: {:?}",
            status.code()
        );
    }

    Ok(())
}

// ============================================================================
// Utilities
// ============================================================================

/// Resolve the fuzz directory for a program name.
/// Supports running from project root (fuzz/<program>/) or from within a fuzz directory.
/// Also tries hyphen/underscore conversion and auto-detects if only one harness exists.
fn resolve_fuzz_dir(cwd: &Path, program_name: &str) -> Result<PathBuf> {
    // Direct match
    let fuzz_dir = cwd.join("fuzz").join(program_name);
    if fuzz_dir.exists() {
        return Ok(fuzz_dir);
    }

    // Try hyphen <-> underscore conversion
    let alt_name = if program_name.contains('-') {
        program_name.replace('-', "_")
    } else {
        program_name.replace('_', "-")
    };
    let alt_dir = cwd.join("fuzz").join(&alt_name);
    if alt_dir.exists() {
        return Ok(alt_dir);
    }

    // If fuzz/ exists and has exactly one harness, use it
    let fuzz_root = cwd.join("fuzz");
    if fuzz_root.exists() {
        if let Ok(entries) = fs::read_dir(&fuzz_root) {
            let harnesses: Vec<_> = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir() && e.path().join("Cargo.toml").exists())
                .collect();
            if harnesses.len() == 1 {
                return Ok(harnesses[0].path());
            }
        }
    }

    // Maybe we're already in the fuzz dir
    if cwd.join("Cargo.toml").exists() && cwd.join("src").exists() {
        return Ok(cwd.to_path_buf());
    }

    bail!(
        "Fuzz directory for {} does not exist. Run `crucible init {}` first.",
        program_name,
        program_name
    );
}

/// Convert a potentially relative path to absolute, relative to cwd.
fn resolve_path(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

/// Find the fuzz binary by querying cargo metadata.
fn find_fuzz_binary(fuzz_dir: &Path, program_name: &str, profile: &str) -> Result<PathBuf> {
    let output = Command::new("cargo")
        .current_dir(fuzz_dir)
        .args(["metadata", "--format-version=1", "--no-deps"])
        .output()
        .context("Failed to run cargo metadata")?;

    if output.status.success() {
        if let Ok(metadata) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
            let target_dir = metadata["target_directory"].as_str().unwrap_or("");
            if !target_dir.is_empty() {
                if let Some(packages) = metadata["packages"].as_array() {
                    for package in packages {
                        let pkg_name = package["name"].as_str().unwrap_or("");
                        if pkg_name.contains(program_name)
                            || pkg_name.contains(&program_name.replace('-', "_"))
                        {
                            // Check explicit [[bin]] targets first - the binary name
                            // may differ from the package name
                            if let Some(targets) = package["targets"].as_array() {
                                for target in targets {
                                    let kinds = target["kind"].as_array();
                                    let is_bin = kinds.map_or(false, |k| {
                                        k.iter().any(|v| v.as_str() == Some("bin"))
                                    });
                                    if is_bin {
                                        if let Some(bin_name) = target["name"].as_str() {
                                            let binary = PathBuf::from(target_dir)
                                                .join(profile)
                                                .join(bin_name);
                                            if binary.exists() {
                                                return Ok(binary);
                                            }
                                        }
                                    }
                                }
                            }

                            // Fall back to package name as binary name
                            let binary =
                                PathBuf::from(target_dir).join(profile).join(pkg_name);
                            if binary.exists() {
                                return Ok(binary);
                            }
                        }
                    }
                }

                let standard_name = format!("{}_fuzz", program_name);
                let standard_path =
                    PathBuf::from(target_dir).join(profile).join(&standard_name);
                if standard_path.exists() {
                    return Ok(standard_path);
                }
            }
        }
    }

    let package_name = format!("{}_fuzz", program_name);
    let fallback = fuzz_dir.join("target").join(profile).join(&package_name);
    if fallback.exists() {
        return Ok(fallback);
    }

    bail!(
        "Fuzz binary not found. Searched for package matching '{}' in target directory.\n\
         Build it first with: crucible run {} <test_name> --release",
        program_name,
        program_name
    )
}
