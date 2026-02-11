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
        ),
        Commands::List { program_name } => fuzz_list(program_name.as_deref()),
        Commands::Show {
            program_name,
            crash_file,
            replay,
        } => fuzz_show(&program_name, crash_file.as_deref(), replay),
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
        fs::write(fuzz_dir.join(".gitignore"), "*/target/\n*/crashes/\n")
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

[features]
fuzz_single = []
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

    if coverage && corpus_in.is_some() && timeout.is_none() && !dry_run && input.is_none() {
        cmd.env("FUZZ_COVERAGE_ONLY", "1");
        println!("[FUZZ] Coverage-only mode: generating coverage from corpus");
    }

    let status = cmd.status().context("Failed to run cargo")?;
    if !status.success() {
        bail!("Fuzz command failed");
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

fn fuzz_show(program_name: &str, crash_file: Option<&str>, replay: bool) -> Result<()> {
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
        let fuzz_path = cwd.join("fuzz").join(program_name);
        if fuzz_path.exists() {
            (fuzz_path, program_name.to_string())
        } else if cwd.join("Cargo.toml").exists() && cwd.join("src").exists() {
            (cwd.clone(), program_name.to_string())
        } else {
            bail!(
                "Fuzz directory not found. Either:\n  \
                 - Run from project root (where fuzz/{0}/ exists)\n  \
                 - Run from inside the fuzz harness directory\n  \
                 - Use '.' as program name to auto-detect",
                program_name
            );
        }
    };

    match crash_file {
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

    let mut crashes = Vec::new();
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

        for file_entry in fs::read_dir(&test_dir)? {
            let file_entry = file_entry?;
            let file_path = file_entry.path();
            let filename = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if filename.starts_with('.') || filename.ends_with(".metadata") {
                continue;
            }
            if filename.ends_with(".meta.json") {
                if let Ok(content) = fs::read_to_string(&file_path) {
                    if let Ok(meta) = serde_json::from_str::<CrashMetadata>(&content) {
                        let crash_id = filename
                            .strip_suffix(".meta.json")
                            .unwrap_or(filename)
                            .to_string();
                        crashes.push((crash_id, test_name.clone(), meta));
                    }
                }
            }
        }
    }

    if crashes.is_empty() {
        println!(
            "No crashes found for {} in: {}",
            program_name,
            crashes_dir.display()
        );
        return Ok(());
    }

    crashes.sort_by(|a, b| b.2.timestamp.cmp(&a.2.timestamp));

    println!(
        "\n=== Crashes for {} ({} total) ===\n",
        program_name,
        crashes.len()
    );
    for (i, (crash_id, test_name, meta)) in crashes.iter().enumerate() {
        println!(
            "  {}. {} ({}, test: {}, {} actions)",
            i + 1,
            crash_id,
            meta.timestamp,
            test_name,
            meta.actions.len()
        );
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

    let mut meta_path = None;
    if let Ok(entries) = fs::read_dir(&crashes_dir) {
        for entry in entries.flatten() {
            let test_dir = entry.path();
            if !test_dir.is_dir() {
                continue;
            }
            let candidate = test_dir.join(format!("{}.meta.json", crash_name));
            if candidate.exists() {
                meta_path = Some(candidate);
                break;
            }
        }
    }

    let meta_path = meta_path.ok_or_else(|| {
        anyhow::anyhow!(
            "Crash metadata not found: {}.meta.json\n\
             Looking in: {}/crashes/*/\n\
             Use `crucible show {}` to list available crashes.",
            crash_name,
            fuzz_dir.display(),
            program_name
        )
    })?;

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

        let status = if action.success { "OK" } else { "FAIL" };
        if params_str.is_empty() {
            println!("  {}. {} -> {}", i + 1, action.name, status);
        } else {
            println!("  {}. {}({}) -> {}", i + 1, action.name, params_str, status);
        }
    }
    println!("================================\n");
    println!(
        "To replay this crash: crucible show {} {} --replay",
        program_name, crash_name
    );

    Ok(())
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
    let mut found_metadata_only = false;
    let mut available_inputs: Vec<String> = Vec::new();

    if let Ok(entries) = fs::read_dir(&crashes_dir) {
        for entry in entries.flatten() {
            let test_dir = entry.path();
            if !test_dir.is_dir() {
                continue;
            }

            let candidate = test_dir.join(crash_name);
            if candidate.exists() && candidate.is_file() {
                crash_path = Some(candidate);
                break;
            }

            for ext in &["", ".bin"] {
                let candidate = test_dir.join(format!("{}{}", crash_name, ext));
                if candidate.exists() && candidate.is_file() {
                    crash_path = Some(candidate);
                    break;
                }
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

    let binary_path = find_fuzz_binary(fuzz_dir, program_name, "release")
        .or_else(|_| find_fuzz_binary(fuzz_dir, program_name, "debug"))?;

    println!("Replaying crash: {}", crash_path.display());
    println!("Using binary: {}\n", binary_path.display());

    let status = Command::new(&binary_path)
        .current_dir(fuzz_dir)
        .env("FUZZ_INPUT_FILE", &crash_path)
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
fn resolve_fuzz_dir(cwd: &Path, program_name: &str) -> Result<PathBuf> {
    let fuzz_dir = cwd.join("fuzz").join(program_name);
    if fuzz_dir.exists() {
        return Ok(fuzz_dir);
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
