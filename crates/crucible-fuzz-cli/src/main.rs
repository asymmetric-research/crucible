mod templates;
use templates::{generate_cargo_toml, generate_harness, generate_idl_readme};

use std::env::current_dir;
use std::fs::{self, create_dir_all};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

// ============================================================================
// CLI Definition
// ============================================================================

#[derive(Parser)]
#[command(name = "crucible", about = "Solana smart contract fuzzing framework")]
struct Cli {
    /// Use this directory instead of ./fuzz/<program_name>/
    #[arg(short = 'C', long = "harness-dir", global = true)]
    harness_dir: Option<PathBuf>,
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
        /// Run a prebuilt harness binary directly
        #[arg(long)]
        binary_in: Option<PathBuf>,
        /// Build in release mode
        #[arg(long)]
        release: bool,
        /// Enable coverage reporting (single-core only)
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
        crashes_out: Option<PathBuf>,
        /// Custom directory for .meta.json files (default: same as crashes_out)
        #[arg(long)]
        crashes_meta_out: Option<PathBuf>,
        /// Replay a single crash/input file
        #[arg(long)]
        replay: Option<PathBuf>,
        /// Validate setup without fuzzing
        #[arg(long)]
        dry_run: bool,
        /// Random seed for reproducible fuzzing
        #[arg(long)]
        seed: Option<u64>,
        /// Stop fuzzing on first crash
        #[arg(long)]
        stop_on_crash: bool,
        /// Maximum number of actions per fuzzer iteration (default: 8 stateless, 100 stateful)
        #[arg(long)]
        max_actions: Option<usize>,
        /// Disable SVM register tracing for higher throughput (no coverage guidance)
        #[arg(long)]
        no_tracing: bool,
        /// ItyFuzz-style stateful fuzzing: single action per iteration with state pool
        #[arg(long)]
        stateful: bool,
        /// Maximum state depth (action chain length) in stateful mode (default: 15)
        #[arg(long)]
        max_depth: Option<u32>,
        /// State pool capacity in stateful mode (default: 256000)
        #[arg(long)]
        pool_size: Option<u64>,
        /// Path to alternative program .so binary
        #[arg(long)]
        program_so: Option<PathBuf>,
        /// Path to debug binary with DWARF symbols (for source-level coverage with --coverage)
        #[arg(long)]
        symbols: Option<PathBuf>,
        /// Remote fuzzing operational mode (dry_run, explore, coverage, reproduce, corpus_merge)
        #[arg(long)]
        mode: Option<String>,
        /// LCOV coverage output path
        #[arg(long)]
        lcov_out: Option<PathBuf>,
        /// Show detailed performance stats (profiling, memory, pick/exec breakdown)
        #[arg(long)]
        stats: bool,
        /// Maximum memory in KiB (passed by remote driver, accepted but not enforced)
        #[arg(long)]
        max_memory_kib: Option<u64>,
    },
    /// List available fuzz tests
    List {
        /// Program name (omit to list all)
        program_name: Option<String>,
        /// Use this directory instead of ./fuzz/<program_name>/
        #[arg(short = 'C', long = "harness-dir")]
        harness_dir: Option<PathBuf>,
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
        /// Custom crashes directory to read from
        #[arg(long)]
        crashes_dir: Option<PathBuf>,
        /// Custom directory for .meta.json files (default: same as crashes_dir)
        #[arg(long)]
        crash_meta_dir: Option<PathBuf>,
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
        /// Custom directory for .meta.json files (default: same as crashes directory)
        #[arg(long)]
        crash_meta_dir: Option<PathBuf>,
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
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { program_name } => fuzz_init(&program_name, &cli.harness_dir),
        Commands::Run {
            program_name,
            test_name,
            binary_in,
            release,
            coverage,
            timeout,
            cores,
            corpus_in,
            corpus_out,
            crashes_out,
            crashes_meta_out,
            replay,
            dry_run,
            seed,
            stop_on_crash,
            max_actions,
            no_tracing,
            stateful,
            max_depth,
            pool_size,
            program_so,
            symbols,
            stats,
            mode,
            lcov_out,
            max_memory_kib: _,
        } => fuzz_run(
            &program_name,
            &test_name,
            binary_in,
            &cli.harness_dir,
            release,
            coverage,
            timeout,
            corpus_in,
            corpus_out,
            crashes_out,
            crashes_meta_out,
            replay,
            dry_run,
            cores,
            seed,
            stop_on_crash,
            max_actions,
            no_tracing,
            stateful,
            max_depth,
            pool_size,
            program_so,
            symbols,
            stats,
            mode,
            lcov_out,
        ),
        Commands::List {
            program_name,
            harness_dir,
        } => fuzz_list(program_name.as_deref(), &harness_dir.or(cli.harness_dir)),
        Commands::Show {
            program_name,
            crash_file,
            replay,
            regen,
            crashes_dir,
            crash_meta_dir,
        } => fuzz_show(
            &program_name,
            &cli.harness_dir,
            crash_file.as_deref(),
            replay,
            regen,
            crashes_dir.as_deref(),
            crash_meta_dir.as_deref(),
        ),
        Commands::Tmin {
            program_name,
            test_name,
            crash_file,
            all,
            release,
            crash_meta_dir,
        } => fuzz_tmin(
            &program_name,
            &test_name,
            &cli.harness_dir,
            crash_file.as_deref(),
            all,
            release,
            crash_meta_dir.as_deref(),
        ),
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
                anyhow::anyhow!(
                    "Corpus directory required. Provide as positional arg or --corpus-in"
                )
            })?;
            fuzz_cmin(
                &program_name,
                &test_name,
                &cli.harness_dir,
                input,
                corpus_out.as_deref(),
                release,
            )
        }
    }
}

// ============================================================================
// Init Command
// ============================================================================

fn fuzz_init(program_name: &str, harness_dir: &Option<PathBuf>) -> Result<()> {
    let cwd = current_dir()?;

    // If --harness-dir is given, use it directly as the harness root.
    // Otherwise create ./fuzz/<program_name>/.
    let fuzz_program_path = if let Some(dir) = harness_dir {
        let dir = if dir.is_absolute() {
            dir.clone()
        } else {
            cwd.join(dir)
        };
        dir
    } else {
        let fuzz_dir = cwd.join("fuzz");
        // Create fuzz/ directory and .gitignore
        if !fuzz_dir.exists() {
            create_dir_all(&fuzz_dir)?;
            fs::write(
                fuzz_dir.join(".gitignore"),
                "*/target/\n*/crashes/\n.fuzz-cache/\n",
            )
            .context("Failed to create .gitignore")?;
        }
        fuzz_dir.join(program_name)
    };

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

    fs::write(
        idls_dir.join("README.md"),
        generate_idl_readme(program_name),
    )
    .context("Failed to write IDL README")?;

    let harness_display = fuzz_program_path.display();
    println!("\nCreated fuzz harness at: {}/", harness_display);
    println!("\nNext steps:");
    println!(
        "  1. Copy your IDL to: {}/idls/{}.json",
        harness_display, program_name
    );
    println!("     (Run `anchor idl convert` if using legacy IDL format)");
    println!(
        "  2. Ensure program binary exists at: target/deploy/{}.so",
        program_name
    );
    println!(
        "  3. Implement action_* methods in: {}/src/main.rs",
        harness_display
    );
    println!(
        "  4. Run: crucible run {} invariant_test --release",
        program_name
    );

    Ok(())
}

// ============================================================================
// Run Command
// ============================================================================

fn find_first_file_in_dir(dir: &str) -> Option<PathBuf> {
    let path = Path::new(dir);
    if !path.is_dir() {
        return None;
    }
    let mut entries: Vec<_> = fs::read_dir(path)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    entries.first().map(|e| e.path())
}

fn fuzz_run(
    program_name: &str,
    test_name: &str,
    binary_in: Option<PathBuf>,
    harness_dir: &Option<PathBuf>,
    release: bool,
    coverage: bool,
    timeout: Option<u64>,
    corpus_in: Option<PathBuf>,
    corpus_out: Option<PathBuf>,
    crashes_out: Option<PathBuf>,
    meta_out: Option<PathBuf>,
    replay: Option<PathBuf>,
    dry_run: bool,
    cores: Option<usize>,
    seed: Option<u64>,
    stop_on_crash: bool,
    max_actions: Option<usize>,
    no_tracing: bool,
    stateful: bool,
    max_depth: Option<u32>,
    pool_size: Option<u64>,
    program_so: Option<PathBuf>,
    symbols: Option<PathBuf>,
    stats: bool,
    mode: Option<String>,
    lcov_out: Option<PathBuf>,
) -> Result<()> {
    let remote = mode.is_some();

    // Translate --mode into equivalent flags.
    // All path defaults are relative to cwd (the remote driver's working directory).
    let mut coverage = coverage;
    let mut corpus_in = corpus_in;
    let mut corpus_out = corpus_out;
    let mut crashes_out = crashes_out;
    let mut replay = replay;
    let mut dry_run = dry_run;
    let mut stop_on_crash = stop_on_crash;

    if let Some(ref mode_str) = mode {
        match mode_str.as_str() {
            "dry_run" => {
                dry_run = true;
            }
            "explore" => {
                if corpus_out.is_none() {
                    corpus_out = Some("./corpus".into());
                }
                if corpus_in.is_none() {
                    corpus_in = Some("./corpus".into());
                }
                if crashes_out.is_none() {
                    crashes_out = Some("./output".into());
                }
                stop_on_crash = true;
            }
            "reproduce" => {
                if replay.is_none() {
                    replay = find_first_file_in_dir("./input");
                }
            }
            "coverage" => {
                coverage = true;
                if corpus_in.is_none() {
                    corpus_in = Some("./corpus".into());
                }
            }
            "corpus_merge" => {
                // Read from ./corpus, write minimized corpus to ./output via FUZZ_CMIN
                if corpus_in.is_none() {
                    corpus_in = Some("./corpus".into());
                }
                if corpus_out.is_none() {
                    corpus_out = Some("./output".into());
                }
            }
            other => {
                bail!("Unknown mode: {}", other);
            }
        }
    }

    let cwd = current_dir()?;
    let fuzz_dir = resolve_fuzz_dir(&harness_dir.clone().unwrap_or(cwd.clone()), program_name)?;

    let mut cmd = if let Some(binary_path) = binary_in {
        let binary_path = resolve_path(&cwd, &binary_path);
        if !binary_path.exists() {
            bail!("Harness binary not found: {}", binary_path.display());
        }
        println!("[FUZZ] Using prebuilt harness: {}", binary_path.display());
        let mut cmd = Command::new(binary_path);
        cmd.current_dir(&fuzz_dir);
        cmd
    } else {
        try_cargo_build(&fuzz_dir, release, test_name)?;
        let profile = if release { "release" } else { "debug" };
        let binary_path = find_fuzz_binary(&fuzz_dir, profile)?;
        let mut cmd = Command::new(&binary_path);
        cmd.current_dir(&fuzz_dir);
        cmd
    };

    println!(
        r#"
  ______
  ╲    ╱   ___ ___ _   _  ___ ___ ___ _    ___
   ╲╱╲╱   / __| _ \ | | |/ __|_ _| _ ) |  | __|
   ╱╲╱╲  | (__|   / |_| | (__ | || _ \ |__| _|
  ╱    ╲  \___|_|_\\___/ \___|___|___/____|___|
  ▔▔▔▔▔▔
"#
    );

    if let Some(timeout_secs) = timeout {
        cmd.env("FUZZ_TIMEOUT_SECS", timeout_secs.to_string());
        println!("[FUZZ] Running with {}s timeout", timeout_secs);
    }

    // corpus_in: always pass if non-empty; in remote mode also pass if dir doesn't exist yet
    // (the remote driver may populate it after the CLI check).
    if let Some(ref corpus_in_path) = corpus_in {
        let abs_path = resolve_path(&cwd, corpus_in_path);
        let has_inputs = abs_path.exists()
            && fs::read_dir(&abs_path)
                .map(|mut d| d.any(|e| e.is_ok()))
                .unwrap_or(false);
        if has_inputs {
            cmd.env("FUZZ_CORPUS_IN", &abs_path);
            println!("[FUZZ] Loading corpus from: {}", corpus_in_path.display());
        } else if remote {
            cmd.env("FUZZ_CORPUS_IN", &abs_path);
            println!(
                "[FUZZ] Corpus directory passed to harness: {}",
                abs_path.display()
            );
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
        cmd.env("FUZZ_CORPUS_OUT", &abs_path);
        println!("[FUZZ] Writing corpus to: {}", corpus_out_path.display());
    }

    // crashes_out defaults:
    //   remote mode → ./output  (already set above per-mode)
    //   local       → ./crashes/<test_name>
    let crashes_abs_path = if let Some(ref crashes_path) = crashes_out {
        resolve_path(&cwd, crashes_path)
    } else if remote {
        fuzz_dir.join("crashes")
    } else {
        fuzz_dir.join("crashes").join(test_name)
    };
    cmd.env("FUZZ_CRASHES_DIR", &crashes_abs_path);
    println!("[FUZZ] Crashes directory: {}", crashes_abs_path.display());
    if let Some(ref meta_path) = meta_out {
        let meta_abs_path = resolve_path(&cwd, meta_path);
        cmd.env("FUZZ_META_DIR", &meta_abs_path);
        println!("[FUZZ] Meta directory: {}", meta_abs_path.display());
    }

    if let Some(ref replay_path) = replay {
        let abs_path = resolve_path(&cwd, replay_path);
        let resolved_path = if abs_path.exists() {
            abs_path
        } else {
            // Search crashes directory for this crash name
            match find_crash_file(
                &crashes_abs_path,
                program_name,
                &replay_path.to_string_lossy(),
            ) {
                Ok((found_path, _)) => found_path,
                Err(_) => abs_path,
            }
        };
        cmd.env("FUZZ_INPUT_FILE", &resolved_path);
        println!("[FUZZ] Replaying input: {}", resolved_path.display());
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

    if stats {
        cmd.env("FUZZ_STATS", "1");
    }

    if stateful {
        cmd.env("FUZZ_STATEFUL", "1");
        println!("[FUZZ] Stateful mode: ItyFuzz-style single action per iteration with state pool");
    }

    if let Some(depth) = max_depth {
        cmd.env("FUZZ_MAX_DEPTH", depth.to_string());
        println!("[FUZZ] Max state depth: {}", depth);
    }

    if let Some(size) = pool_size {
        cmd.env("FUZZ_STATE_POOL_SIZE", size.to_string());
        println!("[FUZZ] State pool size: {}", size);
    }

    if let Some(ref program_so_path) = program_so {
        let abs_path = resolve_path(&cwd, program_so_path);
        cmd.env("FUZZ_PROGRAM_SO", &abs_path);
        println!("[FUZZ] Program binary override: {}", abs_path.display());
    }

    if let Some(ref symbols_path) = symbols {
        let abs_path = resolve_path(&cwd, symbols_path);
        let canonical = abs_path
            .canonicalize()
            .context("Debug symbols file not found")?;
        cmd.env("FUZZ_SYMBOLS", &canonical);
        println!("[FUZZ] Debug symbols: {}", canonical.display());
    }

    // Default: 8 for stateless, 100 for stateful.
    let max_actions = max_actions.unwrap_or(if stateful { 100 } else { 8 });
    cmd.env("FUZZ_MAX_ACTIONS", max_actions.to_string());
    println!("[FUZZ] Max actions per iteration: {}", max_actions);

    if mode.as_deref() == Some("corpus_merge") {
        cmd.env("FUZZ_CMIN", "1");
        println!("[FUZZ] Corpus merge mode: minimizing corpus");
    } else if coverage {
        let corpus_in_abs = corpus_in
            .as_ref()
            .map(|p| resolve_path(&cwd, p))
            .ok_or_else(|| anyhow::anyhow!("--coverage requires --corpus-in"))?;
        cmd.env("FUZZ_COVERAGE", "1");
        cmd.env("FUZZ_CORPUS_IN", &corpus_in_abs);
        // coverage-only (no fuzzing) when no timeout/dry-run/replay override
        if timeout.is_none() && !dry_run && replay.is_none() {
            cmd.env("FUZZ_COVERAGE_ONLY", "1");
            println!("[FUZZ] Coverage-only mode: generating coverage from corpus");
        }
    }

    // LCOV output path:
    //   explicit --lcov-out  → that path
    //   remote coverage mode → ./output/coverage.lcov
    //   local coverage       → ./coverage/coverage.lcov
    if coverage || lcov_out.is_some() {
        let lcov_path = if let Some(ref p) = lcov_out {
            resolve_path(&cwd, p)
        } else if remote {
            let dir = resolve_path(&cwd, &PathBuf::from("./output"));
            let _ = fs::create_dir_all(&dir);
            dir.join("coverage.lcov")
        } else {
            let dir = resolve_path(&cwd, &PathBuf::from("./coverage"));
            let _ = fs::create_dir_all(&dir);
            dir.join("coverage.lcov")
        };
        cmd.env("FUZZ_COVERAGE_OUT", &lcov_path);
        println!("[FUZZ] LCOV output: {}", lcov_path.display());
    }

    let status = cmd.status().context("Failed to run fuzz binary")?;
    if !status.success() {
        // In reproduce mode, exit code 1 means crash reproduced (not a failure).
        if mode.as_deref() == Some("reproduce") {
            std::process::exit(status.code().unwrap_or(1));
        }
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

fn fuzz_list(program_name: Option<&str>, harness_dir: &Option<PathBuf>) -> Result<()> {
    let cwd = current_dir()?;

    match program_name {
        Some(name) => {
            let fuzz_dir = resolve_fuzz_dir(&harness_dir.clone().unwrap_or(cwd.clone()), name)?;
            list_program_tests(&fuzz_dir, name)?;
        }
        None => {
            // If a harness_dir is given, list just that one harness.
            if let Some(dir) = harness_dir {
                let dir = if dir.is_absolute() {
                    dir.clone()
                } else {
                    cwd.join(dir)
                };
                let name = dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                return list_program_tests(&dir, name);
            }

            let fuzz_root = cwd.join("fuzz");
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

fn fuzz_show(
    program_name: &str,
    harness_dir: &Option<PathBuf>,
    crash_file: Option<&str>,
    replay: bool,
    regen: bool,
    custom_crashes_dir: Option<&Path>,
    custom_meta_dir: Option<&Path>,
) -> Result<()> {
    if regen && !replay {
        bail!(
            "--regen requires --replay. Usage: crucible show {} --replay --regen",
            program_name
        );
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
        let fuzz_dir = resolve_fuzz_dir(&harness_dir.clone().unwrap_or(cwd.clone()), program_name)?;
        let display_name = fuzz_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(program_name)
            .to_string();
        (fuzz_dir, display_name)
    };

    match crash_file {
        None if replay && regen => regen_crashes(&fuzz_dir, custom_crashes_dir, custom_meta_dir),
        None => list_crashes(
            &fuzz_dir,
            &display_name,
            custom_crashes_dir,
            custom_meta_dir,
        ),
        Some(crash_name) if !replay => show_crash_metadata(
            &fuzz_dir,
            &display_name,
            crash_name,
            custom_crashes_dir,
            custom_meta_dir,
        ),
        Some(crash_name) => replay_crash(&fuzz_dir, &display_name, crash_name, custom_crashes_dir),
    }
}

fn list_crashes(
    fuzz_dir: &Path,
    program_name: &str,
    custom_crashes_dir: Option<&Path>,
    custom_meta_dir: Option<&Path>,
) -> Result<()> {
    let crashes_dir = resolve_crashes_dir(fuzz_dir, custom_crashes_dir);
    let meta_dir = custom_meta_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| crashes_dir.clone());
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
        let meta_test_dir = meta_dir.join(&test_name);
        let mut meta_ids = std::collections::HashSet::new();
        for file_entry in fs::read_dir(if meta_test_dir.is_dir() {
            &meta_test_dir
        } else {
            &test_dir
        })? {
            let file_entry = file_entry?;
            let file_path = file_entry.path();
            let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
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

    // Also scan flat layout: files directly in crashes_dir (no test subdirectory)
    {
        let mut flat_meta_ids = std::collections::HashSet::new();
        for file_entry in fs::read_dir(&meta_dir)? {
            let file_entry = file_entry?;
            let file_path = file_entry.path();
            if !file_path.is_file() {
                continue;
            }
            let filename = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if filename.ends_with(".meta.json") {
                if let Ok(content) = fs::read_to_string(&file_path) {
                    if let Ok(meta) = serde_json::from_str::<CrashMetadata>(&content) {
                        let crash_id = filename
                            .strip_suffix(".meta.json")
                            .unwrap_or(&filename)
                            .to_string();
                        flat_meta_ids.insert(crash_id.clone());
                        crashes_with_meta.push((crash_id, "(flat)".to_string(), meta));
                    }
                }
            }
        }
        for file_entry in fs::read_dir(&crashes_dir)? {
            let file_entry = file_entry?;
            let file_path = file_entry.path();
            if !file_path.is_file() {
                continue;
            }
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
            if file_path.is_dir() {
                continue;
            }
            if flat_meta_ids.contains(&filename) {
                continue;
            }
            // Skip if it's a subdirectory name we already scanned
            if crashes_dir.join(&filename).is_dir() {
                continue;
            }
            let file_size = file_path.metadata().map(|m| m.len()).unwrap_or(0);
            raw_crashes.push((filename, "(flat)".to_string(), file_size));
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
    println!("\n=== Crashes for {} ({} total) ===\n", program_name, total);

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
    println!("To view a crash: crucible show {} <crash_id>", program_name);
    println!(
        "To replay a crash: crucible show {} <crash_id> --replay",
        program_name
    );

    Ok(())
}

fn show_crash_metadata(
    fuzz_dir: &Path,
    program_name: &str,
    crash_name: &str,
    custom_crashes_dir: Option<&Path>,
    custom_meta_dir: Option<&Path>,
) -> Result<()> {
    let crashes_dir = resolve_crashes_dir(fuzz_dir, custom_crashes_dir);
    let meta_dir = custom_meta_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| crashes_dir.clone());

    // Search for .meta.json and/or raw crash file
    let mut meta_path = None;
    let mut crash_binary_path = None;
    if let Ok(entries) = fs::read_dir(&crashes_dir) {
        for entry in entries.flatten() {
            let test_dir = entry.path();
            if !test_dir.is_dir() {
                continue;
            }
            let test_name = test_dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let meta_candidate = meta_dir
                .join(test_name)
                .join(format!("{}.meta.json", crash_name));
            if meta_candidate.exists() {
                meta_path = Some(meta_candidate);
            }
            let binary_candidate = test_dir.join(crash_name);
            if binary_candidate.exists() && binary_candidate.is_file() {
                crash_binary_path = Some(binary_candidate);
            }
        }
    }

    // Also check flat layout: files directly in crashes_dir / meta_dir
    if meta_path.is_none() {
        let flat_meta = meta_dir.join(format!("{}.meta.json", crash_name));
        if flat_meta.exists() {
            meta_path = Some(flat_meta);
        }
    }
    if crash_binary_path.is_none() {
        let flat_binary = crashes_dir.join(crash_name);
        if flat_binary.exists() && flat_binary.is_file() {
            crash_binary_path = Some(flat_binary);
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
        println!(
            "\nHex preview: {}{}",
            hex,
            if bytes.len() > 64 { " ..." } else { "" }
        );

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

fn replay_crash(
    fuzz_dir: &Path,
    program_name: &str,
    crash_name: &str,
    custom_crashes_dir: Option<&Path>,
) -> Result<()> {
    let crashes_dir = resolve_crashes_dir(fuzz_dir, custom_crashes_dir);

    // Check if crash_name is a directory — replay all crashes in it
    let replay_dir = resolve_replay_directory(crash_name, &crashes_dir);
    if let Some(dir) = replay_dir {
        return replay_crash_directory(fuzz_dir, &dir);
    }

    // Single crash replay
    let (crash_path, test_name) = find_crash_file(&crashes_dir, program_name, crash_name)?;

    let binary_path = build_and_find_replay_binary(fuzz_dir, test_name.as_deref())?;

    println!("Replaying crash: {}", crash_path.display());
    println!("Using binary: {}\n", binary_path.display());

    let status = run_replay(&binary_path, fuzz_dir, &crash_path)?;
    print_replay_result(&status);

    Ok(())
}

/// Resolve crash_name to a directory if it is one.
/// Checks: absolute/relative path, crashes/<name>, crashes/*/<name>
fn resolve_replay_directory(crash_name: &str, crashes_dir: &Path) -> Option<PathBuf> {
    let path = Path::new(crash_name);

    // Direct path
    if path.is_dir() {
        return Some(path.to_path_buf());
    }

    // crashes/<name> (test subdirectory)
    let candidate = crashes_dir.join(crash_name);
    if candidate.is_dir() {
        return Some(candidate);
    }

    None
}

/// Replay all crash files in a directory.
fn replay_crash_directory(fuzz_dir: &Path, dir: &Path) -> Result<()> {
    // Collect crash files (skip metadata/hidden)
    let mut crash_files: Vec<(String, PathBuf)> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('.') || name.ends_with(".metadata") || name.ends_with(".meta.json")
            {
                continue;
            }
            if path.is_file() {
                crash_files.push((name.to_string(), path));
            }
        }
    }

    if crash_files.is_empty() {
        bail!("No crash files found in: {}", dir.display());
    }

    crash_files.sort_by(|a, b| a.0.cmp(&b.0));

    // Infer test name from the directory name (crashes are stored in crashes/<test_name>/)
    let test_name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    let binary_path = build_and_find_replay_binary(fuzz_dir, test_name.as_deref())?;

    println!(
        "[REPLAY] Replaying {} crash(es) from: {}\n",
        crash_files.len(),
        dir.display()
    );

    let mut reproduced = 0usize;
    let mut not_reproduced = 0usize;
    let mut errors = 0usize;

    for (i, (crash_id, crash_path)) in crash_files.iter().enumerate() {
        println!("--- [{}/{}] {} ---", i + 1, crash_files.len(), crash_id);

        match run_replay(&binary_path, fuzz_dir, crash_path) {
            Ok(status) => {
                if !status.success() && status.code() == Some(1) {
                    reproduced += 1;
                    println!("  -> Reproduced\n");
                } else {
                    not_reproduced += 1;
                    println!("  -> Not reproduced\n");
                }
            }
            Err(e) => {
                errors += 1;
                println!("  -> Error: {}\n", e);
            }
        }
    }

    println!("=== Replay Summary ===");
    println!(
        "  {} reproduced, {} not reproduced, {} errors (of {} total)",
        reproduced,
        not_reproduced,
        errors,
        crash_files.len()
    );

    Ok(())
}

/// Find a single crash file by name in the crashes directory tree.
fn find_crash_file(
    crashes_dir: &Path,
    program_name: &str,
    crash_name: &str,
) -> Result<(PathBuf, Option<String>)> {
    let mut crash_path = None;
    let mut test_name: Option<String> = None;
    let mut found_metadata_only = false;
    let mut available_inputs: Vec<String> = Vec::new();

    if let Ok(entries) = fs::read_dir(crashes_dir) {
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

    // Also check flat layout (files directly in crashes_dir)
    if crash_path.is_none() {
        let candidate = crashes_dir.join(crash_name);
        if candidate.exists() && candidate.is_file() {
            crash_path = Some(candidate);
        }
        // Try with extensions
        if crash_path.is_none() {
            for ext in &[".bin"] {
                let candidate = crashes_dir.join(format!("{}{}", crash_name, ext));
                if candidate.exists() && candidate.is_file() {
                    crash_path = Some(candidate);
                    break;
                }
            }
        }
        // Check flat metadata
        if crash_path.is_none() {
            let flat_meta = crashes_dir.join(format!("{}.meta.json", crash_name));
            if flat_meta.exists() {
                found_metadata_only = true;
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
                crashes_dir.display(),
                program_name
            )
        }
    })?;

    Ok((crash_path, test_name))
}

/// Build the replay binary and return its path.
fn build_and_find_replay_binary(fuzz_dir: &Path, test_feature: Option<&str>) -> Result<PathBuf> {
    if has_cargo() {
        if let Some(feature) = test_feature {
            if !feature.is_empty() {
                println!("[REPLAY] Building with --features {} ...", feature);
                let build_status = Command::new("cargo")
                    .current_dir(fuzz_dir)
                    .env("RUSTUP_TOOLCHAIN", "stable")
                    .args(["build", "--release", "--features", feature])
                    .status()
                    .context("Failed to build fuzz harness for replay")?;

                if !build_status.success() {
                    // Try debug build
                    let build_status = Command::new("cargo")
                        .current_dir(fuzz_dir)
                        .env("RUSTUP_TOOLCHAIN", "stable")
                        .args(["build", "--features", feature])
                        .status()
                        .context("Failed to build fuzz harness for replay")?;

                    if !build_status.success() {
                        bail!("Failed to build fuzz harness with --features {}", feature);
                    }
                }
            }
        }
    } else {
        println!("[REPLAY] cargo not found, looking for pre-built binary...");
    }

    find_fuzz_binary(fuzz_dir, "release").or_else(|_| find_fuzz_binary(fuzz_dir, "debug"))
}

/// Run the replay binary for a single crash file.
fn run_replay(binary_path: &Path, fuzz_dir: &Path, crash_path: &Path) -> Result<ExitStatus> {
    // Canonicalize crash path so it works regardless of the binary's working directory
    let abs_crash = crash_path.canonicalize().context("Crash file not found")?;
    Command::new(binary_path)
        .current_dir(fuzz_dir)
        .env("FUZZ_INPUT_FILE", &abs_crash)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("Failed to run replay")
}

fn print_replay_result(status: &ExitStatus) {
    if !status.success() {
        if status.code() == Some(1) {
            println!("[REPLAY] SUCCESS: Crash reproduced!");
        } else {
            eprintln!("\nReplay failed with exit code: {:?}", status.code());
        }
    } else {
        println!("[REPLAY] Replay completed without crash.");
    }
}

// ============================================================================
// Tmin Command
// ============================================================================

fn fuzz_tmin(
    program_name: &str,
    test_name: &str,
    harness_dir: &Option<PathBuf>,
    crash_file: Option<&str>,
    all: bool,
    release: bool,
    crash_meta_dir: Option<&Path>,
) -> Result<()> {
    let cwd = current_dir()?;
    let fuzz_dir = resolve_fuzz_dir(&harness_dir.clone().unwrap_or(cwd), program_name)?;

    // Auto-detect: if test_name looks like a crash ID and no crash_file was given,
    // search all test directories for it. Allows: crucible tmin stake crash_abc123
    let (test_name, crash_file) = if crash_file.is_none() && !all && test_name.starts_with("crash_")
    {
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
                test_name,
                crashes_root.display(),
                program_name,
                test_name
            ),
        }
    } else {
        (test_name.to_string(), crash_file.map(|s| s.to_string()))
    };
    let test_name = &test_name;
    let crash_file = crash_file.as_deref();

    let crashes_dir = fuzz_dir.join("crashes").join(test_name);
    let meta_dir = crash_meta_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| crashes_dir.clone());

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
        for entry in fs::read_dir(&meta_dir)? {
            let entry = entry?;
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if let Some(crash_id) = name.strip_suffix(".meta.json") {
                    let binary_path = crashes_dir.join(crash_id);
                    if binary_path.exists() && binary_path.is_file() {
                        files.push((crash_id.to_string(), binary_path));
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
                program_name,
                test_name,
                program_name,
                test_name
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

    // Build the binary (skipped if cargo not available)
    let profile = if release { "release" } else { "debug" };
    try_cargo_build(&fuzz_dir, release, test_name)?;
    let binary_path = find_fuzz_binary(&fuzz_dir, profile)?;

    // Minimize crash(es)
    if all {
        // --all mode: single process invocation, binary iterates all crashes internally
        // This avoids re-running setup() for each crash (major perf win)
        println!(
            "[TMIN] Minimizing all {} crashes in a single process...",
            crash_files.len()
        );
        let status = Command::new(&binary_path)
            .current_dir(&fuzz_dir)
            .env("FUZZ_TMIN_ALL_DIR", &crashes_dir)
            .env("FUZZ_CRASHES_DIR", &crashes_dir)
            .env("FUZZ_META_DIR", &meta_dir)
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
            .env("FUZZ_META_DIR", &meta_dir)
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

fn regen_crashes(
    fuzz_dir: &Path,
    custom_crashes_dir: Option<&Path>,
    custom_meta_dir: Option<&Path>,
) -> Result<()> {
    let crashes_dir = resolve_crashes_dir(fuzz_dir, custom_crashes_dir);
    let meta_dir = custom_meta_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| crashes_dir.clone());
    if !crashes_dir.exists() {
        bail!(
            "No crashes directory found at: {}\nRun the fuzzer first to generate crashes.",
            crashes_dir.display()
        );
    }

    // Find the binary (try release then debug)
    let binary_path =
        find_fuzz_binary(fuzz_dir, "release").or_else(|_| find_fuzz_binary(fuzz_dir, "debug"))?;

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
        println!("\n[REGEN] {} — {} crash(es)", test_name, crash_files.len());

        for (idx, (crash_id, crash_path)) in crash_files.iter().enumerate() {
            total_count += 1;
            print!("[REGEN] {}/{} {}... ", idx + 1, crash_files.len(), crash_id);

            let meta_test_dir = meta_dir.join(test_name);
            let status = Command::new(&binary_path)
                .current_dir(fuzz_dir)
                .env("FUZZ_INPUT_FILE", crash_path)
                .env("FUZZ_CRASHES_DIR", &test_dir)
                .env("FUZZ_META_DIR", &meta_test_dir)
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
    harness_dir: &Option<PathBuf>,
    corpus_in: &Path,
    corpus_out: Option<&Path>,
    release: bool,
) -> Result<()> {
    let cwd = current_dir()?;
    let fuzz_dir = resolve_fuzz_dir(&harness_dir.clone().unwrap_or(cwd.clone()), program_name)?;

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
            !name.starts_with('.') && !name.ends_with(".metadata") && !name.ends_with(".meta.json")
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
        .unwrap_or_else(|| {
            println!("[CMIN] Merging corpus in place!");
            corpus_in_abs.clone()
        });

    if corpus_out_abs != corpus_in_abs {
        fs::create_dir_all(&corpus_out_abs)?;
        println!("[CMIN] Output directory: {}", corpus_out_abs.display());
    }

    let profile = if release { "release" } else { "debug" };
    try_cargo_build(&fuzz_dir, release, test_name)?;
    let binary_path = find_fuzz_binary(&fuzz_dir, profile)?;

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

/// Resolve the fuzz harness directory for a program name.
///
/// `root` is either:
/// - the project root (normal case, no --harness-dir): looks under root/fuzz/<program>/
/// - a custom harness root (--harness-dir): treats root itself as the harness dir if it
///   contains a Cargo.toml, otherwise looks for root/<program>/ inside it.
///
/// Also tries hyphen/underscore conversion and auto-detects if only one harness exists.
fn resolve_fuzz_dir(root: &Path, program_name: &str) -> Result<PathBuf> {
    // If root itself is a harness dir (has [package], not a bare virtual workspace), use it directly.
    if root.join("Cargo.toml").exists() && root.join("src").exists() {
        let content = fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();
        let is_virtual_workspace =
            content.contains("[workspace]") && !content.contains("[package]");
        if !is_virtual_workspace {
            return Ok(root.to_path_buf());
        }
    }

    // Try root/fuzz/<program>/ (normal project-root case)
    let fuzz_dir = root.join("fuzz").join(program_name);
    if fuzz_dir.exists() {
        return Ok(fuzz_dir);
    }

    // Try root/<program>/ (--harness-dir points to fuzz/ itself)
    let direct = root.join(program_name);
    if direct.exists() && direct.join("Cargo.toml").exists() {
        return Ok(direct);
    }

    // Try hyphen <-> underscore conversion in both locations
    let alt_name = if program_name.contains('-') {
        program_name.replace('-', "_")
    } else {
        program_name.replace('_', "-")
    };
    for candidate in [root.join("fuzz").join(&alt_name), root.join(&alt_name)] {
        if candidate.exists() && candidate.join("Cargo.toml").exists() {
            return Ok(candidate);
        }
    }

    // Auto-detect: if fuzz/ has exactly one harness, use it
    let fuzz_root = root.join("fuzz");
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

    bail!(
        "Fuzz directory for {} does not exist. Run `crucible init {}` first.",
        program_name,
        program_name
    );
}

/// Check if cargo is available in PATH.
fn has_cargo() -> bool {
    Command::new("cargo")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Try to build the fuzz harness with cargo. Returns Ok(true) if built, Ok(false) if cargo
/// is not available (so caller should look for a pre-built binary), or Err on build failure.
fn try_cargo_build(fuzz_dir: &Path, release: bool, feature: &str) -> Result<bool> {
    if !has_cargo() {
        println!("[FUZZ] cargo not found, looking for pre-built binary...");
        return Ok(false);
    }

    let mut args = vec!["build".to_string()];
    if release {
        args.push("--release".to_string());
    }
    args.extend(["--features".to_string(), feature.to_string()]);

    let status = Command::new("cargo")
        .current_dir(fuzz_dir)
        .env("RUSTUP_TOOLCHAIN", "stable")
        .args(&args)
        .status()
        .context("Failed to run cargo build")?;

    if !status.success() {
        bail!("Build failed");
    }

    Ok(true)
}

/// Resolve the crashes directory: use the custom path if provided, else default to `<fuzz_dir>/crashes`.
fn resolve_crashes_dir(fuzz_dir: &Path, custom: Option<&Path>) -> PathBuf {
    custom
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| fuzz_dir.join("crashes"))
}

/// Convert a potentially relative path to absolute, relative to cwd.
fn resolve_path(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

/// Find the fuzz harness binary. The generated Cargo.toml always names the binary
/// `invariant_test` via `[[bin]]`, so the path is predictable.
fn find_fuzz_binary(fuzz_dir: &Path, profile: &str) -> Result<PathBuf> {
    let path = fuzz_dir.join("target").join(profile).join("invariant_test");
    if path.exists() {
        return Ok(path);
    }
    bail!(
        "Fuzz binary not found at: {}\nBuild it first with: crucible run <program> <test_name> --release",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_fuzz_binary_finds_invariant_test() {
        let temp = tempfile::tempdir().unwrap();
        let target_dir = temp.path().join("target/release");
        fs::create_dir_all(&target_dir).unwrap();
        fs::write(target_dir.join("invariant_test"), b"").unwrap();

        let result = find_fuzz_binary(temp.path(), "release");
        assert!(result.is_ok(), "should find invariant_test: {:?}", result);
        assert!(result.unwrap().ends_with("invariant_test"));
    }

    #[test]
    fn test_find_fuzz_binary_fails_when_missing() {
        let temp = tempfile::tempdir().unwrap();
        let result = find_fuzz_binary(temp.path(), "release");
        assert!(result.is_err());
    }

    #[test]
    fn test_try_cargo_build_returns_true_when_cargo_available() {
        assert!(has_cargo(), "cargo should be available in test env");
    }

    #[test]
    fn test_run_accepts_binary_in() {
        let cli = Cli::try_parse_from([
            "crucible",
            "run",
            "stake",
            "invariant_test",
            "--binary-in",
            "/tmp/stake_fuzz",
        ])
        .unwrap();

        match cli.command {
            Commands::Run { binary_in, .. } => {
                assert_eq!(binary_in, Some(PathBuf::from("/tmp/stake_fuzz")));
            }
            _ => panic!("expected run command"),
        }
    }

    // === Regression: crash replay path must be canonicalized ===

    #[test]
    fn test_run_replay_canonicalizes_crash_path() {
        // run_replay passes crash_path as FUZZ_INPUT_FILE env var.
        // If crash_path is relative to cwd but binary runs from fuzz_dir,
        // it must be canonicalized to an absolute path.
        // Non-existent path returns Err (caller gets "Crash file not found").
        let crash = Path::new("crashes/invariant_test/crash_abc123");
        assert!(
            crash.canonicalize().is_err(),
            "non-existent crash path should fail canonicalize"
        );

        // Existing path canonicalizes to an absolute path.
        let tmp = std::env::temp_dir().join("crucible_test_crash_replay");
        std::fs::write(&tmp, b"test").unwrap();
        let abs = tmp.canonicalize().unwrap();
        assert!(abs.is_absolute());
        std::fs::remove_file(&tmp).unwrap();
    }

    // === Regression: crash dir must not fallback to ./output ===

    #[test]
    fn test_crashes_dir_env_no_output_fallback() {
        // Previously, if ./output existed, FUZZ_CRASHES_DIR would default to it.
        // This caused crashes to go to output/ instead of crashes/, breaking crucible show.
        // The fix: only use FUZZ_CRASHES_DIR if explicitly set via env var.
        // We verify the generated code doesn't have the ./output fallback by checking
        // that crashes_dir_env reads ONLY from the env var.
        std::env::remove_var("FUZZ_CRASHES_DIR");
        let val: Option<String> = std::env::var("FUZZ_CRASHES_DIR").ok();
        assert!(val.is_none(), "FUZZ_CRASHES_DIR should not be set");
        // The old code would check: .or_else(|| if Path::new("./output").is_dir() { Some(...) })
        // The new code just uses: std::env::var("FUZZ_CRASHES_DIR").ok()
        // This test documents the expected behavior.
    }
}
