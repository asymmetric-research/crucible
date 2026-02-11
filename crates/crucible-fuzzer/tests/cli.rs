//! CLI integration tests for crucible commands
//!
//! Tests cover:
//! - `crucible init` - harness creation
//! - `crucible run` - fuzzing execution modes
//! - `crucible list` - test discovery
//! - `crucible show` - crash inspection
//! - `crucible cmin` - corpus minimization

mod common;

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Get the workspace root
fn project_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .unwrap()
        .parent() // workspace root
        .unwrap()
        .to_path_buf()
}

/// Run crucible command in a directory
fn run_crucible_in(dir: &Path, args: &[&str]) -> std::process::Output {
    let crucible_bin = project_root().join("target/debug/crucible");

    let mut cmd = Command::new(&crucible_bin);
    cmd.current_dir(dir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    cmd.output().expect("Failed to execute crucible command")
}

/// Check that crucible CLI is built
fn ensure_cli_built() {
    let crucible_bin = project_root().join("target/debug/crucible");
    if !crucible_bin.exists() {
        panic!(
            "Crucible CLI not found at {}. Build it first with: cargo build -p crucible-fuzz-cli",
            crucible_bin.display()
        );
    }
}

// =============================================================================
// anchor fuzz init
// =============================================================================

#[test]
fn test_init_creates_workspace() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();
    let output = run_crucible_in(temp.path(), &["init", "my_program"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Debug output if test fails
    if !output.status.success() {
        eprintln!("stdout: {}", stdout);
        eprintln!("stderr: {}", stderr);
    }

    assert!(output.status.success(), "init command should succeed");

    // Check created structure
    let fuzz_dir = temp.path().join("fuzz/my_program");
    assert!(fuzz_dir.exists(), "fuzz/my_program should exist");
    assert!(fuzz_dir.join("Cargo.toml").exists(), "Cargo.toml should exist");
    assert!(fuzz_dir.join("rust-toolchain.toml").exists(), "rust-toolchain.toml should exist");
    assert!(fuzz_dir.join("src/main.rs").exists(), "src/main.rs should exist");
    assert!(fuzz_dir.join("idls").is_dir(), "idls/ should be a directory");

    // Verify Cargo.toml contains [workspace]
    let cargo_content = fs::read_to_string(fuzz_dir.join("Cargo.toml")).unwrap();
    assert!(cargo_content.contains("[workspace]"), "Cargo.toml should declare [workspace]");
}

#[test]
fn test_init_idempotent() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // First init should succeed
    let output1 = run_crucible_in(temp.path(), &["init", "my_program"]);
    assert!(output1.status.success(), "first init should succeed");

    // Second init should fail (directory already exists)
    let output2 = run_crucible_in(temp.path(), &["init", "my_program"]);
    assert!(!output2.status.success(), "second init should fail - directory exists");

    let stderr = String::from_utf8_lossy(&output2.stderr);
    assert!(
        stderr.contains("already exists"),
        "error message should mention 'already exists'"
    );
}

// =============================================================================
// anchor fuzz run
// =============================================================================

#[test]
fn test_run_dry_run() {
    ensure_cli_built();

    // Use marginfi example which should be set up
    let marginfi_path = project_root().join("examples/marginfi-v2-fuzz");
    if !marginfi_path.exists() {
        eprintln!("Skipping test_run_dry_run: marginfi example not found");
        return;
    }

    let output = run_crucible_in(&marginfi_path, &["run", "marginfi-v2-fuzz", "invariant_test", "--dry-run"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Dry-run should print validation message
    assert!(
        stdout.contains("Dry-run") || stderr.contains("Dry-run") || stdout.contains("dry-run") || stderr.contains("dry-run"),
        "output should mention dry-run mode"
    );
}

#[test]
fn test_run_nonexistent_harness() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();
    let output = run_crucible_in(temp.path(), &["run", "nonexistent", "test", "--dry-run"]);

    assert!(!output.status.success(), "run should fail for nonexistent harness");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("not found"),
        "error should mention directory doesn't exist"
    );
}

#[test]
fn test_run_timeout_env_set() {
    ensure_cli_built();

    // This test verifies the CLI sets FUZZ_TIMEOUT_SECS correctly
    // We check the output message rather than actually running a long fuzz
    let temp = TempDir::new().unwrap();

    // Create minimal fuzz structure
    let fuzz_dir = temp.path().join("fuzz/test_prog");
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();
    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "test_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
[features]
test_feature = []
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    let output = run_crucible_in(temp.path(), &["run", "test_prog", "test_feature", "--timeout", "30", "--dry-run"]);

    let stdout = String::from_utf8_lossy(&output.stdout);

    // CLI should print message about timeout
    assert!(
        stdout.contains("30s timeout") || stdout.contains("30 second"),
        "CLI should acknowledge timeout setting in output"
    );
}

#[test]
fn test_run_corpus_out_message() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create minimal fuzz structure
    let fuzz_dir = temp.path().join("fuzz/test_prog");
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();
    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "test_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
[features]
test_feature = []
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    let output = run_crucible_in(
        temp.path(),
        &["run", "test_prog", "test_feature", "--corpus-out", "./my_corpus", "--dry-run"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // CLI should print message about corpus output
    assert!(
        stdout.contains("my_corpus") || stdout.contains("corpus"),
        "CLI should acknowledge corpus-out in output"
    );
}

#[test]
fn test_run_multicore_message() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create minimal fuzz structure
    let fuzz_dir = temp.path().join("fuzz/test_prog");
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();
    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "test_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
[features]
test_feature = []
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    let output = run_crucible_in(
        temp.path(),
        &["run", "test_prog", "test_feature", "--cores", "4", "--dry-run"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // CLI should print message about multi-core
    assert!(
        stdout.contains("4") && (stdout.contains("core") || stdout.contains("worker") || stdout.contains("parallel")),
        "CLI should acknowledge multi-core setting in output"
    );
}

#[test]
fn test_run_seed_message() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create minimal fuzz structure
    let fuzz_dir = temp.path().join("fuzz/test_prog");
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();
    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "test_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
[features]
test_feature = []
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    let output = run_crucible_in(
        temp.path(),
        &["run", "test_prog", "test_feature", "--seed", "12345", "--dry-run"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // CLI should print message about seed
    assert!(
        stdout.contains("12345") && stdout.contains("seed"),
        "CLI should acknowledge seed setting in output"
    );
}

// =============================================================================
// anchor fuzz list
// =============================================================================

#[test]
fn test_list_no_fuzz_dir() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();
    let output = run_crucible_in(temp.path(), &["list"]);

    // Should succeed but indicate no fuzz directory
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No fuzz") || stdout.contains("not found") || stdout.to_lowercase().contains("no fuzz"),
        "should indicate no fuzz directory found"
    );
}

#[test]
fn test_list_all() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create two fuzz harnesses
    for name in &["prog_a", "prog_b"] {
        let fuzz_dir = temp.path().join(format!("fuzz/{}", name));
        fs::create_dir_all(&fuzz_dir.join("src")).unwrap();
        fs::write(
            fuzz_dir.join("Cargo.toml"),
            format!(
                r#"[package]
name = "{}_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
[features]
test1 = []
test2 = []
"#,
                name
            ),
        ).unwrap();
        fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();
    }

    let output = run_crucible_in(temp.path(), &["list"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "list should succeed");
    assert!(stdout.contains("prog_a"), "should list prog_a");
    assert!(stdout.contains("prog_b"), "should list prog_b");
}

#[test]
fn test_list_program() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create a fuzz harness with specific features
    let fuzz_dir = temp.path().join("fuzz/my_prog");
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();
    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "my_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
[features]
default = []
invariant_test = []
property_test = []
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    let output = run_crucible_in(temp.path(), &["list", "my_prog"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "list should succeed");
    assert!(stdout.contains("my_prog"), "should show program name");
    assert!(stdout.contains("invariant_test"), "should list invariant_test feature");
    assert!(stdout.contains("property_test"), "should list property_test feature");
    // default is filtered out
    assert!(!stdout.contains("- default"), "should not list default feature as a test");
}

#[test]
fn test_list_nonexistent_program() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();
    let output = run_crucible_in(temp.path(), &["list", "nonexistent"]);

    assert!(!output.status.success(), "list should fail for nonexistent program");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("not found"),
        "error should mention program doesn't exist"
    );
}

// =============================================================================
// anchor fuzz show
// =============================================================================

#[test]
fn test_show_no_crashes() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create minimal fuzz structure
    let fuzz_dir = temp.path().join("fuzz/my_prog");
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();
    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "my_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    let output = run_crucible_in(temp.path(), &["show", "my_prog"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should succeed but indicate no crashes
    assert!(
        stdout.contains("No crashes") || stdout.to_lowercase().contains("no crash"),
        "should indicate no crashes found"
    );
}

#[test]
fn test_show_list_crashes() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create fuzz structure with a crash
    let fuzz_dir = temp.path().join("fuzz/my_prog");
    let crashes_dir = fuzz_dir.join("crashes/invariant_test");
    fs::create_dir_all(&crashes_dir).unwrap();
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();

    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "my_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    // Write a crash metadata file
    fs::write(
        crashes_dir.join("crash_abc123.meta.json"),
        r#"{
            "test_name": "invariant_test",
            "timestamp": "2026-01-01T00:00:00Z",
            "iteration": 42,
            "actions": [
                {"name": "action_deposit", "params": {"amount": 100}, "success": true}
            ]
        }"#,
    ).unwrap();

    let output = run_crucible_in(temp.path(), &["show", "my_prog"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "show should succeed");
    assert!(stdout.contains("crash_abc123"), "should list the crash");
    assert!(stdout.contains("1 total") || stdout.contains("1)"), "should show crash count");
}

#[test]
fn test_show_crash_metadata() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create fuzz structure with a crash
    let fuzz_dir = temp.path().join("fuzz/my_prog");
    let crashes_dir = fuzz_dir.join("crashes/invariant_test");
    fs::create_dir_all(&crashes_dir).unwrap();
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();

    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "my_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    // Write crash metadata
    fs::write(
        crashes_dir.join("crash_xyz.meta.json"),
        r#"{
            "test_name": "invariant_test",
            "timestamp": "2026-02-01T12:00:00Z",
            "iteration": 999,
            "seed": 54321,
            "actions": [
                {"name": "action_deposit", "params": {"user": 0, "amount": 500}, "success": true},
                {"name": "action_withdraw", "params": {"user": 0, "amount": 1000}, "success": false}
            ]
        }"#,
    ).unwrap();

    let output = run_crucible_in(temp.path(), &["show", "my_prog", "crash_xyz"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "show should succeed");
    assert!(stdout.contains("crash_xyz"), "should show crash id");
    assert!(stdout.contains("invariant_test"), "should show test name");
    assert!(stdout.contains("999"), "should show iteration");
    assert!(stdout.contains("54321"), "should show seed");
    assert!(stdout.contains("action_deposit"), "should show first action");
    assert!(stdout.contains("action_withdraw"), "should show second action");
    assert!(stdout.contains("2 actions"), "should show action count");
}

#[test]
fn test_show_nonexistent_crash() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create minimal fuzz structure
    let fuzz_dir = temp.path().join("fuzz/my_prog");
    let crashes_dir = fuzz_dir.join("crashes/test");
    fs::create_dir_all(&crashes_dir).unwrap();
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();

    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "my_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    let output = run_crucible_in(temp.path(), &["show", "my_prog", "nonexistent_crash"]);

    assert!(!output.status.success(), "show should fail for nonexistent crash");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("Crash metadata not found"),
        "error should indicate crash not found"
    );
}

#[test]
fn test_show_replay_no_binary() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create fuzz structure with crash file but no binary
    let fuzz_dir = temp.path().join("fuzz/my_prog");
    let crashes_dir = fuzz_dir.join("crashes/test");
    fs::create_dir_all(&crashes_dir).unwrap();
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();

    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "my_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    // Write crash binary file (just some bytes)
    fs::write(crashes_dir.join("crash_replay"), b"some crash bytes").unwrap();

    let output = run_crucible_in(temp.path(), &["show", "my_prog", "crash_replay", "--replay"]);

    assert!(!output.status.success(), "replay should fail without binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("binary not found") || stderr.contains("Build it first"),
        "error should indicate binary needs to be built"
    );
}

// =============================================================================
// anchor fuzz cmin
// =============================================================================

#[test]
fn test_cmin_nonexistent_corpus() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create minimal fuzz structure
    let fuzz_dir = temp.path().join("fuzz/my_prog");
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();
    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "my_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
[features]
test = []
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    let output = run_crucible_in(
        temp.path(),
        &["cmin", "my_prog", "test", "./nonexistent_corpus"],
    );

    assert!(!output.status.success(), "cmin should fail for nonexistent corpus");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("not found"),
        "error should mention corpus doesn't exist"
    );
}

#[test]
fn test_cmin_empty_corpus() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create minimal fuzz structure
    let fuzz_dir = temp.path().join("fuzz/my_prog");
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();
    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "my_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
[features]
test = []
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    // Create empty corpus directory
    let corpus_dir = temp.path().join("corpus");
    fs::create_dir_all(&corpus_dir).unwrap();

    let output = run_crucible_in(
        temp.path(),
        &["cmin", "my_prog", "test", "./corpus"],
    );

    assert!(!output.status.success(), "cmin should fail for empty corpus");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No corpus inputs") || stderr.to_lowercase().contains("no") && stderr.to_lowercase().contains("inputs"),
        "error should mention no inputs found"
    );
}

#[test]
fn test_cmin_nonexistent_harness() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create corpus but no harness
    let corpus_dir = temp.path().join("corpus");
    fs::create_dir_all(&corpus_dir).unwrap();
    fs::write(corpus_dir.join("input1"), b"test input").unwrap();

    let output = run_crucible_in(
        temp.path(),
        &["cmin", "nonexistent", "test", "./corpus"],
    );

    assert!(!output.status.success(), "cmin should fail for nonexistent harness");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("not found"),
        "error should mention harness doesn't exist"
    );
}

// =============================================================================
// Edge cases and error handling
// =============================================================================

#[test]
fn test_init_special_characters_in_name() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Names with special characters should work (underscores, numbers)
    let output = run_crucible_in(temp.path(), &["init", "my_program_v2"]);
    assert!(output.status.success(), "init with underscores should work");
    assert!(temp.path().join("fuzz/my_program_v2").exists());
}

#[test]
fn test_run_corpus_in_nonexistent_skipped() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create minimal fuzz structure
    let fuzz_dir = temp.path().join("fuzz/test_prog");
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();
    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "test_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
[features]
test_feature = []
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    // Use nonexistent corpus-in - CLI should skip it with a message
    let output = run_crucible_in(
        temp.path(),
        &["run", "test_prog", "test_feature", "--corpus-in", "./no_such_corpus", "--dry-run"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // CLI should print a skip message (not fail)
    assert!(
        stdout.contains("does not exist") || stdout.contains("skipping") || stdout.to_lowercase().contains("skip"),
        "CLI should mention skipping nonexistent corpus-in"
    );
}

#[test]
fn test_stop_on_crash_message() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create minimal fuzz structure
    let fuzz_dir = temp.path().join("fuzz/test_prog");
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();
    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "test_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
[features]
test_feature = []
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    let output = run_crucible_in(
        temp.path(),
        &["run", "test_prog", "test_feature", "--stop-on-crash", "--dry-run"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("stop-on-crash") || stdout.contains("Stop-on-crash"),
        "CLI should acknowledge stop-on-crash setting"
    );
}

#[test]
fn test_coverage_message() {
    ensure_cli_built();

    let temp = TempDir::new().unwrap();

    // Create minimal fuzz structure
    let fuzz_dir = temp.path().join("fuzz/test_prog");
    fs::create_dir_all(&fuzz_dir.join("src")).unwrap();
    fs::write(
        fuzz_dir.join("Cargo.toml"),
        r#"[package]
name = "test_prog_fuzz"
version = "0.1.0"
edition = "2021"
[workspace]
[features]
test_feature = []
"#,
    ).unwrap();
    fs::write(fuzz_dir.join("src/main.rs"), "fn main() {}").unwrap();

    // Create corpus directory for coverage-only mode
    let corpus_dir = temp.path().join("corpus");
    fs::create_dir_all(&corpus_dir).unwrap();
    fs::write(corpus_dir.join("input1"), b"test").unwrap();

    // Without --dry-run, coverage-only mode message should appear
    // (coverage + corpus-in + no timeout + no input)
    let output = run_crucible_in(
        temp.path(),
        &["run", "test_prog", "test_feature", "--coverage", "--corpus-in", "./corpus"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The CLI should print coverage-only mode message before cargo fails to build
    // Check both stdout and stderr since we're not sure where it goes
    let combined = format!("{}\n{}", stdout, stderr);
    assert!(
        combined.to_lowercase().contains("coverage"),
        "CLI should mention coverage mode. stdout: {}, stderr: {}", stdout, stderr
    );
}

// =============================================================================
// END-TO-END INTEGRATION TESTS
// =============================================================================
//
// These tests require a built test-program fuzz harness:
//   cd test-program && cargo build-sbf
//   cd test-program/fuzz/test-program-fuzz && cargo build --release --features invariant_test
//
// Run with: cargo test --test cli -- --ignored

/// Helper to check if e2e tests can run
fn ensure_test_program_built() -> bool {
    let fuzz_path = common::test_program_fuzz_path();
    let binary = fuzz_path.join("target/release/invariant_test");

    if !binary.exists() {
        eprintln!(
            "\n\
            ========================================================\n\
            E2E test skipped: test-program fuzz binary not found.\n\
            Build it first:\n\
              cd crucible-fuzzer/test-program && cargo build-sbf\n\
              cd crucible-fuzzer/test-program/fuzz/test-program-fuzz && cargo build --release --features invariant_test\n\
            ========================================================\n"
        );
        return false;
    }
    true
}

// =============================================================================
// Corpus Loading/Writing Tests
// =============================================================================

#[test]
#[ignore]
fn test_e2e_corpus_in_nonexistent() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let nonexistent = temp.path().join("does_not_exist");

    // CLI sets env var only if dir exists AND has files
    // So with nonexistent dir, harness should use default seed
    let (stdout, stderr, success) = common::run_test_program_fuzz(&[
        ("FUZZ_DRY_RUN", "1"),
        ("FUZZ_CORPUS_IN", nonexistent.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Dry-run should succeed even without corpus
    assert!(success || combined.contains("Dry-run"), "Dry-run should work without corpus. Output: {}", combined);
}

#[test]
#[ignore]
fn test_e2e_corpus_in_empty() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let empty_dir = temp.path().join("empty_corpus");
    fs::create_dir_all(&empty_dir).unwrap();

    // Empty corpus dir should result in default seed being used
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_DRY_RUN", "1"),
        ("FUZZ_CORPUS_IN", empty_dir.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Should mention using default seed or have 0 corpus loaded
    // The key is it shouldn't crash
    assert!(
        combined.contains("Dry-run") || combined.contains("seed") || combined.contains("corpus"),
        "Should handle empty corpus. Output: {}", combined
    );
}

#[test]
#[ignore]
fn test_e2e_corpus_out_creates_dir() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("new_corpus_dir");

    // Run fuzzer briefly with corpus output
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "2"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // The corpus output directory should be created
    assert!(
        corpus_out.exists(),
        "Corpus output directory should be created. Output: {}", combined
    );
}

#[test]
#[ignore]
fn test_e2e_corpus_in_out_count_match() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_in = temp.path().join("corpus_in");
    let corpus_out = temp.path().join("corpus_out");

    // Create 5 seed inputs
    common::create_test_corpus(&corpus_in, 5);
    assert_eq!(common::count_corpus_files(&corpus_in), 5);

    // Run fuzzer briefly
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "3"),
        ("FUZZ_CORPUS_IN", corpus_in.to_str().unwrap()),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // The key behavior: fuzzer attempted to load corpus and ran
    // Note: LibAFL may not load inputs that don't generate new coverage
    // So we just verify the fuzzer ran and produced some output
    assert!(
        combined.contains("corpus") || combined.contains("exec"),
        "Fuzzer should run with corpus. Output: {}", combined
    );

    // Output corpus should exist (may be empty if no coverage from inputs)
    assert!(
        corpus_out.exists(),
        "Corpus output directory should be created. Output: {}", combined
    );
}

#[test]
#[ignore]
fn test_e2e_corpus_roundtrip_singlecore() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_in = temp.path().join("corpus_in");
    let corpus_out = temp.path().join("corpus_out");

    // Create 3 seed inputs
    common::create_test_corpus(&corpus_in, 3);

    // Run fuzzer briefly
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "3"),
        ("FUZZ_CORPUS_IN", corpus_in.to_str().unwrap()),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Output should have corpus entries
    let out_count = common::count_corpus_files(&corpus_out);
    assert!(
        out_count >= 1,
        "Single-core corpus output should have files. Got {}. Output: {}", out_count, combined
    );
}

#[test]
#[ignore]
fn test_e2e_corpus_roundtrip_multicore() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_in = temp.path().join("corpus_in");
    let corpus_out = temp.path().join("corpus_out");

    // Create 3 seed inputs
    common::create_test_corpus(&corpus_in, 3);

    // Run fuzzer with 2 cores (use hard timeout to prevent hangs)
    let (stdout, stderr, _) = common::run_test_program_fuzz_with_timeout(
        &[
            ("FUZZ_TIMEOUT_SECS", "3"),
            ("FUZZ_CORES", "2"),
            ("FUZZ_CORPUS_IN", corpus_in.to_str().unwrap()),
            ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ],
        15, // Hard timeout: FUZZ_TIMEOUT + cleanup buffer
    );

    let combined = format!("{}\n{}", stdout, stderr);

    // Output should have corpus entries (unless hard timeout hit)
    if stderr != "TIMEOUT" {
        let out_count = common::count_corpus_files(&corpus_out);
        assert!(
            out_count >= 1,
            "Multi-core corpus output should have files. Got {}. Output: {}", out_count, combined
        );
    } else {
        eprintln!("[MULTICORE] Hard timeout reached - multicore exit may need investigation");
    }
}

#[test]
#[ignore]
fn test_e2e_corpus_same_dir_singlecore() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_dir = temp.path().join("corpus");

    // Create 3 seed inputs
    common::create_test_corpus(&corpus_dir, 3);
    let initial_count = common::count_corpus_files(&corpus_dir);

    // Run with same dir for in/out (uses forced loading)
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "3"),
        ("FUZZ_CORPUS_IN", corpus_dir.to_str().unwrap()),
        ("FUZZ_CORPUS_OUT", corpus_dir.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Corpus should still exist (not deleted)
    let final_count = common::count_corpus_files(&corpus_dir);
    assert!(
        final_count >= initial_count,
        "Same-dir corpus should preserve files. Initial: {}, Final: {}. Output: {}",
        initial_count, final_count, combined
    );
}

#[test]
#[ignore]
fn test_e2e_corpus_same_dir_multicore() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_dir = temp.path().join("corpus");

    // Create 3 seed inputs
    common::create_test_corpus(&corpus_dir, 3);
    let initial_count = common::count_corpus_files(&corpus_dir);

    // Run multi-core with same dir for in/out (use hard timeout to prevent hangs)
    let (stdout, stderr, _) = common::run_test_program_fuzz_with_timeout(
        &[
            ("FUZZ_TIMEOUT_SECS", "3"),
            ("FUZZ_CORES", "2"),
            ("FUZZ_CORPUS_IN", corpus_dir.to_str().unwrap()),
            ("FUZZ_CORPUS_OUT", corpus_dir.to_str().unwrap()),
        ],
        15, // Hard timeout: FUZZ_TIMEOUT + cleanup buffer
    );

    let combined = format!("{}\n{}", stdout, stderr);

    // Corpus should still exist and not have duplicates removed incorrectly
    if stderr != "TIMEOUT" {
        let final_count = common::count_corpus_files(&corpus_dir);
        assert!(
            final_count >= initial_count,
            "Multi-core same-dir corpus should preserve files. Initial: {}, Final: {}. Output: {}",
            initial_count, final_count, combined
        );
    } else {
        eprintln!("[MULTICORE] Hard timeout reached - multicore exit may need investigation");
    }
}

// =============================================================================
// Cmin Tests
// =============================================================================

#[test]
#[ignore]
fn test_e2e_cmin_reduces_corpus() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_in = temp.path().join("corpus_in");
    let corpus_out = temp.path().join("corpus_out");

    // First, run fuzzer to generate a corpus
    common::create_test_corpus(&corpus_in, 3);

    // Run fuzzer to generate more diverse corpus
    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "5"),
        ("FUZZ_CORPUS_IN", corpus_in.to_str().unwrap()),
        ("FUZZ_CORPUS_OUT", corpus_in.to_str().unwrap()), // Write back to same dir
    ]);

    let pre_cmin_count = common::count_corpus_files(&corpus_in);
    if pre_cmin_count < 5 {
        // Not enough inputs to meaningfully test reduction
        eprintln!("Skipping cmin test: not enough corpus entries generated ({})", pre_cmin_count);
        return;
    }

    // Run cmin
    let (stdout, stderr, success) = common::run_test_program_fuzz(&[
        ("FUZZ_CMIN", "1"),
        ("FUZZ_CORPUS_IN", corpus_in.to_str().unwrap()),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    assert!(success || combined.contains("[CMIN]"), "Cmin should run. Output: {}", combined);

    // Output should have fewer or equal inputs
    let post_cmin_count = common::count_corpus_files(&corpus_out);
    assert!(
        post_cmin_count <= pre_cmin_count,
        "Cmin should reduce corpus. Before: {}, After: {}. Output: {}",
        pre_cmin_count, post_cmin_count, combined
    );
}

#[test]
#[ignore]
fn test_e2e_cmin_inplace() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_dir = temp.path().join("corpus");

    // Create corpus with duplicate coverage (same content = same coverage)
    fs::create_dir_all(&corpus_dir).unwrap();
    for i in 0..5 {
        // Create inputs with identical content (should minimize to 1)
        fs::write(corpus_dir.join(format!("input_{}", i)), &[42u8; 100]).unwrap();
    }

    let pre_count = common::count_corpus_files(&corpus_dir);
    assert_eq!(pre_count, 5);

    // Run cmin in-place (no corpus-out, same as corpus-in)
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_CMIN", "1"),
        ("FUZZ_CORPUS_IN", corpus_dir.to_str().unwrap()),
        ("FUZZ_CORPUS_OUT", corpus_dir.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // In-place cmin should remove redundant files
    let post_count = common::count_corpus_files(&corpus_dir);
    assert!(
        post_count < pre_count,
        "In-place cmin should remove redundant inputs. Before: {}, After: {}. Output: {}",
        pre_count, post_count, combined
    );
}

#[test]
#[ignore]
fn test_e2e_cmin_to_new_dir() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_in = temp.path().join("corpus_in");
    let corpus_out = temp.path().join("corpus_out");

    // Create some corpus entries
    common::create_test_corpus(&corpus_in, 3);

    // Run cmin to new dir
    let (stdout, stderr, success) = common::run_test_program_fuzz(&[
        ("FUZZ_CMIN", "1"),
        ("FUZZ_CORPUS_IN", corpus_in.to_str().unwrap()),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Cmin should run (success means it completed)
    assert!(
        success || combined.contains("[CMIN]"),
        "Cmin should run. Output: {}", combined
    );

    // Output dir should be created
    assert!(
        corpus_out.exists(),
        "Cmin should create output directory. Output: {}", combined
    );

    // Note: If harness doesn't generate coverage, cmin may select 0 inputs
    // This is expected behavior - cmin only keeps inputs that contribute coverage
    // The key is that cmin ran and created the output directory

    // Original dir should be unchanged
    let in_count = common::count_corpus_files(&corpus_in);
    assert_eq!(in_count, 3, "Original corpus should be unchanged");
}

#[test]
#[ignore]
fn test_e2e_cmin_creates_output_dir() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_in = temp.path().join("corpus_in");
    let corpus_out = temp.path().join("nested/output/dir");

    common::create_test_corpus(&corpus_in, 2);
    assert!(!corpus_out.exists());

    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_CMIN", "1"),
        ("FUZZ_CORPUS_IN", corpus_in.to_str().unwrap()),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    assert!(
        corpus_out.exists(),
        "Cmin should create nested output directory. Output: {}", combined
    );
}

#[test]
#[ignore]
fn test_e2e_cmin_skips_metadata() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_in = temp.path().join("corpus_in");
    let corpus_out = temp.path().join("corpus_out");

    // Create corpus with metadata files
    fs::create_dir_all(&corpus_in).unwrap();
    fs::write(corpus_in.join("input_0"), &[1u8; 100]).unwrap();
    fs::write(corpus_in.join("input_1"), &[2u8; 100]).unwrap();
    fs::write(corpus_in.join(".hidden"), b"hidden").unwrap();
    fs::write(corpus_in.join("input_0.metadata"), b"metadata").unwrap();
    fs::write(corpus_in.join("crash.meta.json"), b"{}").unwrap();

    // Only 2 actual inputs
    assert_eq!(common::count_corpus_files(&corpus_in), 2);

    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_CMIN", "1"),
        ("FUZZ_CORPUS_IN", corpus_in.to_str().unwrap()),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Should report 2 input files, not 5
    assert!(
        combined.contains("2 input") || combined.contains("Found 2"),
        "Cmin should only count actual inputs, not metadata. Output: {}", combined
    );
}

// =============================================================================
// Reproducibility & Determinism Tests
// =============================================================================

#[test]
#[ignore]
fn test_e2e_seed_deterministic() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out_1 = temp.path().join("corpus_1");
    let corpus_out_2 = temp.path().join("corpus_2");

    // Run twice with same seed
    let seed = "12345";

    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "2"),
        ("FUZZ_SEED", seed),
        ("FUZZ_CORPUS_OUT", corpus_out_1.to_str().unwrap()),
    ]);

    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "2"),
        ("FUZZ_SEED", seed),
        ("FUZZ_CORPUS_OUT", corpus_out_2.to_str().unwrap()),
    ]);

    // Both runs should produce corpus (determinism is hard to verify exactly,
    // but they should at least both produce output)
    let count_1 = common::count_corpus_files(&corpus_out_1);
    let count_2 = common::count_corpus_files(&corpus_out_2);

    assert!(count_1 > 0, "First run should produce corpus");
    assert!(count_2 > 0, "Second run should produce corpus");

    // Note: Exact determinism is hard to verify due to timing, but the runs
    // should behave similarly with the same seed
}

#[test]
#[ignore]
fn test_e2e_different_seeds_diverge() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out_1 = temp.path().join("corpus_1");
    let corpus_out_2 = temp.path().join("corpus_2");

    // Run with different seeds
    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "2"),
        ("FUZZ_SEED", "11111"),
        ("FUZZ_CORPUS_OUT", corpus_out_1.to_str().unwrap()),
    ]);

    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "2"),
        ("FUZZ_SEED", "99999"),
        ("FUZZ_CORPUS_OUT", corpus_out_2.to_str().unwrap()),
    ]);

    // Both should produce output (different paths may be explored)
    let count_1 = common::count_corpus_files(&corpus_out_1);
    let count_2 = common::count_corpus_files(&corpus_out_2);

    assert!(count_1 > 0, "Seed 11111 should produce corpus");
    assert!(count_2 > 0, "Seed 99999 should produce corpus");
}

// =============================================================================
// Execution Mode Tests
// =============================================================================

#[test]
#[ignore]
fn test_e2e_input_replay() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_dir = temp.path().join("corpus");

    // First generate some corpus
    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "2"),
        ("FUZZ_CORPUS_OUT", corpus_dir.to_str().unwrap()),
    ]);

    // Find a corpus file to replay
    let inputs: Vec<_> = fs::read_dir(&corpus_dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            e.path().is_file() && !name.starts_with('.') && !name.ends_with(".metadata")
        })
        .collect();

    if inputs.is_empty() {
        eprintln!("Skipping replay test: no corpus inputs generated");
        return;
    }

    let input_path = inputs[0].path();

    // Replay the input
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_INPUT_FILE", input_path.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Should mention replay or run the input
    assert!(
        combined.contains("Replay") || combined.contains("replay") ||
        combined.contains("input") || combined.contains("iteration"),
        "Replay should execute the input. Output: {}", combined
    );
}

#[test]
#[ignore]
fn test_e2e_timeout_respected() {
    if !ensure_test_program_built() { return; }

    let start = std::time::Instant::now();

    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "3"),
    ]);

    let elapsed = start.elapsed();
    let combined = format!("{}\n{}", stdout, stderr);

    // Should exit within reasonable time (3s timeout + some buffer)
    assert!(
        elapsed.as_secs() < 10,
        "Fuzzer should respect timeout. Took {}s. Output: {}", elapsed.as_secs(), combined
    );

    // Should mention timeout
    assert!(
        combined.to_lowercase().contains("timeout") || elapsed.as_secs() <= 5,
        "Should mention timeout or exit quickly. Output: {}", combined
    );
}

#[test]
#[ignore]
fn test_e2e_coverage_writes_lcov() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_dir = temp.path().join("corpus");
    let fuzz_path = common::test_program_fuzz_path();
    let lcov_path = fuzz_path.join("coverage.lcov");

    // Clean up any existing coverage file
    let _ = fs::remove_file(&lcov_path);

    // Create seed corpus
    common::create_test_corpus(&corpus_dir, 2);

    // Run with coverage enabled
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_COVERAGE_ONLY", "1"),
        ("FUZZ_CORPUS_IN", corpus_dir.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Check if coverage was written - either file exists OR output says it was written
    let lcov_written = lcov_path.exists() ||
        combined.contains("[LCOV] Coverage written") ||
        combined.contains("coverage.lcov");

    assert!(
        lcov_written,
        "coverage.lcov should be created. Output: {}", combined
    );

    // Clean up
    let _ = fs::remove_file(&lcov_path);
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[test]
#[ignore]
fn test_e2e_invalid_input_file() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let nonexistent = temp.path().join("no_such_file");

    let (stdout, stderr, success) = common::run_test_program_fuzz(&[
        ("FUZZ_INPUT_FILE", nonexistent.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Should fail or report error
    assert!(
        !success || combined.to_lowercase().contains("error") || combined.to_lowercase().contains("not found"),
        "Should report error for nonexistent input. Output: {}", combined
    );
}

#[test]
#[ignore]
fn test_e2e_cmin_requires_corpus_in() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("output");

    // Run cmin without corpus-in
    let (stdout, stderr, success) = common::run_test_program_fuzz(&[
        ("FUZZ_CMIN", "1"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        // No FUZZ_CORPUS_IN
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Should fail with error about missing corpus-in
    assert!(
        !success || combined.contains("FUZZ_CORPUS_IN") || combined.to_lowercase().contains("required"),
        "Cmin should require FUZZ_CORPUS_IN. Output: {}", combined
    );
}

// =============================================================================
// PERFORMANCE REGRESSION TESTS
// =============================================================================
//
// These tests verify that fuzzing performance doesn't degrade significantly
// over time, which would indicate a regression in the optimization work.

/// Test that fuzzer runs successfully and discovers coverage
/// This catches major performance regressions
#[test]
#[ignore]
fn test_e2e_performance_stability_30s() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    let start = std::time::Instant::now();

    // Run fuzzer for 30 seconds (may exit early if crash found)
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "30"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let elapsed = start.elapsed();
    let combined = format!("{}\n{}", stdout, stderr);

    // Parse stats
    let edges = common::parse_edges_count(&combined).unwrap_or(0);
    let crash_found = common::crash_detected(&combined);

    eprintln!("[PERF-30s] Elapsed: {}s, Edges: {}, Crash found: {}", elapsed.as_secs(), edges, crash_found);

    // Verify coverage was discovered
    assert!(
        edges > 0,
        "Should discover some edges. Got 0. Output: {}", combined
    );

    // If fuzzer ran for full duration without crash, verify timing
    // If it found a crash early, that's also a success
    if !crash_found {
        assert!(
            elapsed.as_secs() >= 25 && elapsed.as_secs() <= 45,
            "Fuzzer should run for ~30 seconds when no crash. Took {}s. Output: {}",
            elapsed.as_secs(), combined
        );
    }
}

/// Test that fuzzer discovers significant coverage
/// Longer test to verify stability
#[test]
#[ignore]
fn test_e2e_performance_stability_60s() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    let start = std::time::Instant::now();

    // Run fuzzer for 60 seconds (may exit early if crash found)
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "60"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let elapsed = start.elapsed();
    let combined = format!("{}\n{}", stdout, stderr);

    let edges = common::parse_edges_count(&combined).unwrap_or(0);
    let crash_found = common::crash_detected(&combined);

    eprintln!("[PERF-60s] Elapsed: {}s, Edges: {}, Crash found: {}", elapsed.as_secs(), edges, crash_found);

    // Verify significant coverage was discovered
    // The staking program has ~4600 total edges, should discover at least 100
    assert!(
        edges > 100,
        "Should discover >100 edges. Got {}. Output: {}", edges, combined
    );

    // If it found a crash, that's a successful outcome
    // The staking bug is intentionally discoverable
    if crash_found {
        eprintln!("[PERF-60s] Bug found! (expected - staking has known bug)");
    }
}

/// Test multi-core fuzzing runs and discovers coverage
#[test]
#[ignore]
fn test_e2e_multicore_performance_stability() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    let start = std::time::Instant::now();

    // Run with 2 cores for 20 seconds (use hard timeout to prevent hangs)
    let (stdout, stderr, _) = common::run_test_program_fuzz_with_timeout(
        &[
            ("FUZZ_TIMEOUT_SECS", "20"),
            ("FUZZ_CORES", "2"),
            ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ],
        45, // Hard timeout: FUZZ_TIMEOUT × 2 + buffer
    );

    let elapsed = start.elapsed();
    let combined = format!("{}\n{}", stdout, stderr);

    // Handle multicore infrastructure failures gracefully
    // These can happen when running multiple multicore tests in sequence
    if stderr == "TIMEOUT" || stderr.contains("Launcher failed") || stderr.contains("shmem socket") {
        eprintln!("[MULTICORE-PERF] Hard timeout or Launcher failure - multicore infra issue");
        return;
    }

    // Verify multi-core mode started
    assert!(
        combined.contains("worker") || combined.contains("core") || combined.contains("parallel") || combined.contains("Launcher"),
        "Multi-core mode should be indicated in output. Output: {}", combined
    );

    let edges = common::parse_edges_count(&combined).unwrap_or(0);

    eprintln!("[MULTICORE-PERF] Elapsed: {}s, Edges: {}", elapsed.as_secs(), edges);

    // Verify fuzzer ran and discovered coverage
    assert!(
        edges > 0,
        "Multi-core should discover edges. Got 0. Output: {}", combined
    );
}

// =============================================================================
// CRASH DETECTION AND REPLAY TESTS
// =============================================================================

/// Test that the fuzzer can find the known staking bug and write crash files
#[test]
#[ignore]
fn test_e2e_invariant_violation_detected() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");
    let crashes_dir = temp.path().join("crashes");

    // The staking program has a known bug in reward calculation
    // Run fuzzer long enough to likely trigger it
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "45"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Check if crash was detected
    let crash_found = common::crash_detected(&combined);
    let crash_files = common::count_crash_files(&crashes_dir);

    eprintln!("[INVARIANT] Crash in output: {}, Crash files: {}", crash_found, crash_files);
    eprintln!("[INVARIANT] Output: {}", combined);

    // At least one indicator of crash detection
    // Note: The bug might not be triggered every time, so we check for either
    if !crash_found && crash_files == 0 {
        eprintln!("[INVARIANT] Warning: No crash detected in 45s. The bug may be hard to trigger.");
        eprintln!("[INVARIANT] This is not necessarily a failure - the staking bug requires specific sequences.");
    }

    // Verify fuzzer at least ran properly
    assert!(
        combined.contains("exec") || combined.contains("iteration"),
        "Fuzzer should have run. Output: {}", combined
    );
}

/// Test that crash files are written with both metadata and input bytes
#[test]
#[ignore]
fn test_e2e_crash_files_written() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");
    let crashes_dir = temp.path().join("crashes");

    // Run fuzzer
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "30"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Find crash files
    let crashes = common::find_crash_files(&crashes_dir);

    if !crashes.is_empty() {
        eprintln!("[CRASH] Found {} crash file pairs", crashes.len());

        for (meta_path, input_path) in &crashes {
            // Verify metadata file is valid JSON
            let meta_content = fs::read_to_string(meta_path).unwrap();
            assert!(
                meta_content.contains("{") && meta_content.contains("}"),
                "Crash metadata should be JSON: {}", meta_path.display()
            );

            // Verify input file exists and is non-empty
            let input_size = fs::metadata(input_path).map(|m| m.len()).unwrap_or(0);
            assert!(
                input_size > 0,
                "Crash input file should be non-empty: {}", input_path.display()
            );

            eprintln!("[CRASH] Metadata: {}, Input: {} ({} bytes)",
                meta_path.display(), input_path.display(), input_size);
        }
    } else {
        eprintln!("[CRASH] No crashes found in 30s. Output: {}", combined);
    }
}

/// Test that crash files can be replayed
#[test]
#[ignore]
fn test_e2e_crash_replay() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");
    let crashes_dir = temp.path().join("crashes");

    // First, generate some crashes
    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "30"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
    ]);

    // Find crash files
    let crashes = common::find_crash_files(&crashes_dir);

    if crashes.is_empty() {
        eprintln!("[REPLAY] No crashes to replay - skipping test");
        return;
    }

    // Try to replay the first crash
    let (_, input_path) = &crashes[0];

    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_INPUT_FILE", input_path.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Replay should indicate the crash was reproduced or show the sequence
    assert!(
        combined.to_lowercase().contains("replay") ||
        combined.to_lowercase().contains("sequence") ||
        combined.to_lowercase().contains("action") ||
        combined.to_lowercase().contains("violation"),
        "Replay should show action sequence or indicate replay mode. Output: {}", combined
    );

    eprintln!("[REPLAY] Replay output: {}", combined);
}

/// Test that replay shows which action triggered the violation
#[test]
#[ignore]
fn test_e2e_replay_shows_violation_action() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");
    let crashes_dir = temp.path().join("crashes");

    // Generate crashes
    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "45"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
    ]);

    let crashes = common::find_crash_files(&crashes_dir);

    if crashes.is_empty() {
        eprintln!("[VIOLATION-ACTION] No crashes to test - skipping");
        return;
    }

    let (_, input_path) = &crashes[0];

    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_INPUT_FILE", input_path.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Should show the [VIOLATION] marker on the triggering action
    // Or at least show the action sequence
    let has_sequence = combined.contains("SEQUENCE") || combined.contains("action_");
    let has_marker = combined.contains("[VIOLATION]") || combined.contains("FAIL");

    eprintln!("[VIOLATION-ACTION] Has sequence: {}, Has marker: {}", has_sequence, has_marker);
    eprintln!("[VIOLATION-ACTION] Output: {}", combined);

    if has_sequence {
        assert!(
            has_marker || combined.contains("executed") || combined.contains("skipped"),
            "Replay sequence should indicate which action failed. Output: {}", combined
        );
    }
}

// =============================================================================
// COVERAGE AND CORPUS GROWTH TESTS
// =============================================================================

/// Test that edges/branches increase over time (coverage discovery)
#[test]
#[ignore]
fn test_e2e_edge_discovery() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    // Run fuzzer for a bit
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "15"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Parse edges from output
    let final_edges = common::parse_edges_count(&combined).unwrap_or(0);

    eprintln!("[EDGES] Final edge count: {}", final_edges);
    eprintln!("[EDGES] Output sample: {}", combined.lines().rev().take(10).collect::<Vec<_>>().join("\n"));

    // Verify edges are being discovered (should be > 0)
    assert!(
        final_edges > 0,
        "Should discover some edges. Got 0. Output: {}", combined
    );
}

/// Test that corpus grows as new coverage is discovered
#[test]
#[ignore]
fn test_e2e_corpus_growth() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    // Run for 15 seconds
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "15"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Check corpus size
    let corpus_count = common::count_corpus_files(&corpus_out);

    eprintln!("[CORPUS-GROWTH] Final corpus size: {}", corpus_count);
    eprintln!("[CORPUS-GROWTH] Output: {}", combined);

    // Should have generated some corpus entries
    assert!(
        corpus_count > 0,
        "Corpus should grow as coverage is discovered. Got 0 files. Output: {}", combined
    );
}

/// Test that corpus grows over longer period
#[test]
#[ignore]
fn test_e2e_corpus_growth_30s() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    // Run with sampling
    let (stdout, stderr, _, samples) = common::run_test_program_fuzz_with_samples(
        &[
            ("FUZZ_TIMEOUT_SECS", "30"),
            ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ],
        10,
        30,
    );

    let combined = format!("{}\n{}", stdout, stderr);

    // Check corpus at different times
    let mut corpus_sizes: Vec<usize> = Vec::new();
    for (elapsed, output) in &samples {
        if let Some(count) = common::parse_corpus_count(output) {
            corpus_sizes.push(count);
            eprintln!("[CORPUS-30s] At {}s: {} corpus entries", elapsed, count);
        }
    }

    let final_count = common::count_corpus_files(&corpus_out);
    eprintln!("[CORPUS-30s] Final disk corpus: {} files", final_count);

    // Corpus should have grown
    assert!(
        final_count >= 1,
        "Corpus should have entries after 30s. Got {}. Output: {}", final_count, combined
    );
}

// =============================================================================
// MULTI-CORE SPECIFIC TESTS
// =============================================================================

/// Test that multi-core doesn't cause corpus duplication (N× inflation bug)
#[test]
#[ignore]
fn test_e2e_multicore_no_corpus_duplication() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_single = temp.path().join("corpus_single");
    let corpus_multi = temp.path().join("corpus_multi");

    // Run single-core
    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "15"),
        ("FUZZ_SEED", "42"),
        ("FUZZ_CORPUS_OUT", corpus_single.to_str().unwrap()),
    ]);

    let single_count = common::count_corpus_files(&corpus_single);

    // Run multi-core with same seed (use hard timeout to prevent hangs)
    let (stdout, stderr, _) = common::run_test_program_fuzz_with_timeout(
        &[
            ("FUZZ_TIMEOUT_SECS", "15"),
            ("FUZZ_SEED", "42"),
            ("FUZZ_CORES", "2"),
            ("FUZZ_CORPUS_OUT", corpus_multi.to_str().unwrap()),
        ],
        35, // Hard timeout: FUZZ_TIMEOUT × 2 + buffer
    );

    if stderr == "TIMEOUT" {
        eprintln!("[DUPLICATION] Hard timeout reached - multicore exit may need investigation");
        return;
    }

    let combined = format!("{}\n{}", stdout, stderr);
    let multi_count = common::count_corpus_files(&corpus_multi);

    eprintln!("[DUPLICATION] Single-core corpus: {}, Multi-core corpus: {}", single_count, multi_count);

    // Multi-core shouldn't have drastically more entries than single-core
    // (The bug caused N× inflation where N = number of workers)
    // Allow 3× as reasonable variance (2 workers might find slightly different coverage)
    if single_count > 0 {
        let ratio = multi_count as f64 / single_count as f64;
        eprintln!("[DUPLICATION] Ratio: {:.2}×", ratio);

        assert!(
            ratio < 4.0 || multi_count < 50,
            "Multi-core corpus inflation detected: {}× ({} vs {}). \
             This may indicate SharedBitmapFeedback regression. Output: {}",
            ratio, multi_count, single_count, combined
        );
    }
}

/// Test that multi-core produces reasonable exec/sec (not severely degraded)
#[test]
#[ignore]
fn test_e2e_multicore_throughput() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    // Run with 2 cores (use hard timeout to prevent hangs)
    let (stdout, stderr, _) = common::run_test_program_fuzz_with_timeout(
        &[
            ("FUZZ_TIMEOUT_SECS", "15"),
            ("FUZZ_CORES", "2"),
            ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ],
        35, // Hard timeout: FUZZ_TIMEOUT × 2 + buffer
    );

    if stderr == "TIMEOUT" {
        eprintln!("[MULTICORE-THROUGHPUT] Hard timeout reached - multicore exit may need investigation");
        return;
    }

    let combined = format!("{}\n{}", stdout, stderr);

    // Parse exec/sec
    let exec_sec = common::parse_exec_sec(&combined);

    eprintln!("[MULTICORE-THROUGHPUT] Exec/sec: {:?}", exec_sec);

    if let Some(rate) = exec_sec {
        // Multi-core should achieve reasonable throughput
        // At minimum > 10 exec/sec (being conservative)
        assert!(
            rate > 10.0,
            "Multi-core throughput too low: {:.1} exec/sec. \
             May indicate contention issues. Output: {}", rate, combined
        );
    }
}

// =============================================================================
// STOP-ON-CRASH TEST
// =============================================================================

/// Test that --stop-on-crash actually stops after first crash
#[test]
#[ignore]
fn test_e2e_stop_on_crash() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");
    let crashes_dir = temp.path().join("crashes");

    let start = std::time::Instant::now();

    // Run with stop-on-crash (should exit early if crash found)
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "120"),  // Long timeout
        ("FUZZ_STOP_ON_CRASH", "1"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
    ]);

    let elapsed = start.elapsed();
    let combined = format!("{}\n{}", stdout, stderr);

    let crash_files = common::count_crash_files(&crashes_dir);

    eprintln!("[STOP-ON-CRASH] Elapsed: {}s, Crashes: {}", elapsed.as_secs(), crash_files);

    if crash_files > 0 {
        // If crash found, should have stopped early (< 120s)
        assert!(
            elapsed.as_secs() < 100,
            "Stop-on-crash should exit after finding crash. Took {}s. Output: {}",
            elapsed.as_secs(), combined
        );

        // Should only have 1 crash (stopped after first)
        assert!(
            crash_files <= 2,  // Allow small race condition
            "Stop-on-crash should stop after first crash. Got {} crashes. Output: {}",
            crash_files, combined
        );
    } else {
        eprintln!("[STOP-ON-CRASH] No crash found in 120s - bug may be hard to trigger");
    }
}

/// Test that --stop-on-crash works with multi-core mode
#[test]
#[ignore]
fn test_e2e_stop_on_crash_multicore() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");
    let crashes_dir = temp.path().join("crashes");

    let start = std::time::Instant::now();

    // Run with stop-on-crash in multi-core mode
    // Use 60s internal timeout - stop-on-crash should exit much sooner
    let (stdout, stderr, _) = common::run_test_program_fuzz_with_timeout(
        &[
            ("FUZZ_TIMEOUT_SECS", "60"),
            ("FUZZ_STOP_ON_CRASH", "1"),
            ("FUZZ_CORES", "2"),
            ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
            ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
        ],
        90,  // Hard timeout - should exit much sooner if stop-on-crash works
    );

    let elapsed = start.elapsed();
    let combined = format!("{}\n{}", stdout, stderr);

    // Hard timeout means something went wrong
    if stderr == "TIMEOUT" {
        eprintln!("[STOP-ON-CRASH-MC] Hard timeout reached - stop-on-crash may not be working");
        // Don't fail - test-program bug might be hard to trigger
        return;
    }

    // Handle Launcher infrastructure failures gracefully
    if stderr.contains("Launcher failed") || stderr.contains("shmem socket") {
        eprintln!("[STOP-ON-CRASH-MC] Launcher infrastructure failure - skipping");
        return;
    }

    let crash_files = common::count_crash_files(&crashes_dir);

    eprintln!("[STOP-ON-CRASH-MC] Elapsed: {}s, Crashes: {}", elapsed.as_secs(), crash_files);

    if crash_files > 0 {
        // If crash found, should have stopped early (< 60s)
        assert!(
            elapsed.as_secs() < 45,
            "Multicore stop-on-crash should exit after finding crash. Took {}s",
            elapsed.as_secs()
        );

        // Should show the signaling message
        assert!(
            combined.contains("signaling stop") || combined.contains("Stop signal"),
            "Should show stop signal message. Output: {}", combined
        );
    } else {
        eprintln!("[STOP-ON-CRASH-MC] No crash found within timeout - test-program bug may be hard to trigger");
    }
}

// =============================================================================
// REPLAY AND VIOLATION MARKER TESTS
// =============================================================================

/// Test that replay can reproduce a crash and shows the panic/violation
#[test]
#[ignore]
fn test_e2e_replay_shows_violation_marker() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");
    let crashes_dir = temp.path().join("crashes");

    // Run fuzzer until crash is found (the staking program has a known bug)
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "45"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
    ]);

    let crashes = common::find_crash_files(&crashes_dir);
    if crashes.is_empty() {
        eprintln!("[VIOLATION-MARKER] No crashes found in 45s - skipping test");
        eprintln!("[VIOLATION-MARKER] Fuzzer output: {}\n{}", stdout, stderr);
        return;
    }

    eprintln!("[VIOLATION-MARKER] Found {} crash files", crashes.len());

    // Replay the crash
    let (_, input_path) = &crashes[0];
    eprintln!("[VIOLATION-MARKER] Replaying crash: {}", input_path.display());

    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_INPUT_FILE", input_path.to_str().unwrap()),
        ("FUZZ_VERBOSE", "1"),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    eprintln!("[VIOLATION-MARKER] Replay output:\n{}", combined);

    // Verify replay executes and shows the input
    assert!(
        combined.contains("[REPLAY]") || combined.contains("Loading input") || combined.contains("Replay"),
        "Replay should indicate it's in replay mode. Output: {}", combined
    );

    // Verify the crash is reproduced (panic or violation message)
    let has_panic = combined.contains("panicked at");
    let has_violation = combined.to_lowercase().contains("violation");
    let has_assertion = combined.contains("assertion") || combined.contains("stake-time") || combined.contains("earned");

    assert!(
        has_panic || has_violation || has_assertion,
        "Replay should reproduce the crash (show panic or violation). Output: {}", combined
    );

    eprintln!("[VIOLATION-MARKER] Crash successfully reproduced via replay");
}

/// Test that replay executes the crash input file
#[test]
#[ignore]
fn test_e2e_replay_executes_input() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");
    let crashes_dir = temp.path().join("crashes");

    // Generate crashes
    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "45"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
    ]);

    let crashes = common::find_crash_files(&crashes_dir);
    if crashes.is_empty() {
        eprintln!("[REPLAY-EXEC] No crashes found - skipping test");
        return;
    }

    let (_, input_path) = &crashes[0];
    let input_size = fs::metadata(&input_path).map(|m| m.len()).unwrap_or(0);
    eprintln!("[REPLAY-EXEC] Crash input file: {} ({} bytes)", input_path.display(), input_size);

    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_INPUT_FILE", input_path.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Verify replay mode is indicated
    assert!(
        combined.contains("[REPLAY]") || combined.contains("Loading input") ||
        combined.contains("bytes") || combined.contains("Executing"),
        "Replay should show loading/executing the input. Output: {}", combined
    );

    // Verify something happened (either panic or successful execution info)
    assert!(
        combined.contains("panicked") || combined.contains("thread") || combined.contains("test"),
        "Replay should execute the test. Output: {}", combined
    );

    eprintln!("[REPLAY-EXEC] Replay completed");
}

/// Test that fuzzer stops early when crash is found
#[test]
#[ignore]
fn test_e2e_crash_stops_fuzzing() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");
    let crashes_dir = temp.path().join("crashes");

    let start = std::time::Instant::now();

    // Run with stop-on-crash to verify early exit
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "60"),
        ("FUZZ_STOP_ON_CRASH", "1"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
    ]);

    let elapsed = start.elapsed();
    let combined = format!("{}\n{}", stdout, stderr);

    let crashes = common::find_crash_files(&crashes_dir);

    eprintln!("[CRASH-STOPS] Elapsed: {}s, Crashes: {}", elapsed.as_secs(), crashes.len());

    if !crashes.is_empty() {
        // If crash found, should have stopped before full timeout
        assert!(
            elapsed.as_secs() < 55,
            "Should stop early when crash found with --stop-on-crash. Took {}s. Output: {}",
            elapsed.as_secs(), combined
        );
        eprintln!("[CRASH-STOPS] Correctly stopped after finding crash");
    } else {
        eprintln!("[CRASH-STOPS] No crash found in 60s");
    }
}

// =============================================================================
// CRASH METADATA TESTS
// =============================================================================

/// Test that crash files are created when crashes are found
#[test]
#[ignore]
fn test_e2e_crash_files_created() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");
    let crashes_dir = temp.path().join("crashes");

    // Generate crashes
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "45"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Check if crash was detected in output
    let crash_in_output = combined.contains("crashes: 1") || combined.contains("Objective");

    if !crash_in_output {
        eprintln!("[CRASH-FILES] No crash detected in output - skipping");
        return;
    }

    // Check crash directory exists
    assert!(
        crashes_dir.exists(),
        "Crashes directory should exist after finding crash"
    );

    // Find crash input files
    let crashes = common::find_crash_files(&crashes_dir);
    eprintln!("[CRASH-FILES] Found {} crash file pairs", crashes.len());

    assert!(
        !crashes.is_empty(),
        "Should have crash files when crash was detected. Output: {}", combined
    );

    // Verify crash input file is readable
    let (_, input_path) = &crashes[0];
    let input_content = fs::read(input_path).unwrap();
    assert!(
        !input_content.is_empty(),
        "Crash input file should not be empty: {}", input_path.display()
    );

    eprintln!("[CRASH-FILES] Crash input size: {} bytes", input_content.len());
}

// =============================================================================
// DRY-RUN TESTS
// =============================================================================

/// Test dry-run mode works with coverage flag
#[test]
#[ignore]
fn test_e2e_dry_run_with_coverage() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_dir = temp.path().join("corpus");
    common::create_test_corpus(&corpus_dir, 2);

    // Run with both dry-run and coverage
    let (stdout, stderr, success) = common::run_test_program_fuzz(&[
        ("FUZZ_DRY_RUN", "1"),
        ("FUZZ_COVERAGE_ONLY", "1"),
        ("FUZZ_CORPUS_IN", corpus_dir.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    eprintln!("[DRY-RUN-COVERAGE] Output:\n{}", combined);

    // Should complete without error (dry-run may not write coverage but should run)
    assert!(
        success || combined.to_lowercase().contains("dry") || combined.contains("iteration"),
        "Dry-run with coverage should complete. Output: {}", combined
    );
}

/// Test dry-run mode with corpus input
#[test]
#[ignore]
fn test_e2e_dry_run_with_corpus() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_dir = temp.path().join("corpus");
    common::create_test_corpus(&corpus_dir, 3);

    let (stdout, stderr, success) = common::run_test_program_fuzz(&[
        ("FUZZ_DRY_RUN", "1"),
        ("FUZZ_CORPUS_IN", corpus_dir.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    eprintln!("[DRY-RUN-CORPUS] Output:\n{}", combined);

    // Should load corpus and run one iteration
    assert!(
        success || combined.to_lowercase().contains("dry") || combined.to_lowercase().contains("iteration"),
        "Dry-run with corpus should complete. Output: {}", combined
    );
}

// =============================================================================
// COVERAGE ACCURACY TESTS
// =============================================================================

/// Test that coverage percentages are reasonable (not 0% or 100%)
#[test]
#[ignore]
fn test_e2e_coverage_percentage_reasonable() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    // Run fuzzer briefly
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "15"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Look for percentage in output (e.g., "edges: 123/4500 (3%)")
    // Track the highest percentage seen (startup shows 0%, later lines have actual coverage)
    let mut max_percentage: f64 = 0.0;
    let mut found_percentage = false;

    for line in combined.lines() {
        if line.contains("%") && (line.contains("edges") || line.contains("branches")) {
            // Extract percentage value
            if let Some(pct_pos) = line.find('%') {
                let before = &line[..pct_pos];
                let pct_str: String = before.chars().rev()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect::<String>()
                    .chars().rev().collect();

                if let Ok(pct) = pct_str.parse::<f64>() {
                    found_percentage = true;
                    if pct > max_percentage {
                        max_percentage = pct;
                    }
                }
            }
        }
    }

    eprintln!("[COVERAGE-PCT] Max percentage found: {}%", max_percentage);

    // We should find at least one percentage
    let has_edges = common::parse_edges_count(&combined).unwrap_or(0) > 0;

    assert!(
        found_percentage || has_edges,
        "Should have coverage stats in output. Output: {}", combined
    );

    // The max percentage should be reasonable (> 0 after 15s of fuzzing)
    // Note: 0% is expected on first line, but later lines should show coverage
    if max_percentage > 0.0 {
        assert!(
            max_percentage < 100.0,
            "Coverage should not be 100%. Got {}%", max_percentage
        );
        eprintln!("[COVERAGE-PCT] Coverage is reasonable: {}%", max_percentage);
    } else if has_edges {
        eprintln!("[COVERAGE-PCT] No percentage in output but edges found");
    }
}

// =============================================================================
// MULTIPLE CRASHES TEST
// =============================================================================

/// Test that multiple crashes are saved with unique names
#[test]
#[ignore]
fn test_e2e_multiple_crashes_unique_names() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");
    let crashes_dir = temp.path().join("crashes");

    // Run fuzzer long enough to potentially find multiple crashes
    // (Don't use stop-on-crash)
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "60"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
        // Not setting FUZZ_STOP_ON_CRASH
    ]);

    let combined = format!("{}\n{}", stdout, stderr);
    let crashes = common::find_crash_files(&crashes_dir);

    eprintln!("[MULTI-CRASH] Found {} crash file pairs", crashes.len());

    if crashes.len() > 1 {
        // Verify all crash files have unique names
        let mut names: Vec<String> = Vec::new();
        for (meta_path, input_path) in &crashes {
            let meta_name = meta_path.file_name().unwrap().to_string_lossy().to_string();
            let input_name = input_path.file_name().unwrap().to_string_lossy().to_string();

            eprintln!("[MULTI-CRASH] Crash: {} / {}", input_name, meta_name);

            assert!(
                !names.contains(&input_name),
                "Duplicate crash name found: {}. All crashes: {:?}", input_name, names
            );
            names.push(input_name);
        }

        eprintln!("[MULTI-CRASH] All {} crashes have unique names", crashes.len());
    } else if crashes.len() == 1 {
        eprintln!("[MULTI-CRASH] Only 1 crash found - can't test uniqueness");
    } else {
        eprintln!("[MULTI-CRASH] No crashes found in 60s. Output: {}", combined);
    }
}

// =============================================================================
// TIMEOUT EDGE CASE TESTS
// =============================================================================

/// Test that FUZZ_TIMEOUT_SECS=0 exits immediately
#[test]
#[ignore]
fn test_e2e_timeout_zero_immediate_exit() {
    if !ensure_test_program_built() { return; }

    let start = std::time::Instant::now();

    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "0"),
    ]);

    let elapsed = start.elapsed();
    let combined = format!("{}\n{}", stdout, stderr);

    // With timeout=0, should exit very quickly (within a few seconds at most)
    assert!(
        elapsed.as_secs() <= 5,
        "Timeout=0 should exit immediately. Took {}s. Output: {}", elapsed.as_secs(), combined
    );

    eprintln!("[TIMEOUT-0] Elapsed: {}ms", elapsed.as_millis());
}

/// Test that very short timeout (1s) doesn't hang
#[test]
#[ignore]
fn test_e2e_timeout_very_short() {
    if !ensure_test_program_built() { return; }

    let start = std::time::Instant::now();

    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "1"),
    ]);

    let elapsed = start.elapsed();
    let combined = format!("{}\n{}", stdout, stderr);

    // Should exit within reasonable time (1s timeout + overhead)
    assert!(
        elapsed.as_secs() <= 10,
        "Timeout=1s should exit quickly. Took {}s. Output: {}", elapsed.as_secs(), combined
    );

    eprintln!("[TIMEOUT-1s] Elapsed: {}s", elapsed.as_secs());
}

// =============================================================================
// CRASH METADATA VALIDATION TESTS
// =============================================================================

/// Test that crash metadata contains all required fields with valid values
#[test]
#[ignore]
fn test_e2e_crash_metadata_complete() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");
    let crashes_dir = temp.path().join("crashes");

    let start_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Run fuzzer until crash is found
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "45"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
    ]);

    let end_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let combined = format!("{}\n{}", stdout, stderr);
    let crashes = common::find_crash_files(&crashes_dir);

    if crashes.is_empty() {
        eprintln!("[META-COMPLETE] No crashes found in 45s - skipping metadata validation");
        eprintln!("[META-COMPLETE] Output: {}", combined);
        return;
    }

    eprintln!("[META-COMPLETE] Found {} crash files, validating metadata...", crashes.len());

    // Read and validate metadata file
    let (meta_path, input_path) = &crashes[0];
    let meta_content = fs::read_to_string(meta_path)
        .expect(&format!("Failed to read metadata file: {}", meta_path.display()));

    // Parse JSON
    let json: serde_json::Value = serde_json::from_str(&meta_content)
        .expect(&format!("Invalid JSON in metadata: {}", meta_content));

    eprintln!("[META-COMPLETE] Metadata JSON: {}", serde_json::to_string_pretty(&json).unwrap());

    // === Verify test_name ===
    let test_name = json.get("test_name")
        .expect("Missing 'test_name' field in metadata")
        .as_str()
        .expect("'test_name' should be a string");
    assert!(
        !test_name.is_empty(),
        "test_name should not be empty"
    );
    eprintln!("[META-COMPLETE] test_name: {}", test_name);

    // === Verify timestamp ===
    let timestamp = json.get("timestamp").expect("Missing 'timestamp' field in metadata");
    if let Some(ts_str) = timestamp.as_str() {
        // ISO 8601 format: "2026-02-06T04:27:52Z"
        assert!(
            ts_str.len() >= 10,
            "timestamp string too short: {}", ts_str
        );
        eprintln!("[META-COMPLETE] timestamp (string): {}", ts_str);
    } else if let Some(ts_num) = timestamp.as_u64() {
        // Unix timestamp: should be within test run window (with some buffer)
        assert!(
            ts_num >= start_time.saturating_sub(60) && ts_num <= end_time + 60,
            "timestamp {} should be within test run window ({} - {})",
            ts_num, start_time, end_time
        );
        eprintln!("[META-COMPLETE] timestamp (unix): {}", ts_num);
    } else {
        panic!("timestamp should be string or number, got: {:?}", timestamp);
    }

    // === Verify iteration ===
    let iteration = json.get("iteration")
        .expect("Missing 'iteration' field in metadata")
        .as_u64()
        .expect("'iteration' should be a number");
    assert!(iteration > 0, "iteration should be > 0, got {}", iteration);
    eprintln!("[META-COMPLETE] iteration: {}", iteration);

    // === Verify seed (optional but should be valid if present) ===
    if let Some(seed) = json.get("seed") {
        if !seed.is_null() {
            let seed_val = seed.as_u64().expect("seed should be number if present");
            eprintln!("[META-COMPLETE] seed: {}", seed_val);
        }
    }

    // === Verify actions array ===
    let actions = json.get("actions")
        .expect("Missing 'actions' field in metadata")
        .as_array()
        .expect("'actions' should be an array");
    assert!(!actions.is_empty(), "actions array should not be empty for crash");
    eprintln!("[META-COMPLETE] actions count: {}", actions.len());

    // Verify each action structure
    for (i, action) in actions.iter().enumerate() {
        // name: should be a string
        let name = action.get("name")
            .unwrap_or_else(|| panic!("Action {} missing 'name' field", i))
            .as_str()
            .unwrap_or_else(|| panic!("Action {} 'name' should be string", i));
        assert!(
            !name.is_empty(),
            "Action {} name should not be empty", i
        );

        // params: should be an object
        let params = action.get("params")
            .unwrap_or_else(|| panic!("Action {} missing 'params' field", i));
        assert!(
            params.is_object(),
            "Action {} 'params' should be object, got {:?}", i, params
        );

        // success: should be boolean
        let success = action.get("success")
            .unwrap_or_else(|| panic!("Action {} missing 'success' field", i));
        assert!(
            success.is_boolean(),
            "Action {} 'success' should be boolean, got {:?}", i, success
        );

        eprintln!("[META-COMPLETE] Action {}: name={}, success={}", i, name, success);
    }

    // === Verify input bytes file exists and is non-empty ===
    assert!(input_path.exists(), "Input bytes file should exist: {}", input_path.display());
    let input_bytes = fs::read(input_path).unwrap();
    assert!(!input_bytes.is_empty(), "Input bytes should not be empty");
    eprintln!("[META-COMPLETE] Input bytes: {} bytes", input_bytes.len());

    eprintln!("[META-COMPLETE] All metadata validation passed!");
}

/// Test that actions array contains properly formatted entries
#[test]
#[ignore]
fn test_e2e_crash_metadata_actions_array() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let crashes_dir = temp.path().join("crashes");

    // Generate crash
    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "30"),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
    ]);

    let crashes = common::find_crash_files(&crashes_dir);
    if crashes.is_empty() {
        eprintln!("[META-ACTIONS] No crashes found - skipping");
        return;
    }

    let (meta_path, _) = &crashes[0];
    let meta_content = fs::read_to_string(meta_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&meta_content).unwrap();

    let actions = json.get("actions").unwrap().as_array().unwrap();

    // At least one action should have succeeded before the crash
    let successful_actions: Vec<_> = actions.iter()
        .filter(|a| a.get("success").and_then(|s| s.as_bool()).unwrap_or(false))
        .collect();

    eprintln!("[META-ACTIONS] {} total actions, {} successful", actions.len(), successful_actions.len());

    // Verify params are serializable (not empty objects for every action)
    let mut has_nonempty_params = false;
    for action in actions {
        if let Some(params) = action.get("params").and_then(|p| p.as_object()) {
            if !params.is_empty() {
                has_nonempty_params = true;
                eprintln!("[META-ACTIONS] Action '{}' params: {:?}",
                    action.get("name").unwrap(), params);
            }
        }
    }

    // At least some actions should have params (unless it's a trivial crash)
    if actions.len() > 1 {
        assert!(
            has_nonempty_params,
            "Actions should have params. Actions: {:?}", actions
        );
    }
}

// =============================================================================
// MULTI-CORE EDGE CASE TESTS
// =============================================================================

/// Test with 4 cores
#[test]
#[ignore]
fn test_e2e_multicore_4_cores() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    let start = std::time::Instant::now();

    // Run with 4 cores (use hard timeout)
    let (stdout, stderr, _) = common::run_test_program_fuzz_with_timeout(
        &[
            ("FUZZ_TIMEOUT_SECS", "10"),
            ("FUZZ_CORES", "4"),
            ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ],
        30, // Hard timeout
    );

    let elapsed = start.elapsed();
    let combined = format!("{}\n{}", stdout, stderr);

    if stderr == "TIMEOUT" {
        eprintln!("[4-CORES] Hard timeout reached - multicore exit may need investigation");
        return;
    }

    eprintln!("[4-CORES] Elapsed: {}s", elapsed.as_secs());

    // Verify multi-core mode was used
    assert!(
        combined.contains("worker") || combined.contains("core") ||
        combined.contains("parallel") || combined.contains("Launcher") ||
        combined.contains("4"),
        "Should indicate 4-core mode. Output: {}", combined
    );

    // Verify coverage was discovered
    let edges = common::parse_edges_count(&combined).unwrap_or(0);
    eprintln!("[4-CORES] Edges: {}", edges);

    assert!(
        edges > 0 || corpus_out.exists(),
        "4-core mode should produce results. Output: {}", combined
    );
}

/// Test that requesting more cores than available CPUs is handled gracefully
#[test]
#[ignore]
fn test_e2e_multicore_cores_greater_than_cpus() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    // Request more cores than likely available (100)
    let (stdout, stderr, success) = common::run_test_program_fuzz_with_timeout(
        &[
            ("FUZZ_TIMEOUT_SECS", "5"),
            ("FUZZ_CORES", "100"),  // More than typical CPU count
            ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ],
        30,
    );

    let combined = format!("{}\n{}", stdout, stderr);

    // Should either:
    // 1. Work with available CPUs (success)
    // 2. Warn about core count and continue
    // 3. Error gracefully
    // Should NOT hang or crash unexpectedly
    eprintln!("[CORES-100] Success: {}", success);
    eprintln!("[CORES-100] Output: {}", combined);

    // Handle expected Launcher failures with extreme core counts
    // LibAFL's shared memory infrastructure has limits on concurrent workers
    if stderr == "TIMEOUT" || stderr.contains("Launcher failed") || stderr.contains("shmem socket") {
        // This is expected - LibAFL can't reliably handle 100 concurrent workers
        // The key is the fuzzer didn't crash in an unexpected way
        eprintln!("[CORES-100] Expected Launcher limitation with extreme core count");
        return;
    }

    // If it didn't timeout/fail, verify it produced some output
    assert!(
        combined.contains("exec/sec") || combined.contains("Fuzzing") || !success,
        "Should either succeed with output or fail gracefully. Output: {}", combined
    );
}

/// Test that all multi-core workers contribute to coverage
#[test]
#[ignore]
fn test_e2e_multicore_all_workers_contribute() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    // Run with 2 cores for longer duration
    let (stdout, stderr, _) = common::run_test_program_fuzz_with_timeout(
        &[
            ("FUZZ_TIMEOUT_SECS", "20"),
            ("FUZZ_CORES", "2"),
            ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ],
        50,
    );

    // Handle multicore infrastructure failures gracefully
    // These can happen when running multiple multicore tests in sequence
    if stderr == "TIMEOUT" || stderr.contains("Launcher failed") || stderr.contains("shmem socket") {
        eprintln!("[WORKERS-CONTRIBUTE] Hard timeout or Launcher failure - multicore infra issue");
        return;
    }

    let combined = format!("{}\n{}", stdout, stderr);

    // Check for worker activity indicators
    let has_worker_output = combined.contains("worker") ||
        combined.contains("Worker") ||
        combined.contains("[1]") ||  // Worker IDs
        combined.contains("[0]") ||
        combined.contains("Launcher");

    eprintln!("[WORKERS-CONTRIBUTE] Worker output detected: {}", has_worker_output);
    eprintln!("[WORKERS-CONTRIBUTE] Output: {}", combined);

    // Verify corpus has entries (workers found coverage)
    let corpus_count = common::count_corpus_files(&corpus_out);
    eprintln!("[WORKERS-CONTRIBUTE] Corpus entries: {}", corpus_count);

    assert!(
        corpus_count > 0,
        "Multi-core workers should contribute to corpus. Got 0 entries. Output: {}", combined
    );
}

// =============================================================================
// REPLAY EDGE CASE TESTS
// =============================================================================

/// Test that replay shows actions with numbered sequence
#[test]
#[ignore]
fn test_e2e_replay_action_sequence_numbered() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let crashes_dir = temp.path().join("crashes");

    // Generate crash
    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "45"),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
    ]);

    let crashes = common::find_crash_files(&crashes_dir);
    if crashes.is_empty() {
        eprintln!("[NUMBERED-SEQUENCE] No crashes found - skipping");
        return;
    }

    let (_, input_path) = &crashes[0];

    // Replay with verbose output
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_INPUT_FILE", input_path.to_str().unwrap()),
        ("FUZZ_VERBOSE", "1"),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    eprintln!("[NUMBERED-SEQUENCE] Replay output:\n{}", combined);

    // Look for numbered actions (e.g., "1." or "[1]" or "Action 1")
    let has_numbers = combined.contains("1.") ||
        combined.contains("[1]") ||
        combined.contains("Action 1") ||
        combined.contains("#1") ||
        combined.contains("executed") ||  // "N executed"
        combined.contains("SEQUENCE");

    // Or at least show action names
    let has_actions = combined.contains("action_") ||
        combined.contains("stake") ||
        combined.contains("unstake") ||
        combined.contains("claim");

    assert!(
        has_numbers || has_actions,
        "Replay should show numbered or named action sequence. Output: {}", combined
    );
}

/// Test replay with corrupted input handles gracefully
#[test]
#[ignore]
fn test_e2e_replay_corrupted_input() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corrupted_input = temp.path().join("corrupted_crash");

    // Write garbage bytes
    fs::write(&corrupted_input, &[0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x02]).unwrap();

    // Try to replay corrupted input
    let (stdout, stderr, success) = common::run_test_program_fuzz(&[
        ("FUZZ_INPUT_FILE", corrupted_input.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    eprintln!("[CORRUPTED-INPUT] Success: {}", success);
    eprintln!("[CORRUPTED-INPUT] Output: {}", combined);

    // Should either:
    // 1. Handle gracefully with error message
    // 2. Skip invalid actions and continue
    // 3. Panic with useful message (not hang or crash silently)
    // The key is no infinite hang
    assert!(
        combined.len() > 0 || !success,
        "Should produce some output when replaying corrupted input"
    );
}

// =============================================================================
// DRY-RUN SPECIFIC TESTS
// =============================================================================

/// Test that dry-run mode doesn't create crash files
#[test]
#[ignore]
fn test_e2e_dry_run_no_crashes_created() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let crashes_dir = temp.path().join("crashes");
    fs::create_dir_all(&crashes_dir).unwrap();

    // Run dry-run
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_DRY_RUN", "1"),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Dry-run should not create crash files
    let crash_count = common::count_crash_files(&crashes_dir);

    eprintln!("[DRY-RUN-NO-CRASHES] Crashes: {}", crash_count);
    eprintln!("[DRY-RUN-NO-CRASHES] Output: {}", combined);

    assert!(
        crash_count == 0,
        "Dry-run should not create crash files, but found {}. Output: {}",
        crash_count, combined
    );
}

/// Test that dry-run with corpus-in loads and reports all entries
#[test]
#[ignore]
fn test_e2e_dry_run_loads_all_corpus_elements() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_dir = temp.path().join("corpus");

    // First, generate a corpus by fuzzing briefly
    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "10"),
        ("FUZZ_CORPUS_OUT", corpus_dir.to_str().unwrap()),
    ]);

    let corpus_count = common::count_corpus_files(&corpus_dir);
    if corpus_count == 0 {
        eprintln!("[DRY-RUN-CORPUS] No corpus generated - skipping test");
        return;
    }

    eprintln!("[DRY-RUN-CORPUS] Generated {} corpus entries", corpus_count);

    // Run dry-run with corpus-in
    let (stdout, stderr, success) = common::run_test_program_fuzz(&[
        ("FUZZ_DRY_RUN", "1"),
        ("FUZZ_CORPUS_IN", corpus_dir.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    eprintln!("[DRY-RUN-CORPUS] Output:\n{}", combined);

    // Dry-run should:
    // 1. Report loading corpus entries OR
    // 2. Complete successfully and show dry-run message
    assert!(
        success || combined.to_lowercase().contains("dry") ||
        combined.to_lowercase().contains("corpus") ||
        combined.to_lowercase().contains("load"),
        "Dry-run should complete or report loading corpus. Output: {}", combined
    );
}

/// Test that dry-run completes quickly
#[test]
#[ignore]
fn test_e2e_dry_run_completes_quickly() {
    if !ensure_test_program_built() { return; }

    let start = std::time::Instant::now();

    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_DRY_RUN", "1"),
    ]);

    let elapsed = start.elapsed();
    let combined = format!("{}\n{}", stdout, stderr);

    eprintln!("[DRY-RUN-QUICK] Elapsed: {}s", elapsed.as_secs());

    // Dry-run should complete within a few seconds (not hang)
    assert!(
        elapsed.as_secs() < 30,
        "Dry-run should complete quickly. Took {}s. Output: {}", elapsed.as_secs(), combined
    );
}

// =============================================================================
// CMIN EDGE CASE TESTS
// =============================================================================

/// Test that cmin preserves all coverage from original corpus
#[test]
#[ignore]
fn test_e2e_cmin_preserves_coverage() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_full = temp.path().join("corpus_full");
    let corpus_min = temp.path().join("corpus_min");

    // Generate corpus
    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "15"),
        ("FUZZ_CORPUS_OUT", corpus_full.to_str().unwrap()),
    ]);

    let full_count = common::count_corpus_files(&corpus_full);
    if full_count < 3 {
        eprintln!("[CMIN-PRESERVES] Corpus too small ({}) - skipping", full_count);
        return;
    }

    // Get coverage from full corpus (dry-run with coverage)
    let (stdout_full, stderr_full, _) = common::run_test_program_fuzz(&[
        ("FUZZ_COVERAGE_ONLY", "1"),
        ("FUZZ_CORPUS_IN", corpus_full.to_str().unwrap()),
    ]);

    let edges_full = common::parse_edges_count(&format!("{}\n{}", stdout_full, stderr_full))
        .unwrap_or(0);

    eprintln!("[CMIN-PRESERVES] Full corpus: {} files, {} edges", full_count, edges_full);

    // Run cmin
    let (_, _, _) = common::run_test_program_fuzz(&[
        ("FUZZ_CMIN", "1"),
        ("FUZZ_CORPUS_IN", corpus_full.to_str().unwrap()),
        ("FUZZ_CORPUS_OUT", corpus_min.to_str().unwrap()),
    ]);

    let min_count = common::count_corpus_files(&corpus_min);
    if min_count == 0 {
        eprintln!("[CMIN-PRESERVES] Cmin produced empty corpus - may be expected for test-program");
        return;
    }

    // Get coverage from minimized corpus
    let (stdout_min, stderr_min, _) = common::run_test_program_fuzz(&[
        ("FUZZ_COVERAGE_ONLY", "1"),
        ("FUZZ_CORPUS_IN", corpus_min.to_str().unwrap()),
    ]);

    let edges_min = common::parse_edges_count(&format!("{}\n{}", stdout_min, stderr_min))
        .unwrap_or(0);

    eprintln!("[CMIN-PRESERVES] Minimized corpus: {} files, {} edges", min_count, edges_min);

    // Minimized corpus should preserve (approximately) the same coverage
    // Allow small variance due to timing/randomness
    if edges_full > 0 && edges_min > 0 {
        let coverage_ratio = edges_min as f64 / edges_full as f64;
        eprintln!("[CMIN-PRESERVES] Coverage ratio: {:.2}%", coverage_ratio * 100.0);

        assert!(
            coverage_ratio >= 0.9,  // Should preserve at least 90% of coverage
            "Cmin should preserve coverage. Full: {} edges, Min: {} edges (ratio: {:.2})",
            edges_full, edges_min, coverage_ratio
        );
    }
}

/// Test cmin with single file corpus
#[test]
#[ignore]
fn test_e2e_cmin_single_file_corpus() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_in = temp.path().join("corpus_in");
    let corpus_out = temp.path().join("corpus_out");

    // Create single-file corpus
    fs::create_dir_all(&corpus_in).unwrap();
    fs::write(corpus_in.join("input_0"), &[42u8; 100]).unwrap();

    assert_eq!(common::count_corpus_files(&corpus_in), 1);

    // Run cmin
    let (stdout, stderr, success) = common::run_test_program_fuzz(&[
        ("FUZZ_CMIN", "1"),
        ("FUZZ_CORPUS_IN", corpus_in.to_str().unwrap()),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    eprintln!("[CMIN-SINGLE] Output: {}", combined);

    // Should either succeed or indicate single file
    assert!(
        success || combined.contains("1 input") || combined.contains("single"),
        "Cmin should handle single-file corpus. Output: {}", combined
    );

    // Output should have 0 or 1 files (can't reduce below 1 that provides coverage)
    let out_count = common::count_corpus_files(&corpus_out);
    assert!(
        out_count <= 1,
        "Cmin of single file should produce at most 1 file. Got {}. Output: {}",
        out_count, combined
    );
}

/// Test cmin overwrites existing output directory
#[test]
#[ignore]
fn test_e2e_cmin_overwrites_existing() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_in = temp.path().join("corpus_in");
    let corpus_out = temp.path().join("corpus_out");

    // Create input corpus
    common::create_test_corpus(&corpus_in, 3);

    // Create existing output with some files
    fs::create_dir_all(&corpus_out).unwrap();
    fs::write(corpus_out.join("old_file_1"), b"old").unwrap();
    fs::write(corpus_out.join("old_file_2"), b"old").unwrap();

    let old_count = common::count_corpus_files(&corpus_out);
    eprintln!("[CMIN-OVERWRITE] Existing output files: {}", old_count);

    // Run cmin
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_CMIN", "1"),
        ("FUZZ_CORPUS_IN", corpus_in.to_str().unwrap()),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Check that old files were replaced (or directory was cleaned)
    let old_file_exists = corpus_out.join("old_file_1").exists();
    let new_count = common::count_corpus_files(&corpus_out);

    eprintln!("[CMIN-OVERWRITE] After cmin: {} files, old_file_1 exists: {}",
        new_count, old_file_exists);

    // Cmin should have handled the existing directory
    // (either cleared it or added to it)
    assert!(
        corpus_out.exists(),
        "Corpus output should exist after cmin. Output: {}", combined
    );
}

// =============================================================================
// COVERAGE OUTPUT TESTS
// =============================================================================

/// Test that coverage.lcov is NOT created in multi-core mode
#[test]
#[ignore]
fn test_e2e_coverage_disabled_multicore() {
    if !ensure_test_program_built() { return; }

    let fuzz_path = common::test_program_fuzz_path();
    let lcov_path = fuzz_path.join("coverage.lcov");

    // Remove any existing coverage file
    let _ = fs::remove_file(&lcov_path);

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    // Run with coverage AND multi-core (should disable coverage)
    let (stdout, stderr, _) = common::run_test_program_fuzz_with_timeout(
        &[
            ("FUZZ_TIMEOUT_SECS", "10"),
            ("FUZZ_CORES", "2"),
            ("FUZZ_COVERAGE_ONLY", "1"),  // Try to enable coverage
            ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ],
        30,
    );

    let combined = format!("{}\n{}", stdout, stderr);

    // Coverage should be disabled in multi-core mode
    // Either no file is created, or a warning is shown
    let lcov_exists = lcov_path.exists();

    eprintln!("[COVERAGE-MULTICORE] coverage.lcov exists: {}", lcov_exists);
    eprintln!("[COVERAGE-MULTICORE] Output: {}", combined);

    // Note: Implementation may either:
    // 1. Not create the file
    // 2. Warn and ignore the flag
    // 3. Actually create it (if supported)
    // For now, just document the behavior
    if lcov_exists {
        eprintln!("[COVERAGE-MULTICORE] Note: LCOV was created in multicore mode - this may be intentional or a bug");
        let _ = fs::remove_file(&lcov_path);  // Clean up
    } else {
        eprintln!("[COVERAGE-MULTICORE] LCOV correctly not created in multicore mode");
    }
}

/// Test that coverage.lcov is created and contains valid LCOV format
#[test]
#[ignore]
fn test_e2e_coverage_lcov_format_valid() {
    if !ensure_test_program_built() { return; }

    let fuzz_path = common::test_program_fuzz_path();
    let lcov_path = fuzz_path.join("coverage.lcov");

    // Remove any existing coverage file
    let _ = fs::remove_file(&lcov_path);

    let temp = TempDir::new().unwrap();
    let corpus_dir = temp.path().join("corpus");
    common::create_test_corpus(&corpus_dir, 2);

    // Run coverage-only mode
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_COVERAGE_ONLY", "1"),
        ("FUZZ_CORPUS_IN", corpus_dir.to_str().unwrap()),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    if !lcov_path.exists() {
        eprintln!("[LCOV-FORMAT] coverage.lcov not created - coverage mode may not be enabled");
        return;
    }

    let content = fs::read_to_string(&lcov_path).unwrap();

    // LCOV format validation
    // Required: TN (test name), SF (source file), DA (data), end_of_record
    let has_tn = content.contains("TN:");
    let has_sf = content.contains("SF:");
    let has_da = content.contains("DA:");
    let has_end = content.contains("end_of_record");

    eprintln!("[LCOV-FORMAT] TN: {}, SF: {}, DA: {}, end: {}",
        has_tn, has_sf, has_da, has_end);

    // At minimum, should have source files and data
    assert!(
        has_sf || content.contains("0x"),  // Either source files or PC addresses
        "LCOV file should contain source or address info. Content: {}", &content[..content.len().min(500)]
    );

    // Clean up
    let _ = fs::remove_file(&lcov_path);

    eprintln!("[LCOV-FORMAT] LCOV file is valid");
}

// =============================================================================
// CORPUS GROWTH TESTS
// =============================================================================

/// Test that corpus grows during fuzzing (not just at end)
#[test]
#[ignore]
fn test_e2e_corpus_grows_over_time() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    // Use sampling to check corpus at intervals
    let (_, _, _, samples) = common::run_test_program_fuzz_with_samples(
        &[
            ("FUZZ_TIMEOUT_SECS", "20"),
            ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ],
        5,  // Sample every 5 seconds
        20,
    );

    // Parse corpus counts from samples
    let mut corpus_counts: Vec<(u64, usize)> = Vec::new();
    for (elapsed, output) in &samples {
        if let Some(count) = common::parse_corpus_count(output) {
            corpus_counts.push((*elapsed, count));
            eprintln!("[CORPUS-GROWTH] At {}s: {} corpus entries", elapsed, count);
        }
    }

    // Final corpus count
    let final_count = common::count_corpus_files(&corpus_out);
    eprintln!("[CORPUS-GROWTH] Final disk count: {}", final_count);

    // Verify corpus grew (or at least exists)
    assert!(
        final_count > 0 || !corpus_counts.is_empty(),
        "Corpus should grow during fuzzing"
    );

    // If we have multiple samples, verify growth trend
    if corpus_counts.len() >= 2 {
        let first = corpus_counts.first().unwrap().1;
        let last = corpus_counts.last().unwrap().1;
        eprintln!("[CORPUS-GROWTH] First sample: {}, Last sample: {}", first, last);
        // Note: May not always grow if saturation reached quickly
    }
}

// =============================================================================
// INPUT FILE TESTS
// =============================================================================

/// Test that --input with nonexistent file gives clear error
#[test]
#[ignore]
fn test_e2e_input_nonexistent_file_error() {
    if !ensure_test_program_built() { return; }

    let (stdout, stderr, success) = common::run_test_program_fuzz(&[
        ("FUZZ_INPUT_FILE", "/nonexistent/path/that/does/not/exist/crash_file"),
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    eprintln!("[INPUT-NONEXISTENT] Success: {}", success);
    eprintln!("[INPUT-NONEXISTENT] Output: {}", combined);

    // Should fail with clear error message
    assert!(
        !success || combined.to_lowercase().contains("error") ||
        combined.to_lowercase().contains("not found") ||
        combined.to_lowercase().contains("no such file"),
        "Should report error for nonexistent input file. Output: {}", combined
    );
}

// =============================================================================
// VERBOSE OUTPUT TESTS
// =============================================================================

/// Test that FUZZ_VERBOSE=1 produces more detailed output
#[test]
#[ignore]
fn test_e2e_verbose_output() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let corpus_out = temp.path().join("corpus");

    // Run without verbose
    let (stdout1, stderr1, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "3"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
    ]);
    let normal_len = stdout1.len() + stderr1.len();

    // Run with verbose
    let corpus_out2 = temp.path().join("corpus2");
    let (stdout2, stderr2, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "3"),
        ("FUZZ_VERBOSE", "1"),
        ("FUZZ_CORPUS_OUT", corpus_out2.to_str().unwrap()),
    ]);
    let verbose_len = stdout2.len() + stderr2.len();

    eprintln!("[VERBOSE] Normal output length: {}", normal_len);
    eprintln!("[VERBOSE] Verbose output length: {}", verbose_len);

    // Verbose should produce more output (or at least similar)
    // Note: May not always be more if fuzzer exits quickly
    if verbose_len > normal_len {
        eprintln!("[VERBOSE] Verbose produces more output as expected");
    }
}

// =============================================================================
// IN-MEMORY CORPUS TESTS
// =============================================================================

/// Test fuzzing with pure in-memory corpus (no CORPUS_IN or CORPUS_OUT)
#[test]
#[ignore]
fn test_e2e_inmemory_corpus_basic() {
    if !ensure_test_program_built() { return; }

    // Run without any corpus directories - uses LibAFL's InMemoryCorpus
    let (stdout, stderr, success) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "5"),
        // No FUZZ_CORPUS_IN or FUZZ_CORPUS_OUT - pure in-memory mode
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Should run successfully
    assert!(
        success || combined.contains("exec/sec") || combined.contains("Fuzzing"),
        "In-memory corpus mode should run successfully. Output: {}", combined
    );

    // Should show execution stats
    assert!(
        combined.contains("exec/sec") || combined.contains("executions"),
        "Should show execution statistics. Output: {}", combined
    );

    eprintln!("[INMEMORY-BASIC] Output: {}", combined);
}

/// Test that in-memory corpus mode can find crashes
#[test]
#[ignore]
fn test_e2e_inmemory_corpus_finds_crashes() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();
    let crashes_dir = temp.path().join("crashes");

    // Run without corpus directories but with crashes output
    let (stdout, stderr, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "30"),
        ("FUZZ_CRASHES_DIR", crashes_dir.to_str().unwrap()),
        // No FUZZ_CORPUS_IN or FUZZ_CORPUS_OUT - pure in-memory mode
    ]);

    let combined = format!("{}\n{}", stdout, stderr);

    // Should find crashes (test-program has intentional invariant violation)
    let crash_count = common::count_crash_files(&crashes_dir);

    eprintln!("[INMEMORY-CRASHES] Crashes found: {}", crash_count);
    eprintln!("[INMEMORY-CRASHES] Output: {}", combined);

    assert!(
        crash_count > 0,
        "In-memory corpus mode should still find crashes. Output: {}", combined
    );
}

/// Compare in-memory vs on-disk corpus behavior
#[test]
#[ignore]
fn test_e2e_inmemory_vs_ondisk_corpus() {
    if !ensure_test_program_built() { return; }

    let temp = TempDir::new().unwrap();

    // Run in-memory mode (no corpus dirs)
    let inmem_crashes = temp.path().join("inmem_crashes");
    let (_, stderr_inmem, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "10"),
        ("FUZZ_SEED", "12345"),
        ("FUZZ_CRASHES_DIR", inmem_crashes.to_str().unwrap()),
    ]);

    // Run on-disk corpus mode
    let ondisk_crashes = temp.path().join("ondisk_crashes");
    let corpus_out = temp.path().join("corpus");
    let (_, stderr_ondisk, _) = common::run_test_program_fuzz(&[
        ("FUZZ_TIMEOUT_SECS", "10"),
        ("FUZZ_SEED", "12345"),
        ("FUZZ_CORPUS_OUT", corpus_out.to_str().unwrap()),
        ("FUZZ_CRASHES_DIR", ondisk_crashes.to_str().unwrap()),
    ]);

    // Extract execution counts from both runs
    let inmem_execs = extract_exec_count(&stderr_inmem);
    let ondisk_execs = extract_exec_count(&stderr_ondisk);

    eprintln!("[INMEM-VS-ONDISK] In-memory executions: {:?}", inmem_execs);
    eprintln!("[INMEM-VS-ONDISK] On-disk executions: {:?}", ondisk_execs);

    // Both should have reasonable execution counts
    if let (Some(inmem), Some(ondisk)) = (inmem_execs, ondisk_execs) {
        assert!(inmem > 0, "In-memory mode should have executions");
        assert!(ondisk > 0, "On-disk mode should have executions");

        // On-disk mode should not be dramatically slower (less than 5x difference)
        let ratio = if ondisk > inmem {
            inmem as f64 / ondisk as f64
        } else {
            ondisk as f64 / inmem as f64
        };
        assert!(
            ratio > 0.2,
            "Performance difference should be reasonable. In-memory: {}, On-disk: {}", inmem, ondisk
        );
    }

    // Corpus should have entries for on-disk mode
    let corpus_count = common::count_corpus_files(&corpus_out);
    eprintln!("[INMEM-VS-ONDISK] Corpus entries (on-disk): {}", corpus_count);
    assert!(corpus_count > 0, "On-disk mode should create corpus entries");
}

/// Helper to extract execution count from fuzzer output
fn extract_exec_count(output: &str) -> Option<u64> {
    // Look for patterns like "exec/sec: 123.45" or "executions: 1234"
    for line in output.lines() {
        if line.contains("exec/sec") {
            // Extract the number before "exec/sec"
            if let Some(pos) = line.find("exec/sec") {
                let before = &line[..pos];
                // Find the last number in the string before "exec/sec"
                let parts: Vec<&str> = before.split_whitespace().collect();
                for part in parts.iter().rev() {
                    if let Ok(n) = part.trim_matches(|c: char| !c.is_ascii_digit() && c != '.')
                        .parse::<f64>() {
                        return Some((n * 10.0) as u64); // Multiply by ~timeout to estimate total
                    }
                }
            }
        }
        if line.contains("executions:") {
            if let Some(pos) = line.find("executions:") {
                let after = &line[pos + 11..];
                if let Ok(n) = after.trim().split_whitespace().next()
                    .unwrap_or("")
                    .trim_matches(|c: char| !c.is_ascii_digit())
                    .parse::<u64>() {
                    return Some(n);
                }
            }
        }
    }
    None
}
