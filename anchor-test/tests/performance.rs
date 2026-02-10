//! Performance regression tests for anchor fuzz
//!
//! These tests verify:
//! - No significant performance decay over time
//! - Multi-core scaling efficiency
//!
//! NOTE: These tests require the test-program to be built first.
//! They are marked #[ignore] by default and should be run explicitly:
//!   cargo test --test performance -- --ignored

mod common;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Get the test-program fuzz harness path
fn test_program_fuzz_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-program/fuzz/test-program-fuzz")
}

/// Get the project root
fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Check if the test-program fuzzer is built
fn is_test_program_built() -> bool {
    let fuzz_path = test_program_fuzz_path();
    let binary = fuzz_path.join("target/release/invariant_test");
    binary.exists()
}

/// Parse exec/sec from fuzzer output
fn parse_exec_sec(output: &str) -> Option<f64> {
    // Look for patterns like "exec/sec: 123.45" or "123.45 exec/sec"
    for line in output.lines() {
        if line.contains("exec/sec") || line.contains("exec/s") {
            // Try to find a number before or after exec/sec
            for word in line.split_whitespace() {
                if let Ok(val) = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.').parse::<f64>() {
                    if val > 0.0 && val < 1_000_000.0 {
                        return Some(val);
                    }
                }
            }
        }
    }
    None
}

/// Run the fuzzer for a given duration and collect exec/sec samples
fn run_fuzzer_with_samples(
    duration_secs: u64,
    cores: Option<usize>,
) -> Vec<f64> {
    let fuzz_path = test_program_fuzz_path();
    let binary = fuzz_path.join("target/release/invariant_test");

    if !binary.exists() {
        return Vec::new();
    }

    let mut cmd = Command::new(&binary);
    cmd.current_dir(&fuzz_path);
    cmd.env("FUZZ_TIMEOUT_SECS", duration_secs.to_string());

    if let Some(n) = cores {
        cmd.env("FUZZ_CORES", n.to_string());
    }

    // Capture output
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    // Extract all exec/sec readings from output
    let mut samples = Vec::new();
    for line in combined.lines() {
        if let Some(rate) = parse_exec_sec(line) {
            samples.push(rate);
        }
    }

    samples
}

/// Test that performance doesn't decay significantly over 60 seconds
///
/// This test runs the fuzzer for 60 seconds and checks that the exec/sec
/// at the end is not significantly worse than at the start.
#[test]
#[ignore] // Run with: cargo test --test performance -- --ignored
fn test_perf_no_decay_60s() {
    if !is_test_program_built() {
        eprintln!("Skipping test_perf_no_decay_60s: test-program not built");
        eprintln!("Build with: cd test-program/fuzz/test-program-fuzz && cargo build --release --features invariant_test");
        return;
    }

    let samples = run_fuzzer_with_samples(60, None);

    if samples.len() < 4 {
        eprintln!("Not enough samples collected (got {})", samples.len());
        return;
    }

    // Compare first quarter to last quarter
    let quarter = samples.len() / 4;
    let first_avg: f64 = samples[..quarter].iter().sum::<f64>() / quarter as f64;
    let last_avg: f64 = samples[samples.len() - quarter..].iter().sum::<f64>() / quarter as f64;

    // Allow up to 30% degradation (reasonable for sustained fuzzing)
    let degradation = (first_avg - last_avg) / first_avg;

    println!("First quarter avg: {:.2} exec/sec", first_avg);
    println!("Last quarter avg: {:.2} exec/sec", last_avg);
    println!("Degradation: {:.1}%", degradation * 100.0);

    assert!(
        degradation < 0.30,
        "Performance degraded by {:.1}% (>30% threshold). First: {:.2}, Last: {:.2}",
        degradation * 100.0,
        first_avg,
        last_avg
    );
}

/// Test that multi-core scaling provides meaningful speedup
///
/// Compares single-core to 2-core performance. We expect at least 1.3x speedup
/// (accounting for overhead, not perfect 2x scaling).
#[test]
#[ignore] // Run with: cargo test --test performance -- --ignored
fn test_perf_multicore_scaling() {
    if !is_test_program_built() {
        eprintln!("Skipping test_perf_multicore_scaling: test-program not built");
        eprintln!("Build with: cd test-program/fuzz/test-program-fuzz && cargo build --release --features invariant_test");
        return;
    }

    // Run single-core for 30 seconds
    let single_samples = run_fuzzer_with_samples(30, Some(1));
    if single_samples.is_empty() {
        eprintln!("No samples from single-core run");
        return;
    }
    let single_avg: f64 = single_samples.iter().sum::<f64>() / single_samples.len() as f64;

    // Run dual-core for 30 seconds
    let dual_samples = run_fuzzer_with_samples(30, Some(2));
    if dual_samples.is_empty() {
        eprintln!("No samples from dual-core run");
        return;
    }
    let dual_avg: f64 = dual_samples.iter().sum::<f64>() / dual_samples.len() as f64;

    let speedup = dual_avg / single_avg;

    println!("Single-core: {:.2} exec/sec", single_avg);
    println!("Dual-core: {:.2} exec/sec", dual_avg);
    println!("Speedup: {:.2}x", speedup);

    // Expect at least 1.3x speedup with 2 cores
    // (Perfect would be 2x, but overhead is expected)
    assert!(
        speedup >= 1.3,
        "Multi-core speedup too low: {:.2}x (expected >= 1.3x)",
        speedup
    );
}

/// Quick sanity test that doesn't require the fuzzer binary
#[test]
fn test_parse_exec_sec() {
    assert_eq!(parse_exec_sec("exec/sec: 123.45"), Some(123.45));
    assert_eq!(parse_exec_sec("fuzzing... 456.78 exec/sec"), Some(456.78));
    assert_eq!(parse_exec_sec("rate: 1000 exec/s"), Some(1000.0));
    assert_eq!(parse_exec_sec("no rate here"), None);
}

/// Test that the common utilities work correctly
#[test]
fn test_common_utilities() {
    use common::{count_files_in_dir, file_exists_and_nonempty};
    use tempfile::TempDir;
    use std::fs;

    let temp = TempDir::new().unwrap();

    // Test file_exists_and_nonempty
    let empty_file = temp.path().join("empty.txt");
    fs::write(&empty_file, "").unwrap();
    assert!(!file_exists_and_nonempty(&empty_file), "empty file should return false");

    let nonempty_file = temp.path().join("nonempty.txt");
    fs::write(&nonempty_file, "content").unwrap();
    assert!(file_exists_and_nonempty(&nonempty_file), "nonempty file should return true");

    // Test count_files_in_dir
    let subdir = temp.path().join("subdir");
    fs::create_dir(&subdir).unwrap();
    fs::write(subdir.join("a.txt"), "a").unwrap();
    fs::write(subdir.join("b.txt"), "b").unwrap();
    fs::create_dir(subdir.join("nested")).unwrap(); // directory shouldn't be counted
    assert_eq!(count_files_in_dir(&subdir), 2);
}
