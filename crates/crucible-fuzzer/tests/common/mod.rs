//! Common test utilities for crucible CLI tests

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

/// Get the path to the crucible CLI binary
pub fn crucible_binary() -> PathBuf {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .unwrap()
        .parent() // workspace root
        .unwrap()
        .to_path_buf();
    workspace_root.join("target/debug/crucible")
}

/// Run crucible command with given arguments
pub fn run_crucible(args: &[&str], cwd: Option<&Path>) -> Output {
    let mut cmd = Command::new(crucible_binary());
    cmd.args(args);

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    cmd.output().expect("Failed to execute crucible command")
}

/// Run crucible command and return stdout as string
pub fn run_crucible_stdout(args: &[&str], cwd: Option<&Path>) -> String {
    let output = run_crucible(args, cwd);
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Run crucible command and return stderr as string
pub fn run_crucible_stderr(args: &[&str], cwd: Option<&Path>) -> String {
    let output = run_crucible(args, cwd);
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// Parse exec/sec from fuzzer output
/// Looks for patterns like "exec/sec: 123.45" or "123.45 exec/sec"
pub fn parse_exec_sec(output: &str) -> Option<f64> {
    // Try pattern: "exec/sec: 123.45"
    if let Some(pos) = output.find("exec/sec:") {
        let after = &output[pos + 9..];
        if let Some(num_str) = after.split_whitespace().next() {
            if let Ok(val) = num_str
                .trim_matches(|c: char| !c.is_ascii_digit() && c != '.')
                .parse()
            {
                return Some(val);
            }
        }
    }

    // Try pattern: "123.45 exec/sec"
    for line in output.lines() {
        if line.contains("exec/sec") {
            for word in line.split_whitespace() {
                if let Ok(val) = word.parse::<f64>() {
                    return Some(val);
                }
            }
        }
    }

    None
}

/// Get the marginfi-v2-fuzz example path
pub fn marginfi_example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .unwrap()
        .parent() // workspace root
        .unwrap()
        .join("examples/marginfi-v2-fuzz")
}

/// Get the test-program path for performance tests
pub fn test_program_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-program")
}

/// Create a temporary directory with a basic fuzz harness structure
pub fn setup_test_harness(_program_name: &str) -> TempDir {
    let dir = TempDir::new().expect("Failed to create temp dir");
    // The actual harness setup would be done by `anchor fuzz init`
    dir
}

/// Check if a file exists and is non-empty
pub fn file_exists_and_nonempty(path: &Path) -> bool {
    path.exists() && path.metadata().map(|m| m.len() > 0).unwrap_or(false)
}

/// Count files in a directory (non-recursive)
pub fn count_files_in_dir(dir: &Path) -> usize {
    if !dir.is_dir() {
        return 0;
    }
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                .count()
        })
        .unwrap_or(0)
}

/// Wait for a condition with timeout (polling)
pub fn wait_for<F>(condition: F, timeout_ms: u64, poll_interval_ms: u64) -> bool
where
    F: Fn() -> bool,
{
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let interval = std::time::Duration::from_millis(poll_interval_ms);

    while start.elapsed() < timeout {
        if condition() {
            return true;
        }
        std::thread::sleep(interval);
    }

    false
}

/// Get the test-program fuzz harness path
pub fn test_program_fuzz_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-program/fuzz/test-program-fuzz")
}

/// Check if the test-program fuzz binary is built
pub fn test_program_fuzz_binary_exists() -> bool {
    let binary = test_program_fuzz_path().join("target/release/invariant_test");
    binary.exists()
}

/// Check if the test-program .so is built
pub fn test_program_so_exists() -> bool {
    let so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-program/target/deploy/test_program.so");
    so_path.exists()
}

/// Run the test-program fuzz harness with given env vars
/// Returns (stdout, stderr, success)
pub fn run_test_program_fuzz(envs: &[(&str, &str)]) -> (String, String, bool) {
    let fuzz_path = test_program_fuzz_path();
    let binary = fuzz_path.join("target/release/invariant_test");

    let mut cmd = std::process::Command::new(&binary);
    cmd.current_dir(&fuzz_path);
    for (k, v) in envs {
        cmd.env(k, v);
    }

    let output = cmd.output().expect("failed to run test-program-fuzz");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.success(),
    )
}

/// Run test-program fuzz with a hard timeout that kills the process
/// This is essential for multicore tests where FUZZ_TIMEOUT_SECS alone isn't enough
/// (workers call std::process::exit(0) but Launcher may wait indefinitely for LLMP)
/// Returns (stdout, stderr, success)
pub fn run_test_program_fuzz_with_timeout(
    envs: &[(&str, &str)],
    hard_timeout_secs: u64,
) -> (String, String, bool) {
    use std::io::Read;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let fuzz_path = test_program_fuzz_path();
    let binary = fuzz_path.join("target/release/invariant_test");

    let mut cmd = std::process::Command::new(&binary);
    cmd.current_dir(&fuzz_path);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().expect("failed to spawn test-program-fuzz");
    let start = Instant::now();
    let timeout = Duration::from_secs(hard_timeout_secs);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process finished
                let stdout = child
                    .stdout
                    .take()
                    .map(|mut o| {
                        let mut s = String::new();
                        o.read_to_string(&mut s).ok();
                        s
                    })
                    .unwrap_or_default();
                let stderr = child
                    .stderr
                    .take()
                    .map(|mut o| {
                        let mut s = String::new();
                        o.read_to_string(&mut s).ok();
                        s
                    })
                    .unwrap_or_default();
                return (stdout, stderr, status.success());
            }
            Ok(None) => {
                // Still running
                if start.elapsed() > timeout {
                    eprintln!(
                        "[TEST] Hard timeout reached ({}s), killing process",
                        hard_timeout_secs
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                    // Also try to kill any zombie workers (multicore leaves child processes)
                    let _ = std::process::Command::new("pkill")
                        .args(["-9", "-f", "invariant_test"])
                        .output();
                    return ("".to_string(), "TIMEOUT".to_string(), false);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return ("".to_string(), format!("Error: {}", e), false);
            }
        }
    }
}

/// Count corpus files in a directory (excluding metadata)
pub fn count_corpus_files(dir: &Path) -> usize {
    if !dir.is_dir() {
        return 0;
    }
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    let path = e.path();
                    if !path.is_file() {
                        return false;
                    }
                    let name = e.file_name().to_string_lossy().to_string();
                    !name.starts_with('.')
                        && !name.ends_with(".metadata")
                        && !name.ends_with(".meta.json")
                })
                .count()
        })
        .unwrap_or(0)
}

/// Create a test corpus with N input files of varying content
pub fn create_test_corpus(dir: &Path, count: usize) {
    std::fs::create_dir_all(dir).unwrap();
    for i in 0..count {
        // Create inputs with varying content for different coverage paths
        let content = vec![i as u8; 100 + i * 10];
        std::fs::write(dir.join(format!("input_{:04}", i)), &content).unwrap();
    }
}

/// Parse edges count from fuzzer output
/// Looks for patterns like "edges: 123/456" or "edges: 123"
/// Returns the LAST (most recent) edge count found
pub fn parse_edges_count(output: &str) -> Option<usize> {
    let mut last_edges: Option<usize> = None;

    for line in output.lines() {
        if let Some(pos) = line.find("edges:") {
            let after = &line[pos + 6..].trim_start();
            // Handle "edges: 123/456 (50%)" format - find first number
            for part in after.split(|c: char| !c.is_ascii_digit()) {
                if !part.is_empty() {
                    if let Ok(val) = part.parse() {
                        last_edges = Some(val);
                        break;
                    }
                }
            }
        }
    }
    last_edges
}

/// Parse corpus count from fuzzer output
/// Looks for patterns like "corpus: 123" or "Loaded 123 seed inputs"
pub fn parse_corpus_count(output: &str) -> Option<usize> {
    // Try "corpus: N" format
    for line in output.lines() {
        if let Some(pos) = line.find("corpus:") {
            let after = &line[pos + 7..];
            let num_str = after.split_whitespace().next()?;
            if let Ok(val) = num_str.trim().parse() {
                return Some(val);
            }
        }
    }
    // Try "Loaded N seed inputs" format
    for line in output.lines() {
        if line.contains("Loaded") && line.contains("seed inputs") {
            for word in line.split_whitespace() {
                if let Ok(val) = word.parse::<usize>() {
                    return Some(val);
                }
            }
        }
    }
    None
}

/// Parse all exec/sec values from fuzzer output
/// Returns a list of (timestamp_approx, exec_sec) pairs based on line order
pub fn parse_all_exec_sec(output: &str) -> Vec<f64> {
    let mut results = Vec::new();

    for line in output.lines() {
        if line.contains("exec/sec") {
            // Try to extract the number before or after "exec/sec"
            for word in line.split_whitespace() {
                if let Ok(val) = word
                    .trim_matches(|c: char| !c.is_ascii_digit() && c != '.')
                    .parse::<f64>()
                {
                    if val > 0.0 && val < 100000.0 {
                        // Sanity check
                        results.push(val);
                        break;
                    }
                }
            }
        }
    }

    results
}

/// Parse branches count from fuzzer output
pub fn parse_branches_count(output: &str) -> Option<usize> {
    for line in output.lines() {
        if let Some(pos) = line.find("branches:") {
            let after = &line[pos + 9..].trim_start();
            for part in after.split(|c: char| !c.is_ascii_digit()) {
                if !part.is_empty() {
                    if let Ok(val) = part.parse() {
                        return Some(val);
                    }
                }
            }
        }
    }
    None
}

/// Parse total executions from fuzzer output
pub fn parse_total_executions(output: &str) -> Option<u64> {
    // Look for patterns like "total_execs: 12345" or "Total executions: 12345"
    for line in output.lines() {
        if line.to_lowercase().contains("total") && line.contains("exec") {
            for word in line.split_whitespace() {
                if let Ok(val) = word
                    .trim_matches(|c: char| !c.is_ascii_digit())
                    .parse::<u64>()
                {
                    if val > 0 {
                        return Some(val);
                    }
                }
            }
        }
    }
    None
}

/// Check if crash was detected in output
pub fn crash_detected(output: &str) -> bool {
    let lower = output.to_lowercase();
    lower.contains("crash")
        || lower.contains("violation")
        || lower.contains("invariant") && lower.contains("failed")
        || lower.contains("assertion") && lower.contains("failed")
}

/// Count crash files in a directory
/// Only counts our crash format (crash_*.meta.json files), not LibAFL's internal .metadata files
pub fn count_crash_files(crashes_dir: &Path) -> usize {
    if !crashes_dir.is_dir() {
        return 0;
    }

    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(crashes_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if path.is_dir() {
                // Check subdirectories (crashes/test_name/)
                if let Ok(sub_entries) = std::fs::read_dir(&path) {
                    for sub_entry in sub_entries.filter_map(|e| e.ok()) {
                        let sub_name = sub_entry.file_name().to_string_lossy().to_string();
                        // Only count our crash metadata files (crash_*.meta.json)
                        if sub_name.ends_with(".meta.json") && sub_name.starts_with("crash_") {
                            count += 1;
                        }
                    }
                }
            } else if path.is_file() {
                // Count crash_*.meta.json files at root level
                if name.ends_with(".meta.json") && name.starts_with("crash_") {
                    count += 1;
                }
            }
        }
    }
    count
}

/// Find crash files (both metadata and input bytes)
/// Returns Vec of (metadata_path, input_path) tuples
/// Only matches our crash format (.meta.json files), not LibAFL's internal .metadata files
pub fn find_crash_files(crashes_dir: &Path) -> Vec<(PathBuf, PathBuf)> {
    let mut crashes = Vec::new();

    if !crashes_dir.is_dir() {
        return crashes;
    }

    // Helper to find crashes in a directory
    let find_in_dir = |dir: &Path| -> Vec<(PathBuf, PathBuf)> {
        let mut found = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().to_string();
                let path = entry.path();

                if !path.is_file() {
                    continue;
                }

                // Only match our crash format: crash_*.meta.json files
                // These contain test_name, timestamp, actions, etc.
                // Skip LibAFL's internal .metadata files (different format)
                if name.ends_with(".meta.json") && name.starts_with("crash_") {
                    // Format: crash_abc.meta.json -> crash_abc
                    let input_name = name.trim_end_matches(".meta.json");
                    let input_path = dir.join(input_name);
                    if input_path.exists() {
                        found.push((path, input_path));
                    }
                } else if name.starts_with("crash_") && !name.ends_with(".meta.json") {
                    // This is a crash input file - look for its metadata
                    let meta_path = dir.join(format!("{}.meta.json", name));
                    if meta_path.exists() {
                        found.push((meta_path, path));
                    }
                }
            }
        }
        found
    };

    // Check root directory
    crashes.extend(find_in_dir(crashes_dir));

    // Check subdirectories (crashes/test_name/)
    if let Ok(entries) = std::fs::read_dir(crashes_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                crashes.extend(find_in_dir(&path));
            }
        }
    }

    // Deduplicate (in case we found same crash from both directions)
    crashes.sort_by(|a, b| a.1.cmp(&b.1));
    crashes.dedup_by(|a, b| a.1 == b.1);

    crashes
}

/// Run test-program fuzz with timeout and capture periodic output
/// Returns (final_stdout, final_stderr, success, periodic_samples)
/// Each sample is (elapsed_secs, output_so_far)
pub fn run_test_program_fuzz_with_samples(
    envs: &[(&str, &str)],
    sample_interval_secs: u64,
    total_timeout_secs: u64,
) -> (String, String, bool, Vec<(u64, String)>) {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    let fuzz_path = test_program_fuzz_path();
    let binary = fuzz_path.join("target/release/invariant_test");

    let mut cmd = std::process::Command::new(&binary);
    cmd.current_dir(&fuzz_path);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    for (k, v) in envs {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().expect("failed to spawn test-program-fuzz");

    let stderr = child.stderr.take().unwrap();
    let stdout = child.stdout.take().unwrap();

    let stderr_output = Arc::new(Mutex::new(String::new()));
    let stdout_output = Arc::new(Mutex::new(String::new()));
    let samples = Arc::new(Mutex::new(Vec::new()));

    let stderr_clone = stderr_output.clone();
    let stderr_thread = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            if let Ok(line) = line {
                let mut output = stderr_clone.lock().unwrap();
                output.push_str(&line);
                output.push('\n');
            }
        }
    });

    let stdout_clone = stdout_output.clone();
    let stdout_thread = thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(line) = line {
                let mut output = stdout_clone.lock().unwrap();
                output.push_str(&line);
                output.push('\n');
            }
        }
    });

    // Sample periodically
    let start = Instant::now();
    let sample_interval = Duration::from_secs(sample_interval_secs);
    let total_timeout = Duration::from_secs(total_timeout_secs + 5); // Buffer

    let samples_clone = samples.clone();
    let stderr_for_samples = stderr_output.clone();
    let sample_thread = thread::spawn(move || {
        let mut last_sample = Instant::now();
        while start.elapsed() < total_timeout {
            thread::sleep(Duration::from_millis(500));
            if last_sample.elapsed() >= sample_interval {
                let elapsed = start.elapsed().as_secs();
                let output = stderr_for_samples.lock().unwrap().clone();
                samples_clone.lock().unwrap().push((elapsed, output));
                last_sample = Instant::now();
            }
        }
    });

    // Wait for child with timeout
    let status = match child.wait() {
        Ok(s) => s,
        Err(_) => {
            let _ = child.kill();
            return ("".to_string(), "Process killed".to_string(), false, vec![]);
        }
    };

    let _ = stderr_thread.join();
    let _ = stdout_thread.join();
    let _ = sample_thread.join();

    let stdout_final = stdout_output.lock().unwrap().clone();
    let stderr_final = stderr_output.lock().unwrap().clone();
    let samples_final = samples.lock().unwrap().clone();

    (stdout_final, stderr_final, status.success(), samples_final)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_exec_sec_colon_format() {
        let output = "some text exec/sec: 123.45 more text";
        assert_eq!(parse_exec_sec(output), Some(123.45));
    }

    #[test]
    fn test_parse_exec_sec_space_format() {
        let output = "fuzzing... 456.78 exec/sec";
        assert_eq!(parse_exec_sec(output), Some(456.78));
    }

    #[test]
    fn test_parse_exec_sec_not_found() {
        let output = "no execution rate here";
        assert_eq!(parse_exec_sec(output), None);
    }

    #[test]
    fn test_parse_edges_count() {
        assert_eq!(parse_edges_count("edges: 123/456 (27%)"), Some(123));
        assert_eq!(parse_edges_count("edges: 789"), Some(789));
        assert_eq!(parse_edges_count("no edges here"), None);
    }

    #[test]
    fn test_parse_corpus_count() {
        assert_eq!(parse_corpus_count("corpus: 42"), Some(42));
        assert_eq!(parse_corpus_count("[FUZZ] Loaded 15 seed inputs"), Some(15));
        assert_eq!(parse_corpus_count("no corpus info"), None);
    }

    #[test]
    fn test_count_corpus_files() {
        let dir = tempfile::TempDir::new().unwrap();
        // Empty dir
        assert_eq!(count_corpus_files(dir.path()), 0);

        // Add some files
        std::fs::write(dir.path().join("input_0"), b"test").unwrap();
        std::fs::write(dir.path().join("input_1"), b"test").unwrap();
        assert_eq!(count_corpus_files(dir.path()), 2);

        // Add metadata files (should be excluded)
        std::fs::write(dir.path().join(".hidden"), b"hidden").unwrap();
        std::fs::write(dir.path().join("input_0.metadata"), b"meta").unwrap();
        std::fs::write(dir.path().join("crash.meta.json"), b"{}").unwrap();
        assert_eq!(count_corpus_files(dir.path()), 2);
    }
}
