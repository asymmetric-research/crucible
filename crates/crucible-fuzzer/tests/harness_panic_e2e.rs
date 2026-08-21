//! E2E: a bare panic in the harness/invariant (a plain `assert!`, `unwrap()`, arithmetic overflow —
//! anything NOT routed through `fuzz_assert!`/`record_violation`) is a HARNESS BUG. It must alert
//! the author loudly and stop the run — NOT be saved as a `crash_<id>` finding, and NOT silently
//! restart-loop while the objective counter climbs.
//!
//! Requires the test-program harness to be built; marked #[ignore]:
//!   cd test-program/fuzz/test-program-fuzz && cargo build --release --features invariant_test
//!   cargo test -p crucible-fuzzer --test harness_panic_e2e -- --ignored

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

fn test_program_fuzz_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-program/fuzz/test-program-fuzz")
}

#[test]
#[ignore] // Run with: cargo test -p crucible-fuzzer --test harness_panic_e2e -- --ignored
fn harness_panic_alerts_and_stops_without_writing_a_crash() {
    let fuzz_path = test_program_fuzz_path();
    let binary = fuzz_path.join("target/release/invariant_test");
    if !binary.exists() {
        eprintln!(
            "Skipping harness_panic_alerts_and_stops_without_writing_a_crash: test-program not built.\n\
             Build with: cd test-program/fuzz/test-program-fuzz && cargo build --release --features invariant_test"
        );
        return;
    }

    let crash_dir =
        std::env::temp_dir().join(format!("crucible_harness_panic_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&crash_dir);
    std::fs::create_dir_all(&crash_dir).unwrap();

    let mut cmd = Command::new(&binary);
    cmd.current_dir(&fuzz_path);
    // The test hook in the harness invariant raises a raw `assert!(false, ...)` panic.
    cmd.env("CRUCIBLE_TEST_FORCE_PANIC", "1");
    cmd.env("FUZZ_CRASHES_DIR", crash_dir.to_str().unwrap());
    cmd.env("FUZZ_SEED", "1");
    // Safety net so the test can never hang if the stop somehow misfires.
    cmd.env("FUZZ_TIMEOUT_SECS", "30");
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn test-program-fuzz");
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if start.elapsed() > Duration::from_secs(45) {
            let _ = child.kill();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    let output = child.wait_with_output().unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // 1. The run must stop promptly with a non-zero exit (the harness-panic stop code), not hang.
    let status = status.expect("run must terminate on a harness panic, not hang");
    assert!(
        !status.success(),
        "a harness panic must exit non-zero; got {:?}",
        status
    );

    // 2. A prominent harness-panic alert must be printed.
    assert!(
        combined.contains("[HARNESS PANIC]"),
        "should print a [HARNESS PANIC] alert; output was:\n{}",
        combined
    );

    // 3. It must NOT be recorded as a crash — no canonical crash_<id> files, and it must not be
    //    reported as a finding.
    let crash_files: Vec<String> = std::fs::read_dir(&crash_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("crash_"))
        .collect();
    assert!(
        crash_files.is_empty(),
        "a harness panic must not write any crash file; found: {:?}",
        crash_files
    );
    assert!(
        !combined.contains("[FUZZ_FINDING]"),
        "a harness panic must not be reported as a finding; output was:\n{}",
        combined
    );

    let _ = std::fs::remove_dir_all(&crash_dir);
}
