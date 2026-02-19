//! Multi-core fuzzing support for the anchor-fuzz macro.
//!
//! This module contains code generation for multi-core fuzzing using LibAFL's Launcher.
//! Key features:
//! - Uses `load_initial_inputs_forced` so all workers have full corpus access
//! - Monitor displays actual corpus file count (not N× inflated LibAFL count)
//! - Shared memory bitmaps for edge/branch tracking
//! - LLMP message passing for corpus synchronization

use quote::quote;

use crate::codegen;

/// Generate the multi-core fuzzing mode code
///
/// This version uses LibAFL's `load_initial_inputs_forced` so all workers have
/// access to all seed inputs. The monitor is patched to show actual corpus file
/// count instead of LibAFL's N× inflated count.
pub fn multicore_mode(
    mod_name: &syn::Ident,
    fixture_name: &syn::Ident,
    fn_name: &syn::Ident,
    fixture_param_name: &syn::Ident,
    feature_name: &str,
    deser_stmts: &[proc_macro2::TokenStream],
    call_args: &[proc_macro2::TokenStream],
    structured: bool,
    action_type: Option<&proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {
    let init_coverage_totals = codegen::init_coverage_totals(mod_name);

    // Conditional code for structured vs arbitrary mode
    let unstructured_init = if structured {
        quote! {}
    } else {
        quote! { let mut u = Unstructured::new(slice); }
    };

    // Max input size: 1024 for both modes (structured max valid ~336 bytes, 1024 is 3x headroom)
    let max_size_setup = quote! { state.set_max_size(1024); };

    let default_seed_code = if structured {
        let at = action_type.unwrap();
        quote! {
            {
                use libafl::generators::Generator;
                let __seed_max: usize = std::env::var("FUZZ_MAX_ACTIONS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(10)
                    .min(4);
                let mut gen = crucible_fuzzer::ActionGenerator::<#at>::new(1, __seed_max);
                for _ in 0..4 {
                    if let Ok(input) = gen.generate(&mut state) {
                        let _ = fuzzer.add_input(&mut state, &mut executor, &mut mgr, input);
                    }
                }
                if state.corpus().count() == 0 {
                    let input = BytesInput::new(vec![0u8; 256]);
                    fuzzer.add_input(&mut state, &mut executor, &mut mgr, input)
                        .expect("failed to add fallback seed");
                }
            }
        }
    } else {
        quote! {
            let input = BytesInput::new(vec![0u8; 256]);
            fuzzer.add_input(&mut state, &mut executor, &mut mgr, input)
                .expect("failed to add default seed");
        }
    };

    let mutator_setup = if structured {
        let at = action_type.unwrap();
        quote! {
            let __fuzz_max_actions: usize = std::env::var("FUZZ_MAX_ACTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10);
            let trim_stage = crucible_fuzzer::SuccessTrimStage::<#at>::new();
            let seq_mutator = crucible_fuzzer::SequenceMutator::<#at>::new(__fuzz_max_actions);
            let param_mutator = crucible_fuzzer::ParamMutator::<#at>::new();
            let cross_mutator = crucible_fuzzer::CrossoverMutator::<#at>::new(__fuzz_max_actions);
            let mutator = StdMOptMutator::new(
                &mut state,
                tuple_list!(seq_mutator, param_mutator, cross_mutator),
                7, 5
            ).expect("failed to create structured mutator");
            let power_stage = StdPowerMutationalStage::new(mutator);
            let mut stages = tuple_list!(trim_stage, power_stage);
        }
    } else {
        quote! {
            let mutator = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5)
                .expect("failed to create mutator");
            let power_stage = StdPowerMutationalStage::new(mutator);
            let mut stages = tuple_list!(power_stage);
        }
    };

    quote! {
        // === MULTI-CORE MODE ===
        // Check for multi-core mode
        let cores_spec = std::env::var("FUZZ_CORES").ok();
        let use_launcher = cores_spec.is_some();

        if use_launcher {
            // Uses LibAFL Launcher with fork() and LLMP for parallel fuzzing
            use std::collections::HashSet;
            use libafl_bolts::shmem::{ShMem, ShMemProvider, StdShMemProvider};
            use libafl_bolts::core_affinity::Cores;
            use libafl::events::{EventConfig, Launcher, ClientDescription};
            use libafl::monitors::MultiMonitor;
            use libafl::Error as LibAflError;

            let num_cores: usize = cores_spec.as_ref().unwrap().parse()
                .expect("FUZZ_CORES must be a valid number");

            if coverage_enabled {
                eprintln!("[FUZZ] Warning: --coverage LCOV output disabled in multi-core mode");
                eprintln!("[FUZZ] (AFL shared memory coverage still works for fuzzing)");
                #mod_name::COVERAGE_ENABLED.store(false, std::sync::atomic::Ordering::Relaxed);
            }

            // Use seed from env var if provided, otherwise use current time
            let seed = std::env::var("FUZZ_SEED")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| current_nanos().max(1));
            let crash_dir = crashes_dir_env.clone().unwrap_or_else(|| format!("crashes/{}", #feature_name));
            std::fs::create_dir_all(&crash_dir).expect("failed to create crash directory");

            if verbose { eprintln!("[FUZZ] Initializing program analysis..."); }

            // =====================================================================
            // PRE-FORK: Initialize PROGRAM_TOTALS for coverage tracking
            // =====================================================================
            if std::env::var("FUZZ_NO_TRACING").is_err() {
                std::env::set_var("ANCHOR_FUZZ_DEBUGGABLE", "1");
            }
            let template_fixture = #fixture_name::setup();
            #init_coverage_totals

            eprintln!("[FUZZ] Starting {} parallel workers", num_cores);

            // Clean up stale shared memory files from previous runs
            {
                // Remove stale LibAFL socket file
                let _ = std::fs::remove_file("libafl_unix_shmem_server");

                // On macOS, try to clean up orphaned POSIX shared memory segments
                #[cfg(target_os = "macos")]
                {
                    use std::process::Command;
                    if let Ok(output) = Command::new("ipcs").arg("-m").output() {
                        let output_str = String::from_utf8_lossy(&output.stdout);
                        for line in output_str.lines() {
                            if line.contains("libafl") || line.contains("__shmem") {
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if parts.len() >= 2 {
                                    let _ = Command::new("ipcrm").arg("-m").arg(parts[1]).output();
                                }
                            }
                        }
                    }
                }

                #[cfg(unix)]
                {
                    extern "C" {
                        fn shm_unlink(name: *const std::ffi::c_char) -> std::ffi::c_int;
                    }
                    for name in &["/__libafl_fuzzer", "/__libafl_edges", "/__libafl_branches", "/__libafl_corpus"] {
                        let c_name = std::ffi::CString::new(*name).unwrap();
                        unsafe { shm_unlink(c_name.as_ptr()); }
                    }
                }
            }

            // Shared memory provider for coverage map and shared bitmaps
            let mut shmem_provider = StdShMemProvider::new()
                .expect("failed to create shared memory provider");

            // Allocate shared memory for cross-process edge/branch tracking
            let mut shared_edge_shmem = shmem_provider
                .new_shmem(#mod_name::SHARED_EDGE_BITMAP_SIZE)
                .expect("failed to allocate shared edge bitmap");
            shared_edge_shmem.fill(0);
            let shared_edge_ptr = shared_edge_shmem.as_slice().as_ptr() as *mut u8;

            let mut shared_branch_shmem = shmem_provider
                .new_shmem(#mod_name::SHARED_BRANCH_BITMAP_SIZE)
                .expect("failed to allocate shared branch bitmap");
            shared_branch_shmem.fill(0);
            let shared_branch_ptr = shared_branch_shmem.as_slice().as_ptr() as *mut u8;

            // Allocate shared memory for cross-process action counter (8 bytes for AtomicU64)
            let mut shared_actions_shmem = shmem_provider
                .new_shmem(8)
                .expect("failed to allocate shared action counter");
            shared_actions_shmem.fill(0);
            let shared_actions_ptr = shared_actions_shmem.as_slice().as_ptr() as *mut u8;

            // Allocate shared memory for cross-process execution counter (8 bytes for AtomicU64)
            // Batched together with shared_actions to ensure accurate actions/exec ratio
            let mut shared_execs_shmem = shmem_provider
                .new_shmem(8)
                .expect("failed to allocate shared execution counter");
            shared_execs_shmem.fill(0);
            let shared_execs_ptr = shared_execs_shmem.as_slice().as_ptr() as *mut u8;

            // Setup shared corpus directory for multi-core mode
            let shared_corpus_dir = corpus_out_dir.clone()
                .unwrap_or_else(|| {
                    let temp_shared = std::env::temp_dir().join(format!("fuzz_corpus_shared_{}", #feature_name));
                    temp_shared.to_string_lossy().to_string()
                });
            let has_corpus_out = corpus_out_dir.is_some();
            std::fs::create_dir_all(&shared_corpus_dir).expect("failed to create shared corpus directory");

            // Clean corpus_out if it differs from corpus_in
            let loading_from_same_dir = corpus_in_dir.as_ref().map(|cin| {
                std::path::Path::new(cin)
                    .canonicalize()
                    .ok()
                    .and_then(|cin_canon| std::path::Path::new(&shared_corpus_dir)
                        .canonicalize()
                        .ok()
                        .map(|cout_canon| cin_canon == cout_canon))
                    .unwrap_or(false)
            }).unwrap_or(false);

            if !loading_from_same_dir {
                let mut removed = 0usize;
                if let Ok(entries) = std::fs::read_dir(&shared_corpus_dir) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let path = entry.path();
                        if path.is_file() {
                            if std::fs::remove_file(&path).is_ok() {
                                removed += 1;
                            }
                        }
                    }
                }
                if removed > 0 && verbose {
                    eprintln!("[FUZZ] Cleaned {} stale files from corpus output directory", removed);
                }
            }

            if verbose {
                if has_corpus_out {
                    eprintln!("[FUZZ] Using shared corpus directory: {}", shared_corpus_dir);
                } else {
                    eprintln!("[FUZZ] Using temp shared corpus: {}", shared_corpus_dir);
                }
            }

            // Clone values needed for the client closure
            let shared_corpus_dir_for_client = shared_corpus_dir.clone();
            let corpus_in_dir_for_client = corpus_in_dir.clone();

            // File-based stop signal for --stop-on-crash (more reliable across forked processes)
            // When any worker sets this, all workers will see it and abort
            let stop_signal_file = std::env::temp_dir()
                .join(format!("fuzz_stop_signal_{}_{}", #feature_name, std::process::id()));
            // Clean up any stale signal from previous runs
            let _ = std::fs::remove_file(&stop_signal_file);
            let stop_signal_file_for_client = stop_signal_file.clone();

            // Clone corpus dir for monitor closure
            let shared_corpus_dir_for_monitor = shared_corpus_dir.clone();

            // CSV stats file setup for multi-core mode (when FUZZ_STATS_CSV env var is set)
            let __mc_start_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let __stats_csv_mc: Option<std::sync::Arc<std::sync::Mutex<std::fs::File>>> =
                std::env::var("FUZZ_STATS_CSV").ok().map(|path| {
                    let mut f = std::fs::OpenOptions::new()
                        .create(true).write(true).truncate(true)
                        .open(&path).expect("failed to open FUZZ_STATS_CSV file");
                    {
                        use std::io::Write;
                        writeln!(f, "elapsed_secs,executions,exec_sec,corpus,crashes,edges,total_edges,edge_pct,branches,total_branches,branch_pct").unwrap();
                        f.flush().unwrap();
                    }
                    std::sync::Arc::new(std::sync::Mutex::new(f))
                });
            let __csv_ref_mc = __stats_csv_mc.clone();

            // Monitor for aggregated stats across all workers
            // Uses rate-limited caching to avoid expensive operations on every callback
            let monitor = MultiMonitor::new(move |s| {
                use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};

                // Cached monitor values with rate-limiting (avoid expensive ops on every callback)
                static CACHED_EDGE_COUNT: AtomicUsize = AtomicUsize::new(0);
                static CACHED_BRANCH_COUNT: AtomicUsize = AtomicUsize::new(0);
                static CACHED_CORPUS_COUNT: AtomicUsize = AtomicUsize::new(0);
                static LAST_CACHE_UPDATE_MS: AtomicU64 = AtomicU64::new(0);
                const CACHE_REFRESH_MS: u64 = 2000;

                for line in s.lines() {
                    if line.contains("(GLOBAL)") {
                        let mut line = line.replace("objectives", "crashes");

                        // Check if we need to refresh cached values
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;
                        let last_update = LAST_CACHE_UPDATE_MS.load(Ordering::Relaxed);
                        let should_refresh = now_ms.saturating_sub(last_update) >= CACHE_REFRESH_MS;

                        if should_refresh {
                            // Update last refresh time first to avoid thundering herd
                            LAST_CACHE_UPDATE_MS.store(now_ms, Ordering::Relaxed);

                            // Refresh corpus count from disk
                            let real_count = std::fs::read_dir(&shared_corpus_dir_for_monitor)
                                .map(|d| d.filter_map(|e| e.ok())
                                    .filter(|e| {
                                        let name = e.file_name();
                                        let name = name.to_string_lossy();
                                        !name.starts_with('.') && !name.ends_with(".metadata")
                                    })
                                    .count())
                                .unwrap_or(0);
                            CACHED_CORPUS_COUNT.store(real_count, Ordering::Relaxed);

                            // Refresh edge/branch counts from shared bitmaps
                            // Only count first half of edge bitmap (second half is for hitcount buckets)
                            let true_edges = #mod_name::FuzzCallback::count_shared_bits(
                                shared_edge_ptr as *const u8,
                                #mod_name::SHARED_EDGE_BITMAP_SIZE / 2
                            );
                            let true_branches = #mod_name::FuzzCallback::count_shared_bits(
                                shared_branch_ptr as *const u8,
                                #mod_name::SHARED_BRANCH_BITMAP_SIZE
                            );
                            CACHED_EDGE_COUNT.store(true_edges, Ordering::Relaxed);
                            CACHED_BRANCH_COUNT.store(true_branches, Ordering::Relaxed);
                        }

                        // Use cached values for display
                        let cached_corpus = CACHED_CORPUS_COUNT.load(Ordering::Relaxed);
                        let cached_edges = CACHED_EDGE_COUNT.load(Ordering::Relaxed);
                        let cached_branches = CACHED_BRANCH_COUNT.load(Ordering::Relaxed);

                        // Replace LibAFL's inflated corpus count with actual files on disk
                        // LibAFL reports N× corpus count when using load_initial_inputs_forced
                        // (each of N workers reports loading the same corpus)
                        if let Some(corpus_start) = line.find("corpus: ") {
                            let after_corpus = &line[corpus_start + 8..];
                            if let Some(end) = after_corpus.find(',') {
                                line = format!("{}corpus: {}{}",
                                    &line[..corpus_start],
                                    cached_corpus,
                                    &after_corpus[end..]);
                            }
                        }

                        let total_edges: usize = #mod_name::PROGRAM_TOTALS.get()
                            .map(|t| t.values().sum())
                            .unwrap_or(0);
                        let total_branches = total_edges / 2;

                        // Append program-level coverage stats to LibAFL's output
                        if line.contains("exec/sec:") {
                            let edge_pct = if total_edges > 0 { (cached_edges as f64 / total_edges as f64) * 100.0 } else { 0.0 };
                            let branch_pct = if total_branches > 0 { (cached_branches as f64 / total_branches as f64) * 100.0 } else { 0.0 };
                            // Read total actions and executions from shared memory
                            // Both counters are flushed together by workers, ensuring accurate ratio
                            let shared_total_actions = unsafe {
                                let counter = &*(shared_actions_ptr as *const std::sync::atomic::AtomicU64);
                                counter.load(std::sync::atomic::Ordering::Relaxed)
                            };
                            let shared_execs = unsafe {
                                let counter = &*(shared_execs_ptr as *const std::sync::atomic::AtomicU64);
                                counter.load(std::sync::atomic::Ordering::Relaxed)
                            };
                            let avg_actions = if shared_execs > 0 {
                                shared_total_actions as f64 / shared_execs as f64
                            } else { 0.0 };

                            println!("{}, edges: {}/{} ({:.1}%), branches: {}/{} ({:.1}%), actions/exec: {:.1}",
                                line.trim_end(), cached_edges, total_edges, edge_pct, cached_branches, total_branches, branch_pct, avg_actions);

                            // Write CSV stats row if enabled
                            if let Some(ref csv) = __csv_ref_mc {
                                // Handles SI suffixes: k (1000), M (1000000)
                                fn __parse_mc_val(s: &str, key: &str) -> f64 {
                                    s.find(key)
                                        .and_then(|i| {
                                            let rest = &s[i + key.len()..];
                                            let end = rest.find(|c: char| c == ',' || c == '\n' || c == '\r')
                                                .unwrap_or(rest.len());
                                            let token = rest[..end].trim();
                                            if let Some(num) = token.strip_suffix('k') {
                                                num.parse::<f64>().ok().map(|v| v * 1000.0)
                                            } else if let Some(num) = token.strip_suffix('M') {
                                                num.parse::<f64>().ok().map(|v| v * 1_000_000.0)
                                            } else {
                                                token.parse().ok()
                                            }
                                        })
                                        .unwrap_or(0.0)
                                }
                                let elapsed = {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs();
                                    now - __mc_start_secs
                                };
                                let execs = __parse_mc_val(&line, "executions: ") as u64;
                                let exec_sec = __parse_mc_val(&line, "exec/sec: ");
                                let crashes_count = __parse_mc_val(&line, "crashes: ") as u64;
                                if let Ok(mut f) = csv.lock() {
                                    use std::io::Write;
                                    let _ = writeln!(f, "{},{},{:.1},{},{},{},{},{:.1},{},{},{:.1}",
                                        elapsed, execs, exec_sec, cached_corpus, crashes_count,
                                        cached_edges, total_edges, edge_pct, cached_branches, total_branches, branch_pct);
                                    let _ = f.flush();
                                }
                            }
                        } else {
                            println!("{}", line);
                        }
                    }
                }
            });

            // =====================================================================
            // The run_client closure is called once per forked worker
            // Uses load_initial_inputs_forced so all workers have full corpus
            // =====================================================================
            let mut run_client = |state: Option<_>, mut mgr, _client_desc: ClientDescription| {
                let worker_id = _client_desc.core_id().0;

                // Set up panic hook to suppress expected shutdown panics and
                // LibAFL shared memory cleanup panics on Ctrl+C
                std::panic::set_hook(Box::new(|info| {
                    // Suppress by source location (LibAFL shmem cleanup + double-panic)
                    if let Some(loc) = info.location() {
                        let file = loc.file();
                        if file.contains("unix_shmem_server") || file.contains("panicking.rs") {
                            return;
                        }
                    }
                    // Suppress by message content (our intentional shutdown panics)
                    let msg = format!("{}", info);
                    if msg.contains("Stop signal") || msg.contains("Timeout reached") {
                        return;
                    }
                    eprintln!("{}", info);
                }));

                // Check stop signal at startup - if set, exit immediately
                // This prevents respawned workers from continuing after --stop-on-crash
                if stop_signal_file_for_client.exists() {
                    return Err(LibAflError::ShuttingDown);
                }

                let mut coverage_map = vec![0u8; #mod_name::MAP_SIZE];
                let cov_ptr = coverage_map.as_mut_ptr();

                // Setup template fixture per worker (fresh SVM instance)
                if std::env::var("FUZZ_NO_TRACING").is_err() {
                    std::env::set_var("ANCHOR_FUZZ_DEBUGGABLE", "1");
                }
                let template_fixture = #fixture_name::setup();

                // Take snapshot of initial SVM state for reference
                #[allow(unused_mut)]
                let mut template_fixture = template_fixture;
                template_fixture.ctx.take_snapshot();
                if worker_id == 0 {
                    eprintln!("[FUZZ] Worker 0: snapshot taken ({} tracked accounts)",
                        template_fixture.ctx.tracked_accounts_count());
                }

                // SVM swap trick: move SVM out of template so clone is cheap (empty SVM + Arc programs).
                // The real SVM is swapped in/out of each iteration's clone, never deep-copied.
                // Keep a pristine copy for periodic full reset (prevents unbounded internal state growth
                // in LiteSVM's accounts HashMap, program cache, etc.)
                let __pristine_svm = template_fixture.ctx.svm.clone();
                let mut __saved_svm = std::mem::replace(
                    &mut template_fixture.ctx.svm,
                    litesvm::LiteSVM::new(),
                );

                // Periodic full SVM reset interval (0 = disabled)
                let __svm_reset_interval: u64 = std::env::var("FUZZ_SVM_RESET_INTERVAL")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1000);

                // Observer and feedback setup (multi-core uses SharedBitmapFeedback)
                // HitcountsMapObserver applies AFL-style bucketing (1,2,3,4-7,8-15,16-31,32-127,128+)
                let edges_observer = unsafe { StdMapObserver::from_mut_ptr("edges", cov_ptr, #mod_name::MAP_SIZE) };
                let edges_observer = HitcountsMapObserver::new(edges_observer);
                let time_observer = TimeObserver::new("time");

                // SharedBitmapFeedback checks if any NEW bits were set in the shared bitmap
                // TimeFeedback stores execution time metadata for PowerQueueScheduler
                // SuccessPatternFeedback attaches action success/fail metadata to corpus entries
                let bitmap_feedback = #mod_name::SharedBitmapFeedback::new();
                let time_feedback = TimeFeedback::new(&time_observer);
                let success_pattern_feedback = #mod_name::SuccessPatternFeedback::new();
                let mut feedback = feedback_or!(bitmap_feedback, time_feedback, success_pattern_feedback);
                let mut objective = CrashFeedback::new();

                // Create state with shared corpus
                // Use CachedOnDiskCorpus to reduce disk I/O - caches up to 1000 entries in memory
                let rand = StdRand::with_seed(seed.wrapping_add(_client_desc.core_id().0 as u64));
                let corpus = CachedOnDiskCorpus::<BytesInput>::no_meta(&shared_corpus_dir_for_client, 1000)
                    .expect("failed to create cached on-disk corpus");
                let solutions = OnDiskCorpus::new(&crash_dir).expect("failed to create crash corpus");

                let mut state = state.unwrap_or_else(|| {
                    StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)
                        .expect("failed to create StdState")
                });

                // Cap input size to prevent unbounded growth
                #max_size_setup

                // PowerQueueScheduler prioritizes inputs that execute faster and discover more coverage
                let scheduler = PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::explore());

                let start_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let _ = #mod_name::FUZZER_START_TIME.set(start_time);

                let timeout_secs: Option<u64> = std::env::var("FUZZ_TIMEOUT_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok());

                let iteration_counter = std::sync::atomic::AtomicU64::new(0);

                let crash_dir_clone = crash_dir.clone();
                // Track if this worker should stop (timeout or stop-on-crash)
                let mut should_stop = false;

                // Clone stop signal file path for harness closure
                let stop_signal_for_harness = stop_signal_file_for_client.clone();

                // Local accumulators for batching shared counter updates
                // Both are flushed together every 64 iterations to ensure accurate actions/exec ratio
                let mut __local_actions_pending: u64 = 0;
                let mut __local_execs_pending: u64 = 0;

                let mut harness_wrapper = |input: &BytesInput| -> ExitKind {
                    // Check file-based stop signal (set by any worker on --stop-on-crash or timeout)
                    // Rate-limit this check to every 100 iterations to avoid filesystem overhead
                    let current_iter = iteration_counter.load(std::sync::atomic::Ordering::Relaxed);
                    let global_stop = if current_iter % 100 == 0 {
                        stop_signal_for_harness.exists()
                    } else {
                        false
                    };

                    if global_stop || should_stop {
                        // Panic to break out of fuzz_loop - LibAFL will catch this
                        // and the worker will return, triggering ShuttingDown check on respawn
                        panic!("Stop signal received");
                    }

                    let bytes_ref = input.target_bytes();
                    let slice = bytes_ref.as_slice();
                    #unstructured_init

                    let current_iteration = iteration_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // Rate-limit timeout check to every 1000 iterations to avoid syscall overhead
                    if let Some(timeout) = timeout_secs {
                        if current_iteration % 1000 == 0 {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            if now - start_time >= timeout {
                                eprintln!("\n[FUZZ] Timeout reached ({}s). Worker {} stopping.", timeout, worker_id);
                                should_stop = true;
                                // Create stop signal file to notify all workers
                                let _ = std::fs::write(&stop_signal_for_harness, b"stop");
                                panic!("Timeout reached");
                            }
                        }
                    }
                    crucible_test_context::set_current_iteration(current_iteration);
                    crucible_test_context::clear_action_history();
                    crucible_test_context::clear_violation_tracking();
                    // Reset the "new coverage" flag for SharedBitmapFeedback
                    #mod_name::reset_new_coverage_flag();

                    // Periodic full SVM reset: replace working SVM with pristine clone to prevent
                    // unbounded growth in LiteSVM internals (accounts HashMap, program cache, etc.)
                    if __svm_reset_interval > 0 && current_iteration > 0 && current_iteration % __svm_reset_interval == 0 {
                        __saved_svm = __pristine_svm.clone();
                    }

                    #(#deser_stmts)*

                    // Clone template for clean non-SVM state (cheap: empty SVM + Arc programs)
                    let mut #fixture_param_name = template_fixture.clone();

                    // Swap real SVM into the clone
                    std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __saved_svm);

                    let callback = #mod_name::FuzzCallback::with_shared_memory(
                        cov_ptr,
                        #mod_name::MAP_SIZE,
                        shared_edge_ptr,
                        shared_branch_ptr,
                    );
                    #fixture_param_name.ctx.set_invocation_callback(callback);

                    // Track action count before test function for delta calculation
                    let actions_before = crucible_test_context::TOTAL_ACTIONS_DISPATCHED
                        .load(std::sync::atomic::Ordering::Relaxed);

                    #fn_name(#(#call_args),*);

                    // Collect success pattern from action history for SuccessPatternFeedback
                    {
                        let __history = crucible_test_context::get_action_history();
                        let __pattern: Vec<bool> = __history.iter().map(|r| r.success).collect();
                        #mod_name::set_success_pattern(__pattern);
                    }

                    // Flush thread-local bitmap buffers to shared memory at end of iteration.
                    // This is required for SharedBitmapFeedback to detect new coverage.
                    // The buffering still reduces atomic ops by merging updates within the iteration.
                    #mod_name::flush_local_bitmap_buffers(shared_edge_ptr, shared_branch_ptr);

                    // Accumulate this iteration's action count and execution count locally
                    let actions_this_iter = crucible_test_context::TOTAL_ACTIONS_DISPATCHED
                        .load(std::sync::atomic::Ordering::Relaxed) - actions_before;
                    __local_actions_pending += actions_this_iter;
                    __local_execs_pending += 1;

                    // Flush both counters together every 64 iterations to reduce atomic contention.
                    // Flushing together ensures the actions/exec ratio is always accurate since
                    // both numerator and denominator update atomically in lockstep.
                    if current_iteration % 64 == 0 {
                        unsafe {
                            let action_counter = &*(shared_actions_ptr as *const std::sync::atomic::AtomicU64);
                            action_counter.fetch_add(__local_actions_pending, std::sync::atomic::Ordering::Relaxed);
                            let exec_counter = &*(shared_execs_ptr as *const std::sync::atomic::AtomicU64);
                            exec_counter.fetch_add(__local_execs_pending, std::sync::atomic::Ordering::Relaxed);
                        }
                        __local_actions_pending = 0;
                        __local_execs_pending = 0;
                    }

                    // Restore dirty accounts from snapshot (O(dirty) not O(all))
                    if let Some(ref snap) = template_fixture.ctx.snapshot {
                        snap.restore(&mut #fixture_param_name.ctx.svm, &#fixture_param_name.ctx.dirty_tracker);
                    }
                    // Clear all tracked dirty state after restore
                    #fixture_param_name.ctx.dirty_tracker.clear();
                    #fixture_param_name.ctx.taint_log.clear();

                    // Swap restored SVM back for next iteration
                    std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __saved_svm);
                    // fixture is dropped here (cheap: only empty SVM + small fields)

                    if let Some(msg) = crucible_test_context::take_violation() {
                        if std::env::var("FUZZ_VERBOSE").is_ok() {
                            eprintln!("[VIOLATION] {}", msg);
                            crucible_test_context::print_action_sequence();
                        }
                        let input_hash = hash_std(slice);
                        crucible_test_context::write_crash_metadata(&crash_dir_clone, input_hash, Some(seed), slice);

                        // Stop on first crash if requested
                        if std::env::var("FUZZ_STOP_ON_CRASH").is_ok() {
                            eprintln!("[FUZZ] First crash found. Worker {} signaling stop (--stop-on-crash).", worker_id);
                            // Create stop signal file to notify all workers
                            let _ = std::fs::write(&stop_signal_for_harness, b"stop");
                            should_stop = true;
                            // Return Crash to record it, then next iteration will panic and stop
                        }

                        ExitKind::Crash
                    } else {
                        ExitKind::Ok
                    }
                };

                let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
                let timeout = Duration::from_millis(10000);
                let mut executor = InProcessExecutor::with_timeout(
                    &mut harness_wrapper,
                    tuple_list!(edges_observer, time_observer),
                    &mut fuzzer,
                    &mut state,
                    &mut mgr,
                    timeout,
                )
                .expect("failed to create InProcessExecutor");

                // =====================================================================
                // FULL CORPUS LOADING via load_initial_inputs_forced
                // All workers load the full corpus so they can mutate any seed input
                // Monitor is patched to show actual file count instead of N× inflated count
                // =====================================================================
                use libafl::corpus::Corpus;

                // Load from corpus_in if provided, otherwise corpus_out may have entries from prior runs
                let corpus_dirs_to_load: Vec<std::path::PathBuf> = if let Some(ref corpus_in) = corpus_in_dir_for_client {
                    vec![std::path::PathBuf::from(corpus_in)]
                } else if std::fs::read_dir(&shared_corpus_dir_for_client)
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(false)
                {
                    // Corpus out has existing entries, load from there
                    vec![std::path::PathBuf::from(&shared_corpus_dir_for_client)]
                } else {
                    vec![]
                };

                if !corpus_dirs_to_load.is_empty() {
                    // Full loading: all workers load all inputs for complete seed access
                    state.load_initial_inputs_forced(
                        &mut fuzzer,
                        &mut executor,
                        &mut mgr,
                        &corpus_dirs_to_load,
                    ).unwrap_or_else(|e| {
                        eprintln!("[Worker {}] Failed to load corpus: {:?}", worker_id, e);
                    });
                }

                // Ensure at least one input - ALL workers need a seed to fuzz
                if state.corpus().count() == 0 {
                    #default_seed_code
                }

                let loaded = state.corpus().count();
                eprintln!("[Worker {}] Loaded {} corpus entries (ready to fuzz)", worker_id, loaded);

                #mutator_setup

                fuzzer
                    .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                    .expect("error in fuzz loop");

                Ok(())
            };

            // Build and launch the multi-core fuzzer
            let cores = Cores::from((0..num_cores).collect::<Vec<_>>());

            // Set up panic hook for Launcher to suppress expected shutdown panics
            let default_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                // Suppress by source location (LibAFL shmem cleanup + double-panic)
                if let Some(loc) = info.location() {
                    let file = loc.file();
                    if file.contains("unix_shmem_server") || file.contains("panicking.rs") {
                        return;
                    }
                }
                // Suppress by message content
                let msg = format!("{}", info);
                if msg.contains("Storing state in crashed fuzzer") ||
                   msg.contains("Stop signal") ||
                   msg.contains("Timeout reached") {
                    return;
                }
                default_hook(info);
            }));

            // Use catch_unwind to handle expected panics during shutdown gracefully
            let launcher_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Launcher::builder()
                    .shmem_provider(shmem_provider)
                    .configuration(EventConfig::from_name("default"))
                    .monitor(monitor)
                    .run_client(&mut run_client)
                    .cores(&cores)
                    .broker_port(1337)
                    .build()
                    .launch()
            }));

            // Check if stop was due to --stop-on-crash before cleanup
            let was_stop_on_crash = stop_signal_file.exists() &&
                std::env::var("FUZZ_STOP_ON_CRASH").is_ok();

            // Clean up stop signal file
            let _ = std::fs::remove_file(&stop_signal_file);

            match launcher_result {
                Ok(Ok(())) => eprintln!("[FUZZ] Fuzzing completed"),
                Ok(Err(LibAflError::ShuttingDown)) => {
                    if was_stop_on_crash {
                        eprintln!("[FUZZ] Stopped on first crash (--stop-on-crash)");
                    } else {
                        eprintln!("[FUZZ] Fuzzing stopped");
                    }
                }
                Ok(Err(e)) => eprintln!("[FUZZ] Launcher error: {}", e),
                Err(_) => {
                    // Panic during shutdown (expected with --stop-on-crash or timeout)
                    if was_stop_on_crash {
                        eprintln!("[FUZZ] Stopped on first crash (--stop-on-crash)");
                    }
                    // Don't print anything else - shutdown was clean
                }
            }

            return;
        }
    }
}
