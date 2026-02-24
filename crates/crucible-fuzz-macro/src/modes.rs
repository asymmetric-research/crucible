//! Execution modes for the anchor-fuzz macro.
//!
//! This module contains code generation for different execution modes:
//! - Dry-run mode: Validate harness setup with a single iteration
//! - Input replay mode: Replay a specific input file
//! - Coverage-only mode: Run corpus once for coverage report
//! - Tmin mode: Minimize a crash to smallest reproducing action sequence

use quote::quote;

use crate::codegen;

/// Generate the dry-run mode code
pub fn dry_run_mode(
    mod_name: &syn::Ident,
    fixture_name: &syn::Ident,
    fn_name: &syn::Ident,
    simple_deser_stmts: &[proc_macro2::TokenStream],
    call_args: &[proc_macro2::TokenStream],
    structured: bool,
) -> proc_macro2::TokenStream {
    let init_coverage_totals = codegen::init_coverage_totals(mod_name);
    let init_program_binaries = codegen::init_program_binaries(mod_name);

    // For structured mode, simple_deser_stmts reference __raw_bytes
    // For arbitrary mode, they reference u (Unstructured)
    let deser_block = if structured {
        quote! {
            let __raw_bytes = seed_bytes;
            #(#simple_deser_stmts)*
        }
    } else {
        quote! {
            let mut u = Unstructured::new(&seed_bytes);
            #(#simple_deser_stmts)*
        }
    };

    quote! {
        // === DRY-RUN MODE ===
        // Run setup and a single iteration to validate the harness works
        // Supports --coverage and --corpus-in flags
        if dry_run_mode {
            eprintln!("[DRY-RUN] Validating harness setup...");

            // Setup tracing for coverage
            std::env::set_var("ANCHOR_FUZZ_DEBUGGABLE", "1");

            // Run setup
            let template_fixture = #fixture_name::setup();
            eprintln!("[DRY-RUN] Setup completed successfully");
            eprintln!("[DRY-RUN] - {} tracked accounts", template_fixture.ctx.tracked_accounts_count());
            eprintln!("[DRY-RUN] - {} programs loaded", template_fixture.ctx.programs_count());

            // Initialize coverage tracking if --coverage is enabled
            if coverage_enabled {
                #mod_name::COVERAGE_ENABLED.store(true, std::sync::atomic::Ordering::Relaxed);
                #init_coverage_totals
                #init_program_binaries
            }

            // Run a single iteration with seed input
            // Use set_invocation_callback to avoid double SVM clone
            let callback = #mod_name::FuzzCallback::from_raw(cov_ptr, #mod_name::MAP_SIZE);
            let mut fixture = template_fixture.clone();
            fixture.ctx.set_invocation_callback(callback);

            // Load input from corpus-in if specified, otherwise use default seed
            let seed_bytes: Vec<u8> = if let Some(ref corpus_dir) = corpus_in_dir {
                // Try to load first valid input from corpus
                let mut found_bytes = None;
                if let Ok(entries) = std::fs::read_dir(corpus_dir) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let path = entry.path();
                        if path.is_file() {
                            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                // Skip hidden files and metadata
                                if !name.starts_with('.') && !name.ends_with(".metadata") && !name.ends_with(".meta.json") {
                                    if let Ok(bytes) = std::fs::read(&path) {
                                        eprintln!("[DRY-RUN] Using input from corpus: {}", name);
                                        found_bytes = Some(bytes);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                found_bytes.unwrap_or_else(|| {
                    eprintln!("[DRY-RUN] No valid inputs in corpus, using default seed");
                    vec![0u8; 256]
                })
            } else {
                vec![0u8; 256]
            };

            #deser_block

            #fn_name(#(#call_args),*);

            eprintln!("[DRY-RUN] Single iteration completed successfully");

            // Write coverage if --coverage was enabled
            if coverage_enabled {
                #mod_name::write_lcov_coverage("coverage.lcov");
                eprintln!("[DRY-RUN] Coverage written to coverage.lcov");
            }

            eprintln!("[DRY-RUN] Harness validation passed!");
            std::process::exit(0);
        }
    }
}

/// Generate the single input replay mode code
pub fn replay_mode(
    mod_name: &syn::Ident,
    fixture_name: &syn::Ident,
    fn_name: &syn::Ident,
    simple_deser_stmts: &[proc_macro2::TokenStream],
    call_args: &[proc_macro2::TokenStream],
    structured: bool,
) -> proc_macro2::TokenStream {
    let init_coverage_totals = codegen::init_coverage_totals(mod_name);

    // For structured mode, simple_deser_stmts reference __raw_bytes
    let deser_block = if structured {
        quote! {
            let __raw_bytes = input_bytes;
            #(#simple_deser_stmts)*
        }
    } else {
        quote! {
            let mut u = Unstructured::new(&input_bytes);
            #(#simple_deser_stmts)*
        }
    };

    quote! {
        // === SINGLE INPUT REPLAY MODE ===
        // Replay a specific input file and report the outcome
        if let Some(ref input_path) = input_file {
            eprintln!("[REPLAY] Loading input from: {}", input_path);

            let input_bytes = match std::fs::read(input_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("[REPLAY] Failed to read input file: {}", e);
                    std::process::exit(1);
                }
            };

            eprintln!("[REPLAY] Input size: {} bytes", input_bytes.len());

            // Setup tracing for coverage
            std::env::set_var("ANCHOR_FUZZ_DEBUGGABLE", "1");

            // Run setup
            let template_fixture = #fixture_name::setup();

            // Initialize coverage totals for reporting (replay only needs totals, not binaries)
            { #init_coverage_totals }

            // Use set_invocation_callback to avoid double SVM clone
            let callback = #mod_name::FuzzCallback::from_raw(cov_ptr, #mod_name::MAP_SIZE);
            let mut fixture = template_fixture.clone();
            fixture.ctx.set_invocation_callback(callback);

            // Reset iteration counter
            crucible_test_context::set_current_iteration(0);

            // Parse input and run test
            #deser_block

            // Clear any previous action sequence
            crucible_test_context::clear_action_history();

            eprintln!("[REPLAY] Executing test...");
            #fn_name(#(#call_args),*);

            // Check for crash/violation
            let violation_msg = crucible_test_context::take_violation();

            // Rewrite .meta.json with latest action history (includes taint data)
            {
                let input_path_buf = std::path::PathBuf::from(input_path);
                if let (Some(parent), Some(filename)) = (input_path_buf.parent(), input_path_buf.file_name()) {
                    let crash_id = filename.to_string_lossy().to_string();
                    let crashes_dir = parent.to_string_lossy().to_string();
                    crucible_test_context::write_crash_metadata_for_id(&crashes_dir, &crash_id, None);
                    eprintln!("[REPLAY] Updated {}.meta.json", crash_id);
                }
            }

            if let Some(msg) = violation_msg {
                eprintln!("[REPLAY] CRASH REPRODUCED!");
                eprintln!("[REPLAY] Violation: {}", msg);
                crucible_test_context::print_action_sequence();
                std::process::exit(1);
            } else {
                eprintln!("[REPLAY] Test completed without crash");
                eprintln!("[REPLAY] Note: If you expected a crash, the input may be from a different harness version");
                crucible_test_context::print_action_sequence();
                std::process::exit(0);
            }
        }
    }
}

/// Generate the coverage-only mode code
pub fn coverage_only_mode(
    mod_name: &syn::Ident,
    fixture_name: &syn::Ident,
    fn_name: &syn::Ident,
    simple_deser_stmts: &[proc_macro2::TokenStream],
    call_args: &[proc_macro2::TokenStream],
    structured: bool,
) -> proc_macro2::TokenStream {
    let init_coverage_totals = codegen::init_coverage_totals(mod_name);
    let init_program_binaries = codegen::init_program_binaries(mod_name);
    let init_dwarf = codegen::init_dwarf_maps(mod_name);

    // For structured mode, simple_deser_stmts reference __raw_bytes
    let deser_block = if structured {
        quote! {
            let __raw_bytes = input_bytes.clone();
            #(#simple_deser_stmts)*
        }
    } else {
        quote! {
            let mut u = Unstructured::new(&input_bytes);
            #(#simple_deser_stmts)*
        }
    };

    quote! {
        // === COVERAGE-ONLY MODE ===
        // Load corpus and run each input once for coverage, then exit
        if coverage_only_mode {
            let corpus_dir = match &corpus_in_dir {
                Some(dir) => dir.clone(),
                None => {
                    eprintln!("[COVERAGE-ONLY] Error: --corpus-in required for coverage-only mode");
                    std::process::exit(1);
                }
            };

            eprintln!("[COVERAGE-ONLY] Loading corpus from: {}", corpus_dir);

            // Collect input files (excluding metadata)
            let input_files: Vec<_> = match std::fs::read_dir(&corpus_dir) {
                Ok(entries) => entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        let path = e.path();
                        path.is_file() && is_corpus_input(&path)
                    })
                    .collect(),
                Err(e) => {
                    eprintln!("[COVERAGE-ONLY] Failed to read corpus directory: {}", e);
                    std::process::exit(1);
                }
            };

            eprintln!("[COVERAGE-ONLY] Found {} input files", input_files.len());

            if input_files.is_empty() {
                eprintln!("[COVERAGE-ONLY] No input files found in corpus directory");
                std::process::exit(1);
            }

            // Setup tracing for coverage
            std::env::set_var("ANCHOR_FUZZ_DEBUGGABLE", "1");

            // Run setup
            #mod_name::COVERAGE_ENABLED.store(true, std::sync::atomic::Ordering::Relaxed);
            let template_fixture = #fixture_name::setup();

            // Initialize coverage totals, binaries, and DWARF source maps (for LCOV output)
            {
                #init_coverage_totals
                #init_program_binaries
                #init_dwarf
            }

            // Process each input file
            let mut processed = 0usize;
            let mut errors = 0usize;

            for entry in input_files {
                let path = entry.path();
                let input_bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        eprintln!("[COVERAGE-ONLY] Failed to read {}: {}", path.display(), e);
                        errors += 1;
                        continue;
                    }
                };

                // Create fresh fixture for each input
                // Use set_invocation_callback to avoid double SVM clone (critical for performance in loops)
                let callback = #mod_name::FuzzCallback::from_raw(cov_ptr, #mod_name::MAP_SIZE);
                let mut fixture = template_fixture.clone();
                fixture.ctx.set_invocation_callback(callback);

                // Run the test in a closure to handle deserialization failures
                let run_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    #deser_block

                    #fn_name(#(#call_args),*);
                }));

                // Ignore panics from deserialization failures or test assertions
                let _ = run_result;

                // Clear any violation flag
                let _ = crucible_test_context::take_violation();

                processed += 1;

                if processed % 100 == 0 {
                    eprintln!("[COVERAGE-ONLY] Processed {} inputs...", processed);
                }
            }

            eprintln!("[COVERAGE-ONLY] Processed {} inputs ({} errors)", processed, errors);

            // Write coverage output
            let coverage_output = std::env::var("FUZZ_COVERAGE_OUT")
                .unwrap_or_else(|_| "coverage.lcov".to_string());
            #mod_name::write_lcov_coverage(&coverage_output);

            // Print summary
            let state = #mod_name::COVERAGE_STATE.lock().unwrap();
            let total_edges = state.total_edges;
            let total_branches = state.total_branches;
            drop(state);

            let edge_totals: usize = #mod_name::PROGRAM_TOTALS.get()
                .map(|t| t.values().sum())
                .unwrap_or(0);
            let branch_totals = edge_totals / 2;

            eprintln!("[COVERAGE-ONLY] Coverage: {} edges ({:.1}%), {} branches ({:.1}%)",
                total_edges,
                if edge_totals > 0 { (total_edges as f64 / edge_totals as f64) * 100.0 } else { 0.0 },
                total_branches,
                if branch_totals > 0 { (total_branches as f64 / branch_totals as f64) * 100.0 } else { 0.0 },
            );

            std::process::exit(0);
        }
    }
}

/// Generate the tmin (crash minimization) mode code.
///
/// Only works with structured mode (action sequences from #[invariant_test]).
/// Uses a 1-pass linear removal algorithm:
/// 1. Truncate actions after the violation index
/// 2. Try removing each remaining action; keep removal if crash still reproduces
pub fn tmin_mode(
    mod_name: &syn::Ident,
    fixture_name: &syn::Ident,
    fn_name: &syn::Ident,
    structured: bool,
    action_type: Option<&proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {
    if !structured {
        // For non-structured mode, emit a check that prints an error
        return quote! {
            if let Ok(_tmin_file) = std::env::var("FUZZ_TMIN_FILE") {
                eprintln!("[TMIN] ERROR: tmin only supports structured/invariant tests");
                std::process::exit(1);
            }
        };
    }

    let action_ty = match action_type {
        Some(ty) => ty,
        None => {
            return quote! {
                if let Ok(_tmin_file) = std::env::var("FUZZ_TMIN_FILE") {
                    eprintln!("[TMIN] ERROR: tmin requires an action type (structured mode)");
                    std::process::exit(1);
                }
            };
        }
    };

    quote! {
        // === TMIN MODE (Crash Minimization) ===
        // Supports two modes:
        //   FUZZ_TMIN_FILE — minimize a single crash file
        //   FUZZ_TMIN_ALL_DIR — minimize all crashes in a directory (one setup() call)
        if std::env::var("FUZZ_TMIN_FILE").is_ok() || std::env::var("FUZZ_TMIN_ALL_DIR").is_ok() {
            // Collect crash files to minimize
            let crash_files: Vec<(String, std::path::PathBuf)> = if let Ok(all_dir) = std::env::var("FUZZ_TMIN_ALL_DIR") {
                // --all mode: iterate all crash binaries with .meta.json in the directory
                let dir = std::path::Path::new(&all_dir);
                let mut files = Vec::new();
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if name.ends_with(".meta.json") {
                                let crash_id = name.strip_suffix(".meta.json").unwrap().to_string();
                                let binary_path = dir.join(&crash_id);
                                if binary_path.exists() && binary_path.is_file() {
                                    files.push((crash_id, binary_path));
                                }
                            }
                        }
                    }
                }
                files.sort_by(|a, b| a.0.cmp(&b.0));
                eprintln!("[TMIN] Found {} crash(es) to minimize", files.len());
                files
            } else {
                // Single file mode
                let tmin_file = std::env::var("FUZZ_TMIN_FILE").unwrap();
                let crash_id = std::env::var("FUZZ_TMIN_CRASH_ID").unwrap_or_default();
                vec![(crash_id, std::path::PathBuf::from(tmin_file))]
            };

            let crashes_dir = std::env::var("FUZZ_CRASHES_DIR").unwrap_or_else(|_| "crashes".into());

            // Setup fixture once — reused across all crash files.
            // No tracing needed: tmin only checks for violation, not coverage.
            let template_fixture = #fixture_name::setup();

            // Helper: suppress stderr during a closure (avoids verbose invariant output during trials)
            fn with_stderr_suppressed<F: FnOnce() -> R, R>(f: F) -> R {
                extern "C" {
                    fn dup(fd: i32) -> i32;
                    fn dup2(fd1: i32, fd2: i32) -> i32;
                    fn open(path: *const u8, flags: i32) -> i32;
                    fn close(fd: i32) -> i32;
                }
                const O_WRONLY: i32 = 1;
                unsafe {
                    let devnull = open(b"/dev/null\0".as_ptr(), O_WRONLY);
                    if devnull < 0 { return f(); } // fallback: don't suppress
                    let saved = dup(2);
                    dup2(devnull, 2);
                    close(devnull);
                    let result = f();
                    dup2(saved, 2);
                    close(saved);
                    result
                }
            }

            // Helper: execute an action sequence on a fresh clone, return whether it crashes
            let crashes = |actions: &[#action_ty], template: &#fixture_name| -> bool {
                let mut fixture = template.clone();
                crucible_test_context::clear_action_history();
                crucible_test_context::clear_violation_tracking();
                let _ = crucible_test_context::take_violation();
                with_stderr_suppressed(|| #fn_name(&mut fixture, actions.to_vec()));
                crucible_test_context::has_violation()
            };

            let total = crash_files.len();
            let start_time = std::time::Instant::now();

            for (idx, (crash_id, crash_path)) in crash_files.iter().enumerate() {
                let tmin_file = crash_path.to_str().unwrap();
                eprintln!("\n[TMIN] [{}/{}] {}", idx + 1, total, crash_id);

                let crash_bytes = match std::fs::read(tmin_file) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[TMIN] ERROR: failed to read {}: {}", tmin_file, e);
                        continue;
                    }
                };
                let fuzz_input = crucible_fuzzer::FuzzInput::<#action_ty>::from_bytes(&crash_bytes);
                let original_count = fuzz_input.actions.len();

                if original_count == 0 {
                    eprintln!("[TMIN] Skipping: no actions");
                    continue;
                }
                eprint!("[TMIN] {} actions", original_count);

                // Verify crash reproduces
                let mut actions = fuzz_input.actions;
                if !crashes(&actions, &template_fixture) {
                    eprintln!(" — does not reproduce, skipping");
                    continue;
                }

                // Truncate post-violation actions
                let violation_idx = crucible_test_context::get_violation_action_index();
                if let Some(vi) = violation_idx {
                    if vi + 1 < actions.len() {
                        actions.truncate(vi + 1);
                    }
                }

                // Multi-pass forward removal (loop until convergence)
                let mut pass = 1;
                loop {
                    let len_before_pass = actions.len();
                    let mut i = 0;
                    while i < actions.len() {
                        let removed = actions.remove(i);
                        if actions.is_empty() || !crashes(&actions, &template_fixture) {
                            actions.insert(i, removed);
                            i += 1;
                        } else {
                            // action removed successfully, don't increment i
                        }
                    }
                    if actions.len() == len_before_pass {
                        break;
                    }
                    pass += 1;
                }

                let removed_count = original_count - actions.len();
                if removed_count == 0 {
                    eprintln!(" → already minimal");
                } else {
                    eprintln!(" → {} actions ({} removed, {} passes)",
                        actions.len(), removed_count, pass);

                    // Write minimized crash binary
                    let minimized = crucible_fuzzer::FuzzInput::new(actions.clone());
                    std::fs::write(tmin_file, &minimized.to_bytes())
                        .expect("failed to write minimized crash");

                    // Update .meta.json — re-execute to capture clean action history
                    crucible_test_context::clear_action_history();
                    crucible_test_context::clear_violation_tracking();
                    {
                        let mut fixture = template_fixture.clone();
                        with_stderr_suppressed(|| #fn_name(&mut fixture, actions));
                    }
                    if !crash_id.is_empty() {
                        crucible_test_context::write_crash_metadata_for_id(&crashes_dir, crash_id, None);
                    }
                }
            }

            let elapsed = start_time.elapsed();
            eprintln!("\n[TMIN] Done. {} crashes in {:.1}s ({:.1}/s)",
                total, elapsed.as_secs_f64(), total as f64 / elapsed.as_secs_f64());
            std::process::exit(0);
        }
    }
}
