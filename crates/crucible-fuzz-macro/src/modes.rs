//! Execution modes for the anchor-fuzz macro.
//!
//! This module contains code generation for different execution modes:
//! - Dry-run mode: Validate harness setup with a single iteration
//! - Input replay mode: Replay a specific input file
//! - Coverage-only mode: Run corpus once for coverage report

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
            if let Some(msg) = crucible_test_context::take_violation() {
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

            // Initialize coverage totals and binaries (for LCOV output)
            {
                #init_coverage_totals
                #init_program_binaries
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
