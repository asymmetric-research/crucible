//! Single-core fuzzing support for the anchor-fuzz macro.
//!
//! This module contains code generation for single-threaded fuzzing modes:
//! - On-disk corpus mode (when --corpus-out is specified)
//! - In-memory corpus mode (default)
//!
//! The code is structured to minimize duplication while working within Rust's
//! type system constraints (StdState is generic over corpus type).

use quote::quote;

use crate::codegen;

/// Generate the single-core fuzzing mode code
///
/// Uses a macro_rules! macro internally to avoid code duplication between
/// on-disk and in-memory corpus modes. The macro handles all common logic
/// while the outer code handles corpus-specific setup.
pub fn singlecore_mode(
    mod_name: &syn::Ident,
    fixture_name: &syn::Ident,
    fn_name: &syn::Ident,
    fixture_param_name: &syn::Ident,
    feature_name: &str,
    deser_stmts: &[proc_macro2::TokenStream],
    call_args: &[proc_macro2::TokenStream],
    structured: bool,
    action_type: Option<&proc_macro2::TokenStream>,
    contexts: &[syn::Ident],
) -> proc_macro2::TokenStream {
    let monitor_setup = codegen::monitor_setup(mod_name);
    let common_fuzz_setup = codegen::common_fuzz_setup(mod_name, fixture_name);
    let exit_handlers_setup = codegen::exit_handlers_setup(mod_name);
    let observer_feedback_setup = codegen::singlecore_observer_feedback(mod_name);

    // Use structured or arbitrary mutator/seed setup
    let mutator_stages_setup = if structured {
        codegen::structured_mutator_stages_setup(action_type.unwrap())
    } else {
        codegen::mutator_stages_setup()
    };

    let add_default_seed = if structured {
        codegen::structured_add_default_seed(action_type.unwrap())
    } else {
        codegen::add_default_seed()
    };

    // Conditionally include Unstructured creation in harness
    let unstructured_init = if structured {
        quote! {}
    } else {
        quote! { let mut u = Unstructured::new(slice); }
    };

    // Generate per-context code blocks
    let ctx_take_snapshot = codegen::contexts_take_snapshot(contexts);
    let ctx_swap_out = codegen::contexts_swap_out(contexts);
    let ctx_reset = codegen::contexts_reset_check(contexts);
    let ctx_swap_in = codegen::contexts_swap_in(fixture_param_name, contexts);
    let ctx_restore = codegen::contexts_restore_and_clear(fixture_param_name, contexts);
    let ctx_swap_back = codegen::contexts_swap_back(fixture_param_name, contexts);
    let ctx_no_tracing = codegen::contexts_no_tracing_switch(fixture_name, contexts);

    // Harness wrapper code - shared between both corpus modes
    let harness_wrapper_code = quote! {
        // Take snapshot of initial SVM state for reference
        #[allow(unused_mut)]
        let mut template_fixture = template_fixture;
        #ctx_take_snapshot
        if verbose {
            eprintln!("[FUZZ] Snapshot taken ({} tracked accounts)",
                template_fixture.ctx.tracked_accounts_count());
        }

        // SVM swap trick: move SVM out of template so clone is cheap (empty SVM + Arc programs).
        // The real SVM is swapped in/out of each iteration's clone, never deep-copied.
        // Keep a pristine copy for periodic full reset (prevents unbounded internal state growth
        // in LiteSVM's accounts HashMap, program cache, etc.)
        #ctx_swap_out

        // Periodic full SVM reset interval (0 = disabled)
        let __svm_reset_interval: u64 = std::env::var("FUZZ_SVM_RESET_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);

        let mut harness_wrapper = |input: &BytesInput| -> ExitKind {
            let bytes_ref = input.target_bytes();
            let slice = bytes_ref.as_slice();
            #unstructured_init

            let current_iteration = iteration_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // Periodic full SVM reset: replace working SVM with pristine clone to prevent
            // unbounded growth in LiteSVM internals (accounts HashMap, program cache, etc.)
            #ctx_reset

            // Rate-limit timeout check to every 1000 iterations to avoid syscall overhead
            if let Some(timeout) = timeout_secs {
                if current_iteration % 1000 == 0 {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    if now - start_time >= timeout {
                        eprintln!("\n[FUZZ] Timeout reached ({}s). Exiting gracefully.", timeout);
                        if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                            #mod_name::write_lcov_coverage("coverage.lcov");
                        }
                        std::process::exit(0);
                    }
                }
            }

            crucible_test_context::set_current_iteration(current_iteration);
            crucible_test_context::clear_iteration_state();

            #(#deser_stmts)*

            // Clone template for clean non-SVM state (cheap: empty SVM + Arc programs)
            let mut #fixture_param_name = template_fixture.clone();

            // Swap real SVMs into the clone
            #ctx_swap_in

            let callback = #mod_name::FuzzCallback::from_raw(cov_ptr, #mod_name::MAP_SIZE);
            #fixture_param_name.ctx.set_invocation_callback(callback);

            // Wrap test function in catch_unwind so panics print location and exit cleanly
            let __panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #fn_name(#(#call_args),*);
            }));

            // Collect success pattern from action history for SuccessPatternFeedback
            {
                let __history = crucible_test_context::get_action_history();
                let __pattern: Vec<bool> = __history.iter().map(|r| r.success).collect();
                #mod_name::set_success_pattern(__pattern);
            }

            let exec_count = #mod_name::TOTAL_EXECUTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                #mod_name::maybe_write_coverage(exec_count);
            }

            // Restore dirty accounts from snapshot (O(dirty) not O(all))
            #ctx_restore

            // Swap restored SVMs back for next iteration
            #ctx_swap_back
            // fixture is dropped here (cheap: only empty SVM + small fields)

            // On panic: resume unwinding so the default panic handler prints
            // the message with file/line, then the process exits naturally
            if let Err(__panic_payload) = __panic_result {
                std::panic::resume_unwind(__panic_payload);
            }

            if let Some(msg) = crucible_test_context::take_violation() {
                println!("[FUZZ_FINDING] reproduces:true summary:{}", msg);
                eprintln!("[FUZZ_FINDING] {}", msg);
                crucible_test_context::print_action_sequence();
                // Use the same hash as LibAFL (xxh3_64) so our metadata matches LibAFL's crash filenames
                let input_hash = hash_std(slice);
                crucible_test_context::write_crash_metadata(&crash_dir, input_hash, Some(seed), slice);

                // Stop on first crash if requested
                if std::env::var("FUZZ_STOP_ON_CRASH").is_ok() {
                    eprintln!("[FUZZ] First crash found. Exiting (--stop-on-crash).");
                    std::process::exit(0);
                }

                ExitKind::Crash
            } else {
                ExitKind::Ok
            }
        };
    };

    let max_size_setup = codegen::max_size_setup();

    quote! {
        // === SINGLE-THREADED MODE (default) ===

        // Use seed from env var if provided, otherwise use current time
        let seed = std::env::var("FUZZ_SEED")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| current_nanos().max(1));

        // Configure directories based on environment variables
        let crash_dir = crashes_dir_env.unwrap_or_else(|| format!("crashes/{}", #feature_name));
        std::fs::create_dir_all(&crash_dir).expect("failed to create crash directory");

        // Internal macro to avoid code duplication between corpus modes
        // This works around Rust's type system (StdState is generic over corpus type)
        macro_rules! run_fuzz_loop {
            ($corpus:expr) => {{
                #monitor_setup
                #observer_feedback_setup

                let rand = StdRand::with_seed(seed);
                let solutions = OnDiskCorpus::new(&crash_dir).expect("failed to create crash corpus");
                let mut state = StdState::new(rand, $corpus, solutions, &mut feedback, &mut objective)
                    .expect("failed to create StdState");

                // Cap input size to prevent unbounded growth
                #max_size_setup

                let scheduler = PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::explore());

                #common_fuzz_setup
                #harness_wrapper_code

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

                // Load seed corpus if specified
                if let Some(ref corpus_dir) = corpus_in_dir {
                    eprintln!("[FUZZ] Loading seed corpus from: {}", corpus_dir);
                    let corpus_dirs = vec![std::path::PathBuf::from(corpus_dir)];

                    // Always use forced loading so ALL seed inputs are kept.
                    // Non-forced loading rejects entries that don't pass MaxMapFeedback
                    // (e.g. entries that only discovered hitcount bucket novelty).
                    crucible_test_context::set_corpus_loading(true);
                    state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                        .expect("failed to load initial corpus");
                    crucible_test_context::set_corpus_loading(false);

                    let corpus_count = state.corpus().count();
                    let __load_edges = {
                        let s = #mod_name::COVERAGE_STATE.lock().unwrap();
                        s.total_edges
                    };
                    eprintln!("[FUZZ] Loaded {} seed inputs, edges after loading: {} (corpus loading complete)", corpus_count, __load_edges);
                    if corpus_count == 0 {
                        if verbose { eprintln!("[FUZZ] No valid inputs in corpus, using default seed"); }
                        #add_default_seed
                    }
                } else {
                    #add_default_seed
                }

                // After corpus loading, switch to non-tracing SVM for max throughput.
                // The corpus was loaded with tracing enabled so the coverage baseline
                // is populated. Now recreate the fixture without JIT instrumentation.
                #ctx_no_tracing

                #mutator_stages_setup
                #exit_handlers_setup

                fuzzer
                    .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                    .expect("error in fuzz loop");
            }};
        }

        // Branch based on whether corpus output directory is specified
        if let Some(ref corpus_out_path) = corpus_out_dir {
            // === ON-DISK CORPUS MODE ===
            std::fs::create_dir_all(corpus_out_path).expect("failed to create corpus output directory");

            // Check if we're loading from this same directory
            let loading_from_same_dir = corpus_in_dir.as_ref().map(|cin| {
                std::path::Path::new(cin)
                    .canonicalize()
                    .ok()
                    .and_then(|cin_canon| std::path::Path::new(corpus_out_path)
                        .canonicalize()
                        .ok()
                        .map(|cout_canon| cin_canon == cout_canon))
                    .unwrap_or(false)
            }).unwrap_or(false);

            // If NOT loading from this directory, clean up ALL metadata files
            // This prevents CachedOnDiskCorpus from trying to load entries from a previous run
            if !loading_from_same_dir {
                let mut removed = 0usize;
                if let Ok(entries) = std::fs::read_dir(corpus_out_path) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let path = entry.path();
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            // Remove ALL hidden files (LibAFL metadata)
                            if name.starts_with('.') {
                                if std::fs::remove_file(&path).is_ok() {
                                    removed += 1;
                                }
                            }
                        }
                    }
                }
                if removed > 0 && verbose {
                    eprintln!("[FUZZ] Cleaned {} stale metadata files from corpus directory", removed);
                }
            }

            if verbose { eprintln!("[FUZZ] Writing corpus entries to: {}", corpus_out_path); }

            // CachedOnDiskCorpus: caches up to 1000 entries in memory to reduce disk I/O
            let corpus = CachedOnDiskCorpus::<BytesInput>::no_meta(corpus_out_path, 1000)
                .expect("failed to create corpus");

            run_fuzz_loop!(corpus);
        } else {
            // === IN-MEMORY CORPUS MODE (default) ===
            let corpus: InMemoryCorpus<BytesInput> = InMemoryCorpus::new();
            run_fuzz_loop!(corpus);
        }
    }
}
