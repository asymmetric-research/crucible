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
) -> proc_macro2::TokenStream {
    let monitor_setup = codegen::monitor_setup(mod_name);
    let common_fuzz_setup = codegen::common_fuzz_setup(mod_name, fixture_name);
    let iteration_setup = codegen::iteration_setup(fixture_param_name, mod_name);
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

    // Harness wrapper code - shared between both corpus modes
    let harness_wrapper_code = quote! {
        let mut harness_wrapper = |input: &BytesInput| -> ExitKind {
            let bytes_ref = input.target_bytes();
            let slice = bytes_ref.as_slice();
            #unstructured_init

            let current_iteration = iteration_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // Rate-limit timeout check to every 300 iterations to avoid syscall overhead
            if let Some(timeout) = timeout_secs {
                if current_iteration % 300 == 0 {
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
            crucible_test_context::clear_action_history();
            crucible_test_context::clear_violation_tracking();

            #(#deser_stmts)*

            #iteration_setup

            #fn_name(#(#call_args),*);

            let exec_count = #mod_name::TOTAL_EXECUTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                #mod_name::maybe_write_coverage(exec_count);
            }

            if let Some(msg) = crucible_test_context::take_violation() {
                eprintln!("[VIOLATION] {}", msg);
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

    // Max input size: cap to prevent unbounded growth from havoc mutations
    // Structured: 8 actions * (2 bytes variant + ~5 fields * 8 bytes) = ~336 bytes typical max, 1024 is 3x headroom
    // Arbitrary: 1024 matches existing cap
    let max_size_setup = quote! { state.set_max_size(1024); };

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
            ($corpus:expr, $use_forced_loading:expr) => {{
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

                    if $use_forced_loading {
                        // Same-dir case: use load_initial_inputs_forced to avoid re-adding existing entries
                        state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                            .expect("failed to load initial corpus");
                    } else {
                        // Different directories or in-memory: use regular loading
                        state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                            .expect("failed to load initial corpus");
                    }

                    let corpus_count = state.corpus().count();
                    eprintln!("[FUZZ] Loaded {} seed inputs (corpus loading complete)", corpus_count);
                    if corpus_count == 0 {
                        if verbose { eprintln!("[FUZZ] No valid inputs in corpus, using default seed"); }
                        #add_default_seed
                    }
                } else {
                    #add_default_seed
                }

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

            run_fuzz_loop!(corpus, loading_from_same_dir);
        } else {
            // === IN-MEMORY CORPUS MODE (default) ===
            let corpus: InMemoryCorpus<BytesInput> = InMemoryCorpus::new();
            run_fuzz_loop!(corpus, false);
        }
    }
}
