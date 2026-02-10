//! Common code generation blocks for the anchor-fuzz macro.
//!
//! This module contains reusable `quote!` blocks that are shared between
//! different execution modes (single-core, multi-core, dry-run, etc.).

use quote::quote;

/// Generate the initialization code for coverage totals
pub fn init_coverage_totals(mod_name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
        let mut edge_totals: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
        let mut instr_totals: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
        for (pubkey, (total_edges, total_instructions)) in template_fixture.ctx.get_program_coverage_totals() {
            let program_hash = u64::from_le_bytes(
                pubkey.to_bytes()[0..8].try_into().unwrap()
            );
            edge_totals.insert(program_hash, *total_edges);
            instr_totals.insert(program_hash, *total_instructions);
        }
        #mod_name::init_program_totals(edge_totals, instr_totals);
    }
}

/// Generate the initialization code for program binaries
pub fn init_program_binaries(mod_name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
        let mut program_binaries: std::collections::HashMap<u64, Vec<u8>> = std::collections::HashMap::new();
        for (pubkey, binary) in template_fixture.ctx.get_program_binaries() {
            let program_hash = u64::from_le_bytes(
                pubkey.to_bytes()[0..8].try_into().unwrap()
            );
            program_binaries.insert(program_hash, binary);
        }
        #mod_name::init_program_binaries(program_binaries.clone());
    }
}

/// Generate the template setup code
pub fn template_setup(
    fixture_name: &syn::Ident,
    mod_name: &syn::Ident,
) -> proc_macro2::TokenStream {
    let init_totals = init_coverage_totals(mod_name);
    let init_binaries = init_program_binaries(mod_name);

    quote! {
        std::env::set_var("ANCHOR_FUZZ_DEBUGGABLE", "1");
        let template_fixture = #fixture_name::setup();

        // Debug: verify accounts exist in template after setup
        if std::env::var("FUZZ_DEBUG").is_ok() {
            eprintln!("[SETUP] Template created with {} tracked accounts", template_fixture.ctx.tracked_accounts_count());
            eprintln!("[SETUP] Template has {} programs", template_fixture.ctx.programs_count());
        }

        // Initialize coverage tracking data
        {
            #init_totals
            #init_binaries
        }
    }
}

/// Generate the per-iteration setup code
pub fn iteration_setup(
    fixture_param_name: &syn::Ident,
    mod_name: &syn::Ident,
) -> proc_macro2::TokenStream {
    quote! {
        let mut #fixture_param_name = template_fixture.clone();
        let callback = #mod_name::FuzzCallback::from_raw(cov_ptr, #mod_name::MAP_SIZE);
        #fixture_param_name.ctx.set_invocation_callback(callback);

        // First iteration debug: verify accounts after clone
        static FIRST_ITERATION: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
        if std::env::var("FUZZ_DEBUG").is_ok() && FIRST_ITERATION.swap(false, std::sync::atomic::Ordering::SeqCst) {
            eprintln!("[ITER] After clone: {} tracked accounts", #fixture_param_name.ctx.tracked_accounts_count());
        }
    }
}

/// Generate the monitor setup code
pub fn monitor_setup(mod_name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
        let monitor = SimpleMonitor::new(|s| {
            let s = s.replace("objectives", "crashes");
            // Remove LibAFL's "edges: N" if present (we add our own program-level stats)
            let s = {
                let mut result = s.clone();
                if let Some(start) = result.find(", edges:") {
                    // Find the next comma or end of string after ", edges: N"
                    let rest = &result[start + 8..]; // skip ", edges:"
                    let end_offset = rest.find(',').map(|i| i + 8).unwrap_or(rest.len() + 8);
                    result = format!("{}{}", &result[..start], &result[start + end_offset..]);
                }
                result
            };
            let state = #mod_name::COVERAGE_STATE.lock().unwrap();
            let true_edges = state.total_edges;
            let branches = state.total_branches;
            drop(state);
            let total_edges: usize = #mod_name::PROGRAM_TOTALS.get().map(|t| t.values().sum()).unwrap_or(0);
            let total_branches = total_edges / 2;
            // Append program-level coverage stats to LibAFL's output
            if let Some(idx) = s.find("exec/sec:") {
                let edge_pct = if total_edges > 0 { (true_edges as f64 / total_edges as f64) * 100.0 } else { 0.0 };
                let branch_pct = if total_branches > 0 { (branches as f64 / total_branches as f64) * 100.0 } else { 0.0 };
                println!("{}, edges: {}/{} ({:.1}%), branches: {}/{} ({:.1}%)",
                    s.trim_end(), true_edges, total_edges, edge_pct, branches, total_branches, branch_pct);
            } else { println!("{s}"); }
        });
        let mut mgr = SimpleEventManager::new(monitor);
    }
}

/// Generate the observer and feedback setup for single-core mode (shared between on-disk and in-memory corpus modes)
/// HitcountsMapObserver applies AFL-style bucketing (1,2,3,4-7,8-15,16-31,32-127,128+)
/// This reduces noise and helps focus on meaningful coverage differences
pub fn singlecore_observer_feedback(mod_name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
        // HitcountsMapObserver applies AFL-style bucketing (1,2,3,4-7,8-15,16-31,32-127,128+)
        // This reduces noise and helps focus on meaningful coverage differences
        let edges_observer = unsafe { StdMapObserver::from_mut_ptr("edges", cov_ptr, #mod_name::MAP_SIZE) };
        let edges_observer = HitcountsMapObserver::new(edges_observer);
        let time_observer = TimeObserver::new("time");
        let map_feedback = MaxMapFeedback::new(&edges_observer);
        let time_feedback = TimeFeedback::new(&time_observer);
        let mut feedback = feedback_or!(map_feedback, time_feedback);
        let mut objective = CrashFeedback::new();
    }
}

/// Generate the observer and feedback setup for single-core mode (deprecated - use singlecore_observer_feedback)
#[allow(dead_code)]
pub fn observer_feedback_setup_singlecore(mod_name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
        // Use StdMapObserver directly (no hitcount bucketing) for simpler/faster coverage
        let edges_observer = unsafe { StdMapObserver::from_mut_ptr("edges", cov_ptr, #mod_name::MAP_SIZE) };
        let time_observer = TimeObserver::new("time");

        // MaxMapFeedback decides if input is interesting based on coverage
        // TimeFeedback only appends execution time metadata (is_interesting returns false)
        let map_feedback = MaxMapFeedback::new(&edges_observer);
        let time_feedback = TimeFeedback::new(&time_observer);
        let mut feedback = feedback_or!(map_feedback, time_feedback);
        let mut objective = CrashFeedback::new();
    }
}

/// Generate the observer and feedback setup for multi-core mode
#[allow(dead_code)]
pub fn observer_feedback_setup_multicore(mod_name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
        // Use StdMapObserver directly (no hitcount bucketing) for simpler/faster coverage
        let edges_observer = unsafe { StdMapObserver::from_mut_ptr("edges", cov_ptr, #mod_name::MAP_SIZE) };
        let time_observer = TimeObserver::new("time");

        // SharedBitmapFeedback checks if any NEW bits were set in the shared bitmap
        // TimeFeedback stores execution time metadata for PowerQueueScheduler
        // Using feedback_and_fast! so corpus is added ONLY when SharedBitmapFeedback returns true
        // (TimeFeedback::is_interesting returns false, so AND would always be false - use OR but verify)
        let bitmap_feedback = #mod_name::SharedBitmapFeedback::new();
        let time_feedback = TimeFeedback::new(&time_observer);
        let mut feedback = feedback_or!(bitmap_feedback, time_feedback);
        let mut objective = CrashFeedback::new();
    }
}

/// Generate the harness wrapper code
#[allow(dead_code)]
pub fn harness_wrapper_code(
    mod_name: &syn::Ident,
    fn_name: &syn::Ident,
    _feature_name: &str,
    iteration_setup: &proc_macro2::TokenStream,
    deser_stmts: &[proc_macro2::TokenStream],
    call_args: &[proc_macro2::TokenStream],
) -> proc_macro2::TokenStream {
    quote! {
        let mut harness_wrapper = |input: &BytesInput| -> ExitKind {
            let bytes_ref = input.target_bytes();
            let slice = bytes_ref.as_slice();
            let mut u = Unstructured::new(slice);

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
                ExitKind::Crash
            } else {
                ExitKind::Ok
            }
        };
    }
}

/// Generate the mutator and stages setup
pub fn mutator_stages_setup() -> proc_macro2::TokenStream {
    quote! {
        let mutator = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5)
            .expect("failed to create mutator");
        let power_stage = StdPowerMutationalStage::new(mutator);
        let mut stages = tuple_list!(power_stage);
    }
}

/// Generate the exit handlers setup
pub fn exit_handlers_setup(mod_name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
        let default_panic = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                #mod_name::write_lcov_coverage("coverage.lcov");
            }
            default_panic(info);
        }));

        ctrlc::set_handler(move || {
            if coverage_enabled {
                eprintln!("\n[COVERAGE] Ctrl+C received. Coverage files written by periodic updates.");
            }
            std::process::exit(0);
        }).ok();
    }
}

/// Generate the common fuzzing setup
pub fn common_fuzz_setup(
    mod_name: &syn::Ident,
    fixture_name: &syn::Ident,
) -> proc_macro2::TokenStream {
    let template_setup_code = template_setup(fixture_name, mod_name);

    quote! {
        #template_setup_code

        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let _ = #mod_name::FUZZER_START_TIME.set(start_time);

        let timeout_secs: Option<u64> = std::env::var("FUZZ_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok());

        let iteration_counter = std::sync::atomic::AtomicU64::new(0);
    }
}

/// Generate the corpus loading code using LibAFL's built-in load_initial_inputs
/// Note: This is currently unused as singlecore.rs inlines the corpus loading logic
/// in the generic helper function. Kept for potential future use.
#[allow(dead_code)]
pub fn load_corpus_from_dir() -> proc_macro2::TokenStream {
    quote! {
        eprintln!("[FUZZ] Loading seed corpus from: {}", corpus_dir);
        // Use LibAFL's built-in corpus loading which properly sets up all metadata
        // (exec_time, SchedulerTestcaseMetadata, etc.)
        let corpus_dirs = vec![std::path::PathBuf::from(corpus_dir)];
        state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
            .expect("failed to load initial corpus");
        let loaded = state.corpus().count();
        eprintln!("[FUZZ] Loaded {} seed inputs (corpus loading complete)", loaded);
    }
}

/// Generate the default seed input code
pub fn add_default_seed() -> proc_macro2::TokenStream {
    quote! {
        let input = BytesInput::new(vec![0u8; 256]);
        fuzzer.add_input(&mut state, &mut executor, &mut mgr, input)
            .expect("failed to add seed input");
    }
}

/// Generate the is_corpus_input helper function
pub fn is_corpus_input_fn() -> proc_macro2::TokenStream {
    quote! {
        // Helper to check if a file is a corpus input (not metadata)
        // Defined once here and used by coverage-only and fuzzing modes
        fn is_corpus_input(path: &std::path::Path) -> bool {
            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => return false,
            };
            // Skip LibAFL metadata files and our crash metadata
            if file_name.starts_with('.') { return false; }
            if file_name.ends_with(".metadata") { return false; }
            if file_name.ends_with(".meta.json") { return false; }
            if file_name == ".state" { return false; }
            if file_name == ".state.metadata" { return false; }
            true
        }
    }
}
