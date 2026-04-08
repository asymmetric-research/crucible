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

/// Generate the initialization code for DWARF source maps (for source-level LCOV)
pub fn init_dwarf_maps(mod_name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
        // Only build DWARF maps when --coverage + --symbols are both active
        if std::env::var("FUZZ_SYMBOLS").is_ok() {
            let symbols_path = std::env::var("FUZZ_SYMBOLS").unwrap();
            let debug_binary = std::fs::read(&symbols_path)
                .unwrap_or_else(|e| panic!("Failed to read symbols file {}: {}", symbols_path, e));

            let mut dwarf_maps = std::collections::HashMap::new();
            if let Some(source_map) = crucible_test_context::build_dwarf_source_map(&debug_binary) {
                eprintln!("[COVERAGE] DWARF source map loaded: {} PCs resolved, {} functions",
                    source_map.pc_map.len(), source_map.fn_map.len());
                // Associate with all loaded programs
                for (pubkey, _) in template_fixture.ctx.get_program_coverage_totals() {
                    let program_hash = u64::from_le_bytes(
                        pubkey.to_bytes()[0..8].try_into().unwrap()
                    );
                    dwarf_maps.insert(program_hash, source_map.clone());
                }
            } else {
                eprintln!("[COVERAGE] Warning: {} has no DWARF debug info. \
                    Build with [profile.release] debug = true", symbols_path);
            }
            #mod_name::init_dwarf_source_maps(dwarf_maps);
        }
    }
}

/// Generate the template setup code
pub fn template_setup(
    fixture_name: &syn::Ident,
    mod_name: &syn::Ident,
) -> proc_macro2::TokenStream {
    let init_totals = init_coverage_totals(mod_name);
    let init_binaries = init_program_binaries(mod_name);
    let init_dwarf = init_dwarf_maps(mod_name);

    quote! {
        // Always enable tracing for initial fixture setup so corpus loading
        // establishes a coverage baseline. If --no-tracing is set, we switch to
        // a non-instrumented SVM after corpus loading completes.
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
            #init_dwarf
        }
    }
}

/// Generate the monitor setup code
pub fn monitor_setup(mod_name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
        // CSV stats file setup (when FUZZ_STATS_CSV env var is set)
        let __stats_csv: Option<std::sync::Arc<std::sync::Mutex<std::fs::File>>> =
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
        let __csv_ref = __stats_csv.clone();

        let monitor = SimpleMonitor::new(move |s| {
            // Suppress monitor output during corpus loading (too noisy)
            if crucible_test_context::is_corpus_loading() { return; }
            // Helper to parse numeric values from LibAFL's monitor string
            // Handles SI suffixes: k (1000), M (1000000)
            fn __parse_monitor_val(s: &str, key: &str) -> f64 {
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

            let mut s = s.replace("objectives", "crashes").replace("(GLOBAL) ", "");
            // Replace LibAFL's [Testcase #N] prefix with [FUZZ_PULSE]
            if let Some(bracket_end) = s.find(']') {
                s = format!("[FUZZ_PULSE]{}", &s[bracket_end + 1..]);
            }
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
            if let Some(_idx) = s.find("exec/sec:") {
                let edge_pct = if total_edges > 0 { (true_edges as f64 / total_edges as f64) * 100.0 } else { 0.0 };
                let branch_pct = if total_branches > 0 { (branches as f64 / total_branches as f64) * 100.0 } else { 0.0 };
                let total_actions = crucible_test_context::TOTAL_ACTIONS_DISPATCHED.load(std::sync::atomic::Ordering::Relaxed);
                let total_ok = crucible_test_context::TOTAL_ACTIONS_SUCCEEDED.load(std::sync::atomic::Ordering::Relaxed);
                let execs_for_avg = #mod_name::TOTAL_EXECUTIONS.load(std::sync::atomic::Ordering::Relaxed);
                let avg_actions = if execs_for_avg > 0 { total_actions as f64 / execs_for_avg as f64 } else { 0.0 };
                let ok_pct = if total_actions > 0 { (total_ok as f64 / total_actions as f64) * 100.0 } else { 0.0 };
                let discovered = crucible_test_context::succeeded_variant_count();
                let total_variants = crucible_test_context::TOTAL_ACTION_VARIANTS.load(std::sync::atomic::Ordering::Relaxed);
                let discovered_str = if total_variants > 0 {
                    format!(", discovered: {}/{} actions", discovered, total_variants)
                } else {
                    String::new()
                };
                let __memory_kib = {
                    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
                    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
                    if cfg!(target_os = "macos") {
                        (usage.ru_maxrss / 1024) as u64
                    } else {
                        usage.ru_maxrss as u64
                    }
                };
                eprintln!("{}, edges: {}/{} ({:.1}%), branches: {}/{} ({:.1}%), actions/exec: {:.1}, ok: {}/{} ({:.1}%){}, memory_kib: {}",
                    s.trim_end(), true_edges, total_edges, edge_pct, branches, total_branches, branch_pct, avg_actions, total_ok, total_actions, ok_pct, discovered_str, __memory_kib);

                // Write CSV stats row if enabled
                if let Some(ref csv) = __csv_ref {
                    let elapsed = #mod_name::FUZZER_START_TIME.get()
                        .map(|start| {
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs() - start
                        })
                        .unwrap_or(0);
                    let execs = #mod_name::TOTAL_EXECUTIONS.load(std::sync::atomic::Ordering::Relaxed);
                    let exec_sec = __parse_monitor_val(&s, "exec/sec: ");
                    let corpus_count = __parse_monitor_val(&s, "corpus: ") as u64;
                    let crashes_count = __parse_monitor_val(&s, "crashes: ") as u64;
                    if let Ok(mut f) = csv.lock() {
                        use std::io::Write;
                        let _ = writeln!(f, "{},{},{:.1},{},{},{},{},{:.1},{},{},{:.1}",
                            elapsed, execs, exec_sec, corpus_count, crashes_count,
                            true_edges, total_edges, edge_pct, branches, total_branches, branch_pct);
                        let _ = f.flush();
                    }
                }
            } else { eprintln!("{s}"); }
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
        let success_pattern_feedback = #mod_name::SuccessPatternFeedback::new();
        let mut feedback = feedback_or!(map_feedback, time_feedback, success_pattern_feedback);
        let mut objective = CrashFeedback::new();
    }
}

/// Generate the max input size setup.
/// Scans `--corpus-in` directory to find the actual max file size so that
/// stateful corpus entries (which can exceed 1024 bytes) are not truncated.
/// Falls back to 1024 bytes when no corpus is provided.
pub fn max_size_setup() -> proc_macro2::TokenStream {
    quote! {
        let __max_input_size: usize = {
            let mut max = 1024usize;
            if let Some(ref dir) = corpus_in_dir {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        if let Ok(meta) = entry.metadata() {
                            max = max.max(meta.len() as usize);
                        }
                    }
                }
            }
            max
        };
        state.set_max_size(__max_input_size);
    }
}

/// Generate the mutator and stages setup (arbitrary mode - havoc mutations)
pub fn mutator_stages_setup() -> proc_macro2::TokenStream {
    quote! {
        let mutator = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5)
            .expect("failed to create mutator");
        let power_stage = StdPowerMutationalStage::new(mutator);
        let mut stages = tuple_list!(power_stage);
    }
}

/// Generate the mutator and stages setup for structured mode
/// Uses custom SequenceMutator, ParamMutator, CrossoverMutator instead of havoc
pub fn structured_mutator_stages_setup(action_type: &proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    quote! {
        let __fuzz_max_actions: usize = std::env::var("FUZZ_MAX_ACTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);
        let trim_stage = crucible_fuzzer::SuccessTrimStage::<#action_type>::new();
        let seq_mutator = crucible_fuzzer::SequenceMutator::<#action_type>::new(__fuzz_max_actions);
        let param_mutator = crucible_fuzzer::ParamMutator::<#action_type>::new();
        let cross_mutator = crucible_fuzzer::CrossoverMutator::<#action_type>::new(__fuzz_max_actions);
        let mutator = StdMOptMutator::new(
            &mut state,
            tuple_list!(seq_mutator, param_mutator, cross_mutator),
            7, 5
        ).expect("failed to create structured mutator");
        let power_stage = StdPowerMutationalStage::new(mutator);
        let mut stages = tuple_list!(trim_stage, power_stage);
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

/// Generate the default seed input code (arbitrary mode)
pub fn add_default_seed() -> proc_macro2::TokenStream {
    quote! {
        let input = BytesInput::new(vec![0u8; 256]);
        fuzzer.add_input(&mut state, &mut executor, &mut mgr, input)
            .expect("failed to add seed input");
    }
}

/// Generate the default seed input code for structured mode
/// Uses ActionGenerator to create properly-formatted seed inputs
pub fn structured_add_default_seed(action_type: &proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    quote! {
        {
            use libafl::generators::Generator;
            let __seed_max: usize = std::env::var("FUZZ_MAX_ACTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10)
                .min(4);
            let mut gen = crucible_fuzzer::ActionGenerator::<#action_type>::new(1, __seed_max);
            // Generate a few diverse seed inputs
            for _ in 0..4 {
                if let Ok(input) = gen.generate(&mut state) {
                    let _ = fuzzer.add_input(&mut state, &mut executor, &mut mgr, input);
                }
            }
            // Ensure at least one seed exists
            if state.corpus().count() == 0 {
                let input = BytesInput::new(vec![0u8; 256]);
                fuzzer.add_input(&mut state, &mut executor, &mut mgr, input)
                    .expect("failed to add fallback seed input");
            }
        }
    }
}

// ── Multi-context helpers ──────────────────────────────────────────────
//
// These helpers generate per-context code blocks by iterating over
// the `contexts` slice.  When `contexts = [ctx]` (the default), the
// generated code is equivalent to the old single-context codegen.

/// Take snapshots on all contexts.
pub fn contexts_take_snapshot(contexts: &[syn::Ident]) -> proc_macro2::TokenStream {
    let stmts: Vec<_> = contexts
        .iter()
        .map(|field| {
            quote! { template_fixture.#field.take_snapshot(); }
        })
        .collect();
    quote! { #(#stmts)* }
}

/// Create `RefCell`-based `__pristine_svm_{i}` and `__saved_svm_{i}` for
/// every context.  Moves the real SVM out of the template so that
/// `template.clone()` is cheap (empty SVM + Arc programs).
pub fn contexts_swap_out(contexts: &[syn::Ident]) -> proc_macro2::TokenStream {
    let stmts: Vec<_> = contexts
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let pristine = quote::format_ident!("__pristine_svm_{}", i);
            let saved = quote::format_ident!("__saved_svm_{}", i);
            quote! {
                let #pristine = std::cell::RefCell::new(template_fixture.#field.svm.clone());
                let #saved = std::cell::RefCell::new(std::mem::replace(
                    &mut template_fixture.#field.svm,
                    crucible_test_context::litesvm::LiteSVM::new(),
                ));
            }
        })
        .collect();
    quote! { #(#stmts)* }
}

/// Periodic SVM reset: replace each saved SVM with a pristine clone.
pub fn contexts_reset_check(contexts: &[syn::Ident]) -> proc_macro2::TokenStream {
    let stmts: Vec<_> = contexts
        .iter()
        .enumerate()
        .map(|(i, _field)| {
            let pristine = quote::format_ident!("__pristine_svm_{}", i);
            let saved = quote::format_ident!("__saved_svm_{}", i);
            quote! {
                *#saved.borrow_mut() = #pristine.borrow().clone();
            }
        })
        .collect();
    quote! {
        if __svm_reset_interval > 0 && current_iteration > 0 && current_iteration % __svm_reset_interval == 0 {
            #(#stmts)*
        }
    }
}

/// Swap real SVMs from `__saved_svm_{i}` RefCells into `fixture`.
pub fn contexts_swap_in(
    fixture_param: &syn::Ident,
    contexts: &[syn::Ident],
) -> proc_macro2::TokenStream {
    let stmts: Vec<_> = contexts
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let saved = quote::format_ident!("__saved_svm_{}", i);
            quote! {
                std::mem::swap(&mut #fixture_param.#field.svm, &mut *#saved.borrow_mut());
            }
        })
        .collect();
    quote! { #(#stmts)* }
}

/// Restore dirty accounts from snapshot and clear dirty state.
pub fn contexts_restore_and_clear(
    fixture_param: &syn::Ident,
    contexts: &[syn::Ident],
) -> proc_macro2::TokenStream {
    let stmts: Vec<_> = contexts
        .iter()
        .map(|field| {
            quote! {
                if let Some(ref snap) = template_fixture.#field.snapshot {
                    snap.restore(&mut #fixture_param.#field.svm, &#fixture_param.#field.dirty_tracker);
                }
                #fixture_param.#field.dirty_tracker.clear();
            }
        })
        .collect();
    quote! { #(#stmts)* }
}

/// Swap clean SVMs back into `__saved_svm_{i}` RefCells.
pub fn contexts_swap_back(
    fixture_param: &syn::Ident,
    contexts: &[syn::Ident],
) -> proc_macro2::TokenStream {
    let stmts: Vec<_> = contexts
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let saved = quote::format_ident!("__saved_svm_{}", i);
            quote! {
                std::mem::swap(&mut #fixture_param.#field.svm, &mut *#saved.borrow_mut());
            }
        })
        .collect();
    quote! { #(#stmts)* }
}

/// No-tracing switch: recreate fixture without JIT instrumentation and
/// replace both pristine and saved SVMs for all contexts.
pub fn contexts_no_tracing_switch(
    fixture_name: &syn::Ident,
    contexts: &[syn::Ident],
) -> proc_macro2::TokenStream {
    let take_snapshots: Vec<_> = contexts
        .iter()
        .map(|field| quote! { __new_fixture.#field.take_snapshot(); })
        .collect();
    let swap_svms: Vec<_> = contexts
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let pristine = quote::format_ident!("__pristine_svm_{}", i);
            let saved = quote::format_ident!("__saved_svm_{}", i);
            quote! {
                *#pristine.borrow_mut() = __new_fixture.#field.svm.clone();
                *#saved.borrow_mut() = std::mem::replace(
                    &mut __new_fixture.#field.svm,
                    crucible_test_context::litesvm::LiteSVM::new(),
                );
            }
        })
        .collect();
    quote! {
        if std::env::var("FUZZ_NO_TRACING").is_ok() {
            std::env::remove_var("ANCHOR_FUZZ_DEBUGGABLE");
            eprintln!("[FUZZ] Corpus loaded with tracing. Switching to no-tracing mode for fuzzing.");
            let mut __new_fixture = #fixture_name::setup();
            #(#take_snapshots)*
            #(#swap_svms)*
        }
    }
}

// ── Stateful-mode multi-context helpers ───────────────────────────────
//
// Stateful mode uses `mut` variables (not RefCells) for SVM swap.
// These helpers generate code for contexts[1..] (additional contexts);
// the primary context (index 0) is handled by the existing stateful logic.

/// Take snapshots on additional contexts (index 1+).
pub fn stateful_extra_take_snapshot(contexts: &[syn::Ident]) -> proc_macro2::TokenStream {
    let stmts: Vec<_> = contexts
        .iter()
        .skip(1)
        .map(|field| quote! { template_fixture.#field.take_snapshot(); })
        .collect();
    quote! { #(#stmts)* }
}

/// Swap out additional context SVMs into `mut` variables at setup.
pub fn stateful_extra_swap_out(contexts: &[syn::Ident]) -> proc_macro2::TokenStream {
    let stmts: Vec<_> = contexts
        .iter()
        .enumerate()
        .skip(1)
        .map(|(i, field)| {
            let svm_name = quote::format_ident!("__extra_svm_{}", i);
            quote! {
                let mut #svm_name = std::mem::replace(
                    &mut template_fixture.#field.svm,
                    crucible_test_context::litesvm::LiteSVM::new(),
                );
            }
        })
        .collect();
    quote! { #(#stmts)* }
}

/// Swap additional context SVMs into a fixture (stateful iteration start).
pub fn stateful_extra_swap_in(
    fixture_param: &syn::Ident,
    contexts: &[syn::Ident],
) -> proc_macro2::TokenStream {
    let stmts: Vec<_> = contexts
        .iter()
        .enumerate()
        .skip(1)
        .map(|(i, field)| {
            let svm_name = quote::format_ident!("__extra_svm_{}", i);
            quote! {
                std::mem::swap(&mut #fixture_param.#field.svm, &mut #svm_name);
            }
        })
        .collect();
    quote! { #(#stmts)* }
}

/// Restore additional contexts from snapshot, clear dirty, and swap back.
pub fn stateful_extra_restore_and_swap_back(
    fixture_param: &syn::Ident,
    contexts: &[syn::Ident],
) -> proc_macro2::TokenStream {
    let stmts: Vec<_> = contexts
        .iter()
        .enumerate()
        .skip(1)
        .map(|(i, field)| {
            let svm_name = quote::format_ident!("__extra_svm_{}", i);
            quote! {
                if let Some(ref snap) = template_fixture.#field.snapshot {
                    snap.restore(&mut #fixture_param.#field.svm, &#fixture_param.#field.dirty_tracker);
                }
                #fixture_param.#field.dirty_tracker.clear();
                std::mem::swap(&mut #fixture_param.#field.svm, &mut #svm_name);
            }
        })
        .collect();
    quote! { #(#stmts)* }
}

/// Swap additional context SVMs back without restoring (e.g., after seed action).
pub fn stateful_extra_swap_back(
    fixture_param: &syn::Ident,
    contexts: &[syn::Ident],
) -> proc_macro2::TokenStream {
    let stmts: Vec<_> = contexts
        .iter()
        .enumerate()
        .skip(1)
        .map(|(i, field)| {
            let svm_name = quote::format_ident!("__extra_svm_{}", i);
            quote! {
                std::mem::swap(&mut #fixture_param.#field.svm, &mut #svm_name);
            }
        })
        .collect();
    quote! { #(#stmts)* }
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use quote::format_ident;

    /// Helper: convert TokenStream to normalized string for pattern matching.
    fn ts(tokens: proc_macro2::TokenStream) -> String {
        tokens.to_string()
    }

    // ── max_size_setup ──────────────────────────────────────────────────

    #[test]
    fn max_size_setup_scans_corpus_dir() {
        let output = ts(max_size_setup());
        assert!(output.contains("corpus_in_dir"), "should reference corpus_in_dir env");
        assert!(output.contains("read_dir"), "should scan directory");
        assert!(output.contains("metadata"), "should read file metadata");
        assert!(output.contains("1024"), "should default to 1024 bytes");
        assert!(output.contains("set_max_size"), "should call state.set_max_size");
    }

    // ── mutator / seed setup ────────────────────────────────────────────

    #[test]
    fn mutator_stages_setup_uses_havoc() {
        let output = ts(mutator_stages_setup());
        assert!(output.contains("havoc_mutations"), "arbitrary mode should use havoc_mutations");
        assert!(output.contains("StdMOptMutator"), "should use MOpt mutator");
        assert!(output.contains("StdPowerMutationalStage"), "should wrap in power stage");
    }

    #[test]
    fn structured_mutator_stages_has_all_mutators() {
        let action_ty = quote! { TestAction };
        let output = ts(structured_mutator_stages_setup(&action_ty));
        assert!(output.contains("SuccessTrimStage"), "should include trim stage");
        assert!(output.contains("SequenceMutator"), "should include sequence mutator");
        assert!(output.contains("ParamMutator"), "should include param mutator");
        assert!(output.contains("CrossoverMutator"), "should include crossover mutator");
        assert!(output.contains("FUZZ_MAX_ACTIONS"), "should respect max actions env");
    }

    #[test]
    fn add_default_seed_creates_256_byte_input() {
        let output = ts(add_default_seed());
        assert!(output.contains("256"), "default seed should be 256 bytes");
        assert!(output.contains("BytesInput"), "should create BytesInput");
        assert!(output.contains("add_input"), "should add to fuzzer");
    }

    #[test]
    fn structured_add_default_seed_uses_generator() {
        let action_ty = quote! { TestAction };
        let output = ts(structured_add_default_seed(&action_ty));
        assert!(output.contains("ActionGenerator"), "should use ActionGenerator");
        assert!(output.contains("generate"), "should call generate()");
        // Verify fallback seed when corpus is empty
        assert!(output.contains("count") && output.contains("== 0"),
            "should check if corpus is empty for fallback");
    }

    // ── observer / feedback ─────────────────────────────────────────────

    #[test]
    fn singlecore_observer_feedback_has_hitcounts() {
        let mod_name = format_ident!("__fuzz_mod");
        let output = ts(singlecore_observer_feedback(&mod_name));
        assert!(output.contains("HitcountsMapObserver"), "should use HitcountsMapObserver for bucketing");
        assert!(output.contains("MaxMapFeedback"), "should use MaxMapFeedback");
        assert!(output.contains("TimeFeedback"), "should track execution time");
        assert!(output.contains("SuccessPatternFeedback"), "should track action success patterns");
        assert!(output.contains("CrashFeedback"), "should detect crashes");
    }

    // ── template / common setup ─────────────────────────────────────────

    #[test]
    fn template_setup_enables_tracing() {
        let fixture = format_ident!("TestFixture");
        let mod_name = format_ident!("__fuzz_mod");
        let output = ts(template_setup(&fixture, &mod_name));
        assert!(output.contains("ANCHOR_FUZZ_DEBUGGABLE"), "should enable tracing env var");
        assert!(output.contains("setup"), "should call Fixture::setup()");
        assert!(output.contains("init_program_totals"), "should init coverage totals");
        assert!(output.contains("init_program_binaries"), "should init binaries");
    }

    #[test]
    fn common_fuzz_setup_has_timeout_and_counter() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let output = ts(common_fuzz_setup(&mod_name, &fixture));
        assert!(output.contains("FUZZ_TIMEOUT_SECS"), "should parse timeout env");
        assert!(output.contains("AtomicU64"), "should create iteration counter");
        assert!(output.contains("FUZZER_START_TIME"), "should record start time");
    }

    #[test]
    fn monitor_setup_suppresses_during_corpus_loading() {
        let mod_name = format_ident!("__fuzz_mod");
        let output = ts(monitor_setup(&mod_name));
        assert!(output.contains("is_corpus_loading"), "should suppress during corpus loading");
        assert!(output.contains("FUZZ_PULSE"), "should output [FUZZ_PULSE] prefix");
        assert!(output.contains("edges"), "should display edge coverage");
        assert!(output.contains("branches"), "should display branch coverage");
        assert!(output.contains("actions/exec"), "should display actions per execution");
        assert!(output.contains("memory_kib"), "should display memory usage");
    }

    // ── exit handlers ───────────────────────────────────────────────────

    #[test]
    fn exit_handlers_write_coverage_on_panic() {
        let mod_name = format_ident!("__fuzz_mod");
        let output = ts(exit_handlers_setup(&mod_name));
        assert!(output.contains("set_hook"), "should set panic hook");
        assert!(output.contains("write_lcov_coverage"), "should write coverage on panic");
        assert!(output.contains("ctrlc"), "should handle Ctrl+C");
    }

    // ── multi-context helpers ───────────────────────────────────────────

    #[test]
    fn contexts_take_snapshot_single() {
        let contexts = vec![format_ident!("ctx")];
        let output = ts(contexts_take_snapshot(&contexts));
        assert!(output.contains("template_fixture . ctx . take_snapshot"), "should snapshot ctx");
    }

    #[test]
    fn contexts_take_snapshot_multi() {
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(contexts_take_snapshot(&contexts));
        assert!(output.contains("template_fixture . ctx . take_snapshot"), "should snapshot ctx");
        assert!(output.contains("template_fixture . ctx_b . take_snapshot"), "should snapshot ctx_b");
    }

    #[test]
    fn contexts_swap_out_creates_refcells() {
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(contexts_swap_out(&contexts));
        assert!(output.contains("__pristine_svm_0"), "should create pristine for ctx");
        assert!(output.contains("__saved_svm_0"), "should create saved for ctx");
        assert!(output.contains("__pristine_svm_1"), "should create pristine for ctx_b");
        assert!(output.contains("__saved_svm_1"), "should create saved for ctx_b");
        assert!(output.contains("RefCell"), "should use RefCell for swap trick");
        assert!(output.contains("LiteSVM :: new"), "should replace with empty SVM");
    }

    #[test]
    fn contexts_reset_check_uses_interval() {
        let contexts = vec![format_ident!("ctx")];
        let output = ts(contexts_reset_check(&contexts));
        assert!(output.contains("__svm_reset_interval"), "should check reset interval");
        assert!(output.contains("current_iteration"), "should check iteration count");
        assert!(output.contains("__pristine_svm_0"), "should clone from pristine");
        assert!(output.contains("__saved_svm_0"), "should replace saved");
    }

    #[test]
    fn contexts_swap_in_swaps_all() {
        let fixture = format_ident!("fixture");
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(contexts_swap_in(&fixture, &contexts));
        assert!(output.contains("fixture . ctx . svm"), "should swap ctx SVM");
        assert!(output.contains("fixture . ctx_b . svm"), "should swap ctx_b SVM");
        assert!(output.contains("__saved_svm_0"), "should use saved_svm_0");
        assert!(output.contains("__saved_svm_1"), "should use saved_svm_1");
    }

    #[test]
    fn contexts_restore_and_clear_restores_dirty() {
        let fixture = format_ident!("fixture");
        let contexts = vec![format_ident!("ctx")];
        let output = ts(contexts_restore_and_clear(&fixture, &contexts));
        assert!(output.contains("snapshot"), "should check snapshot exists");
        assert!(output.contains("restore"), "should call restore");
        assert!(output.contains("dirty_tracker . clear"), "should clear dirty tracker");
    }

    #[test]
    fn contexts_swap_back_swaps_all() {
        let fixture = format_ident!("fixture");
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(contexts_swap_back(&fixture, &contexts));
        assert!(output.contains("fixture . ctx . svm"), "should swap back ctx");
        assert!(output.contains("fixture . ctx_b . svm"), "should swap back ctx_b");
    }

    #[test]
    fn contexts_no_tracing_switch_recreates_all() {
        let fixture = format_ident!("TestFixture");
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(contexts_no_tracing_switch(&fixture, &contexts));
        assert!(output.contains("FUZZ_NO_TRACING"), "should check no-tracing env");
        assert!(output.contains("remove_var"), "should remove debuggable env var");
        assert!(output.contains("TestFixture :: setup"), "should recreate fixture");
        assert!(output.contains("take_snapshot"), "should re-snapshot");
        assert!(output.contains("__pristine_svm_0"), "should update pristine ctx");
        assert!(output.contains("__pristine_svm_1"), "should update pristine ctx_b");
    }

    // ── stateful-mode extra context helpers ──────────────────────────────

    #[test]
    fn stateful_extra_take_snapshot_skips_primary() {
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(stateful_extra_take_snapshot(&contexts));
        // Should NOT contain ctx (primary), only ctx_b
        assert!(!output.contains("template_fixture . ctx . take_snapshot"),
            "should skip primary context");
        assert!(output.contains("template_fixture . ctx_b . take_snapshot"),
            "should snapshot additional context");
    }

    #[test]
    fn stateful_extra_take_snapshot_empty_for_single_context() {
        let contexts = vec![format_ident!("ctx")];
        let output = ts(stateful_extra_take_snapshot(&contexts));
        assert!(output.is_empty(), "single context should produce no extra snapshot code");
    }

    #[test]
    fn stateful_extra_swap_out_creates_mut_vars() {
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(stateful_extra_swap_out(&contexts));
        assert!(output.contains("__extra_svm_1"), "should create __extra_svm_1 for ctx_b");
        assert!(!output.contains("__extra_svm_0"), "should not create __extra_svm_0 (primary handled separately)");
        assert!(output.contains("LiteSVM :: new"), "should replace with empty SVM");
    }

    #[test]
    fn stateful_extra_swap_in_uses_fixture_param() {
        let fixture = format_ident!("my_fixture");
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(stateful_extra_swap_in(&fixture, &contexts));
        assert!(output.contains("my_fixture . ctx_b . svm"), "should swap ctx_b using fixture param");
        assert!(output.contains("__extra_svm_1"), "should use __extra_svm_1");
    }

    #[test]
    fn stateful_extra_restore_and_swap_back_restores_and_clears() {
        let fixture = format_ident!("my_fixture");
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(stateful_extra_restore_and_swap_back(&fixture, &contexts));
        assert!(output.contains("restore"), "should call restore");
        assert!(output.contains("dirty_tracker . clear"), "should clear dirty tracker");
        assert!(output.contains("__extra_svm_1"), "should swap back using __extra_svm_1");
    }

    // ── is_corpus_input ─────────────────────────────────────────────────

    #[test]
    fn is_corpus_input_fn_filters_metadata() {
        let output = ts(is_corpus_input_fn());
        assert!(output.contains("starts_with ('.')"), "should skip hidden files");
        assert!(output.contains(".metadata"), "should skip .metadata files");
        assert!(output.contains(".meta.json"), "should skip .meta.json files");
        assert!(output.contains(".state"), "should skip .state file");
    }
}
