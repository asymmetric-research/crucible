//! Shared quote! blocks used across execution modes (single-core, multi-core, dry-run, etc.).

use quote::quote;

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

pub fn init_program_binaries(mod_name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
        let mut program_binaries: std::collections::HashMap<u64, Vec<u8>> = std::collections::HashMap::new();
        for (pubkey, binary) in template_fixture.ctx.get_program_binaries() {
            let program_hash = u64::from_le_bytes(
                pubkey.to_bytes()[0..8].try_into().unwrap()
            );
            program_binaries.insert(program_hash, binary);
        }
        #mod_name::init_program_binaries(program_binaries);
    }
}

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
                eprintln!("[COVERAGE] Warning: {} has no DWARF debug info (no source-level \
                    coverage). Rebuild the program with DWARF line info — e.g. \
                    [profile.release] debug = true, strip = false — for per-file/per-line LCOV. \
                    Falling back to bytecode-level LCOV.", symbols_path);
            }
            #mod_name::init_dwarf_source_maps(dwarf_maps);

            // Always build the symbol-table name map from symbols.so (independent of
            // DWARF). When DWARF is absent this is what gives the bytecode-level LCOV
            // real demangled function names instead of fn_<pc> stubs.
            let mut symbol_maps = std::collections::HashMap::new();
            if let Some(name_map) = crucible_test_context::build_symbol_name_map(&debug_binary) {
                eprintln!("[COVERAGE] Symbol-table function names loaded: {} functions", name_map.len());
                for (pubkey, _) in template_fixture.ctx.get_program_coverage_totals() {
                    let program_hash = u64::from_le_bytes(
                        pubkey.to_bytes()[0..8].try_into().unwrap()
                    );
                    symbol_maps.insert(program_hash, name_map.clone());
                }
            }
            #mod_name::init_symbol_name_maps(symbol_maps);
        }
    }
}

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
        std::env::set_var("CRUCIBLE_FUZZ_DEBUGGABLE", "1");
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

pub fn monitor_setup(mod_name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
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
            if crucible_test_context::is_corpus_loading() { return; }
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
            if let Some(bracket_end) = s.find(']') {
                s = format!("[FUZZ_PULSE]{}", &s[bracket_end + 1..]);
            }
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
                let __memory_str = if std::env::var("FUZZ_STATS").is_ok() {
                    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
                    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
                    let kib = if cfg!(target_os = "macos") {
                        (usage.ru_maxrss / 1024) as u64
                    } else {
                        usage.ru_maxrss as u64
                    };
                    format!(", memory_kib: {}", kib)
                } else {
                    String::new()
                };
                eprintln!("{}, edges: {}/{} ({:.1}%), branches: {}/{} ({:.1}%), actions/exec: {:.1}, ok: {}/{} ({:.1}%){}{}",
                    s.trim_end(), true_edges, total_edges, edge_pct, branches, total_branches, branch_pct, avg_actions, total_ok, total_actions, ok_pct, discovered_str, __memory_str);

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

pub fn singlecore_observer_feedback(mod_name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
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

/// Scans `--corpus-in` for max file size so stateful corpus entries aren't truncated.
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

pub fn mutator_stages_setup() -> proc_macro2::TokenStream {
    quote! {
        let mutator = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5)
            .expect("failed to create mutator");
        let power_stage = StdPowerMutationalStage::new(mutator);
        let mut stages = tuple_list!(power_stage);
    }
}

pub fn structured_mutator_stages_setup(
    action_type: &proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    quote! {
        let __fuzz_max_actions: usize = match std::env::var("FUZZ_MAX_ACTIONS") {
            Ok(s) => s.parse().unwrap_or_else(|e| {
                panic!("[FUZZ] FUZZ_MAX_ACTIONS='{}' is not a valid number: {}", s, e);
            }),
            Err(_) => 10,
        };
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

pub fn exit_handlers_setup(mod_name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
        let default_panic = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                let coverage_output = #mod_name::lcov_output_path();
                #mod_name::write_lcov_coverage(&coverage_output);
            }
            default_panic(info);
        }));

        if let Err(e) = ctrlc::set_handler(move || {
            if coverage_enabled {
                eprintln!("\n[COVERAGE] Ctrl+C received. Coverage files written by periodic updates.");
            }
            std::process::exit(0);
        }) {
            eprintln!("[FUZZ] Warning: failed to install Ctrl+C handler: {}", e);
        }
    }
}

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

        let timeout_secs: Option<u64> = match std::env::var("FUZZ_TIMEOUT_SECS") {
            Ok(s) => Some(s.parse().unwrap_or_else(|e| {
                panic!("[FUZZ] FUZZ_TIMEOUT_SECS='{}' is not a valid number: {}", s, e);
            })),
            Err(_) => None,
        };

        let iteration_counter = std::sync::atomic::AtomicU64::new(0);
    }
}

pub fn add_default_seed() -> proc_macro2::TokenStream {
    quote! {
        let input = BytesInput::new(vec![0u8; 256]);
        fuzzer.add_input(&mut state, &mut executor, &mut mgr, input)
            .expect("failed to add seed input");
    }
}

pub fn structured_add_default_seed(
    action_type: &proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    quote! {
        {
            use libafl::generators::Generator;
            let __seed_max: usize = match std::env::var("FUZZ_MAX_ACTIONS") {
                Ok(s) => s.parse().unwrap_or_else(|e| {
                    panic!("[FUZZ] FUZZ_MAX_ACTIONS='{}' is not a valid number: {}", s, e);
                }),
                Err(_) => 10,
            }.min(4);
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

/// No-tracing switch: rebuild each saved SVM as non-debuggable with the
/// same accounts/state, matching the stateful-mode approach.
///
/// The prior implementation called `#fixture_name::setup()` again, but
/// fixtures that use random keypairs would produce new pubkeys that
/// diverged from the template fixture's Rust state — causing
/// "Account not found" panics when actions referenced the old pubkeys.
///
/// Instead, create a fresh non-debuggable `LiteSVM` and replay the
/// template's snapshot into it. Pubkeys stay identical; only the SVM's
/// JIT instrumentation flag changes.
pub fn contexts_no_tracing_switch(
    _fixture_name: &syn::Ident,
    contexts: &[syn::Ident],
) -> proc_macro2::TokenStream {
    let rebuild_svms: Vec<_> = contexts
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let pristine = quote::format_ident!("__pristine_svm_{}", i);
            let saved = quote::format_ident!("__saved_svm_{}", i);
            quote! {
                {
                    let mut __fast_svm = crucible_test_context::litesvm::LiteSVM::new()
                        .with_transaction_history(0)
                        .with_sigverify(false)
                        .with_blockhash_check(false);
                    if let Some(ref __snap) = template_fixture.#field.snapshot {
                        __snap.restore_full(&mut __fast_svm);
                    }
                    *#pristine.borrow_mut() = __fast_svm.clone();
                    *#saved.borrow_mut() = __fast_svm;
                }
            }
        })
        .collect();
    quote! {
        if std::env::var("FUZZ_NO_TRACING").is_ok() {
            std::env::remove_var("CRUCIBLE_FUZZ_DEBUGGABLE");
            eprintln!("[FUZZ] Corpus loaded with tracing. Switching to no-tracing mode for fuzzing.");
            #(#rebuild_svms)*
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
        assert!(
            output.contains("corpus_in_dir"),
            "should reference corpus_in_dir env"
        );
        assert!(output.contains("read_dir"), "should scan directory");
        assert!(output.contains("metadata"), "should read file metadata");
        assert!(output.contains("1024"), "should default to 1024 bytes");
        assert!(
            output.contains("set_max_size"),
            "should call state.set_max_size"
        );
    }

    // ── mutator / seed setup ────────────────────────────────────────────

    #[test]
    fn mutator_stages_setup_uses_havoc() {
        let output = ts(mutator_stages_setup());
        assert!(
            output.contains("havoc_mutations"),
            "arbitrary mode should use havoc_mutations"
        );
        assert!(output.contains("StdMOptMutator"), "should use MOpt mutator");
        assert!(
            output.contains("StdPowerMutationalStage"),
            "should wrap in power stage"
        );
    }

    #[test]
    fn structured_mutator_stages_has_all_mutators() {
        let action_ty = quote! { TestAction };
        let output = ts(structured_mutator_stages_setup(&action_ty));
        assert!(
            output.contains("SuccessTrimStage"),
            "should include trim stage"
        );
        assert!(
            output.contains("SequenceMutator"),
            "should include sequence mutator"
        );
        assert!(
            output.contains("ParamMutator"),
            "should include param mutator"
        );
        assert!(
            output.contains("CrossoverMutator"),
            "should include crossover mutator"
        );
        assert!(
            output.contains("FUZZ_MAX_ACTIONS"),
            "should respect max actions env"
        );
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
        assert!(
            output.contains("ActionGenerator"),
            "should use ActionGenerator"
        );
        assert!(output.contains("generate"), "should call generate()");
        // Verify fallback seed when corpus is empty
        assert!(
            output.contains("count") && output.contains("== 0"),
            "should check if corpus is empty for fallback"
        );
    }

    // ── observer / feedback ─────────────────────────────────────────────

    #[test]
    fn singlecore_observer_feedback_has_hitcounts() {
        let mod_name = format_ident!("__fuzz_mod");
        let output = ts(singlecore_observer_feedback(&mod_name));
        assert!(
            output.contains("HitcountsMapObserver"),
            "should use HitcountsMapObserver for bucketing"
        );
        assert!(
            output.contains("MaxMapFeedback"),
            "should use MaxMapFeedback"
        );
        assert!(
            output.contains("TimeFeedback"),
            "should track execution time"
        );
        assert!(
            output.contains("SuccessPatternFeedback"),
            "should track action success patterns"
        );
        assert!(output.contains("CrashFeedback"), "should detect crashes");
    }

    // ── template / common setup ─────────────────────────────────────────

    #[test]
    fn template_setup_enables_tracing() {
        let fixture = format_ident!("TestFixture");
        let mod_name = format_ident!("__fuzz_mod");
        let output = ts(template_setup(&fixture, &mod_name));
        assert!(
            output.contains("CRUCIBLE_FUZZ_DEBUGGABLE"),
            "should enable tracing env var"
        );
        assert!(output.contains("setup"), "should call Fixture::setup()");
        assert!(
            output.contains("init_program_totals"),
            "should init coverage totals"
        );
        assert!(
            output.contains("init_program_binaries"),
            "should init binaries"
        );
    }

    #[test]
    fn common_fuzz_setup_has_timeout_and_counter() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let output = ts(common_fuzz_setup(&mod_name, &fixture));
        assert!(
            output.contains("FUZZ_TIMEOUT_SECS"),
            "should parse timeout env"
        );
        assert!(
            output.contains("AtomicU64"),
            "should create iteration counter"
        );
        assert!(
            output.contains("FUZZER_START_TIME"),
            "should record start time"
        );
    }

    #[test]
    fn monitor_setup_suppresses_during_corpus_loading() {
        let mod_name = format_ident!("__fuzz_mod");
        let output = ts(monitor_setup(&mod_name));
        assert!(
            output.contains("is_corpus_loading"),
            "should suppress during corpus loading"
        );
        assert!(
            output.contains("FUZZ_PULSE"),
            "should output [FUZZ_PULSE] prefix"
        );
        assert!(output.contains("edges"), "should display edge coverage");
        assert!(
            output.contains("branches"),
            "should display branch coverage"
        );
        assert!(
            output.contains("actions/exec"),
            "should display actions per execution"
        );
        assert!(output.contains("memory_kib"), "should display memory usage");
    }

    // ── exit handlers ───────────────────────────────────────────────────

    #[test]
    fn exit_handlers_write_coverage_on_panic() {
        let mod_name = format_ident!("__fuzz_mod");
        let output = ts(exit_handlers_setup(&mod_name));
        assert!(output.contains("set_hook"), "should set panic hook");
        assert!(
            output.contains("write_lcov_coverage"),
            "should write coverage on panic"
        );
        assert!(
            output.contains("lcov_output_path"),
            "should write panic coverage to configured LCOV path"
        );
        assert!(output.contains("ctrlc"), "should handle Ctrl+C");
    }

    // ── multi-context helpers ───────────────────────────────────────────

    #[test]
    fn contexts_take_snapshot_single() {
        let contexts = vec![format_ident!("ctx")];
        let output = ts(contexts_take_snapshot(&contexts));
        assert!(
            output.contains("template_fixture . ctx . take_snapshot"),
            "should snapshot ctx"
        );
    }

    #[test]
    fn contexts_take_snapshot_multi() {
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(contexts_take_snapshot(&contexts));
        assert!(
            output.contains("template_fixture . ctx . take_snapshot"),
            "should snapshot ctx"
        );
        assert!(
            output.contains("template_fixture . ctx_b . take_snapshot"),
            "should snapshot ctx_b"
        );
    }

    #[test]
    fn contexts_swap_out_creates_refcells() {
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(contexts_swap_out(&contexts));
        assert!(
            output.contains("__pristine_svm_0"),
            "should create pristine for ctx"
        );
        assert!(
            output.contains("__saved_svm_0"),
            "should create saved for ctx"
        );
        assert!(
            output.contains("__pristine_svm_1"),
            "should create pristine for ctx_b"
        );
        assert!(
            output.contains("__saved_svm_1"),
            "should create saved for ctx_b"
        );
        assert!(
            output.contains("RefCell"),
            "should use RefCell for swap trick"
        );
        assert!(
            output.contains("LiteSVM :: new"),
            "should replace with empty SVM"
        );
    }

    #[test]
    fn contexts_reset_check_uses_interval() {
        let contexts = vec![format_ident!("ctx")];
        let output = ts(contexts_reset_check(&contexts));
        assert!(
            output.contains("__svm_reset_interval"),
            "should check reset interval"
        );
        assert!(
            output.contains("current_iteration"),
            "should check iteration count"
        );
        assert!(
            output.contains("__pristine_svm_0"),
            "should clone from pristine"
        );
        assert!(output.contains("__saved_svm_0"), "should replace saved");
    }

    #[test]
    fn contexts_swap_in_swaps_all() {
        let fixture = format_ident!("fixture");
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(contexts_swap_in(&fixture, &contexts));
        assert!(
            output.contains("fixture . ctx . svm"),
            "should swap ctx SVM"
        );
        assert!(
            output.contains("fixture . ctx_b . svm"),
            "should swap ctx_b SVM"
        );
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
        assert!(
            output.contains("dirty_tracker . clear"),
            "should clear dirty tracker"
        );
    }

    #[test]
    fn contexts_swap_back_swaps_all() {
        let fixture = format_ident!("fixture");
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(contexts_swap_back(&fixture, &contexts));
        assert!(
            output.contains("fixture . ctx . svm"),
            "should swap back ctx"
        );
        assert!(
            output.contains("fixture . ctx_b . svm"),
            "should swap back ctx_b"
        );
    }

    #[test]
    fn contexts_no_tracing_switch_rebuilds_all() {
        let fixture = format_ident!("TestFixture");
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(contexts_no_tracing_switch(&fixture, &contexts));
        assert!(
            output.contains("FUZZ_NO_TRACING"),
            "should check no-tracing env"
        );
        assert!(
            output.contains("remove_var"),
            "should remove debuggable env var"
        );
        assert!(
            output.contains("restore_full"),
            "should restore accounts from template snapshot into the fast SVM"
        );
        assert!(
            output.contains("LiteSVM :: new"),
            "should build a fresh non-debuggable LiteSVM"
        );
        assert!(
            output.contains("__pristine_svm_0"),
            "should update pristine ctx"
        );
        assert!(
            output.contains("__pristine_svm_1"),
            "should update pristine ctx_b"
        );
    }

    // ── stateful-mode extra context helpers ──────────────────────────────

    #[test]
    fn stateful_extra_take_snapshot_skips_primary() {
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(stateful_extra_take_snapshot(&contexts));
        // Should NOT contain ctx (primary), only ctx_b
        assert!(
            !output.contains("template_fixture . ctx . take_snapshot"),
            "should skip primary context"
        );
        assert!(
            output.contains("template_fixture . ctx_b . take_snapshot"),
            "should snapshot additional context"
        );
    }

    #[test]
    fn stateful_extra_take_snapshot_empty_for_single_context() {
        let contexts = vec![format_ident!("ctx")];
        let output = ts(stateful_extra_take_snapshot(&contexts));
        assert!(
            output.is_empty(),
            "single context should produce no extra snapshot code"
        );
    }

    #[test]
    fn stateful_extra_swap_out_creates_mut_vars() {
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(stateful_extra_swap_out(&contexts));
        assert!(
            output.contains("__extra_svm_1"),
            "should create __extra_svm_1 for ctx_b"
        );
        assert!(
            !output.contains("__extra_svm_0"),
            "should not create __extra_svm_0 (primary handled separately)"
        );
        assert!(
            output.contains("LiteSVM :: new"),
            "should replace with empty SVM"
        );
    }

    #[test]
    fn stateful_extra_swap_in_uses_fixture_param() {
        let fixture = format_ident!("my_fixture");
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(stateful_extra_swap_in(&fixture, &contexts));
        assert!(
            output.contains("my_fixture . ctx_b . svm"),
            "should swap ctx_b using fixture param"
        );
        assert!(output.contains("__extra_svm_1"), "should use __extra_svm_1");
    }

    #[test]
    fn stateful_extra_restore_and_swap_back_restores_and_clears() {
        let fixture = format_ident!("my_fixture");
        let contexts = vec![format_ident!("ctx"), format_ident!("ctx_b")];
        let output = ts(stateful_extra_restore_and_swap_back(&fixture, &contexts));
        assert!(output.contains("restore"), "should call restore");
        assert!(
            output.contains("dirty_tracker . clear"),
            "should clear dirty tracker"
        );
        assert!(
            output.contains("__extra_svm_1"),
            "should swap back using __extra_svm_1"
        );
    }

    // ── is_corpus_input ─────────────────────────────────────────────────

    #[test]
    fn is_corpus_input_fn_filters_metadata() {
        let output = ts(is_corpus_input_fn());
        assert!(
            output.contains("starts_with ('.')"),
            "should skip hidden files"
        );
        assert!(output.contains(".metadata"), "should skip .metadata files");
        assert!(
            output.contains(".meta.json"),
            "should skip .meta.json files"
        );
        assert!(output.contains(".state"), "should skip .state file");
    }

    // ── D7: Corpus dir cleanup (pre-extraction regression test) ────────

    #[test]
    fn singlecore_mode_cleans_stale_metadata() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let param = format_ident!("fixture");
        let output = ts(crate::singlecore::singlecore_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &param,
            "test",
            &[],
            &[],
            false,
            None,
            &[format_ident!("ctx")],
        ));
        // Singlecore removes only hidden files (metadata)
        assert!(
            output.contains("starts_with ('.')"),
            "should filter hidden files"
        );
        assert!(
            output.contains("remove_file"),
            "should remove stale metadata files"
        );
        assert!(
            output.contains("loading_from_same_dir"),
            "should check if loading from same dir"
        );
    }

    #[test]
    fn singlecore_mode_uses_configured_lcov_output() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let param = format_ident!("fixture");
        let output = ts(crate::singlecore::singlecore_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &param,
            "test",
            &[],
            &[],
            false,
            None,
            &[format_ident!("ctx")],
        ));
        assert!(
            output.contains("lcov_output_path"),
            "singlecore timeout coverage should use configured LCOV output path"
        );
    }

    #[test]
    fn multicore_mode_cleans_corpus_dir() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let param = format_ident!("fixture");
        let output = ts(crate::multicore::multicore_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &param,
            "test",
            &[],
            &[],
            false,
            None,
            &[format_ident!("ctx")],
        ));
        // Multicore removes all files (not just hidden)
        assert!(output.contains("remove_file"), "should remove stale files");
        assert!(
            output.contains("loading_from_same_dir"),
            "should check if loading from same dir"
        );
    }

    // ── Panic capture: panics become canonical crashes (not just LibAFL objectives) ──

    #[test]
    fn singlecore_mode_alerts_and_stops_on_harness_panic() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let param = format_ident!("fixture");
        let output = ts(crate::singlecore::singlecore_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &param,
            "test",
            &[],
            &[],
            false,
            None,
            &[format_ident!("ctx")],
        ));
        // A bare harness panic is alerted-and-stopped via our panic hook (LibAFL chains it before
        // its own objective save / _exit), not saved as a crash. The hook must be armed and
        // installed before the executor, and must exit on a genuine harness panic.
        assert!(
            output.contains("arm_harness_panic_handler"),
            "should arm harness-panic handling before the executor"
        );
        assert!(
            output.contains("harness_panic_alert"),
            "panic hook should alert on a harness panic"
        );
        assert!(
            output.contains("std :: process :: exit") || output.contains("process::exit"),
            "panic hook should stop the run on a genuine harness panic"
        );
        // It must be installed before InProcessExecutor is created (so LibAFL chains it).
        let arm_pos = output
            .find("arm_harness_panic_handler")
            .expect("arm_harness_panic_handler present");
        let exec_pos = output
            .find("InProcessExecutor")
            .expect("InProcessExecutor present");
        assert!(
            arm_pos < exec_pos,
            "panic hook must be installed before the InProcessExecutor is created"
        );
    }

    #[test]
    fn multicore_mode_alerts_and_stops_on_harness_panic() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let param = format_ident!("fixture");
        let output = ts(crate::multicore::multicore_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &param,
            "test",
            &[],
            &[],
            false,
            None,
            &[format_ident!("ctx")],
        ));
        assert!(
            output.contains("arm_harness_panic_handler"),
            "should arm harness-panic handling before the executor"
        );
        assert!(
            output.contains("harness_panic_alert"),
            "panic hook should alert on a harness panic"
        );
        assert!(
            output.contains("std :: process :: exit") || output.contains("process::exit"),
            "panic hook should stop the run on a genuine harness panic"
        );
        let arm_pos = output
            .find("arm_harness_panic_handler")
            .expect("arm_harness_panic_handler present");
        let exec_pos = output
            .find("InProcessExecutor")
            .expect("InProcessExecutor present");
        assert!(
            arm_pos < exec_pos,
            "panic hook must be installed before the InProcessExecutor is created"
        );
    }

    // ── C1: Multicore % 64 batch flush ─────────────────────────────────

    #[test]
    fn multicore_batches_counter_flush_every_64() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let param = format_ident!("fixture");
        let output = ts(crate::multicore::multicore_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &param,
            "test",
            &[],
            &[],
            false,
            None,
            &[format_ident!("ctx")],
        ));
        // Should batch flush shared counters every 64 iterations
        assert!(
            output.contains("% 64"),
            "should flush counters every 64 iterations"
        );
        assert!(
            output.contains("__local_actions_pending"),
            "should accumulate actions locally"
        );
        assert!(
            output.contains("__local_ok_pending"),
            "should accumulate ok count locally"
        );
        assert!(
            output.contains("__local_execs_pending"),
            "should accumulate exec count locally"
        );
    }

    // ── D10: Deser block pattern (pre-extraction regression for modes.rs) ──

    #[test]
    fn dry_run_has_deser_block_structured() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let output = ts(crate::modes::dry_run_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &[],
            &[],
            true,
        ));
        assert!(
            output.contains("__raw_bytes"),
            "structured deser should use __raw_bytes"
        );
    }

    #[test]
    fn dry_run_has_deser_block_arbitrary() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let output = ts(crate::modes::dry_run_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &[],
            &[],
            false,
        ));
        assert!(
            output.contains("Unstructured"),
            "arbitrary deser should use Unstructured"
        );
    }

    #[test]
    fn replay_has_deser_block_structured() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let action_ty = quote! { TestAction };
        let output = ts(crate::modes::replay_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &[],
            &[],
            true,
            Some(&action_ty),
        ));
        assert!(
            output.contains("__raw_bytes"),
            "structured deser should use __raw_bytes"
        );
    }

    #[test]
    fn replay_has_deser_block_arbitrary() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let output = ts(crate::modes::replay_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &[],
            &[],
            false,
            None,
        ));
        assert!(
            output.contains("Unstructured"),
            "arbitrary deser should use Unstructured"
        );
    }

    #[test]
    fn coverage_only_has_deser_block_structured() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let output = ts(crate::modes::coverage_only_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &[],
            &[],
            true,
        ));
        assert!(
            output.contains("__raw_bytes"),
            "structured deser should use __raw_bytes"
        );
    }

    #[test]
    fn coverage_only_has_deser_block_arbitrary() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let output = ts(crate::modes::coverage_only_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &[],
            &[],
            false,
        ));
        assert!(
            output.contains("Unstructured"),
            "arbitrary deser should use Unstructured"
        );
    }
}

#[cfg(test)]
mod tests_new {
    use super::*;
    use quote::format_ident;

    fn ts(tokens: proc_macro2::TokenStream) -> String {
        tokens.to_string()
    }

    // ── FuzzArgs parsing ───────────────────────────────────────────────

    #[test]
    fn fuzz_args_default_is_arbitrary_with_ctx() {
        let args = crate::FuzzArgs::default();
        assert!(!args.structured, "default should be arbitrary mode");
        assert_eq!(args.contexts.len(), 1);
        assert_eq!(args.contexts[0].to_string(), "ctx");
    }

    #[test]
    fn fuzz_args_debug_impl() {
        let args = crate::FuzzArgs::default();
        let debug_str = format!("{:?}", args);
        assert!(
            debug_str.contains("FuzzArgs"),
            "Debug impl should include struct name"
        );
    }

    // ── extract_vec_inner_type ──────────────────────────────────────────

    #[test]
    fn extract_vec_inner_type_returns_inner() {
        let ty: syn::Type = syn::parse_quote! { Vec<u64> };
        let inner = crate::extract_vec_inner_type(&ty);
        assert!(inner.is_some(), "should extract inner type from Vec<u64>");
        let inner_str = quote::quote! { #inner }.to_string();
        assert!(inner_str.contains("u64"), "inner type should be u64");
    }

    #[test]
    fn extract_vec_inner_type_returns_none_for_non_vec() {
        let ty: syn::Type = syn::parse_quote! { HashMap<String, u64> };
        assert!(crate::extract_vec_inner_type(&ty).is_none());
    }

    #[test]
    fn extract_vec_inner_type_returns_none_for_plain() {
        let ty: syn::Type = syn::parse_quote! { u64 };
        assert!(crate::extract_vec_inner_type(&ty).is_none());
    }

    // ── env var defensive parsing ──────────────────────────────────────

    #[test]
    fn common_fuzz_setup_panics_on_bad_timeout() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let output = ts(common_fuzz_setup(&mod_name, &fixture));
        assert!(
            output.contains("is not a valid number"),
            "should panic with descriptive message"
        );
        assert!(
            output.contains("FUZZ_TIMEOUT_SECS"),
            "should mention the env var name"
        );
    }

    #[test]
    fn structured_mutator_panics_on_bad_max_actions() {
        let action_ty = quote::quote! { TestAction };
        let output = ts(structured_mutator_stages_setup(&action_ty));
        assert!(
            output.contains("is not a valid number"),
            "should panic with descriptive message"
        );
        assert!(
            output.contains("FUZZ_MAX_ACTIONS"),
            "should mention FUZZ_MAX_ACTIONS"
        );
    }

    #[test]
    fn structured_seed_panics_on_bad_max_actions() {
        let action_ty = quote::quote! { TestAction };
        let output = ts(structured_add_default_seed(&action_ty));
        assert!(
            output.contains("is not a valid number"),
            "should panic with descriptive message"
        );
    }

    // ── ctrlc handler ──────────────────────────────────────────────────

    #[test]
    fn exit_handlers_warns_on_ctrlc_failure() {
        let mod_name = format_ident!("__fuzz_mod");
        let output = ts(exit_handlers_setup(&mod_name));
        assert!(output.contains("Warning"), "should warn on ctrlc failure");
        assert!(
            output.contains("if let Err"),
            "should use if let Err pattern"
        );
        assert!(
            !output.contains(". ok ()"),
            "should not silently ignore ctrlc errors"
        );
    }

    // ── stateful mode entry ────────────────────────────────────────────

    #[test]
    fn stateful_mode_requires_structured() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let param = format_ident!("fixture");
        let output = ts(crate::stateful::stateful_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &param,
            "test",
            false,
            None,
            &[format_ident!("ctx")],
        ));
        assert!(
            output.contains("only supports structured"),
            "should reject non-structured mode"
        );
    }

    #[test]
    fn stateful_mode_has_pool_capacity() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let param = format_ident!("fixture");
        let action_ty = quote::quote! { TestAction };
        let output = ts(crate::stateful::stateful_mode(
            &mod_name,
            &fixture,
            &fn_name,
            &param,
            "test",
            true,
            Some(&action_ty),
            &[format_ident!("ctx")],
        ));
        assert!(
            output.contains("pool_capacity"),
            "should have pool capacity setting"
        );
        assert!(
            output.contains("FUZZ_STATE_POOL_SIZE"),
            "should parse pool size from env"
        );
    }
}
