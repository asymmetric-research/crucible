use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, ItemFn, FnArg, Type,
};
use anchor_macro_utils::RangeConstraint;

#[proc_macro_attribute]
pub fn anchor_fuzz(args: TokenStream, item: TokenStream) -> TokenStream {
    if !proc_macro2::TokenStream::from(args.clone()).is_empty() {
        return syn::Error::new_spanned(
            proc_macro2::TokenStream::from(args),
            "anchor_fuzz no longer takes arguments - fixture type is inferred from first parameter"
        ).to_compile_error().into();
    }
    
    let mut input_fn = parse_macro_input!(item as ItemFn);
    
    let fn_name = &input_fn.sig.ident;
    let feature_name = fn_name.to_string();
    
    // Parse range constraints 
    let range_constraints: std::collections::HashMap<usize, RangeConstraint> = input_fn.sig.inputs
        .iter()
        .enumerate()
        .filter_map(|(i, arg)| {
            if let FnArg::Typed(pat_ty) = arg {
                pat_ty.attrs.iter()
                    .find(|a| a.path().is_ident("range"))
                    .and_then(|attr| RangeConstraint::from_attr(attr).ok())
                    .map(|constraint| (i, constraint))
            } else {
                None
            }
        })
        .collect();
    
    // Strip range attributes to prevent compiler errors 
    for arg in &mut input_fn.sig.inputs {
        if let FnArg::Typed(pat_ty) = arg {
            pat_ty.attrs.retain(|a| !a.path().is_ident("range"));
        }
    }
    
    // Collect references to inputs
    let inputs: Vec<_> = input_fn.sig.inputs.iter().collect();
    
    // Must have at least one parameter (the fixture)
    if inputs.is_empty() {
        return syn::Error::new_spanned(
            &input_fn.sig,
            "Function must have at least one parameter (fixture: &mut FixtureType)"
        ).to_compile_error().into();
    }
    
    // Extract fixture type from first parameter
    let FnArg::Typed(first_param) = inputs[0] else {
        return syn::Error::new_spanned(
            inputs[0],
            "First parameter must be typed (fixture: &mut FixtureType)"
        ).to_compile_error().into();
    };
    
    // Extract type from &mut FixtureType
    let fixture_type = match &*first_param.ty {
        Type::Reference(type_ref) => {
            if type_ref.mutability.is_none() {
                return syn::Error::new_spanned(
                    &first_param.ty,
                    "Fixture parameter must be mutable (&mut FixtureType)"
                ).to_compile_error().into();
            }
            &*type_ref.elem
        }
        _ => {
            return syn::Error::new_spanned(
                &first_param.ty,
                "Fixture parameter must be a mutable reference (&mut FixtureType)"
            ).to_compile_error().into();
        }
    };
    
    let fixture_name = match fixture_type {
        Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .map(|s| &s.ident)
            .expect("Expected fixture type name"),
        _ => {
            return syn::Error::new_spanned(
                fixture_type,
                "Expected a simple type path for fixture"
            ).to_compile_error().into();
        }
    };
    
    // Get the actual parameter name
    let fixture_param_name = match &*first_param.pat {
        syn::Pat::Ident(pat_ident) => &pat_ident.ident,
        _ => {
            return syn::Error::new_spanned(
                &first_param.pat,
                "Expected simple identifier for fixture parameter"
            ).to_compile_error().into();
        }
    };
    
    // Helper: generate range constraint application code
    fn gen_range_constraint(
        param_name: &proc_macro2::Ident,
        ty: &Type,
        constraint: &RangeConstraint,
    ) -> proc_macro2::TokenStream {
        let start = constraint.start;
        let range_size = if constraint.inclusive {
            constraint.end - constraint.start + 1
        } else {
            constraint.end - constraint.start
        };
        quote! {
            #param_name = (#start as #ty) + (#param_name % (#range_size as #ty));
        }
    }

    // Build parameter parsing - skip first param which is fixture
    let mut deser_stmts = Vec::new();
    let mut call_args = vec![quote! { &mut #fixture_param_name }];

    // Collect param info for all three deserialization modes
    struct ParamInfo {
        name: proc_macro2::Ident,
        ty: Type,
        constraint: Option<RangeConstraint>,
    }
    let params: Vec<ParamInfo> = inputs.iter().enumerate().skip(1).map(|(i, arg)| {
        let FnArg::Typed(pat_ty) = arg else {
            panic!("Expected typed parameter");
        };
        ParamInfo {
            name: quote::format_ident!("param_{}", i),
            ty: (*pat_ty.ty).clone(),
            constraint: range_constraints.get(&i).cloned(),
        }
    }).collect();

    // Generate fuzzing mode deserialization (returns ExitKind::Ok on error)
    for param in &params {
        let name = &param.name;
        let ty = &param.ty;

        deser_stmts.push(quote! {
            let mut #name: #ty = match <#ty as arbitrary::Arbitrary>::arbitrary(&mut u) {
                Ok(v) => v,
                Err(_) => return libafl::prelude::ExitKind::Ok,
            };
        });

        if let Some(ref constraint) = param.constraint {
            deser_stmts.push(gen_range_constraint(name, ty, constraint));
        }

        call_args.push(quote! { #name });
    }

    // Generate simple mode deserialization (uses expect() - for dry-run, replay, coverage-only)
    let simple_deser_stmts: Vec<_> = params.iter().map(|param| {
        let name = &param.name;
        let ty = &param.ty;

        let base_deser = quote! {
            let mut #name: #ty = <#ty as arbitrary::Arbitrary>::arbitrary(&mut u)
                .expect("Failed to deserialize input");
        };

        if let Some(ref constraint) = param.constraint {
            let constraint_code = gen_range_constraint(name, ty, constraint);
            quote! {
                #base_deser
                #constraint_code
            }
        } else {
            base_deser
        }
    }).collect();

    let mod_name = quote::format_ident!("__anchor_fuzz_rt_{}", fn_name);
    let show_fn_name = quote::format_ident!("__show_{}", fn_name);

    // Generate show code (deserialize + print each param)
    let show_body = {
        let param_deserializations: Vec<_> = params.iter().map(|param| {
            let name = &param.name;
            let ty = &param.ty;

            let base_deser = quote! {
                let mut #name: #ty = arbitrary::Arbitrary::arbitrary(&mut u)
                    .expect("Failed to deserialize parameter");
            };

            if let Some(ref constraint) = param.constraint {
                let constraint_code = gen_range_constraint(name, ty, constraint);
                quote! {
                    #base_deser
                    #constraint_code
                    println!("{}: {:#?}", stringify!(#name), #name);
                }
            } else {
                quote! {
                    #base_deser
                    println!("{}: {:#?}", stringify!(#name), #name);
                }
            }
        }).collect();

        quote! {
            println!("Crash Input:");
            #(#param_deserializations)*
        }
    };
    
    // ============================================================================
    // SHARED COVERAGE INITIALIZATION
    // Used by template_setup, replay mode, and coverage-only mode
    // ============================================================================

    // Basic coverage totals (edge_totals + instr_totals) - used by all modes
    let init_coverage_totals = quote! {
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
    };

    // Program binaries (for LCOV output) - used by coverage-only and normal fuzzing
    let init_program_binaries = quote! {
        let mut program_binaries: std::collections::HashMap<u64, Vec<u8>> = std::collections::HashMap::new();
        for (pubkey, binary) in template_fixture.ctx.get_program_binaries() {
            let program_hash = u64::from_le_bytes(
                pubkey.to_bytes()[0..8].try_into().unwrap()
            );
            program_binaries.insert(program_hash, binary);
        }
        #mod_name::init_program_binaries(program_binaries.clone());
    };

    // Cached analysis (for fast HTML generation) - used only by normal fuzzing
    let init_cached_analysis = quote! {
        let mut cached_analysis: std::collections::HashMap<u64, anchor_test_context::CachedProgramAnalysis> = std::collections::HashMap::new();
        for (prog_hash, binary) in &program_binaries {
            let program_name = format!("program_{:016x}", prog_hash);
            if let Some(analysis) = anchor_test_context::build_cached_analysis(&program_name, binary) {
                cached_analysis.insert(*prog_hash, analysis);
            }
        }
        #mod_name::init_cached_analysis(cached_analysis);
    };

    // Template setup - call setup() once to build fully initialized fixture
    // Set env var so TestContext::new() creates a debuggable SVM with register tracing
    let template_setup = quote! {
        std::env::set_var("ANCHOR_FUZZ_DEBUGGABLE", "1");
        let template_fixture = #fixture_name::setup();

        // Debug: verify accounts exist in template after setup
        if std::env::var("FUZZ_DEBUG").is_ok() {
            eprintln!("[SETUP] Template created with {} tracked accounts", template_fixture.ctx.tracked_accounts_count());
            eprintln!("[SETUP] Template has {} programs", template_fixture.ctx.programs_count());
        }

        // Initialize all coverage tracking data
        {
            #init_coverage_totals
            #init_program_binaries
            #init_cached_analysis
        }
    };
    
    // Per-iteration setup - clone fixture and replace ctx with new invocation callback
    // Important: clone ctx directly from template (not from the already-cloned fixture)
    // to avoid potential issues with nested cloning in debuggable mode
    let iteration_setup = quote! {
        let mut #fixture_param_name = template_fixture.clone();
        let callback = #mod_name::FuzzCallback::from_raw(cov_ptr, #mod_name::MAP_SIZE);
        // Clone ctx directly from the original template, not from the cloned fixture
        #fixture_param_name.ctx = template_fixture.ctx.clone_with_invocation_callback(callback);

        // First iteration debug: verify accounts after clone
        static FIRST_ITERATION: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
        if std::env::var("FUZZ_DEBUG").is_ok() && FIRST_ITERATION.swap(false, std::sync::atomic::Ordering::SeqCst) {
            eprintln!("[ITER] After clone: {} tracked accounts", #fixture_param_name.ctx.tracked_accounts_count());
        }
    };

    // ============================================================================
    // SHARED QUOTE BLOCKS FOR FUZZING MODE
    // These are extracted to avoid duplicating ~400 lines between OnDisk and InMemory corpus modes
    // ============================================================================

    // Monitor creation - displays coverage stats with AFL-style formatting
    let monitor_setup = quote! {
        let monitor = SimpleMonitor::new(|s| {
            let s = s.replace("objectives", "crashes");
            let state = #mod_name::COVERAGE_STATE.lock().unwrap();
            let true_edges = state.total_edges;
            let branches = state.total_branches;
            drop(state);
            let total_edges: usize = #mod_name::PROGRAM_TOTALS.get().map(|t| t.values().sum()).unwrap_or(0);
            let total_branches = total_edges / 2;
            if let Some(idx) = s.find("edges:") {
                let prefix = &s[..idx];
                let edges_part = &s[idx..];
                let afl_edges: usize = edges_part.split_whitespace().nth(1)
                    .and_then(|p| p.split('/').next()).and_then(|n| n.parse().ok()).unwrap_or(0);
                let afl_pct = (afl_edges as f64 / (1u64 << 15) as f64) * 100.0;
                let edge_pct = if total_edges > 0 { (true_edges as f64 / total_edges as f64) * 100.0 } else { 0.0 };
                let branch_pct = if total_branches > 0 { (branches as f64 / total_branches as f64) * 100.0 } else { 0.0 };
                println!("{}afl_edges: {}/65536 ({:.1}%), edges: {}/{} ({:.1}%), branches: {}/{} ({:.1}%)",
                    prefix, afl_edges, afl_pct, true_edges, total_edges, edge_pct, branches, total_branches, branch_pct);
            } else { println!("{s}"); }
        });
        let mut mgr = SimpleEventManager::new(monitor);
    };

    // Observer and feedback setup
    let observer_feedback_setup = quote! {
        let std_map = unsafe { StdMapObserver::from_mut_ptr("edges", cov_ptr, #mod_name::MAP_SIZE) };
        let edges_observer = HitcountsMapObserver::new(std_map).track_indices();
        let time_observer = TimeObserver::new("time");

        let map_feedback = MaxMapFeedback::new(&edges_observer);
        let time_feedback = TimeFeedback::new(&time_observer);
        let mut feedback = feedback_or!(map_feedback, time_feedback);
        let mut objective = CrashFeedback::new();
    };

    // Harness wrapper - the core fuzzing logic
    let harness_wrapper_code = quote! {
        let mut harness_wrapper = |input: &BytesInput| -> ExitKind {
            if let Some(timeout) = timeout_secs {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now - start_time >= timeout {
                    eprintln!("\n[FUZZ] Timeout reached ({}s). Exiting gracefully.", timeout);
                    if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                        #mod_name::write_lcov_coverage("coverage.lcov");
                        #mod_name::write_html_coverage("coverage.html");
                    }
                    std::process::exit(0);
                }
            }

            let bytes_ref = input.target_bytes();
            let slice = bytes_ref.as_slice();
            let mut u = Unstructured::new(slice);

            let current_iteration = iteration_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            anchor_test_context::set_current_iteration(current_iteration);

            #(#deser_stmts)*

            #iteration_setup

            #fn_name(#(#call_args),*);

            let exec_count = #mod_name::TOTAL_EXECUTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                #mod_name::maybe_write_coverage(exec_count);
            }

            if let Some(msg) = anchor_test_context::take_violation() {
                eprintln!("[VIOLATION] {}", msg);
                anchor_test_context::print_action_sequence();
                // Use the same hash as LibAFL (xxh3_64) so our metadata matches LibAFL's crash filenames
                let input_hash = hash_std(slice);
                anchor_test_context::write_crash_metadata(&crash_dir, input_hash, Some(seed), slice);
                ExitKind::Crash
            } else {
                ExitKind::Ok
            }
        };
    };

    // Mutator and stages setup
    let mutator_stages_setup = quote! {
        let mutator = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5)
            .expect("failed to create mutator");
        let power_stage = StdPowerMutationalStage::new(mutator);
        let mut stages = tuple_list!(power_stage);
    };

    // Exit handlers (panic hook and ctrlc)
    let exit_handlers_setup = quote! {
        let default_panic = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                #mod_name::write_lcov_coverage("coverage.lcov");
                #mod_name::write_html_coverage("coverage.html");
            }
            default_panic(info);
        }));

        ctrlc::set_handler(move || {
            if coverage_enabled {
                eprintln!("\n[COVERAGE] Ctrl+C received. Coverage files written by periodic updates.");
            }
            std::process::exit(0);
        }).ok();
    };

    // Common fuzzing setup (template, start time, timeout)
    let common_fuzz_setup = quote! {
        #template_setup

        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let _ = #mod_name::FUZZER_START_TIME.set(start_time);

        let timeout_secs: Option<u64> = std::env::var("FUZZ_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok());

        let iteration_counter = std::sync::atomic::AtomicU64::new(0);
    };

    // Corpus loading: load inputs from a directory using add_input()
    // Used by InMemoryCorpus and OnDiskCorpus (different-directory case)
    let load_corpus_from_dir = quote! {
        eprintln!("[FUZZ] Loading seed corpus from: {}", corpus_dir);
        let mut loaded = 0usize;
        if let Ok(entries) = std::fs::read_dir(corpus_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_file() && is_corpus_input(&path) {
                    if let Ok(bytes) = std::fs::read(&path) {
                        let input = BytesInput::new(bytes);
                        if fuzzer.add_input(&mut state, &mut executor, &mut mgr, input).is_ok() {
                            loaded += 1;
                        }
                    }
                }
            }
        }
        eprintln!("[FUZZ] Loaded {} seed inputs from corpus", loaded);
    };

    // Default seed: add a zero-filled seed input
    let add_default_seed = quote! {
        let input = BytesInput::new(vec![0u8; 256]);
        fuzzer.add_input(&mut state, &mut executor, &mut mgr, input)
            .expect("failed to add seed input");
    };

    let expanded = quote! {
        #input_fn

        #[cfg(feature = #feature_name)]
        mod #mod_name {
            use super::*;
            use std::collections::{HashMap, HashSet};
            use std::sync::{Mutex, LazyLock};

            pub const MAP_SIZE: usize = 1 << 16;

            /// Consolidated coverage state - uses Mutex instead of TLS.
            /// Single-threaded fuzzer means no contention, ~20ns lock overhead.
            #[derive(Default)]
            pub struct CoverageState {
                // HOT PATH - use FxHash for speed (10-50x faster than SipHash for integers)
                pub edges: anchor_test_context::FastHashMap<u64, anchor_test_context::FastHashSet<u64>>,
                pub branch_pcs: anchor_test_context::FastHashMap<u64, anchor_test_context::FastHashSet<usize>>,
                // LCOV branch tracking (only when --coverage enabled)
                pub branch_outcomes: HashMap<u64, HashMap<(usize, bool), u64>>, // program -> ((branch_pc, taken) -> count)
                // PC hit tracking for source-level LCOV (only when --coverage enabled)
                pub pc_hits: HashMap<u64, HashMap<usize, u64>>, // program -> (pc -> count)
                pub last_write_iteration: u64,   // Iteration-based throttling (not time-based)
                pub last_coverage_count: usize,  // For smart batching
                // Cached totals for SimpleMonitor (avoid iterating all data)
                pub total_edges: usize,
                pub total_branches: usize,
            }

            pub static COVERAGE_STATE: LazyLock<Mutex<CoverageState>> = LazyLock::new(|| {
                Mutex::new(CoverageState::default())
            });

            // Coverage enabled flag (set by --coverage arg)
            pub static COVERAGE_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

            // Runtime stats tracking
            pub static FUZZER_START_TIME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
            pub static TOTAL_EXECUTIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

            // Static storage for total edges per program (for percentage calculation)
            pub static PROGRAM_TOTALS: std::sync::OnceLock<HashMap<u64, usize>> = std::sync::OnceLock::new();
            // Static storage for total instructions per program
            pub static PROGRAM_TOTAL_INSTRUCTIONS: std::sync::OnceLock<HashMap<u64, usize>> = std::sync::OnceLock::new();
            // Static storage for program binaries (for LCOV function extraction)
            pub static PROGRAM_BINARIES: std::sync::OnceLock<HashMap<u64, Vec<u8>>> = std::sync::OnceLock::new();
            // Cached analysis for fast HTML generation (parsed once at startup)
            pub static CACHED_ANALYSIS: std::sync::OnceLock<HashMap<u64, anchor_test_context::CachedProgramAnalysis>> = std::sync::OnceLock::new();

            pub fn init_program_totals(edge_totals: HashMap<u64, usize>, instruction_totals: HashMap<u64, usize>) {
                let _ = PROGRAM_TOTALS.set(edge_totals);
                let _ = PROGRAM_TOTAL_INSTRUCTIONS.set(instruction_totals);
            }

            pub fn init_program_binaries(binaries: HashMap<u64, Vec<u8>>) {
                let _ = PROGRAM_BINARIES.set(binaries);
            }

            pub fn init_cached_analysis(cached: HashMap<u64, anchor_test_context::CachedProgramAnalysis>) {
                let _ = CACHED_ANALYSIS.set(cached);
            }

            pub struct FuzzCallback {
                ptr: *mut u8,
                len: usize,
            }

            unsafe impl Send for FuzzCallback {}
            unsafe impl Sync for FuzzCallback {}

            impl FuzzCallback {
                pub fn from_raw(ptr: *mut u8, len: usize) -> Self {
                    Self { ptr, len }
                }

                /// Process pre-filtered branch edges and PC hits for coverage tracking
                fn process_trace(
                    &self,
                    program_id: &anchor_test_context::fuzz_types::Pubkey,
                    branch_edges: &[(usize, usize)],
                    visited_pcs: &[usize],
                ) {
                    if branch_edges.is_empty() && visited_pcs.is_empty() {
                        return;
                    }

                    // Include program ID to distinguish same-PC edges across programs
                    let program_hash = u64::from_le_bytes(
                        program_id.to_bytes()[0..8].try_into().unwrap()
                    );

                    let mut local_branch_pcs: anchor_test_context::FastHashSet<usize> = anchor_test_context::FastHashSet::default();
                    local_branch_pcs.reserve(branch_edges.len());
                    let mut local_edges: anchor_test_context::FastHashSet<u64> = anchor_test_context::FastHashSet::default();
                    local_edges.reserve(branch_edges.len());

                    // AFL-style edge tracking with prev_location state
                    let mut prev_location: usize = 0;

                    for &(pc, target_pc) in branch_edges {
                        // Fibonacci hash for better distribution with BPF's small PC range
                        // Combines full (source, target) edge info with golden ratio multiplier
                        let edge_id = ((pc as u64) << 32) | (target_pc as u64);
                        let cur_location = ((edge_id.wrapping_mul(0x9e3779b97f4a7c15)) >> 48) as usize;
                        let edge = (cur_location ^ prev_location) % MAP_SIZE;
                        prev_location = cur_location >> 1;

                        unsafe {
                            // Write to coverage map (must be done inline for AFL compatibility)
                            let buf = std::slice::from_raw_parts_mut(self.ptr, self.len);
                            buf[edge] = buf[edge].wrapping_add(1);
                        }

                        // Collect edges and branches (for SimpleMonitor display)
                        let unique_edge = ((pc as u64) << 32) | (target_pc as u64);
                        local_edges.insert(unique_edge);
                        local_branch_pcs.insert(pc);
                    }

                    // Update global state
                    let mut state = COVERAGE_STATE.lock().unwrap();

                    // Track edges and update cached total
                    let edge_set = state.edges.entry(program_hash).or_default();
                    let old_edge_count = edge_set.len();
                    edge_set.extend(&local_edges);
                    state.total_edges += edge_set.len() - old_edge_count;

                    // Track branch PCs and update cached total
                    let branch_set = state.branch_pcs.entry(program_hash).or_default();
                    let old_branch_count = branch_set.len();
                    branch_set.extend(&local_branch_pcs);
                    state.total_branches += branch_set.len() - old_branch_count;

                    // Track branch outcomes and PC hits for LCOV (only when --coverage enabled)
                    if COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                        let program_outcomes = state.branch_outcomes.entry(program_hash).or_default();
                        for &(pc, target_pc) in branch_edges {
                            // taken = jump target is not the fall-through (pc + 8)
                            let taken = target_pc != pc + 8;
                            *program_outcomes.entry((pc, taken)).or_insert(0) += 1;
                        }

                        // Track all visited PC addresses for source-level LCOV
                        let program_pc_hits = state.pc_hits.entry(program_hash).or_default();
                        for &pc in visited_pcs {
                            *program_pc_hits.entry(pc).or_insert(0) += 1;
                        }
                    }
                }
            }

            impl anchor_test_context::InvocationInspectCallback for FuzzCallback {
                fn before_invocation(
                    &self,
                    _tx: &anchor_test_context::fuzz_types::SanitizedTransaction,
                    _program_indices: &[anchor_test_context::fuzz_types::IndexOfAccount],
                    _invoke_context: &anchor_test_context::fuzz_types::InvokeContext,
                ) {
                    // No-op: coverage tracked in after_invocation
                }

                fn after_invocation(
                    &self,
                    invoke_context: &anchor_test_context::fuzz_types::InvokeContext,
                    register_tracing_enabled: bool,
                ) {
                    if register_tracing_enabled {
                        let coverage_enabled = COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed);

                        invoke_context.iterate_vm_traces(
                            &|instruction_context,
                              executable,
                              register_trace| {
                                if let Ok(program_id) = instruction_context.get_program_key() {
                                    use anchor_test_context::fuzz_types::ebpf;

                                    let (_vm_addr, program) = executable.get_text_bytes();

                                    // Pre-filter: extract only (branch_pc, target_pc) pairs
                                    let mut branch_edges: Vec<(usize, usize)> = Vec::with_capacity(register_trace.len() / 8);

                                    // Collect all visited PCs for source-level LCOV (only when coverage enabled)
                                    let mut visited_pcs: Vec<usize> = if coverage_enabled {
                                        Vec::with_capacity(register_trace.len())
                                    } else {
                                        Vec::new()
                                    };

                                    for i in 0..register_trace.len().saturating_sub(1) {
                                        let pc = register_trace[i][11] as usize;

                                        // Collect all PCs for source-level coverage
                                        if coverage_enabled {
                                            visited_pcs.push(pc);
                                        }

                                        let insn = ebpf::get_insn_unchecked(program, pc);

                                        // Only conditional branches
                                        let is_jmp_class = insn.opc & 7 == ebpf::BPF_JMP;
                                        if !is_jmp_class { continue; }

                                        let opc = insn.opc;
                                        if opc == 0x05 || opc == 0x85 || opc == 0x8d || opc == 0x95 { continue; }

                                        let target_pc = register_trace[i + 1][11] as usize;
                                        branch_edges.push((pc, target_pc));
                                    }

                                    // Also add the last PC if we have any trace data
                                    if coverage_enabled && !register_trace.is_empty() {
                                        let last_pc = register_trace[register_trace.len() - 1][11] as usize;
                                        visited_pcs.push(last_pc);
                                    }

                                    self.process_trace(program_id, &branch_edges, &visited_pcs);
                                }
                            },
                        );
                    }
                }
            }

            /// Write LCOV coverage file to disk
            ///
            /// Tries source-level coverage first (using DWARF debug info),
            /// falls back to bytecode-level if no debug info is available.
            pub fn write_lcov_coverage(output_path: &str) {
                use std::fs::File;
                use std::io::{BufWriter, Write};

                let file = match File::create(output_path) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("[LCOV] Failed to create {}: {}", output_path, e);
                        return;
                    }
                };
                let mut writer = BufWriter::new(file);

                // Get coverage data from state
                let state = COVERAGE_STATE.lock().unwrap();
                let branch_outcomes = state.branch_outcomes.clone();
                let pc_hits = state.pc_hits.clone();
                drop(state); // Release lock before file I/O

                if branch_outcomes.is_empty() && pc_hits.is_empty() {
                    eprintln!("[LCOV] No coverage data to write");
                    return;
                }

                let program_binaries = PROGRAM_BINARIES.get();
                let edge_totals = PROGRAM_TOTALS.get();
                let instr_totals = PROGRAM_TOTAL_INSTRUCTIONS.get();

                let mut programs_written = 0usize;

                // Get all program hashes (union of branch_outcomes and pc_hits keys)
                let mut all_programs: std::collections::HashSet<u64> = branch_outcomes.keys().copied().collect();
                all_programs.extend(pc_hits.keys());

                for prog_hash in all_programs {
                    let program_name = format!("program_{:016x}", prog_hash);

                    let outcomes = branch_outcomes.get(&prog_hash)
                        .cloned()
                        .unwrap_or_default();
                    let hits = pc_hits.get(&prog_hash)
                        .cloned()
                        .unwrap_or_default();

                    let program_data = program_binaries
                        .and_then(|b| b.get(&prog_hash))
                        .map(|v| v.as_slice());

                    let functions = program_data
                        .and_then(|data| anchor_test_context::extract_functions(data))
                        .unwrap_or_default();

                    let total_edges = edge_totals.and_then(|t| t.get(&prog_hash).copied()).unwrap_or(0);
                    let total_branches = total_edges / 2;
                    let total_instructions = instr_totals.and_then(|t| t.get(&prog_hash).copied()).unwrap_or(0);

                    if let Err(e) = anchor_test_context::generate_bytecode_lcov(
                        &mut writer,
                        &program_name,
                        &hits,
                        &outcomes,
                        &functions,
                        total_instructions,
                        total_branches,
                    ) {
                        eprintln!("[LCOV] Error writing coverage for {}: {}", program_name, e);
                    } else {
                        programs_written += 1;
                    }
                }

                // Explicitly flush and sync to ensure data is written before process exit
                if let Err(e) = writer.flush() {
                    eprintln!("[LCOV] Error flushing buffer: {}", e);
                }
                // Get inner file and sync to disk
                let file = writer.into_inner().expect("Failed to get inner file");
                if let Err(e) = file.sync_all() {
                    eprintln!("[LCOV] Error syncing file: {}", e);
                }

                eprintln!("[LCOV] Coverage written to {} ({} programs, {} lines, {} branches)",
                    output_path,
                    programs_written,
                    pc_hits.values().map(|h| h.len()).sum::<usize>(),
                    branch_outcomes.values().map(|h| h.len()).sum::<usize>());
            }

            /// Write coverage files every 5000 iterations when new coverage is discovered.
            /// Uses iteration-based throttling (no syscalls) instead of wall-clock time.
            /// Note: Caller should check COVERAGE_ENABLED before calling this function
            pub fn maybe_write_coverage(exec_count: u64) {
                // Iteration-based throttling: only check every 5000 iterations
                if exec_count % 5000 != 0 {
                    return;
                }

                // Check if new coverage was discovered (use cached totals)
                let mut state = COVERAGE_STATE.lock().unwrap();
                let current_coverage_count = state.total_edges;
                let has_new_coverage = current_coverage_count > state.last_coverage_count;

                if has_new_coverage {
                    // Update coverage count
                    state.last_coverage_count = current_coverage_count;
                    drop(state); // Release lock before file I/O

                    // Write both LCOV and HTML when new coverage is found
                    write_lcov_coverage("coverage.lcov");
                    write_html_coverage("coverage.html");
                }
            }

            /// Write HTML coverage visualization using genhtml (LCOV tool)
            ///
            /// Uses the standard genhtml tool for proper branch coverage visualization.
            /// Falls back to a simple message if genhtml is not installed.
            pub fn write_html_coverage(output_dir: &str) {
                // First check if genhtml is available
                let genhtml_available = std::process::Command::new("genhtml")
                    .arg("--version")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);

                if !genhtml_available {
                    eprintln!("[HTML] genhtml not found. Install lcov for HTML reports:");
                    eprintln!("[HTML]   brew install lcov  # macOS");
                    eprintln!("[HTML]   apt install lcov   # Ubuntu/Debian");
                    return;
                }

                // Find source directory (where program source files are)
                // Search parent dirs and sibling directories for projects with programs/
                let source_dir: Option<String> = {
                    let mut found = None;

                    // Check FUZZ_SOURCE_ROOT env var first
                    if let Ok(root) = std::env::var("FUZZ_SOURCE_ROOT") {
                        found = Some(root);
                    }

                    // Search parent and sibling directories
                    if found.is_none() {
                        'outer: for depth in 1..=8 {
                            let parent: String = (0..depth).map(|_| "..").collect::<Vec<_>>().join("/");

                            // Check if this directory has programs/
                            if std::path::Path::new(&format!("{}/programs", parent)).exists() {
                                found = Some(parent);
                                break;
                            }

                            // Check sibling directories
                            if let Ok(entries) = std::fs::read_dir(&parent) {
                                for entry in entries.filter_map(|e| e.ok()) {
                                    let sibling = entry.path();
                                    if sibling.is_dir() && sibling.join("programs").exists() {
                                        found = Some(sibling.to_string_lossy().to_string());
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }

                    found
                };

                // Run genhtml on the LCOV file
                let mut cmd = std::process::Command::new("genhtml");
                cmd.arg("coverage.lcov")
                    .arg("--branch-coverage")
                    .arg("--output-directory")
                    .arg(output_dir)
                    .arg("--ignore-errors")
                    .arg("source,source,missing,missing,empty") // Ignore missing source files and paths
                    .arg("--synthesize-missing"); // Create placeholder for missing source files

                if let Some(ref src_dir) = source_dir {
                    cmd.arg("--source-directory").arg(src_dir);
                }

                match cmd.output() {
                    Ok(output) => {
                        if output.status.success() {
                            eprintln!("[HTML] Coverage report written to {}/index.html", output_dir);
                        } else {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            // Check for common non-fatal errors
                            if stderr.contains("unused") {
                                // --source-directory not used is fine
                                eprintln!("[HTML] Coverage report written to {}/index.html", output_dir);
                            } else {
                                eprintln!("[HTML] genhtml error: {}", stderr);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[HTML] Failed to run genhtml: {}", e);
                    }
                }
            }
        }

        pub fn #show_fn_name() {
            use arbitrary::Unstructured;
            use std::io::Read;

            let mut bytes = Vec::new();
            std::io::stdin().read_to_end(&mut bytes)
                .expect("Failed to read crash input from stdin");

            let mut u = Unstructured::new(&bytes);

            #show_body
        }

        fn main() {
            if std::env::var("SHOW_CRASH").is_ok() {
                #show_fn_name();
                return;
            }

            // Parse --coverage flag
            let coverage_enabled = std::env::args().any(|a| a == "--coverage");
            #mod_name::COVERAGE_ENABLED.store(coverage_enabled, std::sync::atomic::Ordering::Relaxed);
            if coverage_enabled {
                eprintln!("[COVERAGE] Coverage output enabled. Files will be written when new coverage is discovered.");
            }

            use std::process;
            use libafl::mutators::StdMOptMutator;
            use libafl::prelude::*;
            use libafl::monitors::SimpleMonitor;
            use libafl::schedulers::powersched::PowerSchedule;
            use libafl_bolts::tuples::tuple_list;
            use libafl_bolts::{current_nanos, rands::StdRand, AsSlice, hash_std};
            use std::time::Duration;
            use arbitrary::Unstructured;

            // Parse environment variables for new modes
            let dry_run_mode = std::env::var("FUZZ_DRY_RUN").is_ok();
            let input_file = std::env::var("FUZZ_INPUT_FILE").ok();
            let coverage_only_mode = std::env::var("FUZZ_COVERAGE_ONLY").is_ok();
            let corpus_in_dir = std::env::var("FUZZ_CORPUS_IN").ok();
            let corpus_out_dir = std::env::var("FUZZ_CORPUS_OUT").ok();
            let crashes_dir_env = std::env::var("FUZZ_CRASHES_DIR").ok();

            // Coverage map - just a simple vec, no shared memory needed for InProcessExecutor
            let mut coverage_map = vec![0u8; #mod_name::MAP_SIZE];
            let cov_ptr = coverage_map.as_mut_ptr();

            // === DRY-RUN MODE ===
            // Run setup and a single iteration to validate the harness works
            if dry_run_mode {
                eprintln!("[DRY-RUN] Validating harness setup...");

                // Setup tracing for coverage
                std::env::set_var("ANCHOR_FUZZ_DEBUGGABLE", "1");

                // Run setup
                let template_fixture = #fixture_name::setup();
                eprintln!("[DRY-RUN] Setup completed successfully");
                eprintln!("[DRY-RUN] - {} tracked accounts", template_fixture.ctx.tracked_accounts_count());
                eprintln!("[DRY-RUN] - {} programs loaded", template_fixture.ctx.programs_count());

                // Run a single iteration with seed input
                let callback = #mod_name::FuzzCallback::from_raw(cov_ptr, #mod_name::MAP_SIZE);
                let mut fixture = template_fixture.clone();
                fixture.ctx = template_fixture.ctx.clone_with_invocation_callback(callback);

                // Create minimal input and run test
                let seed_bytes = vec![0u8; 256];
                let mut u = Unstructured::new(&seed_bytes);

                #(#simple_deser_stmts)*

                #fn_name(#(#call_args),*);

                eprintln!("[DRY-RUN] Single iteration completed successfully");
                eprintln!("[DRY-RUN] Harness validation passed!");
                std::process::exit(0);
            }

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

                let callback = #mod_name::FuzzCallback::from_raw(cov_ptr, #mod_name::MAP_SIZE);
                let mut fixture = template_fixture.clone();
                fixture.ctx = template_fixture.ctx.clone_with_invocation_callback(callback);

                // Reset iteration counter
                anchor_test_context::set_current_iteration(0);

                // Parse input and run test
                let mut u = Unstructured::new(&input_bytes);

                #(#simple_deser_stmts)*

                // Clear any previous action sequence
                anchor_test_context::clear_action_history();

                eprintln!("[REPLAY] Executing test...");
                #fn_name(#(#call_args),*);

                // Check for crash/violation
                if let Some(msg) = anchor_test_context::take_violation() {
                    eprintln!("[REPLAY] CRASH REPRODUCED!");
                    eprintln!("[REPLAY] Violation: {}", msg);
                    anchor_test_context::print_action_sequence();
                    std::process::exit(1);
                } else {
                    eprintln!("[REPLAY] Test completed without crash");
                    eprintln!("[REPLAY] Note: If you expected a crash, the input may be from a different harness version");
                    anchor_test_context::print_action_sequence();
                    std::process::exit(0);
                }
            }

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
                    let callback = #mod_name::FuzzCallback::from_raw(cov_ptr, #mod_name::MAP_SIZE);
                    let mut fixture = template_fixture.clone();
                    fixture.ctx = template_fixture.ctx.clone_with_invocation_callback(callback);

                    // Create fresh Unstructured for parsing
                    let mut u = Unstructured::new(&input_bytes);

                    // Run the test in a closure to handle deserialization failures
                    let run_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        #(#simple_deser_stmts)*

                        #fn_name(#(#call_args),*);
                    }));

                    // Ignore panics from deserialization failures or test assertions
                    let _ = run_result;

                    // Clear any violation flag
                    let _ = anchor_test_context::take_violation();

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
                #mod_name::write_html_coverage("coverage.html");

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

            // === NORMAL FUZZING MODE ===

            // === CORPUS ===
            let seed = current_nanos().max(1);

            // Configure directories based on environment variables
            let crash_dir = crashes_dir_env.unwrap_or_else(|| format!("crashes/{}", #feature_name));
            std::fs::create_dir_all(&crash_dir).expect("failed to create crash directory");

            // Branch based on whether corpus output directory is specified
            // This requires separate code paths because StdState is generic over corpus type
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
                // This prevents OnDiskCorpus from trying to load entries from a previous run
                // LibAFL uses hidden files for metadata: .HASH (pointers) and .HASH_N.metadata
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
                    if removed > 0 {
                        eprintln!("[FUZZ] Cleaned {} stale metadata files from corpus directory", removed);
                    }
                }

                eprintln!("[FUZZ] Writing corpus entries to: {}", corpus_out_path);

                // Use shared setup blocks
                #monitor_setup
                #observer_feedback_setup

                // OnDiskCorpus-specific: create corpus and state
                let rand = StdRand::with_seed(seed);
                let corpus = OnDiskCorpus::<BytesInput>::new(corpus_out_path).expect("failed to create corpus");
                let solutions = OnDiskCorpus::new(&crash_dir).expect("failed to create crash corpus");
                let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)
                    .expect("failed to create StdState");

                let scheduler = IndexesLenTimeMinimizerScheduler::new(
                    &edges_observer,
                    PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
                );

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
                    // Check if corpus-in and corpus-out are the same directory
                    let same_directory = std::path::Path::new(corpus_dir)
                        .canonicalize()
                        .ok()
                        .and_then(|cin| std::path::Path::new(corpus_out_path)
                            .canonicalize()
                            .ok()
                            .map(|cout| cin == cout))
                        .unwrap_or(false);

                    if same_directory {
                        // When corpus-in == corpus-out, check if corpus is healthy (has actual input files)
                        // Count non-hidden files (actual inputs vs metadata)
                        let input_count = std::fs::read_dir(corpus_dir)
                            .map(|entries| entries
                                .filter_map(|e| e.ok())
                                .filter(|e| {
                                    let path = e.path();
                                    path.is_file() && is_corpus_input(&path)
                                })
                                .count())
                            .unwrap_or(0);

                        if input_count > 0 {
                            // Healthy corpus - load entries WITHOUT calling add_input
                            eprintln!("[FUZZ] Using existing corpus directory: {}", corpus_dir);
                            let corpus_dirs = vec![std::path::PathBuf::from(corpus_dir)];
                            state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                                .expect("failed to load initial corpus");
                            let corpus_count = state.corpus().count();
                            eprintln!("[FUZZ] Loaded {} existing corpus entries", corpus_count);
                            if corpus_count == 0 {
                                eprintln!("[FUZZ] Warning: No valid inputs in corpus, using default seed");
                                let input = BytesInput::new(vec![0u8; 256]);
                                fuzzer.add_input(&mut state, &mut executor, &mut mgr, input)
                                    .expect("failed to add seed input");
                            }
                        } else {
                            // Corrupted corpus - only metadata, no input files
                            // Clean metadata and start fresh
                            eprintln!("[FUZZ] Corpus directory has no input files, cleaning stale metadata...");
                            if let Ok(entries) = std::fs::read_dir(corpus_dir) {
                                for entry in entries.filter_map(|e| e.ok()) {
                                    let path = entry.path();
                                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                        if name.starts_with('.') {
                                            let _ = std::fs::remove_file(&path);
                                        }
                                    }
                                }
                            }
                            eprintln!("[FUZZ] Starting fresh with default seed");
                            let input = BytesInput::new(vec![0u8; 256]);
                            fuzzer.add_input(&mut state, &mut executor, &mut mgr, input)
                                .expect("failed to add seed input");
                        }
                    } else {
                        // Different directories - load from input dir and add to output corpus
                        #load_corpus_from_dir
                        if loaded == 0 {
                            eprintln!("[FUZZ] Warning: No valid inputs in corpus, using default seed");
                            #add_default_seed
                        }
                    }
                } else {
                    #add_default_seed
                }

                #mutator_stages_setup
                #exit_handlers_setup

                fuzzer
                    .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                    .expect("error in fuzz loop");

            } else {
                // === IN-MEMORY CORPUS MODE (default) ===

                // Use shared setup blocks
                #monitor_setup
                #observer_feedback_setup

                // InMemoryCorpus-specific: create corpus and state
                let rand = StdRand::with_seed(seed);
                let corpus: InMemoryCorpus<BytesInput> = InMemoryCorpus::new();
                let solutions = OnDiskCorpus::new(&crash_dir).expect("failed to create crash corpus");
                let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)
                    .expect("failed to create StdState");

                let scheduler = IndexesLenTimeMinimizerScheduler::new(
                    &edges_observer,
                    PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
                );

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

                // InMemoryCorpus: simple corpus loading (no same-dir handling needed)
                if let Some(ref corpus_dir) = corpus_in_dir {
                    #load_corpus_from_dir
                    if loaded == 0 {
                        eprintln!("[FUZZ] Warning: No valid inputs in corpus, using default seed");
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
            } // end of else (in-memory corpus mode)
        }

    };

    TokenStream::from(expanded)
}
