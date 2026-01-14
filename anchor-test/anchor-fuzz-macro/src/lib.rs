use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, ItemFn, FnArg, Token, Type,
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
    
    // Build parameter parsing - skip first param which is fixture
    let mut deser_stmts = Vec::new();
    let mut call_args = vec![quote! { &mut #fixture_param_name }];
    let mut show_params = Vec::new();
    
    // Parse each input (skip first - that's fixture)
    for (i, arg) in inputs.iter().enumerate().skip(1) {
        let FnArg::Typed(pat_ty) = arg else { 
            return syn::Error::new_spanned(arg, "Expected typed parameter")
                .to_compile_error().into();
        };
        
        let ty = &pat_ty.ty;
        let param_name = quote::format_ident!("param_{}", i);
        
        // Look up range constraint from saved HashMap
        let range_constraint = range_constraints.get(&i);
        
        // Deserialize the parameter
        deser_stmts.push(quote! {
            let mut #param_name: #ty = match <#ty as arbitrary::Arbitrary>::arbitrary(&mut u) {
                Ok(v) => v,
                Err(_) => return libafl::prelude::ExitKind::Ok,
            };
        });

        // Apply constraint if present
        if let Some(constraint) = range_constraint {
            let start = constraint.start;
            let range_size = if constraint.inclusive {
                constraint.end - constraint.start + 1
            } else {
                constraint.end - constraint.start
            };
            deser_stmts.push(quote! {
                #param_name = (#start as #ty) + (#param_name % (#range_size as #ty));
            });
        }
        
        call_args.push(quote! { #param_name });
        show_params.push((param_name.clone(), ty.clone(), range_constraint.cloned()));
    }
    
    let mod_name = quote::format_ident!("__anchor_fuzz_rt_{}", fn_name);
    let show_fn_name = quote::format_ident!("__show_{}", fn_name);
    
    // Generate show code
    let show_body = {
        let param_deserializations: Vec<_> = show_params.iter().map(|(name, ty, range_constraint)| {
            if let Some(constraint) = range_constraint {
                let start = constraint.start;
                let range_size = if constraint.inclusive {
                    constraint.end - constraint.start + 1
                } else {
                    constraint.end - constraint.start
                };
                quote! {
                    let mut #name: #ty = arbitrary::Arbitrary::arbitrary(&mut u)
                        .expect("Failed to deserialize parameter");
                    #name = (#start as #ty) + (#name % (#range_size as #ty));
                    println!("{}: {:#?}", stringify!(#name), #name);
                }
            } else {
                quote! {
                    let #name: #ty = arbitrary::Arbitrary::arbitrary(&mut u)
                        .expect("Failed to deserialize parameter");
                    println!("{}: {:#?}", stringify!(#name), #name);
                }
            }
        }).collect();
        
        quote! {
            println!("Crash Input:");
            #(#param_deserializations)*
        }
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

        // Extract program edge and instruction totals for coverage percentage display
        // Convert Pubkey keys to program hashes (u64) matching the coverage tracking
        {
            let mut edge_totals: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
            let mut instr_totals: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
            let mut program_binaries: std::collections::HashMap<u64, Vec<u8>> = std::collections::HashMap::new();

            for (pubkey, (total_edges, total_instructions)) in template_fixture.ctx.get_program_coverage_totals() {
                let program_hash = u64::from_le_bytes(
                    pubkey.to_bytes()[0..8].try_into().unwrap()
                );
                edge_totals.insert(program_hash, *total_edges);
                instr_totals.insert(program_hash, *total_instructions);
            }

            // Also store program binaries for per-instruction CFG analysis
            for (pubkey, binary) in template_fixture.ctx.get_program_binaries() {
                let program_hash = u64::from_le_bytes(
                    pubkey.to_bytes()[0..8].try_into().unwrap()
                );
                program_binaries.insert(program_hash, binary);
            }

            #mod_name::init_program_totals(edge_totals, instr_totals);
            #mod_name::init_program_binaries(program_binaries.clone());

            // Build cached analysis for fast HTML generation (parse binaries once)
            let mut cached_analysis: std::collections::HashMap<u64, anchor_test_context::CachedProgramAnalysis> = std::collections::HashMap::new();
            for (prog_hash, binary) in &program_binaries {
                let program_name = format!("program_{:016x}", prog_hash);
                if let Some(analysis) = anchor_test_context::build_cached_analysis(&program_name, binary) {
                    cached_analysis.insert(*prog_hash, analysis);
                }
            }
            #mod_name::init_cached_analysis(cached_analysis);
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
                pub edges: HashMap<u64, HashSet<u64>>,           // unique (pc<<32|target) edges
                pub branch_pcs: HashMap<u64, HashSet<usize>>,    // unique branch PCs per program
                pub instruction_pcs: HashMap<u64, HashSet<usize>>, // ALL executed instruction PCs
                pub pc_hit_counts: HashMap<u64, HashMap<usize, u64>>, // program -> (pc -> hit count)
                pub branch_outcomes: HashMap<u64, HashMap<(usize, bool), u64>>, // program -> ((branch_pc, taken) -> count)
                pub last_write_iteration: u64,   // Iteration-based throttling (not time-based)
                pub last_coverage_count: usize,  // For smart batching
                // Cached totals for SimpleMonitor (avoid iterating all data)
                pub total_edges: usize,
                pub total_branches: usize,
                pub total_instructions: usize,
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

                fn process_trace(
                    &self,
                    program_id: &anchor_test_context::fuzz_types::Pubkey,
                    executable: &anchor_test_context::fuzz_types::Executable,
                    register_trace: &[[u64; 12]],
                    discriminator: Option<[u8; 8]>,
                ) {
                    use anchor_test_context::fuzz_types::ebpf;

                    if register_trace.is_empty() {
                        return;
                    }

                    let (_vm_addr, program) = executable.get_text_bytes();
                    // Include program ID to distinguish same-PC edges across programs
                    let program_hash = u64::from_le_bytes(
                        program_id.to_bytes()[0..8].try_into().unwrap()
                    );

                    // Check if detailed coverage tracking is enabled (only with --coverage flag)
                    let detailed_tracking = COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed);

                    // Collect data locally only if detailed tracking is enabled
                    let mut local_instruction_pcs: HashSet<usize> = HashSet::new();
                    let mut local_branch_pcs: HashSet<usize> = HashSet::new();
                    let mut local_edges: HashSet<u64> = HashSet::new();

                    // AFL-style edge tracking with prev_location state
                    let mut prev_location: usize = 0;

                    // Track all executed instruction PCs and conditional branches
                    for i in 0..register_trace.len().saturating_sub(1) {
                        let pc = register_trace[i][11] as usize;

                        // Collect instruction PCs locally (only if detailed tracking)
                        if detailed_tracking {
                            local_instruction_pcs.insert(pc);
                        }

                        let insn = ebpf::get_insn_unchecked(program, pc);

                        // Track: conditional jumps only for edge/branch coverage
                        let is_jmp_class = insn.opc & 7 == ebpf::BPF_JMP;
                        if !is_jmp_class {
                            continue;
                        }

                        // Exclude non-conditional: CALL (0x85), EXIT (0x95), JA (0x05), CALLX (0x8d)
                        let opc = insn.opc;
                        if opc == 0x05 || opc == 0x85 || opc == 0x8d || opc == 0x95 {
                            continue;
                        }

                        // The actual target - where did we go?
                        let target_pc = register_trace[i + 1][11] as usize;

                        // AFL-style edge hashing (from QEMU mode)
                        let cur_location = ((target_pc >> 4) ^ (target_pc << 8)) ^ (program_hash as usize);
                        let edge = (cur_location ^ prev_location) % MAP_SIZE;
                        prev_location = cur_location >> 1;

                        unsafe {
                            // Write to coverage map (must be done inline for AFL compatibility)
                            let buf = std::slice::from_raw_parts_mut(self.ptr, self.len);
                            buf[edge] = buf[edge].wrapping_add(1);
                        }

                        // Always collect edges and branches (for SimpleMonitor display)
                        let unique_edge = ((pc as u64) << 32) | (target_pc as u64);
                        local_edges.insert(unique_edge);
                        local_branch_pcs.insert(pc);
                    }

                    // Always update edges/branches in state (for SimpleMonitor)
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

                    // Skip LCOV tracking if --coverage not enabled
                    if !detailed_tracking {
                        return;
                    }

                    // Track instruction PCs and update cached total (LCOV only)
                    let instr_set = state.instruction_pcs.entry(program_hash).or_default();
                    let old_instr_count = instr_set.len();
                    instr_set.extend(&local_instruction_pcs);
                    state.total_instructions += instr_set.len() - old_instr_count;

                    // LCOV: Track PC hit counts (increment for each occurrence)
                    let program_counts = state.pc_hit_counts.entry(program_hash).or_default();
                    for pc in &local_instruction_pcs {
                        *program_counts.entry(*pc).or_insert(0) += 1;
                    }

                    // LCOV: Track branch outcomes (taken vs not-taken separately)
                    let program_outcomes = state.branch_outcomes.entry(program_hash).or_default();
                    for &edge in &local_edges {
                        let pc = (edge >> 32) as usize;
                        let target_pc = (edge & 0xFFFFFFFF) as usize;
                        // taken = jump target is not the fall-through (pc + 8)
                        let taken = target_pc != pc + 8;
                        *program_outcomes.entry((pc, taken)).or_insert(0) += 1;
                    }
                }
            }

            impl anchor_test_context::InvocationInspectCallback for FuzzCallback {
                fn before_invocation(
                    &self,
                    _tx: &anchor_test_context::fuzz_types::SanitizedTransaction,
                    _program_indices: &[anchor_test_context::fuzz_types::IndexOfAccount],
                    invoke_context: &anchor_test_context::fuzz_types::InvokeContext,
                ) {
                    // Only pop instruction name for top-level instructions, not CPI calls.
                    // Stack height 0 = about to execute top-level instruction
                    // Stack height > 0 = CPI (keep current instruction name)
                    let stack_height = invoke_context.get_stack_height();

                    if stack_height == 0 {
                        // Pop the next instruction name from the batch queue
                        if let Some(name) = anchor_test_context::pop_pending_batch_name() {
                            anchor_test_context::set_current_instruction(Some(name));
                        }
                    }
                }

                fn after_invocation(
                    &self,
                    invoke_context: &anchor_test_context::fuzz_types::InvokeContext,
                    register_tracing_enabled: bool,
                ) {
                    if register_tracing_enabled {
                        invoke_context.iterate_vm_traces(
                            &|instruction_context,
                              executable,
                              register_trace| {
                                if let Ok(program_id) = instruction_context.get_program_key() {
                                    // Extract discriminator from instruction data (first 8 bytes)
                                    let instr_data = instruction_context.get_instruction_data();
                                    let discriminator: Option<[u8; 8]> = if instr_data.len() >= 8 {
                                        instr_data[0..8].try_into().ok()
                                    } else {
                                        None
                                    };

                                    self.process_trace(program_id, executable, register_trace, discriminator);
                                }
                            },
                        );
                    }
                }
            }

            /// Write LCOV coverage file to disk
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
                let pc_hits = state.pc_hit_counts.clone();
                let branch_outcomes = state.branch_outcomes.clone();
                drop(state); // Release lock before file I/O

                if pc_hits.is_empty() {
                    eprintln!("[LCOV] No coverage data to write");
                    return;
                }

                let program_binaries = PROGRAM_BINARIES.get();
                let edge_totals = PROGRAM_TOTALS.get();
                let instr_totals = PROGRAM_TOTAL_INSTRUCTIONS.get();

                let mut programs_written = 0usize;
                for (prog_hash, hits) in &pc_hits {
                    let program_name = format!("program_{:016x}", prog_hash);
                    let functions = program_binaries
                        .and_then(|b| b.get(prog_hash))
                        .and_then(|data| anchor_test_context::extract_functions(data))
                        .unwrap_or_default();

                    let total_instr = instr_totals.and_then(|t| t.get(prog_hash).copied()).unwrap_or(0);
                    let total_edges = edge_totals.and_then(|t| t.get(prog_hash).copied()).unwrap_or(0);
                    let total_branches = total_edges / 2;

                    let outcomes = branch_outcomes.get(prog_hash).cloned().unwrap_or_default();

                    if let Err(e) = anchor_test_context::generate_bytecode_lcov(
                        &mut writer,
                        &program_name,
                        &hits,
                        &outcomes,
                        &functions,
                        total_instr,
                        total_branches,
                    ) {
                        eprintln!("[LCOV] Error writing coverage for {}: {}", program_name, e);
                    } else {
                        programs_written += 1;
                    }
                }

                // Explicitly flush to ensure data is written before process exit
                if let Err(e) = writer.flush() {
                    eprintln!("[LCOV] Error flushing buffer: {}", e);
                }

                eprintln!("[LCOV] Coverage written to {} ({} programs, {} PCs)",
                    output_path, programs_written, pc_hits.values().map(|h| h.len()).sum::<usize>());
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
                let current_coverage_count = state.total_instructions;
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

            /// Write HTML coverage visualization
            pub fn write_html_coverage(output_path: &str) {
                use std::io::Write;

                let file = match std::fs::File::create(output_path) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("[HTML] Failed to create {}: {}", output_path, e);
                        return;
                    }
                };
                let mut writer = std::io::BufWriter::new(file);

                // Get coverage data from state
                let state = COVERAGE_STATE.lock().unwrap();
                let pc_hits = state.pc_hit_counts.clone();
                // Get per-program stats from state
                let edges_map = state.edges.clone();
                let branches_map = state.branch_pcs.clone();
                let instructions_map = state.instruction_pcs.clone();
                drop(state); // Release lock before file I/O

                // Get program binaries
                let Some(binaries) = PROGRAM_BINARIES.get() else {
                    eprintln!("[HTML] No program binaries available");
                    return;
                };

                // Get totals for stats
                let edge_totals = PROGRAM_TOTALS.get();
                let instr_totals = PROGRAM_TOTAL_INSTRUCTIONS.get();

                // Generate HTML for each program
                for (prog_hash, binary) in binaries {
                    // Convert hits for this program
                    let hits: HashMap<usize, u64> = pc_hits.get(prog_hash)
                        .map(|h| h.iter().map(|(&k, &v)| (k, v)).collect())
                        .unwrap_or_default();

                    // Build stats from coverage data
                    let edges_hit = edges_map.get(prog_hash).map(|s| s.len()).unwrap_or(0);
                    let branches_hit = branches_map.get(prog_hash).map(|s| s.len()).unwrap_or(0);
                    let instructions_hit = instructions_map.get(prog_hash).map(|s| s.len()).unwrap_or(0);

                    let edges_total = edge_totals.and_then(|t| t.get(prog_hash).copied()).unwrap_or(0);
                    let branches_total = edges_total / 2;
                    let instructions_total = instr_totals.and_then(|t| t.get(prog_hash).copied()).unwrap_or(0);

                    // Calculate runtime stats
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let start_time = FUZZER_START_TIME.get().copied().unwrap_or(now_secs);
                    let run_time_secs = now_secs.saturating_sub(start_time);
                    let executions = TOTAL_EXECUTIONS.load(std::sync::atomic::Ordering::Relaxed);

                    let stats = anchor_test_context::CoverageWriteStats {
                        run_time_secs,
                        executions,
                        edges_hit,
                        edges_total,
                        branches_hit,
                        branches_total,
                        instructions_hit,
                        instructions_total,
                    };

                    // Use cached analysis if available (fast path), otherwise full analysis
                    let result = if let Some(cached_map) = CACHED_ANALYSIS.get() {
                        if let Some(cached) = cached_map.get(prog_hash) {
                            // Fast path: use pre-computed CFG and function data
                            anchor_test_context::generate_coverage_html_cached(
                                &mut writer,
                                cached,
                                &hits,
                                Some(&stats),
                            )
                        } else {
                            // Fallback: full analysis (shouldn't happen normally)
                            let program_name = format!("program_{:016x}", prog_hash);
                            anchor_test_context::generate_coverage_html(
                                &mut writer,
                                &program_name,
                                binary,
                                &hits,
                                Some(&stats),
                            )
                        }
                    } else {
                        // Fallback: no cache available
                        let program_name = format!("program_{:016x}", prog_hash);
                        anchor_test_context::generate_coverage_html(
                            &mut writer,
                            &program_name,
                            binary,
                            &hits,
                            Some(&stats),
                        )
                    };

                    if let Err(e) = result {
                        eprintln!("[HTML] Error generating HTML: {}", e);
                    }
                }

                if let Err(e) = writer.flush() {
                    eprintln!("[HTML] Error flushing: {}", e);
                } else {
                    eprintln!("[HTML] Coverage written to {}", output_path);
                }
            }
        }

        #[cfg(feature = #feature_name)]
        pub fn #show_fn_name() {
            use arbitrary::Unstructured;
            use std::io::Read;
            
            let mut bytes = Vec::new();
            std::io::stdin().read_to_end(&mut bytes)
                .expect("Failed to read crash input from stdin");
            
            let mut u = Unstructured::new(&bytes);
            
            #show_body
        }

        #[cfg(feature = #feature_name)]
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
            use libafl_bolts::{current_nanos, rands::StdRand, AsSlice};
            use std::time::Duration;
            use arbitrary::Unstructured;

            // Coverage map - just a simple vec, no shared memory needed for InProcessExecutor
            let mut coverage_map = vec![0u8; #mod_name::MAP_SIZE];
            let cov_ptr = coverage_map.as_mut_ptr();

            // Custom monitor that appends true coverage stats
            let monitor = SimpleMonitor::new(|s| {
                // Replace "objectives" with "crashes" for clarity
                let s = s.replace("objectives", "crashes");

                // Get cached coverage stats (no iteration over maps)
                let state = #mod_name::COVERAGE_STATE.lock().unwrap();
                let true_edges = state.total_edges;
                let branches = state.total_branches;
                drop(state);

                let total_edges: usize = #mod_name::PROGRAM_TOTALS.get()
                    .map(|t| t.values().sum())
                    .unwrap_or(0);
                let total_branches = total_edges / 2;

                // Replace "edges: X/65536 (Y%)" with our format
                // LibAFL format: "[Type #N] ..., edges: X/65536 (Y%)"
                if let Some(idx) = s.find("edges:") {
                    let prefix = &s[..idx];
                    // Extract AFL edges count from the string
                    let edges_part = &s[idx..];
                    let afl_edges: usize = edges_part
                        .split_whitespace()
                        .nth(1)
                        .and_then(|p| p.split('/').next())
                        .and_then(|n| n.parse().ok())
                        .unwrap_or(0);
                    let afl_pct = (afl_edges as f64 / 65536.0) * 100.0;
                    let edge_pct = if total_edges > 0 { (true_edges as f64 / total_edges as f64) * 100.0 } else { 0.0 };
                    let branch_pct = if total_branches > 0 { (branches as f64 / total_branches as f64) * 100.0 } else { 0.0 };

                    println!("{}afl_edges: {}/65536 ({:.1}%), edges: {}/{} ({:.1}%), branches: {}/{} ({:.1}%)",
                        prefix, afl_edges, afl_pct, true_edges, total_edges, edge_pct, branches, total_branches, branch_pct);
                } else {
                    println!("{s}");
                }
            });
            let mut mgr = SimpleEventManager::new(monitor);

            // === OBSERVERS ===
            let std_map = unsafe { StdMapObserver::from_mut_ptr("edges", cov_ptr, #mod_name::MAP_SIZE) };
            let edges_observer = HitcountsMapObserver::new(std_map).track_indices();
            let time_observer = TimeObserver::new("time");

            // === FEEDBACK ===
            // Combine map coverage feedback with time feedback
            let map_feedback = MaxMapFeedback::new(&edges_observer);
            let time_feedback = TimeFeedback::new(&time_observer);
            let mut feedback = feedback_or!(map_feedback, time_feedback);
            let mut objective = CrashFeedback::new();

            // === CORPUS ===
            let seed = current_nanos().max(1);
            let rand = StdRand::with_seed(seed);
            let corpus = InMemoryCorpus::<BytesInput>::new();
            let crash_dir = format!("crashes/{}", #feature_name);
            std::fs::create_dir_all(&crash_dir).expect("failed to create crash directory");

            let solutions = OnDiskCorpus::new(&crash_dir).expect("failed to create crash corpus");
            let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)
                .expect("failed to create StdState");

            // === SCHEDULER ===
            // PowerQueueScheduler prioritizes inputs based on execution time and coverage
            let scheduler = IndexesLenTimeMinimizerScheduler::new(
                &edges_observer,
                PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
            );

            #template_setup

            // Initialize fuzzer start time for stats tracking
            let _ = #mod_name::FUZZER_START_TIME.set(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            );

            let mut harness_wrapper = |input: &BytesInput| -> ExitKind {
                let bytes_ref = input.target_bytes();
                let slice = bytes_ref.as_slice();
                let mut u = Unstructured::new(slice);

                #(#deser_stmts)*

                #iteration_setup

                // Run the test
                #fn_name(#(#call_args),*);

                // Coverage tracking (only when --coverage flag passed)
                if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                    // Increment execution counter and get current count for iteration-based throttling
                    let exec_count = #mod_name::TOTAL_EXECUTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // Write coverage files every 5000 iterations when new coverage found (no syscall)
                    #mod_name::maybe_write_coverage(exec_count);
                }

                // Check if an invariant was violated (via fuzz_assert! macros)
                if let Some(msg) = anchor_test_context::take_violation() {
                    eprintln!("[VIOLATION] {}", msg);
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

            // Add initial seed input
            let input = BytesInput::new(vec![0u8; 256]);
            fuzzer
                .add_input(&mut state, &mut executor, &mut mgr, input)
                .expect("failed to add seed input");

            // === STAGES ===
            // Standard mutational stage with MOPT mutations
            let mutator = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5)
                .expect("failed to create mutator");
            let power_stage = StdPowerMutationalStage::new(mutator);
            let mut stages = tuple_list!(power_stage);

            // === EXIT HANDLERS ===
            // Write coverage on panic (runs on main thread, can access thread-locals)
            let default_panic = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                    #mod_name::write_lcov_coverage("coverage.lcov");
                    #mod_name::write_html_coverage("coverage.html");
                }
                default_panic(info);
            }));

            // Note: ctrlc handler runs on a different thread and CANNOT access
            // thread-local coverage data. We rely on periodic writes from maybe_write_coverage()
            // which runs on the main thread every 5 seconds. The last periodic write
            // will have the most recent coverage data.
            ctrlc::set_handler(move || {
                if coverage_enabled {
                    eprintln!("\n[COVERAGE] Ctrl+C received. Coverage files written by periodic updates (every 5s).");
                    eprintln!("[COVERAGE] Check coverage.lcov and coverage.html for the latest coverage snapshot.");
                }
                std::process::exit(0);
            }).ok();

            fuzzer
                .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                .expect("error in fuzz loop");
        }
    };
    
    TokenStream::from(expanded)
}
