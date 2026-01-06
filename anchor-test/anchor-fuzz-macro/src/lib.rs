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
            pub const MAP_SIZE: usize = 1 << 16;

            pub struct FuzzCallback {
                ptr: *mut u8,
                len: usize,
            }

            unsafe impl Send for FuzzCallback {}
            unsafe impl Sync for FuzzCallback {}

            impl FuzzCallback {
                pub fn from_raw(ptr: *mut u8, len: usize) -> Self { Self { ptr, len } }

                fn process_trace(
                    &self,
                    executable: &anchor_test_context::fuzz_types::Executable,
                    register_trace: &[[u64; 12]]
                ) {
                    use anchor_test_context::fuzz_types::ebpf;

                    if register_trace.is_empty() {
                        return;
                    }

                    let (_vm_addr, program) = executable.get_text_bytes();
                    let mut prev_location = 0usize;

                    // Filter for conditional branches and call instructions
                    for i in 0..register_trace.len().saturating_sub(1) {
                        let pc = register_trace[i][11] as usize;
                        let insn = ebpf::get_insn_unchecked(program, pc);

                        // Track: conditional jumps + call instructions (indirect calls are interesting)
                        let dominated = insn.opc & 7 == ebpf::BPF_JMP
                            || insn.opc == ebpf::CALL_IMM
                            || insn.opc == ebpf::CALL_REG;
                        if !dominated {
                            continue;
                        }

                        // The actual target - where did we go?
                        let target_pc = register_trace[i + 1][11] as usize;
                        
                        // Edge: branch_location → target_location
                        let from_hash = (pc >> 4) ^ (pc << 8);
                        let to_hash = (target_pc >> 4) ^ (target_pc << 8);
                        
                        unsafe {
                            let buf = std::slice::from_raw_parts_mut(self.ptr, self.len);
                            buf[(from_hash ^ to_hash) % MAP_SIZE] = 
                                buf[(from_hash ^ to_hash) % MAP_SIZE].wrapping_add(1);
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
                }

                fn after_invocation(
                    &self,
                    invoke_context: &anchor_test_context::fuzz_types::InvokeContext,
                    register_tracing_enabled: bool,
                ) {
                    if register_tracing_enabled {
                        invoke_context.iterate_vm_traces(
                            &|_instruction_context,
                              executable,
                              register_trace| {
                                self.process_trace(executable, register_trace);
                            },
                        );
                    }
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

            use std::process;
            use libafl::mutators::StdMOptMutator;
            use libafl::prelude::*;
            use libafl::monitors::SimpleMonitor;
            use libafl::schedulers::powersched::PowerSchedule;
            use libafl_bolts::tuples::tuple_list;
            use libafl_bolts::{current_nanos, rands::StdRand, AsSlice, AsSliceMut};
            use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};
            use std::time::Duration;
            use arbitrary::Unstructured;

            // Clean up stale Unix shmem server file on Mac (prevents "Connection refused" errors)
            #[cfg(target_os = "macos")]
            {
                let shmem_server_path = std::path::Path::new("./libafl_unix_shmem_server");
                if shmem_server_path.exists() {
                    let _ = std::fs::remove_file(shmem_server_path);
                }
            }

            let mut shmem_provider = StdShMemProvider::new().expect("failed to create ShMemProvider");
            let mut shmem = shmem_provider
                .new_shmem(#mod_name::MAP_SIZE)
                .expect("failed to allocate shared memory for coverage map");

            let monitor = SimpleMonitor::new(|s| println!("{s}"));
            let mut mgr = SimpleEventManager::new(monitor);

            // === OBSERVERS ===
            let cov_ptr = unsafe { shmem.as_slice_mut().as_mut_ptr() };
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
            let solutions = OnDiskCorpus::new(crash_dir).expect("failed to create crash dir");
            let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)
                .expect("failed to create StdState");

            // === SCHEDULER ===
            // PowerQueueScheduler prioritizes inputs based on execution time and coverage
            let scheduler = IndexesLenTimeMinimizerScheduler::new(
                &edges_observer,
                PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
            );

            #template_setup

            let mut harness_wrapper = |input: &BytesInput| -> ExitKind {
                //std::panic::set_hook(Box::new(|_| {
                //    process::abort();
                //}));

                let bytes_ref = input.target_bytes();
                let slice = bytes_ref.as_slice();
                let mut u = Unstructured::new(slice);

                #(#deser_stmts)*

                #iteration_setup

                #fn_name(#(#call_args),*);
                ExitKind::Ok
            };

            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
            let timeout = Duration::from_millis(10000);
            let mut executor = InProcessForkExecutor::new(
                &mut harness_wrapper,
                tuple_list!(edges_observer, time_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
                timeout,
                shmem_provider,
            )
            .expect("failed to create InProcessForkExecutor");

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

            fuzzer
                .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                .expect("error in fuzz loop");
        }
    };
    
    TokenStream::from(expanded)
}
