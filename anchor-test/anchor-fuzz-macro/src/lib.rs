use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, ItemFn, FnArg,
};

// No macro args are supported anymore

#[proc_macro_attribute]
pub fn anchor_fuzz(args: TokenStream, item: TokenStream) -> TokenStream {
    // Disallow arguments
    if !proc_macro2::TokenStream::from(args.clone()).is_empty() {
        return syn::Error::new_spanned(
            proc_macro2::TokenStream::from(args),
            "anchor_fuzz takes no arguments"
        ).to_compile_error().into();
    }
    let input_fn = parse_macro_input!(item as ItemFn);
    
    let fn_name = &input_fn.sig.ident;
    let feature_name = fn_name.to_string();  // Use function name as feature
    let inputs: Vec<_> = input_fn.sig.inputs.iter().collect();
    
    if inputs.is_empty() {
        return syn::Error::new_spanned(
            &input_fn.sig,
            "Function must have at least one parameter (context)"
        ).to_compile_error().into();
    }
    
    // Build parameter parsing (skip first param which is context)
    let mut deser_stmts = Vec::new();
    let mut call_args = vec![quote! { &mut ctx }];
    
    for (i, arg) in inputs.iter().enumerate().skip(1) {
        let FnArg::Typed(pat_ty) = arg else { 
            return syn::Error::new_spanned(arg, "Expected typed parameter")
                .to_compile_error().into();
        };
        
        let ty = &pat_ty.ty;
        let param_name = quote::format_ident!("param_{}", i);
        
        deser_stmts.push(quote! {
            let #param_name: #ty = match <#ty as arbitrary::Arbitrary>::arbitrary(&mut u) {
                Ok(v) => v,
                Err(_) => return libafl::prelude::ExitKind::Ok,
            };
        });
        
        call_args.push(quote! { #param_name });
    }
    
    let mod_name = quote::format_ident!("__anchor_fuzz_rt_{}", fn_name);
    let expanded = quote! {
        #input_fn

        #[cfg(feature = #feature_name)]  
        mod #mod_name {
            use super::*;
            pub const MAP_SIZE: usize = 1 << 16;

            pub struct DefaultTraceCollector {
                ptr: *mut u8,
                len: usize,
            }

            impl DefaultTraceCollector {
                pub fn from_raw(ptr: *mut u8, len: usize) -> Self { Self { ptr, len } }

                pub fn reset(&mut self) {
                    unsafe { std::ptr::write_bytes(self.ptr, 0, self.len); }
                }

                fn hash_edge(prev: usize, cur: usize) -> usize {
                    const MULTIPLIER: usize = 16777619;
                    ((prev.wrapping_mul(MULTIPLIER)) ^ cur) % MAP_SIZE
                }
            }

            impl anchor_test_context::TraceCollector for DefaultTraceCollector {
                fn trace(&mut self, _m: &solana_message::SanitizedMessage, traces: &[Vec<[u64; 12]>]) {
                    if !traces.is_empty() {
                        let mut prev_pc = 0usize;
                        for entry in traces[0].iter() {
                            let next_pc = entry[11] as usize;
                            let edge_hash = Self::hash_edge(prev_pc, next_pc);
                            unsafe {
                                let buf = std::slice::from_raw_parts_mut(self.ptr, self.len);
                                buf[edge_hash] = buf[edge_hash].saturating_add(1);
                            }
                            prev_pc = next_pc;
                        }
                    }
                }
            }
        }

        #[cfg(feature = #feature_name)]  
        fn main() {
            use std::cell::RefCell;
            use std::process;
            use core::iter::Once;
            use std::rc::Rc;

            use libafl::prelude::*;
            use libafl::monitors::tui::TuiMonitor;
            use libafl_bolts::tuples::tuple_list;
            use libafl_bolts::{current_nanos, rands::StdRand, AsSlice, AsSliceMut};
            use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};
            use std::time::Duration;
            use arbitrary::Unstructured;
            
            let mut shmem_provider = StdShMemProvider::new().expect("failed to create ShMemProvider");
            let mut shmem = shmem_provider
                .new_shmem(#mod_name::MAP_SIZE)
                .expect("failed to allocate shared memory for coverage map");

            let monitor = TuiMonitor::builder().build();
            let mut mgr = SimpleEventManager::new(monitor);

            let scheduler = QueueScheduler::new();

            let cov_ptr = unsafe { shmem.as_slice_mut().as_mut_ptr() };
            let std_map = unsafe { StdMapObserver::from_mut_ptr("edges", cov_ptr, #mod_name::MAP_SIZE) };
            let pc_observer = HitcountsMapObserver::new(std_map);

            let mut feedback = MaxMapFeedback::new(&pc_observer);
            let mut objective = CrashFeedback::new();

            let seed = current_nanos().max(1);
            let rand = StdRand::with_seed(seed);
            let corpus = InMemoryCorpus::<BytesInput>::new();
            let solutions = OnDiskCorpus::new("crashes").expect("failed to create crash dir");
            let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)
                .expect("failed to create StdState");

            let mut harness_wrapper = |input: &BytesInput| -> ExitKind {
                std::panic::set_hook(Box::new(|_| {
                    process::abort();
                }));
                let mut collector = #mod_name::DefaultTraceCollector::from_raw(cov_ptr, #mod_name::MAP_SIZE);
                collector.reset();

                // Wrap in catch_unwind to convert panics to crashes
                let bytes_ref = input.target_bytes();
                let slice = bytes_ref.as_slice();
                let mut u = Unstructured::new(slice);

                #(#deser_stmts)*

                let mut ctx = anchor_test_context::TestContext::with_trace_collector(Rc::new(RefCell::new(collector)));

            
                #fn_name(#(#call_args),*);
                ExitKind::Ok
            };

            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
            let timeout = Duration::from_millis(10000);
            let mut executor = InProcessForkExecutor::new(
                &mut harness_wrapper,
                tuple_list!(pc_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
                timeout,
                shmem_provider,
            )
            .expect("failed to create InProcessForkExecutor");

            // Initialize corpus with a single zeroed buffer
            let input = BytesInput::new(vec![0u8; 256]);
            fuzzer
                .add_input(&mut state, &mut executor, &mut mgr, input)
                .expect("failed to add seed input");

            let mutator = StdScheduledMutator::new(havoc_mutations());
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            fuzzer
                .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                .expect("error in fuzz loop");
        }
    };
    TokenStream::from(expanded)
}
