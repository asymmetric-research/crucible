use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, ItemFn, FnArg, Type,
};
use crucible_macro_utils::RangeConstraint;

mod codegen;
mod corpus;
mod coverage;
mod modes;
mod multicore;
mod singlecore;

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

    // Generate coverage-related code from coverage module
    let coverage_code = coverage::all_coverage_code();

    // Generate the is_corpus_input helper function
    let is_corpus_input_fn = codegen::is_corpus_input_fn();

    // Generate the load_inputs_from_dir helper function
    let load_inputs_fn = corpus::load_inputs_into_memory();

    // Generate mode-specific code
    let dry_run_code = modes::dry_run_mode(
        &mod_name,
        fixture_name,
        fn_name,
        &simple_deser_stmts,
        &call_args,
    );

    let replay_code = modes::replay_mode(
        &mod_name,
        fixture_name,
        fn_name,
        &simple_deser_stmts,
        &call_args,
    );

    let coverage_only_code = modes::coverage_only_mode(
        &mod_name,
        fixture_name,
        fn_name,
        &simple_deser_stmts,
        &call_args,
    );

    let cmin_code = corpus::cmin_mode(
        &mod_name,
        fixture_name,
        fn_name,
        &simple_deser_stmts,
        &call_args,
    );

    let multicore_code = multicore::multicore_mode(
        &mod_name,
        fixture_name,
        fn_name,
        fixture_param_name,
        &feature_name,
        &deser_stmts,
        &call_args,
    );

    let singlecore_code = singlecore::singlecore_mode(
        &mod_name,
        fixture_name,
        fn_name,
        fixture_param_name,
        &feature_name,
        &deser_stmts,
        &call_args,
    );

    let expanded = quote! {
        #input_fn

        #[cfg(feature = #feature_name)]
        mod #mod_name {
            use super::*;
            use std::collections::{HashMap, HashSet};
            use std::sync::{Mutex, LazyLock};

            #coverage_code
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
            use libafl::schedulers::QueueScheduler;
            use libafl::schedulers::powersched::{PowerQueueScheduler, PowerSchedule};
            use libafl::corpus::CachedOnDiskCorpus;
            use libafl_bolts::tuples::tuple_list;
            use libafl_bolts::{current_nanos, rands::StdRand, AsSlice, hash_std};
            use std::time::Duration;
            use arbitrary::Unstructured;

            // Parse environment variables for new modes
            let dry_run_mode = std::env::var("FUZZ_DRY_RUN").is_ok();
            let input_file = std::env::var("FUZZ_INPUT_FILE").ok();
            let coverage_only_mode = std::env::var("FUZZ_COVERAGE_ONLY").is_ok();
            let cmin_mode = std::env::var("FUZZ_CMIN").is_ok();
            let corpus_in_dir = std::env::var("FUZZ_CORPUS_IN").ok();
            let corpus_out_dir = std::env::var("FUZZ_CORPUS_OUT").ok();
            let crashes_dir_env = std::env::var("FUZZ_CRASHES_DIR").ok();
            let verbose = std::env::var("FUZZ_VERBOSE").is_ok();

            // Coverage map - just a simple vec, no shared memory needed for InProcessExecutor
            let mut coverage_map = vec![0u8; #mod_name::MAP_SIZE];
            let cov_ptr = coverage_map.as_mut_ptr();

            #is_corpus_input_fn
            #load_inputs_fn

            #dry_run_code
            #replay_code
            #coverage_only_code
            #cmin_code
            #multicore_code
            #singlecore_code
        }

    };

    TokenStream::from(expanded)
}
