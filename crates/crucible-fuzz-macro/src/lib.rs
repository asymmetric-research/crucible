use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, ItemFn, FnArg, Type,
    parse::{Parse, ParseStream},
};
use crucible_macro_utils::RangeConstraint;

mod codegen;
mod corpus;
mod coverage;
mod modes;
mod multicore;
mod singlecore;
mod stateful;

/// Parsed arguments for `#[anchor_fuzz(...)]`
///
/// Supports:
/// - `#[anchor_fuzz]` — default: arbitrary mode, contexts = [ctx]
/// - `#[anchor_fuzz(structured)]` — structured mutation mode
/// - `#[anchor_fuzz(contexts = [ctx, ctx_b])]` — multiple TestContext fields
/// - `#[anchor_fuzz(structured, contexts = [ctx, ctx_b])]` — both
struct FuzzArgs {
    structured: bool,
    contexts: Vec<syn::Ident>,
}

impl Default for FuzzArgs {
    fn default() -> Self {
        FuzzArgs {
            structured: false,
            contexts: vec![quote::format_ident!("ctx")],
        }
    }
}

impl Parse for FuzzArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut structured = false;
        let mut contexts = None;

        while !input.is_empty() {
            let ident: syn::Ident = input.parse()?;
            if ident == "structured" {
                structured = true;
            } else if ident == "contexts" {
                input.parse::<syn::Token![=]>()?;
                let content;
                syn::bracketed!(content in input);
                let fields = content.parse_terminated(syn::Ident::parse, syn::Token![,])?;
                contexts = Some(fields.into_iter().collect());
            } else {
                return Err(syn::Error::new(
                    ident.span(),
                    "expected 'structured' or 'contexts = [...]'",
                ));
            }

            if !input.is_empty() {
                input.parse::<syn::Token![,]>()?;
            }
        }

        Ok(FuzzArgs {
            structured,
            contexts: contexts.unwrap_or_else(|| vec![quote::format_ident!("ctx")]),
        })
    }
}

/// Extract the inner type T from Vec<T>
fn extract_vec_inner_type(ty: &Type) -> Option<Type> {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            if seg.ident == "Vec" {
                if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                        return Some(inner.clone());
                    }
                }
            }
        }
    }
    None
}

#[proc_macro_attribute]
pub fn anchor_fuzz(args: TokenStream, item: TokenStream) -> TokenStream {
    // Parse attribute arguments: structured, contexts = [field1, field2, ...]
    let fuzz_args: FuzzArgs = if args.is_empty() {
        FuzzArgs::default()
    } else {
        parse_macro_input!(args as FuzzArgs)
    };
    let structured = fuzz_args.structured;
    let contexts = fuzz_args.contexts;

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
        constraint.generate_local_constraint(param_name, ty)
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

    // Extract action type for structured mode
    let action_type: Option<Type> = if structured {
        if params.len() != 1 {
            return syn::Error::new_spanned(
                &input_fn.sig,
                "#[anchor_fuzz(structured)] requires exactly 2 parameters: (fixture: &mut Fixture, actions: Vec<ActionType>)"
            ).to_compile_error().into();
        }
        let inner = extract_vec_inner_type(&params[0].ty);
        if inner.is_none() {
            return syn::Error::new_spanned(
                &input_fn.sig,
                "#[anchor_fuzz(structured)] second parameter must be Vec<ActionType>"
            ).to_compile_error().into();
        }
        inner
    } else {
        None
    };

    // Generate deserialization stmts and simple_deser_stmts based on mode
    let mut simple_deser_stmts: Vec<proc_macro2::TokenStream> = Vec::new();

    if structured {
        let action_ty = action_type.as_ref().unwrap();
        let param_name = &params[0].name;

        // Fuzz harness deser_stmts: decode from `slice` (available in harness closure)
        deser_stmts.push(quote! {
            let __fuzz_input = crucible_fuzzer::FuzzInput::<#action_ty>::from_bytes(slice);
            let mut #param_name = __fuzz_input.actions;
            if #param_name.is_empty() {
                return libafl::prelude::ExitKind::Ok;
            }
        });

        call_args.push(quote! { #param_name });

        // Simple deser_stmts for modes: decode from `__raw_bytes` (set by each mode)
        simple_deser_stmts.push(quote! {
            let __fuzz_input = crucible_fuzzer::FuzzInput::<#action_ty>::from_bytes(&__raw_bytes);
            let mut #param_name = __fuzz_input.actions;
        });
    } else {
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
        simple_deser_stmts = params.iter().map(|param| {
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
    }

    let mod_name = quote::format_ident!("__anchor_fuzz_rt_{}", fn_name);
    let show_fn_name = quote::format_ident!("__show_{}", fn_name);

    // Generate show code (deserialize + print each param)
    let show_body = if structured {
        let action_ty = action_type.as_ref().unwrap();
        quote! {
            println!("Crash Input (structured):");
            let (__fuzz_input, __parse_info) = crucible_fuzzer::FuzzInput::<#action_ty>::from_bytes_with_info(&bytes);
            if __parse_info.actual_count < __parse_info.expected_count {
                println!("[WARN] Deserialized {}/{} actions — harness may have changed since crash was recorded",
                    __parse_info.actual_count, __parse_info.expected_count);
            }
            println!("Actions ({} total):", __fuzz_input.actions.len());
            for (i, action) in __fuzz_input.actions.iter().enumerate() {
                println!("  {}: {:?}", i, action);
            }
        }
    } else {
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

    // Show function: conditionally use Unstructured or FuzzInput
    let show_fn_code = if structured {
        quote! {
            pub fn #show_fn_name() {
                use std::io::Read;

                let mut bytes = Vec::new();
                std::io::stdin().read_to_end(&mut bytes)
                    .expect("Failed to read crash input from stdin");

                #show_body
            }
        }
    } else {
        quote! {
            pub fn #show_fn_name() {
                use arbitrary::Unstructured;
                use std::io::Read;

                let mut bytes = Vec::new();
                std::io::stdin().read_to_end(&mut bytes)
                    .expect("Failed to read crash input from stdin");

                let mut u = Unstructured::new(&bytes);

                #show_body
            }
        }
    };

    // Generate coverage-related code from coverage module
    let coverage_code = coverage::all_coverage_code();

    // Generate the is_corpus_input helper function
    let is_corpus_input_fn = codegen::is_corpus_input_fn();

    // Generate the load_inputs_from_dir helper function
    let load_inputs_fn = corpus::load_inputs_into_memory();

    // Convert action_type to TokenStream for passing to codegen functions
    let action_type_tokens: Option<proc_macro2::TokenStream> = action_type.as_ref().map(|ty| quote! { #ty });

    // Generate mode-specific code
    let dry_run_code = modes::dry_run_mode(
        &mod_name,
        fixture_name,
        fn_name,
        &simple_deser_stmts,
        &call_args,
        structured,
    );

    let replay_code = modes::replay_mode(
        &mod_name,
        fixture_name,
        fn_name,
        &simple_deser_stmts,
        &call_args,
        structured,
        action_type_tokens.as_ref(),
    );

    let coverage_only_code = modes::coverage_only_mode(
        &mod_name,
        fixture_name,
        fn_name,
        &simple_deser_stmts,
        &call_args,
        structured,
    );

    let tmin_code = modes::tmin_mode(
        &mod_name,
        fixture_name,
        fn_name,
        structured,
        action_type_tokens.as_ref(),
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
        structured,
        action_type_tokens.as_ref(),
        &contexts,
    );

    let singlecore_code = singlecore::singlecore_mode(
        &mod_name,
        fixture_name,
        fn_name,
        fixture_param_name,
        &feature_name,
        &deser_stmts,
        &call_args,
        structured,
        action_type_tokens.as_ref(),
        &contexts,
    );

    let stateful_code = stateful::stateful_mode(
        &mod_name,
        fixture_name,
        fn_name,
        fixture_param_name,
        &feature_name,
        structured,
        action_type_tokens.as_ref(),
        &contexts,
    );

    // Conditionally include Unstructured import
    let unstructured_import = if structured {
        quote! {}
    } else {
        quote! { use arbitrary::Unstructured; }
    };

    let expanded = quote! {
        #input_fn

        #[cfg(feature = #feature_name)]
        #[global_allocator]
        static __CRUCIBLE_ALLOC: crucible_fuzzer::MiMalloc = crucible_fuzzer::MiMalloc;

        #[cfg(feature = #feature_name)]
        mod #mod_name {
            use super::*;
            use std::collections::{HashMap, HashSet};
            use std::sync::{Mutex, LazyLock};

            #coverage_code
        }

        #[cfg(feature = #feature_name)]
        #show_fn_code

        #[cfg(feature = #feature_name)]
        fn main() {
            if std::env::var("SHOW_CRASH").is_ok() {
                #show_fn_name();
                return;
            }

            // Parse --coverage flag (CLI arg or env var)
            let coverage_enabled = std::env::args().any(|a| a == "--coverage")
                || std::env::var("FUZZ_COVERAGE").is_ok();
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
            #unstructured_import

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
            #tmin_code
            #stateful_code
            #multicore_code
            #singlecore_code
        }

    };

    TokenStream::from(expanded)
}
