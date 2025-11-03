use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, ItemFn, FnArg,
    parse::Parse, parse::ParseStream, Token, Ident, Expr, Lit
};

struct AnchorFuzzArgs {
    setup: Expr,
    runs: Option<usize>,
}

impl Parse for AnchorFuzzArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut setup = None;
        let mut runs = None;
        
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            
            match key.to_string().as_str() {
                "setup" => {
                    setup = Some(input.parse()?);
                }
                "runs" => {
                    let lit: Lit = input.parse()?;
                    if let Lit::Int(int_lit) = lit {
                        runs = Some(int_lit.base10_parse()?);
                    }
                }
                _ => return Err(syn::Error::new(key.span(), "Unknown parameter. Expected 'setup' or 'runs'")),
            }
            
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }
        
        let setup = setup.ok_or_else(|| 
            syn::Error::new(input.span(), "Missing required parameter: setup")
        )?;
        
        Ok(AnchorFuzzArgs { setup, runs })
    }
}

#[proc_macro_attribute]
pub fn anchor_fuzz(args: TokenStream, item: TokenStream) -> TokenStream {

    let args = parse_macro_input!(args as AnchorFuzzArgs);
    let input_fn = parse_macro_input!(item as ItemFn);
    
    let fn_name = &input_fn.sig.ident;
    let inputs: Vec<_> = input_fn.sig.inputs.iter().collect();
    
    if inputs.is_empty() {
        return syn::Error::new_spanned(
            &input_fn.sig,
            "Function must have at least one parameter (fixture)"
        ).to_compile_error().into();
    }
    
    let setup_expr = &args.setup;
    let runs = args.runs.unwrap_or(256);
    
    // Build parameter parsing (skip first param which is fixture)
    let mut deser_stmts = Vec::new();
    let mut call_args = vec![quote! { &mut fixture }];
    
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
    
    let expanded = quote! {
        #input_fn
        
        fn main() {
            use std::sync::Arc;
            use std::sync::atomic::{AtomicUsize, Ordering};
            use arbitrary::Unstructured;
            use libafl::prelude::ExitKind;
            
            let max_runs = #runs;
            let run_count = Arc::new(AtomicUsize::new(0));
            let run_count_clone = run_count.clone();
            
            anchor_fuzz_harness::run_harness(move |data: &[u8]| -> ExitKind {
                // Check iteration limit
                if run_count_clone.fetch_add(1, Ordering::SeqCst) >= max_runs {
                    std::process::exit(0);
                }
                
                let mut u = Unstructured::new(data);
                
                // Parse all parameters
                #(#deser_stmts)*
                
                // Setup fixture
                let mut fixture = #setup_expr();
                
                // Call user function
                #fn_name(#(#call_args),*);
                
                ExitKind::Ok
            });
        }
    }; 
    TokenStream::from(expanded)
}
