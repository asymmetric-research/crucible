// anchor-fuzz-macro/src/lib.rs

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, ItemFn, parse::Parse, parse::ParseStream, 
    Token, Ident, Lit, Expr, ExprRange, FnArg, PatType
};

struct AnchorFuzzArgs {
    setup_type: Ident,
    runs: Option<u32>,
    seed: Option<u64>,
}

impl Parse for AnchorFuzzArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let setup_type: Ident = input.parse()?;
        
        let mut runs = None;
        let mut seed = None;
        
        while input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            
            if input.is_empty() {
                break;
            }
            
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            
            match key.to_string().as_str() {
                "runs" => {
                    let lit: Lit = input.parse()?;
                    if let Lit::Int(int_lit) = lit {
                        runs = Some(int_lit.base10_parse()?);
                    }
                }
                "seed" => {
                    let lit: Lit = input.parse()?;
                    if let Lit::Int(int_lit) = lit {
                        seed = Some(int_lit.base10_parse()?);
                    }
                }
                _ => return Err(syn::Error::new(key.span(), "Unknown parameter")),
            }
        }
        
        Ok(AnchorFuzzArgs {
            setup_type,
            runs,
            seed,
        })
    }
}

struct ParamInfo {
    name: Ident,
    ty: syn::Type,
    range: Option<(Expr, Expr)>,
}

fn parse_range_attr(attrs: &[syn::Attribute]) -> syn::Result<Option<(Expr, Expr)>> {
    for attr in attrs {
        if attr.path().is_ident("range") {
            return attr.parse_args_with(|input: ParseStream| {
                let range: ExprRange = input.parse()?;
                
                let start = range.start
                    .ok_or_else(|| syn::Error::new(input.span(), "Range must have start"))?;
                let end = range.end
                    .ok_or_else(|| syn::Error::new(input.span(), "Range must have end"))?;
                
                Ok(Some((*start, *end)))
            });
        }
    }
    Ok(None)
}

#[proc_macro_attribute]
pub fn anchor_fuzz(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AnchorFuzzArgs);
    let input_fn = parse_macro_input!(input as ItemFn);
    
    let fn_name = &input_fn.sig.ident;
    let fn_body = &input_fn.block;
    
    let setup_type = &args.setup_type;
    let runs = args.runs.unwrap_or(256);
    let seed = args.seed.unwrap_or_else(|| {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    
    // Parse parameters (skip first one which is ctx)
    let mut params = Vec::new();
    for (idx, param) in input_fn.sig.inputs.iter().enumerate() {
        if idx == 0 {
            continue; // Skip context parameter
        }
        
        if let FnArg::Typed(pat_type) = param {
            let name = if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                pat_ident.ident.clone()
            } else {
                return syn::Error::new_spanned(param, "Expected identifier pattern")
                    .to_compile_error()
                    .into();
            };
            
            let ty = (*pat_type.ty).clone();
            let range = match parse_range_attr(&pat_type.attrs) {
                Ok(r) => r,
                Err(e) => return e.to_compile_error().into(),
            };
            
            params.push(ParamInfo { name, ty, range });
        }
    }
    
    // Generate generator creation code with type casts
    let generator_inits = params.iter().enumerate().map(|(idx, param)| {
        let gen_name = quote::format_ident!("{}_gen", param.name);
        let seed_expr = quote! { seed.wrapping_add(#idx as u64) };
        let ty = &param.ty;
        
        if let Some((start, end)) = &param.range {
            quote! {
                let mut #gen_name = anchor_test::generator::RangeGenerator::new(
                    #seed_expr,
                    #start as #ty,
                    #end as #ty
                );
            }
        } else {
            quote! {
                let mut #gen_name = anchor_test::generator::FullRangeGenerator::<#ty>::new(#seed_expr);
            }
        }
    });
    
    // Generate value generation code
    let value_gens = params.iter().map(|param| {
        let name = &param.name;
        let gen_name = quote::format_ident!("{}_gen", param.name);
        quote! {
            let #name = anchor_test::generator::InputGenerator::generate(&mut #gen_name);
        }
    });
    
    // Generate debug print on panic
    let param_names = params.iter().map(|p| &p.name);
    let param_debug = quote! {
        eprintln!("Fuzz test failed!");
        eprintln!("  Seed: {}", seed);
        eprintln!("  Iteration: {}", iteration);
        #(eprintln!("  {}: {:?}", stringify!(#param_names), #param_names);)*
    };
    
    let expanded = quote! {
        #[test]
        fn #fn_name() {
            let seed = #seed;
            
            #(#generator_inits)*
            
            for iteration in 0..#runs {
                let ctx = #setup_type::setup();
                
                #(#value_gens)*
                
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    #fn_body
                }));
                
                if result.is_err() {
                    #param_debug
                    panic!("Fuzz test failed at iteration {}", iteration);
                }
            }
        }
    };
    
    TokenStream::from(expanded)
}
