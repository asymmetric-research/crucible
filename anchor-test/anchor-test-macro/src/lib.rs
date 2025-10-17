use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, parse::Parse, parse::ParseStream, Token, Ident, Path};

/// Parsed attribute arguments for #[anchor_test(...)]
struct AnchorTestArgs {
    setup_path: Option<Path>,
}

impl Parse for AnchorTestArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(AnchorTestArgs { setup_path: None });
        }
        let setup_path: Path = input.parse()?;
        Ok(AnchorTestArgs { setup_path: Some(setup_path) })
    }
}

/// The #[anchor_test] procedural macro
/// 
/// Usage:
/// ```
/// #[anchor_test(CounterTest)]
/// fn test_increment(ctx: CounterTest) {
///     // test code
/// }
/// ```
/// 
/// Expands to:
/// ```
/// #[test]
/// fn test_increment() {
///     let mut ctx = CounterTest::setup();
///     // test code
/// }
/// ```
#[proc_macro_attribute]
pub fn anchor_test(args: TokenStream, input: TokenStream) -> TokenStream {
    let mut parsed_args = parse_macro_input!(args as AnchorTestArgs);
    let input_fn = parse_macro_input!(input as ItemFn);

    // Extract function name
    let fn_name = &input_fn.sig.ident;

    // Get the function body
    let fn_body = &input_fn.block;

    if parsed_args.setup_path.is_none() {
        return TokenStream::from(
            quote!(
                #[test]
                fn #fn_name() {
                    #fn_body            
                }
            )
        );
    }
    // Extract the context parameter
    let ctx_param = match input_fn.sig.inputs.first() {
        Some(syn::FnArg::Typed(pat_type)) => pat_type,
        _ => {
            return syn::Error::new_spanned(
                &input_fn.sig,
                "anchor_test function must have exactly one parameter (ctx: YourContext)"
            )
            .to_compile_error()
            .into();
        }
    };
    
    // Get the parameter name (e.g., "ctx")
    let ctx_name = &ctx_param.pat;
    // Build the setup path - if it's just "CounterTest", make it "CounterTest::setup"
    let setup_call = {
        let path = &parsed_args.setup_path.unwrap(); 

        let path_str = quote!(#path).to_string();

        if !path_str.contains("::") {
            // No method specified default to setup()
            quote! { #path::setup() }
        } else {
            // Just keep as is 
            quote! { #path }
        }
    };

    // Generate the expanded code
    let expanded = quote! {
        #[test]
        fn #fn_name() {
            let mut #ctx_name = #setup_call;
            #fn_body
        }
    };
    TokenStream::from(expanded)
}
