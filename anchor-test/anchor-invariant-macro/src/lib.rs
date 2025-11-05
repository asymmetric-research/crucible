use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse::Parse, parse::ParseStream, parse_macro_input, FnArg, Ident, ImplItem, ItemFn, ItemImpl,
    PatType, Path, Token, Type,
};

/// Generates:
/// ```
/// mod __counter_fixture_fuzz {
///     #[derive(Arbitrary)]
///     pub enum CounterFixtureActions {
///         Increment { amt: u64 },
///         Decrement { amt: u64 },
///     }
///     
///     impl CounterFixture {
///         pub fn __dispatch_action(&mut self, action: CounterFixtureActions) {
///             match action {
///                 CounterFixtureActions::Increment { amt } => self.action_increment(amt),
///                 CounterFixtureActions::Decrement { amt } => self.action_decrement(amt),
///             }
///         }
///     }
/// }
/// ```
/// Macro to mark an impl block as a fuzz fixture
/// Scans for methods starting with `action_` and generates:
/// - An enum with variants for each action
/// - Dispatch logic to call the actions
#[proc_macro_attribute]
pub fn fuzz_fixture(_args: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemImpl);

    // Extract the fixture type name and preserve generics
    let fixture_type = &input.self_ty;
    let generics = &input.generics; // Preserve generics

    let fixture_name = match &**fixture_type {
        Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .map(|s| s.ident.clone())
            .expect("Expected a type name"),
        _ => panic!("Expected a simple type path"),
    };

    // Find all action_* methods
    let mut actions = Vec::new();

    for item in &input.items {
        if let ImplItem::Fn(method) = item {
            let method_name = method.sig.ident.to_string();

            if method_name.starts_with("action_") {
                // Extract action name (remove "action_" prefix)
                let action_name = &method_name[7..];
                let action_ident = format_ident!("{}", to_pascal_case(action_name));

                // Extract parameters (skip &mut self)
                let mut params = Vec::new();
                for arg in &method.sig.inputs {
                    if let FnArg::Typed(PatType { pat, ty, .. }) = arg {
                        // Skip self parameters
                        if let syn::Pat::Ident(pat_ident) = &**pat {
                            if pat_ident.ident != "self" {
                                params.push((pat_ident.ident.clone(), ty.clone()));
                            }
                        }
                    }
                }

                actions.push((action_ident, method.sig.ident.clone(), params));
            }
        }
    }

    if actions.is_empty() {
        panic!("No action_* methods found in impl block. Methods must be named action_something()");
    }

    // Generate the actions enum
    let enum_name = format_ident!("{}Actions", fixture_name);
    let mod_name = format_ident!("__{}_fuzz", to_snake_case(&fixture_name.to_string()));

    let enum_variants = actions.iter().map(|(action_name, _, params)| {
        if params.is_empty() {
            quote! { #action_name }
        } else {
            let fields = params.iter().map(|(name, ty)| {
                quote! { #name: #ty }
            });
            quote! { #action_name { #(#fields),* } }
        }
    });

    // Generate the dispatch match arms
    let dispatch_arms = actions.iter().map(|(action_name, method_name, params)| {
        if params.is_empty() {
            quote! {
                #enum_name::#action_name => self.#method_name(),
            }
        } else {
            let param_names = params.iter().map(|(name, _)| name);
            let param_names_in_call = params.iter().map(|(name, _)| name);
            quote! {
                #enum_name::#action_name { #(#param_names),* } => {
                    self.#method_name(#(#param_names_in_call),*)
                }
            }
        }
    });

    // Generate the hidden module with enum and dispatch
    let generated = quote! {
        #input

        #[doc(hidden)]
        pub mod #mod_name {
            use super::*;
            use arbitrary::Arbitrary;

            #[derive(Arbitrary, Debug, Clone)]
            pub enum #enum_name {
                #(#enum_variants),*
            }

            impl #generics #fixture_type {  // Preserve generics here
                #[doc(hidden)]
                pub fn __dispatch_action(&mut self, action: #enum_name) {
                    match action {
                        #(#dispatch_arms)*
                    }
                }
            }
        }
    };

    TokenStream::from(generated)
}

/// Macro for invariant testing that expands to #[anchor_fuzz]
///
/// Example:
/// ```
/// #[invariant_test(CounterFixture::setup, num_actions_before_reset = 15)]
/// fn fuzz_test(ctx: &mut TestContext) {
///     // invariants
/// }
/// ```
#[proc_macro_attribute]
pub fn invariant_test(args: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);
    let args = parse_macro_input!(args as InvariantTestArgs);

    let fn_name = &input_fn.sig.ident;
    let fn_body = &input_fn.block;

    let fixture_type = &args
        .setup_path
        .segments
        .first()
        .expect("Expected fixture type in setup path")
        .ident;

    let mod_name = format_ident!("__{}_fuzz", to_snake_case(&fixture_type.to_string()));
    let enum_name = format_ident!("{}Actions", fixture_type);
    let setup_path = &args.setup_path;

    let num_actions = args.num_actions_before_reset.unwrap_or(10);

    let expanded = quote! {
        #[anchor_fuzz]
        fn #fn_name(ctx: &mut anchor_test_context::TestContext, actions: Vec<#mod_name::#enum_name>) {
            let mut fixture = #setup_path(ctx);

            for (i, action) in actions.iter().enumerate() {
                if i > 0 && i % #num_actions == 0 {
                    fixture = #setup_path(ctx);
                }

                fixture.__dispatch_action(action.clone());

                // Wrap invariant check in catch_unwind
                let fixture_ref = &fixture;
                #fn_body
            }
        }
    };

    TokenStream::from(expanded)
}
// Parse macro arguments for #[invariant_test]
struct InvariantTestArgs {
    setup_path: Path,
    num_actions_before_reset: Option<usize>,
}

impl Parse for InvariantTestArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let setup_path: Path = input.parse()?;

        let mut num_actions_before_reset = None;

        while !input.is_empty() {
            input.parse::<Token![,]>()?;

            if input.is_empty() {
                break;
            }

            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            if key == "num_actions_before_reset" {
                let lit: syn::LitInt = input.parse()?;
                num_actions_before_reset = Some(lit.base10_parse()?);
            }
        }

        Ok(InvariantTestArgs {
            setup_path,
            num_actions_before_reset,
        })
    }
}

// Helper functions for case conversion
fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect()
}

fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(ch.to_lowercase().next().unwrap());
    }
    result
}
