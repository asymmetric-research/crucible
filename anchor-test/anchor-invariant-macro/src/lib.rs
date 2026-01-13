use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse::Parse, parse::ParseStream, parse_macro_input, FnArg, Ident, ImplItem, ItemFn, ItemImpl,
    PatType, Path, Token, Type, Expr, ExprRange, RangeLimits, Lit, Meta,
};
use std::collections::HashMap;
use anchor_macro_utils::RangeConstraint;

#[proc_macro_attribute]
pub fn fuzz_fixture(_args: TokenStream, item: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(item as ItemImpl);

    let fixture_type = &input.self_ty;

    let fixture_name = match &**fixture_type {
        Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .map(|s| s.ident.clone())
            .expect("Expected a type name"),
        _ => panic!("Expected a simple type path"),
    };

    // Find all action_* methods and their range constraints
    let mut actions = Vec::new();
    let mut constraints: HashMap<(String, String), RangeConstraint> = HashMap::new();
    
    for item in &mut input.items {
        // Each function
        if let ImplItem::Fn(method) = item {
            let method_name = method.sig.ident.to_string();

            if method_name.starts_with("action_") {
                let action_name = &method_name[7..];
                let action_ident = format_ident!("{}", to_pascal_case(action_name));

                let mut params = Vec::new();
                // Each parameter for the action
                for arg in &mut method.sig.inputs {
                    if let FnArg::Typed(PatType { pat, ty, attrs, .. }) = arg {
                        if let syn::Pat::Ident(pat_ident) = &**pat {
                            if pat_ident.ident != "self" {
                                // Check for range constraint before stripping
                                if let Some(range_attr) = attrs.iter().find(|a| a.path().is_ident("range")) {
                                    if let Ok(constraint) = RangeConstraint::from_attr(range_attr) {
                                        constraints.insert(
                                            (action_ident.to_string(), pat_ident.ident.to_string()),
                                            constraint
                                        );
                                    }
                                }
                                // Strip range attributes from original impl so theres no compiler error
                                attrs.retain(|a| !a.path().is_ident("range"));
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

    let enum_name = format_ident!("{}Actions", fixture_name);
    let mod_name = format_ident!("__{}_fuzz", to_snake_case(&fixture_name.to_string()));

    // Get Enum Variants, one for each action
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

    // Generate arms to get action name as string
    let action_name_arms = actions.iter().map(|(action_name, _, params)| {
        let action_str = to_snake_case(&action_name.to_string());
        if params.is_empty() {
            quote! {
                #enum_name::#action_name => #action_str,
            }
        } else {
            quote! {
                #enum_name::#action_name { .. } => #action_str,
            }
        }
    });

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

    // Generate constrain_in_place method to apply constraints to the inputs
    let constrain_arms: Vec<_> = actions.iter().map(|(action_name, _, params)| {
        // Get each constraint for the field
        let field_constraints: Vec<_> = params.iter().filter_map(|(field_name, field_type)| {
            constraints.get(&(action_name.to_string(), field_name.to_string()))
                .map(|constraint| constraint.generate_constraint_expr(field_name, field_type))
        }).collect();

        if field_constraints.is_empty() {
            quote! { #enum_name::#action_name { .. } => {} }
        } else if params.is_empty() {
            quote! { #enum_name::#action_name => {} }
        } else {
            let field_names = params.iter().map(|(name, _)| name);
            quote! {
                #enum_name::#action_name { #(#field_names),* } => {
                    #(#field_constraints)*
                }
            }
        }
    }).collect();

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

            impl #enum_name {
                pub fn constrain_in_place(&mut self) {
                    match self {
                        #(#constrain_arms)*
                    }
                }

                /// Get the action name as a string (for coverage tracking)
                pub fn action_name(&self) -> &'static str {
                    match self {
                        #(#action_name_arms)*
                    }
                }
            }

            impl #fixture_type {
                #[doc(hidden)]
                pub fn __dispatch_action(&mut self, action: #enum_name) {
                    // Set current instruction name for coverage tracking
                    anchor_test_context::set_current_instruction(Some(action.action_name().to_string()));

                    // Dispatch the action
                    match action {
                        #(#dispatch_arms)*
                    }

                    // Clear after action
                    anchor_test_context::set_current_instruction(None);
                }
                #[doc(hidden)]
                pub fn __auto_flush(&mut self) {
                    let _ = self.ctx.send_batch();
                }
            }
        }
    };

    TokenStream::from(generated)
}

#[proc_macro_attribute]
pub fn invariant_test(args: TokenStream, item: TokenStream) -> TokenStream {
    if !proc_macro2::TokenStream::from(args.clone()).is_empty() {
        return syn::Error::new_spanned(
            proc_macro2::TokenStream::from(args),
            "invariant_test no longer takes arguments - fixture type is inferred from parameter"
        ).to_compile_error().into();
    }
    
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let fn_body = &input_fn.block;
    
    // Extract fixture type from first parameter
    let fixture_param = input_fn.sig.inputs.first()
        .expect("invariant_test function must have a fixture parameter");
    
    let FnArg::Typed(pat_type) = fixture_param else {
        return syn::Error::new_spanned(
            fixture_param,
            "Expected typed parameter"
        ).to_compile_error().into();
    };
    
    // Extract type from &mut FixtureType or &FixtureType
    let fixture_type = match &*pat_type.ty {
        Type::Reference(type_ref) => &*type_ref.elem,
        _ => {
            return syn::Error::new_spanned(
                &pat_type.ty,
                "Fixture parameter must be a reference (&mut FixtureType)"
            ).to_compile_error().into();
        }
    };
    
    let fixture_name = match fixture_type {
        Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .map(|s| s.ident.clone())
            .expect("Expected fixture type name"),
        _ => {
            return syn::Error::new_spanned(
                fixture_type,
                "Expected a simple type path for fixture"
            ).to_compile_error().into();
        }
    };
    
    let mod_name = format_ident!("__{}_fuzz", to_snake_case(&fixture_name.to_string()));
    let enum_name = format_ident!("{}Actions", fixture_name);

    let expanded = quote! {
        #[anchor_fuzz]
        fn #fn_name(fixture: &mut #fixture_name, actions: Vec<#mod_name::#enum_name>) {
            let debug = std::env::var("FUZZ_DEBUG").is_ok();
            if debug {
                eprintln!("[FUZZ] Starting iteration with {} actions", actions.len());
            }
            for (i, mut action) in actions.into_iter().enumerate() {
                action.constrain_in_place();
                if debug {
                    eprintln!("[FUZZ] Action {}: {:?}", i, action);
                }
                fixture.__dispatch_action(action);

                #fn_body
            }
            fixture.__auto_flush();
        }
    };

    TokenStream::from(expanded)
}

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
