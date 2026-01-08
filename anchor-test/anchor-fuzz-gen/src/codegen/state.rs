use anchor_lang_idl::types::{Idl, IdlTypeDef, IdlTypeDefTy, IdlDefinedFields, IdlAccount, IdlRepr};
use heck::ToUpperCamelCase;
use quote::{format_ident, quote};

use super::idl_type_to_tokens;

/// Generate state types for deserializing on-chain account data
pub fn generate(idl: &Idl) -> proc_macro2::TokenStream {
    // The accounts section contains account metadata (name + discriminator)
    // The actual type definitions are in the types section
    let state_types = idl.accounts.iter().filter_map(|acc| {
        // Look up the type definition in idl.types by name
        let type_def = idl.types.iter().find(|t| t.name == acc.name)?;
        Some(generate_account_struct(acc, type_def))
    });

    quote! {
        /// State types for deserializing on-chain account data
        pub mod state {
            use super::*;
            use super::types::*;

            #(#state_types)*
        }
    }
}

fn generate_account_struct(
    acc: &IdlAccount,
    type_def: &IdlTypeDef,
) -> proc_macro2::TokenStream {
    let name = format_ident!("{}", type_def.name);
    let discriminator = &acc.discriminator;

    // Check if this is a zero-copy type using the IDL's repr field (not heuristics)
    let is_zero_copy = matches!(&type_def.repr, Some(IdlRepr::C(_)));

    match &type_def.ty {
        IdlTypeDefTy::Struct { fields } => {
            let fields_tokens = generate_struct_fields(fields);

            if is_zero_copy {
                // Zero-copy account
                quote! {
                    #[derive(Clone, Copy)]
                    #[repr(C)]
                    pub struct #name {
                        #fields_tokens
                    }

                    impl #name {
                        pub const DISCRIMINATOR: &'static [u8] = &[#(#discriminator),*];
                        pub const DISCRIMINATOR_LEN: usize = 8;
                    }

                    unsafe impl bytemuck::Pod for #name {}
                    unsafe impl bytemuck::Zeroable for #name {}
                }
            } else {
                // Regular account with borsh serialization
                quote! {
                    #[derive(Clone, AnchorSerialize, AnchorDeserialize)]
                    pub struct #name {
                        #fields_tokens
                    }

                    impl anchor_lang::Discriminator for #name {
                        const DISCRIMINATOR: &'static [u8] = &[#(#discriminator),*];
                    }
                }
            }
        }
        IdlTypeDefTy::Enum { variants } => {
            // Enums in accounts section are rare but possible
            let variants_tokens = variants.iter().map(|v| {
                let variant_name = format_ident!("{}", v.name.to_upper_camel_case());
                match &v.fields {
                    Some(IdlDefinedFields::Named(fields)) => {
                        let field_tokens = fields.iter().map(|f| {
                            let field_name = format_ident!("{}", f.name);
                            let field_type = idl_type_to_tokens(&f.ty);
                            quote! { #field_name: #field_type }
                        });
                        quote! { #variant_name { #(#field_tokens),* } }
                    }
                    Some(IdlDefinedFields::Tuple(types)) => {
                        let type_tokens = types.iter().map(idl_type_to_tokens);
                        quote! { #variant_name(#(#type_tokens),*) }
                    }
                    None => quote! { #variant_name },
                }
            });

            quote! {
                #[derive(Clone, Copy, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)]
                pub enum #name {
                    #(#variants_tokens),*
                }
            }
        }
        IdlTypeDefTy::Type { alias } => {
            let alias_ty = idl_type_to_tokens(alias);
            quote! {
                pub type #name = #alias_ty;
            }
        }
    }
}

fn generate_struct_fields(fields: &Option<IdlDefinedFields>) -> proc_macro2::TokenStream {
    match fields {
        Some(IdlDefinedFields::Named(named_fields)) => {
            let field_tokens = named_fields.iter().map(|f| {
                let field_name = format_ident!("{}", f.name);
                let field_type = idl_type_to_tokens(&f.ty);
                quote! { pub #field_name: #field_type }
            });
            quote! { #(#field_tokens),* }
        }
        Some(IdlDefinedFields::Tuple(tuple_fields)) => {
            let field_tokens = tuple_fields.iter().enumerate().map(|(i, ty)| {
                let idx = syn::Index::from(i);
                let field_type = idl_type_to_tokens(ty);
                quote! { pub #idx: #field_type }
            });
            quote! { #(#field_tokens),* }
        }
        None => quote! {},
    }
}
