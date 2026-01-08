pub mod accounts;
pub mod instructions;
pub mod state;
pub mod types;

use anchor_lang_idl::types::{Idl, IdlArrayLen};
use quote::quote;

/// Convert IdlArrayLen enum to a usize value
pub fn array_len_to_usize(len: &IdlArrayLen) -> usize {
    match len {
        IdlArrayLen::Value(n) => *n,
        IdlArrayLen::Generic(name) => {
            // For generic lengths, we can't know at compile time
            // Fall back to a reasonable default or panic
            panic!("Generic array length '{name}' not supported in codegen")
        }
    }
}

/// Generate the program ID constant
pub fn gen_program_id(idl: &Idl) -> proc_macro2::TokenStream {
    let address_bytes = bs58::decode(&idl.address)
        .into_vec()
        .expect("Invalid IDL address");

    quote! {
        /// Program ID
        pub static ID: Pubkey = Pubkey::new_from_array([#(#address_bytes,)*]);
    }
}

/// Convert IDL type to Rust type tokens
pub fn idl_type_to_tokens(ty: &anchor_lang_idl::types::IdlType) -> proc_macro2::TokenStream {
    use anchor_lang_idl::types::IdlType;

    match ty {
        IdlType::Bool => quote! { bool },
        IdlType::U8 => quote! { u8 },
        IdlType::I8 => quote! { i8 },
        IdlType::U16 => quote! { u16 },
        IdlType::I16 => quote! { i16 },
        IdlType::U32 => quote! { u32 },
        IdlType::I32 => quote! { i32 },
        IdlType::F32 => quote! { f32 },
        IdlType::U64 => quote! { u64 },
        IdlType::I64 => quote! { i64 },
        IdlType::F64 => quote! { f64 },
        IdlType::U128 => quote! { u128 },
        IdlType::I128 => quote! { i128 },
        IdlType::U256 => quote! { [u8; 32] }, // Represented as bytes
        IdlType::I256 => quote! { [u8; 32] }, // Represented as bytes
        IdlType::Bytes => quote! { Vec<u8> },
        IdlType::String => quote! { String },
        IdlType::Pubkey => quote! { Pubkey },
        IdlType::Option(inner) => {
            let inner_ty = idl_type_to_tokens(inner);
            quote! { Option<#inner_ty> }
        }
        IdlType::Vec(inner) => {
            let inner_ty = idl_type_to_tokens(inner);
            quote! { Vec<#inner_ty> }
        }
        IdlType::Array(inner, len) => {
            let inner_ty = idl_type_to_tokens(inner);
            let len_value = array_len_to_usize(len);
            quote! { [#inner_ty; #len_value] }
        }
        IdlType::Defined { name, generics: _ } => {
            let ident = quote::format_ident!("{}", name);
            quote! { #ident }
        }
        IdlType::Generic(name) => {
            let ident = quote::format_ident!("{}", name);
            quote! { #ident }
        }
        // Handle other variants as needed
        _ => quote! { () }, // Fallback
    }
}
