pub mod accounts;
pub mod discriminators;
pub mod instructions;
pub mod schemas;
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

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang_idl::types::{IdlArrayLen, IdlMetadata, IdlType};

    fn make_idl_with_address(address: &str) -> Idl {
        Idl {
            address: address.to_string(),
            metadata: IdlMetadata {
                name: "test".to_string(),
                version: "0.1.0".to_string(),
                spec: "0.1.0".to_string(),
                description: None,
                repository: None,
                dependencies: vec![],
                contact: None,
                deployments: None,
            },
            docs: vec![],
            instructions: vec![],
            accounts: vec![],
            events: vec![],
            errors: vec![],
            types: vec![],
            constants: vec![],
        }
    }

    #[test]
    fn test_gen_program_id() {
        let idl = make_idl_with_address("11111111111111111111111111111111");
        let output = gen_program_id(&idl).to_string();
        assert!(
            output.contains("Pubkey :: new_from_array"),
            "should use new_from_array"
        );
        assert!(output.contains("ID"), "should define ID constant");
    }

    #[test]
    fn test_gen_program_id_stake() {
        let idl = make_idl_with_address("Stake11111111111111111111111111111111111111");
        let output = gen_program_id(&idl).to_string();
        assert!(output.contains("Pubkey :: new_from_array"));
    }

    #[test]
    fn test_idl_type_to_tokens_primitives() {
        assert_eq!(idl_type_to_tokens(&IdlType::Bool).to_string(), "bool");
        assert_eq!(idl_type_to_tokens(&IdlType::U8).to_string(), "u8");
        assert_eq!(idl_type_to_tokens(&IdlType::I8).to_string(), "i8");
        assert_eq!(idl_type_to_tokens(&IdlType::U16).to_string(), "u16");
        assert_eq!(idl_type_to_tokens(&IdlType::I16).to_string(), "i16");
        assert_eq!(idl_type_to_tokens(&IdlType::U32).to_string(), "u32");
        assert_eq!(idl_type_to_tokens(&IdlType::I32).to_string(), "i32");
        assert_eq!(idl_type_to_tokens(&IdlType::F32).to_string(), "f32");
        assert_eq!(idl_type_to_tokens(&IdlType::U64).to_string(), "u64");
        assert_eq!(idl_type_to_tokens(&IdlType::I64).to_string(), "i64");
        assert_eq!(idl_type_to_tokens(&IdlType::F64).to_string(), "f64");
        assert_eq!(idl_type_to_tokens(&IdlType::U128).to_string(), "u128");
        assert_eq!(idl_type_to_tokens(&IdlType::I128).to_string(), "i128");
        assert_eq!(idl_type_to_tokens(&IdlType::Pubkey).to_string(), "Pubkey");
        assert_eq!(idl_type_to_tokens(&IdlType::String).to_string(), "String");
        assert_eq!(
            idl_type_to_tokens(&IdlType::Bytes).to_string(),
            "Vec < u8 >"
        );
    }

    #[test]
    fn test_idl_type_to_tokens_option() {
        let output = idl_type_to_tokens(&IdlType::Option(Box::new(IdlType::U64))).to_string();
        assert_eq!(output, "Option < u64 >");
    }

    #[test]
    fn test_idl_type_to_tokens_vec() {
        let output = idl_type_to_tokens(&IdlType::Vec(Box::new(IdlType::Pubkey))).to_string();
        assert_eq!(output, "Vec < Pubkey >");
    }

    #[test]
    fn test_idl_type_to_tokens_array() {
        let output = idl_type_to_tokens(&IdlType::Array(
            Box::new(IdlType::U8),
            IdlArrayLen::Value(32),
        ))
        .to_string();
        assert_eq!(output, "[u8 ; 32usize]");
    }

    #[test]
    fn test_idl_type_to_tokens_defined() {
        let output = idl_type_to_tokens(&IdlType::Defined {
            name: "MyCustomType".to_string(),
            generics: vec![],
        })
        .to_string();
        assert_eq!(output, "MyCustomType");
    }

    #[test]
    fn test_array_len_to_usize() {
        assert_eq!(array_len_to_usize(&IdlArrayLen::Value(42)), 42);
        assert_eq!(array_len_to_usize(&IdlArrayLen::Value(0)), 0);
    }

    #[test]
    #[should_panic(expected = "Generic array length")]
    fn test_array_len_generic_panics() {
        array_len_to_usize(&IdlArrayLen::Generic("N".to_string()));
    }
}
