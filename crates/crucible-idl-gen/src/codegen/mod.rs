pub mod accounts;
pub mod discriminators;
pub(crate) mod generics;
pub mod instructions;
pub mod schemas;
pub mod state;
pub mod types;

use anchor_lang_idl::types::{Idl, IdlArrayLen};
use quote::quote;

use self::generics::{array_len_to_tokens, generic_args_to_tokens};

/// Convert IdlArrayLen enum to a usize value.
///
/// Note: this only handles `IdlArrayLen::Value(_)` and panics on `Generic`.
/// For generic-aware emission inside `idl_type_to_tokens`, use
/// `generics::array_len_to_tokens` directly.
pub fn array_len_to_usize(len: &IdlArrayLen) -> usize {
    match len {
        IdlArrayLen::Value(n) => *n,
        IdlArrayLen::Generic(name) => {
            panic!("Generic array length '{name}' not supported by array_len_to_usize; use array_len_to_tokens instead")
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
            let len_tokens = array_len_to_tokens(len);
            quote! { [#inner_ty; #len_tokens] }
        }
        IdlType::Defined { name, generics } => {
            let ident = quote::format_ident!("{}", name);
            let args = generic_args_to_tokens(generics);
            quote! { #ident #args }
        }
        IdlType::Generic(name) => {
            let ident = quote::format_ident!("{}", name);
            quote! { #ident }
        }
        _ => panic!("Unsupported IDL type in codegen: {ty:?}"),
    }
}

/// Whether a type can derive `serde::Serialize`.
///
/// serde only implements `Serialize` for fixed arrays up to 32 elements, so
/// any type containing a longer array (directly or through a defined type)
/// cannot get the derive. Used by generated type definitions in bincode
/// programs; instruction args are encoded field-wise and do not rely on the
/// arg struct deriving serde.
pub(crate) fn is_serde_serializable(
    ty: &anchor_lang_idl::types::IdlType,
    all_types: &[anchor_lang_idl::types::IdlTypeDef],
) -> bool {
    use anchor_lang_idl::types::{IdlType, IdlTypeDefTy};

    match ty {
        IdlType::Bool
        | IdlType::U8
        | IdlType::I8
        | IdlType::U16
        | IdlType::I16
        | IdlType::U32
        | IdlType::I32
        | IdlType::F32
        | IdlType::U64
        | IdlType::I64
        | IdlType::F64
        | IdlType::U128
        | IdlType::I128
        | IdlType::Pubkey
        | IdlType::String
        | IdlType::Bytes => true,
        // U256/I256 are emitted as [u8; 32] — within serde's array limit
        IdlType::U256 | IdlType::I256 => true,
        IdlType::Option(inner) | IdlType::Vec(inner) => is_serde_serializable(inner, all_types),
        IdlType::Array(inner, IdlArrayLen::Value(n)) => {
            *n <= 32 && is_serde_serializable(inner, all_types)
        }
        // Generic-length arrays — unknown at codegen time, be conservative
        IdlType::Array(_, IdlArrayLen::Generic(_)) => false,
        IdlType::Defined { name, generics } => {
            // Generic instantiations would require seeing through the typedef
            // body with substitution — conservative.
            if !generics.is_empty() {
                return false;
            }
            let Some(typedef) = all_types.iter().find(|t| &t.name == name) else {
                return false;
            };
            if !typedef.generics.is_empty() {
                return false;
            }
            match &typedef.ty {
                IdlTypeDefTy::Struct { fields } => fields
                    .as_ref()
                    .map_or(true, |f| fields_serde_serializable(f, all_types)),
                IdlTypeDefTy::Enum { variants } => variants.iter().all(|v| {
                    v.fields
                        .as_ref()
                        .map_or(true, |f| fields_serde_serializable(f, all_types))
                }),
                IdlTypeDefTy::Type { alias } => is_serde_serializable(alias, all_types),
            }
        }
        // Type-param references — depend on the instantiation, be conservative
        IdlType::Generic(_) => false,
        _ => false,
    }
}

/// Whether every field in a fields list can derive `serde::Serialize`.
pub(crate) fn fields_serde_serializable(
    fields: &anchor_lang_idl::types::IdlDefinedFields,
    all_types: &[anchor_lang_idl::types::IdlTypeDef],
) -> bool {
    use anchor_lang_idl::types::IdlDefinedFields;

    match fields {
        IdlDefinedFields::Named(named) => named
            .iter()
            .all(|f| is_serde_serializable(&f.ty, all_types)),
        IdlDefinedFields::Tuple(types) => types.iter().all(|t| is_serde_serializable(t, all_types)),
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
    fn test_idl_type_to_tokens_defined_with_generics() {
        use anchor_lang_idl::types::IdlGenericArg;

        let output = idl_type_to_tokens(&IdlType::Defined {
            name: "Foo".to_string(),
            generics: vec![IdlGenericArg::Type { ty: IdlType::U64 }],
        })
        .to_string();
        assert_eq!(output, "Foo < u64 >");

        let output = idl_type_to_tokens(&IdlType::Defined {
            name: "Foo".to_string(),
            generics: vec![
                IdlGenericArg::Type { ty: IdlType::U64 },
                IdlGenericArg::Const { value: "8".into() },
            ],
        })
        .to_string();
        assert_eq!(output, "Foo < u64 , 8 >");
    }

    #[test]
    fn test_idl_type_to_tokens_generic_ref() {
        let output = idl_type_to_tokens(&IdlType::Generic("A".to_string())).to_string();
        assert_eq!(output, "A");
    }

    #[test]
    fn test_idl_type_to_tokens_array_with_generic_len() {
        let output = idl_type_to_tokens(&IdlType::Array(
            Box::new(IdlType::U8),
            IdlArrayLen::Generic("N".to_string()),
        ))
        .to_string();
        assert_eq!(output, "[u8 ; N]");
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
