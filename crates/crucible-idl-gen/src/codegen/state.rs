use anchor_lang_idl::types::{
    Idl, IdlAccount, IdlDefinedFields, IdlRepr, IdlTypeDef, IdlTypeDefTy,
};
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

fn generate_account_struct(acc: &IdlAccount, type_def: &IdlTypeDef) -> proc_macro2::TokenStream {
    let name = format_ident!("{}", type_def.name);
    let discriminator = &acc.discriminator;

    // Check if this is a zero-copy type using the IDL's repr field (not heuristics)
    let is_zero_copy = matches!(&type_def.repr, Some(IdlRepr::C(_)));

    match &type_def.ty {
        IdlTypeDefTy::Struct { fields } => {
            let fields_tokens = generate_struct_fields(fields);

            // Get actual discriminator length from IDL (not hardcoded 8)
            let discriminator_len = discriminator.len();

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
                        pub const DISCRIMINATOR_LEN: usize = #discriminator_len;
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

                    impl #name {
                        pub const DISCRIMINATOR: &'static [u8] = &[#(#discriminator),*];
                        pub const DISCRIMINATOR_LEN: usize = #discriminator_len;
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

/// Generate struct fields for state types
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

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang_idl::types::{
        IdlAccount, IdlDefinedFields, IdlField, IdlMetadata, IdlRepr, IdlReprModifier, IdlType,
        IdlTypeDef, IdlTypeDefTy,
    };

    fn make_idl(accounts: Vec<IdlAccount>, types: Vec<IdlTypeDef>) -> Idl {
        Idl {
            address: "11111111111111111111111111111111".to_string(),
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
            accounts,
            events: vec![],
            errors: vec![],
            types,
            constants: vec![],
        }
    }

    #[test]
    fn test_regular_account() {
        let disc = vec![0xAB, 0xCD, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let idl = make_idl(
            vec![IdlAccount {
                name: "UserAccount".to_string(),
                discriminator: disc.clone(),
            }],
            vec![IdlTypeDef {
                name: "UserAccount".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Named(vec![
                        IdlField {
                            name: "owner".to_string(),
                            docs: vec![],
                            ty: IdlType::Pubkey,
                        },
                        IdlField {
                            name: "balance".to_string(),
                            docs: vec![],
                            ty: IdlType::U64,
                        },
                    ])),
                },
            }],
        );
        let output = generate(&idl).to_string();
        assert!(output.contains("UserAccount"), "should have struct name");
        assert!(
            output.contains("DISCRIMINATOR"),
            "should have DISCRIMINATOR const"
        );
        assert!(
            output.contains("AnchorSerialize"),
            "regular account should have borsh derives"
        );
        assert!(
            output.contains("AnchorDeserialize"),
            "regular account should have borsh derives"
        );
        assert!(output.contains("pub owner : Pubkey"));
        assert!(output.contains("pub balance : u64"));
    }

    #[test]
    fn test_zero_copy_account() {
        let disc = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let idl = make_idl(
            vec![IdlAccount {
                name: "ZcAccount".to_string(),
                discriminator: disc,
            }],
            vec![IdlTypeDef {
                name: "ZcAccount".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: Some(IdlRepr::C(IdlReprModifier {
                    packed: false,
                    align: None,
                })),
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Named(vec![IdlField {
                        name: "value".to_string(),
                        docs: vec![],
                        ty: IdlType::U64,
                    }])),
                },
            }],
        );
        let output = generate(&idl).to_string();
        assert!(
            output.contains("repr (C)"),
            "zero-copy account should have repr(C)"
        );
        assert!(output.contains("bytemuck :: Pod"), "should have Pod");
        assert!(
            output.contains("bytemuck :: Zeroable"),
            "should have Zeroable"
        );
        assert!(
            output.contains("DISCRIMINATOR"),
            "should have DISCRIMINATOR"
        );
    }

    #[test]
    fn test_no_accounts_empty_module() {
        let idl = make_idl(vec![], vec![]);
        let output = generate(&idl).to_string();
        // Should still generate the state module, just empty
        assert!(output.contains("mod state"), "should have state module");
    }

    #[test]
    fn test_account_with_missing_type_silently_skipped() {
        // Account references a type that doesn't exist in idl.types
        let idl = make_idl(
            vec![IdlAccount {
                name: "MissingType".to_string(),
                discriminator: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }],
            vec![], // no types — MissingType has no definition
        );
        let output = generate(&idl).to_string();
        // Should still generate the state module, just without MissingType
        assert!(output.contains("mod state"), "should have state module");
        assert!(
            !output.contains("MissingType"),
            "account with no matching type definition should be silently skipped"
        );
    }

    #[test]
    fn test_account_with_missing_type_others_still_generated() {
        // One account has a type, the other doesn't — the valid one should still be generated
        let idl = make_idl(
            vec![
                IdlAccount {
                    name: "ValidAccount".to_string(),
                    discriminator: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22],
                },
                IdlAccount {
                    name: "BrokenAccount".to_string(),
                    discriminator: vec![1, 2, 3, 4, 5, 6, 7, 8],
                },
            ],
            vec![IdlTypeDef {
                name: "ValidAccount".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Named(vec![IdlField {
                        name: "data".to_string(),
                        docs: vec![],
                        ty: IdlType::U64,
                    }])),
                },
            }],
        );
        let output = generate(&idl).to_string();
        assert!(
            output.contains("ValidAccount"),
            "valid account should still be generated"
        );
        assert!(
            !output.contains("BrokenAccount"),
            "broken account should be silently skipped"
        );
    }

    #[test]
    fn test_discriminator_length_preserved() {
        // Test with 4-byte discriminator (bincode)
        let idl = make_idl(
            vec![IdlAccount {
                name: "NativeAccount".to_string(),
                discriminator: vec![1, 0, 0, 0],
            }],
            vec![IdlTypeDef {
                name: "NativeAccount".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Named(vec![IdlField {
                        name: "x".to_string(),
                        docs: vec![],
                        ty: IdlType::U64,
                    }])),
                },
            }],
        );
        let output = generate(&idl).to_string();
        assert!(
            output.contains("DISCRIMINATOR_LEN : usize = 4usize"),
            "should preserve 4-byte discriminator len"
        );
    }

    // -----------------------------------------------------------------------
    // #4: Enum account type in state module
    // -----------------------------------------------------------------------

    #[test]
    fn test_enum_account() {
        let idl = make_idl(
            vec![IdlAccount {
                name: "StakeState".to_string(),
                discriminator: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22],
            }],
            vec![IdlTypeDef {
                name: "StakeState".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Enum {
                    variants: vec![
                        anchor_lang_idl::types::IdlEnumVariant {
                            name: "Uninitialized".to_string(),
                            fields: None,
                        },
                        anchor_lang_idl::types::IdlEnumVariant {
                            name: "Initialized".to_string(),
                            fields: Some(IdlDefinedFields::Named(vec![IdlField {
                                name: "authority".to_string(),
                                docs: vec![],
                                ty: IdlType::Pubkey,
                            }])),
                        },
                    ],
                },
            }],
        );
        let output = generate(&idl).to_string();
        assert!(
            output.contains("pub enum StakeState"),
            "should generate enum in state module, got: {}",
            output
        );
        assert!(
            output.contains("Uninitialized"),
            "should have Uninitialized variant"
        );
        assert!(
            output.contains("Initialized"),
            "should have Initialized variant"
        );
        assert!(
            output.contains("authority : Pubkey"),
            "should have authority field"
        );
        assert!(
            output.contains("AnchorSerialize"),
            "enum account should have borsh derives"
        );
    }

    // #4: Type alias account type in state module

    #[test]
    fn test_type_alias_account() {
        let idl = make_idl(
            vec![IdlAccount {
                name: "TokenAccount".to_string(),
                discriminator: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }],
            vec![IdlTypeDef {
                name: "TokenAccount".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Type {
                    alias: IdlType::Defined {
                        name: "Account".to_string(),
                        generics: vec![],
                    },
                },
            }],
        );
        let output = generate(&idl).to_string();
        assert!(
            output.contains("pub type TokenAccount = Account"),
            "should generate type alias in state module, got: {}",
            output
        );
    }

    // -----------------------------------------------------------------------
    // #5: Tuple fields in state struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_tuple_fields_in_state_struct() {
        let idl = make_idl(
            vec![IdlAccount {
                name: "PairAccount".to_string(),
                discriminator: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            }],
            vec![IdlTypeDef {
                name: "PairAccount".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Tuple(vec![IdlType::U64, IdlType::Pubkey])),
                },
            }],
        );
        let output = generate(&idl).to_string();
        assert!(
            output.contains("pub 0"),
            "tuple struct fields should use indexed names, got: {}",
            output
        );
        assert!(output.contains("u64"), "should have u64 field");
        assert!(output.contains("Pubkey"), "should have Pubkey field");
        assert!(
            output.contains("DISCRIMINATOR"),
            "should still have discriminator"
        );
    }
}
