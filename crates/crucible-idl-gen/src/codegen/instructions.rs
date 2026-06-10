use anchor_lang_idl::types::{
    Idl, IdlArrayLen, IdlDefinedFields, IdlEnumVariant, IdlType, IdlTypeDef, IdlTypeDefTy,
};
use heck::ToUpperCamelCase;
use quote::{format_ident, quote};

use super::idl_type_to_tokens;

/// Generate instruction argument structs
///
/// `use_bincode`: native (non-Anchor) programs encode instruction args with
/// bincode (fixint, little-endian), not borsh. For those, arg structs override
/// `InstructionData::data()` to emit the 4-byte discriminator followed by
/// field-wise bincode-compatible writes. This preserves correct u64 length
/// prefixes for `Vec`/`String`/bytes args (borsh would emit u32), u32 enum
/// variant tags, and fixed-array bytes even when serde cannot derive
/// `Serialize` for arrays larger than 32. Anchor (8-byte) programs keep the
/// default borsh `InstructionData` path.
pub fn generate(idl: &Idl, use_bincode: bool) -> proc_macro2::TokenStream {
    let instructions = idl.instructions.iter().map(|ix| {
        let name = format_ident!("{}", ix.name.to_upper_camel_case());

        // Generate fields
        let fields = ix.args.iter().map(|arg| {
            let field_name = format_ident!("{}", arg.name);
            let field_type = idl_type_to_tokens(&arg.ty);
            quote! { pub #field_name: #field_type }
        });

        // Generate discriminator
        let discriminator = &ix.discriminator;
        let bincode_writes: Vec<_> = ix
            .args
            .iter()
            .map(|arg| {
                let field_name = format_ident!("{}", arg.name);
                bincode_write_field(quote! { self.#field_name }, &arg.ty, &idl.types)
            })
            .collect();

        // Struct with derives
        if ix.args.is_empty() {
            // No args: borsh and bincode both serialize to nothing, so the
            // default InstructionData path (discriminator only) is correct
            // for both encodings.
            quote! {
                #[derive(Clone, AnchorSerialize, AnchorDeserialize)]
                pub struct #name;

                impl anchor_lang::Discriminator for #name {
                    const DISCRIMINATOR: &'static [u8] = &[#(#discriminator),*];
                }

                impl anchor_lang::InstructionData for #name {}
            }
        } else if use_bincode {
            quote! {
                #[derive(Clone, AnchorSerialize, AnchorDeserialize)]
                pub struct #name {
                    #(#fields),*
                }

                impl anchor_lang::Discriminator for #name {
                    const DISCRIMINATOR: &'static [u8] = &[#(#discriminator),*];
                }

                impl anchor_lang::InstructionData for #name {
                    fn data(&self) -> Vec<u8> {
                        let mut data = Self::DISCRIMINATOR.to_vec();
                        #(#bincode_writes)*
                        data
                    }

                    fn write_to(&self, data: &mut Vec<u8>) {
                        data.clear();
                        data.extend_from_slice(Self::DISCRIMINATOR);
                        #(#bincode_writes)*
                    }
                }
            }
        } else {
            quote! {
                #[derive(Clone, AnchorSerialize, AnchorDeserialize)]
                pub struct #name {
                    #(#fields),*
                }

                impl anchor_lang::Discriminator for #name {
                    const DISCRIMINATOR: &'static [u8] = &[#(#discriminator),*];
                }

                impl anchor_lang::InstructionData for #name {}
            }
        }
    });

    quote! {
        /// Instruction argument structs
        pub mod instruction {
            use super::*;
            use super::types::*;

            #(#instructions)*
        }
    }
}

fn bincode_write_field(
    value: proc_macro2::TokenStream,
    ty: &IdlType,
    all_types: &[IdlTypeDef],
) -> proc_macro2::TokenStream {
    match ty {
        IdlType::String => {
            let write_len = bincode_write_len(quote! { __bytes.len() });
            quote! {
                let __bytes = #value.as_bytes();
                #write_len
                data.extend_from_slice(__bytes);
            }
        }
        IdlType::Bytes => bincode_write_bytes(value),
        IdlType::Vec(inner) if matches!(inner.as_ref(), IdlType::U8) => bincode_write_bytes(value),
        IdlType::Vec(inner) => {
            let write_len = bincode_write_len(quote! { #value.len() });
            let write_item = bincode_write_field(quote! { __item }, inner, all_types);
            quote! {
                #write_len
                for __item in #value.iter() {
                    #write_item
                }
            }
        }
        IdlType::Option(inner) => {
            let write_some = bincode_write_field(quote! { __value }, inner, all_types);
            quote! {
                match &#value {
                    Some(__value) => {
                        data.push(1u8);
                        #write_some
                    }
                    None => data.push(0u8),
                }
            }
        }
        IdlType::Array(inner, IdlArrayLen::Value(_) | IdlArrayLen::Generic(_)) => {
            if matches!(inner.as_ref(), IdlType::U8) {
                quote! {
                    data.extend_from_slice(#value.as_ref());
                }
            } else {
                let write_item = bincode_write_field(quote! { __item }, inner, all_types);
                quote! {
                    for __item in #value.iter() {
                        #write_item
                    }
                }
            }
        }
        IdlType::U256 | IdlType::I256 => {
            quote! {
                data.extend_from_slice(#value.as_ref());
            }
        }
        IdlType::Defined { name, generics } if generics.is_empty() => all_types
            .iter()
            .find(|typedef| typedef.name == *name)
            .map(|typedef| bincode_write_defined(value.clone(), typedef, all_types))
            .unwrap_or_else(|| bincode_write_serde(value)),
        _ => bincode_write_serde(value),
    }
}

fn bincode_write_bytes(value: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    let write_len = bincode_write_len(quote! { __bytes.len() });
    quote! {
        let __bytes = #value.as_slice();
        #write_len
        data.extend_from_slice(__bytes);
    }
}

fn bincode_write_len(len_expr: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    quote! {
        ::bincode::serialize_into(&mut data, &(#len_expr as u64))
            .expect("bincode-serialize instruction arg length");
    }
}

fn bincode_write_serde(value: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    quote! {
        ::bincode::serialize_into(&mut data, &#value)
            .expect("bincode-serialize instruction arg");
    }
}

fn bincode_write_defined(
    value: proc_macro2::TokenStream,
    typedef: &IdlTypeDef,
    all_types: &[IdlTypeDef],
) -> proc_macro2::TokenStream {
    match &typedef.ty {
        IdlTypeDefTy::Struct { fields } => bincode_write_defined_fields(value, fields, all_types),
        IdlTypeDefTy::Type { alias } => bincode_write_field(value, alias, all_types),
        IdlTypeDefTy::Enum { variants } => {
            bincode_write_defined_enum(value, &typedef.name, variants, all_types)
        }
    }
}

fn bincode_write_defined_fields(
    value: proc_macro2::TokenStream,
    fields: &Option<IdlDefinedFields>,
    all_types: &[IdlTypeDef],
) -> proc_macro2::TokenStream {
    match fields {
        Some(IdlDefinedFields::Named(named)) => {
            let writes = named.iter().map(|field| {
                let field_name = format_ident!("{}", field.name);
                bincode_write_field(quote! { #value.#field_name }, &field.ty, all_types)
            });
            quote! { #(#writes)* }
        }
        Some(IdlDefinedFields::Tuple(tuple)) => {
            let writes = tuple.iter().enumerate().map(|(i, ty)| {
                let field_index = syn::Index::from(i);
                bincode_write_field(quote! { #value.#field_index }, ty, all_types)
            });
            quote! { #(#writes)* }
        }
        None => quote! {},
    }
}

fn bincode_write_defined_enum(
    value: proc_macro2::TokenStream,
    enum_name: &str,
    variants: &[IdlEnumVariant],
    all_types: &[IdlTypeDef],
) -> proc_macro2::TokenStream {
    let enum_ident = format_ident!("{}", enum_name);
    let arms = variants.iter().enumerate().map(|(idx, variant)| {
        let variant_ident = format_ident!("{}", variant.name.to_upper_camel_case());
        let idx = idx as u32;
        let write_idx = quote! {
            ::bincode::serialize_into(&mut data, &#idx)
                .expect("bincode-serialize instruction enum variant");
        };

        match &variant.fields {
            Some(IdlDefinedFields::Named(named)) => {
                let bindings: Vec<_> = (0..named.len())
                    .map(|i| format_ident!("__field_{i}"))
                    .collect();
                let pattern_fields = named.iter().zip(bindings.iter()).map(|(field, binding)| {
                    let field_name = format_ident!("{}", field.name);
                    quote! { #field_name: #binding }
                });
                let writes = named.iter().zip(bindings.iter()).map(|(field, binding)| {
                    bincode_write_field(quote! { #binding }, &field.ty, all_types)
                });
                quote! {
                    #enum_ident::#variant_ident { #(#pattern_fields),* } => {
                        #write_idx
                        #(#writes)*
                    }
                }
            }
            Some(IdlDefinedFields::Tuple(tuple)) => {
                let bindings: Vec<_> = (0..tuple.len())
                    .map(|i| format_ident!("__field_{i}"))
                    .collect();
                let writes = tuple
                    .iter()
                    .zip(bindings.iter())
                    .map(|(ty, binding)| bincode_write_field(quote! { #binding }, ty, all_types));
                quote! {
                    #enum_ident::#variant_ident(#(#bindings),*) => {
                        #write_idx
                        #(#writes)*
                    }
                }
            }
            None => {
                quote! {
                    #enum_ident::#variant_ident => {
                        #write_idx
                    }
                }
            }
        }
    });

    quote! {
        match &#value {
            #(#arms),*
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang_idl::types::{IdlField, IdlInstruction, IdlMetadata, IdlType};

    fn make_idl(instructions: Vec<IdlInstruction>) -> Idl {
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
            instructions,
            accounts: vec![],
            events: vec![],
            errors: vec![],
            types: vec![],
            constants: vec![],
        }
    }

    #[test]
    fn test_4_byte_discriminator() {
        let idl = make_idl(vec![IdlInstruction {
            name: "initialize".to_string(),
            docs: vec![],
            discriminator: vec![0, 0, 0, 0],
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl, false).to_string();
        assert!(
            output.contains("DISCRIMINATOR"),
            "should have DISCRIMINATOR const"
        );
        assert!(
            output.contains("0u8 , 0u8 , 0u8 , 0u8"),
            "should emit 4 bytes"
        );
    }

    #[test]
    fn test_8_byte_discriminator() {
        let idl = make_idl(vec![IdlInstruction {
            name: "initialize".to_string(),
            docs: vec![],
            discriminator: vec![231, 205, 66, 242, 220, 87, 145, 38],
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl, false).to_string();
        assert!(output.contains("231u8"), "should emit first byte");
        assert!(output.contains("38u8"), "should emit last byte");
    }

    #[test]
    fn test_empty_args_unit_struct() {
        let idl = make_idl(vec![IdlInstruction {
            name: "doNothing".to_string(),
            docs: vec![],
            discriminator: vec![1, 0, 0, 0],
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl, false).to_string();
        // Should generate a unit struct (no braces with fields)
        assert!(
            output.contains("pub struct DoNothing ;"),
            "empty args should produce unit struct"
        );
    }

    #[test]
    fn test_instruction_with_args() {
        let idl = make_idl(vec![IdlInstruction {
            name: "transfer".to_string(),
            docs: vec![],
            discriminator: vec![2, 0, 0, 0],
            accounts: vec![],
            args: vec![
                IdlField {
                    name: "amount".to_string(),
                    docs: vec![],
                    ty: IdlType::U64,
                },
                IdlField {
                    name: "memo".to_string(),
                    docs: vec![],
                    ty: IdlType::String,
                },
            ],
            returns: None,
        }]);
        let output = generate(&idl, false).to_string();
        assert!(
            output.contains("pub amount : u64"),
            "should have amount field"
        );
        assert!(
            output.contains("pub memo : String"),
            "should have memo field"
        );
    }

    #[test]
    fn test_instruction_name_upper_camel_case() {
        let idl = make_idl(vec![IdlInstruction {
            name: "delegateStake".to_string(),
            docs: vec![],
            discriminator: vec![2, 0, 0, 0],
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl, false).to_string();
        assert!(
            output.contains("DelegateStake"),
            "should convert to UpperCamelCase"
        );
    }

    // -----------------------------------------------------------------------
    // Native (bincode) instruction-arg encoding
    // -----------------------------------------------------------------------

    fn make_native_transfer_ix() -> IdlInstruction {
        IdlInstruction {
            name: "transfer".to_string(),
            docs: vec![],
            discriminator: vec![2, 0, 0, 0],
            accounts: vec![],
            args: vec![
                IdlField {
                    name: "data".to_string(),
                    docs: vec![],
                    ty: IdlType::Vec(Box::new(IdlType::U8)),
                },
                IdlField {
                    name: "memo".to_string(),
                    docs: vec![],
                    ty: IdlType::String,
                },
                IdlField {
                    name: "tag".to_string(),
                    docs: vec![],
                    ty: IdlType::Option(Box::new(IdlType::U32)),
                },
            ],
            returns: None,
        }
    }

    #[test]
    fn test_bincode_args_use_bincode_data() {
        let idl = make_idl(vec![make_native_transfer_ix()]);
        let tokens = generate(&idl, true);
        let output = tokens.to_string();

        // custom data() using bincode, not the default borsh path
        assert!(
            output.contains("fn data (& self)"),
            "bincode instruction should override data(), got: {output}"
        );
        assert!(
            output.contains("bincode :: serialize_into"),
            "data() should serialize dynamic args with bincode-compatible writes, got: {output}"
        );
        assert!(
            output.contains("fn write_to"),
            "bincode instruction should override write_to(), got: {output}"
        );
        // discriminator still prepended
        assert!(
            output.contains("DISCRIMINATOR . to_vec ()"),
            "data() should start with the discriminator, got: {output}"
        );

        // generated code must be valid Rust
        syn::parse2::<syn::File>(tokens).expect("bincode instruction codegen should parse");
    }

    #[test]
    fn test_borsh_args_keep_default_instruction_data() {
        let idl = make_idl(vec![make_native_transfer_ix()]);
        let output = generate(&idl, false).to_string();

        assert!(
            !output.contains("bincode"),
            "borsh instruction should not reference bincode"
        );
        assert!(
            !output.contains("fn data"),
            "borsh instruction should use the default InstructionData::data()"
        );
        assert!(
            !output.contains("serde :: Serialize"),
            "borsh instruction should not derive serde::Serialize"
        );
    }

    #[test]
    fn test_bincode_args_with_large_array_keep_bincode_path() {
        // serde can't Serialize arrays > 32 elements, but fixed arrays still
        // encode identically field-wise and must not force dynamic fields onto
        // the borsh path.
        use anchor_lang_idl::types::IdlArrayLen;
        let idl = make_idl(vec![IdlInstruction {
            name: "writeBlob".to_string(),
            docs: vec![],
            discriminator: vec![9, 0, 0, 0],
            accounts: vec![],
            args: vec![
                IdlField {
                    name: "blob".to_string(),
                    docs: vec![],
                    ty: IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(64)),
                },
                IdlField {
                    name: "memo".to_string(),
                    docs: vec![],
                    ty: IdlType::String,
                },
                IdlField {
                    name: "tag".to_string(),
                    docs: vec![],
                    ty: IdlType::Option(Box::new(IdlType::U32)),
                },
            ],
            returns: None,
        }]);
        let tokens = generate(&idl, true);
        let output = tokens.to_string();
        assert!(
            !output.contains("serde :: Serialize"),
            "large-array args should not need serde::Serialize"
        );
        assert!(
            output.contains("fn data (& self)"),
            "large-array args should still override data(), got: {output}"
        );
        assert!(
            output.contains("extend_from_slice"),
            "large u8 array should be copied as raw fixed bytes, got: {output}"
        );
        assert!(
            output.contains("bincode :: serialize_into"),
            "dynamic fields mixed with large arrays should still use bincode lengths/tags, got: {output}"
        );
        syn::parse2::<syn::File>(tokens)
            .expect("large-array bincode instruction codegen should parse");
    }

    #[test]
    fn test_bincode_empty_args_keep_default_path() {
        // No args → borsh and bincode serialize identically (just the
        // discriminator), so the default path is kept.
        let idl = make_idl(vec![IdlInstruction {
            name: "deactivate".to_string(),
            docs: vec![],
            discriminator: vec![5, 0, 0, 0],
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl, true).to_string();
        assert!(
            !output.contains("bincode"),
            "empty-arg bincode instruction should keep default InstructionData"
        );
        assert!(
            output.contains("pub struct Deactivate ;"),
            "should still emit unit struct"
        );
    }

    #[test]
    fn test_instruction_data_trait() {
        let idl = make_idl(vec![IdlInstruction {
            name: "init".to_string(),
            docs: vec![],
            discriminator: vec![0, 0, 0, 0],
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl, false).to_string();
        assert!(
            output.contains("InstructionData"),
            "should impl InstructionData"
        );
        assert!(
            output.contains("Discriminator"),
            "should impl Discriminator"
        );
    }
}
