use anchor_lang_idl::types::{
    IdlArrayLen, IdlDefinedFields, IdlField, IdlRepr, IdlType, IdlTypeDefTy, Idl,
};
use quote::{format_ident, quote};

/// Generate a function to register account schemas for semantic field-level diffs.
///
/// For each zero-copy (repr(C)) account, generates a diff closure that uses
/// `bytemuck::from_bytes` to cast the raw data and compare each field.
/// Borsh accounts are skipped (they fall back to byte-level diffs).
pub fn generate(idl: &Idl) -> proc_macro2::TokenStream {
    let entries: Vec<_> = idl
        .accounts
        .iter()
        .filter_map(|acc| {
            // Look up the type definition
            let type_def = idl.types.iter().find(|t| t.name == acc.name)?;

            // Only handle zero-copy (repr(C)) struct accounts with named fields
            let is_zero_copy = matches!(&type_def.repr, Some(IdlRepr::C(_)));
            if !is_zero_copy {
                return None;
            }

            let named_fields = match &type_def.ty {
                IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Named(fields)),
                } => fields,
                _ => return None,
            };

            let type_name_str = &acc.name;
            let type_ident = format_ident!("{}", acc.name);
            let disc = &acc.discriminator;

            // Generate per-field comparisons
            let field_comparisons = generate_field_comparisons(named_fields);

            Some(quote! {
                crucible_test_context::AccountSchema {
                    type_name: #type_name_str.into(),
                    discriminator: vec![#(#disc),*],
                    diff_fn: Box::new(|pre_data: &[u8], post_data: &[u8]| {
                        let disc_len = state::#type_ident::DISCRIMINATOR_LEN;
                        let size = std::mem::size_of::<state::#type_ident>();
                        if pre_data.len() < disc_len + size || post_data.len() < disc_len + size {
                            return vec![];
                        }
                        let pre: &state::#type_ident = bytemuck::from_bytes(
                            &pre_data[disc_len..disc_len + size]
                        );
                        let post: &state::#type_ident = bytemuck::from_bytes(
                            &post_data[disc_len..disc_len + size]
                        );
                        let mut deltas = vec![];
                        #(#field_comparisons)*
                        deltas
                    }),
                }
            })
        })
        .collect();

    if entries.is_empty() {
        return quote! {
            /// Register account schemas for semantic field-level diffs.
            /// No zero-copy accounts found in IDL — this is a no-op.
            pub fn register_schemas() {}
        };
    }

    quote! {
        /// Register account schemas for semantic field-level diffs.
        /// Call this once at harness initialization (e.g., in setup()).
        pub fn register_schemas() {
            crucible_test_context::register_account_schemas(vec![
                #(#entries),*
            ]);
        }
    }
}

/// Generate field comparison code for each named field.
/// Returns a Vec of TokenStreams, one per field that can be meaningfully compared.
fn generate_field_comparisons(fields: &[IdlField]) -> Vec<proc_macro2::TokenStream> {
    fields
        .iter()
        .filter_map(|field| {
            // Skip padding fields
            if field.name.starts_with("_pad") || field.name.starts_with("_padding") {
                return None;
            }

            let field_name = format_ident!("{}", field.name);
            let field_name_str = &field.name;

            let format_expr = field_format_expr(&field.ty, &quote! { pre.#field_name }, &quote! { post.#field_name })?;

            Some(format_expr.wrap_comparison(field_name_str))
        })
        .collect()
}

/// Describes how to format and compare a field.
struct FieldFormatting {
    /// Expression to compare pre and post values (returns bool: true if equal)
    eq_expr: proc_macro2::TokenStream,
    /// Expression to format the pre value as a string
    pre_fmt: proc_macro2::TokenStream,
    /// Expression to format the post value as a string
    post_fmt: proc_macro2::TokenStream,
}

impl FieldFormatting {
    fn wrap_comparison(&self, field_name: &str) -> proc_macro2::TokenStream {
        let eq_expr = &self.eq_expr;
        let pre_fmt = &self.pre_fmt;
        let post_fmt = &self.post_fmt;
        quote! {
            if !(#eq_expr) {
                deltas.push(crucible_test_context::FieldDelta {
                    field: #field_name.to_string(),
                    old_value: #pre_fmt,
                    new_value: #post_fmt,
                });
            }
        }
    }
}

/// Generate format expressions for a field based on its IDL type.
/// Returns None for types that can't be meaningfully formatted.
fn field_format_expr(
    ty: &IdlType,
    pre: &proc_macro2::TokenStream,
    post: &proc_macro2::TokenStream,
) -> Option<FieldFormatting> {
    match ty {
        // Numeric primitives and bool — use Display
        IdlType::Bool | IdlType::U8 | IdlType::I8 | IdlType::U16 | IdlType::I16
        | IdlType::U32 | IdlType::I32 | IdlType::U64 | IdlType::I64
        | IdlType::U128 | IdlType::I128 | IdlType::F32 | IdlType::F64 => {
            Some(FieldFormatting {
                eq_expr: quote! { #pre == #post },
                pre_fmt: quote! { format!("{}", #pre) },
                post_fmt: quote! { format!("{}", #post) },
            })
        }

        // Pubkey — in zero-copy structs, Pubkey is [u8; 32] represented as Pubkey type
        IdlType::Pubkey => Some(FieldFormatting {
            eq_expr: quote! { #pre == #post },
            pre_fmt: quote! { #pre.to_string() },
            post_fmt: quote! { #post.to_string() },
        }),

        // Small byte arrays — hex format
        IdlType::Array(inner, len) => {
            let len_val = match len {
                IdlArrayLen::Value(n) => *n,
                _ => return None,
            };

            match inner.as_ref() {
                IdlType::U8 if len_val <= 32 => Some(FieldFormatting {
                    eq_expr: quote! { #pre[..] == #post[..] },
                    pre_fmt: quote! { format!("{:02x?}", &#pre[..]) },
                    post_fmt: quote! { format!("{:02x?}", &#post[..]) },
                }),
                // Skip large arrays and non-u8 arrays (e.g., [Tick; 88])
                _ => None,
            }
        }

        // Defined types (e.g., WrappedI80F48, BankConfig) — use raw byte comparison
        // We use unsafe ptr cast instead of bytemuck::bytes_of because inner enum
        // types (e.g., RiskTier) may not implement Pod/NoUninit.
        // Safety: the parent struct is repr(C) + Pod, so fields are at fixed offsets.
        IdlType::Defined { .. } => {
            Some(FieldFormatting {
                eq_expr: quote! {
                    {
                        let pre_bytes = unsafe {
                            std::slice::from_raw_parts(
                                &#pre as *const _ as *const u8,
                                std::mem::size_of_val(&#pre),
                            )
                        };
                        let post_bytes = unsafe {
                            std::slice::from_raw_parts(
                                &#post as *const _ as *const u8,
                                std::mem::size_of_val(&#post),
                            )
                        };
                        pre_bytes == post_bytes
                    }
                },
                pre_fmt: quote! {
                    {
                        let bytes = unsafe {
                            std::slice::from_raw_parts(
                                &#pre as *const _ as *const u8,
                                std::mem::size_of_val(&#pre).min(32),
                            )
                        };
                        format!("{:02x?}", bytes)
                    }
                },
                post_fmt: quote! {
                    {
                        let bytes = unsafe {
                            std::slice::from_raw_parts(
                                &#post as *const _ as *const u8,
                                std::mem::size_of_val(&#post).min(32),
                            )
                        };
                        format!("{:02x?}", bytes)
                    }
                },
            })
        }

        // Skip types that don't make sense in zero-copy (Option, Vec, String, etc.)
        _ => None,
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

    fn zero_copy_repr() -> Option<IdlRepr> {
        Some(IdlRepr::C(IdlReprModifier {
            packed: false,
            align: None,
        }))
    }

    fn rust_repr() -> Option<IdlRepr> {
        Some(IdlRepr::Rust(IdlReprModifier {
            packed: false,
            align: None,
        }))
    }

    /// Helper: build a zero-copy account with the given fields
    fn zc_account(name: &str, disc: Vec<u8>, fields: Vec<IdlField>) -> (IdlAccount, IdlTypeDef) {
        (
            IdlAccount { name: name.to_string(), discriminator: disc },
            IdlTypeDef {
                name: name.to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: zero_copy_repr(),
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Named(fields)),
                },
            },
        )
    }

    /// Helper: build a single named field
    fn field(name: &str, ty: IdlType) -> IdlField {
        IdlField { name: name.to_string(), docs: vec![], ty }
    }

    /// Parse generated TokenStream through syn to verify valid Rust syntax.
    /// The `state_stubs` parameter provides stub state structs so `state::Foo`
    /// references resolve.
    fn assert_valid_syntax(tokens: proc_macro2::TokenStream, state_stubs: proc_macro2::TokenStream) {
        let wrapped = quote! {
            mod test_wrapper {
                mod state {
                    #state_stubs
                }
                #tokens
            }
        };
        syn::parse2::<syn::File>(wrapped).unwrap_or_else(|e| {
            panic!("Generated schema code is not valid Rust syntax: {}", e);
        });
    }

    // -----------------------------------------------------------------------
    // Basic structure tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_zero_copy_account_generates_schema() {
        let disc = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let idl = make_idl(
            vec![IdlAccount {
                name: "Bank".to_string(),
                discriminator: disc.clone(),
            }],
            vec![IdlTypeDef {
                name: "Bank".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: zero_copy_repr(),
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Named(vec![
                        field("total_deposits", IdlType::U64),
                        field("mint", IdlType::Pubkey),
                    ])),
                },
            }],
        );
        let output = generate(&idl).to_string();
        assert!(output.contains("register_schemas"), "should generate register_schemas function");
        assert!(output.contains("\"Bank\""), "should have type name");
        assert!(output.contains("register_account_schemas"), "should call register_account_schemas");
        assert!(output.contains("bytemuck :: from_bytes"), "should use bytemuck for zero-copy");
        assert!(output.contains("total_deposits"), "should compare total_deposits field");
        assert!(output.contains("mint"), "should compare mint field");
        // Discriminator bytes should be present
        assert!(output.contains("17u8"), "should have discriminator byte 0x11");
    }

    #[test]
    fn test_borsh_account_skipped() {
        let idl = make_idl(
            vec![IdlAccount {
                name: "BorshAccount".to_string(),
                discriminator: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }],
            vec![IdlTypeDef {
                name: "BorshAccount".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None, // no repr(C) → borsh
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Named(vec![
                        field("value", IdlType::U64),
                    ])),
                },
            }],
        );
        let output = generate(&idl).to_string();
        assert!(output.contains("register_schemas"), "should still generate function");
        assert!(!output.contains("register_account_schemas"), "should NOT register borsh accounts");
        assert!(!output.contains("BorshAccount"), "should NOT contain borsh account name");
    }

    #[test]
    fn test_multiple_accounts() {
        let (acc1, ty1) = zc_account("Bank", vec![1, 2, 3, 4, 5, 6, 7, 8], vec![
            field("total", IdlType::U64),
        ]);
        let (acc2, ty2) = zc_account("Group", vec![9, 10, 11, 12, 13, 14, 15, 16], vec![
            field("admin", IdlType::Pubkey),
        ]);
        let idl = make_idl(vec![acc1, acc2], vec![ty1, ty2]);
        let output = generate(&idl).to_string();
        assert!(output.contains("\"Bank\""), "should have Bank entry");
        assert!(output.contains("\"Group\""), "should have Group entry");
        let schema_count = output.matches("AccountSchema").count();
        assert!(schema_count >= 2, "should have at least 2 AccountSchema entries, got {}", schema_count);
    }

    #[test]
    fn test_empty_accounts_generates_noop() {
        let idl = make_idl(vec![], vec![]);
        let output = generate(&idl).to_string();
        assert!(output.contains("register_schemas"), "should still generate function");
        assert!(!output.contains("register_account_schemas"), "empty IDL should not register anything");
    }

    #[test]
    fn test_enum_account_skipped() {
        let idl = make_idl(
            vec![IdlAccount {
                name: "EnumAccount".to_string(),
                discriminator: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }],
            vec![IdlTypeDef {
                name: "EnumAccount".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: zero_copy_repr(),
                generics: vec![],
                ty: IdlTypeDefTy::Enum { variants: vec![] },
            }],
        );
        let output = generate(&idl).to_string();
        assert!(!output.contains("\"EnumAccount\""), "enum accounts should be skipped");
    }

    #[test]
    fn test_type_alias_account_skipped() {
        let idl = make_idl(
            vec![IdlAccount {
                name: "AliasAccount".to_string(),
                discriminator: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }],
            vec![IdlTypeDef {
                name: "AliasAccount".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: zero_copy_repr(),
                generics: vec![],
                ty: IdlTypeDefTy::Type { alias: IdlType::U64 },
            }],
        );
        let output = generate(&idl).to_string();
        assert!(!output.contains("\"AliasAccount\""), "type alias accounts should be skipped");
    }

    #[test]
    fn test_account_with_missing_type_skipped() {
        let idl = make_idl(
            vec![IdlAccount {
                name: "Ghost".to_string(),
                discriminator: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }],
            vec![], // no type definition
        );
        let output = generate(&idl).to_string();
        assert!(!output.contains("\"Ghost\""), "account with no matching type should be skipped");
    }

    #[test]
    fn test_tuple_struct_account_skipped() {
        let idl = make_idl(
            vec![IdlAccount {
                name: "TupleAccount".to_string(),
                discriminator: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }],
            vec![IdlTypeDef {
                name: "TupleAccount".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: zero_copy_repr(),
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Tuple(vec![IdlType::U64, IdlType::Pubkey])),
                },
            }],
        );
        let output = generate(&idl).to_string();
        assert!(!output.contains("\"TupleAccount\""), "tuple struct accounts should be skipped (no named fields)");
    }

    #[test]
    fn test_repr_rust_account_skipped() {
        // repr(Rust) is NOT repr(C) — should be skipped
        let idl = make_idl(
            vec![IdlAccount {
                name: "RustReprAccount".to_string(),
                discriminator: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }],
            vec![IdlTypeDef {
                name: "RustReprAccount".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: rust_repr(),
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Named(vec![
                        field("value", IdlType::U64),
                    ])),
                },
            }],
        );
        let output = generate(&idl).to_string();
        assert!(!output.contains("\"RustReprAccount\""), "repr(Rust) accounts should be skipped");
    }

    // -----------------------------------------------------------------------
    // Padding / field filtering tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_padding_fields_skipped() {
        let (acc, ty) = zc_account("WithPadding", vec![1, 2, 3, 4, 5, 6, 7, 8], vec![
            field("value", IdlType::U64),
            field("_pad0", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(7))),
            field("_padding_0", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(32))),
            field("_pad1", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(4))),
            field("_padding_extra", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(16))),
        ]);
        let idl = make_idl(vec![acc], vec![ty]);
        let output = generate(&idl).to_string();
        assert!(output.contains("\"value\""), "should include value field");
        assert!(!output.contains("\"_pad0\""), "should skip _pad0");
        assert!(!output.contains("\"_pad1\""), "should skip _pad1");
        assert!(!output.contains("\"_padding_0\""), "should skip _padding_0");
        assert!(!output.contains("\"_padding_extra\""), "should skip _padding_extra");
    }

    // -----------------------------------------------------------------------
    // Per-type format tests: verify correct codegen for each IDL field type
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_bool() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("active", IdlType::Bool),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        assert!(output.contains("\"active\""), "bool field should be included");
        // Bool uses Display: format!("{}", ...)
        assert!(output.contains("pre . active == post . active"), "bool should use == comparison");
    }

    #[test]
    fn test_format_unsigned_integers() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("a_u8", IdlType::U8),
            field("a_u16", IdlType::U16),
            field("a_u32", IdlType::U32),
            field("a_u64", IdlType::U64),
            field("a_u128", IdlType::U128),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        for name in &["a_u8", "a_u16", "a_u32", "a_u64", "a_u128"] {
            assert!(output.contains(&format!("\"{}\"", name)),
                "unsigned integer field {} should be included", name);
        }
    }

    #[test]
    fn test_format_signed_integers() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("a_i8", IdlType::I8),
            field("a_i16", IdlType::I16),
            field("a_i32", IdlType::I32),
            field("a_i64", IdlType::I64),
            field("a_i128", IdlType::I128),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        for name in &["a_i8", "a_i16", "a_i32", "a_i64", "a_i128"] {
            assert!(output.contains(&format!("\"{}\"", name)),
                "signed integer field {} should be included", name);
        }
    }

    #[test]
    fn test_format_floats() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("rate_f32", IdlType::F32),
            field("rate_f64", IdlType::F64),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        assert!(output.contains("\"rate_f32\""), "f32 field should be included");
        assert!(output.contains("\"rate_f64\""), "f64 field should be included");
    }

    #[test]
    fn test_format_pubkey() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("owner", IdlType::Pubkey),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        assert!(output.contains("\"owner\""), "pubkey field should be included");
        // Pubkey uses .to_string()
        assert!(output.contains("to_string"), "pubkey should use to_string()");
    }

    #[test]
    fn test_format_small_byte_array() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("hash", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(16))),
            field("sig", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(32))),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        assert!(output.contains("\"hash\""), "[u8; 16] should be included");
        assert!(output.contains("\"sig\""), "[u8; 32] should be included (boundary)");
        // Hex format: {:02x?}
        assert!(output.contains("02x"), "small byte arrays should use hex format");
    }

    #[test]
    fn test_format_large_byte_array_skipped() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("small", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(16))),
            field("large_33", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(33))),
            field("large_64", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(64))),
            field("large_128", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(128))),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        assert!(output.contains("\"small\""), "[u8; 16] should be included");
        assert!(!output.contains("\"large_33\""), "[u8; 33] should be skipped");
        assert!(!output.contains("\"large_64\""), "[u8; 64] should be skipped");
        assert!(!output.contains("\"large_128\""), "[u8; 128] should be skipped");
    }

    #[test]
    fn test_format_non_u8_array_skipped() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("values", IdlType::Array(Box::new(IdlType::U64), IdlArrayLen::Value(4))),
            field("ticks", IdlType::Array(
                Box::new(IdlType::Defined { name: "Tick".into(), generics: vec![] }),
                IdlArrayLen::Value(88),
            )),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        assert!(!output.contains("\"values\""), "[u64; 4] should be skipped");
        assert!(!output.contains("\"ticks\""), "[Tick; 88] should be skipped");
    }

    #[test]
    fn test_format_defined_type() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("config", IdlType::Defined { name: "BankConfig".into(), generics: vec![] }),
            field("wrapped", IdlType::Defined { name: "WrappedI80F48".into(), generics: vec![] }),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        assert!(output.contains("\"config\""), "defined type field should be included");
        assert!(output.contains("\"wrapped\""), "defined type field should be included");
        // Defined types use raw ptr byte comparison
        assert!(output.contains("from_raw_parts"), "defined types should use raw ptr cast");
        assert!(output.contains("size_of_val"), "defined types should use size_of_val");
    }

    #[test]
    fn test_format_option_skipped() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("maybe", IdlType::Option(Box::new(IdlType::U64))),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        assert!(!output.contains("\"maybe\""), "Option fields should be skipped in zero-copy");
    }

    #[test]
    fn test_format_vec_skipped() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("items", IdlType::Vec(Box::new(IdlType::U64))),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        assert!(!output.contains("\"items\""), "Vec fields should be skipped in zero-copy");
    }

    #[test]
    fn test_format_string_skipped() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("name", IdlType::String),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        assert!(!output.contains("\"name\""), "String fields should be skipped in zero-copy");
    }

    #[test]
    fn test_format_generic_array_len_skipped() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("data", IdlType::Array(
                Box::new(IdlType::U8),
                IdlArrayLen::Generic("N".into()),
            )),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        assert!(!output.contains("\"data\""), "generic array length should be skipped");
    }

    // -----------------------------------------------------------------------
    // Mixed account tests (zero-copy + borsh in same IDL)
    // -----------------------------------------------------------------------

    #[test]
    fn test_mixed_zero_copy_and_borsh_accounts() {
        let (zc_acc, zc_ty) = zc_account("ZcAccount", vec![1,2,3,4,5,6,7,8], vec![
            field("value", IdlType::U64),
        ]);
        let idl = make_idl(
            vec![
                zc_acc,
                IdlAccount {
                    name: "BorshAccount".to_string(),
                    discriminator: vec![9,10,11,12,13,14,15,16],
                },
            ],
            vec![
                zc_ty,
                IdlTypeDef {
                    name: "BorshAccount".to_string(),
                    docs: vec![],
                    serialization: Default::default(),
                    repr: None,
                    generics: vec![],
                    ty: IdlTypeDefTy::Struct {
                        fields: Some(IdlDefinedFields::Named(vec![
                            field("data", IdlType::U64),
                        ])),
                    },
                },
            ],
        );
        let output = generate(&idl).to_string();
        assert!(output.contains("\"ZcAccount\""), "zero-copy account should be registered");
        assert!(!output.contains("\"BorshAccount\""), "borsh account should NOT be registered");
        // Should still produce the register_account_schemas call
        assert!(output.contains("register_account_schemas"), "should register the zero-copy one");
    }

    #[test]
    fn test_all_borsh_accounts_generates_noop() {
        let idl = make_idl(
            vec![
                IdlAccount { name: "A".into(), discriminator: vec![1,2,3,4,5,6,7,8] },
                IdlAccount { name: "B".into(), discriminator: vec![9,10,11,12,13,14,15,16] },
            ],
            vec![
                IdlTypeDef {
                    name: "A".to_string(), docs: vec![], serialization: Default::default(),
                    repr: None, generics: vec![],
                    ty: IdlTypeDefTy::Struct {
                        fields: Some(IdlDefinedFields::Named(vec![field("x", IdlType::U64)])),
                    },
                },
                IdlTypeDef {
                    name: "B".to_string(), docs: vec![], serialization: Default::default(),
                    repr: None, generics: vec![],
                    ty: IdlTypeDefTy::Struct {
                        fields: Some(IdlDefinedFields::Named(vec![field("y", IdlType::U64)])),
                    },
                },
            ],
        );
        let output = generate(&idl).to_string();
        assert!(output.contains("register_schemas"), "should still generate function");
        assert!(!output.contains("register_account_schemas"), "all-borsh should be noop");
    }

    // -----------------------------------------------------------------------
    // Discriminator format tests (4-byte vs 8-byte)
    // -----------------------------------------------------------------------

    #[test]
    fn test_4_byte_discriminator_preserved() {
        let (acc, ty) = zc_account("Native", vec![1, 0, 0, 0], vec![
            field("value", IdlType::U64),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        assert!(output.contains("\"Native\""), "should register native account");
        assert!(output.contains("1u8"), "should have discriminator byte 1");
        // Should use 4-byte discriminator length from state::Native::DISCRIMINATOR_LEN
        assert!(output.contains("state :: Native :: DISCRIMINATOR_LEN"));
    }

    #[test]
    fn test_8_byte_discriminator_preserved() {
        let disc = vec![0xAB, 0xCD, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let (acc, ty) = zc_account("Anchor", disc.clone(), vec![
            field("value", IdlType::U64),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        // All 8 discriminator bytes should appear
        for byte in &disc {
            let byte_str = format!("{}u8", byte);
            assert!(output.contains(&byte_str),
                "discriminator byte {} should appear in output", byte_str);
        }
    }

    // -----------------------------------------------------------------------
    // Comprehensive field-type combination: syntax validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_syntax_all_primitive_types() {
        // Account with every primitive type — verify generated code parses
        let (acc, ty) = zc_account("AllPrimitives", vec![1,2,3,4,5,6,7,8], vec![
            field("f_bool", IdlType::Bool),
            field("f_u8", IdlType::U8),
            field("f_i8", IdlType::I8),
            field("f_u16", IdlType::U16),
            field("f_i16", IdlType::I16),
            field("f_u32", IdlType::U32),
            field("f_i32", IdlType::I32),
            field("f_u64", IdlType::U64),
            field("f_i64", IdlType::I64),
            field("f_u128", IdlType::U128),
            field("f_i128", IdlType::I128),
            field("f_f32", IdlType::F32),
            field("f_f64", IdlType::F64),
        ]);
        let tokens = generate(&make_idl(vec![acc], vec![ty]));
        assert_valid_syntax(tokens, quote! {
            pub struct AllPrimitives;
            impl AllPrimitives { pub const DISCRIMINATOR_LEN: usize = 8; }
        });
    }

    #[test]
    fn test_syntax_mixed_field_types() {
        // Account mixing primitives, pubkey, arrays, defined types, and padding
        let (acc, ty) = zc_account("MixedAccount", vec![0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22], vec![
            field("balance", IdlType::U64),
            field("owner", IdlType::Pubkey),
            field("active", IdlType::Bool),
            field("data", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(16))),
            field("config", IdlType::Defined { name: "Config".into(), generics: vec![] }),
            field("_pad0", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(7))),
            field("rate", IdlType::F64),
            field("count", IdlType::I32),
            field("big", IdlType::U128),
            field("sig", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(32))),
            field("large_skip", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(128))),
            field("items_skip", IdlType::Vec(Box::new(IdlType::U64))),
            field("maybe_skip", IdlType::Option(Box::new(IdlType::U64))),
        ]);
        let tokens = generate(&make_idl(vec![acc], vec![ty]));
        assert_valid_syntax(tokens, quote! {
            pub struct MixedAccount;
            impl MixedAccount { pub const DISCRIMINATOR_LEN: usize = 8; }
        });
    }

    #[test]
    fn test_syntax_multiple_zero_copy_accounts() {
        // Multiple accounts, each with different field patterns
        let (acc1, ty1) = zc_account("Bank", vec![1,2,3,4,5,6,7,8], vec![
            field("mint", IdlType::Pubkey),
            field("total_deposits", IdlType::U64),
            field("total_borrows", IdlType::U64),
            field("config", IdlType::Defined { name: "BankConfig".into(), generics: vec![] }),
            field("_pad0", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(7))),
        ]);
        let (acc2, ty2) = zc_account("Account", vec![9,10,11,12,13,14,15,16], vec![
            field("authority", IdlType::Pubkey),
            field("group", IdlType::Pubkey),
            field("flags", IdlType::U64),
            field("lending_account", IdlType::Defined { name: "LendingAccount".into(), generics: vec![] }),
        ]);
        let tokens = generate(&make_idl(vec![acc1, acc2], vec![ty1, ty2]));
        assert_valid_syntax(tokens, quote! {
            pub struct Bank;
            impl Bank { pub const DISCRIMINATOR_LEN: usize = 8; }
            pub struct Account;
            impl Account { pub const DISCRIMINATOR_LEN: usize = 8; }
        });
    }

    #[test]
    fn test_syntax_only_skippable_fields() {
        // Account where ALL fields are skippable — should still generate valid code
        let (acc, ty) = zc_account("AllSkipped", vec![1,2,3,4,5,6,7,8], vec![
            field("_pad0", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(7))),
            field("large", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(128))),
            field("ticks", IdlType::Array(
                Box::new(IdlType::Defined { name: "Tick".into(), generics: vec![] }),
                IdlArrayLen::Value(88),
            )),
        ]);
        let tokens = generate(&make_idl(vec![acc], vec![ty]));
        // Even with no comparable fields, the schema should still be registered
        // (it just produces an empty deltas vec)
        let output = tokens.to_string();
        assert!(output.contains("\"AllSkipped\""), "account with only skippable fields should still be registered");
        assert_valid_syntax(tokens.clone(), quote! {
            pub struct AllSkipped;
            impl AllSkipped { pub const DISCRIMINATOR_LEN: usize = 8; }
        });
    }

    // -----------------------------------------------------------------------
    // Field comparison codegen detail tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_primitive_uses_eq_operator() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("count", IdlType::U64),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        // Primitives compare with ==
        assert!(output.contains("pre . count == post . count"),
            "primitive should use direct == comparison, got: {}", output);
    }

    #[test]
    fn test_pubkey_uses_to_string() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("owner", IdlType::Pubkey),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        // Pubkey formats with .to_string()
        assert!(output.contains("pre . owner . to_string"),
            "pubkey should use .to_string(), got: {}", output);
    }

    #[test]
    fn test_byte_array_uses_slice_comparison() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("hash", IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(16))),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        // Byte arrays compare with [..] == [..]
        assert!(output.contains("pre . hash [..] == post . hash [..]"),
            "byte array should use slice comparison, got: {}", output);
    }

    #[test]
    fn test_defined_uses_unsafe_ptr_cast() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("config", IdlType::Defined { name: "C".into(), generics: vec![] }),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        // Defined types use unsafe raw pointer cast for byte comparison
        assert!(output.contains("from_raw_parts"),
            "defined should use from_raw_parts, got: {}", output);
        assert!(output.contains("as * const _ as * const u8"),
            "defined should cast to *const u8, got: {}", output);
    }

    // -----------------------------------------------------------------------
    // FieldDelta output structure tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_deltas_push_has_field_name() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("balance", IdlType::U64),
            field("mint", IdlType::Pubkey),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        // Each field produces a FieldDelta push with the field name
        assert!(output.contains("\"balance\" . to_string ()"), "should push field name 'balance'");
        assert!(output.contains("\"mint\" . to_string ()"), "should push field name 'mint'");
        // old_value and new_value should be present
        assert!(output.contains("old_value"), "should have old_value in FieldDelta");
        assert!(output.contains("new_value"), "should have new_value in FieldDelta");
    }

    #[test]
    fn test_diff_closure_signature() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("x", IdlType::U64),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        // Diff closure takes (pre_data: &[u8], post_data: &[u8])
        assert!(output.contains("pre_data : & [u8]"), "diff closure should take pre_data: &[u8]");
        assert!(output.contains("post_data : & [u8]"), "diff closure should take post_data: &[u8]");
        // Returns vec of deltas
        assert!(output.contains("let mut deltas = vec ! []"), "should initialize deltas vec");
    }

    #[test]
    fn test_data_length_guard() {
        let (acc, ty) = zc_account("A", vec![1,2,3,4,5,6,7,8], vec![
            field("x", IdlType::U64),
        ]);
        let output = generate(&make_idl(vec![acc], vec![ty])).to_string();
        // Should check data length before casting
        assert!(output.contains("pre_data . len () < disc_len + size"),
            "should guard against undersized pre_data");
        assert!(output.contains("post_data . len () < disc_len + size"),
            "should guard against undersized post_data");
    }
}
