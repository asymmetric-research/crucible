use anchor_lang_idl::types::{
    Idl, IdlDefinedFields, IdlRepr, IdlTypeDef, IdlTypeDefGeneric, IdlTypeDefTy,
};
use heck::ToUpperCamelCase;
use quote::{format_ident, quote};

use super::generics::{generic_params_decl, generic_params_use, type_generic_bounds};
use super::{array_len_to_usize, fields_serde_serializable, idl_type_to_tokens};

/// Generate custom type definitions from IDL types section
pub fn generate(idl: &Idl, use_bincode: bool) -> proc_macro2::TokenStream {
    let type_defs = idl
        .types
        .iter()
        .map(|td| generate_type_def(td, &idl.types, use_bincode));

    quote! {
        /// Custom type definitions
        pub mod types {
            use super::*;

            #(#type_defs)*
        }
    }
}

fn generate_type_def(
    typedef: &IdlTypeDef,
    all_types: &[IdlTypeDef],
    use_bincode: bool,
) -> proc_macro2::TokenStream {
    let name = format_ident!("{}", typedef.name);
    let generics = &typedef.generics;

    // Check if this is a zero-copy type (repr: C)
    let is_zero_copy = matches!(&typedef.repr, Some(IdlRepr::C(_)));

    // Bincode programs can still benefit from serde derives for defined types
    // that are serializable as a whole. Guard: serde has no Serialize impl for
    // arrays > 32 elements, so those types rely on instruction field-wise
    // encoding instead of deriving serde.
    let derive_serde = use_bincode
        && typedef.generics.is_empty()
        && typedef_serde_serializable(typedef, all_types);

    match &typedef.ty {
        IdlTypeDefTy::Struct { fields } => {
            if is_zero_copy {
                generate_zero_copy_struct(&name, fields, &typedef.name, generics, derive_serde)
            } else {
                generate_struct(
                    &name,
                    fields,
                    &typedef.name,
                    all_types,
                    generics,
                    derive_serde,
                )
            }
        }
        IdlTypeDefTy::Enum { variants } => generate_enum(
            &name,
            variants,
            all_types,
            use_bincode,
            generics,
            derive_serde,
        ),
        IdlTypeDefTy::Type { alias } => {
            let alias_ty = idl_type_to_tokens(alias);
            let decl = generic_params_decl(generics);
            quote! {
                pub type #name #decl = #alias_ty;
            }
        }
    }
}

fn generate_struct(
    name: &syn::Ident,
    fields: &Option<IdlDefinedFields>,
    type_name: &str,
    all_types: &[IdlTypeDef],
    generics: &[IdlTypeDefGeneric],
    derive_serde: bool,
) -> proc_macro2::TokenStream {
    let decl = generic_params_decl(generics);
    let serde_derive = serde_serialize_derive(derive_serde);
    let fields_tokens = match fields {
        Some(IdlDefinedFields::Named(named_fields)) => {
            let field_tokens = named_fields.iter().map(|f| {
                let field_name = format_ident!("{}", f.name);
                let field_type = idl_type_to_tokens(&f.ty);
                quote! { pub #field_name: #field_type }
            });
            quote! { #(#field_tokens),* }
        }
        Some(IdlDefinedFields::Tuple(tuple_fields)) => {
            let field_tokens = tuple_fields.iter().map(idl_type_to_tokens);
            // Tuple struct — check if all fields support Copy
            let can_copy = tuple_fields.iter().all(|t| is_copy_type(t, all_types));
            let derives = if can_copy {
                quote! { #[derive(Clone, Copy, Default, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] }
            } else {
                quote! { #[derive(Clone, Default, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] }
            };
            return quote! {
                #derives
                #serde_derive
                pub struct #name #decl (#(pub #field_tokens),*);
            };
        }
        None => quote! {},
    };

    // Check if this is a wrapped numeric type (like WrappedI80F48)
    let extra_impls = generate_extra_impls(type_name, fields);

    // Determine if we should add Copy and Eq based on field types
    let can_copy = should_derive_copy(fields, all_types);
    let can_eq = fields
        .as_ref()
        .map_or(true, |f| can_derive_eq_fields(f, all_types));
    let can_derive_default = fields
        .as_ref()
        .map_or(true, |f| can_derive_default_fields(f));

    // Build derives without Default (we'll implement it manually if needed)
    let derives = match (can_copy, can_eq) {
        (true, true) => {
            if can_derive_default {
                quote! { #[derive(Clone, Copy, Default, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] }
            } else {
                quote! { #[derive(Clone, Copy, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] }
            }
        }
        (true, false) => {
            if can_derive_default {
                quote! { #[derive(Clone, Copy, Default, AnchorSerialize, AnchorDeserialize, PartialEq)] }
            } else {
                quote! { #[derive(Clone, Copy, AnchorSerialize, AnchorDeserialize, PartialEq)] }
            }
        }
        (false, true) => {
            if can_derive_default {
                quote! { #[derive(Clone, Default, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] }
            } else {
                quote! { #[derive(Clone, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] }
            }
        }
        (false, false) => {
            if can_derive_default {
                quote! { #[derive(Clone, Default, AnchorSerialize, AnchorDeserialize, PartialEq)] }
            } else {
                quote! { #[derive(Clone, AnchorSerialize, AnchorDeserialize, PartialEq)] }
            }
        }
    };

    // Generate manual Default impl if we can't derive it
    let default_impl = if !can_derive_default {
        generate_manual_default(name, fields, generics)
    } else {
        quote! {}
    };

    quote! {
        #derives
        #serde_derive
        pub struct #name #decl {
            #fields_tokens
        }

        #default_impl
        #extra_impls
    }
}

/// Emit an extra `#[derive(serde::Serialize)]` attribute for bincode programs.
fn serde_serialize_derive(derive_serde: bool) -> proc_macro2::TokenStream {
    if derive_serde {
        quote! { #[derive(serde::Serialize)] }
    } else {
        quote! {}
    }
}

/// Whether a typedef's body is fully serde-serializable (no arrays > 32, no
/// unresolvable type references).
fn typedef_serde_serializable(typedef: &IdlTypeDef, all_types: &[IdlTypeDef]) -> bool {
    match &typedef.ty {
        IdlTypeDefTy::Struct { fields } => fields
            .as_ref()
            .map_or(true, |f| fields_serde_serializable(f, all_types)),
        IdlTypeDefTy::Enum { variants } => variants.iter().all(|v| {
            v.fields
                .as_ref()
                .map_or(true, |f| fields_serde_serializable(f, all_types))
        }),
        // Plain aliases don't emit a derive at all
        IdlTypeDefTy::Type { .. } => false,
    }
}

/// Generate a zero-copy struct with repr(C) and bytemuck derives
/// Note: We still add borsh derives because types may be used in instruction args
fn generate_zero_copy_struct(
    name: &syn::Ident,
    fields: &Option<IdlDefinedFields>,
    type_name: &str,
    generics: &[IdlTypeDefGeneric],
    derive_serde: bool,
) -> proc_macro2::TokenStream {
    let decl = generic_params_decl(generics);
    let use_ = generic_params_use(generics);
    let pod_bound = type_generic_bounds(generics, quote! { bytemuck::Pod });
    let zeroable_bound = type_generic_bounds(generics, quote! { bytemuck::Zeroable });
    let serde_derive = serde_serialize_derive(derive_serde);
    let fields_tokens = match fields {
        Some(IdlDefinedFields::Named(named_fields)) => {
            let field_tokens = named_fields.iter().map(|f| {
                let field_name = format_ident!("{}", f.name);
                let field_type = idl_type_to_tokens(&f.ty);
                quote! { pub #field_name: #field_type }
            });
            quote! { #(#field_tokens),* }
        }
        Some(IdlDefinedFields::Tuple(tuple_fields)) => {
            let field_tokens = tuple_fields.iter().map(idl_type_to_tokens);
            // Tuple struct - zero-copy
            return quote! {
                #[derive(Clone, Copy, Default, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)]
                #serde_derive
                #[repr(C)]
                pub struct #name #decl (#(pub #field_tokens),*);

                unsafe impl #decl bytemuck::Pod for #name #use_ #pod_bound {}
                unsafe impl #decl bytemuck::Zeroable for #name #use_ #zeroable_bound {}
            };
        }
        None => quote! {},
    };

    // Check if this is a wrapped numeric type (like WrappedI80F48)
    let extra_impls = generate_extra_impls(type_name, fields);

    // Check if we can derive Default (arrays > 32 elements don't implement Default)
    let can_derive_default = fields
        .as_ref()
        .map_or(true, |f| can_derive_default_fields(f));

    // Zero-copy structs need:
    // - repr(C) for memory layout
    // - bytemuck Pod + Zeroable for safe casting
    // - borsh derives for instruction serialization (types may be used in both contexts)
    // - PartialEq for comparisons
    let derives = if can_derive_default {
        quote! { #[derive(Clone, Copy, Default, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] }
    } else {
        quote! { #[derive(Clone, Copy, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] }
    };

    // Generate manual Default impl if we can't derive it
    let default_impl = if !can_derive_default {
        generate_manual_default(name, fields, generics)
    } else {
        quote! {}
    };

    quote! {
        #derives
        #serde_derive
        #[repr(C)]
        pub struct #name #decl {
            #fields_tokens
        }

        unsafe impl #decl bytemuck::Pod for #name #use_ #pod_bound {}
        unsafe impl #decl bytemuck::Zeroable for #name #use_ #zeroable_bound {}

        #default_impl
        #extra_impls
    }
}

fn generate_enum(
    name: &syn::Ident,
    variants: &[anchor_lang_idl::types::IdlEnumVariant],
    all_types: &[IdlTypeDef],
    use_bincode: bool,
    generics: &[IdlTypeDefGeneric],
    derive_serde: bool,
) -> proc_macro2::TokenStream {
    let decl = generic_params_decl(generics);
    // Check if all variants are unit variants (no fields)
    let all_unit = variants.iter().all(|v| v.fields.is_none());

    // Bincode mode: unit-only enums use #[repr(u32)] with manual serialization
    // (bincode encodes enum variant indices as u32 LE, borsh uses u8)
    // Enums with fields (like StakeState) are account state types — keep borsh for those
    if use_bincode && all_unit {
        return generate_bincode_unit_enum(name, variants, generics);
    }

    // Check if first variant is a unit variant (no fields) - required for #[default] attribute
    let first_is_unit = variants.first().map_or(false, |v| v.fields.is_none());

    // Can only derive Default if first variant is a unit variant
    let can_derive_default = first_is_unit;

    // Check if enum can derive Eq (no f32/f64 fields)
    let can_derive_eq = variants.iter().all(|v| {
        v.fields
            .as_ref()
            .map_or(true, |f| can_derive_eq_fields(f, all_types))
    });

    let variants_tokens = variants.iter().enumerate().map(|(i, v)| {
        let variant_name = format_ident!("{}", v.name.to_upper_camel_case());
        // #[default] can only be applied to unit variants (no fields)
        let default_attr = if can_derive_default && i == 0 && v.fields.is_none() {
            quote! { #[default] }
        } else {
            quote! {}
        };

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
            None => quote! { #default_attr #variant_name },
        }
    });

    // Check if enum can derive Copy (all variant fields must be Copy)
    let can_derive_copy = variants.iter().all(|v| {
        v.fields
            .as_ref()
            .map_or(true, |f| should_derive_copy(&Some(f.clone()), all_types))
    });

    // Build derives based on what's possible
    let derives = match (can_derive_copy, can_derive_default, can_derive_eq) {
        (true, true, true) => {
            quote! { #[derive(Clone, Copy, Default, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] }
        }
        (true, true, false) => {
            quote! { #[derive(Clone, Copy, Default, AnchorSerialize, AnchorDeserialize, PartialEq)] }
        }
        (true, false, true) => {
            quote! { #[derive(Clone, Copy, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] }
        }
        (true, false, false) => {
            quote! { #[derive(Clone, Copy, AnchorSerialize, AnchorDeserialize, PartialEq)] }
        }
        (false, true, true) => {
            quote! { #[derive(Clone, Default, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] }
        }
        (false, true, false) => {
            quote! { #[derive(Clone, Default, AnchorSerialize, AnchorDeserialize, PartialEq)] }
        }
        (false, false, true) => {
            quote! { #[derive(Clone, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] }
        }
        (false, false, false) => {
            quote! { #[derive(Clone, AnchorSerialize, AnchorDeserialize, PartialEq)] }
        }
    };

    // Generate manual Default impl for enums where first variant has fields
    let manual_default = if !can_derive_default && !variants.is_empty() {
        generate_enum_manual_default(name, &variants[0], generics)
    } else {
        quote! {}
    };

    // Data-carrying enums in bincode programs derive serde::Serialize when
    // possible; instruction args also have a field-wise fallback for types that
    // cannot derive serde because they contain large fixed arrays.
    let serde_derive = serde_serialize_derive(derive_serde);

    quote! {
        #derives
        #serde_derive
        #[repr(u8)]
        pub enum #name #decl {
            #(#variants_tokens),*
        }

        #manual_default
    }
}

/// Generate a unit enum with u32 variant indices for bincode serialization.
///
/// Bincode programs (native Solana programs) encode enum variants as u32 LE,
/// unlike borsh which uses u8. We use #[repr(u32)] and implement manual
/// AnchorSerialize/AnchorDeserialize to write/read a u32 variant index.
fn generate_bincode_unit_enum(
    name: &syn::Ident,
    variants: &[anchor_lang_idl::types::IdlEnumVariant],
    generics: &[IdlTypeDefGeneric],
) -> proc_macro2::TokenStream {
    let decl = generic_params_decl(generics);
    let use_ = generic_params_use(generics);
    let variant_idents: Vec<_> = variants
        .iter()
        .map(|v| format_ident!("{}", v.name.to_upper_camel_case()))
        .collect();

    let variant_defs = variant_idents.iter().enumerate().map(|(i, ident)| {
        let idx = i as u32;
        if i == 0 {
            quote! { #[default] #ident = #idx }
        } else {
            quote! { #ident = #idx }
        }
    });

    // Match arms for serialization: Self::Variant => 0u32,
    let ser_arms = variant_idents.iter().enumerate().map(|(i, ident)| {
        let idx = i as u32;
        quote! { Self::#ident => #idx }
    });

    // Match arms for deserialization: 0 => Ok(Self::Variant),
    let deser_arms = variant_idents.iter().enumerate().map(|(i, ident)| {
        let idx = i as u32;
        quote! { #idx => Ok(Self::#ident) }
    });

    let name_str = name.to_string();

    quote! {
        #[derive(Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
        #[repr(u32)]
        pub enum #name #decl {
            #(#variant_defs),*
        }

        impl #decl AnchorSerialize for #name #use_ {
            fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
                let idx: u32 = match self {
                    #(#ser_arms),*
                };
                writer.write_all(&idx.to_le_bytes())
            }
        }

        impl #decl AnchorDeserialize for #name #use_ {
            fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
                let mut buf = [0u8; 4];
                reader.read_exact(&mut buf)?;
                let idx = u32::from_le_bytes(buf);
                match idx {
                    #(#deser_arms,)*
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid {} variant index: {}", #name_str, idx),
                    )),
                }
            }
        }
    }
}

/// Generate manual Default impl for enum whose first variant has fields
fn generate_enum_manual_default(
    name: &syn::Ident,
    first_variant: &anchor_lang_idl::types::IdlEnumVariant,
    generics: &[IdlTypeDefGeneric],
) -> proc_macro2::TokenStream {
    let variant_name = format_ident!("{}", first_variant.name.to_upper_camel_case());
    let decl = generic_params_decl(generics);
    let use_ = generic_params_use(generics);
    let default_bound = type_generic_bounds(generics, quote! { Default });

    match &first_variant.fields {
        Some(IdlDefinedFields::Named(fields)) => {
            let field_defaults = fields.iter().map(|f| {
                // Use the IDL field name directly (preserves camelCase)
                let field_name = format_ident!("{}", f.name);
                quote! { #field_name: Default::default() }
            });
            quote! {
                impl #decl Default for #name #use_ #default_bound {
                    fn default() -> Self {
                        Self::#variant_name {
                            #(#field_defaults),*
                        }
                    }
                }
            }
        }
        Some(IdlDefinedFields::Tuple(types)) => {
            let defaults = types.iter().map(|_| quote! { Default::default() });
            quote! {
                impl #decl Default for #name #use_ #default_bound {
                    fn default() -> Self {
                        Self::#variant_name(#(#defaults),*)
                    }
                }
            }
        }
        None => quote! {},
    }
}

/// Check if fields can derive Default
fn can_derive_default_fields(fields: &IdlDefinedFields) -> bool {
    match fields {
        IdlDefinedFields::Named(named) => named.iter().all(|f| can_type_derive_default(&f.ty)),
        IdlDefinedFields::Tuple(types) => types.iter().all(can_type_derive_default),
    }
}

/// Check if a type can derive Default
fn can_type_derive_default(ty: &anchor_lang_idl::types::IdlType) -> bool {
    use anchor_lang_idl::types::{IdlArrayLen, IdlType};

    match ty {
        // Primitives with Default
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
        | IdlType::I128 => true,
        IdlType::Pubkey => true,
        IdlType::String => true,
        IdlType::Bytes => true,
        IdlType::Vec(_) => true,
        IdlType::Option(_) => true,
        // Arrays only have Default for len <= 32 (when len is known at codegen time)
        IdlType::Array(inner, IdlArrayLen::Value(n)) => *n <= 32 && can_type_derive_default(inner),
        // Generic-length arrays — can't determine at codegen time, be conservative
        IdlType::Array(_, IdlArrayLen::Generic(_)) => false,
        // We can't know if user types implement Default, be conservative
        // Users can manually implement Default if needed
        IdlType::Defined { .. } => false,
        // Type-param references — depend on the user's instantiation, be conservative
        IdlType::Generic(_) => false,
        _ => false,
    }
}

/// Check if fields can derive Eq
fn can_derive_eq_fields(fields: &IdlDefinedFields, all_types: &[IdlTypeDef]) -> bool {
    match fields {
        IdlDefinedFields::Named(named) => {
            named.iter().all(|f| can_type_derive_eq(&f.ty, all_types))
        }
        IdlDefinedFields::Tuple(types) => types.iter().all(|t| can_type_derive_eq(t, all_types)),
    }
}

/// Check if a type can derive Eq (f32/f64 cannot)
fn can_type_derive_eq(ty: &anchor_lang_idl::types::IdlType, all_types: &[IdlTypeDef]) -> bool {
    use anchor_lang_idl::types::IdlType;

    match ty {
        // f32 and f64 don't implement Eq
        IdlType::F32 | IdlType::F64 => false,
        // Primitives with Eq
        IdlType::Bool
        | IdlType::U8
        | IdlType::I8
        | IdlType::U16
        | IdlType::I16
        | IdlType::U32
        | IdlType::I32
        | IdlType::U64
        | IdlType::I64
        | IdlType::U128
        | IdlType::I128 => true,
        IdlType::Pubkey => true,
        IdlType::String => true,
        IdlType::Bytes => true,
        IdlType::Vec(inner) => can_type_derive_eq(inner, all_types),
        IdlType::Option(inner) => can_type_derive_eq(inner, all_types),
        IdlType::Array(inner, _) => can_type_derive_eq(inner, all_types),
        // Look up defined types to check their fields recursively
        IdlType::Defined {
            name,
            generics: use_site_generics,
        } => {
            // If the use-site instantiates with generic args we can't see through the
            // typedef body to know what the concrete field types resolve to — conservative.
            if !use_site_generics.is_empty() {
                return false;
            }
            if let Some(typedef) = all_types.iter().find(|t| &t.name == name) {
                // If the typedef itself declares generics, the body contains `Generic(_)`
                // references whose concrete types we can't know — conservative.
                if !typedef.generics.is_empty() {
                    return false;
                }
                match &typedef.ty {
                    IdlTypeDefTy::Struct { fields } => fields
                        .as_ref()
                        .map_or(true, |f| can_derive_eq_fields(f, all_types)),
                    IdlTypeDefTy::Enum { variants } => variants.iter().all(|v| {
                        v.fields
                            .as_ref()
                            .map_or(true, |f| can_derive_eq_fields(f, all_types))
                    }),
                    IdlTypeDefTy::Type { alias } => can_type_derive_eq(alias, all_types),
                }
            } else {
                // Unknown type — be conservative (previous behaviour was unsound: returned true)
                false
            }
        }
        // Type-param references — depend on the user's instantiation, be conservative
        IdlType::Generic(_) => false,
        _ => false,
    }
}

fn should_derive_copy(fields: &Option<IdlDefinedFields>, all_types: &[IdlTypeDef]) -> bool {
    match fields {
        Some(IdlDefinedFields::Named(named_fields)) => {
            named_fields.iter().all(|f| is_copy_type(&f.ty, all_types))
        }
        Some(IdlDefinedFields::Tuple(tuple_fields)) => {
            tuple_fields.iter().all(|t| is_copy_type(t, all_types))
        }
        None => true,
    }
}

fn is_copy_type(ty: &anchor_lang_idl::types::IdlType, all_types: &[IdlTypeDef]) -> bool {
    use anchor_lang_idl::types::IdlType;

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
        | IdlType::Pubkey => true,
        IdlType::Array(inner, _) => is_copy_type(inner, all_types),
        IdlType::Option(inner) => is_copy_type(inner, all_types),
        // Defined types - look up in IDL and recursively check their fields
        IdlType::Defined {
            name,
            generics: use_site_generics,
        } => {
            // If the use-site instantiates with generic args, we'd need full substitution
            // through the typedef body to know if the result is Copy — conservative.
            if !use_site_generics.is_empty() {
                return false;
            }
            if let Some(typedef) = all_types.iter().find(|t| &t.name == name) {
                // Typedef with its own generic params has unknown field types — conservative.
                if !typedef.generics.is_empty() {
                    return false;
                }
                match &typedef.ty {
                    IdlTypeDefTy::Struct { fields } => should_derive_copy(fields, all_types),
                    IdlTypeDefTy::Enum { variants } => {
                        // Enum is Copy if all variant fields are Copy
                        variants.iter().all(|v| match &v.fields {
                            Some(fields) => should_derive_copy(&Some(fields.clone()), all_types),
                            None => true,
                        })
                    }
                    IdlTypeDefTy::Type { alias } => is_copy_type(alias, all_types),
                }
            } else {
                // Type not found in IDL — be conservative, assume not Copy
                false
            }
        }
        // Type-param references — depend on the user's instantiation, be conservative
        IdlType::Generic(_) => false,
        // String and Vec are not Copy
        IdlType::String | IdlType::Bytes | IdlType::Vec(_) => false,
        _ => false,
    }
}

/// Generate manual Default implementation for structs that can't derive it
fn generate_manual_default(
    name: &syn::Ident,
    fields: &Option<IdlDefinedFields>,
    generics: &[IdlTypeDefGeneric],
) -> proc_macro2::TokenStream {
    let field_defaults = match fields {
        Some(IdlDefinedFields::Named(named_fields)) => {
            let defaults = named_fields.iter().map(|f| {
                let field_name = format_ident!("{}", f.name);
                let default_value = type_default_value(&f.ty);
                quote! { #field_name: #default_value }
            });
            quote! { #(#defaults),* }
        }
        Some(IdlDefinedFields::Tuple(_)) | None => {
            // Shouldn't reach here for tuple structs, but handle it
            return quote! {};
        }
    };

    let decl = generic_params_decl(generics);
    let use_ = generic_params_use(generics);
    let default_bound = type_generic_bounds(generics, quote! { Default });

    quote! {
        impl #decl Default for #name #use_ #default_bound {
            fn default() -> Self {
                Self {
                    #field_defaults
                }
            }
        }
    }
}

/// Generate default value expression for a type
fn type_default_value(ty: &anchor_lang_idl::types::IdlType) -> proc_macro2::TokenStream {
    use anchor_lang_idl::types::IdlType;

    match ty {
        // Primitives
        IdlType::Bool => quote! { false },
        IdlType::U8
        | IdlType::I8
        | IdlType::U16
        | IdlType::I16
        | IdlType::U32
        | IdlType::I32
        | IdlType::U64
        | IdlType::I64
        | IdlType::U128
        | IdlType::I128 => quote! { 0 },
        IdlType::F32 | IdlType::F64 => quote! { 0.0 },
        IdlType::Pubkey => quote! { Pubkey::default() },
        IdlType::String => quote! { String::new() },
        IdlType::Bytes => quote! { Vec::new() },
        IdlType::Vec(_) => quote! { Vec::new() },
        IdlType::Option(_) => quote! { None },
        // Arrays - use [T::default(); N] or [0; N] for primitives
        IdlType::Array(inner, len) => {
            let len_val = super::array_len_to_usize(len);
            let inner_default = type_default_value(inner);
            // For simple types, use array literal
            if is_zero_default(inner) {
                quote! { [0; #len_val] }
            } else {
                // For complex types, we need to be careful
                // Use Default::default() for each element
                quote! { [#inner_default; #len_val] }
            }
        }
        // User-defined types - call their default
        IdlType::Defined { name, .. } => {
            let ident = format_ident!("{}", name);
            quote! { #ident::default() }
        }
        _ => quote! { Default::default() },
    }
}

/// Check if a type has a zero default (can use [0; N])
fn is_zero_default(ty: &anchor_lang_idl::types::IdlType) -> bool {
    use anchor_lang_idl::types::IdlType;
    matches!(
        ty,
        IdlType::U8
            | IdlType::I8
            | IdlType::U16
            | IdlType::I16
            | IdlType::U32
            | IdlType::I32
            | IdlType::U64
            | IdlType::I64
            | IdlType::U128
            | IdlType::I128
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang_idl::types::{
        Idl, IdlArrayLen, IdlDefinedFields, IdlEnumVariant, IdlField, IdlMetadata, IdlRepr,
        IdlReprModifier, IdlType, IdlTypeDef, IdlTypeDefTy,
    };

    fn make_idl(types: Vec<IdlTypeDef>, use_bincode: bool) -> (Idl, bool) {
        let idl = Idl {
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
            accounts: vec![],
            events: vec![],
            errors: vec![],
            types,
            constants: vec![],
        };
        (idl, use_bincode)
    }

    fn gen(types: Vec<IdlTypeDef>, use_bincode: bool) -> String {
        let (idl, ub) = make_idl(types, use_bincode);
        generate(&idl, ub).to_string()
    }

    fn make_struct(name: &str, fields: Vec<IdlField>) -> IdlTypeDef {
        IdlTypeDef {
            name: name.to_string(),
            docs: vec![],
            serialization: Default::default(),
            repr: None,
            generics: vec![],
            ty: IdlTypeDefTy::Struct {
                fields: if fields.is_empty() {
                    None
                } else {
                    Some(IdlDefinedFields::Named(fields))
                },
            },
        }
    }

    fn make_field(name: &str, ty: IdlType) -> IdlField {
        IdlField {
            name: name.to_string(),
            docs: vec![],
            ty,
        }
    }

    fn make_unit_enum(name: &str, variants: &[&str]) -> IdlTypeDef {
        IdlTypeDef {
            name: name.to_string(),
            docs: vec![],
            serialization: Default::default(),
            repr: None,
            generics: vec![],
            ty: IdlTypeDefTy::Enum {
                variants: variants
                    .iter()
                    .map(|v| IdlEnumVariant {
                        name: v.to_string(),
                        fields: None,
                    })
                    .collect(),
            },
        }
    }

    // -----------------------------------------------------------------------
    // Struct generation
    // -----------------------------------------------------------------------

    #[test]
    fn test_struct_with_primitives() {
        let output = gen(
            vec![make_struct(
                "MyStruct",
                vec![
                    make_field("x", IdlType::U64),
                    make_field("y", IdlType::I32),
                    make_field("flag", IdlType::Bool),
                ],
            )],
            false,
        );
        assert!(output.contains("MyStruct"), "should have struct name");
        assert!(output.contains("pub x : u64"), "should have x field");
        assert!(output.contains("pub y : i32"), "should have y field");
        assert!(output.contains("pub flag : bool"), "should have flag field");
        assert!(output.contains("Clone"), "should derive Clone");
        assert!(output.contains("Copy"), "should derive Copy");
        assert!(output.contains("Default"), "should derive Default");
        assert!(output.contains("PartialEq"), "should derive PartialEq");
        assert!(output.contains("Eq"), "should derive Eq");
    }

    #[test]
    fn test_struct_with_string_no_copy() {
        let output = gen(
            vec![make_struct(
                "WithString",
                vec![
                    make_field("name", IdlType::String),
                    make_field("id", IdlType::U64),
                ],
            )],
            false,
        );
        assert!(output.contains("Clone"), "should derive Clone");
        // String is not Copy, so Copy should not be derived
        // Check that the derives don't include Copy
        // The output uses "Clone , Default" without Copy
        assert!(
            !output.contains("Copy"),
            "should NOT derive Copy for String field"
        );
    }

    #[test]
    fn test_struct_with_vec_no_copy() {
        let output = gen(
            vec![make_struct(
                "WithVec",
                vec![make_field("items", IdlType::Vec(Box::new(IdlType::U8)))],
            )],
            false,
        );
        assert!(
            !output.contains("Copy"),
            "should NOT derive Copy for Vec field"
        );
    }

    #[test]
    fn test_struct_with_f64_no_eq() {
        let output = gen(
            vec![make_struct(
                "WithFloat",
                vec![make_field("value", IdlType::F64)],
            )],
            false,
        );
        assert!(output.contains("PartialEq"), "should derive PartialEq");
        // Eq appears inside PartialEq, so check that ", Eq" or ", Eq)" does not appear
        // after PartialEq in the derive list
        assert!(
            !output.contains("PartialEq , Eq"),
            "should NOT derive Eq for f64 field"
        );
    }

    #[test]
    fn test_struct_with_large_array_manual_default() {
        let output = gen(
            vec![make_struct(
                "BigArray",
                vec![make_field(
                    "data",
                    IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(64)),
                )],
            )],
            false,
        );
        // Arrays > 32 can't derive Default, should have manual impl
        assert!(
            output.contains("impl Default for BigArray"),
            "should have manual Default impl"
        );
        assert!(
            output.contains("[0 ; 64usize]"),
            "should have [0; 64] default"
        );
    }

    #[test]
    fn test_struct_with_small_array_derive_default() {
        let output = gen(
            vec![make_struct(
                "SmallArray",
                vec![make_field(
                    "data",
                    IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(16)),
                )],
            )],
            false,
        );
        // Arrays <= 32 can derive Default
        assert!(
            output.contains("Default"),
            "should derive Default for small array"
        );
        assert!(
            !output.contains("impl Default for SmallArray"),
            "should NOT have manual Default"
        );
    }

    #[test]
    fn test_empty_struct() {
        let output = gen(vec![make_struct("Empty", vec![])], false);
        assert!(output.contains("Empty"), "should have struct name");
    }

    // -----------------------------------------------------------------------
    // Enum generation (borsh mode)
    // -----------------------------------------------------------------------

    #[test]
    fn test_borsh_unit_enum() {
        let output = gen(
            vec![make_unit_enum("MyEnum", &["Foo", "Bar", "Baz"])],
            false, // borsh mode
        );
        assert!(
            output.contains("repr (u8)"),
            "borsh enum should use repr(u8)"
        );
        assert!(
            output.contains("AnchorSerialize"),
            "should derive AnchorSerialize"
        );
        assert!(
            output.contains("AnchorDeserialize"),
            "should derive AnchorDeserialize"
        );
        assert!(output.contains("Foo"), "should have Foo variant");
        assert!(output.contains("Bar"), "should have Bar variant");
        assert!(output.contains("Baz"), "should have Baz variant");
        // Should NOT have manual ser/deser
        assert!(
            !output.contains("serialize_reader"),
            "borsh should use derived, not manual"
        );
    }

    #[test]
    fn test_borsh_enum_default_first_variant() {
        let output = gen(
            vec![make_unit_enum("WithDefault", &["First", "Second"])],
            false,
        );
        assert!(
            output.contains("# [default]"),
            "first unit variant should have #[default]"
        );
        assert!(output.contains("Default"), "should derive Default");
    }

    // -----------------------------------------------------------------------
    // Enum generation (bincode mode)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bincode_unit_enum() {
        let output = gen(
            vec![make_unit_enum("StakeAuthorize", &["Staker", "Withdrawer"])],
            true, // bincode mode
        );
        assert!(
            output.contains("repr (u32)"),
            "bincode enum should use repr(u32)"
        );
        assert!(
            !output.contains("repr (u8)"),
            "bincode enum should NOT use repr(u8)"
        );
        // Should have manual AnchorSerialize
        assert!(
            output.contains("impl AnchorSerialize for StakeAuthorize"),
            "should have manual AnchorSerialize impl"
        );
        assert!(
            output.contains("impl AnchorDeserialize for StakeAuthorize"),
            "should have manual AnchorDeserialize impl"
        );
        // Should write u32 LE
        assert!(
            output.contains("to_le_bytes"),
            "should use to_le_bytes for u32 serialization"
        );
        assert!(
            output.contains("from_le_bytes"),
            "should use from_le_bytes for deserialization"
        );
    }

    #[test]
    fn test_bincode_struct_derives_serde() {
        let output = gen(
            vec![make_struct(
                "LockupArgs",
                vec![
                    make_field("unixTimestamp", IdlType::I64),
                    make_field("custodian", IdlType::Option(Box::new(IdlType::Pubkey))),
                ],
            )],
            true, // bincode mode
        );
        assert!(
            output.contains("serde :: Serialize"),
            "bincode-program structs should derive serde::Serialize, got: {output}"
        );
    }

    #[test]
    fn test_borsh_struct_no_serde() {
        let output = gen(
            vec![make_struct("Plain", vec![make_field("x", IdlType::U64)])],
            false, // borsh mode
        );
        assert!(
            !output.contains("serde"),
            "borsh-program structs should not derive serde::Serialize"
        );
    }

    #[test]
    fn test_bincode_struct_with_large_array_no_serde() {
        // serde lacks Serialize impls for arrays > 32 elements — the derive
        // would not compile, so it is skipped (borsh fallback covers encoding).
        let output = gen(
            vec![make_struct(
                "BigBlob",
                vec![make_field(
                    "data",
                    IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(64)),
                )],
            )],
            true, // bincode mode
        );
        assert!(
            !output.contains("serde"),
            "structs with arrays > 32 must not derive serde::Serialize, got: {output}"
        );
    }

    #[test]
    fn test_bincode_unit_enum_derives_serde() {
        let output = gen(
            vec![make_unit_enum("StakeAuthorize", &["Staker", "Withdrawer"])],
            true, // bincode mode
        );
        assert!(
            output.contains("serde :: Serialize"),
            "bincode unit enums should derive serde::Serialize, got: {output}"
        );
    }

    #[test]
    fn test_bincode_enum_with_data_variants_uses_borsh() {
        // Enums with fields (like StakeState) should use borsh even in bincode mode
        let output = gen(
            vec![IdlTypeDef {
                name: "StakeState".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Enum {
                    variants: vec![
                        IdlEnumVariant {
                            name: "Uninitialized".to_string(),
                            fields: None,
                        },
                        IdlEnumVariant {
                            name: "Initialized".to_string(),
                            fields: Some(IdlDefinedFields::Tuple(vec![IdlType::Pubkey])),
                        },
                    ],
                },
            }],
            true, // bincode mode
        );
        // Has data variants, so should fall through to borsh-style (repr(u8))
        assert!(
            output.contains("repr (u8)"),
            "enum with data should use repr(u8) even in bincode mode"
        );
        assert!(
            !output.contains("repr (u32)"),
            "should not use repr(u32) for data enum"
        );
    }

    // -----------------------------------------------------------------------
    // Enum with data variants
    // -----------------------------------------------------------------------

    #[test]
    fn test_enum_with_named_fields() {
        let output = gen(
            vec![IdlTypeDef {
                name: "Action".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Enum {
                    variants: vec![
                        IdlEnumVariant {
                            name: "Transfer".to_string(),
                            fields: Some(IdlDefinedFields::Named(vec![
                                make_field("amount", IdlType::U64),
                                make_field("recipient", IdlType::Pubkey),
                            ])),
                        },
                        IdlEnumVariant {
                            name: "Close".to_string(),
                            fields: None,
                        },
                    ],
                },
            }],
            false,
        );
        assert!(output.contains("Transfer"), "should have Transfer variant");
        assert!(output.contains("amount : u64"), "should have amount field");
        assert!(
            output.contains("recipient : Pubkey"),
            "should have recipient field"
        );
        assert!(output.contains("Close"), "should have Close variant");
    }

    #[test]
    fn test_enum_with_tuple_fields() {
        let output = gen(
            vec![IdlTypeDef {
                name: "Value".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Enum {
                    variants: vec![
                        IdlEnumVariant {
                            name: "Single".to_string(),
                            fields: Some(IdlDefinedFields::Tuple(vec![IdlType::U64])),
                        },
                        IdlEnumVariant {
                            name: "Pair".to_string(),
                            fields: Some(IdlDefinedFields::Tuple(vec![IdlType::U64, IdlType::U64])),
                        },
                    ],
                },
            }],
            false,
        );
        assert!(output.contains("Single (u64)"), "should have Single(u64)");
        assert!(
            output.contains("Pair (u64 , u64)"),
            "should have Pair(u64, u64)"
        );
    }

    // -----------------------------------------------------------------------
    // Zero-copy structs
    // -----------------------------------------------------------------------

    #[test]
    fn test_zero_copy_struct() {
        let output = gen(
            vec![IdlTypeDef {
                name: "ZeroCopyData".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: Some(IdlRepr::C(IdlReprModifier {
                    packed: false,
                    align: None,
                })),
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Named(vec![
                        make_field("value", IdlType::U64),
                        make_field("flag", IdlType::U8),
                    ])),
                },
            }],
            false,
        );
        assert!(output.contains("repr (C)"), "zero-copy should have repr(C)");
        assert!(
            output.contains("bytemuck :: Pod"),
            "should have bytemuck::Pod"
        );
        assert!(
            output.contains("bytemuck :: Zeroable"),
            "should have bytemuck::Zeroable"
        );
        assert!(
            output.contains("pub value : u64"),
            "should have value field"
        );
    }

    // -----------------------------------------------------------------------
    // Type aliases
    // -----------------------------------------------------------------------

    #[test]
    fn test_type_alias() {
        let output = gen(
            vec![IdlTypeDef {
                name: "MyAlias".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Type {
                    alias: IdlType::Defined {
                        name: "OriginalType".to_string(),
                        generics: vec![],
                    },
                },
            }],
            false,
        );
        assert!(
            output.contains("pub type MyAlias = OriginalType"),
            "should generate type alias"
        );
    }

    // -----------------------------------------------------------------------
    // WrappedI80F48 special handling
    // -----------------------------------------------------------------------

    #[test]
    fn test_wrapped_i80f48_impls() {
        let output = gen(
            vec![make_struct(
                "WrappedI80F48",
                vec![make_field(
                    "value",
                    IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(16)),
                )],
            )],
            false,
        );
        assert!(
            output.contains("from_i80f48"),
            "should have from_i80f48 method"
        );
        assert!(output.contains("to_i80f48"), "should have to_i80f48 method");
        assert!(
            output.contains("impl From < fixed :: types :: I80F48 > for WrappedI80F48"),
            "should have From<I80F48> impl"
        );
        assert!(
            output.contains("impl From < WrappedI80F48 > for fixed :: types :: I80F48"),
            "should have From<WrappedI80F48> impl"
        );
    }

    #[test]
    fn test_non_i80f48_no_extra_impls() {
        let output = gen(
            vec![make_struct(
                "NormalStruct",
                vec![make_field(
                    "value",
                    IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(16)),
                )],
            )],
            false,
        );
        assert!(
            !output.contains("from_i80f48"),
            "normal struct should not have I80F48 impls"
        );
    }

    // -----------------------------------------------------------------------
    // Helper function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_should_derive_copy() {
        let empty_types = vec![];
        // Primitives → Copy
        assert!(should_derive_copy(
            &Some(IdlDefinedFields::Named(
                vec![make_field("x", IdlType::U64),]
            )),
            &empty_types
        ));
        // String → no Copy
        assert!(!should_derive_copy(
            &Some(IdlDefinedFields::Named(vec![make_field(
                "s",
                IdlType::String
            ),])),
            &empty_types
        ));
        // Vec → no Copy
        assert!(!should_derive_copy(
            &Some(IdlDefinedFields::Named(vec![make_field(
                "v",
                IdlType::Vec(Box::new(IdlType::U8))
            ),])),
            &empty_types
        ));
        // None → Copy
        assert!(should_derive_copy(&None, &empty_types));
    }

    #[test]
    fn test_can_type_derive_eq() {
        let empty_types = vec![];
        // f64 → no Eq
        assert!(!can_type_derive_eq(&IdlType::F64, &empty_types));
        assert!(!can_type_derive_eq(&IdlType::F32, &empty_types));
        // Primitives → Eq
        assert!(can_type_derive_eq(&IdlType::U64, &empty_types));
        assert!(can_type_derive_eq(&IdlType::Bool, &empty_types));
        assert!(can_type_derive_eq(&IdlType::Pubkey, &empty_types));
        // Option<f64> → no Eq
        assert!(!can_type_derive_eq(
            &IdlType::Option(Box::new(IdlType::F64)),
            &empty_types
        ));
    }

    #[test]
    fn test_can_type_derive_default() {
        // Small array → Default
        assert!(can_type_derive_default(&IdlType::Array(
            Box::new(IdlType::U8),
            IdlArrayLen::Value(32),
        )));
        // Large array → no Default
        assert!(!can_type_derive_default(&IdlType::Array(
            Box::new(IdlType::U8),
            IdlArrayLen::Value(33),
        )));
        // Defined type → no Default (conservative)
        assert!(!can_type_derive_default(&IdlType::Defined {
            name: "Foo".to_string(),
            generics: vec![],
        }));
    }

    // -----------------------------------------------------------------------
    // #1: Tuple structs (regular)
    // -----------------------------------------------------------------------

    #[test]
    fn test_tuple_struct() {
        let output = gen(
            vec![IdlTypeDef {
                name: "MyTuple".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Tuple(vec![IdlType::U64, IdlType::Pubkey])),
                },
            }],
            false,
        );
        assert!(
            output.contains("pub struct MyTuple (pub u64 , pub Pubkey)"),
            "should generate tuple struct, got: {}",
            output
        );
        assert!(
            output.contains("Copy"),
            "tuple struct with primitives should derive Copy"
        );
        assert!(
            output.contains("Default"),
            "tuple struct should derive Default"
        );
    }

    #[test]
    fn test_tuple_struct_with_string_no_copy() {
        // Tuple structs always derive Copy in current code (line 66) — this test
        // documents the behavior. If tuple struct derive logic is refined later,
        // update this test.
        let output = gen(
            vec![IdlTypeDef {
                name: "StringTuple".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Tuple(vec![IdlType::String, IdlType::U64])),
                },
            }],
            false,
        );
        assert!(
            output.contains("pub struct StringTuple (pub String , pub u64)"),
            "should generate tuple struct, got: {}",
            output
        );
    }

    // #1: Tuple structs (zero-copy)

    #[test]
    fn test_zero_copy_tuple_struct() {
        let output = gen(
            vec![IdlTypeDef {
                name: "ZcTuple".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: Some(IdlRepr::C(IdlReprModifier {
                    packed: false,
                    align: None,
                })),
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Tuple(vec![IdlType::U64, IdlType::U32])),
                },
            }],
            false,
        );
        assert!(
            output.contains("pub struct ZcTuple (pub u64 , pub u32)"),
            "should generate zero-copy tuple struct, got: {}",
            output
        );
        assert!(output.contains("repr (C)"), "should have repr(C)");
        assert!(output.contains("bytemuck :: Pod"), "should have Pod");
        assert!(
            output.contains("bytemuck :: Zeroable"),
            "should have Zeroable"
        );
    }

    // -----------------------------------------------------------------------
    // #2: Enum manual Default when first variant has data
    // -----------------------------------------------------------------------

    #[test]
    fn test_enum_manual_default_first_variant_named_fields() {
        let output = gen(
            vec![IdlTypeDef {
                name: "Action".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Enum {
                    variants: vec![
                        IdlEnumVariant {
                            name: "Transfer".to_string(),
                            fields: Some(IdlDefinedFields::Named(vec![
                                make_field("amount", IdlType::U64),
                                make_field("recipient", IdlType::Pubkey),
                            ])),
                        },
                        IdlEnumVariant {
                            name: "Close".to_string(),
                            fields: None,
                        },
                    ],
                },
            }],
            false,
        );
        // First variant has fields → can't use #[default], needs manual Default impl
        assert!(
            output.contains("impl Default for Action"),
            "should have manual Default impl when first variant has data, got: {}",
            output
        );
        assert!(output.contains("Transfer"), "should have Transfer variant");
        assert!(
            output.contains("amount : Default :: default ()"),
            "named fields should use Default::default(), got: {}",
            output
        );
    }

    #[test]
    fn test_enum_manual_default_first_variant_tuple_fields() {
        let output = gen(
            vec![IdlTypeDef {
                name: "Value".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Enum {
                    variants: vec![
                        IdlEnumVariant {
                            name: "Single".to_string(),
                            fields: Some(IdlDefinedFields::Tuple(vec![IdlType::U64])),
                        },
                        IdlEnumVariant {
                            name: "None".to_string(),
                            fields: None,
                        },
                    ],
                },
            }],
            false,
        );
        assert!(
            output.contains("impl Default for Value"),
            "should have manual Default impl for tuple first variant, got: {}",
            output
        );
        assert!(
            output.contains("Default :: default ()"),
            "tuple fields should use Default::default()"
        );
    }

    // -----------------------------------------------------------------------
    // #3: Recursive Eq check through Defined types
    // -----------------------------------------------------------------------

    /// Extract the derive block immediately preceding a `pub struct Name` or `pub enum Name`.
    /// Returns the text between the last `derive` and the `pub struct/enum Name` marker.
    fn extract_derive_for(output: &str, type_name: &str) -> String {
        // Find "pub struct TypeName" or "pub enum TypeName"
        let struct_marker = format!("pub struct {}", type_name);
        let enum_marker = format!("pub enum {}", type_name);
        let marker_pos = output
            .find(&struct_marker)
            .or_else(|| output.find(&enum_marker))
            .unwrap_or_else(|| {
                panic!(
                    "could not find '{}' or '{}' in output:\n{}",
                    struct_marker, enum_marker, output
                )
            });

        // Find the last "derive" before this marker
        let before = &output[..marker_pos];
        let derive_pos = before.rfind("derive").unwrap_or_else(|| {
            panic!(
                "could not find derive before '{}' in output:\n{}",
                type_name, output
            )
        });

        output[derive_pos..marker_pos].to_string()
    }

    #[test]
    fn test_eq_not_derived_when_defined_type_has_f64() {
        // Struct "Outer" references "Inner" which has an f64 field → no Eq
        let inner = make_struct("Inner", vec![make_field("price", IdlType::F64)]);
        let outer = make_struct(
            "Outer",
            vec![make_field(
                "data",
                IdlType::Defined {
                    name: "Inner".to_string(),
                    generics: vec![],
                },
            )],
        );
        let output = gen(vec![inner, outer], false);

        let outer_derive = extract_derive_for(&output, "Outer");
        assert!(
            outer_derive.contains("PartialEq"),
            "Outer should derive PartialEq, derive block: {}",
            outer_derive
        );
        // "PartialEq" contains "Eq", so check for ", Eq" or "Eq ," as standalone
        assert!(
            !outer_derive.contains(", Eq") && !outer_derive.contains("Eq ,"),
            "Outer should NOT derive Eq when Inner has f64, derive block: {}",
            outer_derive
        );

        // Inner itself should also not have Eq (direct f64 field)
        let inner_derive = extract_derive_for(&output, "Inner");
        assert!(
            !inner_derive.contains(", Eq") && !inner_derive.contains("Eq ,"),
            "Inner should NOT derive Eq with f64 field, derive block: {}",
            inner_derive
        );
    }

    #[test]
    fn test_eq_derived_when_defined_type_is_clean() {
        // Struct "Outer" references "Inner" which only has u64 → Eq is fine
        let inner = make_struct("Inner", vec![make_field("count", IdlType::U64)]);
        let outer = make_struct(
            "Outer",
            vec![make_field(
                "data",
                IdlType::Defined {
                    name: "Inner".to_string(),
                    generics: vec![],
                },
            )],
        );
        let output = gen(vec![inner, outer], false);

        let outer_derive = extract_derive_for(&output, "Outer");
        assert!(
            outer_derive.contains(", Eq") || outer_derive.contains("Eq ,"),
            "Outer should derive Eq when Inner only has u64, derive block: {}",
            outer_derive
        );
    }

    #[test]
    fn test_eq_check_through_enum_with_f64() {
        // Enum with f64 in a variant field
        let types = vec![
            IdlTypeDef {
                name: "FloatEnum".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: None,
                generics: vec![],
                ty: IdlTypeDefTy::Enum {
                    variants: vec![IdlEnumVariant {
                        name: "Val".to_string(),
                        fields: Some(IdlDefinedFields::Tuple(vec![IdlType::F64])),
                    }],
                },
            },
            make_struct(
                "Wrapper",
                vec![make_field(
                    "inner",
                    IdlType::Defined {
                        name: "FloatEnum".to_string(),
                        generics: vec![],
                    },
                )],
            ),
        ];
        let output = gen(types, false);

        let wrapper_derive = extract_derive_for(&output, "Wrapper");
        assert!(
            wrapper_derive.contains("PartialEq"),
            "Wrapper should derive PartialEq, derive block: {}",
            wrapper_derive
        );
        assert!(
            !wrapper_derive.contains(", Eq") && !wrapper_derive.contains("Eq ,"),
            "Wrapper should NOT derive Eq when FloatEnum has f64, derive block: {}",
            wrapper_derive
        );
    }

    // -----------------------------------------------------------------------
    // #8: is_copy_type with nested Option types
    // -----------------------------------------------------------------------

    #[test]
    fn test_option_string_no_copy() {
        let output = gen(
            vec![make_struct(
                "OptStr",
                vec![make_field(
                    "maybe_name",
                    IdlType::Option(Box::new(IdlType::String)),
                )],
            )],
            false,
        );
        assert!(
            !output.contains("Copy"),
            "Option<String> should NOT derive Copy, got: {}",
            output
        );
    }

    #[test]
    fn test_option_u64_has_copy() {
        let output = gen(
            vec![make_struct(
                "OptNum",
                vec![make_field(
                    "maybe_val",
                    IdlType::Option(Box::new(IdlType::U64)),
                )],
            )],
            false,
        );
        assert!(output.contains("Copy"), "Option<u64> should derive Copy");
    }

    // -----------------------------------------------------------------------
    // #9: type_default_value for Defined types in manual Default
    // -----------------------------------------------------------------------

    #[test]
    fn test_manual_default_with_defined_type_field() {
        // Struct with a Defined field and a large array → forces manual Default
        // The Defined field should generate `Foo::default()` in the impl
        let output = gen(
            vec![make_struct(
                "HasDefined",
                vec![
                    make_field(
                        "inner",
                        IdlType::Defined {
                            name: "Foo".to_string(),
                            generics: vec![],
                        },
                    ),
                    make_field(
                        "big",
                        IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(64)),
                    ),
                ],
            )],
            false,
        );
        assert!(
            output.contains("impl Default for HasDefined"),
            "should have manual Default (Defined field blocks derive)"
        );
        assert!(
            output.contains("Foo :: default ()"),
            "Defined field should use Foo::default() in manual impl, got: {}",
            output
        );
        assert!(
            output.contains("[0 ; 64usize]"),
            "large array should use [0; 64] default"
        );
    }

    // -----------------------------------------------------------------------
    // #10: Zero-copy struct with large array (manual Default + repr(C) + bytemuck)
    // -----------------------------------------------------------------------

    #[test]
    fn test_zero_copy_struct_large_array_manual_default() {
        let output = gen(
            vec![IdlTypeDef {
                name: "BigZc".to_string(),
                docs: vec![],
                serialization: Default::default(),
                repr: Some(IdlRepr::C(IdlReprModifier {
                    packed: false,
                    align: None,
                })),
                generics: vec![],
                ty: IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Named(vec![
                        make_field("start", IdlType::I32),
                        make_field(
                            "data",
                            IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(88)),
                        ),
                    ])),
                },
            }],
            false,
        );
        // Should have all three: repr(C), bytemuck, AND manual Default
        assert!(output.contains("repr (C)"), "should have repr(C)");
        assert!(output.contains("bytemuck :: Pod"), "should have Pod");
        assert!(
            output.contains("bytemuck :: Zeroable"),
            "should have Zeroable"
        );
        assert!(
            output.contains("impl Default for BigZc"),
            "large array in zero-copy should get manual Default, got: {}",
            output
        );
        assert!(
            output.contains("[0 ; 88usize]"),
            "should have [0; 88] default"
        );
        // Should NOT have Default in derive list
        assert!(
            !output.contains("derive (Clone , Copy , Default"),
            "should NOT derive Default when manual impl exists"
        );
    }
}

/// Generate extra implementations for special types
fn generate_extra_impls(
    type_name: &str,
    fields: &Option<IdlDefinedFields>,
) -> proc_macro2::TokenStream {
    // Check if this is WrappedI80F48 or similar wrapped numeric type
    if type_name.contains("WrappedI80F48") || type_name.contains("I80F48") {
        if let Some(IdlDefinedFields::Named(named_fields)) = fields {
            // If it has a single array field, generate From impls
            if named_fields.len() == 1 {
                if let anchor_lang_idl::types::IdlType::Array(_, len) = &named_fields[0].ty {
                    let len_val = array_len_to_usize(len);
                    if len_val == 16 {
                        let struct_name = format_ident!("{}", type_name);
                        let field_name = format_ident!("{}", named_fields[0].name);

                        return quote! {
                            impl #struct_name {
                                pub fn from_i80f48(value: fixed::types::I80F48) -> Self {
                                    Self {
                                        #field_name: value.to_le_bytes(),
                                    }
                                }

                                pub fn to_i80f48(&self) -> fixed::types::I80F48 {
                                    fixed::types::I80F48::from_le_bytes(self.#field_name)
                                }
                            }

                            impl From<fixed::types::I80F48> for #struct_name {
                                fn from(value: fixed::types::I80F48) -> Self {
                                    Self::from_i80f48(value)
                                }
                            }

                            impl From<#struct_name> for fixed::types::I80F48 {
                                fn from(value: #struct_name) -> Self {
                                    value.to_i80f48()
                                }
                            }
                        };
                    }
                }
            }
        }
    }

    quote! {}
}
