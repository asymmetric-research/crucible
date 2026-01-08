use anchor_lang_idl::types::{Idl, IdlTypeDef, IdlTypeDefTy, IdlDefinedFields, IdlRepr};
use heck::ToUpperCamelCase;
use quote::{format_ident, quote};

use super::{idl_type_to_tokens, array_len_to_usize};

/// Generate custom type definitions from IDL types section
pub fn generate(idl: &Idl) -> proc_macro2::TokenStream {
    let type_defs = idl.types.iter().map(generate_type_def);

    quote! {
        /// Custom type definitions
        pub mod types {
            use super::*;

            #(#type_defs)*
        }
    }
}

fn generate_type_def(typedef: &IdlTypeDef) -> proc_macro2::TokenStream {
    let name = format_ident!("{}", typedef.name);

    // Check if this is a zero-copy type (repr: C)
    let is_zero_copy = matches!(&typedef.repr, Some(IdlRepr::C(_)));

    match &typedef.ty {
        IdlTypeDefTy::Struct { fields } => {
            if is_zero_copy {
                generate_zero_copy_struct(&name, fields, &typedef.name)
            } else {
                generate_struct(&name, fields, &typedef.name)
            }
        }
        IdlTypeDefTy::Enum { variants } => {
            generate_enum(&name, variants)
        }
        IdlTypeDefTy::Type { alias } => {
            let alias_ty = idl_type_to_tokens(alias);
            quote! {
                pub type #name = #alias_ty;
            }
        }
    }
}

fn generate_struct(
    name: &syn::Ident,
    fields: &Option<IdlDefinedFields>,
    type_name: &str,
) -> proc_macro2::TokenStream {
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
            // Tuple struct
            return quote! {
                #[derive(Clone, Copy, Default, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)]
                pub struct #name(#(pub #field_tokens),*);
            };
        }
        None => quote! {},
    };

    // Check if this is a wrapped numeric type (like WrappedI80F48)
    let extra_impls = generate_extra_impls(type_name, fields);

    // Determine if we should add Copy and Eq based on field types
    let can_copy = should_derive_copy(fields);
    let can_eq = fields.as_ref().map_or(true, |f| can_derive_eq_fields(f));
    let can_derive_default = fields.as_ref().map_or(true, |f| can_derive_default_fields(f));

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
        generate_manual_default(name, fields)
    } else {
        quote! {}
    };

    quote! {
        #derives
        pub struct #name {
            #fields_tokens
        }

        #default_impl
        #extra_impls
    }
}

/// Generate a zero-copy struct with repr(C) and bytemuck derives
/// Note: We still add borsh derives because types may be used in instruction args
fn generate_zero_copy_struct(
    name: &syn::Ident,
    fields: &Option<IdlDefinedFields>,
    type_name: &str,
) -> proc_macro2::TokenStream {
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
                #[repr(C)]
                pub struct #name(#(pub #field_tokens),*);

                unsafe impl bytemuck::Pod for #name {}
                unsafe impl bytemuck::Zeroable for #name {}
            };
        }
        None => quote! {},
    };

    // Check if this is a wrapped numeric type (like WrappedI80F48)
    let extra_impls = generate_extra_impls(type_name, fields);

    // Check if we can derive Default (arrays > 32 elements don't implement Default)
    let can_derive_default = fields.as_ref().map_or(true, |f| can_derive_default_fields(f));

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
        generate_manual_default(name, fields)
    } else {
        quote! {}
    };

    quote! {
        #derives
        #[repr(C)]
        pub struct #name {
            #fields_tokens
        }

        unsafe impl bytemuck::Pod for #name {}
        unsafe impl bytemuck::Zeroable for #name {}

        #default_impl
        #extra_impls
    }
}

fn generate_enum(
    name: &syn::Ident,
    variants: &[anchor_lang_idl::types::IdlEnumVariant],
) -> proc_macro2::TokenStream {
    // Check if first variant is a unit variant (no fields) - required for #[default] attribute
    let first_is_unit = variants.first().map_or(false, |v| v.fields.is_none());

    // Can only derive Default if first variant is a unit variant
    let can_derive_default = first_is_unit;

    // Check if enum can derive Eq (no f32/f64 fields)
    let can_derive_eq = variants.iter().all(|v| {
        v.fields.as_ref().map_or(true, |f| can_derive_eq_fields(f))
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

    // Build derives based on what's possible
    let derives = match (can_derive_default, can_derive_eq) {
        (true, true) => quote! { #[derive(Clone, Copy, Default, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] },
        (true, false) => quote! { #[derive(Clone, Copy, Default, AnchorSerialize, AnchorDeserialize, PartialEq)] },
        (false, true) => quote! { #[derive(Clone, Copy, AnchorSerialize, AnchorDeserialize, PartialEq, Eq)] },
        (false, false) => quote! { #[derive(Clone, Copy, AnchorSerialize, AnchorDeserialize, PartialEq)] },
    };

    quote! {
        #derives
        #[repr(u8)]
        pub enum #name {
            #(#variants_tokens),*
        }
    }
}

/// Check if fields can derive Default
fn can_derive_default_fields(fields: &IdlDefinedFields) -> bool {
    use anchor_lang_idl::types::IdlType;

    match fields {
        IdlDefinedFields::Named(named) => named.iter().all(|f| can_type_derive_default(&f.ty)),
        IdlDefinedFields::Tuple(types) => types.iter().all(can_type_derive_default),
    }
}

/// Check if a type can derive Default
fn can_type_derive_default(ty: &anchor_lang_idl::types::IdlType) -> bool {
    use anchor_lang_idl::types::IdlType;

    match ty {
        // Primitives with Default
        IdlType::Bool | IdlType::U8 | IdlType::I8 | IdlType::U16 | IdlType::I16
        | IdlType::U32 | IdlType::I32 | IdlType::F32 | IdlType::U64 | IdlType::I64
        | IdlType::F64 | IdlType::U128 | IdlType::I128 => true,
        IdlType::Pubkey => true,
        IdlType::String => true,
        IdlType::Bytes => true,
        IdlType::Vec(_) => true,
        IdlType::Option(_) => true,
        // Arrays only have Default for len <= 32
        IdlType::Array(inner, len) => {
            let len_val = super::array_len_to_usize(len);
            len_val <= 32 && can_type_derive_default(inner)
        }
        // We can't know if user types implement Default, be conservative
        // Users can manually implement Default if needed
        IdlType::Defined { .. } => false,
        _ => false,
    }
}

/// Check if fields can derive Eq
fn can_derive_eq_fields(fields: &IdlDefinedFields) -> bool {
    match fields {
        IdlDefinedFields::Named(named) => named.iter().all(|f| can_type_derive_eq(&f.ty)),
        IdlDefinedFields::Tuple(types) => types.iter().all(can_type_derive_eq),
    }
}

/// Check if a type can derive Eq (f32/f64 cannot)
fn can_type_derive_eq(ty: &anchor_lang_idl::types::IdlType) -> bool {
    use anchor_lang_idl::types::IdlType;

    match ty {
        // f32 and f64 don't implement Eq
        IdlType::F32 | IdlType::F64 => false,
        // Primitives with Eq
        IdlType::Bool | IdlType::U8 | IdlType::I8 | IdlType::U16 | IdlType::I16
        | IdlType::U32 | IdlType::I32 | IdlType::U64 | IdlType::I64
        | IdlType::U128 | IdlType::I128 => true,
        IdlType::Pubkey => true,
        IdlType::String => true,
        IdlType::Bytes => true,
        IdlType::Vec(inner) => can_type_derive_eq(inner),
        IdlType::Option(inner) => can_type_derive_eq(inner),
        IdlType::Array(inner, _) => can_type_derive_eq(inner),
        // Assume user types can derive Eq
        IdlType::Defined { .. } => true,
        _ => true,
    }
}

fn should_derive_copy(fields: &Option<IdlDefinedFields>) -> bool {
    match fields {
        Some(IdlDefinedFields::Named(named_fields)) => {
            named_fields.iter().all(|f| is_copy_type(&f.ty))
        }
        Some(IdlDefinedFields::Tuple(tuple_fields)) => {
            tuple_fields.iter().all(is_copy_type)
        }
        None => true,
    }
}

fn is_copy_type(ty: &anchor_lang_idl::types::IdlType) -> bool {
    use anchor_lang_idl::types::IdlType;

    match ty {
        IdlType::Bool | IdlType::U8 | IdlType::I8 | IdlType::U16 | IdlType::I16
        | IdlType::U32 | IdlType::I32 | IdlType::F32 | IdlType::U64 | IdlType::I64
        | IdlType::F64 | IdlType::U128 | IdlType::I128 | IdlType::Pubkey => true,
        IdlType::Array(inner, _) => is_copy_type(inner),
        IdlType::Option(inner) => is_copy_type(inner),
        // Defined types - assume copy for now, might need refinement
        IdlType::Defined { .. } => true,
        // String and Vec are not Copy
        IdlType::String | IdlType::Bytes | IdlType::Vec(_) => false,
        _ => false,
    }
}

/// Generate manual Default implementation for structs that can't derive it
fn generate_manual_default(
    name: &syn::Ident,
    fields: &Option<IdlDefinedFields>,
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

    quote! {
        impl Default for #name {
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
        IdlType::U8 | IdlType::I8 | IdlType::U16 | IdlType::I16
        | IdlType::U32 | IdlType::I32 | IdlType::U64 | IdlType::I64
        | IdlType::U128 | IdlType::I128 => quote! { 0 },
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
    matches!(ty,
        IdlType::U8 | IdlType::I8 | IdlType::U16 | IdlType::I16
        | IdlType::U32 | IdlType::I32 | IdlType::U64 | IdlType::I64
        | IdlType::U128 | IdlType::I128
    )
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
