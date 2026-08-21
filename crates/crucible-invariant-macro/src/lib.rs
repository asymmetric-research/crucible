use crucible_macro_utils::{MaxLenConstraint, RangeConstraint};
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use syn::{parse_macro_input, FnArg, Ident, ImplItem, ItemFn, ItemImpl, PatType, Type};

static FALLBACK_MAIN_EMITTED: AtomicBool = AtomicBool::new(false);

fn read_cargo_features() -> Vec<String> {
    let manifest_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => dir,
        Err(_) => return Vec::new(),
    };
    let cargo_toml_path = std::path::PathBuf::from(&manifest_dir).join("Cargo.toml");
    let content = match std::fs::read_to_string(&cargo_toml_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut features = Vec::new();
    let mut in_features = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[features]" {
            in_features = true;
            continue;
        }
        if in_features && trimmed.starts_with('[') {
            break;
        }
        if in_features && !trimmed.is_empty() && !trimmed.starts_with('#') {
            if let Some(eq_pos) = trimmed.find('=') {
                let name = trimmed[..eq_pos].trim();
                if !name.is_empty() && name != "default" {
                    features.push(name.to_string());
                }
            }
        }
    }
    features
}

// Field type classification for FuzzAction code generation
enum FieldTypeKind {
    U8,
    U16,
    U32,
    U64,
    U128,
    I8,
    I16,
    I32,
    I64,
    I128,
    Usize,
    Bool,
    Option(Box<FieldTypeKind>),
    Vec(Box<FieldTypeKind>),
}

fn extract_generic_inner<'a>(ty: &'a Type, name: &str) -> Option<&'a Type> {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            if seg.ident == name {
                if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                        return Some(inner);
                    }
                }
            }
        }
    }
    None
}

fn extract_option_inner(ty: &Type) -> Option<&Type> {
    extract_generic_inner(ty, "Option")
}

fn extract_vec_inner(ty: &Type) -> Option<&Type> {
    extract_generic_inner(ty, "Vec")
}

fn classify_field_type(ty: &Type) -> FieldTypeKind {
    if let Some(inner) = extract_option_inner(ty) {
        return FieldTypeKind::Option(Box::new(classify_field_type(inner)));
    }
    if let Some(inner) = extract_vec_inner(ty) {
        return FieldTypeKind::Vec(Box::new(classify_field_type(inner)));
    }
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            return match seg.ident.to_string().as_str() {
                "u8" => FieldTypeKind::U8,
                "u16" => FieldTypeKind::U16,
                "u32" => FieldTypeKind::U32,
                "u64" => FieldTypeKind::U64,
                "u128" => FieldTypeKind::U128,
                "i8" => FieldTypeKind::I8,
                "i16" => FieldTypeKind::I16,
                "i32" => FieldTypeKind::I32,
                "i64" => FieldTypeKind::I64,
                "i128" => FieldTypeKind::I128,
                "usize" => FieldTypeKind::Usize,
                "bool" => FieldTypeKind::Bool,
                _ => FieldTypeKind::U64,
            };
        }
    }
    FieldTypeKind::U64
}

fn field_byte_size(kind: &FieldTypeKind, max_len: Option<usize>) -> usize {
    match kind {
        FieldTypeKind::Vec(inner) => {
            let ml = max_len.unwrap_or(8);
            let elem_size = match inner.as_ref() {
                FieldTypeKind::U128 | FieldTypeKind::I128 => 16,
                _ => 8, // all scalar types serialize as u64
            };
            8 + ml * elem_size // 8-byte length prefix + elements
        }
        FieldTypeKind::U128 | FieldTypeKind::I128 => 16,
        FieldTypeKind::Option(inner) => match inner.as_ref() {
            FieldTypeKind::Vec(vec_inner) => {
                let ml = max_len.unwrap_or(8);
                let elem_size = match vec_inner.as_ref() {
                    FieldTypeKind::U128 | FieldTypeKind::I128 => 16,
                    _ => 8,
                };
                8 + ml * elem_size // Option<Vec<T>> uses same layout as Vec<T>
            }
            FieldTypeKind::U128 | FieldTypeKind::I128 => 16,
            _ => 8, // Option<T> serializes as u64 (value or u64::MAX for None)
        },
        _ => 8, // all scalar types (bool, u8, u16, u32, u64, i*, usize) serialize as u64
    }
}

// ── helpers that produce *expressions* (no trailing comma / semicolon) ──

/// Expression that produces a random value of the given inner kind.
fn gen_inner_random_expr(
    inner_kind: &FieldTypeKind,
    inner_ty: Option<&Type>,
    constraint: Option<&RangeConstraint>,
) -> proc_macro2::TokenStream {
    match (inner_kind, constraint) {
        // u64 — boundary-aware generation
        (FieldTypeKind::U64, Some(c)) => {
            let (lo, hi) = c.exclusive_bounds(&quote! { u64 });
            quote! { crucible_fuzzer::gen_u64(rng, #lo, #hi) }
        }
        (FieldTypeKind::U64, None) => quote! { crucible_fuzzer::gen_u64(rng, 0, u64::MAX) },
        // u128 — boundary-aware generation
        (FieldTypeKind::U128, Some(c)) => {
            let (lo, hi) = c.exclusive_bounds(&quote! { u128 });
            quote! { crucible_fuzzer::gen_u128(rng, #lo, #hi) }
        }
        (FieldTypeKind::U128, None) => quote! { crucible_fuzzer::gen_u128(rng, 0, u128::MAX) },
        // u8/u16/u32 — boundary-aware via gen_u64 then cast
        (FieldTypeKind::U8 | FieldTypeKind::U16 | FieldTypeKind::U32, Some(c)) => {
            let (lo, hi) = c.exclusive_bounds(&quote! { u64 });
            let ty = inner_ty.expect("small unsigned needs inner_ty");
            quote! { crucible_fuzzer::gen_u64(rng, #lo, #hi) as #ty }
        }
        (FieldTypeKind::U8 | FieldTypeKind::U16 | FieldTypeKind::U32, None) => {
            let ty = inner_ty.expect("small unsigned needs inner_ty");
            quote! { crucible_fuzzer::gen_u64(rng, 0, (#ty::MAX as u64) + 1) as #ty }
        }
        // i64 — boundary-aware generation
        (FieldTypeKind::I64, Some(c)) => {
            let (lo, hi) = c.exclusive_bounds(&quote! { i64 });
            quote! { crucible_fuzzer::gen_i64(rng, #lo, #hi) }
        }
        (FieldTypeKind::I64, None) => quote! { crucible_fuzzer::gen_i64(rng, i64::MIN, i64::MAX) },
        // i128 — boundary-aware generation
        (FieldTypeKind::I128, Some(c)) => {
            let (lo, hi) = c.exclusive_bounds(&quote! { i128 });
            quote! { crucible_fuzzer::gen_i128(rng, #lo, #hi) }
        }
        (FieldTypeKind::I128, None) => {
            quote! { crucible_fuzzer::gen_i128(rng, i128::MIN, i128::MAX) }
        }
        // i8/i16/i32 — boundary-aware via gen_i64 then cast
        (FieldTypeKind::I8 | FieldTypeKind::I16 | FieldTypeKind::I32, Some(c)) => {
            let (lo, hi) = c.exclusive_bounds(&quote! { i64 });
            let ty = inner_ty.expect("small signed needs inner_ty");
            quote! { crucible_fuzzer::gen_i64(rng, #lo, #hi) as #ty }
        }
        (FieldTypeKind::I8 | FieldTypeKind::I16 | FieldTypeKind::I32, None) => {
            let ty = inner_ty.expect("small signed needs inner_ty");
            quote! { crucible_fuzzer::gen_i64(rng, #ty::MIN as i64, (#ty::MAX as i64) + 1) as #ty }
        }
        // usize — boundary-aware generation
        (FieldTypeKind::Usize, Some(c)) => {
            let (lo, hi) = c.exclusive_bounds(&quote! { usize });
            quote! { crucible_fuzzer::gen_usize(rng, #lo, #hi) }
        }
        (FieldTypeKind::Usize, None) => quote! { crucible_fuzzer::gen_usize(rng, 0, usize::MAX) },
        // bool — no boundary concept
        (FieldTypeKind::Bool, _) => quote! { crucible_fuzzer::rand_below(rng, 2) == 1 },
        (FieldTypeKind::Option(_), _) | (FieldTypeKind::Vec(_), _) => {
            unreachable!("handled at top level")
        }
    }
}

/// Statement that mutates a value through a mutable reference `ref_tok`.
/// `inner_ty` is the concrete type (e.g. u8, i32) for small-type widen/narrow.
fn gen_inner_mutate_stmt(
    inner_kind: &FieldTypeKind,
    inner_ty: Option<&Type>,
    ref_tok: &proc_macro2::TokenStream,
    constraint: Option<&RangeConstraint>,
) -> proc_macro2::TokenStream {
    match (inner_kind, constraint) {
        // u64 — direct call
        (FieldTypeKind::U64, Some(c)) => {
            let (lo, hi) = c.exclusive_bounds(&quote! { u64 });
            quote! { crucible_fuzzer::mutate_u64(#ref_tok, #lo, #hi, rng); }
        }
        (FieldTypeKind::U64, None) => {
            quote! { crucible_fuzzer::mutate_u64(#ref_tok, 0, u64::MAX, rng); }
        }
        // u128 — direct call
        (FieldTypeKind::U128, Some(c)) => {
            let (lo, hi) = c.exclusive_bounds(&quote! { u128 });
            quote! { crucible_fuzzer::mutate_u128(#ref_tok, #lo, #hi, rng); }
        }
        (FieldTypeKind::U128, None) => {
            quote! { crucible_fuzzer::mutate_u128(#ref_tok, 0, u128::MAX, rng); }
        }
        // u8/u16/u32 — widen to u64, mutate, narrow back
        (FieldTypeKind::U8 | FieldTypeKind::U16 | FieldTypeKind::U32, c) => {
            let ty = inner_ty.expect("small unsigned needs inner_ty");
            let (lo, hi) = match c {
                Some(c) => c.exclusive_bounds(&quote! { u64 }),
                None => (quote! { 0u64 }, quote! { (#ty::MAX as u64) + 1 }),
            };
            quote! {
                {
                    let mut __w = *#ref_tok as u64;
                    crucible_fuzzer::mutate_u64(&mut __w, #lo, #hi, rng);
                    *#ref_tok = __w as #ty;
                }
            }
        }
        // i64 — direct call
        (FieldTypeKind::I64, Some(c)) => {
            let (lo, hi) = c.exclusive_bounds(&quote! { i64 });
            quote! { crucible_fuzzer::mutate_i64(#ref_tok, #lo, #hi, rng); }
        }
        (FieldTypeKind::I64, None) => {
            quote! { crucible_fuzzer::mutate_i64(#ref_tok, i64::MIN, i64::MAX, rng); }
        }
        // i128 — direct call
        (FieldTypeKind::I128, Some(c)) => {
            let (lo, hi) = c.exclusive_bounds(&quote! { i128 });
            quote! { crucible_fuzzer::mutate_i128(#ref_tok, #lo, #hi, rng); }
        }
        (FieldTypeKind::I128, None) => {
            quote! { crucible_fuzzer::mutate_i128(#ref_tok, i128::MIN, i128::MAX, rng); }
        }
        // i8/i16/i32 — widen to i64, mutate, narrow back
        (FieldTypeKind::I8 | FieldTypeKind::I16 | FieldTypeKind::I32, c) => {
            let ty = inner_ty.expect("small signed needs inner_ty");
            let (lo, hi) = match c {
                Some(c) => c.exclusive_bounds(&quote! { i64 }),
                None => (quote! { #ty::MIN as i64 }, quote! { (#ty::MAX as i64) + 1 }),
            };
            quote! {
                {
                    let mut __w = *#ref_tok as i64;
                    crucible_fuzzer::mutate_i64(&mut __w, #lo, #hi, rng);
                    *#ref_tok = __w as #ty;
                }
            }
        }
        // usize — dedicated function
        (FieldTypeKind::Usize, Some(c)) => {
            let (lo, hi) = c.exclusive_bounds(&quote! { usize });
            quote! { crucible_fuzzer::mutate_usize(#ref_tok, #lo, #hi, rng); }
        }
        (FieldTypeKind::Usize, None) => {
            quote! { crucible_fuzzer::mutate_usize(#ref_tok, 0, usize::MAX, rng); }
        }
        // bool
        (FieldTypeKind::Bool, _) => {
            quote! { crucible_fuzzer::mutate_bool(#ref_tok, rng); }
        }
        (FieldTypeKind::Option(_), _) | (FieldTypeKind::Vec(_), _) => {
            unreachable!("handled at top level")
        }
    }
}

// ── top-level code-gen functions ──

/// Generate code for a random field value in FuzzAction::random_variant
fn gen_random_field_code(
    name: &Ident,
    ty: &Type,
    constraint: Option<&RangeConstraint>,
    max_len: Option<usize>,
) -> proc_macro2::TokenStream {
    let kind = classify_field_type(ty);

    if let FieldTypeKind::Vec(ref inner_kind) = kind {
        let ml = max_len.unwrap_or(8);
        let inner_ty = extract_vec_inner(ty);
        let inner_expr = gen_inner_random_expr(inner_kind, inner_ty, constraint);
        return quote! {
            #name: {
                let __len = crucible_fuzzer::rand_below(rng, #ml + 1);
                (0..__len).map(|_| #inner_expr).collect::<Vec<_>>()
            },
        };
    }

    let (inner_kind, is_option) = match &kind {
        FieldTypeKind::Option(inner) => (inner.as_ref(), true),
        other => (other, false),
    };
    let inner_ty = if is_option {
        extract_option_inner(ty)
    } else {
        Some(ty)
    };
    let inner_expr = gen_inner_random_expr(inner_kind, inner_ty, constraint);

    if is_option {
        quote! { #name: if crucible_fuzzer::rand_below(rng, 4) == 0 { None } else { Some(#inner_expr) }, }
    } else {
        quote! { #name: #inner_expr, }
    }
}

/// Generate code for a mutation match arm in FuzzAction::mutate
fn gen_mutate_field_code(
    field_idx: usize,
    name: &Ident,
    ty: &Type,
    constraint: Option<&RangeConstraint>,
    max_len: Option<usize>,
) -> proc_macro2::TokenStream {
    let kind = classify_field_type(ty);

    if let FieldTypeKind::Vec(ref inner_kind) = kind {
        let ml = max_len.unwrap_or(8);
        let inner_ty = extract_vec_inner(ty);
        let inner_random_expr = gen_inner_random_expr(inner_kind, inner_ty, constraint);
        let elem_ref = quote! { &mut #name[__idx] };
        let inner_mutate = gen_inner_mutate_stmt(inner_kind, inner_ty, &elem_ref, constraint);
        return quote! {
            #field_idx => {
                if crucible_fuzzer::rand_below(rng, 100) < 20 {
                    if #name.is_empty() || crucible_fuzzer::rand_below(rng, 2) == 0 {
                        if #name.len() < #ml {
                            #name.push(#inner_random_expr);
                        }
                    } else {
                        let __idx = crucible_fuzzer::rand_below(rng, #name.len());
                        #name.remove(__idx);
                    }
                } else if !#name.is_empty() {
                    let __idx = crucible_fuzzer::rand_below(rng, #name.len());
                    #inner_mutate
                }
            },
        };
    }

    let (inner_kind, is_option) = match &kind {
        FieldTypeKind::Option(inner) => (inner.as_ref(), true),
        other => (other, false),
    };

    if is_option {
        let inner_ty = extract_option_inner(ty);
        let random_expr = gen_inner_random_expr(inner_kind, inner_ty, constraint);
        let inner_ref = quote! { __inner };
        let mutate_stmt = gen_inner_mutate_stmt(inner_kind, inner_ty, &inner_ref, constraint);
        quote! {
            #field_idx => {
                if crucible_fuzzer::rand_below(rng, 100) < 15 {
                    if #name.is_some() {
                        *#name = None;
                    } else {
                        *#name = Some(#random_expr);
                    }
                } else if let Some(ref mut __inner) = #name {
                    #mutate_stmt
                }
            },
        }
    } else {
        let ref_tok = quote! { #name };
        let mutate_stmt = gen_inner_mutate_stmt(inner_kind, Some(ty), &ref_tok, constraint);
        quote! { #field_idx => { #mutate_stmt }, }
    }
}

/// Generate code for serializing a field in FuzzAction::serialize_fields
fn gen_serialize_field_code(
    name: &Ident,
    ty: &Type,
    max_len: Option<usize>,
) -> proc_macro2::TokenStream {
    let kind = classify_field_type(ty);

    if let FieldTypeKind::Vec(ref inner_kind) = kind {
        let ml = max_len.unwrap_or(8);
        let (elem_bytes, pad_bytes) = match inner_kind.as_ref() {
            FieldTypeKind::U128 => (
                quote! { (*__item as u128).to_le_bytes() },
                quote! { 0u128.to_le_bytes() },
            ),
            FieldTypeKind::I128 => (
                quote! { (*__item as u128).to_le_bytes() },
                quote! { 0u128.to_le_bytes() },
            ),
            FieldTypeKind::U8 | FieldTypeKind::U16 | FieldTypeKind::U32 | FieldTypeKind::U64 => (
                quote! { (*__item as u64).to_le_bytes() },
                quote! { 0u64.to_le_bytes() },
            ),
            FieldTypeKind::Usize => (
                quote! { (*__item as u64).to_le_bytes() },
                quote! { 0u64.to_le_bytes() },
            ),
            FieldTypeKind::Bool => (
                quote! { (if *__item { 1u64 } else { 0u64 }).to_le_bytes() },
                quote! { 0u64.to_le_bytes() },
            ),
            FieldTypeKind::I8 | FieldTypeKind::I16 | FieldTypeKind::I32 | FieldTypeKind::I64 => (
                quote! { (*__item as u64).to_le_bytes() },
                quote! { 0u64.to_le_bytes() },
            ),
            _ => unreachable!(),
        };
        return quote! {
            buf.extend_from_slice(&(#name.len() as u64).to_le_bytes());
            for __item in #name.iter() {
                buf.extend_from_slice(&#elem_bytes);
            }
            for _ in #name.len()..#ml {
                buf.extend_from_slice(&#pad_bytes);
            }
        };
    }

    let (inner_kind, is_option) = match &kind {
        FieldTypeKind::Option(inner) => (inner.as_ref(), true),
        other => (other, false),
    };

    // Expression that converts a value to le bytes.
    let to_bytes = |val_tok: proc_macro2::TokenStream,
                    kind: &FieldTypeKind|
     -> proc_macro2::TokenStream {
        match kind {
            FieldTypeKind::U128 => quote! { (#val_tok as u128).to_le_bytes() },
            FieldTypeKind::I128 => quote! { (#val_tok as u128).to_le_bytes() },
            FieldTypeKind::U8 | FieldTypeKind::U16 | FieldTypeKind::U32 | FieldTypeKind::U64 => {
                quote! { (#val_tok as u64).to_le_bytes() }
            }
            FieldTypeKind::Usize => quote! { (#val_tok as u64).to_le_bytes() },
            FieldTypeKind::Bool => quote! { (if #val_tok { 1u64 } else { 0u64 }).to_le_bytes() },
            FieldTypeKind::I8 | FieldTypeKind::I16 | FieldTypeKind::I32 | FieldTypeKind::I64 => {
                quote! { (#val_tok as u64).to_le_bytes() }
            }
            FieldTypeKind::Option(_) | FieldTypeKind::Vec(_) => unreachable!(),
        }
    };

    if is_option {
        let some_bytes = to_bytes(quote! { *__v }, inner_kind);
        let none_bytes = match inner_kind {
            FieldTypeKind::U128 | FieldTypeKind::I128 => quote! { u128::MAX.to_le_bytes() },
            _ => quote! { u64::MAX.to_le_bytes() },
        };
        quote! {
            match #name {
                Some(__v) => buf.extend_from_slice(&#some_bytes),
                None => buf.extend_from_slice(&#none_bytes),
            }
        }
    } else {
        let bytes = to_bytes(quote! { *#name }, inner_kind);
        quote! { buf.extend_from_slice(&#bytes); }
    }
}

/// Generate code for deserializing a field in FuzzAction::deserialize_fields
fn gen_deserialize_field_code(
    name: &Ident,
    ty: &Type,
    max_len: Option<usize>,
) -> proc_macro2::TokenStream {
    let kind = classify_field_type(ty);

    if let FieldTypeKind::Vec(ref inner_kind) = kind {
        let ml = max_len.unwrap_or(8);
        let is_128 = matches!(
            inner_kind.as_ref(),
            FieldTypeKind::U128 | FieldTypeKind::I128
        );
        let elem_size: usize = if is_128 { 16 } else { 8 };
        let (read_raw, raw_to_val) = if is_128 {
            let inner_ty = extract_vec_inner(ty).expect("Vec<T> inner type");
            (
                quote! { u128::from_le_bytes(bytes[*cursor..*cursor + 16].try_into().ok()?) },
                quote! { __raw as #inner_ty },
            )
        } else {
            match inner_kind.as_ref() {
                FieldTypeKind::U8
                | FieldTypeKind::U16
                | FieldTypeKind::U32
                | FieldTypeKind::U64 => {
                    let inner_ty = extract_vec_inner(ty).expect("Vec<T> inner type");
                    (
                        quote! { u64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().ok()?) },
                        quote! { __raw as #inner_ty },
                    )
                }
                FieldTypeKind::Usize => (
                    quote! { u64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().ok()?) },
                    quote! { __raw as usize },
                ),
                FieldTypeKind::Bool => (
                    quote! { u64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().ok()?) },
                    quote! { __raw != 0 },
                ),
                FieldTypeKind::I8
                | FieldTypeKind::I16
                | FieldTypeKind::I32
                | FieldTypeKind::I64 => {
                    let inner_ty = extract_vec_inner(ty).expect("Vec<T> inner type");
                    (
                        quote! { u64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().ok()?) },
                        quote! { __raw as #inner_ty },
                    )
                }
                _ => unreachable!(),
            }
        };
        return quote! {
            let __vec_len = (u64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().ok()?) as usize).min(#ml);
            *cursor += 8;
            let mut #name = Vec::with_capacity(__vec_len);
            for __i in 0usize..#ml {
                let __raw = #read_raw;
                if __i < __vec_len {
                    #name.push(#raw_to_val);
                }
                *cursor += #elem_size;
            }
        };
    }

    let (inner_kind, is_option) = match &kind {
        FieldTypeKind::Option(inner) => (inner.as_ref(), true),
        other => (other, false),
    };

    if is_option {
        match inner_kind {
            FieldTypeKind::U128 | FieldTypeKind::I128 => {
                let inner_ty = extract_option_inner(ty).unwrap_or(ty);
                quote! {
                    let __raw = u128::from_le_bytes(bytes[*cursor..*cursor + 16].try_into().ok()?);
                    let #name = if __raw == u128::MAX { None } else { Some(__raw as #inner_ty) };
                    *cursor += 16;
                }
            }
            _ => {
                let raw_to_val = match inner_kind {
                    FieldTypeKind::U8
                    | FieldTypeKind::U16
                    | FieldTypeKind::U32
                    | FieldTypeKind::U64 => {
                        let inner_ty = extract_option_inner(ty).unwrap_or(ty);
                        quote! { __raw as #inner_ty }
                    }
                    FieldTypeKind::Usize => quote! { __raw as usize },
                    FieldTypeKind::Bool => quote! { __raw != 0 },
                    FieldTypeKind::I8
                    | FieldTypeKind::I16
                    | FieldTypeKind::I32
                    | FieldTypeKind::I64 => {
                        let inner_ty = extract_option_inner(ty).unwrap_or(ty);
                        quote! { __raw as #inner_ty }
                    }
                    FieldTypeKind::Option(_) | FieldTypeKind::Vec(_) => unreachable!(),
                    FieldTypeKind::U128 | FieldTypeKind::I128 => unreachable!("handled above"),
                };
                quote! {
                    let __raw = u64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().ok()?);
                    let #name = if __raw == u64::MAX { None } else { Some(#raw_to_val) };
                    *cursor += 8;
                }
            }
        }
    } else {
        match inner_kind {
            FieldTypeKind::U128 => quote! {
                let #name = u128::from_le_bytes(bytes[*cursor..*cursor + 16].try_into().ok()?) as #ty;
                *cursor += 16;
            },
            FieldTypeKind::I128 => quote! {
                let #name = u128::from_le_bytes(bytes[*cursor..*cursor + 16].try_into().ok()?) as #ty;
                *cursor += 16;
            },
            FieldTypeKind::U8 | FieldTypeKind::U16 | FieldTypeKind::U32 | FieldTypeKind::U64 => {
                quote! {
                    let #name = u64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().ok()?) as #ty;
                    *cursor += 8;
                }
            }
            FieldTypeKind::Usize => quote! {
                let #name = u64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().ok()?) as usize;
                *cursor += 8;
            },
            FieldTypeKind::Bool => quote! {
                let #name = u64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().ok()?) != 0;
                *cursor += 8;
            },
            FieldTypeKind::I8 | FieldTypeKind::I16 | FieldTypeKind::I32 | FieldTypeKind::I64 => {
                quote! {
                    let #name = u64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().ok()?) as #ty;
                    *cursor += 8;
                }
            }
            FieldTypeKind::Option(_) | FieldTypeKind::Vec(_) => unreachable!(),
        }
    }
}

/// Generate code for extracting a field from a JSON params object.
/// Used by `from_name_and_params` to reconstruct actions from .meta.json.
fn gen_from_json_field_code(name: &Ident, ty: &Type) -> proc_macro2::TokenStream {
    let name_str = name.to_string();
    let kind = classify_field_type(ty);
    gen_from_json_kind(name, &name_str, ty, &kind)
}

fn gen_from_json_kind(
    name: &Ident,
    name_str: &str,
    ty: &Type,
    kind: &FieldTypeKind,
) -> proc_macro2::TokenStream {
    match kind {
        FieldTypeKind::U64 => quote! { let #name = __params.get(#name_str)?.as_u64()?; },
        FieldTypeKind::U8 => quote! { let #name = __params.get(#name_str)?.as_u64()? as u8; },
        FieldTypeKind::U16 => quote! { let #name = __params.get(#name_str)?.as_u64()? as u16; },
        FieldTypeKind::U32 => quote! { let #name = __params.get(#name_str)?.as_u64()? as u32; },
        FieldTypeKind::U128 => quote! { let #name = __params.get(#name_str)?.as_u64()? as u128; },
        FieldTypeKind::Usize => quote! { let #name = __params.get(#name_str)?.as_u64()? as usize; },
        FieldTypeKind::I64 => quote! { let #name = __params.get(#name_str)?.as_i64()?; },
        FieldTypeKind::I8 => quote! { let #name = __params.get(#name_str)?.as_i64()? as i8; },
        FieldTypeKind::I16 => quote! { let #name = __params.get(#name_str)?.as_i64()? as i16; },
        FieldTypeKind::I32 => quote! { let #name = __params.get(#name_str)?.as_i64()? as i32; },
        FieldTypeKind::I128 => quote! { let #name = __params.get(#name_str)?.as_i64()? as i128; },
        FieldTypeKind::Bool => quote! { let #name = __params.get(#name_str)?.as_bool()?; },
        FieldTypeKind::Option(inner) => {
            let inner_ty = extract_option_inner(ty).unwrap_or(ty);
            let inner_extract = match inner.as_ref() {
                FieldTypeKind::U64 => quote! { __v.as_u64()? },
                FieldTypeKind::U8 => quote! { __v.as_u64()? as u8 },
                FieldTypeKind::U16 => quote! { __v.as_u64()? as u16 },
                FieldTypeKind::U32 => quote! { __v.as_u64()? as u32 },
                FieldTypeKind::U128 => quote! { __v.as_u64()? as u128 },
                FieldTypeKind::Usize => quote! { __v.as_u64()? as usize },
                FieldTypeKind::I64 => quote! { __v.as_i64()? },
                FieldTypeKind::I8 => quote! { __v.as_i64()? as i8 },
                FieldTypeKind::I16 => quote! { __v.as_i64()? as i16 },
                FieldTypeKind::I32 => quote! { __v.as_i64()? as i32 },
                FieldTypeKind::I128 => quote! { __v.as_i64()? as i128 },
                FieldTypeKind::Bool => quote! { __v.as_bool()? },
                _ => quote! { __v.as_u64()? as #inner_ty },
            };
            quote! {
                let #name: Option<#inner_ty> = match __params.get(#name_str) {
                    Some(__v) if __v.is_null() => None,
                    Some(__v) => Some(#inner_extract),
                    None => None,
                };
            }
        }
        FieldTypeKind::Vec(inner) => {
            let inner_ty = extract_vec_inner(ty).unwrap_or(ty);
            let elem_extract = match inner.as_ref() {
                FieldTypeKind::U64 => quote! { __e.as_u64()? },
                FieldTypeKind::U8 => quote! { __e.as_u64()? as u8 },
                FieldTypeKind::U16 => quote! { __e.as_u64()? as u16 },
                FieldTypeKind::U32 => quote! { __e.as_u64()? as u32 },
                FieldTypeKind::U128 => quote! { __e.as_u64()? as u128 },
                FieldTypeKind::Usize => quote! { __e.as_u64()? as usize },
                FieldTypeKind::I64 => quote! { __e.as_i64()? },
                FieldTypeKind::I8 => quote! { __e.as_i64()? as i8 },
                FieldTypeKind::I16 => quote! { __e.as_i64()? as i16 },
                FieldTypeKind::I32 => quote! { __e.as_i64()? as i32 },
                FieldTypeKind::I128 => quote! { __e.as_i64()? as i128 },
                FieldTypeKind::Bool => quote! { __e.as_bool()? },
                _ => quote! { __e.as_u64()? as #inner_ty },
            };
            quote! {
                let #name: Vec<#inner_ty> = {
                    let __arr = __params.get(#name_str)?.as_array()?;
                    let __items: Option<Vec<#inner_ty>> = __arr.iter().map(|__e| Some(#elem_extract)).collect();
                    __items?
                };
            }
        }
    }
}

/// Generate constraint expression, handling Option<T> and Vec<T> by constraining inner values.
fn gen_constraint_code(
    field_name: &Ident,
    field_type: &Type,
    constraint: &RangeConstraint,
) -> proc_macro2::TokenStream {
    if let Some(inner_ty) = extract_vec_inner(field_type) {
        constraint.generate_vec_constraint_expr(field_name, &inner_ty)
    } else if let Some(inner_ty) = extract_option_inner(field_type) {
        constraint.generate_option_constraint_expr(field_name, &inner_ty)
    } else {
        constraint.generate_constraint_expr(field_name, field_type)
    }
}

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
    let mut max_lens: HashMap<(String, String), MaxLenConstraint> = HashMap::new();
    let mut has_after_action = false;

    // Expand include!() macros to discover actions defined in external files.
    // Also replace include!() items in the impl block with their expanded content,
    // because the compiler won't re-expand include!() in proc macro output.
    // Replace include!() macro items with expanded methods in the impl block
    let mut new_items: Vec<ImplItem> = Vec::new();
    let manifest_dir_str = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let src_dir_path = std::path::PathBuf::from(&manifest_dir_str).join("src");
    for item in input.items.drain(..) {
        if let ImplItem::Macro(ref mac) = item {
            if mac.mac.path.is_ident("include") {
                if let Ok(lit) = mac.mac.parse_body::<syn::LitStr>() {
                    let file_path = src_dir_path.join(lit.value());
                    if let Ok(content) = std::fs::read_to_string(&file_path) {
                        let wrapped = format!("impl Dummy {{ {} }}", content);
                        if let Ok(parsed) = syn::parse_str::<ItemImpl>(&wrapped) {
                            for inner in parsed.items {
                                new_items.push(inner);
                            }
                            continue;
                        }
                    }
                }
            }
        }
        new_items.push(item);
    }
    input.items = new_items;

    // Helper closure to process a method and extract action info
    fn process_method(
        method: &mut syn::ImplItemFn,
        actions: &mut Vec<(Ident, Ident, Vec<(Ident, Box<Type>)>)>,
        constraints: &mut HashMap<(String, String), RangeConstraint>,
        max_lens: &mut HashMap<(String, String), MaxLenConstraint>,
        has_after_action: &mut bool,
    ) {
        let method_name = method.sig.ident.to_string();

        if method_name == "after_action" {
            *has_after_action = true;
        }

        if method_name.starts_with("action_") {
            let action_name = &method_name[7..];
            let action_ident = format_ident!("{}", to_pascal_case(action_name));

            // A method may legitimately exist as TWO cfg-gated variants sharing the same name --
            // e.g. `#[cfg(feature = "admin_actions")]` and `#[cfg(not(feature = "admin_actions"))]`
            // implementations of the same `action_*` fn, exactly one of which survives cfg-stripping
            // in any given build. This macro runs on the raw, PRE-cfg-stripped item list, so both
            // are visible here -- without deduping, the SAME action name gets pushed twice, and the
            // generated dispatch enum/match ends up with a duplicate variant (E0428) even though at
            // most one method body is ever actually compiled in. Any of the cfg-alternate methods
            // resolves the same generated `self.#method_ident(...)` call site identically (they
            // share the same fn name and are meant to be interchangeable), so keeping just the
            // first-seen one for enum/param-constraint purposes is correct -- this is deliberately
            // NOT a "cfg says this one wins" choice, just "one entry per distinct action identity".
            if actions.iter().any(|(id, _, _)| id == &action_ident) {
                return;
            }

            let mut params = Vec::new();
            for arg in &mut method.sig.inputs {
                if let FnArg::Typed(PatType { pat, ty, attrs, .. }) = arg {
                    if let syn::Pat::Ident(pat_ident) = &**pat {
                        if pat_ident.ident != "self" {
                            if let Some(range_attr) =
                                attrs.iter().find(|a| a.path().is_ident("range"))
                            {
                                if let Ok(constraint) = RangeConstraint::from_attr(range_attr) {
                                    constraints.insert(
                                        (action_ident.to_string(), pat_ident.ident.to_string()),
                                        constraint,
                                    );
                                }
                            }
                            if let Some(ml_attr) =
                                attrs.iter().find(|a| a.path().is_ident("max_len"))
                            {
                                if let Ok(ml) = MaxLenConstraint::from_attr(ml_attr) {
                                    max_lens.insert(
                                        (action_ident.to_string(), pat_ident.ident.to_string()),
                                        ml,
                                    );
                                }
                            }
                            attrs.retain(|a| {
                                !a.path().is_ident("range") && !a.path().is_ident("max_len")
                            });
                            params.push((pat_ident.ident.clone(), ty.clone()));
                        }
                    }
                }
            }

            actions.push((action_ident, method.sig.ident.clone(), params));
        }
    }

    for item in &mut input.items {
        if let ImplItem::Fn(method) = item {
            process_method(
                method,
                &mut actions,
                &mut constraints,
                &mut max_lens,
                &mut has_after_action,
            );
        }
    }

    // (include!() methods are already expanded into input.items above)

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

    // Generate arms to convert action to JSON value (for .meta.json)
    let to_json_arms = actions.iter().map(|(action_name, _, params)| {
        if params.is_empty() {
            quote! {
                #enum_name::#action_name => crucible_test_context::serde_json::json!({}),
            }
        } else {
            let field_names: Vec<_> = params.iter().map(|(name, _)| name).collect();
            let json_fields = params.iter().map(|(name, _)| {
                let name_str = name.to_string();
                quote! { #name_str: #name }
            });
            quote! {
                #enum_name::#action_name { #(#field_names),* } => crucible_test_context::serde_json::json!({
                    #(#json_fields),*
                }),
            }
        }
    });

    let dispatch_arms = actions.iter().map(|(action_name, method_name, params)| {
        if params.is_empty() {
            quote! {
                #enum_name::#action_name => self.#method_name().into_success(),
            }
        } else {
            let param_names = params.iter().map(|(name, _)| name);
            let param_names_in_call = params.iter().map(|(name, _)| name);
            quote! {
                #enum_name::#action_name { #(#param_names),* } => {
                    self.#method_name(#(#param_names_in_call),*).into_success()
                }
            }
        }
    });

    // Generate constrain_in_place method to apply constraints to the inputs
    let constrain_arms: Vec<_> = actions
        .iter()
        .map(|(action_name, _, params)| {
            // Get each constraint for the field
            let field_constraints: Vec<_> = params
                .iter()
                .filter_map(|(field_name, field_type)| {
                    constraints
                        .get(&(action_name.to_string(), field_name.to_string()))
                        .map(|constraint| gen_constraint_code(field_name, field_type, constraint))
                })
                .collect();

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
        })
        .collect();

    // ===== Generate FuzzAction trait implementation arms =====
    let num_actions = actions.len();

    let mut random_variant_arms = Vec::new();
    let mut mutate_arms_fuzz = Vec::new();
    let mut variant_index_arms = Vec::new();
    let mut serialize_arms = Vec::new();
    let mut deserialize_arms = Vec::new();
    let mut fuzz_action_name_arms = Vec::new();
    let mut field_byte_count_arms = Vec::new();
    let mut from_json_arms = Vec::new();

    for (idx, (action_name, _, params)) in actions.iter().enumerate() {
        let action_str = to_snake_case(&action_name.to_string());

        if params.is_empty() {
            random_variant_arms.push(quote! { #idx => Self::#action_name, });
            mutate_arms_fuzz.push(quote! { Self::#action_name => {}, });
            variant_index_arms.push(quote! { Self::#action_name => #idx, });
            serialize_arms.push(quote! { Self::#action_name => {}, });
            deserialize_arms.push(quote! { #idx => Some(Self::#action_name), });
            fuzz_action_name_arms.push(quote! { Self::#action_name => #action_str, });
            field_byte_count_arms.push(quote! { #idx => 0, });
            from_json_arms.push(quote! { #action_str => Some(Self::#action_name), });
        } else {
            let field_names: Vec<_> = params.iter().map(|(name, _)| name.clone()).collect();
            let num_fields = params.len();

            // Compute cumulative byte offsets for variable-width fields (Vec)
            let field_sizes: Vec<usize> = params
                .iter()
                .map(|(name, ty)| {
                    let kind = classify_field_type(ty);
                    let ml = max_lens
                        .get(&(action_name.to_string(), name.to_string()))
                        .map(|m| m.max_len);
                    field_byte_size(&kind, ml)
                })
                .collect();
            let total_bytes: usize = field_sizes.iter().sum();

            let random_fields: Vec<_> = params
                .iter()
                .map(|(name, ty)| {
                    let c = constraints.get(&(action_name.to_string(), name.to_string()));
                    let ml = max_lens
                        .get(&(action_name.to_string(), name.to_string()))
                        .map(|m| m.max_len);
                    gen_random_field_code(name, ty, c, ml)
                })
                .collect();

            let mutate_field_arms: Vec<_> = params
                .iter()
                .enumerate()
                .map(|(fi, (name, ty))| {
                    let c = constraints.get(&(action_name.to_string(), name.to_string()));
                    let ml = max_lens
                        .get(&(action_name.to_string(), name.to_string()))
                        .map(|m| m.max_len);
                    gen_mutate_field_code(fi, name, ty, c, ml)
                })
                .collect();

            let ser_fields: Vec<_> = params
                .iter()
                .map(|(name, ty)| {
                    let ml = max_lens
                        .get(&(action_name.to_string(), name.to_string()))
                        .map(|m| m.max_len);
                    gen_serialize_field_code(name, ty, ml)
                })
                .collect();

            let deser_fields: Vec<_> = params
                .iter()
                .map(|(name, ty)| {
                    let ml = max_lens
                        .get(&(action_name.to_string(), name.to_string()))
                        .map(|m| m.max_len);
                    gen_deserialize_field_code(name, ty, ml)
                })
                .collect();

            random_variant_arms.push(quote! {
                #idx => Self::#action_name { #(#random_fields)* },
            });

            mutate_arms_fuzz.push(quote! {
                Self::#action_name { #(#field_names),* } => {
                    let num_mutations = 1 + crucible_fuzzer::rand_below(rng, (#num_fields).min(3));
                    for _ in 0..num_mutations {
                        match crucible_fuzzer::rand_below(rng, #num_fields) {
                            #(#mutate_field_arms)*
                            _ => {}
                        }
                    }
                },
            });

            variant_index_arms.push(quote! { Self::#action_name { .. } => #idx, });

            serialize_arms.push(quote! {
                Self::#action_name { #(#field_names),* } => {
                    #(#ser_fields)*
                },
            });

            deserialize_arms.push(quote! {
                #idx => {
                    if *cursor + #total_bytes > bytes.len() {
                        return None;
                    }
                    #(#deser_fields)*
                    Some(Self::#action_name { #(#field_names),* })
                },
            });

            fuzz_action_name_arms.push(quote! { Self::#action_name { .. } => #action_str, });

            field_byte_count_arms.push(quote! { #idx => #total_bytes, });

            // Generate from_name_and_params arm for this variant
            let from_json_fields: Vec<_> = params
                .iter()
                .map(|(name, ty)| gen_from_json_field_code(name, ty))
                .collect();
            from_json_arms.push(quote! {
                #action_str => {
                    #(#from_json_fields)*
                    Some(Self::#action_name { #(#field_names),* })
                },
            });
        }
    }

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

                /// Get the action parameters as a JSON value (for .meta.json)
                pub fn to_json_params(&self) -> crucible_test_context::serde_json::Value {
                    match self {
                        #(#to_json_arms)*
                    }
                }
            }

            // FuzzAction trait implementation for structured mutation support
            impl crucible_fuzzer::FuzzAction for #enum_name {
                fn variant_count() -> usize {
                    #num_actions
                }

                fn random_variant<R: crucible_fuzzer::FuzzRand>(variant_idx: usize, rng: &mut R) -> Self {
                    match variant_idx % #num_actions {
                        #(#random_variant_arms)*
                        _ => unreachable!(),
                    }
                }

                fn mutate<R: crucible_fuzzer::FuzzRand>(&mut self, rng: &mut R) {
                    match self {
                        #(#mutate_arms_fuzz)*
                    }
                }

                fn action_name(&self) -> &'static str {
                    match self {
                        #(#fuzz_action_name_arms)*
                    }
                }

                fn variant_index(&self) -> usize {
                    match self {
                        #(#variant_index_arms)*
                    }
                }

                fn serialize_fields(&self, buf: &mut Vec<u8>) {
                    match self {
                        #(#serialize_arms)*
                    }
                }

                fn deserialize_fields(variant_idx: usize, bytes: &[u8], cursor: &mut usize) -> Option<Self> {
                    match variant_idx {
                        #(#deserialize_arms)*
                        _ => None,
                    }
                }

                fn field_byte_count(variant_idx: usize) -> usize {
                    match variant_idx {
                        #(#field_byte_count_arms)*
                        _ => 0,
                    }
                }

                fn from_name_and_params(__name: &str, __params: &crucible_fuzzer::serde_json::Value) -> Option<Self> {
                    match __name {
                        #(#from_json_arms)*
                        _ => None,
                    }
                }
            }

            impl #fixture_type {
                #[doc(hidden)]
                /// Dispatch an action and return whether it succeeded.
                /// Works with actions that return () (always success) or Result<(), E> (success/failure).
                pub fn __dispatch_action(&mut self, action: #enum_name) -> bool {
                    use crucible_test_context::IntoActionSuccess;

                    // Set current instruction name for coverage tracking
                    crucible_test_context::set_current_instruction(Some(action.action_name().to_string()));

                    // Dispatch the action and convert result to success bool
                    let success = match action {
                        #(#dispatch_arms)*
                    };

                    // Clear after action
                    crucible_test_context::set_current_instruction(None);

                    // Call after_action callback if defined
                    self.__maybe_after_action();

                    success
                }

                #[doc(hidden)]
                pub fn __auto_flush(&mut self) {
                    let _ = self.ctx.send_batch();
                }
            }
        }
    };

    // Add after_action callback if the method exists
    let after_action_impl = if has_after_action {
        quote! {
            impl #fixture_type {
                #[doc(hidden)]
                #[inline(always)]
                fn __maybe_after_action(&mut self) {
                    self.after_action();
                }
            }
        }
    } else {
        quote! {
            impl #fixture_type {
                #[doc(hidden)]
                #[inline(always)]
                fn __maybe_after_action(&mut self) {
                    // No after_action callback defined
                }
            }
        }
    };

    let fallback_main = if !FALLBACK_MAIN_EMITTED.swap(true, Ordering::SeqCst) {
        let features = read_cargo_features();
        if features.is_empty() {
            quote! {}
        } else {
            let feature_guards: Vec<_> = features
                .iter()
                .map(|f| {
                    quote! { feature = #f }
                })
                .collect();
            quote! {
                #[cfg(not(any(#(#feature_guards),*)))]
                fn main() {
                    eprintln!("No fuzz test selected. Build with --features <test_name>");
                    std::process::exit(1);
                }
            }
        }
    } else {
        quote! {}
    };

    let final_output = quote! {
        #generated
        #after_action_impl
        #fallback_main
    };

    TokenStream::from(final_output)
}

#[proc_macro_attribute]
pub fn invariant_test(args: TokenStream, item: TokenStream) -> TokenStream {
    // Structured mutation is always used for invariant_test — no arguments accepted
    let args_tokens = proc_macro2::TokenStream::from(args);
    if !args_tokens.is_empty() {
        return syn::Error::new_spanned(
            args_tokens,
            "invariant_test no longer accepts arguments. Structured mutation is now the default.",
        )
        .to_compile_error()
        .into();
    }

    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let fn_body = &input_fn.block;

    // Extract fixture type from first parameter
    let fixture_param = input_fn
        .sig
        .inputs
        .first()
        .expect("invariant_test function must have a fixture parameter");

    let FnArg::Typed(pat_type) = fixture_param else {
        return syn::Error::new_spanned(fixture_param, "Expected typed parameter")
            .to_compile_error()
            .into();
    };

    // Extract type from &mut FixtureType or &FixtureType
    let fixture_type = match &*pat_type.ty {
        Type::Reference(type_ref) => &*type_ref.elem,
        _ => {
            return syn::Error::new_spanned(
                &pat_type.ty,
                "Fixture parameter must be a reference (&mut FixtureType)",
            )
            .to_compile_error()
            .into();
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
                "Expected a simple type path for fixture",
            )
            .to_compile_error()
            .into();
        }
    };

    let mod_name = format_ident!("__{}_fuzz", to_snake_case(&fixture_name.to_string()));
    let enum_name = format_ident!("{}Actions", fixture_name);

    let test_name_str = fn_name.to_string();

    let fuzz_attr = quote! { #[crucible_fuzz(structured)] };

    let expanded = quote! {
        #fuzz_attr
        fn #fn_name(fixture: &mut #fixture_name, actions: Vec<#mod_name::#enum_name>) {
            let debug = std::env::var("FUZZ_DEBUG").is_ok();
            let capped_len = actions.len();

            if debug {
                eprintln!("[FUZZ] Starting iteration with {} actions", capped_len);
            }

            // Clear action history and violation tracking at start of iteration
            crucible_test_context::clear_iteration_state();
            // Track total actions for early exit display
            crucible_test_context::set_total_actions(capped_len);
            // Set test name for metadata
            crucible_test_context::set_current_test_name(#test_name_str);
            // Set total variant count for monitor display (idempotent)
            crucible_test_context::TOTAL_ACTION_VARIANTS.store(
                <#mod_name::#enum_name as crucible_fuzzer::FuzzAction>::variant_count(),
                std::sync::atomic::Ordering::Relaxed,
            );

            // Keep executed actions for backfilling JSON params on crash/violation.
            // Only the action names are recorded during the hot loop (push_action_record_lite),
            // and full JSON params are materialized lazily when needed.
            let mut __executed_actions: Vec<#mod_name::#enum_name> = Vec::with_capacity(capped_len);

            for (i, mut action) in actions.into_iter().enumerate() {
                action.constrain_in_place();

                if debug {
                    eprintln!("[FUZZ] Action {}: {:?}", i, action);
                }

                let variant_idx = crucible_fuzzer::FuzzAction::variant_index(&action);

                // Execute the action and get success status
                let success = fixture.__dispatch_action(action.clone());

                if success {
                    crucible_test_context::mark_variant_succeeded(variant_idx);
                }

                // Record lite action (no JSON serialization — deferred to crash/violation)
                crucible_test_context::push_action_record_lite(action.action_name(), success);

                // Keep the action for potential param backfill (move, no extra clone)
                __executed_actions.push(action);

                #fn_body

                // Per-action replay diagnostic: log success + violation + state hash
                if crucible_test_context::is_debug_replay() {
                    let __has_viol = crucible_test_context::has_violation();
                    let __dirty_keys: Vec<_> = fixture.ctx.dirty_tracker.dirty_accounts().iter().copied().collect();
                    let (__state_hash, __slot) = crucible_test_context::compute_svm_debug_hash(
                        &fixture.ctx.svm, &__dirty_keys,
                    );
                    eprintln!("[REPLAY_DIAG] action={}/{} variant={} success={} violation={} slot={} hash={:016x}",
                        i + 1, capped_len,
                        __executed_actions.last().unwrap().action_name(),
                        success, __has_viol, __slot, __state_hash);
                }

                // === EARLY EXIT: Stop immediately if invariant was violated ===
                if crucible_test_context::has_violation() {
                    // Backfill JSON params for ALL executed actions (needed for crash metadata + fuzz show)
                    for (j, a) in __executed_actions.iter().enumerate() {
                        crucible_test_context::backfill_action_params(j, a.to_json_params());
                    }
                    crucible_test_context::set_violation_action_index(i);
                    break;
                }

                // Stop chain on first failure in stateful mode
                // (failed actions produce dead-end states, continuing wastes SVM executions)
                if !success && crucible_test_context::is_stateful_chain_mode() {
                    break;
                }
            }

            // Backfill ALL action params after the loop if not already done by violation.
            // This ensures `fuzz show --replay` and crash metadata always have full params.
            // Only runs in replay/verbose mode — not on the normal fuzzing hot path.
            if !crucible_test_context::has_violation()
                && (std::env::var("FUZZ_INPUT_FILE").is_ok() || debug)
            {
                for (j, a) in __executed_actions.iter().enumerate() {
                    crucible_test_context::backfill_action_params(j, a.to_json_params());
                }
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

/// Parse `[features]` section from Cargo.toml content string.
/// Extracted for testability (read_cargo_features reads from disk).
fn parse_features_from_content(content: &str) -> Vec<String> {
    let mut features = Vec::new();
    let mut in_features = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[features]" {
            in_features = true;
            continue;
        }
        if in_features && trimmed.starts_with('[') {
            break;
        }
        if in_features && !trimmed.is_empty() && !trimmed.starts_with('#') {
            if let Some(eq_pos) = trimmed.find('=') {
                let name = trimmed[..eq_pos].trim();
                if !name.is_empty() && name != "default" {
                    features.push(name.to_string());
                }
            }
        }
    }
    features
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::Type;

    fn parse_type(s: &str) -> Type {
        syn::parse_str::<Type>(s).unwrap()
    }

    // ========================================================================
    // classify_field_type tests
    // ========================================================================

    #[test]
    fn test_classify_u8() {
        assert!(matches!(
            classify_field_type(&parse_type("u8")),
            FieldTypeKind::U8
        ));
    }

    #[test]
    fn test_classify_u64() {
        assert!(matches!(
            classify_field_type(&parse_type("u64")),
            FieldTypeKind::U64
        ));
    }

    #[test]
    fn test_classify_u128() {
        assert!(matches!(
            classify_field_type(&parse_type("u128")),
            FieldTypeKind::U128
        ));
    }

    #[test]
    fn test_classify_bool() {
        assert!(matches!(
            classify_field_type(&parse_type("bool")),
            FieldTypeKind::Bool
        ));
    }

    #[test]
    fn test_classify_i64() {
        assert!(matches!(
            classify_field_type(&parse_type("i64")),
            FieldTypeKind::I64
        ));
    }

    #[test]
    fn test_classify_usize() {
        assert!(matches!(
            classify_field_type(&parse_type("usize")),
            FieldTypeKind::Usize
        ));
    }

    #[test]
    fn test_classify_vec_u64() {
        match classify_field_type(&parse_type("Vec<u64>")) {
            FieldTypeKind::Vec(inner) => assert!(matches!(*inner, FieldTypeKind::U64)),
            other => panic!(
                "Expected Vec(U64), got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn test_classify_option_u64() {
        match classify_field_type(&parse_type("Option<u64>")) {
            FieldTypeKind::Option(inner) => assert!(matches!(*inner, FieldTypeKind::U64)),
            other => panic!(
                "Expected Option(U64), got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn test_classify_option_vec() {
        match classify_field_type(&parse_type("Option<Vec<u8>>")) {
            FieldTypeKind::Option(inner) => match *inner {
                FieldTypeKind::Vec(elem) => assert!(matches!(*elem, FieldTypeKind::U8)),
                _ => panic!("Expected Vec inside Option"),
            },
            _ => panic!("Expected Option"),
        }
    }

    #[test]
    fn test_classify_unknown_defaults_u64() {
        // Unknown type names default to U64
        assert!(matches!(
            classify_field_type(&parse_type("Pubkey")),
            FieldTypeKind::U64
        ));
        assert!(matches!(
            classify_field_type(&parse_type("MyCustomType")),
            FieldTypeKind::U64
        ));
    }

    // ========================================================================
    // field_byte_size tests
    // ========================================================================

    #[test]
    fn test_byte_size_u64() {
        assert_eq!(field_byte_size(&FieldTypeKind::U64, None), 8);
    }

    #[test]
    fn test_byte_size_u128() {
        assert_eq!(field_byte_size(&FieldTypeKind::U128, None), 16);
    }

    #[test]
    fn test_byte_size_bool() {
        assert_eq!(field_byte_size(&FieldTypeKind::Bool, None), 8);
    }

    #[test]
    fn test_byte_size_vec_default() {
        // Vec(U64) with no max_len → 8 + 8*8 = 72
        let kind = FieldTypeKind::Vec(Box::new(FieldTypeKind::U64));
        assert_eq!(field_byte_size(&kind, None), 8 + 8 * 8);
    }

    #[test]
    fn test_byte_size_vec_max_len() {
        // Vec(U64) with max_len=4 → 8 + 4*8 = 40
        let kind = FieldTypeKind::Vec(Box::new(FieldTypeKind::U64));
        assert_eq!(field_byte_size(&kind, Some(4)), 8 + 4 * 8);
    }

    #[test]
    fn test_byte_size_option() {
        // Option(U64) → 8
        let kind = FieldTypeKind::Option(Box::new(FieldTypeKind::U64));
        assert_eq!(field_byte_size(&kind, None), 8);
    }

    #[test]
    fn test_byte_size_option_u128() {
        // Option(U128) → 16
        let kind = FieldTypeKind::Option(Box::new(FieldTypeKind::U128));
        assert_eq!(field_byte_size(&kind, None), 16);
    }

    #[test]
    fn test_byte_size_vec_u128() {
        // Vec(U128) with max_len=3 → 8 + 3*16 = 56
        let kind = FieldTypeKind::Vec(Box::new(FieldTypeKind::U128));
        assert_eq!(field_byte_size(&kind, Some(3)), 8 + 3 * 16);
    }

    #[test]
    fn test_byte_size_all_scalars_are_8() {
        for kind in [
            FieldTypeKind::U8,
            FieldTypeKind::U16,
            FieldTypeKind::U32,
            FieldTypeKind::U64,
            FieldTypeKind::I8,
            FieldTypeKind::I16,
            FieldTypeKind::I32,
            FieldTypeKind::I64,
            FieldTypeKind::Usize,
            FieldTypeKind::Bool,
        ] {
            assert_eq!(
                field_byte_size(&kind, None),
                8,
                "Scalar {:?} should be 8 bytes",
                std::mem::discriminant(&kind)
            );
        }
    }

    #[test]
    fn test_byte_size_option_vec() {
        let kind =
            FieldTypeKind::Option(Box::new(FieldTypeKind::Vec(Box::new(FieldTypeKind::U64))));
        let actual = field_byte_size(&kind, None);
        // Option<Vec<u64>> should match Vec<u64> byte size: 8-byte length prefix + 8*8 elements
        assert_eq!(
            actual, 72,
            "Option<Vec<u64>> should match Vec<u64> byte size"
        );
    }

    // ========================================================================
    // parse_features_from_content tests
    // ========================================================================

    #[test]
    fn test_parse_features_basic() {
        let content = "[features]\nfoo = []\nbar = [\"dep\"]\n";
        let features = parse_features_from_content(content);
        assert_eq!(features, vec!["foo", "bar"]);
    }

    #[test]
    fn test_parse_features_skips_default() {
        let content = "[features]\ndefault = [\"foo\"]\nfoo = []\nbar = []\n";
        let features = parse_features_from_content(content);
        assert_eq!(features, vec!["foo", "bar"]);
    }

    #[test]
    fn test_parse_features_skips_comments() {
        let content = "[features]\n# this is a comment\nfoo = []\n# another comment\nbar = []\n";
        let features = parse_features_from_content(content);
        assert_eq!(features, vec!["foo", "bar"]);
    }

    #[test]
    fn test_parse_features_stops_at_next_section() {
        let content = "[features]\nfoo = []\n[dependencies]\nbar = \"1.0\"\n";
        let features = parse_features_from_content(content);
        assert_eq!(features, vec!["foo"]);
    }

    #[test]
    fn test_parse_features_empty() {
        let content = "[dependencies]\nfoo = \"1.0\"\n";
        let features = parse_features_from_content(content);
        assert!(features.is_empty());
    }

    #[test]
    fn test_parse_features_no_content() {
        let features = parse_features_from_content("");
        assert!(features.is_empty());
    }

    // ========================================================================
    // extract_generic_inner / type helper tests
    // ========================================================================

    #[test]
    fn test_extract_vec_inner() {
        let ty = parse_type("Vec<u64>");
        let inner = extract_vec_inner(&ty);
        assert!(inner.is_some());
        assert!(matches!(
            classify_field_type(inner.unwrap()),
            FieldTypeKind::U64
        ));
    }

    #[test]
    fn test_extract_option_inner() {
        let ty = parse_type("Option<bool>");
        let inner = extract_option_inner(&ty);
        assert!(inner.is_some());
        assert!(matches!(
            classify_field_type(inner.unwrap()),
            FieldTypeKind::Bool
        ));
    }

    #[test]
    fn test_extract_non_generic() {
        let ty = parse_type("u64");
        assert!(extract_vec_inner(&ty).is_none());
        assert!(extract_option_inner(&ty).is_none());
    }

    #[test]
    fn test_extract_wrong_name() {
        let ty = parse_type("HashMap<K, V>");
        assert!(extract_generic_inner(&ty, "Vec").is_none());
        assert!(extract_generic_inner(&ty, "Option").is_none());
    }
}
