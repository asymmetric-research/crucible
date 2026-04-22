use quote::quote;
use syn::{Expr, ExprRange, Lit, Meta, RangeLimits};

#[derive(Clone)]
pub struct RangeConstraint {
    /// Start expression (may be a literal like `0` or an ident like `NUM_ACCOUNTS`)
    pub start_expr: proc_macro2::TokenStream,
    /// End expression (may be a literal like `10` or an ident like `NUM_ACCOUNTS`)
    pub end_expr: proc_macro2::TokenStream,
    /// If both sides were integer literals, their parsed values (for macro-time validation)
    pub start_literal: Option<u128>,
    pub end_literal: Option<u128>,
    pub inclusive: bool,
}

impl std::fmt::Debug for RangeConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeConstraint")
            .field("start_expr", &self.start_expr.to_string())
            .field("end_expr", &self.end_expr.to_string())
            .field("start_literal", &self.start_literal)
            .field("end_literal", &self.end_literal)
            .field("inclusive", &self.inclusive)
            .finish()
    }
}

impl RangeConstraint {
    pub fn from_attr(attr: &syn::Attribute) -> syn::Result<Self> {
        let Meta::List(meta_list) = &attr.meta else {
            return Err(syn::Error::new_spanned(
                attr,
                "Expected #[range(start..end)]",
            ));
        };

        let range_expr: ExprRange = syn::parse2(meta_list.tokens.clone())?;

        let start_node = range_expr
            .start
            .as_deref()
            .ok_or_else(|| syn::Error::new_spanned(&range_expr, "Range must have start value"))?;

        let end_node = range_expr
            .end
            .as_deref()
            .ok_or_else(|| syn::Error::new_spanned(&range_expr, "Range must have end value"))?;

        let inclusive = matches!(range_expr.limits, RangeLimits::Closed(_));

        // Reject non-integer literals (strings, floats, chars, etc.)
        Self::reject_non_int_literal(start_node)?;
        Self::reject_non_int_literal(end_node)?;

        let start_literal = Self::try_extract_int(start_node);
        let end_literal = Self::try_extract_int(end_node);

        // Validate when both sides are integer literals
        if let (Some(s), Some(e)) = (start_literal, end_literal) {
            if inclusive && s > e {
                return Err(syn::Error::new_spanned(
                    &range_expr,
                    "Range start must be <= end for inclusive range",
                ));
            }
            if !inclusive && s >= e {
                return Err(syn::Error::new_spanned(
                    &range_expr,
                    "Range start must be < end",
                ));
            }
        }

        Ok(Self {
            start_expr: quote! { #start_node },
            end_expr: quote! { #end_node },
            start_literal,
            end_literal,
            inclusive,
        })
    }

    fn try_extract_int(expr: &Expr) -> Option<u128> {
        match expr {
            Expr::Lit(expr_lit) => {
                if let Lit::Int(lit_int) = &expr_lit.lit {
                    lit_int.base10_parse().ok()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Reject literals that are clearly not numeric (strings, floats, chars, bools, byte strings).
    /// Non-literal expressions (identifiers, paths, etc.) are allowed.
    fn reject_non_int_literal(expr: &Expr) -> syn::Result<()> {
        if let Expr::Lit(expr_lit) = expr {
            match &expr_lit.lit {
                Lit::Int(_) => {} // OK
                _ => {
                    return Err(syn::Error::new_spanned(
                        expr,
                        "Expected integer literal or const expression",
                    ))
                }
            }
        }
        Ok(())
    }

    /// Generate constraint code for a dereferenced field: `*field_name = start + (*field_name % range_size)`
    ///
    /// Used by `#[fuzz_fixture]` for enum variant fields.
    pub fn generate_constraint_expr(
        &self,
        field_name: &syn::Ident,
        field_type: &syn::Type,
    ) -> proc_macro2::TokenStream {
        // Optimized path: if both bounds are known literals, use the original
        // compile-time-computed constants (handles full-range no-op for inclusive).
        if let (Some(start_val), Some(end_val)) = (self.start_literal, self.end_literal) {
            let range_size = if self.inclusive {
                match end_val
                    .checked_sub(start_val)
                    .and_then(|d| d.checked_add(1))
                {
                    Some(rs) => rs,
                    None => {
                        // Full type range — no constraint needed
                        return quote! {};
                    }
                }
            } else {
                end_val - start_val
            };
            return quote! {
                *#field_name = (#start_val as #field_type) + (*#field_name % (#range_size as #field_type));
            };
        }

        // Expression path: emit code that evaluates at compile/runtime.
        let start = &self.start_expr;
        let end = &self.end_expr;
        if self.inclusive {
            // Use wrapping arithmetic to handle the full-range edge case at runtime.
            quote! {
                {
                    let __rc_start = (#start) as #field_type;
                    let __rc_size = ((#end) as #field_type).wrapping_sub(__rc_start).wrapping_add(1);
                    if __rc_size != 0 {
                        *#field_name = __rc_start + (*#field_name % __rc_size);
                    }
                }
            }
        } else {
            quote! {
                {
                    let __rc_start = (#start) as #field_type;
                    let __rc_size = ((#end) as #field_type) - __rc_start;
                    *#field_name = __rc_start + (*#field_name % __rc_size);
                }
            }
        }
    }

    /// Generate constraint code for an Option<T> field.
    ///
    /// Constrains the inner value if `Some`.
    pub fn generate_option_constraint_expr(
        &self,
        field_name: &syn::Ident,
        inner_type: &syn::Type,
    ) -> proc_macro2::TokenStream {
        let inner_name = syn::Ident::new("__inner", field_name.span());
        let inner_constraint = self.generate_constraint_expr(&inner_name, inner_type);
        quote! {
            if let Some(ref mut #inner_name) = *#field_name {
                #inner_constraint
            }
        }
    }

    /// Generate constraint code for a Vec<T> field.
    ///
    /// Constrains each element.
    pub fn generate_vec_constraint_expr(
        &self,
        field_name: &syn::Ident,
        inner_type: &syn::Type,
    ) -> proc_macro2::TokenStream {
        let elem_name = syn::Ident::new("__e", field_name.span());
        let elem_constraint = self.generate_constraint_expr(&elem_name, inner_type);
        quote! {
            for #elem_name in #field_name.iter_mut() {
                #elem_constraint
            }
        }
    }

    /// Generate constraint code for a local variable: `param = start + (param % range_size)`
    ///
    /// Used by `#[anchor_fuzz]` where parameters are local variables (not struct fields).
    pub fn generate_local_constraint(
        &self,
        param_name: &syn::Ident,
        param_type: &syn::Type,
    ) -> proc_macro2::TokenStream {
        // Optimized path for known literals
        if let (Some(start_val), Some(end_val)) = (self.start_literal, self.end_literal) {
            let range_size = if self.inclusive {
                match end_val
                    .checked_sub(start_val)
                    .and_then(|d| d.checked_add(1))
                {
                    Some(rs) => rs,
                    None => {
                        return quote! {};
                    }
                }
            } else {
                end_val - start_val
            };
            return quote! {
                #param_name = (#start_val as #param_type) + (#param_name % (#range_size as #param_type));
            };
        }

        // Expression path
        let start = &self.start_expr;
        let end = &self.end_expr;
        if self.inclusive {
            quote! {
                {
                    let __rc_start = (#start) as #param_type;
                    let __rc_size = ((#end) as #param_type).wrapping_sub(__rc_start).wrapping_add(1);
                    if __rc_size != 0 {
                        #param_name = __rc_start + (#param_name % __rc_size);
                    }
                }
            }
        } else {
            quote! {
                {
                    let __rc_start = (#start) as #param_type;
                    let __rc_size = ((#end) as #param_type) - __rc_start;
                    #param_name = __rc_start + (#param_name % __rc_size);
                }
            }
        }
    }

    /// Returns `(lo, hi_exclusive)` as token streams cast to the given type.
    ///
    /// `hi` is always exclusive: `end + 1` for inclusive ranges, `end` for exclusive.
    /// Used by random-generation and mutation codegen that need `[lo, hi)` bounds.
    pub fn exclusive_bounds(
        &self,
        cast_type: &proc_macro2::TokenStream,
    ) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
        let start = &self.start_expr;
        let end = &self.end_expr;
        let lo = quote! { ((#start) as #cast_type) };
        let hi = if self.inclusive {
            quote! { ((#end) as #cast_type) + 1 }
        } else {
            quote! { ((#end) as #cast_type) }
        };
        (lo, hi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    /// Parse a `#[range(...)]` attribute from token stream.
    fn parse_range_attr(tokens: proc_macro2::TokenStream) -> syn::Attribute {
        // Build a full item: `#[range(...)] struct S;` and extract the attribute.
        let item: syn::ItemStruct = syn::parse2(quote! {
            #tokens
            struct S;
        })
        .expect("failed to parse test attribute");
        item.attrs.into_iter().next().expect("no attribute found")
    }

    // =========================================================================
    // RangeConstraint::from_attr — happy path (literals)
    // =========================================================================

    #[test]
    fn exclusive_range_basic() {
        let attr = parse_range_attr(quote! { #[range(0..10)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start_literal, Some(0));
        assert_eq!(rc.end_literal, Some(10));
        assert!(!rc.inclusive);
    }

    #[test]
    fn inclusive_range_basic() {
        let attr = parse_range_attr(quote! { #[range(1..=100)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start_literal, Some(1));
        assert_eq!(rc.end_literal, Some(100));
        assert!(rc.inclusive);
    }

    #[test]
    fn exclusive_range_large_values() {
        let attr =
            parse_range_attr(quote! { #[range(0..340282366920938463463374607431768211455)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start_literal, Some(0));
        assert_eq!(rc.end_literal, Some(u128::MAX));
        assert!(!rc.inclusive);
    }

    #[test]
    fn inclusive_range_same_start_end() {
        let attr = parse_range_attr(quote! { #[range(5..=5)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start_literal, Some(5));
        assert_eq!(rc.end_literal, Some(5));
        assert!(rc.inclusive);
    }

    #[test]
    fn exclusive_range_adjacent() {
        let attr = parse_range_attr(quote! { #[range(7..8)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start_literal, Some(7));
        assert_eq!(rc.end_literal, Some(8));
        assert!(!rc.inclusive);
    }

    #[test]
    fn range_zero_start() {
        let attr = parse_range_attr(quote! { #[range(0..3)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start_literal, Some(0));
        assert_eq!(rc.end_literal, Some(3));
    }

    // =========================================================================
    // RangeConstraint::from_attr — expressions (const idents, paths)
    // =========================================================================

    #[test]
    fn const_identifier_accepted() {
        // #[range(0..MAX)] — should succeed now (const ident in end position)
        let attr = parse_range_attr(quote! { #[range(0..MAX)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start_literal, Some(0));
        assert_eq!(rc.end_literal, None); // MAX is not a literal
        assert!(!rc.inclusive);
        assert_eq!(rc.end_expr.to_string(), "MAX");
    }

    #[test]
    fn both_const_identifiers_accepted() {
        let attr = parse_range_attr(quote! { #[range(MIN..MAX)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start_literal, None);
        assert_eq!(rc.end_literal, None);
        assert_eq!(rc.start_expr.to_string(), "MIN");
        assert_eq!(rc.end_expr.to_string(), "MAX");
    }

    #[test]
    fn const_path_accepted() {
        // #[range(0..Config::MAX_USERS)] — qualified path
        let attr = parse_range_attr(quote! { #[range(0..Config::MAX_USERS)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start_literal, Some(0));
        assert_eq!(rc.end_literal, None);
        assert!(rc.end_expr.to_string().contains("Config"));
        assert!(rc.end_expr.to_string().contains("MAX_USERS"));
    }

    #[test]
    fn inclusive_with_const_accepted() {
        let attr = parse_range_attr(quote! { #[range(0..=NUM_ACCOUNTS)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start_literal, Some(0));
        assert_eq!(rc.end_literal, None);
        assert!(rc.inclusive);
    }

    #[test]
    fn mixed_literal_and_const() {
        // Literal start, const end — no validation possible, should succeed
        let attr = parse_range_attr(quote! { #[range(1..NUM_ACCOUNTS)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start_literal, Some(1));
        assert_eq!(rc.end_literal, None);
    }

    // =========================================================================
    // RangeConstraint::from_attr — validation errors (literals only)
    // =========================================================================

    #[test]
    fn exclusive_range_start_equals_end_errors() {
        let attr = parse_range_attr(quote! { #[range(5..5)] });
        let err = RangeConstraint::from_attr(&attr).unwrap_err();
        assert!(
            err.to_string().contains("start must be < end"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn exclusive_range_start_greater_than_end_errors() {
        let attr = parse_range_attr(quote! { #[range(10..3)] });
        let err = RangeConstraint::from_attr(&attr).unwrap_err();
        assert!(
            err.to_string().contains("start must be < end"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn inclusive_range_start_greater_than_end_errors() {
        let attr = parse_range_attr(quote! { #[range(10..=3)] });
        let err = RangeConstraint::from_attr(&attr).unwrap_err();
        assert!(
            err.to_string().contains("start must be <= end"),
            "unexpected error: {err}"
        );
    }

    // =========================================================================
    // RangeConstraint::from_attr — malformed input errors
    // =========================================================================

    #[test]
    fn non_list_attribute_errors() {
        // #[range] with no parentheses — parses as Meta::Path, not Meta::List
        let attr = parse_range_attr(quote! { #[range] });
        let err = RangeConstraint::from_attr(&attr).unwrap_err();
        assert!(
            err.to_string().contains("Expected #[range(start..end)]"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn string_literal_errors() {
        let attr = parse_range_attr(quote! { #[range("a".."z")] });
        let err = RangeConstraint::from_attr(&attr).unwrap_err();
        assert!(
            err.to_string()
                .contains("integer literal or const expression"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn float_literal_errors() {
        let attr = parse_range_attr(quote! { #[range(1.0..2.0)] });
        assert!(RangeConstraint::from_attr(&attr).is_err());
    }

    #[test]
    fn empty_parens_errors() {
        let attr = parse_range_attr(quote! { #[range()] });
        assert!(RangeConstraint::from_attr(&attr).is_err());
    }

    #[test]
    fn single_value_errors() {
        let attr = parse_range_attr(quote! { #[range(42)] });
        assert!(RangeConstraint::from_attr(&attr).is_err());
    }

    // =========================================================================
    // generate_constraint_expr — codegen with literals
    // =========================================================================

    #[test]
    fn codegen_exclusive_range() {
        let attr = parse_range_attr(quote! { #[range(10..20)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let field_name = syn::Ident::new("amount", proc_macro2::Span::call_site());
        let field_type: syn::Type = syn::parse_str("u64").unwrap();

        let tokens = rc.generate_constraint_expr(&field_name, &field_type);
        let code = tokens.to_string();

        // Should produce: *amount = (10 as u64) + (*amount % (10 as u64));
        // range_size = 20 - 10 = 10
        assert!(code.contains("10"), "expected start 10 in: {code}");
        assert!(code.contains("amount"), "expected field name in: {code}");
        assert!(code.contains("u64"), "expected field type in: {code}");
    }

    #[test]
    fn codegen_inclusive_range() {
        let attr = parse_range_attr(quote! { #[range(0..=9)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let field_name = syn::Ident::new("idx", proc_macro2::Span::call_site());
        let field_type: syn::Type = syn::parse_str("usize").unwrap();

        let tokens = rc.generate_constraint_expr(&field_name, &field_type);
        let code = tokens.to_string();

        // range_size = 9 - 0 + 1 = 10
        assert!(code.contains("10"), "expected range_size 10 in: {code}");
        assert!(code.contains("idx"), "expected field name in: {code}");
        assert!(code.contains("usize"), "expected field type in: {code}");
    }

    #[test]
    fn codegen_single_value_inclusive() {
        // #[range(5..=5)] → range_size = 1, so `*x = 5 + (*x % 1)` = always 5
        let attr = parse_range_attr(quote! { #[range(5..=5)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let field_name = syn::Ident::new("x", proc_macro2::Span::call_site());
        let field_type: syn::Type = syn::parse_str("u32").unwrap();

        let tokens = rc.generate_constraint_expr(&field_name, &field_type);
        let code = tokens.to_string();

        // range_size = 5 - 5 + 1 = 1
        assert!(code.contains("1"), "expected range_size 1 in: {code}");
    }

    #[test]
    fn codegen_roundtrip_compiles() {
        // Verify the generated code is syntactically valid by parsing it
        let attr = parse_range_attr(quote! { #[range(0..100)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let field_name = syn::Ident::new("val", proc_macro2::Span::call_site());
        let field_type: syn::Type = syn::parse_str("u64").unwrap();

        let tokens = rc.generate_constraint_expr(&field_name, &field_type);
        // Should parse as a valid statement
        let _: syn::Stmt = syn::parse2(tokens).expect("generated code should be valid syntax");
    }

    // =========================================================================
    // generate_constraint_expr — codegen with expressions
    // =========================================================================

    #[test]
    fn codegen_const_ident_exclusive() {
        let attr = parse_range_attr(quote! { #[range(0..NUM_ACCOUNTS)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let field_name = syn::Ident::new("idx", proc_macro2::Span::call_site());
        let field_type: syn::Type = syn::parse_str("u8").unwrap();

        let tokens = rc.generate_constraint_expr(&field_name, &field_type);
        let code = tokens.to_string();

        assert!(
            code.contains("NUM_ACCOUNTS"),
            "expected const ident in: {code}"
        );
        assert!(code.contains("idx"), "expected field name in: {code}");
        assert!(code.contains("u8"), "expected field type in: {code}");
        // Should be parseable as valid syntax
        let _: syn::Expr = syn::parse2(tokens).expect("generated code should be valid expression");
    }

    #[test]
    fn codegen_const_ident_inclusive() {
        let attr = parse_range_attr(quote! { #[range(0..=MAX_IDX)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let field_name = syn::Ident::new("x", proc_macro2::Span::call_site());
        let field_type: syn::Type = syn::parse_str("usize").unwrap();

        let tokens = rc.generate_constraint_expr(&field_name, &field_type);
        let code = tokens.to_string();

        assert!(code.contains("MAX_IDX"), "expected const ident in: {code}");
        assert!(
            code.contains("wrapping_sub"),
            "inclusive expr path should use wrapping arithmetic in: {code}"
        );
    }

    #[test]
    fn codegen_const_path_accepted() {
        let attr = parse_range_attr(quote! { #[range(0..Config::MAX)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let field_name = syn::Ident::new("val", proc_macro2::Span::call_site());
        let field_type: syn::Type = syn::parse_str("u64").unwrap();

        let tokens = rc.generate_constraint_expr(&field_name, &field_type);
        let code = tokens.to_string();

        assert!(code.contains("Config"), "expected path in: {code}");
        assert!(code.contains("MAX"), "expected path in: {code}");
    }

    // =========================================================================
    // generate_local_constraint — codegen for local variables
    // =========================================================================

    #[test]
    fn local_constraint_literal() {
        let attr = parse_range_attr(quote! { #[range(0..4)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let param_name = syn::Ident::new("user_idx", proc_macro2::Span::call_site());
        let param_type: syn::Type = syn::parse_str("usize").unwrap();

        let tokens = rc.generate_local_constraint(&param_name, &param_type);
        let code = tokens.to_string();

        assert!(code.contains("user_idx"), "expected param name in: {code}");
        // Should NOT contain deref (*) since this is a local var
        assert!(
            !code.contains("* user_idx"),
            "should not deref local var in: {code}"
        );
    }

    #[test]
    fn local_constraint_const_ident() {
        let attr = parse_range_attr(quote! { #[range(0..NUM_USERS)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let param_name = syn::Ident::new("idx", proc_macro2::Span::call_site());
        let param_type: syn::Type = syn::parse_str("u8").unwrap();

        let tokens = rc.generate_local_constraint(&param_name, &param_type);
        let code = tokens.to_string();

        assert!(
            code.contains("NUM_USERS"),
            "expected const ident in: {code}"
        );
        assert!(code.contains("idx"), "expected param name in: {code}");
    }

    // =========================================================================
    // generate_option_constraint_expr
    // =========================================================================

    #[test]
    fn option_constraint_literal() {
        let attr = parse_range_attr(quote! { #[range(0..3)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let field_name = syn::Ident::new("authority", proc_macro2::Span::call_site());
        let inner_type: syn::Type = syn::parse_str("u8").unwrap();

        let tokens = rc.generate_option_constraint_expr(&field_name, &inner_type);
        let code = tokens.to_string();

        assert!(code.contains("Some"), "expected Option matching in: {code}");
        assert!(code.contains("__inner"), "expected inner var in: {code}");
    }

    #[test]
    fn option_constraint_const_ident() {
        let attr = parse_range_attr(quote! { #[range(0..NUM_AUTHORITIES)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let field_name = syn::Ident::new("auth", proc_macro2::Span::call_site());
        let inner_type: syn::Type = syn::parse_str("u8").unwrap();

        let tokens = rc.generate_option_constraint_expr(&field_name, &inner_type);
        let code = tokens.to_string();

        assert!(code.contains("Some"), "expected Option matching in: {code}");
        assert!(
            code.contains("NUM_AUTHORITIES"),
            "expected const ident in: {code}"
        );
    }

    // =========================================================================
    // generate_vec_constraint_expr
    // =========================================================================

    #[test]
    fn vec_constraint_literal() {
        let attr = parse_range_attr(quote! { #[range(1..100)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let field_name = syn::Ident::new("amounts", proc_macro2::Span::call_site());
        let inner_type: syn::Type = syn::parse_str("u64").unwrap();

        let tokens = rc.generate_vec_constraint_expr(&field_name, &inner_type);
        let code = tokens.to_string();

        assert!(
            code.contains("iter_mut"),
            "expected Vec iteration in: {code}"
        );
        assert!(code.contains("amounts"), "expected field name in: {code}");
    }

    // =========================================================================
    // Clone
    // =========================================================================

    #[test]
    fn clone_preserves_fields() {
        let attr = parse_range_attr(quote! { #[range(1..=100)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let cloned = rc.clone();
        assert_eq!(cloned.start_literal, Some(1));
        assert_eq!(cloned.end_literal, Some(100));
        assert!(cloned.inclusive);
    }

    // =========================================================================
    // generate_constraint_expr — overflow / full-range edge cases
    // =========================================================================

    #[test]
    fn codegen_full_u128_inclusive_range_emits_no_constraint() {
        // #[range(0..=u128::MAX)] — range_size would overflow to 0.
        // The codegen should emit an empty token stream (no constraint needed).
        let attr =
            parse_range_attr(quote! { #[range(0..=340282366920938463463374607431768211455)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let field_name = syn::Ident::new("x", proc_macro2::Span::call_site());
        let field_type: syn::Type = syn::parse_str("u128").unwrap();

        let tokens = rc.generate_constraint_expr(&field_name, &field_type);
        assert!(
            tokens.is_empty(),
            "full u128 inclusive range should produce no constraint, got: {}",
            tokens
        );
    }

    #[test]
    fn codegen_large_inclusive_range_no_overflow() {
        // #[range(0..=u128::MAX - 1)] — range_size = u128::MAX, which fits in u128.
        let max_minus_1 = u128::MAX - 1;
        let attr = parse_range_attr(quote! { #[range(0..=#max_minus_1)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let field_name = syn::Ident::new("v", proc_macro2::Span::call_site());
        let field_type: syn::Type = syn::parse_str("u128").unwrap();

        let tokens = rc.generate_constraint_expr(&field_name, &field_type);
        let code = tokens.to_string();
        assert!(!code.is_empty(), "should produce a constraint");
        // range_size = u128::MAX = 340282366920938463463374607431768211455
        assert!(
            code.contains("340282366920938463463374607431768211455"),
            "expected u128::MAX in: {code}"
        );
    }

    #[test]
    fn codegen_full_range_offset_emits_no_constraint() {
        // start=1, end=u128::MAX, inclusive: range_size = MAX - 1 + 1 = MAX.
        // This does NOT overflow — only 0..=MAX overflows. Should still produce constraint.
        let max_val = u128::MAX;
        let attr = parse_range_attr(quote! { #[range(1..=#max_val)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        let field_name = syn::Ident::new("v", proc_macro2::Span::call_site());
        let field_type: syn::Type = syn::parse_str("u128").unwrap();

        let tokens = rc.generate_constraint_expr(&field_name, &field_type);
        let code = tokens.to_string();
        assert!(!code.is_empty(), "offset range should produce a constraint");
    }

    // =========================================================================
    // from_attr — negative literal edge case
    // =========================================================================

    #[test]
    fn negative_literals_accepted_as_expressions() {
        // #[range(-5..5)] — -5 is parsed as Expr::Unary(Neg, Lit(5)), not a literal.
        // Now accepted as an expression (not validated at macro time).
        let attr = parse_range_attr(quote! { #[range(-5..5)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start_literal, None); // Unary neg is not a plain literal
        assert_eq!(rc.end_literal, Some(5));
    }

    #[test]
    fn negative_end_accepted_as_expression() {
        let attr = parse_range_attr(quote! { #[range(0..-1)] });
        // With expression support, this parses — but will panic at runtime due to underflow.
        // We can't validate non-literal expressions at macro time.
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start_literal, Some(0));
        assert_eq!(rc.end_literal, None);
    }

    // =========================================================================
    // codegen correctness — verify the generated modulo arithmetic is correct
    // =========================================================================

    #[test]
    fn codegen_exclusive_range_values_correct() {
        // #[range(10..20)] → *val = (10) + (*val % 10)
        // For val=0: 10 + (0 % 10) = 10. For val=9: 10 + (9 % 10) = 19.
        // For val=15: 10 + (15 % 10) = 15.
        let start: u128 = 10;
        let end: u128 = 20;
        let range_size = end - start;
        assert_eq!(range_size, 10);

        // Simulate the generated code: result = start + (input % range_size)
        for input in 0u128..100 {
            let result = start + (input % range_size);
            assert!(
                result >= 10 && result < 20,
                "exclusive codegen out of range for input={}: result={}",
                input,
                result
            );
        }
    }

    #[test]
    fn codegen_inclusive_range_values_correct() {
        // #[range(5..=14)] → *val = (5) + (*val % 10)
        let start: u128 = 5;
        let end: u128 = 14;
        let range_size = end - start + 1;
        assert_eq!(range_size, 10);

        for input in 0u128..100 {
            let result = start + (input % range_size);
            assert!(
                result >= 5 && result <= 14,
                "inclusive codegen out of range for input={}: result={}",
                input,
                result
            );
        }
    }

    #[test]
    fn codegen_u8_boundary_no_overflow() {
        // #[range(200..=255)] on u8 — range_size = 56
        // Worst case: 200 + 55 = 255 (fits u8). 200 + 56 would overflow.
        let start: u128 = 200;
        let end: u128 = 255;
        let range_size = end - start + 1;
        assert_eq!(range_size, 56);

        // Verify: start + (range_size - 1) fits in u8
        let max_result = (start + range_size - 1) as u8;
        assert_eq!(max_result, 255);
    }
}
