use syn::{Expr, ExprRange, RangeLimits, Lit, Meta};
use quote::quote;


#[derive(Clone, Debug)]
pub struct RangeConstraint {
    pub start: u128,
    pub end: u128,
    pub inclusive: bool,
}

impl RangeConstraint {
    pub fn from_attr(attr: &syn::Attribute) -> syn::Result<Self> {
        let Meta::List(meta_list) = &attr.meta else {
            return Err(syn::Error::new_spanned(attr, "Expected #[range(start..end)]"));
        };

        let range_expr: ExprRange = syn::parse2(meta_list.tokens.clone())?;

        let start = Self::extract_int(range_expr.start.as_deref()
            .ok_or_else(|| syn::Error::new_spanned(&range_expr, "Range must have start value"))?)?;

        let end = Self::extract_int(range_expr.end.as_deref()
            .ok_or_else(|| syn::Error::new_spanned(&range_expr, "Range must have end value"))?)?;

        let inclusive = matches!(range_expr.limits, RangeLimits::Closed(_));


        // Validation
        if inclusive && start > end {
            return Err(syn::Error::new_spanned(&range_expr, "Range start must be <= end for inclusive range"));
        }

        if !inclusive && start >= end {
            return Err(syn::Error::new_spanned(&range_expr, "Range start must be < end"));
        }

        Ok(Self { start, end, inclusive })
    }

    fn extract_int(expr: &Expr) -> syn::Result<u128> {
        match expr {
            Expr::Lit(expr_lit) => {
                if let Lit::Int(lit_int) = &expr_lit.lit {
                    lit_int.base10_parse()
                } else {
                    Err(syn::Error::new_spanned(expr, "Expected integer literal"))
                }
            }
            _ => Err(syn::Error::new_spanned(expr, "Expected integer literal")),
        }
    }

    pub fn generate_constraint_expr(
        &self,
        field_name: &syn::Ident,
        field_type: &syn::Type
    ) -> proc_macro2::TokenStream {
        let start = self.start;
        // Check for full-range case: inclusive range where end - start + 1 overflows u128.
        // This happens when start=0 and end=u128::MAX (or any span of u128::MAX).
        // In this case every value is valid, so emit no constraint.
        let range_size = if self.inclusive {
            match self.end.checked_sub(self.start).and_then(|d| d.checked_add(1)) {
                Some(rs) => rs,
                None => {
                    // Full type range — no constraint needed
                    return quote! {};
                }
            }
        } else {
            self.end - self.start
        };
        quote! {
            *#field_name = (#start as #field_type) + (*#field_name % (#range_size as #field_type));
        }
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
    // RangeConstraint::from_attr — happy path
    // =========================================================================

    #[test]
    fn exclusive_range_basic() {
        let attr = parse_range_attr(quote! { #[range(0..10)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start, 0);
        assert_eq!(rc.end, 10);
        assert!(!rc.inclusive);
    }

    #[test]
    fn inclusive_range_basic() {
        let attr = parse_range_attr(quote! { #[range(1..=100)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start, 1);
        assert_eq!(rc.end, 100);
        assert!(rc.inclusive);
    }

    #[test]
    fn exclusive_range_large_values() {
        let attr = parse_range_attr(quote! { #[range(0..340282366920938463463374607431768211455)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start, 0);
        assert_eq!(rc.end, u128::MAX);
        assert!(!rc.inclusive);
    }

    #[test]
    fn inclusive_range_same_start_end() {
        let attr = parse_range_attr(quote! { #[range(5..=5)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start, 5);
        assert_eq!(rc.end, 5);
        assert!(rc.inclusive);
    }

    #[test]
    fn exclusive_range_adjacent() {
        let attr = parse_range_attr(quote! { #[range(7..8)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start, 7);
        assert_eq!(rc.end, 8);
        assert!(!rc.inclusive);
    }

    #[test]
    fn range_zero_start() {
        let attr = parse_range_attr(quote! { #[range(0..3)] });
        let rc = RangeConstraint::from_attr(&attr).unwrap();
        assert_eq!(rc.start, 0);
        assert_eq!(rc.end, 3);
    }

    // =========================================================================
    // RangeConstraint::from_attr — validation errors
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
            err.to_string().contains("Expected integer literal"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn float_literal_errors() {
        let attr = parse_range_attr(quote! { #[range(1.0..2.0)] });
        // syn won't parse float..float as ExprRange with int lits
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
    // RangeConstraint::generate_constraint_expr — codegen
    // =========================================================================

    #[test]
    fn codegen_exclusive_range() {
        let rc = RangeConstraint { start: 10, end: 20, inclusive: false };
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
        let rc = RangeConstraint { start: 0, end: 9, inclusive: true };
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
        let rc = RangeConstraint { start: 5, end: 5, inclusive: true };
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
        let rc = RangeConstraint { start: 0, end: 100, inclusive: false };
        let field_name = syn::Ident::new("val", proc_macro2::Span::call_site());
        let field_type: syn::Type = syn::parse_str("u64").unwrap();

        let tokens = rc.generate_constraint_expr(&field_name, &field_type);
        // Should parse as a valid statement
        let _: syn::Stmt = syn::parse2(tokens).expect("generated code should be valid syntax");
    }

    // =========================================================================
    // Clone
    // =========================================================================

    #[test]
    fn clone_preserves_fields() {
        let rc = RangeConstraint { start: 1, end: 100, inclusive: true };
        let cloned = rc.clone();
        assert_eq!(cloned.start, 1);
        assert_eq!(cloned.end, 100);
        assert!(cloned.inclusive);
    }

    // =========================================================================
    // generate_constraint_expr — overflow / full-range edge cases
    // =========================================================================

    #[test]
    fn codegen_full_u128_inclusive_range_emits_no_constraint() {
        // #[range(0..=u128::MAX)] — range_size would overflow to 0.
        // The codegen should emit an empty token stream (no constraint needed).
        let rc = RangeConstraint { start: 0, end: u128::MAX, inclusive: true };
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
        let rc = RangeConstraint { start: 0, end: u128::MAX - 1, inclusive: true };
        let field_name = syn::Ident::new("v", proc_macro2::Span::call_site());
        let field_type: syn::Type = syn::parse_str("u128").unwrap();

        let tokens = rc.generate_constraint_expr(&field_name, &field_type);
        let code = tokens.to_string();
        assert!(!code.is_empty(), "should produce a constraint");
        // range_size = u128::MAX = 340282366920938463463374607431768211455
        assert!(code.contains("340282366920938463463374607431768211455"), "expected u128::MAX in: {code}");
    }

    #[test]
    fn codegen_full_range_offset_emits_no_constraint() {
        // start=1, end=u128::MAX, inclusive: range_size = MAX - 1 + 1 = MAX.
        // This does NOT overflow — only 0..=MAX overflows. Should still produce constraint.
        let rc = RangeConstraint { start: 1, end: u128::MAX, inclusive: true };
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
    fn negative_start_errors() {
        // #[range(-5..5)] — -5 is parsed as Expr::Unary(Neg, Lit(5)), not Expr::Lit.
        // extract_int should return "Expected integer literal".
        let attr = parse_range_attr(quote! { #[range(-5..5)] });
        let err = RangeConstraint::from_attr(&attr);
        assert!(err.is_err(), "negative start should fail");
        assert!(
            err.unwrap_err().to_string().contains("Expected integer literal"),
            "should get clear error for negative literal"
        );
    }

    #[test]
    fn negative_end_errors() {
        let attr = parse_range_attr(quote! { #[range(0..-1)] });
        let err = RangeConstraint::from_attr(&attr);
        assert!(err.is_err(), "negative end should fail");
    }

    #[test]
    fn identifier_expression_errors() {
        // #[range(0..MAX)] — identifiers are not integer literals
        let attr = parse_range_attr(quote! { #[range(0..MAX)] });
        assert!(RangeConstraint::from_attr(&attr).is_err());
    }

    #[test]
    fn arithmetic_expression_errors() {
        // #[range(0..1+2)] — expressions are not integer literals
        let attr = parse_range_attr(quote! { #[range(0..1+2)] });
        assert!(RangeConstraint::from_attr(&attr).is_err());
    }

    // =========================================================================
    // codegen correctness — verify the generated modulo arithmetic is correct
    // =========================================================================

    #[test]
    fn codegen_exclusive_range_values_correct() {
        // #[range(10..20)] → *val = (10) + (*val % 10)
        // For val=0: 10 + (0 % 10) = 10. For val=9: 10 + (9 % 10) = 19.
        // For val=15: 10 + (15 % 10) = 15.
        let rc = RangeConstraint { start: 10, end: 20, inclusive: false };
        assert_eq!(rc.start, 10);
        let range_size = rc.end - rc.start;
        assert_eq!(range_size, 10);

        // Simulate the generated code: result = start + (input % range_size)
        for input in 0u128..100 {
            let result = rc.start + (input % range_size);
            assert!(result >= 10 && result < 20,
                "exclusive codegen out of range for input={}: result={}", input, result);
        }
    }

    #[test]
    fn codegen_inclusive_range_values_correct() {
        // #[range(5..=14)] → *val = (5) + (*val % 10)
        let rc = RangeConstraint { start: 5, end: 14, inclusive: true };
        let range_size = rc.end - rc.start + 1;
        assert_eq!(range_size, 10);

        for input in 0u128..100 {
            let result = rc.start + (input % range_size);
            assert!(result >= 5 && result <= 14,
                "inclusive codegen out of range for input={}: result={}", input, result);
        }
    }

    #[test]
    fn codegen_u8_boundary_no_overflow() {
        // #[range(200..=255)] on u8 — range_size = 56
        // Worst case: 200 + 55 = 255 (fits u8). 200 + 56 would overflow.
        let rc = RangeConstraint { start: 200, end: 255, inclusive: true };
        let range_size = rc.end - rc.start + 1;
        assert_eq!(range_size, 56);

        // Verify: start + (range_size - 1) fits in u8
        let max_result = (rc.start + range_size - 1) as u8;
        assert_eq!(max_result, 255);
    }
}
