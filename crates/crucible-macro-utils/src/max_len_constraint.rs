use syn::Meta;

#[derive(Clone, Debug)]
pub struct MaxLenConstraint {
    pub max_len: usize,
}

impl MaxLenConstraint {
    pub fn from_attr(attr: &syn::Attribute) -> syn::Result<Self> {
        let Meta::List(meta_list) = &attr.meta else {
            return Err(syn::Error::new_spanned(attr, "Expected #[max_len(N)]"));
        };

        let lit: syn::LitInt = syn::parse2(meta_list.tokens.clone())?;
        let max_len: usize = lit.base10_parse()?;

        if max_len < 1 {
            return Err(syn::Error::new_spanned(&lit, "max_len must be >= 1"));
        }

        Ok(Self { max_len })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    /// Parse a `#[max_len(...)]` attribute from token stream.
    fn parse_max_len_attr(tokens: proc_macro2::TokenStream) -> syn::Attribute {
        let item: syn::ItemStruct = syn::parse2(quote! {
            #tokens
            struct S;
        })
        .expect("failed to parse test attribute");
        item.attrs.into_iter().next().expect("no attribute found")
    }

    // =========================================================================
    // MaxLenConstraint::from_attr — happy path
    // =========================================================================

    #[test]
    fn basic_max_len() {
        let attr = parse_max_len_attr(quote! { #[max_len(32)] });
        let ml = MaxLenConstraint::from_attr(&attr).unwrap();
        assert_eq!(ml.max_len, 32);
    }

    #[test]
    fn max_len_one() {
        let attr = parse_max_len_attr(quote! { #[max_len(1)] });
        let ml = MaxLenConstraint::from_attr(&attr).unwrap();
        assert_eq!(ml.max_len, 1);
    }

    #[test]
    fn max_len_large() {
        let attr = parse_max_len_attr(quote! { #[max_len(10000)] });
        let ml = MaxLenConstraint::from_attr(&attr).unwrap();
        assert_eq!(ml.max_len, 10000);
    }

    // =========================================================================
    // MaxLenConstraint::from_attr — validation errors
    // =========================================================================

    #[test]
    fn max_len_zero_errors() {
        let attr = parse_max_len_attr(quote! { #[max_len(0)] });
        let err = MaxLenConstraint::from_attr(&attr).unwrap_err();
        assert!(
            err.to_string().contains("max_len must be >= 1"),
            "unexpected error: {err}"
        );
    }

    // =========================================================================
    // MaxLenConstraint::from_attr — malformed input errors
    // =========================================================================

    #[test]
    fn non_list_attribute_errors() {
        let attr = parse_max_len_attr(quote! { #[max_len] });
        let err = MaxLenConstraint::from_attr(&attr).unwrap_err();
        assert!(
            err.to_string().contains("Expected #[max_len(N)]"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn string_literal_errors() {
        let attr = parse_max_len_attr(quote! { #[max_len("ten")] });
        assert!(MaxLenConstraint::from_attr(&attr).is_err());
    }

    #[test]
    fn empty_parens_errors() {
        let attr = parse_max_len_attr(quote! { #[max_len()] });
        assert!(MaxLenConstraint::from_attr(&attr).is_err());
    }

    #[test]
    fn multiple_values_errors() {
        let attr = parse_max_len_attr(quote! { #[max_len(1, 2)] });
        assert!(MaxLenConstraint::from_attr(&attr).is_err());
    }

    #[test]
    fn negative_value_errors() {
        // -1 isn't a valid LitInt (syn parses it as Neg(1)), so parse will fail
        let attr = parse_max_len_attr(quote! { #[max_len(-1)] });
        assert!(MaxLenConstraint::from_attr(&attr).is_err());
    }

    // =========================================================================
    // Clone
    // =========================================================================

    #[test]
    fn clone_preserves_max_len() {
        let ml = MaxLenConstraint { max_len: 42 };
        let cloned = ml.clone();
        assert_eq!(cloned.max_len, 42);
    }

    // =========================================================================
    // Edge cases
    // =========================================================================

    #[test]
    fn max_len_usize_max() {
        // 18446744073709551615 on 64-bit — should parse successfully
        let attr = parse_max_len_attr(quote! { #[max_len(18446744073709551615)] });
        let ml = MaxLenConstraint::from_attr(&attr).unwrap();
        assert_eq!(ml.max_len, usize::MAX);
    }

    #[test]
    fn max_len_overflow_usize_errors() {
        // One more than usize::MAX — should fail base10_parse::<usize>()
        let attr = parse_max_len_attr(quote! { #[max_len(18446744073709551616)] });
        assert!(MaxLenConstraint::from_attr(&attr).is_err());
    }

    #[test]
    fn max_len_expression_errors() {
        // #[max_len(1 + 2)] — not a single LitInt
        let attr = parse_max_len_attr(quote! { #[max_len(1 + 2)] });
        assert!(MaxLenConstraint::from_attr(&attr).is_err());
    }

    #[test]
    fn max_len_float_errors() {
        let attr = parse_max_len_attr(quote! { #[max_len(1.5)] });
        assert!(MaxLenConstraint::from_attr(&attr).is_err());
    }
}
