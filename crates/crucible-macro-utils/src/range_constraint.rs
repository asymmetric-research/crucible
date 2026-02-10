
use syn::{Expr, ExprRange, RangeLimits, Lit, Meta};
use quote::quote;


#[derive(Clone)]
pub struct RangeConstraint {
    pub start: u64,
    pub end: u64,
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

    fn extract_int(expr: &Expr) -> syn::Result<u64> {
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
        let range_size = if self.inclusive {
            self.end - self.start + 1
        } else {
            self.end - self.start
        };
        quote! { 
            *#field_name = (#start as #field_type) + (*#field_name % (#range_size as #field_type));
        }
    }
}
