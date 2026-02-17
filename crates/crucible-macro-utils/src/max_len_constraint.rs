use syn::Meta;

#[derive(Clone)]
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
