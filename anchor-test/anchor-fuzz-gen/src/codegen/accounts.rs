use anchor_lang_idl::types::{Idl, IdlInstructionAccountItem};
use heck::ToUpperCamelCase;
use quote::{format_ident, quote};

/// Generate account context structs for building transactions
pub fn generate(idl: &Idl) -> proc_macro2::TokenStream {
    let account_structs = idl.instructions.iter().map(|ix| {
        let name = format_ident!("{}", ix.name.to_upper_camel_case());

        // Generate fields from accounts
        let fields = ix.accounts.iter().filter_map(|acc| {
            match acc {
                IdlInstructionAccountItem::Single(single) => {
                    let field_name = format_ident!("{}", single.name);

                    // All account fields are Pubkey for the client struct
                    let field_type = if single.optional {
                        quote! { Option<Pubkey> }
                    } else {
                        quote! { Pubkey }
                    };

                    Some(quote! { pub #field_name: #field_type })
                }
                IdlInstructionAccountItem::Composite(_) => {
                    // Skip composite accounts for now
                    // TODO: Handle nested account structs
                    None
                }
            }
        });

        // Generate ToAccountMetas implementation
        let to_account_metas = ix.accounts.iter().filter_map(|acc| {
            match acc {
                IdlInstructionAccountItem::Single(single) => {
                    let field_name = format_ident!("{}", single.name);
                    let is_signer = single.signer;
                    let is_writable = single.writable;

                    if single.optional {
                        Some(quote! {
                            if let Some(key) = &self.#field_name {
                                account_metas.push(AccountMeta {
                                    pubkey: *key,
                                    is_signer: #is_signer,
                                    is_writable: #is_writable,
                                });
                            }
                        })
                    } else {
                        Some(quote! {
                            account_metas.push(AccountMeta {
                                pubkey: self.#field_name,
                                is_signer: #is_signer,
                                is_writable: #is_writable,
                            });
                        })
                    }
                }
                IdlInstructionAccountItem::Composite(_) => None,
            }
        });

        quote! {
            #[derive(Clone)]
            pub struct #name {
                #(#fields),*
            }

            impl anchor_lang::ToAccountMetas for #name {
                fn to_account_metas(&self, _is_signer: Option<bool>) -> Vec<AccountMeta> {
                    let mut account_metas = Vec::new();
                    #(#to_account_metas)*
                    account_metas
                }
            }
        }
    });

    quote! {
        /// Account context structs for building transactions
        pub mod accounts {
            use super::*;
            use super::types::*;
            use anchor_lang::solana_program::instruction::AccountMeta;

            #(#account_structs)*
        }
    }
}
