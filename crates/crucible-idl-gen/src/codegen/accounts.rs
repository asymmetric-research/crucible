use std::collections::HashMap;

use anchor_lang_idl::types::{Idl, IdlInstructionAccountItem};
use heck::{ToSnakeCase, ToUpperCamelCase};
use quote::{format_ident, quote};

/// Generate account context structs for building transactions
pub fn generate(idl: &Idl) -> proc_macro2::TokenStream {
    let account_structs = idl.instructions.iter().map(|ix| {
        let name = format_ident!("{}", ix.name.to_upper_camel_case());

        // Track how many times each name appears (for duplicate detection)
        let mut name_counts: HashMap<String, usize> = HashMap::new();
        for acc in &ix.accounts {
            if let IdlInstructionAccountItem::Single(single) = acc {
                *name_counts.entry(single.name.clone()).or_insert(0) += 1;
            }
        }

        // Track current index for each name during field generation
        let mut name_indices: HashMap<String, usize> = HashMap::new();

        // Generate fields from accounts
        let fields = ix.accounts.iter().filter_map(|acc| {
            match acc {
                IdlInstructionAccountItem::Single(single) => {
                    let base_name = &single.name;
                    let count = name_counts.get(base_name).unwrap_or(&1);
                    let idx = name_indices.entry(base_name.clone()).or_insert(0);

                    // Only add suffix if there are duplicates
                    let field_name = if *count > 1 {
                        format_ident!("{}_{}", base_name.to_snake_case(), idx)
                    } else {
                        format_ident!("{}", base_name.to_snake_case())
                    };
                    *idx += 1;

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

        // Reset indices for ToAccountMetas generation
        let mut name_indices: HashMap<String, usize> = HashMap::new();

        // Generate ToAccountMetas implementation
        let to_account_metas = ix.accounts.iter().filter_map(|acc| {
            match acc {
                IdlInstructionAccountItem::Single(single) => {
                    let base_name = &single.name;
                    let count = name_counts.get(base_name).unwrap_or(&1);
                    let idx = name_indices.entry(base_name.clone()).or_insert(0);

                    // Only add suffix if there are duplicates
                    let field_name = if *count > 1 {
                        format_ident!("{}_{}", base_name.to_snake_case(), idx)
                    } else {
                        format_ident!("{}", base_name.to_snake_case())
                    };
                    *idx += 1;

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

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang_idl::types::{
        Idl, IdlInstruction, IdlInstructionAccount, IdlInstructionAccountItem, IdlMetadata,
    };

    fn make_account(name: &str) -> IdlInstructionAccountItem {
        IdlInstructionAccountItem::Single(IdlInstructionAccount {
            name: name.to_string(),
            docs: vec![],
            writable: false,
            signer: false,
            optional: false,
            address: None,
            pda: None,
            relations: vec![],
        })
    }

    fn make_idl(instructions: Vec<IdlInstruction>) -> Idl {
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
            instructions,
            accounts: vec![],
            events: vec![],
            errors: vec![],
            types: vec![],
            constants: vec![],
        }
    }

    #[test]
    fn test_no_duplicates() {
        let idl = make_idl(vec![IdlInstruction {
            name: "TestInstruction".to_string(),
            docs: vec![],
            discriminator: vec![],
            accounts: vec![
                make_account("accountA"),
                make_account("accountB"),
                make_account("accountC"),
            ],
            args: vec![],
            returns: None,
        }]);

        let generated = generate(&idl).to_string();

        // Should have no suffixes
        assert!(generated.contains("account_a"));
        assert!(generated.contains("account_b"));
        assert!(generated.contains("account_c"));
        assert!(!generated.contains("account_a_0"));
        assert!(!generated.contains("account_b_0"));
    }

    #[test]
    fn test_duplicate_accounts_get_suffixes() {
        let idl = make_idl(vec![IdlInstruction {
            name: "PlaceMarketOrder".to_string(),
            docs: vec![],
            discriminator: vec![],
            accounts: vec![
                make_account("header"),
                make_account("arenas"),
                make_account("header"),
                make_account("arenas"),
            ],
            args: vec![],
            returns: None,
        }]);

        let generated = generate(&idl).to_string();

        // Should have _0 and _1 suffixes for duplicates
        assert!(generated.contains("header_0"));
        assert!(generated.contains("header_1"));
        assert!(generated.contains("arenas_0"));
        assert!(generated.contains("arenas_1"));

        // Should NOT have unsuffixed versions
        let lines: Vec<&str> = generated.lines().collect();
        let has_bare_header = lines.iter().any(|line| {
            line.contains("header") && !line.contains("header_0") && !line.contains("header_1")
        });
        assert!(!has_bare_header, "Should not have bare 'header' field");
    }

    #[test]
    fn test_mixed_duplicates_and_unique() {
        let idl = make_idl(vec![IdlInstruction {
            name: "MixedInstruction".to_string(),
            docs: vec![],
            discriminator: vec![],
            accounts: vec![
                make_account("unique"),
                make_account("duplicate"),
                make_account("duplicate"),
                make_account("anotherUnique"),
            ],
            args: vec![],
            returns: None,
        }]);

        let generated = generate(&idl).to_string();

        // Unique accounts should NOT have suffixes
        assert!(generated.contains("unique"));
        assert!(generated.contains("another_unique"));

        // Duplicate accounts SHOULD have suffixes
        assert!(generated.contains("duplicate_0"));
        assert!(generated.contains("duplicate_1"));
    }
}
