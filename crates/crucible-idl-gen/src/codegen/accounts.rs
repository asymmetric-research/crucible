use std::collections::HashMap;

use anchor_lang_idl::types::{Idl, IdlInstructionAccountItem};
use heck::{ToSnakeCase, ToUpperCamelCase};
use quote::{format_ident, quote};

/// Generate account context structs for building transactions.
///
/// Accounts with a fixed `address` (e.g. sysvars) are auto-filled: they are
/// omitted from the user-facing struct and inserted as hardcoded `Pubkey`
/// constants in `to_account_metas()`.
pub fn generate(idl: &Idl) -> proc_macro2::TokenStream {
    // Collect all fixed-address constants across all instructions for the
    // `addresses` sub-module.
    let mut address_constants: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut seen_addresses: HashMap<String, String> = HashMap::new(); // address → const_name

    let account_structs = idl.instructions.iter().map(|ix| {
        let name = format_ident!("{}", ix.name.to_upper_camel_case());

        // Track how many times each name appears (for duplicate detection)
        // Only count non-fixed-address accounts for struct fields.
        let mut name_counts: HashMap<String, usize> = HashMap::new();
        for acc in &ix.accounts {
            if let IdlInstructionAccountItem::Single(single) = acc {
                if single.address.is_none() {
                    *name_counts.entry(single.name.clone()).or_insert(0) += 1;
                }
            }
        }

        // Track current index for each name during field generation
        let mut name_indices: HashMap<String, usize> = HashMap::new();

        // Generate fields from accounts (skip fixed-address accounts)
        let fields = ix.accounts.iter().filter_map(|acc| {
            match acc {
                IdlInstructionAccountItem::Single(single) => {
                    // Skip fixed-address accounts — they're auto-filled
                    if single.address.is_some() {
                        return None;
                    }

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
                    let is_signer = single.signer;
                    let is_writable = single.writable;

                    if let Some(address) = &single.address {
                        // Fixed-address account: decode base58 and insert literal
                        let address_bytes = match bs58::decode(address).into_vec() {
                            Ok(bytes) if bytes.len() == 32 => bytes,
                            _ => {
                                // Fallback: emit a runtime decode (shouldn't happen for valid IDLs)
                                let addr_str = address.clone();
                                return Some(quote! {
                                    account_metas.push(AccountMeta {
                                        pubkey: #addr_str.parse::<Pubkey>().unwrap(),
                                        is_signer: #is_signer,
                                        is_writable: #is_writable,
                                    });
                                });
                            }
                        };

                        // Register address constant
                        let const_name = single.name.to_snake_case().to_uppercase();
                        if !seen_addresses.contains_key(address) {
                            seen_addresses.insert(address.clone(), const_name.clone());
                            let const_ident = format_ident!("{}", const_name);
                            address_constants.push(quote! {
                                pub static #const_ident: Pubkey = Pubkey::new_from_array([#(#address_bytes,)*]);
                            });
                        }

                        Some(quote! {
                            account_metas.push(AccountMeta {
                                pubkey: Pubkey::new_from_array([#(#address_bytes,)*]),
                                is_signer: #is_signer,
                                is_writable: #is_writable,
                            });
                        })
                    } else {
                        // User-provided account
                        let base_name = &single.name;
                        let count = name_counts.get(base_name).unwrap_or(&1);
                        let idx = name_indices.entry(base_name.clone()).or_insert(0);

                        let field_name = if *count > 1 {
                            format_ident!("{}_{}", base_name.to_snake_case(), idx)
                        } else {
                            format_ident!("{}", base_name.to_snake_case())
                        };
                        *idx += 1;

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

    // Collect all account structs first (need to consume the iterator to populate address_constants)
    let account_structs: Vec<_> = account_structs.collect();

    // Generate addresses sub-module only if there are fixed addresses
    let addresses_mod = if address_constants.is_empty() {
        quote! {}
    } else {
        quote! {
            /// Fixed addresses for sysvar and well-known accounts.
            pub mod addresses {
                use super::*;
                #(#address_constants)*
            }
        }
    };

    quote! {
        /// Account context structs for building transactions
        pub mod accounts {
            use super::*;
            use super::types::*;
            use anchor_lang::solana_program::instruction::AccountMeta;

            #(#account_structs)*

            #addresses_mod
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

    fn make_fixed_account(name: &str, address: &str) -> IdlInstructionAccountItem {
        IdlInstructionAccountItem::Single(IdlInstructionAccount {
            name: name.to_string(),
            docs: vec![],
            writable: false,
            signer: false,
            optional: false,
            address: Some(address.to_string()),
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

    fn make_optional_account(name: &str) -> IdlInstructionAccountItem {
        IdlInstructionAccountItem::Single(IdlInstructionAccount {
            name: name.to_string(),
            docs: vec![],
            writable: true,
            signer: false,
            optional: true,
            address: None,
            pda: None,
            relations: vec![],
        })
    }

    fn make_signer_account(name: &str) -> IdlInstructionAccountItem {
        IdlInstructionAccountItem::Single(IdlInstructionAccount {
            name: name.to_string(),
            docs: vec![],
            writable: false,
            signer: true,
            optional: false,
            address: None,
            pda: None,
            relations: vec![],
        })
    }

    fn make_writable_signer_fixed_account(name: &str, address: &str) -> IdlInstructionAccountItem {
        IdlInstructionAccountItem::Single(IdlInstructionAccount {
            name: name.to_string(),
            docs: vec![],
            writable: true,
            signer: true,
            optional: false,
            address: Some(address.to_string()),
            pda: None,
            relations: vec![],
        })
    }

    #[test]
    fn test_optional_account_generates_option_pubkey() {
        let idl = make_idl(vec![IdlInstruction {
            name: "Authorize".to_string(),
            docs: vec![],
            discriminator: vec![],
            accounts: vec![
                make_account("stake"),
                make_signer_account("authority"),
                make_optional_account("lockupAuthority"),
            ],
            args: vec![],
            returns: None,
        }]);

        let output = generate(&idl).to_string();

        // Should generate Option<Pubkey> field for optional account
        assert!(
            output.contains("Option < Pubkey >"),
            "optional account should generate Option<Pubkey> field"
        );

        // Should generate conditional if-let push in to_account_metas
        assert!(
            output.contains("if let Some"),
            "optional account should generate conditional account push"
        );

        // Non-optional accounts should be plain Pubkey
        assert!(
            output.contains("pub stake : Pubkey"),
            "non-optional account should be plain Pubkey"
        );
    }

    #[test]
    fn test_fixed_address_dedup_across_instructions() {
        let rent_addr = "SysvarRent111111111111111111111111111111111";
        let idl = make_idl(vec![
            IdlInstruction {
                name: "Initialize".to_string(),
                docs: vec![],
                discriminator: vec![],
                accounts: vec![make_account("stake"), make_fixed_account("rent", rent_addr)],
                args: vec![],
                returns: None,
            },
            IdlInstruction {
                name: "Authorize".to_string(),
                docs: vec![],
                discriminator: vec![],
                accounts: vec![make_account("stake"), make_fixed_account("rent", rent_addr)],
                args: vec![],
                returns: None,
            },
        ]);

        let output = generate(&idl).to_string();

        // Should have addresses module
        assert!(
            output.contains("mod addresses"),
            "should have addresses module"
        );
        // Should have exactly one RENT constant (dedup'd across instructions)
        let rent_const_count = output.matches("pub static RENT").count();
        assert_eq!(
            rent_const_count, 1,
            "same address across instructions should produce one constant, got {}",
            rent_const_count
        );
    }

    #[test]
    fn test_writable_signer_on_fixed_address() {
        let idl = make_idl(vec![IdlInstruction {
            name: "SpecialOp".to_string(),
            docs: vec![],
            discriminator: vec![],
            accounts: vec![make_writable_signer_fixed_account(
                "specialSysvar",
                "SysvarRent111111111111111111111111111111111",
            )],
            args: vec![],
            returns: None,
        }]);

        let output = generate(&idl).to_string();

        // Fixed-address account should have is_writable: true and is_signer: true preserved
        assert!(
            output.contains("is_signer : true"),
            "signer flag should be preserved for fixed-address account"
        );
        assert!(
            output.contains("is_writable : true"),
            "writable flag should be preserved for fixed-address account"
        );
    }

    // -----------------------------------------------------------------------
    // #7: Invalid base58 fallback in fixed-address accounts
    // -----------------------------------------------------------------------

    #[test]
    fn test_invalid_base58_address_fallback() {
        let idl = make_idl(vec![IdlInstruction {
            name: "WithBadAddress".to_string(),
            docs: vec![],
            discriminator: vec![],
            accounts: vec![
                make_account("user"),
                make_fixed_account("badSysvar", "NOT_VALID_BASE58!!!"),
            ],
            args: vec![],
            returns: None,
        }]);

        let output = generate(&idl).to_string();
        // Should fall back to runtime parse instead of compile-time byte array
        assert!(
            output.contains("parse"),
            "invalid base58 should fall back to runtime parse, got: {}",
            output
        );
        // User account should still be generated normally
        assert!(
            output.contains("pub user : Pubkey"),
            "user field should still exist"
        );
    }

    #[test]
    fn test_fixed_address_wrong_length_fallback() {
        // Valid base58 but decodes to wrong length (not 32 bytes)
        // "1" decodes to [0] (1 byte), not 32
        let idl = make_idl(vec![IdlInstruction {
            name: "ShortAddr".to_string(),
            docs: vec![],
            discriminator: vec![],
            accounts: vec![make_fixed_account("tooShort", "1")],
            args: vec![],
            returns: None,
        }]);

        let output = generate(&idl).to_string();
        assert!(
            output.contains("parse"),
            "wrong-length base58 should fall back to runtime parse, got: {}",
            output
        );
    }

    #[test]
    fn test_fixed_address_accounts_skipped_in_struct() {
        let idl = make_idl(vec![IdlInstruction {
            name: "Initialize".to_string(),
            docs: vec![],
            discriminator: vec![],
            accounts: vec![
                make_account("stake"),
                make_fixed_account("rentSysvar", "SysvarRent111111111111111111111111111111111"),
            ],
            args: vec![],
            returns: None,
        }]);

        let generated = generate(&idl).to_string();

        // stake should be a struct field
        assert!(generated.contains("stake"), "should have 'stake' field");

        // rentSysvar should NOT be a struct field (it's auto-filled)
        // Check that "rent_sysvar" does not appear as a struct field declaration
        // but DOES appear in to_account_metas as a hardcoded Pubkey
        assert!(
            !generated.contains("pub rent_sysvar"),
            "rentSysvar should not be a struct field"
        );

        // Should have addresses module with constant
        assert!(
            generated.contains("RENT_SYSVAR"),
            "should have RENT_SYSVAR constant"
        );
        assert!(
            generated.contains("mod addresses"),
            "should have addresses module"
        );
    }

    // -----------------------------------------------------------------------
    // Account ordering: verify to_account_metas preserves IDL order
    // -----------------------------------------------------------------------

    /// Extract all `pubkey : self . <name>` references from generated to_account_metas
    /// in order. TokenStream output has spaces everywhere (e.g. `self . source`).
    fn extract_account_order(generated: &str) -> Vec<String> {
        let mut accounts = Vec::new();
        let search = generated;
        let mut pos = 0;
        let self_marker = "pubkey : self . ";
        let fixed_marker = "pubkey : Pubkey :: new_from_array";
        while pos < search.len() {
            // Check for user-provided account
            if let Some(found) = search[pos..].find(self_marker) {
                let abs_pos = pos + found;
                // Check if a fixed-address marker comes before this
                if let Some(fixed_found) = search[pos..].find(fixed_marker) {
                    if pos + fixed_found < abs_pos {
                        accounts.push("__fixed__".to_string());
                        pos = pos + fixed_found + fixed_marker.len();
                        continue;
                    }
                }
                let after = &search[abs_pos + self_marker.len()..];
                let name: String = after
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    accounts.push(name);
                }
                pos = abs_pos + self_marker.len();
            } else if let Some(fixed_found) = search[pos..].find(fixed_marker) {
                accounts.push("__fixed__".to_string());
                pos = pos + fixed_found + fixed_marker.len();
            } else {
                break;
            }
        }
        accounts
    }

    #[test]
    fn test_account_order_preserved_simple() {
        let idl = make_idl(vec![IdlInstruction {
            name: "Transfer".to_string(),
            docs: vec![],
            discriminator: vec![],
            accounts: vec![
                make_account("source"),
                make_account("destination"),
                make_signer_account("authority"),
            ],
            args: vec![],
            returns: None,
        }]);

        let generated = generate(&idl).to_string();
        let order = extract_account_order(&generated);

        assert_eq!(
            order,
            vec!["source", "destination", "authority"],
            "accounts should be in IDL order: source, destination, authority"
        );
    }

    #[test]
    fn test_account_order_preserved_with_fixed_address() {
        // Fixed-address accounts (sysvars) should appear in the same position as the IDL
        let idl = make_idl(vec![IdlInstruction {
            name: "Initialize".to_string(),
            docs: vec![],
            discriminator: vec![],
            accounts: vec![
                make_account("stake"),
                make_fixed_account("rent", "SysvarRent111111111111111111111111111111111"),
                make_account("stakeHistory"),
            ],
            args: vec![],
            returns: None,
        }]);

        let generated = generate(&idl).to_string();
        let order = extract_account_order(&generated);

        // stake (user), rent (fixed), stakeHistory (user)
        assert_eq!(
            order.len(),
            3,
            "should have 3 accounts in to_account_metas, got {:?}",
            order
        );
        assert_eq!(order[0], "stake", "first should be stake");
        assert_eq!(order[1], "__fixed__", "second should be fixed-address rent");
        assert_eq!(order[2], "stake_history", "third should be stakeHistory");
    }

    #[test]
    fn test_account_order_preserved_with_optional() {
        let idl = make_idl(vec![IdlInstruction {
            name: "Authorize".to_string(),
            docs: vec![],
            discriminator: vec![],
            accounts: vec![
                make_account("stake"),
                make_signer_account("authority"),
                make_optional_account("newAuthority"),
            ],
            args: vec![],
            returns: None,
        }]);

        let generated = generate(&idl).to_string();

        // Find the to_account_metas function and verify the order of pushes
        // stake should come before authority which comes before newAuthority (optional)
        let stake_pos = generated
            .find("pubkey : self . stake")
            .expect("should have stake");
        let authority_pos = generated
            .find("pubkey : self . authority")
            .expect("should have authority");
        // Optional accounts use `if let Some(key)` → `pubkey : * key`
        let optional_pos = generated
            .find("if let Some (key)")
            .or_else(|| generated.find("if let Some(key)"))
            .expect("should have optional if-let for newAuthority");

        assert!(
            stake_pos < authority_pos,
            "stake ({}) should appear before authority ({}) in to_account_metas",
            stake_pos,
            authority_pos
        );
        assert!(
            authority_pos < optional_pos,
            "authority ({}) should appear before optional newAuthority ({}) in to_account_metas",
            authority_pos,
            optional_pos
        );
    }

    #[test]
    fn test_account_order_preserved_many_accounts() {
        // 5 accounts in specific order — verify none get reordered
        let idl = make_idl(vec![IdlInstruction {
            name: "ComplexOp".to_string(),
            docs: vec![],
            discriminator: vec![],
            accounts: vec![
                make_signer_account("payer"),
                make_account("vault"),
                make_account("mint"),
                make_account("tokenProgram"),
                make_account("systemProgram"),
            ],
            args: vec![],
            returns: None,
        }]);

        let generated = generate(&idl).to_string();
        let order = extract_account_order(&generated);

        assert_eq!(
            order,
            vec!["payer", "vault", "mint", "token_program", "system_program"],
            "5 accounts should maintain exact IDL order"
        );
    }

    // -----------------------------------------------------------------------
    // Account signer/writable flags: verify flags match IDL
    // -----------------------------------------------------------------------

    #[test]
    fn test_account_flags_preserved() {
        let idl = make_idl(vec![IdlInstruction {
            name: "Transfer".to_string(),
            docs: vec![],
            discriminator: vec![],
            accounts: vec![
                IdlInstructionAccountItem::Single(IdlInstructionAccount {
                    name: "source".to_string(),
                    docs: vec![],
                    writable: true,
                    signer: false,
                    optional: false,
                    address: None,
                    pda: None,
                    relations: vec![],
                }),
                IdlInstructionAccountItem::Single(IdlInstructionAccount {
                    name: "destination".to_string(),
                    docs: vec![],
                    writable: true,
                    signer: false,
                    optional: false,
                    address: None,
                    pda: None,
                    relations: vec![],
                }),
                IdlInstructionAccountItem::Single(IdlInstructionAccount {
                    name: "authority".to_string(),
                    docs: vec![],
                    writable: false,
                    signer: true,
                    optional: false,
                    address: None,
                    pda: None,
                    relations: vec![],
                }),
            ],
            args: vec![],
            returns: None,
        }]);

        let generated = generate(&idl).to_string();

        // Count occurrences of each flag combination
        // source: writable=true, signer=false
        // destination: writable=true, signer=false
        // authority: writable=false, signer=true

        // Extract the to_account_metas body to inspect individual account pushes
        let meta_fn_start = generated
            .find("fn to_account_metas")
            .expect("should have to_account_metas");
        let meta_body = &generated[meta_fn_start..];

        // Find the three account_metas.push blocks in order
        let pushes: Vec<&str> = meta_body
            .split("account_metas . push")
            .skip(1) // first part is before any push
            .collect();

        assert_eq!(
            pushes.len(),
            3,
            "should have 3 account pushes, got {}",
            pushes.len()
        );

        // source: writable, not signer
        assert!(
            pushes[0].contains("is_writable : true"),
            "source should be writable"
        );
        assert!(
            pushes[0].contains("is_signer : false"),
            "source should not be signer"
        );

        // destination: writable, not signer
        assert!(
            pushes[1].contains("is_writable : true"),
            "destination should be writable"
        );
        assert!(
            pushes[1].contains("is_signer : false"),
            "destination should not be signer"
        );

        // authority: not writable, signer
        assert!(
            pushes[2].contains("is_writable : false"),
            "authority should not be writable"
        );
        assert!(
            pushes[2].contains("is_signer : true"),
            "authority should be signer"
        );
    }
}
