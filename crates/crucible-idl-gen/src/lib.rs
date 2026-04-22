extern crate proc_macro;

mod codama;
mod codegen;

use std::{env, fs, path::PathBuf};

use anchor_lang_idl::types::Idl;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, LitStr};

/// Generate a complete module from an Anchor IDL for fuzzing purposes.
///
/// Unlike `declare_program!`, this macro generates:
/// - Instruction argument structs with `InstructionData` impl
/// - Account context structs with `ToAccountMetas` impl
/// - State types for deserializing on-chain account data
/// - Custom type definitions with useful `From`/`Into` impls
///
/// # Usage
///
/// ```rust,ignore
/// crucible_idl_gen::declare_fuzz_program!("path/to/program.json");
/// ```
///
/// Or with explicit program name:
///
/// ```rust,ignore
/// crucible_idl_gen::declare_fuzz_program!(my_program = "path/to/idl.json");
/// ```
#[proc_macro]
pub fn declare_fuzz_program(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeclareFuzzProgram);

    match generate_program(&input) {
        Ok(tokens) => tokens.into(),
        Err(e) => syn::Error::new(input.path.span(), e.to_string())
            .to_compile_error()
            .into(),
    }
}

struct DeclareFuzzProgram {
    name: Option<syn::Ident>,
    path: LitStr,
}

impl syn::parse::Parse for DeclareFuzzProgram {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        // Try to parse: name = "path"
        if input.peek(syn::Ident) && input.peek2(syn::Token![=]) {
            let name: syn::Ident = input.parse()?;
            let _: syn::Token![=] = input.parse()?;
            let path: LitStr = input.parse()?;
            Ok(Self {
                name: Some(name),
                path,
            })
        } else {
            // Just a path: "path/to/idl.json"
            let path: LitStr = input.parse()?;
            Ok(Self { name: None, path })
        }
    }
}

fn generate_program(input: &DeclareFuzzProgram) -> anyhow::Result<proc_macro2::TokenStream> {
    // Resolve IDL path relative to CARGO_MANIFEST_DIR
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .map_err(|e| anyhow::anyhow!("Failed to get CARGO_MANIFEST_DIR: {e}"))?;

    let idl_path = manifest_dir.join(input.path.value());

    // Read and parse IDL (auto-detect Codama vs Anchor format)
    let idl_str = fs::read_to_string(&idl_path)
        .map_err(|e| anyhow::anyhow!("Failed to read IDL at {}: {e}", idl_path.display()))?;

    let mut idl = parse_idl(&idl_str)?;

    // Detect and fix bincode-style discriminators.
    // Native Solana programs use 4-byte u32 LE instruction indices. IDLs may
    // represent these as 8-byte arrays with trailing zeros (e.g. [1,0,0,0,0,0,0,0]).
    // If every instruction discriminator is 8 bytes with the last 4 all zero,
    // truncate to 4 bytes so downstream codegen detects bincode format.
    truncate_bincode_discriminators(&mut idl);

    // Determine module name
    let module_name = input
        .name
        .clone()
        .unwrap_or_else(|| format_ident!("{}", idl.metadata.name));

    // Detect serialization format from discriminator length:
    // 8 bytes → Anchor (borsh), 4 bytes → native/bincode
    let use_bincode = idl
        .instructions
        .first()
        .map(|ix| ix.discriminator.len() == 4)
        .unwrap_or(false);

    // Generate code
    let program_id = codegen::gen_program_id(&idl);
    let instructions = codegen::instructions::generate(&idl);
    let accounts = codegen::accounts::generate(&idl);
    let state = codegen::state::generate(&idl);
    let types = codegen::types::generate(&idl, use_bincode);
    let discriminators = codegen::discriminators::generate(&idl);
    let schemas = codegen::schemas::generate(&idl);

    Ok(quote! {
        /// Generated from IDL for fuzzing purposes.
        pub mod #module_name {
            use anchor_lang::prelude::*;

            #program_id

            #instructions
            #accounts
            #state
            #types
            #discriminators
            #schemas
        }

        /// Auto-register account schemas at binary startup for field-level diffs.
        #[::ctor::ctor]
        fn __crucible_register_schemas() {
            #module_name::register_schemas();
        }
    })
}

/// Auto-detect IDL format and parse accordingly.
///
/// Codama IDLs have `"kind": "rootNode"` at the top level.
/// Everything else is treated as Anchor IDL format.
fn parse_idl(idl_str: &str) -> anyhow::Result<Idl> {
    let json_value: serde_json::Value = serde_json::from_str(idl_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse IDL as JSON: {e}"))?;

    if json_value.get("kind").and_then(|k| k.as_str()) == Some("rootNode") {
        // Codama format
        let root: codama_nodes::RootNode = serde_json::from_value(json_value)
            .map_err(|e| anyhow::anyhow!("Failed to parse Codama IDL: {e}"))?;
        codama::convert(&root)
    } else {
        // Anchor format
        anchor_lang_idl::convert::convert_idl(idl_str.as_bytes())
    }
}

/// Detect bincode-style discriminators and truncate from 8 to 4 bytes.
///
/// Native Solana programs (stake, vote, system) use bincode with 4-byte u32 LE
/// instruction indices. Hand-written IDLs may pad these to 8 bytes to match
/// Anchor's discriminator length (e.g. `[2,0,0,0,0,0,0,0]` for index 2).
///
/// Detection: all instruction discriminators are exactly 8 bytes with the last
/// 4 bytes all zero. This is essentially impossible for real Anchor programs
/// (SHA256 hashes), so the detection is safe.
fn truncate_bincode_discriminators(idl: &mut Idl) {
    if idl.instructions.is_empty() {
        return;
    }

    let all_padded = idl
        .instructions
        .iter()
        .all(|ix| ix.discriminator.len() == 8 && ix.discriminator[4..] == [0, 0, 0, 0]);

    if all_padded {
        for ix in &mut idl.instructions {
            ix.discriminator.truncate(4);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang_idl::types::{
        IdlArrayLen, IdlDefinedFields, IdlInstructionAccountItem, IdlType, IdlTypeDefTy,
    };

    /// Load and parse a test IDL file from test-data/ directory.
    fn parse_test_idl(filename: &str) -> Idl {
        let json = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("test-data")
                .join(filename),
        )
        .unwrap_or_else(|e| panic!("Failed to read {filename}: {e}"));
        parse_idl(&json).unwrap_or_else(|e| panic!("Failed to parse {filename}: {e}"))
    }

    /// Parse IDL and apply bincode discriminator truncation (like the real pipeline).
    fn parse_test_idl_with_truncation(filename: &str) -> Idl {
        let mut idl = parse_test_idl(filename);
        truncate_bincode_discriminators(&mut idl);
        idl
    }

    /// Verify basic IDL invariants that should hold for any valid IDL.
    fn verify_idl_basics(idl: &Idl) {
        assert!(!idl.metadata.name.is_empty(), "IDL should have a name");
        assert!(!idl.address.is_empty(), "IDL should have an address");
        assert!(!idl.instructions.is_empty(), "IDL should have instructions");
    }

    /// Run the full codegen pipeline and return the generated TokenStream.
    fn run_full_pipeline_tokens(filename: &str) -> proc_macro2::TokenStream {
        let mut idl = parse_test_idl(filename);
        truncate_bincode_discriminators(&mut idl);

        let use_bincode = idl
            .instructions
            .first()
            .map(|ix| ix.discriminator.len() == 4)
            .unwrap_or(false);

        let program_id = codegen::gen_program_id(&idl);
        let instructions = codegen::instructions::generate(&idl);
        let accounts = codegen::accounts::generate(&idl);
        let state = codegen::state::generate(&idl);
        let types = codegen::types::generate(&idl, use_bincode);
        let discriminators = codegen::discriminators::generate(&idl);
        let schemas = codegen::schemas::generate(&idl);

        quote! {
            #program_id
            #instructions
            #accounts
            #state
            #types
            #discriminators
            #schemas
        }
    }

    /// Run the full codegen pipeline and return the generated code as a string.
    fn run_full_pipeline(filename: &str) -> String {
        run_full_pipeline_tokens(filename).to_string()
    }

    /// Extract single (non-composite) accounts from an instruction.
    fn single_accounts(
        ix: &anchor_lang_idl::types::IdlInstruction,
    ) -> Vec<&anchor_lang_idl::types::IdlInstructionAccount> {
        ix.accounts
            .iter()
            .filter_map(|a| match a {
                IdlInstructionAccountItem::Single(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Cross-format parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_codama_stake() {
        let idl = parse_test_idl("codama_stake.json");
        verify_idl_basics(&idl);
        assert_eq!(idl.metadata.name, "solanaStakeInterface");
        assert_eq!(idl.instructions.len(), 18);
        // Codama stake has discriminators before truncation
        assert_eq!(idl.instructions[0].discriminator.len(), 8);
    }

    #[test]
    fn test_parse_codama_system() {
        let idl = parse_test_idl("codama_system.json");
        verify_idl_basics(&idl);
        assert!(
            idl.metadata.name.contains("system") || idl.metadata.name.contains("System"),
            "system IDL name: {}",
            idl.metadata.name
        );
        // System program has multiple instructions
        assert!(
            idl.instructions.len() >= 10,
            "system should have >= 10 instructions, got {}",
            idl.instructions.len()
        );
    }

    #[test]
    fn test_parse_codama_token() {
        let idl = parse_test_idl("codama_token.json");
        verify_idl_basics(&idl);
        // Token program has many instructions
        assert!(
            idl.instructions.len() >= 20,
            "token should have >= 20 instructions, got {}",
            idl.instructions.len()
        );
    }

    #[test]
    fn test_parse_codama_compute_budget() {
        let idl = parse_test_idl("codama_compute_budget.json");
        verify_idl_basics(&idl);
        // Minimal program - few instructions, no types
        assert!(
            idl.instructions.len() >= 3,
            "compute_budget should have >= 3 instructions, got {}",
            idl.instructions.len()
        );
    }

    #[test]
    fn test_parse_codama_memo() {
        let idl = parse_test_idl("codama_memo.json");
        verify_idl_basics(&idl);
        // Memo is minimal - should have at least 1 instruction
        assert!(!idl.instructions.is_empty());
    }

    #[test]
    fn test_parse_anchor_stake() {
        let idl = parse_test_idl("anchor_stake.json");
        verify_idl_basics(&idl);
        assert_eq!(idl.instructions.len(), 18);
        assert_eq!(idl.metadata.spec, "0.1.0");
        // Anchor stake has 8-byte padded discriminators (before truncation)
        assert_eq!(idl.instructions[0].discriminator.len(), 8);
        assert_eq!(idl.instructions[0].discriminator[4..], [0, 0, 0, 0]);

        // -- Deep: StakeAuthorize enum --
        let sa = idl
            .types
            .iter()
            .find(|t| t.name == "StakeAuthorize")
            .expect("should have StakeAuthorize type");
        match &sa.ty {
            IdlTypeDefTy::Enum { variants } => {
                assert_eq!(variants.len(), 2);
                assert_eq!(variants[0].name, "Staker");
                assert_eq!(variants[1].name, "Withdrawer");
                assert!(variants[0].fields.is_none());
            }
            other => panic!("StakeAuthorize should be enum, got {:?}", other),
        }

        // -- Deep: Lockup struct field types --
        let lockup = idl
            .types
            .iter()
            .find(|t| t.name == "Lockup")
            .expect("should have Lockup type");
        match &lockup.ty {
            IdlTypeDefTy::Struct {
                fields: Some(IdlDefinedFields::Named(f)),
            } => {
                assert_eq!(f.len(), 3);
                assert_eq!(f[0].name, "unixTimestamp");
                assert_eq!(f[0].ty, IdlType::I64);
                assert_eq!(f[1].name, "epoch");
                assert_eq!(f[1].ty, IdlType::U64);
                assert_eq!(f[2].name, "custodian");
                assert_eq!(f[2].ty, IdlType::Pubkey);
            }
            other => panic!("Lockup should be struct with named fields, got {:?}", other),
        }

        // -- Deep: first instruction account properties --
        let ix0 = &idl.instructions[0];
        assert_eq!(ix0.name, "initialize");
        let accs = single_accounts(ix0);
        assert_eq!(accs[0].name, "stake");
        assert!(accs[0].writable);
        assert!(!accs[0].signer);
        assert_eq!(accs[1].name, "rent");
        assert_eq!(
            accs[1].address.as_deref(),
            Some("SysvarRent111111111111111111111111111111111")
        );
    }

    #[test]
    fn test_parse_anchor_marginfi() {
        let idl = parse_test_idl("anchor_marginfi.json");
        verify_idl_basics(&idl);
        assert_eq!(idl.metadata.name, "marginfi");
        assert_eq!(idl.metadata.spec, "0.1.0");
        assert_eq!(idl.instructions.len(), 45);
        assert_eq!(idl.accounts.len(), 5);
        // Marginfi has real 8-byte SHA256 discriminators
        assert_eq!(idl.instructions[0].discriminator.len(), 8);

        // -- Deep: first instruction discriminator bytes --
        assert_eq!(
            idl.instructions[0].discriminator,
            vec![231, 205, 66, 242, 220, 87, 145, 38]
        );

        // -- Deep: lending_account_deposit instruction --
        let deposit = idl
            .instructions
            .iter()
            .find(|ix| ix.name == "lending_account_deposit")
            .expect("should have lending_account_deposit");
        assert_eq!(
            deposit.discriminator,
            vec![171, 94, 235, 103, 82, 64, 212, 140]
        );
        assert_eq!(deposit.args.len(), 2);
        assert_eq!(deposit.args[0].name, "amount");
        assert_eq!(deposit.args[0].ty, IdlType::U64);
        assert_eq!(deposit.args[1].name, "deposit_up_to_limit");
        assert_eq!(deposit.args[1].ty, IdlType::Option(Box::new(IdlType::Bool)));

        // -- Deep: lending_account_deposit account properties --
        let dep_accs = single_accounts(deposit);
        assert!(dep_accs.iter().any(|a| a.name == "authority" && a.signer));
        assert!(dep_accs
            .iter()
            .any(|a| a.name == "marginfi_account" && a.writable));
        assert!(dep_accs.iter().any(|a| a.name == "bank" && a.writable));
        assert!(dep_accs
            .iter()
            .any(|a| a.name == "liquidity_vault" && a.writable));

        // -- Deep: WrappedI80F48 type structure --
        let wi = idl
            .types
            .iter()
            .find(|t| t.name == "WrappedI80F48")
            .expect("should have WrappedI80F48 type");
        match &wi.ty {
            IdlTypeDefTy::Struct {
                fields: Some(IdlDefinedFields::Named(f)),
            } => {
                assert_eq!(f.len(), 1);
                assert_eq!(f[0].name, "value");
                match &f[0].ty {
                    IdlType::Array(inner, IdlArrayLen::Value(16)) => {
                        assert_eq!(**inner, IdlType::U8);
                    }
                    other => panic!("WrappedI80F48.value should be [u8; 16], got {:?}", other),
                }
            }
            other => panic!(
                "WrappedI80F48 should be struct with named fields, got {:?}",
                other
            ),
        }

        // -- Deep: Bank type first 3 fields --
        let bank = idl
            .types
            .iter()
            .find(|t| t.name == "Bank")
            .expect("should have Bank type");
        match &bank.ty {
            IdlTypeDefTy::Struct {
                fields: Some(IdlDefinedFields::Named(f)),
            } => {
                assert!(f.len() > 3, "Bank should have many fields");
                assert_eq!(f[0].name, "mint");
                assert_eq!(f[0].ty, IdlType::Pubkey);
                assert_eq!(f[1].name, "mint_decimals");
                assert_eq!(f[1].ty, IdlType::U8);
                assert_eq!(f[2].name, "group");
                assert_eq!(f[2].ty, IdlType::Pubkey);
            }
            other => panic!("Bank should be struct, got {:?}", other),
        }

        // -- Deep: Bank account discriminator --
        let bank_acc = idl
            .accounts
            .iter()
            .find(|a| a.name == "Bank")
            .expect("should have Bank account");
        assert_eq!(
            bank_acc.discriminator,
            vec![142, 49, 166, 242, 50, 66, 97, 188]
        );

        // -- Deep: error count --
        assert_eq!(idl.errors.len(), 83);
    }

    #[test]
    fn test_parse_anchor_whirlpool() {
        let idl = parse_test_idl("anchor_whirlpool.json");
        verify_idl_basics(&idl);
        assert_eq!(idl.metadata.name, "whirlpool");
        assert_eq!(idl.instructions.len(), 63);
        assert_eq!(idl.accounts.len(), 12);
        // Should have zero-copy types
        let has_repr_c = idl
            .types
            .iter()
            .any(|t| matches!(&t.repr, Some(anchor_lang_idl::types::IdlRepr::C(_))));
        assert!(has_repr_c, "whirlpool should have repr(C) types");

        // -- Deep: exactly 5 repr(C) types --
        let repr_c_types: Vec<&str> = idl
            .types
            .iter()
            .filter(|t| matches!(&t.repr, Some(anchor_lang_idl::types::IdlRepr::C(_))))
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(
            repr_c_types.len(),
            5,
            "should have 5 repr(C) types, got {:?}",
            repr_c_types
        );
        assert!(repr_c_types.contains(&"Tick"));
        assert!(repr_c_types.contains(&"TickArray"));
        assert!(repr_c_types.contains(&"Oracle"));
        assert!(repr_c_types.contains(&"AdaptiveFeeConstants"));
        assert!(repr_c_types.contains(&"AdaptiveFeeVariables"));

        // -- Deep: Whirlpool type fields --
        let wp = idl
            .types
            .iter()
            .find(|t| t.name == "Whirlpool")
            .expect("should have Whirlpool type");
        match &wp.ty {
            IdlTypeDefTy::Struct {
                fields: Some(IdlDefinedFields::Named(f)),
            } => {
                assert_eq!(f[0].name, "whirlpools_config");
                assert_eq!(f[0].ty, IdlType::Pubkey);
                assert_eq!(f[2].name, "tick_spacing");
                assert_eq!(f[2].ty, IdlType::U16);
                assert_eq!(f[4].name, "fee_rate");
                assert_eq!(f[4].ty, IdlType::U16);
            }
            other => panic!("Whirlpool should be struct, got {:?}", other),
        }

        // -- Deep: TickArray has array of 88 Ticks --
        let ta = idl
            .types
            .iter()
            .find(|t| t.name == "TickArray")
            .expect("should have TickArray type");
        match &ta.ty {
            IdlTypeDefTy::Struct {
                fields: Some(IdlDefinedFields::Named(f)),
            } => {
                assert_eq!(f[0].name, "start_tick_index");
                assert_eq!(f[0].ty, IdlType::I32);
                assert_eq!(f[1].name, "ticks");
                match &f[1].ty {
                    IdlType::Array(inner, IdlArrayLen::Value(88)) => {
                        assert!(
                            matches!(&**inner, IdlType::Defined { name, .. } if name == "Tick"),
                            "ticks inner type should be Defined(Tick), got {:?}",
                            inner
                        );
                    }
                    other => panic!("ticks should be [Tick; 88], got {:?}", other),
                }
            }
            other => panic!("TickArray should be struct, got {:?}", other),
        }

        // -- Deep: first instruction discriminator bytes and account properties --
        let ix0 = &idl.instructions[0];
        assert_eq!(ix0.name, "close_bundled_position");
        assert_eq!(ix0.discriminator, vec![41, 36, 216, 245, 27, 85, 103, 67]);
        let accs = single_accounts(ix0);
        assert!(accs[0].writable, "bundled_position should be writable");
        assert!(accs[3].signer, "position_bundle_authority should be signer");

        // -- Deep: Whirlpool account discriminator --
        let wp_acc = idl
            .accounts
            .iter()
            .find(|a| a.name == "Whirlpool")
            .expect("should have Whirlpool account");
        assert_eq!(
            wp_acc.discriminator,
            vec![63, 149, 209, 12, 225, 128, 99, 9]
        );
    }

    #[test]
    fn test_parse_shank_bubblegum() {
        let idl = parse_test_idl("shank_bubblegum.json");
        verify_idl_basics(&idl);
        assert_eq!(idl.metadata.name, "bubblegum");
        assert!(
            idl.instructions.len() >= 30,
            "bubblegum should have >= 30 instructions, got {}",
            idl.instructions.len()
        );

        // -- Deep: specific instruction names (Shank legacy → snake_case) --
        let ix_names: Vec<&str> = idl.instructions.iter().map(|ix| ix.name.as_str()).collect();
        assert!(ix_names.contains(&"burn"), "should have burn instruction");
        assert!(
            ix_names.contains(&"transfer"),
            "should have transfer instruction"
        );
        // mintV1 → mint_v1 after legacy conversion
        assert!(
            ix_names.contains(&"mint_v1"),
            "should have mint_v1 instruction, got {:?}",
            ix_names
        );

        // -- Deep: burn instruction args --
        let burn = idl
            .instructions
            .iter()
            .find(|ix| ix.name == "burn")
            .expect("should have burn instruction");
        let arg_names: Vec<&str> = burn.args.iter().map(|a| a.name.as_str()).collect();
        assert!(arg_names.contains(&"root"), "burn should have root arg");
        assert!(arg_names.contains(&"nonce"), "burn should have nonce arg");
        // Shank IDLs get 8-byte discriminators from convert_idl
        assert_eq!(
            burn.discriminator.len(),
            8,
            "Shank instruction should get 8-byte discriminator from convert_idl"
        );

        // -- Deep: TokenStandard enum --
        let ts = idl
            .types
            .iter()
            .find(|t| t.name == "TokenStandard")
            .expect("should have TokenStandard type");
        match &ts.ty {
            IdlTypeDefTy::Enum { variants } => {
                assert_eq!(variants.len(), 4);
                assert_eq!(variants[0].name, "NonFungible");
                assert_eq!(variants[3].name, "NonFungibleEdition");
            }
            other => panic!("TokenStandard should be enum, got {:?}", other),
        }

        // -- Deep: MetadataArgs struct --
        let ma = idl
            .types
            .iter()
            .find(|t| t.name == "MetadataArgs")
            .expect("should have MetadataArgs type");
        match &ma.ty {
            IdlTypeDefTy::Struct {
                fields: Some(IdlDefinedFields::Named(f)),
            } => {
                assert_eq!(f.len(), 12, "MetadataArgs should have 12 fields");
                assert_eq!(f[0].name, "name");
                assert_eq!(f[0].ty, IdlType::String);
            }
            other => panic!(
                "MetadataArgs should be struct with named fields, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_parse_shank_candy_guard() {
        let idl = parse_test_idl("shank_candy_guard.json");
        verify_idl_basics(&idl);
        assert_eq!(idl.metadata.name, "candy_guard");
        assert!(
            idl.types.len() >= 20,
            "candy_guard should have >= 20 types, got {}",
            idl.types.len()
        );

        // -- Deep: Allocation struct --
        let alloc = idl
            .types
            .iter()
            .find(|t| t.name == "Allocation")
            .expect("should have Allocation type");
        match &alloc.ty {
            IdlTypeDefTy::Struct {
                fields: Some(IdlDefinedFields::Named(f)),
            } => {
                assert_eq!(f[0].name, "id");
                assert_eq!(f[0].ty, IdlType::U8);
                assert_eq!(f[1].name, "limit");
                assert_eq!(f[1].ty, IdlType::U32);
            }
            other => panic!("Allocation should be struct, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Discriminator truncation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bincode_discriminators_truncated_codama_stake() {
        let idl = parse_test_idl_with_truncation("codama_stake.json");
        // After truncation, all discriminators should be 4 bytes
        for ix in &idl.instructions {
            assert_eq!(
                ix.discriminator.len(),
                4,
                "instruction {} should have 4-byte discriminator after truncation",
                ix.name
            );
        }
        // First instruction (initialize) should be [0,0,0,0]
        assert_eq!(idl.instructions[0].discriminator, vec![0, 0, 0, 0]);
        // Second instruction (authorize) should be [1,0,0,0]
        assert_eq!(idl.instructions[1].discriminator, vec![1, 0, 0, 0]);
    }

    #[test]
    fn test_bincode_discriminators_truncated_anchor_stake() {
        let idl = parse_test_idl_with_truncation("anchor_stake.json");
        // Anchor stake also has padded bincode discriminators
        for ix in &idl.instructions {
            assert_eq!(
                ix.discriminator.len(),
                4,
                "instruction {} should have 4-byte discriminator after truncation",
                ix.name
            );
        }
    }

    #[test]
    fn test_anchor_discriminators_not_truncated() {
        let idl = parse_test_idl_with_truncation("anchor_marginfi.json");
        // Marginfi has real SHA256 discriminators - should NOT be truncated
        for ix in &idl.instructions {
            assert_eq!(
                ix.discriminator.len(),
                8,
                "instruction {} should keep 8-byte discriminator",
                ix.name
            );
        }
        // Verify that last 4 bytes are not all zero (statistically certain for SHA256)
        let has_nonzero_tail = idl
            .instructions
            .iter()
            .any(|ix| ix.discriminator[4..] != [0, 0, 0, 0]);
        assert!(
            has_nonzero_tail,
            "SHA256 discriminators should have non-zero last 4 bytes"
        );
    }

    #[test]
    fn test_truncation_empty_instructions() {
        let mut idl = Idl {
            address: "11111111111111111111111111111111".to_string(),
            metadata: anchor_lang_idl::types::IdlMetadata {
                name: "empty".to_string(),
                version: "0.1.0".to_string(),
                spec: "0.1.0".to_string(),
                description: None,
                repository: None,
                dependencies: vec![],
                contact: None,
                deployments: None,
            },
            docs: vec![],
            instructions: vec![],
            accounts: vec![],
            events: vec![],
            errors: vec![],
            types: vec![],
            constants: vec![],
        };
        // Should not panic on empty instructions
        truncate_bincode_discriminators(&mut idl);
        assert!(idl.instructions.is_empty());
    }

    #[test]
    fn test_truncation_single_all_zero_discriminator() {
        let mut idl = Idl {
            address: "11111111111111111111111111111111".to_string(),
            metadata: anchor_lang_idl::types::IdlMetadata {
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
            instructions: vec![anchor_lang_idl::types::IdlInstruction {
                name: "init".to_string(),
                docs: vec![],
                discriminator: vec![0, 0, 0, 0, 0, 0, 0, 0],
                accounts: vec![],
                args: vec![],
                returns: None,
            }],
            accounts: vec![],
            events: vec![],
            errors: vec![],
            types: vec![],
            constants: vec![],
        };
        truncate_bincode_discriminators(&mut idl);
        // Single instruction with all-zero disc should still truncate
        assert_eq!(idl.instructions[0].discriminator, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_truncation_mixed_discriminators_no_truncate() {
        // One padded (bincode-style), one real SHA → should NOT truncate
        let mut idl = Idl {
            address: "11111111111111111111111111111111".to_string(),
            metadata: anchor_lang_idl::types::IdlMetadata {
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
            instructions: vec![
                anchor_lang_idl::types::IdlInstruction {
                    name: "init".to_string(),
                    docs: vec![],
                    discriminator: vec![0, 0, 0, 0, 0, 0, 0, 0],
                    accounts: vec![],
                    args: vec![],
                    returns: None,
                },
                anchor_lang_idl::types::IdlInstruction {
                    name: "process".to_string(),
                    docs: vec![],
                    discriminator: vec![1, 2, 3, 4, 5, 6, 7, 8],
                    accounts: vec![],
                    args: vec![],
                    returns: None,
                },
            ],
            accounts: vec![],
            events: vec![],
            errors: vec![],
            types: vec![],
            constants: vec![],
        };
        truncate_bincode_discriminators(&mut idl);
        // Should stay at 8 bytes (not all padded)
        assert_eq!(idl.instructions[0].discriminator.len(), 8);
        assert_eq!(idl.instructions[1].discriminator.len(), 8);
    }

    // -----------------------------------------------------------------------
    // Error / edge case tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_invalid_json() {
        let result = parse_idl("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_json_object() {
        let result = parse_idl("{}");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Cross-format equivalence test
    // -----------------------------------------------------------------------

    #[test]
    fn test_codama_anchor_stake_equivalence() {
        let codama = parse_test_idl_with_truncation("codama_stake.json");
        let anchor = parse_test_idl_with_truncation("anchor_stake.json");

        // Same instruction count
        assert_eq!(
            codama.instructions.len(),
            anchor.instructions.len(),
            "instruction count mismatch"
        );

        // Same discriminator values after truncation
        for (c, a) in codama.instructions.iter().zip(&anchor.instructions) {
            assert_eq!(
                c.discriminator, a.discriminator,
                "discriminator mismatch for codama:{} vs anchor:{}",
                c.name, a.name
            );
        }

        // Both have StakeAuthorize with same variants
        let c_sa = codama
            .types
            .iter()
            .find(|t| t.name == "StakeAuthorize")
            .expect("codama should have StakeAuthorize");
        let a_sa = anchor
            .types
            .iter()
            .find(|t| t.name == "StakeAuthorize")
            .expect("anchor should have StakeAuthorize");
        match (&c_sa.ty, &a_sa.ty) {
            (IdlTypeDefTy::Enum { variants: cv }, IdlTypeDefTy::Enum { variants: av }) => {
                assert_eq!(cv.len(), av.len(), "StakeAuthorize variant count mismatch");
                for (c, a) in cv.iter().zip(av) {
                    assert_eq!(c.name, a.name, "StakeAuthorize variant name mismatch");
                }
            }
            _ => panic!("StakeAuthorize should be enum in both formats"),
        }

        // Both have Lockup with same field structure
        let c_lockup = codama
            .types
            .iter()
            .find(|t| t.name == "Lockup")
            .expect("codama should have Lockup");
        let a_lockup = anchor
            .types
            .iter()
            .find(|t| t.name == "Lockup")
            .expect("anchor should have Lockup");
        match (&c_lockup.ty, &a_lockup.ty) {
            (
                IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Named(cf)),
                },
                IdlTypeDefTy::Struct {
                    fields: Some(IdlDefinedFields::Named(af)),
                },
            ) => {
                assert_eq!(cf.len(), af.len(), "Lockup field count mismatch");
                for (c, a) in cf.iter().zip(af) {
                    assert_eq!(c.name, a.name, "Lockup field name mismatch");
                    assert_eq!(c.ty, a.ty, "Lockup field type mismatch for {}", c.name);
                }
            }
            _ => panic!("Lockup should be struct with named fields in both formats"),
        }
    }

    // -----------------------------------------------------------------------
    // End-to-end pipeline tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pipeline_codama_stake() {
        let output = run_full_pipeline("codama_stake.json");
        assert!(
            output.contains("mod instruction"),
            "should have instruction module"
        );
        assert!(
            output.contains("mod accounts"),
            "should have accounts module"
        );
        assert!(output.contains("mod types"), "should have types module");
        assert!(output.contains("mod state"), "should have state module");
        // Bincode: should use repr(u32) for unit enums
        assert!(
            output.contains("repr (u32)"),
            "bincode enum should use repr(u32)"
        );
        // Should have StakeAuthorize type
        assert!(
            output.contains("StakeAuthorize"),
            "should have StakeAuthorize type"
        );
        // Should have specific instructions
        assert!(
            output.contains("Initialize"),
            "should have Initialize instruction"
        );
        assert!(
            output.contains("DelegateStake"),
            "should have DelegateStake instruction"
        );
    }

    #[test]
    fn test_pipeline_codama_system() {
        let output = run_full_pipeline("codama_system.json");
        assert!(output.contains("mod instruction"));
        assert!(output.contains("mod accounts"));
        assert!(output.contains("mod types"));
        // System program has 13 instructions — verify key ones
        assert!(
            output.contains("CreateAccount"),
            "should have CreateAccount instruction"
        );
        assert!(
            output.contains("TransferSol"),
            "should have TransferSol instruction"
        );
        assert!(output.contains("Assign"), "should have Assign instruction");
        assert!(
            output.contains("AdvanceNonceAccount"),
            "should have AdvanceNonceAccount instruction"
        );
        assert!(
            output.contains("InitializeNonceAccount"),
            "should have InitializeNonceAccount instruction"
        );
        // System program has nonce types
        let types_mod = extract_module(&output, "types");
        let has_nonce_type = types_mod.contains("Nonce");
        assert!(
            has_nonce_type,
            "types module should contain nonce-related types"
        );
        // Bincode detection
        assert!(
            output.contains("repr (u32)"),
            "system program is bincode, unit enums should use repr(u32)"
        );
    }

    #[test]
    fn test_pipeline_codama_token() {
        let output = run_full_pipeline("codama_token.json");
        assert!(output.contains("mod instruction"));
        assert!(output.contains("mod types"));
        // Token program has 25 instructions — verify key ones
        assert!(
            output.contains("InitializeMint"),
            "should have InitializeMint instruction"
        );
        assert!(
            output.contains("Transfer"),
            "should have Transfer instruction"
        );
        assert!(
            output.contains("Approve"),
            "should have Approve instruction"
        );
        assert!(output.contains("MintTo"), "should have MintTo instruction");
        assert!(output.contains("Burn"), "should have Burn instruction");
        assert!(
            output.contains("CloseAccount"),
            "should have CloseAccount instruction"
        );
        assert!(
            output.contains("FreezeAccount"),
            "should have FreezeAccount instruction"
        );
        assert!(
            output.contains("TransferChecked"),
            "should have TransferChecked instruction"
        );
        // Token has AuthorityType enum
        let types_mod = extract_module(&output, "types");
        assert!(
            types_mod.contains("AuthorityType"),
            "types should have AuthorityType enum"
        );
        // Token has account types (mint, token, multisig)
        assert!(output.contains("mod state"), "should have state module");
    }

    #[test]
    fn test_pipeline_codama_compute_budget() {
        let output = run_full_pipeline("codama_compute_budget.json");
        assert!(output.contains("mod instruction"));
        // Compute budget has 5 specific instructions
        assert!(
            output.contains("SetComputeUnitLimit"),
            "should have SetComputeUnitLimit instruction"
        );
        assert!(
            output.contains("SetComputeUnitPrice"),
            "should have SetComputeUnitPrice instruction"
        );
        assert!(
            output.contains("RequestHeapFrame"),
            "should have RequestHeapFrame instruction"
        );
        // Minimal program: no custom types needed
        let ix_mod = extract_module(&output, "instruction");
        let disc_count = ix_mod
            .matches("impl anchor_lang :: Discriminator for")
            .count();
        assert_eq!(
            disc_count, 5,
            "compute_budget should have 5 Discriminator impls, got {}",
            disc_count
        );
    }

    #[test]
    fn test_pipeline_codama_memo() {
        let output = run_full_pipeline("codama_memo.json");
        assert!(output.contains("mod instruction"));
        // Memo has exactly 1 instruction
        assert!(
            output.contains("AddMemo"),
            "should have AddMemo instruction"
        );
        let ix_mod = extract_module(&output, "instruction");
        let disc_count = ix_mod
            .matches("impl anchor_lang :: Discriminator for")
            .count();
        assert_eq!(
            disc_count, 1,
            "memo should have exactly 1 Discriminator impl, got {}",
            disc_count
        );
    }

    #[test]
    fn test_pipeline_anchor_stake() {
        let output = run_full_pipeline("anchor_stake.json");
        assert!(output.contains("mod instruction"));
        assert!(output.contains("mod types"));
        // Also bincode (padded discriminators)
        assert!(
            output.contains("repr (u32)"),
            "anchor stake bincode enum should use repr(u32)"
        );

        // anchor_stake has 6 optional accounts (e.g. lockupAuthority in authorize)
        // Verify codegen generates Option<Pubkey> fields and conditional to_account_metas
        assert!(
            output.contains("Option < Pubkey >"),
            "optional accounts should generate Option<Pubkey> fields"
        );
        assert!(
            output.contains("if let Some"),
            "optional accounts should generate conditional account_metas push"
        );
    }

    #[test]
    fn test_pipeline_anchor_marginfi() {
        let output = run_full_pipeline("anchor_marginfi.json");
        assert!(output.contains("mod instruction"));
        assert!(output.contains("mod accounts"));
        assert!(output.contains("mod types"));
        assert!(output.contains("mod state"));
        // Borsh: should use repr(u8) for enums, not repr(u32)
        assert!(
            !output.contains("repr (u32)"),
            "borsh IDL should not use repr(u32)"
        );
        assert!(
            output.contains("repr (u8)"),
            "borsh IDL should use repr(u8)"
        );
        // Should have WrappedI80F48 with From impls
        assert!(
            output.contains("WrappedI80F48"),
            "should have WrappedI80F48 type"
        );
        assert!(
            output.contains("from_i80f48"),
            "should have from_i80f48 method"
        );
    }

    #[test]
    fn test_pipeline_anchor_whirlpool() {
        let output = run_full_pipeline("anchor_whirlpool.json");
        assert!(output.contains("mod instruction"));
        assert!(output.contains("mod accounts"));
        assert!(output.contains("mod types"));
        assert!(output.contains("mod state"));
        // Should have zero-copy types with repr(C) and bytemuck
        assert!(
            output.contains("repr (C)"),
            "should have repr(C) for zero-copy types"
        );
        assert!(
            output.contains("bytemuck"),
            "should have bytemuck derives for zero-copy types"
        );

        // TickArray has [Tick; 88] which can't derive Default (>32)
        // Verify manual Default impl is generated
        assert!(
            output.contains("impl Default for TickArray"),
            "TickArray with [Tick;88] should get manual Default impl"
        );

        // State module should have DISCRIMINATOR_LEN for account types
        assert!(
            output.contains("DISCRIMINATOR_LEN : usize = 8usize"),
            "state account discriminators should be 8 bytes"
        );
    }

    #[test]
    fn test_pipeline_shank_bubblegum() {
        let output = run_full_pipeline("shank_bubblegum.json");
        assert!(output.contains("mod instruction"));
        assert!(output.contains("mod types"));
        // Bubblegum has 34+ instructions — verify key ones
        assert!(output.contains("Burn"), "should have Burn instruction");
        assert!(
            output.contains("Transfer"),
            "should have Transfer instruction"
        );
        assert!(output.contains("MintV1"), "should have MintV1 instruction");
        assert!(
            output.contains("CreateTree"),
            "should have CreateTree instruction"
        );
        assert!(
            output.contains("Delegate"),
            "should have Delegate instruction"
        );
        assert!(
            output.contains("Compress"),
            "should have Compress instruction"
        );
        // Key types
        let types_mod = extract_module(&output, "types");
        assert!(types_mod.contains("Creator"), "types should have Creator");
        assert!(
            types_mod.contains("MetadataArgs"),
            "types should have MetadataArgs"
        );
        assert!(
            types_mod.contains("TokenStandard"),
            "types should have TokenStandard"
        );
        assert!(
            types_mod.contains("LeafSchema"),
            "types should have LeafSchema"
        );
        // Borsh encoding (Shank IDLs)
        assert!(
            !types_mod.contains("repr (u32)"),
            "Shank IDL should NOT have repr(u32)"
        );
    }

    #[test]
    fn test_pipeline_shank_candy_guard() {
        let output = run_full_pipeline("shank_candy_guard.json");
        assert!(output.contains("mod instruction"));
        assert!(output.contains("mod types"));
        // Candy guard has 9 instructions — verify key ones
        assert!(
            output.contains("Initialize"),
            "should have Initialize instruction"
        );
        assert!(output.contains("Mint"), "should have Mint instruction");
        assert!(output.contains("MintV2"), "should have MintV2 instruction");
        assert!(output.contains("Route"), "should have Route instruction");
        assert!(output.contains("Wrap"), "should have Wrap instruction");
        assert!(output.contains("Unwrap"), "should have Unwrap instruction");
        // Key guard types
        let types_mod = extract_module(&output, "types");
        assert!(
            types_mod.contains("Allocation"),
            "types should have Allocation guard"
        );
        assert!(
            types_mod.contains("AllowList"),
            "types should have AllowList guard"
        );
        assert!(
            types_mod.contains("BotTax"),
            "types should have BotTax guard"
        );
        assert!(
            types_mod.contains("EndDate"),
            "types should have EndDate guard"
        );
    }

    // -----------------------------------------------------------------------
    // Pipeline: state module verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_pipeline_marginfi_state_module() {
        let output = run_full_pipeline("anchor_marginfi.json");
        // Marginfi has 5 accounts — verify state module generates all of them
        assert!(
            output.contains("pub struct Bank"),
            "state should have Bank struct"
        );
        assert!(
            output.contains("pub struct MarginfiGroup"),
            "state should have MarginfiGroup struct"
        );
        assert!(
            output.contains("pub struct MarginfiAccount"),
            "state should have MarginfiAccount struct"
        );
    }

    #[test]
    fn test_pipeline_whirlpool_state_module() {
        let output = run_full_pipeline("anchor_whirlpool.json");
        // Whirlpool has 12 accounts — verify key state types exist
        assert!(
            output.contains("pub struct Whirlpool"),
            "state should have Whirlpool struct"
        );
        assert!(
            output.contains("pub struct TickArray"),
            "state should have TickArray struct"
        );
        assert!(
            output.contains("pub struct Position"),
            "state should have Position struct"
        );
    }

    // -----------------------------------------------------------------------
    // Pipeline: type completeness verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_pipeline_all_types_generated() {
        // For each IDL, verify every type in idl.types produces generated code
        for filename in &[
            "anchor_marginfi.json",
            "anchor_whirlpool.json",
            "codama_stake.json",
        ] {
            let idl = parse_test_idl(filename);
            let output = run_full_pipeline(filename);
            for ty in &idl.types {
                let has_struct = output.contains(&format!("struct {}", ty.name));
                let has_enum = output.contains(&format!("enum {}", ty.name));
                let has_alias = output.contains(&format!("type {} =", ty.name));
                assert!(
                    has_struct || has_enum || has_alias,
                    "Type {} from {} not found in generated output",
                    ty.name,
                    filename
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Pipeline: program ID verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_pipeline_program_id_generated() {
        for filename in &[
            "anchor_marginfi.json",
            "codama_stake.json",
            "anchor_whirlpool.json",
        ] {
            let output = run_full_pipeline(filename);
            assert!(
                output.contains("pub static ID"),
                "{} should generate program ID constant",
                filename
            );
            assert!(
                output.contains("Pubkey :: new_from_array"),
                "{} program ID should use new_from_array",
                filename
            );
        }
    }

    // -----------------------------------------------------------------------
    // Pipeline: malformed input handling
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_malformed_codama() {
        let json = r#"{"kind": "rootNode", "program": {"invalid": true}}"#;
        let result = parse_idl(json);
        assert!(result.is_err(), "malformed Codama should error");
    }

    // -----------------------------------------------------------------------
    // Codegen structural count tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pipeline_marginfi_instruction_count() {
        let output = run_full_pipeline("anchor_marginfi.json");
        // Count Discriminator impls to verify all 45 instructions got codegen'd
        let disc_count = output
            .matches("impl anchor_lang :: Discriminator for")
            .count();
        assert_eq!(
            disc_count, 45,
            "should have 45 Discriminator impls (one per instruction), got {}",
            disc_count
        );
    }

    #[test]
    fn test_pipeline_whirlpool_zero_copy_count() {
        let output = run_full_pipeline("anchor_whirlpool.json");
        // Count bytemuck::Pod impls to verify zero-copy types got codegen'd
        let pod_count = output.matches("bytemuck :: Pod").count();
        assert!(
            pod_count >= 5,
            "should have >= 5 Pod impls (for zero-copy types + state), got {}",
            pod_count
        );
    }

    // -----------------------------------------------------------------------
    // Encoding detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bincode_detection_codama_stake() {
        let mut idl = parse_test_idl("codama_stake.json");
        truncate_bincode_discriminators(&mut idl);
        let use_bincode = idl
            .instructions
            .first()
            .map(|ix| ix.discriminator.len() == 4)
            .unwrap_or(false);
        assert!(use_bincode, "codama stake should be detected as bincode");
    }

    #[test]
    fn test_bincode_detection_anchor_stake() {
        let mut idl = parse_test_idl("anchor_stake.json");
        truncate_bincode_discriminators(&mut idl);
        let use_bincode = idl
            .instructions
            .first()
            .map(|ix| ix.discriminator.len() == 4)
            .unwrap_or(false);
        assert!(use_bincode, "anchor stake should be detected as bincode");
    }

    #[test]
    fn test_borsh_detection_marginfi() {
        let mut idl = parse_test_idl("anchor_marginfi.json");
        truncate_bincode_discriminators(&mut idl);
        let use_bincode = idl
            .instructions
            .first()
            .map(|ix| ix.discriminator.len() == 4)
            .unwrap_or(false);
        assert!(!use_bincode, "marginfi should be detected as borsh");
    }

    // -----------------------------------------------------------------------
    // #6: Shank IDLs generate state module content
    // -----------------------------------------------------------------------

    /// Extract the content of a specific module from generated code.
    /// Returns text between `mod <name> {` and its closing `}`.
    fn extract_module(output: &str, module_name: &str) -> String {
        let marker = format!("mod {} {{", module_name);
        // TokenStream spacing: "mod state {"
        let alt_marker = format!("mod {}", module_name);
        let start = output
            .find(&marker)
            .or_else(|| output.find(&alt_marker))
            .unwrap_or_else(|| panic!("could not find module '{}' in output", module_name));

        // Find balanced braces from the first { after start
        let from_start = &output[start..];
        let brace_start = from_start.find('{').unwrap();
        let mut depth = 0;
        let mut end = brace_start;
        for (i, ch) in from_start[brace_start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = brace_start + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        from_start[brace_start..=end].to_string()
    }

    #[test]
    fn test_pipeline_shank_bubblegum_state_module() {
        let idl = parse_test_idl("shank_bubblegum.json");
        assert!(
            !idl.accounts.is_empty(),
            "bubblegum should have account entries, got {}",
            idl.accounts.len()
        );

        let output = run_full_pipeline("shank_bubblegum.json");
        let state_mod = extract_module(&output, "state");

        // Verify account types appear specifically in the state module, not just anywhere
        let mut found_any = false;
        for acc in &idl.accounts {
            if idl.types.iter().any(|t| t.name == acc.name) {
                assert!(
                    state_mod.contains(&acc.name),
                    "state module should contain account type '{}', state module content: {}",
                    acc.name,
                    &state_mod[..state_mod.len().min(500)]
                );
                // Verify it has DISCRIMINATOR (state module specific)
                assert!(
                    state_mod.contains("DISCRIMINATOR"),
                    "state module accounts should have DISCRIMINATOR constant"
                );
                found_any = true;
            }
        }
        assert!(
            found_any,
            "should have found at least one account in state module"
        );
    }

    #[test]
    fn test_pipeline_shank_candy_guard_state_module() {
        let idl = parse_test_idl("shank_candy_guard.json");
        assert!(
            !idl.accounts.is_empty(),
            "candy_guard should have account entries, got {}",
            idl.accounts.len()
        );

        let output = run_full_pipeline("shank_candy_guard.json");
        let state_mod = extract_module(&output, "state");

        let mut found_any = false;
        for acc in &idl.accounts {
            if idl.types.iter().any(|t| t.name == acc.name) {
                assert!(
                    state_mod.contains(&acc.name),
                    "state module should contain account type '{}' in state module",
                    acc.name
                );
                found_any = true;
            }
        }
        assert!(
            found_any,
            "should have found at least one account in state module"
        );
    }

    // -----------------------------------------------------------------------
    // #11: idl_type_to_tokens fallback
    // -----------------------------------------------------------------------

    #[test]
    fn test_idl_type_u256_maps_to_byte_array() {
        let output =
            codegen::idl_type_to_tokens(&anchor_lang_idl::types::IdlType::U256).to_string();
        assert_eq!(output, "[u8 ; 32]", "U256 should map to [u8; 32]");
    }

    #[test]
    fn test_idl_type_i256_maps_to_byte_array() {
        let output =
            codegen::idl_type_to_tokens(&anchor_lang_idl::types::IdlType::I256).to_string();
        assert_eq!(output, "[u8 ; 32]", "I256 should map to [u8; 32]");
    }

    // -----------------------------------------------------------------------
    // #12: Instruction with Defined arg types
    // -----------------------------------------------------------------------

    #[test]
    fn test_pipeline_marginfi_defined_args() {
        let idl = parse_test_idl("anchor_marginfi.json");
        // Find an instruction with a Defined type arg
        let has_defined_arg = idl.instructions.iter().any(|ix| {
            ix.args
                .iter()
                .any(|arg| matches!(&arg.ty, anchor_lang_idl::types::IdlType::Defined { .. }))
        });
        assert!(
            has_defined_arg,
            "marginfi should have instructions with Defined type args"
        );

        let output = run_full_pipeline("anchor_marginfi.json");
        let ix_mod = extract_module(&output, "instruction");

        // BankConfigOpt is a Defined arg type used in lending_pool_configure_bank
        // It must appear in the instruction module (as a field type), not just in types
        assert!(
            ix_mod.contains("BankConfigOpt"),
            "instruction module should reference BankConfigOpt as a field type, ix_mod: {}",
            &ix_mod[..ix_mod.len().min(500)]
        );

        // Verify it's used as a struct field, not just mentioned
        assert!(
            ix_mod.contains("pub bank_config_opt : BankConfigOpt"),
            "should have bank_config_opt field with BankConfigOpt type in instruction module"
        );
    }

    // -----------------------------------------------------------------------
    // Encoding detection: bincode vs borsh vs bytemuck on real IDLs
    // -----------------------------------------------------------------------

    #[test]
    fn test_encoding_bincode_stake_unit_enums_are_repr_u32() {
        // Stake programs use bincode → unit enums must use repr(u32) with manual ser/deser
        let output = run_full_pipeline("codama_stake.json");
        let types_mod = extract_module(&output, "types");

        // StakeAuthorize is a unit enum → should get repr(u32) + manual ser/deser
        assert!(
            types_mod.contains("repr (u32)"),
            "bincode IDL unit enums should use repr(u32)"
        );

        // Manual AnchorSerialize impl (not derived)
        assert!(
            types_mod.contains("impl AnchorSerialize for StakeAuthorize"),
            "bincode unit enum should have manual AnchorSerialize impl"
        );
        assert!(
            types_mod.contains("impl AnchorDeserialize for StakeAuthorize"),
            "bincode unit enum should have manual AnchorDeserialize impl"
        );
        assert!(
            types_mod.contains("to_le_bytes"),
            "bincode ser should write u32 LE"
        );
        assert!(
            types_mod.contains("from_le_bytes"),
            "bincode deser should read u32 LE"
        );
    }

    #[test]
    fn test_encoding_bincode_anchor_stake_same_as_codama() {
        // Anchor-format stake IDL should produce identical encoding to Codama-format
        let codama_output = run_full_pipeline("codama_stake.json");
        let anchor_output = run_full_pipeline("anchor_stake.json");

        let codama_types = extract_module(&codama_output, "types");
        let anchor_types = extract_module(&anchor_output, "types");

        // Both should use repr(u32) for unit enums (StakeAuthorize)
        assert!(
            codama_types.contains("repr (u32)"),
            "codama stake should have repr(u32)"
        );
        assert!(
            anchor_types.contains("repr (u32)"),
            "anchor stake should have repr(u32)"
        );

        // Both should ALSO have repr(u8) — for data enums like StakeState
        // (data enums fall back to borsh-style even in bincode programs)
        assert!(
            codama_types.contains("repr (u8)"),
            "codama stake should have repr(u8) for data enums like StakeState"
        );
        assert!(
            anchor_types.contains("repr (u8)"),
            "anchor stake should have repr(u8) for data enums like StakeState"
        );
    }

    #[test]
    fn test_encoding_borsh_marginfi_enums_are_repr_u8() {
        // Marginfi uses borsh → unit enums must use repr(u8) with derived ser/deser
        let output = run_full_pipeline("anchor_marginfi.json");
        let types_mod = extract_module(&output, "types");

        // Should use repr(u8), NOT repr(u32)
        assert!(
            types_mod.contains("repr (u8)"),
            "borsh IDL unit enums should use repr(u8)"
        );
        assert!(
            !types_mod.contains("repr (u32)"),
            "borsh IDL should NOT have any repr(u32) enums"
        );

        // Should have derived (not manual) ser/deser
        // Derived means AnchorSerialize appears in derive(), not as standalone impl
        assert!(
            !types_mod.contains("impl AnchorSerialize for"),
            "borsh enums should derive AnchorSerialize, not implement manually"
        );
    }

    #[test]
    fn test_encoding_borsh_whirlpool_enums_are_repr_u8() {
        let output = run_full_pipeline("anchor_whirlpool.json");
        let types_mod = extract_module(&output, "types");

        assert!(
            types_mod.contains("repr (u8)"),
            "whirlpool enums should use repr(u8)"
        );
        assert!(
            !types_mod.contains("repr (u32)"),
            "whirlpool should NOT have repr(u32)"
        );
    }

    #[test]
    fn test_encoding_bytemuck_on_repr_c_types() {
        // Whirlpool has repr(C) types → should get bytemuck derives
        let output = run_full_pipeline("anchor_whirlpool.json");
        let types_mod = extract_module(&output, "types");

        assert!(
            types_mod.contains("repr (C)"),
            "whirlpool should have repr(C) types"
        );
        assert!(
            types_mod.contains("bytemuck :: Pod"),
            "repr(C) types should get Pod"
        );
        assert!(
            types_mod.contains("bytemuck :: Zeroable"),
            "repr(C) types should get Zeroable"
        );

        // Marginfi also has repr(C) account types (serialization: bytemuck)
        // Both types and state modules should have bytemuck for zero-copy types
        let marginfi_output = run_full_pipeline("anchor_marginfi.json");
        let marginfi_types = extract_module(&marginfi_output, "types");
        assert!(
            marginfi_types.contains("repr (C)"),
            "marginfi has zero-copy account types → types module should have repr(C)"
        );
        assert!(
            marginfi_types.contains("bytemuck :: Pod"),
            "marginfi zero-copy types should have bytemuck Pod"
        );
    }

    #[test]
    fn test_encoding_no_bytemuck_on_bincode_programs() {
        // Bincode programs (stake) should NOT have bytemuck anywhere
        let codama_output = run_full_pipeline("codama_stake.json");
        let codama_types = extract_module(&codama_output, "types");
        assert!(
            !codama_types.contains("bytemuck"),
            "codama stake (bincode) should NOT have bytemuck"
        );
        assert!(
            !codama_types.contains("repr (C)"),
            "codama stake should NOT have repr(C)"
        );

        let anchor_output = run_full_pipeline("anchor_stake.json");
        let anchor_types = extract_module(&anchor_output, "types");
        assert!(
            !anchor_types.contains("bytemuck"),
            "anchor stake (bincode) should NOT have bytemuck"
        );
    }

    #[test]
    fn test_encoding_whirlpool_state_has_bytemuck_for_zero_copy_accounts() {
        // Zero-copy accounts in state module should get bytemuck, not borsh
        let output = run_full_pipeline("anchor_whirlpool.json");
        let state_mod = extract_module(&output, "state");

        assert!(
            state_mod.contains("bytemuck :: Pod"),
            "whirlpool state module should have bytemuck Pod for zero-copy accounts"
        );
        assert!(
            state_mod.contains("repr (C)"),
            "whirlpool state module should have repr(C) for zero-copy accounts"
        );
    }

    #[test]
    fn test_encoding_marginfi_state_is_zero_copy() {
        // Marginfi accounts have repr: {kind: "c"}, serialization: bytemuck → zero-copy
        let output = run_full_pipeline("anchor_marginfi.json");
        let state_mod = extract_module(&output, "state");

        // Bank is a zero-copy account → should have repr(C) + bytemuck in state
        assert!(
            state_mod.contains("repr (C)"),
            "marginfi Bank state should have repr(C) (it's zero-copy)"
        );
        assert!(
            state_mod.contains("bytemuck :: Pod"),
            "marginfi Bank state should have bytemuck Pod"
        );
        assert!(
            state_mod.contains("DISCRIMINATOR"),
            "marginfi state accounts should have DISCRIMINATOR const"
        );
    }

    #[test]
    fn test_encoding_discriminator_lengths_match_encoding() {
        // Bincode IDLs should have 4-byte discriminators after truncation
        let stake = parse_test_idl_with_truncation("codama_stake.json");
        for ix in &stake.instructions {
            assert_eq!(
                ix.discriminator.len(),
                4,
                "bincode instruction '{}' should have 4-byte disc",
                ix.name
            );
        }

        // Borsh IDLs should keep 8-byte discriminators (not truncated)
        let marginfi = parse_test_idl_with_truncation("anchor_marginfi.json");
        for ix in &marginfi.instructions {
            assert_eq!(
                ix.discriminator.len(),
                8,
                "borsh instruction '{}' should have 8-byte disc",
                ix.name
            );
        }

        // Verify instruction module emits correct discriminator lengths
        let stake_output = run_full_pipeline("codama_stake.json");
        let stake_ix = extract_module(&stake_output, "instruction");
        // 4-byte disc: DISCRIMINATOR: &'static [u8] = &[0u8, 0u8, 0u8, 0u8]
        // Count occurrences of DISCRIMINATOR const
        let disc_count = stake_ix.matches("DISCRIMINATOR : & 'static [u8]").count();
        assert_eq!(
            disc_count, 18,
            "stake should have 18 DISCRIMINATOR consts, got {}",
            disc_count
        );

        let marginfi_output = run_full_pipeline("anchor_marginfi.json");
        let marginfi_ix = extract_module(&marginfi_output, "instruction");
        let disc_count = marginfi_ix
            .matches("DISCRIMINATOR : & 'static [u8]")
            .count();
        assert_eq!(
            disc_count, 45,
            "marginfi should have 45 DISCRIMINATOR consts, got {}",
            disc_count
        );
    }

    #[test]
    fn test_encoding_bincode_data_enum_falls_back_to_borsh() {
        // StakeState in stake IDL has data variants → should use repr(u8) + borsh
        // even though the program is bincode
        let output = run_full_pipeline("codama_stake.json");
        let types_mod = extract_module(&output, "types");

        // StakeState has data variants: Uninitialized, Initialized(Meta), Stake(Meta, Stake), ...
        // Data enums in bincode programs still use borsh-style repr(u8) + derived ser/deser
        assert!(
            types_mod.contains("pub enum StakeState"),
            "should have StakeState enum in types"
        );

        // The enum should use repr(u8) (borsh) because it has data variants
        // while StakeAuthorize (unit-only) uses repr(u32) (bincode)
        // Verify both co-exist in the same types module
        assert!(
            types_mod.contains("repr (u32)"),
            "should have repr(u32) for unit enums"
        );
        assert!(
            types_mod.contains("repr (u8)"),
            "should have repr(u8) for data enums"
        );
    }

    #[test]
    fn test_encoding_shank_idls_use_borsh() {
        // Shank IDLs (bubblegum, candy_guard) get 8-byte SHA discriminators from convert_idl
        // They should use borsh encoding (repr(u8))
        for filename in &["shank_bubblegum.json", "shank_candy_guard.json"] {
            let idl = parse_test_idl_with_truncation(filename);
            let use_bincode = idl
                .instructions
                .first()
                .map(|ix| ix.discriminator.len() == 4)
                .unwrap_or(false);
            assert!(
                !use_bincode,
                "{} should be detected as borsh, not bincode",
                filename
            );

            let output = run_full_pipeline(filename);
            let types_mod = extract_module(&output, "types");
            assert!(
                !types_mod.contains("repr (u32)"),
                "{} should NOT have repr(u32) in types (borsh program)",
                filename
            );
        }
    }

    // -----------------------------------------------------------------------
    // Syntax validation: verify generated code parses as valid Rust
    // -----------------------------------------------------------------------

    /// Parse the generated TokenStream through syn to catch structural/syntax errors
    /// that string matching would miss.
    fn assert_valid_rust_syntax(filename: &str) {
        let tokens = run_full_pipeline_tokens(filename);
        syn::parse2::<syn::File>(tokens).unwrap_or_else(|e| {
            panic!(
                "Generated code for {} is not valid Rust syntax: {}",
                filename, e
            );
        });
    }

    #[test]
    fn test_syntax_valid_codama_stake() {
        assert_valid_rust_syntax("codama_stake.json");
    }
    #[test]
    fn test_syntax_valid_codama_system() {
        assert_valid_rust_syntax("codama_system.json");
    }
    #[test]
    fn test_syntax_valid_codama_token() {
        assert_valid_rust_syntax("codama_token.json");
    }
    #[test]
    fn test_syntax_valid_codama_compute_budget() {
        assert_valid_rust_syntax("codama_compute_budget.json");
    }
    #[test]
    fn test_syntax_valid_codama_memo() {
        assert_valid_rust_syntax("codama_memo.json");
    }
    #[test]
    fn test_syntax_valid_anchor_stake() {
        assert_valid_rust_syntax("anchor_stake.json");
    }
    #[test]
    fn test_syntax_valid_anchor_marginfi() {
        assert_valid_rust_syntax("anchor_marginfi.json");
    }
    #[test]
    fn test_syntax_valid_anchor_whirlpool() {
        assert_valid_rust_syntax("anchor_whirlpool.json");
    }
    #[test]
    fn test_syntax_valid_shank_bubblegum() {
        assert_valid_rust_syntax("shank_bubblegum.json");
    }
    #[test]
    fn test_syntax_valid_shank_candy_guard() {
        assert_valid_rust_syntax("shank_candy_guard.json");
    }

    // -----------------------------------------------------------------------
    // InstructionData: verify data() method emits discriminator + payload
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Schema generation: end-to-end tests on real IDLs
    // -----------------------------------------------------------------------

    #[test]
    fn test_schema_marginfi_all_5_zero_copy_accounts() {
        // Marginfi has 5 accounts, all zero-copy (repr: {kind: "c"})
        let idl = parse_test_idl("anchor_marginfi.json");
        let output = codegen::schemas::generate(&idl).to_string();

        // All 5 should be registered
        assert!(output.contains("\"Bank\""), "should have Bank schema");
        assert!(
            output.contains("\"FeeState\""),
            "should have FeeState schema"
        );
        assert!(
            output.contains("\"MarginfiAccount\""),
            "should have MarginfiAccount schema"
        );
        assert!(
            output.contains("\"MarginfiGroup\""),
            "should have MarginfiGroup schema"
        );
        assert!(
            output.contains("\"StakedSettings\""),
            "should have StakedSettings schema"
        );

        let schema_count = output.matches("AccountSchema").count();
        assert_eq!(
            schema_count, 5,
            "marginfi should have 5 AccountSchema entries, got {}",
            schema_count
        );

        assert!(
            output.contains("register_account_schemas"),
            "should register schemas"
        );
    }

    #[test]
    fn test_schema_marginfi_bank_field_names() {
        // Verify Bank account has the expected field names in its diff closure
        let idl = parse_test_idl("anchor_marginfi.json");
        let output = codegen::schemas::generate(&idl).to_string();

        // Key primitive fields
        assert!(
            output.contains("\"mint_decimals\""),
            "Bank should diff mint_decimals (u8)"
        );
        assert!(
            output.contains("\"last_update\""),
            "Bank should diff last_update (i64)"
        );
        assert!(output.contains("\"flags\""), "Bank should diff flags (u64)");
        assert!(
            output.contains("\"emissions_rate\""),
            "Bank should diff emissions_rate (u64)"
        );
        assert!(
            output.contains("\"lending_position_count\""),
            "Bank should diff lending_position_count (i32)"
        );
        assert!(
            output.contains("\"borrowing_position_count\""),
            "Bank should diff borrowing_position_count (i32)"
        );

        // Pubkey fields
        assert!(
            output.contains("\"mint\""),
            "Bank should diff mint (Pubkey)"
        );
        assert!(
            output.contains("\"group\""),
            "Bank should diff group (Pubkey)"
        );
        assert!(
            output.contains("\"liquidity_vault\""),
            "Bank should diff liquidity_vault (Pubkey)"
        );
        assert!(
            output.contains("\"emissions_mint\""),
            "Bank should diff emissions_mint (Pubkey)"
        );

        // Defined type fields (WrappedI80F48, BankConfig, etc.)
        assert!(
            output.contains("\"asset_share_value\""),
            "Bank should diff asset_share_value (WrappedI80F48)"
        );
        assert!(
            output.contains("\"total_liability_shares\""),
            "Bank should diff total_liability_shares (WrappedI80F48)"
        );
        assert!(
            output.contains("\"total_asset_shares\""),
            "Bank should diff total_asset_shares (WrappedI80F48)"
        );
        assert!(
            output.contains("\"config\""),
            "Bank should diff config (BankConfig)"
        );

        // Padding fields should be excluded
        assert!(!output.contains("\"_pad0\""), "Bank should skip _pad0");
        assert!(!output.contains("\"_pad1\""), "Bank should skip _pad1");
        assert!(!output.contains("\"_pad2\""), "Bank should skip _pad2");
        assert!(
            !output.contains("\"_padding_0\""),
            "Bank should skip _padding_0"
        );
    }

    #[test]
    fn test_schema_marginfi_discriminator_bytes() {
        // Verify Bank discriminator bytes match the IDL
        let idl = parse_test_idl("anchor_marginfi.json");
        let bank_acc = idl.accounts.iter().find(|a| a.name == "Bank").unwrap();
        let output = codegen::schemas::generate(&idl).to_string();

        // Bank discriminator: [142, 49, 166, 242, 50, 66, 97, 188]
        assert_eq!(
            bank_acc.discriminator,
            vec![142, 49, 166, 242, 50, 66, 97, 188]
        );
        assert!(output.contains("142u8"), "should have Bank disc byte 142");
        assert!(output.contains("188u8"), "should have Bank disc byte 188");
    }

    #[test]
    fn test_schema_whirlpool_mixed_zero_copy_and_borsh() {
        // Whirlpool has 12 accounts: 2 zero-copy (Oracle, TickArray), 10 borsh
        let idl = parse_test_idl("anchor_whirlpool.json");
        let output = codegen::schemas::generate(&idl).to_string();

        // Only zero-copy accounts should be registered
        assert!(
            output.contains("\"Oracle\""),
            "should have Oracle schema (zero-copy)"
        );
        assert!(
            output.contains("\"TickArray\""),
            "should have TickArray schema (zero-copy)"
        );

        // Borsh accounts should NOT be registered
        assert!(
            !output.contains("\"Whirlpool\""),
            "Whirlpool (borsh) should not have schema"
        );
        assert!(
            !output.contains("\"Position\""),
            "Position (borsh) should not have schema"
        );
        assert!(
            !output.contains("\"FeeTier\""),
            "FeeTier (borsh) should not have schema"
        );
        assert!(
            !output.contains("\"AdaptiveFeeTier\""),
            "AdaptiveFeeTier (borsh) should not have schema"
        );

        let schema_count = output.matches("AccountSchema").count();
        assert_eq!(
            schema_count, 2,
            "whirlpool should have 2 AccountSchema entries (only zero-copy), got {}",
            schema_count
        );
    }

    #[test]
    fn test_schema_whirlpool_oracle_fields() {
        // Oracle has: whirlpool (Pubkey), trade_enable_timestamp (u64),
        // adaptive_fee_constants/variables (Defined), reserved ([u8; 128] → skip)
        let idl = parse_test_idl("anchor_whirlpool.json");
        let output = codegen::schemas::generate(&idl).to_string();

        // Pubkey field
        assert!(
            output.contains("\"whirlpool\""),
            "Oracle should diff whirlpool (Pubkey)"
        );
        // u64 field
        assert!(
            output.contains("\"trade_enable_timestamp\""),
            "Oracle should diff trade_enable_timestamp (u64)"
        );
        // Defined type fields
        assert!(
            output.contains("\"adaptive_fee_constants\""),
            "Oracle should diff adaptive_fee_constants"
        );
        assert!(
            output.contains("\"adaptive_fee_variables\""),
            "Oracle should diff adaptive_fee_variables"
        );
        // [u8; 128] should be skipped (too large)
        assert!(
            !output.contains("\"reserved\""),
            "Oracle should skip reserved ([u8; 128])"
        );
    }

    #[test]
    fn test_schema_whirlpool_tickarray_skips_tick_array() {
        // TickArray has: start_tick_index (i32), ticks ([Tick; 88]), whirlpool (Pubkey)
        // [Tick; 88] is a non-u8 array → should be skipped
        let idl = parse_test_idl("anchor_whirlpool.json");
        let output = codegen::schemas::generate(&idl).to_string();

        assert!(
            output.contains("\"start_tick_index\""),
            "TickArray should diff start_tick_index (i32)"
        );
        assert!(
            output.contains("\"whirlpool\""),
            "TickArray should diff whirlpool (Pubkey)"
        );
        // [Tick; 88] should be skipped (non-u8 defined-type array)
        assert!(
            !output.contains("\"ticks\""),
            "TickArray should skip ticks ([Tick; 88])"
        );
    }

    #[test]
    fn test_schema_no_accounts_codama_stake() {
        // Stake program IDL has 0 accounts → noop register_schemas
        let idl = parse_test_idl("codama_stake.json");
        let output = codegen::schemas::generate(&idl).to_string();

        assert!(
            output.contains("register_schemas"),
            "should generate register_schemas"
        );
        assert!(
            !output.contains("register_account_schemas"),
            "stake (0 accounts) should not call register_account_schemas"
        );
    }

    #[test]
    fn test_schema_no_accounts_codama_system() {
        let idl = parse_test_idl("codama_system.json");
        let output = codegen::schemas::generate(&idl).to_string();
        assert!(
            !output.contains("register_account_schemas"),
            "system (0 accounts) should not call register_account_schemas"
        );
    }

    #[test]
    fn test_schema_no_accounts_codama_token() {
        let idl = parse_test_idl("codama_token.json");
        let output = codegen::schemas::generate(&idl).to_string();
        assert!(
            !output.contains("register_account_schemas"),
            "token (0 accounts) should not call register_account_schemas"
        );
    }

    #[test]
    fn test_schema_shank_bubblegum_borsh_only() {
        // Bubblegum has 2 accounts (TreeConfig, Voucher), both borsh → noop
        let idl = parse_test_idl("shank_bubblegum.json");
        assert!(!idl.accounts.is_empty(), "bubblegum should have accounts");
        let output = codegen::schemas::generate(&idl).to_string();

        assert!(
            !output.contains("register_account_schemas"),
            "bubblegum (all borsh) should not call register_account_schemas"
        );
        assert!(
            !output.contains("\"TreeConfig\""),
            "TreeConfig (borsh) should not have schema"
        );
        assert!(
            !output.contains("\"Voucher\""),
            "Voucher (borsh) should not have schema"
        );
    }

    #[test]
    fn test_schema_shank_candy_guard_borsh_only() {
        // CandyGuard has 2 accounts (FreezeEscrow, CandyGuard), both borsh → noop
        let idl = parse_test_idl("shank_candy_guard.json");
        assert!(!idl.accounts.is_empty(), "candy_guard should have accounts");
        let output = codegen::schemas::generate(&idl).to_string();

        assert!(
            !output.contains("register_account_schemas"),
            "candy_guard (all borsh) should not call register_account_schemas"
        );
    }

    // -----------------------------------------------------------------------
    // Schema syntax validation on real IDLs (end-to-end through full pipeline)
    // The existing test_syntax_valid_* tests above already validate that the
    // full pipeline including schemas produces valid Rust syntax for all IDLs.
    // These additional tests verify schema-specific generation in isolation.
    // -----------------------------------------------------------------------

    #[test]
    fn test_schema_syntax_marginfi_standalone() {
        // Parse just the schema output for marginfi and validate syntax
        let idl = parse_test_idl("anchor_marginfi.json");
        let tokens = codegen::schemas::generate(&idl);

        // Build stubs for all 5 account types referenced by state::XXX
        let stubs = quote::quote! {
            pub struct Bank;
            impl Bank { pub const DISCRIMINATOR_LEN: usize = 8; }
            pub struct FeeState;
            impl FeeState { pub const DISCRIMINATOR_LEN: usize = 8; }
            pub struct MarginfiAccount;
            impl MarginfiAccount { pub const DISCRIMINATOR_LEN: usize = 8; }
            pub struct MarginfiGroup;
            impl MarginfiGroup { pub const DISCRIMINATOR_LEN: usize = 8; }
            pub struct StakedSettings;
            impl StakedSettings { pub const DISCRIMINATOR_LEN: usize = 8; }
        };
        let wrapped = quote::quote! {
            mod test_wrapper {
                mod state { #stubs }
                #tokens
            }
        };
        syn::parse2::<syn::File>(wrapped).unwrap_or_else(|e| {
            panic!("Marginfi schema code is not valid Rust syntax: {}", e);
        });
    }

    #[test]
    fn test_schema_syntax_whirlpool_standalone() {
        let idl = parse_test_idl("anchor_whirlpool.json");
        let tokens = codegen::schemas::generate(&idl);

        let stubs = quote::quote! {
            pub struct Oracle;
            impl Oracle { pub const DISCRIMINATOR_LEN: usize = 8; }
            pub struct TickArray;
            impl TickArray { pub const DISCRIMINATOR_LEN: usize = 8; }
        };
        let wrapped = quote::quote! {
            mod test_wrapper {
                mod state { #stubs }
                #tokens
            }
        };
        syn::parse2::<syn::File>(wrapped).unwrap_or_else(|e| {
            panic!("Whirlpool schema code is not valid Rust syntax: {}", e);
        });
    }

    #[test]
    fn test_instruction_data_method_contains_discriminator_prepend() {
        // The generated InstructionData impl should produce a data() method that
        // prepends the discriminator bytes before the serialized args.
        // Verify the instruction module contains the pattern for both encodings.

        // Bincode (4-byte disc)
        let stake_output = run_full_pipeline("codama_stake.json");
        let stake_ix = extract_module(&stake_output, "instruction");
        // InstructionData trait impl should exist for each instruction
        let data_impl_count = stake_ix
            .matches("impl anchor_lang :: InstructionData for")
            .count();
        assert_eq!(
            data_impl_count, 18,
            "stake should have 18 InstructionData impls, got {}",
            data_impl_count
        );

        // Borsh (8-byte disc)
        let marginfi_output = run_full_pipeline("anchor_marginfi.json");
        let marginfi_ix = extract_module(&marginfi_output, "instruction");
        let data_impl_count = marginfi_ix
            .matches("impl anchor_lang :: InstructionData for")
            .count();
        assert_eq!(
            data_impl_count, 45,
            "marginfi should have 45 InstructionData impls, got {}",
            data_impl_count
        );
    }

    #[test]
    fn test_instruction_discriminator_byte_values_correct() {
        // Verify the actual byte values in generated discriminators match the IDL.
        let idl = parse_test_idl_with_truncation("anchor_marginfi.json");
        let output = run_full_pipeline("anchor_marginfi.json");
        let ix_mod = extract_module(&output, "instruction");

        // Check first instruction (marginfi_group_initialize) has correct disc bytes
        let ix0 = &idl.instructions[0];
        for byte in &ix0.discriminator {
            let byte_str = format!("{}u8", byte);
            assert!(
                ix_mod.contains(&byte_str),
                "instruction '{}' discriminator should contain byte {}, ix_mod snippet: {}",
                ix0.name,
                byte_str,
                &ix_mod[..ix_mod.len().min(1000)]
            );
        }

        // Check lending_account_deposit has its specific discriminator [171, 94, 235, 103, 82, 64, 212, 140]
        idl.instructions
            .iter()
            .find(|ix| ix.name == "lending_account_deposit")
            .expect("should have lending_account_deposit");
        assert!(
            ix_mod.contains("171u8"),
            "deposit disc should contain 171u8"
        );
        assert!(
            ix_mod.contains("140u8"),
            "deposit disc should contain 140u8"
        );
    }

    #[test]
    fn test_instruction_args_field_types_match_idl() {
        // Verify that instruction arg types in generated code match the IDL.
        let idl = parse_test_idl("anchor_marginfi.json");
        let output = run_full_pipeline("anchor_marginfi.json");
        let ix_mod = extract_module(&output, "instruction");

        // lending_account_deposit has: amount: u64, deposit_up_to_limit: Option<bool>
        let deposit = idl
            .instructions
            .iter()
            .find(|ix| ix.name == "lending_account_deposit")
            .expect("should have lending_account_deposit");
        assert_eq!(deposit.args[0].name, "amount");
        assert_eq!(deposit.args[1].name, "deposit_up_to_limit");
        assert!(
            ix_mod.contains("pub amount : u64"),
            "deposit should have amount: u64 field"
        );
        assert!(
            ix_mod.contains("pub deposit_up_to_limit : Option < bool >"),
            "deposit should have deposit_up_to_limit: Option<bool> field"
        );
    }
}
