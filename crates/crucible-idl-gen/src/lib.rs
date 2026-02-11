extern crate proc_macro;

mod codegen;

use std::{env, fs, path::PathBuf};

use anchor_lang_idl::convert::convert_idl;
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
            Ok(Self { name: Some(name), path })
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

    // Read and parse IDL
    let idl_bytes = fs::read(&idl_path)
        .map_err(|e| anyhow::anyhow!("Failed to read IDL at {}: {e}", idl_path.display()))?;

    let mut idl = convert_idl(&idl_bytes)?;

    // Detect and fix bincode-style discriminators.
    // Native Solana programs use 4-byte u32 LE instruction indices. IDLs may
    // represent these as 8-byte arrays with trailing zeros (e.g. [1,0,0,0,0,0,0,0]).
    // If every instruction discriminator is 8 bytes with the last 4 all zero,
    // truncate to 4 bytes so downstream codegen detects bincode format.
    truncate_bincode_discriminators(&mut idl);

    // Determine module name
    let module_name = input.name.clone()
        .unwrap_or_else(|| format_ident!("{}", idl.metadata.name));

    // Detect serialization format from discriminator length:
    // 8 bytes → Anchor (borsh), 4 bytes → native/bincode
    let use_bincode = idl.instructions.first()
        .map(|ix| ix.discriminator.len() == 4)
        .unwrap_or(false);

    // Generate code
    let program_id = codegen::gen_program_id(&idl);
    let instructions = codegen::instructions::generate(&idl);
    let accounts = codegen::accounts::generate(&idl);
    let state = codegen::state::generate(&idl);
    let types = codegen::types::generate(&idl, use_bincode);
    let discriminators = codegen::discriminators::generate(&idl);

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
        }
    })
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

    let all_padded = idl.instructions.iter().all(|ix| {
        ix.discriminator.len() == 8 && ix.discriminator[4..] == [0, 0, 0, 0]
    });

    if all_padded {
        for ix in &mut idl.instructions {
            ix.discriminator.truncate(4);
        }
    }
}
