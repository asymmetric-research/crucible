pub fn generate_cargo_toml(program_name: &str) -> String {
    // Pin the harness to the same crucible version as the CLI that generated it,
    // so pushes to main can't break generated or existing harnesses.
    let version = env!("CARGO_PKG_VERSION");

    format!(
        r#"[package]
name = "{program_name}_fuzz"
version = "0.1.0"
edition = "2021"
rust-version = "1.89"

[workspace]
# Standalone workspace - isolated from parent project to avoid Solana version conflicts

[dependencies]
# Fuzzing framework
crucible-fuzzer = "{version}"
crucible-test-context = "{version}"
crucible-idl-gen = "{version}"

anchor-lang = "1.0.1"

# Compatible client facade crates. LiteSVM 0.15.2 uses a mixed modular Solana
# graph internally, so these should not be blanket-upgraded to 4.x.
# `serde` feature: generated native-program (bincode) arg structs derive
# serde::Serialize, so Pubkey fields must implement it too.
solana-pubkey = {{ version = "3.0", features = ["serde"] }}
solana-keypair = "3.1.2"
solana-signer = "3.0.1"

# Fuzzing
libafl = {{ version = "0.15.1", features = ["std", "cli", "prelude"] }}
libafl_bolts = {{ version = "0.15.1", features = ["std"] }}
arbitrary = {{ version = "1", features = ["derive"] }}

# Utilities
anyhow = "1.0"
bytemuck = "1.14"
ctor = "0.6"
ctrlc = "3.4"

# Native-program (bincode) instruction encoding — generated code for 4-byte
# discriminator IDLs serializes args with serde + bincode (fixint, LE).
serde = {{ version = "1.0", features = ["derive"] }}
bincode = "1.3"

[[bin]]
name = "invariant_test"
path = "src/main.rs"

[features]
invariant_test = []
"#
    )
}

pub fn generate_harness(program_name: &str) -> String {
    let fixture_name = to_pascal_case(program_name);
    format!(
        r#"use crucible_fuzzer::*;
use anchor_lang::prelude::*;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_pubkey::Pubkey;
use anchor_lang::system_program;
use std::rc::Rc;

// Generate types from IDL (no crate dependency - avoids version conflicts)
crucible_idl_gen::declare_fuzz_program!("idls/{program_name}.json");

use {program_name}::instruction;
use {program_name}::accounts;

#[derive(Clone)]
struct {fixture_name} {{
    ctx: TestContext,
    program_id: Pubkey,
    admin: Rc<Keypair>,
    // TODO: Add your state here (users, accounts, etc.)
}}

#[fuzz_fixture]
impl {fixture_name} {{
    /// Called ONCE to setup initial state (programs + accounts)
    pub fn setup() -> Self {{
        let mut ctx = TestContext::new();
        let program_id = {program_name}::ID;

        // Load program binary (built separately from fuzz harness)
        ctx.add_program(&program_id, "../../target/deploy/{program_name}.so").unwrap();

        // Create admin account
        let admin = Rc::new(Keypair::new());
        ctx.create_account()
            .pubkey(admin.pubkey())
            .lamports(100_000_000_000)
            .owner(system_program::ID)
            .create()
            .unwrap();

        // TODO: Initialize your program state here

        Self {{ ctx, program_id, admin }}
    }}

    /// ACTIONS - Define actions that the fuzzer can call
    pub fn action_noop(&mut self) {{
        // Placeholder - replace with real actions
    }}

    // TODO: Add your actions here
}}

#[invariant_test]
fn invariant_test(fixture: &mut {fixture_name}) {{
    // TODO: Add invariant checks that should hold after every action
}}
"#,
    )
}

pub fn generate_idl_readme(program_name: &str) -> String {
    format!(
        r#"# IDL Files

Place your program's IDL JSON file here as `{program_name}.json`.

## Generating IDL

If you have the legacy (v0.29) IDL format:
```bash
anchor idl convert target/idl/{program_name}.json -o fuzz/{program_name}/idls/{program_name}.json
```

If you have the new IDL format (v0.30+), copy it directly.
"#
    )
}

pub fn to_pascal_case(s: &str) -> String {
    s.split(|c: char| c == '_' || c == '-')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect()
}
