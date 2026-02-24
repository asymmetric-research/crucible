# Using crucible-idl-gen (Standalone Harnesses)

For programs using different Solana versions than the fuzzer, `crucible-idl-gen` generates types from IDL without a crate dependency.

## Setup

1. **Convert your IDL to JSON format:**
   ```bash
   anchor idl convert target/idl/my_program.json -o fuzz/my_fuzz/idls/my_program.json
   ```

2. **Add crucible-idl-gen to your fuzz Cargo.toml:**
   ```toml
   [dependencies]
   crucible-idl-gen = { git = "https://github.com/asymmetric-research/crucible", branch = "main" }
   ```

3. **Generate types in main.rs:**
   ```rust
   crucible_idl_gen::declare_fuzz_program!("idls/my_program.json");

   // Or with explicit module name
   crucible_idl_gen::declare_fuzz_program!(my_program = "idls/my_program.json");

   // Now use generated types
   use my_program::{instruction, accounts, ID};
   ```

## Generated Code

The macro generates:
- `instruction::*` - Instruction structs with `InstructionData` impl
- `accounts::*` - Account context structs with `ToAccountMetas` impl
- `state::*` - Account state types for deserialization
- `types::*` - Custom type definitions
- `ID` - Program ID constant
- `register_schemas()` - Register account schemas for semantic field-level diffs in crash output

## Example Usage

```rust
crucible_idl_gen::declare_fuzz_program!("idls/lending.json");

#[fuzz_fixture]
impl MyFixture {
    pub fn setup() -> Self {
        lending::register_schemas();  // Enable semantic field diffs in crash output

        let mut ctx = TestContext::new();
        // ... setup accounts, load program ...
        Self { ctx }
    }

    pub fn action_deposit(&mut self, amount: u64) {
        self.ctx.program(lending::ID)
            .call(lending::instruction::Deposit { amount })
            .accounts(lending::accounts::Deposit {
                user: user_pubkey,
                reserve: reserve_pda,
                // ...
            })
            .signers(&[&user])
            .send().ok();
    }
}
```
