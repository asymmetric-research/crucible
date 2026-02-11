<p align="center">
  <img src="docs/crucible.png" alt="Crucible" width="400">
</p>

<p align="center">
  <strong>Coverage-guided fuzzing framework for Solana smart contracts</strong>
</p>

<p align="center">
  Built on <a href="https://github.com/AFLplusplus/LibAFL">LibAFL</a> and <a href="https://github.com/LiteSVM/litesvm">LiteSVM</a> for fast, local transaction simulation with edge-level coverage tracking.
</p>

---

Crucible enables property-based testing and stateful invariant checking for Solana programs through randomly generated action sequences. Define your program's actions, write invariants, and let the fuzzer find violations automatically.

## Quick Start

### Install

```bash
cargo install crucible-fuzz-cli
```

### Initialize a fuzz harness

```bash
crucible init <program_name>
```

### Run a fuzz test

```bash
crucible run <program_name> <test_name> --release --timeout 60
```

---

## Setup & Running

### Initialize a fuzz project

```bash
crucible init <project_name>
```

### Run a fuzz test

```bash
crucible run <project_name> <test_name>

crucible run <project_name> <test_name> --release  # Optimized

crucible run <project_name> <test_name> --timeout 60  # Stop after 60 seconds

crucible run <project_name> <test_name> --release --coverage --timeout 120
```

### Feature flags

Every fuzz test must be added as a feature in `Cargo.toml`:

```toml
[features]
fuzz_single = []
invariant_fuzz = []
```

The test name must match the feature name exactly.

---

## Project Structure

After `crucible init myproject`:

```
myproject/
├── Cargo.toml
├── programs/
│   └── myproject/          # Your Solana program
├── fuzz/
│   └── myproject-fuzz/
│       ├── Cargo.toml      # Fuzzer dependencies + features
│       ├── src/
│       │   └── main.rs     # Fixtures, actions, and tests
│       └── crashes/        # Crash artifacts saved here
│           └── <test_name>/
│               ├── abc123          # Raw crash input
│               └── abc123.meta.json  # Crash metadata
```

---

## Using crucible-idl-gen (Standalone Harnesses)

For programs using different Solana versions than the fuzzer, `crucible-idl-gen` generates types from IDL without a crate dependency.

### Setup

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

### Generated Code

The macro generates:
- `instruction::*` - Instruction structs with `InstructionData` impl
- `accounts::*` - Account context structs with `ToAccountMetas` impl
- `state::*` - Account state types for deserialization
- `types::*` - Custom type definitions
- `ID` - Program ID constant

### Example Usage

```rust
crucible_idl_gen::declare_fuzz_program!("idls/lending.json");

fn setup() -> Self {
    ctx.program(lending::ID)
        .call(lending::instruction::Deposit { amount })
        .accounts(lending::accounts::Deposit {
            user: user_pubkey,
            reserve: reserve_pda,
            // ...
        })
        .signers(&[&user])
        .send()?;
}
```

---

## TestContext API

### Program Loading

```rust
ctx.add_program(&program_id, "path/to/program.so")?;
```

### Account Creation

```rust
// Generic account
ctx.create_account()
    .pubkey(address)
    .lamports(1_000_000_000)
    .owner(system_program::id())
    .size(128)  // optional
    .create()?;

// Mint account
ctx.create_mint()
    .pubkey(mint_address)
    .mint_authority(authority)
    .decimals(9)
    .create()?;

// Token account
ctx.create_token_account()
    .pubkey(token_address)
    .mint(mint_address)
    .token_owner(owner)
    .amount(1000)
    .create()?;
```

### Program Calls

```rust
ctx.program(program_id)
    .call(instruction::DoSomething { amount })
    .accounts(accounts::DoSomething {
        user: user.pubkey(),
        pool: pool_pda,
        system_program: system_program::id(),
    })
    .signers(&[&*user])
    .send()?;
```

### Transaction Results (`TxOutcome`)

The `.send()` method returns `Result<TxOutcome>`, a parsed transaction result:

```rust
use crucible_test_context::TxOutcome;

let result = ctx.program(program_id)
    .call(instruction::DoSomething { amount })
    .accounts(accounts::DoSomething { /* ... */ })
    .signers(&[&*user])
    .send()?;

match result {
    TxOutcome::Success { compute_units, logs } => {
        println!("Used {} CU", compute_units);
    }
    TxOutcome::ProgramError { error, error_code, logs, .. } => {
        if let Some(code) = error_code {
            println!("Failed with error code: {}", code);
        }
    }
}
```

**Helper methods:**
- `is_success()` / `is_error()` - Check outcome type
- `error_code()` - Extract `Custom(N)` error codes
- `logs()` - Get program logs
- `unwrap()` / `expect(msg)` - Panic on error with detailed message
- `into_result()` - Convert to `Result<(), TxError>` for `?` operator

---

### Raw Instruction Calls

For non-Anchor programs or custom instructions:

```rust
use solana_instruction::{AccountMeta, Instruction};

let instruction = Instruction {
    program_id: my_program_id,
    accounts: vec![
        AccountMeta::new(user.pubkey(), true),
        AccountMeta::new(pool_pda, false),
        AccountMeta::new_readonly(config, false),
    ],
    data: my_instruction_data.try_to_vec()?,
};

ctx.raw_call(instruction)
    .signers(&[&*user])
    .send()?;
```

### Transaction Batching

Combine multiple instructions into a single atomic transaction:

```rust
ctx.program(program_id)
    .call(instruction::Initialize {})
    .accounts(accounts::Initialize { /* ... */ })
    .signers(&[&*payer])
    .add_transaction()?;

ctx.program(program_id)
    .call(instruction::Deposit { amount: 1000 })
    .accounts(accounts::Deposit { /* ... */ })
    .signers(&[&*user])
    .add_transaction()?;

// Send all queued instructions as ONE atomic transaction
ctx.send_batch()?;
```

### Account Reading/Writing

```rust
let account: MyAccount = ctx.read_anchor_account(&address)?;
let account: Account = ctx.get_account(&address)?;
ctx.write_anchor_account(&address, &my_data)?;
```

### Time Control

```rust
let current = ctx.slot();
ctx.warp_to_slot(current + 1000);
ctx.advance_slots(100);
```

### Mock Pyth Oracles

```rust
let oracle = ctx.create_mock_pyth_oracle()
    .price(100_00000000)  // $100 with 8 decimals
    .exponent(-8)
    .confidence(100_000)
    .build()?;

ctx.update_pyth_price(&oracle, 95_00000000, -8)?;
ctx.refresh_pyth_oracle(&oracle)?;
```

---

## Fixture Requirements

```rust
#[derive(Clone)]  // Required - fixture is cloned each iteration
struct MyFixture {
    ctx: TestContext,
    program_id: Pubkey,
    user: Rc<Keypair>,  // Keypairs wrapped in Rc<>
    pool_pda: Pubkey,
}

#[fuzz_fixture]
impl MyFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        // ... initialization ...
        Self { ctx, /* fields */ }
    }
}
```

---

## Action Naming Convention

Actions must be prefixed with `action_` for auto-discovery:

```rust
#[fuzz_fixture]
impl MyFixture {
    pub fn setup() -> Self { /* ... */ }

    pub fn action_stake(&mut self, amount: u64) { }
    pub fn action_withdraw(&mut self, #[range(0..3)] user_idx: usize) { }

    pub fn helper_method(&self) { }  // Not discovered
}
```

### Action Return Types

```rust
// Implicit success
pub fn action_advance_time(&mut self, slots: u64) {
    self.ctx.advance_slots(slots);
}

// Explicit success/failure tracking
pub fn action_deposit(&mut self, amount: u64) -> Result<()> {
    self.ctx.program(self.program_id)
        .call(instruction::Deposit { amount })
        .accounts(accounts::Deposit { /* ... */ })
        .signers(&[&*self.user])
        .send()?
        .into_result()
}
```

### After-Action Callback

```rust
#[fuzz_fixture]
impl MyFixture {
    pub fn setup() -> Self { /* ... */ }
    pub fn action_deposit(&mut self, amount: u64) { /* ... */ }

    // Optional: called after EVERY action dispatch
    pub fn after_action(&self) {
        let pool = self.ctx.read_anchor_account::<Pool>(&self.pool_pda).ok();
        if let Some(pool) = pool {
            eprintln!("[STATS] total_deposited: {}", pool.total_deposited);
        }
    }
}
```

---

## Range Constraints

Bound fuzz inputs using `#[range(start..end)]`:

```rust
pub fn action_stake(
    &mut self,
    #[range(0..3)] user_idx: usize,  // 0, 1, or 2
    #[range(0..1_000_000)] amount: u64,
) { }
```

---

## Simple Fuzzing (`#[anchor_fuzz]`)

For testing individual operations with random inputs:

```rust
#[anchor_fuzz]
fn fuzz_stake(fixture: &mut StakingFixture, #[range(0..100_000)] amount: u64) {
    fixture.action_stake(0, amount);
    let user = fixture.ctx.read_anchor_account::<User>(&fixture.user_pda).unwrap();
    fuzz_assert_le!(user.staked, INITIAL_BALANCE);
}
```

---

## Invariant Fuzzing (`#[invariant_test]` + `#[fuzz_fixture]`)

For testing complex interactions with random action sequences:

```rust
#[fuzz_fixture]
impl StakingFixture {
    pub fn setup() -> Self { /* ... */ }
    pub fn action_stake(&mut self, #[range(0..3)] user: usize, amount: u64) { }
    pub fn action_unstake(&mut self, #[range(0..3)] user: usize, amount: u64) { }
    pub fn action_claim(&mut self, #[range(0..3)] user: usize) { }
    pub fn action_advance_time(&mut self, #[range(0..10000)] slots: u64) {
        self.ctx.warp_to_slot(self.ctx.slot() + slots);
    }
}

#[invariant_test]
fn invariant_fuzz(fixture: &mut StakingFixture) {
    // Runs AFTER EACH action in the sequence
    let pool = fixture.ctx.read_anchor_account::<Pool>(&fixture.pool_pda).unwrap();
    fuzz_assert_le!(pool.total_staked, fixture.total_deposited);
}
```

---

## Assertion Macros

Use `fuzz_assert_*` macros instead of `assert!` in invariant checks:

| Macro | Description |
|-------|-------------|
| `fuzz_assert!(cond)` | Assert condition is true |
| `fuzz_assert_eq!(a, b)` | Assert `a == b` |
| `fuzz_assert_ne!(a, b)` | Assert `a != b` |
| `fuzz_assert_lt!(a, b)` | Assert `a < b` |
| `fuzz_assert_le!(a, b)` | Assert `a <= b` |
| `fuzz_assert_gt!(a, b)` | Assert `a > b` |
| `fuzz_assert_ge!(a, b)` | Assert `a >= b` |
| `fuzz_assert_approx_eq!(a, b, delta)` | Assert `\|a - b\| <= delta` |

Standard `assert!` panics crash the entire fuzzer process. The `fuzz_assert_*` macros record violations and report them as crashes to LibAFL without killing the process.

---

## Crash Analysis & Replay

### List all crashes

```bash
crucible show <project>
```

### View crash metadata

```bash
crucible show <project> <crash_file>
```

### Replay crash

```bash
crucible show <project> <crash_file> --replay
```

---

## CLI Reference

### `crucible init`

```bash
crucible init <program_name>
```

Creates a standalone fuzz workspace in `fuzz/<program_name>/`.

### `crucible run`

```bash
crucible run <program_name> <test_name> [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--release` | Build in release mode (recommended) |
| `--coverage` | Enable LCOV coverage output |
| `--timeout <SECS>` | Stop after N seconds |
| `--cores N` / `-j N` | Run N parallel fuzzer workers |
| `--corpus-in <DIR>` | Load seed corpus from directory |
| `--corpus-out <DIR>` | Write corpus to directory |
| `--crashes-dir <DIR>` | Custom crash output directory |
| `--input <FILE>` | Replay a single input file |
| `--dry-run` | Validate setup without fuzzing |
| `--seed <N>` | Random seed for reproducible fuzzing |

**Examples:**

```bash
# Basic fuzzing
crucible run myproject invariant_test --release --timeout 60

# Multi-core fuzzing (4 workers)
crucible run myproject invariant_test --release -j 4

# Coverage report
crucible run myproject invariant_test --release --coverage --timeout 120

# Dry-run validation
crucible run myproject invariant_test --dry-run

# Replay a crash
crucible run myproject invariant_test --input ./crashes/invariant_test/abc123

# Reproducible fuzzing
crucible run myproject invariant_test --release --seed 12345
```

**Environment variables:**

| Variable | Description |
|----------|-------------|
| `FUZZ_VERBOSE=1` | Enable verbose harness output |

### `crucible list`

```bash
crucible list <program_name>   # List tests for a program
crucible list                  # List all fuzz harnesses
```

### `crucible show`

```bash
crucible show <program>                       # List all crashes
crucible show <program> <crash_file>          # View metadata
crucible show <program> <crash_file> --replay # Replay crash
```

### `crucible cmin`

Minimize corpus to smallest set preserving all coverage.

```bash
crucible cmin <program> <test> <corpus_dir> --release
crucible cmin <program> <test> <corpus_dir> --corpus-out ./corpus_min --release
```

---

## Execution Modes

1. **Normal Fuzzing** (default) - Continuous input generation and mutation
2. **Dry-Run** (`--dry-run`) - Single iteration to validate harness setup
3. **Input Replay** (`--input`) - Execute one specific input file
4. **Coverage-Only** (`--coverage --corpus-in`) - Run corpus once for coverage report
5. **Seeded Fuzzing** (`--corpus-in`) - Start from pre-existing corpus
6. **Multi-Core** (`--cores N`) - Parallel fuzzer workers with shared coverage

---

## Full Documentation

See [docs/harness_guide.md](docs/harness_guide.md) for an in-depth guide to writing effective fuzz harnesses, including:

- Iterative debugging workflow
- Bypassing common blockers
- Writing effective invariants
- Account patching with bytemuck
- Diagnostic logging patterns
- Common lending protocol errors
