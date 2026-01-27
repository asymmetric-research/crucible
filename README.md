# Anchor Fuzz Documentation

## Setup & Running

### Initialize a fuzz project

```bash
anchor fuzz init <project_name>
```

### Run a fuzz test

```bash
anchor fuzz run <project_name> <test_name>

anchor fuzz run <project_name> <test_name> --release  # Optimized

anchor fuzz run <project_name> <test_name> --timeout 60  # Stop after 60 seconds

anchor fuzz run <project_name> <test_name> --release --coverage --timeout 120
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

After `anchor fuzz init myproject`:

```
myproject/
├── Anchor.toml
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

## Using anchor-fuzz-gen (Standalone Harnesses)

For programs using different Solana versions than the fuzzer, `anchor-fuzz-gen` generates types from IDL without a crate dependency.

### Setup

1. **Convert your IDL to JSON format:**
   ```bash
   anchor idl convert target/idl/my_program.json -o fuzz/my_fuzz/idls/my_program.json
   ```

2. **Add anchor-fuzz-gen to your fuzz Cargo.toml:**
   ```toml
   [dependencies]
   anchor-fuzz-gen = { path = "path/to/anchor-fuzz-gen" }
   ```

3. **Generate types in main.rs:**
   ```rust
   // Generate module from IDL
   anchor_fuzz_gen::declare_fuzz_program!("idls/my_program.json");

   // Or with explicit module name
   anchor_fuzz_gen::declare_fuzz_program!(my_program = "idls/my_program.json");

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
anchor_fuzz_gen::declare_fuzz_program!("idls/lending.json");

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
// Anchor program call (recommended)
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
use anchor_test_context::TxOutcome;

let result = ctx.program(program_id)
    .call(instruction::DoSomething { amount })
    .accounts(accounts::DoSomething { /* ... */ })
    .signers(&[&*user])
    .send()?;

match result {
    TxOutcome::Success { compute_units, logs } => {
        // Transaction succeeded
        println!("Used {} CU", compute_units);
    }
    TxOutcome::ProgramError { error, error_code, logs, .. } => {
        // Transaction failed (e.g., program error, constraint violation)
        if let Some(code) = error_code {
            println!("Failed with error code: {}", code);
        }
        for log in &logs {
            eprintln!("  {}", log);
        }
    }
}
```

**TxOutcome variants:**
- `Success { compute_units, logs }` - Transaction executed successfully
- `ProgramError { error, error_code, instruction_index, logs }` - Transaction failed

**Helper methods:**
- `is_success()` - Returns true if transaction succeeded
- `is_error()` - Returns true if transaction failed
- `error_code()` - Extracts `Custom(N)` error codes (e.g., Anchor error codes)
- `logs()` - Returns program logs
- `unwrap()` - Panics with detailed error message if failed
- `expect(msg)` - Panics with custom message if failed
- `into_result()` - Converts to `Result<(), TxError>` for `?` operator

**Common patterns:**

```rust
// Expect success or panic with logs
result.unwrap();

// Check for specific error code
if result.error_code() == Some(6051) {
    // Handle specific Anchor error
}

// Ignore expected failures
let success = matches!(&result, Ok(TxOutcome::Success { .. }));
if !success {
    // Transaction failed - may be expected in fuzzing
}
```

---

### Raw Instruction Calls

For non-Anchor programs or custom instructions:

```rust
use solana_sdk::instruction::{AccountMeta, Instruction};

// Build instruction manually
let instruction = Instruction {
    program_id: my_program_id,
    accounts: vec![
        AccountMeta::new(user.pubkey(), true),      // writable, signer
        AccountMeta::new(pool_pda, false),          // writable, not signer
        AccountMeta::new_readonly(config, false),   // readonly, not signer
    ],
    data: my_instruction_data.try_to_vec()?,
};

// Send via raw_call
ctx.raw_call(instruction)
    .signers(&[&*user])
    .send()?;
```

### Transaction Batching

Combine multiple instructions into a single transaction using `add_transaction()` and `send_batch()`:

```rust
// Queue multiple instructions (not sent yet)
ctx.program(program_id)
    .call(instruction::Initialize {})
    .accounts(accounts::Initialize { /* ... */ })
    .signers(&[&*payer])
    .add_transaction()?;  // Queued, not sent

ctx.program(program_id)
    .call(instruction::Deposit { amount: 1000 })
    .accounts(accounts::Deposit { /* ... */ })
    .signers(&[&*user])
    .add_transaction()?;  // Queued, not sent

ctx.program(program_id)
    .call(instruction::Stake { amount: 500 })
    .accounts(accounts::Stake { /* ... */ })
    .signers(&[&*user])
    .add_transaction()?;  // Queued, not sent

// Send all queued instructions as ONE atomic transaction
ctx.send_batch()?;
```

**Key behaviors:**
- Signers are deduplicated automatically (first signer = fee payer)
- All instructions succeed or fail together (atomic)
- Queue is cleared after `send_batch()` regardless of success/failure
- Empty queue is a no-op

**Use cases:**
- Initialize + deposit in one transaction
- Flash loan patterns (borrow → use → repay)
- Complex multi-step operations that must be atomic

### Account Reading/Writing

```rust
// Read Anchor account (deserializes with discriminator)
let account: MyAccount = ctx.read_anchor_account(&address)?;

// Read raw account
let account: Account = ctx.get_account(&address)?;

// Write Anchor account
ctx.write_anchor_account(&address, &my_data)?;
```

### Time Control

```rust
let current = ctx.slot();
ctx.warp_to_slot(current + 1000);
ctx.advance_slots(100);
```

### Mock Pyth Oracles

Create mock Pyth price feed accounts for testing DeFi protocols:

```rust
// Create a mock Pyth oracle with $100 price
let oracle = ctx.create_mock_pyth_oracle()
    .price(100_00000000)  // $100 with 8 decimals
    .exponent(-8)
    .confidence(100_000)
    .build()?;

// Update the price
ctx.update_pyth_price(&oracle, 95_00000000, -8)?;  // $95

// Refresh oracle timestamp to avoid staleness checks
ctx.refresh_pyth_oracle(&oracle)?;
```

**Builder methods:**
- `.price(i64)` - Price value in smallest units (e.g., $100 with exp=-8 → 100_00000000)
- `.exponent(i32)` - Price exponent (typically -8 for USD)
- `.confidence(u64)` - Confidence interval
- `.publish_time(i64)` - Override publish time (defaults to current time)
- `.feed_id([u8; 32])` - Custom feed ID (defaults to oracle pubkey)
- `.program_id(Pubkey)` - Override Pyth program ID

---

## Fixture Requirements

Fixtures must satisfy these requirements for snapshotting to work:

```rust
#[derive(Clone)]  // Required - fixture is cloned each iteration
struct MyFixture {
    ctx: TestContext,              // Owns the context
    program_id: Pubkey,
    user: Rc<Keypair>,             // Keypairs wrapped in Rc<>
    pool_pda: Pubkey,
    // All fields must implement Clone
}
```

### Setup signature

```rust
#[fuzz_fixture]
impl MyFixture {
    // Must take no arguments, returns Self
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        // ... initialization ...
        Self { ctx, /* fields */ }
    }
}
```

**Why cloning matters:** The fuzzer calls `setup()` once to create a template fixture. Each fuzzing iteration clones this template, avoiding expensive re-initialization.

---

## Action Naming Convention

Actions must be prefixed with `action_` for auto-discovery:

```rust
#[fuzz_fixture]
impl MyFixture {
    pub fn setup() -> Self { /* ... */ }

    // ✅ Discovered - generates Action::Stake variant
    pub fn action_stake(&mut self, amount: u64) { }

    // ✅ Discovered - generates Action::Withdraw variant
    pub fn action_withdraw(&mut self, #[range(0..3)] user_idx: usize) { }

    // ❌ Not discovered - no action_ prefix
    pub fn helper_method(&self) { }
}
```

### Action Return Types

Actions can return `()` (implicit success) or `Result<T, E>` (explicit success/failure tracking):

```rust
#[fuzz_fixture]
impl MyFixture {
    // Implicit success - always recorded as successful
    pub fn action_advance_time(&mut self, slots: u64) {
        self.ctx.advance_slots(slots);
    }

    // Explicit success/failure - Result determines success status
    pub fn action_deposit(&mut self, amount: u64) -> Result<()> {
        self.ctx.program(self.program_id)
            .call(instruction::Deposit { amount })
            .accounts(accounts::Deposit { /* ... */ })
            .signers(&[&*self.user])
            .send()?
            .into_result()
    }
}
```

The success/failure status is recorded in `.meta.json` crash metadata.

### After-Action Callback

Define an optional `after_action` method for custom logging or accounting after every action:

```rust
#[fuzz_fixture]
impl MyFixture {
    pub fn setup() -> Self { /* ... */ }

    pub fn action_deposit(&mut self, amount: u64) { /* ... */ }
    pub fn action_withdraw(&mut self, amount: u64) { /* ... */ }

    // Optional: called after EVERY action dispatch
    pub fn after_action(&self) {
        // Query state, log metrics, update shadow accounting, etc.
        let pool = self.ctx.read_anchor_account::<Pool>(&self.pool_pda).ok();
        if let Some(pool) = pool {
            eprintln!("[STATS] total_deposited: {}", pool.total_deposited);
        }
    }
}
```

**Use cases:**
- Logging state changes after each action
- Updating shadow state for invariant checking
- Collecting metrics for debugging coverage issues

### Action Stats Tracking Pattern

For better visibility into fuzzer progress, use atomic counters to track action success/failure rates:

```rust
mod action_stats {
    use std::sync::atomic::{AtomicU32, Ordering};

    macro_rules! define_counters {
        ($($name:ident),*) => {
            $(pub static $name: (AtomicU32, AtomicU32) = (AtomicU32::new(0), AtomicU32::new(0));)*
        }
    }

    // Define counters for each action type
    define_counters!(DEPOSIT, BORROW, REPAY, WITHDRAW, LIQUIDATE);

    pub fn record(counter: &(AtomicU32, AtomicU32), success: bool) {
        if success {
            counter.0.fetch_add(1, Ordering::Relaxed);
        } else {
            counter.1.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn print_summary() {
        eprintln!("\n=== Action Stats ===");
        eprintln!("deposit:    {} ok / {} fail", DEPOSIT.0.load(Ordering::Relaxed), DEPOSIT.1.load(Ordering::Relaxed));
        eprintln!("borrow:     {} ok / {} fail", BORROW.0.load(Ordering::Relaxed), BORROW.1.load(Ordering::Relaxed));
        // ... etc
    }
}
```

Use in actions:
```rust
pub fn action_deposit(&mut self, amount: u64) {
    let result = self.ctx.program(self.program_id)
        .call(instruction::Deposit { amount })
        .accounts(/* ... */)
        .signers(&[&*self.user])
        .send();

    let success = result.map(|o| o.is_success()).unwrap_or(false);
    action_stats::record(&action_stats::DEPOSIT, success);
}
```

Use in `after_action` for periodic reporting:
```rust
pub fn after_action(&self) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);

    // Print summary every 1000 actions to avoid spam
    if count > 0 && count % 1000 == 0 {
        action_stats::print_summary();

        // Optional: state snapshot
        eprintln!("\n=== State Snapshot (action {}) ===", count);
        // Read and print relevant protocol state...
    }
}
```

---

## Range Constraints

Bound fuzz inputs using `#[range(start..end)]`:

```rust
#[anchor_fuzz]
fn fuzz_test(
    fixture: &mut MyFixture,
    #[range(0..1_000_000)] amount: u64,      // 0 to 999,999
    #[range(0..3)] user_idx: usize,           // 0, 1, or 2
) {
    fixture.action_stake(user_idx, amount);
}
```

Works on action parameters too:

```rust
pub fn action_stake(
    &mut self,
    #[range(0..3)] user_idx: usize,
    amount: u64,
) { }
```

**Syntax:**
- `#[range(0..10)]` - exclusive end (0-9)
- `#[range(0..=10)]` - inclusive end (0-10)

---

## Simple Fuzzing (`#[anchor_fuzz]`)

For testing individual operations with random inputs.

```rust
#[anchor_fuzz]
fn fuzz_stake(fixture: &mut StakingFixture, #[range(0..100_000)] amount: u64) {
    // Fuzzer generates random `amount` values
    fixture.action_stake(0, amount);
    
    // Check invariants
    let user = fixture.ctx.read_anchor_account::<User>(&fixture.user_pda).unwrap();
    assert!(user.staked <= INITIAL_BALANCE);
}
```

**How it works:**
1. Fuzzer generates random bytes via LibAFL
2. Bytes are deserialized into typed parameters via `arbitrary`
3. Range constraints are applied
4. Your function is called with the generated inputs
5. Panics are captured as crashes

**You write:** The test logic inside the function.

**Fuzzer handles:** Input generation, iteration, coverage tracking, crash detection.

---

## Invariant Fuzzing (`#[invariant_test]` + `#[fuzz_fixture]`)

For testing complex interactions with random action sequences.

### Define actions in fixture

```rust
#[fuzz_fixture]
impl StakingFixture {
    pub fn setup() -> Self { /* ... */ }

    pub fn action_stake(&mut self, #[range(0..3)] user: usize, amount: u64) {
        // ... stake logic ...
    }

    pub fn action_unstake(&mut self, #[range(0..3)] user: usize, amount: u64) {
        // ... unstake logic ...
    }

    pub fn action_claim(&mut self, #[range(0..3)] user: usize) {
        // ... claim logic ...
    }

    pub fn action_advance_time(&mut self, #[range(0..10000)] slots: u64) {
        self.ctx.warp_to_slot(self.ctx.slot() + slots);
    }
}
```

### Define invariant test

```rust
#[invariant_test]
fn invariant_fuzz(fixture: &mut StakingFixture) {
    // This code runs AFTER EACH action in the sequence
    
    let pool = fixture.ctx.read_anchor_account::<Pool>(&fixture.pool_pda).unwrap();
    
    // Invariant: total staked should never exceed deposits
    assert!(pool.total_staked <= fixture.total_deposited);
    
    // Invariant: no user should have negative rewards
    for user in &fixture.users {
        let account = fixture.ctx.read_anchor_account::<UserAccount>(&user.pda).unwrap();
        assert!(account.rewards >= 0);
    }
}
```

**How it works:**
1. Fuzzer generates a `Vec<StakingFixtureActions>` (random action sequence)
2. Each action has randomized parameters (with constraints applied)
3. For each action:
   - Action is dispatched to the appropriate `action_*` method
   - Your invariant check runs
4. If invariant fails → crash captured

**Actions enum (auto-generated):**

```rust
// Generated by #[fuzz_fixture]
enum StakingFixtureActions {
    Stake { user: usize, amount: u64 },
    Unstake { user: usize, amount: u64 },
    Claim { user: usize },
    AdvanceTime { slots: u64 },
}
```

---

## Crash Analysis & Replay

When a crash is found, it's saved to `crashes/<test_name>/<hash>` along with a `.meta.json` file containing rich metadata.

### Crash Metadata (.meta.json)

Each crash file has a companion `.meta.json` with:
- Test name
- Timestamp
- Iteration count
- Random seed
- Full action sequence with parameters (after range constraints applied) and success/failure status

Example `crashes/invariant_test/abc123.meta.json`:
```json
{
  "test_name": "invariant_test",
  "timestamp": "2026-01-26T10:30:00Z",
  "iteration": 12345,
  "seed": 42,
  "actions": [
    {"name": "deposit", "params": {"user_idx": 2, "amount": 50000}, "success": true},
    {"name": "borrow", "params": {"user_idx": 1, "amount": 10000}, "success": true},
    {"name": "liquidate", "params": {"user_idx": 0}, "success": false}
  ]
}
```

### List all crashes

```bash
anchor fuzz show <project>
```

Lists all crashes with metadata summary (timestamp, test name, action count).

### View crash metadata (no compilation needed)

```bash
anchor fuzz show <project> <crash_file>
```

Reads the `.meta.json` file and displays the action sequence with parameters:

```
=== CRASH METADATA ===
Test: invariant_test
Time: 2026-01-26T10:30:00Z
Iteration: 12345
Seed: 42

=== ACTION SEQUENCE (3 actions) ===
  1. deposit(user_idx=2, amount=50000) -> OK
  2. borrow(user_idx=1, amount=10000) -> OK
  3. liquidate(user_idx=0) -> FAIL
==============================
```

### Replay crash (requires compilation)

```bash
anchor fuzz show <project> <crash_file> --replay
```

Actually replays the crash by building and running the binary with `SHOW_CRASH=1`.

---

## Generated Code

The `#[fuzz_fixture]` macro generates:

```rust
// Actions enum with all action_* methods as variants
#[derive(Arbitrary, Debug, Clone)]
pub enum MyFixtureActions {
    Stake { user: usize, amount: u64 },
    Unstake { user: usize, amount: u64 },
    // ...
}

impl MyFixtureActions {
    // Applies #[range] constraints to fields
    pub fn constrain_in_place(&mut self) { /* ... */ }

    // Returns action name as string (for crash metadata)
    pub fn action_name(&self) -> &'static str { /* ... */ }

    // Returns parameters as JSON (for .meta.json)
    pub fn to_json_params(&self) -> serde_json::Value { /* ... */ }
}

impl MyFixture {
    // Dispatches action to appropriate method, returns success status
    pub fn __dispatch_action(&mut self, action: MyFixtureActions) -> bool { /* ... */ }

    // Called after each action if after_action() method is defined
    fn __maybe_after_action(&self) { /* ... */ }
}
```

The `#[invariant_test]` macro generates:

```rust
#[anchor_fuzz]
fn invariant_fuzz(fixture: &mut MyFixture, actions: Vec<MyFixtureActions>) {
    // Clear action history at start
    anchor_test_context::clear_action_history();

    for action in actions {
        action.constrain_in_place();

        // Get action info for history (after constraints applied)
        let action_name = action.action_name().to_string();
        let action_params = action.to_json_params();

        // Execute action and track success
        let success = fixture.__dispatch_action(action);

        // Record in history for .meta.json
        anchor_test_context::push_action_record(&action_name, action_params, success);

        // Your invariant check code runs here
    }
}
```

---

## Common Patterns

### Safe amount clamping

```rust
pub fn action_unstake(&mut self, user_idx: usize, amount: u64) {
    let user = &self.users[user_idx];
    let account = self.ctx.read_anchor_account::<UserAccount>(&user.pda).unwrap();
    
    // Clamp to available balance
    let safe_amount = amount.min(account.staked_amount);
    if safe_amount == 0 { return; }
    
    // ... proceed with unstake ...
}
```

### Handling expected errors

```rust
use anchor_test_context::TxOutcome;

pub fn action_claim(&mut self, user_idx: usize) {
    let result = self.ctx.program(self.program_id)
        .call(instruction::Claim {})
        .accounts(/* ... */)
        .signers(&[&*self.users[user_idx].keypair])
        .send();

    // Option 1: Ignore all errors (simplest)
    let _ = result;

    // Option 2: Track success/failure
    if let Ok(TxOutcome::Success { .. }) = &result {
        self.stats.claims += 1;
    }

    // Option 3: Log program errors for debugging
    if let Ok(TxOutcome::ProgramError { error, logs, .. }) = &result {
        if std::env::var("FUZZ_DEBUG").is_ok() {
            eprintln!("Claim failed: {:?}", error);
            for log in logs { eprintln!("  {}", log); }
        }
    }
}
```

---

## Assertion Macros

Use `fuzz_assert_*` macros instead of `assert!` in invariant checks. These record violations without panicking, allowing the fuzzer to continue and properly track crashes.

### Available Macros

| Macro | Description | Example |
|-------|-------------|---------|
| `fuzz_assert!(cond)` | Assert condition is true | `fuzz_assert!(balance >= 0)` |
| `fuzz_assert_eq!(a, b)` | Assert `a == b` | `fuzz_assert_eq!(total, expected)` |
| `fuzz_assert_ne!(a, b)` | Assert `a != b` | `fuzz_assert_ne!(state, INVALID)` |
| `fuzz_assert_lt!(a, b)` | Assert `a < b` | `fuzz_assert_lt!(debt, collateral)` |
| `fuzz_assert_le!(a, b)` | Assert `a <= b` | `fuzz_assert_le!(used, capacity)` |
| `fuzz_assert_gt!(a, b)` | Assert `a > b` | `fuzz_assert_gt!(supply, 0)` |
| `fuzz_assert_ge!(a, b)` | Assert `a >= b` | `fuzz_assert_ge!(balance, 0)` |
| `fuzz_assert_approx_eq!(a, b, delta)` | Assert `|a - b| <= delta` | `fuzz_assert_approx_eq!(price, oracle_price, 100)` |

### Usage

```rust
use anchor_test_context::{fuzz_assert, fuzz_assert_le, fuzz_assert_eq};

#[invariant_test]
fn check_invariants(fixture: &mut MyFixture) {
    let pool = fixture.ctx.read_anchor_account::<Pool>(&fixture.pool_pda).unwrap();

    // Basic assertion
    fuzz_assert!(pool.total_staked >= 0);

    // Comparison with custom message
    fuzz_assert_le!(
        pool.total_borrowed,
        pool.total_deposited,
        "Bad debt: borrowed {} > deposited {}",
        pool.total_borrowed,
        pool.total_deposited
    );

    // Equality check
    fuzz_assert_eq!(
        pool.total_shares,
        fixture.expected_shares,
        "Share mismatch"
    );

    // Approximate equality (for floating point or fixed-point)
    fuzz_assert_approx_eq!(
        calculated_interest,
        expected_interest,
        1000,  // max delta
        "Interest calculation off by more than 1000"
    );
}
```

### Why Not `assert!`?

Standard `assert!` panics crash the entire fuzzer process. The `fuzz_assert_*` macros instead:

1. Record the violation message
2. Return control to the harness
3. Report the violation as a crash/objective to LibAFL
4. Continue fuzzing with the next input

This enables proper crash tracking and corpus management.

---

### Shadow state for invariants

```rust
#[derive(Clone)]
struct User {
    keypair: Rc<Keypair>,
    pda: Pubkey,
    // Shadow state for invariant checking
    expected_balance: u64,
    stake_time: u128,
}

pub fn action_stake(&mut self, user_idx: usize, amount: u64) {
    // Update shadow state
    self.users[user_idx].expected_balance -= amount;

    // Execute on-chain action
    // ...
}
```

---

## Coverage Reporting

The fuzzer supports detailed coverage tracking with the `--coverage` flag, generating both LCOV and HTML outputs.

### Enabling Coverage

Coverage is disabled by default for maximum performance. Enable it with the `--coverage` flag:

```bash
# Run with coverage tracking enabled
./target/release/my_fuzz -- --coverage

# Or via cargo
cargo run --release --features invariant_test -- --coverage
```

**Performance note:** With coverage enabled, expect ~500-800 exec/s. Without coverage, expect ~1500+ exec/s.

### Output Files

- **`coverage.lcov`** - LCOV format coverage data for CI integration
- **`coverage.html`** - Interactive HTML visualization with syntax highlighting

Files are written every 5000 iterations when new coverage is discovered.

### Visualization Options

#### 1. Terminal Summary (Recommended)

Get a quick coverage summary from the command line:

```bash
# Install lcov tools (macOS)
brew install lcov

# Summary stats (--ignore-errors format required for bytecode LCOV)
lcov --summary coverage.lcov --ignore-errors format

# Example output:
# Summary coverage rate:
#   source files: 1
#   lines.......: 100.0% (18852 of 18852 lines)  # Only hit lines are reported
#   functions...: 24.5% (323 of 1316 functions)  # This is the useful metric!
```

**Note:** For bytecode LCOV, the "functions" percentage is the most meaningful metric. The "lines" percentage shows 100% because we only write data for PCs that were actually executed (not all possible PCs).

#### 2. HTML Report (Future)

HTML report generation via `genhtml` requires source files to display. For bytecode-level coverage, source files don't exist. This will be supported when source-level LCOV (with DWARF debug info) is implemented.

For now, use the terminal summary and real-time stats during fuzzing.

#### 3. CI Integration

```yaml
# .github/workflows/fuzz.yml
- name: Run fuzzer
  run: timeout 60 cargo run --release --features invariant_test || true

- name: Coverage summary
  run: |
    lcov --summary coverage.lcov --ignore-errors format > coverage_summary.txt
    cat coverage_summary.txt

- name: Upload coverage artifacts
  uses: actions/upload-artifact@v3
  with:
    name: coverage-report
    path: |
      coverage.lcov
      coverage_summary.txt
```

#### 4. Coverage Report Script

A Python script is provided for detailed per-function analysis:

```bash
# Show named functions with branch coverage
python3 anchor-test/scripts/coverage_report.py coverage.lcov

# Show all functions (including auto-named fn_xxx)
python3 anchor-test/scripts/coverage_report.py coverage.lcov --all

# Show only never-hit functions
python3 anchor-test/scripts/coverage_report.py coverage.lcov --cold
```

Example output:
```
=== NAMED FUNCTION COVERAGE ===

Function                                             Hits     Branches Missing PCs
-----------------------------------------------------------------------------------------------
entrypoint                                          25542          3/6 36850,36861,36870
function_76431                                      12585         7/14 76432,76435,76440... +4
function_143708                                     10955            -
-----------------------------------------------------------------------------------------------

Summary: 12/204 functions hit (5.9%)
         2052/4088 branches taken (50.2%)

=== NEVER HIT (192) ===
  function_117380 (PC: 117380)
  function_117385 (PC: 117385)
  ...
```

The "Missing PCs" column shows which branch instruction addresses were never taken, helping identify unexplored code paths.

#### 5. CFG Visualization (Graphviz)

Generate a Control Flow Graph with coverage overlay:

```bash
# Build the cfg_viz tool (from anchor-test directory)
cargo build --release -p anchor-test-context --bin cfg_viz

# Generate DOT file for a specific function
./target/release/cfg_viz program.so coverage.lcov entrypoint > cfg.dot

# Convert to image (requires: brew install graphviz)
dot -Tpng cfg.dot -o cfg.png   # PNG
dot -Tsvg cfg.dot -o cfg.svg   # SVG (scalable, recommended)

# Interactive viewer (requires: brew install xdot)
xdot cfg.dot
```

The visualization shows:
- **Green blocks**: 100% of instructions hit
- **Yellow blocks**: Partially covered
- **Red blocks**: Never executed
- **Green edges**: Branch was taken
- **Red dashed edges**: Branch was never taken

Example output:
```
┌──────────────────────────────┐
│ Block 36846 (4/4 = 100%)     │ ← Green: fully covered
│ + 08fee: mov64               │
│ + 08fef: lddw                │
│ + 08ff1: ldxdw               │
│ + 08ff2: jeq                 │
└──────────────────────────────┘
         │              │
         ▼              ▼
    [taken]         [not taken]
```

### Understanding Bytecode LCOV

Since the coverage maps PC (Program Counter) offsets rather than source lines:

- **DA:36989,1234** - PC offset 36989 was executed 1234 times
- **FN:36989,lending_account_deposit** - Function `lending_account_deposit` starts at PC 36989
- **BRDA:148,0,0,500** - Branch at PC 148, taken 500 times

To map PCs to source code manually:

```bash
# Disassemble the BPF binary
llvm-objdump -d target/deploy/program.so > program.asm

# Find function at PC 36989
grep -n "36989:" program.asm
```

### Required Dependencies

Add `ctrlc` to your fuzz harness `Cargo.toml` for the exit handler:

```toml
[dependencies]
ctrlc = "3.4"
```

---

## CLI Reference

### `anchor fuzz init`

Initialize a fuzz project for a program.

```bash
anchor fuzz init <program_name>
```

Creates a standalone fuzz workspace in `fuzz/<program_name>/` with:
- `Cargo.toml` with `[workspace]` for isolation
- `rust-toolchain.toml` (stable Rust)
- `src/main.rs` template
- `idls/` directory for IDL files

### `anchor fuzz run`

Run a fuzz test.

```bash
anchor fuzz run <program_name> <test_name> [OPTIONS]
```

**Options:**
| Flag | Description |
|------|-------------|
| `--release` | Build and run in release mode (recommended for fuzzing) |
| `--coverage` | Enable coverage tracking and HTML/LCOV output |
| `--timeout <SECS>` | Stop fuzzing after specified seconds |

**Examples:**
```bash
# Basic run
anchor fuzz run myproject invariant_test

# Production fuzzing (optimized + coverage + 10 minute timeout)
anchor fuzz run myproject invariant_test --release --coverage --timeout 600

# Quick smoke test (1 minute)
anchor fuzz run myproject invariant_test --release --timeout 60
```

**Environment variables:**
- `FUZZ_DEBUG=1` - Enable verbose debug logging
- `FUZZ_TIMEOUT_SECS=N` - Alternative to --timeout flag

### `anchor fuzz show`

View and replay crash information.

```bash
# List all crashes for a program
anchor fuzz show <program_name>

# View crash metadata (no compilation needed)
anchor fuzz show <program_name> <crash_file>

# Replay crash (requires compilation)
anchor fuzz show <program_name> <crash_file> --replay
```

**Options:**
| Flag | Description |
|------|-------------|
| `--replay` | Actually replay the crash by running the binary |

**Examples:**
```bash
# List all crashes
anchor fuzz show myproject

# View action sequence from metadata
anchor fuzz show myproject crashes/invariant_test/abc123

# Replay to debug
anchor fuzz show myproject crashes/invariant_test/abc123 --replay
```

---

## Example Harnesses

Reference implementations in `examples/`:

| Example | Description | Key Features |
|---------|-------------|--------------|
| `anchor-counter` | Minimal counter program | Simplest possible harness, good starting point |
| `staking` | Multi-user staking protocol | Time control (`warp_to_slot`), multiple users |
| `marginfi-v2-fuzz` | **Primary reference** - Complex lending protocol | Action stats, state snapshots, flash loans, multi-bank |
| `klend` | Kamino Lending harness | Standalone workspace, IDL-based types, oracle mocking |
| `whirlpools` | Orca DEX (CLMM) | Tick arrays, positions, liquidity management |

### Recommended Learning Path

1. **Start with `anchor-counter`** - Understand basic fixture structure
2. **Study `staking`** - Learn multi-user patterns and time control
3. **Reference `marginfi-v2-fuzz`** - See production-quality harness with stats tracking
4. **Check `klend`** - Standalone workspace pattern for version isolation

### Running Examples

```bash
# Build the target program first (from program directory)
anchor build

# Run the fuzz harness
anchor fuzz run marginfi-v2-fuzz invariant_test --release --timeout 60

# Run with coverage
anchor fuzz run klend invariant_test --release --coverage --timeout 120
```
