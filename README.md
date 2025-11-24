# Anchor Fuzz Documentation

## Setup & Running

### Initialize a fuzz project

```bash
anchor fuzz init <project_name>
```

### Run a fuzz test

```bash
anchor fuzz run <project_name> <test_name>

anchor fuzz run <project_name> <test_name> --release // Optimized
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
│       └── src/
│           └── main.rs     # Fixtures, actions, and tests
└── crashes/                # Crash artifacts saved here
    └── <test_name>/
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

## Crash Replay

When a crash is found, it's saved to `crashes/<test_name>/<hash>`.

### View crash inputs

```bash
anchor fuzz show <project> crashes/<test_name>/<crash_hash>
```

Example:

```bash
anchor fuzz show staking crashes/invariant_fuzz/ded8fcc0c883fc7
```

Output:

```
Crash Input:
param_1: [
    Stake { user: 0, amount: 1000 },
    AdvanceTime { slots: 500 },
    Stake { user: 0, amount: 10000000 },
    Claim { user: 1 },
]
```

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
}

impl MyFixture {
    // Dispatches action to appropriate method
    pub fn __dispatch_action(&mut self, action: MyFixtureActions) { /* ... */ }
}
```

The `#[invariant_test]` macro generates:

```rust
#[anchor_fuzz]
fn invariant_fuzz(fixture: &mut MyFixture, actions: Vec<MyFixtureActions>) {
    for action in actions {
        action.constrain_in_place();
        fixture.__dispatch_action(action);
        
        // Your invariant check code here
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

### Ignoring expected errors

```rust
pub fn action_claim(&mut self, user_idx: usize) {
    // Use let _ to ignore result - some actions may fail legitimately
    let _ = self.ctx.program(self.program_id)
        .call(instruction::Claim {})
        .accounts(/* ... */)
        .signers(&[&*self.users[user_idx].keypair])
        .send();  // Don't unwrap - let it fail gracefully
}
```

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
