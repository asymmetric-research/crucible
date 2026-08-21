# TestContext API Reference

## Index

- [Context Construction](#context-construction) — `new`, `builder`, initial slot policy
- [Program Loading](#program-loading) — `add_program`
- [Account Creation](#account-creation) — `create_account`, `create_mint`, `create_token_account`
- [Program Calls](#program-calls) — `program(...).call(...).accounts(...).signers(...).send()`
- [Transaction Results (`TxOutcome`)](#transaction-results-txoutcome)
- [Raw Instruction Calls](#raw-instruction-calls) — `raw_call` for non-Anchor / custom instructions
- [Transaction Batching](#transaction-batching) — `add_transaction`, `send_batch`
- [Account Reading/Writing](#account-readingwriting) — `read_anchor_account`, `update_account`, zero-copy helpers
- [RPC Account Cloning](#rpc-account-cloning) — `clone_from_rpc`, `clone_account(s)`
- [Time and Runtime State](#time-and-runtime-state) — slots, sysvars, epoch stake
- [Mock Pyth Oracles](#mock-pyth-oracles)
- [Fixture Hooks](#fixture-hooks) — `setup`, `after_action` (see also [Writing Tests](writing-tests.md))

## Context Construction

`TestContext::new()` starts at slot `0` with Crucible's all-features-enabled policy:

```rust
let mut ctx = TestContext::new();
```

Select a different initial Clock and SlotHashes baseline with `TestContextBuilder`:

```rust
let historical = TestContext::builder()
    .initial_slot(250_000_000)
    .build();

let mainnet_slot = TestContext::builder()
    .mainnet_slot()
    .build();
```

`mainnet_slot()` uses `litesvm::MAINNET_DEFAULT_SLOT` but retains Crucible's all-features-enabled
policy. The builder keeps the initial Clock and SlotHashes entry aligned, and the last slot-setting
call wins. In contrast, a raw `litesvm::LiteSVM::new()` uses
LiteSVM's mainnet slot and feature defaults; `TestContext::from_svm` preserves those caller-owned
settings. Caller-supplied SVMs are treated as opaque: generated alternate workers clone them
verbatim so custom builtins, syscalls, and epoch stakes are not reconstructed or lost. That also
means Crucible cannot toggle register tracing on an SVM supplied through `from_svm`; use
`TestContext::new()` or the builder when a harness needs Crucible's traced/untraced worker modes.
If setup mutates `ctx.svm` directly with custom builtins or syscalls, call
`ctx.preserve_runtime_config()` afterward for the same lossless-clone behavior. Runtime settings
configured through TestContext methods, including compute budget and epoch stake, are rebuilt
automatically and do not need that call.

## Program Loading

```rust
ctx.add_program(&program_id, "path/to/program.so")?;
```

LiteSVM 0.15 loads this as an immutable BPF Upgradeable Loader deployment: an executable
`Program` account plus a separate `ProgramData` account whose upgrade authority is `None`. Tests
that inspect or count program accounts must include both. If an instruction requires a matching
upgrade authority, clone suitable loader accounts from RPC or seed the `ProgramData` explicitly;
the default immutable deployment cannot satisfy that constraint.

## Account Creation

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

**Lamports default to rent-exempt.** If you don't call `.lamports(...)`, the account
is created with the SVM's rent-exempt minimum for its final data length — matching real
Solana, where a non-rent-exempt account can't exist. (Otherwise a tx touching the account
as writable fails at commit with `InsufficientFundsForRent`, even after the program logic
succeeds.) `.lamports(n)` overrides this exactly, including a deliberately low balance for
negative tests (note: a 0-lamport account does not persist).

## Program Calls

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

## Transaction Results (`TxOutcome`)

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

LiteSVM 0.15 validates account locks even when signature verification is disabled. Failed
transactions also retain their original execution error rather than replacing it with a later
rent error. These are intentional validator-aligned semantics; `TxOutcome`'s public metadata
shape is unchanged.

---

## Raw Instruction Calls

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

Instruction encoding remains program-specific. The migration of Solana sysvar account data to
wincode does not change a native program that expects bincode instruction data, nor an
Anchor/Borsh instruction ABI.

## Transaction Batching

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

## Account Reading/Writing

```rust
let account: MyAccount = ctx.read_anchor_account(&address)?;
let account: Account = ctx.get_account(&address)?;
ctx.write_anchor_account(&address, &my_data)?;
```

Read-modify-write a single account atomically:

```rust
ctx.update_account(&address, |account| {
    account.lamports += 1_000_000;
    Ok(())
})?;
```

Check whether an account exists with at least `min_size` bytes of data (useful in invariants that need to skip uninitialized accounts):

```rust
if ctx.account_has_data(&pubkey, 8) {
    let data: MyAccount = ctx.read_anchor_account(&pubkey)?;
    // ...
}
```

### Zero-Copy Accounts

For accounts using `bytemuck`/zero-copy layouts. Default discriminator length is 8 bytes; use the `_with_discriminator` variants for non-Anchor zero-copy formats.

```rust
let pool: Pool = ctx.read_zero_copy_account(&pool_address)?;
ctx.write_zero_copy_account(&pool_address, &updated_pool)?;

// Custom discriminator length (e.g., 0 for raw layouts):
let raw: RawState = ctx.read_zero_copy_account_with_discriminator(&address, 0)?;
ctx.write_zero_copy_account_with_discriminator(&address, &raw, 0)?;
```

### SPL Token Balance

```rust
let amount = ctx.token_balance(&token_account_address);
```

## RPC Account Cloning

Clone accounts directly from mainnet/devnet into your test environment. Accounts are cached to disk in `.fuzz-cache/accounts/` - subsequent runs load from cache without RPC calls.

Requires the `rpc-clone` feature in your fuzz harness Cargo.toml:
```toml
crucible-test-context = { ..., features = ["rpc-clone"] }
```

### Basic Usage
```rust
fn setup() -> Self {
    let mut ctx = TestContext::new();
    let mut cloner = ctx.clone_from_rpc("https://api.mainnet-beta.solana.com");

    // Clone a program (auto-handles BPF Upgradeable Loader)
    cloner.clone_account(&program_id)?;

    // Batch clone accounts (PDAs, token accounts, oracles, etc)
    cloner.clone_accounts(&[reserve_a, reserve_b, oracle_a])?;

    // ...
}
```

### Cache Management
```rust
// Force re-fetch from RPC (ignore disk cache)
let mut cloner = ctx.clone_from_rpc(rpc_url).force_refresh();
cloner.clone_account(&stale_account)?;

// Custom cache directory
let mut cloner = ctx.clone_from_rpc(rpc_url).cache_dir("./my-cache");

// Invalidate specific account or entire cache
cloner.invalidate(&pubkey)?;
cloner.clear_cache()?;
```

### Program Account Fetching
```rust
use solana_rpc_client_api::filter::{RpcFilterType, Memcmp};

// Fetch all accounts owned by a program (requires filters)
// WARNING: Unfiltered getProgramAccounts can return millions of results
let filters = vec![RpcFilterType::DataSize(200)];
let pubkeys = cloner.clone_program_accounts(&program_id, &filters)?;
```

### How Caching Works
- First run: fetches from RPC and saves to `.fuzz-cache/accounts/<pubkey>.json` + `.bin`
- Subsequent runs: loads from disk (no network calls)
- Use `.force_refresh()` to re-fetch stale accounts
- Add `.fuzz-cache/` to `.gitignore`

## Time and Runtime State

`TestContext::new()` begins at slot `0`; use the context builder above when the initial slot is
part of the fixture. Change time after construction with:

```rust
let current = ctx.slot();
ctx.warp_to_slot(current + 1000);
ctx.advance_slots(100);
```

Set a sysvar through LiteSVM's coherent account/cache path:

```rust
use anchor_lang::prelude::Clock;

let mut clock = ctx.svm.get_sysvar::<Clock>();
clock.unix_timestamp += 3_600;
ctx.set_sysvar(&clock);
```

Solana 4 sysvar account data uses wincode. A custom `T` passed to `set_sysvar` must implement
`Sysvar + SysvarId + wincode::Serialize<Src = T>`; bincode remains valid only where the target
program's own ABI requires it.

Programs that call the epoch-stake syscalls can receive realistic setup-time values:

```rust
ctx.set_epoch_stake(vote_account, 500_000)?;
ctx.set_epoch_stakes([(vote_account_a, 500_000), (vote_account_b, 750_000)])?;
```

The single-account form adjusts the cluster total and removes an entry when its stake is zero.
The batch form replaces the complete map. Configure epoch stakes during fixture setup, before
Crucible captures snapshots, so every traced, untraced, and state-pool SVM receives the same
runtime-only values. Either setter returns an error after `take_snapshot()` freezes runtime
configuration.

See the [LiteSVM 0.15.2 migration guide](litesvm-0.15-migration.md) for compact-snapshot sysvar
limitations and the distinction between Crucible and raw LiteSVM defaults.

## Mock Pyth Oracles

```rust
let oracle = ctx.create_mock_pyth_oracle()
    .price(100_00000000)  // $100 with 8 decimals
    .exponent(-8)
    .confidence(100_000)
    .build()?;

ctx.update_pyth_price(&oracle, 95_00000000, -8)?;
ctx.refresh_pyth_oracle(&oracle)?;
```

## Fixture Hooks

`#[fuzz_fixture]` recognises a few special method names on the fixture impl:

- `setup() -> Self` — required. Builds the initial state once per iteration (stateless) or once per state-pool entry (stateful).
- `action_*` — fuzz-discovered actions, see [Writing Tests › Action Naming Convention](writing-tests.md#action-naming-convention).
- `after_action(&self)` — optional. Called after every action dispatch. Useful for diagnostic logging or state stats. See [Writing Tests › After-Action Callback](writing-tests.md#after-action-callback).
