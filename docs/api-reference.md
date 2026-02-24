# TestContext API Reference

## Program Loading

```rust
ctx.add_program(&program_id, "path/to/program.so")?;
```

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

## Time Control

```rust
let current = ctx.slot();
ctx.warp_to_slot(current + 1000);
ctx.advance_slots(100);
```

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
