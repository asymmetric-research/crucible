# Writing Solana/Anchor Fuzz Harnesses

This guide covers critical practices for writing effective fuzz harnesses for Solana programs built with Anchor. **First read the [API Reference](api-reference.md) and [Writing Tests](writing-tests.md)** for the framework API and examples.

---

## Core Workflow: Iterative Feedback Loop

**The key to writing effective harnesses is running the fuzzer frequently and using feedback to guide development.**

### Run Early and Often

```bash
# Run with short timeouts during development (3-5 seconds)
crucible run <program> <test> --release --timeout 5
```

**During development:**
- Run for **3-5 seconds** if there's verbose debug output
- Run for **10-30 seconds** if output is clean to see coverage trends
- Watch for: error patterns, coverage plateaus, action failures

### What to Look For

1. **Coverage growth** - Is `edges` count increasing over time?
2. **Error patterns** - Are the same errors repeating? (indicates a blocker)
3. **Execution speed** - Should be 200+ exec/sec once setup completes
4. **Corpus growth** - Is the fuzzer finding new interesting inputs?

```
# Good output - coverage growing, exec speed normal:
[FUZZ_PULSE] run time: 3s, corpus: 50, exec/sec: 1234, edges: 1491/65536 (2%)
[FUZZ_PULSE] run time: 6s, corpus: 85, exec/sec: 1180, edges: 1572/65536 (2%)  <- growth!

# Bad output - coverage stuck, repeated errors:
[DEBUG] Deposit failed: Custom(6090)
[DEBUG] Deposit failed: Custom(6090)
[DEBUG] Deposit failed: Custom(6090)  <- same error = blocker
```

### Debug Output Management

Use a global DEBUG flag to control verbose output:

```rust
const DEBUG: bool = true;  // Set to false for production runs

if DEBUG {
    eprintln!("[DEBUG] Action result: {:?}", result);
}
```

---

## 1. Result Handling

```rust
use crucible_test_context::TxOutcome;

match result? {
    TxOutcome::Success { compute_units, logs } => {
        // Transaction succeeded
    }
    TxOutcome::ProgramError { error, error_code, logs, .. } => {
        // Transaction failed
        if let Some(code) = error_code {
            println!("Failed with error code: {}", code);
        }
    }
}
```

## 2. Admin/Authority Whitelists

Many Solana programs have **hardcoded authority whitelists**. Look for:
- `ADMINS`, `AUTHORITIES`, `ALLOWED_SIGNERS` arrays
- `is_admin()`, `is_authority()` check functions
- Constraints like `#[account(constraint = is_admin(&signer.key()))]`

**Always check the program source** for these patterns. If found:
1. Locate the predefined keypair files (often in `localnet/`, `test-keys/`, or similar)
2. Load and use those specific keypairs instead of generating random ones

## 3. PDA Seed Encoding

Anchor PDAs can encode arguments as either **binary bytes** or **string bytes**. Check the actual program source:

```rust
// Binary encoding:
seeds = [b"account", &id.to_le_bytes()]

// String encoding:
seeds = [b"tick_array", whirlpool.as_ref(), start_tick_index.to_string().as_bytes()]
```

**The IDL won't tell you which encoding is used** - you must read the Rust source.

## 4. Setup Must Be Loud and Fail-Fast

During initialization, **always panic on failure**:

```rust
match result? {
    TxOutcome::Success { .. } => eprintln!("[SETUP] InitializeX SUCCESS"),
    TxOutcome::ProgramError { error, logs, .. } => {
        eprintln!("[SETUP] InitializeX FAILED: {:?}", error);
        for log in &logs { eprintln!("  {}", log); }
        panic!("Setup failed: InitializeX");
    }
}
```

## 5. Initialization Order Dependencies

Solana programs have strict initialization order. Common pattern:
1. **Global config** (WhirlpoolsConfig, Protocol, etc.)
2. **Fee/tier structures** (FeeTier, PriceFeed, etc.)
3. **Token mints** (often must be ordered by pubkey: `mint_a < mint_b`)
4. **Main accounts** (Pool, Vault, Market)
5. **Supporting structures** (TickArrays, OrderBooks, etc.)
6. **User accounts** (with token accounts funded)
7. **Positions/state** with initial values (liquidity, deposits, etc.)

## 6. Reading Anchor Error Codes

When you see errors like `Custom(2003)` or `Custom(6038)`:
- Anchor errors 2000-2999 are **constraint errors** (seeds, signer, owner, etc.)
- Anchor errors 6000+ are **program-specific errors** defined in the program

Look up the error in:
1. The program's `error.rs` or error enum
2. Anchor's standard errors (ConstraintSeeds=2006, ConstraintRaw=2003, etc.)

## 7. Token Account Requirements

For DeFi programs:
- Create token accounts with correct mint and owner
- Fund accounts with sufficient tokens (check decimal places!)
- Mint authority must match what the program expects
- Order mints correctly if program requires (e.g., `token_mint_a < token_mint_b`)

## 8. Sysvar and Program IDs

For Solana v3:

```rust
use anchor_lang::system_program;
system_program::ID  // not system_program::id()
```

## 9. Debugging Checklist

When a harness isn't working:
1. Enable **loud setup** (eprintln + panic on all failures)
2. Check **admin/authority requirements** in program source
3. Verify **PDA seed encoding** matches program source
4. Confirm **initialization order** is correct
5. Check **account constraints** in the Accounts struct
6. Read **program logs** from failed transactions
7. Verify **token balances** are sufficient

## 10. Coverage Expectations

Different program types have different coverage profiles:
- **AMM/DEX** (Whirlpool, Raydium): ~2000-3000 edges
- **Lending** (Marginfi, Kamino): ~2000-4000 edges
- **Governance/Simple**: ~500-1500 edges

---

# Bypassing Blockers

When coverage plateaus or actions consistently fail, you have a **blocker**.

## 11. Identifying Blockers from Error Messages

**Common error patterns and fixes:**

| Error | Likely Cause | Fix |
|-------|--------------|-----|
| `Custom(6090)` DepositLimitExceeded | Config limit too low | Patch account data or use UpdateConfig |
| `Custom(6007)` MathOverflow | last_update.slot is 0 | Set to current SVM slot |
| `Custom(3002)` AccountDiscriminatorMismatch | Instruction format wrong | IDL outdated vs binary |
| `Custom(3008)` InvalidProgramId | Wrong token_program | Check SPL Token vs Token-2022 |

## 12. Adjusting Initial State (Account Patching)

When UpdateConfig instructions fail, patch account data directly:

```rust
fn configure_reserve_manually(ctx: &mut TestContext, reserve: &Pubkey, program_id: &Pubkey) {
    let account = ctx.get_account(reserve).unwrap();
    let mut data = account.data.clone();

    let config_offset = 5000;
    data[config_offset] = 0;  // status = Active
    data[config_offset + 16..config_offset + 24]
        .copy_from_slice(&u64::MAX.to_le_bytes());  // deposit_limit = MAX

    ctx.create_account()
        .pubkey(*reserve)
        .lamports(account.lamports)
        .owner(*program_id)
        .data(&data)
        .create()
        .unwrap();
}
```

## 13. IDL vs Binary Layout Mismatches

**The IDL may not match the actual binary layout.** Write a known value and see what the program reads:

```rust
data[config_offset + 16..config_offset + 18].copy_from_slice(&1000u16.to_le_bytes());
// Run the program - if it shows "limit: 1000", deposit_limit is at offset 16
```

## 14. Action Dependencies and Multi-Step Flows

Some actions depend on previous actions completing successfully:

```
deposit_reserve_liquidity  ->  get cTokens
deposit_obligation_collateral  ->  cTokens become collateral
borrow_obligation_liquidity  ->  borrow against collateral
```

## 15. Early Return Checks

Check prerequisites before attempting actions that depend on prior state:

```rust
pub fn action_borrow(&mut self, user_idx: usize, amount: u64) {
    let has_collateral = /* check on-chain state */;
    if !has_collateral {
        return;  // Don't waste cycles on guaranteed failure
    }
    // Proceed with borrow...
}
```

---

# Writing Effective Invariants

## 16. Deserialize On-Chain State

**Don't just track local variables** - read actual on-chain state to verify:

```rust
fn invariant_check(&mut self) {
    for position in &self.positions {
        let on_chain_data: PositionAccount = self.ctx
            .read_anchor_account(&position.pubkey)
            .expect("Position account must exist");

        assert_eq!(
            on_chain_data.liquidity,
            position.expected_liquidity,
            "Position liquidity mismatch"
        );
    }
}
```

## 17. Designing Useful Invariants

**Conservation invariants** (tokens in = tokens out):
```rust
let total_in_vaults = self.ctx.token_balance(&vault_a) + self.ctx.token_balance(&vault_b);
let expected = self.total_deposits - self.total_withdrawals + self.accrued_fees;
fuzz_assert_ge!(total_in_vaults, expected, "Token conservation violated");
```

**Solvency invariants** (protocol can meet obligations):
```rust
let total_liabilities = self.positions.iter().map(|p| p.owed_amount).sum();
let total_assets = self.ctx.token_balance(&vault);
fuzz_assert_ge!(total_assets, total_liabilities, "Protocol insolvent");
```

**State consistency invariants** (data structures are valid):
```rust
for pos in &self.positions {
    fuzz_assert_lt!(pos.tick_lower, pos.tick_upper, "Invalid tick range");
}
```

---

# Advanced: Bytemuck Struct Access

When manual byte offset patching becomes unwieldy, use **bytemuck** with `#[repr(C)]` structs for type-safe account access.

```rust
use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct ReserveConfig {
    pub status: u8,
    pub _padding1: [u8; 7],
    pub loan_to_value_pct: u8,
    pub liquidation_threshold_pct: u8,
    pub deposit_limit: u64,
    pub borrow_limit: u64,
    // ...
}
```

Reading and writing:

```rust
let reserve: &Reserve = bytemuck::from_bytes(&account.data[8..8 + RESERVE_SIZE]);
let reserve: &mut Reserve = bytemuck::from_bytes_mut(&mut data[8..8 + RESERVE_SIZE]);
reserve.config.deposit_limit = u64::MAX;
```

---

# Diagnostic Logging Patterns

Track per-action success/failure rates to identify blockers:

```rust
use std::sync::atomic::{AtomicU32, Ordering};

struct ActionStats {
    attempts: AtomicU32,
    success: AtomicU32,
    early_return: AtomicU32,
    program_error: AtomicU32,
}
```

---

# Common Lending Protocol Errors

| Code | Name | Cause | Fix |
|------|------|-------|-----|
| 6006 | InvalidAccountInput | Wrong remaining_accounts | Read state to discover required accounts |
| 6007 | MathOverflow | last_update.slot = 0 | Set to current slot |
| 6020 | ObligationDepositsEmpty | Borrow without collateral | Early return check for deposits |
| 6051 | ReserveStale | Reserve not refreshed | Call RefreshReserve or patch last_update |
| 6087 | CollateralNonLiquidatable | LTV = 0% | Set loan_to_value_pct > 0 |
| 6090 | DepositLimitExceeded | deposit_limit too low | Set deposit_limit = u64::MAX |
| 6091 | BorrowLimitExceeded | borrow_limit too low | Set borrow_limit = u64::MAX |

---

# Checklist for New Harnesses

- [ ] Create `types.rs` with bytemuck structs matching program accounts
- [ ] Set up mock oracles for any price feeds
- [ ] Configure reserves/pools with reasonable limits (u64::MAX)
- [ ] Patch freshness/staleness fields (last_update.slot)
- [ ] Add remaining_accounts logic for instructions that need them
- [ ] Add early return checks for state prerequisites
- [ ] Add diagnostic logging to all actions
- [ ] Run initial fuzzing and analyze error patterns
- [ ] Iterate on fixes until major actions succeed

---

# Debugging Workflow Summary

```
1. WRITE/MODIFY  ->  2. BUILD  ->  3. RUN (3-5s)  ->  4. ANALYZE
       ^                                                    |
       +----------------------------------------------------+
```

| Symptom | Likely Cause | Section |
|---------|--------------|---------|
| Setup panics | Initialization order wrong | 5 |
| Same error every time | Blocker - config/state issue | 11-15 |
| Coverage stuck at low % | Actions failing silently | 14 |
| Program panics with enum error | Patching corrupted enum | 12 |
| Later actions can't find accounts | State not persisted | 14, 16 |
