# Writing Solana/Anchor Fuzz Harnesses

This guide covers critical practices for writing effective fuzz harnesses for Solana programs built with Anchor. **First read `fuzz/README.md`** for the framework API and examples.

---

## Core Workflow: Iterative Feedback Loop

**The key to writing effective harnesses is running the fuzzer frequently and using feedback to guide development.**

### Run Early and Often

```bash
# Run with short timeouts during development (3-5 seconds)
anchor fuzz run <program> <test>
# or directly:
/tmp/klend-fuzz-run/release/my_fuzz 2>&1 &
PID=$!; sleep 5; kill $PID
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
[UserStats #0] run time: 3s, edges: 1491/65536 (2%)
[UserStats #0] run time: 6s, edges: 1572/65536 (2%)  ← growth!

# Bad output - coverage stuck, repeated errors:
[DEBUG] Deposit failed: Custom(6090)
[DEBUG] Deposit failed: Custom(6090)
[DEBUG] Deposit failed: Custom(6090)  ← same error = blocker
```

### Debug Output Management

Use a global DEBUG flag to control verbose output:

```rust
const DEBUG: bool = true;  // Set to false for production runs

if DEBUG {
    eprintln!("[DEBUG] Action result: {:?}", result);
}
```

This lets you toggle between verbose debugging and clean fuzzing runs.

---

## 1. Result Handling

Solana transaction results are **nested Results**:

```rust
// send() returns Result<TransactionResult>
// where TransactionResult = Result<TransactionMetadata, FailedTransactionMetadata>

// WRONG - treats failed transactions as success:
match result {
    Ok(_) => { /* SUCCESS */ }
    Err(e) => { /* FAILED */ }
}

// CORRECT - properly distinguishes outcomes:
match result {
    Ok(Ok(meta)) => { /* Transaction succeeded */ }
    Ok(Err(failed)) => {
        // Transaction failed - inspect failed.err and failed.meta.logs
    }
    Err(e) => { /* Couldn't send transaction */ }
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

```rust
// Example: Load predefined admin keypair
let bytes: [u8; 64] = [/* from localnet-admin-keypair.json */];
let admin = Keypair::try_from(bytes.as_slice()).unwrap();
```

## 3. PDA Seed Encoding

Anchor PDAs can encode arguments as either **binary bytes** or **string bytes**. Check the actual program source:

```rust
// Binary encoding (common for small fixed-size values):
seeds = [b"account", &id.to_le_bytes()]

// String encoding (common for human-readable/variable-size values):
seeds = [b"tick_array", whirlpool.as_ref(), start_tick_index.to_string().as_bytes()]
```

**The IDL won't tell you which encoding is used** - you must read the Rust source with `seeds = [...]` constraints.

## 4. Setup Must Be Loud and Fail-Fast

During initialization, **always panic on failure** so you know exactly where setup breaks:

```rust
// WRONG - silent failure, harness continues with broken state:
match result {
    Ok(Ok(_)) => debug_print!("Success"),
    Ok(Err(e)) => debug_print!("Failed: {:?}", e),  // Continues silently!
    Err(e) => debug_print!("Error: {:?}", e),
}

// CORRECT - immediate visibility and hard stop:
match result {
    Ok(Ok(_)) => eprintln!("[SETUP] InitializeX SUCCESS"),
    Ok(Err(failed)) => {
        eprintln!("[SETUP] InitializeX TX_FAILED: {:?}", failed.err);
        for log in &failed.meta.logs { eprintln!("  {}", log); }
        panic!("Setup failed: InitializeX");
    }
    Err(e) => {
        eprintln!("[SETUP] InitializeX SEND_FAILED: {:?}", e);
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
// System program
use anchor_lang::system_program;
system_program::ID  // not system_program::id()

// Sysvar IDs may need manual definition
mod sysvar {
    pub mod rent {
        pub fn id() -> Pubkey { /* hardcoded bytes */ }
    }
}
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
- **AMM/DEX** (Whirlpool, Raydium): ~2000-3000 edges - complex math + tick/price logic
- **Lending** (Marginfi, Kamino): ~2000-4000 edges - many conditional branches for health checks
- **Governance/Simple**: ~500-1500 edges - straightforward state transitions

Low coverage may indicate setup failures or missing action coverage, not simple program logic.

---

# Bypassing Blockers

When coverage plateaus or actions consistently fail, you have a **blocker**. Common types:

## 11. Identifying Blockers from Error Messages

litesvm outputs detailed error information. Use it:

```rust
Ok(Err(failed)) => {
    eprintln!("Error: {:?}", failed.err);
    for log in &failed.meta.logs {
        eprintln!("  {}", log);
    }
}
```

**Common error patterns and fixes:**

| Error | Likely Cause | Fix |
|-------|--------------|-----|
| `Custom(6090)` DepositLimitExceeded | Config limit too low | Patch account data or use UpdateConfig |
| `Custom(6007)` MathOverflow | last_update.slot is 0 | Set to current SVM slot |
| `Custom(3002)` AccountDiscriminatorMismatch | Instruction format wrong | IDL outdated vs binary |
| `Custom(3008)` InvalidProgramId | Wrong token_program | Check SPL Token vs Token-2022 |
| `TryFromPrimitiveError` | Enum field corrupted | Restore enum bytes after patching |

## 12. Fixing Actions

**Problem:** Actions fail with specific program errors.

**Solution:** Read the error message to understand what check is failing.

```
Program log: Cannot deposit liquidity above the reserve deposit limit.
             New total deposit: 100001 > limit: 1000
```

This tells you exactly what's wrong. Fix by:
1. Using the program's UpdateConfig instruction, OR
2. Directly patching the account data

## 13. Adjusting Initial State (Account Patching)

When UpdateConfig instructions fail (e.g., discriminator mismatch), patch account data directly:

```rust
fn configure_reserve_manually(ctx: &mut TestContext, reserve: &Pubkey, program_id: &Pubkey) {
    let account = ctx.get_account(reserve).unwrap();
    let mut data = account.data.clone();

    // Find the correct offset empirically (see section 14)
    let config_offset = 5000;

    // Patch fields
    data[config_offset] = 0;  // status = Active
    data[config_offset + 16..config_offset + 24]
        .copy_from_slice(&u64::MAX.to_le_bytes());  // deposit_limit = MAX

    // Write back
    ctx.create_account()
        .pubkey(*reserve)
        .lamports(account.lamports)
        .owner(*program_id)
        .data(&data)
        .create()
        .unwrap();
}
```

**Warning:** After patching large regions, restore any enum fields to valid values:

```rust
// After setting u64::MAX across a range, restore status byte
data[config_offset] = 0;  // status must be valid enum (0=Active, 1=Obsolete, etc.)
```

## 14. IDL vs Binary Layout Mismatches

**The IDL may not match the actual binary layout.** This is common when:
- The IDL is outdated
- The binary has different padding/alignment
- Padding arrays have different sizes than documented

### Detecting Mismatches

Write a known value and see what the program reads:

```rust
// Write 1000u16 at offset 16
data[config_offset + 16..config_offset + 18].copy_from_slice(&1000u16.to_le_bytes());

// Run the program - if it shows "limit: 1000", deposit_limit is at offset 16!
```

### Finding Correct Offsets

1. **Empirical discovery:** Write unique values at suspected offsets, observe what the program reads
2. **GitHub source:** Fetch the actual struct definitions from source:
   ```bash
   curl https://raw.githubusercontent.com/Program/repo/main/src/state/account.rs
   ```
3. **Calculate from struct:** Add up field sizes with alignment padding:
   ```
   discriminator(8) + version(8) + last_update(16) + pubkey(32) + ...
   ```

### Example: klend deposit_limit Discovery

The IDL suggested deposit_limit at offset 160 in config. But:
```rust
// Writing 1000u16 at offset 16 for max_liquidation_bonus_bps...
data[config_offset + 16..config_offset + 18].copy_from_slice(&1000u16.to_le_bytes());

// ...program showed "limit: 1000" - deposit_limit was actually at offset 16!
```

## 15. Action Dependencies and Multi-Step Flows

Some actions depend on previous actions completing successfully:

```
deposit_reserve_liquidity → user gets cTokens
deposit_obligation_collateral → cTokens become collateral
borrow_obligation_liquidity → borrow against collateral
```

**Common bug:** Creating accounts in one action but not persisting them:

```rust
// WRONG - creates account but doesn't save reference
let collateral_acc = ctx.create_token_account()...;
// Later actions can't find it!

// CORRECT - save to fixture state
let collateral_acc = ctx.create_token_account()...;
self.users[user_idx].token_accounts.insert(mint, collateral_acc);  // Save it!
```

## 16. Intermittent vs Permanent Errors

**Intermittent errors** (occur sometimes) are often fine:
- "Insufficient funds" - user doesn't have tokens for this specific action
- "Position not found" - position was closed by earlier action
- "No liquidity" - pool state varies

**Permanent errors** (occur always) are blockers:
- Same error on every iteration = something is fundamentally wrong
- Track with counters:

```rust
static ERROR_COUNT: AtomicU32 = AtomicU32::new(0);
if let Ok(Err(failed)) = result {
    let count = ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
    if count < 5 {
        eprintln!("[DEBUG] Error: {:?}", failed.err);
    }
}
```

If you see 5 of the same error immediately, investigate before continuing.

---

# Writing Effective Invariants

## 17. Track Dynamic State Changes

Instructions can **create, transfer, or close accounts**. Your fixture must track these:

```rust
#[derive(Clone)]
struct MyFixture {
    ctx: TestContext,
    // Track ALL accounts that can change
    user_accounts: Vec<Pubkey>,           // Can grow via create_account
    positions: Vec<PositionData>,          // Can grow/shrink via open/close
    account_owners: HashMap<Pubkey, Pubkey>, // Track ownership transfers
}

// When an action creates a new account, ADD it to tracking:
pub fn action_transfer_account(&mut self, from_idx: usize, to: Pubkey) {
    // ... execute transfer ...
    if result.is_ok() {
        // UPDATE TRACKING - the account now has a new owner
        let account_pubkey = self.user_accounts[from_idx];
        self.account_owners.insert(account_pubkey, to);
    }
}

pub fn action_open_position(&mut self, ...) {
    // ... execute open position ...
    if result.is_ok() {
        // ADD to tracking - new account exists
        self.positions.push(new_position_data);
    }
}
```

## 18. Handle Multi-Instruction Sequences

Some bugs only manifest in **specific instruction sequences** (e.g., flashloans):

```rust
// Flashloan pattern: borrow → use → repay (must happen atomically)
// The invariant must understand this context

struct MyFixture {
    // Track in-flight operations
    pending_flashloan: Option<FlashloanContext>,
    in_flashloan_sequence: bool,
}

// Invariant must account for intermediate states:
fn invariant_check(&self) {
    if self.in_flashloan_sequence {
        // During flashloan, balances are temporarily inconsistent - that's OK
        return;
    }

    // Only check conservation OUTSIDE of atomic sequences
    assert!(self.total_deposited >= self.total_borrowed);
}
```

## 19. Deserialize On-Chain State for Invariants

**Don't just track local variables** - read actual on-chain state to verify:

```rust
fn invariant_check(&mut self) {
    // READ ACTUAL ON-CHAIN STATE - don't trust local tracking alone
    for position in &self.positions {
        let on_chain_data: PositionAccount = self.ctx
            .read_anchor_account(&position.pubkey)
            .expect("Position account must exist");

        // Compare on-chain state to expected state
        assert_eq!(
            on_chain_data.liquidity,
            position.expected_liquidity,
            "Position liquidity mismatch - local tracking diverged from on-chain"
        );
    }

    // Verify token balances match expected
    let vault_balance = self.ctx.token_balance(&self.vault_pubkey);
    assert!(
        vault_balance >= self.total_user_deposits,
        "Vault balance {} < total deposits {}",
        vault_balance, self.total_user_deposits
    );
}
```

## 20. Designing Useful Invariants

**Conservation invariants** (tokens in = tokens out):
```rust
// Total tokens in protocol = sum of all user deposits - withdrawals + fees
let total_in_vaults = self.ctx.token_balance(&vault_a) + self.ctx.token_balance(&vault_b);
let expected = self.total_deposits - self.total_withdrawals + self.accrued_fees;
assert!(total_in_vaults >= expected, "Token conservation violated");
```

**Solvency invariants** (protocol can meet obligations):
```rust
// Protocol must always be able to cover all positions
let total_liabilities = self.positions.iter().map(|p| p.owed_amount).sum();
let total_assets = self.ctx.token_balance(&vault);
assert!(total_assets >= total_liabilities, "Protocol insolvent");
```

**State consistency invariants** (data structures are valid):
```rust
// Position tick ranges must be valid
for pos in &self.positions {
    assert!(pos.tick_lower < pos.tick_upper, "Invalid tick range");
    assert!(pos.tick_lower % TICK_SPACING == 0, "Tick not aligned");
}

// Account ownership must be consistent
for (account, expected_owner) in &self.account_owners {
    let on_chain = self.ctx.read_account(account).unwrap();
    assert_eq!(on_chain.owner, *expected_owner, "Owner mismatch");
}
```

**Access control invariants** (permissions respected):
```rust
// Only admin should be able to modify config
// (Track who successfully called admin functions)
assert!(
    self.config_modifications.iter().all(|m| m.caller == self.admin.pubkey()),
    "Non-admin modified config"
);
```

## 21. Introspection for Complex Programs

For programs with **internal function calls or complex control flow**, analyze:

1. **CPI (Cross-Program Invocation)** patterns - which programs are called?
2. **Reentrance guards** - can actions be nested?
3. **State machines** - what transitions are valid?

```rust
// If program has internal phases/modes, track them:
struct MyFixture {
    protocol_mode: ProtocolMode,  // Normal, Paused, Migration, etc.
}

fn invariant_check(&self) {
    match self.protocol_mode {
        ProtocolMode::Normal => {
            // Full invariants apply
            self.check_solvency();
            self.check_conservation();
        }
        ProtocolMode::Paused => {
            // Only check that no state changed
            self.check_no_mutations();
        }
        ProtocolMode::Migration => {
            // Relaxed invariants during migration
            self.check_migration_safety();
        }
    }
}
```

---

# Debugging Workflow Summary

When developing a harness, follow this iterative loop:

```
┌─────────────────────────────────────────────────────────────────┐
│  1. WRITE/MODIFY  →  2. BUILD  →  3. RUN (3-5s)  →  4. ANALYZE │
│         ↑                                              │        │
│         └──────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

### Step-by-Step

1. **Write initial harness** with setup + 1-2 actions
2. **Build and run for 3-5 seconds**
3. **Check output:**
   - Setup succeeded? (no panics)
   - Actions executing? (see logs)
   - Coverage growing? (edges increasing)
   - Errors repeating? (blocker detected)

4. **If blocker found:**
   - Read error message carefully
   - Check error code in program's error.rs
   - Look for: limit exceeded, invalid state, missing account, wrong signer
   - Fix via: account patching, config update, action fix, state tracking

5. **If coverage stuck:**
   - Add more actions
   - Check action dependencies (do earlier actions enable later ones?)
   - Verify accounts are being persisted correctly
   - Consider if program needs specific state (e.g., oracle prices)

6. **Once working:** Run for 30s-5m to verify sustained coverage growth

### Quick Reference

| Symptom | Likely Cause | Section |
|---------|--------------|---------|
| Setup panics | Initialization order wrong | §5 |
| Same error every time | Blocker - config/state issue | §11-16 |
| Coverage stuck at low % | Actions failing silently | §15 |
| Program panics with enum error | Patching corrupted enum | §13 |
| "limit: X" shows wrong value | IDL/binary layout mismatch | §14 |
| Later actions can't find accounts | State not persisted | §15, §17 |

---

**Key insight**: The IDL provides the interface, but the **program source code** reveals the actual constraints, whitelists, encoding details, and state transitions that determine whether your harness will work and your invariants will catch real bugs.

---

# Advanced: Bytemuck Struct Access

When manual byte offset patching becomes unwieldy, use **bytemuck** with `#[repr(C)]` structs for type-safe account access.

## 22. Creating types.rs with Bytemuck Structs

Instead of manual offset calculations:

```rust
// BAD: Fragile, error-prone, no type safety
let ltv_offset = 8 + 264 + 12;  // Where does 12 come from?
data[ltv_offset] = 80;
```

Create structs that mirror the program's account layout:

```rust
// types.rs
use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct Reserve {
    pub last_update: LastUpdate,
    pub lending_market: [u8; 32],
    pub liquidity: ReserveLiquidity,
    pub config: ReserveConfig,
    pub padding: [u8; 150],
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct ReserveConfig {
    pub status: u8,
    pub _padding1: [u8; 7],
    pub asset_tier: u8,
    pub _padding2: [u8; 7],
    pub loan_to_value_pct: u8,           // Now you know exactly where LTV is!
    pub liquidation_threshold_pct: u8,
    // ... other fields
}

pub const RESERVE_SIZE: usize = std::mem::size_of::<Reserve>();
```

### Steps to Create types.rs

1. **Find program's account structs** in source code (e.g., `src/state/reserve.rs`)
2. **Copy struct definitions** preserving exact field order
3. **Add bytemuck derives**: `#[repr(C)]`, `Pod`, `Zeroable`
4. **Convert non-Pod types**:
   - `Pubkey` → `[u8; 32]`
   - `bool` → `u8`
   - Nested structs → also make `#[repr(C)]` Pod
5. **Handle u128 stored as [u64; 2]** (common in DeFi for fixed-point math):

```rust
pub fn u64_pair_to_u128(pair: [u64; 2]) -> u128 {
    (pair[0] as u128) | ((pair[1] as u128) << 64)
}

pub fn u128_to_u64_pair(value: u128) -> [u64; 2] {
    [value as u64, (value >> 64) as u64]
}
```

## 23. Reading Account Data with Bytemuck

```rust
use types::{Reserve, RESERVE_SIZE};

fn read_reserve(ctx: &TestContext, pubkey: &Pubkey) -> Reserve {
    let account = ctx.get_account(pubkey).unwrap();
    // Skip 8-byte Anchor discriminator
    let reserve: &Reserve = bytemuck::from_bytes(&account.data[8..8 + RESERVE_SIZE]);
    *reserve
}

// Example: Check if LTV is configured correctly
let reserve = read_reserve(&ctx, &sol_reserve);
assert_eq!(reserve.config.loan_to_value_pct, 80, "LTV should be 80%");
```

## 24. Writing Account Data with Bytemuck

```rust
fn configure_reserve_manually(
    ctx: &mut TestContext,
    reserve_pubkey: &Pubkey,
    program_id: &Pubkey,
    current_slot: u64,
) {
    let account = ctx.get_account(reserve_pubkey).unwrap();
    let mut data = account.data.clone();

    // Get mutable reference via bytemuck
    let reserve: &mut Reserve = bytemuck::from_bytes_mut(&mut data[8..8 + RESERVE_SIZE]);

    // Now you can access fields directly - no offset math!
    reserve.last_update.slot = current_slot;
    reserve.last_update.stale = 0;

    reserve.config.loan_to_value_pct = 80;
    reserve.config.liquidation_threshold_pct = 85;
    reserve.config.deposit_limit = u64::MAX;
    reserve.config.borrow_limit = u64::MAX;

    // Set oracle price (u128 stored as [u64; 2])
    let price_sf: u128 = 100 * 10_u128.pow(18);
    reserve.liquidity.market_price_sf = u128_to_u64_pair(price_sf);

    // Write back
    ctx.set_account(reserve_pubkey, Account {
        lamports: account.lamports,
        data,
        owner: *program_id,
        ..Default::default()
    });
}
```

## 25. Benefits of Bytemuck Approach

| Manual Offsets | Bytemuck Structs |
|---------------|------------------|
| `data[8 + 264 + 12] = 80` | `reserve.config.loan_to_value_pct = 80` |
| Silent failures if offset wrong | Compile-time type checking |
| Must recalculate on struct changes | Just update struct definition |
| Hard to debug | Self-documenting code |
| Easy to miss padding | Explicit padding fields |

---

# Advanced: Dynamic remaining_accounts

## 26. When Instructions Need remaining_accounts

Many DeFi instructions require **dynamic accounts** based on on-chain state:

| Instruction | remaining_accounts Needed |
|-------------|---------------------------|
| RefreshObligation | All deposit/borrow reserve pubkeys |
| Liquidate | Collateral reserve + debt reserve |
| FlashLoan | All affected pool/reserve accounts |
| MultiHop Swap | Intermediate pool accounts |

The fuzzer can't know these statically - must read state to discover them.

## 27. Pattern: Read State to Build remaining_accounts

```rust
fn queue_refresh_obligation(&mut self, user_idx: usize) -> anyhow::Result<()> {
    use types::{Obligation, OBLIGATION_SIZE};

    let user_obligation = self.users[user_idx].obligation;
    let mut remaining_accounts = Vec::new();

    // Read the obligation to discover which reserves it references
    if let Ok(account) = self.ctx.get_account(&user_obligation) {
        if account.data.len() >= 8 + OBLIGATION_SIZE {
            let obligation: &Obligation = bytemuck::from_bytes(
                &account.data[8..8 + OBLIGATION_SIZE]
            );

            // Collect deposit reserves
            for deposit in &obligation.deposits {
                if deposit.deposit_reserve != [0u8; 32] {
                    remaining_accounts.push(Pubkey::new_from_array(deposit.deposit_reserve));
                }
            }

            // Collect borrow reserves (avoid duplicates)
            for borrow in &obligation.borrows {
                if borrow.borrow_reserve != [0u8; 32] {
                    let pubkey = Pubkey::new_from_array(borrow.borrow_reserve);
                    if !remaining_accounts.contains(&pubkey) {
                        remaining_accounts.push(pubkey);
                    }
                }
            }
        }
    }

    // Now call with discovered accounts
    self.ctx.program(self.program_id)
        .call(instruction::RefreshObligation {})
        .accounts(accounts::RefreshObligation {
            lending_market: self.lending_market,
            obligation: user_obligation,
        })
        .remaining_accounts(remaining_accounts)  // Dynamic!
        .add_transaction()
}
```

## 28. Error: InvalidAccountInput (6006)

If you see `Custom(6006)` InvalidAccountInput, the program expected accounts that weren't provided. Check:

1. Is the instruction expecting remaining_accounts?
2. Does the on-chain state (obligation, pool, etc.) reference other accounts?
3. Are you passing accounts in the correct order?

---

# Advanced: State Dependency Chains

## 29. Understanding Action Dependencies

Most DeFi protocols have **state dependencies** where later actions require earlier actions to succeed:

```
Lending Protocol Chain:
  deposit_reserve_liquidity  →  get cTokens (receipt tokens)
  deposit_obligation_collateral  →  cTokens become collateral
  borrow_obligation_liquidity  →  borrow against collateral
  repay_obligation_liquidity  →  repay debt
  withdraw_obligation_collateral  →  reclaim cTokens
```

**Problem**: Random fuzzing rarely discovers these chains because:
- Each action picks random parameters (different users)
- State from one action doesn't influence the next
- Probability of valid sequence = `1/num_actions^chain_length`

## 30. Solution: Early Return Checks

Check prerequisites before attempting actions that depend on prior state:

```rust
pub fn action_borrow(&mut self, user_idx: usize, amount: u64) {
    use types::{Obligation, OBLIGATION_SIZE};

    // EARLY RETURN: Check if user has collateral deposited
    if let Ok(account) = self.ctx.get_account(&self.users[user_idx].obligation) {
        if account.data.len() >= 8 + OBLIGATION_SIZE {
            let obligation: &Obligation = bytemuck::from_bytes(
                &account.data[8..8 + OBLIGATION_SIZE]
            );

            // Check for NON-EMPTY deposit slots
            let has_collateral = obligation.deposits.iter()
                .any(|d| d.deposit_reserve != [0u8; 32]);

            if !has_collateral {
                // Log and skip - don't waste cycles on guaranteed failure
                eprintln!("[SKIP] borrow: user {} has no collateral", user_idx);
                return;
            }
        }
    }

    // Proceed with borrow...
}
```

## 31. Checking the Right Field

**Critical**: Check fields that are set **immediately**, not computed fields.

```rust
// WRONG: deposited_value_sf is COMPUTED by RefreshObligation
// It's 0 until RefreshObligation runs, even if user deposited collateral
let has_collateral = obligation.deposited_value_sf != [0, 0];

// RIGHT: deposit_reserve is SET by DepositObligationCollateral
// It's populated immediately when collateral is deposited
let has_collateral = obligation.deposits.iter()
    .any(|d| d.deposit_reserve != [0u8; 32]);
```

### Common Field Types

| Field Type | When Set | When to Check |
|-----------|----------|---------------|
| Reserve pubkey in slot | By deposit/borrow action | Before dependent actions |
| Value/amount fields (sf) | By refresh/compound action | After refresh |
| Status flags | By admin/init action | Anytime |
| Timestamps | By action execution | For staleness checks |

## 32. Alternative: Smart Actions

Make actions automatically set up prerequisites:

```rust
pub fn action_borrow(&mut self, user_idx: usize, amount: u64) {
    // Check if user has collateral
    let has_collateral = self.user_has_collateral(user_idx);

    if !has_collateral {
        // Auto-setup: deposit collateral first
        let collateral_amount = amount * 2;  // Over-collateralize
        self.action_deposit(user_idx, collateral_amount);
        self.action_deposit_collateral(user_idx, collateral_amount);
    }

    // Now borrow
    self.do_borrow(user_idx, amount);
}
```

## 33. Alternative: Compound Actions

Create high-level actions that combine multiple operations:

```rust
pub fn action_full_borrow_flow(&mut self, user_idx: usize, collateral: u64, borrow: u64) {
    // Always execute full sequence
    self.action_deposit(user_idx, collateral);
    self.action_deposit_collateral(user_idx, collateral);
    self.action_borrow(user_idx, borrow);
}
```

---

# Diagnostic Logging Patterns

## 34. Action Statistics Tracking

Track per-action success/failure rates to identify blockers:

```rust
use std::sync::atomic::{AtomicU32, Ordering};

struct ActionStats {
    attempts: AtomicU32,
    success: AtomicU32,
    early_return: AtomicU32,
    program_error: AtomicU32,
}

static BORROW_STATS: ActionStats = ActionStats {
    attempts: AtomicU32::new(0),
    success: AtomicU32::new(0),
    early_return: AtomicU32::new(0),
    program_error: AtomicU32::new(0),
};

pub fn action_borrow(&mut self, user_idx: usize, amount: u64) {
    BORROW_STATS.attempts.fetch_add(1, Ordering::Relaxed);

    // Early return case
    if !self.user_has_collateral(user_idx) {
        BORROW_STATS.early_return.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let result = self.do_borrow(user_idx, amount);

    match &result {
        Ok(TxOutcome::Success { compute_units, .. }) => {
            BORROW_STATS.success.fetch_add(1, Ordering::Relaxed);
            eprintln!("[SUCCESS] borrow: CU={}", compute_units);
        }
        Ok(TxOutcome::ProgramError { error_code, .. }) => {
            BORROW_STATS.program_error.fetch_add(1, Ordering::Relaxed);
            eprintln!("[ERROR] borrow: code={:?}", error_code);
        }
        _ => {}
    }
}
```

## 35. Periodic Summary Output

Print statistics periodically to track progress:

```rust
fn print_action_stats() {
    eprintln!("=== Action Statistics ===");
    eprintln!("deposit:      {}/{} success",
        DEPOSIT_STATS.success.load(Ordering::Relaxed),
        DEPOSIT_STATS.attempts.load(Ordering::Relaxed));
    eprintln!("deposit_coll: {}/{} success",
        DEPOSIT_COLL_STATS.success.load(Ordering::Relaxed),
        DEPOSIT_COLL_STATS.attempts.load(Ordering::Relaxed));
    eprintln!("borrow:       {}/{} success ({} early return)",
        BORROW_STATS.success.load(Ordering::Relaxed),
        BORROW_STATS.attempts.load(Ordering::Relaxed),
        BORROW_STATS.early_return.load(Ordering::Relaxed));
}
```

---

# Common Lending Protocol Errors

## 36. Error Reference

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
- [ ] Consider smart actions or compound actions for state chains
- [ ] Run initial fuzzing and analyze error patterns
- [ ] Iterate on fixes until major actions succeed
