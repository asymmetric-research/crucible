# Writing Tests

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

For non-Anchor programs or hand-rolled instructions, use `ctx.raw_call(instruction)` instead of the typed `ctx.program(..).call(..)` builder. See [API Reference › Raw Instruction Calls](api-reference.md#raw-instruction-calls).

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

## Account-Mutation Checks

Run a harness with `--mutate-accounts` to probe common missing account checks on cloned SVM state:

```bash
crucible run myproject invariant_test --release --mutate-accounts --timeout 60
```

Current finding labels:

- `[CC-1 owner]` missing owner check
- `[CC-2 sysvar]` missing sysvar identity check
- `[CC-3 pda-spoof]` off-curve account accepted after both address and owner change
- `[CC-4 signer]` missing signer assertion
- `[CC-5 type-tag]` missing discriminator/type-tag check
- `[CC-token fake-mint-owner]` SPL mint-shaped account accepted under a wrong owner
- `[CC-token fake-account-owner]` SPL token-account-shaped account accepted under a wrong owner
- `[CC-token wrong-mint]` token account accepted with a mint field that does not match the mint account

For token relation checks, seed both the token account and the mint account in the instruction. If
only a token account is passed, the wrong-mint probe is skipped.

---

## Simple Fuzzing (`#[crucible_fuzz]`)

For testing individual operations with random inputs:

```rust
#[crucible_fuzz]
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
