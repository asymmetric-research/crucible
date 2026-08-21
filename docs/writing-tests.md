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

`TestContext::new()` starts at slot `0` with all features enabled. When the fixture needs a
specific initial Clock, set it before creating accounts or loading programs:

```rust
let mut ctx = TestContext::builder()
    .initial_slot(250_000_000)
    .build();

// Or use the mainnet feature-activation slot bundled with LiteSVM 0.15.2.
let mut ctx = TestContext::builder().mainnet_slot().build();
```

The mainnet-slot convenience changes the Clock, not Crucible's all-features-enabled policy. Use
`advance_slots` or `warp_to_slot` for later time changes. Programs that query epoch stake should
also configure `set_epoch_stake`/`set_epoch_stakes` during `setup()` so the value is captured for
every fuzzing SVM. See the [LiteSVM 0.15.2 migration guide](litesvm-0.15-migration.md).

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

Run a harness with `--mutate-accounts` to probe common missing account checks:

```bash
crucible run myproject invariant_test --release --mutate-accounts --timeout 60
```

Probes are deterministic and run when an action/instruction shape first
completes. See [Constraint-Check Engine](constraint-check-engine.md) for the
current label/probe table and common false-positive notes.

Harness shape matters:

- Seed at least two valid same-class accounts for same-class relation probes.
- Register discriminators or schemas for type-tagged accounts where possible.
- Pass both a token account and mint account for SPL token relation probes.
- Expect one probe per instruction shape per worker; if a bug is state-dependent,
  drive the vulnerable state before the first successful call to that instruction.
- Treat findings as triage inputs when the program intentionally permits
  same-class swaps, duplicate aliases, public value reads, or redundant signers.

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
