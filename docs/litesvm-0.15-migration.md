# LiteSVM 0.15.2 Migration

Crucible is pinned to [LiteSVM 0.15.2](https://github.com/LiteSVM/litesvm/releases/tag/v0.15.2).
The minimum supported Rust version is 1.89.

This upgrade changes several runtime details that harness authors may observe. Crucible preserves
its established defaults where they are part of the testing API, but otherwise follows the
corrected LiteSVM 0.15 transaction and account semantics.

## Context construction and slots

`TestContext::new()` remains deterministic: it starts at slot `0`, disables signature and
blockhash verification, and uses Crucible's all-features-enabled runtime policy.

Use the builder when a test needs a different initial Clock:

```rust
use crucible_test_context::TestContext;

let slot_zero = TestContext::new();
let historical = TestContext::builder().initial_slot(250_000_000).build();
let current_mainnet_baseline = TestContext::builder().mainnet_slot().build();
```

`mainnet_slot()` selects `litesvm::MAINNET_DEFAULT_SLOT` (`435_456_000` in LiteSVM 0.15.2); it
does not change Crucible's feature policy. Construction keeps Clock and the initial SlotHashes
entry aligned. If both slot setters are used, the last call wins.
`warp_to_slot` and `advance_slots` remain the post-construction time controls.

This differs intentionally from `litesvm::LiteSVM::new()`, which starts at LiteSVM's bundled
mainnet feature slot and uses its mainnet feature set. `TestContext::from_svm` preserves the
provided SVM rather than applying Crucible's defaults. Such an SVM is treated as opaque and cloned
verbatim for generated alternate workers, preserving custom builtins, syscalls, feature state,
transaction history, airdrop identity, and epoch stakes. LiteSVM cannot change register-tracing
instrumentation after programs are loaded, so `from_svm` also preserves the caller's tracing mode;
use `TestContext::new()` or the builder when Crucible must construct both traced and untraced
workers.

Directly installing custom builtins or syscalls on the public `ctx.svm` field also creates opaque
runtime state. Call `ctx.preserve_runtime_config()` after those setup changes so generated workers
clone the runtime verbatim. Settings exposed by TestContext itself, including compute budget and
epoch stakes, remain rebuildable without this opt-in.

## Runtime behavior changes

### Programs are upgradeable-loader accounts

`TestContext::add_program` now follows LiteSVM 0.15's default deployment layout. It creates an
executable BPF Upgradeable Loader `Program` account and a separate `ProgramData` account. The
generated `ProgramData` has no upgrade authority, so the deployed program is immutable.

Code that counts accounts, inspects owners, or restores snapshots must allow for both accounts.
An instruction that requires `program_data.upgrade_authority_address == Some(authority)` still
needs a matching `ProgramData` account, either cloned from RPC or explicitly seeded; the default
immutable deployment cannot satisfy that constraint by itself.

Crucible rebuilds LiteSVM's 0.15 default program set after enabling all features. That set includes
the feature-selected Token program, Token-2022 v11, both Memo IDs, the associated-token and
address-lookup-table programs, and the core-BPF Stake program. Do not carry forward assertions
about embedded program bytes, owners, loader layout, or account counts from an older runtime. If
a test depends on an exact deployed version, load or RPC-clone that program explicitly.

### Epoch stake is configurable

LiteSVM no longer hard-codes the epoch-stake syscalls to zero. Configure the vote-account stakes
during fixture setup when a program calls `sol_get_epoch_stake`:

```rust
ctx.set_epoch_stake(vote_account, 500_000)?;
ctx.set_epoch_stakes([(vote_account_a, 500_000), (vote_account_b, 750_000)])?;
```

`set_epoch_stake` updates one vote account and the cluster total; a zero value removes it.
`set_epoch_stakes` replaces the complete map. Configure these values before Crucible captures the
fixture snapshot so traced, untraced, and state-pool SVMs receive the same runtime-only state.
Both setters return an error after `take_snapshot()` freezes runtime configuration.

### Corrected transaction semantics

Crucible adopts the 0.15 transaction behavior rather than reproducing older runtime quirks. In
particular, account-lock validation still runs when signature verification is disabled, and a
failed transaction retains its original execution error instead of being replaced by a later rent
error. Harness assertions should be updated only when they depended on one of those old behaviors;
`TxOutcome` continues to expose logs, compute units, fees, return data, inner instructions, and the
transaction error.

## Callback and dependency migration

The invocation callback now receives the SVM and transaction on both sides of an invocation. The
before hook also receives a mutable invoke context and both hooks receive the tracing flag:

```rust
fn before_invocation(
    &self,
    svm: &LiteSVM,
    tx: &SanitizedTransaction,
    program_indices: &[IndexOfAccount],
    invoke_context: &mut InvokeContext,
    enable_register_tracing: bool,
);

fn after_invocation(
    &self,
    svm: &LiteSVM,
    tx: &SanitizedTransaction,
    program_indices: &[IndexOfAccount],
    invoke_context: &InvokeContext,
    enable_register_tracing: bool,
);
```

Runtime-context modules also moved: import `InstructionContext` from
`solana_transaction_context::instruction` and `TransactionReturnData` from
`solana_transaction_context::transaction` when implementing custom integrations.

LiteSVM 0.15 uses the modular Agave/Solana crates and does not put every `solana-*` package on one
major version. Representative constraints are account 4.3, message 4.2+, transaction/runtime 4.1,
and sysvar 4.1 alongside instruction 3.4, keypair 3.1, signer/pubkey 3.0, and the compatible
address bridge. Harnesses should inherit Crucible's generated dependency set instead of forcing
every Solana crate to a single major. A standalone harness remains useful when the target program
itself is built against an older Solana or Anchor stack.

## Sysvars, Rent, and snapshots

Solana 4 sysvar account data uses `wincode`. `TestContext::set_sysvar` therefore accepts `T` with
`Sysvar + SysvarId + wincode::Serialize<Src = T>`. Clock and other sysvar bytes in snapshots are
also encoded and decoded with wincode.

This does **not** change a target program's instruction format. Keep bincode for native
instructions or account types whose on-chain ABI specifies bincode; keep Borsh for Borsh/Anchor
ABIs.

With Crucible's all-features-enabled policy, `Rent::default()` uses the current rent representation
(one-year threshold and the corresponding per-byte rate). The calculated rent-exempt minimum is
unchanged from the legacy two-year representation, but tests comparing raw Rent fields or bytes
must use the active representation.

Snapshot restoration preserves raw sysvar accounts and refreshes LiteSVM's sysvar cache. Compact
state snapshots inherit Clock, EpochRewards, EpochSchedule, Fees, LastRestartSlot,
RecentBlockhashes, Rent, and StakeHistory from their root state. `SlotHashes` and `SlotHistory`
are deliberately excluded from compact deltas because of their size; directly mutating either is
not safe for compact state-pool restoration. Account metadata such as `executable` and
`rent_epoch` participates in snapshot comparisons, and ProgramData accounts are restored before
their executable Program accounts.

Invalid framework-owned snapshot or sysvar data is now an error rather than silently falling back
to a default Clock or ignoring a failed restore.
