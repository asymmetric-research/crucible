# Taint Analysis (Per-Action Account Tracking)

Crucible can track which accounts each action reads and writes, and optionally capture byte-level diffs showing exactly what changed. This makes crash analysis much easier — instead of just seeing action names, you see the account mutations that led to the violation.

## Basic taint tracking

Basic taint tracking (read/write account sets) is **always active** — it adds negligible overhead since account metadata is already tracked internally. Every crash metadata file includes per-action taint data:

```json
{
  "name": "action_deposit",
  "params": { "user_idx": 0, "amount": 50000000 },
  "success": true,
  "taint": {
    "tx_count": 1,
    "written_accounts": ["Fj3k...", "9xG2..."],
    "read_accounts": ["11111111...", "TokenkegQ..."]
  }
}
```

## Byte-level diffs (`--taint-diffs`)

For detailed before/after snapshots of every account mutation, enable taint diffs:

```bash
crucible run myproject invariant_test --release --taint-diffs
```

This captures pre/post account state for each transaction and produces detailed change summaries:

```json
{
  "name": "action_deposit",
  "success": true,
  "taint": {
    "tx_count": 1,
    "written_accounts": ["Fj3k...", "9xG2..."],
    "read_accounts": ["11111111..."],
    "account_changes": [
      {
        "pubkey": "Fj3k...",
        "kind": "Modified",
        "lamports": [100000000, 150000000],
        "changed_ranges": [[8, 8], [24, 8]]
      }
    ]
  }
}
```

Each `account_changes` entry shows:
- **kind** — `Created`, `Modified`, or `Deleted`
- **lamports** — `[pre, post]` lamport balances
- **changed_ranges** — `[offset, length]` pairs of modified byte regions

## Enhanced crash output

When taint data is available, `crucible show --replay` prints account changes inline with the action sequence:

```
=== FUZZ SEQUENCE (6 executed, 0 skipped) ===
  1. action_deposit(user_idx=0, amount=50000000) -> OK
     wrote: Fj3k...(+50M lamports), 9xG2...(data[8..16])
  2. action_borrow(user_idx=1, amount=40000000) -> OK
     wrote: Fj3k...(data[24..32])
  3. action_withdraw(user_idx=0, amount=99999999) -> OK [VIOLATION]
     wrote: Fj3k...(data[8..16], data[24..32])
================================
```

## Auto-enabled on replay

Taint diffs are **automatically enabled** when replaying crashes (`--input` flag or `crucible show --replay`), so you always get the richest output when investigating violations.

## Semantic field diffs (with IDL)

When account schemas are registered, taint diffs show **field-level** changes using account type names and field names from the IDL instead of raw byte offsets:

```
  Without schemas:
     GPgHqr3h...(data[278..280], data[1536..1537])

  With schemas:
     GPgHqr3h...(total_asset_shares: [00, 00, ...] -> [01, 01, ...], flags: 0 -> 1)
```

To enable semantic diffs, call `register_schemas()` in your fixture's `setup()` method:

```rust
crucible_idl_gen::declare_fuzz_program!("idls/my_program.json");

#[fuzz_fixture]
impl MyFixture {
    pub fn setup() -> Self {
        my_program::register_schemas();  // Register IDL account schemas
        // ... rest of setup
    }
}
```

This works for zero-copy (`repr(C)`) account types. Borsh-only accounts fall back to byte-range diffs. Semantic diffs are automatically active during `crucible show --replay`.
