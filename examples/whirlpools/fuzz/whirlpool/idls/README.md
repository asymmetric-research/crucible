# IDL Files

Place your program's IDL JSON file here as `whirlpool.json`.

## Generating IDL

If you have the legacy (v0.29) IDL format:
```bash
anchor idl convert target/idl/whirlpool.json -o fuzz/whirlpool/idls/whirlpool.json
```

If you have the new IDL format (v0.30+), copy it directly.

## Required Format

The IDL must have an `address` field at the root level:
```json
{
  "address": "YourProgramIdHere...",
  "metadata": { ... },
  "instructions": [ ... ],
  ...
}
```

If your IDL only has the address in `metadata.address`, run `anchor idl convert` to fix it.
