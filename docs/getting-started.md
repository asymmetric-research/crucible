# Getting Started

Crucible requires Rust 1.89 or newer and uses LiteSVM 0.15.2. Existing harnesses upgrading from
an older LiteSVM release should read the [migration guide](litesvm-0.15-migration.md) before
regenerating their lockfile.

## Setup & Running

### Initialize a fuzz project

```bash
crucible init <project_name>
```

This creates `fuzz/<project_name>/` by default. Use `-C <dir>` to place the harness elsewhere.

### Run a fuzz test

```bash
crucible run <project_name> <test_name>

crucible run <project_name> <test_name> --release  # Optimized

crucible run <project_name> <test_name> --timeout 60  # Stop after 60 seconds

crucible run <project_name> <test_name> --release --cores 8  # 8 parallel fuzzer workers (-j 8 also works)

crucible run <project_name> <test_name> --release --stateful  # Stateful mode (single action per iter with state pool)
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

After `crucible init myproject`:

```
myproject/
├── Cargo.toml
├── programs/
│   └── myproject/          # Your Solana program
├── fuzz/
│   └── myproject/
│       ├── Cargo.toml      # Standalone workspace + features
│       ├── idls/
│       │   └── myproject.json  # Program IDL
│       ├── src/
│       │   └── main.rs     # Fixtures, actions, and tests
│       └── crashes/        # Crash artifacts saved here
│           └── <test_name>/
│               ├── abc123          # Raw crash input
│               └── abc123.meta.json  # Crash metadata
```
