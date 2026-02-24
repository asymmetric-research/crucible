# Coverage Reports

Crucible can generate LCOV coverage reports showing which lines of your Solana program were exercised during fuzzing. There are two modes: **bytecode-level** (default, no extra setup) and **source-level** (requires a debug binary, produces highlighted Rust source).

## Bytecode-level coverage

Just add `--coverage` to your run command. This generates `coverage.lcov` using SBF program counter addresses as line numbers:

```bash
crucible run myproject invariant_test --release --coverage --timeout 60
```

This is useful for tracking coverage growth over time, but the LCOV output uses fake line numbers (PC addresses) rather than real source locations.

## Source-level coverage

For proper source-level reports that map to your Rust code, you need a **debug binary** — the unstripped ELF with DWARF debug sections.

### Step 1: Build the debug binary

Add these settings to your program's workspace `Cargo.toml` under `[profile.release]`:

```toml
[profile.release]
opt-level = 1    # Better DWARF accuracy (opt-level 3 causes gaps due to inlining)
debug = 2        # Full DWARF debug info
strip = false    # Keep debug sections in the binary
```

Then build just your program (not the whole workspace, to avoid transitive dependency issues):

```bash
cargo build-sbf --manifest-path programs/<your_program>/Cargo.toml
```

This produces two binaries:
- `target/deploy/<program>.so` — stripped, for SVM execution (~1.5 MB)
- `target/sbpf-solana-solana/release/<program>.so` — unstripped with DWARF (~30-40 MB)

> **Important:** The execution binary and debug binary must come from the **same build** so that PC addresses match. If you rebuild the debug binary, also copy the deploy binary to your fuzz harness.

### Step 2: Copy the deploy binary

Copy the freshly built deploy binary to your fuzz harness directory (replacing the existing one):

```bash
cp target/deploy/<program>.so path/to/fuzz/harness/<program>.so
```

### Step 3: Run with `--symbols`

Point `--symbols` at the unstripped debug binary:

```bash
crucible run myproject invariant_test --release --coverage --timeout 60 \
  --symbols /path/to/target/sbpf-solana-solana/release/<program>.so
```

You should see output like:

```
[COVERAGE] DWARF source map loaded: 143160 PCs resolved
[LCOV] Source-level coverage: 133 source files
[LCOV] Coverage written to coverage.lcov (2 programs, 23994 lines, 2166 branches)
```

### Step 4: Generate HTML report

The `coverage.lcov` file is written inside the fuzz harness target directory. Use `lcov` and `genhtml` to produce a browsable HTML report.

First, extract only your program's source files (filtering out stdlib and third-party crate paths):

```bash
lcov --extract coverage.lcov '*/programs/<your_program>/*' -o program_coverage.lcov
```

Then generate HTML:

```bash
genhtml program_coverage.lcov -o coverage_html --legend
open coverage_html/index.html
```

> **Tip:** Run `genhtml` from your program's workspace root so that relative source paths resolve correctly.

## Why opt-level 1?

At `opt-level = 3` (the default for release), the compiler aggressively inlines and reorders code. This produces lossy DWARF debug info — many source lines have no corresponding instructions, causing gaps in the coverage report. `opt-level = 1` preserves the source-to-instruction mapping much more faithfully:

| Setting | Executable lines | Lines hit | Coverage |
|---------|-----------------|-----------|----------|
| opt-level 3 | 2,708 | 657 | 24.3% |
| opt-level 1 | 1,988 | 856 | 43.1% |

The opt-level 1 binary is larger and slower at runtime. The recommended workflow is to fuzz normally (without `--coverage`) to build up a corpus, then generate the coverage report separately:

```bash
# 1. Fuzz normally to build a corpus (fast, no coverage overhead)
crucible run myproject invariant_test --release --timeout 300 --corpus-out ./corpus

# 2. Replay the corpus with --coverage to generate the report (quick single pass)
crucible run myproject invariant_test --release --coverage --corpus-in ./corpus \
  --symbols /path/to/debug/binary.so
```

This way your main fuzzing runs at full speed, and coverage reports are generated on demand from the saved corpus.

## Installing lcov and genhtml

```bash
# macOS
brew install lcov

# Ubuntu/Debian
sudo apt install lcov
```
