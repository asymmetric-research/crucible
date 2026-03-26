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

Then build with `--debug` and **platform-tools v1.51+** (earlier versions have a linker bug that corrupts DWARF address relocations):

```bash
cargo build-sbf --debug --tools-version v1.51 \
  --manifest-path programs/<your_program>/Cargo.toml
```

> **Important:** Platform-tools versions before v1.51 produce corrupted DWARF debug info due to a bug in the SBF linker (LLD) where `R_SBF_64_64` relocations are incorrectly applied to debug sections instead of `R_SBF_64_ABS64`. This causes `addr2line` to resolve 0 PCs. See [anza-xyz/llvm-project#159](https://github.com/anza-xyz/llvm-project/pull/159) for details.

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

To write the LCOV file to a custom path (e.g., for remote fuzzing integration), use `--lcov-out`:

```bash
crucible run myproject invariant_test --release --coverage --corpus-in ./corpus \
  --lcov-out ./output/coverage.lcov
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

## Different optimization levels (3-binary workflow)

When you fuzz with an optimized binary (default `cargo build-sbf`) but need source-level coverage, the PCs from the optimized binary won't match the DWARF debug info (which requires `opt-level = 1`). Use `--program-so` to load a debug-stripped binary whose instruction layout matches the DWARF symbols binary.

### Build the binaries

```bash
cd programs/my_program

# Build 1: optimized binary for fuzzing
cargo build-sbf
cp target/deploy/my_program.so /path/to/fuzz/optimized.so

# Build 2: debug binary for coverage (edit Cargo.toml first, or append)
cat >> Cargo.toml <<'EOF'
[profile.release]
opt-level = 1
debug = 2
strip = false
EOF

cargo build-sbf
cp target/deploy/my_program.so /path/to/fuzz/debug.so           # stripped, for execution
cp target/sbpf-solana-solana/release/my_program.so /path/to/fuzz/symbols.so  # unstripped, for DWARF
```

This produces 3 binaries:

| Binary | Optimization | DWARF | Purpose |
|--------|-------------|-------|---------|
| `optimized.so` | default (fast) | no | Fuzzing |
| `debug.so` | opt-level=1, stripped | no | Coverage execution (PCs match symbols) |
| `symbols.so` | opt-level=1, unstripped | yes | DWARF source mapping |

### Run coverage with --program-so

```bash
# Fuzz with the optimized binary (fast)
crucible run myproject invariant_test --release --timeout 300 --corpus-out ./corpus

# Generate coverage: load debug.so for execution, symbols.so for DWARF
crucible run myproject invariant_test --release --coverage --corpus-in ./corpus \
  --program-so ./debug.so --symbols ./symbols.so
```

The `--program-so` flag overrides the `.so` that the harness loads into litesvm at runtime, without requiring any harness code changes.

## LCOV format reference

The generated `coverage.lcov` file uses standard LCOV format. This section documents the format and how to programmatically consume it for automated coverage analysis (e.g., in `solana-rag`'s `coverage_analysis` / `coverage_loop` tools).

### File structure

Each source file gets a record block:

```
TN:fuzzer
SF:/absolute/path/to/source_file.rs
FN:<line>,<function_name>
FNDA:<hit_count>,<function_name>
FNF:<functions_found>
FNH:<functions_hit>
DA:<line_number>,<execution_count>
DA:<line_number>,<execution_count>
...
LF:<lines_found>
LH:<lines_hit>
BRDA:<line>,<block>,<branch>,<taken_count>
BRF:<branches_found>
BRH:<branches_hit>
end_of_record
```

**Key record types:**
- `SF:` — absolute path to the source file (only user source files, stdlib/deps filtered out)
- `FN:` / `FNDA:` — function declarations and hit counts
- `DA:<line>,<count>` — line hit data. `count=0` means executable but not reached
- `BRDA:<line>,<block>,<branch>,<taken>` — branch data. `taken=-` means not executed
- `LF:` / `LH:` — total lines found vs hit (for computing line coverage %)

### Source-level vs bytecode-level

| | Source-level (with `--symbols`) | Bytecode-level (without `--symbols`) |
|---|---|---|
| `SF:` paths | Real source files (`programs/stake/src/processor.rs`) | Synthetic (`program_2a54379117d8a106.bpf`) |
| `DA:` line numbers | Actual source line numbers (1-based) | SBF program counter addresses |
| `FN:` names | Demangled Rust function names | `fn_0`, `fn_25`, etc. |
| Useful for | Gap analysis, genhtml, CI reporting | Tracking coverage growth over time |

### Generating source-level LCOV for programmatic analysis

The recommended flow for tools that want to analyze coverage gaps:

```bash
# 1. Fuzz to build corpus (fast, multi-core, no coverage overhead)
crucible run prog test --release -j 4 --timeout 300 --corpus-out ./corpus

# 2. Generate source-level LCOV (single pass over corpus, no mutation)
#    Requires: debug.so (same opt-level as symbols.so) + symbols.so (DWARF)
crucible run prog test --release --coverage --corpus-in ./corpus \
  --program-so ./debug.so \
  --symbols ./symbols.so \
  --lcov-out ./output/coverage.lcov
```

**What happens in step 2:**
1. `FUZZ_COVERAGE_ONLY=1` is set automatically (coverage + corpus-in + no timeout)
2. Each corpus input is replayed once with SVM register tracing enabled
3. PCs from execution are mapped to source locations via DWARF from `--symbols`
4. LCOV is written with real file paths and line numbers

### Parsing LCOV programmatically

Python example (matches `solana-rag`'s `coverage.parse_lcov()`):

```python
def parse_lcov(path: str) -> list[dict]:
    """Returns per-file coverage: source_file, lines_hit, lines_total, hit_pct, uncovered_lines."""
    results = []
    current_file = ""
    lines_hit = lines_total = 0
    uncovered = []

    for line in open(path):
        line = line.strip()
        if line.startswith("SF:"):
            current_file = line[3:]
            lines_hit = lines_total = 0
            uncovered = []
        elif line.startswith("DA:"):
            parts = line[3:].split(",")
            line_no, count = int(parts[0]), int(parts[1])
            lines_total += 1
            if count > 0:
                lines_hit += 1
            else:
                uncovered.append(line_no)
        elif line == "end_of_record" and current_file:
            hit_pct = (lines_hit / lines_total * 100) if lines_total else 0
            results.append({
                "source_file": current_file,
                "lines_hit": lines_hit,
                "lines_total": lines_total,
                "hit_pct": round(hit_pct, 1),
                "uncovered_lines": sorted(uncovered),
            })
            current_file = ""
    return results
```

### Mapping uncovered lines to instructions/functions

Once you have `uncovered_lines` per file, map them to program instructions using the source tree:

1. For each uncovered line range, find which function it belongs to (using `line_start`/`line_end` from the indexed source tree)
2. Group uncovered ranges by function name
3. Use these gaps to decide which actions to add or improve in the fuzz harness

**Example gap output:**
```
processor.rs: StakeInstruction::Merge (lines 412-445) — 0% covered
  → Need action_merge in harness

processor.rs: StakeInstruction::AuthorizeChecked (lines 220-235) — 0% covered
  → Admin-only, intentionally excluded

helpers/delegate.rs: validate_delegated_amount (lines 89-102) — partial
  → Edge case: delegation with lockup not tested
```

### CLI flags summary for coverage

| Flag | Env var | Description |
|------|---------|-------------|
| `--coverage` | `FUZZ_COVERAGE` | Enable LCOV output (sets `COVERAGE_ENABLED`) |
| `--symbols <path>` | `FUZZ_SYMBOLS` | Path to unstripped `.so` with DWARF debug info |
| `--program-so <path>` | `FUZZ_PROGRAM_SO` | Override which `.so` litesvm loads (for coverage with different opt-level) |
| `--lcov-out <path>` | `FUZZ_COVERAGE_OUT` | Custom LCOV output path (default: `coverage.lcov`) |
| `--corpus-in <dir>` | `FUZZ_CORPUS_IN` | Load corpus for replay (with `--coverage`, triggers coverage-only mode) |

**Coverage-only mode** is activated automatically when `--coverage` + `--corpus-in` are both set without `--timeout`. It replays each corpus input once and writes LCOV, then exits.

### Build requirements

| Requirement | Details |
|-------------|---------|
| **platform-tools >= v1.51** | Required for correct DWARF. Use `cargo build-sbf --tools-version v1.51`. See [anza-xyz/llvm-project#159](https://github.com/anza-xyz/llvm-project/pull/159). |
| **`--debug` flag** | Pass to `cargo build-sbf` to set `DW_AT_comp_dir` for source path resolution |
| **`[profile.release]`** | `opt-level = 1, debug = 2, strip = false` in program's `Cargo.toml` |
| **Same build for debug.so + symbols.so** | Both must come from the same `cargo build-sbf` invocation so PCs match |

## Installing lcov and genhtml

```bash
# macOS
brew install lcov

# Ubuntu/Debian
sudo apt install lcov
```
