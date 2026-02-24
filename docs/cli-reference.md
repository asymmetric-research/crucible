# CLI Reference

## `crucible init`

```bash
crucible init <program_name>
```

Creates a standalone fuzz workspace in `fuzz/<program_name>/`.

## `crucible run`

```bash
crucible run <program_name> <test_name> [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--release` | Build in release mode (recommended) |
| `--coverage` | Enable LCOV coverage output |
| `--timeout <SECS>` | Stop after N seconds |
| `--cores N` / `-j N` | Run N parallel fuzzer workers |
| `--corpus-in <DIR>` | Load seed corpus from directory |
| `--corpus-out <DIR>` | Write corpus to directory |
| `--crashes-dir <DIR>` | Custom crash output directory |
| `--input <FILE>` | Replay a single input file |
| `--dry-run` | Validate setup without fuzzing |
| `--seed <N>` | Random seed for reproducible fuzzing |
| `--symbols <PATH>` | Path to debug binary with DWARF symbols (for source-level coverage) |
| `--no-tracing` | Disable SVM register tracing (~2x faster, no coverage) |
| `--stop-on-crash` | Stop fuzzing on first crash |
| `--max-actions <N>` | Max actions per iteration (default: 10) |
| `--taint` | Track per-action read/write account sets |
| `--taint-diffs` | Track per-action byte-level account diffs (implies `--taint`) |

**Examples:**

```bash
# Basic fuzzing
crucible run myproject invariant_test --release --timeout 60

# Multi-core fuzzing (4 workers)
crucible run myproject invariant_test --release -j 4

# Coverage report
crucible run myproject invariant_test --release --coverage --timeout 120

# Dry-run validation
crucible run myproject invariant_test --dry-run

# Replay a crash
crucible run myproject invariant_test --input ./crashes/invariant_test/abc123

# Reproducible fuzzing
crucible run myproject invariant_test --release --seed 12345
```

**Environment variables:**

| Variable | Description |
|----------|-------------|
| `FUZZ_VERBOSE=1` | Enable verbose harness output |
| `FUZZ_TAINT=1` | Track per-action read/write account sets |
| `FUZZ_TAINT_DIFFS=1` | Track per-action byte-level account diffs (implies taint) |

## `crucible list`

```bash
crucible list <program_name>   # List tests for a program
crucible list                  # List all fuzz harnesses
```

## `crucible show`

```bash
crucible show <program>                       # List all crashes
crucible show <program> <crash_file>          # View metadata
crucible show <program> <crash_file> --replay # Replay crash
```

## `crucible cmin`

Minimize corpus to smallest set preserving all coverage.

```bash
crucible cmin <program> <test> <corpus_dir> --release
crucible cmin <program> <test> <corpus_dir> --corpus-out ./corpus_min --release
```

## `crucible tmin`

Minimize a crash to the smallest action sequence that still reproduces the violation.

```bash
crucible tmin <program> <test> <crash_file> [OPTIONS]
crucible tmin <program> <test> --all [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--release` | Build in release mode |
| `--all` | Minimize all crashes for this test |

Only works with structured/invariant tests (action sequences). Overwrites crash files in place.

```bash
# Minimize a single crash
crucible tmin myproject invariant_test crash_abc123 --release

# Minimize all crashes
crucible tmin myproject invariant_test --all --release
```

---

## Execution Modes

1. **Normal Fuzzing** (default) - Continuous input generation and mutation
2. **Dry-Run** (`--dry-run`) - Single iteration to validate harness setup
3. **Input Replay** (`--input`) - Execute one specific input file
4. **Coverage-Only** (`--coverage --corpus-in`) - Run corpus once for coverage report
5. **Seeded Fuzzing** (`--corpus-in`) - Start from pre-existing corpus
6. **Multi-Core** (`--cores N`) - Parallel fuzzer workers with shared coverage
7. **Corpus Minimization** (`crucible cmin`) - Reduce corpus to minimal set preserving coverage
8. **Crash Minimization** (`crucible tmin`) - Reduce crash to minimal reproducing action sequence
9. **Taint Diffs** (`--taint-diffs`) - Track per-action byte-level account mutations
