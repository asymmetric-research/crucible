# CLI Reference

## `crucible init`

```bash
crucible init <program_name> [-C <HARNESS_DIR>]
```

Creates a standalone fuzz workspace in `fuzz/<program_name>/` by default, or directly in `-C/--harness-dir`.

## `crucible run`

```bash
crucible run <program_name> <test_name> [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--binary-in <PATH>` | Run a prebuilt harness binary directly |
| `--release` | Build in release mode (recommended) |
| `--coverage` | Enable coverage reporting |
| `--timeout <SECS>` | Stop after N seconds |
| `--cores N` / `-j N` | Run N parallel fuzzer workers |
| `--corpus-in <DIR>` | Load seed corpus from directory |
| `--corpus-out <DIR>` | Write corpus to directory |
| `--crashes-out <DIR>` | Custom crash output directory |
| `--replay <FILE>` | Replay a single input file |
| `--dry-run` | Validate setup without fuzzing |
| `--seed <N>` | Random seed for reproducible fuzzing |
| `--symbols <PATH>` | Path to debug binary with DWARF symbols (for source-level coverage) |
| `--no-tracing` | Disable SVM register tracing (~2x faster, no coverage) |
| `--mutate-accounts` | Enable the constraint-check engine (account-mutation probes for missing security checks; see [Constraint-Check Engine](constraint-check-engine.md)) |
| `--stop-on-crash` | Stop fuzzing on first crash |
| `--max-actions <N>` | Max actions per iteration (default: 8 stateless, 100 stateful) |
| `--stateful` | Stateful fuzzing: single action per iteration with state pool |
| `--max-depth <N>` | Maximum state depth (action chain length) in stateful mode (default: 15) |
| `--pool-size <N>` | State pool capacity in stateful mode (default: 256000). Also scales the fingerprint-dedup keyspace, so a larger pool raises the distinct-state ceiling |
| `--program-so <PATH>` | Override the program `.so` loaded by the harness |
| `--mode <MODE>` | Remote fuzzing operational mode (see [Remote Fuzzing Integration](remote-fuzzing.md)) |
| `--lcov-out <PATH>` | Custom LCOV coverage output file path |

**Examples:**

```bash
# Basic fuzzing
crucible run myproject invariant_test --release --timeout 60

# Run a prebuilt harness directly
crucible run myproject invariant_test --binary-in ./fuzz/myproject/target/release/invariant_test

# Multi-core fuzzing (4 workers)
crucible run myproject invariant_test --release -j 4

# Coverage report
crucible run myproject invariant_test --release --coverage --timeout 120

# Coverage with custom output path
crucible run myproject invariant_test --release --coverage --lcov-out ./output/coverage.lcov

# Custom harness directory
crucible run myproject invariant_test -C ./custom-harness --release

# Dry-run validation
crucible run myproject invariant_test --dry-run

# Replay a crash
crucible run myproject invariant_test --replay ./crashes/invariant_test/abc123

# Reproducible fuzzing
crucible run myproject invariant_test --release --seed 12345

# Stateful mode
crucible run myproject invariant_test --release --stateful

# Stateful with custom depth and multi-core
crucible run myproject invariant_test --release --stateful --max-depth 20 -j 4
```

**Environment variables:**

| Variable | Description |
|----------|-------------|
| `FUZZ_VERBOSE=1` | Enable verbose harness output |
| `FUZZ_STATS_CSV=<path>` | Write per-second stats to CSV file for benchmarking |

## `crucible list`

```bash
crucible list <program_name>   # List tests for a program
crucible list -C ./fuzz/myproject  # List tests from a harness dir
crucible list                  # List all fuzz harnesses
```

## `crucible show`

```bash
crucible show <program>                                    # List all crashes
crucible show <program> <crash_file>                       # View metadata
crucible show <program> <crash_file> --replay              # Replay crash
crucible show <program> --crashes-dir <DIR>                # List crashes from custom dir
crucible show <program> <crash_file> --crashes-dir <DIR>   # View metadata from custom dir
crucible show . <crash_file>                               # Auto-detect from current dir
```

Use `"."` as the program name to auto-detect the fuzz harness when running from within the fuzz directory.

`-C/--harness-dir` is a global option for locating a custom harness directory on `init`, `run`, `list`, `show`, `tmin`, and `cmin`.

| Flag | Description |
|------|-------------|
| `--replay` | Actually replay the crash by running the binary |
| `--regen` | Regenerate crash metadata (requires `--replay`) |
| `--crashes-dir <DIR>` | Custom crashes directory to read from (supports flat and nested layouts) |

## `crucible cmin`

Minimize corpus to smallest set preserving all coverage.

```bash
crucible cmin <program> <test> <corpus_dir> --release
crucible cmin <program> <test> <corpus_dir> --corpus-out ./corpus_min --release
crucible cmin <program> <test> --corpus-in <DIR> --release
```

| Flag | Description |
|------|-------------|
| `--release` | Build in release mode |
| `--corpus-in <DIR>` | Input corpus directory (alternative to positional arg) |
| `--corpus-out <DIR>` | Output directory (default: overwrite input) |

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
3. **Input Replay** (`--replay`) - Execute one specific input file
4. **Coverage-Only** (`--coverage --corpus-in`) - Run corpus once for coverage report
5. **Seeded Fuzzing** (`--corpus-in`) - Start from pre-existing corpus
6. **Multi-Core** (`--cores N`) - Parallel fuzzer workers with shared coverage
7. **Stateful** (`--stateful`) - Single action per iteration with state pool
8. **Corpus Minimization** (`crucible cmin`) - Reduce corpus to minimal set preserving coverage
9. **Crash Minimization** (`crucible tmin`) - Reduce crash to minimal reproducing action sequence

### Stateful Mode

Stateful mode (`--stateful`) uses a state-pool approach where each fuzzer iteration executes a **single action** on a state selected from a pool, rather than replaying an entire action sequence from scratch.

- States form a tree: each state has a parent and a depth (action chain length)
- New states are created by applying an action to an existing state
- The state pool is bounded; states are evicted based on coverage novelty
- `--max-depth <N>` controls maximum chain length (default: 100)
- Works with both single-core and multi-core (`-j N`)
- Crashes record the full action chain from root to violation

```bash
# Basic stateful fuzzing
crucible run myproject invariant_test --release --stateful

# With custom depth limit
crucible run myproject invariant_test --release --stateful --max-depth 50

# Multi-core stateful
crucible run myproject invariant_test --release --stateful -j 4
```

---

## Constraint-Check Engine (`--mutate-accounts`)

`--mutate-accounts` enables deterministic account-mutation probes for common
missing account checks. During fuzzing, an instruction is probed once per distinct
executed path (its baseline edge trace), so a check that only applies in some
states is still exercised. Findings use stable labels and can be inspected,
replayed, and minimized with the usual `crucible show` and `crucible tmin` flows.

> **When to use it.** `--mutate-accounts` is a thoroughness pass, not a mode for
> long campaigns. Run it after normal fuzzing has saturated the corpus (coverage
> plateaued): every successful transaction runs an extra baseline probe and hashes
> its edge trace, so throughput drops. Normal fuzzing (without the flag) is
> unaffected.

See [Constraint-Check Engine](constraint-check-engine.md) for the current probe
table, replay behavior, crash-corpus notes, and common false positives.

```bash
# Find missing-check bugs while fuzzing
crucible run myproject invariant_test --release --mutate-accounts --timeout 60

# Findings are normal crashes - inspect / replay / minimize as usual
crucible show myproject <crash_id>
crucible show myproject <crash_id> --replay
```

---

## Remote Fuzzing Integration

For running Crucible as a managed engine on a remote fuzzing platform, see the dedicated **[Remote Fuzzing Integration Guide](remote-fuzzing.md)** covering:

- All five operational modes (`dry_run`, `explore`, `reproduce`, `coverage`, `corpus_merge`)
- Directory conventions (`./corpus`, `./input`, `./output`)
- Structured output protocol (`[FUZZ_PULSE]`, `[FUZZ_FINDING]`, `[FUZZ_ERROR]`)
- Bundle layout and manifest configuration
- Exit code semantics per mode
