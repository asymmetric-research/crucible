# Remote Fuzzing Integration

Crucible integrates with the standard driver protocol used by remote fuzzing platforms, allowing it to run as a managed fuzzing engine. The integration is implemented entirely through the `--mode` CLI flag, which translates the driver's operational modes into equivalent Crucible flags and directory conventions.

---

## Quick Start

A minimal remote fuzzing bundle for a Crucible harness needs:

1. The `crucible` binary
2. The compiled fuzz harness (under `fuzz/<program>/`)
3. The program `.so` binary
4. A manifest pointing the standard driver at `crucible run`

```json
{
  "executable_path_in_bundle": "bin/crucible",
  "executable_sub_command": ["run", "myproject", "invariant_test", "--release"],
  "supported_tasks": ["explore", "reproduce", "lineage_cover", "corpus_merge"],
  "coverage": {
    "kind": "lcov",
    "lcov_config": {
      "SourcesPathInBundle": "src/",
      "SourcesOriginalPath": "/build/src/"
    }
  }
}
```

The standard driver appends `--mode <mode>`, `--cores <N>`, and `--max-memory-kib <N>` to the sub-command. Crucible accepts all three. `--max-memory-kib` is parsed but not currently enforced.

---

## How Invocation Works

The driver invokes:

```
<bundle>/bin/crucible run <program> <test> --release --mode <mode> --cores <N> --max-memory-kib <N>
```

Crucible's `--mode` flag translates each mode into native flags before the underlying harness binary is launched. All standard Crucible flags (`--corpus-in`, `--crashes-out`, etc.) can still be passed alongside `--mode` to override defaults.

---

## Operational Modes

### `dry_run`

Validates that the harness can compile, set up, and execute one iteration.

| Aspect | Behavior |
|--------|----------|
| Maps to | `--dry-run` |
| Corpus | None required |
| Output | None |
| Exit code | 0 = OK, non-zero = error |

```bash
crucible run myproject invariant_test --release --mode dry_run
# Equivalent to:
crucible run myproject invariant_test --release --dry-run
```

### `explore`

Primary fuzzing mode. The harness continuously generates and mutates inputs, looking for invariant violations.

| Aspect | Behavior |
|--------|----------|
| Corpus in | `./corpus` (if the directory exists) |
| Corpus out | `./output` |
| Crashes out | `./output` |
| Stop-on-crash | Enabled (exits after first finding) |
| Structured output | `[FUZZ_PULSE]`, `[FUZZ_FINDING]` on stdout; verbose details on stderr |

```bash
crucible run myproject invariant_test --release --mode explore --cores 4
# Equivalent to:
crucible run myproject invariant_test --release \
  --corpus-in ./corpus --corpus-out ./output --crashes-out ./output \
  --stop-on-crash -j 4
```

**Override defaults** by passing flags explicitly:

```bash
# Use a custom corpus directory
crucible run myproject invariant_test --release --mode explore --corpus-in ./seeds

# Custom crashes directory (overrides ./output for crashes)
crucible run myproject invariant_test --release --mode explore --crashes-out ./findings
```

When a crash is found:
1. The crash file (binary input) is written to `./output` (or `--crashes-out`)
2. A `.meta.json` file with the action sequence is written alongside it
3. `[FUZZ_FINDING] reproduces:true summary:<msg>` is emitted
4. The process exits

### `reproduce`

Attempts to replay a known crash to verify it still triggers.

| Aspect | Behavior |
|--------|----------|
| Input | First file found in `./input/` directory |
| Non-reproduction signal | `did not reproduce` printed to stdout |
| Taint diffs | Auto-enabled for rich replay output |

```bash
crucible run myproject invariant_test --release --mode reproduce
# Equivalent to:
crucible run myproject invariant_test --release --replay ./input/<first_file>
```

**Output protocol:**

- If the crash **reproduces**: `[FUZZ_FINDING] reproduces:true summary:<msg>` on stdout, exit code 1
- If the crash **does not reproduce**: `[FUZZ_FINDING] reproduces:false summary:did not reproduce` on stdout, plus the literal string `did not reproduce` on stdout. Exit code 0.

The driver uses the presence of `did not reproduce` (case-sensitive) on stdout to determine reproduction status. The exit code is **not** used for this determination.

### `coverage`

Replays the corpus once and generates an LCOV coverage report.

| Aspect | Behavior |
|--------|----------|
| Maps to | `--coverage --corpus-in ./corpus` |
| Corpus in | `./corpus` |
| LCOV output | `./output/coverage.lcov` |
| Exit code | 0 = success |

```bash
crucible run myproject invariant_test --release --mode coverage
# Equivalent to:
crucible run myproject invariant_test --release \
  --coverage --corpus-in ./corpus --lcov-out ./output/coverage.lcov
```

The LCOV file is in standard LCOV format. For source-level coverage (real file paths and line numbers rather than bytecode PCs), pass `--symbols <path>` pointing to the unstripped debug binary. See [Coverage Reports](coverage.md) for details.

### `corpus_merge`

Merges and deduplicates the corpus, writing the effective (minimized) subset to the output directory.

| Aspect | Behavior |
|--------|----------|
| Corpus in | `./corpus` |
| Output | `./output` (merged corpus files) |
| Method | Greedy set-cover: replays all inputs, keeps minimum set preserving all coverage |
| Exit code | 0 = success |

```bash
crucible run myproject invariant_test --release --mode corpus_merge
# Equivalent to:
crucible run myproject invariant_test --release \
  --corpus-in ./corpus --corpus-out ./output
# (internally runs the cmin greedy set-cover algorithm)
```

The driver checks the number of files in `./output` after execution. Fewer files than in `./corpus` indicates effective merging.

---

## Directory Layout

When running under a remote driver, the working directory is structured by the driver:

```
<workdir>/
├── corpus/        # Input corpus (explore, coverage, corpus_merge)
├── input/         # Single crash file (reproduce mode)
└── output/        # All output: corpus, crashes, coverage.lcov
```

Crucible maps these directories to its native `--corpus-in`, `--corpus-out`, `--crashes-out`, and `--lcov-out` flags.

---

## Structured Output Protocol

Crucible emits structured output that the remote driver parses for status tracking and finding detection.

### `[FUZZ_PULSE]` — Progress Updates

Emitted periodically during `explore` mode (approximately once per second).

```
[FUZZ_PULSE] execs/s:<uint64> corpus_count:<uint64> coverage:<uint64> memory_kib:<uint64>
```

All fields are optional per the protocol. Crucible typically emits a superset:

```
[FUZZ_PULSE] run time: 30s, exec/sec: 1234, corpus: 567, crashes: 0, edges: 1500/65536 (2.3%), memory_kib: 204800
```

The driver extracts `execs/s`, `corpus_count`, `coverage`, and `memory_kib` from any `[FUZZ_PULSE]` line using key-value parsing.

Crucible emits two pulse lines per update:
- **stdout**: spec-compliant `[FUZZ_PULSE] execs/s:N corpus_count:N coverage:N memory_kib:N` (for the driver)
- **stderr**: verbose human-readable line with edges, branches, action stats, etc. (captured as artifact)

### `[FUZZ_FINDING]` — Crash/Violation Discovered

Emitted when an invariant violation is detected.

```
[FUZZ_FINDING] reproduces:true summary:<string>
```

In `explore` mode, this is followed by the crash file being written to the output directory. The process then exits (stop-on-crash is enforced).

In `reproduce` mode, findings go to stdout:
```
[FUZZ_FINDING] reproduces:true summary:Invariant violated: total_supply exceeded cap
[FUZZ_FINDING] reproduces:false summary:did not reproduce
```

### `[FUZZ_ERROR]` — Fatal Error

Emitted when the harness cannot continue (e.g., missing input file, configuration error).

```
[FUZZ_ERROR] <error_message>
```

The driver treats any `[FUZZ_ERROR]` as a fatal failure.

### `did not reproduce`

In `reproduce` mode, if the crash input does not trigger a violation, the literal string `did not reproduce` (case-sensitive) is printed to stdout. This is the driver's detection mechanism — the exit code is not used.

---

## Manifest Configuration Reference

The standard driver manifest is a JSON object:

```json
{
  "executable_path_in_bundle": "bin/crucible",
  "executable_sub_command": ["run", "myproject", "invariant_test", "--release"],
  "supported_tasks": ["explore", "reproduce", "lineage_cover", "corpus_merge"],
  "extra": {
    "FUZZ_VERBOSE": "1",
    "RUST_LOG": "info"
  },
  "coverage": {
    "kind": "lcov",
    "lcov_config": {
      "SourcesPathInBundle": "programs/myproject/src/",
      "SourcesOriginalPath": "/home/builder/programs/myproject/src/"
    }
  }
}
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `executable_path_in_bundle` | Yes | Relative path to the `crucible` binary in the bundle |
| `executable_sub_command` | Yes | Arguments passed before `--mode`, `--cores`, `--max-memory-kib` |
| `supported_tasks` | Yes | Which modes the harness supports |
| `extra` | No | Environment variables set before invocation |
| `coverage.kind` | If coverage | `"lcov"` for Crucible |
| `coverage.lcov_config.SourcesPathInBundle` | If coverage | Path to sources in the bundle (for LCOV path rewriting) |
| `coverage.lcov_config.SourcesOriginalPath` | If coverage | Original source path on the build machine |

### Supported Tasks

| Task | Driver Name | Crucible Mode |
|------|---------------|---------------|
| Explore | `explore` | `--mode explore` |
| Reproduce | `reproduce` | `--mode reproduce` |
| Coverage | `lineage_cover` | `--mode coverage` |
| Corpus merge | `corpus_merge` | `--mode corpus_merge` |

Note: `lineage_cover` in `supported_tasks` maps to `--mode coverage`. The task name differs from the mode name.

### Environment Variables via `extra`

Any key-value pairs in `extra` are set as environment variables. Useful Crucible variables:

| Variable | Description |
|----------|-------------|
| `FUZZ_VERBOSE=1` | Verbose harness output (action stats, state snapshots) |
| `FUZZ_TAINT_DIFFS=1` | Enable byte-level account diffs in crash metadata |
| `FUZZ_STATS_CSV=stats.csv` | Write per-second fuzzing stats to CSV |

---

## Building a Remote Fuzzing Bundle

A typical bundle layout:

```
bundle/
├── bin/
│   └── crucible                          # CLI binary
├── fuzz/
│   └── myproject/
│       ├── Cargo.toml
│       ├── src/main.rs                   # Harness code
│       ├── idls/myproject.json           # Program IDL
│       └── target/release/myproject_fuzz # Compiled harness binary
├── target/
│   └── deploy/myproject.so              # Program binary (loaded by harness)
├── programs/
│   └── myproject/src/                   # Source files (for LCOV path mapping)
└── manifest.json                        # Standard driver config
```

### Build Steps

```bash
# 1. Build the program binary
cd /path/to/program
cargo build-sbf

# 2. Build the fuzz harness
cd fuzz/myproject
cargo build --release --features invariant_test

# 3. Build the crucible CLI
cd /path/to/crucible
cargo build --release -p crucible-fuzz-cli

# 4. Assemble the bundle
mkdir -p bundle/bin bundle/fuzz/myproject bundle/target/deploy bundle/programs/myproject/src
cp target/release/crucible bundle/bin/
cp -r fuzz/myproject/ bundle/fuzz/myproject/
cp target/deploy/myproject.so bundle/target/deploy/
cp -r programs/myproject/src/ bundle/programs/myproject/src/
```

---

## CLI Flags Accepted from Driver

The standard driver appends these flags to every invocation:

| Flag | Source | How Crucible Handles It |
|------|--------|------------------------|
| `--mode <mode>` | Driver | Translated into native Crucible flags (see mode table above) |
| `--cores <N>` | Driver | Passed to `-j N` for multi-core fuzzing |
| `--max-memory-kib <N>` | Driver | Parsed and accepted; **not enforced** (no memory limit applied) |

All three are defined as clap arguments on `crucible run` and will not cause parse errors.

---

## Exit Codes

| Mode | Exit 0 | Non-zero |
|------|--------|----------|
| `dry_run` | Setup OK | Setup failed |
| `explore` | Crash found and written | Build/runtime error |
| `reproduce` | Did not reproduce (check stdout for `did not reproduce`) | Crash reproduced, or input read error |
| `coverage` | LCOV written | Corpus missing or build error |
| `corpus_merge` | Merged corpus written | Corpus missing or build error |

Note: In `reproduce` mode, the exit code is **not** used to determine reproduction status. The driver checks for the string `did not reproduce` on stdout. Exit 0 = did not reproduce, exit 1 = crash reproduced (the inner harness returns 1 on reproduction, and the CLI passes it through without treating it as an error).

---

## Differences from Standalone Usage

When running under a remote driver (`--mode` set), Crucible behaves slightly differently:

| Behavior | Standalone | Remote |
|----------|-----------|----------|
| Corpus directory | User-specified or `fuzz/<prog>/corpus/` | `./corpus` (CWD-relative) |
| Crash directory | `fuzz/<prog>/crashes/<test>/` | `./output` |
| Coverage output | `coverage.lcov` in fuzz target dir | `./output/coverage.lcov` |
| Stop-on-crash | Off by default | Always on in `explore` |
| Taint diffs on replay | Auto-enabled | Auto-enabled |

Explicit flags always override mode defaults (e.g., `--mode explore --crashes-out ./custom` uses `./custom` instead of `./output`).
