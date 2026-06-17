<p align="center">
  <img src="assets/crucible_logo.png" alt="Crucible" width="400">
</p>

<p align="center">
  <strong>Coverage-guided fuzzing framework for Solana smart contracts</strong>
</p>

<p align="center">
  Built on <a href="https://github.com/AFLplusplus/LibAFL">LibAFL</a> and <a href="https://github.com/LiteSVM/litesvm">LiteSVM</a> for fast, local transaction simulation with edge-level coverage tracking.
</p>

---

Crucible enables property-based testing and stateful invariant checking for Solana programs through randomly generated action sequences. Define your program's actions, write invariants, and let the fuzzer find violations.

## Performance

Upperbound throughput on small/medium programs with MacBook Pro M3:

| Mode      | 1 core    | 12 cores   | 12 cores, no tracing |
|-----------|-----------|------------|----------------------|
| Stateless | 1,200/s   | 9,600/s    | 22,000/s             |
| Stateful  | 8,200/s   | 67,000/s   | 130,000/s            |


## Features

- **Works on any compiled Solana program.** Coverage comes from sBPF edge tracing on the LiteSVM execution trace, so no source-side instrumentation or program rebuild is required. Standard Anchor/Codama/Shank IDL is sufficient to generate typed call bindings at compile time. See [IDL Code Generation](docs/idl-gen.md). When no IDL available, calling can still be done with `raw_call()`
- **Concise harness API.** TestContext collapses account construction, signing, instruction encoding, and result parsing into one builder chain: `ctx.program(...).call(...).accounts(...).signers(...).send()`. Helpers cover time control (`advance_epoch`, `warp_to_slot`), account creation, and mint setup. Reduces testing boilerplate by 50-70%. See [API Reference](docs/api-reference.md). 
- **Typed-action mutator.** Mutations rewrite typed `Vec<Action>` entries directly. Sequence operations (insert, delete, swap, splice) and parameter rewrites (numeric values biased toward boundaries and declared `#[range(..)]` endpoints) keep every generated input structurally valid. Roughly a 5x improvement in bug discovery rate over `arbitrary`. 
- **Stateless mode.** Each iteration clones the post-setup snapshot and executes a full mutated sequence against it. Coverage feedback is per-sequence: sequences that reach a new edge survive into the corpus. 
- **Stateful mode.** Keeps a coverage-indexed pool of live program states and applies one mutated action at a time, picking up where prior iterations left off. Roughly an order-of-magnitude throughput gain over stateless, at the cost of higher memory use as the pool grows with coverage.
- **Crash triage built in.** Findings are minimized with `crucible tmin` and replayed with `crucible show`. Programs compiled with debug symbols produce LCOV reports viewable with `genhtml`. See [Crash Analysis](docs/crash-analysis.md) and [Coverage Reports](docs/coverage.md).

---

## Quick Start

### Install

From source:

```bash
git clone https://github.com/asymmetric-research/crucible
cd crucible
cargo install --path crates/crucible-fuzz-cli
```

### Initialize a fuzz harness

```bash
crucible init <program_name>
```

Defaults to `fuzz/<program_name>/`

### Run a fuzz test

```bash
crucible run <program_name> <test_name> --release
```

---

## Documentation

| Topic | Description |
|-------|-------------|
| [Getting Started](docs/getting-started.md) | Setup, running, project structure, feature flags |
| [IDL Code Generation](docs/idl-gen.md) | Using `crucible-idl-gen` for standalone harnesses |
| [API Reference](docs/api-reference.md) | TestContext API — program loading, accounts, transactions, RPC cloning, time, oracles |
| [Writing Tests](docs/writing-tests.md) | Fixtures, actions, range constraints, simple & invariant fuzzing, assertion macros |
| [CLI Reference](docs/cli-reference.md) | All `crucible` commands and execution modes |
| [Constraint-Check Engine](docs/constraint-check-engine.md) | `--mutate-accounts` probes, finding labels, replay behavior, false-positive notes |
| [Crash Analysis](docs/crash-analysis.md) | Listing, viewing, replaying, and minimizing crashes |
| [Coverage Reports](docs/coverage.md) | Bytecode & source-level coverage, LCOV, genhtml |
| [Harness Guide](docs/harness-guide.md) | In-depth guide to writing effective fuzz harnesses |

---

## License

Licensed under the [MIT License](LICENSE).
