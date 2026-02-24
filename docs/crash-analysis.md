# Crash Analysis & Replay

## List all crashes

```bash
crucible show <project>
```

## View crash metadata

```bash
crucible show <project> <crash_file>
```

## Replay crash

```bash
crucible show <project> <crash_file> --replay
```

## Minimize a crash

Crashes often contain unnecessary actions — setup noise that doesn't contribute to the violation. Use `crucible tmin` to reduce a crash to the smallest action sequence that still triggers the same invariant violation:

```bash
# Minimize a single crash
crucible tmin <project> <test_name> <crash_file> --release

# Minimize all crashes for a test
crucible tmin <project> <test_name> --all --release
```

The minimized crash overwrites the original file in place (same filename, updated binary + metadata). Use `crucible show` to view the minimized sequence.

**Algorithm:** Multi-pass forward removal. First, actions after the violation are truncated. Then each remaining action is tried for removal — if the crash still reproduces without it, it's discarded. Passes repeat until no more actions can be removed (convergence), handling cases where removing later actions makes earlier ones removable.

**Example output:**

```
[TMIN] Original: 10 actions
[TMIN] Crash reproduces. Minimizing...
[TMIN] Truncated 2 post-violation actions (violation at index 7)
[TMIN]   [0] send_batch — REMOVED
[TMIN]   [0] borrow — REMOVED
[TMIN]   [0] deposit — KEPT
[TMIN]   [1] flashloan_start — KEPT
[TMIN]   [2] borrow — KEPT
[TMIN]   [3] transfer_account — KEPT
[TMIN]   [4] flashloan_end — KEPT
[TMIN] Pass 2...
[TMIN]   [0] deposit — KEPT
[TMIN]   [1] flashloan_start — KEPT
[TMIN]   [2] borrow — KEPT
[TMIN]   [3] transfer_account — KEPT
[TMIN]   [4] flashloan_end — KEPT
[TMIN] Result: 10 → 5 actions (5 removed)
```
