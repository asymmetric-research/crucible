# Constraint-Check Engine

`--mutate-accounts` turns on deterministic probes for common missing account
checks. During fuzzing, an instruction is probed once per distinct executed path
(its baseline edge trace, so state-conditional checks are still reached). Each
worker dedupes findings by a stable identity `{class}:{program}:{discriminator}`,
where `discriminator` is the IDL-registered instruction discriminator (1 byte for
some native programs, 4 for bincode, 8 for Anchor — **not** a fixed 8-byte prefix,
which would fold variable instruction arguments such as swap amounts into the
identity). The identity is **per (constraint class, instruction)**: it deliberately
does **not** include the mutated account's slot/role or field offset, so the same
class firing on different accounts, at different offsets, or via different executed
paths collapses to a single finding. An instruction therefore yields at most one
finding per probe class — e.g. an instruction that trips both `CC-7.7` and `CC-9.5`
reports 2 findings, not one per (role, path). The specific account and offset are
still recorded in the finding *message* for triage; only the dedup identity is
coarse. (Trade-off: two genuinely independent bugs of the *same* class on the *same*
instruction — e.g. a missing owner check on two different accounts — collapse into
one finding; the message names the account that tripped first, so widen the audit
to the instruction's other same-class accounts when triaging.)

An instruction is probed once per distinct executed path, so it is probed many
times over a campaign and a single probe can surface several findings at once.
Selection reports the highest-priority finding whose identity has **not** already
been reported: repeats collapse to the first, and a lower-priority class is no
longer permanently masked by a higher-priority one reported on an earlier probe —
a later probe surfaces the next unreported class instead. (An instruction reached
on only a single path for the whole campaign is probed just once, so only the top
class from that one probe is reported; reaching it on a second path surfaces the
next.)

> **When to run it.** `--mutate-accounts` is a thoroughness pass, not a long-run
> mode. Use it once normal fuzzing has saturated the corpus (coverage plateaued):
> probing runs an extra baseline transaction per success and hashes its edge trace,
> so throughput drops while the flag is on. Plain fuzzing (no flag) is unaffected.

Findings are reported with labels that identify the suspected missing check.
Replay and tmin re-enable the probes named by crash metadata and keep probing
repeated discriminators until the target finding is hit or the replay finishes.

Crash directories are append-only. If probe gates change between builds, older
mutation crash files can remain in the corpus even when the current engine no
longer reproduces them. Use a fresh crash directory or prune non-reproducing
artifacts before auditing current probe behavior.

> **Migration note (finding-id format changes).** The `mutation_finding_id` format
> has changed twice: the 2026-06-17 change moved from an 8-byte discriminator prefix
> to the registered discriminator length (`{class}:{program}:{registered-disc}`,
> with a `:{role}` suffix at the time), and a later change dropped the `:{role}`
> suffix so the identity is per (class, instruction) — current form
> `{class}:{program}:{registered-disc}`. Crashes produced under an older format carry
> a stale `mutation_finding_id` and may report `reproduces: false` on
> `show --replay` / `run --replay` / `tmin` (most visible for native programs, where
> the discriminator width itself changed, 8 bytes → 1/4). **Regenerate mutation
> crashes after upgrading** by running a fresh `--mutate-accounts` campaign into a
> clean `--crashes-out` directory; the new crashes are self-consistent and dedupe
> correctly. Pre-fix crash corpora are not migrated in place. (Replay/tmin still also
> match coarsely on `account-mutation:{program}:{disc}`, which is unchanged across all
> formats, so instruction-level matching keeps working.)

## Current Default Probes

| Finding label | Probe | What it tests | Common false-positive / blind-spot notes |
|---------------|-------|---------------|------------------------------------------|
| `[CC-1 owner]` | Owner equality | Replays with a load-bearing account's runtime owner changed to an attacker owner. | Can fire on public/read-only data where ownership is irrelevant. Off-curve PDA-like accounts are skipped by default. |
| `[CC-2 sysvar]` | Sysvar identity | Replaces a sysvar meta with a decoy and poisons the canonical sysvar value. | Only handled sysvars are covered; arbitrary non-sysvar key equality is not. |
| `[CC-3 pda-spoof]` | PDA address + owner | Substitutes an off-curve account with a decoy at a wrong address and wrong owner. | Does not prove pure canonical-bump or same-owner derivation bugs. Lamport-only PDA slots may be intentionally flexible. |
| `[CC-4 signer]` | Signer assertion | Clears signer intent or replaces an accepted signer with a valid wrong signer. | Redundant cosigners can look suspicious; payer-as-authority cases are intentionally conservative. |
| `[CC-5 type-tag]` | Discriminator/type tag | Flips registered discriminator bytes and checks whether equivalent effects still occur. | Requires registered schema/discriminator data; raw parsers that ignore discriminators can need manual review. |
| `[CC-7 field-ref]` | Raw pubkey field relation | Substitutes same-class accounts when one account body embeds another account key. | Authorized same-class sibling operations can be benign; singleton classes are skipped. |
| `[CC-7 root-ref]` | Root/child key relation | Substitutes child-like accounts around a singleton/root key relation. | Root-like accounts are usually singleton, so only child-side substitutions are generally useful. |
| `[CC-7 value-ref]` | Referenced value account | Substitutes a referenced value account when the source account embeds its key. | If the referenced account is not read on that path, this can be noisy. |
| `[CC-7.3 bidirectional-ref]` | Mutual/shared-root relation | Breaks a pairwise or shared-root relation between two same-class accounts. | Same-market or admin-authorized sibling swaps can be benign. |
| `[CC-7.7 semantic-swap]` | Same-class semantic swap | Replaces a load-bearing account with another same-class account that has a different embedded-key profile. | Scalar-only relations are out of scope; authorized same-class operations need triage. |
| `[CC-9 authority]` | Direct authority / wrong role | Keeps a valid signature but uses a wrong signer for an account that embeds the expected signer key. | Embedded pubkeys are not always authorities; keys stored as hashes/indexes are not detected. |
| `[CC-9.5 cross-authority]` | Raw shared-field scoped authority | Breaks a shared non-signer pubkey field between same-class accounts. | This is a structural proxy, not a full value-flow oracle; benign shared fields can require triage. |
| `[CC-token fake-mint-owner]` | SPL mint owner | Replays with a mint-shaped account whose runtime owner is not the SPL Token program. | Token-2022 extension accounts are not parsed by the current exact-length SPL parser. |
| `[CC-token fake-account-owner]` | SPL token-account owner | Replays with a token-account-shaped account whose runtime owner is not the SPL Token program. | SPL CPI paths usually self-reject; Token-2022 extension accounts are skipped. |
| `[CC-token wrong-mint]` | SPL token mint relation | Mutates a token account so its `mint` field does not match the mint account passed to the instruction. | Requires both the token account and mint account in the instruction metas. |
| `[CC-token forged-mint-pair]` | Forged matching token+mint pair | Substitutes a token account and mint that match each other while canonical state still references the original mint. | Narrow by design; indirect or cross-instruction mint bindings remain out of scope. |
| `[CC-14 duplicate-account]` | Duplicate account aliasing | Replays with two same-class account metas aliased to the same pubkey and reports divergent outcomes. | Benign aliasing, self-transfers, and idempotent closes need triage; byte-identical pairs are skipped. |
| `[CC-13 forwarded-account]` | Account forwarded into a downstream CPI without validation | Targets accounts the program passed into a CPI in the baseline (resolved from inner instructions); forges a malformed version (wrong owner, then corrupted data) and replays. Fires when the tx still succeeds and does work — the malformed account flowed through unvalidated. | A validating program/CPI rejects the forgery (no finding). Residual FP: a forwarded account whose owner/data genuinely don't matter to the callee (e.g. a by-design-arbitrary transfer recipient); may co-fire with CC-1/CC-5 under a distinct label. |

## Known false positives

The engine **prints every finding** — it does not suppress or demote. Aggressive suppression
risks hiding real bugs (a wrongly-classified finding would simply vanish), so the trade-off here
is to surface everything and let triage dismiss the known patterns below.

- **`[CC-1 owner]` on a program / address-pinned account.** An owner mutation that still succeeds
  on a *deployed program* account (owner is a BPF loader) or any account whose slot is pinned by a
  fixed key / ATA / fixed PDA and whose `.owner` is never read. On mainnet that owner is not
  attacker-settable, so it cannot be exploited. (CC-1 *is* a real bug for an unpinned, data-bearing
  account that the program reads — don't dismiss those.)
- **`[CC-9.5 cross-authority]` on an SPL non-authority window.** A shared 32-byte window between
  two SPL-token-shaped accounts that lands on a non-authority field — e.g. an empty `delegate`
  (≈ offset 77) or other COption/padding/state bytes — rather than a real `owner`/authority. Two
  accounts coincidentally sharing an empty delegate is not a shared authority.

## Excluding an instruction from probes

If a specific instruction only ever produces false positives, a harness author can exclude it from
account-mutation probing — **blanket** across all constraint classes:

```rust
// Per call (registers the instruction type; every send of it is then skipped):
ctx.program(program_id)
    .call(instruction::SomeInstruction { .. })
    .accounts(accounts::SomeInstruction { .. })
    .skip_account_mutation()
    .signers(&[..])
    .send()?;

// Or once, at setup (also covers `send_batch`):
ctx.skip_account_mutation_for(&some_instruction);
```

The exclusion is keyed by the instruction's `(program, discriminator)`, applies to every send
(including `send_batch`), and is silent — a skipped instruction simply yields no findings. It does
not affect replay of pre-existing crashes. (For excluding a single *account* rather than a whole
instruction, see `ctx.mark_owner_unverified(pubkey)` — note that is honored by fewer strategies.)
