# Constraint-Check Engine

`--mutate-accounts` turns on deterministic probes for common missing account
checks. During fuzzing, probes run when an action/instruction shape first
completes. Each worker then dedupes that shape, keyed by program id plus the
first 8 instruction-data bytes, so later states for the same shape may not be
probed in the same run.

Findings are reported with labels that identify the suspected missing check.
Replay and tmin re-enable the probes named by crash metadata and keep probing
repeated discriminators until the target finding is hit or the replay finishes.

Crash directories are append-only. If probe gates change between builds, older
mutation crash files can remain in the corpus even when the current engine no
longer reproduces them. Use a fresh crash directory or prune non-reproducing
artifacts before auditing current probe behavior.

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
