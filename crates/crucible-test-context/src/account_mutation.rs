use crate::{record_mutation_violation, FastHashSet};
use anchor_lang::prelude::sysvar::SysvarId;
use anchor_lang::prelude::{Clock, EpochSchedule, SlotHashes, SlotHistory, StakeHistory};
use anchor_lang::solana_program::instruction::Instruction;
use anyhow::Result;
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::{legacy::Message, VersionedMessage};
use solana_pubkey::{bytes_are_curve_point, Pubkey};
use solana_signer::Signer;
use solana_sysvar::epoch_rewards::EpochRewards;
#[allow(deprecated)]
use solana_sysvar::fees::Fees;
use solana_sysvar::last_restart_slot::LastRestartSlot;
#[allow(deprecated)]
use solana_sysvar::recent_blockhashes::RecentBlockhashes;
use solana_transaction::versioned::VersionedTransaction;
use std::cell::RefCell;

const DEFAULT_SKIP_PDA_CANDIDATES: bool = true;

/// Wrong owner written by the owner-mutation strategy. A recognizable, non-executable key
/// that no legitimate program could own, so a surviving mutation means the owner was never
/// checked — never a blur of several possible causes.
const CRUCIBLE_ATTACKER: Pubkey = Pubkey::new_from_array([0xCC; 32]);
/// Fallback used in the unlikely case an account is already owned by [`CRUCIBLE_ATTACKER`],
/// so the mutation is always a real change.
const CRUCIBLE_ATTACKER_ALT: Pubkey = Pubkey::new_from_array([0xCD; 32]);

/// Replacement address used by the substitution strategies (CC-2 sysvar, CC-3 PDA). A clone of the
/// target account is planted here and the instruction's account meta is repointed to it, so only the
/// address differs — a surviving success means the account's identity was never verified.
const CRUCIBLE_DECOY: Pubkey = Pubkey::new_from_array([0xDD; 32]);
const CRUCIBLE_DECOY_ALT: Pubkey = Pubkey::new_from_array([0xDE; 32]);

fn decoy_for(target: Pubkey) -> Pubkey {
    if target == CRUCIBLE_DECOY {
        CRUCIBLE_DECOY_ALT
    } else {
        CRUCIBLE_DECOY
    }
}

/// Clone the instructions, repointing every `AccountMeta` for `target` at `decoy`.
fn rewrite_account(
    instructions: &[Instruction],
    target: Pubkey,
    decoy: Pubkey,
) -> Vec<Instruction> {
    instructions
        .iter()
        .map(|ix| {
            let mut ix = ix.clone();
            for meta in &mut ix.accounts {
                if meta.pubkey == target {
                    meta.pubkey = decoy;
                }
            }
            ix
        })
        .collect()
}

/// Plant a clone of `target`'s account at `decoy`, repoint the metas, and replay. Returns true iff the
/// substituted transaction still succeeds (identity not verified). `target` must not be a signer
/// (PDAs and sysvars never are), so signers/payer are unaffected.
fn substitute_probe(ctx: &ProbeCtx, target: Pubkey, decoy: Pubkey) -> bool {
    let mut probe = ctx.svm.clone();
    let Some(account) = probe.get_account(&target) else {
        return false;
    };
    if probe.set_account(decoy, account).is_err() {
        return false;
    }
    let rewritten = rewrite_account(ctx.instructions, target, decoy);
    probe_matches_baseline_effects(ctx, &mut probe, &rewritten, &[(target, decoy)], &[])
}

thread_local! {
    /// Instruction types whose mutation battery already ran this run (per worker). The key is
    /// `(program_id, 8-byte discriminator)`. This persists for the whole run — it is *not*
    /// cleared between iterations — so each instruction type is probed at most once per worker.
    static PROBED_IX_TYPES: RefCell<FastHashSet<ProbeKey>> = RefCell::new(FastHashSet::default());
}

type ProbeKey = (Pubkey, [u8; 8]);

/// Reset the per-run probed-instruction set. Intended for in-process tests that drive several
/// harness runs within one process; the fuzzer itself starts each worker process fresh.
pub fn reset_probed_account_mutations() {
    PROBED_IX_TYPES.with(|s| s.borrow_mut().clear());
}

#[derive(Clone, Debug)]
pub struct AccountMutationConfig {
    enabled: bool,
    skip_pda_candidates: bool,
    unverified_accounts: FastHashSet<Pubkey>,
}

impl Default for AccountMutationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            skip_pda_candidates: DEFAULT_SKIP_PDA_CANDIDATES,
            unverified_accounts: FastHashSet::default(),
        }
    }
}

impl AccountMutationConfig {
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }

    pub fn set_skip_pda_candidates(&mut self, skip_pda_candidates: bool) {
        self.skip_pda_candidates = skip_pda_candidates;
    }

    pub fn mark_unverified(&mut self, pubkey: Pubkey) {
        self.unverified_accounts.insert(pubkey);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn skip_pda_candidates(&self) -> bool {
        self.skip_pda_candidates
    }
}

/// Default config, enabling probes when `FUZZ_MUTATE_ACCOUNTS` is set. The CLI `--mutate-accounts`
/// flag sets this env var, and replay propagates it for mutation-finding crashes, so every
/// execution mode (single/multi-core, stateful, replay) picks it up without per-mode codegen.
pub(crate) fn config_from_env() -> AccountMutationConfig {
    let mut config = AccountMutationConfig::default();
    if std::env::var("FUZZ_MUTATE_ACCOUNTS").is_ok() {
        config.enable();
    }
    config
}

/// A single self-documenting finding: one constraint class, one account, one mutated transaction
/// that still succeeded.
struct Finding {
    id: String,
    message: String,
}

/// Inputs shared by every strategy. Borrows the pre-transaction (baseline) SVM, which is never
/// mutated — strategies clone it for each probe.
struct ProbeCtx<'a> {
    svm: &'a LiteSVM,
    baseline_after: &'a LiteSVM,
    instructions: &'a [Instruction],
    signers: &'a [&'a Keypair],
    payer: &'a Keypair,
    sigverify: bool,
    config: &'a AccountMutationConfig,
}

/// One isolated constraint-class probe. Each strategy owns exactly one oracle and one finding
/// label, so a finding names the missing check unambiguously. New constraint classes (signer,
/// sysvar-switch, arbitrary-program, field cross-reference, ...) are added as new strategies
/// without touching the call sites.
trait MutationStrategy {
    fn probe(&self, ctx: &ProbeCtx) -> Vec<Finding>;
}

fn enabled_strategies(_config: &AccountMutationConfig) -> Vec<Box<dyn MutationStrategy>> {
    vec![
        Box::new(PdaSubstitutionStrategy),
        Box::new(SysvarSubstitutionStrategy),
        Box::new(OwnerStrategy),
        Box::new(SignerStrategy),
        Box::new(TypeTagStrategy),
    ]
}

/// `(program_id, first 8 bytes of instruction data)` — the identity used to probe each
/// instruction type at most once. Data shorter than 8 bytes is zero-padded.
fn probe_key(ix: &Instruction) -> ProbeKey {
    let mut disc = [0u8; 8];
    let n = ix.data.len().min(8);
    disc[..n].copy_from_slice(&ix.data[..n]);
    (ix.program_id, disc)
}

fn disc_hex(ix: &Instruction) -> String {
    let n = ix.data.len().min(8);
    ix.data[..n].iter().map(|b| format!("{b:02x}")).collect()
}

fn finding_id(class: &str, ix: &Instruction) -> String {
    format!("{class}:{}:{}", ix.program_id, disc_hex(ix))
}

pub(crate) fn maybe_probe_account_mutation(
    svm: &LiteSVM,
    config: &AccountMutationConfig,
    instructions: &[Instruction],
    signers: &[&Keypair],
    payer: &Keypair,
    sigverify: bool,
) {
    if !config.enabled || instructions.is_empty() {
        return;
    }

    // Probe each instruction type only once per run. Multi-instruction transactions are keyed by
    // their first instruction.
    let key = probe_key(&instructions[0]);
    if PROBED_IX_TYPES.with(|s| s.borrow().contains(&key)) {
        return;
    }

    // Baseline gate: the unmutated transaction must succeed first, otherwise a surviving mutation
    // tells us nothing. Run it on a clone so the live SVM is untouched.
    let mut baseline = svm.clone();
    match send_probe_transaction(&mut baseline, instructions, signers, payer, sigverify) {
        Ok(Ok(_)) => {}
        // Don't burn the key on a failed baseline — a later occurrence (in a different state) may
        // have a succeeding baseline and deserve a probe.
        _ => return,
    }
    PROBED_IX_TYPES.with(|s| {
        s.borrow_mut().insert(key);
    });

    let ctx = ProbeCtx {
        svm,
        baseline_after: &baseline,
        instructions,
        signers,
        payer,
        sigverify,
        config,
    };

    let findings: Vec<Finding> = enabled_strategies(config)
        .iter()
        .flat_map(|s| s.probe(&ctx))
        .collect();

    // The violation TLS holds one message per iteration and the harness early-exits on the first.
    // Replay/tmin may set an expected finding id so earlier, unrelated mutation bugs in the same
    // action sequence do not mask the original crash class.
    let expected = crate::expected_mutation_finding_id();
    let selected = match expected.as_deref() {
        Some(id) => findings.iter().find(|finding| finding.id == id),
        None => findings.first(),
    };

    if let Some(first) = selected {
        record_mutation_violation(first.message.clone(), first.id.clone());
        if std::env::var("FUZZ_DEBUG").is_ok() {
            for extra in findings.iter().filter(|extra| extra.id != first.id) {
                eprintln!("[ACCOUNT_MUTATION] additional finding: {}", extra.message);
            }
        }
    } else if expected.is_some() && !findings.is_empty() && std::env::var("FUZZ_DEBUG").is_ok() {
        eprintln!(
            "[ACCOUNT_MUTATION] ignored {} finding(s) while waiting for replay target {:?}",
            findings.len(),
            expected
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnerCandidate {
    pubkey: Pubkey,
    original_owner: Pubkey,
}

/// CC-1: an account the program reads (deserializes) without verifying its owner. Mutating the
/// owner to a sentinel and still succeeding means the owner check is missing.
struct OwnerStrategy;

impl MutationStrategy for OwnerStrategy {
    fn probe(&self, ctx: &ProbeCtx) -> Vec<Finding> {
        let mut findings = Vec::new();
        for candidate in collect_owner_candidates(ctx.svm, ctx.instructions, ctx.config) {
            // Relevance gate first: if the program never reads this account's data, spoofing its
            // owner gains an attacker nothing — skip it to avoid false positives.
            if !account_is_load_bearing(ctx, &candidate.pubkey) {
                continue;
            }

            let sentinel = wrong_owner(candidate.original_owner);
            let mut probe = ctx.svm.clone();
            let Some(mut account) = probe.get_account(&candidate.pubkey) else {
                continue;
            };
            account.owner = sentinel;
            let _ = probe.set_account(candidate.pubkey, account);

            if probe_matches_baseline_effects(
                ctx,
                &mut probe,
                ctx.instructions,
                &[],
                &[candidate.pubkey],
            ) {
                findings.push(Finding {
                    id: finding_id("CC-1 owner", &ctx.instructions[0]),
                    message: format!(
                        "[CC-1 owner] account {} owner {}->{} instr {}:{} still succeeded after owner mutation",
                        candidate.pubkey,
                        candidate.original_owner,
                        sentinel,
                        ctx.instructions[0].program_id,
                        disc_hex(&ctx.instructions[0]),
                    ),
                });
            }
        }
        findings
    }
}

fn wrong_owner(original_owner: Pubkey) -> Pubkey {
    if original_owner == CRUCIBLE_ATTACKER {
        CRUCIBLE_ATTACKER_ALT
    } else {
        CRUCIBLE_ATTACKER
    }
}

/// CC-5: an account the program deserializes by type but whose discriminator (type tag) it never
/// verifies — type confusion. Bit-flipping the discriminator and still succeeding means the program
/// trusts the account's type without checking it. The discriminator length comes from the IDL schema
/// registry, so this is correct for Anchor (8-byte), native (4-byte), and Codama programs; accounts
/// with no registered discriminator are skipped (we never guess a tag width).
struct TypeTagStrategy;

impl MutationStrategy for TypeTagStrategy {
    fn probe(&self, ctx: &ProbeCtx) -> Vec<Finding> {
        let mut findings = Vec::new();
        for pubkey in collect_typed_candidates(ctx.svm, ctx.instructions) {
            // Relevance gate: an account the program never reads is not exploitable.
            if !account_is_load_bearing(ctx, &pubkey) {
                continue;
            }
            let mut probe = ctx.svm.clone();
            let Some(mut account) = probe.get_account(&pubkey) else {
                continue;
            };
            let Some(disc_len) = crate::schema::lookup_discriminator_len(&account.data) else {
                continue;
            };
            if account.data.len() < disc_len {
                continue;
            }
            for b in account.data[..disc_len].iter_mut() {
                *b = !*b; // flip the type tag; body left intact
            }
            let _ = probe.set_account(pubkey, account);

            if probe_matches_baseline_effects(ctx, &mut probe, ctx.instructions, &[], &[pubkey]) {
                findings.push(Finding {
                    id: finding_id("CC-5 type-tag", &ctx.instructions[0]),
                    message: format!(
                        "[CC-5 type-tag] account {} discriminator bit-flipped, instr {}:{} still succeeded (missing discriminator check)",
                        pubkey,
                        ctx.instructions[0].program_id,
                        disc_hex(&ctx.instructions[0]),
                    ),
                });
            }
        }
        findings
    }
}

/// CC-5 targets: any data-bearing, non-executable, non-sysvar account whose data matches a registered
/// discriminator (a typed account). PDAs are intentionally included — Anchor state accounts are PDAs
/// and are the prime type-confusion targets.
fn collect_typed_candidates(svm: &LiteSVM, instructions: &[Instruction]) -> Vec<Pubkey> {
    let mut seen = FastHashSet::default();
    let mut candidates = Vec::new();
    for ix in instructions {
        for meta in &ix.accounts {
            if !seen.insert(meta.pubkey) {
                continue;
            }
            if meta.pubkey == ix.program_id || is_known_sysvar(&meta.pubkey) {
                continue;
            }
            let Some(account) = svm.get_account(&meta.pubkey) else {
                continue;
            };
            if account.executable || account.data.is_empty() {
                continue;
            }
            if crate::schema::lookup_discriminator_len(&account.data).is_some() {
                candidates.push(meta.pubkey);
            }
        }
    }
    candidates
}

/// CC-4: an account whose signature is meant to authorize the action but whose `is_signer` flag is
/// never enforced by the program. Clearing the flag and still succeeding means the signer check is
/// missing. If the harness supplied a signer keypair for an account that was not marked signer in
/// the instruction metas, a succeeding baseline is also a missing-signer finding: the program
/// accepted the action without the signature the harness author intended. The fee payer is skipped
/// because it must sign for transaction fees.
struct SignerStrategy;

impl MutationStrategy for SignerStrategy {
    fn probe(&self, ctx: &ProbeCtx) -> Vec<Finding> {
        let mut findings = Vec::new();
        let payer = ctx.payer.pubkey();
        for candidate in signer_candidates(ctx.instructions, ctx.signers) {
            if candidate.pubkey == payer {
                continue;
            }
            let flipped = clear_signer(ctx.instructions, candidate.pubkey);
            let mut probe = ctx.svm.clone();
            if probe_matches_baseline_effects(ctx, &mut probe, &flipped, &[], &[]) {
                let detail = match candidate.kind {
                    SignerCandidateKind::MetaSigner => "is_signer cleared",
                    SignerCandidateKind::SuppliedSigner => {
                        "signer keypair supplied but account meta was not signer"
                    }
                };
                findings.push(Finding {
                    id: finding_id("CC-4 signer", &ctx.instructions[0]),
                    message: format!(
                        "[CC-4 signer] account {} {}, instr {}:{} still succeeded (missing signer check)",
                        candidate.pubkey,
                        detail,
                        ctx.instructions[0].program_id,
                        disc_hex(&ctx.instructions[0]),
                    ),
                });
            }
        }
        findings
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignerCandidateKind {
    MetaSigner,
    SuppliedSigner,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SignerCandidate {
    pubkey: Pubkey,
    kind: SignerCandidateKind,
}

/// Distinct signer-intent pubkeys in first-seen order. Instruction metas are authoritative, but
/// harness-supplied signer keypairs are also treated as intent when their pubkey appears as an
/// account in the instruction. This covers IDL/native harnesses where the builder had a keypair but
/// the account meta forgot to carry `is_signer`.
fn signer_candidates(instructions: &[Instruction], signers: &[&Keypair]) -> Vec<SignerCandidate> {
    let mut seen = FastHashSet::default();
    let mut candidates = Vec::new();
    let mut account_pubkeys = FastHashSet::default();
    for ix in instructions {
        for meta in &ix.accounts {
            account_pubkeys.insert(meta.pubkey);
            if meta.is_signer && seen.insert(meta.pubkey) {
                candidates.push(SignerCandidate {
                    pubkey: meta.pubkey,
                    kind: SignerCandidateKind::MetaSigner,
                });
            }
        }
    }
    for signer in signers {
        let pubkey = signer.pubkey();
        if account_pubkeys.contains(&pubkey) && seen.insert(pubkey) {
            candidates.push(SignerCandidate {
                pubkey,
                kind: SignerCandidateKind::SuppliedSigner,
            });
        }
    }
    candidates
}

/// Clone the instructions, clearing `is_signer` for every occurrence of `target`.
fn clear_signer(instructions: &[Instruction], target: Pubkey) -> Vec<Instruction> {
    instructions
        .iter()
        .map(|ix| {
            let mut ix = ix.clone();
            for meta in &mut ix.accounts {
                if meta.pubkey == target {
                    meta.is_signer = false;
                }
            }
            ix
        })
        .collect()
}

/// CC-3: an account expected to be a specific PDA whose derivation the program never verifies.
/// Substituting a clone at a different address and still succeeding means the address went unchecked.
struct PdaSubstitutionStrategy;

impl MutationStrategy for PdaSubstitutionStrategy {
    fn probe(&self, ctx: &ProbeCtx) -> Vec<Finding> {
        let mut findings = Vec::new();
        for target in collect_pda_candidates(ctx.svm, ctx.instructions, ctx.config) {
            if !account_is_identity_relevant(ctx, &target) {
                continue;
            }
            let decoy = decoy_for(target);
            if substitute_probe(ctx, target, decoy) {
                findings.push(Finding {
                    id: finding_id("CC-3 pda", &ctx.instructions[0]),
                    message: format!(
                        "[CC-3 pda] account {} substituted with decoy {} instr {}:{} still succeeded (missing PDA derivation check)",
                        target,
                        decoy,
                        ctx.instructions[0].program_id,
                        disc_hex(&ctx.instructions[0]),
                    ),
                });
            }
        }
        findings
    }
}

/// CC-3 targets: off-curve (PDA-like), non-executable, non-sysvar accounts. Data is not required:
/// derivation checks are often about an authority or role address whose account body is empty. The
/// strategy applies an identity-relevance gate before reporting so inert threaded-through accounts
/// are skipped.
fn collect_pda_candidates(
    svm: &LiteSVM,
    instructions: &[Instruction],
    config: &AccountMutationConfig,
) -> Vec<Pubkey> {
    let mut seen = FastHashSet::default();
    let mut candidates = Vec::new();
    for ix in instructions {
        for meta in &ix.accounts {
            if !seen.insert(meta.pubkey) {
                continue;
            }
            if meta.pubkey == ix.program_id
                || config.unverified_accounts.contains(&meta.pubkey)
                || is_known_sysvar(&meta.pubkey)
                || !is_off_curve(&meta.pubkey)
            {
                continue;
            }
            let Some(account) = svm.get_account(&meta.pubkey) else {
                continue;
            };
            if account.executable {
                continue;
            }
            candidates.push(meta.pubkey);
        }
    }
    candidates
}

/// CC-2: a sysvar passed as an account, whose identity (key) the program never verifies — the
/// Wormhole class. Substituting a clone at a different address and still succeeding means the program
/// trusted the account by position, not by key. Relevance-gated so a sysvar the program ignores
/// (e.g. it reads the runtime cache instead) is not falsely reported.
struct SysvarSubstitutionStrategy;

impl MutationStrategy for SysvarSubstitutionStrategy {
    fn probe(&self, ctx: &ProbeCtx) -> Vec<Finding> {
        let mut findings = Vec::new();
        for target in collect_sysvar_candidates(ctx.instructions) {
            if !account_is_load_bearing(ctx, &target) {
                continue;
            }
            let decoy = decoy_for(target);
            if substitute_probe(ctx, target, decoy) {
                findings.push(Finding {
                    id: finding_id("CC-2 sysvar", &ctx.instructions[0]),
                    message: format!(
                        "[CC-2 sysvar] account {} substituted with decoy {} instr {}:{} still succeeded (missing sysvar identity check)",
                        target,
                        decoy,
                        ctx.instructions[0].program_id,
                        disc_hex(&ctx.instructions[0]),
                    ),
                });
            }
        }
        findings
    }
}

/// CC-2 targets: known sysvars passed as instruction accounts.
fn collect_sysvar_candidates(instructions: &[Instruction]) -> Vec<Pubkey> {
    let mut seen = FastHashSet::default();
    let mut candidates = Vec::new();
    for ix in instructions {
        for meta in &ix.accounts {
            if meta.pubkey == ix.program_id {
                continue;
            }
            if is_known_sysvar(&meta.pubkey) && seen.insert(meta.pubkey) {
                candidates.push(meta.pubkey);
            }
        }
    }
    candidates
}

/// Owner-mutation targets: non-executable, non-sysvar, data-bearing accounts. PDA-like addresses are
/// skipped by default: mutating an owner in-place at a key-pinned PDA fabricates an account state an
/// attacker cannot normally create on-chain. Harnesses can opt into PDA owner probes when a target has
/// a reachable program-owned account-creation path that makes that class meaningful.
fn collect_owner_candidates(
    svm: &LiteSVM,
    instructions: &[Instruction],
    config: &AccountMutationConfig,
) -> Vec<OwnerCandidate> {
    let mut seen = FastHashSet::default();
    let mut candidates = Vec::new();
    for ix in instructions {
        for meta in &ix.accounts {
            if !seen.insert(meta.pubkey) {
                continue;
            }
            if meta.pubkey == ix.program_id
                || config.unverified_accounts.contains(&meta.pubkey)
                || is_known_sysvar(&meta.pubkey)
                || (config.skip_pda_candidates && is_off_curve(&meta.pubkey))
            {
                continue;
            }
            let Some(account) = svm.get_account(&meta.pubkey) else {
                continue;
            };
            if account.executable || account.data.is_empty() {
                continue;
            }
            candidates.push(OwnerCandidate {
                pubkey: meta.pubkey,
                original_owner: account.owner,
            });
        }
    }

    candidates
}

fn probe_matches_baseline_effects(
    ctx: &ProbeCtx,
    probe: &mut LiteSVM,
    mutated_instructions: &[Instruction],
    equivalent_accounts: &[(Pubkey, Pubkey)],
    ignored_accounts: &[Pubkey],
) -> bool {
    if !matches!(
        send_probe_transaction(
            probe,
            mutated_instructions,
            ctx.signers,
            ctx.payer,
            ctx.sigverify,
        ),
        Ok(Ok(_))
    ) {
        return false;
    }

    post_state_matches(
        ctx.baseline_after,
        probe,
        ctx.instructions,
        mutated_instructions,
        equivalent_accounts,
        ignored_accounts,
        ctx.payer.pubkey(),
    )
}

fn post_state_matches(
    baseline: &LiteSVM,
    mutated: &LiteSVM,
    baseline_instructions: &[Instruction],
    mutated_instructions: &[Instruction],
    equivalent_accounts: &[(Pubkey, Pubkey)],
    ignored_accounts: &[Pubkey],
    payer: Pubkey,
) -> bool {
    let mut ignored = FastHashSet::default();
    for pubkey in ignored_accounts {
        ignored.insert(*pubkey);
    }
    for (baseline_key, mutated_key) in equivalent_accounts {
        if !same_account_state(
            baseline.get_account(baseline_key),
            mutated.get_account(mutated_key),
        ) {
            return false;
        }
        ignored.insert(*baseline_key);
        ignored.insert(*mutated_key);
    }

    let mut keys = instruction_account_keys(baseline_instructions);
    keys.extend(instruction_account_keys(mutated_instructions));
    keys.insert(payer);

    for key in keys {
        if ignored.contains(&key) {
            continue;
        }
        if !same_account_state(baseline.get_account(&key), mutated.get_account(&key)) {
            return false;
        }
    }

    true
}

fn instruction_account_keys(instructions: &[Instruction]) -> FastHashSet<Pubkey> {
    let mut keys = FastHashSet::default();
    for ix in instructions {
        for meta in &ix.accounts {
            keys.insert(meta.pubkey);
        }
    }
    keys
}

fn same_account_state(
    a: Option<solana_account::Account>,
    b: Option<solana_account::Account>,
) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.lamports == b.lamports
                && a.data == b.data
                && a.owner == b.owner
                && a.executable == b.executable
                && a.rent_epoch == b.rent_epoch
        }
        _ => false,
    }
}

fn account_is_identity_relevant(ctx: &ProbeCtx, pubkey: &Pubkey) -> bool {
    account_is_load_bearing(ctx, pubkey) || account_is_lamport_bearing(ctx, pubkey)
}

/// Relevance gate (Neodyme-style): corrupt the account data and replay. If every corrupted replay
/// still succeeds the program never read the contents (inert account), so a surviving owner mutation
/// would be a false positive. We try Anchor-friendly body corruption plus prefix/full corruption so
/// native, Pinocchio, and closed-source layouts with important bytes before offset 8 are covered.
fn account_is_load_bearing(ctx: &ProbeCtx, pubkey: &Pubkey) -> bool {
    let Some(account) = ctx.svm.get_account(pubkey) else {
        return false;
    };
    if account.data.is_empty() {
        return false;
    }

    for data in data_corruption_variants(&account.data) {
        let mut probe = ctx.svm.clone();
        let Some(mut account) = probe.get_account(pubkey) else {
            continue;
        };
        account.data = data;
        let _ = probe.set_account(*pubkey, account);

        if !matches!(
            send_probe_transaction(
                &mut probe,
                ctx.instructions,
                ctx.signers,
                ctx.payer,
                ctx.sigverify,
            ),
            Ok(Ok(_))
        ) {
            return true;
        }
    }

    false
}

fn account_is_lamport_bearing(ctx: &ProbeCtx, pubkey: &Pubkey) -> bool {
    let Some(account) = ctx.svm.get_account(pubkey) else {
        return false;
    };
    if account.lamports == 0 {
        return false;
    }

    let mut probe = ctx.svm.clone();
    let Some(mut account) = probe.get_account(pubkey) else {
        return false;
    };
    account.lamports = 0;
    let _ = probe.set_account(*pubkey, account);

    !matches!(
        send_probe_transaction(
            &mut probe,
            ctx.instructions,
            ctx.signers,
            ctx.payer,
            ctx.sigverify,
        ),
        Ok(Ok(_))
    )
}

fn data_corruption_variants(data: &[u8]) -> Vec<Vec<u8>> {
    let mut variants = Vec::new();
    let len = data.len();

    if len > 8 {
        push_unique_corruption(&mut variants, data, 8..len);
    }
    push_unique_corruption(&mut variants, data, 0..len.min(8));
    push_unique_corruption(&mut variants, data, 0..len);

    variants
}

fn push_unique_corruption(variants: &mut Vec<Vec<u8>>, data: &[u8], range: std::ops::Range<usize>) {
    if range.is_empty() {
        return;
    }

    let mut corrupted = data.to_vec();
    for b in &mut corrupted[range] {
        *b = if *b == 0xFF { 0x00 } else { 0xFF };
    }
    if corrupted != data && !variants.iter().any(|existing| existing == &corrupted) {
        variants.push(corrupted);
    }
}

fn is_off_curve(pubkey: &Pubkey) -> bool {
    !bytes_are_curve_point(pubkey)
}

fn send_probe_transaction(
    svm: &mut LiteSVM,
    instructions: &[Instruction],
    signers: &[&Keypair],
    payer: &Keypair,
    sigverify: bool,
) -> Result<litesvm::types::TransactionResult> {
    let blockhash = if sigverify {
        svm.expire_blockhash();
        svm.latest_blockhash()
    } else {
        svm.latest_blockhash()
    };
    let message = Message::new_with_blockhash(instructions, Some(&payer.pubkey()), &blockhash);

    let tx = if sigverify {
        let mut keypairs = signers.to_vec();
        if !keypairs.iter().any(|k| k.pubkey() == payer.pubkey()) {
            keypairs.push(payer);
        }
        VersionedTransaction::try_new(VersionedMessage::Legacy(message), &keypairs)?
    } else {
        let num_sigs = message.header.num_required_signatures as usize;
        let signatures = vec![solana_signature::Signature::default(); num_sigs];
        VersionedTransaction {
            signatures,
            message: VersionedMessage::Legacy(message),
        }
    };

    Ok(svm.send_transaction(tx))
}

#[allow(deprecated)]
fn is_known_sysvar(pubkey: &Pubkey) -> bool {
    *pubkey == Clock::id()
        || *pubkey == EpochSchedule::id()
        || *pubkey == SlotHashes::id()
        || *pubkey == SlotHistory::id()
        || *pubkey == StakeHistory::id()
        || *pubkey == anchor_lang::prelude::Rent::id()
        || *pubkey == EpochRewards::id()
        || *pubkey == Fees::id()
        || *pubkey == LastRestartSlot::id()
        || *pubkey == RecentBlockhashes::id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::instruction::AccountMeta;
    use solana_account::Account;

    fn make_account(owner: Pubkey, data: Vec<u8>) -> Account {
        Account {
            lamports: 1_000_000,
            data,
            owner,
            executable: false,
            rent_epoch: 0,
        }
    }

    fn on_curve_pubkey() -> Pubkey {
        Keypair::new().pubkey()
    }

    #[test]
    fn probe_key_is_deterministic_and_pads_short_data() {
        let prog = Pubkey::new_unique();
        let a = Instruction {
            program_id: prog,
            accounts: vec![],
            data: vec![1, 2, 3],
        };
        let b = a.clone();
        assert_eq!(probe_key(&a), probe_key(&b));
        assert_eq!(probe_key(&a), (prog, [1, 2, 3, 0, 0, 0, 0, 0]));

        let long = Instruction {
            program_id: prog,
            accounts: vec![],
            data: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        };
        assert_eq!(probe_key(&long), (prog, [1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn collect_owner_candidates_keeps_data_accounts_including_writable() {
        let mut svm = LiteSVM::new();
        let config = AccountMutationConfig::default();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let keep = on_curve_pubkey();
        let writable = on_curve_pubkey();
        let empty = on_curve_pubkey();

        svm.set_account(keep, make_account(owner, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]))
            .unwrap();
        svm.set_account(
            writable,
            make_account(owner, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]),
        )
        .unwrap();
        svm.set_account(empty, make_account(owner, vec![])).unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(keep, false),
                AccountMeta::new(writable, false), // writable -> kept; runtime decides conclusiveness
                AccountMeta::new_readonly(empty, false), // empty data -> dropped
                AccountMeta::new_readonly(Clock::id(), false), // sysvar -> dropped
                AccountMeta::new_readonly(program_id, false), // program id -> dropped
            ],
            data: vec![],
        };

        let candidates = collect_owner_candidates(&svm, &[ix], &config);
        assert_eq!(
            candidates,
            vec![
                OwnerCandidate {
                    pubkey: keep,
                    original_owner: owner,
                },
                OwnerCandidate {
                    pubkey: writable,
                    original_owner: owner,
                },
            ]
        );
    }

    #[test]
    fn collect_owner_candidates_keeps_account_writable_in_any_instruction() {
        let mut svm = LiteSVM::new();
        let config = AccountMutationConfig::default();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let acct = on_curve_pubkey();
        svm.set_account(acct, make_account(owner, vec![9; 16]))
            .unwrap();

        // read-only in ix0 but writable in ix1 -> still probed; if owner mutation triggers a
        // runtime write-ownership failure later the strategy simply will not report it.
        let ix0 = Instruction {
            program_id,
            accounts: vec![AccountMeta::new_readonly(acct, false)],
            data: vec![],
        };
        let ix1 = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(acct, false)],
            data: vec![],
        };

        assert_eq!(
            collect_owner_candidates(&svm, &[ix0, ix1], &config),
            vec![OwnerCandidate {
                pubkey: acct,
                original_owner: owner,
            }]
        );
    }

    #[test]
    fn collect_owner_candidates_skips_pdas_by_default_and_can_include() {
        let mut svm = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let (pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);
        svm.set_account(pda, make_account(owner, vec![7; 16]))
            .unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new_readonly(pda, false)],
            data: vec![],
        };

        let mut config = AccountMutationConfig::default();
        assert!(collect_owner_candidates(&svm, std::slice::from_ref(&ix), &config).is_empty());

        config.set_skip_pda_candidates(false);
        assert_eq!(
            collect_owner_candidates(&svm, &[ix], &config),
            vec![OwnerCandidate {
                pubkey: pda,
                original_owner: owner,
            }]
        );
    }

    #[test]
    fn collect_pda_candidates_keeps_offcurve_accounts_even_without_data() {
        let mut svm = LiteSVM::new();
        let config = AccountMutationConfig::default();
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let (pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);
        let (empty_pda, _) = Pubkey::find_program_address(&[b"authority"], &program_id);
        let on_curve = Keypair::new().pubkey();
        svm.set_account(pda, make_account(owner, vec![7; 16]))
            .unwrap();
        svm.set_account(empty_pda, make_account(owner, vec![]))
            .unwrap();
        svm.set_account(on_curve, make_account(owner, vec![7; 16]))
            .unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(pda, false),
                AccountMeta::new_readonly(empty_pda, false), // empty PDA authority -> kept
                AccountMeta::new_readonly(on_curve, false),  // on-curve -> dropped
                AccountMeta::new_readonly(Clock::id(), false), // sysvar -> dropped
            ],
            data: vec![],
        };
        assert_eq!(
            collect_pda_candidates(&svm, &[ix], &config),
            vec![pda, empty_pda]
        );
    }

    #[test]
    fn post_state_matches_ignores_intentional_target_mutation_but_checks_effects() {
        let mut baseline = LiteSVM::new();
        let mut mutated = LiteSVM::new();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let target = on_curve_pubkey();
        let recipient = on_curve_pubkey();
        let payer = on_curve_pubkey();

        baseline
            .set_account(target, make_account(owner, vec![1; 8]))
            .unwrap();
        mutated
            .set_account(target, make_account(Pubkey::new_unique(), vec![9; 8]))
            .unwrap();
        baseline
            .set_account(recipient, make_account(owner, vec![2; 8]))
            .unwrap();
        mutated
            .set_account(recipient, make_account(owner, vec![2; 8]))
            .unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(target, false),
                AccountMeta::new(recipient, false),
            ],
            data: vec![],
        };

        assert!(post_state_matches(
            &baseline,
            &mutated,
            std::slice::from_ref(&ix),
            std::slice::from_ref(&ix),
            &[],
            &[target],
            payer,
        ));

        mutated
            .set_account(recipient, make_account(owner, vec![3; 8]))
            .unwrap();
        assert!(!post_state_matches(
            &baseline,
            &mutated,
            std::slice::from_ref(&ix),
            std::slice::from_ref(&ix),
            &[],
            &[target],
            payer,
        ));
    }

    #[test]
    fn post_state_matches_maps_substitution_decoy_to_baseline_target() {
        let mut baseline = LiteSVM::new();
        let mut mutated = LiteSVM::new();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let target = on_curve_pubkey();
        let decoy = on_curve_pubkey();
        let recipient = on_curve_pubkey();
        let payer = on_curve_pubkey();

        baseline
            .set_account(target, make_account(owner, vec![1; 8]))
            .unwrap();
        mutated
            .set_account(target, make_account(owner, vec![9; 8]))
            .unwrap();
        mutated
            .set_account(decoy, make_account(owner, vec![1; 8]))
            .unwrap();
        baseline
            .set_account(recipient, make_account(owner, vec![2; 8]))
            .unwrap();
        mutated
            .set_account(recipient, make_account(owner, vec![2; 8]))
            .unwrap();

        let baseline_ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(target, false),
                AccountMeta::new(recipient, false),
            ],
            data: vec![],
        };
        let mutated_ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(decoy, false),
                AccountMeta::new(recipient, false),
            ],
            data: vec![],
        };

        assert!(post_state_matches(
            &baseline,
            &mutated,
            &[baseline_ix],
            &[mutated_ix],
            &[(target, decoy)],
            &[],
            payer,
        ));
    }

    #[test]
    fn rewrite_account_repoints_only_target() {
        let program_id = Pubkey::new_unique();
        let target = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        let decoy = Pubkey::new_unique();
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(target, false),
                AccountMeta::new_readonly(other, true),
            ],
            data: vec![],
        };
        let out = rewrite_account(std::slice::from_ref(&ix), target, decoy);
        assert_eq!(out[0].accounts[0].pubkey, decoy);
        assert!(out[0].accounts[0].is_writable); // flags preserved
        assert_eq!(out[0].accounts[1].pubkey, other);
        assert!(out[0].accounts[1].is_signer);
    }

    #[test]
    fn decoy_for_uses_alt_when_equal() {
        assert_eq!(decoy_for(Pubkey::new_unique()), CRUCIBLE_DECOY);
        assert_eq!(decoy_for(CRUCIBLE_DECOY), CRUCIBLE_DECOY_ALT);
    }

    #[test]
    fn collect_sysvar_candidates_picks_sysvars_only() {
        let program_id = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(Clock::id(), false),
                AccountMeta::new_readonly(other, false), // not a sysvar/system -> dropped
                AccountMeta::new_readonly(Clock::id(), false), // dup -> deduped
            ],
            data: vec![],
        };
        assert_eq!(collect_sysvar_candidates(&[ix]), vec![Clock::id()]);
    }

    #[test]
    fn wrong_owner_uses_alt_when_already_attacker() {
        assert_eq!(wrong_owner(Pubkey::new_unique()), CRUCIBLE_ATTACKER);
        assert_eq!(wrong_owner(CRUCIBLE_ATTACKER), CRUCIBLE_ATTACKER_ALT);
    }

    #[test]
    fn signer_candidates_dedupes_across_instructions() {
        let program_id = Pubkey::new_unique();
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();
        let non_signer = Pubkey::new_unique();
        let ix0 = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(a, true),
                AccountMeta::new_readonly(non_signer, false),
            ],
            data: vec![],
        };
        let ix1 = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(a, true), // duplicate signer
                AccountMeta::new(b, true),
            ],
            data: vec![],
        };
        assert_eq!(
            signer_candidates(&[ix0, ix1], &[]),
            vec![
                SignerCandidate {
                    pubkey: a,
                    kind: SignerCandidateKind::MetaSigner,
                },
                SignerCandidate {
                    pubkey: b,
                    kind: SignerCandidateKind::MetaSigner,
                },
            ]
        );
    }

    #[test]
    fn signer_candidates_includes_supplied_signer_present_as_non_signer_account() {
        let program_id = Pubkey::new_unique();
        let supplied = Keypair::new();
        let payer = Keypair::new();
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(supplied.pubkey(), false),
                AccountMeta::new_readonly(Pubkey::new_unique(), false),
            ],
            data: vec![],
        };

        assert_eq!(
            signer_candidates(&[ix], &[&payer, &supplied]),
            vec![SignerCandidate {
                pubkey: supplied.pubkey(),
                kind: SignerCandidateKind::SuppliedSigner,
            }]
        );
    }

    #[test]
    fn clear_signer_clears_only_target_in_all_instructions() {
        let program_id = Pubkey::new_unique();
        let target = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(target, true),
                AccountMeta::new(other, true),
            ],
            data: vec![],
        };

        let flipped = clear_signer(std::slice::from_ref(&ix), target);
        assert!(!flipped[0].accounts[0].is_signer); // target cleared
        assert!(flipped[0].accounts[1].is_signer); // other untouched
    }

    #[test]
    fn data_corruption_variants_cover_anchor_body_prefix_and_full_data() {
        let data: Vec<u8> = (0..16).collect();
        let variants = data_corruption_variants(&data);

        assert!(
            variants
                .iter()
                .any(|v| v[..8] == data[..8] && v[8..] != data[8..]),
            "should preserve 8-byte discriminator and corrupt body"
        );
        assert!(
            variants
                .iter()
                .any(|v| v[..8] != data[..8] && v[8..] == data[8..]),
            "should corrupt prefix for native/pinocchio layouts"
        );
        assert!(
            variants
                .iter()
                .any(|v| v[..8] != data[..8] && v[8..] != data[8..]),
            "should include full-data corruption for closed-source layouts"
        );
    }
}
