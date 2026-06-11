use crate::{record_mutation_violation, FastHashMap, FastHashSet};
use anchor_lang::prelude::sysvar::SysvarId;
use anchor_lang::prelude::{Clock, EpochSchedule, SlotHashes, SlotHistory, StakeHistory};
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::program_pack::Pack;
use anchor_lang::solana_program::system_program;
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
use std::collections::HashSet;

const DEFAULT_SKIP_PDA_CANDIDATES: bool = true;

/// Wrong owner written by the owner-mutation strategy. A recognizable, non-executable key
/// that no legitimate program could own, so a surviving mutation means the owner was never
/// checked — never a blur of several possible causes.
const CRUCIBLE_ATTACKER: Pubkey = Pubkey::new_from_array([0xCC; 32]);
/// Fallback used in the unlikely case an account is already owned by [`CRUCIBLE_ATTACKER`],
/// so the mutation is always a real change.
const CRUCIBLE_ATTACKER_ALT: Pubkey = Pubkey::new_from_array([0xCD; 32]);

/// Fixed replacement address used by sysvar/PDA probes.
const CRUCIBLE_DECOY: Pubkey = Pubkey::new_from_array([0xDD; 32]);
const CRUCIBLE_DECOY_ALT: Pubkey = Pubkey::new_from_array([0xDE; 32]);
const TOKEN_2022_PROGRAM: Pubkey =
    solana_pubkey::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFicQfKkqPnx5xSvyJm");

fn decoy_for(target: Pubkey) -> Pubkey {
    if target == CRUCIBLE_DECOY {
        CRUCIBLE_DECOY_ALT
    } else {
        CRUCIBLE_DECOY
    }
}

fn token_decoy_for(target: Pubkey) -> Pubkey {
    let decoy = Keypair::new().pubkey();
    if decoy == target {
        Keypair::new().pubkey()
    } else {
        decoy
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

fn substitute_mutated_account_probe(
    ctx: &ProbeCtx,
    target: Pubkey,
    decoy: Pubkey,
    mut mutate: impl FnMut(&mut solana_account::Account),
) -> bool {
    let mut probe = ctx.svm.clone();
    let Some(mut account) = probe.get_account(&target) else {
        return false;
    };
    mutate(&mut account);
    if probe.set_account(decoy, account).is_err() {
        return false;
    }
    let rewritten = rewrite_account(ctx.instructions, target, decoy);
    probe_matches_baseline_effects(ctx, &mut probe, &rewritten, &[], &[target, decoy])
}

fn substitute_existing_load_bearing_account_probe(
    ctx: &ProbeCtx,
    target: Pubkey,
    replacement: Pubkey,
) -> bool {
    let mut probe = ctx.svm.clone();
    let rewritten = rewrite_account(ctx.instructions, target, replacement);
    if !probe_matches_baseline_effects(ctx, &mut probe, &rewritten, &[], &[target, replacement]) {
        return false;
    }

    replacement_is_load_bearing_under_rewrite(ctx, target, replacement, &rewritten)
}

fn substitute_existing_referenced_target_probe(
    ctx: &ProbeCtx,
    target: Pubkey,
    replacement: Pubkey,
) -> bool {
    let mut probe = ctx.svm.clone();
    let rewritten = rewrite_account(ctx.instructions, target, replacement);
    probe_matches_baseline_effects(ctx, &mut probe, &rewritten, &[], &[target, replacement])
}

fn probe_matches_baseline_effects_with_signers(
    ctx: &ProbeCtx,
    probe: &mut LiteSVM,
    mutated_instructions: &[Instruction],
    signers: &[&Keypair],
    equivalent_accounts: &[(Pubkey, Pubkey)],
    ignored_accounts: &[Pubkey],
) -> bool {
    if !matches!(
        send_probe_transaction(
            probe,
            mutated_instructions,
            signers,
            ctx.payer,
            ctx.sigverify
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
    observed_accounts: &'a HashSet<Pubkey>,
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
        Box::new(TokenFakeOwnerStrategy),
        Box::new(TokenWrongMintStrategy),
        Box::new(BidirectionalFieldBindingStrategy),
        Box::new(FieldCrossReferenceStrategy),
        Box::new(SysvarSubstitutionStrategy),
        Box::new(OwnerStrategy),
        Box::new(SignerStrategy),
        Box::new(AuthoritySignerStrategy),
        Box::new(TypeTagStrategy),
        Box::new(SemanticSwapStrategy),
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

fn select_finding<'a>(findings: &'a [Finding], expected: Option<&str>) -> Option<&'a Finding> {
    match expected {
        Some(id) => findings.iter().find(|finding| finding.id == id),
        None => findings
            .iter()
            .enumerate()
            .min_by_key(|(index, finding)| (finding_priority(finding), *index))
            .map(|(_, finding)| finding),
    }
}

fn finding_priority(finding: &Finding) -> u8 {
    if finding.id.starts_with("CC-8 value-ref:") {
        0
    } else {
        10
    }
}

pub(crate) fn maybe_probe_account_mutation(
    svm: &LiteSVM,
    config: &AccountMutationConfig,
    observed_accounts: &HashSet<Pubkey>,
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
        observed_accounts,
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
    let selected = select_finding(&findings, expected.as_deref());

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
            let ignored = signer_probe_ignored_accounts(ctx.instructions, &flipped, payer);
            if probe_matches_baseline_effects(ctx, &mut probe, &flipped, &[], &ignored) {
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

fn signer_probe_ignored_accounts(
    baseline_instructions: &[Instruction],
    mutated_instructions: &[Instruction],
    payer: Pubkey,
) -> Vec<Pubkey> {
    let mut keys = instruction_account_keys(baseline_instructions);
    keys.extend(instruction_account_keys(mutated_instructions));
    if keys.contains(&payer) {
        Vec::new()
    } else {
        vec![payer]
    }
}

/// CC-10: account data names an authority/delegate signer, but the instruction accepts a different
/// valid signer. This is separate from CC-4: the replacement account still signs, so a plain
/// `is_signer` assertion is satisfied.
struct AuthoritySignerStrategy;

impl MutationStrategy for AuthoritySignerStrategy {
    fn probe(&self, ctx: &ProbeCtx) -> Vec<Finding> {
        let mut findings = Vec::new();
        let payer = ctx.payer.pubkey();

        for source in instruction_account_keys(ctx.instructions) {
            if account_has_signer_meta(ctx.instructions, source) || is_known_sysvar(&source) {
                continue;
            }
            let Some(account) = ctx.svm.get_account(&source) else {
                continue;
            };
            if account.executable
                || account.data.is_empty()
                || is_spl_token_shape(&account)
                || !account_is_load_bearing(ctx, &source)
            {
                continue;
            }

            for signer in signer_meta_pubkeys(ctx.instructions) {
                if signer == payer
                    || signer == source
                    || !data_contains_pubkey(&account.data, &signer)
                    || !signer_is_load_bearing(ctx, signer)
                {
                    continue;
                }

                let attacker = Keypair::new();
                let attacker_pubkey = attacker.pubkey();
                let mut probe = ctx.svm.clone();
                if probe
                    .set_account(attacker_pubkey, system_signer_account())
                    .is_err()
                {
                    continue;
                }

                let rewritten = rewrite_account(ctx.instructions, signer, attacker_pubkey);
                let mut signers = ctx.signers.to_vec();
                signers.push(&attacker);

                if probe_matches_baseline_effects_with_signers(
                    ctx,
                    &mut probe,
                    &rewritten,
                    &signers,
                    &[],
                    &[signer, attacker_pubkey],
                ) {
                    findings.push(Finding {
                        id: finding_id("CC-10 authority", &ctx.instructions[0]),
                        message: format!(
                            "[CC-10 authority] account {} contains authority {}, but instr {}:{} still succeeded with replacement signer {}",
                            source,
                            signer,
                            ctx.instructions[0].program_id,
                            disc_hex(&ctx.instructions[0]),
                            attacker_pubkey,
                        ),
                    });
                }
            }
        }

        findings
    }
}

fn signer_meta_pubkeys(instructions: &[Instruction]) -> Vec<Pubkey> {
    let mut seen = FastHashSet::default();
    let mut signers = Vec::new();
    for ix in instructions {
        for meta in &ix.accounts {
            if meta.is_signer && seen.insert(meta.pubkey) {
                signers.push(meta.pubkey);
            }
        }
    }
    signers
}

fn account_has_signer_meta(instructions: &[Instruction], pubkey: Pubkey) -> bool {
    instructions
        .iter()
        .flat_map(|ix| ix.accounts.iter())
        .any(|meta| meta.pubkey == pubkey && meta.is_signer)
}

fn signer_is_load_bearing(ctx: &ProbeCtx, signer: Pubkey) -> bool {
    let flipped = clear_signer(ctx.instructions, signer);
    let mut probe = ctx.svm.clone();
    let ignored = signer_probe_ignored_accounts(ctx.instructions, &flipped, ctx.payer.pubkey());
    !probe_matches_baseline_effects(ctx, &mut probe, &flipped, &[], &ignored)
}

fn system_signer_account() -> solana_account::Account {
    solana_account::Account {
        lamports: 1_000_000,
        data: Vec::new(),
        owner: system_program::id(),
        executable: false,
        rent_epoch: 0,
    }
}

/// CC-3: an off-curve account accepted after both its address and owner are changed.
struct PdaSubstitutionStrategy;

impl MutationStrategy for PdaSubstitutionStrategy {
    fn probe(&self, ctx: &ProbeCtx) -> Vec<Finding> {
        let mut findings = Vec::new();
        for target in collect_pda_candidates(ctx.svm, ctx.instructions, ctx.config) {
            if !account_is_identity_relevant(ctx, &target) {
                continue;
            }
            let decoy = decoy_for(target);
            let Some(account) = ctx.svm.get_account(&target) else {
                continue;
            };
            let spoof_owner = wrong_owner(account.owner);
            if substitute_mutated_account_probe(ctx, target, decoy, |account| {
                account.owner = spoof_owner;
            }) {
                findings.push(Finding {
                    id: finding_id("CC-3 pda-spoof", &ctx.instructions[0]),
                    message: format!(
                        "[CC-3 pda-spoof] account {} substituted with decoy {} owner {}->{} instr {}:{} still succeeded (missing PDA derivation/owner check)",
                        target,
                        decoy,
                        account.owner,
                        spoof_owner,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenShapeKind {
    Mint,
    Account,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TokenShapeCandidate {
    pubkey: Pubkey,
    owner: Pubkey,
    kind: TokenShapeKind,
}

/// Token owner checks are common enough to get precise labels instead of generic CC-1 findings.
struct TokenFakeOwnerStrategy;

impl MutationStrategy for TokenFakeOwnerStrategy {
    fn probe(&self, ctx: &ProbeCtx) -> Vec<Finding> {
        let mut findings = Vec::new();
        for candidate in collect_token_shape_candidates(ctx.svm, ctx.instructions) {
            if !account_is_load_bearing(ctx, &candidate.pubkey) {
                continue;
            }

            let decoy = token_decoy_for(candidate.pubkey);
            let spoof_owner = wrong_owner(candidate.owner);
            if substitute_mutated_account_probe(ctx, candidate.pubkey, decoy, |account| {
                account.owner = spoof_owner;
            }) {
                let (class, label, detail) = match candidate.kind {
                    TokenShapeKind::Mint => (
                        "CC-token fake-mint-owner",
                        "[CC-token fake-mint-owner]",
                        "SPL mint-shaped",
                    ),
                    TokenShapeKind::Account => (
                        "CC-token fake-account-owner",
                        "[CC-token fake-account-owner]",
                        "SPL token-account-shaped",
                    ),
                };
                findings.push(Finding {
                    id: finding_id(class, &ctx.instructions[0]),
                    message: format!(
                        "{} account {} substituted with decoy {} owner {}->{} instr {}:{} still succeeded (missing {} owner check)",
                        label,
                        candidate.pubkey,
                        decoy,
                        candidate.owner,
                        spoof_owner,
                        ctx.instructions[0].program_id,
                        disc_hex(&ctx.instructions[0]),
                        detail,
                    ),
                });
            }
        }
        findings
    }
}

#[derive(Clone, Debug, PartialEq)]
struct TokenAccountCandidate {
    pubkey: Pubkey,
    token: spl_token::state::Account,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MintCandidate {
    pubkey: Pubkey,
}

/// Detects instructions that receive both a token account and a mint but never verify their relation.
struct TokenWrongMintStrategy;

impl MutationStrategy for TokenWrongMintStrategy {
    fn probe(&self, ctx: &ProbeCtx) -> Vec<Finding> {
        let mut findings = Vec::new();
        let (token_accounts, mints) = collect_token_relation_candidates(ctx.svm, ctx.instructions);
        if token_accounts.is_empty() || mints.is_empty() {
            return findings;
        }

        for token_account in token_accounts {
            if !account_is_load_bearing(ctx, &token_account.pubkey) {
                continue;
            }
            if !baseline_has_non_fee_effect(ctx) {
                continue;
            }
            for mint in &mints {
                if token_account.token.mint != mint.pubkey {
                    continue;
                }
                let wrong_mint = mints
                    .iter()
                    .map(|candidate| candidate.pubkey)
                    .find(|pubkey| *pubkey != mint.pubkey)
                    .unwrap_or(CRUCIBLE_ATTACKER);
                let mut spoofed_token = token_account.token.clone();
                spoofed_token.mint = wrong_mint;
                let Some(data) = pack_token_account(spoofed_token) else {
                    continue;
                };
                let decoy = token_decoy_for(token_account.pubkey);
                if substitute_mutated_account_probe(ctx, token_account.pubkey, decoy, |account| {
                    account.data = data.clone();
                }) {
                    findings.push(Finding {
                        id: finding_id("CC-token wrong-mint", &ctx.instructions[0]),
                        message: format!(
                            "[CC-token wrong-mint] token account {} substituted with decoy {} mint {}->{} while mint account {} was provided, instr {}:{} still succeeded",
                            token_account.pubkey,
                            decoy,
                            mint.pubkey,
                            wrong_mint,
                            mint.pubkey,
                            ctx.instructions[0].program_id,
                            disc_hex(&ctx.instructions[0]),
                        ),
                    });
                }
            }
        }
        findings
    }
}

fn collect_token_shape_candidates(
    svm: &LiteSVM,
    instructions: &[Instruction],
) -> Vec<TokenShapeCandidate> {
    let mut seen = FastHashSet::default();
    let mut candidates = Vec::new();
    for ix in instructions {
        for meta in &ix.accounts {
            if !seen.insert(meta.pubkey)
                || meta.pubkey == ix.program_id
                || is_known_sysvar(&meta.pubkey)
            {
                continue;
            }
            let Some(account) = svm.get_account(&meta.pubkey) else {
                continue;
            };
            if account.executable || !is_token_program_owner(&account.owner) {
                continue;
            }
            if unpack_mint(&account.data).is_some() {
                candidates.push(TokenShapeCandidate {
                    pubkey: meta.pubkey,
                    owner: account.owner,
                    kind: TokenShapeKind::Mint,
                });
            } else if unpack_token_account(&account.data).is_some() {
                candidates.push(TokenShapeCandidate {
                    pubkey: meta.pubkey,
                    owner: account.owner,
                    kind: TokenShapeKind::Account,
                });
            }
        }
    }
    candidates
}

fn collect_token_relation_candidates(
    svm: &LiteSVM,
    instructions: &[Instruction],
) -> (Vec<TokenAccountCandidate>, Vec<MintCandidate>) {
    let mut seen = FastHashSet::default();
    let mut token_accounts = Vec::new();
    let mut mints = Vec::new();
    for ix in instructions {
        for meta in &ix.accounts {
            if !seen.insert(meta.pubkey)
                || meta.pubkey == ix.program_id
                || is_known_sysvar(&meta.pubkey)
            {
                continue;
            }
            let Some(account) = svm.get_account(&meta.pubkey) else {
                continue;
            };
            if account.executable || !is_token_program_owner(&account.owner) {
                continue;
            }
            if let Some(token) = unpack_token_account(&account.data) {
                token_accounts.push(TokenAccountCandidate {
                    pubkey: meta.pubkey,
                    token,
                });
            } else if unpack_mint(&account.data).is_some() {
                mints.push(MintCandidate {
                    pubkey: meta.pubkey,
                });
            }
        }
    }
    (token_accounts, mints)
}

fn is_token_program_owner(owner: &Pubkey) -> bool {
    *owner == spl_token::id() || *owner == TOKEN_2022_PROGRAM
}

fn is_spl_token_shape(account: &solana_account::Account) -> bool {
    is_token_program_owner(&account.owner)
        && (unpack_mint(&account.data).is_some() || unpack_token_account(&account.data).is_some())
}

fn unpack_mint(data: &[u8]) -> Option<spl_token::state::Mint> {
    if data.len() != spl_token::state::Mint::LEN {
        return None;
    }
    spl_token::state::Mint::unpack(data).ok()
}

fn unpack_token_account(data: &[u8]) -> Option<spl_token::state::Account> {
    if data.len() != spl_token::state::Account::LEN {
        return None;
    }
    spl_token::state::Account::unpack(data).ok()
}

fn pack_token_account(token: spl_token::state::Account) -> Option<Vec<u8>> {
    let mut data = vec![0; spl_token::state::Account::LEN];
    spl_token::state::Account::pack(token, &mut data).ok()?;
    Some(data)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct AccountClass {
    owner: Pubkey,
    shape: AccountShape,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum AccountShape {
    SplMint,
    SplTokenAccount,
    Discriminator(Vec<u8>),
    DataLen(usize),
}

#[derive(Clone, Debug)]
struct AccountClassIndex {
    by_pubkey: FastHashMap<Pubkey, AccountClass>,
    by_class: FastHashMap<AccountClass, Vec<Pubkey>>,
}

impl AccountClassIndex {
    fn build(
        svm: &LiteSVM,
        observed_accounts: &HashSet<Pubkey>,
        config: &AccountMutationConfig,
    ) -> Self {
        let mut by_pubkey = FastHashMap::default();
        let mut by_class: FastHashMap<AccountClass, Vec<Pubkey>> = FastHashMap::default();

        for pubkey in observed_accounts {
            if config.unverified_accounts.contains(pubkey) || is_known_sysvar(pubkey) {
                continue;
            }
            let Some(account) = svm.get_account(pubkey) else {
                continue;
            };
            let Some(class) = classify_account(&account) else {
                continue;
            };
            by_pubkey.insert(*pubkey, class.clone());
            by_class.entry(class).or_default().push(*pubkey);
        }

        for accounts in by_class.values_mut() {
            accounts.sort_by_key(|pubkey| pubkey.to_bytes());
        }

        Self {
            by_pubkey,
            by_class,
        }
    }

    fn class_count(&self, pubkey: &Pubkey) -> usize {
        self.by_pubkey
            .get(pubkey)
            .and_then(|class| self.by_class.get(class))
            .map(|accounts| accounts.len())
            .unwrap_or(0)
    }

    fn class_label(&self, pubkey: &Pubkey) -> String {
        self.by_pubkey
            .get(pubkey)
            .map(account_class_label)
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn same_class_replacements(&self, pubkey: &Pubkey) -> Vec<Pubkey> {
        let Some(class) = self.by_pubkey.get(pubkey) else {
            return Vec::new();
        };
        let Some(accounts) = self.by_class.get(class) else {
            return Vec::new();
        };
        if accounts.len() < 2 {
            return Vec::new();
        }
        accounts
            .iter()
            .copied()
            .filter(|candidate| candidate != pubkey)
            .collect()
    }
}

fn classify_account(account: &solana_account::Account) -> Option<AccountClass> {
    if account.executable || account.data.is_empty() {
        return None;
    }

    let shape = if is_token_program_owner(&account.owner) {
        if unpack_mint(&account.data).is_some() {
            AccountShape::SplMint
        } else if unpack_token_account(&account.data).is_some() {
            AccountShape::SplTokenAccount
        } else if let Some(discriminator) = registered_discriminator(&account.data) {
            AccountShape::Discriminator(discriminator)
        } else {
            AccountShape::DataLen(account.data.len())
        }
    } else if let Some(discriminator) = registered_discriminator(&account.data) {
        AccountShape::Discriminator(discriminator)
    } else {
        AccountShape::DataLen(account.data.len())
    };

    Some(AccountClass {
        owner: account.owner,
        shape,
    })
}

fn registered_discriminator(data: &[u8]) -> Option<Vec<u8>> {
    let disc_len = crate::schema::lookup_discriminator_len(data)?;
    if data.len() < disc_len {
        return None;
    }
    Some(data[..disc_len].to_vec())
}

fn account_class_label(class: &AccountClass) -> String {
    match &class.shape {
        AccountShape::SplMint => format!("owner {} spl-mint", class.owner),
        AccountShape::SplTokenAccount => format!("owner {} spl-token-account", class.owner),
        AccountShape::Discriminator(discriminator) => {
            format!(
                "owner {} discriminator {}",
                class.owner,
                bytes_hex(discriminator)
            )
        }
        AccountShape::DataLen(len) => format!("owner {} data-len {}", class.owner, len),
    }
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FieldRefEdge {
    source: Pubkey,
    target: Pubkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct BidirectionalRefPair {
    left: Pubkey,
    right: Pubkey,
    root: Option<Pubkey>,
}

struct BidirectionalFieldBindingStrategy;

impl MutationStrategy for BidirectionalFieldBindingStrategy {
    fn probe(&self, ctx: &ProbeCtx) -> Vec<Finding> {
        let mut findings = Vec::new();
        let class_index = AccountClassIndex::build(ctx.svm, ctx.observed_accounts, ctx.config);
        let current_accounts = instruction_account_keys(ctx.instructions);

        for pair in collect_bidirectional_ref_pairs(ctx.svm, ctx.instructions) {
            if !account_is_load_bearing(ctx, &pair.left)
                || !account_is_load_bearing(ctx, &pair.right)
            {
                continue;
            }
            if let Some(root) = pair.root {
                if !account_is_identity_relevant(ctx, &root) {
                    continue;
                }
            }

            for (substituted, counterpart) in [(pair.left, pair.right), (pair.right, pair.left)] {
                for replacement in class_index.same_class_replacements(&substituted) {
                    if current_accounts.contains(&replacement)
                        || bidirectional_replacement_preserves_relation(
                            ctx.svm,
                            pair,
                            counterpart,
                            replacement,
                        )
                    {
                        continue;
                    }
                    if substitute_existing_load_bearing_account_probe(ctx, substituted, replacement)
                    {
                        findings.push(cc83_finding(ctx, pair, substituted, replacement));
                    }
                }
            }
        }

        findings
    }
}

fn bidirectional_replacement_preserves_relation(
    svm: &LiteSVM,
    pair: BidirectionalRefPair,
    counterpart: Pubkey,
    replacement: Pubkey,
) -> bool {
    let Some(replacement_account) = svm.get_account(&replacement) else {
        return false;
    };
    let Some(counterpart_account) = svm.get_account(&counterpart) else {
        return false;
    };

    if let Some(root) = pair.root {
        data_contains_pubkey(&replacement_account.data, &root)
    } else {
        data_contains_pubkey(&replacement_account.data, &counterpart)
            && data_contains_pubkey(&counterpart_account.data, &replacement)
    }
}

fn cc83_finding(
    ctx: &ProbeCtx,
    pair: BidirectionalRefPair,
    substituted: Pubkey,
    replacement: Pubkey,
) -> Finding {
    let relation = if let Some(root) = pair.root {
        format!("shared root {}", root)
    } else {
        "mutual counterpart keys".to_string()
    };

    Finding {
        id: finding_id("CC-8.3 bidirectional-ref", &ctx.instructions[0]),
        message: format!(
            "[CC-8.3 bidirectional-ref] accounts {} and {} are linked by {}, substituted {} with same-class account {}, instr {}:{} still succeeded (missing bidirectional/shared-root field binding check)",
            pair.left,
            pair.right,
            relation,
            substituted,
            replacement,
            ctx.instructions[0].program_id,
            disc_hex(&ctx.instructions[0]),
        ),
    }
}

fn collect_bidirectional_ref_pairs(
    svm: &LiteSVM,
    instructions: &[Instruction],
) -> Vec<BidirectionalRefPair> {
    let current_accounts = instruction_account_keys(instructions);
    let edges = collect_field_ref_edges(svm, instructions);
    let edge_set: FastHashSet<FieldRefEdge> = edges.iter().copied().collect();
    let mut pairs = Vec::new();
    let mut seen = FastHashSet::default();

    for edge in &edges {
        if edge.source.to_bytes() >= edge.target.to_bytes() {
            continue;
        }
        let reverse = FieldRefEdge {
            source: edge.target,
            target: edge.source,
        };
        if edge_set.contains(&reverse) {
            let pair = BidirectionalRefPair {
                left: edge.source,
                right: edge.target,
                root: None,
            };
            if seen.insert(pair) {
                pairs.push(pair);
            }
        }
    }

    let mut roots: Vec<Pubkey> = current_accounts.iter().copied().collect();
    roots.sort_by_key(|pubkey| pubkey.to_bytes());

    for root in roots {
        if is_known_sysvar(&root) {
            continue;
        }
        let mut members: Vec<Pubkey> = edges
            .iter()
            .filter(|edge| edge.target == root && edge.source != root)
            .map(|edge| edge.source)
            .collect();
        members.sort_by_key(|pubkey| pubkey.to_bytes());
        members.dedup();

        for (i, left) in members.iter().enumerate() {
            for right in members.iter().skip(i + 1) {
                let pair = BidirectionalRefPair {
                    left: *left,
                    right: *right,
                    root: Some(root),
                };
                if seen.insert(pair) {
                    pairs.push(pair);
                }
            }
        }
    }

    pairs.sort_by_key(|pair| {
        (
            pair.root.map(|root| root.to_bytes()).unwrap_or([0; 32]),
            pair.left.to_bytes(),
            pair.right.to_bytes(),
        )
    });
    pairs
}

struct FieldCrossReferenceStrategy;

impl MutationStrategy for FieldCrossReferenceStrategy {
    fn probe(&self, ctx: &ProbeCtx) -> Vec<Finding> {
        let mut findings = Vec::new();
        let class_index = AccountClassIndex::build(ctx.svm, ctx.observed_accounts, ctx.config);
        let current_accounts = instruction_account_keys(ctx.instructions);

        for edge in collect_field_ref_edges(ctx.svm, ctx.instructions) {
            if !account_is_load_bearing(ctx, &edge.source) {
                continue;
            }

            let target_data_relevant = account_is_load_bearing(ctx, &edge.target);
            let Some(source_account) = ctx.svm.get_account(&edge.source) else {
                continue;
            };

            if target_data_relevant {
                for replacement in class_index.same_class_replacements(&edge.source) {
                    if current_accounts.contains(&replacement) {
                        continue;
                    }
                    let Some(replacement_account) = ctx.svm.get_account(&replacement) else {
                        continue;
                    };
                    if data_contains_pubkey(&replacement_account.data, &edge.target) {
                        continue;
                    }
                    if substitute_existing_load_bearing_account_probe(ctx, edge.source, replacement)
                    {
                        findings.push(cc8_finding(
                            ctx,
                            &class_index,
                            edge,
                            edge.source,
                            replacement,
                        ));
                    }
                }
            }

            for replacement in class_index.same_class_replacements(&edge.target) {
                if current_accounts.contains(&replacement)
                    || data_contains_pubkey(&source_account.data, &replacement)
                {
                    continue;
                }
                if target_data_relevant
                    && substitute_existing_load_bearing_account_probe(ctx, edge.target, replacement)
                {
                    findings.push(cc8_finding(
                        ctx,
                        &class_index,
                        edge,
                        edge.target,
                        replacement,
                    ));
                } else if !target_data_relevant
                    && substitute_existing_referenced_target_probe(ctx, edge.target, replacement)
                {
                    findings.push(cc8_value_ref_finding(ctx, &class_index, edge, replacement));
                }
            }
        }

        findings
    }
}

fn cc8_finding(
    ctx: &ProbeCtx,
    class_index: &AccountClassIndex,
    edge: FieldRefEdge,
    substituted: Pubkey,
    replacement: Pubkey,
) -> Finding {
    let opposite = if substituted == edge.source {
        edge.target
    } else {
        edge.source
    };
    let (class, label) = if class_index.class_count(&opposite) <= 1 {
        ("CC-8 root-ref", "[CC-8 root-ref]")
    } else {
        ("CC-8 field-ref", "[CC-8 field-ref]")
    };

    Finding {
        id: finding_id(class, &ctx.instructions[0]),
        message: format!(
            "{} account {} references {}, substituted {} with same-class account {}, instr {}:{} still succeeded (missing field cross-reference check)",
            label,
            edge.source,
            edge.target,
            substituted,
            replacement,
            ctx.instructions[0].program_id,
            disc_hex(&ctx.instructions[0]),
        ),
    }
}

fn cc8_value_ref_finding(
    ctx: &ProbeCtx,
    class_index: &AccountClassIndex,
    edge: FieldRefEdge,
    replacement: Pubkey,
) -> Finding {
    Finding {
        id: finding_id("CC-8 value-ref", &ctx.instructions[0]),
        message: format!(
            "[CC-8 value-ref] account {} references {}, substituted referenced account with same-class account {} ({}), instr {}:{} still succeeded (missing referenced account binding check)",
            edge.source,
            edge.target,
            replacement,
            class_index.class_label(&replacement),
            ctx.instructions[0].program_id,
            disc_hex(&ctx.instructions[0]),
        ),
    }
}

fn collect_field_ref_edges(svm: &LiteSVM, instructions: &[Instruction]) -> Vec<FieldRefEdge> {
    let current_accounts = instruction_account_keys(instructions);
    let mut edges = Vec::new();
    let mut seen = FastHashSet::default();

    for source in &current_accounts {
        if is_known_sysvar(source) {
            continue;
        }
        let Some(account) = svm.get_account(source) else {
            continue;
        };
        if account.executable || account.data.is_empty() || is_spl_token_shape(&account) {
            continue;
        }
        for target in &current_accounts {
            if source == target || is_known_sysvar(target) || target == &Pubkey::default() {
                continue;
            }
            let Some(target_account) = svm.get_account(target) else {
                continue;
            };
            if is_spl_token_shape(&target_account) {
                continue;
            }
            let edge = FieldRefEdge {
                source: *source,
                target: *target,
            };
            if data_contains_pubkey(&account.data, target) && seen.insert(edge) {
                edges.push(edge);
            }
        }
    }

    edges.sort_by_key(|edge| (edge.source.to_bytes(), edge.target.to_bytes()));
    edges
}

fn data_contains_pubkey(data: &[u8], pubkey: &Pubkey) -> bool {
    data.windows(32).any(|window| window == pubkey.as_ref())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SemanticSwapCandidate {
    target: Pubkey,
    replacement: Pubkey,
    target_keys: Vec<Pubkey>,
    replacement_keys: Vec<Pubkey>,
}

struct SemanticSwapStrategy;

impl MutationStrategy for SemanticSwapStrategy {
    fn probe(&self, ctx: &ProbeCtx) -> Vec<Finding> {
        let class_index = AccountClassIndex::build(ctx.svm, ctx.observed_accounts, ctx.config);
        let mut findings = Vec::new();

        for candidate in collect_semantic_swap_candidates(ctx, &class_index) {
            if !account_is_load_bearing(ctx, &candidate.target) {
                continue;
            }
            if substitute_existing_load_bearing_account_probe(
                ctx,
                candidate.target,
                candidate.replacement,
            ) {
                findings.push(cc86_finding(ctx, &class_index, &candidate));
            }
        }

        findings
    }
}

fn collect_semantic_swap_candidates(
    ctx: &ProbeCtx,
    class_index: &AccountClassIndex,
) -> Vec<SemanticSwapCandidate> {
    collect_semantic_swap_candidates_for_accounts(
        ctx.svm,
        ctx.instructions,
        ctx.observed_accounts,
        ctx.config,
        class_index,
    )
}

fn collect_semantic_swap_candidates_for_accounts(
    svm: &LiteSVM,
    instructions: &[Instruction],
    observed_accounts: &HashSet<Pubkey>,
    config: &AccountMutationConfig,
    class_index: &AccountClassIndex,
) -> Vec<SemanticSwapCandidate> {
    let current_accounts = instruction_account_keys(instructions);
    let explained_accounts = collect_explained_cc8_accounts(svm, instructions);
    let mut targets: Vec<Pubkey> = current_accounts.iter().copied().collect();
    targets.sort_by_key(|pubkey| pubkey.to_bytes());

    let mut candidates = Vec::new();
    for target in targets {
        if config.unverified_accounts.contains(&target)
            || is_known_sysvar(&target)
            || explained_accounts.contains(&target)
        {
            continue;
        }
        let Some(account) = svm.get_account(&target) else {
            continue;
        };
        if account.executable || account.data.is_empty() || is_spl_token_shape(&account) {
            continue;
        }

        let target_keys = embedded_observed_pubkeys(&account.data, observed_accounts);
        if target_keys.is_empty() {
            continue;
        }

        for replacement in class_index.same_class_replacements(&target) {
            if current_accounts.contains(&replacement)
                || config.unverified_accounts.contains(&replacement)
                || explained_accounts.contains(&replacement)
            {
                continue;
            }
            let Some(replacement_account) = svm.get_account(&replacement) else {
                continue;
            };
            if is_spl_token_shape(&replacement_account) {
                continue;
            }
            let replacement_keys =
                embedded_observed_pubkeys(&replacement_account.data, observed_accounts);
            if replacement_keys.is_empty() || replacement_keys == target_keys {
                continue;
            }
            candidates.push(SemanticSwapCandidate {
                target,
                replacement,
                target_keys: target_keys.clone(),
                replacement_keys,
            });
        }
    }

    candidates
}

fn collect_explained_cc8_accounts(
    svm: &LiteSVM,
    instructions: &[Instruction],
) -> FastHashSet<Pubkey> {
    let mut explained = FastHashSet::default();
    for edge in collect_field_ref_edges(svm, instructions) {
        explained.insert(edge.source);
        explained.insert(edge.target);
    }
    for pair in collect_bidirectional_ref_pairs(svm, instructions) {
        explained.insert(pair.left);
        explained.insert(pair.right);
        if let Some(root) = pair.root {
            explained.insert(root);
        }
    }
    explained
}

fn embedded_observed_pubkeys(data: &[u8], observed_accounts: &HashSet<Pubkey>) -> Vec<Pubkey> {
    let mut keys = FastHashSet::default();
    for window in data.windows(32) {
        let pubkey = Pubkey::new_from_array(window.try_into().unwrap());
        if pubkey != Pubkey::default()
            && !is_known_sysvar(&pubkey)
            && observed_accounts.contains(&pubkey)
        {
            keys.insert(pubkey);
        }
    }
    let mut keys: Vec<Pubkey> = keys.into_iter().collect();
    keys.sort_by_key(|pubkey| pubkey.to_bytes());
    keys
}

fn cc86_finding(
    ctx: &ProbeCtx,
    class_index: &AccountClassIndex,
    candidate: &SemanticSwapCandidate,
) -> Finding {
    Finding {
        id: finding_id("CC-8.6 semantic-swap", &ctx.instructions[0]),
        message: format!(
            "[CC-8.6 semantic-swap] account {} ({}) has embedded-key profile with {} observed key(s), substituted with same-class account {} with {} observed key(s), instr {}:{} still succeeded (missing semantic same-class binding check)",
            candidate.target,
            class_index.class_label(&candidate.target),
            candidate.target_keys.len(),
            candidate.replacement,
            candidate.replacement_keys.len(),
            ctx.instructions[0].program_id,
            disc_hex(&ctx.instructions[0]),
        ),
    }
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
            if sysvar_substitution_probe(ctx, target, decoy) {
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

fn sysvar_substitution_probe(ctx: &ProbeCtx, target: Pubkey, decoy: Pubkey) -> bool {
    let mut probe = ctx.svm.clone();
    let Some(account) = probe.get_account(&target) else {
        return false;
    };
    if probe.set_account(decoy, account).is_err() {
        return false;
    }
    if !poison_canonical_sysvar(&mut probe, target) {
        return false;
    }

    let rewritten = rewrite_account(ctx.instructions, target, decoy);
    probe_matches_baseline_effects(ctx, &mut probe, &rewritten, &[(target, decoy)], &[])
}

fn poison_canonical_sysvar(svm: &mut LiteSVM, target: Pubkey) -> bool {
    if target == solana_sysvar::clock::ID {
        let mut sysvar = svm.get_sysvar::<solana_sysvar::clock::Clock>();
        sysvar.slot = sysvar.slot.wrapping_add(1);
        sysvar.unix_timestamp = sysvar.unix_timestamp.wrapping_add(1);
        svm.set_sysvar(&sysvar);
        return true;
    }

    if target == solana_sysvar::epoch_rewards::ID {
        let mut sysvar = svm.get_sysvar::<solana_sysvar::epoch_rewards::EpochRewards>();
        sysvar.distribution_starting_block_height =
            sysvar.distribution_starting_block_height.wrapping_add(1);
        sysvar.active = !sysvar.active;
        svm.set_sysvar(&sysvar);
        return true;
    }

    if target == solana_sysvar::epoch_schedule::ID {
        let sysvar = solana_sysvar::epoch_schedule::EpochSchedule::without_warmup();
        svm.set_sysvar(&sysvar);
        return true;
    }

    #[allow(deprecated)]
    if target == solana_sysvar::fees::ID {
        let mut sysvar = svm.get_sysvar::<solana_sysvar::fees::Fees>();
        sysvar.fee_calculator.lamports_per_signature =
            sysvar.fee_calculator.lamports_per_signature.wrapping_add(1);
        svm.set_sysvar(&sysvar);
        return true;
    }

    if target == solana_sysvar::last_restart_slot::ID {
        let mut sysvar = svm.get_sysvar::<solana_sysvar::last_restart_slot::LastRestartSlot>();
        sysvar.last_restart_slot = sysvar.last_restart_slot.wrapping_add(1);
        svm.set_sysvar(&sysvar);
        return true;
    }

    if target == solana_sysvar::rent::ID {
        let mut sysvar = svm.get_sysvar::<solana_sysvar::rent::Rent>();
        #[allow(deprecated)]
        {
            sysvar.lamports_per_byte_year = sysvar.lamports_per_byte_year.wrapping_add(1);
        }
        svm.set_sysvar(&sysvar);
        return true;
    }

    if target == solana_sysvar::slot_history::ID {
        let mut sysvar = svm.get_sysvar::<solana_sysvar::slot_history::SlotHistory>();
        sysvar.add(sysvar.next_slot.wrapping_add(1));
        svm.set_sysvar(&sysvar);
        return true;
    }

    false
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

fn baseline_has_non_fee_effect(ctx: &ProbeCtx) -> bool {
    baseline_has_non_fee_effect_between(
        ctx.svm,
        ctx.baseline_after,
        ctx.instructions,
        ctx.payer.pubkey(),
    )
}

fn baseline_has_non_fee_effect_between(
    before: &LiteSVM,
    after: &LiteSVM,
    instructions: &[Instruction],
    payer: Pubkey,
) -> bool {
    instruction_account_keys(instructions)
        .into_iter()
        .filter(|key| *key != payer)
        .any(|key| !same_account_state(before.get_account(&key), after.get_account(&key)))
}

fn account_is_identity_relevant(ctx: &ProbeCtx, pubkey: &Pubkey) -> bool {
    account_is_load_bearing(ctx, pubkey) || account_is_lamport_bearing(ctx, pubkey)
}

fn replacement_is_load_bearing_under_rewrite(
    ctx: &ProbeCtx,
    target: Pubkey,
    replacement: Pubkey,
    rewritten: &[Instruction],
) -> bool {
    let Some(account) = ctx.svm.get_account(&replacement) else {
        return false;
    };
    if account.data.is_empty() {
        return false;
    }

    for data in data_corruption_variants(&account.data) {
        let mut probe = ctx.svm.clone();
        let Some(mut account) = probe.get_account(&replacement) else {
            continue;
        };
        account.data = data;
        let _ = probe.set_account(replacement, account);

        if !matches!(
            send_probe_transaction(&mut probe, rewritten, ctx.signers, ctx.payer, ctx.sigverify),
            Ok(Ok(_))
        ) {
            return true;
        }

        if !post_state_matches(
            ctx.baseline_after,
            &probe,
            ctx.instructions,
            rewritten,
            &[],
            &[target, replacement],
            ctx.payer.pubkey(),
        ) {
            return true;
        }
    }

    false
}

/// Relevance gate: corrupt account data and replay. If corruption still succeeds, the account is
/// treated as inert for structural probes.
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

        if !post_state_matches(
            ctx.baseline_after,
            &probe,
            ctx.instructions,
            ctx.instructions,
            &[],
            &[*pubkey],
            ctx.payer.pubkey(),
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
    use anchor_lang::solana_program::program_option::COption;
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

    fn packed_mint(decimals: u8) -> Vec<u8> {
        let mut data = vec![0; spl_token::state::Mint::LEN];
        spl_token::state::Mint::pack(
            spl_token::state::Mint {
                mint_authority: COption::None,
                supply: 0,
                decimals,
                is_initialized: true,
                freeze_authority: COption::None,
            },
            &mut data,
        )
        .unwrap();
        data
    }

    fn packed_token_account(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
        let mut data = vec![0; spl_token::state::Account::LEN];
        spl_token::state::Account::pack(
            spl_token::state::Account {
                mint,
                owner,
                amount,
                delegate: COption::None,
                state: spl_token::state::AccountState::Initialized,
                is_native: COption::None,
                delegated_amount: 0,
                close_authority: COption::None,
            },
            &mut data,
        )
        .unwrap();
        data
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
    fn select_finding_prefers_value_ref_unless_replay_targets_exact_id() {
        let ix = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![],
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let field_id = finding_id("CC-8 field-ref", &ix);
        let value_id = finding_id("CC-8 value-ref", &ix);
        let findings = vec![
            Finding {
                id: field_id.clone(),
                message: "field".to_string(),
            },
            Finding {
                id: value_id.clone(),
                message: "value".to_string(),
            },
        ];

        assert_eq!(select_finding(&findings, None).unwrap().id, value_id);
        assert_eq!(
            select_finding(&findings, Some(&field_id)).unwrap().id,
            field_id
        );
        assert!(select_finding(&findings, Some("missing")).is_none());
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
    fn collect_token_shape_candidates_picks_initialized_mint_and_token_account() {
        let mut svm = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let mint = on_curve_pubkey();
        let token_account = on_curve_pubkey();
        let owner = on_curve_pubkey();
        let random_data = on_curve_pubkey();

        svm.set_account(mint, make_account(spl_token::id(), packed_mint(6)))
            .unwrap();
        svm.set_account(
            token_account,
            make_account(spl_token::id(), packed_token_account(mint, owner, 10)),
        )
        .unwrap();
        svm.set_account(random_data, make_account(spl_token::id(), vec![1; 32]))
            .unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(token_account, false),
                AccountMeta::new_readonly(random_data, false),
            ],
            data: vec![],
        };

        assert_eq!(
            collect_token_shape_candidates(&svm, &[ix]),
            vec![
                TokenShapeCandidate {
                    pubkey: mint,
                    owner: spl_token::id(),
                    kind: TokenShapeKind::Mint,
                },
                TokenShapeCandidate {
                    pubkey: token_account,
                    owner: spl_token::id(),
                    kind: TokenShapeKind::Account,
                },
            ]
        );
    }

    #[test]
    fn collect_token_relation_candidates_requires_a_mint_account() {
        let mut svm = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let mint = on_curve_pubkey();
        let token_account = on_curve_pubkey();
        let owner = on_curve_pubkey();

        svm.set_account(
            token_account,
            make_account(spl_token::id(), packed_token_account(mint, owner, 10)),
        )
        .unwrap();

        let token_only_ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new_readonly(token_account, false)],
            data: vec![],
        };
        let (token_accounts, mints) = collect_token_relation_candidates(&svm, &[token_only_ix]);
        assert_eq!(token_accounts.len(), 1);
        assert!(mints.is_empty());

        svm.set_account(mint, make_account(spl_token::id(), packed_mint(6)))
            .unwrap();
        let paired_ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(token_account, false),
                AccountMeta::new_readonly(mint, false),
            ],
            data: vec![],
        };
        let (token_accounts, mints) = collect_token_relation_candidates(&svm, &[paired_ix]);
        assert_eq!(token_accounts.len(), 1);
        assert_eq!(mints, vec![MintCandidate { pubkey: mint }]);
    }

    #[test]
    fn baseline_has_non_fee_effect_ignores_payer_only_changes() {
        let mut before = LiteSVM::new();
        let mut after = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let payer = on_curve_pubkey();
        let target = on_curve_pubkey();

        before
            .set_account(payer, make_account(owner, vec![1; 8]))
            .unwrap();
        before
            .set_account(target, make_account(owner, vec![2; 8]))
            .unwrap();
        after
            .set_account(payer, make_account(owner, vec![1; 8]))
            .unwrap();
        after
            .set_account(target, make_account(owner, vec![2; 8]))
            .unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(target, false),
            ],
            data: vec![],
        };
        assert!(!baseline_has_non_fee_effect_between(
            &before,
            &after,
            std::slice::from_ref(&ix),
            payer,
        ));

        after
            .set_account(payer, make_account(owner, vec![9; 8]))
            .unwrap();
        assert!(!baseline_has_non_fee_effect_between(
            &before,
            &after,
            std::slice::from_ref(&ix),
            payer,
        ));

        after
            .set_account(target, make_account(owner, vec![3; 8]))
            .unwrap();
        assert!(baseline_has_non_fee_effect_between(
            &before,
            &after,
            &[ix],
            payer,
        ));
    }

    #[test]
    fn baseline_has_non_fee_effect_detects_account_closure() {
        let mut before = LiteSVM::new();
        let after = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let payer = on_curve_pubkey();
        let target = on_curve_pubkey();

        before
            .set_account(target, make_account(owner, vec![2; 8]))
            .unwrap();
        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(target, false)],
            data: vec![],
        };
        assert!(baseline_has_non_fee_effect_between(
            &before,
            &after,
            &[ix],
            payer,
        ));
    }

    #[test]
    fn token_account_amount_equality_is_not_required_for_wrong_mint_gate() {
        let mut before = LiteSVM::new();
        let mut after = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let mint = on_curve_pubkey();
        let owner = on_curve_pubkey();
        let payer = on_curve_pubkey();
        let token_account = on_curve_pubkey();
        let state = on_curve_pubkey();

        for svm in [&mut before, &mut after] {
            svm.set_account(
                token_account,
                make_account(spl_token::id(), packed_token_account(mint, owner, 10)),
            )
            .unwrap();
        }
        after
            .set_account(state, make_account(owner, vec![3; 8]))
            .unwrap();
        before
            .set_account(state, make_account(owner, vec![2; 8]))
            .unwrap();
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(token_account, false),
                AccountMeta::new(state, false),
            ],
            data: vec![],
        };

        assert!(baseline_has_non_fee_effect_between(
            &before,
            &after,
            &[ix],
            payer,
        ));
    }

    #[test]
    fn account_class_index_groups_same_shape_and_skips_singletons() {
        let mut svm = LiteSVM::new();
        let owner = Pubkey::new_unique();
        let same_a = on_curve_pubkey();
        let same_b = on_curve_pubkey();
        let singleton = on_curve_pubkey();
        let empty = on_curve_pubkey();

        let mut same_a_data = vec![0xAA; 8];
        same_a_data.extend_from_slice(&[1; 8]);
        let mut same_b_data = vec![0xAA; 8];
        same_b_data.extend_from_slice(&[2; 8]);
        let mut singleton_data = vec![0xBB; 8];
        singleton_data.extend_from_slice(&[3; 16]);
        svm.set_account(same_a, make_account(owner, same_a_data))
            .unwrap();
        svm.set_account(same_b, make_account(owner, same_b_data))
            .unwrap();
        svm.set_account(singleton, make_account(owner, singleton_data))
            .unwrap();
        svm.set_account(empty, make_account(owner, Vec::new()))
            .unwrap();

        let observed = HashSet::from([same_a, same_b, singleton, empty]);
        let index = AccountClassIndex::build(&svm, &observed, &AccountMutationConfig::default());

        assert_eq!(index.class_count(&same_a), 2);
        assert_eq!(index.class_count(&singleton), 1);
        assert_eq!(index.class_count(&empty), 0);
        assert_eq!(index.same_class_replacements(&same_a), vec![same_b]);
        assert!(index.same_class_replacements(&singleton).is_empty());
    }

    #[test]
    fn collect_field_ref_edges_finds_pubkey_embedded_in_account_data() {
        let mut svm = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let source = Pubkey::new_from_array([1; 32]);
        let target = Pubkey::new_from_array([2; 32]);
        let unrelated = Pubkey::new_from_array([3; 32]);
        let mut source_data = vec![9; 7];
        source_data.extend_from_slice(target.as_ref());
        source_data.extend_from_slice(&[8; 5]);

        svm.set_account(source, make_account(owner, source_data))
            .unwrap();
        svm.set_account(target, make_account(owner, vec![4; 16]))
            .unwrap();
        svm.set_account(unrelated, make_account(owner, vec![5; 16]))
            .unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(source, false),
                AccountMeta::new_readonly(target, false),
                AccountMeta::new_readonly(unrelated, false),
            ],
            data: vec![],
        };

        assert_eq!(
            collect_field_ref_edges(&svm, &[ix]),
            vec![FieldRefEdge { source, target }]
        );
    }

    #[test]
    fn collect_field_ref_edges_skips_spl_token_accounts() {
        let mut svm = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let mint = on_curve_pubkey();
        let token_owner = on_curve_pubkey();
        let token_account = on_curve_pubkey();

        svm.set_account(mint, make_account(spl_token::id(), packed_mint(6)))
            .unwrap();
        svm.set_account(token_owner, make_account(system_program::id(), vec![1; 8]))
            .unwrap();
        svm.set_account(
            token_account,
            make_account(spl_token::id(), packed_token_account(mint, token_owner, 10)),
        )
        .unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(token_account, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(token_owner, false),
            ],
            data: vec![],
        };

        assert!(collect_field_ref_edges(&svm, &[ix]).is_empty());
    }

    #[test]
    fn semantic_swap_candidates_require_same_class_with_different_embedded_keys() {
        let mut svm = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let target = Pubkey::new_from_array([1; 32]);
        let replacement = Pubkey::new_from_array([2; 32]);
        let target_key = Pubkey::new_from_array([3; 32]);
        let replacement_key = Pubkey::new_from_array([4; 32]);

        let mut target_data = vec![0xAA; 8];
        target_data.extend_from_slice(target_key.as_ref());
        target_data.extend_from_slice(&1u64.to_le_bytes());
        let mut replacement_data = vec![0xAA; 8];
        replacement_data.extend_from_slice(replacement_key.as_ref());
        replacement_data.extend_from_slice(&1u64.to_le_bytes());

        svm.set_account(target, make_account(owner, target_data))
            .unwrap();
        svm.set_account(replacement, make_account(owner, replacement_data))
            .unwrap();

        let observed = HashSet::from([target, replacement, target_key, replacement_key]);
        let config = AccountMutationConfig::default();
        let index = AccountClassIndex::build(&svm, &observed, &config);
        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new_readonly(target, false)],
            data: vec![],
        };

        assert_eq!(
            collect_semantic_swap_candidates_for_accounts(&svm, &[ix], &observed, &config, &index,),
            vec![SemanticSwapCandidate {
                target,
                replacement,
                target_keys: vec![target_key],
                replacement_keys: vec![replacement_key],
            }]
        );
    }

    #[test]
    fn semantic_swap_candidates_skip_singletons_current_accounts_and_accounts_without_keys() {
        let mut svm = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let target = Pubkey::new_from_array([1; 32]);
        let replacement = Pubkey::new_from_array([2; 32]);
        let target_key = Pubkey::new_from_array([3; 32]);
        let replacement_key = Pubkey::new_from_array([4; 32]);

        let mut target_data = vec![0xAA; 8];
        target_data.extend_from_slice(target_key.as_ref());
        let mut replacement_data = vec![0xAA; 8];
        replacement_data.extend_from_slice(replacement_key.as_ref());

        svm.set_account(target, make_account(owner, target_data.clone()))
            .unwrap();
        let observed_singleton = HashSet::from([target, target_key]);
        let config = AccountMutationConfig::default();
        let singleton_index = AccountClassIndex::build(&svm, &observed_singleton, &config);
        let singleton_ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new_readonly(target, false)],
            data: vec![],
        };
        assert!(collect_semantic_swap_candidates_for_accounts(
            &svm,
            &[singleton_ix],
            &observed_singleton,
            &config,
            &singleton_index,
        )
        .is_empty());

        svm.set_account(replacement, make_account(owner, replacement_data))
            .unwrap();
        let observed = HashSet::from([target, replacement, target_key, replacement_key]);
        let index = AccountClassIndex::build(&svm, &observed, &config);
        let replacement_present_ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(target, false),
                AccountMeta::new_readonly(replacement, false),
            ],
            data: vec![],
        };
        assert!(collect_semantic_swap_candidates_for_accounts(
            &svm,
            &[replacement_present_ix],
            &observed,
            &config,
            &index,
        )
        .is_empty());

        let no_key_target = Pubkey::new_from_array([5; 32]);
        let no_key_replacement = Pubkey::new_from_array([6; 32]);
        svm.set_account(no_key_target, make_account(owner, vec![0xBB; 48]))
            .unwrap();
        svm.set_account(no_key_replacement, make_account(owner, vec![0xBB; 48]))
            .unwrap();
        let observed_no_keys = HashSet::from([no_key_target, no_key_replacement]);
        let no_key_index = AccountClassIndex::build(&svm, &observed_no_keys, &config);
        let no_key_ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new_readonly(no_key_target, false)],
            data: vec![],
        };
        assert!(collect_semantic_swap_candidates_for_accounts(
            &svm,
            &[no_key_ix],
            &observed_no_keys,
            &config,
            &no_key_index,
        )
        .is_empty());
    }

    #[test]
    fn semantic_swap_candidates_skip_accounts_explained_by_field_refs() {
        let mut svm = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let target = Pubkey::new_from_array([1; 32]);
        let replacement = Pubkey::new_from_array([2; 32]);
        let related = Pubkey::new_from_array([3; 32]);
        let replacement_key = Pubkey::new_from_array([4; 32]);

        let mut target_data = vec![0xAA; 8];
        target_data.extend_from_slice(related.as_ref());
        let mut replacement_data = vec![0xAA; 8];
        replacement_data.extend_from_slice(replacement_key.as_ref());

        svm.set_account(target, make_account(owner, target_data))
            .unwrap();
        svm.set_account(replacement, make_account(owner, replacement_data))
            .unwrap();
        svm.set_account(related, make_account(owner, vec![0xBB; 16]))
            .unwrap();

        let observed = HashSet::from([target, replacement, related, replacement_key]);
        let config = AccountMutationConfig::default();
        let index = AccountClassIndex::build(&svm, &observed, &config);
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(target, false),
                AccountMeta::new_readonly(related, false),
            ],
            data: vec![],
        };

        assert!(collect_semantic_swap_candidates_for_accounts(
            &svm,
            &[ix],
            &observed,
            &config,
            &index,
        )
        .is_empty());
    }

    #[test]
    fn collect_bidirectional_ref_pairs_finds_mutual_account_refs() {
        let mut svm = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let left = Pubkey::new_from_array([1; 32]);
        let right = Pubkey::new_from_array([2; 32]);

        let mut left_data = vec![0xAA; 8];
        left_data.extend_from_slice(right.as_ref());
        let mut right_data = vec![0xBB; 8];
        right_data.extend_from_slice(left.as_ref());

        svm.set_account(left, make_account(owner, left_data))
            .unwrap();
        svm.set_account(right, make_account(owner, right_data))
            .unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(left, false),
                AccountMeta::new_readonly(right, false),
            ],
            data: vec![],
        };

        assert_eq!(
            collect_bidirectional_ref_pairs(&svm, &[ix]),
            vec![BidirectionalRefPair {
                left,
                right,
                root: None,
            }]
        );
    }

    #[test]
    fn collect_bidirectional_ref_pairs_ignores_one_way_refs() {
        let mut svm = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let left = Pubkey::new_from_array([1; 32]);
        let right = Pubkey::new_from_array([2; 32]);

        let mut left_data = vec![0xAA; 8];
        left_data.extend_from_slice(right.as_ref());

        svm.set_account(left, make_account(owner, left_data))
            .unwrap();
        svm.set_account(right, make_account(owner, vec![0xBB; 16]))
            .unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(left, false),
                AccountMeta::new_readonly(right, false),
            ],
            data: vec![],
        };

        assert!(collect_bidirectional_ref_pairs(&svm, &[ix]).is_empty());
    }

    #[test]
    fn collect_bidirectional_ref_pairs_finds_shared_root_refs_only_when_root_is_present() {
        let mut svm = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let left = Pubkey::new_from_array([1; 32]);
        let right = Pubkey::new_from_array([2; 32]);
        let root = Pubkey::new_from_array([3; 32]);

        let mut left_data = vec![0xAA; 8];
        left_data.extend_from_slice(root.as_ref());
        let mut right_data = vec![0xBB; 8];
        right_data.extend_from_slice(root.as_ref());

        svm.set_account(left, make_account(owner, left_data))
            .unwrap();
        svm.set_account(right, make_account(owner, right_data))
            .unwrap();
        svm.set_account(root, make_account(owner, vec![0xCC; 16]))
            .unwrap();

        let root_present_ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(left, false),
                AccountMeta::new_readonly(right, false),
                AccountMeta::new_readonly(root, false),
            ],
            data: vec![],
        };
        assert_eq!(
            collect_bidirectional_ref_pairs(&svm, &[root_present_ix]),
            vec![BidirectionalRefPair {
                left,
                right,
                root: Some(root),
            }]
        );

        let root_absent_ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(left, false),
                AccountMeta::new_readonly(right, false),
            ],
            data: vec![],
        };
        assert!(collect_bidirectional_ref_pairs(&svm, &[root_absent_ix]).is_empty());
    }

    #[test]
    fn bidirectional_replacement_preserves_only_unbroken_relations() {
        let mut svm = LiteSVM::new();
        let owner = Pubkey::new_unique();
        let left = Pubkey::new_from_array([1; 32]);
        let right = Pubkey::new_from_array([2; 32]);
        let replacement_valid = Pubkey::new_from_array([3; 32]);
        let replacement_wrong = Pubkey::new_from_array([4; 32]);

        let mut right_data = vec![0xAA; 8];
        right_data.extend_from_slice(left.as_ref());
        right_data.extend_from_slice(replacement_valid.as_ref());
        let mut replacement_valid_data = vec![0xBB; 8];
        replacement_valid_data.extend_from_slice(right.as_ref());
        let replacement_wrong_data = vec![0xCC; 40];

        svm.set_account(right, make_account(owner, right_data))
            .unwrap();
        svm.set_account(
            replacement_valid,
            make_account(owner, replacement_valid_data),
        )
        .unwrap();
        svm.set_account(
            replacement_wrong,
            make_account(owner, replacement_wrong_data),
        )
        .unwrap();

        let pair = BidirectionalRefPair {
            left,
            right,
            root: None,
        };
        assert!(bidirectional_replacement_preserves_relation(
            &svm,
            pair,
            right,
            replacement_valid,
        ));
        assert!(!bidirectional_replacement_preserves_relation(
            &svm,
            pair,
            right,
            replacement_wrong,
        ));
    }

    #[test]
    fn data_contains_pubkey_matches_exact_32_byte_window() {
        let target = Pubkey::new_from_array([7; 32]);
        let mut data = vec![1; 3];
        data.extend_from_slice(target.as_ref());
        data.extend_from_slice(&[2; 3]);

        assert!(data_contains_pubkey(&data, &target));
        assert!(!data_contains_pubkey(
            &data,
            &Pubkey::new_from_array([8; 32])
        ));
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
    fn signer_probe_ignores_only_out_of_instruction_fee_payer() {
        let mut baseline = LiteSVM::new();
        let mut mutated = LiteSVM::new();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let payer = on_curve_pubkey();
        let account = on_curve_pubkey();

        baseline
            .set_account(payer, make_account(owner, vec![1; 8]))
            .unwrap();
        mutated
            .set_account(payer, make_account(owner, vec![1; 8]))
            .unwrap();
        let mut mutated_payer = mutated.get_account(&payer).unwrap();
        mutated_payer.lamports -= 5_000;
        mutated.set_account(payer, mutated_payer).unwrap();

        baseline
            .set_account(account, make_account(owner, vec![2; 8]))
            .unwrap();
        mutated
            .set_account(account, make_account(owner, vec![2; 8]))
            .unwrap();

        let ix_without_payer = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(account, false)],
            data: vec![],
        };
        let ignored =
            signer_probe_ignored_accounts(&[ix_without_payer.clone()], &[ix_without_payer], payer);
        assert_eq!(ignored, vec![payer]);
        assert!(post_state_matches(
            &baseline,
            &mutated,
            std::slice::from_ref(&Instruction {
                program_id,
                accounts: vec![AccountMeta::new(account, false)],
                data: vec![],
            }),
            std::slice::from_ref(&Instruction {
                program_id,
                accounts: vec![AccountMeta::new(account, false)],
                data: vec![],
            }),
            &[],
            &ignored,
            payer,
        ));

        let ix_with_payer = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer, false),
                AccountMeta::new(account, false),
            ],
            data: vec![],
        };
        let ignored = signer_probe_ignored_accounts(
            &[ix_with_payer.clone()],
            &[ix_with_payer.clone()],
            payer,
        );
        assert!(ignored.is_empty());
        assert!(!post_state_matches(
            &baseline,
            &mutated,
            std::slice::from_ref(&ix_with_payer),
            std::slice::from_ref(&ix_with_payer),
            &[],
            &ignored,
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
    fn token_decoy_is_on_curve_and_not_target() {
        let target = Pubkey::new_unique();
        let decoy = token_decoy_for(target);
        assert_ne!(decoy, target);
        assert!(bytes_are_curve_point(&decoy));
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
    fn poison_canonical_sysvar_changes_supported_sysvar_data() {
        let mut svm = LiteSVM::new();
        let before = svm.get_account(&solana_sysvar::rent::ID).unwrap().data;

        assert!(poison_canonical_sysvar(&mut svm, solana_sysvar::rent::ID));

        let after = svm.get_account(&solana_sysvar::rent::ID).unwrap().data;
        assert_ne!(before, after);
        assert!(!poison_canonical_sysvar(&mut svm, Pubkey::new_unique()));
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
    fn signer_meta_pubkeys_and_meta_lookup_use_instruction_flags_only() {
        let program_id = Pubkey::new_unique();
        let signer = Pubkey::new_unique();
        let non_signer = Pubkey::new_unique();
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(signer, true),
                AccountMeta::new_readonly(non_signer, false),
            ],
            data: vec![],
        };

        assert_eq!(signer_meta_pubkeys(std::slice::from_ref(&ix)), vec![signer]);
        assert!(account_has_signer_meta(std::slice::from_ref(&ix), signer));
        assert!(!account_has_signer_meta(&[ix], non_signer));
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
