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
    matches!(
        send_probe_transaction(
            &mut probe,
            &rewritten,
            ctx.signers,
            ctx.payer,
            ctx.sigverify
        ),
        Ok(Ok(_))
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
    message: String,
}

/// Inputs shared by every strategy. Borrows the pre-transaction (baseline) SVM, which is never
/// mutated — strategies clone it for each probe.
struct ProbeCtx<'a> {
    svm: &'a LiteSVM,
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
        Box::new(OwnerStrategy),
        Box::new(SignerStrategy),
        Box::new(TypeTagStrategy),
        Box::new(PdaSubstitutionStrategy),
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

    // The violation TLS holds one message per iteration and the harness early-exits on the first,
    // so surface the first finding and log the rest for debugging.
    if let Some(first) = findings.first() {
        record_mutation_violation(first.message.clone());
        if std::env::var("FUZZ_DEBUG").is_ok() {
            for extra in &findings[1..] {
                eprintln!("[ACCOUNT_MUTATION] additional finding: {}", extra.message);
            }
        }
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

            if let Ok(Ok(_)) = send_probe_transaction(
                &mut probe,
                ctx.instructions,
                ctx.signers,
                ctx.payer,
                ctx.sigverify,
            ) {
                findings.push(Finding {
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

            if let Ok(Ok(_)) = send_probe_transaction(
                &mut probe,
                ctx.instructions,
                ctx.signers,
                ctx.payer,
                ctx.sigverify,
            ) {
                findings.push(Finding {
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
            if let Ok(Ok(_)) =
                send_probe_transaction(&mut probe, &flipped, ctx.signers, ctx.payer, ctx.sigverify)
            {
                let detail = match candidate.kind {
                    SignerCandidateKind::MetaSigner => "is_signer cleared",
                    SignerCandidateKind::SuppliedSigner => {
                        "signer keypair supplied but account meta was not signer"
                    }
                };
                findings.push(Finding {
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
        for target in collect_pda_candidates(ctx.svm, ctx.instructions) {
            // Relevance gate: a PDA the program never reads is not exploitable.
            if !account_is_load_bearing(ctx, &target) {
                continue;
            }
            let decoy = decoy_for(target);
            if substitute_probe(ctx, target, decoy) {
                findings.push(Finding {
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

/// CC-3 targets: off-curve (PDA-like), data-bearing, non-executable, non-sysvar accounts. These are
/// exactly the addresses the owner strategy skips by default — PDA identity is the derivation check,
/// which the owner check subsumes once present.
fn collect_pda_candidates(svm: &LiteSVM, instructions: &[Instruction]) -> Vec<Pubkey> {
    let mut seen = FastHashSet::default();
    let mut candidates = Vec::new();
    for ix in instructions {
        for meta in &ix.accounts {
            if !seen.insert(meta.pubkey) {
                continue;
            }
            if meta.pubkey == ix.program_id
                || is_known_sysvar(&meta.pubkey)
                || !is_off_curve(&meta.pubkey)
            {
                continue;
            }
            let Some(account) = svm.get_account(&meta.pubkey) else {
                continue;
            };
            if account.executable || account.data.is_empty() {
                continue;
            }
            candidates.push(meta.pubkey);
        }
    }
    candidates
}

/// Owner-mutation targets: non-executable, non-sysvar, data-bearing accounts. Writable accounts are
/// included (a probe that triggers a runtime ownership failure simply does not report). PDA-like
/// (off-curve) addresses are skipped by default — they are covered by the CC-3 derivation check;
/// set `skip_pda_candidates=false` to also owner-probe them.
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

        // Default: PDAs are skipped by the owner strategy (CC-3 owns PDA identity).
        let mut config = AccountMutationConfig::default();
        assert!(collect_owner_candidates(&svm, std::slice::from_ref(&ix), &config).is_empty());

        // Opt-in: also owner-probe PDAs.
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
    fn collect_pda_candidates_keeps_offcurve_data_accounts_only() {
        let mut svm = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let (pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);
        let on_curve = Keypair::new().pubkey();
        svm.set_account(pda, make_account(owner, vec![7; 16]))
            .unwrap();
        svm.set_account(on_curve, make_account(owner, vec![7; 16]))
            .unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(pda, false),
                AccountMeta::new_readonly(on_curve, false), // on-curve -> dropped
                AccountMeta::new_readonly(Clock::id(), false), // sysvar -> dropped
            ],
            data: vec![],
        };
        assert_eq!(collect_pda_candidates(&svm, &[ix]), vec![pda]);
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
