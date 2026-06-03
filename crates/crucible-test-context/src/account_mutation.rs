use crate::{record_violation, FastHashSet};
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
    vec![Box::new(OwnerStrategy)]
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
        record_violation(first.message.clone());
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

/// Owner-mutation targets: non-signer, read-only, non-executable, non-sysvar, non-PDA accounts
/// that carry data. Read-only because the runtime's write-ownership rule would reject a mutated
/// owner on a *writable* account for a non-program reason (inconclusive); data-bearing because an
/// owner check is only exploitable on accounts the program actually deserializes.
fn collect_owner_candidates(
    svm: &LiteSVM,
    instructions: &[Instruction],
    config: &AccountMutationConfig,
) -> Vec<OwnerCandidate> {
    // An account writable in *any* instruction is excluded.
    let mut writable_anywhere = FastHashSet::default();
    for ix in instructions {
        for meta in &ix.accounts {
            if meta.is_writable {
                writable_anywhere.insert(meta.pubkey);
            }
        }
    }

    let mut seen = FastHashSet::default();
    let mut candidates = Vec::new();
    for ix in instructions {
        for meta in &ix.accounts {
            if !seen.insert(meta.pubkey) {
                continue;
            }
            if meta.pubkey == ix.program_id
                || writable_anywhere.contains(&meta.pubkey)
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

/// Relevance gate (Neodyme-style): corrupt the account body — preserving the 8-byte discriminator
/// so the type tag still matches — and replay. If the transaction still succeeds the program never
/// read the contents (inert account), so a surviving owner mutation would be a false positive.
/// Accounts too small to have a body have all their bytes corrupted.
fn account_is_load_bearing(ctx: &ProbeCtx, pubkey: &Pubkey) -> bool {
    let mut probe = ctx.svm.clone();
    let Some(mut account) = probe.get_account(pubkey) else {
        return false;
    };
    if account.data.is_empty() {
        return false;
    }
    if account.data.len() <= 8 {
        account.data.iter_mut().for_each(|b| *b = 0xFF);
    } else {
        account.data[8..].iter_mut().for_each(|b| *b = 0xFF);
    }
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
    fn collect_owner_candidates_keeps_only_readonly_data_accounts() {
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
                AccountMeta::new(writable, false), // writable -> dropped
                AccountMeta::new_readonly(empty, false), // empty data -> dropped
                AccountMeta::new_readonly(Clock::id(), false), // sysvar -> dropped
                AccountMeta::new_readonly(program_id, false), // program id -> dropped
            ],
            data: vec![],
        };

        let candidates = collect_owner_candidates(&svm, &[ix], &config);
        assert_eq!(
            candidates,
            vec![OwnerCandidate {
                pubkey: keep,
                original_owner: owner,
            }]
        );
    }

    #[test]
    fn collect_owner_candidates_drops_account_writable_in_any_instruction() {
        let mut svm = LiteSVM::new();
        let config = AccountMutationConfig::default();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let acct = on_curve_pubkey();
        svm.set_account(acct, make_account(owner, vec![9; 16]))
            .unwrap();

        // read-only in ix0 but writable in ix1 -> excluded
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

        assert!(collect_owner_candidates(&svm, &[ix0, ix1], &config).is_empty());
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
    fn wrong_owner_uses_alt_when_already_attacker() {
        assert_eq!(wrong_owner(Pubkey::new_unique()), CRUCIBLE_ATTACKER);
        assert_eq!(wrong_owner(CRUCIBLE_ATTACKER), CRUCIBLE_ATTACKER_ALT);
    }
}
