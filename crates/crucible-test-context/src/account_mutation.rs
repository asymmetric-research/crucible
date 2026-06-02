use crate::{record_violation, FastHashSet};
use anchor_lang::prelude::sysvar::SysvarId;
use anchor_lang::prelude::{Clock, EpochSchedule, SlotHashes, SlotHistory, StakeHistory};
use anchor_lang::solana_program::instruction::Instruction;
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

pub const DEFAULT_OWNER_MUTATION_SAMPLE_RATE: u64 = 10;
const DEFAULT_PROBES_PER_SAMPLED_TX: usize = 1;
const DEFAULT_SKIP_PDA_CANDIDATES: bool = true;

#[derive(Clone, Debug)]
pub struct AccountMutationConfig {
    enabled: bool,
    sample_rate: u64,
    probes_per_sampled_tx: usize,
    skip_pda_candidates: bool,
    unverified_accounts: FastHashSet<Pubkey>,
}

impl Default for AccountMutationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sample_rate: DEFAULT_OWNER_MUTATION_SAMPLE_RATE,
            probes_per_sampled_tx: DEFAULT_PROBES_PER_SAMPLED_TX,
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

    pub fn set_sample_rate(&mut self, sample_rate: u64) {
        self.sample_rate = sample_rate.max(1);
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

    pub fn sample_rate(&self) -> u64 {
        self.sample_rate
    }

    pub fn skip_pda_candidates(&self) -> bool {
        self.skip_pda_candidates
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnerMutationCandidate {
    pubkey: Pubkey,
    original_owner: Pubkey,
}

pub(crate) fn maybe_probe_account_mutation(
    svm: &LiteSVM,
    config: &AccountMutationConfig,
    instructions: &[Instruction],
    signers: &[&Keypair],
    payer: &Keypair,
    sigverify: bool,
) {
    if !config.enabled || instructions.is_empty() || config.probes_per_sampled_tx == 0 {
        return;
    }

    let fingerprint = transaction_fingerprint(instructions, signers, payer);
    if !should_sample(fingerprint, config.sample_rate) {
        return;
    }

    let candidates = collect_candidates(svm, instructions, config);
    if candidates.is_empty() {
        return;
    }

    // The first implementation intentionally performs one probe per sampled tx.
    // Keep the loop shape so the config can grow without changing call sites.
    for probe_idx in 0..config.probes_per_sampled_tx.min(1) {
        let candidate_idx = choose_index(
            fingerprint,
            0x9e37_79b9_7f4a_7c15u64 ^ probe_idx as u64,
            candidates.len(),
        );
        let candidate = &candidates[candidate_idx];
        let replacement_owners =
            replacement_owners(svm, instructions, candidate, fingerprint, probe_idx as u64);
        if replacement_owners.is_empty() {
            continue;
        }

        let owner_idx = choose_index(
            fingerprint,
            0xc2b2_ae3d_27d4_eb4fu64 ^ probe_idx as u64,
            replacement_owners.len(),
        );
        let replacement_owner = replacement_owners[owner_idx];

        let mut probe_svm = svm.clone();
        if let Some(mut account) = probe_svm.get_account(&candidate.pubkey) {
            account.owner = replacement_owner;
            let _ = probe_svm.set_account(candidate.pubkey, account);
        } else {
            continue;
        }

        let result =
            send_probe_transaction(&mut probe_svm, instructions, signers, payer, sigverify);
        match result {
            Ok(Ok(_)) => {
                record_violation(format!(
                    "owner mutation succeeded: account {} original_owner {} mutated_owner {} program {}",
                    candidate.pubkey,
                    candidate.original_owner,
                    replacement_owner,
                    instructions
                        .first()
                        .map(|ix| ix.program_id.to_string())
                        .unwrap_or_else(|| "<none>".to_string())
                ));
                return;
            }
            Ok(Err(_)) => {}
            Err(err) => {
                if std::env::var("FUZZ_DEBUG").is_ok() {
                    eprintln!("[OWNER_MUTATION] probe transaction failed to build: {err}");
                }
            }
        }
    }
}

fn collect_candidates(
    svm: &LiteSVM,
    instructions: &[Instruction],
    config: &AccountMutationConfig,
) -> Vec<OwnerMutationCandidate> {
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
            if account.executable {
                continue;
            }
            candidates.push(OwnerMutationCandidate {
                pubkey: meta.pubkey,
                original_owner: account.owner,
            });
        }
    }

    candidates
}

fn is_off_curve(pubkey: &Pubkey) -> bool {
    !bytes_are_curve_point(pubkey)
}

fn replacement_owners(
    svm: &LiteSVM,
    instructions: &[Instruction],
    candidate: &OwnerMutationCandidate,
    fingerprint: u64,
    probe_idx: u64,
) -> Vec<Pubkey> {
    let mut seen = FastHashSet::default();
    let mut owners = Vec::new();

    let mut push = |owner: Pubkey| {
        if owner != candidate.original_owner && seen.insert(owner) {
            owners.push(owner);
        }
    };

    push(synthetic_owner(fingerprint, candidate.pubkey, probe_idx));
    for ix in instructions {
        push(ix.program_id);
    }
    push(system_program::id());

    for ix in instructions {
        for meta in &ix.accounts {
            if meta.pubkey == candidate.pubkey {
                continue;
            }
            if let Some(account) = svm.get_account(&meta.pubkey) {
                push(account.owner);
            }
        }
    }

    owners
}

fn should_sample(fingerprint: u64, sample_rate: u64) -> bool {
    fingerprint % sample_rate.max(1) == 0
}

fn choose_index(fingerprint: u64, salt: u64, len: usize) -> usize {
    debug_assert!(len > 0);
    (mix64(fingerprint ^ salt) as usize) % len
}

fn transaction_fingerprint(
    instructions: &[Instruction],
    signers: &[&Keypair],
    payer: &Keypair,
) -> u64 {
    let mut hash = FNV_OFFSET;
    mix_bytes(&mut hash, b"crucible-owner-mutation-v1");
    mix_pubkey(&mut hash, &payer.pubkey());
    mix_u64(&mut hash, signers.len() as u64);
    for signer in signers {
        mix_pubkey(&mut hash, &signer.pubkey());
    }
    mix_u64(&mut hash, instructions.len() as u64);
    for ix in instructions {
        mix_pubkey(&mut hash, &ix.program_id);
        mix_bytes(&mut hash, &ix.data);
        mix_u64(&mut hash, ix.accounts.len() as u64);
        for meta in &ix.accounts {
            mix_pubkey(&mut hash, &meta.pubkey);
            mix_u8(&mut hash, meta.is_signer as u8);
            mix_u8(&mut hash, meta.is_writable as u8);
        }
    }
    hash
}

fn synthetic_owner(fingerprint: u64, pubkey: Pubkey, probe_idx: u64) -> Pubkey {
    let mut out = [0u8; 32];
    let mut seed = fingerprint ^ probe_idx.rotate_left(17);
    for chunk in 0..4 {
        seed = mix64(
            seed ^ u64::from_le_bytes(
                pubkey.to_bytes()[chunk * 8..chunk * 8 + 8]
                    .try_into()
                    .unwrap(),
            ),
        );
        out[chunk * 8..chunk * 8 + 8].copy_from_slice(&seed.to_le_bytes());
    }
    Pubkey::new_from_array(out)
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

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn mix_bytes(hash: &mut u64, bytes: &[u8]) {
    mix_u64(hash, bytes.len() as u64);
    for byte in bytes {
        mix_u8(hash, *byte);
    }
}

fn mix_pubkey(hash: &mut u64, pubkey: &Pubkey) {
    mix_bytes(hash, pubkey.as_ref());
}

fn mix_u8(hash: &mut u64, value: u8) {
    *hash ^= value as u64;
    *hash = hash.wrapping_mul(FNV_PRIME);
}

fn mix_u64(hash: &mut u64, value: u64) {
    for byte in value.to_le_bytes() {
        mix_u8(hash, byte);
    }
}

fn mix64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^= x >> 33;
    x
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::instruction::AccountMeta;
    use solana_account::Account;

    fn make_account(owner: Pubkey, executable: bool) -> Account {
        Account {
            lamports: 1_000_000,
            data: vec![],
            owner,
            executable,
            rent_epoch: 0,
        }
    }

    fn on_curve_pubkey() -> Pubkey {
        Keypair::new().pubkey()
    }

    #[test]
    fn owner_mutation_sampling_is_deterministic() {
        let payer = Keypair::new();
        let signer = Keypair::new();
        let account = Pubkey::new_unique();
        let ix = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![AccountMeta::new(account, false)],
            data: vec![1, 2, 3],
        };
        let signers = vec![&payer, &signer];

        let first = transaction_fingerprint(std::slice::from_ref(&ix), &signers, &payer);
        let second = transaction_fingerprint(std::slice::from_ref(&ix), &signers, &payer);

        assert_eq!(first, second);
        assert!(should_sample(first, 1));
    }

    #[test]
    fn owner_mutation_candidate_selection_filters_unverified_and_system_accounts() {
        let mut svm = LiteSVM::new();
        let mut config = AccountMutationConfig::default();
        let owner = Pubkey::new_unique();
        let keep = on_curve_pubkey();
        let unverified = on_curve_pubkey();
        let missing = Pubkey::new_unique();

        svm.set_account(keep, make_account(owner, false)).unwrap();
        svm.set_account(unverified, make_account(owner, false))
            .unwrap();

        let program_id = Pubkey::new_unique();
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(keep, false),
                AccountMeta::new(keep, false),
                AccountMeta::new(unverified, false),
                AccountMeta::new(missing, false),
                AccountMeta::new_readonly(Clock::id(), false),
                AccountMeta::new_readonly(program_id, false),
            ],
            data: vec![],
        };

        config.mark_unverified(unverified);

        let candidates = collect_candidates(&svm, &[ix], &config);

        assert_eq!(
            candidates,
            vec![OwnerMutationCandidate {
                pubkey: keep,
                original_owner: owner,
            }]
        );
    }

    #[test]
    fn owner_mutation_candidate_selection_skips_pdas_by_default() {
        let mut svm = LiteSVM::new();
        let config = AccountMutationConfig::default();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let (pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);

        svm.set_account(pda, make_account(owner, false)).unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(pda, false)],
            data: vec![],
        };

        let candidates = collect_candidates(&svm, &[ix], &config);

        assert!(candidates.is_empty());
    }

    #[test]
    fn owner_mutation_candidate_selection_can_include_pdas() {
        let mut svm = LiteSVM::new();
        let mut config = AccountMutationConfig::default();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let (pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);

        config.set_skip_pda_candidates(false);
        svm.set_account(pda, make_account(owner, false)).unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(pda, false)],
            data: vec![],
        };

        let candidates = collect_candidates(&svm, &[ix], &config);

        assert_eq!(
            candidates,
            vec![OwnerMutationCandidate {
                pubkey: pda,
                original_owner: owner,
            }]
        );
    }

    #[test]
    fn owner_mutation_replacement_owners_skip_original_and_dedupe() {
        let mut svm = LiteSVM::new();
        let original_owner = system_program::id();
        let other_owner = Pubkey::new_unique();
        let candidate_pk = on_curve_pubkey();
        let other_pk = on_curve_pubkey();
        let program_id = Pubkey::new_unique();
        let candidate = OwnerMutationCandidate {
            pubkey: candidate_pk,
            original_owner,
        };

        svm.set_account(candidate_pk, make_account(original_owner, false))
            .unwrap();
        svm.set_account(other_pk, make_account(other_owner, false))
            .unwrap();

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(candidate_pk, false),
                AccountMeta::new(other_pk, false),
            ],
            data: vec![],
        };

        let owners = replacement_owners(&svm, &[ix], &candidate, 42, 0);
        let unique: FastHashSet<_> = owners.iter().copied().collect();

        assert_eq!(owners.len(), unique.len());
        assert!(!owners.contains(&original_owner));
        assert!(owners.contains(&program_id));
        assert!(owners.contains(&other_owner));
    }
}
