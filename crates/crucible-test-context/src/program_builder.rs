use crate::instruction_builder;
use crate::{tx_result_to_outcome, TestContext, TxOutcome};
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::{InstructionData, ToAccountMetas};
use anyhow::{Context, Result};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

pub struct ProgramBuilder<'a> {
    pub(crate) ctx: &'a mut TestContext,
    pub(crate) instruction: Instruction,
    pub(crate) signers: Vec<Keypair>,
    pub(crate) fee_payer: Option<Keypair>,
}

impl ProgramBuilder<'_> {
    pub fn call<I>(mut self, instruction: I) -> Self
    where
        I: InstructionData,
    {
        self.instruction.data = instruction.data();
        self
    }

    pub fn accounts<A>(mut self, accounts: A) -> Self
    where
        A: ToAccountMetas,
    {
        self.instruction.accounts = accounts.to_account_metas(None);
        self
    }

    pub fn remaining_accounts(mut self, accounts: Vec<Pubkey>) -> Self {
        for pubkey in accounts {
            self.instruction
                .accounts
                .push(AccountMeta::new_readonly(pubkey, false));
        }
        self
    }

    pub fn remaining_accounts_metas(mut self, metas: Vec<AccountMeta>) -> Self {
        self.instruction.accounts.extend(metas);
        self
    }

    pub fn signers(mut self, signers: &[&Keypair]) -> Self {
        self.signers = signers.iter().map(|k| k.insecure_clone()).collect();
        self
    }

    pub fn fee_payer(mut self, fee_payer: &Keypair) -> Self {
        self.fee_payer = Some(fee_payer.insecure_clone());
        self
    }

    pub fn send(self) -> Result<TxOutcome> {
        // Resolve fee payer: explicit > first signer > Pubkey::default (for dirty tracking)
        let fee_payer_pubkey = self
            .fee_payer
            .as_ref()
            .map(|kp| kp.pubkey())
            .or_else(|| self.signers.first().map(|kp| kp.pubkey()))
            .unwrap_or_default();

        let mut all_signers = self.signers;
        if let Some(ref fp) = self.fee_payer {
            if !all_signers.iter().any(|k| k.pubkey() == fp.pubkey()) {
                all_signers.insert(0, fp.insecure_clone());
            }
        }
        let payer = self
            .fee_payer
            .as_ref()
            .unwrap_or(
                all_signers
                    .first()
                    .context("At least one signer required")?,
            )
            .insecure_clone();
        let signer_refs: Vec<&Keypair> = all_signers.iter().collect();
        let ixs = std::slice::from_ref(&self.instruction);

        // Pre-tx: dirty tracking
        let __t_pre = std::time::Instant::now();
        self.ctx.dirty_tracker.record_tx(ixs, &fee_payer_pubkey);
        crate::SEND_BATCH_PRE_NS.with(|c| c.set(c.get() + __t_pre.elapsed().as_nanos() as u64));

        // Account-mutation probe runs on a cloned SVM and never replaces the real outcome.
        self.ctx
            .maybe_probe_account_mutation(ixs, &signer_refs, &payer);

        // SVM execution — pass all signers, including fee payer
        let __t_svm = std::time::Instant::now();
        let result = instruction_builder::send_transaction(
            &mut self.ctx.svm,
            vec![self.instruction],
            &signer_refs,
            &payer,
            self.ctx.sigverify,
        )?;
        crate::SEND_BATCH_SVM_NS.with(|c| c.set(c.get() + __t_svm.elapsed().as_nanos() as u64));

        // Post-tx: outcome parsing
        let __t_post = std::time::Instant::now();
        let outcome = tx_result_to_outcome(result);

        // Track tx success/failure for monitor display
        crate::increment_action_count();
        if outcome.is_success() {
            crate::increment_action_success_count();
        }
        crate::SEND_BATCH_POST_NS.with(|c| c.set(c.get() + __t_post.elapsed().as_nanos() as u64));

        Ok(outcome)
    }

    pub fn add_transaction(self) -> Result<()> {
        self.ctx.pending_instructions.push(self.instruction);
        self.ctx.pending_signers.extend(self.signers);
        Ok(())
    }
}
