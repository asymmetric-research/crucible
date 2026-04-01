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
        let fee_payer_pubkey = self
            .fee_payer
            .as_ref()
            .map(|kp| kp.pubkey())
            .context("At least one signer required if fee payer is not set explicitly")?;

        let fee_payer = self
            .fee_payer
            .as_ref()
            .or(self.signers.first())
            .context("At least one signer required if fee payer is not set explicitly")?
            .insecure_clone();

        let ixs = std::slice::from_ref(&self.instruction);

        // Pre-tx: dirty tracking + metadata capture
        let __t_pre = std::time::Instant::now();
        self.ctx.dirty_tracker.record_tx(ixs, &fee_payer_pubkey);
        let captured = crate::snapshot::capture_tx_meta(ixs, &fee_payer_pubkey);
        let pre_state = if self.ctx.taint_log.collects_diffs() {
            Some(crate::snapshot::snapshot_writable_accounts(
                &self.ctx.svm,
                ixs,
                &fee_payer_pubkey,
            ))
        } else {
            None
        };
        crate::SEND_BATCH_PRE_NS.with(|c| c.set(c.get() + __t_pre.elapsed().as_nanos() as u64));

        // SVM execution
        let __t_svm = std::time::Instant::now();
        let result = instruction_builder::send_instruction(
            &mut self.ctx.svm,
            self.instruction,
            &self.signers,
            &fee_payer,
        )?;
        crate::SEND_BATCH_SVM_NS.with(|c| c.set(c.get() + __t_svm.elapsed().as_nanos() as u64));

        // Post-tx: outcome parsing + taint record
        let __t_post = std::time::Instant::now();
        let outcome = tx_result_to_outcome(result);

        // Track tx success/failure for monitor display
        crate::increment_action_count();
        if outcome.is_success() {
            crate::increment_action_success_count();
        }

        // Build taint record from captured metadata (only for successful txs)
        if outcome.is_success() {
            let taint = crate::snapshot::build_taint_record_from_captured(
                &self.ctx.svm,
                captured,
                pre_state.as_ref(),
            );
            self.ctx.taint_log.push(taint);
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
