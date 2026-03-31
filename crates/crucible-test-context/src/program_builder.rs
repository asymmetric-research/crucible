use crate::{TestContext, TxOutcome, tx_result_to_outcome};
use solana_pubkey::Pubkey;
use solana_keypair::Keypair;
use solana_signer::Signer;
use anchor_lang::solana_program::instruction::{Instruction, AccountMeta};
use anchor_lang::{InstructionData, ToAccountMetas};
use anyhow::Result;
use crate::instruction_builder;

pub struct ProgramBuilder<'a> {
    pub(crate) ctx: &'a mut TestContext,
    pub(crate) instruction: Instruction,
    pub(crate) signers: Vec<Keypair>,
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
            self.instruction.accounts.push(AccountMeta::new_readonly(pubkey, false));
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

    pub fn send(self) -> Result<TxOutcome> {
        let fee_payer = self.signers.first().map(|k| k.pubkey()).unwrap_or_default();
        let ixs = std::slice::from_ref(&self.instruction);

        // Pre-tx: dirty tracking
        let __t_pre = std::time::Instant::now();
        self.ctx.dirty_tracker.record_tx(ixs, &fee_payer);
        crate::SEND_BATCH_PRE_NS.with(|c| c.set(c.get() + __t_pre.elapsed().as_nanos() as u64));

        // SVM execution
        let __t_svm = std::time::Instant::now();
        let result = instruction_builder::send_instruction(&mut self.ctx.svm, self.instruction, &self.signers)?;
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
