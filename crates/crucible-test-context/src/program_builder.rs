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

        // Always: record dirty accounts (just FxHashSet inserts, zero-alloc)
        self.ctx.dirty_tracker.record_tx(ixs, &fee_payer);

        // Capture metadata + optional pre-state before instruction is consumed
        let captured = crate::snapshot::capture_tx_meta(ixs, &fee_payer);
        let pre_state = if self.ctx.taint_log.collects_diffs() {
            Some(crate::snapshot::snapshot_writable_accounts(&self.ctx.svm, ixs, &fee_payer))
        } else {
            None
        };

        let result = instruction_builder::send_instruction(&mut self.ctx.svm, self.instruction, &self.signers)?;
        let outcome = tx_result_to_outcome(result);

        // Build taint record from captured metadata (only for successful txs)
        if outcome.is_success() {
            let taint = crate::snapshot::build_taint_record_from_captured(
                &self.ctx.svm, captured, pre_state.as_ref(),
            );
            self.ctx.taint_log.push(taint);
        }

        Ok(outcome)
    }

    pub fn add_transaction(self) -> Result<()> {
        self.ctx.pending_instructions.push(self.instruction);
        self.ctx.pending_signers.extend(self.signers);
        Ok(())
    }
}
