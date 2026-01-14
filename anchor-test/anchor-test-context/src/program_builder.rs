use crate::{TestContext, TxOutcome, tx_result_to_outcome};
use solana_pubkey::Pubkey;
use solana_keypair::Keypair;
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
        let result = instruction_builder::send_instruction(&mut self.ctx.svm, self.instruction, &self.signers)?;
        Ok(tx_result_to_outcome(result))
    }

    pub fn add_transaction(self) -> Result<()> {
        self.ctx.pending_instructions.push(self.instruction);
        self.ctx.pending_signers.extend(self.signers);
        // Capture current instruction name for coverage tracking
        self.ctx.pending_instruction_names.push(crate::get_current_instruction());
        Ok(())
    }
}
