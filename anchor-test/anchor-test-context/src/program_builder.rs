use litesvm::LiteSVM;
use solana_sdk::{
    instruction::Instruction,
    signature::{Keypair, Signer},
    message::{Message, VersionedMessage},
    transaction::VersionedTransaction,
};
use anchor_lang::{InstructionData, ToAccountMetas};
use anyhow::Result;
use crate::instruction_builder;

pub struct ProgramBuilder<'a> {
    pub(crate) svm: &'a mut LiteSVM,
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

    pub fn signers(mut self, signers: &[&Keypair]) -> Self {
        self.signers = signers.iter().map(|k| k.insecure_clone()).collect();
        self
    }

    pub fn send(self) -> Result<litesvm::types::TransactionResult> {  
        instruction_builder::send_instruction(self.svm, self.instruction, &self.signers)
    }
}

