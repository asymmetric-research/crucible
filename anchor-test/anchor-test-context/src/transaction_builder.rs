use crate::TestContext;
use solana_sdk::{
    instruction::Instruction,
    signature::Keypair,
};

pub struct TransactionBuilder<'a> {
    pub(crate) ctx: &'a mut TestContext,
    pub(crate) instructions: Vec<Instruction>,  
    pub(crate) signers: Vec<Keypair>,
}

impl TransactionBuilder<'_> {
    pub fn add_instruction<F>(mut self, builder: F) -> Self 
    where
        F: FnOnce() -> Instruction,
    {
        self.instructions.push(builder());
        self
    }

    pub fn signers(mut self, signers: &[&Keypair]) -> Self {
        self.signers = signers.iter().map(|k| k.insecure_clone()).collect();
        self
    }

    pub fn send(self) -> anyhow::Result<litesvm::types::TransactionResult> {
        todo!("Transaction batching not yet implemented")
    }
}
