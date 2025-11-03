use std::rc::Rc;
use std::cell::RefCell;
use litesvm::LiteSVM;
use solana_sdk::{
    instruction::Instruction,
    signature::{Keypair, Signer},
    message::{Message, VersionedMessage},
    transaction::VersionedTransaction,
};
use anyhow::Result;

pub struct InstructionBuilder {
    pub(crate) svm: Rc<RefCell<LiteSVM>>,
    pub(crate) instruction: Instruction,  
    pub(crate) signers: Vec<Keypair>,     
}

impl InstructionBuilder {
    pub fn signers(mut self, signers: &[&Keypair]) -> Self {
        self.signers = signers.iter().map(|k| k.insecure_clone()).collect();
        self
    }

    pub fn send(self) -> Result<litesvm::types::TransactionResult> {  
        send_instruction(&self.svm, self.instruction, &self.signers)
    }
}

pub fn send_instruction(
    svm: &Rc<RefCell<LiteSVM>>,
    instruction: Instruction,
    signers: &[Keypair],
) -> Result<litesvm::types::TransactionResult> {
    if signers.is_empty() {
        return Err(anyhow::anyhow!("At least one signer (fee payer) is required"));
    }
    // Expire so we don't get AlreadyProcessed
    svm.borrow_mut().expire_blockhash(); 

    // Get recent blockhash from SVM
    let blockhash = svm.borrow().latest_blockhash();

    // Create message with single instruction
    let message = Message::new_with_blockhash(
        &[instruction],
        Some(&signers[0].pubkey()),  // First signer as payer
        &blockhash,
    );

    // Create transaction
    let tx = VersionedTransaction::try_new(
        VersionedMessage::Legacy(message), 
        signers
    )?;

    let result = svm.borrow_mut().send_transaction(tx);

    Ok(result)
}
