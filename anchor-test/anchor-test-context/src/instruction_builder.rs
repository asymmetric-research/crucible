use crate::{TestContext, TxOutcome, tx_result_to_outcome};
use anchor_lang::solana_program::instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_message::{legacy::Message, VersionedMessage};
use solana_transaction::versioned::VersionedTransaction;
use anyhow::Result;

pub struct InstructionBuilder<'a> {
    pub(crate) ctx: &'a mut TestContext,
    pub(crate) instruction: Instruction,  
    pub(crate) signers: Vec<Keypair>,     
}

impl InstructionBuilder<'_> {
    pub fn signers(mut self, signers: &[&Keypair]) -> Self {
        self.signers = signers.iter().map(|k| k.insecure_clone()).collect();
        self
    }

    pub fn send(self) -> Result<TxOutcome> {
        let result = send_instruction(&mut self.ctx.svm, self.instruction, &self.signers)?;
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

pub fn send_instruction(
    svm: &mut litesvm::LiteSVM,
    instruction: Instruction,
    signers: &[Keypair],
) -> Result<litesvm::types::TransactionResult> {
    let signer_refs: Vec<&Keypair> = signers.iter().collect();
    send_transaction(svm, vec![instruction], &signer_refs)
}

pub fn send_transaction(
    svm: &mut litesvm::LiteSVM,
    instructions: Vec<Instruction>,
    signers: &[&Keypair],
) -> Result<litesvm::types::TransactionResult> {
    if signers.is_empty() {
        return Err(anyhow::anyhow!("At least one signer (fee payer) is required"));
    }

    let debug = std::env::var("FUZZ_DEBUG").is_ok();

    svm.expire_blockhash();
    let blockhash = svm.latest_blockhash();

    let message = Message::new_with_blockhash(
        &instructions,
        Some(&signers[0].pubkey()),
        &blockhash,
    );

    let tx = VersionedTransaction::try_new(
        VersionedMessage::Legacy(message),
        signers
    )?;

    let result = svm.send_transaction(tx);

    if debug {
        match &result {
            Ok(meta) => {
                eprintln!("[TX] SUCCESS - compute_units={}", meta.compute_units_consumed);
            }
            Err(failed) => {
                eprintln!("[TX] FAILED - error: {:?}", failed.err);
                for log in &failed.meta.logs {
                    eprintln!("[TX]   {}", log);
                }
            }
        }
    }

    Ok(result)
}
