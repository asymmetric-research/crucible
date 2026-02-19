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

        let result = send_instruction(&mut self.ctx.svm, self.instruction, &self.signers)?;
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
