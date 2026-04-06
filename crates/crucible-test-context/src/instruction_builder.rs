use crate::{tx_result_to_outcome, TestContext, TxOutcome};
use anchor_lang::solana_program::instruction::Instruction;
use anyhow::{Context, Result};
use solana_keypair::Keypair;
use solana_message::{legacy::Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

pub struct InstructionBuilder<'a> {
    pub(crate) ctx: &'a mut TestContext,
    pub(crate) instruction: Instruction,
    pub(crate) signers: Vec<Keypair>,
    pub(crate) fee_payer: Option<Keypair>,
}

impl InstructionBuilder<'_> {
    pub fn signers(mut self, signers: &[&Keypair]) -> Self {
        self.signers = signers.iter().map(|k| k.insecure_clone()).collect();
        self
    }

    pub fn fee_payer(mut self, fee_payer: &Keypair) -> Self {
        self.fee_payer = Some(fee_payer.insecure_clone());
        self
    }

    pub fn send(self) -> Result<TxOutcome> {
        let ixs = std::slice::from_ref(&self.instruction);
        let fee_payer_pubkey = self
            .fee_payer
            .as_ref()
            .map(|kp| kp.pubkey())
            .context("At least one signer required if fee payer is not set explicitly")?;

        let fee_payer = self
            .fee_payer
            .as_ref()
            .map(|kp| kp.insecure_clone())
            .context("At least one signer required if fee payer is not set explicitly")?
            .insecure_clone();

        // Pre-tx: dirty tracking
        let __t_pre = std::time::Instant::now();
        self.ctx.dirty_tracker.record_tx(ixs, &fee_payer_pubkey);
        crate::SEND_BATCH_PRE_NS.with(|c| c.set(c.get() + __t_pre.elapsed().as_nanos() as u64));

        // SVM execution
        let __t_svm = std::time::Instant::now();
        let result = send_instruction(
            &mut self.ctx.svm,
            self.instruction,
            &self.signers,
            &fee_payer,
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

pub fn send_instruction(
    svm: &mut litesvm::LiteSVM,
    instruction: Instruction,
    signers: &[Keypair],
    payer: &Keypair,
) -> Result<litesvm::types::TransactionResult> {
    let signer_refs: Vec<&Keypair> = signers.iter().collect();
    send_transaction(svm, vec![instruction], &signer_refs, payer)
}

pub fn send_transaction(
    svm: &mut litesvm::LiteSVM,
    instructions: Vec<Instruction>,
    signers: &[&Keypair],
    payer: &Keypair,
) -> Result<litesvm::types::TransactionResult> {
    let debug = std::env::var("FUZZ_DEBUG").is_ok();

    svm.expire_blockhash();
    let blockhash = svm.latest_blockhash();

    let message = Message::new_with_blockhash(&instructions, Some(&payer.pubkey()), &blockhash);

    let mut keypairs = signers.to_vec();
    keypairs.push(payer);

    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(message), &keypairs)?;

    let result = svm.send_transaction(tx);

    if debug {
        match &result {
            Ok(meta) => {
                eprintln!(
                    "[TX] SUCCESS - compute_units={}",
                    meta.compute_units_consumed
                );
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
