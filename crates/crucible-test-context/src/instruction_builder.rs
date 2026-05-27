use crate::{tx_result_to_outcome, TestContext, TxOutcome};
use anchor_lang::solana_program::instruction::Instruction;
use anyhow::{Context, Result};
use solana_keypair::Keypair;
use solana_message::{legacy::Message, VersionedMessage};
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
            .or_else(|| self.signers.first().map(|kp| kp.pubkey()))
            .unwrap_or_default();

        let mut all_signers = self.signers;
        if let Some(ref fp) = self.fee_payer {
            if !all_signers.iter().any(|k| k.pubkey() == fp.pubkey()) {
                all_signers.insert(0, fp.insecure_clone());
            }
        }
        let fee_payer = all_signers
            .first()
            .context("At least one signer required")?
            .insecure_clone();
        let signer_refs: Vec<&Keypair> = all_signers.iter().collect();

        // Pre-tx: dirty tracking
        let __t_pre = std::time::Instant::now();
        self.ctx.dirty_tracker.record_tx(ixs, &fee_payer_pubkey);
        crate::SEND_BATCH_PRE_NS.with(|c| c.set(c.get() + __t_pre.elapsed().as_nanos() as u64));

        // Owner-mutation probe runs on a cloned SVM and never replaces the real outcome.
        self.ctx
            .maybe_probe_owner_mutation(ixs, &signer_refs, &fee_payer);

        // SVM execution
        let __t_svm = std::time::Instant::now();
        let result = send_transaction(
            &mut self.ctx.svm,
            vec![self.instruction],
            &signer_refs,
            &fee_payer,
            self.ctx.sigverify,
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

pub fn send_transaction(
    svm: &mut litesvm::LiteSVM,
    instructions: Vec<Instruction>,
    signers: &[&Keypair],
    payer: &Keypair,
    sigverify: bool,
) -> Result<litesvm::types::TransactionResult> {
    let debug = std::env::var("FUZZ_DEBUG").is_ok();

    let __t0 = std::time::Instant::now();
    let blockhash = if sigverify {
        // Full mode: expire and get fresh blockhash
        svm.expire_blockhash();
        svm.latest_blockhash()
    } else {
        // Fuzzing mode: blockhash_check is disabled, skip expire_blockhash()
        // which writes RecentBlockhashes sysvar (occasionally spikes to 111µs).
        svm.latest_blockhash()
    };
    let __t_blockhash = __t0.elapsed().as_nanos() as u64;

    let __t1 = std::time::Instant::now();
    let message = Message::new_with_blockhash(&instructions, Some(&payer.pubkey()), &blockhash);

    let tx = if sigverify {
        let mut keypairs = signers.to_vec();
        if !keypairs.iter().any(|k| k.pubkey() == payer.pubkey()) {
            keypairs.push(payer);
        }
        VersionedTransaction::try_new(VersionedMessage::Legacy(message), &keypairs)?
    } else {
        // Dummy signatures: skip ed25519 computation (~77µs per tx).
        // Safe because sigverify is disabled on the SVM.
        let num_sigs = message.header.num_required_signatures as usize;
        let signatures = vec![solana_signature::Signature::default(); num_sigs];
        VersionedTransaction {
            signatures,
            message: VersionedMessage::Legacy(message),
        }
    };
    let __t_sign = __t1.elapsed().as_nanos() as u64;

    let __t2 = std::time::Instant::now();
    let result = svm.send_transaction(tx);
    let __t_exec = __t2.elapsed().as_nanos() as u64;

    crate::SEND_TX_BLOCKHASH_NS.with(|c| c.set(c.get() + __t_blockhash));
    crate::SEND_TX_SIGN_NS.with(|c| c.set(c.get() + __t_sign));
    crate::SEND_TX_EXEC_NS.with(|c| c.set(c.get() + __t_exec));

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
