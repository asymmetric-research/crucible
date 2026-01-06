use std::rc::Rc;
use std::collections::HashSet;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_pubkey::Pubkey;

// Re-export types from anchor-lang for anchor program interactions
use anchor_lang::prelude::{Clock, Rent};
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::system_program;
use anchor_lang::{
    AnchorDeserialize,
    AnchorSerialize,
    Discriminator,
};
use spl_token::solana_program::program_option::COption;
use anchor_lang::solana_program::program_pack::Pack;
use anyhow::Result;
pub use crate::account_builders::MintAccountBuilder;
pub use crate::account_builders::GenericAccountBuilder;
pub use crate::account_builders::TokenAccountBuilder;
pub use crate::instruction_builder::InstructionBuilder;
pub use crate::transaction_builder::TransactionBuilder;
pub use crate::program_builder::ProgramBuilder;
pub use crate::account_builders::AccountBuilderBase;

mod account_builders;
mod instruction_builder;
mod program_builder;
mod transaction_builder;
mod system_program_builder;
pub mod trace_collector;

pub use litesvm::InvocationInspectCallback;

// Re-export types needed by generated code
pub mod fuzz_types {
    pub use solana_transaction::sanitized::SanitizedTransaction;
    pub use solana_transaction_context::IndexOfAccount;
    pub use solana_program_runtime::invoke_context::{InvokeContext, Executable};
    pub use solana_sbpf::ebpf;
}

/// Stores program data for reloading into debuggable SVMs
#[derive(Clone)]
pub struct ProgramData {
    pub program_id: Pubkey,
    pub data: Vec<u8>,
}

pub struct TestContext {
    pub svm: LiteSVM,
    pub pending_instructions: Vec<Instruction>,
    pending_signers: Vec<Keypair>,
    /// Programs loaded into this context (for reloading into debuggable SVMs)
    programs: Vec<ProgramData>,
    /// Account pubkeys that have been set (for copying to debuggable SVMs)
    tracked_accounts: HashSet<Pubkey>,
}

impl Clone for TestContext {
    fn clone(&self) -> Self {
        Self {
            svm: self.svm.clone(),
            pending_instructions: self.pending_instructions.clone(),
            pending_signers: self.pending_signers.iter().map(|k| k.insecure_clone()).collect(),
            programs: self.programs.clone(),
            tracked_accounts: self.tracked_accounts.clone(),
        }
    }
}


/// Empty callback that does nothing - used during setup to avoid DefaultRegisterTracingCallback
/// trying to find .so files on disk for built-in programs.
pub struct EmptyInvocationCallback;

impl InvocationInspectCallback for EmptyInvocationCallback {
    fn before_invocation(
        &self,
        _tx: &solana_transaction::sanitized::SanitizedTransaction,
        _program_indices: &[solana_transaction_context::IndexOfAccount],
        _invoke_context: &solana_program_runtime::invoke_context::InvokeContext,
    ) {}

    fn after_invocation(
        &self,
        _invoke_context: &solana_program_runtime::invoke_context::InvokeContext,
        _register_tracing_enabled: bool,
    ) {}
}

impl TestContext {
    pub fn new() -> Self {
        // When ANCHOR_FUZZ_DEBUGGABLE is set (by the fuzz macro), create a debuggable SVM
        // so programs are loaded with register tracing support baked in.
        // Use EmptyInvocationCallback to suppress "Error collecting register tracing" messages
        // from DefaultRegisterTracingCallback trying to find .so files for built-in programs.
        let svm = if std::env::var("ANCHOR_FUZZ_DEBUGGABLE").is_ok() {
            let mut svm = LiteSVM::new_debuggable(true);
            svm.set_invocation_inspect_callback(EmptyInvocationCallback);
            svm
        } else {
            LiteSVM::new()
        };

        Self {
            svm,
            pending_instructions: Vec::new(),
            pending_signers: Vec::new(),
            programs: Vec::new(),
            tracked_accounts: HashSet::new(),
        }
    }

    pub fn with_invocation_callback<C: InvocationInspectCallback + 'static>(callback: C) -> Self {
        let mut svm = LiteSVM::new_debuggable(true)
            .with_transaction_history(0)
            .with_sigverify(false)
            .with_blockhash_check(false);
        svm.set_invocation_inspect_callback(callback);
        Self {
            svm,
            pending_instructions: Vec::new(),
            pending_signers: Vec::new(),
            programs: Vec::new(),
            tracked_accounts: HashSet::new(),
        }
    }

    pub fn add_program(&mut self, program_id: &Pubkey, program_path: &str) -> Result<()> {
        let program_data = std::fs::read(program_path)?;
        self.svm.add_program(program_id.clone(), &program_data);
        // Store program data for reloading into debuggable SVMs
        self.programs.push(ProgramData {
            program_id: *program_id,
            data: program_data,
        });
        Ok(())
    }

    pub fn from_svm(svm: LiteSVM) -> Self {
        Self {
            svm,
            pending_instructions: Vec::new(),
            pending_signers: Vec::new(),
            programs: Vec::new(),
            tracked_accounts: HashSet::new(),
        }
    }

    pub fn into_svm(self) -> LiteSVM {
        self.svm
    }

    /// Clone this context and set an invocation callback for coverage tracking.
    /// The source SVM must have been created with debuggable mode (via ANCHOR_FUZZ_DEBUGGABLE env var)
    /// for register tracing to work. Cloning preserves the debuggable state and loaded programs.
    pub fn clone_with_invocation_callback<C: InvocationInspectCallback + 'static>(&self, callback: C) -> Self {
        // Just clone the SVM directly and set callback - don't use builder methods
        // as they may create a fresh SVM and lose account data
        let mut cloned_svm = self.svm.clone();
        cloned_svm.set_invocation_inspect_callback(callback);

        Self {
            svm: cloned_svm,
            pending_instructions: self.pending_instructions.clone(),
            pending_signers: self.pending_signers.iter().map(|k| k.insecure_clone()).collect(),
            programs: self.programs.clone(),
            tracked_accounts: self.tracked_accounts.clone(),
        }
    }

    /// Track an account pubkey so it gets copied when cloning with invocation callback.
    /// Called internally by account builders.
    pub fn track_account(&mut self, pubkey: Pubkey) {
        self.tracked_accounts.insert(pubkey);
    }

    /// Get count of tracked accounts (for debugging)
    pub fn tracked_accounts_count(&self) -> usize {
        self.tracked_accounts.len()
    }

    /// Get count of loaded programs (for debugging)
    pub fn programs_count(&self) -> usize {
        self.programs.len()
    }

    /// Check if a specific account exists in the SVM (for debugging)
    pub fn account_exists(&self, pubkey: &Pubkey) -> bool {
        self.svm.get_account(pubkey).is_some()
    }

    /// Account Creation Helpers

    // Create a basic default account
    pub fn create_account(&mut self) -> GenericAccountBuilder<'_> {
        GenericAccountBuilder {
            ctx: self,
            address: Pubkey::default(),  
            account_state: Account {
                lamports: 0,  
                data: vec![],  
                owner: system_program::id(), 
                executable: false,
                rent_epoch: 0,
            },
        }
    }
    
    // Create a mint account
    pub fn create_mint(&mut self) -> MintAccountBuilder<'_> {
        let rent = Rent::default();
        MintAccountBuilder {
            ctx: self,
            address: Pubkey::default(),
            account_state: Account {
                lamports: rent.minimum_balance(spl_token::state::Mint::LEN),
                data: vec![0; spl_token::state::Mint::LEN],
                owner: spl_token::id(),  
                executable: false,
                rent_epoch: 0,
            },
            mint: spl_token::state::Mint {
                mint_authority: COption::None,  
                supply: 0,
                decimals: 0,  
                is_initialized: true,
                freeze_authority: COption::None,
            },
        }
    }
    pub fn create_token_account(&mut self) -> TokenAccountBuilder<'_> {
        let rent = Rent::default();
        TokenAccountBuilder {
            ctx: self,
            address: Pubkey::default(),
            account_state: Account {
                lamports: rent.minimum_balance(spl_token::state::Account::LEN),
                data: vec![0; spl_token::state::Account::LEN],
                owner: spl_token::id(),  
                executable: false,
                rent_epoch: 0,
            },
            token_state: spl_token::state::Account {
                mint: Pubkey::default(),  
                owner: Pubkey::default(),  
                amount: 0,
                delegate: COption::None,
                state: spl_token::state::AccountState::Initialized,
                is_native: COption::None,
                delegated_amount: 0,
                close_authority: COption::None,
            },
        }
    }
    
    /// Transfer tokens between accounts
    pub fn transfer_tokens(
        &mut self,
        from: &Pubkey,
        to: &Pubkey,
        owner: &Keypair,
        amount: u64,
    ) -> anyhow::Result<()> {
        self.raw_call(spl_token::instruction::transfer(
                &spl_token::id(),
                from,
                to,
                &owner.pubkey(),
                &[],
                amount,
            )?)
            .signers(&[owner])
            .send()?;
        Ok(())
    }
    
    pub fn mint_to(
        &mut self,
        mint: &Pubkey,
        destination: &Pubkey,
        amount: u64,
        authority: &Rc<Keypair>,
    ) -> anyhow::Result<()> {
        self.raw_call(spl_token::instruction::mint_to(
                &spl_token::id(),
                mint,
                destination,
                &authority.pubkey(),
                &[],
                amount,
            )?)
            .signers(&[&**authority])
            .send()?;
        Ok(())
    }

    pub fn warp_to_slot(&mut self, slot: u64) {
        self.svm.warp_to_slot(slot);
    }
    
    pub fn advance_slots(&mut self, slots: u64) {
        let current_slot = self.slot();
        let target_slot = current_slot + slots;
        self.svm.warp_to_slot(target_slot);
    }

    /// Getters

    pub fn slot(&self) -> u64 {
        self.svm.get_sysvar::<Clock>().slot
    }

    pub fn get_account(&self, address: &Pubkey) -> Result<Account> {
        self.read_account(address)
    }

    // Read an account at a Pubkey
    pub fn read_account(&self, address: &Pubkey) -> Result<Account> {
        self.svm
            .get_account(address)
            .ok_or_else(|| anyhow::anyhow!("Account not found: {}", address))
    }
    
    // Read anchor account at address and deserialize the data
    pub fn read_anchor_account<T: AnchorDeserialize>(&self, address: &Pubkey) -> Result<T> {
        let account = self.read_account(address)?;
        
        // Anchor accounts have 8-byte discriminator prefix
        if account.data.len() < 8 {
            return Err(anyhow::anyhow!("Account data too small for discriminator"));
        }
        
        // Deserialize from bytes after discriminator
        T::deserialize(&mut &account.data[8..])
            .map_err(|e| anyhow::anyhow!("Failed to deserialize account: {}", e))
    }

    pub fn token_balance(&self, token_account: &Pubkey) -> u64 {
        self.svm
            .get_account(token_account)
            .and_then(|acc| spl_token::state::Account::unpack(&acc.data).ok())
            .map(|state| state.amount)
            .unwrap_or(0)
    }

    /// Setters

    // Write account directly to SVM
    pub fn write_account(&mut self, address: &Pubkey, account: Account) -> Result<()> {
        self.tracked_accounts.insert(*address);
        let _ = self.svm.set_account(*address, account);
        Ok(())
    }
    
    // Serialize with discriminator, write to SVM
    pub fn write_anchor_account<T: AnchorSerialize + Discriminator>(
        &mut self, 
        address: &Pubkey, 
        data: &T
    ) -> Result<()> {
        // Read existing account to preserve lamports, owner, etc.
        let mut account = self.read_account(address)?;
        
        // Build new data: discriminator + serialized T
        let mut account_data = T::DISCRIMINATOR.to_vec();
        data.serialize(&mut account_data)?;
        
        // Update account data and write back
        account.data = account_data;
        let _ = self.svm.set_account(*address, account);
        
        Ok(())
    }

    /// Callers - each returns a builder

    // Escape hatch for raw instructions
    pub fn raw_call(&mut self, instruction: Instruction) -> InstructionBuilder<'_> {
        InstructionBuilder {
            ctx: self,
            instruction,
            signers: vec![],
        }
    }
    
    // For calling Anchor programs dynamically
    pub fn program(&mut self, program_id: Pubkey) -> ProgramBuilder<'_> {  
        ProgramBuilder {
            ctx: self,
            instruction: Instruction {
                program_id,
                accounts: vec![],
                data: vec![],
            },
            signers: vec![],  
        }
    }
    
    // For batching multiple instructions
    pub fn transaction(&mut self) -> TransactionBuilder<'_> {
        TransactionBuilder {
            ctx: self,
            instructions: vec![],
            signers: vec![],
        }
    }

    pub fn send_batch(&mut self) -> Result<Option<litesvm::types::TransactionResult>> {
        // Empty queue is a noop
        if self.pending_instructions.is_empty() {
            return Ok(None);
        }

        let debug = std::env::var("FUZZ_DEBUG").is_ok();
        let num_ixs = self.pending_instructions.len();

        // Deduplicate signers while preserving order (first = fee payer)
        let mut seen = std::collections::HashSet::new();
        let unique_signers: Vec<&Keypair> = self.pending_signers
            .iter()
            .filter(|k| seen.insert(k.pubkey()))
            .collect();

        if debug {
            eprintln!("[TX] Sending batch with {} instructions", num_ixs);
            for (i, ix) in self.pending_instructions.iter().enumerate() {
                eprintln!("[TX]   ix[{}]: program={}", i, ix.program_id);
            }
        }

        // Send transaction with all queued instructions
        let result = instruction_builder::send_transaction(
            &mut self.svm,
            self.pending_instructions.clone(),
            &unique_signers
        )?;

        if debug {
            match &result {
                Ok(meta) => {
                    eprintln!("[TX] SUCCESS - compute_units={}, logs:", meta.compute_units_consumed);
                    for log in &meta.logs {
                        eprintln!("[TX]   {}", log);
                    }
                }
                Err(failed) => {
                    eprintln!("[TX] FAILED - error: {:?}", failed.err);
                    eprintln!("[TX]   logs:");
                    for log in &failed.meta.logs {
                        eprintln!("[TX]   {}", log);
                    }
                }
            }
        }

        // Clear queue regardless of success/failure
        self.pending_instructions.clear();
        self.pending_signers.clear();

        Ok(Some(result))
    }
}

