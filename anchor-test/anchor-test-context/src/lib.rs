use std::rc::Rc;
use std::collections::HashSet;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_pubkey::Pubkey;
use solana_transaction_error::TransactionError;

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
pub use crate::mock_oracles::{
    MockPythOracleBuilder,
    PriceUpdateV2,
    PriceFeedMessage,
    VerificationLevel,
    DEFAULT_PYTH_RECEIVER_ID,
    PYTH_DISCRIMINATOR,
};

mod account_builders;
mod instruction_builder;
mod program_builder;
mod transaction_builder;
mod system_program_builder;
mod mock_oracles;

pub use litesvm::InvocationInspectCallback;

/// Parsed transaction outcome from litesvm execution
#[derive(Debug, Clone)]
pub enum TxOutcome {
    /// Transaction executed successfully
    Success {
        compute_units: u64,
        logs: Vec<String>,
    },
    /// Transaction failed with program error
    ProgramError {
        /// Raw error from SVM
        error: TransactionError,
        /// Parsed error code (e.g., 6051 from Custom(6051))
        error_code: Option<u32>,
        /// Instruction index that failed
        instruction_index: Option<u8>,
        /// Program logs up to failure
        logs: Vec<String>,
    },
}

/// Error type for TxOutcome::into_result()
#[derive(Debug, Clone)]
pub struct TxError {
    pub error: TransactionError,
    pub error_code: Option<u32>,
    pub instruction_index: Option<u8>,
    pub logs: Vec<String>,
}

impl std::error::Error for TxError {}

impl std::fmt::Display for TxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Transaction failed")?;
        if let Some(code) = self.error_code {
            write!(f, " (error code: {})", code)?;
        }
        if let Some(idx) = self.instruction_index {
            write!(f, " at instruction {}", idx)?;
        }
        Ok(())
    }
}

impl TxOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, TxOutcome::Success { .. })
    }

    pub fn is_error(&self) -> bool {
        matches!(self, TxOutcome::ProgramError { .. })
    }

    pub fn error_code(&self) -> Option<u32> {
        match self {
            TxOutcome::ProgramError { error_code, .. } => *error_code,
            _ => None,
        }
    }

    pub fn logs(&self) -> &[String] {
        match self {
            TxOutcome::Success { logs, .. } => logs,
            TxOutcome::ProgramError { logs, .. } => logs,
        }
    }

    pub fn compute_units(&self) -> Option<u64> {
        match self {
            TxOutcome::Success { compute_units, .. } => Some(*compute_units),
            _ => None,
        }
    }

    /// Unwrap success or panic with detailed error message including logs
    pub fn unwrap(self) {
        match self {
            TxOutcome::Success { .. } => {}
            TxOutcome::ProgramError { error, error_code, logs, .. } => {
                let mut msg = format!("Transaction failed: {:?}", error);
                if let Some(code) = error_code {
                    msg.push_str(&format!(" (code: {})", code));
                }
                msg.push_str("\nLogs:\n");
                for log in &logs {
                    msg.push_str(&format!("  {}\n", log));
                }
                panic!("{}", msg);
            }
        }
    }

    /// Expect success or panic with custom message
    pub fn expect(self, msg: &str) {
        match self {
            TxOutcome::Success { .. } => {}
            TxOutcome::ProgramError { logs, .. } => {
                let mut full_msg = format!("{}\nLogs:\n", msg);
                for log in &logs {
                    full_msg.push_str(&format!("  {}\n", log));
                }
                panic!("{}", full_msg);
            }
        }
    }

    /// Convert to Result for ? operator compatibility
    pub fn into_result(self) -> std::result::Result<(), TxError> {
        match self {
            TxOutcome::Success { .. } => Ok(()),
            TxOutcome::ProgramError { error, error_code, instruction_index, logs } => {
                Err(TxError { error, error_code, instruction_index, logs })
            }
        }
    }
}

/// Parse litesvm TransactionError to extract error code
/// Extracts Custom(N) error codes from InstructionError variants
pub fn parse_error_code(err: &TransactionError) -> Option<u32> {
    let debug_str = format!("{:?}", err);
    if let Some(custom_start) = debug_str.find("Custom(") {
        let after_custom = &debug_str[custom_start + 7..];
        if let Some(end) = after_custom.find(')') {
            return after_custom[..end].parse().ok();
        }
    }
    None
}

/// Parse litesvm TransactionError to extract instruction index
pub fn parse_instruction_index(err: &TransactionError) -> Option<u8> {
    let debug_str = format!("{:?}", err);
    if let Some(start) = debug_str.find("InstructionError(") {
        let after_prefix = &debug_str[start + 17..];
        if let Some(comma) = after_prefix.find(',') {
            return after_prefix[..comma].trim().parse().ok();
        }
    }
    None
}

/// Convert litesvm transaction result to TxOutcome
pub fn tx_result_to_outcome(result: litesvm::types::TransactionResult) -> TxOutcome {
    match result {
        Ok(meta) => TxOutcome::Success {
            compute_units: meta.compute_units_consumed,
            logs: meta.logs,
        },
        Err(failed) => TxOutcome::ProgramError {
            error: failed.err.clone(),
            error_code: parse_error_code(&failed.err),
            instruction_index: parse_instruction_index(&failed.err),
            logs: failed.meta.logs,
        },
    }
}

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

    /// Returns the slot that the next transaction will likely see (current + 1)
    pub fn next_slot(&self) -> u64 {
        self.slot() + 1
    }

    /// Check if account exists AND has at least `min_size` bytes of data
    pub fn account_has_data(&self, pubkey: &Pubkey, min_size: usize) -> bool {
        self.svm.get_account(pubkey)
            .map(|acc| acc.data.len() >= min_size)
            .unwrap_or(false)
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

    /// Update account data using a closure. Enables atomic read-modify-write pattern.
    ///
    /// # Example
    /// ```ignore
    /// ctx.update_account(&reserve_pubkey, |data| {
    ///     // Modify data in place (e.g., using bytemuck)
    ///     let reserve: &mut Reserve = bytemuck::from_bytes_mut(&mut data[8..]);
    ///     reserve.config.loan_to_value_pct = 80;
    /// })?;
    /// ```
    pub fn update_account<F>(&mut self, pubkey: &Pubkey, f: F) -> Result<()>
    where
        F: FnOnce(&mut Vec<u8>),
    {
        let mut account = self.read_account(pubkey)?;
        f(&mut account.data);
        self.write_account(pubkey, account)
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

    pub fn send_batch(&mut self) -> Result<Option<TxOutcome>> {
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

        let outcome = tx_result_to_outcome(result);

        if debug {
            match &outcome {
                TxOutcome::Success { compute_units, logs } => {
                    eprintln!("[TX] SUCCESS - compute_units={}, logs:", compute_units);
                    for log in logs {
                        eprintln!("[TX]   {}", log);
                    }
                }
                TxOutcome::ProgramError { error, error_code, logs, .. } => {
                    eprintln!("[TX] FAILED - error: {:?}", error);
                    if let Some(code) = error_code {
                        eprintln!("[TX]   error code: {}", code);
                    }
                    eprintln!("[TX]   logs:");
                    for log in logs {
                        eprintln!("[TX]   {}", log);
                    }
                }
            }
        }

        // Clear queue regardless of success/failure
        self.pending_instructions.clear();
        self.pending_signers.clear();

        Ok(Some(outcome))
    }
}

