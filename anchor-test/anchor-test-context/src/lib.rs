use std::rc::Rc;
use std::cell::RefCell;
use litesvm::LiteSVM;
use solana_sdk::{
    account::Account,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    instruction::Instruction,
    system_program,
    rent::Rent,
};
use anchor_lang::{
    //prelude::*,
    AnchorDeserialize, 
    AnchorSerialize,
    Discriminator,
};
use spl_token::solana_program::program_option::COption;
use solana_program::program_pack::Pack;
use anyhow::Result;
pub use crate::account_builders::MintAccountBuilder;
pub use crate::account_builders::GenericAccountBuilder;
pub use crate::account_builders::TokenAccountBuilder;
pub use crate::instruction_builder::InstructionBuilder;
pub use crate::transaction_builder::TransactionBuilder;
pub use crate::program_builder::ProgramBuilder;
pub use crate::account_builders::AccountBuilderBase;
use anchor_fuzz_harness;
 

mod account_builders;
mod instruction_builder;
mod program_builder;
mod transaction_builder;
mod system_program_builder;

pub use anchor_fuzz_harness::DefaultTraceCollector;
pub use anchor_fuzz_harness::TRACE_COLLECTOR;
use litesvm::types::TraceCollector;

pub struct TestContext {
    svm: Rc<RefCell<LiteSVM>>,
}

impl TestContext {
    pub fn new() -> Self {
        let svm = anchor_fuzz_harness::TRACE_COLLECTOR.with(|tc| {
            // Cast to trait object for LiteSVM
            let trace_collector: Rc<RefCell<dyn TraceCollector>> = tc.clone();
            Rc::new(RefCell::new(
                LiteSVM::new().with_trace_collector(trace_collector)
            ))
        });
        
        Self { svm }
    }
    
    pub fn add_program(&self, program_id: &Pubkey, program_path: &str) -> Result<()> {
        let program_data = std::fs::read(program_path)?;
        
        self.svm.borrow_mut().add_program(program_id.clone(), &program_data);
        Ok(())
    }

    /// Account Creation Helpers

    // Create a basic default account
    pub fn create_account(&self) -> GenericAccountBuilder {
        GenericAccountBuilder {
            svm: self.svm.clone(),
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
    pub fn create_mint(&self) -> MintAccountBuilder {
        let rent = Rent::default();
        MintAccountBuilder {
            svm: self.svm.clone(),
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
    
    // Create an ATA account
    pub fn create_token_account(&self) -> TokenAccountBuilder {
        let rent = Rent::default();
        TokenAccountBuilder {
            svm: self.svm.clone(),
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
    /// Getters

    // Read an account at a Pubkey
    pub fn read_account(&self, address: &Pubkey) -> Result<Account> {
        self.svm.borrow()
            .get_account(address)
            .ok_or_else(|| anyhow::anyhow!("Account not found: {}", address))
    }
    
    // Read anchor account at address and deserialize the 
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

    /// Setters

    // Write account directly to SVM
    pub fn write_account(&self, address: &Pubkey, account: Account) -> Result<()> {
        self.svm.borrow_mut().set_account(*address, account);
        Ok(())
    }
    
    // Serialize with discriminator, write to SVM
    pub fn write_anchor_account<T: AnchorSerialize + Discriminator>(
        &self, 
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
        self.svm.borrow_mut().set_account(*address, account);
        
        Ok(())
    }

    /// Callers - each returns a builder

    // Escape hatch for raw instructions
    pub fn raw_call(&self, instruction: Instruction) -> InstructionBuilder {
        InstructionBuilder {
            svm: self.svm.clone(),
            instruction,
            signers: vec![],
        }
    }
    
    // For calling Anchor programs dynamically
    pub fn program(&self, program_id: Pubkey) -> ProgramBuilder {  
        ProgramBuilder {
            svm: self.svm.clone(),  
            instruction: Instruction {
                program_id,
                accounts: vec![],
                data: vec![],
            },
            signers: vec![],  
        }
    }
    
    // For batching multiple instructions
    pub fn transaction(&self) -> TransactionBuilder {
        TransactionBuilder {
            svm: self.svm.clone(),
            instructions: vec![],
            signers: vec![],
        }
    }
}
