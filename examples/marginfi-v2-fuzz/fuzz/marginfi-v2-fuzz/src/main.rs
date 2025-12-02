use anchor_test::*;
use anchor_test_context::ProgramBuilder;
use anchor_lang::prelude::*;
use solana_sdk::{
    signature::{Keypair, Signer},
    pubkey::Pubkey,
    system_program,
    sysvar,
};
use std::{rc::Rc, collections::HashMap};
use fixed::types::I80F48;
use fixed_macro::types::I80F48;

use marginfi_program::{
    instruction,
    accounts,
    state::marginfi_group::{
        MarginfiGroup, BankConfigCompact, WrappedI80F48, 
        BankOperationalState, RiskTier, InterestRateConfigCompact,
    },
    state::marginfi_account::{MarginfiAccount, ACCOUNT_IN_FLASHLOAN, ACCOUNT_DISABLED},
};
use pyth_solana_receiver_sdk::price_update::{PriceUpdateV2, PriceFeedMessage, VerificationLevel};
use anchor_spl::token::spl_token;
use marginfi_program::state::marginfi_group::Bank;
use bytemuck;
use arbitrary::Arbitrary;

// ============================================================================
// Fixture Data Structures
// ============================================================================

#[derive(Clone)]
struct BankData {
    bank: Pubkey,
    mint: Pubkey,
    oracle: Pubkey,
    liquidity_vault: Pubkey,
    decimals: u8,
    price: I80F48,  
}

#[derive(Clone)]
struct UserData {
    keypair: Rc<Keypair>,
    marginfi_account: Pubkey,
    token_accounts: HashMap<Pubkey, Pubkey>,
}

#[derive(Clone)]
struct MarginfiFixture {
    ctx: TestContext,
    program_id: Pubkey,
    admin: Rc<Keypair>,
    group: Pubkey,
    fee_state: Pubkey,
    global_fee_wallet: Pubkey,
    banks: Vec<BankData>,
    users: Vec<UserData>,
    all_marginfi_accounts: Vec<Pubkey>,
}

// ============================================================================
// Flashloan Inner Action Enum
// ============================================================================

#[derive(Clone, Debug, Arbitrary)]
pub enum FlashloanInnerAction {
    Deposit {
        bank_idx: usize,
        amount: u64,
    },
    Borrow {
        bank_idx: usize,
        amount: u64,
    },
    Repay {
        bank_idx: usize,
        amount: u64,
        repay_all: bool,
    },
    Withdraw {
        bank_idx: usize,
        amount: u64,
        withdraw_all: bool,
    },
    TransferAccount {
        to_user_idx: usize,
    },
}

// ============================================================================
// Fixture Implementation
// ============================================================================

#[fuzz_fixture]
impl MarginfiFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = marginfi_program::ID;
        
        ctx.add_program(&program_id, "target/deploy/marginfi.so")
            .expect("Failed to load marginfi program");
        
        let admin = Rc::new(Keypair::new());
        ctx.create_account()
            .pubkey(admin.pubkey())
            .lamports(100_000_000_000)
            .owner(system_program::id())
            .create()
            .unwrap();
        
        let fee_state = Self::init_fee_state(&mut ctx, &admin, &program_id);
        let group = Self::init_group(&mut ctx, &admin, &fee_state, &program_id);
        
        let global_fee_wallet = admin.pubkey();
        
        let sol_mint = ctx.create_mint()
            .pubkey(Keypair::new().pubkey())
            .decimals(9)
            .mint_authority(admin.pubkey())
            .create()
            .unwrap();
            
        let usdc_mint = ctx.create_mint()
            .pubkey(Keypair::new().pubkey())
            .decimals(6)
            .mint_authority(admin.pubkey())
            .create()
            .unwrap();
        
        let sol_oracle = Self::create_oracle(&mut ctx, I80F48!(100.0), 9);
        let usdc_oracle = Self::create_oracle(&mut ctx, I80F48!(1.0), 6);
        
        let sol_bank = Self::create_bank(
            &mut ctx, &program_id, &group, &fee_state, 
            &sol_mint, &sol_oracle, 9, &admin, sol_bank_config()
        );
        
        let usdc_bank = Self::create_bank(
            &mut ctx, &program_id, &group, &fee_state,
            &usdc_mint, &usdc_oracle, 6, &admin, usdc_bank_config()
        );
        
       let banks = vec![
            BankData { bank: sol_bank.0, mint: sol_mint, oracle: sol_oracle, liquidity_vault: sol_bank.1, decimals: 9, price: I80F48!(100.0) },
            BankData { bank: usdc_bank.0, mint: usdc_mint, oracle: usdc_oracle, liquidity_vault: usdc_bank.1, decimals: 6, price: I80F48!(1.0) },
        ]; 

        let users: Vec<_> = (0..3)
            .map(|_| Self::create_user(&mut ctx, &program_id, &group, &banks, &admin))
            .collect();
        
        let all_marginfi_accounts: Vec<Pubkey> = users.iter()
            .map(|u| u.marginfi_account)
            .collect();
            
        let mut fixture = Self {
            ctx, 
            program_id, 
            admin,
            group, 
            fee_state, 
            global_fee_wallet,
            banks, 
            users,
            all_marginfi_accounts,
        };

        //fixture.seed_initial_liquidity();
        
        fixture
    }

    fn seed_initial_liquidity(&mut self) {
        for bank_idx in 0..self.banks.len() {
            let bank = &self.banks[bank_idx];
            let user = &self.users[0];
            let amount = 500 * 10_u64.pow(bank.decimals as u32);
            let token_account = user.token_accounts.get(&bank.mint).unwrap();
            
            let _ = self.ctx.program(self.program_id)
                .call(instruction::LendingAccountDeposit { 
                    amount, 
                    deposit_up_to_limit: None 
                })
                .accounts(accounts::LendingAccountDeposit {
                    group: self.group,
                    marginfi_account: user.marginfi_account,
                    authority: user.keypair.pubkey(),
                    bank: bank.bank,
                    signer_token_account: *token_account,
                    liquidity_vault: bank.liquidity_vault,
                    token_program: spl_token::id(),
                })
                .signers(&[&*user.keypair])
                .send();
        }
    }

    // ========================================================================
    // Setup Helpers
    // ========================================================================
    
    fn init_fee_state(ctx: &mut TestContext, admin: &Rc<Keypair>, program_id: &Pubkey) -> Pubkey {
        let (fee_state, _) = Pubkey::find_program_address(&[b"feestate"], program_id);
        
        ctx.program(*program_id)
            .call(instruction::InitGlobalFeeState {
                admin: admin.pubkey(),
                fee_wallet: admin.pubkey(),
                bank_init_flat_sol_fee: 0,
                program_fee_fixed: WrappedI80F48::from(I80F48::ZERO),
                program_fee_rate: WrappedI80F48::from(I80F48::ZERO),
            })
            .accounts(accounts::InitFeeState {
                payer: admin.pubkey(),
                fee_state,
                rent: sysvar::rent::id(),
                system_program: system_program::id(),
            })
            .signers(&[&**admin])
            .send()
            .unwrap();
        
        fee_state
    }
    
    fn init_group(ctx: &mut TestContext, admin: &Rc<Keypair>, fee_state: &Pubkey, program_id: &Pubkey) -> Pubkey {
        let group = Keypair::new();
        
        ctx.program(*program_id)
            .call(instruction::MarginfiGroupInitialize { is_arena_group: false })
            .accounts(accounts::MarginfiGroupInitialize {
                marginfi_group: group.pubkey(),
                admin: admin.pubkey(),
                fee_state: *fee_state,
                system_program: system_program::id(),
            })
            .signers(&[&**admin, &group])
            .send()
            .unwrap();
        
        group.pubkey()
    }
    
    fn create_oracle(ctx: &mut TestContext, price: I80F48, decimals: u8) -> Pubkey {
        let oracle = Keypair::new();
        let native_price = (price * I80F48::from_num(10_i64.pow(decimals as u32))).to_num::<i64>();
        
        let price_update = PriceUpdateV2 {
            write_authority: Pubkey::default(),
            verification_level: VerificationLevel::Full,
            price_message: PriceFeedMessage {
                feed_id: oracle.pubkey().to_bytes(),
                price: native_price,
                conf: 100_000,
                exponent: -(decimals as i32),
                publish_time: 0,
                prev_publish_time: 0,
                ema_price: native_price,
                ema_conf: 100_000,
            },
            posted_slot: 1,
        };
        
        let discriminator: [u8; 8] = [34, 241, 35, 99, 157, 126, 244, 205];
        let mut data = discriminator.to_vec();
        price_update.serialize(&mut data).unwrap();
        
        ctx.create_account()
            .pubkey(oracle.pubkey())
            .owner(pyth_solana_receiver_sdk::ID)
            .lamports(10_000_000)
            .data(&data)
            .create()
            .unwrap();
        
        oracle.pubkey()
    }
    
    fn create_bank(
        ctx: &mut TestContext,
        program_id: &Pubkey,
        group: &Pubkey,
        fee_state: &Pubkey,
        mint: &Pubkey,
        oracle: &Pubkey,
        _decimals: u8,
        admin: &Rc<Keypair>,
        config: BankConfigCompact,
    ) -> (Pubkey, Pubkey) {
        let bank = Keypair::new();
        
        let (liquidity_vault, _) = Pubkey::find_program_address(
            &[b"liquidity_vault", bank.pubkey().as_ref()], program_id
        );
        let (liquidity_vault_authority, _) = Pubkey::find_program_address(
            &[b"liquidity_vault_auth", bank.pubkey().as_ref()], program_id
        );
        let (insurance_vault, _) = Pubkey::find_program_address(
            &[b"insurance_vault", bank.pubkey().as_ref()], program_id
        );
        let (insurance_vault_authority, _) = Pubkey::find_program_address(
            &[b"insurance_vault_auth", bank.pubkey().as_ref()], program_id
        );
        let (fee_vault, _) = Pubkey::find_program_address(
            &[b"fee_vault", bank.pubkey().as_ref()], program_id
        );
        let (fee_vault_authority, _) = Pubkey::find_program_address(
            &[b"fee_vault_auth", bank.pubkey().as_ref()], program_id
        );
        
        ctx.program(*program_id)
            .call(instruction::LendingPoolAddBank { bank_config: config })
            .accounts(accounts::LendingPoolAddBank {
                marginfi_group: *group,
                admin: admin.pubkey(),
                fee_payer: admin.pubkey(),
                fee_state: *fee_state,
                global_fee_wallet: admin.pubkey(),
                bank_mint: *mint,
                bank: bank.pubkey(),
                liquidity_vault_authority,
                liquidity_vault,
                insurance_vault_authority,
                insurance_vault,
                fee_vault_authority,
                fee_vault,
                rent: sysvar::rent::id(),
                token_program: spl_token::id(),
                system_program: system_program::id(),
            })
            .signers(&[&**admin, &bank])
            .send()
            .unwrap();
        
        ctx.program(*program_id)
            .call(instruction::LendingPoolConfigureBankOracle {
                setup: 3,
                oracle: *oracle,
            })
            .accounts(accounts::LendingPoolConfigureBankOracle {
                group: *group,
                admin: admin.pubkey(),
                bank: bank.pubkey(),
            })
            .remaining_accounts(vec![*oracle])
            .signers(&[&**admin])
            .send()
            .unwrap();
        
        (bank.pubkey(), liquidity_vault)
    }
    
    fn create_user(
        ctx: &mut TestContext,
        program_id: &Pubkey,
        group: &Pubkey,
        banks: &[BankData],
        admin: &Rc<Keypair>,
    ) -> UserData {
        let keypair = Rc::new(Keypair::new());
        
        ctx.create_account()
            .pubkey(keypair.pubkey())
            .lamports(10_000_000_000)
            .owner(system_program::id())
            .create()
            .unwrap();
        
        let marginfi_account = Keypair::new();
        ctx.program(*program_id)
            .call(instruction::MarginfiAccountInitialize {})
            .accounts(accounts::MarginfiAccountInitialize {
                marginfi_group: *group,
                marginfi_account: marginfi_account.pubkey(),
                authority: keypair.pubkey(),
                fee_payer: keypair.pubkey(),
                system_program: system_program::id(),
            })
            .signers(&[&*keypair, &marginfi_account])
            .send()
            .unwrap();
        
        let mut token_accounts = HashMap::new();
        for bank in banks {
            let token_account = ctx.create_token_account()
                .pubkey(Keypair::new().pubkey())
                .mint(bank.mint)
                .token_owner(keypair.pubkey())
                .create()
                .unwrap();
            
            let amount = 1_000 * 10_u64.pow(bank.decimals as u32);
            ctx.mint_to(&bank.mint, &token_account, amount, admin).unwrap();
            
            token_accounts.insert(bank.mint, token_account);
        }
        
        UserData { keypair, marginfi_account: marginfi_account.pubkey(), token_accounts }
    }

    // ========================================================================
    // Balance Helpers
    // ========================================================================
    
    fn get_user_token_balance(&self, user_idx: usize, bank_idx: usize) -> u64 {
        let user = &self.users[user_idx];
        let bank = &self.banks[bank_idx];
        let token_account = user.token_accounts.get(&bank.mint).unwrap();
        self.ctx.token_balance(token_account)
    }
    
    fn cap_to_balance(&self, user_idx: usize, bank_idx: usize, amount: u64) -> u64 {
        let balance = self.get_user_token_balance(user_idx, bank_idx); 
        amount.min(balance)
    }

    fn build_health_remaining_accounts(&self, _user_idx: usize) -> Vec<Pubkey> {
        let mut accounts = Vec::new();
        for bank in &self.banks {
            accounts.push(bank.bank);
            accounts.push(bank.oracle);
        }
        accounts
    }

    // ========================================================================
    // Instruction Builders (shared between actions and flashloan)
    // ========================================================================

    fn build_deposit<'a>(
        &'a mut self,
        user_idx: usize,
        bank_idx: usize,
        amount: u64,
    ) -> ProgramBuilder<'a> {
        let user = &self.users[user_idx];
        let bank = &self.banks[bank_idx];
        let token_account = *user.token_accounts.get(&bank.mint).unwrap();
        
        self.ctx.program(self.program_id)
            .call(instruction::LendingAccountDeposit { 
                amount, 
                deposit_up_to_limit: None 
            })
            .accounts(accounts::LendingAccountDeposit {
                group: self.group,
                marginfi_account: user.marginfi_account,
                authority: user.keypair.pubkey(),
                bank: bank.bank,
                signer_token_account: token_account,
                liquidity_vault: bank.liquidity_vault,
                token_program: spl_token::id(),
            })
            .signers(&[&*user.keypair])
    }

    fn build_borrow<'a>(
        &'a mut self,
        user_idx: usize,
        bank_idx: usize,
        amount: u64,
    ) -> ProgramBuilder<'a> {
        let user = &self.users[user_idx];
        let bank = &self.banks[bank_idx];
        let token_account = *user.token_accounts.get(&bank.mint).unwrap();
        
        let (liquidity_vault_authority, _) = Pubkey::find_program_address(
            &[b"liquidity_vault_auth", bank.bank.as_ref()],
            &self.program_id,
        );
        
        let remaining = self.build_health_remaining_accounts(user_idx);
        
        self.ctx.program(self.program_id)
            .call(instruction::LendingAccountBorrow { amount })
            .accounts(accounts::LendingAccountBorrow {
                group: self.group,
                marginfi_account: user.marginfi_account,
                authority: user.keypair.pubkey(),
                bank: bank.bank,
                destination_token_account: token_account,
                bank_liquidity_vault_authority: liquidity_vault_authority,
                liquidity_vault: bank.liquidity_vault,
                token_program: spl_token::id(),
            })
            .remaining_accounts(remaining)
            .signers(&[&*user.keypair])
    }

    fn build_repay<'a>(
        &'a mut self,
        user_idx: usize,
        bank_idx: usize,
        amount: u64,
        repay_all: bool,
    ) -> ProgramBuilder<'a> {
        let user = &self.users[user_idx];
        let bank = &self.banks[bank_idx];
        let token_account = *user.token_accounts.get(&bank.mint).unwrap();
        
        self.ctx.program(self.program_id)
            .call(instruction::LendingAccountRepay { 
                amount, 
                repay_all: Some(repay_all) 
            })
            .accounts(accounts::LendingAccountRepay {
                group: self.group,
                marginfi_account: user.marginfi_account,
                authority: user.keypair.pubkey(),
                bank: bank.bank,
                signer_token_account: token_account,
                liquidity_vault: bank.liquidity_vault,
                token_program: spl_token::id(),
            })
            .signers(&[&*user.keypair])
    }

    fn build_withdraw<'a>(
        &'a mut self,
        user_idx: usize,
        bank_idx: usize,
        amount: u64,
        withdraw_all: bool,
    ) -> ProgramBuilder<'a> {
        let user = &self.users[user_idx];
        let bank = &self.banks[bank_idx];
        let token_account = *user.token_accounts.get(&bank.mint).unwrap();
        
        let (liquidity_vault_authority, _) = Pubkey::find_program_address(
            &[b"liquidity_vault_auth", bank.bank.as_ref()],
            &self.program_id,
        );
        
        let remaining = self.build_health_remaining_accounts(user_idx);
        
        self.ctx.program(self.program_id)
            .call(instruction::LendingAccountWithdraw { 
                amount, 
                withdraw_all: Some(withdraw_all) 
            })
            .accounts(accounts::LendingAccountWithdraw {
                group: self.group,
                marginfi_account: user.marginfi_account,
                authority: user.keypair.pubkey(),
                bank: bank.bank,
                destination_token_account: token_account,
                bank_liquidity_vault_authority: liquidity_vault_authority,
                liquidity_vault: bank.liquidity_vault,
                token_program: spl_token::id(),
            })
            .remaining_accounts(remaining)
            .signers(&[&*user.keypair])
    }

    fn build_transfer_account<'a>(
        &'a mut self,
        from_user_idx: usize,
        to_user_idx: usize,
        new_marginfi_account: &Keypair,
    ) -> ProgramBuilder<'a> {
        let from_user = &self.users[from_user_idx];
        let to_user = &self.users[to_user_idx];
        
        self.ctx.program(self.program_id)
            .call(instruction::TransferToNewAccount {})
            .accounts(accounts::TransferToNewAccount {
                group: self.group,
                old_marginfi_account: from_user.marginfi_account,
                new_marginfi_account: new_marginfi_account.pubkey(),
                authority: from_user.keypair.pubkey(),
                new_authority: to_user.keypair.pubkey(),
                global_fee_wallet: self.global_fee_wallet,
                system_program: system_program::id(),
            })
            .signers(&[&*from_user.keypair, new_marginfi_account])
    }

    /// Variant for flashloan context where we need to specify the source marginfi account explicitly
    fn build_transfer_account_from<'a>(
        &'a mut self,
        from_user_idx: usize,
        to_user_idx: usize,
        old_marginfi_account: Pubkey,
        new_marginfi_account: &Keypair,
    ) -> ProgramBuilder<'a> {
        let from_user = &self.users[from_user_idx];
        let to_user = &self.users[to_user_idx];
        
        self.ctx.program(self.program_id)
            .call(instruction::TransferToNewAccount {})
            .accounts(accounts::TransferToNewAccount {
                group: self.group,
                old_marginfi_account,
                new_marginfi_account: new_marginfi_account.pubkey(),
                authority: from_user.keypair.pubkey(),
                new_authority: to_user.keypair.pubkey(),
                global_fee_wallet: self.global_fee_wallet,
                system_program: system_program::id(),
            })
            .signers(&[&*from_user.keypair, new_marginfi_account])
    }

    // ========================================================================
    // Standalone Actions (use send())
    // ========================================================================
    
    pub fn action_deposit(
        &mut self,
        #[range(0..3)] user_idx: usize,
        #[range(0..2)] bank_idx: usize,
        #[range(1..100_000_000)] amount: u64,
    ) {
        let amount = self.cap_to_balance(user_idx, bank_idx, amount);
        if amount == 0 { return; }
        
        let _ = self.build_deposit(user_idx, bank_idx, amount).send();
    }

    //pub fn action_borrow(
    //    &mut self,
    //    #[range(0..3)] user_idx: usize,
    //    #[range(0..2)] bank_idx: usize,
    //    #[range(1..100_000_000)] amount: u64,
    //) {
    //    if amount == 0 { return; }
    //    
    //    let _ = self.build_borrow(user_idx, bank_idx, amount).send();
    //}

    //pub fn action_repay(
    //    &mut self,
    //    #[range(0..3)] user_idx: usize,
    //    #[range(0..2)] bank_idx: usize,
    //    #[range(1..100_000_000)] amount: u64,
    //    repay_all: bool,
    //) {
    //    let amount = self.cap_to_balance(user_idx, bank_idx, amount);
    //    if amount == 0 && !repay_all { return; }
    //    
    //    let _ = self.build_repay(user_idx, bank_idx, amount, repay_all).send();
    //}

    //pub fn action_withdraw(
    //    &mut self,
    //    #[range(0..3)] user_idx: usize,
    //    #[range(0..2)] bank_idx: usize,
    //    #[range(1..100_000_000)] amount: u64,
    //    withdraw_all: bool,
    //) {
    //    if amount == 0 && !withdraw_all { return; }
    //    
    //    let _ = self.build_withdraw(user_idx, bank_idx, amount, withdraw_all).send();
    //}

    //pub fn action_transfer_account(
    //    &mut self,
    //    #[range(0..3)] from_user_idx: usize,
    //    #[range(0..3)] to_user_idx: usize,
    //) {
    //    let new_marginfi_account = Keypair::new();
    //    let new_account_pubkey = new_marginfi_account.pubkey();
    //    
    //    let _ = self.build_transfer_account(from_user_idx, to_user_idx, &new_marginfi_account).send();
    //    
    //    self.all_marginfi_accounts.push(new_account_pubkey);
    //}

    // ========================================================================
    // Constraint Helpers
    // ========================================================================
    
    const MAX_AMOUNT: u64 = 100_000_000;
    
    fn constrain_bank_idx(&self, idx: usize) -> usize {
        idx % self.banks.len()
    }
    
    fn constrain_user_idx(&self, idx: usize) -> usize {
        idx % self.users.len()
    }
    
    fn constrain_amount(&self, amount: u64) -> u64 {
        (amount % Self::MAX_AMOUNT).max(1)
    }
    
    // ========================================================================
    // Flashloan Sequence Action
    // ========================================================================

    pub fn action_flashloan_sequence(
        &mut self,
        #[range(0..3)] user_idx: usize,
        inner_actions: Vec<FlashloanInnerAction>,
    ) {
        
        let inner_actions: Vec<_> = inner_actions.into_iter().take(2).collect();
        
        let end_index = (1 + inner_actions.len()) as u64;
        
        let user = &self.users[user_idx];
        let user_keypair = user.keypair.clone();
        let current_marginfi_account = user.marginfi_account;
        
        // Instruction 0: Start flashloan
        let start = self.ctx.program(self.program_id)
            .call(instruction::LendingAccountStartFlashloan { end_index })
            .accounts(accounts::LendingAccountStartFlashloan {
                marginfi_account: current_marginfi_account,
                authority: user_keypair.pubkey(),
                ixs_sysvar: sysvar::instructions::id(),
            })
            .signers(&[&*user_keypair])
            .add_transaction();
        
        // Instructions 1..N: Inner actions
        for action in &inner_actions {
            match action {
                FlashloanInnerAction::Deposit { bank_idx, amount } => {
                    let bank_idx = self.constrain_bank_idx(*bank_idx);
                    let amount = self.constrain_amount(*amount);
                    let amount = self.cap_to_balance(user_idx, bank_idx, amount);
                    let _ = self.build_deposit(user_idx, bank_idx, amount).add_transaction();
                }
                
                FlashloanInnerAction::Borrow { bank_idx, amount } => {
                    let bank_idx = self.constrain_bank_idx(*bank_idx);
                    let _ = self.build_borrow(user_idx, bank_idx, *amount % 100_000_000).add_transaction();
                }
                
                FlashloanInnerAction::Repay { bank_idx, amount, repay_all } => {
                    let bank_idx = self.constrain_bank_idx(*bank_idx);
                    let amount = self.constrain_amount(*amount);
                    let amount = self.cap_to_balance(user_idx, bank_idx, amount);
                    let _ = self.build_repay(user_idx, bank_idx, amount, *repay_all).add_transaction();
                }
                
                FlashloanInnerAction::Withdraw { bank_idx, amount, withdraw_all } => {
                    let bank_idx = self.constrain_bank_idx(*bank_idx);
                    let amount = self.constrain_amount(*amount);
                    let _ = self.build_withdraw(user_idx, bank_idx, amount, *withdraw_all).add_transaction();
                }
                
                FlashloanInnerAction::TransferAccount { to_user_idx } => {
                    let new_account = Keypair::new();
                    let new_account_pubkey = new_account.pubkey();
                    let to_user_idx = self.constrain_user_idx(*to_user_idx);
                    
                    let _ = self.build_transfer_account_from(
                        user_idx,
                        to_user_idx,
                        current_marginfi_account,
                        &new_account,
                    ).add_transaction();
                    
                    self.all_marginfi_accounts.push(new_account_pubkey);
                }
            }
        }
        
        // Final instruction: End flashloan (on ORIGINAL account)
        let remaining = self.build_health_remaining_accounts(user_idx);
        let _ = self.ctx.program(self.program_id)
            .call(instruction::LendingAccountEndFlashloan {})
            .accounts(accounts::LendingAccountEndFlashloan {
                marginfi_account: current_marginfi_account,
                authority: user_keypair.pubkey(),
            })
            .remaining_accounts(remaining)
            .signers(&[&*user_keypair])
            .add_transaction();
        
        let _ = self.ctx.send_batch();
    }
}
// ============================================================================
// Bank Configs
// ============================================================================

fn sol_bank_config() -> BankConfigCompact {
    BankConfigCompact {
        asset_weight_init: WrappedI80F48::from(I80F48!(0.8)),
        asset_weight_maint: WrappedI80F48::from(I80F48!(0.9)),
        liability_weight_init: WrappedI80F48::from(I80F48!(1.2)),
        liability_weight_maint: WrappedI80F48::from(I80F48!(1.1)),
        deposit_limit: u64::MAX,
        borrow_limit: u64::MAX,
        operational_state: BankOperationalState::Operational,
        risk_tier: RiskTier::Collateral,
        oracle_max_age: 100,
        interest_rate_config: InterestRateConfigCompact {
            optimal_utilization_rate: WrappedI80F48::from(I80F48!(0.5)),
            plateau_interest_rate: WrappedI80F48::from(I80F48!(0.5)),
            max_interest_rate: WrappedI80F48::from(I80F48!(4.0)),
            insurance_fee_fixed_apr: WrappedI80F48::from(I80F48!(0.01)),
            insurance_ir_fee: WrappedI80F48::from(I80F48!(0.05)),
            protocol_fixed_fee_apr: WrappedI80F48::from(I80F48!(0.01)),
            protocol_ir_fee: WrappedI80F48::from(I80F48!(0.1)),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn usdc_bank_config() -> BankConfigCompact {
    BankConfigCompact {
        asset_weight_init: WrappedI80F48::from(I80F48!(0.95)),
        asset_weight_maint: WrappedI80F48::from(I80F48!(0.98)),
        liability_weight_init: WrappedI80F48::from(I80F48!(1.05)),
        liability_weight_maint: WrappedI80F48::from(I80F48!(1.02)),
        deposit_limit: u64::MAX,
        borrow_limit: u64::MAX,
        operational_state: BankOperationalState::Operational,
        risk_tier: RiskTier::Collateral,
        oracle_max_age: 100,
        interest_rate_config: InterestRateConfigCompact {
            optimal_utilization_rate: WrappedI80F48::from(I80F48!(0.8)),
            plateau_interest_rate: WrappedI80F48::from(I80F48!(0.1)),
            max_interest_rate: WrappedI80F48::from(I80F48!(3.0)),
            insurance_fee_fixed_apr: WrappedI80F48::from(I80F48!(0.005)),
            insurance_ir_fee: WrappedI80F48::from(I80F48!(0.02)),
            protocol_fixed_fee_apr: WrappedI80F48::from(I80F48!(0.005)),
            protocol_ir_fee: WrappedI80F48::from(I80F48!(0.05)),
            ..Default::default()
        },
        ..Default::default()
    }
}

// ============================================================================
// Tests
// ============================================================================
#[invariant_test]
fn invariant_test(fixture: &mut MarginfiFixture) {
    bad_debt_check(fixture);
}


fn bad_debt_check(fixture: &mut MarginfiFixture) {
    for account_pubkey in fixture.all_marginfi_accounts.clone() {
        let Ok(account_data) = fixture.ctx.get_account(&account_pubkey) else { continue };
        let account: &MarginfiAccount = bytemuck::from_bytes(&account_data.data[8..]);
        
        if account.get_flag(ACCOUNT_DISABLED) { continue }
        
        let mut assets_usd = I80F48::ZERO;
        let mut liabs_usd = I80F48::ZERO;
        
        for bal in account.lending_account.balances.iter() {
            if bal.active == 0 { continue }
            let Some(bank) = fixture.banks.iter().find(|b| b.bank == bal.bank_pk) else { continue };
            
            let a: I80F48 = bal.asset_shares.into();
            let l: I80F48 = bal.liability_shares.into();
            let scale = I80F48::from_num(10_u64.pow(bank.decimals as u32));
            
            assets_usd += a * bank.price / scale;
            liabs_usd += l * bank.price / scale;
        }
        
        assert!(liabs_usd <= assets_usd, "BAD DEBT: {} > {}", liabs_usd, assets_usd);
    }
}
